package xdp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
)

const (
	iptablesTable             = "filter"
	iptablesParent            = "INPUT"
	iptablesChainStart        = "NWRAW_"
	iptablesEgressParent      = "OUTPUT"
	iptablesForwardTable      = "mangle"
	iptablesForwardChainStart = "NWFW_"
	iptablesLegacyTable       = "raw"
	zstackProtocol            = "253"
)

// iptablesRunner isolates command execution so policy compilation can be
// tested without changing the local firewall. The production runner has a
// short timeout because a blocked iptables lock must not stall the agent.
type iptablesRunner interface {
	Run(args ...string) (string, error)
}

type execIPTablesRunner struct {
	path string
}

func (r execIPTablesRunner) Run(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// ZStack and libvirt update their chains concurrently with NodeWall. Ask
	// iptables to wait for xtables.lock instead of failing a reconciliation
	// during a short network-agent update window.
	commandArgs := append([]string{"-w", "5"}, args...)
	output, err := exec.CommandContext(ctx, r.path, commandArgs...).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("iptables %s: %w: %s", strings.Join(commandArgs, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

// IPTablesManager is an opt-in compatibility dataplane for old, non-Kubernetes
// Linux hosts. It never edits a foreign chain: each protected interface owns a
// dedicated chain in filter/INPUT and filter/OUTPUT. The historical NWRAW_*
// names are retained so upgrades and uninstall can identify every owned chain.
// Filtering after conntrack preserves replies to host-originated connections;
// raw/PREROUTING cannot distinguish these replies from unsolicited traffic.
// It only changes kernel netfilter tables through the iptables command; it
// does not create or update persistence files under /etc/iptables. The manager
// is never selected by the real XDP backend or by install-time auto mode.
//
// VM forwarding never enters these local-host hooks. ZStack's raw/NFLOG and
// FORWARD chains remain authoritative for guests and protocol 253 traffic.
type IPTablesManager struct {
	*MockManager

	runner         iptablesRunner
	inputResolver  func(string) string
	outputResolver func(string) string
	egressPolicies map[string]DirectionPolicy
	legacyCleaned  map[string]bool
	chainDigests   map[string][32]byte
	chainEpochs    map[string]string
	applyMu        sync.Mutex
	packetAudit    bool
}

func NewIPTablesManager() *IPTablesManager {
	return newIPTablesManager(execIPTablesRunner{path: "iptables"}, bridgeInputInterface)
}

func newIPTablesManager(runner iptablesRunner, inputResolver func(string) string) *IPTablesManager {
	if inputResolver == nil {
		inputResolver = func(iface string) string { return iface }
	}
	return &IPTablesManager{
		MockManager:    NewMockManager(),
		runner:         runner,
		inputResolver:  inputResolver,
		outputResolver: func(iface string) string { return iface },
		egressPolicies: make(map[string]DirectionPolicy),
		legacyCleaned:  make(map[string]bool),
		chainDigests:   make(map[string][32]byte),
		chainEpochs:    make(map[string]string),
	}
}

func (m *IPTablesManager) Attach(ifaceName string, _ AttachMode) error {
	if err := m.MockManager.Attach(ifaceName, AttachModeIPTables); err != nil {
		return err
	}
	if err := m.sync(ifaceName); err != nil {
		_ = m.MockManager.Detach(ifaceName)
		return err
	}
	return nil
}

func (m *IPTablesManager) Detach(ifaceName string) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()

	var errs []error
	m.removeOwnedChain(iptablesTable, iptablesChainName(ifaceName), &errs)
	m.removeOwnedChain(iptablesTable, iptablesEgressChainName(ifaceName), &errs)
	if err := m.removeLegacyChains(ifaceName); err != nil {
		errs = append(errs, err)
	}
	delete(m.egressPolicies, ifaceName)
	delete(m.legacyCleaned, ifaceName)
	delete(m.chainDigests, iptablesChainName(ifaceName))
	delete(m.chainDigests, iptablesEgressChainName(ifaceName))
	delete(m.chainEpochs, iptablesChainName(ifaceName))
	delete(m.chainEpochs, iptablesEgressChainName(ifaceName))
	if err := m.MockManager.Detach(ifaceName); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *IPTablesManager) removeOwnedChain(table, chain string, errs *[]error) {
	output, err := m.runner.Run("-t", table, "-S", chain)
	if err != nil {
		// Some iptables-nft releases report an already-removed chain as
		// "incompatible". Confirm absence with a successful full-table read;
		// an incompatible chain that still exists must remain an error.
		nftAbsent := strings.Contains(strings.ToLower(output), "is incompatible") && m.chainAbsentFromTable(table, chain)
		if !isMissingIPTablesObject(output, err) && !nftAbsent {
			*errs = append(*errs, fmt.Errorf("inspect NodeWall chain %s/%s: %w", table, chain, err))
		}
		return
	}
	// Remove references by exact target, including stale bridge/interface jumps,
	// while leaving all other chains and their rule order untouched.
	m.removeAllChainReferences(table, chain, errs)
	if output, err := m.runner.Run("-t", table, "-F", chain); err != nil && !isMissingIPTablesObject(output, err) {
		*errs = append(*errs, fmt.Errorf("flush NodeWall chain %s/%s: %w", table, chain, err))
		return
	}
	if output, err := m.runner.Run("-t", table, "-X", chain); err != nil && !isMissingIPTablesObject(output, err) {
		*errs = append(*errs, fmt.Errorf("remove NodeWall chain %s/%s: %w", table, chain, err))
	}
}

func (m *IPTablesManager) chainAbsentFromTable(table, chain string) bool {
	output, err := m.runner.Run("-t", table, "-S")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		fields, err := splitIPTablesArgs(line)
		if err != nil {
			return false
		}
		if len(fields) >= 2 && (fields[0] == "-N" || fields[0] == "-P") && fields[1] == chain {
			return false
		}
		if ruleTargetsChain(fields, chain) {
			return false
		}
	}
	return true
}

func (m *IPTablesManager) removeLegacyChains(ifaceName string) error {
	var errs []error
	m.removeOwnedChain(iptablesLegacyTable, iptablesChainName(ifaceName), &errs)
	m.removeOwnedChain(iptablesLegacyTable, iptablesEgressChainName(ifaceName), &errs)
	m.removeOwnedChain(iptablesForwardTable, iptablesForwardEgressChainName(ifaceName), &errs)
	return errors.Join(errs...)
}

func (m *IPTablesManager) removeAllChainReferences(table, target string, errs *[]error) {
	output, err := m.runner.Run("-t", table, "-S")
	if err != nil {
		if !isMissingIPTablesObject(output, err) {
			*errs = append(*errs, fmt.Errorf("inspect %s references to %s: %w", table, target, err))
		}
		return
	}
	for _, line := range ruleLines(output) {
		fields, err := splitIPTablesArgs(line)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("parse %s rule while removing %s: %w", table, target, err))
			continue
		}
		if len(fields) < 4 || fields[0] != "-A" || !ruleTargetsChain(fields, target) {
			continue
		}
		// `iptables -S` emits a rule beginning with `-A`; replacing that
		// operation with `-D` gives an exact deletion even when the jump was
		// inserted by an older NodeWall process in another parent chain.
		fields[0] = "-D"
		args := append([]string{"-t", table}, fields...)
		if output, deleteErr := m.runner.Run(args...); deleteErr != nil && !isMissingIPTablesObject(output, deleteErr) {
			*errs = append(*errs, fmt.Errorf("remove NodeWall reference %s/%s: %w", table, target, deleteErr))
		}
	}
}

func ruleTargetsChain(fields []string, target string) bool {
	for index := 0; index+1 < len(fields); index++ {
		if (fields[index] == "-j" || fields[index] == "-g") && fields[index+1] == target {
			return true
		}
	}
	return false
}

// iptables -S quotes comments and escapes quotes/backslashes. Parse arguments
// without a shell so migration can remove an exact jump while preserving a
// foreign rule whose comment merely mentions a NodeWall chain.
func splitIPTablesArgs(line string) ([]string, error) {
	var result []string
	var word strings.Builder
	var quote rune
	escaped, started := false, false
	for _, character := range line {
		if escaped {
			word.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped, started = true, true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				word.WriteRune(character)
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote, started = character, true
		case ' ', '\t':
			if started {
				result = append(result, word.String())
				word.Reset()
				started = false
			}
		default:
			word.WriteRune(character)
			started = true
		}
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("unterminated quote or escape in iptables rule")
	}
	if started {
		result = append(result, word.String())
	}
	return result, nil
}

func isMissingIPTablesObject(output string, err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(output + " " + err.Error())
	return strings.Contains(message, "no chain/target/match") || strings.Contains(message, "no such chain") || strings.Contains(message, "does a chain")
}

func (m *IPTablesManager) WriteConfig(ifaceName string, cfg Config) error {
	if err := m.MockManager.WriteConfig(ifaceName, cfg); err != nil {
		return err
	}
	return m.sync(ifaceName)
}

// ApplyDirectionPolicy compiles host egress policy into a private filter/OUTPUT
// chain. Keeping it separate from ingress avoids replacing rules for the other
// direction during an update; guest forwarding stays outside the host policy.
func (m *IPTablesManager) ApplyDirectionPolicy(ifaceName string, direction models.PolicyDirection, policy DirectionPolicy) error {
	if direction != models.DirectionEgress {
		return nil
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	previous, existed := m.egressPolicies[ifaceName]
	m.egressPolicies[ifaceName] = copyDirectionPolicy(policy)
	if err := m.syncLocked(ifaceName); err != nil {
		if existed {
			m.egressPolicies[ifaceName] = previous
		} else {
			delete(m.egressPolicies, ifaceName)
		}
		_ = m.syncLocked(ifaceName)
		return err
	}
	return nil
}

// Reconcile restores NodeWall host hooks after another agent rebuilds filter
// rules. It is safe to call repeatedly; unchanged rules cause no mutation.
func (m *IPTablesManager) Reconcile() error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	for _, iface := range m.Interfaces() {
		runtime, err := m.MockManager.Runtime(iface)
		if err != nil || !runtime.Attached {
			continue
		}
		chain := iptablesChainName(iface)
		if !m.chainMatches(chain) {
			if err := m.syncLocked(iface); err != nil {
				return err
			}
			log.Printf("nodewall: restored externally changed iptables host rules on %s", iface)
			continue
		}
		if err := m.ensureFirstJump(m.inputResolver(iface), chain); err != nil {
			return err
		}
		if _, ok := m.egressPolicies[iface]; ok {
			egressChain := iptablesEgressChainName(iface)
			if !m.chainMatches(egressChain) {
				if err := m.syncLocked(iface); err != nil {
					return err
				}
				log.Printf("nodewall: restored externally changed iptables egress rules on %s", iface)
				continue
			}
			if err := m.ensureEgressJumps(iface, egressChain); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *IPTablesManager) chainMatches(chain string) bool {
	expected, ok := m.chainDigests[chain]
	if !ok {
		return false
	}
	output, err := m.runner.Run("-t", iptablesTable, "-S", chain)
	if err != nil {
		return false
	}
	digest, _, err := iptablesRulesDigest(output)
	return err == nil && digest == expected
}

func iptablesRulesDigest(output string) ([32]byte, int, error) {
	var rules [][]string
	for _, line := range ruleLines(output) {
		fields, err := splitIPTablesArgs(line)
		if err != nil {
			return [32]byte{}, 0, err
		}
		rules = append(rules, fields)
	}
	encoded, err := json.Marshal(rules)
	return sha256.Sum256(encoded), len(rules), err
}

func (m *IPTablesManager) Runtime(ifaceName string) (Runtime, error) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	runtime, err := m.MockManager.Runtime(ifaceName)
	if err != nil {
		return runtime, err
	}
	runtime.Mode = AttachModeIPTables
	runtime.ObjectPath = "iptables://filter/" + iptablesChainName(ifaceName)
	runtime.ProgramLoaded = runtime.Attached
	if runtime.Attached {
		if !m.chainMatches(iptablesChainName(ifaceName)) || !m.jumpMatches(iptablesParent, "-i", m.inputResolver(ifaceName), iptablesChainName(ifaceName)) {
			runtime.ProgramLoaded = false
			return runtime, fmt.Errorf("NodeWall ingress rules or INPUT hook changed externally; waiting for reconciliation")
		}
		if _, ok := m.egressPolicies[ifaceName]; ok {
			if !m.chainMatches(iptablesEgressChainName(ifaceName)) {
				runtime.ProgramLoaded = false
				return runtime, fmt.Errorf("NodeWall egress rules changed externally; waiting for reconciliation")
			}
			for _, device := range m.egressInterfaces(ifaceName) {
				if !m.jumpMatches(iptablesEgressParent, "-o", device, iptablesEgressChainName(ifaceName)) {
					runtime.ProgramLoaded = false
					return runtime, fmt.Errorf("NodeWall OUTPUT hook changed externally; waiting for reconciliation")
				}
			}
		}
	}
	return runtime, nil
}

func (m *IPTablesManager) ReadStats(ifaceName string) (models.InterfaceStats, error) {
	counters, err := m.readCounters(ifaceName)
	if err != nil {
		return models.InterfaceStats{}, err
	}
	stats := statsFromCounters(counters, models.DirectionIngress)
	return stats, nil
}

func (m *IPTablesManager) ReadDropLogs(ifaceName string, limit int) ([]models.InterceptLogEntry, error) {
	counters, err := m.readCounters(ifaceName)
	if err != nil {
		return nil, err
	}
	return dropLogsFromCounters(counters, models.DirectionIngress, limit), nil
}

func (m *IPTablesManager) ReadDirectionStats(ifaceName string, direction models.PolicyDirection) (models.InterfaceStats, error) {
	counters, err := m.readDirectionCounters(ifaceName, direction)
	if err != nil {
		return models.InterfaceStats{}, err
	}
	return statsFromCounters(counters, direction), nil
}

func (m *IPTablesManager) ReadDirectionDropLogs(ifaceName string, direction models.PolicyDirection, limit int) ([]models.InterceptLogEntry, error) {
	counters, err := m.readDirectionCounters(ifaceName, direction)
	if err != nil {
		return nil, err
	}
	return dropLogsFromCounters(counters, direction, limit), nil
}

func (m *IPTablesManager) ReadDirectionSourceStats(ifaceName string, direction models.PolicyDirection, limit int) ([]models.SourceStat, error) {
	counters, err := m.readDirectionCounters(ifaceName, direction)
	if err != nil {
		return nil, err
	}
	return sourceStatsFromCounters(counters, direction, limit), nil
}

func (m *IPTablesManager) ReadDirectionPortStats(ifaceName string, direction models.PolicyDirection, limit int) ([]models.PortStat, error) {
	counters, err := m.readDirectionCounters(ifaceName, direction)
	if err != nil {
		return nil, err
	}
	return portStatsFromCounters(counters, limit), nil
}

func statsFromCounters(counters []iptablesCounter, direction models.PolicyDirection) models.InterfaceStats {
	stats := models.InterfaceStats{Direction: direction}
	for _, counter := range counters {
		if counter.target == "DROP" {
			stats.Dropped += counter.packets
		} else if counter.target == "RETURN" {
			stats.Passed += counter.packets
		}
	}
	return stats
}

func dropLogsFromCounters(counters []iptablesCounter, direction models.PolicyDirection, limit int) []models.InterceptLogEntry {
	aggregated := make(map[string]models.InterceptLogEntry)
	traffic := &models.FirewallTraffic{Evidence: models.FirewallRuleCounter, Hook: "input"}
	if direction == models.DirectionEgress {
		traffic.Hook, traffic.Origin = "output", "host"
	}
	for _, counter := range counters {
		if !counter.wouldDrop || counter.packets == 0 {
			continue
		}
		// More than one private rule may account for the same disposition.
		remote := strings.TrimSpace(counter.remoteAddress(direction))
		key := fmt.Sprintf("%s|%s|%d|%s|%t", direction, remote, counter.port, counter.reason, counter.target == "DROP")
		item := aggregated[key]
		item.Direction = direction
		item.Traffic = traffic
		item.CounterEpoch = counter.epoch
		item.SourceIP = sourceForLog(remote)
		if item.SourceIP == "" {
			item.SourceCIDR = remote
		}
		item.Port = counter.port
		item.Reason = counter.reason
		item.Count += counter.packets
		// RETURN accounts for an observe-only match, not an actual rejection.
		if counter.target == "DROP" {
			item.Drops += counter.packets
		}
		aggregated[key] = item
	}
	items := make([]models.InterceptLogEntry, 0, len(aggregated))
	for _, item := range aggregated {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Drops == items[j].Drops {
			if items[i].SourceIP == items[j].SourceIP {
				return items[i].Port < items[j].Port
			}
			return items[i].SourceIP < items[j].SourceIP
		}
		return items[i].Drops > items[j].Drops
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func (m *IPTablesManager) ReadSourceStats(ifaceName string, limit int) ([]models.SourceStat, error) {
	counters, err := m.readCounters(ifaceName)
	if err != nil {
		return nil, err
	}
	return sourceStatsFromCounters(counters, models.DirectionIngress, limit), nil
}

func sourceStatsFromCounters(counters []iptablesCounter, direction models.PolicyDirection, limit int) []models.SourceStat {
	aggregated := make(map[string]models.SourceStat)
	for _, counter := range counters {
		remote := sourceForLog(counter.remoteAddress(direction))
		if remote == "" || remote == "0.0.0.0" || !counter.terminal() {
			continue
		}
		current := aggregated[remote]
		current.SourceIP = remote
		if counter.target == "DROP" {
			current.Dropped += counter.packets
		} else if counter.target == "RETURN" {
			current.Passed += counter.packets
		}
		current.Total = current.Passed + current.Dropped
		if current.Total > 0 {
			current.DropRatio = float64(current.Dropped) / float64(current.Total)
		}
		current.Risk = classifyRisk(current.Passed, current.Dropped)
		aggregated[remote] = current
	}
	items := make([]models.SourceStat, 0, len(aggregated))
	for _, item := range aggregated {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Dropped != items[j].Dropped {
			return items[i].Dropped > items[j].Dropped
		}
		if items[i].Passed != items[j].Passed {
			return items[i].Passed > items[j].Passed
		}
		return items[i].SourceIP < items[j].SourceIP
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func (m *IPTablesManager) ReadPortStats(ifaceName string, limit int) ([]models.PortStat, error) {
	counters, err := m.readCounters(ifaceName)
	if err != nil {
		return nil, err
	}
	return portStatsFromCounters(counters, limit), nil
}

func portStatsFromCounters(counters []iptablesCounter, limit int) []models.PortStat {
	aggregated := make(map[uint16]models.PortStat)
	for _, counter := range counters {
		if counter.port == 0 || !counter.terminal() {
			continue
		}
		item := aggregated[counter.port]
		item.Port = counter.port
		if counter.target == "DROP" {
			item.Dropped += counter.packets
		} else if counter.target == "RETURN" {
			item.Passed += counter.packets
		}
		item.Total = item.Passed + item.Dropped
		item.Risk = classifyRisk(item.Passed, item.Dropped)
		aggregated[counter.port] = item
	}
	items := make([]models.PortStat, 0, len(aggregated))
	for _, item := range aggregated {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Total > items[j].Total })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func (m *IPTablesManager) ReadReplyAllowLogs(string, int) ([]models.InterceptLogEntry, error) {
	return []models.InterceptLogEntry{}, nil
}

func (m *IPTablesManager) sync(ifaceName string) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	return m.syncLocked(ifaceName)
}

func (m *IPTablesManager) syncLocked(ifaceName string) error {

	runtime, err := m.MockManager.Runtime(ifaceName)
	if err != nil {
		return err
	}
	if !runtime.Attached {
		return nil
	}
	chain := iptablesChainName(ifaceName)
	input := m.inputResolver(ifaceName)
	if err := m.ensureChain(iptablesTable, chain); err != nil {
		return err
	}
	if err := m.replaceChainRules(ifaceName, chain, runtime); err != nil {
		return err
	}
	if err := m.ensureFirstJump(input, chain); err != nil {
		return err
	}
	if policy, ok := m.egressPolicies[ifaceName]; ok {
		egressChain := iptablesEgressChainName(ifaceName)
		if err := m.ensureChain(iptablesTable, egressChain); err != nil {
			return err
		}
		if err := m.replaceDirectionChain(iptablesTable, egressChain, ifaceName, policy, "-d"); err != nil {
			return err
		}
		if err := m.ensureEgressJumps(ifaceName, egressChain); err != nil {
			return err
		}
	}
	if !m.legacyCleaned[ifaceName] {
		// Retire only our old raw/mangle hooks after the new host hooks exist.
		// Leaving a legacy DROP hook in place would still reject reply packets
		// before the stateful INPUT/OUTPUT chains could see them.
		if err := m.removeLegacyChains(ifaceName); err != nil {
			return fmt.Errorf("migrate legacy NodeWall hooks: %w", err)
		}
		m.legacyCleaned[ifaceName] = true
	}
	return nil
}

func (m *IPTablesManager) ensureChain(table, chain string) error {
	output, err := m.runner.Run("-t", table, "-N", chain)
	if err == nil || strings.Contains(output, "Chain already exists") {
		return nil
	}
	return err
}

func (m *IPTablesManager) replaceChainRules(iface, chain string, runtime Runtime) error {
	policy := DirectionPolicy{
		BypassCIDRs:      runtime.BypassCIDRs,
		BlockedCIDRs:     runtime.BlockedCIDRs,
		ICMPAllowCIDRs:   runtime.ICMPAllowCIDRs,
		ICMPBlockedCIDRs: runtime.ICMPBlockedCIDRs,
		Allowlist:        runtime.Allowlist,
		PublicPortRules:  runtime.PublicPortRules,
		DeniedPortRules:  runtime.DeniedPortRules,
		AllowedPortRules: runtime.AllowedPortRules,
		RateLimitRules:   runtime.RateLimitRules,
		NonIPv4Action:    runtime.Config.NonIPv4Action,
		PolicyEnforced:   runtime.Config.PolicyEnforced,
		ObserveOnly:      runtime.Config.ObserveOnly,
	}
	return m.replaceDirectionChain(iptablesTable, chain, iface, policy, "-s")
}

func (m *IPTablesManager) replaceDirectionChain(table, chain, iface string, policy DirectionPolicy, addressFlag string) error {
	if _, err := m.runner.Run("-t", table, "-F", chain); err != nil {
		return err
	}
	m.chainEpochs[chain] = rand.Text()
	failOpen := func(err error) error {
		delete(m.chainDigests, chain)
		// A failed policy compile must not leave a half-written DROP chain.
		// Clear the partial rules and leave a terminal RETURN so traffic keeps
		// following the host's existing firewall while the error is reported.
		_, _ = m.runner.Run("-t", table, "-F", chain)
		if _, fallbackErr := m.runner.Run("-t", table, "-A", chain, "-j", "RETURN"); fallbackErr != nil {
			return fmt.Errorf("%w; fail-open rule also failed: %v", err, fallbackErr)
		}
		return err
	}
	compiledRules := 0
	appendRule := func(args ...string) error {
		_, err := m.runner.Run(append([]string{"-t", table, "-A", chain}, args...)...)
		if err == nil {
			compiledRules++
		}
		return err
	}
	// ZStack control traffic keeps following the host's existing firewall.
	if err := appendRule("-p", zstackProtocol, "-j", "RETURN"); err != nil {
		return failOpen(err)
	}
	dropTarget := "DROP"
	if policy.ObserveOnly {
		// Keep matching the policy in observe mode so rule counters expose
		// would-be interceptions, but use RETURN for every disposition.
		dropTarget = "RETURN"
	}
	for _, cidr := range policy.BypassCIDRs {
		if err := appendRule(addressFlag, cidr, "-m", "comment", "--comment", "nodewall:bypass", "-j", "RETURN"); err != nil {
			return failOpen(err)
		}
	}
	for _, cidr := range policy.BlockedCIDRs {
		if err := appendRule(addressFlag, cidr, "-m", "comment", "--comment", "nodewall:blocked_source", "-j", dropTarget); err != nil {
			return failOpen(err)
		}
	}
	for _, cidr := range policy.ICMPBlockedCIDRs {
		if err := appendRule("-p", "icmp", addressFlag, cidr, "-m", "comment", "--comment", "nodewall:blocked_icmp", "-j", dropTarget); err != nil {
			return failOpen(err)
		}
	}
	for index, rule := range policy.RateLimitRules {
		if err := appendRateLimitRule(appendRule, rule, index, addressFlag, dropTarget); err != nil {
			return failOpen(err)
		}
	}
	for _, block := range policy.TemporaryBlocks {
		if strings.TrimSpace(block.SourceIP) == "" {
			continue
		}
		if err := appendRule(addressFlag, block.SourceIP+"/32", "-m", "comment", "--comment", "nodewall:temporary_block", "-j", dropTarget); err != nil {
			return failOpen(err)
		}
	}
	for _, rule := range policy.DeniedPortRules {
		if err := appendPortRule(appendRule, rule, "nodewall:denied_port", dropTarget); err != nil {
			return failOpen(err)
		}
	}
	// Filter hooks run after conntrack. Explicit revocations stay above this
	// rule, while DNS/HTTPS replies and SSH server responses keep their original
	// ephemeral ports without requiring broad high-port or CDN-IP allowlists.
	if err := appendRule("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "nodewall:reply_flow", "-j", "RETURN"); err != nil {
		return failOpen(err)
	}

	enforced := policy.PolicyEnforced || len(policy.BypassCIDRs) > 0 || len(policy.BlockedCIDRs) > 0 ||
		len(policy.ICMPAllowCIDRs) > 0 || len(policy.ICMPBlockedCIDRs) > 0 || len(policy.Allowlist) > 0 ||
		len(policy.PublicPortRules) > 0 || len(policy.DeniedPortRules) > 0 || len(policy.AllowedPortRules) > 0 ||
		len(policy.RateLimitRules) > 0 || len(policy.TemporaryBlocks) > 0
	if enforced {
		for _, rule := range policy.PublicPortRules {
			if err := appendPortRule(appendRule, rule, "nodewall:public_port", "RETURN"); err != nil {
				return failOpen(err)
			}
		}
		for _, rule := range policy.AllowedPortRules {
			if err := appendPortRule(appendRule, rule, "nodewall:allowed_port", "RETURN"); err != nil {
				return failOpen(err)
			}
		}
		for _, cidr := range policy.ICMPAllowCIDRs {
			if err := appendRule("-p", "icmp", addressFlag, cidr, "-m", "comment", "--comment", "nodewall:allowed_icmp", "-j", "RETURN"); err != nil {
				return failOpen(err)
			}
		}
		for _, cidr := range policy.Allowlist {
			if err := appendRule(addressFlag, cidr, "-m", "comment", "--comment", "nodewall:allowlist", "-j", "RETURN"); err != nil {
				return failOpen(err)
			}
		}
		// A blocklist alone is an explicit-deny policy. It must not silently
		// become a global default deny, which would cut management access.
		if len(policy.Allowlist) > 0 || len(policy.AllowedPortRules) > 0 {
			if err := appendRule("-m", "comment", "--comment", "nodewall:default_deny", "-j", dropTarget); err != nil {
				return failOpen(err)
			}
			if m.packetAudit {
				direction := models.DirectionIngress
				if addressFlag == "-d" {
					direction = models.DirectionEgress
				}
				// Insert before the existing verdict. During a live rebuild
				// a sample can only be emitted once its verdict is installed.
				location := []string{"-t", table, "-I", chain, strconv.Itoa(compiledRules)}
				if _, err := m.runner.Run(append(location, defaultDenyAuditRule(iface, direction, policy.ObserveOnly)...)...); err != nil {
					// Audit support is optional on old kernels and iptables builds.
					// The verdict and its full rule counter still apply.
					log.Printf("warning: default-deny packet audit unavailable on %s: %v", iface, err)
					m.packetAudit = false
				} else {
					compiledRules++
				}
			}
		}
	}
	if err := appendRule("-j", "RETURN"); err != nil {
		return failOpen(err)
	}
	// Snapshot the kernel's canonical rendering (implicit protocol matches,
	// conntrack state order and hashlimit units can differ from our arguments).
	// Later checks ignore packet counters but compare every rule and its order.
	// Refuse to learn a chain that was concurrently emptied during this apply.
	output, err := m.runner.Run("-t", table, "-S", chain)
	if err != nil {
		return failOpen(fmt.Errorf("verify private chain %s: %w", chain, err))
	}
	digest, count, err := iptablesRulesDigest(output)
	if err != nil || count != compiledRules {
		return failOpen(fmt.Errorf("private chain %s changed during apply: got %d rules, expected %d (parse error: %v)", chain, count, compiledRules, err))
	}
	m.chainDigests[chain] = digest
	return nil
}

func appendPortRule(appendRule func(...string) error, rule models.PortRule, comment, target string) error {
	protocol := strings.ToLower(strings.TrimSpace(string(rule.Protocol)))
	switch protocol {
	case string(models.PortProtocolTCP), string(models.PortProtocolUDP):
		return appendRule("-p", protocol, "--dport", strconv.Itoa(int(rule.Port)), "-m", "comment", "--comment", comment, "-j", target)
	case string(models.PortProtocolICMP):
		return appendRule("-p", "icmp", "-m", "comment", "--comment", comment, "-j", target)
	default:
		return fmt.Errorf("unsupported iptables protocol %q", rule.Protocol)
	}
}

func appendRateLimitRule(appendRule func(...string) error, rule models.RateLimitRule, index int, addressFlag, target string) error {
	if rule.RequestsPerMinute == 0 || rule.Burst == 0 {
		return nil
	}
	args := make([]string, 0, 20)
	if source := strings.TrimSpace(rule.SourceIP); source != "" {
		args = append(args, addressFlag, source)
	}
	protocol := strings.ToLower(strings.TrimSpace(string(rule.Protocol)))
	if protocol == "" {
		protocol = string(models.PortProtocolTCP)
	}
	if protocol != string(models.PortProtocolTCP) && protocol != string(models.PortProtocolUDP) && protocol != string(models.PortProtocolICMP) {
		return fmt.Errorf("unsupported rate-limit protocol %q", rule.Protocol)
	}
	args = append(args, "-p", protocol)
	if rule.Port > 0 && protocol != string(models.PortProtocolICMP) {
		args = append(args, "--dport", strconv.Itoa(int(rule.Port)))
	}
	name := rateLimitName(rule, index)
	args = append(args,
		"-m", "hashlimit",
		"--hashlimit-above", strconv.FormatUint(rule.RequestsPerMinute, 10)+"/minute",
		"--hashlimit-burst", strconv.FormatUint(rule.Burst, 10),
		"--hashlimit-mode", hashlimitAddressMode(addressFlag),
		"--hashlimit-name", name,
		"-m", "comment", "--comment", "nodewall:rate_limited",
		"-j", target,
	)
	return appendRule(args...)
}

func hashlimitAddressMode(addressFlag string) string {
	if addressFlag == "-d" {
		return "dstip"
	}
	return "srcip"
}

func rateLimitName(rule models.RateLimitRule, index int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d|%d", rule.ID, rule.SourceIP, rule.Protocol, rule.Port, index)
	sum := sha256.Sum256([]byte(seed))
	return "nw" + fmt.Sprintf("%x", sum[:4])
}

func (m *IPTablesManager) ensureFirstJump(input, chain string) error {
	return m.ensureJumpFirst(iptablesTable, iptablesParent, "-i", input, chain)
}

func (m *IPTablesManager) ensureEgressJumps(ifaceName, outputChain string) error {
	for _, device := range m.egressInterfaces(ifaceName) {
		if err := m.ensureJumpFirst(iptablesTable, iptablesEgressParent, "-o", device, outputChain); err != nil {
			return err
		}
	}
	return nil
}

func (m *IPTablesManager) egressInterfaces(ifaceName string) []string {
	devices := []string{m.outputResolver(ifaceName), m.inputResolver(ifaceName), ifaceName}
	seen := make(map[string]struct{}, len(devices))
	result := make([]string, 0, len(devices))
	for _, device := range devices {
		device = strings.TrimSpace(device)
		if device == "" {
			continue
		}
		if _, ok := seen[device]; ok {
			continue
		}
		seen[device] = struct{}{}
		result = append(result, device)
	}
	return result
}

func (m *IPTablesManager) ensureJumpFirst(table, parent, flag, device, chain string) error {
	output, err := m.runner.Run("-t", table, "-S", parent)
	if err != nil {
		return err
	}
	desired := jumpRule(parent, flag, device, chain)
	lines := ruleLines(output)
	if jumpIsFirst(lines, desired) {
		return nil
	}
	duplicates := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == desired {
			duplicates++
		}
	}
	for range duplicates {
		if _, err := m.runner.Run("-t", table, "-D", parent, flag, device, "-j", chain); err != nil {
			return err
		}
	}
	_, err = m.runner.Run("-t", table, "-I", parent, "1", flag, device, "-j", chain)
	return err
}

func (m *IPTablesManager) jumpMatches(parent, flag, device, chain string) bool {
	output, err := m.runner.Run("-t", iptablesTable, "-S", parent)
	return err == nil && jumpIsFirst(ruleLines(output), jumpRule(parent, flag, device, chain))
}

func jumpIsFirst(lines []string, desired string) bool {
	position := -1
	for index, line := range lines {
		if strings.TrimSpace(line) == desired {
			position = index
			break
		}
	}
	if position >= 0 {
		for _, line := range lines[:position] {
			if !isNodeWallJump(line) {
				return false
			}
		}
		return true
	}
	return false
}

func jumpRule(parent, flag, device, chain string) string {
	return "-A " + parent + " " + flag + " " + device + " -j " + chain
}

func ruleLines(output string) []string {
	lines := strings.FieldsFunc(output, func(r rune) bool { return r == '\n' || r == '\r' })
	rules := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// `iptables -S` emits the chain policy as `-P`; it is not a rule and
		// must never cause the NodeWall jump to be rebuilt.
		if strings.HasPrefix(line, "-A ") {
			rules = append(rules, line)
		}
	}
	return rules
}

func countRuleLines(output, desired string) int {
	count := 0
	for _, line := range ruleLines(output) {
		if strings.TrimSpace(line) == desired {
			count++
		}
	}
	return count
}

func isNodeWallJump(line string) bool {
	fields, err := splitIPTablesArgs(line)
	if err != nil {
		return false
	}
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "-j" && (strings.HasPrefix(fields[index+1], iptablesChainStart) || strings.HasPrefix(fields[index+1], iptablesForwardChainStart)) {
			return true
		}
	}
	return false
}

func (m *IPTablesManager) readCounters(ifaceName string) ([]iptablesCounter, error) {
	return m.readChainCounters(iptablesChainName(ifaceName))
}

func (m *IPTablesManager) readDirectionCounters(ifaceName string, direction models.PolicyDirection) ([]iptablesCounter, error) {
	if direction == models.DirectionIngress {
		return m.readCounters(ifaceName)
	}
	if direction != models.DirectionEgress {
		return nil, fmt.Errorf("unsupported policy direction %q", direction)
	}
	return m.readChainCounters(iptablesEgressChainName(ifaceName))
}

func (m *IPTablesManager) readChainCounters(chain string) ([]iptablesCounter, error) {
	// Take the counters and their generation together, outside a rule rebuild.
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	output, err := m.runner.Run("-t", iptablesTable, "-L", chain, "-v", "-x", "-n")
	if err != nil {
		if isMissingIPTablesObject(output, err) || (strings.Contains(strings.ToLower(output), "is incompatible") && m.chainAbsentFromTable(iptablesTable, chain)) {
			return nil, errNotAttached
		}
		return nil, err
	}
	counters := parseIPTablesListCounters(output)
	for i := range counters {
		counters[i].epoch = m.chainEpochs[chain]
	}
	return counters, nil
}

type iptablesCounter struct {
	packets     uint64
	target      string
	source      string
	destination string
	port        uint16
	reason      string
	wouldDrop   bool
	epoch       string
}

func (counter iptablesCounter) terminal() bool {
	return counter.target == "DROP" || counter.target == "RETURN"
}

func parseIPTablesListCounters(output string) []iptablesCounter {
	items := make([]iptablesCounter, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		packets, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		item := iptablesCounter{packets: packets, target: fields[2], source: "0.0.0.0/0", destination: "0.0.0.0/0", reason: "iptables_drop"}
		if len(fields) >= 9 {
			item.source = fields[7]
			item.destination = fields[8]
		}
		for _, field := range fields {
			if strings.HasPrefix(field, "dpt:") {
				if port, err := strconv.ParseUint(strings.TrimPrefix(field, "dpt:"), 10, 16); err == nil {
					item.port = uint16(port)
				}
			}
			if strings.HasPrefix(field, "nodewall:") {
				item.reason = field
			}
		}
		item.wouldDrop = item.target == "DROP" || (item.target == "RETURN" && isObservedDropReason(item.reason))
		items = append(items, item)
	}
	return items
}

func (counter iptablesCounter) remoteAddress(direction models.PolicyDirection) string {
	if direction == models.DirectionEgress {
		return counter.destination
	}
	return counter.source
}

func isObservedDropReason(reason string) bool {
	switch reason {
	case "nodewall:blocked_source", "nodewall:blocked_icmp", "nodewall:denied_port",
		"nodewall:rate_limited", "nodewall:temporary_block", "nodewall:default_deny",
		"nodewall:restricted_policy":
		return true
	default:
		return false
	}
}

func sourceForLog(source string) string {
	source = strings.TrimSpace(source)
	if strings.HasSuffix(source, "/32") {
		return strings.TrimSuffix(source, "/32")
	}
	if strings.Contains(source, "/") {
		return ""
	}
	return source
}

func iptablesChainName(iface string) string {
	var builder strings.Builder
	for _, char := range strings.ToUpper(iface) {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	name := iptablesChainStart + builder.String()
	if len(name) <= 28 {
		return name
	}
	sum := sha256.Sum256([]byte(iface))
	return iptablesChainStart + fmt.Sprintf("%x", sum[:8])
}

func iptablesEgressChainName(iface string) string {
	var builder strings.Builder
	for _, char := range strings.ToUpper(iface) {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	name := iptablesChainStart + "OUT_" + builder.String()
	if len(name) <= 28 {
		return name
	}
	sum := sha256.Sum256([]byte("egress:" + iface))
	return iptablesChainStart + "O" + fmt.Sprintf("%x", sum[:8])
}

func iptablesForwardEgressChainName(iface string) string {
	var builder strings.Builder
	for _, char := range strings.ToUpper(iface) {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	name := iptablesForwardChainStart + "OUT_" + builder.String()
	if len(name) <= 28 {
		return name
	}
	sum := sha256.Sum256([]byte("forward-egress:" + iface))
	return iptablesForwardChainStart + "O" + fmt.Sprintf("%x", sum[:8])
}

func copyDirectionPolicy(policy DirectionPolicy) DirectionPolicy {
	policy.BypassCIDRs = append([]string(nil), policy.BypassCIDRs...)
	policy.BlockedCIDRs = append([]string(nil), policy.BlockedCIDRs...)
	policy.ICMPAllowCIDRs = append([]string(nil), policy.ICMPAllowCIDRs...)
	policy.ICMPBlockedCIDRs = append([]string(nil), policy.ICMPBlockedCIDRs...)
	policy.Allowlist = append([]string(nil), policy.Allowlist...)
	policy.PublicPortRules = append([]models.PortRule(nil), policy.PublicPortRules...)
	policy.DeniedPortRules = append([]models.PortRule(nil), policy.DeniedPortRules...)
	policy.AllowedPortRules = append([]models.PortRule(nil), policy.AllowedPortRules...)
	policy.RateLimitRules = append([]models.RateLimitRule(nil), policy.RateLimitRules...)
	policy.TemporaryBlocks = append([]models.TemporaryBlock(nil), policy.TemporaryBlocks...)
	return policy
}

func bridgeInputInterface(iface string) string {
	target, err := os.Readlink(filepath.Join("/sys/class/net", iface, "master"))
	if err != nil {
		return iface
	}
	name := filepath.Base(target)
	if name == "." || name == "/" || name == "" {
		return iface
	}
	return name
}

var _ Dataplane = (*IPTablesManager)(nil)
