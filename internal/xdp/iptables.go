package xdp

import (
	"context"
	"crypto/sha256"
	"fmt"
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
	iptablesTable             = "raw"
	iptablesParent            = "PREROUTING"
	iptablesChainStart        = "NWRAW_"
	iptablesEgressParent      = "OUTPUT"
	iptablesForwardTable      = "mangle"
	iptablesForwardParent     = "FORWARD"
	iptablesForwardChainStart = "NWFW_"
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
	output, err := exec.CommandContext(ctx, r.path, args...).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

// IPTablesManager is an opt-in compatibility dataplane for old, non-Kubernetes
// Linux hosts. It never edits a foreign chain: each protected interface owns a
// dedicated NWRAW_* chain and a first-position jump in raw/PREROUTING.
//
// ZStack reserves IP protocol 253 for its network agent. Every managed chain
// returns that protocol before evaluating NodeWall rules, preserving the
// existing zstack-network NFLOG behaviour below the NodeWall jump.
type IPTablesManager struct {
	*MockManager

	runner         iptablesRunner
	inputResolver  func(string) string
	outputResolver func(string) string
	egressPolicies map[string]DirectionPolicy
	applyMu        sync.Mutex
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

	removeJump := func(table, parent, flag, device, target string) {
		output, err := m.runner.Run("-t", table, "-S", parent)
		if err != nil {
			return
		}
		desired := jumpRule(parent, flag, device, target)
		for range countRuleLines(output, desired) {
			_, _ = m.runner.Run("-t", table, "-D", parent, flag, device, "-j", target)
		}
	}
	removeChain := func(table, parent, flag, device, chain string) {
		removeJump(table, parent, flag, device, chain)
		_, _ = m.runner.Run("-t", table, "-F", chain)
		_, _ = m.runner.Run("-t", table, "-X", chain)
	}
	removeChain(iptablesTable, iptablesParent, "-i", m.inputResolver(ifaceName), iptablesChainName(ifaceName))
	for _, device := range m.egressInterfaces(ifaceName) {
		removeChain(iptablesTable, iptablesEgressParent, "-o", device, iptablesEgressChainName(ifaceName))
		removeChain(iptablesForwardTable, iptablesForwardParent, "-o", device, iptablesForwardEgressChainName(ifaceName))
	}
	delete(m.egressPolicies, ifaceName)
	return m.MockManager.Detach(ifaceName)
}

func (m *IPTablesManager) WriteConfig(ifaceName string, cfg Config) error {
	if err := m.MockManager.WriteConfig(ifaceName, cfg); err != nil {
		return err
	}
	return m.sync(ifaceName)
}

// ApplyDirectionPolicy compiles egress policy into private chains for both
// host-originated traffic (raw/OUTPUT) and bridge-forwarded traffic
// (mangle/FORWARD). Keeping these separate from ingress avoids replacing
// rules for the other direction during an update.
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

// Reconcile restores a NodeWall jump that a network agent has moved below its
// own raw-table catch-all rule. It is safe to call repeatedly; unchanged rules
// cause no iptables mutation.
func (m *IPTablesManager) Reconcile() error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	for _, iface := range m.Interfaces() {
		runtime, err := m.MockManager.Runtime(iface)
		if err != nil || !runtime.Attached {
			continue
		}
		chain := iptablesChainName(iface)
		if _, err := m.runner.Run("-t", iptablesTable, "-S", chain); err != nil {
			if err := m.syncLocked(iface); err != nil {
				return err
			}
			continue
		}
		if err := m.ensureFirstJump(m.inputResolver(iface), chain); err != nil {
			return err
		}
		if _, ok := m.egressPolicies[iface]; ok {
			egressChain := iptablesEgressChainName(iface)
			if _, err := m.runner.Run("-t", iptablesTable, "-S", egressChain); err != nil {
				if err := m.syncLocked(iface); err != nil {
					return err
				}
				continue
			}
			forwardChain := iptablesForwardEgressChainName(iface)
			if _, err := m.runner.Run("-t", iptablesForwardTable, "-S", forwardChain); err != nil {
				if err := m.syncLocked(iface); err != nil {
					return err
				}
				continue
			}
			if err := m.ensureEgressJumps(iface, egressChain, forwardChain); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *IPTablesManager) Runtime(ifaceName string) (Runtime, error) {
	runtime, err := m.MockManager.Runtime(ifaceName)
	if err != nil {
		return runtime, err
	}
	runtime.Mode = AttachModeIPTables
	runtime.ObjectPath = "iptables://raw/" + iptablesChainName(ifaceName)
	runtime.ProgramLoaded = runtime.Attached
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
		if counter.wouldDrop {
			stats.Dropped += counter.packets
		} else if counter.target == "RETURN" {
			stats.Passed += counter.packets
		}
	}
	return stats
}

func dropLogsFromCounters(counters []iptablesCounter, direction models.PolicyDirection, limit int) []models.InterceptLogEntry {
	aggregated := make(map[string]models.InterceptLogEntry)
	for _, counter := range counters {
		if !counter.wouldDrop || counter.packets == 0 {
			continue
		}
		// A target can be reached through either raw/OUTPUT or mangle/FORWARD.
		// Combine those counters so the UI exposes one cumulative disposition.
		remote := sourceForLog(counter.remoteAddress(direction))
		if remote == "" {
			remote = "0.0.0.0"
		}
		key := fmt.Sprintf("%s|%s|%d|%s", direction, remote, counter.port, counter.reason)
		item := aggregated[key]
		item.Direction = direction
		item.SourceIP = remote
		item.Port = counter.port
		item.Reason = counter.reason
		item.Count += counter.packets
		item.Drops += counter.packets
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
		if remote == "" || remote == "0.0.0.0" {
			continue
		}
		current := aggregated[remote]
		current.SourceIP = remote
		if counter.wouldDrop {
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
	sort.Slice(items, func(i, j int) bool { return items[i].Dropped > items[j].Dropped })
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
		if counter.port == 0 {
			continue
		}
		item := aggregated[counter.port]
		item.Port = counter.port
		if counter.wouldDrop {
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
	if err := m.replaceChainRules(chain, runtime); err != nil {
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
		if err := m.replaceDirectionChain(iptablesTable, egressChain, policy, "-d"); err != nil {
			return err
		}
		forwardChain := iptablesForwardEgressChainName(ifaceName)
		if err := m.ensureChain(iptablesForwardTable, forwardChain); err != nil {
			return err
		}
		if err := m.replaceDirectionChain(iptablesForwardTable, forwardChain, policy, "-d"); err != nil {
			return err
		}
		if err := m.ensureEgressJumps(ifaceName, egressChain, forwardChain); err != nil {
			return err
		}
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

func (m *IPTablesManager) replaceChainRules(chain string, runtime Runtime) error {
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
	return m.replaceDirectionChain(iptablesTable, chain, policy, "-s")
}

func (m *IPTablesManager) replaceDirectionChain(table, chain string, policy DirectionPolicy, addressFlag string) error {
	if _, err := m.runner.Run("-t", table, "-F", chain); err != nil {
		return err
	}
	failOpen := func(err error) error {
		// A failed policy compile must not leave a half-written DROP chain.
		// Clear the partial rules and leave a terminal RETURN so traffic keeps
		// following the host's existing firewall while the error is reported.
		_, _ = m.runner.Run("-t", table, "-F", chain)
		if _, fallbackErr := m.runner.Run("-t", table, "-A", chain, "-j", "RETURN"); fallbackErr != nil {
			return fmt.Errorf("%w; fail-open rule also failed: %v", err, fallbackErr)
		}
		return err
	}
	appendRule := func(args ...string) error {
		_, err := m.runner.Run(append([]string{"-t", table, "-A", chain}, args...)...)
		return err
	}
	// ZStack uses protocol 253 in its raw table. Returning here keeps its
	// NFLOG rule reachable even when this chain is restored above ZStack.
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
		}
	}
	if err := appendRule("-j", "RETURN"); err != nil {
		return failOpen(err)
	}
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

func (m *IPTablesManager) ensureEgressJumps(ifaceName, outputChain, forwardChain string) error {
	for _, device := range m.egressInterfaces(ifaceName) {
		if err := m.ensureJumpFirst(iptablesTable, iptablesEgressParent, "-o", device, outputChain); err != nil {
			return err
		}
		if err := m.ensureJumpFirst(iptablesForwardTable, iptablesForwardParent, "-o", device, forwardChain); err != nil {
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
	position := -1
	for index, line := range lines {
		if strings.TrimSpace(line) == desired {
			position = index
			break
		}
	}
	if position >= 0 {
		atTop := true
		for _, line := range lines[:position] {
			if !isNodeWallJump(line) {
				atTop = false
				break
			}
		}
		if atTop {
			return nil
		}
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
	fields := strings.Fields(line)
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "-j" && (strings.HasPrefix(fields[index+1], iptablesChainStart) || strings.HasPrefix(fields[index+1], iptablesForwardChainStart)) {
			return true
		}
	}
	return false
}

func (m *IPTablesManager) readCounters(ifaceName string) ([]iptablesCounter, error) {
	chain := iptablesChainName(ifaceName)
	output, err := m.runner.Run("-t", iptablesTable, "-L", chain, "-v", "-x", "-n")
	if err != nil {
		return nil, err
	}
	return parseIPTablesListCounters(output), nil
}

func (m *IPTablesManager) readDirectionCounters(ifaceName string, direction models.PolicyDirection) ([]iptablesCounter, error) {
	if direction == models.DirectionIngress {
		return m.readCounters(ifaceName)
	}
	if direction != models.DirectionEgress {
		return nil, fmt.Errorf("unsupported policy direction %q", direction)
	}
	chains := []struct {
		table string
		chain string
	}{
		{table: iptablesTable, chain: iptablesEgressChainName(ifaceName)},
		{table: iptablesForwardTable, chain: iptablesForwardEgressChainName(ifaceName)},
	}
	counters := make([]iptablesCounter, 0)
	for _, item := range chains {
		output, err := m.runner.Run("-t", item.table, "-L", item.chain, "-v", "-x", "-n")
		if err != nil {
			return nil, err
		}
		counters = append(counters, parseIPTablesListCounters(output)...)
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
	if source == "0.0.0.0/0" {
		return "0.0.0.0"
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
