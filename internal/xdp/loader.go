package xdp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"nodewall/internal/models"
)

var errNotAttached = errors.New("xdp program not attached")

type interfaceState struct {
	ifaceName        string
	ifaceIndex       int
	mode             AttachMode
	bypassCIDRs      []string
	blockCIDRs       []string
	icmpAllowCIDRs   []string
	icmpBlockCIDRs   []string
	allowlist        []string
	publicPorts      []uint16
	deniedPorts      []uint16
	allowedPorts     []uint16
	publicPortRules  []models.PortRule
	deniedPortRules  []models.PortRule
	allowedPortRules []models.PortRule
	rateLimitRules   []models.RateLimitRule
	cfg              Config
	spec             *ebpf.CollectionSpec
	collection       *ebpf.Collection
	link             xdpAttachment
	tcLink           tcCloser
	programLoaded    bool
}

// xdpAttachment is the small lifetime contract the manager needs from an
// attached program. Newer kernels expose a cilium/ebpf link, while older
// kernels require the legacy RTM_SETLINK XDP API and therefore cannot provide
// a link.Link value. Keeping the manager on Close-only lets both attach paths
// share the same rollback and detach handling.
type xdpAttachment interface {
	Close() error
}

type Manager struct {
	mu         sync.RWMutex
	objectPath string
	states     map[string]*interfaceState
}

func NewManager(objectPath string) *Manager {
	return &Manager{
		objectPath: objectPath,
		states:     make(map[string]*interfaceState),
	}
}

func (m *Manager) Attach(ifaceName string, mode AttachMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("resolve interface %q: %w", ifaceName, err)
	}

	state := m.states[ifaceName]
	if state != nil && state.link != nil {
		return nil
	}

	state, err = m.loadState(ifaceName, iface.Index, mode)
	if err != nil {
		return err
	}

	flags := xdpAttachFlags(mode)
	var lnk xdpAttachment
	lnk, err = link.AttachXDP(link.XDPOptions{
		Program:   state.collection.Programs["xdp_acl"],
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil && shouldFallbackToGenericXDP(err) {
		// Kernels before 5.7 do not support bpf_link. Try the legacy netlink
		// attach path before falling back from native to generic XDP; it keeps
		// NodeWall on its XDP dataplane without requiring iptables.
		lnk, err = attachLegacyXDP(state.collection.Programs["xdp_acl"], iface.Index, flags)
		if err == nil {
			state.mode = mode
		} else if mode == AttachModeNative {
			// Driver mode is unavailable on some virtual or older NIC drivers.
			// Retry the generic mode through both APIs before returning the
			// original failure to the caller.
			genericFlags := link.XDPGenericMode
			lnk, err = link.AttachXDP(link.XDPOptions{
				Program:   state.collection.Programs["xdp_acl"],
				Interface: iface.Index,
				Flags:     genericFlags,
			})
			if err != nil && shouldFallbackToGenericXDP(err) {
				lnk, err = attachLegacyXDP(state.collection.Programs["xdp_acl"], iface.Index, genericFlags)
			}
			if err == nil {
				state.mode = AttachModeGeneric
			}
		}
	}
	if err != nil {
		state.collection.Close()
		return fmt.Errorf("attach xdp on %s: %w", ifaceName, err)
	}

	tcLink, err := attachTCEgressTracker(iface.Index, state.collection.Programs["tc_egress_track"])
	if err != nil {
		_ = lnk.Close()
		state.collection.Close()
		return fmt.Errorf("attach tc egress tracker on %s: %w", ifaceName, err)
	}

	state.link = lnk
	state.tcLink = tcLink
	state.programLoaded = true
	m.states[ifaceName] = state
	return nil
}

func xdpAttachFlags(mode AttachMode) link.XDPAttachFlags {
	if mode == AttachModeNative {
		return link.XDPDriverMode
	}
	return link.XDPGenericMode
}

func shouldFallbackToGenericXDP(err error) bool {
	return errors.Is(err, link.ErrNotSupported) ||
		errors.Is(err, ebpf.ErrNotSupported) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.EINVAL)
}

func shouldIgnoreTCXAttachError(err error) bool {
	return errors.Is(err, link.ErrNotSupported) || errors.Is(err, ebpf.ErrNotSupported)
}

type tcCloser interface {
	Close() error
}

func attachTCEgressTracker(ifaceIndex int, prog *ebpf.Program) (tcCloser, error) {
	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Interface: ifaceIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err == nil {
		return tcLink, nil
	}
	if !shouldIgnoreTCXAttachError(err) {
		return nil, err
	}
	return attachTCEgressFallback(ifaceIndex, prog)
}

func (m *Manager) Detach(ifaceName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ifaceName]
	if !ok || state.link == nil {
		return nil
	}

	if err := state.link.Close(); err != nil {
		return fmt.Errorf("detach xdp from %s: %w", ifaceName, err)
	}
	if state.tcLink != nil {
		if err := state.tcLink.Close(); err != nil {
			return fmt.Errorf("detach tc egress tracker from %s: %w", ifaceName, err)
		}
	}

	state.link = nil
	state.tcLink = nil
	state.programLoaded = false
	if state.collection != nil {
		state.collection.Close()
		state.collection = nil
	}

	return nil
}

func (m *Manager) UpsertCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	value := allowValue{Allow: 1}
	if err := state.collection.Maps["allow_ipv4"].Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update allowlist map for %s: %w", ifaceName, err)
	}

	state.allowlist = upsertSortedCIDR(state.allowlist, normalized)
	return nil
}

func (m *Manager) UpsertBypassCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	value := allowValue{Allow: 1}
	if err := state.collection.Maps["bypass_ipv4"].Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update bypass map for %s: %w", ifaceName, err)
	}

	state.bypassCIDRs = upsertSortedCIDR(state.bypassCIDRs, normalized)
	return nil
}

func (m *Manager) UpsertBlockedCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	value := allowValue{Allow: 1}
	if err := state.collection.Maps["block_ipv4"].Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update block map for %s: %w", ifaceName, err)
	}

	state.blockCIDRs = upsertSortedCIDR(state.blockCIDRs, normalized)
	return nil
}

func (m *Manager) UpsertICMPAllowCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["icmp_allow_ipv4"].Update(key, allowValue{Allow: 1}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update icmp_allow_ipv4 map for %s: %w", ifaceName, err)
	}
	state.icmpAllowCIDRs = upsertSortedCIDR(state.icmpAllowCIDRs, normalized)
	return nil
}

func (m *Manager) UpsertICMPBlockedCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["icmp_block_ipv4"].Update(key, allowValue{Allow: 1}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update icmp_block_ipv4 map for %s: %w", ifaceName, err)
	}
	state.icmpBlockCIDRs = upsertSortedCIDR(state.icmpBlockCIDRs, normalized)
	return nil
}

func (m *Manager) UpsertPort(ifaceName string, port uint16) error {
	if err := m.UpsertPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.UpsertPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *Manager) UpsertPublicPort(ifaceName string, port uint16) error {
	if err := m.UpsertPublicPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.UpsertPublicPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *Manager) UpsertDeniedPort(ifaceName string, port uint16) error {
	if err := m.UpsertDeniedPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.UpsertDeniedPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *Manager) UpsertPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, err := portRuleToKey(rule)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["allow_ports"].Update(key, portValue{Allow: 1}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update allow_ports map for %s: %w", ifaceName, err)
	}
	state.allowedPortRules = upsertSortedPortRule(state.allowedPortRules, models.PortRule{Protocol: models.ParsePortProtocol(string(rule.Protocol)), Port: rule.Port})
	state.allowedPorts = models.CollapsePortRules(state.allowedPortRules)
	return nil
}

func (m *Manager) UpsertPublicPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, err := portRuleToKey(rule)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["public_ports"].Update(key, portValue{Allow: 1}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update public_ports map for %s: %w", ifaceName, err)
	}
	state.publicPortRules = upsertSortedPortRule(state.publicPortRules, models.PortRule{Protocol: models.ParsePortProtocol(string(rule.Protocol)), Port: rule.Port})
	state.publicPorts = models.CollapsePortRules(state.publicPortRules)
	return nil
}

func (m *Manager) UpsertDeniedPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, err := portRuleToKey(rule)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["deny_ports"].Update(key, portValue{Allow: 1}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update deny_ports map for %s: %w", ifaceName, err)
	}
	state.deniedPortRules = upsertSortedPortRule(state.deniedPortRules, models.PortRule{Protocol: models.ParsePortProtocol(string(rule.Protocol)), Port: rule.Port})
	state.deniedPorts = models.CollapsePortRules(state.deniedPortRules)
	return nil
}

func (m *Manager) DeleteCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	if err := state.collection.Maps["allow_ipv4"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete allowlist entry for %s: %w", ifaceName, err)
	}

	state.allowlist = deleteSortedCIDR(state.allowlist, normalized)
	return nil
}

func (m *Manager) DeleteBypassCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	if err := state.collection.Maps["bypass_ipv4"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete bypass entry for %s: %w", ifaceName, err)
	}

	state.bypassCIDRs = deleteSortedCIDR(state.bypassCIDRs, normalized)
	return nil
}

func (m *Manager) DeleteBlockedCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	if err := state.collection.Maps["block_ipv4"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete block entry for %s: %w", ifaceName, err)
	}

	state.blockCIDRs = deleteSortedCIDR(state.blockCIDRs, normalized)
	return nil
}

func (m *Manager) DeleteICMPAllowCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["icmp_allow_ipv4"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete icmp_allow_ipv4 entry for %s: %w", ifaceName, err)
	}
	state.icmpAllowCIDRs = deleteSortedCIDR(state.icmpAllowCIDRs, normalized)
	return nil
}

func (m *Manager) DeleteICMPBlockedCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["icmp_block_ipv4"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete icmp_block_ipv4 entry for %s: %w", ifaceName, err)
	}
	state.icmpBlockCIDRs = deleteSortedCIDR(state.icmpBlockCIDRs, normalized)
	return nil
}

func (m *Manager) DeletePort(ifaceName string, port uint16) error {
	if err := m.DeletePortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.DeletePortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *Manager) DeletePublicPort(ifaceName string, port uint16) error {
	if err := m.DeletePublicPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.DeletePublicPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *Manager) DeleteDeniedPort(ifaceName string, port uint16) error {
	if err := m.DeleteDeniedPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.DeleteDeniedPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *Manager) DeletePortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, err := portRuleToKey(rule)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["allow_ports"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete allow_ports entry for %s: %w", ifaceName, err)
	}
	state.allowedPortRules = deleteSortedPortRule(state.allowedPortRules, rule)
	state.allowedPorts = models.CollapsePortRules(state.allowedPortRules)
	return nil
}

func (m *Manager) DeletePublicPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, err := portRuleToKey(rule)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["public_ports"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete public_ports entry for %s: %w", ifaceName, err)
	}
	state.publicPortRules = deleteSortedPortRule(state.publicPortRules, rule)
	state.publicPorts = models.CollapsePortRules(state.publicPortRules)
	return nil
}

func (m *Manager) DeleteDeniedPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	key, err := portRuleToKey(rule)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["deny_ports"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete deny_ports entry for %s: %w", ifaceName, err)
	}
	state.deniedPortRules = deleteSortedPortRule(state.deniedPortRules, rule)
	state.deniedPorts = models.CollapsePortRules(state.deniedPortRules)
	return nil
}

func (m *Manager) ReplaceAllowlist(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	if err := resetAllowlistMap(state.collection.Maps["allow_ipv4"]); err != nil {
		return fmt.Errorf("reset allowlist map: %w", err)
	}

	for _, cidr := range normalizeCIDRs(cidrs) {
		key, _, err := CIDRToKey(cidr)
		if err != nil {
			return err
		}
		if err := state.collection.Maps["allow_ipv4"].Update(key, allowValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("replace allowlist entry %s: %w", cidr, err)
		}
	}

	state.allowlist = normalizeCIDRs(cidrs)
	return nil
}

func (m *Manager) ReplaceBypassCIDRs(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	if err := resetAllowlistMap(state.collection.Maps["bypass_ipv4"]); err != nil {
		return fmt.Errorf("reset bypass map: %w", err)
	}

	for _, cidr := range normalizeCIDRs(cidrs) {
		key, _, err := CIDRToKey(cidr)
		if err != nil {
			return err
		}
		if err := state.collection.Maps["bypass_ipv4"].Update(key, allowValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("replace bypass entry %s: %w", cidr, err)
		}
	}

	state.bypassCIDRs = normalizeCIDRs(cidrs)
	return nil
}

func (m *Manager) ReplaceBlockedCIDRs(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	if err := resetAllowlistMap(state.collection.Maps["block_ipv4"]); err != nil {
		return fmt.Errorf("reset block map: %w", err)
	}

	for _, cidr := range normalizeCIDRs(cidrs) {
		key, _, err := CIDRToKey(cidr)
		if err != nil {
			return err
		}
		if err := state.collection.Maps["block_ipv4"].Update(key, allowValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("replace block entry %s: %w", cidr, err)
		}
	}

	state.blockCIDRs = normalizeCIDRs(cidrs)
	return nil
}

func (m *Manager) ReplaceICMPAllowCIDRs(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	if err := resetAllowlistMap(state.collection.Maps["icmp_allow_ipv4"]); err != nil {
		return fmt.Errorf("reset icmp_allow_ipv4 map: %w", err)
	}
	for _, cidr := range normalizeCIDRs(cidrs) {
		key, _, err := CIDRToKey(cidr)
		if err != nil {
			return err
		}
		if err := state.collection.Maps["icmp_allow_ipv4"].Update(key, allowValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("replace icmp allow entry %s: %w", cidr, err)
		}
	}
	state.icmpAllowCIDRs = normalizeCIDRs(cidrs)
	return nil
}

func (m *Manager) ReplaceICMPBlockedCIDRs(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	if err := resetAllowlistMap(state.collection.Maps["icmp_block_ipv4"]); err != nil {
		return fmt.Errorf("reset icmp_block_ipv4 map: %w", err)
	}
	for _, cidr := range normalizeCIDRs(cidrs) {
		key, _, err := CIDRToKey(cidr)
		if err != nil {
			return err
		}
		if err := state.collection.Maps["icmp_block_ipv4"].Update(key, allowValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("replace icmp block entry %s: %w", cidr, err)
		}
	}
	state.icmpBlockCIDRs = normalizeCIDRs(cidrs)
	return nil
}

func (m *Manager) ReplacePorts(ifaceName string, ports []uint16) error {
	rules := make([]models.PortRule, 0, len(ports)*2)
	for _, port := range normalizePorts(ports) {
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolTCP, Port: port})
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
	}
	return m.ReplacePortRules(ifaceName, rules)
}

func (m *Manager) ReplacePublicPorts(ifaceName string, ports []uint16) error {
	rules := make([]models.PortRule, 0, len(ports)*2)
	for _, port := range normalizePorts(ports) {
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolTCP, Port: port})
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
	}
	return m.ReplacePublicPortRules(ifaceName, rules)
}

func (m *Manager) ReplaceDeniedPorts(ifaceName string, ports []uint16) error {
	rules := make([]models.PortRule, 0, len(ports)*2)
	for _, port := range normalizePorts(ports) {
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolTCP, Port: port})
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
	}
	return m.ReplaceDeniedPortRules(ifaceName, rules)
}

func (m *Manager) ReplacePortRules(ifaceName string, rules []models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	normalized := normalizePortRules(rules, nil)
	if err := resetPortMap(state.collection.Maps["allow_ports"]); err != nil {
		return fmt.Errorf("reset allow_ports map: %w", err)
	}
	for _, rule := range normalized {
		key, err := portRuleToKey(rule)
		if err != nil {
			return err
		}
		if err := state.collection.Maps["allow_ports"].Update(key, portValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("replace allow port %s/%d: %w", rule.Protocol, rule.Port, err)
		}
	}
	state.allowedPortRules = normalized
	state.allowedPorts = models.CollapsePortRules(normalized)
	return nil
}

func (m *Manager) ReplacePublicPortRules(ifaceName string, rules []models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	normalized := normalizePortRules(rules, nil)
	if err := resetPortMap(state.collection.Maps["public_ports"]); err != nil {
		return fmt.Errorf("reset public_ports map: %w", err)
	}
	for _, rule := range normalized {
		key, err := portRuleToKey(rule)
		if err != nil {
			return err
		}
		if err := state.collection.Maps["public_ports"].Update(key, portValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("replace public port %s/%d: %w", rule.Protocol, rule.Port, err)
		}
	}
	state.publicPortRules = normalized
	state.publicPorts = models.CollapsePortRules(normalized)
	return nil
}

func (m *Manager) ReplaceDeniedPortRules(ifaceName string, rules []models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	normalized := normalizePortRules(rules, nil)
	if err := resetPortMap(state.collection.Maps["deny_ports"]); err != nil {
		return fmt.Errorf("reset deny_ports map: %w", err)
	}
	for _, rule := range normalized {
		key, err := portRuleToKey(rule)
		if err != nil {
			return err
		}
		if err := state.collection.Maps["deny_ports"].Update(key, portValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("replace denied port %s/%d: %w", rule.Protocol, rule.Port, err)
		}
	}
	state.deniedPortRules = normalized
	state.deniedPorts = models.CollapsePortRules(normalized)
	return nil
}

func (m *Manager) ReplaceRateLimitRules(ifaceName string, rules []models.RateLimitRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}
	normalized, err := normalizeRateLimitRules(rules)
	if err != nil {
		return err
	}
	if err := resetRateLimitMap(state.collection.Maps["rate_limits"]); err != nil {
		return fmt.Errorf("reset rate_limits map: %w", err)
	}
	for _, rule := range normalized {
		key, err := rateLimitRuleToKey(rule)
		if err != nil {
			return err
		}
		value := rateLimitValue{
			RequestsPerMinute: rule.RequestsPerMinute,
			Burst:             rule.Burst,
			Tokens:            rule.Burst,
		}
		if err := state.collection.Maps["rate_limits"].Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("replace rate limit %s:%d/%s: %w", rule.SourceIP, rule.Port, rule.Direction, err)
		}
	}
	state.rateLimitRules = normalized
	return nil
}

func (m *Manager) ListCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}

	out := make([]string, len(state.allowlist))
	copy(out, state.allowlist)
	return out, nil
}

func (m *Manager) ListBypassCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}

	out := make([]string, len(state.bypassCIDRs))
	copy(out, state.bypassCIDRs)
	return out, nil
}

func (m *Manager) ListBlockedCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}

	out := make([]string, len(state.blockCIDRs))
	copy(out, state.blockCIDRs)
	return out, nil
}

func (m *Manager) ListICMPAllowCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	out := make([]string, len(state.icmpAllowCIDRs))
	copy(out, state.icmpAllowCIDRs)
	return out, nil
}

func (m *Manager) ListICMPBlockedCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	out := make([]string, len(state.icmpBlockCIDRs))
	copy(out, state.icmpBlockCIDRs)
	return out, nil
}

func (m *Manager) ListPorts(ifaceName string) ([]uint16, error) {
	rules, err := m.ListPortRules(ifaceName)
	if err != nil {
		return nil, err
	}
	return models.CollapsePortRules(rules), nil
}

func (m *Manager) ListPublicPorts(ifaceName string) ([]uint16, error) {
	rules, err := m.ListPublicPortRules(ifaceName)
	if err != nil {
		return nil, err
	}
	return models.CollapsePortRules(rules), nil
}

func (m *Manager) ListDeniedPorts(ifaceName string) ([]uint16, error) {
	rules, err := m.ListDeniedPortRules(ifaceName)
	if err != nil {
		return nil, err
	}
	return models.CollapsePortRules(rules), nil
}

func (m *Manager) ListPortRules(ifaceName string) ([]models.PortRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	out := make([]models.PortRule, len(state.allowedPortRules))
	copy(out, state.allowedPortRules)
	return out, nil
}

func (m *Manager) ListPublicPortRules(ifaceName string) ([]models.PortRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	out := make([]models.PortRule, len(state.publicPortRules))
	copy(out, state.publicPortRules)
	return out, nil
}

func (m *Manager) ListDeniedPortRules(ifaceName string) ([]models.PortRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	out := make([]models.PortRule, len(state.deniedPortRules))
	copy(out, state.deniedPortRules)
	return out, nil
}

func (m *Manager) ReadStats(ifaceName string) (models.InterfaceStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return models.InterfaceStats{}, errNotAttached
	}

	var value statsValue
	key := uint32(0)
	if err := state.collection.Maps["stats_map"].Lookup(key, &value); err != nil {
		return models.InterfaceStats{}, fmt.Errorf("lookup stats: %w", err)
	}

	return models.InterfaceStats{
		Passed:  value.Passed,
		Dropped: value.Dropped,
	}, nil
}

func (m *Manager) ReadConfig(ifaceName string) (Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return Config{}, errNotAttached
	}

	var value configValue
	if err := state.collection.Maps["config_map"].Lookup(configKey, &value); err != nil {
		return Config{}, fmt.Errorf("lookup config: %w", err)
	}

	return configFromValue(value), nil
}

func (m *Manager) WriteConfig(ifaceName string, cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	value, err := configToValue(cfg)
	if err != nil {
		return err
	}

	if err := state.collection.Maps["config_map"].Update(configKey, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update config map: %w", err)
	}

	state.cfg = cfg
	return nil
}

func (m *Manager) Runtime(ifaceName string) (Runtime, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return Runtime{Interface: ifaceName, ObjectPath: m.objectPath}, nil
	}

	return Runtime{
		Interface:        ifaceName,
		Attached:         state.link != nil,
		Mode:             state.mode,
		BypassCIDRs:      append([]string(nil), state.bypassCIDRs...),
		BlockedCIDRs:     append([]string(nil), state.blockCIDRs...),
		ICMPAllowCIDRs:   append([]string(nil), state.icmpAllowCIDRs...),
		ICMPBlockedCIDRs: append([]string(nil), state.icmpBlockCIDRs...),
		Allowlist:        append([]string(nil), state.allowlist...),
		PublicPorts:      append([]uint16(nil), state.publicPorts...),
		DeniedPorts:      append([]uint16(nil), state.deniedPorts...),
		AllowedPorts:     append([]uint16(nil), state.allowedPorts...),
		PublicPortRules:  append([]models.PortRule(nil), state.publicPortRules...),
		DeniedPortRules:  append([]models.PortRule(nil), state.deniedPortRules...),
		AllowedPortRules: append([]models.PortRule(nil), state.allowedPortRules...),
		RateLimitRules:   append([]models.RateLimitRule(nil), state.rateLimitRules...),
		Config:           state.cfg,
		ObjectPath:       m.objectPath,
		ProgramLoaded:    state.programLoaded,
	}, nil
}

func (m *Manager) Interfaces() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]string, 0, len(m.states))
	for iface := range m.states {
		out = append(out, iface)
	}
	return out
}

func (m *Manager) DiscoverInterfaces() (models.InterfaceInventory, error) {
	inventory, err := DetectHostInterfaces()
	if err != nil {
		return models.InterfaceInventory{}, err
	}
	return mergeInventoryWithStates(inventory, m.Interfaces()), nil
}

func (m *Manager) ReadSourceStats(ifaceName string, limit int) ([]models.SourceStat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return nil, errNotAttached
	}

	statsMap := state.collection.Maps["source_stats"]
	if statsMap == nil {
		return nil, fmt.Errorf("source_stats map not loaded")
	}

	var (
		key   uint32
		value sourceStatsValue
		out   []models.SourceStat
	)

	iter := statsMap.Iterate()
	for iter.Next(&key, &value) {
		total := value.Passed + value.Dropped
		if total == 0 {
			continue
		}
		dropRatio := 0.0
		if total > 0 {
			dropRatio = float64(value.Dropped) / float64(total)
		}
		out = append(out, models.SourceStat{
			SourceIP:  sourceIPFromUint32(key),
			Passed:    value.Passed,
			Dropped:   value.Dropped,
			Total:     total,
			DropRatio: dropRatio,
			Risk:      classifyRisk(value.Passed, value.Dropped),
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Dropped == out[j].Dropped {
			return out[i].Passed > out[j].Passed
		}
		return out[i].Dropped > out[j].Dropped
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) ReadPortStats(ifaceName string, limit int) ([]models.PortStat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return nil, errNotAttached
	}
	statsMap := state.collection.Maps["port_stats"]
	if statsMap == nil {
		return nil, fmt.Errorf("port_stats map not loaded")
	}

	var (
		key   uint16
		value portStatsValue
		out   []models.PortStat
	)

	iter := statsMap.Iterate()
	for iter.Next(&key, &value) {
		total := value.Passed + value.Dropped
		if total == 0 {
			continue
		}
		out = append(out, models.PortStat{
			Port:    key,
			Passed:  value.Passed,
			Dropped: value.Dropped,
			Total:   total,
			Risk:    classifyRisk(value.Passed, value.Dropped),
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Dropped == out[j].Dropped {
			return out[i].Passed > out[j].Passed
		}
		return out[i].Dropped > out[j].Dropped
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) ReadDropLogs(ifaceName string, limit int) ([]models.InterceptLogEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return nil, errNotAttached
	}

	logMap := state.collection.Maps["drop_logs"]
	if logMap == nil {
		return nil, fmt.Errorf("drop_logs map not loaded")
	}

	var (
		key   dropLogKey
		value dropLogValue
		out   []models.InterceptLogEntry
	)

	iter := logMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Drops == 0 {
			continue
		}
		out = append(out, models.InterceptLogEntry{
			Direction: models.DirectionIngress,
			SourceIP:  sourceIPFromUint32(key.SourceIP),
			Port:      key.DestPort,
			Reason:    dropReasonLabel(key.Reason),
			Count:     value.Drops,
			Drops:     value.Drops,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Drops == out[j].Drops {
			if out[i].SourceIP == out[j].SourceIP {
				return out[i].Port > out[j].Port
			}
			return out[i].SourceIP < out[j].SourceIP
		}
		return out[i].Drops > out[j].Drops
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) ReadReplyAllowLogs(ifaceName string, limit int) ([]models.InterceptLogEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return nil, errNotAttached
	}

	logMap := state.collection.Maps["reply_allow_logs"]
	if logMap == nil {
		return nil, fmt.Errorf("reply_allow_logs map not loaded")
	}

	var (
		key   replyLogKey
		value replyLogValue
		out   []models.InterceptLogEntry
	)

	iter := logMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Allowed == 0 {
			continue
		}
		out = append(out, models.InterceptLogEntry{
			Direction: models.DirectionIngress,
			SourceIP:  sourceIPFromUint32(key.SourceIP),
			Port:      key.DestPort,
			Reason:    "reply_flow_allowed",
			Count:     value.Allowed,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			if out[i].SourceIP == out[j].SourceIP {
				return out[i].Port > out[j].Port
			}
			return out[i].SourceIP < out[j].SourceIP
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) loadState(ifaceName string, ifaceIndex int, mode AttachMode) (*interfaceState, error) {
	if _, err := os.Stat(m.objectPath); err != nil {
		return nil, fmt.Errorf("bpf object %q not available: %w", m.objectPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(m.objectPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load collection: %w", err)
	}

	state := &interfaceState{
		ifaceName:        ifaceName,
		ifaceIndex:       ifaceIndex,
		mode:             mode,
		bypassCIDRs:      nil,
		blockCIDRs:       nil,
		allowlist:        nil,
		publicPorts:      nil,
		deniedPorts:      nil,
		allowedPorts:     nil,
		publicPortRules:  nil,
		deniedPortRules:  nil,
		allowedPortRules: nil,
		cfg: Config{
			NonIPv4Action: models.NonIPv4Pass,
		},
		spec:       spec,
		collection: coll,
	}

	initialConfig, err := configToValue(Config{NonIPv4Action: models.NonIPv4Pass, ReplyFlowTimeoutSeconds: 60})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("initialize config map: %w", err)
	}
	if err := state.collection.Maps["config_map"].Update(configKey, initialConfig, ebpf.UpdateAny); err != nil {
		coll.Close()
		return nil, fmt.Errorf("initialize config map: %w", err)
	}

	return state, nil
}

func (m *Manager) getStateLocked(ifaceName string) (*interfaceState, error) {
	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return nil, errNotAttached
	}
	return state, nil
}

func resetAllowlistMap(mb *ebpf.Map) error {
	var (
		key   lpmKey
		value allowValue
	)

	iter := mb.Iterate()
	for iter.Next(&key, &value) {
		if err := mb.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}

	return iter.Err()
}

func resetPortMap(mb *ebpf.Map) error {
	var (
		key   portRuleKey
		value portValue
	)
	iter := mb.Iterate()
	for iter.Next(&key, &value) {
		if err := mb.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return iter.Err()
}

func resetRateLimitMap(mb *ebpf.Map) error {
	var (
		key   rateLimitKey
		value rateLimitValue
	)
	iter := mb.Iterate()
	for iter.Next(&key, &value) {
		if err := mb.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return iter.Err()
}
