package xdp

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"nodewall/internal/models"
)

// ApplyDirectionPolicy programs the egress TC/eBPF maps. XDP runs only at
// ingress, so a separate TC egress hook is used for host-originated outbound
// packets while keeping the existing ingress maps untouched. The TC program
// records forwarded bridge/CNI flows for reply tracking but deliberately
// leaves their enforcement to the bridge or CNI, matching the legacy
// iptables backend's host-only hooks and the Kubernetes safety boundary.
func (m *Manager) ApplyDirectionPolicy(ifaceName string, direction models.PolicyDirection, policy DirectionPolicy) error {
	if direction != models.DirectionEgress {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.getStateLocked(ifaceName)
	if err != nil {
		return err
	}

	mapNames := []string{
		"egress_allow_ipv4", "egress_bypass_ipv4", "egress_block_ipv4",
		"egress_icmp_allow_ipv4", "egress_icmp_block_ipv4", "egress_allow_ports",
		"egress_public_ports", "egress_deny_ports", "egress_rate_limits",
	}
	for _, name := range mapNames {
		if state.collection.Maps[name] == nil {
			return fmt.Errorf("BPF object is missing %s; regenerate the XDP/TC object before enabling egress enforcement", name)
		}
	}

	// Keep the hook fail-open while maps are being replaced. If a map update
	// fails halfway through, the caller can recover without cutting off the
	// node's network access with a partially-written default-deny policy.
	safeCfg := state.cfg
	safeCfg.EgressPolicyEnforced = false
	safeCfg.EgressObserveOnly = false
	safeCfg.EgressPortPolicyEnabled = false
	safeCfg.EgressRateLimitEnabled = false
	safeCfg.EgressDefaultDeny = false
	if err := m.writeConfigLocked(state, safeCfg); err != nil {
		return fmt.Errorf("disable egress enforcement while updating maps: %w", err)
	}

	blocked := append([]string(nil), policy.BlockedCIDRs...)
	for _, block := range policy.TemporaryBlocks {
		if addr, parseErr := netip.ParseAddr(block.SourceIP); parseErr == nil && addr.Is4() {
			blocked = append(blocked, netip.PrefixFrom(addr, 32).String())
		}
	}
	if err := replaceLPMMap(state.collection.Maps["egress_allow_ipv4"], policy.Allowlist); err != nil {
		return fmt.Errorf("replace egress allowlist: %w", err)
	}
	if err := replaceLPMMap(state.collection.Maps["egress_bypass_ipv4"], policy.BypassCIDRs); err != nil {
		return fmt.Errorf("replace egress bypass list: %w", err)
	}
	if err := replaceLPMMap(state.collection.Maps["egress_block_ipv4"], blocked); err != nil {
		return fmt.Errorf("replace egress block list: %w", err)
	}
	if err := replaceLPMMap(state.collection.Maps["egress_icmp_allow_ipv4"], policy.ICMPAllowCIDRs); err != nil {
		return fmt.Errorf("replace egress ICMP allow list: %w", err)
	}
	if err := replaceLPMMap(state.collection.Maps["egress_icmp_block_ipv4"], policy.ICMPBlockedCIDRs); err != nil {
		return fmt.Errorf("replace egress ICMP block list: %w", err)
	}
	if err := replacePortMap(state.collection.Maps["egress_allow_ports"], policy.AllowedPortRules); err != nil {
		return fmt.Errorf("replace egress allowed ports: %w", err)
	}
	if err := replacePortMap(state.collection.Maps["egress_public_ports"], policy.PublicPortRules); err != nil {
		return fmt.Errorf("replace egress public ports: %w", err)
	}
	if err := replacePortMap(state.collection.Maps["egress_deny_ports"], policy.DeniedPortRules); err != nil {
		return fmt.Errorf("replace egress denied ports: %w", err)
	}
	if err := replaceRateLimitMap(state.collection.Maps["egress_rate_limits"], policy.RateLimitRules); err != nil {
		return fmt.Errorf("replace egress rate limits: %w", err)
	}

	nextCfg := safeCfg
	nextCfg.EgressPolicyEnforced = policy.PolicyEnforced || len(policy.BypassCIDRs) > 0 || len(blocked) > 0 ||
		len(policy.ICMPAllowCIDRs) > 0 || len(policy.ICMPBlockedCIDRs) > 0 || len(policy.Allowlist) > 0 ||
		len(policy.PublicPortRules) > 0 || len(policy.DeniedPortRules) > 0 || len(policy.AllowedPortRules) > 0 ||
		len(policy.RateLimitRules) > 0
	nextCfg.EgressObserveOnly = policy.ObserveOnly
	nextCfg.EgressNonIPv4Action = policy.NonIPv4Action
	nextCfg.EgressPortPolicyEnabled = len(policy.AllowedPortRules) > 0
	nextCfg.EgressRateLimitEnabled = len(policy.RateLimitRules) > 0
	nextCfg.EgressDefaultDeny = len(policy.Allowlist) > 0 || len(policy.AllowedPortRules) > 0
	if err := m.writeConfigLocked(state, nextCfg); err != nil {
		return fmt.Errorf("enable egress enforcement: %w", err)
	}
	return nil
}

func (m *Manager) writeConfigLocked(state *interfaceState, cfg Config) error {
	value, err := configToValue(cfg)
	if err != nil {
		return err
	}
	if err := state.collection.Maps["config_map"].Update(configKey, value, ebpf.UpdateAny); err != nil {
		return err
	}
	state.cfg = cfg
	return nil
}

func replaceLPMMap(mb *ebpf.Map, cidrs []string) error {
	if err := resetAllowlistMap(mb); err != nil {
		return err
	}
	for _, cidr := range normalizeCIDRs(cidrs) {
		key, _, err := CIDRToKey(cidr)
		if err != nil {
			return err
		}
		if err := mb.Update(key, allowValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func replacePortMap(mb *ebpf.Map, rules []models.PortRule) error {
	if err := resetPortMap(mb); err != nil {
		return err
	}
	for _, rule := range normalizePortRules(rules, nil) {
		key, err := portRuleToKey(rule)
		if err != nil {
			return err
		}
		if err := mb.Update(key, portValue{Allow: 1}, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func replaceRateLimitMap(mb *ebpf.Map, rules []models.RateLimitRule) error {
	if err := resetRateLimitMap(mb); err != nil {
		return err
	}
	normalized, err := normalizeRateLimitRules(rules)
	if err != nil {
		return err
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
		if err := mb.Update(key, value, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

// MockManager accepts both directions so API and rollback tests can exercise
// the same control flow without requiring a Linux firewall.
func (m *MockManager) ApplyDirectionPolicy(_ string, _ models.PolicyDirection, _ DirectionPolicy) error {
	return nil
}
