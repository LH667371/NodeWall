package xdp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"nodewall/internal/models"
)

const (
	configKey        uint32 = 0
	nonIPv4PassUint8 uint8  = 0
	nonIPv4DropUint8 uint8  = 1
)

type lpmKey struct {
	PrefixLen uint32
	Addr      uint32
}

type allowValue struct {
	Allow uint8
}

type statsValue struct {
	Passed  uint64
	Dropped uint64
}

type configValue struct {
	NonIPv4Action     uint8
	PortPolicyEnabled uint8
	Reserved          [6]byte
}

type sourceStatsValue struct {
	Passed     uint64
	Dropped    uint64
	LastSeenNS uint64
}

type portValue struct {
	Allow uint8
}

type portRuleKey struct {
	Protocol uint8
	Pad0     uint8
	Port     uint16
	Reserved uint8
	Pad1     uint8
}

// rateLimitKey mirrors struct rate_limit_key in bpf/xdp_acl.h.
type rateLimitKey struct {
	SourceIP uint32
	DestPort uint16
	Protocol uint8
	Reserved uint8
}

// rateLimitValue mirrors struct rate_limit_value. The first two uint32 fields
// reserve the kernel spin lock and its alignment padding; user space writes
// them as zero while the XDP program owns the lock during token updates.
type rateLimitValue struct {
	Lock              uint32
	LockPadding       uint32
	RequestsPerMinute uint64
	Burst             uint64
	Tokens            uint64
	LastRefillMS      uint64
}

type portStatsValue struct {
	Passed  uint64
	Dropped uint64
}

type dropLogKey struct {
	SourceIP uint32
	DestPort uint16
	Reason   uint8
	Reserved uint8
}

type dropLogValue struct {
	Drops      uint64
	LastSeenNS uint64
}

type replyLogKey struct {
	SourceIP uint32
	DestPort uint16
	Protocol uint8
	Reserved uint8
}

type replyLogValue struct {
	Allowed    uint64
	LastSeenNS uint64
}

const (
	dropReasonBlockedSource    uint8 = 1
	dropReasonDeniedPort       uint8 = 2
	dropReasonRestrictedPolicy uint8 = 3
	dropReasonSourceNotAllowed uint8 = 4
	dropReasonRateLimited      uint8 = 5
)

func CIDRToKey(cidr string) (lpmKey, string, error) {
	cidr = strings.TrimSpace(cidr)

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		addr, addrErr := netip.ParseAddr(cidr)
		if addrErr != nil {
			return lpmKey{}, "", fmt.Errorf("parse cidr: %w", err)
		}
		if !addr.Is4() {
			return lpmKey{}, "", fmt.Errorf("only IPv4 CIDRs are supported")
		}
		prefix = netip.PrefixFrom(addr, 32)
	}

	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return lpmKey{}, "", fmt.Errorf("only IPv4 CIDRs are supported")
	}

	addr := prefix.Addr().As4()
	return lpmKey{
		PrefixLen: uint32(prefix.Bits()),
		Addr:      binary.LittleEndian.Uint32(addr[:]),
	}, prefix.String(), nil
}

func configToValue(cfg Config) (configValue, error) {
	value, err := configActionToValue(cfg.NonIPv4Action)
	if err != nil {
		return configValue{}, err
	}
	if cfg.PortPolicyEnabled {
		value.PortPolicyEnabled = 1
	}
	if cfg.RateLimitEnabled {
		value.Reserved[3] = 1
	}
	if cfg.PolicyEnforced {
		value.Reserved[0] = 1
	}
	if cfg.EgressPolicyEnforced {
		value.Reserved[2] = 1
	}
	if cfg.ObserveOnly {
		value.Reserved[4] = 1
	}
	timeout := cfg.ReplyFlowTimeoutSeconds
	if timeout <= 0 {
		timeout = 60
	}
	if timeout > 255 {
		timeout = 255
	}
	value.Reserved[1] = uint8(timeout)
	return value, nil
}

func configActionToValue(action models.NonIPv4Action) (configValue, error) {
	switch action {
	case "", models.NonIPv4Pass:
		return configValue{NonIPv4Action: nonIPv4PassUint8}, nil
	case models.NonIPv4Drop:
		return configValue{NonIPv4Action: nonIPv4DropUint8}, nil
	default:
		return configValue{}, fmt.Errorf("unsupported non_ipv4_action %q", action)
	}
}

func configFromValue(value configValue) Config {
	cfg := Config{
		NonIPv4Action: models.NonIPv4Pass,
	}
	if value.NonIPv4Action == nonIPv4DropUint8 {
		cfg.NonIPv4Action = models.NonIPv4Drop
	}
	cfg.PortPolicyEnabled = value.PortPolicyEnabled == 1
	cfg.RateLimitEnabled = value.Reserved[3] == 1
	cfg.PolicyEnforced = value.Reserved[0] == 1
	cfg.EgressPolicyEnforced = value.Reserved[2] == 1
	cfg.ObserveOnly = value.Reserved[4] == 1
	if value.Reserved[1] == 0 {
		cfg.ReplyFlowTimeoutSeconds = 60
	} else {
		cfg.ReplyFlowTimeoutSeconds = int(value.Reserved[1])
	}
	return cfg
}

func normalizeCIDRs(cidrs []string) []string {
	seen := make(map[string]struct{}, len(cidrs))
	out := make([]string, 0, len(cidrs))

	for _, cidr := range cidrs {
		_, normalized, err := CIDRToKey(cidr)
		if err != nil {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}

	sort.Strings(out)
	return out
}

func upsertSortedCIDR(cidrs []string, cidr string) []string {
	normalized := normalizeCIDRs([]string{cidr})
	if len(normalized) == 0 {
		return normalizeCIDRs(cidrs)
	}

	next := append(slices.Clone(cidrs), normalized[0])
	return normalizeCIDRs(next)
}

func deleteSortedCIDR(cidrs []string, cidr string) []string {
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return normalizeCIDRs(cidrs)
	}

	next := make([]string, 0, len(cidrs))
	for _, existing := range cidrs {
		if existing != normalized {
			next = append(next, existing)
		}
	}

	return normalizeCIDRs(next)
}

func sourceIPFromUint32(value uint32) string {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	return netip.AddrFrom4(buf).String()
}

func dropReasonLabel(reason uint8) string {
	switch reason {
	case dropReasonBlockedSource:
		return "blocked_source"
	case dropReasonDeniedPort:
		return "denied_port"
	case dropReasonRestrictedPolicy:
		return "restricted_policy"
	case dropReasonSourceNotAllowed:
		return "source_not_allowed"
	case dropReasonRateLimited:
		return "rate_limited"
	default:
		return "unknown"
	}
}

func classifyRisk(passed, dropped uint64) string {
	total := passed + dropped
	if total == 0 {
		return "low"
	}
	ratio := float64(dropped) / float64(total)
	switch {
	case dropped >= 100 || ratio >= 0.9:
		return "high"
	case dropped >= 20 || ratio >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

func normalizePorts(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return nil
	}
	seen := make(map[uint16]struct{}, len(ports))
	out := make([]uint16, 0, len(ports))
	for _, port := range ports {
		if port == 0 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}

func normalizePortRules(rules []models.PortRule, fallback []uint16) []models.PortRule {
	normalized := models.NormalizePortRules(rules, fallback)
	if len(normalized) == 0 {
		return nil
	}
	slices.SortFunc(normalized, func(a, b models.PortRule) int {
		if a.Protocol == b.Protocol {
			if a.Port < b.Port {
				return -1
			}
			if a.Port > b.Port {
				return 1
			}
			return 0
		}
		if a.Protocol == models.PortProtocolICMP {
			return 1
		}
		if b.Protocol == models.PortProtocolICMP {
			return -1
		}
		if a.Protocol == models.PortProtocolTCP {
			return -1
		}
		return 1
	})
	return normalized
}

func upsertSortedPortRule(rules []models.PortRule, rule models.PortRule) []models.PortRule {
	next := append(slices.Clone(rules), rule)
	return normalizePortRules(next, nil)
}

func deleteSortedPortRule(rules []models.PortRule, rule models.PortRule) []models.PortRule {
	normalized := normalizePortRules([]models.PortRule{rule}, nil)
	if len(normalized) == 0 {
		return normalizePortRules(rules, nil)
	}
	target := normalized[0]
	next := make([]models.PortRule, 0, len(rules))
	for _, item := range rules {
		if item.Protocol == target.Protocol && item.Port == target.Port {
			continue
		}
		next = append(next, item)
	}
	return normalizePortRules(next, nil)
}

const (
	maxRateLimitRequestsPerMinute uint64 = 1_000_000
	maxRateLimitBurst             uint64 = 1_000_000
)

func rateLimitProtocol(protocol models.PortProtocol) (uint8, error) {
	switch protocol {
	case models.PortProtocolTCP:
		return 6, nil
	case models.PortProtocolUDP:
		return 17, nil
	default:
		return 0, fmt.Errorf("rate limits support only tcp and udp")
	}
}

func rateLimitRuleToKey(rule models.RateLimitRule) (rateLimitKey, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(rule.SourceIP))
	if err != nil || !addr.Is4() {
		return rateLimitKey{}, fmt.Errorf("rate limit source_ip must be an IPv4 address: %q", rule.SourceIP)
	}
	if rule.Port == 0 {
		return rateLimitKey{}, fmt.Errorf("rate limit port must be greater than 0")
	}
	protocolValue := strings.ToLower(strings.TrimSpace(string(rule.Protocol)))
	if protocolValue == "" {
		// Older persisted rate-limit records predate protocol-specific rules;
		// retain compatibility by treating them as TCP limits.
		protocolValue = string(models.PortProtocolTCP)
	}
	protocol, err := rateLimitProtocol(models.PortProtocol(protocolValue))
	if err != nil {
		return rateLimitKey{}, err
	}
	bytes := addr.As4()
	return rateLimitKey{
		SourceIP: binary.LittleEndian.Uint32(bytes[:]),
		DestPort: rule.Port,
		Protocol: protocol,
	}, nil
}

func normalizeRateLimitRules(rules []models.RateLimitRule) ([]models.RateLimitRule, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	seen := make(map[rateLimitKey]struct{}, len(rules))
	out := make([]models.RateLimitRule, 0, len(rules))
	for _, rule := range rules {
		if rule.RequestsPerMinute == 0 || rule.RequestsPerMinute > maxRateLimitRequestsPerMinute {
			return nil, fmt.Errorf("rate limit requests_per_minute must be between 1 and %d", maxRateLimitRequestsPerMinute)
		}
		if rule.Burst == 0 || rule.Burst > maxRateLimitBurst {
			return nil, fmt.Errorf("rate limit burst must be between 1 and %d", maxRateLimitBurst)
		}
		key, err := rateLimitRuleToKey(rule)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		addr := netip.AddrFrom4([4]byte{
			byte(key.SourceIP),
			byte(key.SourceIP >> 8),
			byte(key.SourceIP >> 16),
			byte(key.SourceIP >> 24),
		})
		rule.SourceIP = addr.String()
		rule.Protocol = models.PortProtocol(strings.ToLower(strings.TrimSpace(string(rule.Protocol))))
		if rule.Protocol == "" {
			rule.Protocol = models.PortProtocolTCP
		}
		out = append(out, rule)
	}
	slices.SortFunc(out, func(a, b models.RateLimitRule) int {
		if a.SourceIP != b.SourceIP {
			return strings.Compare(a.SourceIP, b.SourceIP)
		}
		if a.Port != b.Port {
			if a.Port < b.Port {
				return -1
			}
			return 1
		}
		return strings.Compare(string(a.Protocol), string(b.Protocol))
	})
	return out, nil
}

func portRuleToKey(rule models.PortRule) (portRuleKey, error) {
	protocol := models.ParsePortProtocol(string(rule.Protocol))
	if rule.Port == 0 && protocol != models.PortProtocolICMP {
		return portRuleKey{}, fmt.Errorf("port must be greater than 0")
	}
	var protocolNum uint8 = 6
	if protocol == models.PortProtocolUDP {
		protocolNum = 17
	}
	if protocol == models.PortProtocolICMP {
		protocolNum = 1
	}
	return portRuleKey{
		Protocol: protocolNum,
		Port:     rule.Port,
	}, nil
}

func upsertSortedPort(ports []uint16, port uint16) []uint16 {
	next := append(slices.Clone(ports), port)
	return normalizePorts(next)
}

func deleteSortedPort(ports []uint16, port uint16) []uint16 {
	next := make([]uint16, 0, len(ports))
	for _, item := range ports {
		if item != port {
			next = append(next, item)
		}
	}
	return normalizePorts(next)
}
