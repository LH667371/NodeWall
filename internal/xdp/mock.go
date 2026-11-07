package xdp

import (
	"fmt"
	"slices"
	"sync"

	"nodewall/internal/models"
)

type mockState struct {
	mode             AttachMode
	attached         bool
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
	stats            models.InterfaceStats
	sourceStats      map[string]models.SourceStat
	portStats        map[uint16]models.PortStat
	dropLogs         map[string]models.InterceptLogEntry
	replyLogs        map[string]models.InterceptLogEntry
}

type MockManager struct {
	mu     sync.RWMutex
	states map[string]*mockState
}

func NewMockManager() *MockManager {
	return &MockManager{
		states: make(map[string]*mockState),
	}
}

func (m *MockManager) Attach(ifaceName string, mode AttachMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	state.attached = true
	state.mode = mode
	if state.cfg.NonIPv4Action == "" {
		state.cfg.NonIPv4Action = models.NonIPv4Pass
	}
	state.stats.Passed += 10
	m.bumpSourceLocked(state, "10.0.0.10", 8, 0)
	m.bumpSourceLocked(state, "203.0.113.9", 0, 3)
	return nil
}

func (m *MockManager) Detach(ifaceName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	state.attached = false
	state.stats.Dropped += 1
	return nil
}

func (m *MockManager) UpsertCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	state.allowlist = upsertSortedCIDR(state.allowlist, normalized)
	state.stats.Passed += 5
	m.bumpSourceLocked(state, "10.0.0.10", 5, 0)
	return nil
}

func (m *MockManager) UpsertBypassCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	state.bypassCIDRs = upsertSortedCIDR(state.bypassCIDRs, normalized)
	state.stats.Passed += 3
	return nil
}

func (m *MockManager) UpsertBlockedCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	state.blockCIDRs = upsertSortedCIDR(state.blockCIDRs, normalized)
	state.stats.Dropped += 3
	m.bumpDropLogLocked(state, "203.0.113.9", 443, "blocked_source", 3)
	return nil
}

func (m *MockManager) UpsertICMPAllowCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}
	state.icmpAllowCIDRs = upsertSortedCIDR(state.icmpAllowCIDRs, normalized)
	return nil
}

func (m *MockManager) UpsertICMPBlockedCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}
	state.icmpBlockCIDRs = upsertSortedCIDR(state.icmpBlockCIDRs, normalized)
	return nil
}

func (m *MockManager) UpsertPort(ifaceName string, port uint16) error {
	if err := m.UpsertPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.UpsertPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *MockManager) UpsertPublicPort(ifaceName string, port uint16) error {
	if err := m.UpsertPublicPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.UpsertPublicPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *MockManager) UpsertDeniedPort(ifaceName string, port uint16) error {
	if err := m.UpsertDeniedPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.UpsertDeniedPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *MockManager) UpsertPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := portRuleToKey(rule); err != nil {
		return err
	}

	state := m.ensureStateLocked(ifaceName)
	normalized := models.PortRule{Protocol: models.ParsePortProtocol(string(rule.Protocol)), Port: rule.Port}
	state.allowedPortRules = upsertSortedPortRule(state.allowedPortRules, normalized)
	state.allowedPorts = models.CollapsePortRules(state.allowedPortRules)
	m.bumpPortLocked(state, rule.Port, 5, 0)
	return nil
}

func (m *MockManager) UpsertPublicPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := portRuleToKey(rule); err != nil {
		return err
	}

	state := m.ensureStateLocked(ifaceName)
	normalized := models.PortRule{Protocol: models.ParsePortProtocol(string(rule.Protocol)), Port: rule.Port}
	state.publicPortRules = upsertSortedPortRule(state.publicPortRules, normalized)
	state.publicPorts = models.CollapsePortRules(state.publicPortRules)
	m.bumpPortLocked(state, rule.Port, 6, 0)
	return nil
}

func (m *MockManager) UpsertDeniedPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := portRuleToKey(rule); err != nil {
		return err
	}

	state := m.ensureStateLocked(ifaceName)
	normalized := models.PortRule{Protocol: models.ParsePortProtocol(string(rule.Protocol)), Port: rule.Port}
	state.deniedPortRules = upsertSortedPortRule(state.deniedPortRules, normalized)
	state.deniedPorts = models.CollapsePortRules(state.deniedPortRules)
	m.bumpPortLocked(state, rule.Port, 0, 7)
	m.bumpDropLogLocked(state, "198.51.100.8", rule.Port, "denied_port", 7)
	return nil
}

func (m *MockManager) DeleteCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	state.allowlist = deleteSortedCIDR(state.allowlist, normalized)
	state.stats.Dropped += 1
	m.bumpSourceLocked(state, "198.51.100.25", 0, 4)
	return nil
}

func (m *MockManager) DeleteBypassCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	state.bypassCIDRs = deleteSortedCIDR(state.bypassCIDRs, normalized)
	return nil
}

func (m *MockManager) DeleteBlockedCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}

	state.blockCIDRs = deleteSortedCIDR(state.blockCIDRs, normalized)
	return nil
}

func (m *MockManager) DeleteICMPAllowCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}
	state.icmpAllowCIDRs = deleteSortedCIDR(state.icmpAllowCIDRs, normalized)
	return nil
}

func (m *MockManager) DeleteICMPBlockedCIDR(ifaceName, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.ensureStateLocked(ifaceName)
	_, normalized, err := CIDRToKey(cidr)
	if err != nil {
		return err
	}
	state.icmpBlockCIDRs = deleteSortedCIDR(state.icmpBlockCIDRs, normalized)
	return nil
}

func (m *MockManager) DeletePort(ifaceName string, port uint16) error {
	if err := m.DeletePortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.DeletePortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *MockManager) DeletePublicPort(ifaceName string, port uint16) error {
	if err := m.DeletePublicPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.DeletePublicPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *MockManager) DeleteDeniedPort(ifaceName string, port uint16) error {
	if err := m.DeleteDeniedPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolTCP, Port: port}); err != nil {
		return err
	}
	return m.DeleteDeniedPortRule(ifaceName, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
}

func (m *MockManager) DeletePortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	state.allowedPortRules = deleteSortedPortRule(state.allowedPortRules, rule)
	state.allowedPorts = models.CollapsePortRules(state.allowedPortRules)
	m.bumpPortLocked(state, rule.Port, 0, 2)
	return nil
}

func (m *MockManager) DeletePublicPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	state.publicPortRules = deleteSortedPortRule(state.publicPortRules, rule)
	state.publicPorts = models.CollapsePortRules(state.publicPortRules)
	return nil
}

func (m *MockManager) DeleteDeniedPortRule(ifaceName string, rule models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	state.deniedPortRules = deleteSortedPortRule(state.deniedPortRules, rule)
	state.deniedPorts = models.CollapsePortRules(state.deniedPortRules)
	return nil
}

func (m *MockManager) ReplaceAllowlist(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	for _, cidr := range cidrs {
		if _, _, err := CIDRToKey(cidr); err != nil {
			return err
		}
	}

	state.allowlist = normalizeCIDRs(cidrs)
	state.stats.Passed += uint64(len(state.allowlist))
	m.bumpSourceLocked(state, "10.1.1.20", uint64(len(state.allowlist))*2, 0)
	return nil
}

func (m *MockManager) ReplaceBypassCIDRs(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	for _, cidr := range cidrs {
		if _, _, err := CIDRToKey(cidr); err != nil {
			return err
		}
	}

	state.bypassCIDRs = normalizeCIDRs(cidrs)
	return nil
}

func (m *MockManager) ReplaceBlockedCIDRs(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	for _, cidr := range cidrs {
		if _, _, err := CIDRToKey(cidr); err != nil {
			return err
		}
	}

	state.blockCIDRs = normalizeCIDRs(cidrs)
	return nil
}

func (m *MockManager) ReplaceICMPAllowCIDRs(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.ensureStateLocked(ifaceName)
	state.icmpAllowCIDRs = normalizeCIDRs(cidrs)
	return nil
}

func (m *MockManager) ReplaceICMPBlockedCIDRs(ifaceName string, cidrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.ensureStateLocked(ifaceName)
	state.icmpBlockCIDRs = normalizeCIDRs(cidrs)
	return nil
}

func (m *MockManager) ReplacePorts(ifaceName string, ports []uint16) error {
	rules := make([]models.PortRule, 0, len(ports)*2)
	for _, port := range normalizePorts(ports) {
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolTCP, Port: port})
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
	}
	return m.ReplacePortRules(ifaceName, rules)
}

func (m *MockManager) ReplacePublicPorts(ifaceName string, ports []uint16) error {
	rules := make([]models.PortRule, 0, len(ports)*2)
	for _, port := range normalizePorts(ports) {
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolTCP, Port: port})
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
	}
	return m.ReplacePublicPortRules(ifaceName, rules)
}

func (m *MockManager) ReplaceDeniedPorts(ifaceName string, ports []uint16) error {
	rules := make([]models.PortRule, 0, len(ports)*2)
	for _, port := range normalizePorts(ports) {
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolTCP, Port: port})
		rules = append(rules, models.PortRule{Protocol: models.PortProtocolUDP, Port: port})
	}
	return m.ReplaceDeniedPortRules(ifaceName, rules)
}

func (m *MockManager) ReplacePortRules(ifaceName string, rules []models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	state.allowedPortRules = normalizePortRules(rules, nil)
	state.allowedPorts = models.CollapsePortRules(state.allowedPortRules)
	for _, rule := range state.allowedPortRules {
		m.bumpPortLocked(state, rule.Port, 8, 0)
	}
	return nil
}

func (m *MockManager) ReplacePublicPortRules(ifaceName string, rules []models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	state.publicPortRules = normalizePortRules(rules, nil)
	state.publicPorts = models.CollapsePortRules(state.publicPortRules)
	for _, rule := range state.publicPortRules {
		m.bumpPortLocked(state, rule.Port, 10, 0)
	}
	return nil
}

func (m *MockManager) ReplaceDeniedPortRules(ifaceName string, rules []models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	state.deniedPortRules = normalizePortRules(rules, nil)
	state.deniedPorts = models.CollapsePortRules(state.deniedPortRules)
	for _, rule := range state.deniedPortRules {
		m.bumpPortLocked(state, rule.Port, 0, 9)
	}
	return nil
}

func (m *MockManager) ReplaceRateLimitRules(ifaceName string, rules []models.RateLimitRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	normalized, err := normalizeRateLimitRules(rules)
	if err != nil {
		return err
	}
	state.rateLimitRules = normalized
	return nil
}

func (m *MockManager) ListCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}

	return slices.Clone(state.allowlist), nil
}

func (m *MockManager) ListBypassCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}

	return slices.Clone(state.bypassCIDRs), nil
}

func (m *MockManager) ListBlockedCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	return slices.Clone(state.blockCIDRs), nil
}

func (m *MockManager) ListICMPAllowCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	return slices.Clone(state.icmpAllowCIDRs), nil
}

func (m *MockManager) ListICMPBlockedCIDRs(ifaceName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	return slices.Clone(state.icmpBlockCIDRs), nil
}

func (m *MockManager) ListPorts(ifaceName string) ([]uint16, error) {
	rules, err := m.ListPortRules(ifaceName)
	if err != nil {
		return nil, err
	}
	return models.CollapsePortRules(rules), nil
}

func (m *MockManager) ListPublicPorts(ifaceName string) ([]uint16, error) {
	rules, err := m.ListPublicPortRules(ifaceName)
	if err != nil {
		return nil, err
	}
	return models.CollapsePortRules(rules), nil
}

func (m *MockManager) ListDeniedPorts(ifaceName string) ([]uint16, error) {
	rules, err := m.ListDeniedPortRules(ifaceName)
	if err != nil {
		return nil, err
	}
	return models.CollapsePortRules(rules), nil
}

func (m *MockManager) ListPortRules(ifaceName string) ([]models.PortRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	return slices.Clone(state.allowedPortRules), nil
}

func (m *MockManager) ListPublicPortRules(ifaceName string) ([]models.PortRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	return slices.Clone(state.publicPortRules), nil
}

func (m *MockManager) ListDeniedPortRules(ifaceName string) ([]models.PortRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state := m.ensureStateLocked(ifaceName)
	return slices.Clone(state.deniedPortRules), nil
}

func (m *MockManager) ReadStats(ifaceName string) (models.InterfaceStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return models.InterfaceStats{}, errNotAttached
	}

	if state.attached {
		state.stats.Passed += 1
		m.bumpSourceLocked(state, "10.0.0.10", 1, 0)
		m.bumpSourceLocked(state, "203.0.113.9", 0, 1)
		m.bumpPortLocked(state, 443, 2, 0)
		m.bumpPortLocked(state, 80, 0, 1)
	}
	return state.stats, nil
}

func (m *MockManager) ReadConfig(ifaceName string) (Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return Config{}, errNotAttached
	}

	return state.cfg, nil
}

func (m *MockManager) WriteConfig(ifaceName string, cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.ensureStateLocked(ifaceName)
	if _, err := configToValue(cfg); err != nil {
		return err
	}
	state.cfg = Config{
		NonIPv4Action:        defaultNonIPv4(cfg.NonIPv4Action),
		PortPolicyEnabled:    cfg.PortPolicyEnabled,
		RateLimitEnabled:     cfg.RateLimitEnabled,
		PolicyEnforced:       cfg.PolicyEnforced,
		EgressPolicyEnforced: cfg.EgressPolicyEnforced,
		ObserveOnly:          cfg.ObserveOnly,
	}
	return nil
}

func (m *MockManager) Runtime(ifaceName string) (Runtime, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return Runtime{Interface: ifaceName}, nil
	}

	return Runtime{
		Interface:        ifaceName,
		Attached:         state.attached,
		Mode:             state.mode,
		BypassCIDRs:      slices.Clone(state.bypassCIDRs),
		BlockedCIDRs:     slices.Clone(state.blockCIDRs),
		ICMPAllowCIDRs:   slices.Clone(state.icmpAllowCIDRs),
		ICMPBlockedCIDRs: slices.Clone(state.icmpBlockCIDRs),
		Allowlist:        slices.Clone(state.allowlist),
		PublicPorts:      slices.Clone(state.publicPorts),
		DeniedPorts:      slices.Clone(state.deniedPorts),
		AllowedPorts:     slices.Clone(state.allowedPorts),
		PublicPortRules:  slices.Clone(state.publicPortRules),
		DeniedPortRules:  slices.Clone(state.deniedPortRules),
		AllowedPortRules: slices.Clone(state.allowedPortRules),
		RateLimitRules:   slices.Clone(state.rateLimitRules),
		Config:           state.cfg,
		ObjectPath:       "mock://nodewall",
		ProgramLoaded:    state.attached,
	}, nil
}

func (m *MockManager) Interfaces() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]string, 0, len(m.states))
	for iface := range m.states {
		out = append(out, iface)
	}
	slices.Sort(out)
	return out
}

func (m *MockManager) DiscoverInterfaces() (models.InterfaceInventory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	inventory, err := DetectHostInterfaces()
	if err != nil || len(inventory.Interfaces) == 0 {
		inventory = mockInventory()
	}

	return mergeInventoryWithStates(inventory, uniqueSortedStrings(func() []string {
		out := make([]string, 0, len(m.states))
		for iface := range m.states {
			out = append(out, iface)
		}
		return out
	}())), nil
}

func (m *MockManager) ReadSourceStats(ifaceName string, limit int) ([]models.SourceStat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	if state.sourceStats == nil {
		state.sourceStats = make(map[string]models.SourceStat)
	}
	m.bumpSourceLocked(state, "203.0.113.9", 0, 1)

	out := make([]models.SourceStat, 0, len(state.sourceStats))
	for _, item := range state.sourceStats {
		item.Total = item.Passed + item.Dropped
		if item.Total > 0 {
			item.DropRatio = float64(item.Dropped) / float64(item.Total)
		}
		item.Risk = classifyRisk(item.Passed, item.Dropped)
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b models.SourceStat) int {
		switch {
		case a.Dropped > b.Dropped:
			return -1
		case a.Dropped < b.Dropped:
			return 1
		case a.Passed > b.Passed:
			return -1
		case a.Passed < b.Passed:
			return 1
		default:
			return 0
		}
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MockManager) ReadPortStats(ifaceName string, limit int) ([]models.PortStat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	if state.portStats == nil {
		state.portStats = make(map[uint16]models.PortStat)
	}
	m.bumpPortLocked(state, 443, 3, 0)
	m.bumpPortLocked(state, 80, 0, 2)

	out := make([]models.PortStat, 0, len(state.portStats))
	for _, item := range state.portStats {
		item.Total = item.Passed + item.Dropped
		item.Risk = classifyRisk(item.Passed, item.Dropped)
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b models.PortStat) int {
		switch {
		case a.Dropped > b.Dropped:
			return -1
		case a.Dropped < b.Dropped:
			return 1
		case a.Passed > b.Passed:
			return -1
		case a.Passed < b.Passed:
			return 1
		default:
			return 0
		}
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MockManager) ReadDropLogs(ifaceName string, limit int) ([]models.InterceptLogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	if state.dropLogs == nil {
		state.dropLogs = make(map[string]models.InterceptLogEntry)
	}
	m.bumpDropLogLocked(state, "192.168.5.200", 8080, "source_not_allowed", 2)

	out := make([]models.InterceptLogEntry, 0, len(state.dropLogs))
	for _, item := range state.dropLogs {
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b models.InterceptLogEntry) int {
		switch {
		case a.Drops > b.Drops:
			return -1
		case a.Drops < b.Drops:
			return 1
		default:
			return 0
		}
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MockManager) ReadReplyAllowLogs(ifaceName string, limit int) ([]models.InterceptLogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ifaceName]
	if !ok {
		return nil, errNotAttached
	}
	if state.replyLogs == nil {
		state.replyLogs = make(map[string]models.InterceptLogEntry)
	}
	m.bumpReplyLogLocked(state, "223.5.5.5", 53000, 3)

	out := make([]models.InterceptLogEntry, 0, len(state.replyLogs))
	for _, item := range state.replyLogs {
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b models.InterceptLogEntry) int {
		switch {
		case a.Drops > b.Drops:
			return -1
		case a.Drops < b.Drops:
			return 1
		default:
			return 0
		}
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MockManager) ensureStateLocked(ifaceName string) *mockState {
	state, ok := m.states[ifaceName]
	if ok {
		return state
	}

	state = &mockState{
		mode:         AttachModeNative,
		cfg:          Config{NonIPv4Action: models.NonIPv4Pass},
		allowlist:    nil,
		allowedPorts: nil,
		sourceStats:  make(map[string]models.SourceStat),
		portStats:    make(map[uint16]models.PortStat),
		dropLogs:     make(map[string]models.InterceptLogEntry),
		replyLogs:    make(map[string]models.InterceptLogEntry),
	}
	m.states[ifaceName] = state
	return state
}

func (m *MockManager) bumpSourceLocked(state *mockState, source string, passed, dropped uint64) {
	item := state.sourceStats[source]
	item.SourceIP = source
	item.Passed += passed
	item.Dropped += dropped
	item.Total = item.Passed + item.Dropped
	if item.Total > 0 {
		item.DropRatio = float64(item.Dropped) / float64(item.Total)
	}
	item.Risk = classifyRisk(item.Passed, item.Dropped)
	state.sourceStats[source] = item
}

func (m *MockManager) bumpPortLocked(state *mockState, port uint16, passed, dropped uint64) {
	item := state.portStats[port]
	item.Port = port
	item.Passed += passed
	item.Dropped += dropped
	item.Total = item.Passed + item.Dropped
	item.Risk = classifyRisk(item.Passed, item.Dropped)
	state.portStats[port] = item
}

func (m *MockManager) bumpDropLogLocked(state *mockState, source string, port uint16, reason string, drops uint64) {
	key := fmt.Sprintf("%s|%d|%s", source, port, reason)
	item := state.dropLogs[key]
	item.Direction = models.DirectionIngress
	item.SourceIP = source
	item.Port = port
	item.Reason = reason
	item.Count += drops
	item.Drops += drops
	state.dropLogs[key] = item
}

func (m *MockManager) bumpReplyLogLocked(state *mockState, source string, port uint16, count uint64) {
	key := fmt.Sprintf("%s|%d|reply_flow_allowed", source, port)
	item := state.replyLogs[key]
	item.Direction = models.DirectionIngress
	item.SourceIP = source
	item.Port = port
	item.Reason = "reply_flow_allowed"
	item.Count += count
	state.replyLogs[key] = item
}

func defaultNonIPv4(action models.NonIPv4Action) models.NonIPv4Action {
	if action == "" {
		return models.NonIPv4Pass
	}
	return action
}

func NewDataplane(mode, objectPath string) (Dataplane, error) {
	switch mode {
	case "", "real":
		return NewManager(objectPath), nil
	case "mock":
		return NewMockManager(), nil
	case "iptables", "legacy", "zstack-iptables":
		return NewIPTablesManager(), nil
	default:
		return nil, fmt.Errorf("unsupported dataplane mode %q", mode)
	}
}
