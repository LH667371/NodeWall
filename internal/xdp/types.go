package xdp

import (
	"errors"

	"nodewall/internal/models"
)

type Dataplane interface {
	UpsertBypassCIDR(ifaceName, cidr string) error
	DeleteBypassCIDR(ifaceName, cidr string) error
	ReplaceBypassCIDRs(ifaceName string, cidrs []string) error
	ListBypassCIDRs(ifaceName string) ([]string, error)
	UpsertBlockedCIDR(ifaceName, cidr string) error
	DeleteBlockedCIDR(ifaceName, cidr string) error
	ReplaceBlockedCIDRs(ifaceName string, cidrs []string) error
	ListBlockedCIDRs(ifaceName string) ([]string, error)
	UpsertICMPAllowCIDR(ifaceName, cidr string) error
	DeleteICMPAllowCIDR(ifaceName, cidr string) error
	ReplaceICMPAllowCIDRs(ifaceName string, cidrs []string) error
	ListICMPAllowCIDRs(ifaceName string) ([]string, error)
	UpsertICMPBlockedCIDR(ifaceName, cidr string) error
	DeleteICMPBlockedCIDR(ifaceName, cidr string) error
	ReplaceICMPBlockedCIDRs(ifaceName string, cidrs []string) error
	ListICMPBlockedCIDRs(ifaceName string) ([]string, error)
	Attach(ifaceName string, mode AttachMode) error
	Detach(ifaceName string) error
	UpsertCIDR(ifaceName, cidr string) error
	DeleteCIDR(ifaceName, cidr string) error
	ReplaceAllowlist(ifaceName string, cidrs []string) error
	ListCIDRs(ifaceName string) ([]string, error)
	UpsertPublicPortRule(ifaceName string, rule models.PortRule) error
	DeletePublicPortRule(ifaceName string, rule models.PortRule) error
	ReplacePublicPortRules(ifaceName string, rules []models.PortRule) error
	ListPublicPortRules(ifaceName string) ([]models.PortRule, error)
	UpsertDeniedPortRule(ifaceName string, rule models.PortRule) error
	DeleteDeniedPortRule(ifaceName string, rule models.PortRule) error
	ReplaceDeniedPortRules(ifaceName string, rules []models.PortRule) error
	ListDeniedPortRules(ifaceName string) ([]models.PortRule, error)
	ReplaceRateLimitRules(ifaceName string, rules []models.RateLimitRule) error
	UpsertPortRule(ifaceName string, rule models.PortRule) error
	DeletePortRule(ifaceName string, rule models.PortRule) error
	ReplacePortRules(ifaceName string, rules []models.PortRule) error
	ListPortRules(ifaceName string) ([]models.PortRule, error)
	UpsertPublicPort(ifaceName string, port uint16) error
	DeletePublicPort(ifaceName string, port uint16) error
	ReplacePublicPorts(ifaceName string, ports []uint16) error
	ListPublicPorts(ifaceName string) ([]uint16, error)
	UpsertDeniedPort(ifaceName string, port uint16) error
	DeleteDeniedPort(ifaceName string, port uint16) error
	ReplaceDeniedPorts(ifaceName string, ports []uint16) error
	ListDeniedPorts(ifaceName string) ([]uint16, error)
	UpsertPort(ifaceName string, port uint16) error
	DeletePort(ifaceName string, port uint16) error
	ReplacePorts(ifaceName string, ports []uint16) error
	ListPorts(ifaceName string) ([]uint16, error)
	ReadStats(ifaceName string) (models.InterfaceStats, error)
	ReadConfig(ifaceName string) (Config, error)
	WriteConfig(ifaceName string, cfg Config) error
	Runtime(ifaceName string) (Runtime, error)
	Interfaces() []string
	DiscoverInterfaces() (models.InterfaceInventory, error)
	ReadSourceStats(ifaceName string, limit int) ([]models.SourceStat, error)
	ReadPortStats(ifaceName string, limit int) ([]models.PortStat, error)
	ReadDropLogs(ifaceName string, limit int) ([]models.InterceptLogEntry, error)
	ReadReplyAllowLogs(ifaceName string, limit int) ([]models.InterceptLogEntry, error)
}

type AttachMode string

const (
	AttachModeNative  AttachMode = "native"
	AttachModeGeneric AttachMode = "generic"
	// AttachModeIPTables identifies the legacy userspace dataplane. It does
	// not attach an XDP program and is only intended for non-Kubernetes hosts
	// whose older kernel cannot load the eBPF implementation.
	AttachModeIPTables AttachMode = "iptables"
)

type Config struct {
	NonIPv4Action           models.NonIPv4Action `json:"non_ipv4_action"`
	PortPolicyEnabled       bool                 `json:"port_policy_enabled"`
	RateLimitEnabled        bool                 `json:"rate_limit_enabled"`
	PolicyEnforced          bool                 `json:"policy_enforced"`
	EgressPolicyEnforced    bool                 `json:"egress_policy_enforced"`
	ObserveOnly             bool                 `json:"observe_only"`
	ReplyFlowTimeoutSeconds int                  `json:"reply_flow_timeout_seconds"`
}

// DirectionPolicy is the policy representation consumed by dataplanes that
// can enforce both ingress and egress traffic. The regular Dataplane
// interface remains focused on the v1 ingress map operations so older or
// observation-only backends can keep their existing implementation.
type DirectionPolicy struct {
	BypassCIDRs      []string
	BlockedCIDRs     []string
	ICMPAllowCIDRs   []string
	ICMPBlockedCIDRs []string
	Allowlist        []string
	PublicPortRules  []models.PortRule
	DeniedPortRules  []models.PortRule
	AllowedPortRules []models.PortRule
	RateLimitRules   []models.RateLimitRule
	TemporaryBlocks  []models.TemporaryBlock
	NonIPv4Action    models.NonIPv4Action
	PolicyEnforced   bool
	ObserveOnly      bool
}

// DirectionalDataplane is implemented by backends that can apply a complete
// direction-specific policy. It is deliberately optional: native XDP still
// handles ingress at the XDP hook and only tracks egress reply flows.
type DirectionalDataplane interface {
	ApplyDirectionPolicy(ifaceName string, direction models.PolicyDirection, policy DirectionPolicy) error
}

// DirectionalStats is optional because native XDP only exposes ingress packet
// disposition counters; the iptables compatibility backend can expose both
// its ingress and egress chains.
type DirectionalStats interface {
	ReadDirectionStats(ifaceName string, direction models.PolicyDirection) (models.InterfaceStats, error)
	ReadDirectionDropLogs(ifaceName string, direction models.PolicyDirection, limit int) ([]models.InterceptLogEntry, error)
	ReadDirectionSourceStats(ifaceName string, direction models.PolicyDirection, limit int) ([]models.SourceStat, error)
	ReadDirectionPortStats(ifaceName string, direction models.PolicyDirection, limit int) ([]models.PortStat, error)
}

type Runtime struct {
	Interface        string
	Attached         bool
	Mode             AttachMode
	BypassCIDRs      []string
	BlockedCIDRs     []string
	ICMPAllowCIDRs   []string
	ICMPBlockedCIDRs []string
	Allowlist        []string
	PublicPorts      []uint16
	DeniedPorts      []uint16
	AllowedPorts     []uint16
	PublicPortRules  []models.PortRule
	DeniedPortRules  []models.PortRule
	AllowedPortRules []models.PortRule
	RateLimitRules   []models.RateLimitRule
	Config           Config
	ObjectPath       string
	ProgramLoaded    bool
}

func IsNotAttached(err error) bool {
	return errors.Is(err, errNotAttached)
}
