package models

import (
	"strings"
	"time"
)

// NonIPv4Action retains its wire name for compatibility; the XDP policy uses
// it for IPv6 while allowing ARP and unrelated Ethernet protocols through.
type NonIPv4Action string
type PolicyDirection string
type PortProtocol string

const (
	NonIPv4Pass NonIPv4Action = "pass"
	NonIPv4Drop NonIPv4Action = "drop"

	DirectionIngress PolicyDirection = "ingress"
	DirectionEgress  PolicyDirection = "egress"

	PortProtocolTCP  PortProtocol = "tcp"
	PortProtocolUDP  PortProtocol = "udp"
	PortProtocolICMP PortProtocol = "icmp"
)

type ACLRule struct {
	CIDR    string `json:"cidr"`
	Action  string `json:"action"`
	Comment string `json:"comment,omitempty"`
}

// RuleDescription stores operator-authored notes separately from packet
// matching data so descriptions work consistently for every rule family.
type RuleDescription struct {
	Kind        string       `json:"kind"`
	Value       string       `json:"value"`
	Protocol    PortProtocol `json:"protocol,omitempty"`
	Description string       `json:"description,omitempty"`
}

type PortRule struct {
	Protocol PortProtocol `json:"protocol"`
	Port     uint16       `json:"port"`
}

type DirectionPolicy struct {
	Enabled          bool              `json:"enabled"`
	Mode             string            `json:"mode"`
	DefaultAction    string            `json:"default_action"`
	NonIPv4Action    NonIPv4Action     `json:"non_ipv4_action"`
	BypassCIDRs      []string          `json:"bypass_cidrs,omitempty"`
	BlockedCIDRs     []string          `json:"blocked_cidrs,omitempty"`
	ICMPAllowCIDRs   []string          `json:"icmp_allow_cidrs,omitempty"`
	ICMPBlockedCIDRs []string          `json:"icmp_blocked_cidrs,omitempty"`
	PublicPorts      []uint16          `json:"public_ports,omitempty"`
	DeniedPorts      []uint16          `json:"denied_ports,omitempty"`
	AllowedPorts     []uint16          `json:"allowed_ports,omitempty"`
	PublicPortRules  []PortRule        `json:"public_port_rules,omitempty"`
	DeniedPortRules  []PortRule        `json:"denied_port_rules,omitempty"`
	AllowedPortRules []PortRule        `json:"allowed_port_rules,omitempty"`
	Challenge        ChallengeSpec     `json:"challenge,omitempty"`
	Rules            []ACLRule         `json:"rules"`
	RuleDescriptions []RuleDescription `json:"rule_descriptions,omitempty"`
	ObserveOnly      bool              `json:"observe_only,omitempty"`
	PendingPublish   *PublishRecord    `json:"pending_publish,omitempty"`
}

type InterfacePolicy struct {
	NodeID           string            `json:"node_id"`
	Interface        string            `json:"interface"`
	Enabled          bool              `json:"enabled"`
	Mode             string            `json:"mode"`
	DefaultAction    string            `json:"default_action"`
	NonIPv4Action    NonIPv4Action     `json:"non_ipv4_action"`
	BypassCIDRs      []string          `json:"bypass_cidrs,omitempty"`
	BlockedCIDRs     []string          `json:"blocked_cidrs,omitempty"`
	ICMPAllowCIDRs   []string          `json:"icmp_allow_cidrs,omitempty"`
	ICMPBlockedCIDRs []string          `json:"icmp_blocked_cidrs,omitempty"`
	PublicPorts      []uint16          `json:"public_ports,omitempty"`
	DeniedPorts      []uint16          `json:"denied_ports,omitempty"`
	AllowedPorts     []uint16          `json:"allowed_ports,omitempty"`
	PublicPortRules  []PortRule        `json:"public_port_rules,omitempty"`
	DeniedPortRules  []PortRule        `json:"denied_port_rules,omitempty"`
	AllowedPortRules []PortRule        `json:"allowed_port_rules,omitempty"`
	Challenge        ChallengeSpec     `json:"challenge,omitempty"`
	Rules            []ACLRule         `json:"rules"`
	RuleDescriptions []RuleDescription `json:"rule_descriptions,omitempty"`
	Ingress          DirectionPolicy   `json:"ingress"`
	Egress           DirectionPolicy   `json:"egress"`
	UpdatedAt        time.Time         `json:"updated_at,omitempty"`
	PendingPublish   *PublishRecord    `json:"pending_publish,omitempty"`
}

type ChallengeSpec struct {
	Enabled          bool     `json:"enabled"`
	Provider         string   `json:"provider,omitempty"`
	ProtectedPorts   []uint16 `json:"protected_ports,omitempty"`
	RequestThreshold uint64   `json:"request_threshold,omitempty"`
}

// SSHTransferPolicy controls SSH application-layer file transfer behavior.
// These settings are applied by sshd, not by the XDP dataplane, because SFTP
// and SCP are encrypted after the SSH session is established.
type SSHTransferPolicy struct {
	BlockSFTP      bool `json:"block_sftp"`
	BlockSCP       bool `json:"block_scp"`
	AuditTransfers bool `json:"audit_transfers"`
	AuditSessions  bool `json:"audit_sessions"`
	AuditCommands  bool `json:"audit_commands"`
	ScanUploads    bool `json:"scan_uploads"`
	// VerifyPaths is retained only to read older state files. New clients must
	// use ScanUploads; uploaded-file checks do not require a configured path.
	VerifyPaths []string `json:"verify_paths,omitempty"`
}

type SSHUploadSecurityStatus struct {
	Enabled       bool       `json:"enabled"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	LastStatus    string     `json:"last_status,omitempty"`
	FilesChecked  int        `json:"files_checked"`
	Findings      int        `json:"findings"`
	LastError     string     `json:"last_error,omitempty"`
}

type SSHIntegrityStatus struct {
	Enabled       bool       `json:"enabled"`
	Paths         []string   `json:"paths,omitempty"`
	BaselineAt    *time.Time `json:"baseline_at,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	BaselineFiles int        `json:"baseline_files"`
	Added         int        `json:"added"`
	Changed       int        `json:"changed"`
	Deleted       int        `json:"deleted"`
	LastError     string     `json:"last_error,omitempty"`
}

// SSHProtectionSettings controls the agent-side SSH failure guard. The guard
// consumes authentication failure events and applies temporary source blocks
// through the existing XDP dataplane. TransferPolicy is kept alongside it so
// the console can manage both SSH-layer controls from one security page.
type SSHProtectionSettings struct {
	Enabled            bool              `json:"enabled"`
	MaxFailures        int               `json:"max_failures"`
	WindowSeconds      int               `json:"window_seconds"`
	BanDurationSeconds int               `json:"ban_duration_seconds"`
	TrustedCIDRs       []string          `json:"trusted_cidrs,omitempty"`
	LogPath            string            `json:"log_path,omitempty"`
	Transfer           SSHTransferPolicy `json:"transfer"`
}

type SSHProtectionStatus struct {
	NodeID            string                  `json:"node_id,omitempty"`
	TransferEffective bool                    `json:"transfer_effective"`
	Settings          SSHProtectionSettings   `json:"settings"`
	Integrity         SSHIntegrityStatus      `json:"integrity"`
	UploadSecurity    SSHUploadSecurityStatus `json:"upload_security"`
	Ports             []uint16                `json:"ports"`
	ActiveBlocks      []TemporaryBlock        `json:"active_blocks"`
	TrackedSources    int                     `json:"tracked_sources"`
	TotalBans         uint64                  `json:"total_bans"`
	LastFailureAt     *time.Time              `json:"last_failure_at,omitempty"`
	LastBanAt         *time.Time              `json:"last_ban_at,omitempty"`
	LastError         string                  `json:"last_error,omitempty"`
}

type DispositionStatus string

const (
	DispositionOpen        DispositionStatus = "open"
	DispositionAllowlisted DispositionStatus = "allowlisted"
	DispositionBypassed    DispositionStatus = "bypassed"
	DispositionBlocked     DispositionStatus = "blocked"
	DispositionRateLimited DispositionStatus = "rate_limited"
	DispositionTempBlocked DispositionStatus = "temp_blocked"
	DispositionReleased    DispositionStatus = "released"
)

type RateLimitRule struct {
	ID                string          `json:"id"`
	Interface         string          `json:"interface"`
	Direction         PolicyDirection `json:"direction,omitempty"`
	SourceIP          string          `json:"source_ip"`
	Protocol          PortProtocol    `json:"protocol"`
	Port              uint16          `json:"port,omitempty"`
	RequestsPerMinute uint64          `json:"requests_per_minute"`
	Burst             uint64          `json:"burst"`
	Mode              string          `json:"mode,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	ExpiresAt         *time.Time      `json:"expires_at,omitempty"`
	Status            string          `json:"status,omitempty"`
}

type TemporaryBlock struct {
	ID        string          `json:"id"`
	Interface string          `json:"interface"`
	Direction PolicyDirection `json:"direction,omitempty"`
	SourceIP  string          `json:"source_ip"`
	Port      uint16          `json:"port,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Status    string          `json:"status,omitempty"`
}

type LogDisposition struct {
	SourceIP  string            `json:"source_ip"`
	Port      uint16            `json:"port,omitempty"`
	Direction PolicyDirection   `json:"direction,omitempty"`
	Status    DispositionStatus `json:"status"`
	Scope     string            `json:"scope,omitempty"`
	Reference string            `json:"reference,omitempty"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type PublishStatus string

const (
	PublishPendingConfirm PublishStatus = "pending_confirm"
	PublishConfirmed      PublishStatus = "confirmed"
	PublishRolledBack     PublishStatus = "rolled_back"
	PublishFailed         PublishStatus = "failed"
)

type PublishRecord struct {
	PublishID       string          `json:"publish_id"`
	NodeID          string          `json:"node_id"`
	Interface       string          `json:"interface"`
	Direction       PolicyDirection `json:"direction,omitempty"`
	PreviousVersion string          `json:"previous_version,omitempty"`
	NewVersion      string          `json:"new_version,omitempty"`
	Status          PublishStatus   `json:"status"`
	ExpiresIn       int             `json:"expires_in,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	ConfirmedAt     *time.Time      `json:"confirmed_at,omitempty"`
}

type InterfaceHealth struct {
	Interface            string    `json:"interface"`
	XDPAttached          bool      `json:"xdp_attached"`
	MapOK                bool      `json:"map_ok"`
	StatsOK              bool      `json:"stats_ok"`
	RateLimitEnforced    bool      `json:"rate_limit_enforced"`
	PolicyEnforced       bool      `json:"policy_enforced"`
	ObserveOnly          bool      `json:"observe_only"`
	EgressPolicyEnforced bool      `json:"egress_policy_enforced"`
	EnforcementOK        bool      `json:"enforcement_ok"`
	LastCheckAt          time.Time `json:"last_check_at"`
	LastError            string    `json:"last_error,omitempty"`
}

type HealthStatus struct {
	NodeID      string            `json:"node_id"`
	Status      string            `json:"status"`
	AgentOK     bool              `json:"agent_ok"`
	Interfaces  []InterfaceHealth `json:"interfaces"`
	LastCheckAt time.Time         `json:"last_check_at"`
}

type Node struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	NameCustomized bool                  `json:"name_customized,omitempty"`
	AgentURL       string                `json:"agent_url"`
	AdvertiseIP    string                `json:"advertise_ip,omitempty"`
	AgentHTTPAddr  string                `json:"agent_http_addr,omitempty"`
	SSH            *SSHConnectionProfile `json:"ssh,omitempty"`
	LastSeenAt     time.Time             `json:"last_seen_at,omitempty"`
}

// SystemMetrics is a dependency-free snapshot collected from the Linux kernel
// pseudo-filesystems. Rates are calculated from the previous snapshot held by
// the agent, so the first sample intentionally reports zero rates.
type SystemMetrics struct {
	NodeID          string                `json:"node_id"`
	CapturedAt      time.Time             `json:"captured_at"`
	SampleSeconds   float64               `json:"sample_seconds"`
	UptimeSeconds   float64               `json:"uptime_seconds"`
	CPU             CPUMetrics            `json:"cpu"`
	Memory          MemoryMetrics         `json:"memory"`
	Network         NetworkMetrics        `json:"network"`
	Disk            DiskMetrics           `json:"disk"`
	Kernel          KernelMetrics         `json:"kernel"`
	Processes       ProcessMetrics        `json:"processes"`
	Sockets         SocketMetrics         `json:"sockets"`
	FileDescriptors FileDescriptorMetrics `json:"file_descriptors"`
	Filesystems     []FilesystemMetric    `json:"filesystems,omitempty"`
	Accelerators    []AcceleratorMetrics  `json:"accelerators,omitempty"`
}

type CPUMetrics struct {
	UsagePercent  float64 `json:"usage_percent"`
	UserPercent   float64 `json:"user_percent"`
	SystemPercent float64 `json:"system_percent"`
	IowaitPercent float64 `json:"iowait_percent"`
	StealPercent  float64 `json:"steal_percent"`
	Cores         int     `json:"cores"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
}

type MemoryMetrics struct {
	TotalBytes      uint64  `json:"total_bytes"`
	UsedBytes       uint64  `json:"used_bytes"`
	AvailableBytes  uint64  `json:"available_bytes"`
	UsedPercent     float64 `json:"used_percent"`
	CachedBytes     uint64  `json:"cached_bytes"`
	SwapTotalBytes  uint64  `json:"swap_total_bytes"`
	SwapUsedBytes   uint64  `json:"swap_used_bytes"`
	SwapUsedPercent float64 `json:"swap_used_percent"`
}

type NetworkMetrics struct {
	RxBytesPerSecond   float64                  `json:"rx_bytes_per_second"`
	TxBytesPerSecond   float64                  `json:"tx_bytes_per_second"`
	RxPacketsPerSecond float64                  `json:"rx_packets_per_second"`
	TxPacketsPerSecond float64                  `json:"tx_packets_per_second"`
	RxErrorsPerSecond  float64                  `json:"rx_errors_per_second"`
	TxErrorsPerSecond  float64                  `json:"tx_errors_per_second"`
	RxDroppedPerSecond float64                  `json:"rx_dropped_per_second"`
	TxDroppedPerSecond float64                  `json:"tx_dropped_per_second"`
	RxBytes            uint64                   `json:"rx_bytes"`
	TxBytes            uint64                   `json:"tx_bytes"`
	RxPackets          uint64                   `json:"rx_packets"`
	TxPackets          uint64                   `json:"tx_packets"`
	RxErrors           uint64                   `json:"rx_errors"`
	TxErrors           uint64                   `json:"tx_errors"`
	RxDropped          uint64                   `json:"rx_dropped"`
	TxDropped          uint64                   `json:"tx_dropped"`
	Interfaces         []NetworkInterfaceMetric `json:"interfaces,omitempty"`
}

type NetworkInterfaceMetric struct {
	Name               string  `json:"name"`
	OperationalState   string  `json:"operational_state,omitempty"`
	RxBytes            uint64  `json:"rx_bytes"`
	TxBytes            uint64  `json:"tx_bytes"`
	RxPackets          uint64  `json:"rx_packets"`
	TxPackets          uint64  `json:"tx_packets"`
	RxErrors           uint64  `json:"rx_errors"`
	TxErrors           uint64  `json:"tx_errors"`
	RxDropped          uint64  `json:"rx_dropped"`
	TxDropped          uint64  `json:"tx_dropped"`
	RxBytesPerSecond   float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond   float64 `json:"tx_bytes_per_second"`
	RxPacketsPerSecond float64 `json:"rx_packets_per_second"`
	TxPacketsPerSecond float64 `json:"tx_packets_per_second"`
	RxErrorsPerSecond  float64 `json:"rx_errors_per_second"`
	TxErrorsPerSecond  float64 `json:"tx_errors_per_second"`
	RxDroppedPerSecond float64 `json:"rx_dropped_per_second"`
	TxDroppedPerSecond float64 `json:"tx_dropped_per_second"`
}

// DiskMetrics follows the useful subset of node_exporter disk counters. Raw
// counters are retained for audit/detail views; rates are calculated by the
// agent from the previous sample.
type DiskMetrics struct {
	ReadBytesPerSecond     float64            `json:"read_bytes_per_second"`
	WriteBytesPerSecond    float64            `json:"write_bytes_per_second"`
	ReadOpsPerSecond       float64            `json:"read_ops_per_second"`
	WriteOpsPerSecond      float64            `json:"write_ops_per_second"`
	IOUtilizationPercent   float64            `json:"io_utilization_percent"`
	ReadAwaitMilliseconds  float64            `json:"read_await_milliseconds"`
	WriteAwaitMilliseconds float64            `json:"write_await_milliseconds"`
	ReadBytes              uint64             `json:"read_bytes"`
	WriteBytes             uint64             `json:"write_bytes"`
	ReadOps                uint64             `json:"read_ops"`
	WriteOps               uint64             `json:"write_ops"`
	Devices                []DiskDeviceMetric `json:"devices,omitempty"`
}

type DiskDeviceMetric struct {
	Name                   string  `json:"name"`
	ReadBytes              uint64  `json:"read_bytes"`
	WriteBytes             uint64  `json:"write_bytes"`
	ReadOps                uint64  `json:"read_ops"`
	WriteOps               uint64  `json:"write_ops"`
	ReadBytesPerSecond     float64 `json:"read_bytes_per_second"`
	WriteBytesPerSecond    float64 `json:"write_bytes_per_second"`
	ReadOpsPerSecond       float64 `json:"read_ops_per_second"`
	WriteOpsPerSecond      float64 `json:"write_ops_per_second"`
	IOUtilizationPercent   float64 `json:"io_utilization_percent"`
	ReadAwaitMilliseconds  float64 `json:"read_await_milliseconds"`
	WriteAwaitMilliseconds float64 `json:"write_await_milliseconds"`
}

// KernelMetrics mirrors node_exporter names such as ctxt, intr, forks,
// procs_running and procs_blocked while presenting them as one API object.
type KernelMetrics struct {
	ContextSwitches          uint64  `json:"context_switches"`
	ContextSwitchesPerSecond float64 `json:"context_switches_per_second"`
	Interrupts               uint64  `json:"interrupts"`
	InterruptsPerSecond      float64 `json:"interrupts_per_second"`
	Forks                    uint64  `json:"forks"`
	ForksPerSecond           float64 `json:"forks_per_second"`
	ProcessesRunning         uint64  `json:"processes_running"`
	ProcessesBlocked         uint64  `json:"processes_blocked"`
}

type ProcessMetrics struct {
	Total   uint64          `json:"total"`
	Running uint64          `json:"running"`
	Blocked uint64          `json:"blocked"`
	Top     []ProcessMetric `json:"top,omitempty"`
}

type SocketMetrics struct {
	Used         uint64 `json:"used"`
	TCPInUse     uint64 `json:"tcp_in_use"`
	TCPOrphan    uint64 `json:"tcp_orphan"`
	TCPTimeWait  uint64 `json:"tcp_time_wait"`
	TCPAllocated uint64 `json:"tcp_allocated"`
	UDPInUse     uint64 `json:"udp_in_use"`
}

type FileDescriptorMetrics struct {
	Allocated   uint64  `json:"allocated"`
	Unused      uint64  `json:"unused"`
	Maximum     uint64  `json:"maximum"`
	UsedPercent float64 `json:"used_percent"`
}

type ProcessMetric struct {
	PID           int     `json:"pid"`
	Name          string  `json:"name"`
	State         string  `json:"state"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryBytes   uint64  `json:"memory_bytes"`
	MemoryPercent float64 `json:"memory_percent"`
}

type FilesystemMetric struct {
	Device         string  `json:"device"`
	Mountpoint     string  `json:"mountpoint"`
	FSType         string  `json:"fstype"`
	TotalBytes     uint64  `json:"total_bytes"`
	FreeBytes      uint64  `json:"free_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

// SystemMetricPoint is a compact time-series sample used by the monitoring
// console. It intentionally contains rates and percentages rather than raw
// counters so the browser can render a useful chart without knowing how the
// Linux proc counters are calculated.
type SystemMetricPoint struct {
	CPUCores                   int       `json:"cpu_cores"`
	MemoryTotalBytes           float64   `json:"memory_total_bytes"`
	Timestamp                  time.Time `json:"timestamp"`
	NodeID                     string    `json:"node_id,omitempty"`
	UptimeSeconds              float64   `json:"uptime_seconds"`
	CPUPercent                 float64   `json:"cpu_percent"`
	CPUUserPercent             float64   `json:"cpu_user_percent"`
	CPUSystemPercent           float64   `json:"cpu_system_percent"`
	CPUIowaitPercent           float64   `json:"cpu_iowait_percent"`
	CPUStealPercent            float64   `json:"cpu_steal_percent"`
	Load1                      float64   `json:"load_1"`
	Load5                      float64   `json:"load_5"`
	Load15                     float64   `json:"load_15"`
	MemoryPercent              float64   `json:"memory_percent"`
	MemoryUsedBytes            float64   `json:"memory_used_bytes"`
	MemoryAvailableBytes       float64   `json:"memory_available_bytes"`
	SwapUsedBytes              float64   `json:"swap_used_bytes"`
	SwapUsedPercent            float64   `json:"swap_used_percent"`
	RxBytesPerSecond           float64   `json:"rx_bytes_per_second"`
	TxBytesPerSecond           float64   `json:"tx_bytes_per_second"`
	RxPacketsPerSecond         float64   `json:"rx_packets_per_second"`
	TxPacketsPerSecond         float64   `json:"tx_packets_per_second"`
	RxErrorsPerSecond          float64   `json:"rx_errors_per_second"`
	TxErrorsPerSecond          float64   `json:"tx_errors_per_second"`
	RxDroppedPerSecond         float64   `json:"rx_dropped_per_second"`
	TxDroppedPerSecond         float64   `json:"tx_dropped_per_second"`
	DiskReadBytesPerSecond     float64   `json:"disk_read_bytes_per_second"`
	DiskWriteBytesPerSecond    float64   `json:"disk_write_bytes_per_second"`
	DiskReadOpsPerSecond       float64   `json:"disk_read_ops_per_second"`
	DiskWriteOpsPerSecond      float64   `json:"disk_write_ops_per_second"`
	DiskIOUtilizationPercent   float64   `json:"disk_io_utilization_percent"`
	DiskReadAwaitMilliseconds  float64   `json:"disk_read_await_milliseconds"`
	DiskWriteAwaitMilliseconds float64   `json:"disk_write_await_milliseconds"`
	FilesystemUsedPercent      float64   `json:"filesystem_used_percent"`
	FilesystemAvailableBytes   float64   `json:"filesystem_available_bytes"`
	ContextSwitchesPerSecond   float64   `json:"context_switches_per_second"`
	InterruptsPerSecond        float64   `json:"interrupts_per_second"`
	ForksPerSecond             float64   `json:"forks_per_second"`
	ProcessesTotal             float64   `json:"processes_total"`
	ProcessesRunning           float64   `json:"processes_running"`
	ProcessesBlocked           float64   `json:"processes_blocked"`
	TCPInUse                   float64   `json:"tcp_in_use"`
	TCPTimeWait                float64   `json:"tcp_time_wait"`
	UDPInUse                   float64   `json:"udp_in_use"`
	FileDescriptorsAllocated   float64   `json:"file_descriptors_allocated"`
	FileDescriptorsMaximum     float64   `json:"file_descriptors_maximum"`
	FileDescriptorsUsedPercent float64   `json:"file_descriptors_used_percent"`
}

type SystemMetricNodeSummary struct {
	NodeID           string                `json:"node_id"`
	Name             string                `json:"name"`
	Status           string                `json:"status"`
	Timestamp        time.Time             `json:"timestamp,omitempty"`
	UptimeSeconds    float64               `json:"uptime_seconds"`
	CPUCores         int                   `json:"cpu_cores"`
	CPUPercent       float64               `json:"cpu_percent"`
	MemoryPercent    float64               `json:"memory_percent"`
	MemoryTotalBytes uint64                `json:"memory_total_bytes"`
	MemoryUsedBytes  uint64                `json:"memory_used_bytes"`
	SwapUsedBytes    uint64                `json:"swap_used_bytes"`
	Sockets          SocketMetrics         `json:"sockets"`
	FileDescriptors  FileDescriptorMetrics `json:"file_descriptors"`
	RxBytesPerSecond float64               `json:"rx_bytes_per_second"`
	TxBytesPerSecond float64               `json:"tx_bytes_per_second"`
	Disk             DiskMetrics           `json:"disk"`
	Kernel           KernelMetrics         `json:"kernel"`
	Processes        ProcessMetrics        `json:"processes"`
	Filesystems      []FilesystemMetric    `json:"filesystems,omitempty"`
}

// SystemMetricsHistory is the server-side response for the Grafana-like
// monitoring view. The control plane persists samples independently of browsers
// and returns bounded, time-bucketed points for long-range queries.
type SystemMetricsHistory struct {
	Scope                 string                    `json:"scope"`
	NodeID                string                    `json:"node_id,omitempty"`
	RangeSeconds          int                       `json:"range_seconds"`
	SampleIntervalSeconds int                       `json:"sample_interval_seconds"`
	RetentionSeconds      int                       `json:"retention_seconds"`
	StorageError          string                    `json:"storage_error,omitempty"`
	Points                []SystemMetricPoint       `json:"points"`
	Nodes                 []SystemMetricNodeSummary `json:"nodes"`
}

// AcceleratorMetrics deliberately has no vendor-specific dependency. An
// NVIDIA collector can populate this later by reading a supported kernel
// interface without changing the API shape.
type AcceleratorMetrics struct {
	Vendor             string  `json:"vendor"`
	Index              int     `json:"index"`
	Name               string  `json:"name,omitempty"`
	MemoryTotalBytes   uint64  `json:"memory_total_bytes,omitempty"`
	MemoryUsedBytes    uint64  `json:"memory_used_bytes,omitempty"`
	UtilizationPercent float64 `json:"utilization_percent,omitempty"`
	TemperatureC       float64 `json:"temperature_c,omitempty"`
}

// SSHConnectionProfile stores only connection metadata. Authentication
// secrets stay with the operator's local SSH client and are never persisted.
type SSHConnectionProfile struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	User string `json:"user"`
}

type InterfaceRuntime struct {
	// Recovery survives an agent restart while an automatic connectivity check
	// is pending. A restart restores these snapshots before attaching anything.
	Recovery         map[PolicyDirection]DirectionRuntime `json:"safety_recovery,omitempty"`
	Interface        string                               `json:"interface"`
	Attached         bool                                 `json:"attached"`
	AttachMode       string                               `json:"attach_mode,omitempty"`
	BypassCIDRs      []string                             `json:"bypass_cidrs,omitempty"`
	BlockedCIDRs     []string                             `json:"blocked_cidrs,omitempty"`
	ICMPAllowCIDRs   []string                             `json:"icmp_allow_cidrs,omitempty"`
	ICMPBlockedCIDRs []string                             `json:"icmp_blocked_cidrs,omitempty"`
	Allowlist        []string                             `json:"allowlist"`
	PublicPorts      []uint16                             `json:"public_ports,omitempty"`
	DeniedPorts      []uint16                             `json:"denied_ports,omitempty"`
	AllowedPorts     []uint16                             `json:"allowed_ports,omitempty"`
	PublicPortRules  []PortRule                           `json:"public_port_rules,omitempty"`
	DeniedPortRules  []PortRule                           `json:"denied_port_rules,omitempty"`
	AllowedPortRules []PortRule                           `json:"allowed_port_rules,omitempty"`
	NonIPv4Action    NonIPv4Action                        `json:"non_ipv4_action"`
	// EnforcementConfirmed is set only after an explicit enforcing policy
	// publish. A newly attached interface remains observe-only until that
	// confirmation, so adding one allow rule cannot silently default-deny the
	// rest of a ZStack bridge.
	EnforcementConfirmed bool             `json:"enforcement_confirmed,omitempty"`
	ObserveOnly          bool             `json:"observe_only,omitempty"`
	Challenge            ChallengeSpec    `json:"challenge,omitempty"`
	RateLimits           []RateLimitRule  `json:"rate_limits,omitempty"`
	TemporaryBlocks      []TemporaryBlock `json:"temporary_blocks,omitempty"`
	Egress               DirectionRuntime `json:"egress"`
	PendingPublish       *PublishRecord   `json:"pending_publish,omitempty"`
	LastUpdatedAt        time.Time        `json:"last_updated_at"`
	LastStats            *InterfaceStats  `json:"last_stats,omitempty"`
	Trend                []TrafficPoint   `json:"trend,omitempty"`
}

type DirectionRuntime struct {
	Attached         bool             `json:"attached"`
	AttachMode       string           `json:"attach_mode,omitempty"`
	BypassCIDRs      []string         `json:"bypass_cidrs,omitempty"`
	BlockedCIDRs     []string         `json:"blocked_cidrs,omitempty"`
	ICMPAllowCIDRs   []string         `json:"icmp_allow_cidrs,omitempty"`
	ICMPBlockedCIDRs []string         `json:"icmp_blocked_cidrs,omitempty"`
	Allowlist        []string         `json:"allowlist"`
	PublicPorts      []uint16         `json:"public_ports,omitempty"`
	DeniedPorts      []uint16         `json:"denied_ports,omitempty"`
	AllowedPorts     []uint16         `json:"allowed_ports,omitempty"`
	PublicPortRules  []PortRule       `json:"public_port_rules,omitempty"`
	DeniedPortRules  []PortRule       `json:"denied_port_rules,omitempty"`
	AllowedPortRules []PortRule       `json:"allowed_port_rules,omitempty"`
	NonIPv4Action    NonIPv4Action    `json:"non_ipv4_action"`
	Challenge        ChallengeSpec    `json:"challenge,omitempty"`
	RateLimits       []RateLimitRule  `json:"rate_limits,omitempty"`
	TemporaryBlocks  []TemporaryBlock `json:"temporary_blocks,omitempty"`
	ObserveOnly      bool             `json:"observe_only,omitempty"`
	PendingPublish   *PublishRecord   `json:"pending_publish,omitempty"`
	LastUpdatedAt    time.Time        `json:"last_updated_at"`
	LastStats        *InterfaceStats  `json:"last_stats,omitempty"`
	Trend            []TrafficPoint   `json:"trend,omitempty"`
}

type InterfaceStats struct {
	Direction PolicyDirection `json:"direction,omitempty"`
	Passed    uint64          `json:"passed"`
	Dropped   uint64          `json:"dropped"`
}

type SourceStat struct {
	SourceIP    string       `json:"source_ip"`
	Passed      uint64       `json:"passed"`
	Dropped     uint64       `json:"dropped"`
	Total       uint64       `json:"total"`
	DropRatio   float64      `json:"drop_ratio"`
	Risk        string       `json:"risk"`
	Geo         *GeoLocation `json:"geo,omitempty"`
	CountryCode string       `json:"country_code,omitempty"`
	CountryName string       `json:"country_name,omitempty"`
}

type GeoLocation struct {
	ContinentCode string `json:"continent_code,omitempty"`
	ContinentName string `json:"continent_name,omitempty"`
	CountryCode   string `json:"country_code,omitempty"`
	CountryName   string `json:"country_name,omitempty"`
}

type CountryStat struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Total       uint64 `json:"total"`
	Dropped     uint64 `json:"dropped"`
	Sources     uint64 `json:"sources"`
}

type InterfaceInsights struct {
	Direction       PolicyDirection   `json:"direction,omitempty"`
	Interface       string            `json:"interface"`
	TopPassed       []SourceStat      `json:"top_passed"`
	TopDropped      []SourceStat      `json:"top_dropped"`
	TopAttackers    []SourceStat      `json:"top_attackers"`
	TopCountries    []CountryStat     `json:"top_countries,omitempty"`
	TopPorts        []PortStat        `json:"top_ports,omitempty"`
	Trend           []TrafficPoint    `json:"trend"`
	SuggestedBlocks []BlockSuggestion `json:"suggested_blocks"`
	ChallengeAdvice ChallengeAdvice   `json:"challenge_advice,omitempty"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type TrafficPoint struct {
	Timestamp string `json:"timestamp"`
	Passed    uint64 `json:"passed"`
	Dropped   uint64 `json:"dropped"`
}

type BlockSuggestion struct {
	SourceIP      string `json:"source_ip"`
	SuggestedCIDR string `json:"suggested_cidr"`
	Risk          string `json:"risk"`
	Reason        string `json:"reason"`
}

type PortStat struct {
	Port    uint16 `json:"port"`
	Passed  uint64 `json:"passed"`
	Dropped uint64 `json:"dropped"`
	Total   uint64 `json:"total"`
	Risk    string `json:"risk"`
}

type InterceptLogEntry struct {
	Direction   PolicyDirection `json:"direction,omitempty"`
	SourceIP    string          `json:"source_ip"`
	Port        uint16          `json:"port,omitempty"`
	Reason      string          `json:"reason"`
	Count       uint64          `json:"count,omitempty"`
	Drops       uint64          `json:"drops"`
	Geo         *GeoLocation    `json:"geo,omitempty"`
	Disposition *LogDisposition `json:"disposition,omitempty"`
}

type DropLogRecord struct {
	Timestamp   time.Time       `json:"timestamp"`
	NodeID      string          `json:"node_id,omitempty"`
	Interface   string          `json:"interface"`
	Direction   PolicyDirection `json:"direction,omitempty"`
	SourceIP    string          `json:"source_ip"`
	Port        uint16          `json:"port,omitempty"`
	Reason      string          `json:"reason"`
	Count       uint64          `json:"count,omitempty"`
	Drops       uint64          `json:"drops"`
	Geo         *GeoLocation    `json:"geo,omitempty"`
	Disposition *LogDisposition `json:"disposition,omitempty"`
}

type DropLogSettings struct {
	Enabled                 bool   `json:"enabled"`
	LogDir                  string `json:"log_dir"`
	RetentionDays           int    `json:"retention_days"`
	FlushIntervalSeconds    int    `json:"flush_interval_seconds"`
	ReplyFlowTimeoutSeconds int    `json:"reply_flow_timeout_seconds"`
}

type AuthSecuritySettings struct {
	MaxFailures         int `json:"max_failures"`
	WindowSeconds       int `json:"window_seconds"`
	LockDurationSeconds int `json:"lock_duration_seconds"`
	ActiveLocks         int `json:"active_locks,omitempty"`
}

type ChallengeAdvice struct {
	Recommended bool     `json:"recommended"`
	Ports       []uint16 `json:"ports,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Provider    string   `json:"provider,omitempty"`
}

type DetectedInterface struct {
	Name           string             `json:"name"`
	MTU            int                `json:"mtu"`
	Flags          []string           `json:"flags"`
	HardwareAddr   string             `json:"hardware_addr,omitempty"`
	Addresses      []string           `json:"addresses,omitempty"`
	IsUp           bool               `json:"is_up"`
	IsLoopback     bool               `json:"is_loopback"`
	IsPhysical     bool               `json:"is_physical"`
	IsRecommended  bool               `json:"is_recommended"`
	Attached       bool               `json:"attached,omitempty"`
	BypassCIDRs    int                `json:"bypass_cidrs,omitempty"`
	BlockedCIDRs   int                `json:"blocked_cidrs,omitempty"`
	AllowCIDRs     int                `json:"allow_cidrs,omitempty"`
	PublicPorts    int                `json:"public_ports,omitempty"`
	DeniedPorts    int                `json:"denied_ports,omitempty"`
	AllowPorts     int                `json:"allow_ports,omitempty"`
	AttachMode     string             `json:"attach_mode,omitempty"`
	LastPassed     uint64             `json:"last_passed,omitempty"`
	LastDropped    uint64             `json:"last_dropped,omitempty"`
	PendingPublish *PublishRecord     `json:"pending_publish,omitempty"`
	Egress         DirectionInventory `json:"egress,omitempty"`
}

type InterfaceInventory struct {
	Interfaces  []DetectedInterface `json:"interfaces"`
	Recommended string              `json:"recommended,omitempty"`
}

type DirectionInventory struct {
	Attached        bool           `json:"attached"`
	AttachMode      string         `json:"attach_mode,omitempty"`
	BypassCIDRs     int            `json:"bypass_cidrs,omitempty"`
	BlockedCIDRs    int            `json:"blocked_cidrs,omitempty"`
	AllowCIDRs      int            `json:"allow_cidrs,omitempty"`
	PublicPorts     int            `json:"public_ports,omitempty"`
	DeniedPorts     int            `json:"denied_ports,omitempty"`
	AllowPorts      int            `json:"allow_ports,omitempty"`
	LastPassed      uint64         `json:"last_passed,omitempty"`
	LastDropped     uint64         `json:"last_dropped,omitempty"`
	RateLimits      int            `json:"rate_limits,omitempty"`
	TemporaryBlocks int            `json:"temporary_blocks,omitempty"`
	ObserveOnly     bool           `json:"observe_only,omitempty"`
	PendingPublish  *PublishRecord `json:"pending_publish,omitempty"`
}

func DefaultDirectionPolicy(direction PolicyDirection) DirectionPolicy {
	policy := DirectionPolicy{
		Enabled:       true,
		Mode:          "whitelist",
		DefaultAction: "drop",
		NonIPv4Action: NonIPv4Drop,
		Challenge: ChallengeSpec{
			Enabled:          true,
			Provider:         "reverse-proxy",
			ProtectedPorts:   []uint16{80, 443},
			RequestThreshold: 500,
		},
	}
	if direction == DirectionEgress {
		policy.ObserveOnly = true
	}
	return policy
}

func NormalizeInterfacePolicy(policy InterfacePolicy) InterfacePolicy {
	if policy.Ingress.Mode == "" {
		policy.Ingress = DirectionPolicy{
			Enabled:          policy.Enabled,
			Mode:             policy.Mode,
			DefaultAction:    policy.DefaultAction,
			NonIPv4Action:    policy.NonIPv4Action,
			BypassCIDRs:      append([]string(nil), policy.BypassCIDRs...),
			BlockedCIDRs:     append([]string(nil), policy.BlockedCIDRs...),
			ICMPAllowCIDRs:   append([]string(nil), policy.ICMPAllowCIDRs...),
			ICMPBlockedCIDRs: append([]string(nil), policy.ICMPBlockedCIDRs...),
			PublicPorts:      append([]uint16(nil), policy.PublicPorts...),
			DeniedPorts:      append([]uint16(nil), policy.DeniedPorts...),
			AllowedPorts:     append([]uint16(nil), policy.AllowedPorts...),
			PublicPortRules:  append([]PortRule(nil), policy.PublicPortRules...),
			DeniedPortRules:  append([]PortRule(nil), policy.DeniedPortRules...),
			AllowedPortRules: append([]PortRule(nil), policy.AllowedPortRules...),
			Challenge:        policy.Challenge,
			Rules:            append([]ACLRule(nil), policy.Rules...),
			RuleDescriptions: append([]RuleDescription(nil), policy.RuleDescriptions...),
			PendingPublish:   policy.PendingPublish,
		}
	}
	if policy.Egress.Mode == "" {
		policy.Egress = DefaultDirectionPolicy(DirectionEgress)
	}
	if policy.Ingress.Mode == "" {
		policy.Ingress = DefaultDirectionPolicy(DirectionIngress)
	}
	if policy.Ingress.NonIPv4Action == "" {
		policy.Ingress.NonIPv4Action = NonIPv4Drop
	}
	// Older policy files used mode=observe without persisting the explicit
	// observe_only marker. Treat that legacy mode as fail-open so a trial or
	// restart cannot accidentally turn an old policy into enforcement.
	if strings.EqualFold(strings.TrimSpace(policy.Ingress.Mode), "observe") {
		policy.Ingress.ObserveOnly = true
	}
	if strings.EqualFold(strings.TrimSpace(policy.Egress.Mode), "observe") {
		policy.Egress.ObserveOnly = true
	}
	if policy.Egress.NonIPv4Action == "" {
		policy.Egress.NonIPv4Action = NonIPv4Drop
	}
	if policy.Ingress.PendingPublish == nil && policy.PendingPublish != nil {
		pending := *policy.PendingPublish
		policy.Ingress.PendingPublish = &pending
	}
	if policy.PendingPublish == nil && policy.Ingress.PendingPublish != nil {
		pending := *policy.Ingress.PendingPublish
		policy.PendingPublish = &pending
	}
	policy.Enabled = policy.Ingress.Enabled
	policy.Mode = policy.Ingress.Mode
	policy.DefaultAction = policy.Ingress.DefaultAction
	policy.NonIPv4Action = policy.Ingress.NonIPv4Action
	policy.BypassCIDRs = append([]string(nil), policy.Ingress.BypassCIDRs...)
	policy.BlockedCIDRs = append([]string(nil), policy.Ingress.BlockedCIDRs...)
	policy.ICMPAllowCIDRs = append([]string(nil), policy.Ingress.ICMPAllowCIDRs...)
	policy.ICMPBlockedCIDRs = append([]string(nil), policy.Ingress.ICMPBlockedCIDRs...)
	policy.Ingress.PublicPortRules = normalizePortRules(policy.Ingress.PublicPortRules, policy.Ingress.PublicPorts)
	policy.Ingress.DeniedPortRules = normalizePortRules(policy.Ingress.DeniedPortRules, policy.Ingress.DeniedPorts)
	policy.Ingress.AllowedPortRules = normalizePortRules(policy.Ingress.AllowedPortRules, policy.Ingress.AllowedPorts)
	policy.Egress.PublicPortRules = normalizePortRules(policy.Egress.PublicPortRules, policy.Egress.PublicPorts)
	policy.Egress.DeniedPortRules = normalizePortRules(policy.Egress.DeniedPortRules, policy.Egress.DeniedPorts)
	policy.Egress.AllowedPortRules = normalizePortRules(policy.Egress.AllowedPortRules, policy.Egress.AllowedPorts)
	policy.Ingress.PublicPorts = collapsePortRules(policy.Ingress.PublicPortRules)
	policy.Ingress.DeniedPorts = collapsePortRules(policy.Ingress.DeniedPortRules)
	policy.Ingress.AllowedPorts = collapsePortRules(policy.Ingress.AllowedPortRules)
	policy.Egress.PublicPorts = collapsePortRules(policy.Egress.PublicPortRules)
	policy.Egress.DeniedPorts = collapsePortRules(policy.Egress.DeniedPortRules)
	policy.Egress.AllowedPorts = collapsePortRules(policy.Egress.AllowedPortRules)
	policy.Ingress.RuleDescriptions = normalizeRuleDescriptions(policy.Ingress.RuleDescriptions, policy.Ingress.Rules)
	policy.Egress.RuleDescriptions = normalizeRuleDescriptions(policy.Egress.RuleDescriptions, policy.Egress.Rules)
	policy.PublicPortRules = append([]PortRule(nil), policy.Ingress.PublicPortRules...)
	policy.DeniedPortRules = append([]PortRule(nil), policy.Ingress.DeniedPortRules...)
	policy.AllowedPortRules = append([]PortRule(nil), policy.Ingress.AllowedPortRules...)
	policy.PublicPorts = append([]uint16(nil), policy.Ingress.PublicPorts...)
	policy.DeniedPorts = append([]uint16(nil), policy.Ingress.DeniedPorts...)
	policy.AllowedPorts = append([]uint16(nil), policy.Ingress.AllowedPorts...)
	policy.Challenge = policy.Ingress.Challenge
	policy.Rules = append([]ACLRule(nil), policy.Ingress.Rules...)
	policy.RuleDescriptions = append([]RuleDescription(nil), policy.Ingress.RuleDescriptions...)
	if policy.Ingress.PendingPublish != nil {
		pending := *policy.Ingress.PendingPublish
		policy.PendingPublish = &pending
	} else {
		policy.PendingPublish = nil
	}
	return policy
}

func normalizeRuleDescriptions(descriptions []RuleDescription, legacyRules []ACLRule) []RuleDescription {
	seen := make(map[string]int, len(descriptions)+len(legacyRules))
	out := make([]RuleDescription, 0, len(descriptions)+len(legacyRules))
	keyFor := func(item RuleDescription) string {
		return item.Kind + "\x00" + item.Value + "\x00" + string(item.Protocol)
	}
	for _, item := range descriptions {
		item.Kind = strings.TrimSpace(item.Kind)
		item.Value = strings.TrimSpace(item.Value)
		item.Description = strings.TrimSpace(item.Description)
		if item.Kind == "" || item.Value == "" || item.Description == "" {
			continue
		}
		key := keyFor(item)
		if index, ok := seen[key]; ok {
			out[index] = item
			continue
		}
		seen[key] = len(out)
		out = append(out, item)
	}
	for _, rule := range legacyRules {
		value := strings.TrimSpace(rule.CIDR)
		description := strings.TrimSpace(rule.Comment)
		if value == "" || description == "" {
			continue
		}
		item := RuleDescription{Kind: "source", Value: value, Description: description}
		key := keyFor(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = len(out)
		out = append(out, item)
	}
	return out
}

func DirectionPolicyFor(policy InterfacePolicy, direction PolicyDirection) DirectionPolicy {
	policy = NormalizeInterfacePolicy(policy)
	if direction == DirectionEgress {
		return policy.Egress
	}
	return policy.Ingress
}

func WithDirectionPolicy(policy InterfacePolicy, direction PolicyDirection, next DirectionPolicy) InterfacePolicy {
	policy = NormalizeInterfacePolicy(policy)
	if direction == DirectionEgress {
		policy.Egress = next
		return NormalizeInterfacePolicy(policy)
	}
	policy.Ingress = next
	return NormalizeInterfacePolicy(policy)
}

func NormalizePortRules(rules []PortRule, fallbackPorts []uint16) []PortRule {
	return normalizePortRules(rules, fallbackPorts)
}

func CollapsePortRules(rules []PortRule) []uint16 {
	return collapsePortRules(rules)
}

func ParsePortProtocol(value string) PortProtocol {
	switch value {
	case "udp", "UDP":
		return PortProtocolUDP
	case "icmp", "ICMP":
		return PortProtocolICMP
	default:
		return PortProtocolTCP
	}
}

func normalizePortRules(rules []PortRule, fallbackPorts []uint16) []PortRule {
	if len(rules) == 0 && len(fallbackPorts) > 0 {
		expanded := make([]PortRule, 0, len(fallbackPorts)*2)
		for _, port := range fallbackPorts {
			if port == 0 {
				continue
			}
			expanded = append(expanded, PortRule{Protocol: PortProtocolTCP, Port: port})
			expanded = append(expanded, PortRule{Protocol: PortProtocolUDP, Port: port})
		}
		rules = expanded
	}
	if len(rules) == 0 {
		return nil
	}
	seen := map[uint32]struct{}{}
	out := make([]PortRule, 0, len(rules))
	for _, item := range rules {
		protocol := normalizePortProtocol(item.Protocol)
		if item.Port == 0 && protocol != PortProtocolICMP {
			continue
		}
		protoKey := uint32(6)
		if protocol == PortProtocolUDP {
			protoKey = 17
		}
		if protocol == PortProtocolICMP {
			protoKey = 1
		}
		key := uint32(item.Port)<<8 | protoKey
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, PortRule{
			Protocol: protocol,
			Port:     item.Port,
		})
	}
	return out
}

func collapsePortRules(rules []PortRule) []uint16 {
	if len(rules) == 0 {
		return nil
	}
	seen := map[uint16]struct{}{}
	out := make([]uint16, 0, len(rules))
	for _, item := range rules {
		if item.Port == 0 {
			continue
		}
		if _, ok := seen[item.Port]; ok {
			continue
		}
		seen[item.Port] = struct{}{}
		out = append(out, item.Port)
	}
	return out
}

func normalizePortProtocol(protocol PortProtocol) PortProtocol {
	switch protocol {
	case PortProtocolUDP:
		return PortProtocolUDP
	case PortProtocolICMP:
		return PortProtocolICMP
	default:
		return PortProtocolTCP
	}
}
