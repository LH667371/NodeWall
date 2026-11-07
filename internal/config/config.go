package config

import (
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type AgentConfig struct {
	TokenFile              string
	ScanReportDir          string
	ListenAddr             string
	NodeID                 string
	StateFile              string
	DropLogStateFile       string
	DropLogDir             string
	BPFObjectPath          string
	ConfirmTimeout         time.Duration
	DropLogEnabled         bool
	DropLogRetention       int
	DropLogFlush           time.Duration
	ReplyFlowTimeout       time.Duration
	DefaultXDPMode         string
	DataplaneMode          string
	IPTablesReconcileEvery time.Duration
	DevMode                string
	DefaultInterface       string
	DefaultHTTPHost        string
	GeoIPDBPath            string
	ManagerGRPCAddr        string
	ManagerURL             string
	AgentHTTPAddr          string
	AutoUpdate             bool
	AutoUpdateEvery        time.Duration
	SSHProtectionStateFile string
	SSHAuthLogPath         string
	SSHActivityLogPath     string
	SSHProtectionPoll      time.Duration
	TLSEnabled             bool
	TLSCertFile            string
	TLSKeyFile             string
	TLSCAFile              string
	TLSInsecureSkipVerify  bool
	ManagerQUICAddr        string
}

type ServerConfig struct {
	MonitoringHistoryDir   string
	MonitoringHistoryBytes int64
	TokenFile              string
	NodeCredentialsFile    string
	AgentTLSCertFile       string
	AgentTLSKeyFile        string
	InstallMode            string
	ListenAddr             string
	NodeID                 string
	AgentURL               string
	WebDir                 string
	StateFile              string
	AuthSettingsFile       string
	DevMode                string
	DefaultInterface       string
	DefaultXDPMode         string
	AuthEnabled            bool
	AuthFile               string
	AllowedCIDRs           []string
	AllowedIPs             []string
	AllowedMACs            []string
	GRPCListenAddr         string
	QUICListenAddr         string
	WebAccessMode          string
	SSHKeyPath             string
	TLSEnabled             bool
	TLSCertFile            string
	TLSKeyFile             string
	TLSCAFile              string
	TLSInsecureSkipVerify  bool
}

func LoadAgentConfig() AgentConfig {
	devMode := getenv("NODEWALL_DEV_MODE", "")
	tlsDefault := devMode == "" || devMode == "real"
	return AgentConfig{
		ScanReportDir:          getenv("NODEWALL_SCAN_REPORT_DIR", "/var/lib/nodewall/scan-reports"),
		TokenFile:              getenv("NODEWALL_AGENT_TOKEN_FILE", "/etc/nodewall/agent-token"),
		ListenAddr:             getenv("NODEWALL_AGENT_ADDR", "127.0.0.1:9080"),
		NodeID:                 getenv("NODEWALL_NODE_ID", "node-01"),
		StateFile:              getenv("NODEWALL_AGENT_STATE", "examples/agent-state.json"),
		DropLogStateFile:       getenv("NODEWALL_DROP_LOG_STATE", "/etc/nodewall/drop-log-state.json"),
		DropLogDir:             getenv("NODEWALL_LOG_DIR", "/var/lib/nodewall/logs"),
		BPFObjectPath:          getenv("NODEWALL_BPF_OBJECT", "bpf/gen/xdpacl_bpfel.o"),
		ConfirmTimeout:         getDuration("NODEWALL_CONFIRM_TIMEOUT", 180*time.Second),
		DropLogEnabled:         getBool("NODEWALL_DROP_LOG_ENABLED", true),
		DropLogRetention:       getInt("NODEWALL_DROP_LOG_RETENTION_DAYS", 7),
		DropLogFlush:           getDuration("NODEWALL_DROP_LOG_FLUSH_INTERVAL", 30*time.Second),
		ReplyFlowTimeout:       getDuration("NODEWALL_REPLY_FLOW_TIMEOUT", 60*time.Second),
		DefaultXDPMode:         getenv("NODEWALL_XDP_MODE", "native"),
		DataplaneMode:          getenv("NODEWALL_DATAPLANE", "real"),
		IPTablesReconcileEvery: getDuration("NODEWALL_IPTABLES_RECONCILE_INTERVAL", 5*time.Second),
		DevMode:                getenv("NODEWALL_DEV_MODE", ""),
		DefaultInterface:       getenv("NODEWALL_DEFAULT_INTERFACE", ""),
		DefaultHTTPHost:        "127.0.0.1",
		GeoIPDBPath:            getenv("NODEWALL_GEOIP_DB", ""),
		ManagerGRPCAddr:        getenv("NODEWALL_MANAGER_GRPC_ADDR", ""),
		ManagerURL:             getenv("NODEWALL_MANAGER_URL", ""),
		AgentHTTPAddr:          getenv("NODEWALL_AGENT_HTTP_ADDR", ""),
		AutoUpdate:             getBool("NODEWALL_AUTO_UPDATE", true),
		AutoUpdateEvery:        getDuration("NODEWALL_AUTO_UPDATE_INTERVAL", 10*time.Minute),
		SSHProtectionStateFile: getenv("NODEWALL_SSH_PROTECTION_STATE", "/etc/nodewall/ssh-protection.json"),
		SSHAuthLogPath:         getenv("NODEWALL_SSH_AUTH_LOG", ""),
		SSHActivityLogPath:     getenv("NODEWALL_SSH_ACTIVITY_LOG", "/var/log/nodewall/ssh-activity.log"),
		SSHProtectionPoll:      getDuration("NODEWALL_SSH_PROTECTION_POLL", time.Second),
		TLSEnabled:             getBool("NODEWALL_TLS_ENABLED", tlsDefault),
		TLSCertFile:            getenv("NODEWALL_TLS_CERT", "/etc/nodewall/tls/agent.crt"),
		TLSKeyFile:             getenv("NODEWALL_TLS_KEY", "/etc/nodewall/tls/agent.key"),
		TLSCAFile:              getenv("NODEWALL_TLS_CA", ""),
		TLSInsecureSkipVerify:  getBool("NODEWALL_TLS_INSECURE_SKIP_VERIFY", true),
		ManagerQUICAddr:        getenv("NODEWALL_MANAGER_QUIC_ADDR", ""),
	}
}

func LoadServerConfig() ServerConfig {
	devMode := getenv("NODEWALL_DEV_MODE", "")
	tlsDefault := devMode == "" || devMode == "real"
	agentURL := getenv("NODEWALL_AGENT_URL", "")
	if agentURL == "" {
		scheme := "http"
		if tlsDefault || getBool("NODEWALL_TLS_ENABLED", tlsDefault) {
			scheme = "https"
		}
		agentURL = scheme + "://127.0.0.1:9080"
	}
	if endpoint, err := url.Parse(agentURL); err == nil && (endpoint.Hostname() == "0.0.0.0" || endpoint.Hostname() == "::") {
		endpoint.Host = net.JoinHostPort("127.0.0.1", endpoint.Port())
		agentURL = endpoint.String()
	}
	return ServerConfig{
		MonitoringHistoryDir:   getenv("NODEWALL_MONITORING_HISTORY_DIR", "/var/lib/nodewall/monitoring"),
		MonitoringHistoryBytes: int64(getInt("NODEWALL_MONITORING_HISTORY_MIB", 512)) << 20,
		TokenFile:              getenv("NODEWALL_AGENT_TOKEN_FILE", "/etc/nodewall/agent-token"),
		NodeCredentialsFile:    getenv("NODEWALL_NODE_CREDENTIALS_FILE", "/etc/nodewall/node-credentials.json"),
		AgentTLSCertFile:       getenv("NODEWALL_AGENT_TLS_CERT", getenv("NODEWALL_TLS_CERT", "/etc/nodewall/tls/agent.crt")),
		AgentTLSKeyFile:        getenv("NODEWALL_AGENT_TLS_KEY", getenv("NODEWALL_TLS_KEY", "/etc/nodewall/tls/agent.key")),
		InstallMode:            getenv("NODEWALL_INSTALL_MODE", "all-in-one"),
		// The authenticated server is the management entry point. Keep it
		// reachable on the host's interfaces by default; deployments that need a
		// loopback-only listener can still set NODEWALL_SERVER_ADDR explicitly.
		ListenAddr:            getenv("NODEWALL_SERVER_ADDR", "0.0.0.0:8080"),
		NodeID:                getenv("NODEWALL_NODE_ID", "node-01"),
		AgentURL:              agentURL,
		WebDir:                getenv("NODEWALL_WEB_DIR", "web/dist"),
		StateFile:             getenv("NODEWALL_SERVER_STATE", "/etc/nodewall/server-state.json"),
		AuthSettingsFile:      getenv("NODEWALL_AUTH_SETTINGS_FILE", "/etc/nodewall/auth-settings.json"),
		DevMode:               devMode,
		DefaultInterface:      getenv("NODEWALL_DEFAULT_INTERFACE", ""),
		DefaultXDPMode:        getenv("NODEWALL_XDP_MODE", "native"),
		AuthEnabled:           getBool("NODEWALL_AUTH_ENABLED", devMode == "" || devMode == "real"),
		AuthFile:              getenv("NODEWALL_AUTH_FILE", "/etc/nodewall/auth.json"),
		AllowedCIDRs:          getCSV("NODEWALL_ALLOWED_CIDRS"),
		AllowedIPs:            getCSV("NODEWALL_ALLOWED_IPS"),
		AllowedMACs:           getCSV("NODEWALL_ALLOWED_MACS"),
		GRPCListenAddr:        getenv("NODEWALL_SERVER_GRPC_ADDR", ""),
		QUICListenAddr:        getenv("NODEWALL_SERVER_QUIC_ADDR", ""),
		WebAccessMode:         strings.ToLower(strings.TrimSpace(getenv("NODEWALL_WEB_ACCESS", "public"))),
		SSHKeyPath:            getenv("NODEWALL_SSH_KEY", "/etc/nodewall/ssh/id_ed25519"),
		TLSEnabled:            getBool("NODEWALL_TLS_ENABLED", tlsDefault),
		TLSCertFile:           getenv("NODEWALL_TLS_CERT", "/etc/nodewall/tls/server.crt"),
		TLSKeyFile:            getenv("NODEWALL_TLS_KEY", "/etc/nodewall/tls/server.key"),
		TLSCAFile:             getenv("NODEWALL_TLS_CA", ""),
		TLSInsecureSkipVerify: getBool("NODEWALL_TLS_INSECURE_SKIP_VERIFY", true),
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

func getDuration(key string, fallback time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
		if seconds, err := strconv.Atoi(value); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}

	return fallback
}

func getBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func getInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getCSV(key string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
