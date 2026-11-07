package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/monitoring"
	"nodewall/internal/nodeauth"
	"nodewall/internal/service"
	"nodewall/internal/sshconsole"
	"nodewall/internal/store"
	"nodewall/internal/transporttls"
	"nodewall/internal/version"

	"github.com/quic-go/webtransport-go"
)

type ServerHandler struct {
	nodeCredentials      *nodeauth.Registry
	enrollmentMu         sync.Mutex
	enrollmentTickets    map[string]time.Time
	nodeID               string
	webDir               string
	defaultInterface     string
	defaultXDPMode       string
	service              *service.PolicyService
	store                *store.Store
	reverseHTTP          *http.Client
	auth                 *authManager
	sshConsole           *sshconsole.Manager
	tlsCertFile          string
	h3Port               string
	grpcPort             string
	controlPortRules     []models.PortRule
	deleteEventsMu       sync.Mutex
	deleteEvents         []map[string]any
	systemMetricsMu      sync.Mutex
	systemMetricsFetch   sync.Map
	metricsArchive       *monitoring.History
	metricsArchiveError  string
	systemMetricsCache   map[string]cachedSystemMetric
	systemMetricsHistory map[string][]models.SystemMetricPoint
}

const (
	// Share samples between page requests and the independent five-second poll.
	systemMetricsCacheTTL       = 4 * time.Second
	systemMetricsSampleInterval = 5 * time.Second
	systemMetricsHistoryWindow  = monitoring.HistoryRetention
	systemMetricsHistoryLimit   = int(6*time.Hour/systemMetricsSampleInterval) + 1
)

type cachedSystemMetric struct {
	metrics   models.SystemMetrics
	fetchedAt time.Time
}

type clusterNodeAggregate struct {
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	AgentURL         string                `json:"agent_url"`
	Interface        string                `json:"interface"`
	Passed           uint64                `json:"passed"`
	Dropped          uint64                `json:"dropped"`
	RecentPassed     uint64                `json:"recent_passed"`
	RecentDropped    uint64                `json:"recent_dropped"`
	RecentDropRate   float64               `json:"recent_drop_rate"`
	Trusted          uint64                `json:"trusted"`
	PendingRelease   uint64                `json:"pending_release"`
	Status           string                `json:"status"`
	ProtectionStatus string                `json:"protection_status"`
	LastSeenAt       time.Time             `json:"last_seen_at,omitempty"`
	CPUPercent       float64               `json:"cpu_percent"`
	MemoryPercent    float64               `json:"memory_percent"`
	RxBytesPerSec    float64               `json:"rx_bytes_per_second"`
	TxBytesPerSec    float64               `json:"tx_bytes_per_second"`
	SystemMetrics    *models.SystemMetrics `json:"system_metrics,omitempty"`
}

const trafficWindow = 5 * time.Minute

type trafficWindowStats struct {
	WindowSeconds int     `json:"window_seconds"`
	RecentPassed  uint64  `json:"recent_passed"`
	RecentDropped uint64  `json:"recent_dropped"`
	PassedPPS     float64 `json:"passed_pps"`
	DroppedPPS    float64 `json:"dropped_pps"`
	DropRate      float64 `json:"drop_rate"`
}

// recentTrafficStats converts cumulative XDP snapshots into a bounded window.
// Counters are intentionally kept cumulative for audit/detail views, while the
// overview needs deltas so its primary numbers remain useful over time.
func recentTrafficStats(current models.InterfaceStats, trend []models.TrafficPoint, now time.Time) trafficWindowStats {
	type sample struct {
		at      time.Time
		passed  uint64
		dropped uint64
	}

	samples := make([]sample, 0, len(trend)+1)
	for _, point := range trend {
		at, err := time.Parse(time.RFC3339, strings.TrimSpace(point.Timestamp))
		if err != nil {
			continue
		}
		samples = append(samples, sample{at: at, passed: point.Passed, dropped: point.Dropped})
	}
	samples = append(samples, sample{at: now, passed: current.Passed, dropped: current.Dropped})
	sort.SliceStable(samples, func(i, j int) bool { return samples[i].at.Before(samples[j].at) })
	if len(samples) == 0 {
		return trafficWindowStats{WindowSeconds: int(trafficWindow / time.Second)}
	}

	end := samples[len(samples)-1]
	cutoff := end.at.Add(-trafficWindow)
	start := samples[0]
	for _, candidate := range samples {
		if candidate.at.After(cutoff) {
			break
		}
		start = candidate
	}

	delta := func(begin, finish uint64) uint64 {
		// A restart or XDP reattach resets counters. Treat the new value as the
		// interval delta instead of allowing unsigned underflow.
		if finish < begin {
			return finish
		}
		return finish - begin
	}
	passed := delta(start.passed, end.passed)
	dropped := delta(start.dropped, end.dropped)
	elapsed := end.at.Sub(start.at).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed > trafficWindow.Seconds() {
		elapsed = trafficWindow.Seconds()
	}
	total := passed + dropped
	stats := trafficWindowStats{
		WindowSeconds: int(trafficWindow / time.Second),
		RecentPassed:  passed,
		RecentDropped: dropped,
	}
	if total > 0 {
		stats.DropRate = float64(dropped) / float64(total)
	}
	if elapsed > 0 {
		stats.PassedPPS = float64(passed) / elapsed
		stats.DroppedPPS = float64(dropped) / elapsed
	}
	return stats
}

func mergeTrafficWindow(total *trafficWindowStats, next trafficWindowStats) {
	total.RecentPassed += next.RecentPassed
	total.RecentDropped += next.RecentDropped
	total.PassedPPS += next.PassedPPS
	total.DroppedPPS += next.DroppedPPS
	if total.RecentPassed+total.RecentDropped > 0 {
		total.DropRate = float64(total.RecentDropped) / float64(total.RecentPassed+total.RecentDropped)
	}
}

func NewServerHandler(cfg config.ServerConfig, svc *service.PolicyService, st *store.Store) (*ServerHandler, error) {
	var history *monitoring.History
	archiveError := ""
	if cfg.MonitoringHistoryDir != "" {
		var err error
		history, err = monitoring.OpenHistory(cfg.MonitoringHistoryDir, cfg.MonitoringHistoryBytes)
		if err != nil {
			archiveError = fmt.Sprintf("open monitoring history: %v", err)
			log.Printf("warning: %s; monitoring continues in memory", archiveError)
			history = nil
		}
	}
	auth, err := newAuthManager(cfg)
	if err != nil {
		return nil, err
	}
	reverseHTTP := &http.Client{Timeout: 10 * time.Second}
	if cfg.TLSEnabled {
		tlsConfig, tlsErr := transporttls.ClientConfig(cfg.TLSCAFile, "", cfg.TLSInsecureSkipVerify)
		if tlsErr != nil {
			return nil, tlsErr
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
		reverseHTTP.Transport = transport
	}
	if svc != nil {
		svc.SetHTTPClient(reverseHTTP)
		svc.SetControlPortRules(controlPlanePortRules(cfg))
	}
	h3Port := ""
	_, grpcPort, _ := net.SplitHostPort(cfg.GRPCListenAddr)
	if cfg.TLSEnabled {
		_, port, portErr := net.SplitHostPort(strings.TrimSpace(cfg.QUICListenAddr))
		if portErr == nil {
			h3Port = port
		}
	}
	return &ServerHandler{
		metricsArchive:       history,
		metricsArchiveError:  archiveError,
		nodeID:               cfg.NodeID,
		webDir:               cfg.WebDir,
		defaultInterface:     cfg.DefaultInterface,
		defaultXDPMode:       cfg.DefaultXDPMode,
		service:              svc,
		store:                st,
		reverseHTTP:          reverseHTTP,
		auth:                 auth,
		sshConsole:           sshconsole.NewWithKeyPath(cfg.SSHKeyPath),
		tlsCertFile:          cfg.TLSCertFile,
		h3Port:               h3Port,
		grpcPort:             grpcPort,
		controlPortRules:     controlPlanePortRules(cfg),
		systemMetricsCache:   make(map[string]cachedSystemMetric),
		systemMetricsHistory: make(map[string][]models.SystemMetricPoint),
	}, nil
}

func (h *ServerHandler) pushDeleteEvent(nodeID, phase, status, message string) {
	h.deleteEventsMu.Lock()
	defer h.deleteEventsMu.Unlock()
	h.deleteEvents = append(h.deleteEvents, map[string]any{
		"id":        fmt.Sprintf("del-%d", time.Now().UnixNano()),
		"node_id":   nodeID,
		"phase":     phase,
		"status":    status,
		"message":   message,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
	if len(h.deleteEvents) > 100 {
		h.deleteEvents = append([]map[string]any(nil), h.deleteEvents[len(h.deleteEvents)-100:]...)
	}
}

func (h *ServerHandler) listDeleteEvents() []map[string]any {
	h.deleteEventsMu.Lock()
	defer h.deleteEventsMu.Unlock()
	out := make([]map[string]any, len(h.deleteEvents))
	copy(out, h.deleteEvents)
	return out
}

func (h *ServerHandler) Routes() http.Handler {
	return h.routes(nil)
}

// RoutesWithWebTransport adds the browser terminal's WebTransport CONNECT
// endpoint to the same authenticated route tree used by HTTP/1.1, HTTP/2 and
// the WSS fallback.
func (h *ServerHandler) RoutesWithWebTransport(transport *webtransport.Server) http.Handler {
	return h.routes(transport)
}

func (h *ServerHandler) routes(transport *webtransport.Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /nodes", h.handleNodes)
	mux.HandleFunc("GET /events/cluster", h.handleClusterEvents)
	mux.HandleFunc("GET /cluster/aggregate", h.handleClusterAggregate)
	mux.HandleFunc("GET /monitoring/history", h.handleMonitoringHistory)
	mux.HandleFunc("GET /version", h.handleVersion)
	mux.HandleFunc("POST /nodes", h.handleUpsertNode)
	mux.HandleFunc("POST /nodes/enrollment", h.handleEnrollmentTicket)
	mux.HandleFunc("POST /join/enroll", h.handleNodeEnrollment)
	mux.HandleFunc("POST /join/heartbeat", h.handleJoinHeartbeat)
	mux.HandleFunc("PUT /nodes/{node}/name", h.handleUpdateNodeName)
	mux.HandleFunc("DELETE /nodes/{node}", h.handleDeleteNode)
	mux.HandleFunc("GET /nodes/{node}/ssh-connection", h.handleNodeSSHConnection)
	mux.HandleFunc("PUT /nodes/{node}/ssh-connection", h.handleNodeSSHConnection)
	mux.HandleFunc("POST /nodes/{node}/ssh-connection/test", h.handleNodeSSHConnectionTest)
	mux.HandleFunc("POST /nodes/{node}/ssh-sessions", h.handleSSHSessionCreate)
	mux.HandleFunc("DELETE /ssh-sessions/{session}", h.handleSSHSessionDelete)
	mux.HandleFunc("GET /ssh/public-key", h.handleSSHPublicKey)
	mux.HandleFunc("GET /ssh-sessions/{session}/terminal", h.handleSSHTerminal)
	if transport != nil {
		mux.HandleFunc("CONNECT /ssh-sessions/{session}/terminal-transport", func(w http.ResponseWriter, r *http.Request) {
			h.handleSSHWebTransportTerminal(w, r, transport)
		})
	}
	mux.HandleFunc("GET /ssh-sessions/{session}/files", h.handleSSHFiles)
	mux.HandleFunc("POST /ssh-sessions/{session}/files", h.handleSSHFiles)
	mux.HandleFunc("GET /join/script", h.handleJoinScript)
	mux.HandleFunc("GET /join/version", h.handleJoinVersion)
	mux.HandleFunc("GET /join/tls-cert", h.handleJoinTLSCert)
	mux.HandleFunc("GET /join/nodewall", h.handleJoinBinary)
	mux.HandleFunc("GET /bootstrap", h.handleBootstrap)
	mux.HandleFunc("GET /auth/session", h.handleAuthSession)
	mux.HandleFunc("POST /auth/password", h.handlePasswordChange)
	mux.HandleFunc("GET /auth/users", h.handleAuthUsers)
	mux.HandleFunc("POST /auth/users", h.handleAuthUsers)
	mux.HandleFunc("PUT /auth/users/{username}", h.handleAuthUser)
	mux.HandleFunc("DELETE /auth/users/{username}", h.handleAuthUser)
	mux.HandleFunc("PUT /auth/users/{username}/password", h.handleAuthUserPassword)
	mux.HandleFunc("GET /settings/auth", h.handleAuthSettings)
	mux.HandleFunc("PUT /settings/auth", h.handleUpdateAuthSettings)
	mux.HandleFunc("GET /settings/logging", h.handleProxyLoggingSettings)
	mux.HandleFunc("PUT /settings/logging", h.handleProxyLoggingSettings)
	mux.HandleFunc("GET /logs/drop", h.handleProxyRecentDropLogs)
	mux.HandleFunc("DELETE /logs/drop", h.handleProxyRecentDropLogs)
	mux.HandleFunc("POST /logs/actions/allow", h.handleLogAllowAction)
	mux.HandleFunc("POST /logs/actions/block", h.handleLogBlockAction)
	mux.HandleFunc("POST /logs/actions/rate-limit", h.handleLogRateLimitAction)
	mux.HandleFunc("POST /logs/actions/temp-block", h.handleLogTempBlockAction)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/policy", h.handleGetPolicy)
	mux.HandleFunc("PUT /nodes/{node}/interfaces/{iface}/policy", h.handleUpdatePolicy)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/protection-baseline", h.handleEnableProtectionBaseline)
	mux.HandleFunc("GET /nodes/{node}/health", h.handleProxyHealth)
	mux.HandleFunc("GET /nodes/{node}/system/metrics", h.handleProxySystemMetrics)
	mux.HandleFunc("GET /nodes/{node}/security/summary", h.handleProxySecuritySummary)
	mux.HandleFunc("GET /nodes/{node}/security/scan", h.handleProxySecurityScan)
	mux.HandleFunc("POST /nodes/{node}/security/scan", h.handleProxySecurityScan)
	mux.HandleFunc("GET /nodes/{node}/security/scan/report", h.handleProxySecurityScanReport)
	mux.HandleFunc("GET /nodes/{node}/security/scan/reports", h.handleProxySecurityScanReports)
	mux.HandleFunc("GET /nodes/{node}/security/scan/reports/{scan}", h.handleProxySecurityScanReport)
	mux.HandleFunc("POST /nodes/{node}/security/scan/{finding}/quarantine", h.handleProxySecurityQuarantine)
	mux.HandleFunc("POST /nodes/{node}/security/scan/{finding}/terminate", h.handleProxySecurityProcessTerminate)
	mux.HandleFunc("GET /nodes/{node}/security/quarantine", h.handleProxySecurityQuarantineList)
	mux.HandleFunc("DELETE /nodes/{node}/security/quarantine/{entry}", h.handleProxySecurityQuarantineDelete)
	mux.HandleFunc("POST /nodes/{node}/security/quarantine/{entry}/restore", h.handleProxySecurityQuarantineRestore)
	mux.HandleFunc("GET /nodes/{node}/ssh-protection", h.handleProxySSHProtection)
	mux.HandleFunc("GET /nodes/{node}/ssh-protection/activity", h.handleProxySSHActivity)
	mux.HandleFunc("PUT /nodes/{node}/ssh-protection", h.handleProxySSHProtection)
	mux.HandleFunc("PUT /nodes/{node}/ssh-protection/transfer", h.handleProxySSHTransferPolicy)
	mux.HandleFunc("POST /nodes/{node}/ssh-protection/integrity/baseline", h.handleProxySSHIntegrityBaseline)
	mux.HandleFunc("POST /nodes/{node}/ssh-protection/integrity/verify", h.handleProxySSHIntegrityVerify)
	mux.HandleFunc("DELETE /nodes/{node}/ssh-protection/blocks/{id}", h.handleProxySSHProtectionBlockDelete)
	mux.HandleFunc("GET /nodes/{node}/interfaces", h.handleProxyInterfaces)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/summary", h.handleProxyInterfaceSummary)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/insights", h.handleProxyInsights)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/drop-logs", h.handleProxyDropLogs)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/temporary-blocks", h.handleProxyTemporaryBlocks)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/temporary-blocks", h.handleProxyTemporaryBlocks)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/temporary-blocks/{id}", h.handleProxyTemporaryBlockDelete)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/rate-limits", h.handleProxyRateLimits)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/rate-limits", h.handleProxyRateLimits)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/rate-limits/{id}", h.handleProxyRateLimitDelete)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/stats", h.handleProxyStats)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/attach", h.handleProxyAttach)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/detach", h.handleProxyDetach)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/protection-baseline/confirm", h.handleConfirmProtectionBaseline)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/protection-baseline/rollback", h.handleRollbackProtectionBaseline)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/bypass", h.handleProxyBypass)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/bypass", h.handleProxyBypassUpsert)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/bypass", h.handleProxyBypassDelete)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/bypass/{cidr}", h.handleProxyBypassDelete)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/block", h.handleProxyBlock)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/block", h.handleProxyBlockUpsert)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/block", h.handleProxyBlockDelete)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/block/{cidr}", h.handleProxyBlockDelete)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/allowlist", h.handleProxyAllowlist)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/allowlist", h.handleProxyAllowlistUpsert)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/allowlist", h.handleProxyAllowlistDelete)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/allowlist/{cidr}", h.handleProxyAllowlistDelete)
	mux.HandleFunc("PUT /nodes/{node}/interfaces/{iface}/rule-description", h.handleProxyRuleDescription)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/icmp-allowlist", h.handleProxyICMPAllowlist)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/icmp-allowlist", h.handleProxyICMPAllowlistUpsert)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/icmp-allowlist", h.handleProxyICMPAllowlistDelete)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/icmp-allowlist/{cidr}", h.handleProxyICMPAllowlistDelete)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/icmp-blocklist", h.handleProxyICMPBlocklist)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/icmp-blocklist", h.handleProxyICMPBlocklistUpsert)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/icmp-blocklist", h.handleProxyICMPBlocklistDelete)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/icmp-blocklist/{cidr}", h.handleProxyICMPBlocklistDelete)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/public-ports", h.handleProxyPublicPorts)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/public-ports", h.handleProxyPublicPortsUpsert)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/public-ports/{port}", h.handleProxyPublicPortsDelete)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/denied-ports", h.handleProxyDeniedPorts)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/denied-ports", h.handleProxyDeniedPortsUpsert)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/denied-ports/{port}", h.handleProxyDeniedPortsDelete)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/ports", h.handleProxyPorts)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/ports", h.handleProxyPortsUpsert)
	mux.HandleFunc("DELETE /nodes/{node}/interfaces/{iface}/ports/{port}", h.handleProxyPortsDelete)
	mux.Handle("/", h.webStaticHandler())
	return securityHeaders(h.auth.wrap(captureConfirmation(mux)), h.h3Port)
}

func securityHeaders(next http.Handler, h3Port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			if strings.TrimSpace(h3Port) != "" {
				w.Header().Set("Alt-Svc", `h3=":`+h3Port+`"; ma=86400`)
			}
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' https: ws: wss:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

func (h *ServerHandler) webStaticHandler() http.Handler {
	fileServer := http.FileServer(http.Dir(h.webDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSpace(r.URL.Path)
		switch {
		case path == "/" || strings.HasSuffix(path, ".html"):
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		case strings.Contains(path, "/assets/"):
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			w.Header().Set("Cache-Control", "public, max-age=300")
		}
		fileServer.ServeHTTP(w, r)
	})
}

func (h *ServerHandler) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	clientIP, _ := requestSourceAddr(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":           h.nodeID,
		"default_interface": h.defaultInterface,
		"default_xdp_mode":  h.defaultXDPMode,
		"client_ip":         clientIP.String(),
		"h3_port":           h.h3Port,
	})
}

func (h *ServerHandler) handleVersion(w http.ResponseWriter, r *http.Request) {
	info := version.Current()
	writeJSON(w, http.StatusOK, map[string]string{
		"version":         info.AppVersion,
		"app_version":     info.AppVersion,
		"package_version": info.PackageVersion,
	})
}

func (h *ServerHandler) handleJoinVersion(w http.ResponseWriter, r *http.Request) {
	if !h.joinAuthorized(w, r) {
		return
	}
	h.handleVersion(w, r)
}

func (h *ServerHandler) handleJoinTLSCert(w http.ResponseWriter, r *http.Request) {
	if !h.joinAuthorized(w, r) {
		return
	}
	if strings.TrimSpace(h.tlsCertFile) == "" {
		writeError(w, http.StatusNotFound, errors.New("TLS certificate is not configured"))
		return
	}
	certificate, err := os.ReadFile(h.tlsCertFile)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("TLS certificate is not available"))
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(certificate)
}

func (h *ServerHandler) handleJoinScript(w http.ResponseWriter, r *http.Request) {
	if !h.joinAuthorized(w, r) {
		return
	}
	ticket := r.URL.Query().Get("token")
	pin := ""
	if h.nodeCredentials != nil {
		var err error
		pin, err = h.managerCertificatePin()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	script, err := h.buildJoinScript(r, ticket, pin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(script))
}

func (h *ServerHandler) buildJoinScript(r *http.Request, ticket, pin string) (string, error) {
	baseURL := requestBaseURL(r)
	publicKey, err := h.sshConsole.PublicKey()
	if err != nil {
		return "", fmt.Errorf("prepare NodeWall SSH public key: %w", err)
	}
	publicKey = strings.TrimSpace(publicKey)
	managerGRPC := strings.TrimSpace(r.URL.Query().Get("manager_grpc"))
	managerQUIC := strings.TrimSpace(r.URL.Query().Get("manager_quic"))
	grpcPort, quicPort := h.grpcPort, h.h3Port
	if grpcPort == "" {
		grpcPort = "50051"
	}
	if quicPort == "" {
		quicPort = "50052"
	}
	if managerGRPC == "" {
		if host, _, err := net.SplitHostPort(r.Host); err == nil {
			managerGRPC = net.JoinHostPort(host, grpcPort)
		} else {
			managerGRPC = net.JoinHostPort(r.Host, grpcPort)
		}
	}
	if managerQUIC == "" {
		if host, _, err := net.SplitHostPort(r.Host); err == nil {
			managerQUIC = net.JoinHostPort(host, quicPort)
		} else {
			managerQUIC = net.JoinHostPort(r.Host, quicPort)
		}
	}
	binarySHA256 := joinBinarySHA256()

	// The join script deliberately separates the management bridge address from
	// the physical uplink. ZStack puts the IPv4 address on br_*, while iptables
	// protection must be keyed by the underlying physical port. Service startup
	// is also attempted independently of systemd so a damaged service manager
	// does not prevent a verified Agent from coming online for this boot.
	script := "#!/usr/bin/env bash\n" +
		"set -euo pipefail\n" +
		"progress() { printf '[nodewall] %s\\n' \"$*\" >&2; }\n" +
		"\n" +
		"JOIN_IFACE=\"\"\n" +
		"while [[ $# -gt 0 ]]; do\n" +
		"  case \"$1\" in\n" +
		"    --iface) JOIN_IFACE=\"${2:-}\"; shift 2 ;;\n" +
		"    *) echo \"unknown arg: $1\" >&2; exit 1 ;;\n" +
		"  esac\n" +
		"done\n" +
		"\n" +
		"ARCH=$(uname -m)\n" +
		"case \"$ARCH\" in\n" +
		"  x86_64|amd64) ARCH=amd64 ;;\n" +
		"  aarch64|arm64) ARCH=arm64 ;;\n" +
		"  *) echo \"unsupported arch: $ARCH\" >&2; exit 1 ;;\n" +
		"esac\n" +
		"\n" +
		"if [[ -z \"$JOIN_IFACE\" ]]; then\n" +
		"  mapfile -t CANDIDATES < <(ip -o -4 addr show up scope global | awk '{print $2}' | awk '!seen[$0]++')\n" +
		"  DEFAULT_IFACE=$(ip -o route show default | awk '{print $5}' | head -n1)\n" +
		"  if [[ ${#CANDIDATES[@]} -eq 0 ]]; then\n" +
		"    echo \"no usable interface found\" >&2\n" +
		"    exit 1\n" +
		"  elif [[ ${#CANDIDATES[@]} -eq 1 ]]; then\n" +
		"    JOIN_IFACE=\"${CANDIDATES[0]}\"\n" +
		"  else\n" +
		"    echo \"select interface for manager connectivity:\"\n" +
		"    for i in \"${!CANDIDATES[@]}\"; do\n" +
		"      IFACE=\"${CANDIDATES[$i]}\"\n" +
		"      IP=$(ip -o -4 addr show dev \"$IFACE\" | awk '{print $4}' | head -n1)\n" +
		"      MARK=\"\"\n" +
		"      if [[ \"$IFACE\" == \"$DEFAULT_IFACE\" ]]; then MARK=\" (default)\"; fi\n" +
		"      echo \"  [$((i+1))] $IFACE  $IP$MARK\"\n" +
		"    done\n" +
		"    read -rp \"choose [1-${#CANDIDATES[@]}] (default auto): \" CHOICE\n" +
		"    if [[ -z \"${CHOICE:-}\" ]]; then\n" +
		"      JOIN_IFACE=\"$DEFAULT_IFACE\"\n" +
		"    elif [[ \"$CHOICE\" =~ ^[0-9]+$ ]] && (( CHOICE >= 1 && CHOICE <= ${#CANDIDATES[@]} )); then\n" +
		"      JOIN_IFACE=\"${CANDIDATES[$((CHOICE-1))]}\"\n" +
		"    else\n" +
		"      echo \"invalid choice\" >&2\n" +
		"      exit 1\n" +
		"    fi\n" +
		"  fi\n" +
		"fi\n" +
		"\n" +
		"if [[ -z \"$JOIN_IFACE\" ]]; then\n" +
		"  JOIN_IFACE=$(ip -o route show default | awk '{print $5}' | head -n1)\n" +
		"fi\n" +
		"if [[ -z \"$JOIN_IFACE\" ]]; then\n" +
		"  echo \"failed to determine interface\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"\n" +
		"SELECTED_BRIDGE=\"$JOIN_IFACE\"\n" +
		"BRIDGE_IP=$(ip -o -4 addr show dev \"$SELECTED_BRIDGE\" | awk '{print $4}' | head -n1 | cut -d/ -f1)\n" +
		"if [[ -d \"/sys/class/net/$SELECTED_BRIDGE/bridge\" ]]; then\n" +
		"  PHYSICAL_IFACE=\"\"\n" +
		"  for PORT_PATH in \"/sys/class/net/$SELECTED_BRIDGE/brif/\"*; do\n" +
		"    [[ -e \"$PORT_PATH\" ]] || continue\n" +
		"    PORT_NAME=\"${PORT_PATH##*/}\"\n" +
		"    case \"$PORT_NAME\" in lo|veth*|vnic*|outer*|tap*|qvb*|qvo*|qbr*|cni*|flannel*) continue ;; esac\n" +
		"    if [[ -e \"/sys/class/net/$PORT_NAME/device\" ]]; then PHYSICAL_IFACE=\"$PORT_NAME\"; break; fi\n" +
		"  done\n" +
		"  if [[ -z \"$PHYSICAL_IFACE\" ]]; then\n" +
		"    echo \"bridge $SELECTED_BRIDGE has no physical uplink; choose the physical port\" >&2\n" +
		"    exit 1\n" +
		"  fi\n" +
		"  JOIN_IFACE=\"$PHYSICAL_IFACE\"\n" +
		"  JOIN_IP=\"$BRIDGE_IP\"\n" +
		"else\n" +
		"  JOIN_IP=$(ip -o -4 addr show dev \"$JOIN_IFACE\" | awk '{print $4}' | head -n1 | cut -d/ -f1)\n" +
		"  if [[ -z \"$JOIN_IP\" && -L \"/sys/class/net/$JOIN_IFACE/master\" ]]; then\n" +
		"    MASTER_IFACE=\"$(basename \"$(readlink \"/sys/class/net/$JOIN_IFACE/master\")\")\"\n" +
		"    JOIN_IP=$(ip -o -4 addr show dev \"$MASTER_IFACE\" | awk '{print $4}' | head -n1 | cut -d/ -f1)\n" +
		"  fi\n" +
		"fi\n" +
		"if [[ -z \"$JOIN_IP\" ]]; then\n" +
		"  echo \"selected interface has no IPv4: $JOIN_IFACE\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"if [[ \"$SELECTED_BRIDGE\" != \"$JOIN_IFACE\" ]]; then progress \"bridge $SELECTED_BRIDGE -> physical $JOIN_IFACE ($JOIN_IP)\"; else progress \"selected interface $JOIN_IFACE ($JOIN_IP)\"; fi\n" +
		"\n" +
		"NODEWALL_SSH_PUBLIC_KEY='" + publicKey + "'\n" +
		"run_root() { if [[ \"${EUID:-$(id -u)}\" -eq 0 ]]; then \"$@\"; else sudo \"$@\"; fi; }\n" +
		"progress 'configuring NodeWall SSH access'\n" +
		"run_root install -d -m 700 /root/.ssh\n" +
		"if ! run_root grep -qxF \"$NODEWALL_SSH_PUBLIC_KEY\" /root/.ssh/authorized_keys 2>/dev/null; then\n" +
		"  printf '%s\\n' \"$NODEWALL_SSH_PUBLIC_KEY\" | run_root tee -a /root/.ssh/authorized_keys >/dev/null\n" +
		"fi\n" +
		"run_root chmod 600 /root/.ssh/authorized_keys\n" +
		"\n" +
		"systemd_online() {\n" +
		"  command -v systemctl >/dev/null 2>&1 || return 1\n" +
		"  if command -v timeout >/dev/null 2>&1; then timeout 5 systemctl show --property=SystemState --value >/dev/null 2>&1; else systemctl show --property=SystemState --value >/dev/null 2>&1; fi\n" +
		"}\n" +
		"SYSTEMD_ONLINE=false\n" +
		"if systemd_online; then SYSTEMD_ONLINE=true; else progress 'systemd unavailable; direct-agent fallback will be used'; fi\n" +
		"start_direct_agent() {\n" +
		"  progress 'starting NodeWall agent directly'\n" +
		"  run_root sh -c 'set -a; . /etc/nodewall/nodewall.env; set +a; mkdir -p /var/log/nodewall; if [ -r /var/run/nodewall-agent.pid ] && kill -0 \"$(cat /var/run/nodewall-agent.pid)\" 2>/dev/null; then exit 0; fi; nohup /opt/nodewall/bin/nodewall agent >>/var/log/nodewall/agent.log 2>&1 </dev/null & echo $! >/var/run/nodewall-agent.pid'\n" +
		"  sleep 1\n" +
		"  DIRECT_PID=\"$(run_root cat /var/run/nodewall-agent.pid 2>/dev/null || true)\"\n" +
		"  if [[ -z \"$DIRECT_PID\" ]] || ! run_root kill -0 \"$DIRECT_PID\" 2>/dev/null; then\n" +
		"    echo '[nodewall] direct Agent failed to stay running; recent log:' >&2\n" +
		"    run_root tail -n 40 /var/log/nodewall/agent.log 2>/dev/null || true\n" +
		"    exit 1\n" +
		"  fi\n" +
		"}\n" +
		"\n" +
		"JOIN_TMP=$(mktemp -d)\n" +
		"trap 'rm -f \"$JOIN_TMP/nodewall\" \"$JOIN_TMP/manager.crt\" \"$JOIN_TMP/public.pem\" \"$JOIN_TMP/public.der\"; rmdir \"$JOIN_TMP\"' EXIT\n" +
		joinCurlSetupScript(baseURL, pin, ticket, binarySHA256) +
		"if [[ \"${CURL_CERT_MODE:-curl}\" == \"curl\" ]]; then progress 'downloading manager certificate'; curl \"${CURL_ARGS[@]}\" \"" + baseURL + "/join/tls-cert?token=" + url.QueryEscape(ticket) + "\" -o \"$JOIN_TMP/manager.crt\"; fi\n" +
		"progress 'downloading NodeWall agent binary'\n" +
		"curl \"${CURL_ARGS[@]}\" \"" + baseURL + "/join/nodewall?arch=${ARCH}&token=" + url.QueryEscape(ticket) + "\" -o \"$JOIN_TMP/nodewall\"\n" +
		"if [[ -z \"${NODEWALL_BINARY_SHA256:-}\" ]]; then echo '[nodewall] manager did not provide a binary SHA-256' >&2; exit 1; fi\n" +
		"progress 'verifying NodeWall agent binary'\n" +
		"printf '%s  %s\\n' \"$NODEWALL_BINARY_SHA256\" \"$JOIN_TMP/nodewall\" | sha256sum -c -\n" +
		"chmod +x \"$JOIN_TMP/nodewall\"\n" +
		"progress 'installing NodeWall agent'\n" +
		"run_root install -d -m 700 /etc/nodewall/tls\n" +
		"run_root install -m 644 \"$JOIN_TMP/manager.crt\" /etc/nodewall/tls/manager.crt\n" +
		"run_root \"$JOIN_TMP/nodewall\" install --enable-services=false --mode agent-only --agent-addr 0.0.0.0:9080 --manager-url \"" + baseURL + "\" --manager-grpc-addr \"" + managerGRPC + "\" --manager-quic-addr \"" + managerQUIC + "\" --advertise-addr \"${JOIN_IP}:9080\" --join-token '" + ticket + "' --manager-ca /etc/nodewall/tls/manager.crt --default-interface \"$JOIN_IFACE\"\n" +
		"run_root sed -i '/^NODEWALL_TLS_CA=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_TLS_CA=/etc/nodewall/tls/manager.crt' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i '/^NODEWALL_TLS_INSECURE_SKIP_VERIFY=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_TLS_INSECURE_SKIP_VERIFY=false' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i '/^NODEWALL_AGENT_ADDR=/d' /etc/nodewall/nodewall.env || true\n" +
		"echo 'NODEWALL_AGENT_ADDR=0.0.0.0:9080' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i \"s/^NODEWALL_AGENT_HTTP_ADDR=.*/NODEWALL_AGENT_HTTP_ADDR=${JOIN_IP}:9080/\" /etc/nodewall/nodewall.env || true\n" +
		"run_root sed -i '/^NODEWALL_AGENT_URL=/d' /etc/nodewall/nodewall.env || true\n" +
		"echo \"NODEWALL_AGENT_URL=https://${JOIN_IP}:9080\" | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root install -d -m 755 /etc/systemd/system/nodewall-agent.service.d\n" +
		"cat <<'NODEWALL_MEMLOCK' | run_root tee /etc/systemd/system/nodewall-agent.service.d/10-memlock.conf >/dev/null\n" +
		"[Service]\n" +
		"LimitMEMLOCK=infinity\n" +
		"NODEWALL_MEMLOCK\n" +
		"if [[ \"$SYSTEMD_ONLINE\" == true ]]; then\n" +
		"  if ! run_root grep -q '^ExecStart=/opt/nodewall/bin/nodewall agent$' /etc/systemd/system/nodewall-agent.service 2>/dev/null; then\n" +
		"    progress 'systemd unit verification failed; switching to direct-agent fallback'\n" +
		"    SYSTEMD_ONLINE=false\n" +
		"  fi\n" +
		"fi\n" +
		"if [[ \"$SYSTEMD_ONLINE\" == true ]]; then\n" +
		"  progress 'starting NodeWall agent with systemd'\n" +
		"  if ! run_root systemctl daemon-reload || ! run_root systemctl enable nodewall-agent.service || ! run_root systemctl restart nodewall-agent.service || ! run_root systemctl is-active --quiet nodewall-agent.service; then\n" +
		"    progress 'systemd Agent start failed; switching to direct-agent fallback'\n" +
		"    start_direct_agent\n" +
		"  fi\n" +
		"else\n" +
		"  start_direct_agent\n" +
		"fi\n" +
		"progress 'NodeWall agent enrollment completed'\n"

	return script, nil
}

func (h *ServerHandler) handleJoinBinary(w http.ResponseWriter, r *http.Request) {
	if !h.joinAuthorized(w, r) {
		return
	}
	arch := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("arch")))
	if arch == "" {
		arch = runtime.GOARCH
	}
	switch arch {
	case "x86_64":
		arch = "amd64"
	case "aarch64":
		arch = "arm64"
	}
	if arch != runtime.GOARCH {
		writeError(w, http.StatusBadRequest, errors.New("requested arch is not available on this manager"))
		return
	}
	http.ServeFile(w, r, resolvedJoinBinaryPath())
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		scheme = "https"
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "127.0.0.1:8080"
	}
	return scheme + "://" + host
}

func (h *ServerHandler) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.auth.sessionState(r))
}

func (h *ServerHandler) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	h.auth.handlePasswordChange(w, r)
}

func (h *ServerHandler) handleAuthUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.auth.createUser(w, r)
		return
	}
	h.auth.listUsers(w, r)
}

func (h *ServerHandler) handleAuthUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		h.auth.deleteUser(w, r)
		return
	}
	h.auth.updateUser(w, r)
}

func (h *ServerHandler) handleAuthUserPassword(w http.ResponseWriter, r *http.Request) {
	h.auth.resetUserPassword(w, r)
}

func (h *ServerHandler) handleAuthSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.auth.authSettings())
}

func (h *ServerHandler) handleUpdateAuthSettings(w http.ResponseWriter, r *http.Request) {
	var settings models.AuthSecuritySettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.auth.updateAuthSettings(settings); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, h.auth.authSettings())
}

func (h *ServerHandler) handleProxyLoggingSettings(w http.ResponseWriter, r *http.Request) {
	h.proxyNode(w, r, h.nodeID, "/settings/logging")
}

func (h *ServerHandler) handleProxyRecentDropLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		nodes := h.service.ListNodes(r.Context())
		limit := 500
		if value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit"))); err == nil && value > 0 {
			limit = min(value, 2000)
		}
		nodeLimit := min(limit, 1000)
		merged := make([]models.DropLogRecord, 0, 256)
		for _, node := range nodes {
			nodeCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			var payload struct {
				Logs []models.DropLogRecord `json:"logs"`
			}
			err := h.nodeJSON(nodeCtx, node.ID, http.MethodGet, "/logs/drop?limit="+strconv.Itoa(nodeLimit), nil, &payload)
			cancel()
			if err != nil {
				continue
			}
			for i := range payload.Logs {
				// Agent logs do not know the manager-side node identity. Add it while
				// merging so cluster-wide log rows remain traceable to one node.
				payload.Logs[i].NodeID = node.ID
			}

			policyByIface := make(map[string]models.InterfacePolicy)
			runtimeCache := make(map[string]runtimeDispositionState)
			for _, record := range payload.Logs {
				if _, ok := policyByIface[record.Interface]; !ok {
					policyByIface[record.Interface] = h.ensurePolicy(r.Context(), node.ID, record.Interface)
				}
				direction := record.Direction
				if direction == "" {
					direction = models.DirectionIngress
				}
				cacheKey := record.Interface + "|" + string(direction)
				if _, ok := runtimeCache[cacheKey]; ok {
					continue
				}
				var tempResp struct {
					TemporaryBlocks []models.TemporaryBlock `json:"temporary_blocks"`
				}
				var rateResp struct {
					RateLimits []models.RateLimitRule `json:"rate_limits"`
				}
				_ = h.nodeJSON(r.Context(), node.ID, http.MethodGet, "/interfaces/"+record.Interface+"/temporary-blocks?direction="+string(direction), nil, &tempResp)
				_ = h.nodeJSON(r.Context(), node.ID, http.MethodGet, "/interfaces/"+record.Interface+"/rate-limits?direction="+string(direction), nil, &rateResp)
				runtimeCache[cacheKey] = runtimeDispositionState{
					TempBlocks: tempResp.TemporaryBlocks,
					RateLimits: rateResp.RateLimits,
				}
			}
			enrichDropLogsWithDisposition(payload.Logs, policyByIface, runtimeCache)
			merged = append(merged, payload.Logs...)
		}
		sort.SliceStable(merged, func(i, j int) bool {
			return merged[i].Timestamp.After(merged[j].Timestamp)
		})
		if len(merged) > limit {
			merged = merged[:limit]
		}
		writeJSON(w, http.StatusOK, map[string]any{"logs": merged})
		return
	}
	if r.Method == http.MethodDelete {
		nodes := h.service.ListNodes(r.Context())
		if len(nodes) == 0 {
			h.proxyNode(w, r, h.nodeID, "/logs/drop")
			return
		}
		failed := make([]string, 0)
		for _, node := range nodes {
			nodeCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			err := h.nodeJSON(nodeCtx, node.ID, http.MethodDelete, "/logs/drop", nil, nil)
			cancel()
			if err != nil {
				failed = append(failed, node.ID)
			}
		}
		if len(failed) > 0 {
			writeError(w, http.StatusBadGateway, fmt.Errorf("failed to clear logs on nodes: %s", strings.Join(failed, ", ")))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "cleared", "nodes": len(nodes)})
		return
	}
	h.proxyNode(w, r, h.nodeID, "/logs/drop")
}

func (h *ServerHandler) handleNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.service.ListNodes(r.Context()))
}

func (h *ServerHandler) handleClusterAggregate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.buildClusterAggregate(r.Context(), requestDirection(r)))
}

func (h *ServerHandler) handleMonitoringHistory(w http.ResponseWriter, r *http.Request) {
	from, to, rangeSeconds, err := monitoringTimeWindow(r, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node"))
	nodes := h.service.ListNodes(r.Context())
	targets := nodes
	if nodeID != "" {
		var found bool
		for _, node := range nodes {
			if node.ID == nodeID {
				targets = []models.Node{node}
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("node %q not found", nodeID))
			return
		}
	}

	// A direct page load may arrive before the SSE stream has taken its first
	// sample. Ensure the requested scope has at least one current sample while
	// still reusing the short-lived cache used by cluster aggregation.
	h.collectSystemMetrics(r.Context(), targets)
	if r.URL.Query().Get("from") == "" && r.URL.Query().Get("to") == "" {
		// Include samples captured during this request, not just before it.
		from, to, rangeSeconds, _ = monitoringTimeWindow(r, time.Now().UTC())
	}

	points := h.systemMetricHistoryPoints(nodeID, from, to)
	var archivedHistory map[string][]models.SystemMetricPoint
	step := systemMetricsSampleInterval
	if h.metricsArchive != nil {
		// Bound the response to chart resolution, even for multi-day queries.
		step = max(step, time.Duration((rangeSeconds+1199)/1200)*time.Second)
		step = ((step + systemMetricsSampleInterval - 1) / systemMetricsSampleInterval) * systemMetricsSampleInterval
		ids := make([]string, 0, len(targets))
		for _, node := range targets {
			ids = append(ids, node.ID)
		}
		history, err := h.metricsArchive.Query(r.Context(), ids, from, to, step)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		archivedHistory = history
		points = aggregateSystemMetricPoints(history, from.Truncate(step), to)
		if nodeID != "" {
			points = history[nodeID]
		}
	}
	h.systemMetricsMu.Lock()
	archiveError := h.metricsArchiveError
	h.systemMetricsMu.Unlock()
	result := models.SystemMetricsHistory{
		Scope:                 "cluster",
		NodeID:                nodeID,
		RangeSeconds:          rangeSeconds,
		SampleIntervalSeconds: int(step / time.Second),
		RetentionSeconds:      int(systemMetricsHistoryWindow / time.Second),
		StorageError:          archiveError,
		Points:                points,
		Nodes:                 h.systemMetricNodeSummaries(nodes),
	}
	if nodeID != "" {
		result.Scope = "node"
		result.Nodes = h.systemMetricNodeSummaries(targets)
	}
	for i := range result.Nodes {
		summary := &result.Nodes[i]
		history := archivedHistory[summary.NodeID]
		if summary.Timestamp.IsZero() && len(history) > 0 {
			// After a restart an offline node has no live cache. Show its last
			// retained sample with its historical timestamp, not invented zeros.
			point := history[len(history)-1]
			summary.Timestamp, summary.UptimeSeconds = point.Timestamp, point.UptimeSeconds
			summary.CPUCores, summary.CPUPercent, summary.MemoryPercent = point.CPUCores, point.CPUPercent, point.MemoryPercent
			summary.MemoryTotalBytes, summary.MemoryUsedBytes = uint64(point.MemoryTotalBytes), uint64(point.MemoryUsedBytes)
			summary.RxBytesPerSecond, summary.TxBytesPerSecond = point.RxBytesPerSecond, point.TxBytesPerSecond
			summary.Disk.ReadBytesPerSecond, summary.Disk.WriteBytesPerSecond = point.DiskReadBytesPerSecond, point.DiskWriteBytesPerSecond
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func monitoringTimeWindow(r *http.Request, now time.Time) (time.Time, time.Time, int, error) {
	fromRaw := strings.TrimSpace(r.URL.Query().Get("from"))
	toRaw := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromRaw == "" && toRaw == "" {
		rangeSeconds := monitoringRangeSeconds(r.URL.Query().Get("range"))
		to := now.UTC()
		return to.Add(-time.Duration(rangeSeconds) * time.Second), to, rangeSeconds, nil
	}
	if fromRaw == "" || toRaw == "" {
		return time.Time{}, time.Time{}, 0, errors.New("monitoring custom range requires both from and to")
	}

	from, err := time.Parse(time.RFC3339, fromRaw)
	if err != nil {
		return time.Time{}, time.Time{}, 0, fmt.Errorf("invalid monitoring range start: %w", err)
	}
	to, err := time.Parse(time.RFC3339, toRaw)
	if err != nil {
		return time.Time{}, time.Time{}, 0, fmt.Errorf("invalid monitoring range end: %w", err)
	}
	now = now.UTC()
	from = from.UTC()
	to = to.UTC()
	oldest := now.Add(-systemMetricsHistoryWindow)
	if from.Before(oldest) {
		from = oldest
	}
	if to.After(now) {
		to = now
	}
	if !to.After(from) {
		return time.Time{}, time.Time{}, 0, errors.New("monitoring custom range must be within the retained seven-day history")
	}
	return from, to, int(to.Sub(from) / time.Second), nil
}

func monitoringRangeSeconds(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 15 * 60
	}
	switch value {
	case 5 * 60, 15 * 60, 30 * 60, 60 * 60, 3 * 60 * 60, 6 * 60 * 60, 12 * 60 * 60, 24 * 60 * 60, 3 * 24 * 60 * 60, 7 * 24 * 60 * 60:
		return value
	default:
		return 15 * 60
	}
}

func (h *ServerHandler) readSystemMetrics(ctx context.Context, node models.Node) (*models.SystemMetrics, error) {
	nodeID := strings.TrimSpace(node.ID)
	if nodeID == "" {
		return nil, errors.New("node id is required")
	}
	lock, _ := h.systemMetricsFetch.LoadOrStore(nodeID, &sync.Mutex{})
	mu := lock.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	h.systemMetricsMu.Lock()
	if cached, ok := h.systemMetricsCache[nodeID]; ok && now.Sub(cached.fetchedAt) < systemMetricsCacheTTL {
		metrics := cached.metrics
		h.systemMetricsMu.Unlock()
		return &metrics, nil
	}
	h.systemMetricsMu.Unlock()

	var metrics models.SystemMetrics
	if err := h.nodeJSON(ctx, nodeID, http.MethodGet, "/system/metrics", nil, &metrics); err != nil {
		return nil, err
	}
	if metrics.Memory.TotalBytes == 0 {
		return nil, errors.New("system metrics returned no memory total")
	}
	if metrics.CapturedAt.IsZero() {
		metrics.CapturedAt = now.UTC()
	}
	point := systemMetricPoint(nodeID, metrics)
	var archiveErr error
	if h.metricsArchive != nil {
		archiveErr = h.metricsArchive.Append(point)
	}

	h.systemMetricsMu.Lock()
	if h.systemMetricsCache == nil {
		h.systemMetricsCache = make(map[string]cachedSystemMetric)
	}
	if h.systemMetricsHistory == nil {
		h.systemMetricsHistory = make(map[string][]models.SystemMetricPoint)
	}
	h.systemMetricsCache[nodeID] = cachedSystemMetric{metrics: metrics, fetchedAt: now}
	previousArchiveError := h.metricsArchiveError
	if h.metricsArchive != nil {
		h.metricsArchiveError = ""
		if archiveErr != nil {
			h.metricsArchiveError = archiveErr.Error()
		}
	}
	h.systemMetricsHistory[nodeID] = append(h.systemMetricsHistory[nodeID], point)
	cutoff := now.Add(-6 * time.Hour)
	history := h.systemMetricsHistory[nodeID]
	start := 0
	for start < len(history) && history[start].Timestamp.Before(cutoff) {
		start++
	}
	if start > 0 {
		history = history[start:]
	}
	if len(history) > systemMetricsHistoryLimit {
		history = history[len(history)-systemMetricsHistoryLimit:]
	}
	h.systemMetricsHistory[nodeID] = history
	h.systemMetricsMu.Unlock()
	if archiveErr != nil && archiveErr.Error() != previousArchiveError {
		log.Printf("warning: persist monitoring history: %v", archiveErr)
	}
	return &metrics, nil
}

func systemMetricPoint(nodeID string, metrics models.SystemMetrics) models.SystemMetricPoint {
	filesystemTotal, filesystemUsed, filesystemAvailable := filesystemTotals(metrics.Filesystems)
	filesystemUsedPercent := 0.0
	if filesystemTotal > 0 {
		filesystemUsedPercent = float64(filesystemUsed) / float64(filesystemTotal) * 100
	}
	return models.SystemMetricPoint{
		CPUCores:                   metrics.CPU.Cores,
		MemoryTotalBytes:           float64(metrics.Memory.TotalBytes),
		Timestamp:                  metrics.CapturedAt,
		NodeID:                     nodeID,
		UptimeSeconds:              metrics.UptimeSeconds,
		CPUPercent:                 metrics.CPU.UsagePercent,
		CPUUserPercent:             metrics.CPU.UserPercent,
		CPUSystemPercent:           metrics.CPU.SystemPercent,
		CPUIowaitPercent:           metrics.CPU.IowaitPercent,
		CPUStealPercent:            metrics.CPU.StealPercent,
		Load1:                      metrics.CPU.Load1,
		Load5:                      metrics.CPU.Load5,
		Load15:                     metrics.CPU.Load15,
		MemoryPercent:              metrics.Memory.UsedPercent,
		MemoryUsedBytes:            float64(metrics.Memory.UsedBytes),
		MemoryAvailableBytes:       float64(metrics.Memory.AvailableBytes),
		SwapUsedBytes:              float64(metrics.Memory.SwapUsedBytes),
		SwapUsedPercent:            metrics.Memory.SwapUsedPercent,
		RxBytesPerSecond:           metrics.Network.RxBytesPerSecond,
		TxBytesPerSecond:           metrics.Network.TxBytesPerSecond,
		RxPacketsPerSecond:         metrics.Network.RxPacketsPerSecond,
		TxPacketsPerSecond:         metrics.Network.TxPacketsPerSecond,
		RxErrorsPerSecond:          metrics.Network.RxErrorsPerSecond,
		TxErrorsPerSecond:          metrics.Network.TxErrorsPerSecond,
		RxDroppedPerSecond:         metrics.Network.RxDroppedPerSecond,
		TxDroppedPerSecond:         metrics.Network.TxDroppedPerSecond,
		DiskReadBytesPerSecond:     metrics.Disk.ReadBytesPerSecond,
		DiskWriteBytesPerSecond:    metrics.Disk.WriteBytesPerSecond,
		DiskReadOpsPerSecond:       metrics.Disk.ReadOpsPerSecond,
		DiskWriteOpsPerSecond:      metrics.Disk.WriteOpsPerSecond,
		DiskIOUtilizationPercent:   metrics.Disk.IOUtilizationPercent,
		DiskReadAwaitMilliseconds:  metrics.Disk.ReadAwaitMilliseconds,
		DiskWriteAwaitMilliseconds: metrics.Disk.WriteAwaitMilliseconds,
		FilesystemUsedPercent:      filesystemUsedPercent,
		FilesystemAvailableBytes:   float64(filesystemAvailable),
		ContextSwitchesPerSecond:   metrics.Kernel.ContextSwitchesPerSecond,
		InterruptsPerSecond:        metrics.Kernel.InterruptsPerSecond,
		ForksPerSecond:             metrics.Kernel.ForksPerSecond,
		ProcessesTotal:             float64(metrics.Processes.Total),
		ProcessesRunning:           float64(metrics.Processes.Running),
		ProcessesBlocked:           float64(metrics.Processes.Blocked),
		TCPInUse:                   float64(metrics.Sockets.TCPInUse),
		TCPTimeWait:                float64(metrics.Sockets.TCPTimeWait),
		UDPInUse:                   float64(metrics.Sockets.UDPInUse),
		FileDescriptorsAllocated:   float64(metrics.FileDescriptors.Allocated),
		FileDescriptorsMaximum:     float64(metrics.FileDescriptors.Maximum),
		FileDescriptorsUsedPercent: metrics.FileDescriptors.UsedPercent,
	}
}

func filesystemTotals(filesystems []models.FilesystemMetric) (total, used, available uint64) {
	for _, item := range filesystems {
		total += item.TotalBytes
		used += item.UsedBytes
		available += item.AvailableBytes
	}
	return total, used, available
}

func (h *ServerHandler) systemMetricHistoryPoints(nodeID string, from, to time.Time) []models.SystemMetricPoint {
	h.systemMetricsMu.Lock()
	defer h.systemMetricsMu.Unlock()
	if nodeID != "" {
		return filterSystemMetricPoints(h.systemMetricsHistory[nodeID], from, to)
	}
	return aggregateSystemMetricPoints(h.systemMetricsHistory, from, to)
}

func filterSystemMetricPoints(source []models.SystemMetricPoint, from, to time.Time) []models.SystemMetricPoint {
	points := make([]models.SystemMetricPoint, 0, len(source))
	for _, point := range source {
		if point.Timestamp.Before(from) || point.Timestamp.After(to) {
			continue
		}
		points = append(points, point)
	}
	return points
}

func aggregateSystemMetricPoints(history map[string][]models.SystemMetricPoint, from, to time.Time) []models.SystemMetricPoint {
	type bucket struct {
		point models.SystemMetricPoint
		count int
	}
	buckets := make(map[time.Time]*bucket)
	for _, points := range history {
		for _, point := range points {
			if point.Timestamp.Before(from) || point.Timestamp.After(to) {
				continue
			}
			at := point.Timestamp.UTC().Truncate(systemMetricsSampleInterval)
			current := buckets[at]
			if current == nil {
				current = &bucket{point: models.SystemMetricPoint{Timestamp: at}}
				buckets[at] = current
			}
			current.point.UptimeSeconds += point.UptimeSeconds
			current.point.CPUCores += point.CPUCores
			current.point.MemoryTotalBytes += point.MemoryTotalBytes
			current.point.CPUPercent += point.CPUPercent
			current.point.CPUUserPercent += point.CPUUserPercent
			current.point.CPUSystemPercent += point.CPUSystemPercent
			current.point.CPUIowaitPercent += point.CPUIowaitPercent
			current.point.CPUStealPercent += point.CPUStealPercent
			current.point.Load1 += point.Load1
			current.point.Load5 += point.Load5
			current.point.Load15 += point.Load15
			current.point.MemoryPercent += point.MemoryPercent
			current.point.MemoryUsedBytes += point.MemoryUsedBytes
			current.point.MemoryAvailableBytes += point.MemoryAvailableBytes
			current.point.SwapUsedBytes += point.SwapUsedBytes
			current.point.SwapUsedPercent += point.SwapUsedPercent
			current.point.RxBytesPerSecond += point.RxBytesPerSecond
			current.point.TxBytesPerSecond += point.TxBytesPerSecond
			current.point.RxPacketsPerSecond += point.RxPacketsPerSecond
			current.point.TxPacketsPerSecond += point.TxPacketsPerSecond
			current.point.RxErrorsPerSecond += point.RxErrorsPerSecond
			current.point.TxErrorsPerSecond += point.TxErrorsPerSecond
			current.point.RxDroppedPerSecond += point.RxDroppedPerSecond
			current.point.TxDroppedPerSecond += point.TxDroppedPerSecond
			current.point.DiskReadBytesPerSecond += point.DiskReadBytesPerSecond
			current.point.DiskWriteBytesPerSecond += point.DiskWriteBytesPerSecond
			current.point.DiskReadOpsPerSecond += point.DiskReadOpsPerSecond
			current.point.DiskWriteOpsPerSecond += point.DiskWriteOpsPerSecond
			current.point.DiskIOUtilizationPercent += point.DiskIOUtilizationPercent
			current.point.DiskReadAwaitMilliseconds += point.DiskReadAwaitMilliseconds
			current.point.DiskWriteAwaitMilliseconds += point.DiskWriteAwaitMilliseconds
			current.point.FilesystemUsedPercent += point.FilesystemUsedPercent
			current.point.FilesystemAvailableBytes += point.FilesystemAvailableBytes
			current.point.ContextSwitchesPerSecond += point.ContextSwitchesPerSecond
			current.point.InterruptsPerSecond += point.InterruptsPerSecond
			current.point.ForksPerSecond += point.ForksPerSecond
			current.point.ProcessesTotal += point.ProcessesTotal
			current.point.ProcessesRunning += point.ProcessesRunning
			current.point.ProcessesBlocked += point.ProcessesBlocked
			current.point.TCPInUse += point.TCPInUse
			current.point.TCPTimeWait += point.TCPTimeWait
			current.point.UDPInUse += point.UDPInUse
			current.point.FileDescriptorsAllocated += point.FileDescriptorsAllocated
			current.point.FileDescriptorsMaximum += point.FileDescriptorsMaximum
			current.point.FileDescriptorsUsedPercent += point.FileDescriptorsUsedPercent
			current.count++
		}
	}
	points := make([]models.SystemMetricPoint, 0, len(buckets))
	for _, current := range buckets {
		if current.count > 0 {
			current.point.UptimeSeconds /= float64(current.count)
			current.point.CPUPercent /= float64(current.count)
			current.point.CPUUserPercent /= float64(current.count)
			current.point.CPUSystemPercent /= float64(current.count)
			current.point.CPUIowaitPercent /= float64(current.count)
			current.point.CPUStealPercent /= float64(current.count)
			current.point.Load1 /= float64(current.count)
			current.point.Load5 /= float64(current.count)
			current.point.Load15 /= float64(current.count)
			current.point.MemoryPercent /= float64(current.count)
			current.point.SwapUsedPercent /= float64(current.count)
			current.point.DiskIOUtilizationPercent /= float64(current.count)
			current.point.DiskReadAwaitMilliseconds /= float64(current.count)
			current.point.DiskWriteAwaitMilliseconds /= float64(current.count)
			current.point.FilesystemUsedPercent /= float64(current.count)
			current.point.FileDescriptorsUsedPercent /= float64(current.count)
		}
		points = append(points, current.point)
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Timestamp.Before(points[j].Timestamp) })
	return points
}

func (h *ServerHandler) systemMetricNodeSummaries(nodes []models.Node) []models.SystemMetricNodeSummary {
	h.systemMetricsMu.Lock()
	defer h.systemMetricsMu.Unlock()
	result := make([]models.SystemMetricNodeSummary, 0, len(nodes))
	for _, node := range nodes {
		summary := models.SystemMetricNodeSummary{
			NodeID: node.ID,
			Name:   node.Name,
			Status: "offline",
		}
		if !node.LastSeenAt.IsZero() && time.Since(node.LastSeenAt) <= 2*time.Minute {
			summary.Status = "online"
		}
		history := h.systemMetricsHistory[node.ID]
		if len(history) > 0 {
			point := history[len(history)-1]
			summary.Timestamp = point.Timestamp
			summary.UptimeSeconds = point.UptimeSeconds
			summary.CPUPercent = point.CPUPercent
			summary.MemoryPercent = point.MemoryPercent
			summary.RxBytesPerSecond = point.RxBytesPerSecond
			summary.TxBytesPerSecond = point.TxBytesPerSecond
			summary.Disk.ReadBytesPerSecond = point.DiskReadBytesPerSecond
			summary.Disk.WriteBytesPerSecond = point.DiskWriteBytesPerSecond
			summary.Kernel.ContextSwitchesPerSecond = point.ContextSwitchesPerSecond
		}
		if cached, ok := h.systemMetricsCache[node.ID]; ok {
			summary.UptimeSeconds = cached.metrics.UptimeSeconds
			summary.CPUCores = cached.metrics.CPU.Cores
			summary.MemoryTotalBytes = cached.metrics.Memory.TotalBytes
			summary.MemoryUsedBytes = cached.metrics.Memory.UsedBytes
			summary.SwapUsedBytes = cached.metrics.Memory.SwapUsedBytes
			summary.Disk = cached.metrics.Disk
			summary.Kernel = cached.metrics.Kernel
			summary.Processes = cached.metrics.Processes
			summary.Sockets = cached.metrics.Sockets
			summary.FileDescriptors = cached.metrics.FileDescriptors
			summary.Filesystems = cached.metrics.Filesystems
		}
		result = append(result, summary)
	}
	return result
}

func (h *ServerHandler) handleClusterEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	send := func() {
		nodes := h.service.ListNodes(r.Context())
		nodesPayload, err := json.Marshal(nodes)
		if err != nil {
			return
		}
		overviewPayload, err := json.Marshal(map[string]any{
			"ingress": h.buildClusterAggregate(r.Context(), models.DirectionIngress),
			"egress":  h.buildClusterAggregate(r.Context(), models.DirectionEgress),
		})
		if err != nil {
			return
		}
		deletePayload, err := json.Marshal(h.listDeleteEvents())
		if err != nil {
			return
		}
		_, _ = w.Write([]byte("event: nodes\n"))
		_, _ = w.Write([]byte("data: " + string(nodesPayload) + "\n\n"))
		_, _ = w.Write([]byte("event: overview\n"))
		_, _ = w.Write([]byte("data: " + string(overviewPayload) + "\n\n"))
		_, _ = w.Write([]byte("event: node_delete\n"))
		_, _ = w.Write([]byte("data: " + string(deletePayload) + "\n\n"))
		flusher.Flush()
	}

	send()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

func (h *ServerHandler) buildClusterAggregate(ctx context.Context, direction models.PolicyDirection) map[string]any {
	result := map[string]any{
		"passed":         uint64(0),
		"dropped":        uint64(0),
		"recent_passed":  uint64(0),
		"recent_dropped": uint64(0),
		"passed_pps":     float64(0),
		"dropped_pps":    float64(0),
		"drop_rate":      float64(0),
		"window_seconds": int(trafficWindow / time.Second),
		"trusted":        uint64(0),
		"pendingRelease": uint64(0),
		"nodes":          []clusterNodeAggregate{},
		"top_attackers":  []models.SourceStat{},
		"top_countries":  []models.CountryStat{},
		"top_ports":      []models.PortStat{},
		"top_passed":     []models.SourceStat{},
		"trend":          []models.TrafficPoint{},
		"system": map[string]any{
			"node_count":             0,
			"sampled_nodes":          0,
			"average_cpu_percent":    float64(0),
			"average_memory_percent": float64(0),
			"rx_bytes_per_second":    float64(0),
			"tx_bytes_per_second":    float64(0),
		},
	}
	var passed, dropped, trusted, pendingRelease uint64
	windowTotals := trafficWindowStats{WindowSeconds: int(trafficWindow / time.Second)}
	sources := make(map[string]models.SourceStat)
	countries := make(map[string]models.CountryStat)
	ports := make(map[uint16]models.PortStat)
	trend := make(map[string]models.TrafficPoint)
	nodeRows := make([]clusterNodeAggregate, 0)
	var systemCPUSum, systemMemorySum, systemRxSum, systemTxSum float64
	var systemSampled, systemOnline int
	now := time.Now()

	mergeSource := func(item models.SourceStat) {
		key := strings.TrimSpace(item.SourceIP)
		if key == "" {
			return
		}
		current := sources[key]
		current.SourceIP = key
		current.Passed += item.Passed
		current.Dropped += item.Dropped
		current.Total = current.Passed + current.Dropped
		if current.Total > 0 {
			current.DropRatio = float64(current.Dropped) / float64(current.Total)
		}
		current.Risk = aggregateRisk(current.Passed, current.Dropped)
		if current.Geo == nil {
			current.Geo = item.Geo
		}
		if current.CountryCode == "" {
			current.CountryCode = item.CountryCode
			current.CountryName = item.CountryName
		}
		sources[key] = current
	}

	mergeCountry := func(item models.CountryStat) {
		key := strings.ToUpper(strings.TrimSpace(item.CountryCode))
		if key == "" {
			key = "UNKNOWN"
		}
		current := countries[key]
		current.CountryCode = key
		if current.CountryName == "" {
			current.CountryName = item.CountryName
		}
		current.Total += item.Total
		current.Dropped += item.Dropped
		current.Sources += item.Sources
		countries[key] = current
	}

	mergePort := func(item models.PortStat) {
		current := ports[item.Port]
		current.Port = item.Port
		current.Passed += item.Passed
		current.Dropped += item.Dropped
		current.Total = current.Passed + current.Dropped
		current.Risk = aggregateRisk(current.Passed, current.Dropped)
		ports[item.Port] = current
	}

	mergeTrend := func(item models.TrafficPoint) {
		key := strings.TrimSpace(item.Timestamp)
		if key == "" {
			return
		}
		current := trend[key]
		current.Timestamp = key
		current.Passed += item.Passed
		current.Dropped += item.Dropped
		trend[key] = current
	}

	nodes := h.service.ListNodes(ctx)
	for _, node := range nodes {
		if strings.TrimSpace(node.ID) == "" {
			continue
		}
		online := !node.LastSeenAt.IsZero() && now.Sub(node.LastSeenAt) <= 2*time.Minute
		nodeRow := clusterNodeAggregate{
			ID:               node.ID,
			Name:             node.Name,
			AgentURL:         node.AgentURL,
			Status:           "offline",
			ProtectionStatus: "unavailable",
			LastSeenAt:       node.LastSeenAt,
		}
		if online {
			nodeRow.Status = "online"
		}
		metricsCtx, metricsCancel := context.WithTimeout(ctx, 3*time.Second)
		systemMetrics, metricsErr := h.readSystemMetrics(metricsCtx, node)
		metricsCancel()
		if metricsErr == nil && systemMetrics != nil {
			nodeRow.CPUPercent = systemMetrics.CPU.UsagePercent
			nodeRow.MemoryPercent = systemMetrics.Memory.UsedPercent
			nodeRow.RxBytesPerSec = systemMetrics.Network.RxBytesPerSecond
			nodeRow.TxBytesPerSec = systemMetrics.Network.TxBytesPerSecond
			nodeRow.SystemMetrics = systemMetrics
			systemSampled++
			if online {
				systemOnline++
				systemCPUSum += systemMetrics.CPU.UsagePercent
				systemMemorySum += systemMetrics.Memory.UsedPercent
				systemRxSum += systemMetrics.Network.RxBytesPerSecond
				systemTxSum += systemMetrics.Network.TxBytesPerSecond
			}
		}
		nodeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		var inventory struct {
			Interfaces  []models.DetectedInterface `json:"interfaces"`
			Recommended string                     `json:"recommended"`
		}
		err := h.nodeJSON(nodeCtx, node.ID, http.MethodGet, "/interfaces", nil, &inventory)
		cancel()
		if err != nil {
			nodeRows = append(nodeRows, nodeRow)
			continue
		}
		interfaces := inventory.Interfaces
		if len(interfaces) == 0 {
			nodeRows = append(nodeRows, nodeRow)
			continue
		}
		var focus *models.DetectedInterface
		for i := range interfaces {
			if interfaces[i].IsPhysical && interfaces[i].Name == inventory.Recommended {
				focus = &interfaces[i]
				break
			}
		}
		if focus == nil {
			for i := range interfaces {
				if interfaces[i].IsPhysical {
					focus = &interfaces[i]
					break
				}
			}
		}
		if focus == nil {
			for i := range interfaces {
				if interfaces[i].Name == inventory.Recommended {
					focus = &interfaces[i]
					break
				}
			}
		}
		if focus == nil {
			focus = &interfaces[0]
		}
		if strings.TrimSpace(focus.Name) == "" {
			nodeRows = append(nodeRows, nodeRow)
			continue
		}
		iface := focus.Name
		nodeRow.Interface = iface
		var health models.HealthStatus
		healthCtx, healthCancel := context.WithTimeout(ctx, 3*time.Second)
		healthErr := h.nodeJSON(healthCtx, node.ID, http.MethodGet, "/health", nil, &health)
		healthCancel()
		if healthErr == nil {
			nodeRow.ProtectionStatus = protectionStatusForInterface(health, iface)
		}
		var stats struct {
			Passed  uint64 `json:"passed"`
			Dropped uint64 `json:"dropped"`
		}
		var allowlist struct {
			Allowlist []string `json:"allowlist"`
		}
		var bypass struct {
			BypassCIDRs []string `json:"bypass_cidrs"`
		}
		var tempBlocks struct {
			TemporaryBlocks []models.TemporaryBlock `json:"temporary_blocks"`
		}
		var insights models.InterfaceInsights
		_ = h.nodeJSON(ctx, node.ID, http.MethodGet, "/interfaces/"+iface+"/stats?direction="+string(direction), nil, &stats)
		_ = h.nodeJSON(ctx, node.ID, http.MethodGet, "/interfaces/"+iface+"/allowlist?direction="+string(direction), nil, &allowlist)
		_ = h.nodeJSON(ctx, node.ID, http.MethodGet, "/interfaces/"+iface+"/bypass?direction="+string(direction), nil, &bypass)
		_ = h.nodeJSON(ctx, node.ID, http.MethodGet, "/interfaces/"+iface+"/temporary-blocks?direction="+string(direction), nil, &tempBlocks)
		_ = h.nodeJSON(ctx, node.ID, http.MethodGet, "/interfaces/"+iface+"/insights?direction="+string(direction), nil, &insights)
		nodeRow.Passed = stats.Passed
		nodeRow.Dropped = stats.Dropped
		recent := recentTrafficStats(models.InterfaceStats{Direction: direction, Passed: stats.Passed, Dropped: stats.Dropped}, insights.Trend, now)
		nodeRow.RecentPassed = recent.RecentPassed
		nodeRow.RecentDropped = recent.RecentDropped
		nodeRow.RecentDropRate = recent.DropRate
		nodeRow.Trusted = uint64(len(allowlist.Allowlist) + len(bypass.BypassCIDRs))
		nodeRow.PendingRelease = uint64(len(tempBlocks.TemporaryBlocks))
		nodeRows = append(nodeRows, nodeRow)
		passed += stats.Passed
		dropped += stats.Dropped
		mergeTrafficWindow(&windowTotals, recent)
		trusted += nodeRow.Trusted
		pendingRelease += nodeRow.PendingRelease

		seenSources := make(map[string]struct{})
		for _, item := range append(append([]models.SourceStat{}, insights.TopPassed...), insights.TopDropped...) {
			if _, ok := seenSources[item.SourceIP]; ok {
				continue
			}
			seenSources[item.SourceIP] = struct{}{}
			mergeSource(item)
		}
		for _, item := range insights.TopCountries {
			mergeCountry(item)
		}
		for _, item := range insights.TopPorts {
			mergePort(item)
		}
		for _, item := range insights.Trend {
			mergeTrend(item)
		}
	}

	sourceItems := make([]models.SourceStat, 0, len(sources))
	for _, item := range sources {
		sourceItems = append(sourceItems, item)
	}
	topPassed := append([]models.SourceStat(nil), sourceItems...)
	sort.Slice(topPassed, func(i, j int) bool {
		if topPassed[i].Passed == topPassed[j].Passed {
			return topPassed[i].Dropped > topPassed[j].Dropped
		}
		return topPassed[i].Passed > topPassed[j].Passed
	})
	if len(topPassed) > 10 {
		topPassed = topPassed[:10]
	}
	topAttackers := append([]models.SourceStat(nil), sourceItems...)
	sort.Slice(topAttackers, func(i, j int) bool {
		if topAttackers[i].Dropped == topAttackers[j].Dropped {
			return topAttackers[i].Passed > topAttackers[j].Passed
		}
		return topAttackers[i].Dropped > topAttackers[j].Dropped
	})
	if len(topAttackers) > 10 {
		topAttackers = topAttackers[:10]
	}

	countryItems := make([]models.CountryStat, 0, len(countries))
	for _, item := range countries {
		countryItems = append(countryItems, item)
	}
	sort.Slice(countryItems, func(i, j int) bool {
		if countryItems[i].Dropped == countryItems[j].Dropped {
			return countryItems[i].Total > countryItems[j].Total
		}
		return countryItems[i].Dropped > countryItems[j].Dropped
	})
	if len(countryItems) > 10 {
		countryItems = countryItems[:10]
	}

	portItems := make([]models.PortStat, 0, len(ports))
	for _, item := range ports {
		portItems = append(portItems, item)
	}
	sort.Slice(portItems, func(i, j int) bool {
		if portItems[i].Total == portItems[j].Total {
			return portItems[i].Dropped > portItems[j].Dropped
		}
		return portItems[i].Total > portItems[j].Total
	})
	if len(portItems) > 10 {
		portItems = portItems[:10]
	}

	trendItems := make([]models.TrafficPoint, 0, len(trend))
	for _, item := range trend {
		trendItems = append(trendItems, item)
	}
	sort.Slice(trendItems, func(i, j int) bool { return trendItems[i].Timestamp < trendItems[j].Timestamp })
	if len(trendItems) > 24 {
		trendItems = trendItems[len(trendItems)-24:]
	}

	result["passed"] = passed
	result["dropped"] = dropped
	result["recent_passed"] = windowTotals.RecentPassed
	result["recent_dropped"] = windowTotals.RecentDropped
	result["passed_pps"] = windowTotals.PassedPPS
	result["dropped_pps"] = windowTotals.DroppedPPS
	result["drop_rate"] = windowTotals.DropRate
	result["trusted"] = trusted
	result["pendingRelease"] = pendingRelease
	result["nodes"] = nodeRows
	result["top_attackers"] = topAttackers
	result["top_countries"] = countryItems
	result["top_ports"] = portItems
	result["top_passed"] = topPassed
	result["trend"] = trendItems
	systemSummary := map[string]any{
		"node_count":             len(nodes),
		"sampled_nodes":          systemSampled,
		"average_cpu_percent":    float64(0),
		"average_memory_percent": float64(0),
		"rx_bytes_per_second":    float64(0),
		"tx_bytes_per_second":    float64(0),
	}
	if systemOnline > 0 {
		systemSummary["average_cpu_percent"] = systemCPUSum / float64(systemOnline)
		systemSummary["average_memory_percent"] = systemMemorySum / float64(systemOnline)
		systemSummary["rx_bytes_per_second"] = systemRxSum
		systemSummary["tx_bytes_per_second"] = systemTxSum
	}
	result["system"] = systemSummary
	return result
}

func protectionStatusForInterface(health models.HealthStatus, iface string) string {
	for _, item := range health.Interfaces {
		if item.Interface != iface {
			continue
		}
		switch {
		case !item.XDPAttached:
			return "not_enabled"
		case item.ObserveOnly:
			return "not_enabled"
		case item.MapOK && item.StatsOK && item.PolicyEnforced && item.EnforcementOK:
			return "enforced"
		default:
			return "degraded"
		}
	}
	if health.Status == "ok" {
		return "not_enabled"
	}
	return "unavailable"
}

func aggregateRisk(passed, dropped uint64) string {
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

func (h *ServerHandler) handleUpsertNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string                       `json:"id"`
		Name     string                       `json:"name"`
		AgentURL string                       `json:"agent_url"`
		SSH      *models.SSHConnectionProfile `json:"ssh"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Name = strings.TrimSpace(req.Name)
	req.AgentURL = strings.TrimSpace(req.AgentURL)
	if req.ID == "" || req.AgentURL == "" {
		writeError(w, http.StatusBadRequest, errors.New("id and agent_url are required"))
		return
	}
	if req.Name == "" {
		req.Name = req.ID
	}
	node := models.Node{ID: req.ID, Name: req.Name, AgentURL: req.AgentURL, SSH: req.SSH}
	h.store.UpsertNode(r.Context(), node)
	writeJSON(w, http.StatusOK, node)
}

func (h *ServerHandler) handleUpdateNodeName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	node, err := h.store.UpdateNodeName(r.Context(), r.PathValue("node"), req.Name)
	if err != nil {
		if errors.Is(err, store.ErrNodeNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (h *ServerHandler) handleNodeSSHConnection(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node"))
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	if r.Method == http.MethodGet {
		profile := node.SSH
		if profile == nil {
			profile = &models.SSHConnectionProfile{Host: node.AdvertiseIP, Port: 22, User: "root"}
		}
		writeJSON(w, http.StatusOK, profile)
		return
	}

	var profile models.SSHConnectionProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	normalized, err := normalizeSSHConnectionProfile(profile, node)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	node.SSH = &normalized
	h.store.UpsertNode(r.Context(), node)
	writeJSON(w, http.StatusOK, normalized)
}

func (h *ServerHandler) handleNodeSSHConnectionTest(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node"))
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	profile := models.SSHConnectionProfile{}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&profile); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if profile.Host == "" && node.SSH != nil {
		profile = *node.SSH
	}
	normalized, err := normalizeSSHConnectionProfile(profile, node)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	address := net.JoinHostPort(normalized.Host, strconv.Itoa(int(normalized.Port)))
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("ssh port is unreachable: %w", err))
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	banner := make([]byte, 256)
	n, readErr := conn.Read(banner)
	bannerText := ""
	if n > 0 {
		bannerText = string(banner[:n])
	}
	if readErr != nil || !strings.HasPrefix(bannerText, "SSH-") {
		writeError(w, http.StatusBadGateway, errors.New("port is reachable but is not an SSH service"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "reachable",
		"profile": normalized,
		"banner":  strings.TrimSpace(bannerText),
	})
}

func normalizeSSHConnectionProfile(profile models.SSHConnectionProfile, node models.Node) (models.SSHConnectionProfile, error) {
	profile.Host = strings.TrimSpace(profile.Host)
	profile.User = strings.TrimSpace(profile.User)
	if profile.Host == "" {
		profile.Host = strings.TrimSpace(node.AdvertiseIP)
	}
	if profile.Port == 0 {
		profile.Port = 22
	}
	if profile.User == "" {
		profile.User = "root"
	}
	if profile.Host == "" || !validSSHHost(profile.Host) {
		return profile, errors.New("ssh host must be an IPv4, IPv6, or hostname")
	}
	if profile.Port == 0 {
		return profile, errors.New("ssh port must be between 1 and 65535")
	}
	if !validSSHUser(profile.User) {
		return profile, errors.New("ssh user contains invalid characters")
	}
	return profile, nil
}

func validSSHHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return !addr.IsUnspecified()
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if part == "" || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		for _, char := range part {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '_' {
				return false
			}
		}
	}
	return true
}

func validSSHUser(user string) bool {
	if len(user) == 0 || len(user) > 64 {
		return false
	}
	for _, char := range user {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && !strings.ContainsRune("._-", char) {
			return false
		}
	}
	return true
}

func (h *ServerHandler) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node id is required"))
		return
	}
	nodes := h.service.ListNodes(r.Context())
	node, ok := service.FindNode(nodes, nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}

	h.pushDeleteEvent(nodeID, "start", "running", "node delete requested")
	cleanupStatus := "skipped"
	agentDeleteStatus := "skipped"
	lastSeen := node.LastSeenAt
	isOnline := !lastSeen.IsZero() && time.Since(lastSeen) <= 2*time.Minute
	if isOnline && strings.TrimSpace(node.AgentURL) != "" {
		h.pushDeleteEvent(nodeID, "cleanup", "running", "triggering remote cleanup")
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(node.AgentURL, "/")+"/maintenance/cleanup", nil)
		if err == nil {
			if resp, err := h.reverseHTTP.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode < 300 {
					cleanupStatus = "cleaned"
					h.pushDeleteEvent(nodeID, "cleanup", "success", "remote cleanup done")
				} else {
					cleanupStatus = "cleanup_failed"
					h.pushDeleteEvent(nodeID, "cleanup", "failed", "remote cleanup failed")
				}
			} else {
				cleanupStatus = "cleanup_unreachable"
				h.pushDeleteEvent(nodeID, "cleanup", "failed", "remote cleanup unreachable")
			}
		} else {
			cleanupStatus = "cleanup_failed"
			h.pushDeleteEvent(nodeID, "cleanup", "failed", "remote cleanup request build failed")
		}
		cancel()

		h.pushDeleteEvent(nodeID, "agent_delete", "running", "triggering remote full delete")
		ctxDelete, cancelDelete := context.WithTimeout(r.Context(), 5*time.Second)
		body := bytes.NewBufferString(`{"full_delete":true}`)
		delReq, err := http.NewRequestWithContext(ctxDelete, http.MethodPost, strings.TrimRight(node.AgentURL, "/")+"/maintenance/delete", body)
		if err == nil {
			delReq.Header.Set("Content-Type", "application/json")
			if resp, err := h.reverseHTTP.Do(delReq); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode < 300 {
					agentDeleteStatus = "triggered"
					h.pushDeleteEvent(nodeID, "agent_delete", "success", "remote full delete triggered")
				} else {
					agentDeleteStatus = "failed"
					h.pushDeleteEvent(nodeID, "agent_delete", "failed", "remote full delete failed")
				}
			} else {
				agentDeleteStatus = "unreachable"
				h.pushDeleteEvent(nodeID, "agent_delete", "failed", "remote full delete unreachable")
			}
		} else {
			agentDeleteStatus = "failed"
			h.pushDeleteEvent(nodeID, "agent_delete", "failed", "remote full delete request build failed")
		}
		cancelDelete()
	}

	if h.nodeCredentials != nil {
		if err := h.nodeCredentials.Revoke(nodeID); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("revoke node credential: %w", err))
			return
		}
	}
	deleted := h.store.DeleteNode(r.Context(), nodeID)
	if !deleted {
		h.pushDeleteEvent(nodeID, "finalize", "failed", "node not found while deleting")
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	h.pushDeleteEvent(nodeID, "finalize", "success", "node removed from manager list")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":              "deleted",
		"node_id":             nodeID,
		"cleanup_status":      cleanupStatus,
		"agent_delete_status": agentDeleteStatus,
	})
}

func (h *ServerHandler) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	writeJSON(w, http.StatusOK, policy)
}

func (h *ServerHandler) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var rawPolicy models.InterfacePolicy
	if err := json.Unmarshal(body, &rawPolicy); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var envelope struct {
		Policy          *models.InterfacePolicy `json:"policy"`
		ConfirmPassword string                  `json:"confirm_password"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := rawPolicy
	if envelope.Policy != nil {
		policy = *envelope.Policy
	}
	policy.NodeID = r.PathValue("node")
	policy.Interface = r.PathValue("iface")
	policy = h.ensureControlPlanePortRules(policy)
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), policy.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	current := h.ensurePolicy(r.Context(), node.ID, policy.Interface)
	if h.blockUnsafeSSHPolicy(w, r, current, policy, envelope.ConfirmPassword) {
		return
	}
	updated, err := h.service.UpdatePolicyAndApply(r.Context(), policy)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleEnableProtectionBaseline turns on host enforcement only after the
// access rules needed to recover the node are part of the same policy update.
// XDP itself stays fail-open until the agent receives this populated policy.
func (h *ServerHandler) handleEnableProtectionBaseline(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TrialSeconds int `json:"trial_seconds"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, errors.New("invalid protection baseline request"))
			return
		}
	}
	if request.TrialSeconds < 0 || request.TrialSeconds > 120 {
		writeError(w, http.StatusBadRequest, errors.New("trial_seconds must be between 0 and 120"))
		return
	}
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), r.PathValue("node"))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}

	policy := h.ensurePolicy(r.Context(), node.ID, r.PathValue("iface"))
	ingress := models.DirectionPolicyFor(policy, models.DirectionIngress)
	ingress.Enabled = true
	ingress.Mode = "whitelist"
	ingress.DefaultAction = "drop"
	ingress.NonIPv4Action = models.NonIPv4Drop
	ingress.ObserveOnly = false

	var sshInfo sshAccessInfo
	if err := h.nodeJSON(r.Context(), node.ID, http.MethodGet, "/system/ssh", nil, &sshInfo); err != nil || len(sshInfo.Ports) == 0 {
		writeError(w, http.StatusBadGateway, errors.New("cannot detect sshd ports; protection was not enabled"))
		return
	}
	sshPorts := sshInfo.Ports
	baselinePorts := h.recoveryPortRulesForNode(r.Context(), node)
	for _, rule := range baselinePorts {
		ingress.PublicPortRules = appendUniquePortRule(ingress.PublicPortRules, rule)
	}
	ingress.PublicPorts = models.CollapsePortRules(ingress.PublicPortRules)
	policy = models.WithDirectionPolicy(policy, models.DirectionIngress, ingress)
	policy = h.service.WithClusterInterconnect(r.Context(), policy)
	policy = h.ensureControlPlanePortRules(policy)

	if request.TrialSeconds > 0 {
		updated, trial, err := h.service.BeginPolicyTrial(r.Context(), policy, time.Duration(request.TrialSeconds)*time.Second)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "trial",
			"policy": updated,
			"trial":  trial,
			"baseline": map[string]any{
				"ssh_ports":     sshPorts,
				"control_ports": baselinePorts,
				"cluster_nodes": len(h.service.ListNodes(r.Context())),
			},
		})
		return
	}

	updated, err := h.service.UpdatePolicyAndApply(r.Context(), policy)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy": updated,
		"baseline": map[string]any{
			"ssh_ports":     sshPorts,
			"control_ports": baselinePorts,
			"cluster_nodes": len(h.service.ListNodes(r.Context())),
		},
	})
}

func (h *ServerHandler) handleConfirmProtectionBaseline(w http.ResponseWriter, r *http.Request) {
	updated, err := h.service.ConfirmPolicyTrial(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "confirmed",
		"policy": updated,
	})
}

func (h *ServerHandler) handleRollbackProtectionBaseline(w http.ResponseWriter, r *http.Request) {
	if err := h.service.RollbackPolicyTrial(r.Context(), r.PathValue("node"), r.PathValue("iface")); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
}

func policyRequiresSSHConfirmation(ctx context.Context, h *ServerHandler, node models.Node, current, next models.InterfacePolicy) bool {
	ports := sshPortsForNode(ctx, h, node)
	currentIngress := models.DirectionPolicyFor(current, models.DirectionIngress)
	nextIngress := models.DirectionPolicyFor(next, models.DirectionIngress)
	for _, port := range ports {
		if portPolicyChanges(currentIngress, nextIngress, port) {
			return true
		}
	}
	return false
}

func portPolicyChanges(current, next models.DirectionPolicy, port uint16) bool {
	return effectiveTCPPortAction(current, port) == "allow" && effectiveTCPPortAction(next, port) != "allow"
}

func effectiveTCPPortAction(policy models.DirectionPolicy, port uint16) string {
	contains := func(rules []models.PortRule, ports []uint16) bool {
		for _, rule := range models.NormalizePortRules(rules, ports) {
			if rule.Port == port && rule.Protocol == models.PortProtocolTCP {
				return true
			}
		}
		return false
	}
	if contains(policy.DeniedPortRules, policy.DeniedPorts) {
		return "deny"
	}
	if contains(policy.PublicPortRules, policy.PublicPorts) || contains(policy.AllowedPortRules, policy.AllowedPorts) {
		return "allow"
	}
	if len(policy.AllowedPortRules) > 0 || len(policy.AllowedPorts) > 0 {
		return "deny"
	}
	return "allow"
}

func sshPortsForNode(ctx context.Context, h *ServerHandler, node models.Node) []uint16 {
	var payload struct {
		Ports []uint16 `json:"ports"`
	}
	if err := h.nodeJSON(ctx, node.ID, http.MethodGet, "/system/ssh", nil, &payload); err == nil && len(payload.Ports) > 0 {
		return payload.Ports
	}
	return []uint16{22}
}

func confirmPasswordFromRequest(r *http.Request) string {
	return confirmationPassword(r)
}

func (h *ServerHandler) sshMutationBlocked(w http.ResponseWriter, r *http.Request, policy models.InterfacePolicy, port uint16, action, password string) bool {
	if requestDirection(r) != models.DirectionIngress || port == 0 {
		return false
	}
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), r.PathValue("node"))
	if !ok {
		return false
	}
	ports := sshPortsForNode(r.Context(), h, node)
	for _, sshPort := range ports {
		if sshPort != port {
			continue
		}
		currentAction := effectiveTCPPortAction(models.DirectionPolicyFor(policy, models.DirectionIngress), port)
		nextAction := action
		if action == "remove" {
			if currentAction != "allow" {
				return false
			}
			nextAction = "deny"
		}
		if nextAction == "allow" {
			return false
		}
		if currentAction == nextAction {
			return false
		}
		if h.auth == nil || !h.auth.verifyCurrentPassword(r, password) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   "ssh confirmation required",
				"code":    "SSH_CONFIRM_REQUIRED",
				"service": "sshd",
				"port":    port,
			})
			return true
		}
	}
	return false
}

func (h *ServerHandler) handleProxyHealth(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/health")
}

func (h *ServerHandler) handleProxySystemMetrics(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/system/metrics")
}

func (h *ServerHandler) handleProxySecuritySummary(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/security/summary")
}

func (h *ServerHandler) handleProxySecurityScan(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/security/scan")
}

func (h *ServerHandler) handleProxySecurityScanReport(w http.ResponseWriter, r *http.Request) {
	path := "/security/scan/report"
	if id := r.PathValue("scan"); id != "" {
		path = "/security/scan/reports/" + url.PathEscape(id)
	}
	if query := r.URL.RawQuery; query != "" {
		path += "?" + query
	}
	h.proxy(w, r, path)
}

func (h *ServerHandler) handleProxySecurityScanReports(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/security/scan/reports")
}

func (h *ServerHandler) handleProxySecurityQuarantine(w http.ResponseWriter, r *http.Request) {
	finding := url.PathEscape(r.PathValue("finding"))
	h.proxy(w, r, "/security/scan/"+finding+"/quarantine")
}

func (h *ServerHandler) handleProxySecurityProcessTerminate(w http.ResponseWriter, r *http.Request) {
	finding := url.PathEscape(r.PathValue("finding"))
	h.proxy(w, r, "/security/scan/"+finding+"/terminate")
}

func (h *ServerHandler) handleProxySecurityQuarantineList(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/security/quarantine")
}

func (h *ServerHandler) handleProxySecurityQuarantineDelete(w http.ResponseWriter, r *http.Request) {
	entry := url.PathEscape(r.PathValue("entry"))
	h.proxy(w, r, "/security/quarantine/"+entry)
}

func (h *ServerHandler) handleProxySecurityQuarantineRestore(w http.ResponseWriter, r *http.Request) {
	entry := url.PathEscape(r.PathValue("entry"))
	h.proxy(w, r, "/security/quarantine/"+entry+"/restore")
}

func (h *ServerHandler) handleProxySSHProtection(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("node")
	var payload any
	if r.Method == http.MethodGet {
		payload = nil
	} else {
		var settings models.SSHProtectionSettings
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		payload = settings
	}
	var response models.SSHProtectionStatus
	if err := h.nodeJSON(r.Context(), nodeID, r.Method, "/ssh-protection", payload, &response); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *ServerHandler) handleProxySSHActivity(w http.ResponseWriter, r *http.Request) {
	path := "/ssh-protection/activity"
	if query := r.URL.RawQuery; query != "" {
		path += "?" + query
	}
	var response map[string]any
	if err := h.nodeJSON(r.Context(), r.PathValue("node"), http.MethodGet, path, nil, &response); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

type sshTransferPolicyRequest struct {
	models.SSHTransferPolicy
	CurrentPassword string `json:"current_password"`
}

func (h *ServerHandler) handleProxySSHTransferPolicy(w http.ResponseWriter, r *http.Request) {
	var request sshTransferPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if h.auth != nil && !h.auth.verifyCurrentPassword(r, request.CurrentPassword) {
		writeError(w, http.StatusUnauthorized, errors.New("current password confirmation is required"))
		return
	}
	if h.auth == nil && strings.TrimSpace(request.CurrentPassword) == "" {
		writeError(w, http.StatusUnauthorized, errors.New("current password confirmation is required"))
		return
	}
	var response models.SSHProtectionStatus
	if err := h.nodeJSON(r.Context(), r.PathValue("node"), http.MethodPut, "/ssh-protection/transfer", request.SSHTransferPolicy, &response); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

type sshIntegrityBaselineRequest struct {
	CurrentPassword string `json:"current_password"`
}

func (h *ServerHandler) handleProxySSHIntegrityBaseline(w http.ResponseWriter, r *http.Request) {
	var request sshIntegrityBaselineRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if h.auth != nil && !h.auth.verifyCurrentPassword(r, request.CurrentPassword) {
		writeError(w, http.StatusUnauthorized, errors.New("current password confirmation is required"))
		return
	}
	if h.auth == nil && strings.TrimSpace(request.CurrentPassword) == "" {
		writeError(w, http.StatusUnauthorized, errors.New("current password confirmation is required"))
		return
	}
	var response map[string]any
	if err := h.nodeJSON(r.Context(), r.PathValue("node"), http.MethodPost, "/ssh-protection/integrity/baseline", nil, &response); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *ServerHandler) handleProxySSHIntegrityVerify(w http.ResponseWriter, r *http.Request) {
	var response map[string]any
	if err := h.nodeJSON(r.Context(), r.PathValue("node"), http.MethodPost, "/ssh-protection/integrity/verify", nil, &response); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *ServerHandler) handleProxySSHProtectionBlockDelete(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("node")
	path := "/ssh-protection/blocks/" + url.PathEscape(r.PathValue("id"))
	if err := h.nodeJSON(r.Context(), nodeID, http.MethodDelete, path, nil, nil); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "released"})
}

func (h *ServerHandler) handleProxyInterfaces(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("node")
	var payload struct {
		Interfaces  []models.DetectedInterface `json:"interfaces"`
		Recommended string                     `json:"recommended"`
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := h.nodeJSON(ctx, nodeID, http.MethodGet, "/interfaces", nil, &payload); err == nil {
		writeJSON(w, http.StatusOK, payload)
		return
	}

	// Graceful fallback: return predictable payload so the UI does not stay pending on broken nodes.
	writeJSON(w, http.StatusOK, h.inferInterfacesFallback(r.Context(), nodeID))
}

func (h *ServerHandler) handleProxyInterfaceSummary(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("node")
	iface := r.PathValue("iface")
	direction := requestDirection(r)

	policy := h.ensurePolicy(r.Context(), nodeID, iface)
	var health models.HealthStatus
	var stats models.InterfaceStats
	var insights models.InterfaceInsights
	var bypass struct {
		BypassCIDRs []string `json:"bypass_cidrs"`
	}
	var blocked struct {
		BlockedCIDRs []string `json:"blocked_cidrs"`
	}
	var icmpAllow struct {
		ICMPAllowCIDRs []string `json:"icmp_allow_cidrs"`
	}
	var icmpBlocked struct {
		ICMPBlockedCIDRs []string `json:"icmp_blocked_cidrs"`
	}
	var allowlist struct {
		Allowlist []string `json:"allowlist"`
	}
	var publicPorts struct {
		PublicPorts     []uint16          `json:"public_ports"`
		PublicPortRules []models.PortRule `json:"public_port_rules"`
	}
	var deniedPorts struct {
		DeniedPorts     []uint16          `json:"denied_ports"`
		DeniedPortRules []models.PortRule `json:"denied_port_rules"`
	}
	var allowedPorts struct {
		Ports            []uint16          `json:"ports"`
		AllowedPortRules []models.PortRule `json:"port_rules"`
	}
	var interfaceLogs struct {
		Logs []models.DropLogRecord `json:"logs"`
	}
	var temporaryBlocks struct {
		TemporaryBlocks []models.TemporaryBlock `json:"temporary_blocks"`
	}
	var rateLimits struct {
		RateLimits []models.RateLimitRule `json:"rate_limits"`
	}

	get := func(path string, out any) error {
		ctx, cancel := context.WithTimeout(r.Context(), 1200*time.Millisecond)
		defer cancel()
		return h.nodeJSON(ctx, nodeID, http.MethodGet, path, nil, out)
	}
	var wg sync.WaitGroup
	wg.Add(14)
	go func() { defer wg.Done(); _ = get("/health", &health) }()
	go func() { defer wg.Done(); _ = get(withDirection("/interfaces/"+iface+"/stats", direction), &stats) }()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/insights", direction), &insights)
	}()
	go func() { defer wg.Done(); _ = get(withDirection("/interfaces/"+iface+"/bypass", direction), &bypass) }()
	go func() { defer wg.Done(); _ = get(withDirection("/interfaces/"+iface+"/block", direction), &blocked) }()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/icmp-allowlist", direction), &icmpAllow)
	}()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/icmp-blocklist", direction), &icmpBlocked)
	}()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/allowlist", direction), &allowlist)
	}()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/public-ports", direction), &publicPorts)
	}()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/denied-ports", direction), &deniedPorts)
	}()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/ports", direction), &allowedPorts)
	}()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/drop-logs", direction), &interfaceLogs)
	}()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/temporary-blocks", direction), &temporaryBlocks)
	}()
	go func() {
		defer wg.Done()
		_ = get(withDirection("/interfaces/"+iface+"/rate-limits", direction), &rateLimits)
	}()
	wg.Wait()

	// The manager policy is durable state, while the agent is the source of
	// truth for the rules currently loaded into XDP. A previous direct agent
	// update (or an interrupted manager apply) can leave the manager showing an
	// empty observe policy even though the dataplane is enforcing rules. Adopt
	// that active agent snapshot once, so the UI and subsequent edits operate on
	// the rules that are actually protecting the host.
	if recovered, ok := recoverPolicyFromAgent(policy, direction, health, allowlist.Allowlist,
		bypass.BypassCIDRs, blocked.BlockedCIDRs, icmpAllow.ICMPAllowCIDRs,
		icmpBlocked.ICMPBlockedCIDRs, publicPorts.PublicPorts, publicPorts.PublicPortRules,
		deniedPorts.DeniedPorts, deniedPorts.DeniedPortRules, allowedPorts.Ports,
		allowedPorts.AllowedPortRules); ok {
		if !reflect.DeepEqual(models.NormalizeInterfacePolicy(policy), models.NormalizeInterfacePolicy(recovered)) {
			policy = h.store.PutPolicy(r.Context(), recovered)
		} else {
			policy = recovered
		}
	}
	var protectionTrial any
	if recovery, ok := h.store.PendingPolicyUpdate(nodeID, iface); ok && recovery.TrialExpiresAt.After(time.Now()) {
		protectionTrial = map[string]any{
			"expires_at": recovery.TrialExpiresAt,
			"seconds":    int(time.Until(recovery.TrialExpiresAt).Round(time.Second) / time.Second),
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"policy":             policy,
		"protection_trial":   protectionTrial,
		"health":             health,
		"stats":              stats,
		"recent_stats":       recentTrafficStats(stats, insights.Trend, time.Now()),
		"insights":           insights,
		"bypass":             bypass.BypassCIDRs,
		"blocked":            blocked.BlockedCIDRs,
		"icmp_allow":         icmpAllow.ICMPAllowCIDRs,
		"icmp_blocked":       icmpBlocked.ICMPBlockedCIDRs,
		"allowlist":          allowlist.Allowlist,
		"public_ports":       publicPorts.PublicPorts,
		"public_port_rules":  publicPorts.PublicPortRules,
		"denied_ports":       deniedPorts.DeniedPorts,
		"denied_port_rules":  deniedPorts.DeniedPortRules,
		"ports":              allowedPorts.Ports,
		"allowed_port_rules": allowedPorts.AllowedPortRules,
		"interface_logs":     interfaceLogs.Logs,
		"temporary_blocks":   temporaryBlocks.TemporaryBlocks,
		"rate_limits":        rateLimits.RateLimits,
	})
}

func recoverPolicyFromAgent(policy models.InterfacePolicy, direction models.PolicyDirection, health models.HealthStatus,
	allowlist, bypass, blocked, icmpAllow, icmpBlocked []string,
	publicPorts []uint16, publicRules []models.PortRule,
	deniedPorts []uint16, deniedRules []models.PortRule,
	allowedPorts []uint16, allowedRules []models.PortRule) (models.InterfacePolicy, bool) {
	selected := models.DirectionPolicyFor(policy, direction)
	if !policyNeedsAgentRecovery(selected) {
		return policy, false
	}

	publicRules = models.NormalizePortRules(publicRules, publicPorts)
	deniedRules = models.NormalizePortRules(deniedRules, deniedPorts)
	allowedRules = models.NormalizePortRules(allowedRules, allowedPorts)
	evidence := len(allowlist) + len(bypass) + len(blocked) + len(icmpAllow) + len(icmpBlocked) +
		len(publicRules) + len(deniedRules) + len(allowedRules)
	if evidence == 0 {
		return policy, false
	}

	// If the health request completed, prefer an attached/enforced snapshot.
	// Rule data alone is still sufficient when the health probe timed out.
	active := false
	for _, item := range health.Interfaces {
		if item.Interface == policy.Interface && (item.XDPAttached || item.PolicyEnforced) {
			active = true
			break
		}
	}
	if !active && len(allowlist) == 0 && len(allowedRules) == 0 && len(publicRules) == 0 {
		return policy, false
	}

	next := selected
	next.Enabled = true
	next.Mode = "whitelist"
	next.DefaultAction = "drop"
	next.NonIPv4Action = models.NonIPv4Drop
	next.ObserveOnly = false
	next.BypassCIDRs = append([]string(nil), bypass...)
	next.BlockedCIDRs = append([]string(nil), blocked...)
	next.ICMPAllowCIDRs = append([]string(nil), icmpAllow...)
	next.ICMPBlockedCIDRs = append([]string(nil), icmpBlocked...)
	next.Rules = make([]models.ACLRule, 0, len(allowlist))
	for _, cidr := range allowlist {
		next.Rules = append(next.Rules, models.ACLRule{CIDR: cidr, Action: "allow"})
	}
	next.PublicPortRules = publicRules
	next.DeniedPortRules = deniedRules
	next.AllowedPortRules = allowedRules
	next.PublicPorts = models.CollapsePortRules(publicRules)
	next.DeniedPorts = models.CollapsePortRules(deniedRules)
	next.AllowedPorts = models.CollapsePortRules(allowedRules)
	return models.WithDirectionPolicy(policy, direction, next), true
}

func policyNeedsAgentRecovery(policy models.DirectionPolicy) bool {
	if !strings.EqualFold(strings.TrimSpace(policy.Mode), "observe") &&
		!strings.EqualFold(strings.TrimSpace(policy.DefaultAction), "pass") {
		return false
	}
	return len(policy.Rules) == 0 && len(policy.BypassCIDRs) == 0 && len(policy.BlockedCIDRs) == 0 &&
		len(policy.ICMPAllowCIDRs) == 0 && len(policy.ICMPBlockedCIDRs) == 0 &&
		len(policy.PublicPorts) == 0 && len(policy.DeniedPorts) == 0 && len(policy.AllowedPorts) == 0 &&
		len(policy.PublicPortRules) == 0 && len(policy.DeniedPortRules) == 0 && len(policy.AllowedPortRules) == 0
}

func (h *ServerHandler) handleProxyInsights(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/interfaces/"+r.PathValue("iface")+"/insights")
}

func (h *ServerHandler) handleProxyDropLogs(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/interfaces/"+r.PathValue("iface")+"/drop-logs")
}

func (h *ServerHandler) handleProxyStats(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/interfaces/"+r.PathValue("iface")+"/stats")
}

func (h *ServerHandler) handleProxyAttach(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/interfaces/"+r.PathValue("iface")+"/attach")
}

func (h *ServerHandler) handleProxyDetach(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/interfaces/"+r.PathValue("iface")+"/detach")
}

func (h *ServerHandler) handleProxyBypass(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, requestDirection(r))
	writeJSON(w, http.StatusOK, map[string]any{"bypass_cidrs": cloneStringSlice(selected.BypassCIDRs)})
}

func (h *ServerHandler) handleProxyBypassUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	selected.BypassCIDRs = appendUnique(selected.BypassCIDRs, req.CIDR)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyBypassDelete(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	selected.BypassCIDRs = deleteString(selected.BypassCIDRs, cidrFromRequest(r))
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyBlock(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, requestDirection(r))
	writeJSON(w, http.StatusOK, map[string]any{"blocked_cidrs": cloneStringSlice(selected.BlockedCIDRs)})
}

func (h *ServerHandler) handleProxyBlockUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	selected.BlockedCIDRs = appendUnique(selected.BlockedCIDRs, req.CIDR)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyBlockDelete(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	selected.BlockedCIDRs = deleteString(selected.BlockedCIDRs, cidrFromRequest(r))
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyAllowlist(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, requestDirection(r))
	writeJSON(w, http.StatusOK, map[string]any{"allowlist": extractCIDRs(selected.Rules)})
}

func (h *ServerHandler) handleProxyAllowlistUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR    string `json:"cidr"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	rules := appendOrUpdateAllowRule(selected.Rules, req.CIDR, req.Comment)
	selected.Rules = rules
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyAllowlistDelete(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	cidrs := deleteString(extractCIDRs(selected.Rules), cidrFromRequest(r))
	selected.Rules = makeAllowRules(cidrs)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyRuleDescription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind        string `json:"kind"`
		Value       string `json:"value"`
		Protocol    string `json:"protocol"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Kind = strings.TrimSpace(req.Kind)
	req.Value = strings.TrimSpace(req.Value)
	req.Description = strings.TrimSpace(req.Description)
	if req.Value == "" || len(req.Description) > 256 {
		writeError(w, http.StatusBadRequest, errors.New("rule value is required and description must be at most 256 characters"))
		return
	}
	category, ok := ruleDescriptionCategory(req.Kind)
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("unsupported rule kind"))
		return
	}
	protocol := models.PortProtocol("")
	if category == "port" {
		switch strings.ToLower(strings.TrimSpace(req.Protocol)) {
		case "tcp":
			protocol = models.PortProtocolTCP
		case "udp":
			protocol = models.PortProtocolUDP
		case "icmp":
			protocol = models.PortProtocolICMP
		default:
			writeError(w, http.StatusBadRequest, errors.New("a valid protocol is required for port rules"))
			return
		}
	}

	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	if !ruleDescriptionTargetExists(req.Kind, req.Value, protocol, selected) {
		writeError(w, http.StatusNotFound, errors.New("rule not found"))
		return
	}

	descriptions := make([]models.RuleDescription, 0, len(selected.RuleDescriptions)+1)
	for _, item := range selected.RuleDescriptions {
		if item.Kind == category && item.Value == req.Value && item.Protocol == protocol {
			continue
		}
		descriptions = append(descriptions, item)
	}
	if req.Description != "" {
		descriptions = append(descriptions, models.RuleDescription{
			Kind: category, Value: req.Value, Protocol: protocol, Description: req.Description,
		})
	}
	selected.RuleDescriptions = descriptions
	// Keep old allowlist comments in sync so older clients do not resurrect a
	// cleared or changed description after a policy refresh.
	if req.Kind == "allowlist" {
		selected.Rules = appendOrUpdateAllowRule(selected.Rules, req.Value, req.Description)
	}
	updated := models.WithDirectionPolicy(policy, direction, selected)
	updated = h.store.PutPolicy(r.Context(), updated)
	writeJSON(w, http.StatusOK, updated)
}

func (h *ServerHandler) handleProxyICMPAllowlist(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, requestDirection(r))
	writeJSON(w, http.StatusOK, map[string]any{"icmp_allow_cidrs": cloneStringSlice(selected.ICMPAllowCIDRs)})
}

func (h *ServerHandler) handleProxyICMPAllowlistUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	selected.ICMPAllowCIDRs = appendUnique(selected.ICMPAllowCIDRs, req.CIDR)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyICMPAllowlistDelete(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	selected.ICMPAllowCIDRs = deleteString(selected.ICMPAllowCIDRs, cidrFromRequest(r))
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyICMPBlocklist(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, requestDirection(r))
	writeJSON(w, http.StatusOK, map[string]any{"icmp_blocked_cidrs": cloneStringSlice(selected.ICMPBlockedCIDRs)})
}

func (h *ServerHandler) handleProxyICMPBlocklistUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	selected.ICMPBlockedCIDRs = appendUnique(selected.ICMPBlockedCIDRs, req.CIDR)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyICMPBlocklistDelete(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	selected.ICMPBlockedCIDRs = deleteString(selected.ICMPBlockedCIDRs, cidrFromRequest(r))
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyPublicPorts(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, requestDirection(r))
	selected.PublicPortRules = models.NormalizePortRules(selected.PublicPortRules, selected.PublicPorts)
	writeJSON(w, http.StatusOK, map[string]any{"public_ports": models.CollapsePortRules(selected.PublicPortRules), "public_port_rules": selected.PublicPortRules})
}

func (h *ServerHandler) handleProxyPublicPortsUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port            uint16 `json:"port"`
		Protocol        string `json:"protocol"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	if h.sshMutationBlocked(w, r, policy, req.Port, "allow", req.ConfirmPassword) {
		return
	}
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	protocol, hasProtocol := parseOptionalPortProtocolServer(req.Protocol)
	selected.PublicPortRules = models.NormalizePortRules(selected.PublicPortRules, selected.PublicPorts)
	if hasProtocol {
		selected.PublicPortRules = appendUniquePortRule(selected.PublicPortRules, models.PortRule{Protocol: protocol, Port: req.Port})
	} else {
		selected.PublicPortRules = appendUniquePortRule(selected.PublicPortRules, models.PortRule{Protocol: models.PortProtocolTCP, Port: req.Port})
		selected.PublicPortRules = appendUniquePortRule(selected.PublicPortRules, models.PortRule{Protocol: models.PortProtocolUDP, Port: req.Port})
	}
	selected.PublicPorts = models.CollapsePortRules(selected.PublicPortRules)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyPublicPortsDelete(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.ParseUint(r.PathValue("port"), 10, 16)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	if h.sshMutationBlocked(w, r, policy, uint16(port), "remove", confirmPasswordFromRequest(r)) {
		return
	}
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	protocol, hasProtocol := parseOptionalPortProtocolServer(r.URL.Query().Get("protocol"))
	selected.PublicPortRules = models.NormalizePortRules(selected.PublicPortRules, selected.PublicPorts)
	if hasProtocol {
		selected.PublicPortRules = deletePortRule(selected.PublicPortRules, models.PortRule{Protocol: protocol, Port: uint16(port)})
	} else {
		selected.PublicPortRules = deletePortRulesByPort(selected.PublicPortRules, uint16(port))
	}
	selected.PublicPorts = models.CollapsePortRules(selected.PublicPortRules)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyDeniedPorts(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, requestDirection(r))
	selected.DeniedPortRules = models.NormalizePortRules(selected.DeniedPortRules, selected.DeniedPorts)
	writeJSON(w, http.StatusOK, map[string]any{"denied_ports": models.CollapsePortRules(selected.DeniedPortRules), "denied_port_rules": selected.DeniedPortRules})
}

func (h *ServerHandler) handleProxyDeniedPortsUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port            uint16 `json:"port"`
		Protocol        string `json:"protocol"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	if h.sshMutationBlocked(w, r, policy, req.Port, "deny", req.ConfirmPassword) {
		return
	}
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	protocol, hasProtocol := parseOptionalPortProtocolServer(req.Protocol)
	selected.DeniedPortRules = models.NormalizePortRules(selected.DeniedPortRules, selected.DeniedPorts)
	if hasProtocol {
		selected.DeniedPortRules = appendUniquePortRule(selected.DeniedPortRules, models.PortRule{Protocol: protocol, Port: req.Port})
	} else {
		selected.DeniedPortRules = appendUniquePortRule(selected.DeniedPortRules, models.PortRule{Protocol: models.PortProtocolTCP, Port: req.Port})
		selected.DeniedPortRules = appendUniquePortRule(selected.DeniedPortRules, models.PortRule{Protocol: models.PortProtocolUDP, Port: req.Port})
	}
	selected.DeniedPorts = models.CollapsePortRules(selected.DeniedPortRules)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyDeniedPortsDelete(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.ParseUint(r.PathValue("port"), 10, 16)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	if h.sshMutationBlocked(w, r, policy, uint16(port), "allow", confirmPasswordFromRequest(r)) {
		return
	}
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	protocol, hasProtocol := parseOptionalPortProtocolServer(r.URL.Query().Get("protocol"))
	selected.DeniedPortRules = models.NormalizePortRules(selected.DeniedPortRules, selected.DeniedPorts)
	if hasProtocol {
		selected.DeniedPortRules = deletePortRule(selected.DeniedPortRules, models.PortRule{Protocol: protocol, Port: uint16(port)})
	} else {
		selected.DeniedPortRules = deletePortRulesByPort(selected.DeniedPortRules, uint16(port))
	}
	selected.DeniedPorts = models.CollapsePortRules(selected.DeniedPortRules)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyPorts(w http.ResponseWriter, r *http.Request) {
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, requestDirection(r))
	selected.AllowedPortRules = models.NormalizePortRules(selected.AllowedPortRules, selected.AllowedPorts)
	writeJSON(w, http.StatusOK, map[string]any{"ports": models.CollapsePortRules(selected.AllowedPortRules), "port_rules": selected.AllowedPortRules})
}

func (h *ServerHandler) handleProxyPortsUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port            uint16 `json:"port"`
		Protocol        string `json:"protocol"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	if h.sshMutationBlocked(w, r, policy, req.Port, "allow", req.ConfirmPassword) {
		return
	}
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	protocol, hasProtocol := parseOptionalPortProtocolServer(req.Protocol)
	selected.AllowedPortRules = models.NormalizePortRules(selected.AllowedPortRules, selected.AllowedPorts)
	if hasProtocol {
		selected.AllowedPortRules = appendUniquePortRule(selected.AllowedPortRules, models.PortRule{Protocol: protocol, Port: req.Port})
	} else {
		selected.AllowedPortRules = appendUniquePortRule(selected.AllowedPortRules, models.PortRule{Protocol: models.PortProtocolTCP, Port: req.Port})
		selected.AllowedPortRules = appendUniquePortRule(selected.AllowedPortRules, models.PortRule{Protocol: models.PortProtocolUDP, Port: req.Port})
	}
	selected.AllowedPorts = models.CollapsePortRules(selected.AllowedPortRules)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

func (h *ServerHandler) handleProxyPortsDelete(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.ParseUint(r.PathValue("port"), 10, 16)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy := h.ensurePolicy(r.Context(), r.PathValue("node"), r.PathValue("iface"))
	if h.sshMutationBlocked(w, r, policy, uint16(port), "remove", confirmPasswordFromRequest(r)) {
		return
	}
	direction := requestDirection(r)
	selected := models.DirectionPolicyFor(policy, direction)
	protocol, hasProtocol := parseOptionalPortProtocolServer(r.URL.Query().Get("protocol"))
	selected.AllowedPortRules = models.NormalizePortRules(selected.AllowedPortRules, selected.AllowedPorts)
	if hasProtocol {
		selected.AllowedPortRules = deletePortRule(selected.AllowedPortRules, models.PortRule{Protocol: protocol, Port: uint16(port)})
	} else {
		selected.AllowedPortRules = deletePortRulesByPort(selected.AllowedPortRules, uint16(port))
	}
	selected.AllowedPorts = models.CollapsePortRules(selected.AllowedPortRules)
	h.applyImmediatePolicyUpdate(w, r, models.WithDirectionPolicy(policy, direction, selected))
}

// applyImmediatePolicyUpdate makes the API result match the dataplane state.
// Persisting a rule after a failed Agent apply used to make the console claim
// success while the BPF maps retained the old rule set.
func (h *ServerHandler) applyImmediatePolicyUpdate(w http.ResponseWriter, r *http.Request, policy models.InterfacePolicy) {
	current := h.ensurePolicy(r.Context(), policy.NodeID, policy.Interface)
	policy = h.ensureRecoveryAccessPolicy(r.Context(), policy, !h.requestRemovesSSHPort(r.Context(), r, policy.NodeID))
	if h.blockUnsafeSSHPolicy(w, r, current, policy, confirmPasswordFromRequest(r)) {
		return
	}
	updated, err := h.service.UpdatePolicyAndApply(r.Context(), policy)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("apply policy immediately: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *ServerHandler) proxy(w http.ResponseWriter, r *http.Request, path string) {
	h.proxyNode(w, r, r.PathValue("node"), path)
}

func (h *ServerHandler) proxyNode(w http.ResponseWriter, r *http.Request, nodeID, path string) {
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}

	var body io.Reader
	if r.Body != nil {
		defer r.Body.Close()
		payload, _ := io.ReadAll(r.Body)
		body = bytes.NewReader(payload)
	}

	proxyPath, err := preserveProxyQuery(path, r.URL.Query())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, node.AgentURL+proxyPath, body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	req.Header = r.Header.Clone()

	resp, err := h.reverseHTTP.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// preserveProxyQuery keeps read-side filters such as direction when the
// server forwards a request to an agent. Some proxy handlers build a path
// with their own query values; avoid adding a duplicate key in that case.
func preserveProxyQuery(path string, query url.Values) (string, error) {
	parsed, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("parse proxy path: %w", err)
	}
	existing := parsed.Query()
	for key, values := range query {
		if _, ok := existing[key]; ok {
			continue
		}
		for _, value := range values {
			existing.Add(key, value)
		}
	}
	parsed.RawQuery = existing.Encode()
	return parsed.RequestURI(), nil
}

func (h *ServerHandler) WebExists() bool {
	info, err := os.Stat(filepath.Clean(h.webDir))
	return err == nil && info.IsDir()
}

func (h *ServerHandler) ensurePolicy(ctx context.Context, nodeID, iface string) models.InterfacePolicy {
	policy, err := h.service.GetPolicy(ctx, nodeID, iface)
	if err == nil {
		policy = models.NormalizeInterfacePolicy(policy)
		if h.service != nil {
			enriched := h.service.WithClusterInterconnect(ctx, policy)
			if !reflect.DeepEqual(policy, enriched) {
				policy = h.store.PutPolicy(ctx, enriched)
			}
		}
		return policy
	}
	policy = models.InterfacePolicy{
		NodeID:        nodeID,
		Interface:     iface,
		Enabled:       true,
		Mode:          "observe",
		DefaultAction: "pass",
		NonIPv4Action: models.NonIPv4Drop,
		Rules:         nil,
	}
	policy.Ingress.ObserveOnly = true
	policy.Egress.ObserveOnly = true
	// Seed a newly discovered interface with the current cluster addresses so
	// the first policy edit carries the same interconnect context as later
	// reconciliations. The policy is still observe-only until an explicit
	// protection baseline is published.
	if h.service != nil {
		policy = h.service.WithClusterInterconnect(ctx, policy)
	}
	policy = h.ensureControlPlanePortRules(policy)
	// Reading an untouched interface must not attach a fail-open program as a
	// side effect. Enforcement starts only after a rule change or the explicit
	// protection-baseline action has supplied recovery access rules.
	return h.store.PutPolicy(ctx, models.NormalizeInterfacePolicy(policy))
}

// controlPlanePortRules derives the listener ports from the active server
// configuration rather than assuming 8080. This keeps a custom HTTPS or
// HTTP/3 deployment reachable as soon as the protection baseline is enabled.
func controlPlanePortRules(cfg config.ServerConfig) []models.PortRule {
	// 8082 is the manager's ZStack-facing HTTPS entry point. Keep it in the
	// baseline even when the local process is bound to another port (for example
	// when ZStack forwards 8082 to the internal 8080 listener).
	rules := []models.PortRule{{Protocol: models.PortProtocolTCP, Port: 8082}}
	appendAddress := func(address string, protocol models.PortProtocol) {
		_, portText, err := net.SplitHostPort(strings.TrimSpace(address))
		if err != nil {
			return
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return
		}
		rules = appendUniquePortRule(rules, models.PortRule{Protocol: protocol, Port: uint16(port)})
	}
	appendAddress(cfg.ListenAddr, models.PortProtocolTCP)
	appendAddress(cfg.GRPCListenAddr, models.PortProtocolTCP)
	if cfg.TLSEnabled {
		appendAddress(cfg.QUICListenAddr, models.PortProtocolUDP)
	}
	return rules
}

// ensureControlPlanePortRules stages the manager's control ports on every
// policy, including observe-only policies. Staging is harmless while the
// interface is disabled, and means a later page-triggered enable cannot omit
// the port that is needed to recover the node.
func (h *ServerHandler) ensureControlPlanePortRules(policy models.InterfacePolicy) models.InterfacePolicy {
	policy = models.NormalizeInterfacePolicy(policy)
	ingress := models.DirectionPolicyFor(policy, models.DirectionIngress)
	ingress.PublicPortRules = models.NormalizePortRules(ingress.PublicPortRules, ingress.PublicPorts)
	ingress.DeniedPortRules = models.NormalizePortRules(ingress.DeniedPortRules, ingress.DeniedPorts)
	ingress.AllowedPortRules = models.NormalizePortRules(ingress.AllowedPortRules, ingress.AllowedPorts)
	for _, rule := range h.controlPortRules {
		if containsPortRule(ingress.DeniedPortRules, rule) || containsPortRule(ingress.PublicPortRules, rule) || containsPortRule(ingress.AllowedPortRules, rule) {
			continue
		}
		ingress.PublicPortRules = appendUniquePortRule(ingress.PublicPortRules, rule)
	}
	ingress.PublicPorts = models.CollapsePortRules(ingress.PublicPortRules)
	return models.WithDirectionPolicy(policy, models.DirectionIngress, ingress)
}

// standardRecoveryPortRules are the host services required to recover a
// protected ZStack/Kubernetes node. They are added only when an operator
// explicitly enables enforcement; a newly attached interface stays
// observe-only and therefore cannot be locked out by adding one rule.
func standardRecoveryPortRules() []models.PortRule {
	return []models.PortRule{
		{Protocol: models.PortProtocolTCP, Port: 53},
		{Protocol: models.PortProtocolUDP, Port: 53},
		{Protocol: models.PortProtocolUDP, Port: 123},
	}
}

func (h *ServerHandler) recoveryPortRulesForNode(ctx context.Context, node models.Node) []models.PortRule {
	rules := make([]models.PortRule, 0, 8)
	for _, port := range sshPortsForNode(ctx, h, node) {
		rules = appendUniquePortRule(rules, models.PortRule{Protocol: models.PortProtocolTCP, Port: port})
	}
	for _, rule := range standardRecoveryPortRules() {
		rules = appendUniquePortRule(rules, rule)
	}
	// A physical ZStack node can forward traffic to the manager VM. Keep the
	// manager's control listeners reachable on every protected cluster
	// interface, rather than only on the manager's own interface.
	for _, rule := range h.controlPortRules {
		rules = appendUniquePortRule(rules, rule)
	}
	return rules
}

func (h *ServerHandler) requestRemovesSSHPort(ctx context.Context, r *http.Request, nodeID string) bool {
	if r.Method != http.MethodDelete || requestDirection(r) != models.DirectionIngress {
		return false
	}
	port, err := strconv.ParseUint(strings.TrimSpace(r.PathValue("port")), 10, 16)
	if err != nil || port == 0 {
		return false
	}
	node, ok := service.FindNode(h.service.ListNodes(ctx), nodeID)
	if !ok {
		return false
	}
	for _, sshPort := range sshPortsForNode(ctx, h, node) {
		if uint16(port) == sshPort {
			return true
		}
	}
	return false
}

// ensureRecoveryAccessPolicy makes an enforcing policy retain the recovery
// ports before it reaches the agent. Explicit deny rules remain authoritative
// and are guarded by the SSH confirmation path for the active sshd port.
func (h *ServerHandler) ensureRecoveryAccessPolicy(ctx context.Context, policy models.InterfacePolicy, preserveSSH bool) models.InterfacePolicy {
	policy = models.NormalizeInterfacePolicy(policy)
	ingress := models.DirectionPolicyFor(policy, models.DirectionIngress)
	if !ingress.Enabled || ingress.ObserveOnly || strings.EqualFold(strings.TrimSpace(ingress.Mode), "observe") {
		return policy
	}
	node, ok := service.FindNode(h.service.ListNodes(ctx), policy.NodeID)
	if !ok {
		return policy
	}
	sshPorts := make(map[uint16]struct{})
	for _, port := range sshPortsForNode(ctx, h, node) {
		sshPorts[port] = struct{}{}
	}
	ingress.PublicPortRules = models.NormalizePortRules(ingress.PublicPortRules, ingress.PublicPorts)
	ingress.AllowedPortRules = models.NormalizePortRules(ingress.AllowedPortRules, ingress.AllowedPorts)
	ingress.DeniedPortRules = models.NormalizePortRules(ingress.DeniedPortRules, ingress.DeniedPorts)
	for _, rule := range h.recoveryPortRulesForNode(ctx, node) {
		if !preserveSSH && rule.Protocol == models.PortProtocolTCP {
			if _, isSSH := sshPorts[rule.Port]; isSSH {
				continue
			}
		}
		if containsPortRule(ingress.DeniedPortRules, rule) || containsPortRule(ingress.PublicPortRules, rule) || containsPortRule(ingress.AllowedPortRules, rule) {
			continue
		}
		ingress.PublicPortRules = appendUniquePortRule(ingress.PublicPortRules, rule)
	}
	ingress.PublicPorts = models.CollapsePortRules(ingress.PublicPortRules)
	return models.WithDirectionPolicy(policy, models.DirectionIngress, ingress)
}

func (h *ServerHandler) inferInterfacesFallback(ctx context.Context, nodeID string) map[string]any {
	interfaces := make([]models.DetectedInterface, 0)
	seen := map[string]struct{}{}
	appendIface := func(name string, recommended bool) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		interfaces = append(interfaces, models.DetectedInterface{
			Name:          name,
			IsPhysical:    true,
			IsRecommended: recommended,
		})
	}
	for _, iface := range h.service.ListPolicyInterfaces(ctx, nodeID) {
		appendIface(iface, false)
	}
	recommended := ""
	if len(interfaces) > 0 {
		recommended = interfaces[0].Name
	}
	if h.defaultInterface != "" {
		appendIface(h.defaultInterface, recommended == "")
		if recommended == "" {
			recommended = h.defaultInterface
		}
	}
	return map[string]any{
		"interfaces":  interfaces,
		"recommended": recommended,
	}
}

func appendUnique(items []string, item string) []string {
	item = strings.TrimSpace(item)
	if item == "" || slices.Contains(items, item) {
		return items
	}
	return append(items, item)
}

func deleteString(items []string, item string) []string {
	item = strings.TrimSpace(item)
	out := make([]string, 0, len(items))
	for _, current := range items {
		if current != item {
			out = append(out, current)
		}
	}
	return out
}

func appendUniquePort(items []uint16, item uint16) []uint16 {
	if item == 0 || slices.Contains(items, item) {
		return items
	}
	return append(items, item)
}

func appendUniquePortRule(items []models.PortRule, item models.PortRule) []models.PortRule {
	return models.NormalizePortRules(append(items, item), nil)
}

func deletePort(items []uint16, item uint16) []uint16 {
	out := make([]uint16, 0, len(items))
	for _, current := range items {
		if current != item {
			out = append(out, current)
		}
	}
	return out
}

func deletePortRule(items []models.PortRule, target models.PortRule) []models.PortRule {
	normalized := models.NormalizePortRules([]models.PortRule{target}, nil)
	if len(normalized) == 0 {
		return models.NormalizePortRules(items, nil)
	}
	target = normalized[0]
	out := make([]models.PortRule, 0, len(items))
	for _, current := range items {
		if current.Protocol == target.Protocol && current.Port == target.Port {
			continue
		}
		out = append(out, current)
	}
	return models.NormalizePortRules(out, nil)
}

func deletePortRulesByPort(items []models.PortRule, port uint16) []models.PortRule {
	out := make([]models.PortRule, 0, len(items))
	for _, current := range items {
		if current.Port != port {
			out = append(out, current)
		}
	}
	return models.NormalizePortRules(out, nil)
}

func parseOptionalPortProtocolServer(value string) (models.PortProtocol, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", false
	case "both", "tcp+udp", "tcp_udp":
		return "", false
	case "icmp":
		return models.PortProtocolICMP, true
	case "udp":
		return models.PortProtocolUDP, true
	default:
		return models.PortProtocolTCP, true
	}
}

func ruleDescriptionCategory(kind string) (string, bool) {
	switch kind {
	case "allowlist", "blocked":
		return "source", true
	case "bypass":
		return "bypass", true
	case "icmpAllow", "icmpBlocked":
		return "icmp", true
	case "public", "allowed", "denied":
		return "port", true
	default:
		return "", false
	}
}

func ruleDescriptionTargetExists(kind, value string, protocol models.PortProtocol, selected models.DirectionPolicy) bool {
	contains := func(items []string) bool { return slices.Contains(items, value) }
	switch kind {
	case "allowlist":
		for _, rule := range selected.Rules {
			if strings.TrimSpace(rule.CIDR) == value && (rule.Action == "" || rule.Action == "allow") {
				return true
			}
		}
	case "bypass":
		return contains(selected.BypassCIDRs)
	case "blocked":
		return contains(selected.BlockedCIDRs)
	case "icmpAllow":
		return contains(selected.ICMPAllowCIDRs)
	case "icmpBlocked":
		return contains(selected.ICMPBlockedCIDRs)
	case "public", "allowed", "denied":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || (port == 0 && protocol != models.PortProtocolICMP) {
			return false
		}
		var rules []models.PortRule
		var legacy []uint16
		switch kind {
		case "public":
			rules, legacy = selected.PublicPortRules, selected.PublicPorts
		case "allowed":
			rules, legacy = selected.AllowedPortRules, selected.AllowedPorts
		case "denied":
			rules, legacy = selected.DeniedPortRules, selected.DeniedPorts
		}
		for _, rule := range models.NormalizePortRules(rules, legacy) {
			if rule.Port == uint16(port) && rule.Protocol == protocol {
				return true
			}
		}
	}
	return false
}

func makeAllowRules(cidrs []string) []models.ACLRule {
	rules := make([]models.ACLRule, 0, len(cidrs))
	for _, cidr := range cidrs {
		rules = append(rules, models.ACLRule{CIDR: cidr, Action: "allow"})
	}
	return rules
}

func appendOrUpdateAllowRule(rules []models.ACLRule, cidr, comment string) []models.ACLRule {
	cidr = strings.TrimSpace(cidr)
	comment = strings.TrimSpace(comment)
	if cidr == "" {
		return rules
	}
	out := make([]models.ACLRule, 0, len(rules)+1)
	updated := false
	for _, rule := range rules {
		if strings.TrimSpace(rule.CIDR) == cidr {
			out = append(out, models.ACLRule{CIDR: cidr, Action: "allow", Comment: comment})
			updated = true
			continue
		}
		out = append(out, rule)
	}
	if !updated {
		out = append(out, models.ACLRule{CIDR: cidr, Action: "allow", Comment: comment})
	}
	return out
}

func decodePathValue(value string) string {
	return strings.ReplaceAll(value, "%2F", "/")
}

func cidrFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	queryCIDR := strings.TrimSpace(r.URL.Query().Get("cidr"))
	if queryCIDR != "" {
		return queryCIDR
	}
	return decodePathValue(strings.TrimSpace(r.PathValue("cidr")))
}

func withDirection(path string, direction models.PolicyDirection) string {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + "direction=" + string(direction)
}

func cloneStringSlice(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func extractCIDRs(rules []models.ACLRule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Action == "" || rule.Action == "allow" {
			out = append(out, rule.CIDR)
		}
	}
	return out
}

func requestSourceAddr(r *http.Request) (netip.Addr, bool) {
	// Forwarding headers are client-controlled unless a trusted proxy is
	// configured. Access checks and lockouts must use the actual socket peer.
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func requestDirection(r *http.Request) models.PolicyDirection {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("direction"))) {
	case string(models.DirectionEgress):
		return models.DirectionEgress
	default:
		return models.DirectionIngress
	}
}
