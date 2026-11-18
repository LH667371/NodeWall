package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
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
	"sync/atomic"
	"time"

	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/monitoring"
	"nodewall/internal/nodeauth"
	"nodewall/internal/securestore"
	"nodewall/internal/service"
	"nodewall/internal/sshconsole"
	"nodewall/internal/store"
	"nodewall/internal/transporttls"
	"nodewall/internal/version"

	"github.com/quic-go/webtransport-go"
)

type ServerHandler struct {
	nodeCredentials          *nodeauth.Registry
	relayManagerURL          string
	relayManagerCA           string
	enrollmentMu             sync.Mutex
	enrollmentTickets        map[string]time.Time
	nodeID                   string
	webDir                   string
	defaultInterface         string
	defaultXDPMode           string
	service                  *service.PolicyService
	store                    *store.Store
	reverseHTTP              *http.Client
	auth                     *authManager
	sshConsole               *sshconsole.Manager
	tlsCertFile              string
	h3Port                   string
	grpcPort                 string
	controlPortRules         []models.PortRule
	deleteEventsMu           sync.Mutex
	deleteEvents             []map[string]any
	eventDispositionMu       sync.Mutex
	eventDispositionSubs     map[chan struct{}]struct{}
	eventDispositionRev      uint64
	systemMetricsMu          sync.Mutex
	systemMetricsFetch       sync.Map
	monitoringSampledAt      time.Time
	monitoringArchiveMu      sync.Mutex
	monitoringArchiveCache   map[string]cachedMonitoringArchive
	metricsArchive           *monitoring.History
	metricsArchiveError      string
	systemMetricsCache       map[string]cachedSystemMetric
	systemMetricsHistory     map[string][]models.SystemMetricPoint
	overviewAggregateMu      sync.Mutex
	overviewAggregateCache   map[string]cachedOverviewAggregate
	pageSnapshotMu           sync.Mutex
	pageSnapshotCache        map[string]cachedPageSnapshot
	pageSnapshotPending      map[string]chan struct{}
	configurationLocks       sync.Map
	configurationVersions    sync.Map
	configurationMu          sync.Mutex
	consoleRevision          uint64
	consoleUpdateMu          sync.Mutex
	consoleUpdateSubscribers map[chan struct{}]struct{}
}

const (
	systemMetricsDisplayMaxAge = 3 * systemMetricsSampleInterval
	systemMetricsHistoryWindow = monitoring.HistoryRetention
	systemMetricsHistoryLimit  = int(6*time.Hour/systemMetricsSampleInterval) + 1
	// Page snapshots are shared by all browser streams. A slightly longer TTL
	// than the heartbeat keeps many Web clients from multiplying Agent probes.
	pageSnapshotTTL = 8 * time.Second
)

type cachedSystemMetric struct {
	metrics   models.SystemMetrics
	fetchedAt time.Time
}

// cachedMonitoringArchive prevents every browser heartbeat from rereading the
// same hourly JSONL segments. The cache is intentionally short lived: the
// independent sampler remains the source of live values, while this cache only
// fills the gap after a restart or when a long range reaches persisted data.
type cachedMonitoringArchive struct {
	points    map[string][]models.SystemMetricPoint
	fetchedAt time.Time
	err       error
}

type cachedOverviewAggregate struct {
	value     map[string]any
	fetchedAt time.Time
}

type cachedPageSnapshot struct {
	value     map[string]any
	fetchedAt time.Time
}

type clusterNodeAggregate struct {
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	AgentURL         string                `json:"agent_url"`
	ServerHTTPAddr   string                `json:"server_http_addr,omitempty"`
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

const (
	trafficWindow          = 5 * time.Minute
	clusterOnlineThreshold = time.Minute
)

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
	handler := &ServerHandler{
		relayManagerURL:        strings.TrimRight(strings.TrimSpace(cfg.ManagerURL), "/"),
		relayManagerCA:         cfg.TLSCAFile,
		metricsArchive:         history,
		metricsArchiveError:    archiveError,
		nodeID:                 cfg.NodeID,
		webDir:                 cfg.WebDir,
		defaultInterface:       cfg.DefaultInterface,
		defaultXDPMode:         cfg.DefaultXDPMode,
		service:                svc,
		store:                  st,
		reverseHTTP:            reverseHTTP,
		auth:                   auth,
		sshConsole:             sshconsole.NewWithKeyPath(cfg.SSHKeyPath),
		tlsCertFile:            cfg.TLSCertFile,
		h3Port:                 h3Port,
		grpcPort:               grpcPort,
		controlPortRules:       controlPlanePortRules(cfg),
		systemMetricsCache:     make(map[string]cachedSystemMetric),
		systemMetricsHistory:   make(map[string][]models.SystemMetricPoint),
		monitoringArchiveCache: make(map[string]cachedMonitoringArchive),
		overviewAggregateCache: make(map[string]cachedOverviewAggregate),
		pageSnapshotCache:      make(map[string]cachedPageSnapshot),
		eventDispositionSubs:   make(map[chan struct{}]struct{}),
	}
	if svc != nil {
		svc.SetHTTPClientResolver(handler.nodeHTTPClientForEndpoint)
	}
	auth.mailSender = handler.sendSMTPMail
	return handler, nil
}

// subscribeEventDispositions gives each browser its own notification channel.
// The SSE stream still sends a complete snapshot, so dropped wakeups are safe
// and a reconnect always reconstructs the authoritative state.
func (h *ServerHandler) subscribeEventDispositions() chan struct{} {
	updates := make(chan struct{}, 1)
	h.eventDispositionMu.Lock()
	if h.eventDispositionSubs == nil {
		h.eventDispositionSubs = make(map[chan struct{}]struct{})
	}
	h.eventDispositionSubs[updates] = struct{}{}
	h.eventDispositionMu.Unlock()
	return updates
}

func (h *ServerHandler) unsubscribeEventDispositions(updates chan struct{}) {
	h.eventDispositionMu.Lock()
	delete(h.eventDispositionSubs, updates)
	h.eventDispositionMu.Unlock()
	close(updates)
}

func (h *ServerHandler) notifyEventDispositionSubscribers() {
	h.eventDispositionMu.Lock()
	defer h.eventDispositionMu.Unlock()
	for updates := range h.eventDispositionSubs {
		select {
		case updates <- struct{}{}:
		default:
		}
	}
}

func (h *ServerHandler) eventDispositionSnapshot(ctx context.Context) map[string]any {
	return map[string]any{
		"revision":     h.currentEventDispositionRevision(),
		"dispositions": h.store.ListEventDispositions(ctx, ""),
	}
}

func (h *ServerHandler) currentEventDispositionRevision() uint64 {
	return atomic.LoadUint64(&h.eventDispositionRev)
}

func (h *ServerHandler) bumpEventDispositionRevision() uint64 {
	return atomic.AddUint64(&h.eventDispositionRev, 1)
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
	mux.HandleFunc("GET /events/dispositions", h.handleEventDispositions)
	mux.HandleFunc("PUT /events/dispositions/{event}", h.handleEventDispositions)
	mux.HandleFunc("GET /cluster/aggregate", h.handleClusterAggregate)
	mux.HandleFunc("GET /overview/snapshot", h.handleOverviewSnapshot)
	mux.HandleFunc("GET /monitoring/history", h.handleMonitoringHistory)
	mux.HandleFunc("GET /version", h.handleVersion)
	mux.HandleFunc("POST /nodes", h.handleUpsertNode)
	mux.HandleFunc("POST /nodes/enrollment", h.handleEnrollmentTicket)
	mux.HandleFunc("POST /join/enroll", h.handleNodeEnrollment)
	mux.HandleFunc("POST /join/heartbeat", h.handleJoinHeartbeat)
	mux.HandleFunc("POST /join/relay", h.handleNodeRelay)
	mux.HandleFunc("PUT /nodes/{node}/name", h.handleUpdateNodeName)
	mux.HandleFunc("POST /nodes/{node}/update", h.handleUpdateNode)
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
	mux.HandleFunc("GET /join/clamav/manifest", h.handleJoinClamAVManifest)
	mux.HandleFunc("GET /join/clamav/{kind}/{name}", h.handleJoinClamAVFile)
	mux.HandleFunc("GET /join/bootstrap/{kind}", h.handleJoinBootstrap)
	mux.HandleFunc("GET /bootstrap", h.handleBootstrap)
	mux.HandleFunc("GET /auth/session", h.handleAuthSession)
	mux.HandleFunc("POST /auth/password", h.handlePasswordChange)
	mux.HandleFunc("POST /auth/forgot-password/request", h.handleForgotPasswordRequest)
	mux.HandleFunc("POST /auth/forgot-password/reset", h.handleForgotPasswordReset)
	mux.HandleFunc("GET /settings/smtp", h.withConfigurationSync(h.handleSMTPSettings))
	mux.HandleFunc("PUT /settings/smtp", h.withConfigurationSync(h.handleSMTPSettings))
	mux.HandleFunc("POST /settings/smtp/test", h.handleSMTPTest)
	mux.HandleFunc("GET /account/security", h.handleAccountSecurity)
	mux.HandleFunc("GET /account/passkeys", h.handlePasskeyList)
	mux.HandleFunc("POST /account/passkeys/register/options", h.handlePasskeyRegistrationOptions)
	mux.HandleFunc("POST /account/passkeys/register/verify", h.handlePasskeyRegistrationVerify)
	mux.HandleFunc("POST /account/passkeys/{id}/delete", h.handlePasskeyDelete)
	mux.HandleFunc("POST /auth/passkey/login/options", h.handlePasskeyLoginOptions)
	mux.HandleFunc("POST /auth/passkey/login/verify", h.handlePasskeyLoginVerify)
	mux.HandleFunc("POST /account/email/request", h.handleEmailVerificationRequest)
	mux.HandleFunc("POST /account/email/confirm", h.handleEmailVerificationConfirm)
	mux.HandleFunc("POST /account/otp/setup", h.handleOTPSetup)
	mux.HandleFunc("POST /account/otp/verify", h.handleOTPVerify)
	mux.HandleFunc("POST /account/otp/disable", h.handleOTPDisable)
	mux.HandleFunc("GET /auth/users", h.handleAuthUsers)
	mux.HandleFunc("POST /auth/users", h.handleAuthUsers)
	mux.HandleFunc("PUT /auth/users/{username}", h.handleAuthUser)
	mux.HandleFunc("DELETE /auth/users/{username}", h.handleAuthUser)
	mux.HandleFunc("PUT /auth/users/{username}/password", h.handleAuthUserPassword)
	mux.HandleFunc("GET /settings/auth", h.withConfigurationSync(h.handleAuthSettings))
	mux.HandleFunc("PUT /settings/auth", h.withConfigurationSync(h.handleUpdateAuthSettings))
	mux.HandleFunc("GET /settings/passkey", h.withConfigurationSync(h.handlePasskeySettings))
	mux.HandleFunc("PUT /settings/passkey", h.withConfigurationSync(h.handlePasskeySettings))
	mux.HandleFunc("GET /settings/logging", h.withConfigurationSync(h.handleProxyLoggingSettings))
	mux.HandleFunc("PUT /settings/logging", h.withConfigurationSync(h.handleProxyLoggingSettings))
	mux.HandleFunc("GET /logs/drop", h.handleProxyRecentDropLogs)
	mux.HandleFunc("DELETE /logs/drop", h.handleProxyRecentDropLogs)
	mux.HandleFunc("GET /events/snapshot", h.handleEventsSnapshot)
	mux.HandleFunc("POST /logs/actions/allow", h.handleLogAllowAction)
	mux.HandleFunc("POST /logs/actions/block", h.handleLogBlockAction)
	mux.HandleFunc("POST /logs/actions/rate-limit", h.handleLogRateLimitAction)
	mux.HandleFunc("POST /logs/actions/temp-block", h.handleLogTempBlockAction)
	mux.HandleFunc("GET /nodes/{node}/interfaces/{iface}/policy", h.handleGetPolicy)
	mux.HandleFunc("PUT /nodes/{node}/interfaces/{iface}/policy", h.handleUpdatePolicy)
	mux.HandleFunc("POST /policy/copy", h.handleCopyPolicy)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/protection-baseline", h.handleEnableProtectionBaseline)
	mux.HandleFunc("POST /nodes/{node}/interfaces/{iface}/protection-baseline/disable", h.handleDisableProtectionBaseline)
	mux.HandleFunc("GET /nodes/{node}/health", h.handleProxyHealth)
	mux.HandleFunc("GET /nodes/{node}/protection-status", h.handleNodeProtectionStatus)
	mux.HandleFunc("GET /nodes/{node}/system/metrics", h.handleProxySystemMetrics)
	mux.HandleFunc("GET /nodes/{node}/security/summary", h.handleProxySecuritySummary)
	mux.HandleFunc("GET /nodes/{node}/security/scan", h.handleProxySecurityScan)
	mux.HandleFunc("GET /nodes/{node}/security/scan/events", h.handleProxySecurityScanEvents)
	mux.HandleFunc("POST /nodes/{node}/security/scan", h.handleProxySecurityScan)
	mux.HandleFunc("POST /nodes/{node}/security/scan/stop", h.handleProxySecurityScanStop)
	mux.HandleFunc("GET /nodes/{node}/security/scan/report", h.handleProxySecurityScanReport)
	mux.HandleFunc("GET /nodes/{node}/security/scan/reports", h.handleProxySecurityScanReports)
	mux.HandleFunc("GET /nodes/{node}/security/scan/reports/{scan}", h.handleProxySecurityScanReport)
	mux.HandleFunc("POST /nodes/{node}/security/scan/{finding}/quarantine", h.handleProxySecurityQuarantine)
	mux.HandleFunc("POST /nodes/{node}/security/scan/{finding}/ignore", h.handleProxySecurityFindingIgnore)
	mux.HandleFunc("POST /nodes/{node}/security/scan/{finding}/terminate", h.handleProxySecurityProcessTerminate)
	mux.HandleFunc("GET /nodes/{node}/security/quarantine", h.handleProxySecurityQuarantineList)
	mux.HandleFunc("DELETE /nodes/{node}/security/quarantine/{entry}", h.handleProxySecurityQuarantineDelete)
	mux.HandleFunc("POST /nodes/{node}/security/quarantine/{entry}/restore", h.handleProxySecurityQuarantineRestore)
	mux.HandleFunc("POST /nodes/{node}/security/quarantine/{entry}/load", h.handleProxySecurityQuarantineModuleLoad)
	mux.HandleFunc("POST /nodes/{node}/security/quarantine/{entry}/unload", h.handleProxySecurityQuarantineModuleUnload)
	mux.HandleFunc("GET /nodes/{node}/ssh-protection", h.withConfigurationSync(h.handleProxySSHProtection))
	mux.HandleFunc("GET /nodes/{node}/ssh-protection/activity", h.handleProxySSHActivity)
	mux.HandleFunc("PUT /nodes/{node}/ssh-protection", h.withConfigurationSync(h.handleProxySSHProtection))
	mux.HandleFunc("PUT /nodes/{node}/ssh-protection/transfer", h.withConfigurationSync(h.handleProxySSHTransferPolicy))
	mux.HandleFunc("GET /nodes/{node}/ssh-protection/keys", h.handleProxySSHAuthorizedKeys)
	mux.HandleFunc("POST /nodes/{node}/ssh-protection/keys", h.handleProxySSHAuthorizedKeys)
	mux.HandleFunc("DELETE /nodes/{node}/ssh-protection/keys/{fingerprint}", h.handleProxySSHAuthorizedKeyDelete)
	mux.HandleFunc("PUT /nodes/{node}/ssh-protection/authentication", h.withConfigurationSync(h.handleProxySSHAuthenticationPolicy))
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
	return securityHeaders(h.auth.wrap(h.withConsoleMutationSync(captureConfirmation(mux))), h.h3Port, h.auth.trustProxyHeaders)
}

func securityHeaders(next http.Handler, h3Port string, trustProxyHeaders bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil || (trustProxyHeaders && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")) {
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
	baseURL := requestBaseURL(r, h.auth.trustProxyHeaders)
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
		"\n" +
		"systemd_online() {\n" +
		"  command -v systemctl >/dev/null 2>&1 || return 1\n" +
		"  local SYSTEMD_STATE\n" +
		"  if command -v timeout >/dev/null 2>&1; then SYSTEMD_STATE=\"$(timeout 5 systemctl show --property=SystemState 2>/dev/null || true)\"; else SYSTEMD_STATE=\"$(systemctl show --property=SystemState 2>/dev/null || true)\"; fi\n" +
		"  SYSTEMD_STATE=\"${SYSTEMD_STATE#SystemState=}\"\n" +
		"  [[ -n \"$SYSTEMD_STATE\" && \"$SYSTEMD_STATE\" != offline && \"$SYSTEMD_STATE\" != unknown ]]\n" +
		"}\n" +
		"SYSTEMD_ONLINE=false\n" +
		"if systemd_online; then SYSTEMD_ONLINE=true; else progress 'systemd bus unavailable; direct startup will be used and boot enablement will still be attempted'; fi\n" +
		"start_direct_agent() {\n" +
		"  progress 'starting NodeWall agent directly'\n" +
		"  run_root install -d -m 755 /var/run/nodewall /var/log/nodewall\n" +
		"  run_root sh -c 'set -a; . /etc/nodewall/nodewall.env; set +a; pid_file=/var/run/nodewall/agent.pid; if [ -r \"$pid_file\" ] && kill -0 \"$(cat \"$pid_file\")\" 2>/dev/null; then exit 0; fi; if [ -r /var/run/nodewall-agent.pid ] && kill -0 \"$(cat /var/run/nodewall-agent.pid)\" 2>/dev/null; then exit 0; fi; rm -f /var/run/nodewall-agent.pid; nohup /opt/nodewall/bin/nodewall agent >>/var/log/nodewall/agent.log 2>&1 </dev/null & echo $! >\"$pid_file\"'\n" +
		"  sleep 1\n" +
		"  DIRECT_PID=\"$(run_root cat /var/run/nodewall/agent.pid 2>/dev/null || true)\"\n" +
		"  if [[ -z \"$DIRECT_PID\" ]] || ! run_root kill -0 \"$DIRECT_PID\" 2>/dev/null; then\n" +
		"    echo '[nodewall] direct Agent failed to stay running; recent log:' >&2\n" +
		"    run_root tail -n 40 /var/log/nodewall/agent.log 2>/dev/null || true\n" +
		"    exit 1\n" +
		"  fi\n" +
		"}\n" +
		"\n" +
		"JOIN_TMP=$(mktemp -d)\n" +
		"trap 'rm -f \"$JOIN_TMP/nodewall\" \"$JOIN_TMP/manager.crt\" \"$JOIN_TMP/public.pem\" \"$JOIN_TMP/public.der\" \"$JOIN_TMP/bootstrap-state\" \"$JOIN_TMP/bootstrap-credentials\" \"$JOIN_TMP/bootstrap-auth\" \"$JOIN_TMP/bootstrap-key\"; rmdir \"$JOIN_TMP\"' EXIT\n" +
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
		"INSTALL_SERVICE_ARGS=(--enable-services=false --service-manager=none)\n" +
		"if [[ \"$SYSTEMD_ONLINE\" == true ]]; then INSTALL_SERVICE_ARGS=(--enable-services=true --service-manager=systemd); elif [[ -d /etc/init.d ]]; then INSTALL_SERVICE_ARGS=(--enable-services=true --service-manager=sysv); fi\n" +
		"run_root \"$JOIN_TMP/nodewall\" install \"${INSTALL_SERVICE_ARGS[@]}\" --mode agent-only --agent-addr 0.0.0.0:9080 --manager-url \"" + baseURL + "\" --manager-grpc-addr \"" + managerGRPC + "\" --manager-quic-addr \"" + managerQUIC + "\" --advertise-addr \"${JOIN_IP}:9080\" --join-token '" + ticket + "' --manager-ca /etc/nodewall/tls/manager.crt --default-interface \"$JOIN_IFACE\" --console-public-key \"$NODEWALL_SSH_PUBLIC_KEY\"\n" +
		"run_root sed -i '/^NODEWALL_TLS_CA=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_TLS_CA=/etc/nodewall/tls/manager.crt' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i '/^NODEWALL_TLS_INSECURE_SKIP_VERIFY=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_TLS_INSECURE_SKIP_VERIFY=false' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i '/^NODEWALL_AGENT_ADDR=/d' /etc/nodewall/nodewall.env || true\n" +
		"echo 'NODEWALL_AGENT_ADDR=0.0.0.0:9080' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i \"s/^NODEWALL_AGENT_HTTP_ADDR=.*/NODEWALL_AGENT_HTTP_ADDR=${JOIN_IP}:9080/\" /etc/nodewall/nodewall.env || true\n" +
		"run_root sed -i '/^NODEWALL_AGENT_URL=/d' /etc/nodewall/nodewall.env || true\n" +
		"echo \"NODEWALL_AGENT_URL=https://${JOIN_IP}:9080\" | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"progress 'synchronizing standby manager state'\n" +
		"NODEWALL_JOIN_NODE_ID=\"$(run_root sh -c 'grep ^NODEWALL_NODE_ID= /etc/nodewall/nodewall.env | cut -d= -f2-')\"\n" +
		"NODEWALL_JOIN_TOKEN=\"$(run_root cat /etc/nodewall/agent-token)\"\n" +
		"for BOOTSTRAP_KIND in state credentials auth key; do\n" +
		"  curl \"${CURL_ARGS[@]}\" -H \"X-Nodewall-Node-ID: ${NODEWALL_JOIN_NODE_ID}\" -H \"Authorization: Bearer ${NODEWALL_JOIN_TOKEN}\" \"" + baseURL + "/join/bootstrap/${BOOTSTRAP_KIND}\" -o \"$JOIN_TMP/bootstrap-${BOOTSTRAP_KIND}\"\n" +
		"done\n" +
		"run_root install -m 600 \"$JOIN_TMP/bootstrap-state\" /etc/nodewall/server-state.json\n" +
		"run_root install -m 600 \"$JOIN_TMP/bootstrap-credentials\" /etc/nodewall/node-credentials.json\n" +
		"run_root install -m 600 \"$JOIN_TMP/bootstrap-auth\" /etc/nodewall/auth.json\n" +
		"run_root install -m 600 \"$JOIN_TMP/bootstrap-key\" /etc/nodewall/cluster.key\n" +
		"run_root sed -i '/^NODEWALL_CLUSTER_KEY_FILE=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_CLUSTER_KEY_FILE=/etc/nodewall/cluster.key' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i '/^NODEWALL_INSTALL_MODE=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_INSTALL_MODE=all-in-one' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		// The first agent-only install already selected a free web port. Keep
		// that exact bind address so a host service such as ZStack on 8080 is
		// never overwritten during standby promotion.
		"NODEWALL_SERVER_ADDR=\"$(run_root sh -c 'grep ^NODEWALL_SERVER_ADDR= /etc/nodewall/nodewall.env | cut -d= -f2-')\"\n" +
		"if [[ -z \"$NODEWALL_SERVER_ADDR\" ]]; then echo '[nodewall] selected web address is missing' >&2; exit 1; fi\n" +
		"SERVER_PORT=\"${NODEWALL_SERVER_ADDR##*:}\"\n" +
		"run_root sed -i '/^NODEWALL_SERVER_HTTP_ADDR=/d' /etc/nodewall/nodewall.env\n" +
		"echo \"NODEWALL_SERVER_HTTP_ADDR=${JOIN_IP}:${SERVER_PORT}\" | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i '/^NODEWALL_SERVER_GRPC_ADDR=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_SERVER_GRPC_ADDR=0.0.0.0:50051' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i '/^NODEWALL_SERVER_QUIC_ADDR=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_SERVER_QUIC_ADDR=0.0.0.0:50052' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i '/^NODEWALL_WEB_ACCESS=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_WEB_ACCESS=public' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root sed -i '/^NODEWALL_AUTH_ENABLED=/d' /etc/nodewall/nodewall.env\n" +
		"echo 'NODEWALL_AUTH_ENABLED=true' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"run_root install -d -m 755 /etc/systemd/system/nodewall-agent.service.d\n" +
		"cat <<'NODEWALL_MEMLOCK' | run_root tee /etc/systemd/system/nodewall-agent.service.d/10-memlock.conf >/dev/null\n" +
		"[Service]\n" +
		"LimitMEMLOCK=infinity\n" +
		"NODEWALL_MEMLOCK\n" +
		// Keep unit enablement in one helper. The caller uses it only after the
		// systemd probe succeeds; a host with an unavailable bus follows its
		// SysV or direct-start path instead of launching duplicate processes.
		"systemd_enable_unit() {\n" +
		"  if ! command -v systemctl >/dev/null 2>&1; then\n" +
		"    run_root test -f \"/etc/systemd/system/$1\" || return 1\n" +
		"    run_root install -d -m 755 /etc/systemd/system/multi-user.target.wants\n" +
		"    run_root ln -sf \"/etc/systemd/system/$1\" \"/etc/systemd/system/multi-user.target.wants/$1\"\n" +
		"    return 0\n" +
		"  fi\n" +
		"  run_root systemctl daemon-reload >/dev/null 2>&1 || true\n" +
		"  if run_root systemctl enable \"$1\" >/dev/null 2>&1; then return 0; fi\n" +
		"  run_root test -f \"/etc/systemd/system/$1\" || return 1\n" +
		"  run_root install -d -m 755 /etc/systemd/system/multi-user.target.wants\n" +
		"  run_root ln -sf \"/etc/systemd/system/$1\" \"/etc/systemd/system/multi-user.target.wants/$1\"\n" +
		"}\n" +
		"systemd_start_unit() {\n" +
		"  run_root systemctl restart \"$1\" >/dev/null 2>&1 && run_root systemctl is-active --quiet \"$1\"\n" +
		"}\n" +
		"if [[ \"$SYSTEMD_ONLINE\" == true ]]; then\n" +
		"  run_root sed -i '/^NODEWALL_SERVICE_MANAGER=/d' /etc/nodewall/nodewall.env || true\n" +
		"  echo 'NODEWALL_SERVICE_MANAGER=systemd' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"elif [[ -d /etc/init.d ]]; then\n" +
		"  run_root sed -i '/^NODEWALL_SERVICE_MANAGER=/d' /etc/nodewall/nodewall.env || true\n" +
		"  echo 'NODEWALL_SERVICE_MANAGER=sysv' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"else\n" +
		"  run_root sed -i '/^NODEWALL_SERVICE_MANAGER=/d' /etc/nodewall/nodewall.env || true\n" +
		"  echo 'NODEWALL_SERVICE_MANAGER=none' | run_root tee -a /etc/nodewall/nodewall.env >/dev/null\n" +
		"fi\n" +
		"AGENT_STARTED=false\n" +
		"if [[ \"$SYSTEMD_ONLINE\" == true ]] && systemd_enable_unit nodewall-agent.service; then\n" +
		"  if [[ \"$SYSTEMD_ONLINE\" == true ]] && systemd_start_unit nodewall-agent.service; then\n" +
		"    AGENT_STARTED=true\n" +
		"  fi\n" +
		"elif [[ -x /etc/init.d/nodewall-agent ]]; then\n" +
		"  AGENT_STARTED=true\n" +
		"fi\n" +
		"if [[ \"$AGENT_STARTED\" != true ]]; then start_direct_agent; fi\n" +
		"start_direct_server() {\n" +
		"  progress 'starting NodeWall management server directly'\n" +
		"  run_root install -d -m 755 /var/run/nodewall /var/log/nodewall\n" +
		"  run_root sh -c 'set -a; . /etc/nodewall/nodewall.env; set +a; pid_file=/var/run/nodewall/server.pid; if [ -r \"$pid_file\" ] && kill -0 \"$(cat \"$pid_file\")\" 2>/dev/null; then exit 0; fi; if [ -r /var/run/nodewall-server.pid ] && kill -0 \"$(cat /var/run/nodewall-server.pid)\" 2>/dev/null; then exit 0; fi; rm -f /var/run/nodewall-server.pid; nohup /opt/nodewall/bin/nodewall server >>/var/log/nodewall/server.log 2>&1 </dev/null & echo $! >\"$pid_file\"'\n" +
		"  sleep 1\n" +
		"  SERVER_PID=\"$(run_root cat /var/run/nodewall/server.pid 2>/dev/null || true)\"\n" +
		"  if [[ -z \"$SERVER_PID\" ]] || ! run_root kill -0 \"$SERVER_PID\" 2>/dev/null; then\n" +
		"    echo '[nodewall] direct management server failed to stay running; recent log:' >&2\n" +
		"    run_root tail -n 40 /var/log/nodewall/server.log 2>/dev/null || true\n" +
		"    exit 1\n" +
		"  fi\n" +
		"}\n" +
		"SERVER_STARTED=false\n" +
		"if [[ \"$SYSTEMD_ONLINE\" == true ]] && systemd_enable_unit nodewall-server.service; then\n" +
		"  if [[ \"$SYSTEMD_ONLINE\" == true ]] && systemd_start_unit nodewall-server.service; then\n" +
		"    SERVER_STARTED=true\n" +
		"  fi\n" +
		"elif [[ -x /etc/init.d/nodewall-server ]]; then\n" +
		"  SERVER_STARTED=true\n" +
		"fi\n" +
		"if [[ \"$SERVER_STARTED\" != true ]]; then start_direct_server; fi\n" +
		"progress 'ClamAV engine and databases will synchronize automatically from enrolled cluster nodes; check Agent logs for progress'\n" +
		"progress 'NodeWall agent and management server enrollment completed'\n"

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

// handleJoinBootstrap serves the manager snapshot needed by an enrolled node
// to run a local standby web console. The node credential is checked by
// joinAuthorized before any state, credentials, or password hashes leave the
// active manager.
func (h *ServerHandler) handleJoinBootstrap(w http.ResponseWriter, r *http.Request) {
	if !h.joinAuthorized(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch strings.ToLower(strings.TrimSpace(r.PathValue("kind"))) {
	case "state":
		w.Header().Set("Content-Type", "application/json")
		data, err := h.store.ExportJSON()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_, _ = w.Write(data)
	case "credentials":
		w.Header().Set("Content-Type", "application/json")
		if h.nodeCredentials == nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("node credential registry unavailable"))
			return
		}
		data, err := h.nodeCredentials.ExportJSON()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_, _ = w.Write(data)
	case "auth":
		if h.auth == nil || strings.TrimSpace(h.auth.authFile) == "" {
			writeError(w, http.StatusServiceUnavailable, errors.New("manager authentication store unavailable"))
			return
		}
		data, _, _, err := securestore.ReadValid(h.auth.authFile, func(payload []byte) error {
			if !json.Valid(payload) {
				return errors.New("invalid manager authentication store")
			}
			return nil
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !json.Valid(data) {
			writeError(w, http.StatusInternalServerError, errors.New("manager authentication store is invalid"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	case "key":
		keyPath := securestore.KeyPath()
		if strings.TrimSpace(keyPath) == "" {
			writeError(w, http.StatusServiceUnavailable, errors.New("cluster encryption key is not configured"))
			return
		}
		data, err := os.ReadFile(keyPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=cluster.key")
		_, _ = w.Write(data)
	default:
		writeError(w, http.StatusNotFound, errors.New("unknown bootstrap resource"))
	}
}

func requestBaseURL(r *http.Request, trustProxyHeaders bool) string {
	scheme := "http"
	if r.TLS != nil || (trustProxyHeaders && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")) {
		scheme = "https"
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "127.0.0.1:8086"
	}
	return scheme + "://" + host
}

func (h *ServerHandler) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.auth.sessionState(r))
}

func (h *ServerHandler) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	h.auth.handlePasswordChange(w, r)
}

func (h *ServerHandler) handleForgotPasswordRequest(w http.ResponseWriter, r *http.Request) {
	h.auth.handleForgotPasswordRequest(w, r)
}

func (h *ServerHandler) handleForgotPasswordReset(w http.ResponseWriter, r *http.Request) {
	h.auth.handleForgotPasswordReset(w, r)
}

func (h *ServerHandler) handleSMTPSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var settings models.SMTPSettings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&settings); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.auth.updateSMTPSettings(settings); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, h.auth.smtpSettingsView())
}

func (h *ServerHandler) handleSMTPTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	to := strings.TrimSpace(req.To)
	if to == "" {
		to = h.auth.smtpSettings().FromEmail
	}
	settings := h.auth.smtpSettings()
	subject := strings.TrimSpace(settings.SubjectPrefix + " SMTP test")
	if err := h.auth.sendMail(r.Context(), to, subject, "NodeWall SMTP test succeeded.\n\nThis message confirms that the configured mail transport is working."); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "sent", "to": to})
}

func (h *ServerHandler) handleEmailVerificationRequest(w http.ResponseWriter, r *http.Request) {
	h.auth.handleEmailVerificationRequest(w, r)
}

func (h *ServerHandler) handleEmailVerificationConfirm(w http.ResponseWriter, r *http.Request) {
	h.auth.handleEmailVerificationConfirm(w, r)
}

func (h *ServerHandler) handleAccountSecurity(w http.ResponseWriter, r *http.Request) {
	h.auth.handleAccountSecurity(w, r)
}

func (h *ServerHandler) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	h.auth.handlePasskeyList(w, r)
}

func (h *ServerHandler) handlePasskeyRegistrationOptions(w http.ResponseWriter, r *http.Request) {
	h.auth.handlePasskeyRegistrationOptions(w, r)
}

func (h *ServerHandler) handlePasskeyRegistrationVerify(w http.ResponseWriter, r *http.Request) {
	h.auth.handlePasskeyRegistrationVerify(w, r)
}

func (h *ServerHandler) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	h.auth.handlePasskeyDelete(w, r)
}

func (h *ServerHandler) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	h.auth.handlePasskeyLoginOptions(w, r)
}

func (h *ServerHandler) handlePasskeyLoginVerify(w http.ResponseWriter, r *http.Request) {
	h.auth.handlePasskeyLoginVerify(w, r)
}

func (h *ServerHandler) handleOTPSetup(w http.ResponseWriter, r *http.Request) {
	h.auth.handleOTPSetup(w, r)
}

func (h *ServerHandler) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	h.auth.handleOTPVerify(w, r)
}

func (h *ServerHandler) handleOTPDisable(w http.ResponseWriter, r *http.Request) {
	h.auth.handleOTPDisable(w, r)
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
	// Passkey configuration has its own save operation. A login-policy form
	// opened before another Web enabled Passkey must not disable it again.
	current := h.auth.authSettings()
	settings.PasskeyEnabled = current.PasskeyEnabled
	settings.PasskeyRPID = current.PasskeyRPID
	settings.PasskeyOrigins = current.PasskeyOrigins
	settings.PasskeyTLSMode = current.PasskeyTLSMode
	if err := h.auth.updateAuthSettings(settings); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, h.auth.authSettings())
}

func (h *ServerHandler) handlePasskeySettings(w http.ResponseWriter, r *http.Request) {
	h.auth.handlePasskeySettings(w, r)
}

func (h *ServerHandler) handleProxyLoggingSettings(w http.ResponseWriter, r *http.Request) {
	h.proxyNode(w, r, h.nodeID, "/settings/logging")
}

func (h *ServerHandler) handleProxyRecentDropLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		limit := 500
		if value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit"))); err == nil && value > 0 {
			limit = min(value, 2000)
		}
		merged := h.collectRecentDropLogs(r.Context(), limit)
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

func (h *ServerHandler) collectRecentDropLogs(ctx context.Context, limit int) []models.DropLogRecord {
	limit = min(max(limit, 1), 2000)
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}
	nodeLimit := min(limit, 1000)
	merged := make([]models.DropLogRecord, 0, 256)
	var mergedMu sync.Mutex
	var workers sync.WaitGroup
	semaphore := make(chan struct{}, 8)
	for _, node := range h.service.ListNodes(ctx) {
		node := node
		workers.Go(func() {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			nodeCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			defer cancel()
			var payload struct {
				Logs []models.DropLogRecord `json:"logs"`
			}
			if err := h.nodeJSON(nodeCtx, node.ID, http.MethodGet, "/logs/drop?limit="+strconv.Itoa(nodeLimit), nil, &payload); err != nil {
				return
			}
			for i := range payload.Logs {
				payload.Logs[i].NodeID = node.ID
			}
			policyByIface := make(map[string]models.InterfacePolicy)
			runtimeCache := make(map[string]runtimeDispositionState)
			for _, record := range payload.Logs {
				if _, ok := policyByIface[record.Interface]; !ok {
					policyByIface[record.Interface] = h.ensurePolicy(ctx, node.ID, record.Interface)
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
				_ = h.nodeJSON(ctx, node.ID, http.MethodGet, "/interfaces/"+record.Interface+"/temporary-blocks?direction="+string(direction), nil, &tempResp)
				_ = h.nodeJSON(ctx, node.ID, http.MethodGet, "/interfaces/"+record.Interface+"/rate-limits?direction="+string(direction), nil, &rateResp)
				runtimeCache[cacheKey] = runtimeDispositionState{TempBlocks: tempResp.TemporaryBlocks, RateLimits: rateResp.RateLimits}
			}
			enrichDropLogsWithDisposition(payload.Logs, policyByIface, runtimeCache)
			mergedMu.Lock()
			merged = append(merged, payload.Logs...)
			mergedMu.Unlock()
		})
	}
	workers.Wait()
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].Timestamp.After(merged[j].Timestamp) })
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged
}

func (h *ServerHandler) handleNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.service.ListNodes(r.Context()))
}

func (h *ServerHandler) handleClusterAggregate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.cachedClusterAggregate(r.Context(), requestDirection(r)))
}

func (h *ServerHandler) handleMonitoringHistory(w http.ResponseWriter, r *http.Request) {
	from, to, rangeSeconds, err := monitoringTimeWindow(r, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node"))
	if nodeID != "" && h.service != nil {
		if _, ok := service.FindNode(h.service.ListNodes(r.Context()), nodeID); !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("node %q not found", nodeID))
			return
		}
	}
	writeJSON(w, http.StatusOK, h.monitoringHistorySnapshot(r.Context(), nodeID, from, to, rangeSeconds))
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
	lock, _ := h.systemMetricsFetch.LoadOrStore(nodeID, make(chan struct{}, 1))
	gate := lock.(chan struct{})
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var metrics models.SystemMetrics
	if err := h.nodeJSON(ctx, nodeID, http.MethodGet, "/system/metrics", nil, &metrics); err != nil {
		return nil, err
	}
	if metrics.Memory.TotalBytes == 0 {
		return nil, errors.New("system metrics returned no memory total")
	}

	return &metrics, nil
}

func (h *ServerHandler) cachedSystemMetrics(nodeID string, now time.Time) *models.SystemMetrics {
	h.systemMetricsMu.Lock()
	defer h.systemMetricsMu.Unlock()
	cached, ok := h.systemMetricsCache[nodeID]
	if !ok || now.Sub(cached.fetchedAt) > systemMetricsDisplayMaxAge {
		return nil
	}
	metrics := cached.metrics
	return &metrics
}

func systemMetricPoint(nodeID string, metrics models.SystemMetrics) models.SystemMetricPoint {
	filesystemTotal, filesystemUsed, filesystemAvailable := filesystemTotals(metrics.Filesystems)
	filesystemUsedPercent := 0.0
	if filesystemTotal > 0 {
		filesystemUsedPercent = float64(filesystemUsed) / float64(filesystemTotal) * 100
	}
	return models.SystemMetricPoint{
		CPUCores:                   metrics.CPU.Cores,
		LogicalCPUs:                append([]models.LogicalCPUMetric(nil), metrics.CPU.LogicalCPUs...),
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
		DiskDevices:                append([]models.DiskDeviceMetric(nil), metrics.Disk.Devices...),
		NetworkInterfaces:          append([]models.NetworkInterfaceMetric(nil), metrics.Network.Interfaces...),
		Filesystems:                append([]models.FilesystemMetric(nil), metrics.Filesystems...),
		Accelerators:               append([]models.AcceleratorMetrics(nil), metrics.Accelerators...),
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

func (h *ServerHandler) monitoringLiveSnapshot(nodes []models.Node, from, to time.Time) (map[string][]models.SystemMetricPoint, []models.SystemMetricNodeSummary, time.Time, string) {
	h.systemMetricsMu.Lock()
	defer h.systemMetricsMu.Unlock()
	result := make(map[string][]models.SystemMetricPoint, len(nodes))
	for _, node := range nodes {
		if node.ID == "" {
			continue
		}
		result[node.ID] = filterSystemMetricPoints(h.systemMetricsHistory[node.ID], from, to)
	}
	return result, h.systemMetricNodeSummariesLocked(nodes), h.monitoringSampledAt, h.metricsArchiveError
}

func monitoringHistoryCacheKey(nodeIDs []string, from, to time.Time, step time.Duration) string {
	ids := append([]string(nil), nodeIDs...)
	sort.Strings(ids)
	// Round moving "last N minutes" windows to a small, fixed window. Otherwise
	// every five-second heartbeat would create a new cache key and reread the
	// same archive segments despite the short TTL.
	cacheBucket := 30 * time.Second
	return strings.Join(ids, ",") + "|" + from.UTC().Truncate(cacheBucket).Format(time.RFC3339Nano) + "|" + to.UTC().Truncate(cacheBucket).Format(time.RFC3339Nano) + "|" + step.String()
}

func cloneMonitoringPoints(source map[string][]models.SystemMetricPoint) map[string][]models.SystemMetricPoint {
	result := make(map[string][]models.SystemMetricPoint, len(source))
	for nodeID, points := range source {
		result[nodeID] = append([]models.SystemMetricPoint(nil), points...)
	}
	return result
}

func mergeMonitoringPoints(older, newer []models.SystemMetricPoint) []models.SystemMetricPoint {
	byTimestamp := make(map[int64]models.SystemMetricPoint, len(older)+len(newer))
	for _, point := range older {
		byTimestamp[point.Timestamp.UnixNano()] = point
	}
	for _, point := range newer {
		// The in-memory sample is the newest source when both the archive and
		// the live sampler contain the same timestamp bucket.
		byTimestamp[point.Timestamp.UnixNano()] = point
	}
	result := make([]models.SystemMetricPoint, 0, len(byTimestamp))
	for _, point := range byTimestamp {
		result = append(result, point)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Timestamp.Before(result[j].Timestamp) })
	return result
}

func (h *ServerHandler) monitoringArchivePoints(ctx context.Context, nodes []models.Node, from, to time.Time, rangeSeconds int) (map[string][]models.SystemMetricPoint, error) {
	if h.metricsArchive == nil || len(nodes) == 0 {
		return nil, nil
	}
	// Keep the stream payload bounded to roughly the same resolution as the
	// direct history endpoint. A short range remains at the sampling
	// cadence, while multi-day views use larger archive buckets.
	step := monitoringHistoryStep(rangeSeconds)
	ids := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node.ID != "" {
			ids = append(ids, node.ID)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	key := monitoringHistoryCacheKey(ids, from, to, step)
	now := time.Now()
	h.monitoringArchiveMu.Lock()
	if cached, ok := h.monitoringArchiveCache[key]; ok && now.Sub(cached.fetchedAt) < 4*time.Second {
		points, err := cloneMonitoringPoints(cached.points), cached.err
		h.monitoringArchiveMu.Unlock()
		return points, err
	}
	h.monitoringArchiveMu.Unlock()

	points, err := h.metricsArchive.Query(ctx, ids, from, to, step)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	h.monitoringArchiveMu.Lock()
	if h.monitoringArchiveCache == nil {
		h.monitoringArchiveCache = make(map[string]cachedMonitoringArchive)
	}
	for cachedKey, cached := range h.monitoringArchiveCache {
		if now.Sub(cached.fetchedAt) > time.Minute {
			delete(h.monitoringArchiveCache, cachedKey)
		}
	}
	if len(h.monitoringArchiveCache) >= 64 {
		var oldestKey string
		var oldestAt time.Time
		for cachedKey, cached := range h.monitoringArchiveCache {
			if oldestKey == "" || cached.fetchedAt.Before(oldestAt) {
				oldestKey, oldestAt = cachedKey, cached.fetchedAt
			}
		}
		if oldestKey != "" {
			delete(h.monitoringArchiveCache, oldestKey)
		}
	}
	h.monitoringArchiveCache[key] = cachedMonitoringArchive{
		points:    cloneMonitoringPoints(points),
		fetchedAt: now,
		err:       err,
	}
	h.monitoringArchiveMu.Unlock()
	return points, err
}

// monitoringStreamSnapshot reads only completed in-memory or archived samples.
// Browser streams must never trigger a fresh agent collection: the
// independent sampler owns that work and keeps slow nodes from blocking page
// updates or increasing CPU when several browsers are open.
func (h *ServerHandler) monitoringStreamSnapshot(ctx context.Context, nodeID string, rangeSeconds int, fromRaw, toRaw string) models.SystemMetricsHistory {
	if rangeSeconds <= 0 {
		rangeSeconds = 15 * 60
	}
	now := time.Now().UTC()
	from := now.Add(-time.Duration(rangeSeconds) * time.Second)
	if parsedFrom, err := time.Parse(time.RFC3339, strings.TrimSpace(fromRaw)); err == nil {
		if parsedTo, toErr := time.Parse(time.RFC3339, strings.TrimSpace(toRaw)); toErr == nil && parsedTo.After(parsedFrom) {
			from, now, rangeSeconds = parsedFrom.UTC(), parsedTo.UTC(), int(parsedTo.Sub(parsedFrom).Seconds())
		}
	}
	return h.monitoringHistorySnapshot(ctx, nodeID, from, now, rangeSeconds)
}

// The HTTP and SSE paths read the same live batch and archive. Browser
// refreshes do not issue Agent probes or compete with the sampling schedule.
func (h *ServerHandler) monitoringHistorySnapshot(ctx context.Context, nodeID string, from, to time.Time, rangeSeconds int) models.SystemMetricsHistory {
	step := monitoringHistoryStep(rangeSeconds)
	result := models.SystemMetricsHistory{
		Scope: "cluster", NodeID: nodeID, RangeSeconds: rangeSeconds,
		SampleIntervalSeconds: int(step / time.Second),
		RetentionSeconds:      int(systemMetricsHistoryWindow / time.Second),
	}
	if nodeID != "" {
		result.Scope = "node"
	}
	if h.service == nil {
		result.Points = resampleMonitoringPoints(h.systemMetricHistoryPoints(nodeID, from, to), step)
		return result
	}
	nodes := h.service.ListNodes(ctx)
	if nodeID != "" {
		nodes = slices.DeleteFunc(nodes, func(node models.Node) bool { return node.ID != nodeID })
	}
	history, summaries, sampledAt, storageError := h.monitoringLiveSnapshot(nodes, from, to)
	result.Nodes, result.SampledAt, result.StorageError = summaries, sampledAt, storageError
	needArchive := rangeSeconds > int(systemMetricsHistoryWindow/time.Second)
	for _, current := range history {
		if len(current) == 0 || current[0].Timestamp.After(from.Add(systemMetricsSampleInterval)) {
			needArchive = true
			break
		}
	}
	if needArchive {
		archiveEnd := to
		if !sampledAt.IsZero() && sampledAt.Before(archiveEnd) {
			archiveEnd = sampledAt
		}
		if archiveEnd.After(from) {
			archived, err := h.monitoringArchivePoints(ctx, nodes, from, archiveEnd, rangeSeconds)
			if err != nil {
				result.StorageError = err.Error()
			} else {
				for id, older := range archived {
					history[id] = mergeMonitoringPoints(older, history[id])
				}
			}
		}
	}
	for id, current := range history {
		history[id] = resampleMonitoringPoints(current, step)
	}
	for index := range result.Nodes {
		summary := &result.Nodes[index]
		current := history[summary.NodeID]
		if len(current) > 0 && summary.Timestamp.Before(current[len(current)-1].Timestamp) {
			applyMetricPointSummary(summary, current[len(current)-1])
		}
	}
	if nodeID != "" {
		result.Points = history[nodeID]
	} else {
		result.NodePoints = history
		result.Points = aggregateSystemMetricPoints(history, from.Truncate(step), to)
	}
	return result
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

// The HTTP and SSE projections must preserve the same device identities after
// a restart, even when the agent is offline and only archived samples remain.
func applyMetricPointSummary(summary *models.SystemMetricNodeSummary, point models.SystemMetricPoint) {
	summary.Timestamp, summary.UptimeSeconds = point.Timestamp, point.UptimeSeconds
	summary.CPUCores, summary.CPUPercent = point.CPUCores, point.CPUPercent
	summary.LogicalCPUs = append([]models.LogicalCPUMetric(nil), point.LogicalCPUs...)
	summary.MemoryPercent = point.MemoryPercent
	summary.MemoryTotalBytes, summary.MemoryUsedBytes = uint64(point.MemoryTotalBytes), uint64(point.MemoryUsedBytes)
	summary.SwapUsedBytes = uint64(point.SwapUsedBytes)
	summary.RxBytesPerSecond, summary.TxBytesPerSecond = point.RxBytesPerSecond, point.TxBytesPerSecond
	summary.Disk.ReadBytesPerSecond, summary.Disk.WriteBytesPerSecond = point.DiskReadBytesPerSecond, point.DiskWriteBytesPerSecond
	summary.Disk.ReadOpsPerSecond, summary.Disk.WriteOpsPerSecond = point.DiskReadOpsPerSecond, point.DiskWriteOpsPerSecond
	summary.Disk.IOUtilizationPercent = point.DiskIOUtilizationPercent
	summary.Disk.ReadAwaitMilliseconds, summary.Disk.WriteAwaitMilliseconds = point.DiskReadAwaitMilliseconds, point.DiskWriteAwaitMilliseconds
	summary.Disk.Devices = append([]models.DiskDeviceMetric(nil), point.DiskDevices...)
	summary.NetworkInterfaces = append([]models.NetworkInterfaceMetric(nil), point.NetworkInterfaces...)
	summary.Filesystems = append([]models.FilesystemMetric(nil), point.Filesystems...)
	summary.Accelerators = append([]models.AcceleratorMetrics(nil), point.Accelerators...)
	summary.Kernel.ContextSwitchesPerSecond, summary.Kernel.InterruptsPerSecond, summary.Kernel.ForksPerSecond = point.ContextSwitchesPerSecond, point.InterruptsPerSecond, point.ForksPerSecond
	summary.Processes.Total, summary.Processes.Running, summary.Processes.Blocked = uint64(point.ProcessesTotal), uint64(point.ProcessesRunning), uint64(point.ProcessesBlocked)
	summary.Sockets.TCPInUse, summary.Sockets.TCPTimeWait, summary.Sockets.UDPInUse = uint64(point.TCPInUse), uint64(point.TCPTimeWait), uint64(point.UDPInUse)
	summary.FileDescriptors.Allocated, summary.FileDescriptors.Maximum, summary.FileDescriptors.UsedPercent = uint64(point.FileDescriptorsAllocated), uint64(point.FileDescriptorsMaximum), point.FileDescriptorsUsedPercent
}

func (h *ServerHandler) systemMetricNodeSummariesLocked(nodes []models.Node) []models.SystemMetricNodeSummary {
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
			applyMetricPointSummary(&summary, point)
		}
		if cached, ok := h.systemMetricsCache[node.ID]; ok {
			summary.UptimeSeconds = cached.metrics.UptimeSeconds
			summary.CPUCores = cached.metrics.CPU.Cores
			summary.LogicalCPUs = append([]models.LogicalCPUMetric(nil), cached.metrics.CPU.LogicalCPUs...)
			summary.MemoryTotalBytes = cached.metrics.Memory.TotalBytes
			summary.MemoryUsedBytes = cached.metrics.Memory.UsedBytes
			summary.SwapUsedBytes = cached.metrics.Memory.SwapUsedBytes
			summary.Disk = cached.metrics.Disk
			summary.NetworkInterfaces = append([]models.NetworkInterfaceMetric(nil), cached.metrics.Network.Interfaces...)
			summary.Kernel = cached.metrics.Kernel
			summary.Processes = cached.metrics.Processes
			summary.Sockets = cached.metrics.Sockets
			summary.FileDescriptors = cached.metrics.FileDescriptors
			summary.Filesystems = cached.metrics.Filesystems
			summary.Accelerators = cached.metrics.Accelerators
		}
		result = append(result, summary)
	}
	return result
}

// securityNodeStreamSnapshot reads the completed state needed by the security
// workspace in parallel. Each request has a short, independent deadline so a
// slow Agent contributes stale data instead of holding the page stream open.
func (h *ServerHandler) securityNodeStreamSnapshot(ctx context.Context, nodeID string) map[string]any {
	return h.securityNodeStreamSnapshotFor(ctx, nodeID, "all")
}

func (h *ServerHandler) securityNodeStreamSnapshotFor(ctx context.Context, nodeID, feature string) map[string]any {
	result := map[string]any{"node_id": nodeID}
	if h.service != nil {
		node, ok := service.FindNode(h.service.ListNodes(ctx), nodeID)
		if !ok {
			result["status"] = "offline"
			return result
		}
		// A standby Web server can keep serving the last cluster snapshot while
		// the active manager is down. Do not call a reachable node offline solely
		// because its heartbeat still points at that manager; probe the Agent
		// directly before declaring it unavailable.
		if node.LastSeenAt.IsZero() || time.Since(node.LastSeenAt) > clusterOnlineThreshold {
			probeCtx, probeCancel := context.WithTimeout(ctx, 2*time.Second)
			var health models.HealthStatus
			err := h.nodeJSON(probeCtx, nodeID, http.MethodGet, "/health", nil, &health)
			probeCancel()
			if err != nil {
				result["status"] = "offline"
				result["reason"] = err.Error()
				return result
			}
			result["reachable"] = true
		}
	}
	paths := map[string]string{
		"summary":     "/security/summary",
		"scan":        "/security/scan",
		"reports":     "/security/scan/reports",
		"quarantine":  "/security/quarantine",
		"ssh":         "/ssh-protection",
		"sshActivity": "/ssh-protection/activity?limit=100",
	}
	switch feature {
	case "firewall":
		paths = map[string]string{}
	case "ssh":
		paths = map[string]string{"ssh": "/ssh-protection", "sshActivity": "/ssh-protection/activity?limit=100", "sshKeys": "/ssh-protection/keys"}
	case "malware":
		delete(paths, "ssh")
		delete(paths, "sshActivity")
	case "overview":
		delete(paths, "reports")
		delete(paths, "quarantine")
	}
	var mu sync.Mutex
	var workers sync.WaitGroup
	for key, path := range paths {
		key, path := key, path
		workers.Go(func() {
			requestCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			defer cancel()
			var payload any
			if err := h.nodeJSON(requestCtx, nodeID, http.MethodGet, path, nil, &payload); err != nil {
				return
			}
			mu.Lock()
			result[key] = payload
			mu.Unlock()
		})
	}
	workers.Wait()
	if ssh, ok := result["ssh"].(map[string]any); ok {
		result["ssh_settings_etag"] = h.configurationETag("ssh:"+nodeID, ssh)
	}
	return result
}

func (h *ServerHandler) securityInterfaceStreamSnapshot(ctx context.Context, nodeID, iface string, direction models.PolicyDirection) map[string]any {
	result := map[string]any{"interface_status": "unavailable"}
	probeCtx, probeCancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	var inventory models.InterfaceInventory
	var health models.HealthStatus
	var inventoryErr, healthErr error
	var workers sync.WaitGroup
	workers.Go(func() {
		inventoryErr = h.nodeJSON(probeCtx, nodeID, http.MethodGet, "/interfaces", nil, &inventory)
	})
	workers.Go(func() {
		healthErr = h.nodeJSON(probeCtx, nodeID, http.MethodGet, "/health", nil, &health)
	})
	workers.Wait()
	probeCancel()
	requestedInterface := strings.TrimSpace(iface)
	iface = requestedInterface
	if inventoryErr == nil {
		result["inventory"] = inventory
		if !slices.ContainsFunc(inventory.Interfaces, func(item models.DetectedInterface) bool {
			return item.Name == requestedInterface
		}) {
			iface = clusterFocusInterface(inventory)
		}
	}
	if healthErr == nil {
		// Health lists dataplane attachments and may omit a valid, inactive
		// NIC. Use it to find a default only when resolving an automatic or
		// invalid selection. A failed inventory probe cannot invalidate a NIC.
		automatic := requestedInterface == "" || iface != requestedInterface
		if automatic && !slices.ContainsFunc(health.Interfaces, func(item models.InterfaceHealth) bool {
			return item.Interface == iface
		}) {
			if active := healthFocusInterface(health); active != "" {
				iface = active
			}
		}
		result["health"] = health
		if iface != "" {
			result["protection_status"] = protectionStatusForInterface(health, iface, false)
		}
	}
	if iface == "" {
		return result
	}
	result["interface"] = iface
	summaryCtx, summaryCancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer summaryCancel()
	summary := h.interfaceSummarySnapshot(summaryCtx, nodeID, iface, direction, &health)
	if summaryCtx.Err() == nil {
		result["current"] = summary
		if healthErr == nil {
			result["interface_status"] = "ready"
		}
	}
	return result
}

func (h *ServerHandler) securityStreamSnapshot(ctx context.Context, feature, nodeID string) map[string]any {
	return h.securityStreamSnapshotFor(ctx, feature, nodeID, "", models.DirectionIngress)
}

func (h *ServerHandler) securityStreamSnapshotFor(ctx context.Context, feature, nodeID, iface string, direction models.PolicyDirection) map[string]any {
	feature = strings.TrimSpace(feature)
	if feature == "" {
		feature = "overview"
	}
	key := "security:" + feature + ":" + strings.TrimSpace(nodeID) + ":" + strings.TrimSpace(iface) + ":" + string(direction)
	return h.cachedConsoleSnapshot(ctx, key, func(previous cachedPageSnapshot, hadPrevious bool) map[string]any {
		if h.service == nil {
			value := map[string]any{"feature": feature, "node_id": nodeID, "nodes": []map[string]any{}}
			return value
		}
		nodes := h.service.ListNodes(ctx)
		targets := nodes
		if strings.TrimSpace(nodeID) != "" {
			targets = nil
			for _, node := range nodes {
				if node.ID == nodeID {
					targets = append(targets, node)
					break
				}
			}
		}
		items := make([]map[string]any, len(targets))
		var workers sync.WaitGroup
		for index, node := range targets {
			index, node := index, node
			workers.Go(func() {
				items[index] = h.securityNodeStreamSnapshotFor(ctx, node.ID, feature)
				items[index]["name"] = node.Name
				if fmt.Sprint(items[index]["status"]) == "offline" {
					return
				}
				if feature == "firewall" || (feature == "overview" && node.ID == nodeID) {
					for key, value := range h.securityInterfaceStreamSnapshot(ctx, node.ID, iface, direction) {
						items[index][key] = value
					}
				}
			})
		}
		workers.Wait()
		if ctx.Err() != nil && hadPrevious {
			return previous.value
		}
		if hadPrevious {
			if oldNodes, ok := previous.value["nodes"].([]map[string]any); ok {
				oldByID := make(map[string]map[string]any, len(oldNodes))
				for _, item := range oldNodes {
					if id := fmt.Sprint(item["node_id"]); id != "" {
						oldByID[id] = item
					}
				}
				for index, item := range items {
					if len(item) <= 1 {
						if old := oldByID[fmt.Sprint(item["node_id"])]; old != nil {
							items[index] = old
						}
					}
				}
			}
		}
		return map[string]any{"feature": feature, "node_id": nodeID, "nodes": items}
	})
}

func (h *ServerHandler) settingsStreamSnapshot(ctx context.Context, nodeID string, nodeScope ...bool) map[string]any {
	// /settings/logging reads and writes the manager Agent. The selected host
	// in another page must never change the configuration shown here.
	nodeID = h.nodeID
	key := "settings"
	var protection map[string]any
	if len(nodeScope) > 0 && nodeScope[0] {
		protection = h.protectionStreamSnapshot(ctx)
	}
	if protection != nil {
		key += ":nodes"
	}
	return h.cachedConsoleSnapshot(ctx, key, func(previous cachedPageSnapshot, hadPrevious bool) map[string]any {
		value := map[string]any{"logging_node_id": nodeID}
		tags := map[string]string{}
		if h.auth != nil {
			h.configurationMu.Lock()
			value["auth"] = h.auth.authSettings()
			value["passkey"] = h.auth.passkeySettingsView()
			value["smtp"] = h.auth.smtpSettingsView()
			for _, name := range []string{"auth", "passkey", "smtp"} {
				key := "/settings/" + name
				if name == "auth" || name == "passkey" {
					key = "web-auth"
				}
				tags[name] = h.configurationETag(key, value[name])
			}
			h.configurationMu.Unlock()
		}
		if h.service != nil && strings.TrimSpace(nodeID) != "" {
			requestCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			var logging any
			if h.nodeJSON(requestCtx, nodeID, http.MethodGet, "/settings/logging", nil, &logging) == nil {
				value["logging"] = logging
				tags["logging"] = h.configurationETag("/settings/logging", logging)
			}
			cancel()
		}
		if hadPrevious {
			if _, ok := value["logging"]; !ok {
				if old, exists := previous.value["logging"]; exists {
					value["logging"] = old
				}
			}
		}
		if ctx.Err() != nil && hadPrevious {
			return previous.value
		}
		if protection != nil {
			value["node_protection"] = protection
		}
		value["settings_etags"] = tags
		return value
	})
}

func (h *ServerHandler) protectionStreamSnapshot(ctx context.Context) map[string]any {
	key := "node-protection"
	return h.cachedConsoleSnapshot(ctx, key, func(previous cachedPageSnapshot, hadPrevious bool) map[string]any {
		result := map[string]any{}
		if h.service == nil {
			return result
		}
		nodes := h.service.ListNodes(ctx)
		var mu sync.Mutex
		var workers sync.WaitGroup
		semaphore := make(chan struct{}, 8)
		for _, node := range nodes {
			node := node
			workers.Go(func() {
				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				status := map[string]any{"node_id": node.ID, "protection_status": "unavailable", "reachable": false}
				requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				var inventory models.InterfaceInventory
				var health models.HealthStatus
				var healthErr error
				var probes sync.WaitGroup
				probes.Go(func() {
					_ = h.nodeJSON(requestCtx, node.ID, http.MethodGet, "/interfaces", nil, &inventory)
				})
				probes.Go(func() {
					healthErr = h.nodeJSON(requestCtx, node.ID, http.MethodGet, "/health", nil, &health)
				})
				probes.Wait()
				iface := clusterFocusInterface(inventory)
				if iface == "" {
					iface = healthFocusInterface(health)
				}
				if iface != "" {
					status["interface"] = iface
				}
				if healthErr == nil {
					status["reachable"] = true
					status["protection_status"] = protectionStatusForInterface(health, iface, true)
				} else {
					status["reason"] = healthErr.Error()
				}
				status["node_status"] = clusterNodeStatus(node, healthErr == nil)
				status["checked_at"] = time.Now().UTC()
				cancel()
				mu.Lock()
				result[node.ID] = status
				mu.Unlock()
			})
		}
		workers.Wait()
		value := map[string]any{}
		for key, item := range result {
			value[key] = item
		}
		return value
	})
}

func (h *ServerHandler) overviewStreamSnapshot(ctx context.Context, nodeID, iface string, direction models.PolicyDirection) map[string]any {
	key := "overview-data:" + strings.TrimSpace(nodeID) + ":" + strings.TrimSpace(iface) + ":" + string(direction)
	return h.cachedConsoleSnapshot(ctx, key, func(previous cachedPageSnapshot, hadPrevious bool) map[string]any {
		value := map[string]any{"node_id": nodeID, "interface": iface, "direction": direction}
		if h.service != nil && strings.TrimSpace(nodeID) != "" {
			// Health remains independent of the optional rule summary. Validate
			// the requested NIC on every snapshot: a node switch can otherwise
			// keep asking the new host for the previous host's interface forever.
			var health models.HealthStatus
			var healthErr error
			var inventory models.InterfaceInventory
			inventoryNeeded := strings.TrimSpace(iface) == ""
			var inventoryErr error
			probeCtx, probeCancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			var probes sync.WaitGroup
			if inventoryNeeded {
				probes.Go(func() {
					inventoryErr = h.nodeJSON(probeCtx, nodeID, http.MethodGet, "/interfaces", nil, &inventory)
				})
			}
			probes.Go(func() {
				healthErr = h.nodeJSON(probeCtx, nodeID, http.MethodGet, "/health", nil, &health)
			})
			probes.Wait()
			probeCancel()
			if inventoryNeeded && inventoryErr == nil {
				iface = clusterFocusInterface(inventory)
				value["inventory"] = inventory
			}
			if healthErr == nil {
				matched := false
				for _, item := range health.Interfaces {
					matched = matched || item.Interface == iface
				}
				if !matched {
					if active := healthFocusInterface(health); active != "" {
						iface = active
					}
				}
				value["health"] = health
				value["reachable"] = true
				value["protection_status"] = protectionStatusForInterface(health, iface, true)
			} else {
				value["health"] = models.HealthStatus{NodeID: nodeID, Status: "unavailable"}
				value["reachable"] = false
				value["protection_status"] = "unavailable"
				value["reason"] = healthErr.Error()
			}
			value["interface"] = iface
			value["interface_status"] = "unavailable"
			var summary any
			var summaryOK bool
			var security map[string]any
			var workers sync.WaitGroup
			if strings.TrimSpace(iface) != "" {
				workers.Go(func() {
					// The interface summary fans out to the Agent's health, rule,
					// stats, and insight endpoints. Give that fan-out its own budget;
					// a slow inventory probe must not consume the entire deadline and
					// make an otherwise healthy firewall card render as disabled.
					summaryCtx, summaryCancel := context.WithTimeout(ctx, 3500*time.Millisecond)
					defer summaryCancel()
					summary = h.interfaceSummarySnapshot(summaryCtx, nodeID, iface, direction, &health)
					summaryOK = summaryCtx.Err() == nil && healthErr == nil
				})
			}
			workers.Go(func() {
				// Security summary collection is independent of the interface
				// summary and must not inherit its deadline or cancellation.
				securityCtx, securityCancel := context.WithTimeout(ctx, 2500*time.Millisecond)
				defer securityCancel()
				security = h.securityNodeStreamSnapshotFor(securityCtx, nodeID, "overview")
			})
			workers.Wait()
			if summaryOK {
				value["current"] = summary
				value["interface_status"] = "ready"
			}
			value["security"] = security
		}
		if hadPrevious {
			if _, ok := value["current"]; !ok && value["reachable"] == true && value["interface"] == previous.value["interface"] {
				if old, exists := previous.value["current"]; exists {
					value["current"] = old
				}
			}
		}
		if ctx.Err() != nil && hadPrevious {
			return previous.value
		}
		return value
	})
}

func (h *ServerHandler) handleOverviewSnapshot(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.URL.Query().Get("node"))
	iface := strings.TrimSpace(r.URL.Query().Get("iface"))
	writeJSON(w, http.StatusOK, h.overviewStreamSnapshot(r.Context(), nodeID, iface, requestDirection(r)))
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
	section := strings.TrimSpace(r.URL.Query().Get("section"))
	explicitSection := section != ""
	if section == "" {
		section = "cluster"
	}
	eventFeed := section == "events" || r.URL.Query().Get("event_feed") == "1"
	monitoringNodeID := strings.TrimSpace(r.URL.Query().Get("node"))
	monitoringRange := monitoringRangeSeconds(r.URL.Query().Get("range"))
	securityFeature := strings.TrimSpace(r.URL.Query().Get("feature"))
	securityInterface := strings.TrimSpace(r.URL.Query().Get("iface"))
	securityDirection := models.PolicyDirection(strings.TrimSpace(r.URL.Query().Get("direction")))
	if securityDirection != models.DirectionEgress {
		securityDirection = models.DirectionIngress
	}
	pageNodeID := strings.TrimSpace(r.URL.Query().Get("node"))
	overviewNodeID := pageNodeID
	overviewInterface := strings.TrimSpace(r.URL.Query().Get("iface"))
	overviewDirection := models.PolicyDirection(strings.TrimSpace(r.URL.Query().Get("direction")))
	if overviewDirection != models.DirectionEgress {
		overviewDirection = models.DirectionIngress
	}

	send := func(event string, payload any) bool {
		data, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		if _, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	sendUpdates := func() bool {
		nodes := h.service.ListNodes(r.Context())
		return send("nodes", nodes) && send("node_delete", h.listDeleteEvents()) && send("event_dispositions", h.eventDispositionSnapshot(r.Context()))
	}

	// Legacy clients receive overview frames, but their expensive collection
	// must not delay heartbeat or operation events on this same stream.
	overviewResults := make(chan map[string]any, 1)
	overviewInFlight := false
	startOverview := func() {
		if section != "overview" || overviewInFlight || r.URL.Query().Get("overview") == "0" {
			return
		}
		overviewInFlight = true
		go func() {
			result := map[string]any{
				"ingress": h.cachedClusterAggregate(r.Context(), models.DirectionIngress),
				"egress":  h.cachedClusterAggregate(r.Context(), models.DirectionEgress),
			}
			select {
			case overviewResults <- result:
			case <-r.Context().Done():
			}
		}()
	}
	var lastMonitoringSample time.Time
	monitoringSent, monitoringInFlight := false, false
	monitoringResults := make(chan models.SystemMetricsHistory, 1)
	startMonitoring := func() {
		if section != "monitoring" || monitoringInFlight {
			return
		}
		h.systemMetricsMu.Lock()
		unchanged := lastMonitoringSample.Equal(h.monitoringSampledAt)
		h.systemMetricsMu.Unlock()
		if monitoringSent && unchanged {
			return
		}
		monitoringInFlight = true
		go func() {
			snapshot := h.monitoringStreamSnapshot(r.Context(), monitoringNodeID, monitoringRange, r.URL.Query().Get("from"), r.URL.Query().Get("to"))
			select {
			case monitoringResults <- snapshot:
			case <-r.Context().Done():
			}
		}()
	}
	eventResults := make(chan map[string]any, 1)
	eventsInFlight := false
	startEventSnapshot := func() {
		if !eventFeed || eventsInFlight {
			return
		}
		eventsInFlight = true
		go func() {
			value := h.eventsStreamSnapshot(r.Context())
			select {
			case eventResults <- value:
			case <-r.Context().Done():
			}
		}()
	}
	pageResults := make(chan map[string]any, 1)
	pageInFlight := false
	pageEventName := func() string {
		switch section {
		case "overview":
			return "overview_data"
		case "cluster":
			if explicitSection {
				return "cluster"
			}
			return ""
		case "security":
			return "security"
		case "management":
			return "settings"
		default:
			return ""
		}
	}
	startPageSnapshot := func() {
		if pageInFlight || pageEventName() == "" {
			return
		}
		pageInFlight = true
		go func() {
			var value map[string]any
			// Older console tabs read the feed from their page payload. Keep
			// that shape without making new tabs wait for every event source.
			legacyEvents := !eventFeed && (section == "overview" || (section == "security" && (securityFeature == "" || securityFeature == "overview")))
			var events map[string]any
			var worker sync.WaitGroup
			if legacyEvents {
				worker.Go(func() { events = h.eventsStreamSnapshot(r.Context()) })
			}
			switch section {
			case "overview":
				value = h.overviewStreamSnapshot(r.Context(), overviewNodeID, overviewInterface, overviewDirection)
			case "cluster":
				value = h.protectionStreamSnapshot(r.Context())
			case "security":
				value = h.securityStreamSnapshotFor(r.Context(), securityFeature, pageNodeID, securityInterface, securityDirection)
			case "management":
				value = h.settingsStreamSnapshot(r.Context(), pageNodeID, r.URL.Query().Get("settings_scope") == "node")
			}
			if legacyEvents {
				worker.Wait()
				value = maps.Clone(value)
				value["events"] = events
				if section == "overview" {
					value["logs"] = events["logs"]
				}
			}
			select {
			case pageResults <- value:
			case <-r.Context().Done():
			}
		}()
	}
	// Page snapshots can involve a slow Agent. Collection stays off the stream
	// writer so heartbeats and disposition updates remain responsive.
	if !sendUpdates() {
		return
	}
	dispositionUpdates := h.subscribeEventDispositions()
	defer h.unsubscribeEventDispositions(dispositionUpdates)
	consoleUpdates, unsubscribeConsole := h.subscribeConsoleUpdates()
	defer unsubscribeConsole()
	startPageSnapshot()
	startEventSnapshot()
	startMonitoring()
	startOverview()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !sendUpdates() {
				return
			}
			startPageSnapshot()
			startEventSnapshot()
			startMonitoring()
			startOverview()
		case _, ok := <-dispositionUpdates:
			if !ok || !send("event_dispositions", h.eventDispositionSnapshot(r.Context())) {
				return
			}
		case <-consoleUpdates:
			if !sendUpdates() {
				return
			}
			startPageSnapshot()
			startEventSnapshot()
			startOverview()
		case result := <-overviewResults:
			overviewInFlight = false
			if !send("overview", result) {
				return
			}
		case result := <-pageResults:
			pageInFlight = false
			if revision, ok := result["revision"].(uint64); ok && revision < atomic.LoadUint64(&h.consoleRevision) {
				startPageSnapshot()
				continue
			}
			if !send(pageEventName(), result) {
				return
			}
		case result := <-eventResults:
			eventsInFlight = false
			if revision, ok := result["revision"].(uint64); ok && revision < atomic.LoadUint64(&h.consoleRevision) {
				startEventSnapshot()
				continue
			}
			if !send("events", result) {
				return
			}
		case result := <-monitoringResults:
			monitoringInFlight = false
			lastMonitoringSample, monitoringSent = result.SampledAt, true
			if !send("monitoring", result) {
				return
			}
		}
	}
}

// clusterFocusInterface selects the same interface for the lightweight node
// status endpoint and the full cluster overview.
func clusterFocusInterface(inventory models.InterfaceInventory) string {
	// Prefer the interface that is already attached. The host's route-based
	// recommendation can change after enrollment (and a bridge can move the
	// management address), while protection status must follow the actual
	// dataplane interface. Without this preference a healthy attachment on a
	// secondary NIC is reported as "unknown" because the probe checks a
	// different physical interface.
	for _, iface := range inventory.Interfaces {
		if iface.Attached && iface.IsPhysical && !iface.IsLoopback {
			return iface.Name
		}
	}
	for _, iface := range inventory.Interfaces {
		if iface.Attached && !iface.IsLoopback {
			return iface.Name
		}
	}
	for _, iface := range inventory.Interfaces {
		if iface.IsPhysical && iface.Name == inventory.Recommended {
			return iface.Name
		}
	}
	for _, iface := range inventory.Interfaces {
		if iface.IsPhysical {
			return iface.Name
		}
	}
	for _, iface := range inventory.Interfaces {
		if iface.Name == inventory.Recommended {
			return iface.Name
		}
	}
	if len(inventory.Interfaces) > 0 {
		return inventory.Interfaces[0].Name
	}
	return ""
}

func (h *ServerHandler) handleNodeProtectionStatus(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("node")
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	result := map[string]string{"node_id": nodeID, "protection_status": "unavailable"}
	var inventory models.InterfaceInventory
	var health models.HealthStatus
	var healthErr error
	var probes sync.WaitGroup
	probes.Go(func() {
		_ = h.nodeJSON(ctx, nodeID, http.MethodGet, "/interfaces", nil, &inventory)
	})
	probes.Go(func() {
		healthErr = h.nodeJSON(ctx, nodeID, http.MethodGet, "/health", nil, &health)
	})
	probes.Wait()
	iface := clusterFocusInterface(inventory)
	if strings.TrimSpace(iface) == "" {
		iface = healthFocusInterface(health)
	}
	if strings.TrimSpace(iface) != "" {
		result["interface"] = iface
	}
	if healthErr == nil {
		result["protection_status"] = protectionStatusForInterface(health, iface, true)
		result["connection_status"] = "reachable"
	} else {
		// A transient inventory failure must not turn a healthy dataplane into an
		// unexplained "unknown" status when /health is still authoritative.
		// Conversely, if the health probe itself failed, return that error for
		// diagnosis regardless of whether inventory also failed.
		result["reason"] = healthErr.Error()
		result["connection_status"] = "unreachable"
	}
	result["node_status"] = clusterNodeStatus(node, healthErr == nil)
	result["checked_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	writeJSON(w, http.StatusOK, result)
}

// A Web's inability to reach an Agent is a path failure, not evidence that a
// node with a recent authenticated heartbeat has gone offline cluster-wide.
func clusterNodeStatus(node models.Node, reachable bool) string {
	if reachable || (!node.LastSeenAt.IsZero() && time.Since(node.LastSeenAt) <= clusterOnlineThreshold) {
		return "online"
	}
	return "offline"
}

type clusterNodeProbe struct {
	iface           string
	health          models.HealthStatus
	healthOK        bool
	passed, dropped uint64
	trusted         uint64
	pendingRelease  uint64
	insights        models.InterfaceInsights
}

func (h *ServerHandler) probeClusterNode(ctx context.Context, node models.Node, direction models.PolicyDirection) clusterNodeProbe {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var probe clusterNodeProbe
	var inventory models.InterfaceInventory
	var inventoryErr, healthErr error
	var probes sync.WaitGroup
	probes.Go(func() {
		inventoryErr = h.nodeJSON(ctx, node.ID, http.MethodGet, "/interfaces", nil, &inventory)
	})
	probes.Go(func() {
		healthErr = h.nodeJSON(ctx, node.ID, http.MethodGet, "/health", nil, &probe.health)
	})
	probes.Wait()
	probe.iface = clusterFocusInterface(inventory)
	probe.healthOK = healthErr == nil
	if strings.TrimSpace(probe.iface) == "" && probe.healthOK {
		probe.iface = healthFocusInterface(probe.health)
	}
	if strings.TrimSpace(probe.iface) == "" {
		return probe
	}
	if inventoryErr != nil && !probe.healthOK {
		return probe
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
	base := "/interfaces/" + probe.iface + "/"
	query := "?direction=" + string(direction)
	_ = h.nodeJSON(ctx, node.ID, http.MethodGet, base+"stats"+query, nil, &stats)
	_ = h.nodeJSON(ctx, node.ID, http.MethodGet, base+"allowlist"+query, nil, &allowlist)
	_ = h.nodeJSON(ctx, node.ID, http.MethodGet, base+"bypass"+query, nil, &bypass)
	_ = h.nodeJSON(ctx, node.ID, http.MethodGet, base+"temporary-blocks"+query, nil, &tempBlocks)
	_ = h.nodeJSON(ctx, node.ID, http.MethodGet, base+"insights"+query, nil, &probe.insights)
	probe.passed, probe.dropped = stats.Passed, stats.Dropped
	probe.trusted = uint64(len(allowlist.Allowlist) + len(bypass.BypassCIDRs))
	probe.pendingRelease = uint64(len(tempBlocks.TemporaryBlocks))
	return probe
}

func (h *ServerHandler) cachedClusterAggregate(ctx context.Context, direction models.PolicyDirection) map[string]any {
	key := string(direction)
	h.overviewAggregateMu.Lock()
	defer h.overviewAggregateMu.Unlock()
	if h.overviewAggregateCache == nil {
		h.overviewAggregateCache = make(map[string]cachedOverviewAggregate)
	}
	if cached, ok := h.overviewAggregateCache[key]; ok && time.Since(cached.fetchedAt) < 5*time.Second {
		return cached.value
	}
	value := h.buildClusterAggregate(ctx, direction)
	if ctx.Err() != nil {
		return value
	}
	h.overviewAggregateCache[key] = cachedOverviewAggregate{value: value, fetchedAt: time.Now()}
	return value
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
			"node_count":                      0,
			"sampled_nodes":                   0,
			"average_cpu_percent":             float64(0),
			"average_memory_percent":          float64(0),
			"average_filesystem_used_percent": float64(0),
			"uptime_seconds":                  float64(0),
			"rx_bytes_per_second":             float64(0),
			"tx_bytes_per_second":             float64(0),
		},
	}
	var passed, dropped, trusted, pendingRelease uint64
	windowTotals := trafficWindowStats{WindowSeconds: int(trafficWindow / time.Second)}
	sources := make(map[string]models.SourceStat)
	countries := make(map[string]models.CountryStat)
	ports := make(map[uint16]models.PortStat)
	trend := make(map[string]models.TrafficPoint)
	nodeRows := make([]clusterNodeAggregate, 0)
	var systemCPUSum, systemMemorySum, systemFilesystemSum, systemRxSum, systemTxSum float64
	var systemMaxUptime float64
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
		if current.SourceDomain == "" {
			current.SourceDomain = item.SourceDomain
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
	probes := make([]clusterNodeProbe, len(nodes))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(8, len(nodes)) {
		workers.Go(func() {
			for i := range jobs {
				node := nodes[i]
				if strings.TrimSpace(node.ID) != "" {
					probes[i] = h.probeClusterNode(ctx, node, direction)
				}
			}
		})
	}
	for i := range nodes {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	for i, node := range nodes {
		if strings.TrimSpace(node.ID) == "" {
			continue
		}
		probe := probes[i]
		online := node.ID == h.nodeID || (!node.LastSeenAt.IsZero() && now.Sub(node.LastSeenAt) <= clusterOnlineThreshold) || probe.healthOK
		nodeRow := clusterNodeAggregate{
			ID:               node.ID,
			Name:             node.Name,
			AgentURL:         node.AgentURL,
			ServerHTTPAddr:   node.ServerHTTPAddr,
			Status:           "offline",
			ProtectionStatus: "unavailable",
			LastSeenAt:       node.LastSeenAt,
		}
		if online {
			nodeRow.Status = "online"
		}
		// A stale heartbeat is only a hint. probeClusterNode also checks the
		// Agent directly, which lets a standby Web server keep showing reachable
		// peers while the active manager is offline.
		if !online {
			nodeRows = append(nodeRows, nodeRow)
			continue
		}
		// The independent monitoring loop owns slow resource sampling. Reading
		// only its completed cache keeps GPU or filesystem delays from consuming
		// the deadline needed for interface and protection health checks.
		systemMetrics := h.cachedSystemMetrics(node.ID, now)
		if systemMetrics != nil {
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
				filesystemTotal := float64(0)
				filesystemUsed := float64(0)
				for _, filesystem := range systemMetrics.Filesystems {
					filesystemTotal += float64(filesystem.TotalBytes)
					filesystemUsed += float64(filesystem.UsedBytes)
				}
				if filesystemTotal > 0 {
					systemFilesystemSum += filesystemUsed / filesystemTotal * 100
				}
				if systemMetrics.UptimeSeconds > systemMaxUptime {
					systemMaxUptime = systemMetrics.UptimeSeconds
				}
				systemRxSum += systemMetrics.Network.RxBytesPerSecond
				systemTxSum += systemMetrics.Network.TxBytesPerSecond
			}
		}
		iface := probe.iface
		if strings.TrimSpace(iface) == "" {
			nodeRows = append(nodeRows, nodeRow)
			continue
		}
		nodeRow.Interface = iface
		if probe.healthOK {
			nodeRow.ProtectionStatus = protectionStatusForInterface(probe.health, iface, true)
		}
		nodeRow.Passed = probe.passed
		nodeRow.Dropped = probe.dropped
		insights := probe.insights
		recent := recentTrafficStats(models.InterfaceStats{Direction: direction, Passed: probe.passed, Dropped: probe.dropped}, insights.Trend, now)
		nodeRow.RecentPassed = recent.RecentPassed
		nodeRow.RecentDropped = recent.RecentDropped
		nodeRow.RecentDropRate = recent.DropRate
		nodeRow.Trusted = probe.trusted
		nodeRow.PendingRelease = probe.pendingRelease
		nodeRows = append(nodeRows, nodeRow)
		passed += probe.passed
		dropped += probe.dropped
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
		"node_count":                      len(nodes),
		"sampled_nodes":                   systemSampled,
		"average_cpu_percent":             float64(0),
		"average_memory_percent":          float64(0),
		"average_filesystem_used_percent": float64(0),
		"uptime_seconds":                  systemMaxUptime,
		"rx_bytes_per_second":             float64(0),
		"tx_bytes_per_second":             float64(0),
	}
	if systemOnline > 0 {
		systemSummary["average_cpu_percent"] = systemCPUSum / float64(systemOnline)
		systemSummary["average_memory_percent"] = systemMemorySum / float64(systemOnline)
		systemSummary["average_filesystem_used_percent"] = systemFilesystemSum / float64(systemOnline)
		systemSummary["rx_bytes_per_second"] = systemRxSum
		systemSummary["tx_bytes_per_second"] = systemTxSum
	}
	result["system"] = systemSummary
	return result
}

func healthFocusInterface(health models.HealthStatus) string {
	for _, item := range health.Interfaces {
		if item.XDPAttached || item.PolicyEnforced || item.EgressPolicyEnforced {
			return item.Interface
		}
	}
	if len(health.Interfaces) > 0 {
		return health.Interfaces[0].Interface
	}
	return ""
}

func protectionStatusForInterface(health models.HealthStatus, iface string, fallbackToActive bool) string {
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
	if fallbackToActive {
		// Inventory and health can be captured across a short interface rename or
		// bridge reconfiguration window. If the requested focus interface is not
		// present, use an attached interface as the authoritative cluster status
		// instead of hiding a healthy dataplane as unavailable.
		for _, item := range health.Interfaces {
			if !item.XDPAttached && !item.PolicyEnforced && !item.EgressPolicyEnforced {
				continue
			}
			switch {
			case item.ObserveOnly:
				return "not_enabled"
			case item.MapOK && item.StatsOK && item.PolicyEnforced && item.EnforcementOK:
				return "enforced"
			default:
				return "degraded"
			}
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
	nodeClient, nodeCredential, clientErr := h.nodeHTTPClient(nodeID)
	if clientErr != nil {
		writeError(w, http.StatusBadGateway, clientErr)
		return
	}

	h.pushDeleteEvent(nodeID, "start", "running", "node delete requested")
	cleanupStatus := "skipped"
	agentDeleteStatus := "skipped"
	lastSeen := node.LastSeenAt
	isOnline := !lastSeen.IsZero() && time.Since(lastSeen) <= 2*time.Minute
	// The UI sends force=true when the operator explicitly removes a node.
	// Honor it so a node whose heartbeat is stale but whose Agent is reachable
	// still receives the cleanup/uninstall request.
	forceCleanup := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("force")), "true")
	if (isOnline || forceCleanup) && strings.TrimSpace(node.AgentURL) != "" {
		h.pushDeleteEvent(nodeID, "cleanup", "running", "triggering remote cleanup")
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(node.AgentURL, "/")+"/maintenance/cleanup", nil)
		if err == nil {
			setNodeAuthHeaders(req, nodeCredential)
			if resp, err := nodeClient.Do(req); err == nil {
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
			setNodeAuthHeaders(delReq, nodeCredential)
			if resp, err := nodeClient.Do(delReq); err == nil {
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
	h.bumpEventDispositionRevision()
	h.notifyEventDispositionSubscribers()
	h.pushDeleteEvent(nodeID, "finalize", "success", "node removed from manager list")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":              "deleted",
		"node_id":             nodeID,
		"cleanup_status":      cleanupStatus,
		"agent_delete_status": agentDeleteStatus,
	})
}

// handleUpdateNode forces one enrolled Agent to fetch and install the
// manager's current package. The request is intentionally proxied through the
// node-authenticated client so the browser never receives or forwards an
// Agent credential.
func (h *ServerHandler) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node id is required"))
		return
	}
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	nodeClient, nodeCredential, clientErr := h.nodeHTTPClient(nodeID)
	if clientErr != nil {
		writeError(w, http.StatusBadGateway, clientErr)
		return
	}
	if strings.TrimSpace(node.AgentURL) == "" {
		writeError(w, http.StatusBadGateway, errors.New("node agent endpoint is unavailable"))
		return
	}

	h.pushDeleteEvent(nodeID, "update", "running", "triggering remote agent update")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	trustProxyHeaders := h.auth != nil && h.auth.trustProxyHeaders
	managerURL := requestBaseURL(r, trustProxyHeaders)
	requestBody, err := json.Marshal(map[string]string{"manager_url": managerURL})
	if err != nil {
		h.pushDeleteEvent(nodeID, "update", "failed", "remote update request build failed")
		writeError(w, http.StatusInternalServerError, fmt.Errorf("encode update request: %w", err))
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(node.AgentURL, "/")+"/maintenance/update", bytes.NewReader(requestBody))
	if err != nil {
		h.pushDeleteEvent(nodeID, "update", "failed", "remote update request build failed")
		writeError(w, http.StatusBadGateway, fmt.Errorf("build agent update request: %w", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	setNodeAuthHeaders(req, nodeCredential)
	resp, err := nodeClient.Do(req)
	if err != nil {
		h.pushDeleteEvent(nodeID, "update", "failed", "remote update unreachable")
		writeError(w, http.StatusBadGateway, fmt.Errorf("trigger agent update: %w", err))
		return
	}
	defer resp.Body.Close()
	payload := map[string]any{}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload)
	if resp.StatusCode >= 300 {
		h.pushDeleteEvent(nodeID, "update", "failed", "remote agent update rejected")
		if message, ok := payload["error"].(string); ok && strings.TrimSpace(message) != "" {
			writeError(w, resp.StatusCode, errors.New(message))
			return
		}
		writeError(w, http.StatusBadGateway, fmt.Errorf("agent update failed with status %s", resp.Status))
		return
	}
	h.pushDeleteEvent(nodeID, "update", "success", "remote agent update accepted")
	payload["node_id"] = nodeID
	if status, ok := payload["status"].(string); !ok || strings.TrimSpace(status) == "" {
		payload["status"] = "started"
	}
	writeJSON(w, http.StatusAccepted, payload)
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
	updated, err := h.service.UpdatePolicyAndApplyIfCurrent(r.Context(), policy, policy.UpdatedAt)
	if err != nil {
		if errors.Is(err, service.ErrPolicyChanged) {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "CONFIG_CHANGED", "error": err.Error()})
			return
		}
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
		TrialSeconds int                    `json:"trial_seconds"`
		Direction    models.PolicyDirection `json:"direction"`
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
	direction := request.Direction
	if direction == "" {
		direction = models.DirectionIngress
	}
	if direction != models.DirectionIngress && direction != models.DirectionEgress {
		writeError(w, http.StatusBadRequest, errors.New("direction must be ingress or egress"))
		return
	}
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), r.PathValue("node"))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}

	policy := h.ensurePolicy(r.Context(), node.ID, r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, direction)
	selected.Enabled = true
	selected.Mode = "whitelist"
	selected.DefaultAction = "drop"
	selected.NonIPv4Action = models.NonIPv4Drop
	selected.ObserveOnly = false
	if direction == models.DirectionEgress && !directionPolicyHasRules(selected) {
		writeError(w, http.StatusBadRequest, errors.New("egress protection requires at least one egress rule"))
		return
	}
	policy = models.WithDirectionPolicy(policy, direction, selected)

	var sshPorts []uint16
	var baselinePorts []models.PortRule
	if direction == models.DirectionIngress {
		var sshInfo sshAccessInfo
		if err := h.nodeJSON(r.Context(), node.ID, http.MethodGet, "/system/ssh", nil, &sshInfo); err != nil || len(sshInfo.Ports) == 0 {
			writeError(w, http.StatusBadGateway, errors.New("cannot detect sshd ports; protection was not enabled"))
			return
		}
		sshPorts = sshInfo.Ports
		baselinePorts = h.recoveryPortRulesForNode(r.Context(), node)
		ingress := models.DirectionPolicyFor(policy, models.DirectionIngress)
		for _, rule := range baselinePorts {
			ingress.PublicPortRules = appendUniquePortRule(ingress.PublicPortRules, rule)
		}
		ingress.PublicPorts = models.CollapsePortRules(ingress.PublicPortRules)
		policy = models.WithDirectionPolicy(policy, models.DirectionIngress, ingress)
		policy = h.service.WithClusterInterconnect(r.Context(), policy)
		policy = h.ensureControlPlanePortRules(policy)
	}

	if request.TrialSeconds > 0 {
		updated, trial, err := h.service.BeginPolicyTrialForDirection(r.Context(), policy, time.Duration(request.TrialSeconds)*time.Second, direction)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "trial",
			"policy": updated,
			"trial":  trial,
			"baseline": map[string]any{
				"direction":     direction,
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
			"direction":     direction,
			"ssh_ports":     sshPorts,
			"control_ports": baselinePorts,
			"cluster_nodes": len(h.service.ListNodes(r.Context())),
		},
	})
}

// handleDisableProtectionBaseline turns off enforcement for one direction
// while keeping the policy and observation data intact. Detaching the whole
// interface would also remove the other direction's protection, which makes
// the UI action unnecessarily dangerous on bridged/ZStack hosts.
func (h *ServerHandler) handleDisableProtectionBaseline(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Direction models.PolicyDirection `json:"direction"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, errors.New("invalid protection disable request"))
			return
		}
	}
	direction := request.Direction
	if direction == "" {
		direction = requestDirection(r)
	}
	if direction == "" {
		direction = models.DirectionIngress
	}
	if direction != models.DirectionIngress && direction != models.DirectionEgress {
		writeError(w, http.StatusBadRequest, errors.New("direction must be ingress or egress"))
		return
	}
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), r.PathValue("node"))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}

	policy := h.ensurePolicy(r.Context(), node.ID, r.PathValue("iface"))
	selected := models.DirectionPolicyFor(policy, direction)
	selected.Enabled = true
	selected.ObserveOnly = true
	selected.Mode = "observe"
	selected.DefaultAction = "pass"
	policy = models.WithDirectionPolicy(policy, direction, selected)
	updated, err := h.service.UpdatePolicyAndApply(r.Context(), policy)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("disable protection: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "disabled",
		"direction": direction,
		"policy":    updated,
	})
}

func directionPolicyHasRules(policy models.DirectionPolicy) bool {
	return len(policy.Rules) > 0 ||
		len(policy.BypassCIDRs) > 0 ||
		len(policy.BlockedCIDRs) > 0 ||
		len(policy.ICMPAllowCIDRs) > 0 ||
		len(policy.ICMPBlockedCIDRs) > 0 ||
		len(policy.PublicPortRules) > 0 || len(policy.PublicPorts) > 0 ||
		len(policy.DeniedPortRules) > 0 || len(policy.DeniedPorts) > 0 ||
		len(policy.AllowedPortRules) > 0 || len(policy.AllowedPorts) > 0
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

func (h *ServerHandler) handleProxySecurityScanEvents(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/security/scan/events")
}

func (h *ServerHandler) handleProxySecurityScanStop(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/security/scan/stop")
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

func (h *ServerHandler) handleProxySecurityFindingIgnore(w http.ResponseWriter, r *http.Request) {
	finding := url.PathEscape(r.PathValue("finding"))
	h.proxy(w, r, "/security/scan/"+finding+"/ignore")
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

func (h *ServerHandler) handleProxySecurityQuarantineModuleLoad(w http.ResponseWriter, r *http.Request) {
	entry := url.PathEscape(r.PathValue("entry"))
	h.proxy(w, r, "/security/quarantine/"+entry+"/load")
}

func (h *ServerHandler) handleProxySecurityQuarantineModuleUnload(w http.ResponseWriter, r *http.Request) {
	entry := url.PathEscape(r.PathValue("entry"))
	h.proxy(w, r, "/security/quarantine/"+entry+"/unload")
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

type sshAuthenticationPolicyProxyRequest struct {
	AllowPasswordLogin *bool  `json:"allow_password_login"`
	CurrentPassword    string `json:"current_password"`
}

func (h *ServerHandler) handleProxySSHAuthenticationPolicy(w http.ResponseWriter, r *http.Request) {
	var request sshAuthenticationPolicyProxyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if request.AllowPasswordLogin == nil {
		writeError(w, http.StatusBadRequest, errors.New("allow_password_login is required"))
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
	if err := h.nodeJSON(r.Context(), r.PathValue("node"), http.MethodPut, "/ssh-protection/authentication", map[string]any{
		"allow_password_login": *request.AllowPasswordLogin,
	}, &response); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *ServerHandler) handleProxySSHAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	path := "/ssh-protection/keys"
	if r.Method == http.MethodGet {
		var response map[string]any
		if err := h.nodeJSON(r.Context(), r.PathValue("node"), http.MethodGet, path, nil, &response); err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var request struct {
		PublicKey       string `json:"public_key"`
		Comment         string `json:"comment"`
		CurrentPassword string `json:"current_password"`
	}
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
	if err := h.nodeJSON(r.Context(), r.PathValue("node"), http.MethodPost, path, map[string]string{
		"public_key": request.PublicKey,
		"comment":    request.Comment,
	}, &response); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *ServerHandler) handleProxySSHAuthorizedKeyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var request struct {
		CurrentPassword string `json:"current_password"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	// Ordinary keys do not need a second password prompt. The NodeWall console
	// key and the last key on a password-disabled host can sever management
	// access, so those two cases still require explicit confirmation.
	nodeID := r.PathValue("node")
	var keyState struct {
		Keys []models.SSHAuthorizedKey `json:"keys"`
	}
	if err := h.nodeJSON(r.Context(), nodeID, http.MethodGet, "/ssh-protection/keys", nil, &keyState); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	fingerprint := strings.TrimSpace(r.PathValue("fingerprint"))
	var target *models.SSHAuthorizedKey
	for index := range keyState.Keys {
		if keyState.Keys[index].Fingerprint == fingerprint {
			copy := keyState.Keys[index]
			target = &copy
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, errors.New("SSH public key was not found"))
		return
	}
	// New agents identify the active console key by fingerprint. Historical
	// NodeWall keys are intentionally removable without a password; otherwise
	// repeated installs leave unusable keys that operators cannot clean up. Keep
	// the reserved comment as a compatibility fallback for older agents that do
	// not return the ownership annotations yet.
	requiresPassword := target.NodeWallActive || (target.NodeWallManaged && !target.NodeWallActiveKnown) || (!target.NodeWallManaged && strings.EqualFold(strings.TrimSpace(target.Comment), "nodewall-console"))
	if len(keyState.Keys) <= 1 {
		var protection models.SSHProtectionStatus
		if err := h.nodeJSON(r.Context(), nodeID, http.MethodGet, "/ssh-protection", nil, &protection); err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		requiresPassword = requiresPassword || (protection.Settings.AllowPasswordLogin != nil && !*protection.Settings.AllowPasswordLogin)
	}
	if requiresPassword {
		if h.auth != nil && !h.auth.verifyCurrentPassword(r, request.CurrentPassword) {
			writeError(w, http.StatusUnauthorized, errors.New("current password confirmation is required for this SSH key"))
			return
		}
		if h.auth == nil && strings.TrimSpace(request.CurrentPassword) == "" {
			writeError(w, http.StatusUnauthorized, errors.New("current password confirmation is required for this SSH key"))
			return
		}
	}
	path := "/ssh-protection/keys/" + url.PathEscape(fingerprint)
	var response map[string]any
	var deletePayload any
	if requiresPassword {
		deletePayload = map[string]bool{"confirmed": true}
	}
	if err := h.nodeJSON(r.Context(), nodeID, http.MethodDelete, path, deletePayload, &response); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if response == nil {
		response = map[string]any{}
	}
	response["status"] = "removed"
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

func (h *ServerHandler) handleProxySSHTransferPolicy(w http.ResponseWriter, r *http.Request) {
	var policy models.SSHTransferPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// The route uses the console's normal session, role, CSRF and configuration
	// version checks. Transfer settings do not change SSH authentication.
	var response models.SSHProtectionStatus
	if err := h.nodeJSON(r.Context(), r.PathValue("node"), http.MethodPut, "/ssh-protection/transfer", policy, &response); err != nil {
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
	writeJSON(w, http.StatusOK, h.interfaceSummarySnapshot(r.Context(), r.PathValue("node"), r.PathValue("iface"), requestDirection(r), nil))
}

// The summary belongs to the manager: policies are durable manager state,
// while counters and active rules come from individual Agent endpoints.
// HTTP and SSE share this cache and collector; Agents expose no /summary API.
func (h *ServerHandler) interfaceSummarySnapshot(ctx context.Context, nodeID, iface string, direction models.PolicyDirection, knownHealth *models.HealthStatus) map[string]any {
	key := "interface-summary:" + nodeID + ":" + iface + ":" + string(direction)
	return h.cachedConsoleSnapshot(ctx, key, func(_ cachedPageSnapshot, _ bool) map[string]any {
		return h.collectInterfaceSummary(ctx, nodeID, iface, direction, knownHealth)
	})
}

func (h *ServerHandler) collectInterfaceSummary(ctx context.Context, nodeID, iface string, direction models.PolicyDirection, knownHealth *models.HealthStatus) map[string]any {
	policy := h.ensurePolicy(ctx, nodeID, iface)
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
		// A remote Agent may be doing an inventory or filesystem probe at the
		// same time. Give each independent rule request enough time to complete;
		// the calls remain parallel, so one slow endpoint does not serialize the
		// page or erase the rules that are already persisted in the manager.
		ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		defer cancel()
		return h.nodeJSON(ctx, nodeID, http.MethodGet, path, nil, out)
	}
	var wg sync.WaitGroup
	wg.Add(13)
	if knownHealth != nil {
		health = *knownHealth
	} else {
		wg.Add(1)
		go func() { defer wg.Done(); _ = get("/health", &health) }()
	}
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
			policy = h.store.PutPolicy(ctx, recovered)
		} else {
			policy = recovered
		}
	}
	var protectionTrial any
	if recovery, ok := h.store.PendingPolicyUpdate(nodeID, iface); ok && recovery.TrialExpiresAt.After(time.Now()) {
		// A recovery record is shared by both directions, but the console is
		// direction-scoped. Only expose a trial when its publish ID belongs to
		// the direction currently being viewed; otherwise an egress trial is
		// incorrectly rendered as an ingress trial (and vice versa).
		directionMatches := recovery.TrialDirection == "" || recovery.TrialDirection == direction
		_, directionPending := recovery.TrialPublishIDs[direction]
		if directionMatches && (len(recovery.TrialPublishIDs) == 0 || directionPending) {
			protectionTrial = map[string]any{
				"direction":  recovery.TrialDirection,
				"expires_at": recovery.TrialExpiresAt,
				"seconds":    int(time.Until(recovery.TrialExpiresAt).Round(time.Second) / time.Second),
			}
		}
	}

	return map[string]any{
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
	}
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

// nodeHTTPClient pins each enrolled Agent to the certificate captured during
// enrollment. The manager's own TLS CA only authenticates the management Web
// server; using it for every node made cluster rows fall back to
// "防护状态未知" as soon as nodes used independent self-signed certificates.
func (h *ServerHandler) nodeHTTPClient(nodeID string) (*http.Client, nodeauth.Credential, error) {
	defaultClient := h.reverseHTTP
	if defaultClient == nil {
		defaultClient = http.DefaultClient
	}
	if h.nodeCredentials == nil {
		return defaultClient, nodeauth.Credential{}, nil
	}
	credential, ok := h.nodeCredentials.Get(nodeID)
	var durableNode models.Node
	if h.service != nil {
		if node, nodeOK := service.FindNode(h.service.ListNodes(context.Background()), nodeID); nodeOK {
			durableNode = node
			if h.nodeID != "" && node.ID != h.nodeID {
				if endpoint, err := url.Parse(strings.TrimSpace(node.AgentURL)); err == nil {
					host := endpoint.Hostname()
					ip := net.ParseIP(host)
					local, localOK := service.FindNode(h.service.ListNodes(context.Background()), h.nodeID)
					localEndpoint, localErr := url.Parse(strings.TrimSpace(local.AgentURL))
					samePort := localOK && localErr == nil && endpoint.Port() != "" && endpoint.Port() == localEndpoint.Port()
					if samePort && (strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())) {
						// A peer's loopback address resolves to this manager's agent.
						// Refuse the request instead of sending actions to the wrong host.
						return nil, credential, fmt.Errorf("node %s advertises a loopback Agent URL; configure a reachable node address", nodeID)
					}
				}
			}
			// A re-enrollment can keep the endpoint while replacing the node ID,
			// or keep the ID while rotating the endpoint certificate. In both cases
			// the endpoint is the stable identity for the TLS pin used by proxy
			// requests, so prefer its matching credential over a stale ID row.
			if !ok || (strings.TrimRight(strings.TrimSpace(credential.AgentURL), "/") != strings.TrimRight(strings.TrimSpace(node.AgentURL), "/")) {
				if byURL, byURLOK := h.nodeCredentials.GetByAgentURL(node.AgentURL); byURLOK {
					credential, ok = byURL, true
				}
			}
		}
	}
	if !ok || strings.TrimSpace(credential.Certificate) == "" {
		if durableNode.ID != "" && strings.TrimSpace(durableNode.AgentURL) != "" && !ok {
			return defaultClient, credential, fmt.Errorf("node %s has no enrolled credential for %s", nodeID, durableNode.AgentURL)
		}
		return defaultClient, credential, nil
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(credential.AgentURL)), "https://") {
		return defaultClient, credential, nil
	}
	// All page collectors and policy operations share the enrollment transport.
	// Creating a new Transport for every request loses HTTP/2 multiplexing and
	// leaves idle connections behind; multiple standby Webs then amplify each
	// probe into a new TLS handshake. The transport reloads the registry on
	// every request and retires its pool when the pinned certificate changes.
	if transport, ok := defaultClient.Transport.(*nodeauth.Transport); ok && transport.Registry == h.nodeCredentials {
		return defaultClient, credential, nil
	}
	if transport, ok := defaultClient.Transport.(*nodeRelayTransport); ok && transport.handler == h {
		return defaultClient, credential, nil
	}
	tlsConfig, err := transporttls.ClientConfigFromPEM([]byte(credential.Certificate), "", false)
	if err != nil {
		return nil, credential, fmt.Errorf("build TLS client for node %s: %w", nodeID, err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			ForceAttemptHTTP2: true,
		},
	}, credential, nil
}

func (h *ServerHandler) nodeHTTPClientForEndpoint(endpoint string) (*http.Client, map[string]string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed == nil || parsed.Host == "" {
		return h.reverseHTTP, nil, nil
	}
	for _, node := range h.service.ListNodes(context.Background()) {
		agent, parseErr := url.Parse(strings.TrimSpace(node.AgentURL))
		if parseErr != nil || agent == nil || agent.Scheme != parsed.Scheme || agent.Host != parsed.Host {
			continue
		}
		client, credential, clientErr := h.nodeHTTPClient(node.ID)
		if clientErr != nil {
			return nil, nil, clientErr
		}
		headers := map[string]string{}
		if strings.TrimSpace(credential.NodeID) != "" && strings.TrimSpace(credential.Token) != "" {
			headers[nodeauth.NodeHeader] = credential.NodeID
			headers["Authorization"] = "Bearer " + credential.Token
		}
		return client, headers, nil
	}
	return h.reverseHTTP, nil, nil
}

func setNodeAuthHeaders(req *http.Request, credential nodeauth.Credential) {
	if strings.TrimSpace(credential.NodeID) == "" || strings.TrimSpace(credential.Token) == "" {
		return
	}
	req.Header.Set(nodeauth.NodeHeader, credential.NodeID)
	req.Header.Set("Authorization", "Bearer "+credential.Token)
}

func (h *ServerHandler) proxyNode(w http.ResponseWriter, r *http.Request, nodeID, path string) {
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	client, credential, err := h.nodeHTTPClient(nodeID)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	streamingScan := strings.HasSuffix(path, "/security/scan/events")
	if streamingScan {
		// A scan event stream is intentionally long-lived. The ordinary node
		// proxy timeout protects request/response APIs but would cut this stream
		// off before the next heartbeat.
		streamClient := *client
		streamClient.Timeout = 0
		client = &streamClient
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
	setNodeAuthHeaders(req, credential)

	resp, err := client.Do(req)
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
	if streamingScan && resp.StatusCode == http.StatusOK && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		// Each agent flush must reach the browser while the upstream connection
		// remains open; a plain io.Copy can otherwise buffer the whole event.
		_, _ = io.Copy(flushingResponseWriter{w}, resp.Body)
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

type flushingResponseWriter struct{ http.ResponseWriter }

func (w flushingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err != nil {
		return n, err
	}
	return n, http.NewResponseController(w.ResponseWriter).Flush()
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
	// Every manager also proxies policy and health requests to the enrolled
	// agents. Keep the agent listener reachable across the cluster so a standby
	// manager can continue operating after the original manager is offline.
	if endpoint, err := url.Parse(strings.TrimSpace(cfg.AgentURL)); err == nil && endpoint != nil {
		if port := endpoint.Port(); port != "" {
			if parsed, err := strconv.ParseUint(port, 10, 16); err == nil && parsed > 0 {
				protocol := models.PortProtocolTCP
				if endpoint.Scheme == "quic" || endpoint.Scheme == "https3" {
					protocol = models.PortProtocolUDP
				}
				rules = appendUniquePortRule(rules, models.PortRule{Protocol: protocol, Port: uint16(parsed)})
			}
		}
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
	appendIface := func(name string, recommended, attached bool) {
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
			Attached:      attached,
		})
	}
	// A slow inventory scan must not make the console choose an old policy
	// interface (for example eno1) when the dataplane is actually attached to a
	// different NIC (for example ens3). Health is cheaper and authoritative for
	// this fallback, so put an attached/enforced interface first.
	var health models.HealthStatus
	healthCtx, healthCancel := context.WithTimeout(ctx, 2*time.Second)
	if h.nodeJSON(healthCtx, nodeID, http.MethodGet, "/health", nil, &health) == nil {
		for _, item := range health.Interfaces {
			if item.XDPAttached || item.PolicyEnforced || item.EgressPolicyEnforced {
				appendIface(item.Interface, len(interfaces) == 0, true)
			}
		}
	}
	healthCancel()
	for _, iface := range h.service.ListPolicyInterfaces(ctx, nodeID) {
		appendIface(iface, false, false)
	}
	recommended := ""
	if len(interfaces) > 0 {
		recommended = interfaces[0].Name
	}
	if h.defaultInterface != "" {
		appendIface(h.defaultInterface, recommended == "", false)
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
