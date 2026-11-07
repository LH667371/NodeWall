package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodewall/internal/geoip"
	"nodewall/internal/health"
	"nodewall/internal/integrity"
	"nodewall/internal/models"
	"nodewall/internal/monitoring"
	"nodewall/internal/rollback"
	"nodewall/internal/securityscan"
	"nodewall/internal/sshpolicy"
	"nodewall/internal/xdp"
)

type AgentStateStore interface {
	Save(context.Context, map[string]models.InterfaceRuntime) error
	Load(context.Context) (map[string]models.InterfaceRuntime, error)
}

type DropLogRecorder interface {
	Settings() models.DropLogSettings
	UpdateSettings(models.DropLogSettings) error
	Recent(limit int) ([]models.DropLogRecord, error)
	Clear() error
}

type SSHProtectionSettingsStore interface {
	Save(context.Context, models.SSHProtectionSettings) error
	Load(context.Context) (models.SSHProtectionSettings, error)
}

type SSHProtectionOptions struct {
	StateStore            SSHProtectionSettingsStore
	LogPath               string
	PollInterval          time.Duration
	TransferPolicyApplier SSHTransferPolicyApplier
	IntegrityManifestPath string
	ActivityLogPath       string
}

type SSHTransferPolicyApplier interface {
	Apply(context.Context, models.SSHTransferPolicy) error
}

type AgentHandler struct {
	sshSettingsUpdateMu        sync.Mutex
	sshTransferApplied         bool
	policyMu                   sync.Mutex
	nodeID                     string
	xdp                        xdp.Dataplane
	health                     health.Probe
	rollback                   *rollback.Manager
	confirmTimeout             time.Duration
	state                      AgentStateStore
	recorder                   DropLogRecorder
	geoipDB                    *geoip.CountryDB
	runtimeMu                  sync.RWMutex
	runtimes                   map[string]models.InterfaceRuntime
	sshProtectionMu            sync.RWMutex
	sshProtectionSettings      models.SSHProtectionSettings
	sshProtectionStore         SSHProtectionSettingsStore
	sshProtectionLogPath       string
	sshActivityLogPath         string
	sshProtectionPoll          time.Duration
	sshTransferApplier         SSHTransferPolicyApplier
	sshIntegrityMu             sync.RWMutex
	sshIntegrityPath           string
	sshIntegrityManifest       integrity.Manifest
	sshIntegrityStatus         models.SSHIntegrityStatus
	sshFailures                map[string][]time.Time
	sshTotalBans               uint64
	sshLastFailureAt           *time.Time
	sshLastBanAt               *time.Time
	sshLastError               string
	sshLogOffset               int64
	sshLogInfo                 os.FileInfo
	sshJournalSince            time.Time
	sshJournalSeen             map[string]time.Time
	securityMu                 sync.RWMutex
	securityScanner            securityscan.Scanner
	securityJob                *securityScanJob
	securityArchiveDir         string
	securityArchiveWarning     string
	securityArchiveUnavailable string
	securityReports            map[string]scanReportSummary
	monitor                    *monitoring.Collector
}

func NewAgentHandler(nodeID string, xdpManager xdp.Dataplane, state AgentStateStore, confirmTimeout time.Duration, recorder DropLogRecorder, geoipDB *geoip.CountryDB, sshOptions ...SSHProtectionOptions) *AgentHandler {
	options := SSHProtectionOptions{LogPath: detectSSHLogPath(), PollInterval: time.Second, IntegrityManifestPath: "/etc/nodewall/ssh-transfer-integrity.json", ActivityLogPath: "/var/log/nodewall/ssh-activity.log"}
	if len(sshOptions) > 0 {
		options = sshOptions[0]
		if strings.TrimSpace(options.LogPath) == "" {
			options.LogPath = detectSSHLogPath()
		}
		if options.PollInterval <= 0 {
			options.PollInterval = time.Second
		}
		if strings.TrimSpace(options.IntegrityManifestPath) == "" {
			options.IntegrityManifestPath = "/etc/nodewall/ssh-transfer-integrity.json"
		}
		if strings.TrimSpace(options.ActivityLogPath) == "" {
			options.ActivityLogPath = "/var/log/nodewall/ssh-activity.log"
		}
	}
	handler := &AgentHandler{
		nodeID:                nodeID,
		xdp:                   xdpManager,
		health:                health.Probe{NodeID: nodeID, XDP: xdpManager},
		confirmTimeout:        confirmTimeout,
		state:                 state,
		recorder:              recorder,
		geoipDB:               geoipDB,
		runtimes:              make(map[string]models.InterfaceRuntime),
		sshProtectionSettings: defaultSSHProtectionSettings(options.LogPath),
		sshProtectionStore:    options.StateStore,
		sshProtectionLogPath:  options.LogPath,
		sshActivityLogPath:    options.ActivityLogPath,
		sshProtectionPoll:     options.PollInterval,
		sshTransferApplier:    options.TransferPolicyApplier,
		sshIntegrityPath:      options.IntegrityManifestPath,
		sshFailures:           make(map[string][]time.Time),
		securityScanner:       securityscan.New(),
		monitor:               monitoring.NewCollector(nodeID),
	}
	if handler.sshTransferApplier == nil {
		applier := sshpolicy.New()
		applier.ActivityLogPath = handler.sshActivityLogPath
		handler.sshTransferApplier = applier
	}
	handler.rollback = rollback.NewManager(confirmTimeout, func(ctx context.Context, snapshot rollback.Snapshot) error {
		handler.policyMu.Lock()
		defer handler.policyMu.Unlock()
		return handler.restoreSnapshot(ctx, snapshot)
	})
	return handler
}

func (h *AgentHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /system/ssh", h.handleSSHInfo)
	mux.HandleFunc("GET /system/metrics", h.handleSystemMetrics)
	mux.HandleFunc("GET /security/summary", h.handleSecuritySummary)
	mux.HandleFunc("GET /security/scan", h.handleSecurityScanStatus)
	mux.HandleFunc("GET /security/scan/report", h.handleSecurityScanReport)
	mux.HandleFunc("GET /security/scan/reports", h.handleSecurityScanReports)
	mux.HandleFunc("GET /security/scan/reports/{scan}", h.handleSecurityScanReport)
	mux.HandleFunc("POST /security/scan", h.handleSecurityScanStart)
	mux.HandleFunc("POST /security/scan/{finding}/terminate", h.handleSecurityProcessTerminate)
	mux.HandleFunc("POST /security/scan/{finding}/quarantine", h.handleSecurityQuarantine)
	mux.HandleFunc("GET /security/quarantine", h.handleSecurityQuarantineList)
	mux.HandleFunc("DELETE /security/quarantine/{entry}", h.handleSecurityQuarantineDelete)
	mux.HandleFunc("POST /security/quarantine/{entry}/restore", h.handleSecurityQuarantineRestore)
	mux.HandleFunc("GET /ssh-protection", h.handleSSHProtection)
	mux.HandleFunc("GET /ssh-protection/activity", h.handleSSHActivity)
	mux.HandleFunc("PUT /ssh-protection", h.handleSSHProtection)
	mux.HandleFunc("PUT /ssh-protection/transfer", h.handleSSHTransferPolicy)
	mux.HandleFunc("POST /ssh-protection/integrity/baseline", h.handleSSHIntegrityBaseline)
	mux.HandleFunc("POST /ssh-protection/integrity/verify", h.handleSSHIntegrityVerify)
	mux.HandleFunc("DELETE /ssh-protection/blocks/{id}", h.handleDeleteSSHProtectionBlock)
	mux.HandleFunc("GET /interfaces", h.handleInterfaces)
	mux.HandleFunc("GET /settings/logging", h.handleGetLoggingSettings)
	mux.HandleFunc("PUT /settings/logging", h.handleUpdateLoggingSettings)
	mux.HandleFunc("GET /logs/drop", h.handleRecentDropLogs)
	mux.HandleFunc("DELETE /logs/drop", h.handleClearDropLogs)
	mux.HandleFunc("GET /interfaces/{iface}/temporary-blocks", h.handleListTemporaryBlocks)
	mux.HandleFunc("POST /interfaces/{iface}/temporary-blocks", h.handleCreateTemporaryBlock)
	mux.HandleFunc("DELETE /interfaces/{iface}/temporary-blocks/{id}", h.handleDeleteTemporaryBlock)
	mux.HandleFunc("GET /interfaces/{iface}/rate-limits", h.handleListRateLimits)
	mux.HandleFunc("POST /interfaces/{iface}/rate-limits", h.handleCreateRateLimit)
	mux.HandleFunc("DELETE /interfaces/{iface}/rate-limits/{id}", h.handleDeleteRateLimit)
	mux.HandleFunc("GET /interfaces/{iface}/insights", h.handleInsights)
	mux.HandleFunc("GET /interfaces/{iface}/drop-logs", h.handleDropLogs)
	mux.HandleFunc("POST /interfaces/{iface}/attach", h.handleAttach)
	mux.HandleFunc("POST /interfaces/{iface}/detach", h.handleDetach)
	mux.HandleFunc("POST /interfaces/{iface}/bypass", h.handleAddBypass)
	mux.HandleFunc("DELETE /interfaces/{iface}/bypass/{cidr}", h.handleDeleteBypass)
	mux.HandleFunc("GET /interfaces/{iface}/bypass", h.handleListBypass)
	mux.HandleFunc("POST /interfaces/{iface}/block", h.handleAddBlock)
	mux.HandleFunc("DELETE /interfaces/{iface}/block/{cidr}", h.handleDeleteBlock)
	mux.HandleFunc("GET /interfaces/{iface}/block", h.handleListBlock)
	mux.HandleFunc("POST /interfaces/{iface}/allowlist", h.handleAddAllowlist)
	mux.HandleFunc("DELETE /interfaces/{iface}/allowlist/{cidr}", h.handleDeleteAllowlist)
	mux.HandleFunc("GET /interfaces/{iface}/allowlist", h.handleListAllowlist)
	mux.HandleFunc("POST /interfaces/{iface}/icmp-allowlist", h.handleAddICMPAllowlist)
	mux.HandleFunc("DELETE /interfaces/{iface}/icmp-allowlist/{cidr}", h.handleDeleteICMPAllowlist)
	mux.HandleFunc("GET /interfaces/{iface}/icmp-allowlist", h.handleListICMPAllowlist)
	mux.HandleFunc("POST /interfaces/{iface}/icmp-blocklist", h.handleAddICMPBlocklist)
	mux.HandleFunc("DELETE /interfaces/{iface}/icmp-blocklist/{cidr}", h.handleDeleteICMPBlocklist)
	mux.HandleFunc("GET /interfaces/{iface}/icmp-blocklist", h.handleListICMPBlocklist)
	mux.HandleFunc("POST /interfaces/{iface}/public-ports", h.handleAddPublicPort)
	mux.HandleFunc("DELETE /interfaces/{iface}/public-ports/{port}", h.handleDeletePublicPort)
	mux.HandleFunc("GET /interfaces/{iface}/public-ports", h.handleListPublicPorts)
	mux.HandleFunc("POST /interfaces/{iface}/denied-ports", h.handleAddDeniedPort)
	mux.HandleFunc("DELETE /interfaces/{iface}/denied-ports/{port}", h.handleDeleteDeniedPort)
	mux.HandleFunc("GET /interfaces/{iface}/denied-ports", h.handleListDeniedPorts)
	mux.HandleFunc("POST /interfaces/{iface}/ports", h.handleAddPort)
	mux.HandleFunc("DELETE /interfaces/{iface}/ports/{port}", h.handleDeletePort)
	mux.HandleFunc("GET /interfaces/{iface}/ports", h.handleListPorts)
	mux.HandleFunc("GET /interfaces/{iface}/stats", h.handleStats)
	mux.HandleFunc("POST /interfaces/{iface}/publish", h.handlePublish)
	mux.HandleFunc("POST /interfaces/{iface}/apply", h.handlePublish)
	mux.HandleFunc("POST /interfaces/{iface}/confirm", h.handleConfirm)
	mux.HandleFunc("POST /interfaces/{iface}/rollback", h.handleRollback)
	mux.HandleFunc("POST /maintenance/cleanup", h.handleMaintenanceCleanup)
	mux.HandleFunc("POST /maintenance/delete", h.handleMaintenanceDelete)
	return mux
}

func (h *AgentHandler) handleSSHInfo(w http.ResponseWriter, r *http.Request) {
	ports := detectSSHPorts()
	writeJSON(w, http.StatusOK, sshAccessInfo{Ports: ports, Clients: activeSSHClientIPs("/proc", ports)})
}

func (h *AgentHandler) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	if h.monitor == nil {
		writeError(w, http.StatusInternalServerError, errors.New("system monitoring is unavailable"))
		return
	}
	metrics, err := h.monitor.Collect(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, metrics)
}

func (h *AgentHandler) handleMaintenanceCleanup(w http.ResponseWriter, r *http.Request) {
	for _, iface := range h.runtimeKeys() {
		_ = h.xdp.Detach(iface)
	}
	h.clearRuntimes()
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "cleaned",
	})
}

func (h *AgentHandler) handleMaintenanceDelete(w http.ResponseWriter, r *http.Request) {
	h.handleMaintenanceCleanup(w, r)
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	script := fmt.Sprintf("nohup sh -c 'sleep 2; %q cleanup --restart-services=true' >/var/log/nodewall-self-delete.log 2>&1 &", exePath)
	_ = exec.Command("sh", "-c", script).Run()
}

func (h *AgentHandler) LoadState(ctx context.Context) error {
	if h.state == nil {
		return nil
	}

	runtimes, err := h.state.Load(ctx)
	if err != nil {
		return err
	}

	for iface, runtime := range runtimes {
		legacyUnconfirmed := !runtime.EnforcementConfirmed
		for direction, snapshot := range runtime.Recovery {
			runtime = withDirectionState(runtime, direction, snapshot)
		}
		runtime.Recovery = nil
		if runtime.PendingPublish != nil {
			runtime.PendingPublish.Status = models.PublishFailed
			runtime.PendingPublish = nil
		}
		if runtime.Egress.PendingPublish != nil {
			runtime.Egress.PendingPublish.Status = models.PublishFailed
			runtime.Egress.PendingPublish = nil
		}
		// State written before the explicit enforcement marker was introduced
		// must fail open after upgrade. Operators can re-enable the protection
		// baseline deliberately once recovery ports and cluster routes are set.
		if legacyUnconfirmed || !runtime.EnforcementConfirmed {
			runtime.EnforcementConfirmed = false
			runtime.ObserveOnly = true
		}
		runtime.PublicPortRules = models.NormalizePortRules(runtime.PublicPortRules, runtime.PublicPorts)
		runtime.DeniedPortRules = models.NormalizePortRules(runtime.DeniedPortRules, runtime.DeniedPorts)
		runtime.AllowedPortRules = models.NormalizePortRules(runtime.AllowedPortRules, runtime.AllowedPorts)
		runtime.PublicPorts = models.CollapsePortRules(runtime.PublicPortRules)
		runtime.DeniedPorts = models.CollapsePortRules(runtime.DeniedPortRules)
		runtime.AllowedPorts = models.CollapsePortRules(runtime.AllowedPortRules)
		runtime.NonIPv4Action = defaultAction(runtime.NonIPv4Action)
		runtime.Egress.PublicPortRules = models.NormalizePortRules(runtime.Egress.PublicPortRules, runtime.Egress.PublicPorts)
		runtime.Egress.DeniedPortRules = models.NormalizePortRules(runtime.Egress.DeniedPortRules, runtime.Egress.DeniedPorts)
		runtime.Egress.AllowedPortRules = models.NormalizePortRules(runtime.Egress.AllowedPortRules, runtime.Egress.AllowedPorts)
		runtime.Egress.PublicPorts = models.CollapsePortRules(runtime.Egress.PublicPortRules)
		runtime.Egress.DeniedPorts = models.CollapsePortRules(runtime.Egress.DeniedPortRules)
		runtime.Egress.AllowedPorts = models.CollapsePortRules(runtime.Egress.AllowedPortRules)
		runtime.Egress.NonIPv4Action = defaultAction(runtime.Egress.NonIPv4Action)
		h.setRuntime(iface, runtime)
	}

	return h.reconcileState(ctx)
}

func (h *AgentHandler) handleAttach(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if err := h.validateAttachableInterface(iface); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := h.xdp.Attach(iface, xdp.ParseAttachMode(req.Mode)); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	runtime := h.ensureRuntime(iface)
	runtime.Attached = true
	if !runtime.EnforcementConfirmed {
		runtime.ObserveOnly = true
	}
	// XDP attach also installs the tc egress tracker, but it must only be
	// reported as active after the attach operation succeeds. Keeping this
	// state false for undiscovered interfaces prevents the inventory API from
	// claiming that every host interface is protected on startup.
	runtime.Egress.Attached = true
	runtime.Egress.AttachMode = "tc"
	// The dataplane may transparently fall back from native to generic XDP.
	// Persist the mode that was actually attached so restart reconciliation
	// does not blindly retry an unsupported mode.
	if dataplaneRuntime, err := h.xdp.Runtime(iface); err == nil && dataplaneRuntime.Mode != "" {
		runtime.AttachMode = string(dataplaneRuntime.Mode)
	} else {
		runtime.AttachMode = string(xdp.ParseAttachMode(req.Mode))
	}
	runtime.LastUpdatedAt = time.Now().UTC()
	h.setRuntime(iface, runtime)
	if err := h.xdp.ReplaceRateLimitRules(iface, runtime.RateLimits); err != nil {
		_ = h.xdp.Detach(iface)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		_ = h.xdp.Detach(iface)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) validateAttachableInterface(iface string) error {
	inventory, err := xdp.DetectHostInterfaces()
	if err != nil {
		return err
	}
	for _, item := range inventory.Interfaces {
		if item.Name != iface {
			continue
		}
		if !item.IsPhysical || item.IsLoopback {
			return fmt.Errorf("interface %s is not a physical interface and cannot be attached", iface)
		}
		return nil
	}
	// Keep compatibility for mocked or pre-provisioned interfaces not discoverable by net.Interfaces.
	return nil
}

func (h *AgentHandler) handleDetach(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if err := h.xdp.Detach(iface); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	runtime := h.ensureRuntime(iface)
	runtime.Attached = false
	runtime.Egress.Attached = false
	runtime.Egress.AttachMode = ""
	runtime.LastUpdatedAt = time.Now().UTC()
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.xdp.UpsertCIDR(iface, req.CIDR); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	runtime := h.ensureRuntime(iface)
	runtime.Allowlist = appendCIDR(runtime.Allowlist, req.CIDR)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleAddBypass(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.xdp.UpsertBypassCIDR(iface, req.CIDR); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	runtime := h.ensureRuntime(iface)
	runtime.BypassCIDRs = appendCIDR(runtime.BypassCIDRs, req.CIDR)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleDeleteAllowlist(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	cidr := strings.ReplaceAll(r.PathValue("cidr"), "%2F", "/")
	if err := h.xdp.DeleteCIDR(iface, cidr); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	runtime := h.ensureRuntime(iface)
	runtime.Allowlist = removeCIDR(runtime.Allowlist, cidr)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleDeleteBypass(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	cidr := strings.ReplaceAll(r.PathValue("cidr"), "%2F", "/")
	if err := h.xdp.DeleteBypassCIDR(iface, cidr); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	runtime := h.ensureRuntime(iface)
	runtime.BypassCIDRs = removeCIDR(runtime.BypassCIDRs, cidr)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleAddBlock(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.xdp.UpsertBlockedCIDR(iface, req.CIDR); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	runtime := h.ensureRuntime(iface)
	runtime.BlockedCIDRs = appendCIDR(runtime.BlockedCIDRs, req.CIDR)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleDeleteBlock(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	cidr := strings.ReplaceAll(r.PathValue("cidr"), "%2F", "/")
	if err := h.xdp.DeleteBlockedCIDR(iface, cidr); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	runtime := h.ensureRuntime(iface)
	runtime.BlockedCIDRs = removeCIDR(runtime.BlockedCIDRs, cidr)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleListBlock(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	cidrs, err := h.xdp.ListBlockedCIDRs(iface)
	if err != nil {
		cidrs = h.ensureRuntime(iface).BlockedCIDRs
	}
	writeJSON(w, http.StatusOK, map[string]any{"blocked_cidrs": cidrs})
}

func (h *AgentHandler) handleListAllowlist(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	allowlist, err := h.xdp.ListCIDRs(iface)
	if err != nil {
		allowlist = h.ensureRuntime(iface).Allowlist
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowlist": allowlist})
}

func (h *AgentHandler) handleAddICMPAllowlist(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.xdp.UpsertICMPAllowCIDR(iface, req.CIDR); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	runtime := h.ensureRuntime(iface)
	runtime.ICMPAllowCIDRs = appendCIDR(runtime.ICMPAllowCIDRs, req.CIDR)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleDeleteICMPAllowlist(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	cidr := strings.ReplaceAll(r.PathValue("cidr"), "%2F", "/")
	if err := h.xdp.DeleteICMPAllowCIDR(iface, cidr); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	runtime := h.ensureRuntime(iface)
	runtime.ICMPAllowCIDRs = removeCIDR(runtime.ICMPAllowCIDRs, cidr)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleListICMPAllowlist(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	cidrs, err := h.xdp.ListICMPAllowCIDRs(iface)
	if err != nil {
		cidrs = h.ensureRuntime(iface).ICMPAllowCIDRs
	}
	writeJSON(w, http.StatusOK, map[string]any{"icmp_allow_cidrs": cidrs})
}

func (h *AgentHandler) handleAddICMPBlocklist(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.xdp.UpsertICMPBlockedCIDR(iface, req.CIDR); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	runtime := h.ensureRuntime(iface)
	runtime.ICMPBlockedCIDRs = appendCIDR(runtime.ICMPBlockedCIDRs, req.CIDR)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleDeleteICMPBlocklist(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	cidr := strings.ReplaceAll(r.PathValue("cidr"), "%2F", "/")
	if err := h.xdp.DeleteICMPBlockedCIDR(iface, cidr); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	runtime := h.ensureRuntime(iface)
	runtime.ICMPBlockedCIDRs = removeCIDR(runtime.ICMPBlockedCIDRs, cidr)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleListICMPBlocklist(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	cidrs, err := h.xdp.ListICMPBlockedCIDRs(iface)
	if err != nil {
		cidrs = h.ensureRuntime(iface).ICMPBlockedCIDRs
	}
	writeJSON(w, http.StatusOK, map[string]any{"icmp_blocked_cidrs": cidrs})
}

func (h *AgentHandler) handleListBypass(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	cidrs, err := h.xdp.ListBypassCIDRs(iface)
	if err != nil {
		cidrs = h.ensureRuntime(iface).BypassCIDRs
	}
	writeJSON(w, http.StatusOK, map[string]any{"bypass_cidrs": cidrs})
}

func (h *AgentHandler) handleAddPort(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	var req struct {
		Port     uint16 `json:"port"`
		Protocol string `json:"protocol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	protocol, hasProtocol := parseOptionalPortProtocol(req.Protocol)
	if hasProtocol {
		if err := h.xdp.UpsertPortRule(iface, models.PortRule{Protocol: protocol, Port: req.Port}); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		if err := h.xdp.UpsertPort(iface, req.Port); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	runtime := h.ensureRuntime(iface)
	if hasProtocol {
		runtime.AllowedPortRules = appendPortRule(runtime.AllowedPortRules, models.PortRule{Protocol: protocol, Port: req.Port})
	} else {
		runtime.AllowedPortRules = appendPortRule(runtime.AllowedPortRules, models.PortRule{Protocol: models.PortProtocolTCP, Port: req.Port})
		runtime.AllowedPortRules = appendPortRule(runtime.AllowedPortRules, models.PortRule{Protocol: models.PortProtocolUDP, Port: req.Port})
	}
	runtime.AllowedPorts = models.CollapsePortRules(runtime.AllowedPortRules)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleAddPublicPort(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	var req struct {
		Port     uint16 `json:"port"`
		Protocol string `json:"protocol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	protocol, hasProtocol := parseOptionalPortProtocol(req.Protocol)
	if hasProtocol {
		if err := h.xdp.UpsertPublicPortRule(iface, models.PortRule{Protocol: protocol, Port: req.Port}); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		if err := h.xdp.UpsertPublicPort(iface, req.Port); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	runtime := h.ensureRuntime(iface)
	if hasProtocol {
		runtime.PublicPortRules = appendPortRule(runtime.PublicPortRules, models.PortRule{Protocol: protocol, Port: req.Port})
	} else {
		runtime.PublicPortRules = appendPortRule(runtime.PublicPortRules, models.PortRule{Protocol: models.PortProtocolTCP, Port: req.Port})
		runtime.PublicPortRules = appendPortRule(runtime.PublicPortRules, models.PortRule{Protocol: models.PortProtocolUDP, Port: req.Port})
	}
	runtime.PublicPorts = models.CollapsePortRules(runtime.PublicPortRules)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleDeletePort(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	portValue := r.PathValue("port")
	port, err := parsePort(portValue)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	protocol, hasProtocol := parseOptionalPortProtocol(r.URL.Query().Get("protocol"))
	if hasProtocol {
		if err := h.xdp.DeletePortRule(iface, models.PortRule{Protocol: protocol, Port: port}); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		if err := h.xdp.DeletePort(iface, port); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	runtime := h.ensureRuntime(iface)
	if hasProtocol {
		runtime.AllowedPortRules = removePortRule(runtime.AllowedPortRules, models.PortRule{Protocol: protocol, Port: port})
	} else {
		runtime.AllowedPortRules = removePortRulesByPort(runtime.AllowedPortRules, port)
	}
	runtime.AllowedPorts = models.CollapsePortRules(runtime.AllowedPortRules)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleDeletePublicPort(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	portValue := r.PathValue("port")
	port, err := parsePort(portValue)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	protocol, hasProtocol := parseOptionalPortProtocol(r.URL.Query().Get("protocol"))
	if hasProtocol {
		if err := h.xdp.DeletePublicPortRule(iface, models.PortRule{Protocol: protocol, Port: port}); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		if err := h.xdp.DeletePublicPort(iface, port); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	runtime := h.ensureRuntime(iface)
	if hasProtocol {
		runtime.PublicPortRules = removePortRule(runtime.PublicPortRules, models.PortRule{Protocol: protocol, Port: port})
	} else {
		runtime.PublicPortRules = removePortRulesByPort(runtime.PublicPortRules, port)
	}
	runtime.PublicPorts = models.CollapsePortRules(runtime.PublicPortRules)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleAddDeniedPort(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	var req struct {
		Port     uint16 `json:"port"`
		Protocol string `json:"protocol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	protocol, hasProtocol := parseOptionalPortProtocol(req.Protocol)
	if hasProtocol {
		if err := h.xdp.UpsertDeniedPortRule(iface, models.PortRule{Protocol: protocol, Port: req.Port}); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		if err := h.xdp.UpsertDeniedPort(iface, req.Port); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	runtime := h.ensureRuntime(iface)
	if hasProtocol {
		runtime.DeniedPortRules = appendPortRule(runtime.DeniedPortRules, models.PortRule{Protocol: protocol, Port: req.Port})
	} else {
		runtime.DeniedPortRules = appendPortRule(runtime.DeniedPortRules, models.PortRule{Protocol: models.PortProtocolTCP, Port: req.Port})
		runtime.DeniedPortRules = appendPortRule(runtime.DeniedPortRules, models.PortRule{Protocol: models.PortProtocolUDP, Port: req.Port})
	}
	runtime.DeniedPorts = models.CollapsePortRules(runtime.DeniedPortRules)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleDeleteDeniedPort(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	portValue := r.PathValue("port")
	port, err := parsePort(portValue)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	protocol, hasProtocol := parseOptionalPortProtocol(r.URL.Query().Get("protocol"))
	if hasProtocol {
		if err := h.xdp.DeleteDeniedPortRule(iface, models.PortRule{Protocol: protocol, Port: port}); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		if err := h.xdp.DeleteDeniedPort(iface, port); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	runtime := h.ensureRuntime(iface)
	if hasProtocol {
		runtime.DeniedPortRules = removePortRule(runtime.DeniedPortRules, models.PortRule{Protocol: protocol, Port: port})
	} else {
		runtime.DeniedPortRules = removePortRulesByPort(runtime.DeniedPortRules, port)
	}
	runtime.DeniedPorts = models.CollapsePortRules(runtime.DeniedPortRules)
	runtime.LastUpdatedAt = time.Now().UTC()
	if err := h.syncPolicyConfig(iface, runtime); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.setRuntime(iface, runtime)
	_ = h.persist(r.Context())
	writeJSON(w, http.StatusOK, runtime)
}

func (h *AgentHandler) handleListDeniedPorts(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	rules, err := h.xdp.ListDeniedPortRules(iface)
	if err != nil {
		rules = h.ensureRuntime(iface).DeniedPortRules
	}
	writeJSON(w, http.StatusOK, map[string]any{"denied_ports": models.CollapsePortRules(rules), "denied_port_rules": rules})
}

func (h *AgentHandler) handleListPorts(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	rules, err := h.xdp.ListPortRules(iface)
	if err != nil {
		rules = h.ensureRuntime(iface).AllowedPortRules
	}
	writeJSON(w, http.StatusOK, map[string]any{"ports": models.CollapsePortRules(rules), "port_rules": rules})
}

func (h *AgentHandler) handleListPublicPorts(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	rules, err := h.xdp.ListPublicPortRules(iface)
	if err != nil {
		rules = h.ensureRuntime(iface).PublicPortRules
	}
	writeJSON(w, http.StatusOK, map[string]any{"public_ports": models.CollapsePortRules(rules), "public_port_rules": rules})
}

func (h *AgentHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	direction := requestPolicyDirection(r)
	if direction == models.DirectionEgress {
		if directional, ok := h.xdp.(xdp.DirectionalStats); ok {
			if stats, err := directional.ReadDirectionStats(iface, direction); err == nil {
				stats.Direction = direction
				h.recordDirectionTrend(iface, direction, stats)
				writeJSON(w, http.StatusOK, stats)
				return
			}
		}
		stats := models.InterfaceStats{Direction: models.DirectionEgress}
		if current := h.ensureRuntime(iface).Egress.LastStats; current != nil {
			stats = *current
			stats.Direction = models.DirectionEgress
		}
		writeJSON(w, http.StatusOK, stats)
		return
	}
	stats, err := h.xdp.ReadStats(iface)
	if err != nil {
		if xdp.IsNotAttached(err) {
			stats := models.InterfaceStats{Direction: models.DirectionIngress}
			if current := h.ensureRuntime(iface).LastStats; current != nil {
				stats = *current
				stats.Direction = models.DirectionIngress
			}
			writeJSON(w, http.StatusOK, stats)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	stats.Direction = models.DirectionIngress
	h.recordTrend(iface, stats)
	writeJSON(w, http.StatusOK, stats)
}

func (h *AgentHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := h.health.Check(r.Context())
	// A persisted runtime can say that an interface is attached even when
	// recovery failed before the dataplane manager recreated its link. Keep
	// that mismatch visible instead of reporting a misleading healthy agent.
	for iface, runtime := range h.runtimeSnapshotAll() {
		if !runtime.Attached {
			continue
		}
		found := false
		for _, item := range status.Interfaces {
			if item.Interface == iface {
				found = true
				break
			}
		}
		if found {
			continue
		}
		status.Status = "degraded"
		status.Interfaces = append(status.Interfaces, models.InterfaceHealth{
			Interface:   iface,
			XDPAttached: false,
			MapOK:       false,
			StatsOK:     false,
			LastCheckAt: time.Now().UTC(),
			LastError:   "persisted interface state is attached but dataplane is not loaded",
		})
	}
	writeJSON(w, http.StatusOK, status)
}

func (h *AgentHandler) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	inventory, err := h.xdp.DiscoverInterfaces()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for i := range inventory.Interfaces {
		_ = h.pruneExpiredDispositions(r.Context(), inventory.Interfaces[i].Name)
		runtime := h.ensureRuntime(inventory.Interfaces[i].Name)
		var lastPassed, lastDropped uint64
		if runtime.LastStats != nil {
			lastPassed = runtime.LastStats.Passed
			lastDropped = runtime.LastStats.Dropped
		}
		var egressPassed, egressDropped uint64
		if runtime.Egress.LastStats != nil {
			egressPassed = runtime.Egress.LastStats.Passed
			egressDropped = runtime.Egress.LastStats.Dropped
		}
		inventory.Interfaces[i].Attached = runtime.Attached
		inventory.Interfaces[i].BypassCIDRs = len(runtime.BypassCIDRs)
		inventory.Interfaces[i].BlockedCIDRs = len(runtime.BlockedCIDRs)
		inventory.Interfaces[i].AllowCIDRs = len(runtime.Allowlist)
		inventory.Interfaces[i].PublicPorts = len(models.NormalizePortRules(runtime.PublicPortRules, runtime.PublicPorts))
		inventory.Interfaces[i].DeniedPorts = len(models.NormalizePortRules(runtime.DeniedPortRules, runtime.DeniedPorts))
		inventory.Interfaces[i].AllowPorts = len(models.NormalizePortRules(runtime.AllowedPortRules, runtime.AllowedPorts))
		inventory.Interfaces[i].AttachMode = runtime.AttachMode
		inventory.Interfaces[i].LastPassed = lastPassed
		inventory.Interfaces[i].LastDropped = lastDropped
		inventory.Interfaces[i].PendingPublish = runtime.PendingPublish
		inventory.Interfaces[i].Egress = models.DirectionInventory{
			Attached:        runtime.Egress.Attached,
			AttachMode:      runtime.Egress.AttachMode,
			BypassCIDRs:     len(runtime.Egress.BypassCIDRs),
			BlockedCIDRs:    len(runtime.Egress.BlockedCIDRs),
			AllowCIDRs:      len(runtime.Egress.Allowlist),
			PublicPorts:     len(models.NormalizePortRules(runtime.Egress.PublicPortRules, runtime.Egress.PublicPorts)),
			DeniedPorts:     len(models.NormalizePortRules(runtime.Egress.DeniedPortRules, runtime.Egress.DeniedPorts)),
			AllowPorts:      len(models.NormalizePortRules(runtime.Egress.AllowedPortRules, runtime.Egress.AllowedPorts)),
			LastPassed:      egressPassed,
			LastDropped:     egressDropped,
			RateLimits:      len(runtime.Egress.RateLimits),
			TemporaryBlocks: len(runtime.Egress.TemporaryBlocks),
			ObserveOnly:     runtime.Egress.ObserveOnly,
			PendingPublish:  runtime.Egress.PendingPublish,
		}
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (h *AgentHandler) handleInsights(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	direction := requestPolicyDirection(r)
	if direction == models.DirectionEgress {
		insights, err := h.buildDirectionInsights(iface, direction, 10)
		if err == nil {
			writeJSON(w, http.StatusOK, insights)
			return
		}
		runtime := h.ensureRuntime(iface).Egress
		writeJSON(w, http.StatusOK, emptyDirectionInsights(iface, direction, runtime.Trend))
		return
	}
	insights, err := h.buildInsights(iface, 10)
	if err != nil {
		if xdp.IsNotAttached(err) {
			writeJSON(w, http.StatusOK, models.InterfaceInsights{
				Direction:       models.DirectionIngress,
				Interface:       iface,
				TopPassed:       []models.SourceStat{},
				TopDropped:      []models.SourceStat{},
				TopAttackers:    []models.SourceStat{},
				TopCountries:    []models.CountryStat{},
				TopPorts:        []models.PortStat{},
				Trend:           append([]models.TrafficPoint(nil), h.ensureRuntime(iface).Trend...),
				SuggestedBlocks: []models.BlockSuggestion{},
				UpdatedAt:       time.Now().UTC(),
			})
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	insights.Direction = models.DirectionIngress
	writeJSON(w, http.StatusOK, insights)
}

func (h *AgentHandler) handleDropLogs(w http.ResponseWriter, r *http.Request) {
	direction := requestPolicyDirection(r)
	if direction == models.DirectionEgress {
		if directional, ok := h.xdp.(xdp.DirectionalStats); ok {
			logs, err := directional.ReadDirectionDropLogs(r.PathValue("iface"), direction, 20)
			if err == nil {
				runtime := h.ensureRuntime(r.PathValue("iface"))
				for i := range logs {
					if geo, ok := h.lookupGeo(logs[i].SourceIP); ok {
						logs[i].Geo = &geo
					}
					disposition := buildDispositionFor(runtime, r.PathValue("iface"), direction, logs[i].SourceIP, logs[i].Port)
					logs[i].Disposition = &disposition
				}
				writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"logs": []models.InterceptLogEntry{}})
		return
	}
	logs, err := h.xdp.ReadDropLogs(r.PathValue("iface"), 20)
	if err != nil {
		if xdp.IsNotAttached(err) {
			writeJSON(w, http.StatusOK, map[string]any{"logs": []models.InterceptLogEntry{}})
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	runtime := h.ensureRuntime(r.PathValue("iface"))
	for i := range logs {
		if geo, ok := h.lookupGeo(logs[i].SourceIP); ok {
			logs[i].Geo = &geo
		}
		disposition := buildDispositionFor(runtime, r.PathValue("iface"), models.DirectionIngress, logs[i].SourceIP, logs[i].Port)
		logs[i].Disposition = &disposition
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}

func (h *AgentHandler) handleGetLoggingSettings(w http.ResponseWriter, r *http.Request) {
	if h.recorder == nil {
		writeJSON(w, http.StatusOK, models.DropLogSettings{})
		return
	}
	writeJSON(w, http.StatusOK, h.recorder.Settings())
}

func (h *AgentHandler) handleUpdateLoggingSettings(w http.ResponseWriter, r *http.Request) {
	if h.recorder == nil {
		writeError(w, http.StatusBadRequest, errors.New("logging settings unavailable"))
		return
	}
	var settings models.DropLogSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.recorder.UpdateSettings(settings); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.applyReplyFlowTimeout(r.Context()); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, h.recorder.Settings())
}

func (h *AgentHandler) handleRecentDropLogs(w http.ResponseWriter, r *http.Request) {
	if h.recorder == nil {
		writeJSON(w, http.StatusOK, map[string]any{"logs": []models.DropLogRecord{}})
		return
	}
	limit := 300
	if value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit"))); err == nil && value > 0 {
		limit = min(value, 1000)
	}
	logs, err := h.recorder.Recent(limit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	for i := range logs {
		if geo, ok := h.lookupGeo(logs[i].SourceIP); ok {
			logs[i].Geo = &geo
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}

func (h *AgentHandler) handleClearDropLogs(w http.ResponseWriter, r *http.Request) {
	if h.recorder == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "cleared"})
		return
	}
	if err := h.recorder.Clear(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "cleared"})
}

func (h *AgentHandler) handlePublish(w http.ResponseWriter, r *http.Request) {
	h.policyMu.Lock()
	defer h.policyMu.Unlock()
	iface := r.PathValue("iface")
	var req struct {
		Direction        models.PolicyDirection `json:"direction"`
		PublishID        string                 `json:"publish_id"`
		BypassCIDRs      []string               `json:"bypass_cidrs"`
		BlockedCIDRs     []string               `json:"blocked_cidrs"`
		ICMPAllowCIDRs   []string               `json:"icmp_allow_cidrs"`
		ICMPBlockedCIDRs []string               `json:"icmp_blocked_cidrs"`
		Allowlist        []string               `json:"allowlist"`
		PublicPorts      []uint16               `json:"public_ports"`
		DeniedPorts      []uint16               `json:"denied_ports"`
		AllowedPorts     []uint16               `json:"allowed_ports"`
		PublicPortRules  []models.PortRule      `json:"public_port_rules"`
		DeniedPortRules  []models.PortRule      `json:"denied_port_rules"`
		AllowedPortRules []models.PortRule      `json:"allowed_port_rules"`
		NonIPv4Action    models.NonIPv4Action   `json:"non_ipv4_action"`
		Challenge        models.ChallengeSpec   `json:"challenge"`
		ConfirmTimeout   int                    `json:"confirm_timeout"`
		Immediate        bool                   `json:"immediate"`
		SafetyTimeout    int                    `json:"safety_timeout"`
		ObserveOnly      bool                   `json:"observe_only"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	direction := req.Direction
	if direction == "" {
		direction = models.DirectionIngress
	}
	if direction != models.DirectionIngress && direction != models.DirectionEgress {
		writeError(w, http.StatusBadRequest, errors.New("direction must be ingress or egress"))
		return
	}
	runtime := h.ensureRuntime(iface)
	directionRuntime := directionStateFor(runtime, direction)
	snapshot := rollback.Snapshot{
		Direction:        direction,
		Interface:        iface,
		Attached:         directionRuntime.Attached,
		AttachMode:       directionRuntime.AttachMode,
		BypassCIDRs:      append([]string(nil), directionRuntime.BypassCIDRs...),
		BlockedCIDRs:     append([]string(nil), directionRuntime.BlockedCIDRs...),
		ICMPAllowCIDRs:   append([]string(nil), directionRuntime.ICMPAllowCIDRs...),
		ICMPBlockedCIDRs: append([]string(nil), directionRuntime.ICMPBlockedCIDRs...),
		Allowlist:        append([]string(nil), directionRuntime.Allowlist...),
		PublicPorts:      append([]uint16(nil), directionRuntime.PublicPorts...),
		DeniedPorts:      append([]uint16(nil), directionRuntime.DeniedPorts...),
		AllowedPorts:     append([]uint16(nil), directionRuntime.AllowedPorts...),
		PublicPortRules:  append([]models.PortRule(nil), directionRuntime.PublicPortRules...),
		DeniedPortRules:  append([]models.PortRule(nil), directionRuntime.DeniedPortRules...),
		AllowedPortRules: append([]models.PortRule(nil), directionRuntime.AllowedPortRules...),
		RateLimitRules:   append([]models.RateLimitRule(nil), directionRuntime.RateLimits...),
		TemporaryBlocks:  append([]models.TemporaryBlock(nil), directionRuntime.TemporaryBlocks...),
		NonIPv4Action:    directionRuntime.NonIPv4Action,
		Challenge:        directionRuntime.Challenge,
		ObserveOnly:      directionRuntime.ObserveOnly,
	}

	req.PublicPortRules = models.NormalizePortRules(req.PublicPortRules, req.PublicPorts)
	req.DeniedPortRules = models.NormalizePortRules(req.DeniedPortRules, req.DeniedPorts)
	req.AllowedPortRules = models.NormalizePortRules(req.AllowedPortRules, req.AllowedPorts)
	req.PublicPorts = models.CollapsePortRules(req.PublicPortRules)
	req.DeniedPorts = models.CollapsePortRules(req.DeniedPortRules)
	req.AllowedPorts = models.CollapsePortRules(req.AllowedPortRules)

	publishID := req.PublishID
	if publishID == "" && !req.Immediate {
		publishID = fmt.Sprintf("pub-%d", time.Now().UnixNano())
	}
	confirmTimeout := h.confirmTimeout
	if req.ConfirmTimeout > 0 {
		confirmTimeout = time.Duration(req.ConfirmTimeout) * time.Second
	}
	safetyStarted := req.SafetyTimeout > 0
	applyCompleted := false
	if safetyStarted {
		if _, pending := runtime.Recovery[direction]; pending {
			writeError(w, http.StatusConflict, errors.New("a policy update is already being verified"))
			return
		}
		if publishID == "" {
			writeError(w, http.StatusBadRequest, errors.New("automatic safety checks require a publish_id"))
			return
		}
		recovery := make(map[models.PolicyDirection]models.DirectionRuntime, len(runtime.Recovery)+1)
		for key, value := range runtime.Recovery {
			recovery[key] = value
		}
		recovery[direction] = directionRuntime
		runtime.Recovery = recovery
		h.setRuntime(iface, runtime)
		if err := h.persist(r.Context()); err != nil {
			delete(recovery, direction)
			h.setRuntime(iface, runtime)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("save recovery snapshot before policy update: %w", err))
			return
		}
		timeout := time.Duration(min(max(req.SafetyTimeout, 1), 120)) * time.Second
		h.rollback.BeginWithTimeout(r.Context(), publishID, snapshot, timeout)
		defer func() {
			if !applyCompleted {
				h.rollback.Confirm(publishID)
			}
		}()
	}

	if direction == models.DirectionIngress {
		if err := h.xdp.ReplaceBypassCIDRs(iface, req.BypassCIDRs); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.xdp.ReplaceBlockedCIDRs(iface, req.BlockedCIDRs); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.xdp.ReplaceICMPAllowCIDRs(iface, req.ICMPAllowCIDRs); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.xdp.ReplaceICMPBlockedCIDRs(iface, req.ICMPBlockedCIDRs); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.xdp.ReplaceAllowlist(iface, req.Allowlist); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.xdp.ReplacePublicPortRules(iface, req.PublicPortRules); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.xdp.ReplaceDeniedPortRules(iface, req.DeniedPortRules); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.xdp.ReplacePortRules(iface, req.AllowedPortRules); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.xdp.ReplaceRateLimitRules(iface, directionRuntime.RateLimits); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.xdp.WriteConfig(iface, xdp.Config{
			NonIPv4Action:           defaultAction(req.NonIPv4Action),
			PortPolicyEnabled:       len(req.AllowedPortRules) > 0,
			RateLimitEnabled:        len(directionRuntime.RateLimits) > 0,
			PolicyEnforced:          policyEnforcedFor(req.BypassCIDRs, req.BlockedCIDRs, req.ICMPAllowCIDRs, req.ICMPBlockedCIDRs, req.Allowlist, req.PublicPorts, req.DeniedPorts, req.AllowedPorts) || len(directionRuntime.TemporaryBlocks) > 0,
			EgressPolicyEnforced:    directionPolicyEnforced(runtime.Egress),
			ObserveOnly:             req.ObserveOnly,
			ReplyFlowTimeoutSeconds: h.replyFlowTimeoutSeconds(),
		}); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		for _, item := range directionRuntime.TemporaryBlocks {
			if err := h.applyTemporaryBlock(iface, item); err != nil {
				_ = h.restoreSnapshot(r.Context(), snapshot)
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
	}

	if direction == models.DirectionEgress {
		if directional, ok := h.xdp.(xdp.DirectionalDataplane); ok {
			policy := xdp.DirectionPolicy{
				BypassCIDRs:      req.BypassCIDRs,
				BlockedCIDRs:     req.BlockedCIDRs,
				ICMPAllowCIDRs:   req.ICMPAllowCIDRs,
				ICMPBlockedCIDRs: req.ICMPBlockedCIDRs,
				Allowlist:        req.Allowlist,
				PublicPortRules:  req.PublicPortRules,
				DeniedPortRules:  req.DeniedPortRules,
				AllowedPortRules: req.AllowedPortRules,
				RateLimitRules:   directionRuntime.RateLimits,
				TemporaryBlocks:  directionRuntime.TemporaryBlocks,
				NonIPv4Action:    defaultAction(req.NonIPv4Action),
				PolicyEnforced:   policyEnforcedFor(req.BypassCIDRs, req.BlockedCIDRs, req.ICMPAllowCIDRs, req.ICMPBlockedCIDRs, req.Allowlist, req.PublicPorts, req.DeniedPorts, req.AllowedPorts) || len(directionRuntime.TemporaryBlocks) > 0,
				ObserveOnly:      req.ObserveOnly,
			}
			if err := directional.ApplyDirectionPolicy(iface, models.DirectionEgress, policy); err != nil {
				_ = h.restoreSnapshot(r.Context(), snapshot)
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
	}

	if direction == models.DirectionIngress {
		healthStatus := h.health.Check(r.Context())
		if !isHealthyForInterface(healthStatus, iface) {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, errors.New("health check failed after publish"))
			return
		}
	}

	nextDirectionRuntime := models.DirectionRuntime{
		Attached:         true,
		AttachMode:       directionRuntime.AttachMode,
		BypassCIDRs:      append([]string(nil), req.BypassCIDRs...),
		BlockedCIDRs:     append([]string(nil), req.BlockedCIDRs...),
		ICMPAllowCIDRs:   append([]string(nil), req.ICMPAllowCIDRs...),
		ICMPBlockedCIDRs: append([]string(nil), req.ICMPBlockedCIDRs...),
		Allowlist:        append([]string(nil), req.Allowlist...),
		PublicPorts:      normalizePortList(req.PublicPorts),
		DeniedPorts:      normalizePortList(req.DeniedPorts),
		AllowedPorts:     normalizePortList(req.AllowedPorts),
		PublicPortRules:  models.NormalizePortRules(req.PublicPortRules, req.PublicPorts),
		DeniedPortRules:  models.NormalizePortRules(req.DeniedPortRules, req.DeniedPorts),
		AllowedPortRules: models.NormalizePortRules(req.AllowedPortRules, req.AllowedPorts),
		NonIPv4Action:    defaultAction(req.NonIPv4Action),
		Challenge:        normalizeChallenge(req.Challenge),
		RateLimits:       append([]models.RateLimitRule(nil), directionRuntime.RateLimits...),
		TemporaryBlocks:  append([]models.TemporaryBlock(nil), directionRuntime.TemporaryBlocks...),
		ObserveOnly:      req.ObserveOnly,
		PendingPublish:   publishRecordForApply(req.Immediate, publishID, h.nodeID, iface, direction, confirmTimeout),
		LastUpdatedAt:    time.Now().UTC(),
	}
	runtime = withDirectionState(runtime, direction, nextDirectionRuntime)
	if direction == models.DirectionIngress {
		runtime.BypassCIDRs = append([]string(nil), nextDirectionRuntime.BypassCIDRs...)
		runtime.BlockedCIDRs = append([]string(nil), nextDirectionRuntime.BlockedCIDRs...)
		runtime.ICMPAllowCIDRs = append([]string(nil), nextDirectionRuntime.ICMPAllowCIDRs...)
		runtime.ICMPBlockedCIDRs = append([]string(nil), nextDirectionRuntime.ICMPBlockedCIDRs...)
		runtime.Allowlist = append([]string(nil), nextDirectionRuntime.Allowlist...)
		runtime.PublicPorts = append([]uint16(nil), nextDirectionRuntime.PublicPorts...)
		runtime.DeniedPorts = append([]uint16(nil), nextDirectionRuntime.DeniedPorts...)
		runtime.AllowedPorts = append([]uint16(nil), nextDirectionRuntime.AllowedPorts...)
		runtime.PublicPortRules = append([]models.PortRule(nil), nextDirectionRuntime.PublicPortRules...)
		runtime.DeniedPortRules = append([]models.PortRule(nil), nextDirectionRuntime.DeniedPortRules...)
		runtime.AllowedPortRules = append([]models.PortRule(nil), nextDirectionRuntime.AllowedPortRules...)
		runtime.NonIPv4Action = nextDirectionRuntime.NonIPv4Action
		runtime.ObserveOnly = nextDirectionRuntime.ObserveOnly
		runtime.Challenge = nextDirectionRuntime.Challenge
		runtime.Attached = nextDirectionRuntime.Attached
		runtime.PendingPublish = nextDirectionRuntime.PendingPublish
		runtime.LastUpdatedAt = nextDirectionRuntime.LastUpdatedAt
	}
	if direction == models.DirectionEgress && runtime.Attached {
		cfg, err := h.xdp.ReadConfig(iface)
		if err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		cfg.EgressPolicyEnforced = directionPolicyEnforced(nextDirectionRuntime)
		if err := h.xdp.WriteConfig(iface, cfg); err != nil {
			_ = h.restoreSnapshot(r.Context(), snapshot)
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	h.setRuntime(iface, runtime)
	if !req.Immediate {
		h.rollback.BeginWithTimeout(r.Context(), publishID, snapshot, confirmTimeout)
	}
	if err := h.persist(r.Context()); err != nil {
		_ = h.restoreSnapshot(context.WithoutCancel(r.Context()), snapshot)
		writeError(w, http.StatusInternalServerError, fmt.Errorf("persist policy update: %w", err))
		return
	}
	applyCompleted = true

	writeJSON(w, http.StatusOK, map[string]any{
		"publish_id": publishID,
		"direction":  direction,
		"status":     applyStatus(req.Immediate),
		"expires_in": applyExpiresIn(req.Immediate, confirmTimeout),
		"runtime":    runtime,
	})
}

func publishRecordForApply(immediate bool, publishID, nodeID, iface string, direction models.PolicyDirection, timeout time.Duration) *models.PublishRecord {
	if immediate {
		return nil
	}
	return &models.PublishRecord{
		PublishID: publishID,
		NodeID:    nodeID,
		Interface: iface,
		Direction: direction,
		Status:    models.PublishPendingConfirm,
		ExpiresIn: int(timeout / time.Second),
		CreatedAt: time.Now().UTC(),
	}
}

func applyStatus(immediate bool) models.PublishStatus {
	if immediate {
		return models.PublishConfirmed
	}
	return models.PublishPendingConfirm
}

func applyExpiresIn(immediate bool, timeout time.Duration) int {
	if immediate {
		return 0
	}
	return int(timeout / time.Second)
}

func (h *AgentHandler) handleConfirm(w http.ResponseWriter, r *http.Request) {
	h.policyMu.Lock()
	defer h.policyMu.Unlock()
	var req struct {
		PublishID string                 `json:"publish_id"`
		Direction models.PolicyDirection `json:"direction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	session, pending := h.rollback.Pending(req.PublishID)
	if !pending || session.Snapshot.Interface != r.PathValue("iface") || (req.Direction != "" && session.Snapshot.Direction != req.Direction) || !h.rollback.Confirm(req.PublishID) {
		writeError(w, http.StatusNotFound, rollback.ErrPendingNotFound)
		return
	}

	iface := r.PathValue("iface")
	runtime := h.ensureRuntime(iface)
	direction := req.Direction
	if direction == "" {
		direction = session.Snapshot.Direction
	}
	if direction == "" {
		if runtime.PendingPublish != nil && runtime.PendingPublish.PublishID == req.PublishID {
			direction = models.DirectionIngress
		} else {
			direction = models.DirectionEgress
		}
	}
	if direction == models.DirectionIngress && runtime.PendingPublish != nil && runtime.PendingPublish.PublishID == req.PublishID {
		runtime.PendingPublish.Status = models.PublishConfirmed
		runtime.PendingPublish = nil
		runtime.LastUpdatedAt = time.Now().UTC()
	} else if direction == models.DirectionEgress && runtime.Egress.PendingPublish != nil && runtime.Egress.PendingPublish.PublishID == req.PublishID {
		runtime.Egress.PendingPublish.Status = models.PublishConfirmed
		runtime.Egress.PendingPublish = nil
		runtime.Egress.LastUpdatedAt = time.Now().UTC()
	}
	runtime.Recovery = maps.Clone(runtime.Recovery)
	delete(runtime.Recovery, direction)
	h.setRuntime(iface, runtime)
	if err := h.persist(r.Context()); err != nil {
		_ = h.restoreSnapshot(context.WithoutCancel(r.Context()), session.Snapshot)
		writeError(w, http.StatusInternalServerError, fmt.Errorf("persist policy confirmation: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

func (h *AgentHandler) handleRollback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublishID string                 `json:"publish_id"`
		Direction models.PolicyDirection `json:"direction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	session, pending := h.rollback.Pending(req.PublishID)
	if !pending || session.Snapshot.Interface != r.PathValue("iface") || (req.Direction != "" && req.Direction != session.Snapshot.Direction) {
		writeError(w, http.StatusNotFound, rollback.ErrPendingNotFound)
		return
	}
	if err := h.rollback.RollbackNow(r.Context(), req.PublishID); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
}

func (h *AgentHandler) restoreSnapshot(ctx context.Context, snapshot rollback.Snapshot) error {
	runtime := h.ensureRuntime(snapshot.Interface)
	runtime.Recovery = maps.Clone(runtime.Recovery)
	delete(runtime.Recovery, snapshot.Direction)
	if snapshot.Direction == models.DirectionIngress {
		if snapshot.Attached {
			mode := xdp.ParseAttachMode(snapshot.AttachMode)
			if err := h.xdp.Attach(snapshot.Interface, mode); err != nil {
				return err
			}
		} else {
			_ = h.xdp.Detach(snapshot.Interface)
		}

		if snapshot.Attached {
			if err := h.xdp.ReplaceBypassCIDRs(snapshot.Interface, snapshot.BypassCIDRs); err != nil {
				return err
			}
			if err := h.xdp.ReplaceBlockedCIDRs(snapshot.Interface, snapshot.BlockedCIDRs); err != nil {
				return err
			}
			if err := h.xdp.ReplaceICMPAllowCIDRs(snapshot.Interface, snapshot.ICMPAllowCIDRs); err != nil {
				return err
			}
			if err := h.xdp.ReplaceICMPBlockedCIDRs(snapshot.Interface, snapshot.ICMPBlockedCIDRs); err != nil {
				return err
			}
			if err := h.xdp.ReplaceAllowlist(snapshot.Interface, snapshot.Allowlist); err != nil {
				return err
			}
			if err := h.xdp.ReplacePublicPortRules(snapshot.Interface, models.NormalizePortRules(snapshot.PublicPortRules, snapshot.PublicPorts)); err != nil {
				return err
			}
			if err := h.xdp.ReplaceDeniedPortRules(snapshot.Interface, models.NormalizePortRules(snapshot.DeniedPortRules, snapshot.DeniedPorts)); err != nil {
				return err
			}
			if err := h.xdp.ReplacePortRules(snapshot.Interface, models.NormalizePortRules(snapshot.AllowedPortRules, snapshot.AllowedPorts)); err != nil {
				return err
			}
			if err := h.xdp.ReplaceRateLimitRules(snapshot.Interface, snapshot.RateLimitRules); err != nil {
				return err
			}
			if err := h.xdp.WriteConfig(snapshot.Interface, xdp.Config{
				NonIPv4Action:           defaultAction(snapshot.NonIPv4Action),
				PortPolicyEnabled:       len(snapshot.AllowedPorts) > 0,
				RateLimitEnabled:        len(snapshot.RateLimitRules) > 0,
				PolicyEnforced:          policyEnforcedFor(snapshot.BypassCIDRs, snapshot.BlockedCIDRs, snapshot.ICMPAllowCIDRs, snapshot.ICMPBlockedCIDRs, snapshot.Allowlist, snapshot.PublicPorts, snapshot.DeniedPorts, snapshot.AllowedPorts) || len(snapshot.TemporaryBlocks) > 0,
				EgressPolicyEnforced:    directionPolicyEnforced(runtime.Egress),
				ObserveOnly:             snapshot.ObserveOnly,
				ReplyFlowTimeoutSeconds: h.replyFlowTimeoutSeconds(),
			}); err != nil {
				return err
			}
			for _, item := range snapshot.TemporaryBlocks {
				if err := h.applyTemporaryBlock(snapshot.Interface, item); err != nil {
					return err
				}
			}
		}

		runtime.Attached = snapshot.Attached
		runtime.AttachMode = snapshot.AttachMode
		if snapshot.Attached {
			if dataplaneRuntime, err := h.xdp.Runtime(snapshot.Interface); err == nil && dataplaneRuntime.Mode != "" {
				runtime.AttachMode = string(dataplaneRuntime.Mode)
			}
		}
		runtime.BypassCIDRs = append([]string(nil), snapshot.BypassCIDRs...)
		runtime.BlockedCIDRs = append([]string(nil), snapshot.BlockedCIDRs...)
		runtime.ICMPAllowCIDRs = append([]string(nil), snapshot.ICMPAllowCIDRs...)
		runtime.ICMPBlockedCIDRs = append([]string(nil), snapshot.ICMPBlockedCIDRs...)
		runtime.Allowlist = append([]string(nil), snapshot.Allowlist...)
		runtime.PublicPorts = append([]uint16(nil), snapshot.PublicPorts...)
		runtime.DeniedPorts = append([]uint16(nil), snapshot.DeniedPorts...)
		runtime.AllowedPorts = append([]uint16(nil), snapshot.AllowedPorts...)
		runtime.PublicPortRules = models.NormalizePortRules(snapshot.PublicPortRules, snapshot.PublicPorts)
		runtime.DeniedPortRules = models.NormalizePortRules(snapshot.DeniedPortRules, snapshot.DeniedPorts)
		runtime.AllowedPortRules = models.NormalizePortRules(snapshot.AllowedPortRules, snapshot.AllowedPorts)
		runtime.NonIPv4Action = defaultAction(snapshot.NonIPv4Action)
		runtime.EnforcementConfirmed = !snapshot.ObserveOnly
		runtime.ObserveOnly = snapshot.ObserveOnly
		runtime.Challenge = snapshot.Challenge
		runtime.RateLimits = append([]models.RateLimitRule(nil), snapshot.RateLimitRules...)
		runtime.TemporaryBlocks = append([]models.TemporaryBlock(nil), snapshot.TemporaryBlocks...)
		runtime.PendingPublish = nil
		runtime.LastUpdatedAt = time.Now().UTC()
	} else {
		if directional, ok := h.xdp.(xdp.DirectionalDataplane); ok {
			if err := directional.ApplyDirectionPolicy(snapshot.Interface, models.DirectionEgress, directionPolicyFromSnapshot(snapshot)); err != nil {
				return err
			}
		}
		runtime.Egress = models.DirectionRuntime{
			Attached:         snapshot.Attached,
			AttachMode:       snapshot.AttachMode,
			BypassCIDRs:      append([]string(nil), snapshot.BypassCIDRs...),
			BlockedCIDRs:     append([]string(nil), snapshot.BlockedCIDRs...),
			ICMPAllowCIDRs:   append([]string(nil), snapshot.ICMPAllowCIDRs...),
			ICMPBlockedCIDRs: append([]string(nil), snapshot.ICMPBlockedCIDRs...),
			Allowlist:        append([]string(nil), snapshot.Allowlist...),
			PublicPorts:      append([]uint16(nil), snapshot.PublicPorts...),
			DeniedPorts:      append([]uint16(nil), snapshot.DeniedPorts...),
			AllowedPorts:     append([]uint16(nil), snapshot.AllowedPorts...),
			PublicPortRules:  models.NormalizePortRules(snapshot.PublicPortRules, snapshot.PublicPorts),
			DeniedPortRules:  models.NormalizePortRules(snapshot.DeniedPortRules, snapshot.DeniedPorts),
			AllowedPortRules: models.NormalizePortRules(snapshot.AllowedPortRules, snapshot.AllowedPorts),
			NonIPv4Action:    defaultAction(snapshot.NonIPv4Action),
			Challenge:        snapshot.Challenge,
			RateLimits:       append([]models.RateLimitRule(nil), snapshot.RateLimitRules...),
			TemporaryBlocks:  append([]models.TemporaryBlock(nil), snapshot.TemporaryBlocks...),
			ObserveOnly:      snapshot.ObserveOnly,
			PendingPublish:   nil,
			LastUpdatedAt:    time.Now().UTC(),
		}
	}
	h.setRuntime(snapshot.Interface, runtime)
	return h.persist(ctx)
}

func (h *AgentHandler) ensureRuntime(iface string) models.InterfaceRuntime {
	h.runtimeMu.RLock()
	runtime, ok := h.runtimes[iface]
	h.runtimeMu.RUnlock()
	if ok {
		return runtime
	}

	return newInterfaceRuntime(iface)
}

func newInterfaceRuntime(iface string) models.InterfaceRuntime {
	return models.InterfaceRuntime{
		Interface:            iface,
		BypassCIDRs:          nil,
		BlockedCIDRs:         nil,
		ICMPAllowCIDRs:       nil,
		ICMPBlockedCIDRs:     nil,
		Allowlist:            nil,
		PublicPorts:          nil,
		DeniedPorts:          nil,
		AllowedPorts:         nil,
		PublicPortRules:      nil,
		DeniedPortRules:      nil,
		AllowedPortRules:     nil,
		NonIPv4Action:        models.NonIPv4Drop,
		ObserveOnly:          true,
		EnforcementConfirmed: false,
		Challenge:            models.ChallengeSpec{Enabled: true, Provider: "reverse-proxy", ProtectedPorts: []uint16{80, 443}, RequestThreshold: 500},
		RateLimits:           nil,
		TemporaryBlocks:      nil,
		Egress: models.DirectionRuntime{
			Attached:        false,
			AttachMode:      "",
			NonIPv4Action:   models.NonIPv4Drop,
			Challenge:       models.ChallengeSpec{Enabled: true, Provider: "reverse-proxy", ProtectedPorts: []uint16{80, 443}, RequestThreshold: 500},
			RateLimits:      nil,
			TemporaryBlocks: nil,
			ObserveOnly:     true,
		},
	}
}

func (h *AgentHandler) setRuntime(iface string, runtime models.InterfaceRuntime) {
	h.runtimeMu.Lock()
	h.runtimes[iface] = runtime
	h.runtimeMu.Unlock()
}

func (h *AgentHandler) runtimeSnapshotAll() map[string]models.InterfaceRuntime {
	h.runtimeMu.RLock()
	defer h.runtimeMu.RUnlock()
	runtimes := make(map[string]models.InterfaceRuntime, len(h.runtimes))
	for iface, runtime := range h.runtimes {
		runtimes[iface] = runtime
	}
	return runtimes
}

func (h *AgentHandler) runtimeKeys() []string {
	h.runtimeMu.RLock()
	defer h.runtimeMu.RUnlock()
	if len(h.runtimes) == 0 {
		return nil
	}
	keys := make([]string, 0, len(h.runtimes))
	for iface := range h.runtimes {
		keys = append(keys, iface)
	}
	return keys
}

func (h *AgentHandler) clearRuntimes() {
	h.runtimeMu.Lock()
	h.runtimes = make(map[string]models.InterfaceRuntime)
	h.runtimeMu.Unlock()
}

func (h *AgentHandler) persist(ctx context.Context) error {
	if h.state == nil {
		return nil
	}
	return h.state.Save(ctx, h.runtimeSnapshotAll())
}

// syncPolicyConfig keeps the enforcement gate in config_map consistent with
// the rule maps. The XDP program intentionally short-circuits to XDP_PASS
// while this gate is disabled, so updating only an allowlist/blocklist map is
// not sufficient to activate a policy.
func (h *AgentHandler) syncPolicyConfig(iface string, runtime models.InterfaceRuntime) error {
	cfg, err := h.xdp.ReadConfig(iface)
	if err != nil {
		return fmt.Errorf("read policy config for %s: %w", iface, err)
	}

	cfg.NonIPv4Action = defaultAction(runtime.NonIPv4Action)
	cfg.PortPolicyEnabled = len(runtime.AllowedPortRules) > 0 || len(runtime.AllowedPorts) > 0
	cfg.RateLimitEnabled = len(runtime.RateLimits) > 0
	cfg.ObserveOnly = runtime.ObserveOnly
	cfg.PolicyEnforced = policyEnforcedFor(
		runtime.BypassCIDRs,
		runtime.BlockedCIDRs,
		runtime.ICMPAllowCIDRs,
		runtime.ICMPBlockedCIDRs,
		runtime.Allowlist,
		runtime.PublicPorts,
		runtime.DeniedPorts,
		runtime.AllowedPorts,
	) || len(runtime.TemporaryBlocks) > 0
	cfg.EgressPolicyEnforced = directionPolicyEnforced(runtime.Egress)
	cfg.ReplyFlowTimeoutSeconds = h.replyFlowTimeoutSeconds()

	if err := h.xdp.WriteConfig(iface, cfg); err != nil {
		return fmt.Errorf("write policy config for %s: %w", iface, err)
	}
	return nil
}

func (h *AgentHandler) reconcileState(ctx context.Context) error {
	for iface, runtime := range h.runtimeSnapshotAll() {
		if err := h.pruneExpiredDispositions(ctx, iface); err != nil {
			return err
		}
		runtime = h.ensureRuntime(iface)
		if !runtime.Attached {
			continue
		}

		mode := xdp.ParseAttachMode(runtime.AttachMode)
		if err := h.xdp.Attach(iface, mode); err != nil {
			return err
		}
		if dataplaneRuntime, err := h.xdp.Runtime(iface); err == nil && dataplaneRuntime.Mode != "" {
			runtime.AttachMode = string(dataplaneRuntime.Mode)
			h.setRuntime(iface, runtime)
		}
		if err := h.xdp.ReplaceAllowlist(iface, runtime.Allowlist); err != nil {
			return err
		}
		if err := h.xdp.ReplaceBypassCIDRs(iface, runtime.BypassCIDRs); err != nil {
			return err
		}
		if err := h.xdp.ReplaceBlockedCIDRs(iface, runtime.BlockedCIDRs); err != nil {
			return err
		}
		if err := h.xdp.ReplaceICMPAllowCIDRs(iface, runtime.ICMPAllowCIDRs); err != nil {
			return err
		}
		if err := h.xdp.ReplaceICMPBlockedCIDRs(iface, runtime.ICMPBlockedCIDRs); err != nil {
			return err
		}
		if err := h.xdp.ReplacePublicPortRules(iface, models.NormalizePortRules(runtime.PublicPortRules, runtime.PublicPorts)); err != nil {
			return err
		}
		if err := h.xdp.ReplaceDeniedPortRules(iface, models.NormalizePortRules(runtime.DeniedPortRules, runtime.DeniedPorts)); err != nil {
			return err
		}
		if err := h.xdp.ReplacePortRules(iface, models.NormalizePortRules(runtime.AllowedPortRules, runtime.AllowedPorts)); err != nil {
			return err
		}
		if err := h.xdp.ReplaceRateLimitRules(iface, runtime.RateLimits); err != nil {
			return err
		}
		if err := h.syncPolicyConfig(iface, runtime); err != nil {
			return err
		}
		if runtime.Egress.Attached {
			if directional, ok := h.xdp.(xdp.DirectionalDataplane); ok {
				if err := directional.ApplyDirectionPolicy(iface, models.DirectionEgress, directionPolicyFromRuntime(runtime.Egress)); err != nil {
					return err
				}
			}
		}
		for _, item := range runtime.TemporaryBlocks {
			if err := h.applyTemporaryBlock(iface, item); err != nil {
				return err
			}
		}
	}

	return h.persist(ctx)
}

func directionStateFor(runtime models.InterfaceRuntime, direction models.PolicyDirection) models.DirectionRuntime {
	if direction == models.DirectionEgress {
		return runtime.Egress
	}
	return models.DirectionRuntime{
		Attached:         runtime.Attached,
		AttachMode:       runtime.AttachMode,
		BypassCIDRs:      append([]string(nil), runtime.BypassCIDRs...),
		BlockedCIDRs:     append([]string(nil), runtime.BlockedCIDRs...),
		ICMPAllowCIDRs:   append([]string(nil), runtime.ICMPAllowCIDRs...),
		ICMPBlockedCIDRs: append([]string(nil), runtime.ICMPBlockedCIDRs...),
		Allowlist:        append([]string(nil), runtime.Allowlist...),
		PublicPorts:      append([]uint16(nil), runtime.PublicPorts...),
		DeniedPorts:      append([]uint16(nil), runtime.DeniedPorts...),
		AllowedPorts:     append([]uint16(nil), runtime.AllowedPorts...),
		PublicPortRules:  models.NormalizePortRules(runtime.PublicPortRules, runtime.PublicPorts),
		DeniedPortRules:  models.NormalizePortRules(runtime.DeniedPortRules, runtime.DeniedPorts),
		AllowedPortRules: models.NormalizePortRules(runtime.AllowedPortRules, runtime.AllowedPorts),
		NonIPv4Action:    runtime.NonIPv4Action,
		ObserveOnly:      runtime.ObserveOnly,
		Challenge:        runtime.Challenge,
		RateLimits:       append([]models.RateLimitRule(nil), runtime.RateLimits...),
		TemporaryBlocks:  append([]models.TemporaryBlock(nil), runtime.TemporaryBlocks...),
		PendingPublish:   runtime.PendingPublish,
		LastUpdatedAt:    runtime.LastUpdatedAt,
		LastStats:        runtime.LastStats,
		Trend:            append([]models.TrafficPoint(nil), runtime.Trend...),
	}
}

func withDirectionState(runtime models.InterfaceRuntime, direction models.PolicyDirection, next models.DirectionRuntime) models.InterfaceRuntime {
	if direction == models.DirectionEgress {
		runtime.Egress = next
		return runtime
	}
	runtime.Attached = next.Attached
	runtime.AttachMode = next.AttachMode
	runtime.BypassCIDRs = append([]string(nil), next.BypassCIDRs...)
	runtime.BlockedCIDRs = append([]string(nil), next.BlockedCIDRs...)
	runtime.ICMPAllowCIDRs = append([]string(nil), next.ICMPAllowCIDRs...)
	runtime.ICMPBlockedCIDRs = append([]string(nil), next.ICMPBlockedCIDRs...)
	runtime.Allowlist = append([]string(nil), next.Allowlist...)
	runtime.PublicPorts = append([]uint16(nil), next.PublicPorts...)
	runtime.DeniedPorts = append([]uint16(nil), next.DeniedPorts...)
	runtime.AllowedPorts = append([]uint16(nil), next.AllowedPorts...)
	runtime.PublicPortRules = models.NormalizePortRules(next.PublicPortRules, next.PublicPorts)
	runtime.DeniedPortRules = models.NormalizePortRules(next.DeniedPortRules, next.DeniedPorts)
	runtime.AllowedPortRules = models.NormalizePortRules(next.AllowedPortRules, next.AllowedPorts)
	runtime.NonIPv4Action = next.NonIPv4Action
	runtime.EnforcementConfirmed = !next.ObserveOnly
	runtime.ObserveOnly = next.ObserveOnly
	runtime.Challenge = next.Challenge
	runtime.RateLimits = append([]models.RateLimitRule(nil), next.RateLimits...)
	runtime.TemporaryBlocks = append([]models.TemporaryBlock(nil), next.TemporaryBlocks...)
	runtime.PendingPublish = next.PendingPublish
	runtime.LastUpdatedAt = next.LastUpdatedAt
	runtime.LastStats = next.LastStats
	runtime.Trend = append([]models.TrafficPoint(nil), next.Trend...)
	return runtime
}

func (h *AgentHandler) buildInsights(iface string, limit int) (models.InterfaceInsights, error) {
	_ = h.pruneExpiredDispositions(context.Background(), iface)
	items, err := h.xdp.ReadSourceStats(iface, limit)
	if err != nil {
		return models.InterfaceInsights{}, err
	}
	stats, err := h.xdp.ReadStats(iface)
	if err == nil {
		h.recordTrend(iface, stats)
	}
	portStats, _ := h.xdp.ReadPortStats(iface, limit)
	h.enrichSourceStats(items)

	topDropped := slices.Clone(items)
	slices.SortFunc(topDropped, func(a, b models.SourceStat) int {
		switch {
		case a.Dropped > b.Dropped:
			return -1
		case a.Dropped < b.Dropped:
			return 1
		default:
			return 0
		}
	})

	topPassed := slices.Clone(items)
	slices.SortFunc(topPassed, func(a, b models.SourceStat) int {
		switch {
		case a.Passed > b.Passed:
			return -1
		case a.Passed < b.Passed:
			return 1
		default:
			return 0
		}
	})

	attackers := make([]models.SourceStat, 0, len(items))
	for _, item := range topDropped {
		if item.Dropped > 0 {
			attackers = append(attackers, item)
		}
	}
	if limit > 0 {
		if len(topDropped) > limit {
			topDropped = topDropped[:limit]
		}
		if len(topPassed) > limit {
			topPassed = topPassed[:limit]
		}
		if len(attackers) > limit {
			attackers = attackers[:limit]
		}
	}

	return models.InterfaceInsights{
		Interface:       iface,
		TopPassed:       topPassed,
		TopDropped:      topDropped,
		TopAttackers:    attackers,
		TopCountries:    summarizeCountries(items, limit),
		TopPorts:        portStats,
		Trend:           append([]models.TrafficPoint(nil), h.ensureRuntime(iface).Trend...),
		SuggestedBlocks: buildBlockSuggestions(attackers, h.ensureRuntime(iface).Allowlist),
		ChallengeAdvice: buildChallengeAdvice(h.ensureRuntime(iface), portStats),
		UpdatedAt:       time.Now().UTC(),
	}, nil
}

func (h *AgentHandler) buildDirectionInsights(iface string, direction models.PolicyDirection, limit int) (models.InterfaceInsights, error) {
	if direction != models.DirectionEgress {
		return h.buildInsights(iface, limit)
	}
	_ = h.pruneExpiredDispositions(context.Background(), iface)
	directional, ok := h.xdp.(xdp.DirectionalStats)
	if !ok {
		return models.InterfaceInsights{}, fmt.Errorf("dataplane does not expose egress statistics")
	}
	items, err := directional.ReadDirectionSourceStats(iface, direction, limit)
	if err != nil {
		return models.InterfaceInsights{}, err
	}
	if stats, err := directional.ReadDirectionStats(iface, direction); err == nil {
		stats.Direction = direction
		h.recordDirectionTrend(iface, direction, stats)
	}
	portStats, _ := directional.ReadDirectionPortStats(iface, direction, limit)
	h.enrichSourceStats(items)

	topDropped := slices.Clone(items)
	slices.SortFunc(topDropped, func(a, b models.SourceStat) int {
		switch {
		case a.Dropped > b.Dropped:
			return -1
		case a.Dropped < b.Dropped:
			return 1
		default:
			return 0
		}
	})
	topPassed := slices.Clone(items)
	slices.SortFunc(topPassed, func(a, b models.SourceStat) int {
		switch {
		case a.Passed > b.Passed:
			return -1
		case a.Passed < b.Passed:
			return 1
		default:
			return 0
		}
	})
	attackers := make([]models.SourceStat, 0, len(items))
	for _, item := range topDropped {
		if item.Dropped > 0 {
			attackers = append(attackers, item)
		}
	}
	if limit > 0 {
		if len(topDropped) > limit {
			topDropped = topDropped[:limit]
		}
		if len(topPassed) > limit {
			topPassed = topPassed[:limit]
		}
		if len(attackers) > limit {
			attackers = attackers[:limit]
		}
	}

	runtime := h.ensureRuntime(iface).Egress
	return models.InterfaceInsights{
		Direction:       direction,
		Interface:       iface,
		TopPassed:       topPassed,
		TopDropped:      topDropped,
		TopAttackers:    attackers,
		TopCountries:    summarizeCountries(items, limit),
		TopPorts:        portStats,
		Trend:           append([]models.TrafficPoint(nil), runtime.Trend...),
		SuggestedBlocks: buildBlockSuggestions(attackers, runtime.Allowlist),
		UpdatedAt:       time.Now().UTC(),
	}, nil
}

func emptyDirectionInsights(iface string, direction models.PolicyDirection, trend []models.TrafficPoint) models.InterfaceInsights {
	return models.InterfaceInsights{
		Direction:       direction,
		Interface:       iface,
		Trend:           append([]models.TrafficPoint(nil), trend...),
		TopPassed:       []models.SourceStat{},
		TopDropped:      []models.SourceStat{},
		TopAttackers:    []models.SourceStat{},
		TopCountries:    []models.CountryStat{},
		TopPorts:        []models.PortStat{},
		SuggestedBlocks: []models.BlockSuggestion{},
		UpdatedAt:       time.Now().UTC(),
	}
}

func (h *AgentHandler) recordTrend(iface string, stats models.InterfaceStats) {
	h.recordDirectionTrend(iface, models.DirectionIngress, stats)
}

func (h *AgentHandler) recordDirectionTrend(iface string, direction models.PolicyDirection, stats models.InterfaceStats) {
	// Stats polling is concurrent with policy and health requests. Keep the
	// read-modify-write under one lock so a trend update cannot race with a
	// policy update or another stats request for the same interface.
	h.runtimeMu.Lock()
	runtime, ok := h.runtimes[iface]
	if !ok {
		runtime = newInterfaceRuntime(iface)
	}
	point := models.TrafficPoint{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Passed:    stats.Passed,
		Dropped:   stats.Dropped,
	}

	directionRuntime := directionStateFor(runtime, direction)
	trend := append([]models.TrafficPoint(nil), directionRuntime.Trend...)
	if len(trend) > 0 {
		last := trend[len(trend)-1]
		if last.Passed == point.Passed && last.Dropped == point.Dropped {
			directionRuntime.LastStats = &stats
			runtime = withDirectionState(runtime, direction, directionRuntime)
			h.runtimes[iface] = runtime
			h.runtimeMu.Unlock()
			return
		}
	}

	trend = append(trend, point)
	if len(trend) > 24 {
		trend = trend[len(trend)-24:]
	}
	directionRuntime.Trend = trend
	directionRuntime.LastStats = &stats
	directionRuntime.LastUpdatedAt = time.Now().UTC()
	runtime = withDirectionState(runtime, direction, directionRuntime)
	h.runtimes[iface] = runtime
	h.runtimeMu.Unlock()
	_ = h.persist(context.Background())
}

func (h *AgentHandler) enrichSourceStats(items []models.SourceStat) {
	for i := range items {
		geo, ok := h.lookupGeo(items[i].SourceIP)
		if !ok {
			continue
		}
		items[i].Geo = &geo
		items[i].CountryCode = geo.CountryCode
		items[i].CountryName = geo.CountryName
	}
}

func (h *AgentHandler) lookupGeo(sourceIP string) (models.GeoLocation, bool) {
	if h.geoipDB == nil {
		return models.GeoLocation{}, false
	}
	addr, err := netip.ParseAddr(sourceIP)
	if err != nil {
		return models.GeoLocation{}, false
	}
	return h.geoipDB.Lookup(addr)
}

func summarizeCountries(items []models.SourceStat, limit int) []models.CountryStat {
	type aggregate struct {
		name    string
		total   uint64
		dropped uint64
		sources uint64
	}
	byCountry := make(map[string]*aggregate)
	for _, item := range items {
		code := strings.TrimSpace(item.CountryCode)
		name := strings.TrimSpace(item.CountryName)
		if code == "" && item.Geo != nil {
			code = strings.TrimSpace(item.Geo.CountryCode)
			name = strings.TrimSpace(item.Geo.CountryName)
		}
		if code == "" {
			code = "ZZ"
		}
		if name == "" {
			name = "Unknown"
		}
		if _, ok := byCountry[code]; !ok {
			byCountry[code] = &aggregate{name: name}
		}
		byCountry[code].total += item.Total
		byCountry[code].dropped += item.Dropped
		byCountry[code].sources++
	}

	out := make([]models.CountryStat, 0, len(byCountry))
	for code, item := range byCountry {
		out = append(out, models.CountryStat{
			CountryCode: code,
			CountryName: item.name,
			Total:       item.total,
			Dropped:     item.dropped,
			Sources:     item.sources,
		})
	}
	slices.SortFunc(out, func(a, b models.CountryStat) int {
		switch {
		case a.Dropped > b.Dropped:
			return -1
		case a.Dropped < b.Dropped:
			return 1
		case a.Total > b.Total:
			return -1
		case a.Total < b.Total:
			return 1
		default:
			return 0
		}
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func buildBlockSuggestions(items []models.SourceStat, allowlist []string) []models.BlockSuggestion {
	suggestions := make([]models.BlockSuggestion, 0, len(items))
	allowed := make(map[string]struct{}, len(allowlist))
	for _, cidr := range allowlist {
		allowed[cidr] = struct{}{}
	}

	for _, item := range items {
		if item.Dropped == 0 {
			continue
		}
		if item.Risk != "high" && item.Dropped < 20 {
			continue
		}

		addr, err := netip.ParseAddr(item.SourceIP)
		if err != nil || !addr.Is4() {
			continue
		}

		suggested := netip.PrefixFrom(addr, 32).String()
		if _, ok := allowed[suggested]; ok {
			continue
		}

		reason := fmt.Sprintf("drop_ratio=%.2f dropped=%d", item.DropRatio, item.Dropped)
		suggestions = append(suggestions, models.BlockSuggestion{
			SourceIP:      item.SourceIP,
			SuggestedCIDR: suggested,
			Risk:          item.Risk,
			Reason:        reason,
		})
	}

	if len(suggestions) > 5 {
		suggestions = suggestions[:5]
	}
	return suggestions
}

func buildChallengeAdvice(runtime models.InterfaceRuntime, ports []models.PortStat) models.ChallengeAdvice {
	challenge := normalizeChallenge(runtime.Challenge)
	if !challenge.Enabled {
		return models.ChallengeAdvice{}
	}

	protected := make(map[uint16]struct{}, len(challenge.ProtectedPorts))
	for _, port := range challenge.ProtectedPorts {
		protected[port] = struct{}{}
	}

	var hottest *models.PortStat
	for i := range ports {
		if _, ok := protected[ports[i].Port]; !ok {
			continue
		}
		if hottest == nil || ports[i].Total > hottest.Total {
			hottest = &ports[i]
		}
	}
	if hottest == nil {
		return models.ChallengeAdvice{
			Recommended: false,
			Ports:       challenge.ProtectedPorts,
			Provider:    challenge.Provider,
			Reason:      "no protected port pressure detected",
		}
	}

	recommended := hottest.Total >= challenge.RequestThreshold || hottest.Risk == "high"
	return models.ChallengeAdvice{
		Recommended: recommended,
		Ports:       challenge.ProtectedPorts,
		Provider:    challenge.Provider,
		Reason:      fmt.Sprintf("port=%d total=%d risk=%s threshold=%d", hottest.Port, hottest.Total, hottest.Risk, challenge.RequestThreshold),
	}
}

func requestPolicyDirection(r *http.Request) models.PolicyDirection {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("direction"))) {
	case string(models.DirectionEgress):
		return models.DirectionEgress
	default:
		return models.DirectionIngress
	}
}

func appendCIDR(allowlist []string, cidr string) []string {
	if slices.Contains(allowlist, cidr) {
		return allowlist
	}
	next := append([]string(nil), allowlist...)
	next = append(next, cidr)
	slices.Sort(next)
	return next
}

func appendPort(ports []uint16, port uint16) []uint16 {
	return normalizePortList(append(append([]uint16(nil), ports...), port))
}

func appendPortRule(rules []models.PortRule, rule models.PortRule) []models.PortRule {
	return models.NormalizePortRules(append(append([]models.PortRule(nil), rules...), rule), nil)
}

func removePortRule(rules []models.PortRule, rule models.PortRule) []models.PortRule {
	target := models.NormalizePortRules([]models.PortRule{rule}, nil)
	if len(target) == 0 {
		return models.NormalizePortRules(rules, nil)
	}
	next := make([]models.PortRule, 0, len(rules))
	for _, item := range rules {
		if item.Protocol == target[0].Protocol && item.Port == target[0].Port {
			continue
		}
		next = append(next, item)
	}
	return models.NormalizePortRules(next, nil)
}

func removePortRulesByPort(rules []models.PortRule, port uint16) []models.PortRule {
	next := make([]models.PortRule, 0, len(rules))
	for _, item := range rules {
		if item.Port != port {
			next = append(next, item)
		}
	}
	return models.NormalizePortRules(next, nil)
}

func removePort(ports []uint16, port uint16) []uint16 {
	next := make([]uint16, 0, len(ports))
	for _, item := range ports {
		if item != port {
			next = append(next, item)
		}
	}
	return normalizePortList(next)
}

func parsePort(value string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return uint16(port), nil
}

func parseOptionalPortProtocol(value string) (models.PortProtocol, bool) {
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

func normalizeChallenge(challenge models.ChallengeSpec) models.ChallengeSpec {
	challenge.Provider = strings.TrimSpace(challenge.Provider)
	if challenge.Provider == "" {
		challenge.Provider = "reverse-proxy"
	}
	challenge.ProtectedPorts = normalizePortList(challenge.ProtectedPorts)
	if len(challenge.ProtectedPorts) == 0 {
		challenge.ProtectedPorts = []uint16{80, 443}
	}
	if challenge.RequestThreshold == 0 {
		challenge.RequestThreshold = 500
	}
	return challenge
}

func normalizePortList(ports []uint16) []uint16 {
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
	slices.Sort(out)
	return out
}

func removeCIDR(allowlist []string, cidr string) []string {
	next := make([]string, 0, len(allowlist))
	for _, item := range allowlist {
		if item != cidr {
			next = append(next, item)
		}
	}
	return next
}

func isHealthyForInterface(status models.HealthStatus, iface string) bool {
	for _, item := range status.Interfaces {
		if item.Interface == iface {
			return item.XDPAttached && item.MapOK && item.StatsOK
		}
	}
	return false
}

func defaultAction(action models.NonIPv4Action) models.NonIPv4Action {
	if action == "" {
		return models.NonIPv4Drop
	}
	return action
}

func (h *AgentHandler) replyFlowTimeoutSeconds() int {
	if h.recorder == nil {
		return 60
	}
	settings := h.recorder.Settings()
	if settings.ReplyFlowTimeoutSeconds <= 0 {
		return 60
	}
	return settings.ReplyFlowTimeoutSeconds
}

func (h *AgentHandler) applyReplyFlowTimeout(ctx context.Context) error {
	for iface, runtime := range h.runtimeSnapshotAll() {
		if !runtime.Attached {
			continue
		}
		cfg, err := h.xdp.ReadConfig(iface)
		if err != nil {
			if xdp.IsNotAttached(err) {
				continue
			}
			return err
		}
		cfg.ReplyFlowTimeoutSeconds = h.replyFlowTimeoutSeconds()
		if err := h.xdp.WriteConfig(iface, cfg); err != nil {
			return err
		}
	}
	return h.persist(ctx)
}

func policyEnforcedFor(bypassCIDRs, blockedCIDRs, icmpAllowCIDRs, icmpBlockedCIDRs, allowlist []string, publicPorts, deniedPorts, allowedPorts []uint16) bool {
	return len(bypassCIDRs) > 0 ||
		len(blockedCIDRs) > 0 ||
		len(icmpAllowCIDRs) > 0 ||
		len(icmpBlockedCIDRs) > 0 ||
		len(allowlist) > 0 ||
		len(publicPorts) > 0 ||
		len(deniedPorts) > 0 ||
		len(allowedPorts) > 0
}

func directionPolicyEnforced(runtime models.DirectionRuntime) bool {
	return policyEnforcedFor(
		runtime.BypassCIDRs,
		runtime.BlockedCIDRs,
		runtime.ICMPAllowCIDRs,
		runtime.ICMPBlockedCIDRs,
		runtime.Allowlist,
		runtime.PublicPorts,
		runtime.DeniedPorts,
		runtime.AllowedPorts,
	)
}

func directionPolicyFromRuntime(runtime models.DirectionRuntime) xdp.DirectionPolicy {
	return xdp.DirectionPolicy{
		BypassCIDRs:      append([]string(nil), runtime.BypassCIDRs...),
		BlockedCIDRs:     append([]string(nil), runtime.BlockedCIDRs...),
		ICMPAllowCIDRs:   append([]string(nil), runtime.ICMPAllowCIDRs...),
		ICMPBlockedCIDRs: append([]string(nil), runtime.ICMPBlockedCIDRs...),
		Allowlist:        append([]string(nil), runtime.Allowlist...),
		PublicPortRules:  models.NormalizePortRules(runtime.PublicPortRules, runtime.PublicPorts),
		DeniedPortRules:  models.NormalizePortRules(runtime.DeniedPortRules, runtime.DeniedPorts),
		AllowedPortRules: models.NormalizePortRules(runtime.AllowedPortRules, runtime.AllowedPorts),
		RateLimitRules:   append([]models.RateLimitRule(nil), runtime.RateLimits...),
		TemporaryBlocks:  append([]models.TemporaryBlock(nil), runtime.TemporaryBlocks...),
		NonIPv4Action:    defaultAction(runtime.NonIPv4Action),
		PolicyEnforced:   directionPolicyEnforced(runtime) || len(runtime.TemporaryBlocks) > 0,
		ObserveOnly:      runtime.ObserveOnly,
	}
}

func directionPolicyFromSnapshot(snapshot rollback.Snapshot) xdp.DirectionPolicy {
	return xdp.DirectionPolicy{
		BypassCIDRs:      append([]string(nil), snapshot.BypassCIDRs...),
		BlockedCIDRs:     append([]string(nil), snapshot.BlockedCIDRs...),
		ICMPAllowCIDRs:   append([]string(nil), snapshot.ICMPAllowCIDRs...),
		ICMPBlockedCIDRs: append([]string(nil), snapshot.ICMPBlockedCIDRs...),
		Allowlist:        append([]string(nil), snapshot.Allowlist...),
		PublicPortRules:  models.NormalizePortRules(snapshot.PublicPortRules, snapshot.PublicPorts),
		DeniedPortRules:  models.NormalizePortRules(snapshot.DeniedPortRules, snapshot.DeniedPorts),
		AllowedPortRules: models.NormalizePortRules(snapshot.AllowedPortRules, snapshot.AllowedPorts),
		RateLimitRules:   append([]models.RateLimitRule(nil), snapshot.RateLimitRules...),
		TemporaryBlocks:  append([]models.TemporaryBlock(nil), snapshot.TemporaryBlocks...),
		NonIPv4Action:    defaultAction(snapshot.NonIPv4Action),
		PolicyEnforced:   policyEnforcedFor(snapshot.BypassCIDRs, snapshot.BlockedCIDRs, snapshot.ICMPAllowCIDRs, snapshot.ICMPBlockedCIDRs, snapshot.Allowlist, snapshot.PublicPorts, snapshot.DeniedPorts, snapshot.AllowedPorts),
		ObserveOnly:      snapshot.ObserveOnly,
	}
}
