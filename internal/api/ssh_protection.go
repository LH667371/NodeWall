package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nodewall/internal/integrity"
	"nodewall/internal/models"
	"nodewall/internal/sshactivity"
)

var sshFailurePatterns = []*regexp.Regexp{
	regexp.MustCompile(`Failed password for (?:invalid user )?\S+ from ([0-9]{1,3}(?:\.[0-9]{1,3}){3}) port`),
	regexp.MustCompile(`Invalid user \S+ from ([0-9]{1,3}(?:\.[0-9]{1,3}){3}) port`),
	regexp.MustCompile(`authentication failure;.*rhost=([0-9]{1,3}(?:\.[0-9]{1,3}){3})`),
	regexp.MustCompile(`maximum authentication attempts exceeded.*from ([0-9]{1,3}(?:\.[0-9]{1,3}){3})`),
}

const sshJournalLogPath = "journalctl"

var runJournalctl = func(args ...string) ([]byte, error) {
	return exec.Command("journalctl", args...).CombinedOutput()
}

func detectSSHLogPath() string {
	for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	if journalctlUsable() {
		return sshJournalLogPath
	}
	// Keep the traditional path as the final fallback so an enabled guard
	// reports an actionable missing-source error on minimal non-systemd hosts.
	return "/var/log/auth.log"
}

func resolveSSHLogPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return detectSSHLogPath()
	}
	if path == sshJournalLogPath {
		return path
	}
	if (path == "/var/log/auth.log" || path == "/var/log/secure") && !regularFile(path) {
		if journalctlUsable() {
			return sshJournalLogPath
		}
	}
	return path
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func defaultSSHProtectionSettings(logPath string) models.SSHProtectionSettings {
	logPath = resolveSSHLogPath(logPath)
	return models.SSHProtectionSettings{
		MaxFailures:        5,
		WindowSeconds:      10 * 60,
		BanDurationSeconds: 60 * 60,
		LogPath:            logPath,
	}
}

func normalizeSSHProtectionSettings(settings models.SSHProtectionSettings, fallbackLogPath string) (models.SSHProtectionSettings, error) {
	defaults := defaultSSHProtectionSettings(fallbackLogPath)
	if settings.MaxFailures == 0 {
		settings.MaxFailures = defaults.MaxFailures
	}
	if settings.WindowSeconds == 0 {
		settings.WindowSeconds = defaults.WindowSeconds
	}
	if settings.BanDurationSeconds == 0 {
		settings.BanDurationSeconds = defaults.BanDurationSeconds
	}
	if strings.TrimSpace(settings.LogPath) == "" {
		settings.LogPath = defaults.LogPath
	}
	settings.LogPath = resolveSSHLogPath(settings.LogPath)
	if settings.MaxFailures < 1 || settings.MaxFailures > 100 {
		return settings, fmt.Errorf("max_failures must be between 1 and 100")
	}
	if settings.WindowSeconds < 30 || settings.WindowSeconds > 24*60*60 {
		return settings, fmt.Errorf("window_seconds must be between 30 and 86400")
	}
	if settings.BanDurationSeconds < 60 || settings.BanDurationSeconds > 7*24*60*60 {
		return settings, fmt.Errorf("ban_duration_seconds must be between 60 and 604800")
	}
	// Only standard SSH authentication sources are accepted. This prevents an
	// authenticated UI user from turning the agent into an arbitrary file reader.
	if settings.LogPath != "/var/log/auth.log" && settings.LogPath != "/var/log/secure" && settings.LogPath != sshJournalLogPath {
		return settings, fmt.Errorf("log_path must be /var/log/auth.log, /var/log/secure, or journalctl")
	}
	trusted := make([]string, 0, len(settings.TrustedCIDRs))
	for _, raw := range settings.TrustedCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := parseTrustedPrefix(raw)
		if err != nil {
			return settings, fmt.Errorf("invalid trusted_cidrs entry %q: %w", raw, err)
		}
		trusted = appendUniqueString(trusted, prefix.String())
	}
	settings.TrustedCIDRs = trusted
	return settings, nil
}

func parseTrustedPrefix(raw string) (netip.Prefix, error) {
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("must be an IPv4 CIDR")
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("must be an IPv4 address or CIDR")
	}
	return netip.PrefixFrom(addr.Unmap(), 32), nil
}

func appendUniqueString(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func (h *AgentHandler) LoadSSHProtectionState(ctx context.Context) (resultErr error) {
	defer func() {
		if resultErr != nil {
			h.setSSHProtectionError(resultErr)
		}
	}()
	settings := defaultSSHProtectionSettings(h.sshProtectionLogPath)
	if h.sshProtectionStore != nil {
		loaded, err := h.sshProtectionStore.Load(ctx)
		if err != nil {
			return err
		}
		if loaded.MaxFailures != 0 || loaded.WindowSeconds != 0 || loaded.BanDurationSeconds != 0 || loaded.LogPath != "" || !reflect.DeepEqual(loaded.Transfer, models.SSHTransferPolicy{}) {
			settings = loaded
		}
	}
	normalized, err := normalizeSSHProtectionSettings(settings, h.sshProtectionLogPath)
	if err != nil {
		return err
	}
	h.sshProtectionMu.Lock()
	h.sshProtectionSettings = normalized
	h.sshProtectionMu.Unlock()
	manifest, err := integrity.Load(h.sshIntegrityPath)
	if err != nil && len(normalized.Transfer.VerifyPaths) > 0 {
		return fmt.Errorf("load SSH integrity baseline: %w", err)
	}
	h.sshIntegrityMu.Lock()
	h.sshIntegrityManifest = manifest
	h.sshIntegrityStatus = models.SSHIntegrityStatus{
		Enabled:       len(normalized.Transfer.VerifyPaths) > 0,
		Paths:         append([]string(nil), normalized.Transfer.VerifyPaths...),
		BaselineAt:    timePtrIfNonZero(manifest.CreatedAt),
		BaselineFiles: len(manifest.Entries),
	}
	h.sshIntegrityMu.Unlock()
	return nil
}

func (h *AgentHandler) RunSSHProtection(ctx context.Context) {
	poll := h.sshProtectionPoll
	if poll <= 0 {
		poll = time.Second
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = h.pollSSHProtection(ctx)
		}
	}
}

// ReconcileSSHTransferPolicy upgrades previously enabled hooks after an agent
// update. A clean installation never changes sshd until a user enables controls.
func (h *AgentHandler) ReconcileSSHTransferPolicy(ctx context.Context) error {
	h.sshSettingsUpdateMu.Lock()
	defer h.sshSettingsUpdateMu.Unlock()
	h.sshProtectionMu.RLock()
	policy := h.sshProtectionSettings.Transfer
	h.sshProtectionMu.RUnlock()
	policy.VerifyPaths = nil
	if reflect.DeepEqual(policy, models.SSHTransferPolicy{}) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := h.sshTransferApplier.Apply(ctx, policy)
	h.sshProtectionMu.Lock()
	defer h.sshProtectionMu.Unlock()
	h.sshTransferApplied = err == nil
	if err != nil {
		h.sshLastError = fmt.Sprintf("SSH transfer policy is not verified: %v", err)
	}
	return err
}

func (h *AgentHandler) pollSSHProtection(ctx context.Context) error {
	if err := h.pruneAllTemporaryBlocks(ctx); err != nil {
		return err
	}
	h.sshProtectionMu.RLock()
	settings := h.sshProtectionSettings
	h.sshProtectionMu.RUnlock()
	if !settings.Enabled {
		return nil
	}
	lines, err := h.readSSHLogLines(settings.LogPath)
	if err != nil {
		h.setSSHProtectionError(err)
		return err
	}
	for _, line := range lines {
		if sourceIP, ok := parseSSHFailureSource(line); ok {
			h.processSSHFailure(ctx, sourceIP)
		}
	}
	return nil
}

func (h *AgentHandler) readSSHLogLines(path string) ([]string, error) {
	if path == sshJournalLogPath {
		return h.readSSHJournalLines()
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && hasJournalctl() {
			return h.readSSHJournalLines()
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("SSH authentication log source %q is unavailable; install rsyslog or enable journald: %w", path, err)
		}
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	h.sshProtectionMu.Lock()
	if h.sshLogInfo != nil && (!os.SameFile(h.sshLogInfo, info) || h.sshLogOffset > info.Size()) {
		h.sshLogOffset = 0
	}
	h.sshLogInfo = info
	offset := h.sshLogOffset
	if h.sshProtectionLogPath != path {
		h.sshProtectionLogPath = path
		offset = 0
		h.sshLogOffset = 0
	}
	h.sshProtectionMu.Unlock()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	lines := make([]string, 0, 16)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	current, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	h.sshProtectionMu.Lock()
	h.sshLogOffset = current
	h.sshProtectionMu.Unlock()
	return lines, nil
}

func hasJournalctl() bool {
	return journalctlUsable()
}

func journalctlUsable() bool {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return false
	}
	_, err := exec.Command("journalctl", "--no-pager", "--quiet", "--output=cat", "--since", "1 minute ago").CombinedOutput()
	return err == nil
}

func (h *AgentHandler) readSSHJournalLines() ([]string, error) {
	now := time.Now().UTC()
	h.sshProtectionMu.RLock()
	since := h.sshJournalSince
	h.sshProtectionMu.RUnlock()
	if since.IsZero() {
		// Include a short startup window so an agent restart does not miss a
		// login failure that arrived just before the process became ready.
		since = now.Add(-time.Minute)
	}
	output, err := runJournalctl(
		"--no-pager",
		"--quiet",
		"--output=short-iso",
		// Older systemd/journalctl versions reject RFC3339's `T` and `Z`
		// suffix even though they accept the equivalent local timestamp. Use
		// the portable form so the SSH guard keeps polling after a restart.
		"--since", since.Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		if text := strings.TrimSpace(string(output)); text != "" {
			return nil, fmt.Errorf("read SSH authentication journal: %w: %s", err, text)
		}
		return nil, fmt.Errorf("read SSH authentication journal: %w", err)
	}
	text := strings.TrimSpace(string(output))
	if text == "" {
		return nil, nil
	}
	h.sshProtectionMu.Lock()
	if h.sshJournalSince.Before(now) {
		h.sshJournalSince = now
	}
	if h.sshJournalSeen == nil {
		h.sshJournalSeen = make(map[string]time.Time)
	}
	lines := make([]string, 0)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, seen := h.sshJournalSeen[line]; seen {
			continue
		}
		h.sshJournalSeen[line] = now
		lines = append(lines, line)
	}
	if len(h.sshJournalSeen) > 2048 {
		cutoff := now.Add(-10 * time.Minute)
		for line, seenAt := range h.sshJournalSeen {
			if seenAt.Before(cutoff) {
				delete(h.sshJournalSeen, line)
			}
		}
	}
	h.sshProtectionMu.Unlock()
	return lines, nil
}

func parseSSHFailureSource(line string) (string, bool) {
	for _, pattern := range sshFailurePatterns {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(matches[1])
		if err == nil && addr.Is4() && !addr.IsLoopback() && !addr.IsUnspecified() {
			return addr.Unmap().String(), true
		}
	}
	return "", false
}

func (h *AgentHandler) processSSHFailure(ctx context.Context, sourceIP string) {
	now := time.Now().UTC()
	h.sshProtectionMu.Lock()
	settings := h.sshProtectionSettings
	if !settings.Enabled {
		h.sshProtectionMu.Unlock()
		return
	}
	h.sshLastFailureAt = &now
	windowStart := now.Add(-time.Duration(settings.WindowSeconds) * time.Second)
	failures := h.sshFailures[sourceIP]
	kept := failures[:0]
	for _, timestamp := range failures {
		if timestamp.After(windowStart) {
			kept = append(kept, timestamp)
		}
	}
	kept = append(kept, now)
	h.sshFailures[sourceIP] = kept
	shouldBan := len(kept) >= settings.MaxFailures && !h.hasActiveSSHBlock(sourceIP) && !h.isTrustedSSHSource(sourceIP, settings.TrustedCIDRs)
	if shouldBan {
		delete(h.sshFailures, sourceIP)
	}
	h.sshProtectionMu.Unlock()

	if shouldBan {
		if err := h.addAutomaticSSHBlock(ctx, sourceIP, settings.BanDurationSeconds); err != nil {
			h.setSSHProtectionError(err)
			return
		}
		banAt := time.Now().UTC()
		h.sshProtectionMu.Lock()
		h.sshTotalBans++
		h.sshLastBanAt = &banAt
		h.sshLastError = ""
		h.sshProtectionMu.Unlock()
	}
}

func (h *AgentHandler) isTrustedSSHSource(sourceIP string, trusted []string) bool {
	addr, err := netip.ParseAddr(sourceIP)
	if err != nil || !addr.Is4() {
		return true
	}
	for _, raw := range trusted {
		prefix, err := parseTrustedPrefix(raw)
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	for _, runtime := range h.runtimeSnapshotAll() {
		for _, raw := range append(append(append([]string{}, runtime.Allowlist...), runtime.BypassCIDRs...), runtime.BlockedCIDRs...) {
			prefix, err := parseTrustedPrefix(raw)
			if err == nil && (prefix.Contains(addr) && !sshContainsString(runtime.BlockedCIDRs, prefix.String())) {
				return true
			}
		}
	}
	return false
}

func sshContainsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func (h *AgentHandler) hasActiveSSHBlock(sourceIP string) bool {
	now := time.Now().UTC()
	for _, runtime := range h.runtimeSnapshotAll() {
		for _, block := range runtime.TemporaryBlocks {
			if strings.HasPrefix(block.Reason, "ssh:") && block.SourceIP == sourceIP && block.ExpiresAt.After(now) {
				return true
			}
		}
	}
	return false
}

func (h *AgentHandler) addAutomaticSSHBlock(ctx context.Context, sourceIP string, durationSeconds int) error {
	iface := h.sshProtectionInterface()
	if iface == "" {
		return fmt.Errorf("no attached interface available for SSH protection")
	}
	previous := h.ensureRuntime(iface)
	selected := directionStateFor(previous, models.DirectionIngress)
	now := time.Now().UTC()
	ports := detectSSHPorts()
	port := uint16(22)
	if len(ports) > 0 {
		port = ports[0]
	}
	block := models.TemporaryBlock{
		ID:        fmt.Sprintf("ssh-%d", now.UnixNano()),
		Interface: iface,
		Direction: models.DirectionIngress,
		SourceIP:  sourceIP,
		Port:      port,
		Reason:    "ssh: authentication failures",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(durationSeconds) * time.Second),
		Status:    "active",
	}
	selected.TemporaryBlocks = append(selected.TemporaryBlocks, block)
	selected.LastUpdatedAt = now
	next := withDirectionState(previous, models.DirectionIngress, selected)
	h.setRuntime(iface, next)
	if err := h.applyTemporaryBlock(iface, block); err != nil {
		h.setRuntime(iface, previous)
		return err
	}
	if next.Attached {
		if err := h.syncPolicyConfig(iface, next); err != nil {
			h.setRuntime(iface, previous)
			_ = h.removeTemporaryBlock(iface, previous, block, selected.TemporaryBlocks[:len(selected.TemporaryBlocks)-1])
			_ = h.syncPolicyConfig(iface, previous)
			return err
		}
	}
	if err := h.persist(ctx); err != nil {
		return err
	}
	return nil
}

func (h *AgentHandler) sshProtectionInterface() string {
	for iface, runtime := range h.runtimeSnapshotAll() {
		if runtime.Attached {
			return iface
		}
	}
	interfaces := h.xdp.Interfaces()
	if len(interfaces) > 0 {
		return interfaces[0]
	}
	return ""
}

func (h *AgentHandler) pruneAllTemporaryBlocks(ctx context.Context) error {
	for _, iface := range h.runtimeKeys() {
		if err := h.pruneExpiredDispositions(ctx, iface); err != nil {
			return err
		}
	}
	return nil
}

func (h *AgentHandler) setSSHProtectionError(err error) {
	h.sshProtectionMu.Lock()
	if err == nil {
		h.sshLastError = ""
	} else {
		h.sshLastError = err.Error()
	}
	h.sshProtectionMu.Unlock()
}

func (h *AgentHandler) sshProtectionStatus() models.SSHProtectionStatus {
	h.sshProtectionMu.RLock()
	settings := h.sshProtectionSettings
	tracked := 0
	for source, timestamps := range h.sshFailures {
		if len(timestamps) > 0 {
			tracked++
		}
		_ = source
	}
	status := models.SSHProtectionStatus{
		NodeID:            h.nodeID,
		TransferEffective: h.sshTransferApplied,
		Settings:          settings,
		Ports:             detectSSHPorts(),
		TrackedSources:    tracked,
		TotalBans:         h.sshTotalBans,
		LastFailureAt:     cloneTimePtr(h.sshLastFailureAt),
		LastBanAt:         cloneTimePtr(h.sshLastBanAt),
		LastError:         h.sshLastError,
	}
	h.sshProtectionMu.RUnlock()
	h.sshIntegrityMu.RLock()
	integrityStatus := h.sshIntegrityStatus
	integrityStatus.Paths = append([]string(nil), integrityStatus.Paths...)
	h.sshIntegrityMu.RUnlock()
	now := time.Now().UTC()
	for _, runtime := range h.runtimeSnapshotAll() {
		for _, block := range runtime.TemporaryBlocks {
			if strings.HasPrefix(block.Reason, "ssh:") && block.ExpiresAt.After(now) {
				status.ActiveBlocks = append(status.ActiveBlocks, block)
			}
		}
	}
	status.Integrity = integrityStatus
	status.UploadSecurity = h.sshUploadSecurityStatus(settings.Transfer.ScanUploads)
	return status
}

func (h *AgentHandler) sshUploadSecurityStatus(enabled bool) models.SSHUploadSecurityStatus {
	status := models.SSHUploadSecurityStatus{Enabled: enabled}
	records, err := sshactivity.Read(h.sshActivityLogPath, 100)
	if err != nil {
		status.LastError = err.Error()
		return status
	}
	for _, record := range records {
		if record.Event != "upload_scan" {
			continue
		}
		status.LastCheckedAt = &record.At
		status.LastStatus = record.ScanStatus
		status.FilesChecked = record.Files
		status.Findings = record.Findings
		break
	}
	return status
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func timePtrIfNonZero(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func (h *AgentHandler) handleSSHProtection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, h.sshProtectionStatus())
	case http.MethodPut:
		h.sshSettingsUpdateMu.Lock()
		defer h.sshSettingsUpdateMu.Unlock()
		var settings models.SSHProtectionSettings
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		h.sshProtectionMu.RLock()
		current := h.sshProtectionSettings
		h.sshProtectionMu.RUnlock()
		if settings.LogPath == "" {
			settings.LogPath = current.LogPath
		}
		// Transfer controls change sshd and must go through the separate
		// password-confirmed endpoint; a routine login-protection save must not
		// persist an unapplied transfer policy by accident.
		settings.Transfer = current.Transfer
		normalized, err := normalizeSSHProtectionSettings(settings, h.sshProtectionLogPath)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if h.sshProtectionStore != nil {
			if err := h.sshProtectionStore.Save(r.Context(), normalized); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		h.sshProtectionMu.Lock()
		h.sshProtectionSettings = normalized
		h.sshFailures = make(map[string][]time.Time)
		h.sshLastError = ""
		h.sshProtectionMu.Unlock()
		writeJSON(w, http.StatusOK, h.sshProtectionStatus())
	default:
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
	}
}

func (h *AgentHandler) handleSSHActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	records, err := sshactivity.ReadFiltered(h.sshActivityLogPath, limit, sshactivity.Filter{
		SessionID: strings.TrimSpace(r.URL.Query().Get("session")), Event: strings.TrimSpace(r.URL.Query().Get("event")),
		SourceIP: strings.TrimSpace(r.URL.Query().Get("source")), User: strings.TrimSpace(r.URL.Query().Get("user")),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

func (h *AgentHandler) handleSSHTransferPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	h.sshSettingsUpdateMu.Lock()
	defer h.sshSettingsUpdateMu.Unlock()
	var policy models.SSHTransferPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Path-based baselines were replaced by upload-time checks. Clear the
	// legacy field when an older client sends it so the UI cannot accidentally
	// keep presenting path configuration as the active feature.
	policy.VerifyPaths = nil
	h.sshProtectionMu.RLock()
	current := h.sshProtectionSettings
	applied := h.sshTransferApplied
	h.sshProtectionMu.RUnlock()
	if reflect.DeepEqual(current.Transfer, policy) && applied {
		writeJSON(w, http.StatusOK, h.sshProtectionStatus())
		return
	}
	pathsChanged := len(current.Transfer.VerifyPaths) > 0
	// Every transfer setting is represented by the generated wrapper. Applying
	// only the block/audit-transfer flags left command auditing and upload
	// scanning stale until a later restart.
	if err := h.sshTransferApplier.Apply(r.Context(), policy); err != nil {
		h.sshProtectionMu.Lock()
		h.sshTransferApplied = false
		h.sshProtectionMu.Unlock()
		h.setSSHProtectionError(err)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	previousPolicy := current.Transfer
	current.Transfer = policy
	if h.sshProtectionStore != nil {
		if err := h.sshProtectionStore.Save(r.Context(), current); err != nil {
			recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
			recoveryErr := h.sshTransferApplier.Apply(recoveryCtx, previousPolicy)
			cancel()
			combined := errors.Join(fmt.Errorf("persist SSH settings: %w", err), recoveryErr)
			if recoveryErr != nil {
				h.sshProtectionMu.Lock()
				h.sshTransferApplied = false
				h.sshProtectionMu.Unlock()
			}
			h.setSSHProtectionError(combined)
			writeError(w, http.StatusInternalServerError, combined)
			return
		}
	}
	cleanupWarning := ""
	if pathsChanged {
		if err := os.Remove(h.sshIntegrityPath); err != nil && !os.IsNotExist(err) {
			cleanupWarning = fmt.Sprintf("SSH policy is active; clearing the unused integrity baseline failed: %v", err)
		}
		h.sshIntegrityMu.Lock()
		h.sshIntegrityManifest = integrity.Manifest{}
		h.sshIntegrityStatus = models.SSHIntegrityStatus{
			Enabled: len(policy.VerifyPaths) > 0,
			Paths:   append([]string(nil), policy.VerifyPaths...),
		}
		h.sshIntegrityMu.Unlock()
	}
	h.sshProtectionMu.Lock()
	h.sshProtectionSettings.Transfer = policy
	h.sshTransferApplied = true
	h.sshLastError = cleanupWarning
	h.sshProtectionMu.Unlock()
	writeJSON(w, http.StatusOK, h.sshProtectionStatus())
}

func (h *AgentHandler) handleSSHIntegrityBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	h.sshProtectionMu.RLock()
	paths := append([]string(nil), h.sshProtectionSettings.Transfer.VerifyPaths...)
	h.sshProtectionMu.RUnlock()
	if len(paths) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("configure at least one integrity path first"))
		return
	}
	manifest, err := integrity.Build(r.Context(), paths)
	if err != nil {
		h.setSSHIntegrityError(err)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := integrity.Save(h.sshIntegrityPath, manifest); err != nil {
		h.setSSHIntegrityError(err)
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	h.sshIntegrityMu.Lock()
	h.sshIntegrityManifest = manifest
	h.sshIntegrityStatus = models.SSHIntegrityStatus{
		Enabled:       true,
		Paths:         append([]string(nil), manifest.Paths...),
		BaselineAt:    timePtrIfNonZero(manifest.CreatedAt),
		BaselineFiles: len(manifest.Entries),
	}
	h.sshIntegrityMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"integrity": h.sshProtectionStatus().Integrity})
}

func (h *AgentHandler) handleSSHIntegrityVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	h.sshIntegrityMu.RLock()
	baseline := h.sshIntegrityManifest
	h.sshIntegrityMu.RUnlock()
	if baseline.CreatedAt.IsZero() || len(baseline.Paths) == 0 {
		writeError(w, http.StatusConflict, errors.New("create an integrity baseline first"))
		return
	}
	current, err := integrity.Build(r.Context(), baseline.Paths)
	if err != nil {
		h.setSSHIntegrityError(err)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	difference := integrity.Compare(baseline, current)
	h.sshIntegrityMu.Lock()
	h.sshIntegrityStatus.Paths = append([]string(nil), baseline.Paths...)
	h.sshIntegrityStatus.Enabled = true
	h.sshIntegrityStatus.BaselineAt = timePtrIfNonZero(baseline.CreatedAt)
	h.sshIntegrityStatus.LastCheckedAt = &difference.CheckedAt
	h.sshIntegrityStatus.BaselineFiles = len(baseline.Entries)
	h.sshIntegrityStatus.Added = len(difference.Added)
	h.sshIntegrityStatus.Changed = len(difference.Changed)
	h.sshIntegrityStatus.Deleted = len(difference.Deleted)
	h.sshIntegrityStatus.LastError = ""
	h.sshIntegrityMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"integrity": h.sshProtectionStatus().Integrity,
		"report":    difference,
	})
}

func (h *AgentHandler) setSSHIntegrityError(err error) {
	h.sshIntegrityMu.Lock()
	h.sshIntegrityStatus.LastError = err.Error()
	h.sshIntegrityMu.Unlock()
}

func (h *AgentHandler) handleDeleteSSHProtectionBlock(w http.ResponseWriter, r *http.Request) {
	targetID := strings.TrimSpace(r.PathValue("id"))
	for iface, runtime := range h.runtimeSnapshotAll() {
		selected := directionStateFor(runtime, models.DirectionIngress)
		next := make([]models.TemporaryBlock, 0, len(selected.TemporaryBlocks))
		var removed *models.TemporaryBlock
		for _, block := range selected.TemporaryBlocks {
			if block.ID == targetID && strings.HasPrefix(block.Reason, "ssh:") {
				copy := block
				removed = &copy
				continue
			}
			next = append(next, block)
		}
		if removed == nil {
			continue
		}
		if err := h.removeTemporaryBlock(iface, runtime, *removed, next); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		selected.TemporaryBlocks = next
		selected.LastUpdatedAt = time.Now().UTC()
		nextRuntime := withDirectionState(runtime, models.DirectionIngress, selected)
		if nextRuntime.Attached {
			if err := h.syncPolicyConfig(iface, nextRuntime); err != nil {
				_ = h.applyTemporaryBlock(iface, *removed)
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		h.setRuntime(iface, nextRuntime)
		if err := h.persist(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "released"})
		return
	}
	writeError(w, http.StatusNotFound, fmt.Errorf("SSH protection block %q not found", targetID))
}

func detectSSHPorts() []uint16 {
	// The running daemon is authoritative. Reading only sshd_config misses
	// ports supplied by an Include file or a daemon still serving an older
	// configuration during a reload, both of which could leave an operator
	// unprotected from an unsafe policy change.
	if ports := detectListeningSSHPorts("/proc"); len(ports) > 0 {
		return ports
	}
	return detectConfiguredSSHPorts("/etc/ssh/sshd_config")
}

// detectListeningSSHPorts returns the TCP listening ports owned by the sshd
// master process. It uses procfs rather than shelling out to ss/lsof so the
// agent has no runtime dependency on external diagnostic tools.
func detectListeningSSHPorts(procRoot string) []uint16 {
	listenerPorts := readListeningTCPPorts(procRoot)
	if len(listenerPorts) == 0 {
		return nil
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	ports := make(map[uint16]struct{})
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if _, err := strconv.ParseUint(pid, 10, 32); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(procRoot, pid, "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "sshd" {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(procRoot, pid, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(procRoot, pid, "fd", fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(target)
			if !ok {
				continue
			}
			if port, ok := listenerPorts[inode]; ok {
				ports[port] = struct{}{}
			}
		}
	}
	return sortedSSHPorts(ports)
}

func readListeningTCPPorts(procRoot string) map[string]uint16 {
	ports := make(map[string]uint16)
	for _, name := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(filepath.Join(procRoot, "net", name))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			// In /proc/net/tcp, state 0A is LISTEN and inode is field 9.
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			_, portHex, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			port, err := strconv.ParseUint(portHex, 16, 16)
			if err != nil || port == 0 {
				continue
			}
			ports[fields[9]] = uint16(port)
		}
	}
	return ports
}

func socketInode(target string) (string, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return "", false
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	if _, err := strconv.ParseUint(inode, 10, 64); err != nil || inode == "" {
		return "", false
	}
	return inode, true
}

func detectConfiguredSSHPorts(configPath string) []uint16 {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return []uint16{22}
	}
	ports := make(map[uint16]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) != 2 || !strings.EqualFold(fields[0], "port") {
			continue
		}
		port, err := strconv.ParseUint(fields[1], 10, 16)
		if err == nil && port > 0 {
			ports[uint16(port)] = struct{}{}
		}
	}
	if len(ports) == 0 {
		return []uint16{22}
	}
	return sortedSSHPorts(ports)
}

func sortedSSHPorts(input map[uint16]struct{}) []uint16 {
	ports := make([]uint16, 0, len(input))
	for port := range input {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}
