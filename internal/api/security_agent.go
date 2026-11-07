package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/securityscan"
)

// Root scans include container layers, source trees, and mounted data. Keep a
// generous deadline so a large host can finish coverage instead of producing
// a partial report solely because the fixed API window expired.
const securityScanTimeout = 2 * time.Hour

var securityQuarantineRoot = "/var/lib/nodewall/quarantine"

const quarantineMetadataSuffix = ".nodewall-quarantine.json"

const maxDeletedProcessSnapshot = 256 << 20

type securityScanJob struct {
	NodeID                 string
	ID                     string
	Status                 string
	Root                   string
	StartedAt              time.Time
	FinishedAt             *time.Time
	FilesScanned           uint64
	FilesSkipped           uint64
	MountsSkipped          uint64
	ReadErrors             uint64
	BytesScanned           uint64
	Phase                  string
	Findings               []securityscan.Finding
	Truncated              bool
	Error                  string
	ArchiveError           string
	AutoQuarantine         bool
	AutoTerminateProcesses bool
	QuarantineErrors       []string
	processActions         map[string]bool
}

type securityScanView struct {
	NodeID                 string                 `json:"node_id,omitempty"`
	ID                     string                 `json:"id,omitempty"`
	Status                 string                 `json:"status"`
	Root                   string                 `json:"root,omitempty"`
	StartedAt              time.Time              `json:"started_at,omitempty"`
	FinishedAt             *time.Time             `json:"finished_at,omitempty"`
	FilesScanned           uint64                 `json:"files_scanned"`
	FilesSkipped           uint64                 `json:"files_skipped"`
	MountsSkipped          uint64                 `json:"mounts_skipped"`
	ReadErrors             uint64                 `json:"read_errors"`
	BytesScanned           uint64                 `json:"bytes_scanned"`
	Phase                  string                 `json:"phase,omitempty"`
	Findings               []securityscan.Finding `json:"findings"`
	Truncated              bool                   `json:"truncated"`
	Error                  string                 `json:"error,omitempty"`
	ArchiveError           string                 `json:"archive_error,omitempty"`
	AutoQuarantine         bool                   `json:"auto_quarantine,omitempty"`
	AutoTerminateProcesses bool                   `json:"auto_terminate_processes,omitempty"`
	QuarantineErrors       []string               `json:"quarantine_errors,omitempty"`
}

// securityScanReport is the stable, downloadable representation of a single
// scan. It is separate from the polling view so report metadata can
// evolve without changing the console's live API.
type securityScanReport struct {
	ReportID               string                 `json:"report_id"`
	NodeID                 string                 `json:"node_id"`
	Status                 string                 `json:"status"`
	Root                   string                 `json:"root"`
	StartedAt              time.Time              `json:"started_at"`
	FinishedAt             *time.Time             `json:"finished_at,omitempty"`
	GeneratedAt            time.Time              `json:"generated_at"`
	FilesScanned           uint64                 `json:"files_scanned"`
	FilesSkipped           uint64                 `json:"files_skipped"`
	MountsSkipped          uint64                 `json:"mounts_skipped"`
	ReadErrors             uint64                 `json:"read_errors"`
	BytesScanned           uint64                 `json:"bytes_scanned"`
	SizeDisplay            string                 `json:"size_display"`
	FindingsCount          int                    `json:"findings_count"`
	SeverityCounts         map[string]int         `json:"severity_counts"`
	Findings               []securityscan.Finding `json:"findings"`
	Truncated              bool                   `json:"truncated"`
	Error                  string                 `json:"error,omitempty"`
	AutoQuarantine         bool                   `json:"auto_quarantine,omitempty"`
	AutoTerminateProcesses bool                   `json:"auto_terminate_processes,omitempty"`
	QuarantineErrors       []string               `json:"quarantine_errors,omitempty"`
}

var securityScanReportTemplate = template.Must(template.New("security-scan-report").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>NodeWall 扫描报告 - {{.ReportID}}</title>
  <style>
    :root{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#183247;background:#f4f8fb}
    body{margin:0;padding:32px}main{max-width:1100px;margin:0 auto;background:#fff;border:1px solid #d9e4ec;border-radius:16px;padding:28px;box-shadow:0 10px 30px #18324712}
    h1{margin:0 0 8px;font-size:26px}h2{margin:28px 0 12px;font-size:18px}.muted{color:#6b8293}
    .summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:24px 0}.card{padding:15px;border:1px solid #d9e4ec;border-radius:12px;background:#f8fbfd}.card strong{display:block;font-size:22px;margin-top:5px}
    table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;vertical-align:top;padding:12px 10px;border-bottom:1px solid #e5edf2}th{color:#5c7383;background:#f8fbfd}.path{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.high{color:#c7384d;font-weight:700}.medium{color:#b36a00;font-weight:700}.low{color:#287d67;font-weight:700}
    @media print{body{padding:0;background:#fff}main{border:0;box-shadow:none;max-width:none}}
  </style>
</head>
<body><main>
  <h1>NodeWall 扫描报告</h1>
  <div class="muted">报告编号：{{.ReportID}}　节点：{{.NodeID}}　开始：{{.StartedAt}}　结束：{{.FinishedAt}}　生成：{{.GeneratedAt}}</div>
  <div class="summary">
    <div class="card">扫描状态<strong>{{.Status}}</strong></div>
    <div class="card">扫描路径<strong class="path">{{.Root}}</strong></div>
    <div class="card">扫描文件<strong>{{.FilesScanned}}</strong></div>
    <div class="card">跳过 / 读取失败<strong>{{.FilesSkipped}} / {{.ReadErrors}}</strong></div>
    <div class="card">扫描数据<strong>{{.SizeDisplay}}</strong></div>
    <div class="card">风险文件<strong>{{.FindingsCount}}</strong></div>
    <div class="card">风险等级<strong>高 {{index .SeverityCounts "high"}} / 中 {{index .SeverityCounts "medium"}} / 低 {{index .SeverityCounts "low"}}</strong></div>
  </div>
  {{if .Error}}<p class="high">扫描未完成：{{.Error}}</p>{{end}}
  {{if .Truncated}}<p class="high">提示：存在未检查文件或结果达到上限，报告不是完整结果。</p>{{end}}
  <h2>风险明细</h2>
  {{if .Findings}}<table><thead><tr><th>等级</th><th>文件</th><th>规则</th><th>说明</th><th>SHA-256</th></tr></thead><tbody>
  {{range .Findings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td class="path">{{.Path}}</td><td>{{.Rule}}</td><td>{{.Detail}}</td><td class="path">{{.SHA256}}</td></tr>{{end}}
  </tbody></table>{{else}}<p class="muted">已检查内容未命中内置规则；不代表未检查的文件安全。</p>{{end}}
  <p class="muted">NodeWall 内置规则扫描结果仅用于安全排查，不等同于商业杀毒软件的完整病毒库检测。</p>
</main></body></html>`))

func (h *AgentHandler) handleSecuritySummary(w http.ResponseWriter, r *http.Request) {
	health := h.health.Check(r.Context())
	checks := []map[string]any{
		{
			"id":       "xdp",
			"title":    "XDP 防护",
			"status":   securityCheckStatus(health.Status == "ok" && health.AgentOK),
			"detail":   securityHealthDetail(health),
			"readOnly": true,
		},
		{
			"id":       "ssh",
			"title":    "SSH 防护",
			"status":   securityCheckStatus(h.sshProtectionEnabled()),
			"detail":   fmt.Sprintf("检测到 SSH 端口: %s", formatPorts(detectSSHPorts())),
			"readOnly": true,
		},
		{
			"id":       "scanner",
			"title":    "内置病毒扫描",
			"status":   "ok",
			"detail":   "NodeWall 内置规则引擎，支持扫描与人工隔离",
			"readOnly": true,
		},
		{
			"id":       "permissions",
			"title":    "关键文件权限",
			"status":   securityCheckStatus(!hasWorldWritableCriticalFile()),
			"detail":   criticalPermissionDetail(),
			"readOnly": true,
		},
	}
	if h.securityArchiveUnavailable != "" {
		checks[2]["status"] = "review"
		checks[2]["detail"] = "scan report archive unavailable: " + h.securityArchiveUnavailable
	}
	h.securityMu.RLock()
	job := cloneSecurityScanView(h.securityJob)
	h.securityMu.RUnlock()
	job.NodeID = h.nodeID
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":      h.nodeID,
		"engine":       "nodewall",
		"checks":       checks,
		"scan":         job,
		"quarantine":   map[string]any{"enabled": true, "automatic": false},
		"generated_at": time.Now().UTC(),
	})
}

func (h *AgentHandler) handleSecurityScanStatus(w http.ResponseWriter, r *http.Request) {
	h.securityMu.RLock()
	view := cloneSecurityScanView(h.securityJob)
	h.securityMu.RUnlock()
	view.NodeID = h.nodeID
	writeJSON(w, http.StatusOK, view)
}

func (h *AgentHandler) handleSecurityScanReport(w http.ResponseWriter, r *http.Request) {
	h.securityMu.RLock()
	job := cloneSecurityScanView(h.securityJob)
	id := r.PathValue("scan")
	var report securityScanReport
	var err error
	if id != "" {
		report, err = h.readArchivedScan(id)
	} else {
		report = buildSecurityScanReport(h.nodeID, job)
	}
	h.securityMu.RUnlock()
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		} else if !scanReportID.MatchString(id) {
			status = http.StatusBadRequest
		}
		writeError(w, status, err)
		return
	}
	if report.Status == "idle" || report.Status == "running" {
		writeError(w, http.StatusConflict, errors.New("wait for the security scan to finish before downloading its report"))
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch format {
	case "", "json":
		filename := fmt.Sprintf("nodewall-scan-%s.json", report.ReportID)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		writeJSON(w, http.StatusOK, report)
	case "html":
		filename := fmt.Sprintf("nodewall-scan-%s.html", report.ReportID)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		if err := securityScanReportTemplate.Execute(w, report); err != nil {
			return
		}
	default:
		writeError(w, http.StatusBadRequest, errors.New("report format must be json or html"))
	}
}

func (h *AgentHandler) handleSecurityScanReports(w http.ResponseWriter, r *http.Request) {
	h.securityMu.RLock()
	reports := h.scanReportList()
	archiveError := h.securityArchiveWarning
	if h.securityArchiveUnavailable != "" {
		archiveError = h.securityArchiveUnavailable
	}
	if h.securityJob != nil {
		if h.securityJob.ArchiveError != "" {
			archiveError = h.securityJob.ArchiveError
		}
	}
	h.securityMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"reports": reports, "limit": scanReportLimit, "archive_error": archiveError})
}

func buildSecurityScanReport(nodeID string, scan securityScanView) securityScanReport {
	findings := append([]securityscan.Finding{}, scan.Findings...)
	severityCounts := map[string]int{
		securityscan.SeverityHigh:   0,
		securityscan.SeverityMedium: 0,
		securityscan.SeverityLow:    0,
	}
	for _, finding := range findings {
		severityCounts[finding.Severity]++
	}
	generatedAt := scan.StartedAt
	if scan.FinishedAt != nil {
		generatedAt = *scan.FinishedAt
	}
	return securityScanReport{
		ReportID:               scan.ID,
		NodeID:                 nodeID,
		Status:                 scan.Status,
		Root:                   scan.Root,
		StartedAt:              scan.StartedAt,
		FinishedAt:             scan.FinishedAt,
		GeneratedAt:            generatedAt,
		FilesScanned:           scan.FilesScanned,
		FilesSkipped:           scan.FilesSkipped,
		MountsSkipped:          scan.MountsSkipped,
		ReadErrors:             scan.ReadErrors,
		BytesScanned:           scan.BytesScanned,
		SizeDisplay:            formatScanBytes(scan.BytesScanned),
		FindingsCount:          len(findings),
		SeverityCounts:         severityCounts,
		Findings:               findings,
		Truncated:              scan.Truncated,
		Error:                  scan.Error,
		AutoQuarantine:         scan.AutoQuarantine,
		AutoTerminateProcesses: scan.AutoTerminateProcesses,
		QuarantineErrors:       append([]string(nil), scan.QuarantineErrors...),
	}
}

func formatScanBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	valueFloat := float64(value)
	units := []string{"KB", "MB", "GB", "TB"}
	for _, name := range units {
		valueFloat /= unit
		if valueFloat < unit || name == units[len(units)-1] {
			return fmt.Sprintf("%.1f %s", valueFloat, name)
		}
	}
	return fmt.Sprintf("%d B", value)
}

func (h *AgentHandler) handleSecurityScanStart(w http.ResponseWriter, r *http.Request) {
	if h.securityArchiveUnavailable != "" {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("scan report archive unavailable: %s", h.securityArchiveUnavailable))
		return
	}
	var req struct {
		Path                   string `json:"path"`
		AutoQuarantine         bool   `json:"auto_quarantine"`
		AutoTerminateProcesses bool   `json:"auto_terminate_processes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	root, err := securityscan.ValidateRoot(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// A global recovery scan is the containment path: when the caller opts
	// into automatic quarantine, also terminate confirmed hidden/deleted
	// process findings immediately. File-only scans keep the safer manual
	// process action unless the caller explicitly enables this flag.
	autoTerminateProcesses := req.AutoTerminateProcesses || (root == "/" && req.AutoQuarantine)

	h.securityMu.Lock()
	if h.securityJob != nil && h.securityJob.Status == "running" {
		h.securityMu.Unlock()
		writeError(w, http.StatusConflict, errors.New("a security scan is already running"))
		return
	}
	if h.securityJob != nil && h.securityJob.ArchiveError != "" {
		if err := h.archiveCurrentScan(); err != nil {
			h.securityMu.Unlock()
			writeError(w, http.StatusInternalServerError, fmt.Errorf("save previous scan before replacing it: %w", err))
			return
		}
	}
	job := &securityScanJob{
		NodeID:                 h.nodeID,
		ID:                     fmt.Sprintf("scan-%d", time.Now().UnixNano()),
		Status:                 "running",
		Root:                   root,
		StartedAt:              time.Now().UTC(),
		Findings:               []securityscan.Finding{},
		Phase:                  scanPhase(root),
		AutoQuarantine:         req.AutoQuarantine,
		AutoTerminateProcesses: autoTerminateProcesses,
		processActions:         make(map[string]bool),
	}
	previousJob := h.securityJob
	h.securityJob = job
	if err := h.archiveCurrentScan(); err != nil {
		h.securityJob = previousJob
		h.securityMu.Unlock()
		writeError(w, http.StatusInternalServerError, fmt.Errorf("persist scan before starting: %w", err))
		return
	}
	view := cloneSecurityScanView(job)
	h.securityMu.Unlock()

	go h.runSecurityScan(job.ID, root, req.AutoQuarantine)
	writeJSON(w, http.StatusAccepted, view)
}

// handleSecurityProcessTerminate is intentionally separate from file
// quarantine. Process findings can point at a deleted or proc-hidden
// executable, so containment snapshots or moves the verified executable
// before using the kernel signal path to terminate the process.
func (h *AgentHandler) handleSecurityProcessTerminate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Confirm) != "TERMINATE_PROCESS" {
		writeError(w, http.StatusBadRequest, errors.New("type TERMINATE_PROCESS to confirm process termination"))
		return
	}

	findingID := strings.TrimSpace(r.PathValue("finding"))
	h.securityMu.Lock()
	if h.securityJob == nil || len(h.securityJob.Findings) == 0 {
		h.securityMu.Unlock()
		writeError(w, http.StatusNotFound, errors.New("process finding not found"))
		return
	}
	index := -1
	var finding securityscan.Finding
	for i, item := range h.securityJob.Findings {
		if item.ID == findingID {
			index = i
			finding = item
			break
		}
	}
	if index < 0 || finding.Source != "process" || finding.PID <= 1 {
		h.securityMu.Unlock()
		writeError(w, http.StatusConflict, errors.New("finding is not a terminable process"))
		return
	}
	if finding.PID == os.Getpid() || securityscan.IsTrustedPath(finding.Executable) {
		h.securityMu.Unlock()
		writeError(w, http.StatusConflict, errors.New("refusing to terminate a NodeWall-owned process"))
		return
	}
	if finding.Terminated {
		view := cloneSecurityScanView(h.securityJob)
		h.securityMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"status": "already_terminated", "scan": view})
		return
	}
	scanID := h.securityJob.ID
	// Preserve the executable while the process still has an open reference.
	// This is essential for /path/to/file (deleted) findings, whose last copy
	// would disappear as soon as the process exits.
	h.securityMu.Unlock()
	quarantineTarget, quarantineErr, quarantineAttempted := quarantineProcessFinding(finding, scanID)
	// Release the job lock while waiting for SIGTERM/SIGKILL. The scan poller
	// must remain responsive while a process exits.
	termination, err := securityscan.TerminateProcess(finding.PID)
	if err != nil {
		h.securityMu.Lock()
		if h.securityJob != nil && h.securityJob.ID == scanID && index < len(h.securityJob.Findings) && h.securityJob.Findings[index].ID == findingID {
			if quarantineErr != nil {
				h.securityJob.Findings[index].TerminationError = fmt.Sprintf("quarantine failed: %v; %v", quarantineErr, err)
			} else {
				h.securityJob.Findings[index].TerminationError = err.Error()
			}
			if quarantineAttempted && quarantineTarget != "" {
				h.securityJob.Findings[index].Quarantined = true
				h.securityJob.Findings[index].QuarantinePath = quarantineTarget
			}
			_ = h.archiveCurrentScan()
		}
		h.securityMu.Unlock()
		writeError(w, http.StatusConflict, err)
		return
	}

	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob != nil && h.securityJob.ID == scanID && index < len(h.securityJob.Findings) && h.securityJob.Findings[index].ID == findingID {
		if quarantineAttempted && quarantineTarget != "" {
			h.securityJob.Findings[index].Quarantined = true
			h.securityJob.Findings[index].QuarantinePath = quarantineTarget
		}
		if quarantineErr != nil {
			h.securityJob.Findings[index].TerminationError = fmt.Sprintf("quarantine failed: %v", quarantineErr)
		}
		h.securityJob.Findings[index].Terminated = true
		h.securityJob.Findings[index].Termination = &termination
		h.securityJob.Findings[index].Detail += fmt.Sprintf("; process termination requested via %s", termination.Method)
		_ = h.archiveCurrentScan()
	}
	view := cloneSecurityScanView(h.securityJob)
	writeJSON(w, http.StatusOK, map[string]any{"status": "terminated", "termination": termination, "scan": view})
}

func (h *AgentHandler) runSecurityScan(jobID, root string, autoQuarantine ...bool) {
	ctx, cancel := context.WithTimeout(context.Background(), securityScanTimeout)
	defer cancel()
	report, err := h.securityScanner.Scan(ctx, root, func(progress securityscan.Progress) {
		var processIDs []string
		h.securityMu.Lock()
		if h.securityJob != nil && h.securityJob.ID == jobID {
			if h.securityJob.processActions == nil {
				h.securityJob.processActions = make(map[string]bool)
			}
			h.securityJob.FilesScanned = progress.FilesScanned
			h.securityJob.FilesSkipped = progress.FilesSkipped
			h.securityJob.MountsSkipped = progress.MountsSkipped
			h.securityJob.ReadErrors = progress.ReadErrors
			h.securityJob.BytesScanned = progress.BytesScanned
			h.securityJob.Phase = progress.Phase
			if progress.FindingsReady {
				h.securityJob.Findings = append([]securityscan.Finding(nil), progress.ProcessFindings...)
				if h.securityJob.AutoTerminateProcesses {
					for _, finding := range progress.ProcessFindings {
						if automaticProcessContainmentEligible(finding) && !h.securityJob.processActions[finding.ID] {
							h.securityJob.processActions[finding.ID] = true
							processIDs = append(processIDs, finding.ID)
						}
					}
				}
			}
		}
		h.securityMu.Unlock()
		for _, findingID := range processIDs {
			go h.containProcessFinding(jobID, findingID)
		}
	})

	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil || h.securityJob.ID != jobID {
		return
	}
	now := time.Now().UTC()
	h.securityJob.FinishedAt = &now
	h.securityJob.FilesScanned = report.FilesScanned
	h.securityJob.FilesSkipped = report.FilesSkipped
	h.securityJob.MountsSkipped = report.MountsSkipped
	h.securityJob.ReadErrors = report.ReadErrors
	h.securityJob.BytesScanned = report.BytesScanned
	h.securityJob.Findings = mergeProcessActions(h.securityJob.Findings, report.Findings)
	h.securityJob.Truncated = report.Truncated
	if len(autoQuarantine) > 0 && autoQuarantine[0] {
		// Quarantine only findings that passed the scanner's strict eligibility
		// checks. This remains safe for a partial report when a large-host scan
		// reaches its deadline: evidence is preserved, while high-confidence
		// user-controlled payloads are still isolated.
		h.securityJob.AutoQuarantine = true
		for index := range h.securityJob.Findings {
			finding := &h.securityJob.Findings[index]
			if finding.Source == "process" {
				continue
			}
			if !finding.Quarantinable || finding.Quarantined {
				continue
			}
			target, quarantineErr := isolateFinding(*finding, jobID)
			if target != "" {
				finding.Quarantined = true
				finding.QuarantinePath = target
			}
			if quarantineErr != nil {
				h.securityJob.QuarantineErrors = append(h.securityJob.QuarantineErrors, fmt.Sprintf("%s: %v", finding.Path, quarantineErr))
			}
		}
	}
	if err != nil {
		h.securityJob.Status = "failed"
		h.securityJob.Error = err.Error()
	} else {
		h.securityJob.Status = "completed"
		h.securityJob.Phase = "completed"
	}
	_ = h.archiveCurrentScan()
}

func scanPhase(root string) string {
	if root == "/" {
		return "process"
	}
	return "files"
}

func automaticProcessContainmentEligible(finding securityscan.Finding) bool {
	if finding.Source != "process" || finding.PID <= 1 || finding.Executable == "" {
		return false
	}
	// The scanner runs inside nodewall-agent. Even if a transient proc view
	// makes its own PID look hidden, automatic containment must never terminate
	// the process that is collecting evidence and serving the recovery API.
	if finding.PID == os.Getpid() {
		return false
	}
	if securityscan.IsTrustedPath(finding.Executable) {
		return false
	}
	switch finding.Rule {
	case "cryptominer", "deleted-executable", "hidden-process", "cgroup-hidden-process":
		return true
	default:
		return false
	}
}

func mergeProcessActions(previous, current []securityscan.Finding) []securityscan.Finding {
	if len(previous) == 0 {
		return current
	}
	actions := make(map[string]securityscan.Finding, len(previous))
	for _, finding := range previous {
		if finding.Terminated || finding.Termination != nil || finding.TerminationError != "" || finding.Quarantined {
			actions[finding.ID] = finding
		}
	}
	for index := range current {
		if action, ok := actions[current[index].ID]; ok {
			current[index].Terminated = action.Terminated
			current[index].Termination = action.Termination
			current[index].TerminationError = action.TerminationError
			current[index].Quarantined = action.Quarantined
			current[index].QuarantinePath = action.QuarantinePath
		}
	}
	return current
}

func (h *AgentHandler) containProcessFinding(jobID, findingID string) {
	h.securityMu.RLock()
	if h.securityJob == nil || h.securityJob.ID != jobID {
		h.securityMu.RUnlock()
		return
	}
	var finding securityscan.Finding
	for _, item := range h.securityJob.Findings {
		if item.ID == findingID {
			finding = item
			break
		}
	}
	h.securityMu.RUnlock()
	if finding.ID == "" || !automaticProcessContainmentEligible(finding) {
		return
	}
	quarantineTarget, quarantineErr, quarantineAttempted := quarantineProcessFinding(finding, jobID)
	termination, terminationErr := securityscan.TerminateProcess(finding.PID)
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil || h.securityJob.ID != jobID {
		return
	}
	for index := range h.securityJob.Findings {
		if h.securityJob.Findings[index].ID != findingID {
			continue
		}
		if quarantineAttempted && quarantineTarget != "" {
			h.securityJob.Findings[index].Quarantined = true
			h.securityJob.Findings[index].QuarantinePath = quarantineTarget
		}
		if quarantineErr != nil {
			h.securityJob.Findings[index].TerminationError = fmt.Sprintf("quarantine failed: %v", quarantineErr)
		}
		if terminationErr != nil {
			if quarantineErr != nil {
				h.securityJob.Findings[index].TerminationError += "; "
			}
			h.securityJob.Findings[index].TerminationError += terminationErr.Error()
			break
		}
		h.securityJob.Findings[index].Terminated = true
		h.securityJob.Findings[index].Termination = &termination
		h.securityJob.Findings[index].Detail += fmt.Sprintf("; process terminated via %s", termination.Method)
		break
	}
	_ = h.archiveCurrentScan()
}

// quarantineProcessFinding preserves the executable before the process is
// terminated. A normal executable can be moved directly; an executable that
// was already unlinked is still available through /proc/<pid>/exe and must be
// copied there before the final process reference disappears.
func quarantineProcessFinding(finding securityscan.Finding, scanID string) (target string, err error, attempted bool) {
	if finding.Source == "process" && strings.HasSuffix(strings.TrimSpace(finding.Executable), " (deleted)") {
		target, err := snapshotDeletedProcessExecutable(finding, scanID)
		return target, err, true
	}
	if finding.Quarantinable {
		target, err := isolateFinding(finding, scanID)
		return target, err, true
	}
	return "", nil, false
}

func isolateFinding(finding securityscan.Finding, scanID string) (string, error) {
	if !finding.Quarantinable {
		return "", errors.New("finding is evidence only and is not safe for automatic isolation")
	}
	if err := verifyQuarantineFinding(finding); err != nil {
		return "", err
	}
	quarantineDir := filepath.Join(securityQuarantineRoot, scanID)
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return "", err
	}
	target := filepath.Join(quarantineDir, finding.ID+"-"+filepath.Base(finding.Path))
	info, err := os.Lstat(finding.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		if err != nil {
			return "", err
		}
		return "", errors.New("finding is no longer a regular file")
	}
	// Remove every execute bit before the file leaves the host's normal tree.
	// The quarantine copy is additionally owner-only, so an accidental restore
	// cannot make the payload executable again.
	if err := os.Chmod(finding.Path, info.Mode().Perm()&^0o111); err != nil {
		return "", fmt.Errorf("remove execute permission: %w", err)
	}
	if err := moveRegularFile(finding.Path, target); err != nil {
		return "", fmt.Errorf("isolate file: %w", err)
	}
	if err := os.Chmod(target, 0o600); err != nil {
		return target, fmt.Errorf("lock quarantine file permissions: %w", err)
	}
	metadata := quarantineMetadata{
		OriginalPath:   finding.Path,
		Restorable:     true,
		ScanID:         scanID,
		FindingID:      finding.ID,
		Rule:           finding.Rule,
		Severity:       finding.Severity,
		SHA256:         finding.SHA256,
		OriginalMode:   info.Mode().Perm().String(),
		QuarantineMode: "0600",
		Source:         finding.Source,
		DetectedAt:     finding.DetectedAt,
	}
	if err := os.WriteFile(quarantineMetadataPath(target), marshalQuarantineMetadata(metadata), 0o600); err != nil {
		// The payload is already isolated. Keep it in place and surface the
		// metadata failure so the operator knows the original path needs review.
		return target, fmt.Errorf("write quarantine metadata: %w", err)
	}
	return target, nil
}

// moveRegularFile handles the common same-filesystem rename and the
// cross-filesystem case (for example a scan under a mounted data volume).
// The source was already verified and made non-executable by the caller.
func moveRegularFile(source, target string) error {
	if err := os.Rename(source, target); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return err
	}

	src, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	copyErr := func() error {
		if _, err := io.Copy(dst, src); err != nil {
			return err
		}
		return dst.Sync()
	}()
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(target)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(target)
		return closeErr
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	return nil
}

// snapshotDeletedProcessExecutable copies an executable that has already been
// unlinked from its original path. The open process reference is the only
// remaining copy, so this must happen before SIGTERM/SIGKILL is sent.
func snapshotDeletedProcessExecutable(finding securityscan.Finding, scanID string) (string, error) {
	if finding.PID <= 1 {
		return "", errors.New("invalid process PID for executable snapshot")
	}
	quarantineDir := filepath.Join(securityQuarantineRoot, scanID)
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return "", err
	}
	sourcePath := fmt.Sprintf("/proc/%d/exe", finding.PID)
	src, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("open deleted process executable: %w", err)
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("deleted process executable is not a regular file")
	}
	if finding.Size > 0 && info.Size() != finding.Size {
		return "", errors.New("deleted process executable changed since the scan")
	}
	if info.Size() > maxDeletedProcessSnapshot {
		return "", fmt.Errorf("deleted process executable exceeds %d-byte snapshot limit", maxDeletedProcessSnapshot)
	}
	base := filepath.Base(strings.TrimSuffix(strings.TrimSpace(finding.Executable), " (deleted)"))
	if base == "." || base == "/" || base == "" {
		base = "deleted-executable"
	}
	target := filepath.Join(quarantineDir, finding.ID+"-"+base)
	tmp, err := os.CreateTemp(quarantineDir, ".nodewall-deleted-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	hasher := sha256.New()
	limit := int64(maxDeletedProcessSnapshot)
	if finding.Size > 0 {
		limit = finding.Size + 1
	}
	written, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(src, limit))
	if err != nil {
		_ = tmp.Close()
		return "", err
	}
	if finding.Size > 0 && written != finding.Size {
		_ = tmp.Close()
		return "", errors.New("deleted process executable size changed during snapshot")
	}
	if written > maxDeletedProcessSnapshot {
		_ = tmp.Close()
		return "", fmt.Errorf("deleted process executable exceeds %d-byte snapshot limit", maxDeletedProcessSnapshot)
	}
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if finding.SHA256 != "" && !strings.EqualFold(actualSHA, finding.SHA256) {
		_ = tmp.Close()
		return "", errors.New("deleted process executable hash changed since the scan")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return "", fmt.Errorf("store deleted process executable: %w", err)
	}
	removeTemp = false
	metadata := quarantineMetadata{
		OriginalPath:   strings.TrimSuffix(strings.TrimSpace(finding.Executable), " (deleted)"),
		Restorable:     false,
		ScanID:         scanID,
		FindingID:      finding.ID,
		Rule:           finding.Rule,
		Severity:       finding.Severity,
		SHA256:         actualSHA,
		OriginalMode:   finding.Mode,
		QuarantineMode: "0600",
		Source:         "deleted-process-executable",
		DetectedAt:     finding.DetectedAt,
	}
	if err := os.WriteFile(quarantineMetadataPath(target), marshalQuarantineMetadata(metadata), 0o600); err != nil {
		return target, fmt.Errorf("write quarantine metadata: %w", err)
	}
	return target, nil
}

type quarantineMetadata struct {
	OriginalPath   string    `json:"original_path"`
	Restorable     bool      `json:"restorable"`
	ScanID         string    `json:"scan_id"`
	FindingID      string    `json:"finding_id"`
	Rule           string    `json:"rule,omitempty"`
	Severity       string    `json:"severity,omitempty"`
	SHA256         string    `json:"sha256,omitempty"`
	OriginalMode   string    `json:"original_mode,omitempty"`
	QuarantineMode string    `json:"quarantine_mode,omitempty"`
	Source         string    `json:"source,omitempty"`
	DetectedAt     time.Time `json:"detected_at,omitempty"`
}

func quarantineMetadataPath(payloadPath string) string {
	return payloadPath + quarantineMetadataSuffix
}

func marshalQuarantineMetadata(metadata quarantineMetadata) []byte {
	payload, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		// All fields are scalar values, so this is unreachable. Returning a
		// valid JSON object keeps the caller's file operation deterministic if
		// the structure changes in the future.
		return []byte("{}\n")
	}
	return append(payload, '\n')
}

func readQuarantineMetadata(payloadPath string) (quarantineMetadata, error) {
	payload, err := os.ReadFile(quarantineMetadataPath(payloadPath))
	if err != nil {
		return quarantineMetadata{}, err
	}
	var metadata quarantineMetadata
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return quarantineMetadata{}, err
	}
	return metadata, nil
}

type quarantineEntry struct {
	ID             string    `json:"id"`
	RelativePath   string    `json:"relative_path"`
	OriginalPath   string    `json:"original_path,omitempty"`
	Restorable     bool      `json:"restorable"`
	QuarantinePath string    `json:"quarantine_path"`
	ScanID         string    `json:"scan_id"`
	Name           string    `json:"name"`
	Size           int64     `json:"size"`
	Mode           string    `json:"mode"`
	ModifiedAt     time.Time `json:"modified_at"`
}

func quarantineEntryID(relativePath string) string {
	sum := sha256.Sum256([]byte(filepath.ToSlash(relativePath)))
	return hex.EncodeToString(sum[:])
}

func listQuarantineEntries() ([]quarantineEntry, error) {
	entries := make([]quarantineEntry, 0)
	rootInfo, err := os.Stat(securityQuarantineRoot)
	if os.IsNotExist(err) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}
	if !rootInfo.IsDir() {
		return nil, errors.New("quarantine root is not a directory")
	}
	err = filepath.WalkDir(securityQuarantineRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		// Quarantine contents are operator evidence. Ignore symlinks and
		// special files so the UI never exposes a path that escapes the root.
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		if strings.HasSuffix(entry.Name(), quarantineMetadataSuffix) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(securityQuarantineRoot, path)
		if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return nil
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		scanID := ""
		if len(parts) > 1 {
			scanID = parts[0]
		}
		quarantineItem := quarantineEntry{
			ID:             quarantineEntryID(relative),
			RelativePath:   filepath.ToSlash(relative),
			QuarantinePath: path,
			ScanID:         scanID,
			Name:           filepath.Base(relative),
			Size:           info.Size(),
			Mode:           info.Mode().Perm().String(),
			ModifiedAt:     info.ModTime().UTC(),
		}
		if metadata, metadataErr := readQuarantineMetadata(path); metadataErr == nil {
			quarantineItem.OriginalPath = metadata.OriginalPath
			quarantineItem.Restorable = metadata.Restorable
		}
		entries = append(entries, quarantineItem)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ModifiedAt.Equal(entries[j].ModifiedAt) {
			return entries[i].RelativePath < entries[j].RelativePath
		}
		return entries[i].ModifiedAt.After(entries[j].ModifiedAt)
	})
	return entries, nil
}

func quarantinePathForID(id string) (string, quarantineEntry, error) {
	if len(id) != sha256.Size*2 {
		return "", quarantineEntry{}, os.ErrNotExist
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", quarantineEntry{}, os.ErrNotExist
	}
	entries, err := listQuarantineEntries()
	if err != nil {
		return "", quarantineEntry{}, err
	}
	for _, entry := range entries {
		if entry.ID != id {
			continue
		}
		path := filepath.Join(securityQuarantineRoot, filepath.FromSlash(entry.RelativePath))
		return path, entry, nil
	}
	return "", quarantineEntry{}, os.ErrNotExist
}

func (h *AgentHandler) handleSecurityQuarantineList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	entries, err := listQuarantineEntries()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_id": h.nodeID, "root": securityQuarantineRoot, "entries": entries})
}

func (h *AgentHandler) handleSecurityQuarantineDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var req struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Confirm) != "DELETE_QUARANTINE" {
		writeError(w, http.StatusBadRequest, errors.New("type DELETE_QUARANTINE to confirm permanent deletion"))
		return
	}
	path, entry, err := quarantinePathForID(strings.TrimSpace(r.PathValue("entry")))
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, errors.New("quarantine entry not found"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("quarantine entry not found"))
		return
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		writeError(w, http.StatusConflict, errors.New("quarantine entry is not a regular file"))
		return
	}
	if err := os.Remove(path); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := os.Remove(quarantineMetadataPath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("remove quarantine metadata: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_id": h.nodeID, "status": "deleted", "entry": entry})
}

func (h *AgentHandler) handleSecurityQuarantineRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var req struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Confirm) != "RESTORE_QUARANTINE" {
		writeError(w, http.StatusBadRequest, errors.New("type RESTORE_QUARANTINE to confirm restore"))
		return
	}
	path, entry, err := quarantinePathForID(strings.TrimSpace(r.PathValue("entry")))
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, errors.New("quarantine entry not found"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !entry.Restorable || entry.OriginalPath == "" || !filepath.IsAbs(entry.OriginalPath) {
		writeError(w, http.StatusConflict, errors.New("original path is unavailable for this quarantine entry"))
		return
	}
	originalPath := filepath.Clean(entry.OriginalPath)
	if originalPath == securityQuarantineRoot || strings.HasPrefix(originalPath, securityQuarantineRoot+string(os.PathSeparator)) {
		writeError(w, http.StatusConflict, errors.New("refusing to restore into the quarantine directory"))
		return
	}
	if info, statErr := os.Lstat(originalPath); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			writeError(w, http.StatusConflict, errors.New("restore target exists and is not a regular file"))
			return
		}
		writeError(w, http.StatusConflict, errors.New("restore target already exists; remove it or choose manual recovery"))
		return
	} else if !errors.Is(statErr, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, statErr)
		return
	}
	if info, statErr := os.Lstat(path); statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		writeError(w, http.StatusNotFound, errors.New("quarantine entry is no longer a regular file"))
		return
	}
	if err := os.Rename(path, originalPath); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("restore file: %w", err))
		return
	}
	if err := os.Remove(quarantineMetadataPath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("remove quarantine metadata: %w", err))
		return
	}
	h.securityMu.Lock()
	if h.securityJob != nil {
		for index := range h.securityJob.Findings {
			if h.securityJob.Findings[index].ID == entry.ID || h.securityJob.Findings[index].QuarantinePath == path {
				h.securityJob.Findings[index].Quarantined = false
				h.securityJob.Findings[index].QuarantinePath = ""
			}
		}
		_ = h.archiveCurrentScan()
	}
	h.securityMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"node_id": h.nodeID, "status": "restored", "original_path": originalPath, "entry": entry})
}

func (h *AgentHandler) handleSecurityQuarantine(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Confirm) != "QUARANTINE" {
		writeError(w, http.StatusBadRequest, errors.New("type QUARANTINE to confirm manual isolation"))
		return
	}

	findingID := strings.TrimSpace(r.PathValue("finding"))
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil || h.securityJob.Status != "completed" {
		writeError(w, http.StatusConflict, errors.New("complete a scan before isolating a finding"))
		return
	}
	index := -1
	var finding securityscan.Finding
	scanID := h.securityJob.ID
	for i, item := range h.securityJob.Findings {
		if item.ID == findingID {
			index = i
			finding = item
			break
		}
	}
	if index < 0 {
		writeError(w, http.StatusNotFound, errors.New("finding not found in the latest scan"))
		return
	}
	if !finding.Quarantinable {
		writeError(w, http.StatusConflict, errors.New("this finding is evidence only and cannot be isolated automatically"))
		return
	}
	info, err := os.Lstat(finding.Path)
	if err != nil || !info.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, errors.New("finding is no longer a regular file"))
		return
	}
	if err := verifyQuarantineFinding(finding); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	target, err := isolateFinding(finding, scanID)
	if target != "" && h.securityJob != nil && index < len(h.securityJob.Findings) && h.securityJob.Findings[index].ID == findingID {
		h.securityJob.Findings[index].Quarantined = true
		h.securityJob.Findings[index].QuarantinePath = target
		_ = h.archiveCurrentScan()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	view := cloneSecurityScanView(h.securityJob)
	writeJSON(w, http.StatusOK, map[string]any{"status": "quarantined", "path": target, "scan": view})
}

// Refuse to isolate a replacement file that no longer matches the report.
func verifyQuarantineFinding(finding securityscan.Finding) error {
	file, err := os.OpenFile(finding.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != finding.Size || finding.SHA256 == "" {
		return errors.New("finding changed since the scan; scan it again before isolation")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, finding.Size+1)); err != nil {
		return err
	}
	current, err := os.Lstat(finding.Path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) || hex.EncodeToString(hasher.Sum(nil)) != finding.SHA256 {
		return errors.New("finding changed since the scan; scan it again before isolation")
	}
	return nil
}

func cloneSecurityScanView(job *securityScanJob) securityScanView {
	if job == nil {
		return securityScanView{Status: "idle", Findings: []securityscan.Finding{}}
	}
	return securityScanView{
		NodeID: job.NodeID, ID: job.ID, Status: job.Status, Root: job.Root, StartedAt: job.StartedAt,
		FinishedAt: job.FinishedAt, FilesScanned: job.FilesScanned, BytesScanned: job.BytesScanned,
		FilesSkipped: job.FilesSkipped, MountsSkipped: job.MountsSkipped, ReadErrors: job.ReadErrors, Phase: job.Phase,
		Findings: append([]securityscan.Finding(nil), job.Findings...), Truncated: job.Truncated, Error: job.Error, ArchiveError: job.ArchiveError,
		AutoQuarantine: job.AutoQuarantine, AutoTerminateProcesses: job.AutoTerminateProcesses,
		QuarantineErrors: append([]string(nil), job.QuarantineErrors...),
	}
}

func securityCheckStatus(ok bool) string {
	if ok {
		return "ok"
	}
	return "review"
}

func securityHealthDetail(status models.HealthStatus) string {
	for _, item := range status.Interfaces {
		if item.LastError != "" {
			return item.LastError
		}
	}
	return "XDP、策略和统计状态正常"
}

func (h *AgentHandler) sshProtectionEnabled() bool {
	h.sshProtectionMu.RLock()
	defer h.sshProtectionMu.RUnlock()
	return h.sshProtectionSettings.Enabled
}

func formatPorts(ports []uint16) string {
	if len(ports) == 0 {
		return "未发现"
	}
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprint(port))
	}
	return strings.Join(parts, ", ")
}

func hasWorldWritableCriticalFile() bool {
	for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config"} {
		info, err := os.Stat(path)
		if err == nil && info.Mode().Perm()&0o002 != 0 {
			return true
		}
	}
	return false
}

func criticalPermissionDetail() string {
	if hasWorldWritableCriticalFile() {
		return "发现关键系统文件对所有用户可写"
	}
	return "未发现关键系统文件对所有用户可写"
}
