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
	"sync"
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

// Kernel module operations are process-wide actions. Serialize them across
// concurrent Web clients so a load/unload pair cannot observe an intermediate
// sysfs state or race two insmod/rmmod commands against each other.
var securityKernelModuleMu sync.Mutex

const quarantineMetadataSuffix = ".nodewall-quarantine.json"

const maxDeletedProcessSnapshot = 256 << 20

type securityScanJob struct {
	NodeID                 string
	ID                     string
	Status                 string
	Mode                   string
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
	CoverageGaps           []securityscan.CoverageGap
	CoverageGapsOmitted    uint64
	SignatureEngine        securityscan.SignatureEngineStatus
	Error                  string
	ArchiveError           string
	AutoQuarantine         bool
	AutoTerminateProcesses bool
	QuarantineErrors       []string
	processActions         map[string]bool
	processIsolations      map[string]processIsolation
	cancel                 context.CancelFunc
}

type processIsolation struct {
	target string
	info   os.FileInfo
}

type securityScanView struct {
	NodeID                 string                             `json:"node_id,omitempty"`
	ID                     string                             `json:"id,omitempty"`
	Status                 string                             `json:"status"`
	Mode                   string                             `json:"mode,omitempty"`
	Root                   string                             `json:"root,omitempty"`
	StartedAt              time.Time                          `json:"started_at,omitempty"`
	FinishedAt             *time.Time                         `json:"finished_at,omitempty"`
	FilesScanned           uint64                             `json:"files_scanned"`
	FilesSkipped           uint64                             `json:"files_skipped"`
	MountsSkipped          uint64                             `json:"mounts_skipped"`
	ReadErrors             uint64                             `json:"read_errors"`
	BytesScanned           uint64                             `json:"bytes_scanned"`
	Phase                  string                             `json:"phase,omitempty"`
	Findings               []securityscan.Finding             `json:"findings"`
	Truncated              bool                               `json:"truncated"`
	CoverageGaps           []securityscan.CoverageGap         `json:"coverage_gaps,omitempty"`
	CoverageGapsOmitted    uint64                             `json:"coverage_gaps_omitted,omitempty"`
	SignatureEngine        securityscan.SignatureEngineStatus `json:"signature_engine"`
	Error                  string                             `json:"error,omitempty"`
	ArchiveError           string                             `json:"archive_error,omitempty"`
	AutoQuarantine         bool                               `json:"auto_quarantine,omitempty"`
	AutoTerminateProcesses bool                               `json:"auto_terminate_processes,omitempty"`
	QuarantineErrors       []string                           `json:"quarantine_errors,omitempty"`
}

// securityScanReport is the stable, downloadable representation of a single
// scan. It is separate from the polling view so report metadata can
// evolve without changing the console's live API.
type securityScanReport struct {
	ReportID               string                             `json:"report_id"`
	NodeID                 string                             `json:"node_id"`
	Status                 string                             `json:"status"`
	Mode                   string                             `json:"mode,omitempty"`
	Root                   string                             `json:"root"`
	StartedAt              time.Time                          `json:"started_at"`
	FinishedAt             *time.Time                         `json:"finished_at,omitempty"`
	GeneratedAt            time.Time                          `json:"generated_at"`
	FilesScanned           uint64                             `json:"files_scanned"`
	FilesSkipped           uint64                             `json:"files_skipped"`
	MountsSkipped          uint64                             `json:"mounts_skipped"`
	ReadErrors             uint64                             `json:"read_errors"`
	BytesScanned           uint64                             `json:"bytes_scanned"`
	SizeDisplay            string                             `json:"size_display"`
	FindingsCount          int                                `json:"findings_count"`
	SeverityCounts         map[string]int                     `json:"severity_counts"`
	Findings               []securityscan.Finding             `json:"findings"`
	Truncated              bool                               `json:"truncated"`
	CoverageGaps           []securityscan.CoverageGap         `json:"coverage_gaps,omitempty"`
	CoverageGapsOmitted    uint64                             `json:"coverage_gaps_omitted,omitempty"`
	SignatureEngine        securityscan.SignatureEngineStatus `json:"signature_engine"`
	Error                  string                             `json:"error,omitempty"`
	AutoQuarantine         bool                               `json:"auto_quarantine,omitempty"`
	AutoTerminateProcesses bool                               `json:"auto_terminate_processes,omitempty"`
	QuarantineErrors       []string                           `json:"quarantine_errors,omitempty"`
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
  {{if .CoverageGaps}}<h2>未覆盖范围</h2><ul>{{range .CoverageGaps}}<li><code>{{.Path}}</code>：{{.Reason}}</li>{{end}}</ul>{{end}}
  {{if .CoverageGapsOmitted}}<p>另外有 {{.CoverageGapsOmitted}} 项未列出。</p>{{end}}
  <p>外部特征库：{{.SignatureEngine.Name}} / {{.SignatureEngine.Status}}{{if .SignatureEngine.Version}} / {{.SignatureEngine.Version}}{{end}}{{if .SignatureEngine.Error}} / {{.SignatureEngine.Error}}{{end}}</p>
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
		"quarantine":   map[string]any{"enabled": true, "automatic": true},
		"generated_at": time.Now().UTC(),
	})
}

func (h *AgentHandler) handleSecurityScanStatus(w http.ResponseWriter, r *http.Request) {
	h.securityMu.RLock()
	if r.URL.Query().Get("summary") == "1" {
		view := eventScanSummary{scanReportSummary: scanReportSummary{Status: "idle"}}
		if job := h.securityJob; job != nil {
			view = eventScanSummary{scanReportSummary: scanReportSummary{
				ID: job.ID, Status: job.Status, Mode: job.Mode, Root: job.Root, StartedAt: job.StartedAt,
				FinishedAt: job.FinishedAt, FilesScanned: job.FilesScanned, FindingsCount: len(job.Findings), Truncated: job.Truncated,
			}, Error: job.Error}
		}
		h.securityMu.RUnlock()
		writeJSON(w, http.StatusOK, view)
		return
	}
	view := cloneSecurityScanView(h.securityJob)
	h.securityMu.RUnlock()
	view.NodeID = h.nodeID
	writeJSON(w, http.StatusOK, view)
}

func (h *AgentHandler) handleSecurityScanEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, errors.New("scan event stream is unavailable"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	subscriber := make(chan securityScanView, 1)
	h.securityMu.Lock()
	if h.securityScanSubscribers == nil {
		h.securityScanSubscribers = make(map[chan securityScanView]struct{})
	}
	h.securityScanSubscribers[subscriber] = struct{}{}
	initial := cloneSecurityScanView(h.securityJob)
	initial.NodeID = h.nodeID
	h.securityMu.Unlock()
	defer func() {
		h.securityMu.Lock()
		delete(h.securityScanSubscribers, subscriber)
		h.securityMu.Unlock()
	}()

	writeScanEvent := func(view securityScanView) error {
		payload, err := json.Marshal(view)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: scan\ndata: %s\n\n", payload); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
	if err := writeScanEvent(initial); err != nil {
		return
	}
	heartbeat := time.NewTicker(10 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case view := <-subscriber:
			if err := writeScanEvent(view); err != nil {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
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
		Mode:                   scan.Mode,
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
		CoverageGaps:           append([]securityscan.CoverageGap(nil), scan.CoverageGaps...),
		CoverageGapsOmitted:    scan.CoverageGapsOmitted,
		SignatureEngine:        scan.SignatureEngine,
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
		Mode                   string `json:"mode"`
		AutoQuarantine         bool   `json:"auto_quarantine"`
		AutoTerminateProcesses bool   `json:"auto_terminate_processes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "full"
	}
	if mode != "full" && mode != "process" && mode != "hidden-process" {
		writeError(w, http.StatusBadRequest, errors.New("scan mode must be full, process, or hidden-process"))
		return
	}
	if mode == "process" || mode == "hidden-process" {
		req.Path = "/"
		req.AutoTerminateProcesses = true
		// Quick scans are the recovery path for a host that is about to reboot.
		// Automatically isolate only findings that pass the scanner's strict
		// user-controlled-file checks; record a startup-block intent in the
		// report before changing any directly correlated transient service.
		req.AutoQuarantine = true
	}
	root, err := securityscan.ValidateRoot(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Each automatic action still requires a verifiable identity and recoverable
	// isolation. Evidence-only findings are archived without pretending they can
	// be restored as host files.
	autoTerminateProcesses := req.AutoTerminateProcesses

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
		Mode:                   mode,
		Root:                   root,
		StartedAt:              time.Now().UTC(),
		Findings:               []securityscan.Finding{},
		Phase:                  scanPhase(root),
		AutoQuarantine:         req.AutoQuarantine,
		AutoTerminateProcesses: autoTerminateProcesses,
		processActions:         make(map[string]bool),
	}
	scanCtx, cancel := context.WithTimeout(context.Background(), securityScanTimeout)
	job.cancel = cancel
	previousJob := h.securityJob
	h.securityJob = job
	if err := h.archiveCurrentScan(); err != nil {
		cancel()
		h.securityJob = previousJob
		h.securityMu.Unlock()
		writeError(w, http.StatusInternalServerError, fmt.Errorf("persist scan before starting: %w", err))
		return
	}
	view := cloneSecurityScanView(job)
	h.securityMu.Unlock()

	go h.runSecurityScanContext(scanCtx, job.ID, root, mode, req.AutoQuarantine)
	writeJSON(w, http.StatusAccepted, view)
}

func (h *AgentHandler) handleSecurityScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	h.securityMu.Lock()
	if h.securityJob == nil || h.securityJob.Status != "running" {
		h.securityMu.Unlock()
		writeError(w, http.StatusConflict, errors.New("no security scan is running"))
		return
	}
	job := h.securityJob
	cancel := job.cancel
	job.Phase = "stopping"
	view := cloneSecurityScanView(job)
	h.securityMu.Unlock()
	if cancel != nil {
		cancel()
	}
	writeJSON(w, http.StatusAccepted, view)
}

// handleSecurityProcessTerminate is intentionally separate from file
// quarantine. Process findings can point at a deleted or proc-hidden
// executable, so containment snapshots the verified executable before using
// the kernel signal path and only then moves/removes the original file.
func (h *AgentHandler) handleSecurityProcessTerminate(w http.ResponseWriter, r *http.Request) {
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
	if (finding.Rule != "cryptominer" && !finding.Deleted) || securityscan.IsProtectedProcessPath(finding.Executable) || (!finding.Quarantinable && !finding.Deleted) {
		h.securityMu.Unlock()
		writeError(w, http.StatusConflict, errors.New("process is evidence-only; only a verified quarantinable cryptominer can be isolated"))
		return
	}
	// A process action must use the exact identity captured by the scan. Older
	// reports may lack the start time even though they contain a complete
	// executable hash; enrich that one field from the live process only when
	// the recorded hash and size are already present and still match. Never
	// replace a non-empty hash or size with newly observed values, because that
	// would turn a stale report into authorization to terminate a new process.
	if finding.ProcessStartTime == "" {
		if finding.SHA256 == "" || finding.Size <= 0 {
			h.securityMu.Unlock()
			writeError(w, http.StatusConflict, errors.New("process finding lacks verified identity; run a new scan"))
			return
		}
		enriched := securityscan.EnrichProcessFinding(finding)
		if enriched.ProcessStartTime == "" || enriched.SHA256 == "" || enriched.Size != finding.Size || !strings.EqualFold(enriched.SHA256, finding.SHA256) {
			h.securityMu.Unlock()
			writeError(w, http.StatusConflict, errors.New("cannot verify process identity; run a new scan"))
			return
		}
		finding = enriched
		h.securityJob.Findings[index] = enriched
	}
	if finding.Terminated {
		view := cloneSecurityScanView(h.securityJob)
		h.securityMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"status": "already_terminated", "scan": view})
		return
	}
	if h.securityJob.Status == "running" && h.securityJob.processActions[findingID] {
		h.securityMu.Unlock()
		writeError(w, http.StatusConflict, errors.New("automatic process containment is in progress"))
		return
	}
	scanID := h.securityJob.ID
	h.securityMu.Unlock()
	// Reuse the same verify -> pre-snapshot -> verified signal -> isolate
	// sequence as automatic containment. Keeping one path prevents the manual
	// endpoint from accidentally sending an unverified signal.
	h.containProcessFindingContext(r.Context(), scanID, findingID, true)
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil || h.securityJob.ID != scanID || index >= len(h.securityJob.Findings) || h.securityJob.Findings[index].ID != findingID {
		writeError(w, http.StatusConflict, errors.New("security scan changed while containing process"))
		return
	}
	result := h.securityJob.Findings[index]
	if result.TerminationError != "" {
		writeError(w, http.StatusConflict, errors.New(result.TerminationError))
		return
	}
	if !result.Terminated || result.Termination == nil {
		writeError(w, http.StatusConflict, errors.New("process termination was not confirmed"))
		return
	}
	view := cloneSecurityScanView(h.securityJob)
	writeJSON(w, http.StatusOK, map[string]any{"status": "terminated", "termination": result.Termination, "scan": view})
}

func (h *AgentHandler) handleSecurityFindingIgnore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	findingID := strings.TrimSpace(r.PathValue("finding"))
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil || h.securityJob.Status == "running" || len(h.securityJob.Findings) == 0 {
		writeError(w, http.StatusNotFound, errors.New("finding not found in the latest scan"))
		return
	}
	for index := range h.securityJob.Findings {
		if h.securityJob.Findings[index].ID != findingID {
			continue
		}
		h.securityJob.Findings[index].Ignored = true
		_ = h.archiveCurrentScan()
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ignored",
			"scan":   cloneSecurityScanView(h.securityJob),
		})
		return
	}
	writeError(w, http.StatusNotFound, errors.New("finding not found in the latest scan"))
}

// runSecurityScan keeps the small test/development helper compatible while
// production requests use runSecurityScanContext so the cancel handle is
// owned by the active job.
func (h *AgentHandler) runSecurityScan(jobID, root string, autoQuarantine ...bool) {
	ctx, cancel := context.WithTimeout(context.Background(), securityScanTimeout)
	defer cancel()
	h.runSecurityScanContext(ctx, jobID, root, "full", autoQuarantine...)
}

func (h *AgentHandler) runSecurityScanContext(ctx context.Context, jobID, root, mode string, autoQuarantine ...bool) {
	// Remove masks left by pre-change NodeWall releases before collecting new
	// evidence. The scan now handles the real module/loader file directly.
	_ = removeLegacyKernelModuleBlocks()
	progressHandler := func(progress securityscan.Progress) {
		type processAction struct {
			id       string
			fdScript bool
		}
		var processActions []processAction
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
			h.securityJob.Truncated = progress.Truncated
			h.securityJob.CoverageGaps = append([]securityscan.CoverageGap(nil), progress.CoverageGaps...)
			h.securityJob.CoverageGapsOmitted = progress.CoverageGapsOmitted
			h.securityJob.SignatureEngine = progress.SignatureEngine
			if progress.FindingsReady {
				h.securityJob.Findings = mergeProcessActions(h.securityJob.Findings, append([]securityscan.Finding(nil), progress.ProcessFindings...))
				if h.securityJob.AutoTerminateProcesses {
					for index := range h.securityJob.Findings {
						finding := h.securityJob.Findings[index]
						if finding.Source != "process" && finding.Source != "fd-script" {
							continue
						}
						if finding.Source == "fd-script" && !h.securityJob.AutoQuarantine {
							h.securityJob.Findings[index].ContainmentBlockedReason = "未自动处置：未启用隔离区样本保存"
							continue
						}
						if reason := automaticProcessContainmentBlockReason(finding); finding.Source == "process" && reason != "" {
							h.securityJob.Findings[index].ContainmentBlockedReason = reason
							continue
						}
						identityKey := fmt.Sprintf("pid:%d:%s", finding.PID, finding.ProcessStartTime)
						if !h.securityJob.processActions[finding.ID] && !h.securityJob.processActions[identityKey] {
							h.securityJob.processActions[finding.ID] = true
							h.securityJob.processActions[identityKey] = true
							processActions = append(processActions, processAction{id: finding.ID, fdScript: finding.Source == "fd-script"})
						} else if !h.securityJob.processActions[finding.ID] {
							h.securityJob.Findings[index].TerminationError = "未重复处置：同一进程已有另一条处置记录"
						}
					}
				}
			}
		}
		h.securityMu.Unlock()
		h.publishSecurityScan(jobID)
		for _, action := range processActions {
			// Complete containment before publishing the final scan status, so a
			// completed report cannot race with a still-running process action.
			if action.fdScript {
				h.containFDScriptFinding(ctx, jobID, action.id)
			} else {
				h.containProcessFindingContext(ctx, jobID, action.id)
			}
			h.publishSecurityScan(jobID)
		}
	}
	var report securityscan.Report
	var err error
	if mode == "process" || mode == "hidden-process" {
		report, err = h.securityScanner.ScanProcesses(ctx, progressHandler)
	} else {
		report, err = h.securityScanner.Scan(ctx, root, progressHandler)
	}

	h.securityMu.Lock()
	if h.securityJob == nil || h.securityJob.ID != jobID {
		h.securityMu.Unlock()
		return
	}
	h.securityJob.FilesScanned = report.FilesScanned
	h.securityJob.FilesSkipped = report.FilesSkipped
	h.securityJob.MountsSkipped = report.MountsSkipped
	h.securityJob.ReadErrors = report.ReadErrors
	h.securityJob.BytesScanned = report.BytesScanned
	h.securityJob.Findings = mergeProcessActions(h.securityJob.Findings, report.Findings)
	h.securityJob.Truncated = report.Truncated
	h.securityJob.CoverageGaps = append([]securityscan.CoverageGap(nil), report.CoverageGaps...)
	h.securityJob.CoverageGapsOmitted = report.CoverageGapsOmitted
	h.securityJob.SignatureEngine = report.SignatureEngine
	h.securityMu.Unlock()
	h.publishSecurityScan(jobID)
	if len(autoQuarantine) > 0 && autoQuarantine[0] && !errors.Is(err, context.Canceled) {
		h.containScanFiles(ctx, jobID)
	}
	h.securityMu.Lock()
	if h.securityJob == nil || h.securityJob.ID != jobID {
		h.securityMu.Unlock()
		return
	}
	if ctx.Err() != nil && err == nil {
		err = ctx.Err()
	}
	if h.securityJob.cancel != nil {
		h.securityJob.cancel()
		h.securityJob.cancel = nil
	}
	now := time.Now().UTC()
	h.securityJob.FinishedAt = &now
	if errors.Is(err, context.Canceled) {
		h.securityJob.Status = "cancelled"
		h.securityJob.Error = "scan stopped by operator"
		h.securityJob.Phase = "cancelled"
	} else if err != nil {
		h.securityJob.Status = "failed"
		h.securityJob.Error = err.Error()
	} else {
		h.securityJob.Status = "completed"
		h.securityJob.Phase = "completed"
	}
	_ = h.archiveCurrentScan()
	h.securityMu.Unlock()
	h.publishSecurityScan(jobID)
}

func removeLegacyKernelModuleBlocks() error {
	entries, err := os.ReadDir("/etc/modprobe.d")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var firstErr error
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "nodewall-") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		path := filepath.Join("/etc/modprobe.d", name)
		content, readErr := os.ReadFile(path)
		if readErr != nil || !strings.Contains(string(content), "NodeWall containment for hidden kernel module") {
			continue
		}
		if removeErr := removeKernelModuleBlock(path); removeErr != nil && firstErr == nil {
			firstErr = removeErr
		}
	}
	return firstErr
}

// containScanFiles associates directly executing processes before moving an
// executable. File and process actions run without holding the job lock.
func (h *AgentHandler) containScanFiles(ctx context.Context, jobID string) {
	h.securityMu.Lock()
	if h.securityJob == nil || h.securityJob.ID != jobID {
		h.securityMu.Unlock()
		return
	}
	h.securityJob.AutoQuarantine = true
	findings := append([]securityscan.Finding(nil), h.securityJob.Findings...)
	autoTerminate := h.securityJob.AutoTerminateProcesses
	h.securityMu.Unlock()
	for _, finding := range findings {
		if ctx.Err() != nil {
			return
		}
		if finding.Rule == "hidden-kernel-module" {
			h.containKernelModuleFinding(ctx, jobID, finding)
			continue
		}
		if finding.Source == "journal" && finding.Rule == "malware-persistence" {
			h.markStartupReview(ctx, jobID, finding)
			continue
		}
		if finding.Source == "file" && finding.Severity == securityscan.SeverityHigh &&
			(securityscan.IsSystemdUnitPath(finding.Path) || securityscan.IsTransientSystemdRuntimePath(finding.Path) || securityscan.IsOperatorManagedStartupPath(finding.Path)) &&
			isStartupPersistenceRule(finding.Rule) && !finding.Quarantinable {
			h.markStartupReview(ctx, jobID, finding)
			continue
		}
		if finding.Source == "process" || !finding.Quarantinable || finding.Quarantined {
			continue
		}
		var target string
		var quarantineErr error
		if autoTerminate {
			var processes []securityscan.Finding
			processes, quarantineErr = securityscan.FindProcessesForFileFinding(ctx, finding)
			if quarantineErr == nil && len(processes) > 0 {
				h.securityMu.Lock()
				if h.securityJob == nil || h.securityJob.ID != jobID {
					h.securityMu.Unlock()
					return
				}
				if h.securityJob.processActions == nil {
					h.securityJob.processActions = make(map[string]bool)
				}
				for index := range processes {
					processes[index].ContainmentBlockedReason = automaticProcessContainmentBlockReason(processes[index])
					process := processes[index]
					h.securityJob.processActions[process.ID] = true
				}
				h.securityJob.Findings = append(h.securityJob.Findings, processes...)
				h.securityMu.Unlock()
				for _, process := range processes {
					if ctx.Err() != nil {
						return
					}
					h.containProcessFindingContext(ctx, jobID, process.ID)
					h.securityMu.RLock()
					if h.securityJob != nil && h.securityJob.ID == jobID {
						for _, result := range h.securityJob.Findings {
							if result.ID == process.ID {
								if result.QuarantinePath != "" {
									target = result.QuarantinePath
								}
								if result.TerminationError != "" {
									quarantineErr = errors.New(result.TerminationError)
								} else if result.QuarantinePath == "" {
									reason := result.ContainmentBlockedReason
									if reason == "" {
										reason = "关联进程尚未完成隔离"
									}
									quarantineErr = errors.New(reason)
								}
								break
							}
						}
					}
					h.securityMu.RUnlock()
				}
			} else if quarantineErr == nil {
				target, quarantineErr = isolateFinding(finding, jobID)
			}
		} else {
			target, quarantineErr = isolateFinding(finding, jobID)
		}
		h.securityMu.Lock()
		if h.securityJob == nil || h.securityJob.ID != jobID {
			h.securityMu.Unlock()
			return
		}
		for index := range h.securityJob.Findings {
			if h.securityJob.Findings[index].ID == finding.ID && target != "" {
				h.securityJob.Findings[index].Quarantined = true
				h.securityJob.Findings[index].QuarantinePath = target
				h.securityJob.Findings[index].ContainmentEvidence = containmentEvidence(finding, target)
				h.securityJob.Findings[index].StartupBlocked = false
				h.securityJob.Findings[index].StartupBlockPath = ""
				h.securityJob.Findings[index].StartupBlockOwned = false
				break
			}
		}
		if quarantineErr != nil {
			h.securityJob.QuarantineErrors = append(h.securityJob.QuarantineErrors, fmt.Sprintf("%s: %v", finding.Path, quarantineErr))
		}
		h.securityMu.Unlock()
		h.publishSecurityScan(jobID)
	}
}

func (h *AgentHandler) containKernelModuleFinding(ctx context.Context, jobID string, finding securityscan.Finding) {
	if err := ctx.Err(); err != nil {
		return
	}
	target, startupPath, unloadMethod, isolateErr, unloadErr := containKernelModuleAction(finding, jobID)
	h.securityMu.Lock()
	if h.securityJob == nil || h.securityJob.ID != jobID {
		h.securityMu.Unlock()
		return
	}
	for index := range h.securityJob.Findings {
		if h.securityJob.Findings[index].ID != finding.ID {
			continue
		}
		updated := &h.securityJob.Findings[index]
		updated.StartupBlocked = startupPath != ""
		updated.StartupBlockPath = startupPath
		updated.StartupBlockOwned = startupPath != ""
		updated.ModuleUnloaded = unloadErr == nil
		updated.ContainmentEvidence = fmt.Sprintf("sysfs 对象 %s 仅作为运行态证据；未写入新的启动阻断策略", finding.Path)
		if unloadErr == nil {
			updated.ContainmentEvidence += fmt.Sprintf("；已由扫描器执行 %s 卸载当前内存模块", unloadMethod)
		}
		if isolateErr == nil && target != "" {
			updated.Quarantined = true
			updated.QuarantinePath = target
			updated.ContainmentEvidence += fmt.Sprintf("；已隔离模块文件 %s", target)
		} else if isolateErr != nil && unloadErr == nil {
			updated.ContainmentBlockedReason = isolateErr.Error()
			updated.ContainmentEvidence += "；未保存磁盘样本"
		} else if isolateErr != nil {
			updated.ContainmentBlockedReason = isolateErr.Error()
		}
		if unloadErr != nil {
			if updated.ContainmentBlockedReason == "" {
				updated.ContainmentBlockedReason = unloadErr.Error()
			} else {
				updated.ContainmentBlockedReason += "；" + unloadErr.Error()
			}
		}
		if isolateErr != nil || unloadErr != nil {
			h.securityJob.QuarantineErrors = append(h.securityJob.QuarantineErrors, fmt.Sprintf("%s: %v", finding.Path, firstContainmentError(isolateErr, unloadErr)))
		}
		_ = h.archiveCurrentScan()
		break
	}
	h.securityMu.Unlock()
	h.publishSecurityScan(jobID)
}

func firstContainmentError(isolateErr, unloadErr error) error {
	if isolateErr != nil {
		return isolateErr
	}
	if unloadErr != nil {
		return unloadErr
	}
	return errors.New("内核模块处置未产生结果")
}

func scanPhase(root string) string {
	if root == "/" {
		return "process"
	}
	return "files"
}

func automaticProcessContainmentEligible(finding securityscan.Finding) bool {
	return automaticProcessContainmentBlockReason(finding) == ""
}

func automaticProcessContainmentBlockReason(finding securityscan.Finding) string {
	if finding.Source != "process" {
		return "不是进程发现"
	}
	if finding.PID <= 1 {
		return "未自动处置：PID 无效或受系统保护"
	}
	if finding.PID == os.Getpid() || securityscan.IsTrustedPath(finding.Executable) {
		return "未自动处置：进程属于 NodeWall"
	}
	if securityscan.IsProtectedProcessPath(finding.Executable) {
		return "未自动处置：系统或平台可执行文件只保留篡改证据，需人工核验后处理"
	}
	if finding.Rule == "hidden-process" {
		return "未自动处置：仅隐藏 PID 的进程视图异常保留为证据"
	}
	if finding.Rule == "high-cpu-process" {
		return "未自动处置：单纯高 CPU 只能作为观察证据，不能据此终止进程"
	}
	if finding.Deleted && securityscan.IsSystemdUpdatePath(finding.Executable) {
		return "未自动处置：systemd 更新留下的已删除进程仅作证据"
	}
	if finding.Deleted && finding.Rule != "cryptominer" && finding.Rule != "clamav-signature" {
		return "未自动处置：已删除可执行文件缺少独立恶意特征，需人工确认"
	}
	if finding.Rule != "cryptominer" && finding.Rule != "clamav-signature" {
		return "未自动处置：进程缺少可自动处置的独立恶意特征"
	}
	if !finding.Deleted && !finding.Quarantinable {
		return "未自动处置：可执行文件不满足可恢复隔离条件"
	}
	if finding.Executable == "" || !filepath.IsAbs(finding.Executable) || finding.ProcessStartTime == "" {
		return "未自动处置：缺少可核验的进程身份或可执行文件路径"
	}
	if finding.Size <= 0 || finding.Size > maxDeletedProcessSnapshot {
		return "未自动处置：可执行文件大小无效或超过隔离限制"
	}
	// A complete SHA-256 is required: the snapshot and live executable are
	// compared against it before signaling, never just by path or PID.
	hash, err := hex.DecodeString(finding.SHA256)
	if err != nil || len(hash) != sha256.Size {
		return "未自动处置：缺少完整的可执行文件 SHA-256"
	}
	return ""
}

func mergeProcessActions(previous, current []securityscan.Finding) []securityscan.Finding {
	if len(previous) == 0 {
		return current
	}
	actions := make(map[string]securityscan.Finding, len(previous))
	for _, finding := range previous {
		if finding.Terminated || finding.Termination != nil || finding.TerminationError != "" || finding.ContainmentBlockedReason != "" || finding.Quarantined || finding.EvidenceArchived || finding.StartupBlocked || len(finding.StartupBlocks) > 0 {
			actions[finding.ID] = finding
		}
	}
	for index := range current {
		if action, ok := actions[current[index].ID]; ok {
			current[index].Terminated = action.Terminated
			current[index].Termination = action.Termination
			current[index].TerminationError = action.TerminationError
			current[index].ContainmentBlockedReason = action.ContainmentBlockedReason
			current[index].Quarantined = action.Quarantined
			current[index].QuarantinePath = action.QuarantinePath
			current[index].EvidenceArchived = action.EvidenceArchived
			current[index].EvidencePath = action.EvidencePath
			current[index].ContainmentEvidence = action.ContainmentEvidence
			current[index].StartupBlocked = action.StartupBlocked
			current[index].StartupBlockPath = action.StartupBlockPath
			current[index].StartupBlockOwned = action.StartupBlockOwned
			current[index].ModuleUnloaded = action.ModuleUnloaded
			current[index].StartupBlocks = append([]securityscan.StartupBlock(nil), action.StartupBlocks...)
		}
	}
	return current
}

func (h *AgentHandler) containProcessFinding(jobID, findingID string) {
	h.containProcessFindingContext(context.Background(), jobID, findingID)
}

// containProcessFindingContext performs automatic containment by default. The
// manual flag is used only by the explicit operator endpoint; system/package
// processes and ordinary high-CPU evidence remain protected from termination.
func (h *AgentHandler) containProcessFindingContext(ctx context.Context, jobID, findingID string, manual ...bool) {
	manualAction := len(manual) > 0 && manual[0]
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
	isolationKey := fmt.Sprintf("%s\x00%s\x00%d", finding.Executable, finding.SHA256, finding.Size)
	previousIsolation, previouslyIsolated := h.securityJob.processIsolations[isolationKey]
	h.securityMu.RUnlock()
	if finding.ID == "" || (!manualAction && !automaticProcessContainmentEligible(finding)) {
		return
	}
	var quarantineTarget string
	var quarantineErr error
	var sampleTarget string
	var termination securityscan.ProcessTermination
	var terminationErr error
	var executableInfo os.FileInfo
	if err := ctx.Err(); err != nil {
		terminationErr = fmt.Errorf("process containment cancelled: %w", err)
	} else if previouslyIsolated && !finding.Deleted {
		// A prior finding may have isolated the inode shared by several PIDs.
		// Reuse the evidence only when this process still holds that inode.
		current, statErr := os.Stat(fmt.Sprintf("/proc/%d/exe", finding.PID))
		if statErr != nil || previousIsolation.info == nil || !os.SameFile(current, previousIsolation.info) {
			terminationErr = errors.New("shared process executable no longer matches the isolated inode")
		} else if updated, verifyErr := securityscan.ProcessFindingAfterIsolation(finding, previousIsolation.target); verifyErr != nil {
			terminationErr = fmt.Errorf("verify previously isolated executable: %w", verifyErr)
		} else {
			finding = updated
			quarantineTarget = previousIsolation.target
			if err := ctx.Err(); err != nil {
				terminationErr = fmt.Errorf("process containment cancelled before signal: %w", err)
			} else {
				termination, terminationErr = securityscan.TerminateProcessVerified(finding)
			}
		}
	} else if err := securityscan.VerifyProcessFinding(finding); err != nil {
		terminationErr = fmt.Errorf("verify process before snapshot: %w", err)
	} else if finding.Deleted {
		// For an already-unlinked executable the procfs descriptor is the only
		// remaining copy. Snapshot it first, verify the identity again, then send
		// the signal while the descriptor is still open.
		var attempted bool
		quarantineTarget, quarantineErr, attempted = quarantineProcessFinding(finding, jobID)
		if !attempted && quarantineErr == nil {
			quarantineErr = errors.New("process executable could not be isolated for recovery")
		}
		if quarantineErr == nil {
			if verifyErr := securityscan.VerifyProcessFinding(finding); verifyErr != nil {
				terminationErr = fmt.Errorf("verify process before signal: %w", verifyErr)
			}
		}
		if quarantineErr == nil && terminationErr == nil {
			if err := ctx.Err(); err != nil {
				terminationErr = fmt.Errorf("process containment cancelled before signal: %w", err)
			} else {
				termination, terminationErr = securityscan.TerminateProcessVerified(finding)
			}
		}
	} else {
		// Preserve the payload without changing its path or execute bits. The
		// source is moved into quarantine only after the verified process exits.
		if finding.Path == "" || filepath.Clean(finding.Path) != filepath.Clean(finding.Executable) || !filepath.IsAbs(finding.Executable) {
			terminationErr = errors.New("process executable path cannot be isolated safely")
		} else {
			executableInfo, terminationErr = os.Stat(fmt.Sprintf("/proc/%d/exe", finding.PID))
		}
		if terminationErr == nil {
			sampleTarget, terminationErr = snapshotLiveProcessExecutable(finding, jobID)
		}
		if terminationErr == nil {
			if verifyErr := securityscan.VerifyProcessFinding(finding); verifyErr != nil {
				terminationErr = fmt.Errorf("verify process before signal: %w", verifyErr)
			}
		}
		if terminationErr == nil {
			if err := ctx.Err(); err != nil {
				terminationErr = fmt.Errorf("process containment cancelled before signal: %w", err)
			} else {
				termination, terminationErr = securityscan.TerminateProcessVerified(finding)
			}
		}
		if terminationErr == nil {
			quarantineTarget, quarantineErr = isolateProcessFindingAfterTermination(finding, jobID, executableInfo)
			if quarantineErr == nil {
				removeProcessExecutableSnapshot(sampleTarget)
				h.securityMu.Lock()
				if h.securityJob != nil && h.securityJob.ID == jobID {
					if h.securityJob.processIsolations == nil {
						h.securityJob.processIsolations = make(map[string]processIsolation)
					}
					h.securityJob.processIsolations[isolationKey] = processIsolation{target: quarantineTarget, info: executableInfo}
				}
				h.securityMu.Unlock()
			} else if quarantineTarget == "" {
				// Keep the sample when the original could not be moved. If it was
				// moved but a later step failed, retain the actual destination.
				quarantineTarget = sampleTarget
			}
		}
		if quarantineTarget == "" && sampleTarget != "" {
			// An identity change or cancellation after the snapshot must still
			// leave its recorded sample discoverable in the scan report.
			quarantineTarget = sampleTarget
		}
	}
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil || h.securityJob.ID != jobID {
		return
	}
	for index := range h.securityJob.Findings {
		if h.securityJob.Findings[index].ID != findingID {
			continue
		}
		if quarantineTarget != "" {
			h.securityJob.Findings[index].Quarantined = true
			h.securityJob.Findings[index].QuarantinePath = quarantineTarget
			h.securityJob.Findings[index].ContainmentEvidence = containmentEvidence(finding, quarantineTarget)
		}
		// A later file-isolation error must not erase a confirmed process exit;
		// callers need both facts to distinguish partial containment from failure.
		if termination.Exited {
			h.securityJob.Findings[index].Terminated = true
			h.securityJob.Findings[index].Termination = &termination
			h.securityJob.Findings[index].Detail += fmt.Sprintf("; automatic process containment requested by scan, terminated via %s", termination.Method)
		}
		if quarantineErr != nil {
			h.securityJob.Findings[index].TerminationError = fmt.Sprintf("quarantine failed: %v", quarantineErr)
		} else if terminationErr != nil {
			h.securityJob.Findings[index].TerminationError = terminationErr.Error()
		}
		break
	}
	_ = h.archiveCurrentScan()
}

func containmentEvidence(finding securityscan.Finding, target string) string {
	matched := fmt.Sprintf("规则 %s 命中", finding.Rule)
	metadata, err := readQuarantineMetadata(target)
	if err != nil {
		return matched + "；隔离记录中的校验信息不可用"
	}
	switch metadata.Source {
	case "deleted-process-executable":
		matched += "；从进程的 /proc/PID/exe 保存已删除的可执行文件样本"
	case "process-pre-snapshot":
		matched += "；保存进程退出前的可执行文件样本，原路径是否隔离请查看处置结果"
	default:
		matched += "；隔离前校验普通文件的路径、inode 和文件类型"
	}
	if metadata.SHA256 != "" {
		matched += "; SHA-256 " + metadata.SHA256
	}
	return matched
}

// quarantineProcessFinding preserves an executable before process termination.
// Deleted executables are copied through /proc/<pid>/exe because that open
// reference is the only remaining copy once the process exits. Normal files
// are handled by isolateProcessFindingAfterTermination after the signal.
func quarantineProcessFinding(finding securityscan.Finding, scanID string) (target string, err error, attempted bool) {
	if finding.Source == "process" && (finding.Deleted || strings.HasSuffix(strings.TrimSpace(finding.Executable), " (deleted)")) {
		target, err := snapshotDeletedProcessExecutable(finding, scanID)
		return target, err, true
	}
	if finding.Source == "process" && finding.Executable != "" && finding.Path == finding.Executable {
		target, err := isolateFindingWithEligibility(finding, scanID, true)
		return target, err, true
	}
	return "", nil, false
}

// snapshotLiveProcessExecutable preserves a copy while the process still
// owns the original inode. The source path and permissions are left intact;
// containment moves it only after the verified process has exited. Keeping a
// separate sample makes a failed post-termination isolation recoverable.
func snapshotLiveProcessExecutable(finding securityscan.Finding, scanID string) (string, error) {
	if finding.PID <= 1 || finding.Executable == "" || finding.Deleted {
		return "", errors.New("invalid live process executable snapshot request")
	}
	if err := verifyTrustedSourceParents(finding.Executable); err != nil {
		return "", fmt.Errorf("refusing unsafe process snapshot path: %w", err)
	}
	src, err := os.OpenFile(finding.Executable, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("open process executable: %w", err)
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() != finding.Size || finding.Size > maxDeletedProcessSnapshot {
		return "", errors.New("process executable changed before snapshot")
	}
	proc, err := os.Open(fmt.Sprintf("/proc/%d/exe", finding.PID))
	if err != nil {
		return "", fmt.Errorf("open process executable reference: %w", err)
	}
	procInfo, statErr := proc.Stat()
	_ = proc.Close()
	if statErr != nil || !os.SameFile(info, procInfo) {
		return "", errors.New("process no longer executes the file selected for snapshot")
	}
	attrs, attrErr := readQuarantineAttrs(src)
	if attrErr != nil {
		return "", fmt.Errorf("read original file attributes: %w", attrErr)
	}
	hasher := sha256.New()
	if n, copyErr := io.Copy(hasher, io.NewSectionReader(src, 0, finding.Size+1)); copyErr != nil || n != finding.Size || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), finding.SHA256) {
		return "", errors.New("process executable changed while creating snapshot")
	}
	quarantineDir := filepath.Join(securityQuarantineRoot, scanID)
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return "", err
	}
	base := filepath.Base(strings.TrimSpace(finding.Executable))
	if base == "." || base == "/" || base == "" {
		base = "process-executable"
	}
	tmp, err := os.CreateTemp(quarantineDir, ".nodewall-process-sample-*")
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
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		_ = tmp.Close()
		return "", err
	}
	copyHash := sha256.New()
	if n, copyErr := io.Copy(io.MultiWriter(tmp, copyHash), io.NewSectionReader(src, 0, finding.Size+1)); copyErr != nil || n != finding.Size || !strings.EqualFold(hex.EncodeToString(copyHash.Sum(nil)), finding.SHA256) {
		_ = tmp.Close()
		return "", errors.New("process executable changed while saving snapshot")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	target := filepath.Join(quarantineDir, finding.ID+"-sample-"+base)
	if err := os.Rename(tmpPath, target); err != nil {
		return "", fmt.Errorf("store process executable snapshot: %w", err)
	}
	removeTemp = false
	stat, _ := info.Sys().(*syscall.Stat_t)
	metadata := quarantineMetadata{
		// Keep the pre-signal copy recoverable. If the process exits but the
		// original path changes before the post-termination move, the operator
		// can still restore this exact inode and its recorded metadata.
		OriginalPath: finding.Executable, Restorable: true, ScanID: scanID, FindingID: finding.ID,
		Rule: finding.Rule, Severity: finding.Severity, SHA256: finding.SHA256,
		OriginalMode: info.Mode().Perm().String(), ModeKnown: true, Attributes: attrs, QuarantineMode: "0600",
		Source: "process-pre-snapshot", DetectedAt: finding.DetectedAt, QuarantinedAt: time.Now().UTC(),
	}
	if stat != nil {
		metadata.OriginalModeBits = uint32(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
		metadata.ModeKnown = true
		metadata.OriginalUID = int(stat.Uid)
		metadata.OriginalGID = int(stat.Gid)
		metadata.OwnerKnown = true
	}
	metadataFile, err := os.OpenFile(quarantineMetadataPath(target), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = os.Remove(target)
		return "", fmt.Errorf("create process snapshot metadata: %w", err)
	}
	_, writeErr := metadataFile.Write(marshalQuarantineMetadata(metadata))
	if writeErr == nil {
		writeErr = metadataFile.Sync()
	}
	if closeErr := metadataFile.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(target)
		_ = os.Remove(quarantineMetadataPath(target))
		return "", fmt.Errorf("write process snapshot metadata: %w", writeErr)
	}
	return target, nil
}

func removeProcessExecutableSnapshot(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(path)
	_ = os.Remove(quarantineMetadataPath(path))
}

func isolateFinding(finding securityscan.Finding, scanID string) (string, error) {
	return isolateFindingWithEligibility(finding, scanID, false)
}

// isolateFindingManually is used after an operator explicitly confirms the
// action in the UI. Manual containment may cover evidence-only file rules
// (for example a dangerous command in a script), while automatic containment
// remains restricted to Finding.Quarantinable.
func isolateFindingManually(finding securityscan.Finding, scanID string) (string, error) {
	if finding.Rule == "hidden-kernel-module" {
		return isolateKernelModuleFile(finding, scanID, true)
	}
	if normalized, err := normalizeManualSystemdFinding(finding); err != nil {
		return "", err
	} else {
		finding = normalized
	}
	if finding.Source != "file" && !(finding.Source == "" && finding.PID == 0 && strings.TrimSpace(finding.Path) != "") {
		return "", errors.New("only regular file findings can be manually isolated")
	}
	return isolateFindingWithEligibility(finding, scanID, true)
}

// isolateKernelModuleFile isolates the on-disk module referenced by a live
// sysfs finding. The /sys/module directory itself is a kernel virtual view and
// must never be moved or deleted. Automatic containment only accepts an
// external module path; an operator-confirmed action may also isolate a
// package-path module when the hidden-module evidence is explicit.
func isolateKernelModuleFile(finding securityscan.Finding, scanID string, manual bool) (string, error) {
	modulePath := ""
	if candidate := filepath.Clean(strings.TrimSpace(finding.ModulePath)); candidate != "." && candidate != "" &&
		(manual || !securityscan.IsSystemFilePath(candidate)) {
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			modulePath = candidate
		}
	}
	for _, candidate := range finding.RelatedPaths {
		if modulePath != "" {
			break
		}
		candidate = filepath.Clean(strings.TrimSpace(candidate))
		if candidate == "" || candidate == "/proc/modules" || strings.HasPrefix(candidate, "/sys/") {
			continue
		}
		if !manual && securityscan.IsSystemFilePath(candidate) {
			continue
		}
		info, err := os.Lstat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			modulePath = candidate
			break
		}
	}
	if modulePath == "" {
		return "", errors.New("无法定位内核模块文件；/sys/module 只是内核虚拟目录，当前运行实例需要从可信环境恢复")
	}
	moduleFinding := finding
	moduleFinding.Path = modulePath
	moduleFinding.Source = "kernel-module"
	moduleFinding.SystemFile = false
	if strings.TrimSpace(moduleFinding.ModuleName) == "" {
		moduleFinding.ModuleName = kernelModuleName(finding)
	}
	return isolateFindingWithEligibility(moduleFinding, scanID, manual)
}

func kernelModuleName(finding securityscan.Finding) string {
	path := filepath.Clean(strings.TrimSpace(finding.Path))
	if !strings.HasPrefix(path, "/sys/module/") {
		return ""
	}
	rel, err := filepath.Rel("/sys/module", path)
	if err != nil || rel == "." || strings.ContainsRune(rel, filepath.Separator) {
		return ""
	}
	for _, r := range rel {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return ""
		}
	}
	return rel
}

func removeKernelModuleBlock(path string) error {
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "." || filepath.Dir(clean) != "/etc/modprobe.d" || !strings.HasPrefix(filepath.Base(clean), "nodewall-") || !strings.HasSuffix(filepath.Base(clean), ".conf") {
		return errors.New("拒绝删除非 NodeWall 管理的模块阻断策略")
	}
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("模块阻断策略不是普通文件")
	}
	return os.Remove(clean)
}

// containKernelModuleAction performs the destructive part of hidden-module
// containment without holding securityMu. /sys/module is a kernel virtual
// view and is never treated as a file. When a verified external .ko payload is
// available it is moved to quarantine first; the live module is then unloaded.
// No modprobe/systemd mask is created: persistence must be removed by
// quarantining the actual loader or module file, not by adding another boot
// policy that malware could bypass or rewrite.
func containKernelModuleAction(finding securityscan.Finding, scanID string) (target, startupPath, unloadMethod string, isolateErr, unloadErr error) {
	securityKernelModuleMu.Lock()
	defer securityKernelModuleMu.Unlock()
	// Remove a mask created by an older NodeWall version before taking the
	// actual containment action. This is a cleanup of our own previous state,
	// never a new persistence control.
	startupPath = filepath.Join("/etc/modprobe.d", "nodewall-"+finding.ID+".conf")
	if err := removeKernelModuleBlock(startupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		isolateErr = fmt.Errorf("清理旧的内核模块阻断策略: %w", err)
	}
	startupPath = ""
	if isolateErr == nil {
		target, isolateErr = isolateKernelModuleFile(finding, scanID, false)
	}
	unloadMethod, unloadErr = unloadKernelModule(kernelModuleName(finding), finding.Path)
	return target, startupPath, unloadMethod, isolateErr, unloadErr
}

func isolateFindingWithEligibility(finding securityscan.Finding, scanID string, manual bool) (string, error) {
	return isolateFindingWithExpectedInode(finding, scanID, manual, nil)
}

// isolateProcessFindingAfterTermination completes the destructive part of a
// process action after the verified process has exited. The inode captured
// before the signal is still required, so a replacement at the path cannot be
// mistaken for the process payload.
func isolateProcessFindingAfterTermination(finding securityscan.Finding, scanID string, expected os.FileInfo) (string, error) {
	return isolateFindingWithExpectedInode(finding, scanID, true, expected)
}

func isolateFindingWithExpectedInode(finding securityscan.Finding, scanID string, manual bool, expectedInode os.FileInfo) (string, error) {
	if !manual && !finding.Quarantinable {
		return "", errors.New("finding is evidence only and is not safe for automatic isolation")
	}
	if securityscan.IsSystemFilePath(finding.Path) && !securityscan.IsOperatorManagedStartupPath(finding.Path) &&
		!(manual && finding.Rule == "hidden-kernel-module") && !(manual && isManualStartupFinding(finding)) {
		return "", errors.New("system package files cannot be isolated through the security scan")
	}
	if err := verifyTrustedSourceParents(finding.Path); err != nil {
		return "", fmt.Errorf("refusing unsafe isolation path: %w", err)
	}
	if err := verifyQuarantineFinding(finding); err != nil {
		return "", err
	}
	quarantineDir := filepath.Join(securityQuarantineRoot, scanID)
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return "", err
	}
	baseName := filepath.Base(strings.TrimSuffix(strings.TrimSpace(finding.Path), " (deleted)"))
	if baseName == "." || baseName == "/" || baseName == "" {
		baseName = "payload"
	}
	target := filepath.Join(quarantineDir, finding.ID+"-"+baseName)
	file, err := os.OpenFile(finding.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		if err != nil {
			return "", err
		}
		return "", errors.New("finding is no longer a regular file")
	}
	current, err := os.Lstat(finding.Path)
	if err != nil || !os.SameFile(info, current) {
		return "", errors.New("finding changed before isolation")
	}
	if expectedInode != nil && !os.SameFile(info, expectedInode) {
		return "", errors.New("process executable changed after termination")
	}
	if finding.Source == "process" && expectedInode == nil {
		processExe, openErr := os.Open(fmt.Sprintf("/proc/%d/exe", finding.PID))
		if openErr != nil {
			return "", fmt.Errorf("open process executable: %w", openErr)
		}
		processInfo, statErr := processExe.Stat()
		_ = processExe.Close()
		if statErr != nil || !os.SameFile(info, processInfo) {
			return "", errors.New("process no longer executes the file selected for isolation")
		}
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(file, 0, finding.Size+1)); err != nil || info.Size() != finding.Size || !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), finding.SHA256) {
		return "", errors.New("finding changed before isolation; rescan it")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return "", errors.New("cannot safely isolate a file with multiple hard links or unknown identity")
	}
	attrs, err := readQuarantineAttrs(file)
	if err != nil {
		return "", fmt.Errorf("read original file attributes: %w", err)
	}
	mode := info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	startupLinks, err := prepareSystemdUnitIsolation(finding.Path)
	if err != nil {
		return "", err
	}
	rollbackStartup := func() {
		if len(startupLinks) > 0 {
			rollbackSystemdUnitIsolation(startupLinks)
		}
	}
	metadata := quarantineMetadata{
		OriginalPath: finding.Path, Restorable: true, ScanID: scanID, FindingID: finding.ID,
		Rule: finding.Rule, Severity: finding.Severity, SHA256: finding.SHA256,
		OriginalMode: info.Mode().Perm().String(), OriginalModeBits: uint32(mode), ModeKnown: true,
		OriginalUID: int(stat.Uid), OriginalGID: int(stat.Gid), OwnerKnown: true, Attributes: attrs,
		QuarantineMode: "0600", Source: finding.Source, ModuleName: finding.ModuleName, DetectedAt: finding.DetectedAt,
		QuarantinedAt: time.Now().UTC(),
		StartupLinks:  startupLinks,
	}
	metadataPath := quarantineMetadataPath(target)
	metadataFile, err := os.OpenFile(metadataPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		rollbackStartup()
		return "", fmt.Errorf("create quarantine metadata: %w", err)
	}
	_, writeErr := metadataFile.Write(marshalQuarantineMetadata(metadata))
	if writeErr == nil {
		writeErr = metadataFile.Sync()
	}
	if closeErr := metadataFile.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(metadataPath)
		rollbackStartup()
		return "", fmt.Errorf("write quarantine metadata: %w", writeErr)
	}
	// Remove every execute bit before the file leaves the host's normal tree.
	// The quarantine copy is additionally owner-only, so an accidental restore
	// cannot make the payload executable again.
	if err := file.Chmod(mode &^ 0o111); err != nil {
		_ = os.Remove(metadataPath)
		rollbackStartup()
		return "", fmt.Errorf("remove execute permission: %w", err)
	}
	if err := moveRegularFile(finding.Path, target, file, info, finding.SHA256); err != nil {
		_ = os.Remove(metadataPath)
		rollbackStartup()
		if restoreErr := file.Chmod(mode); restoreErr != nil {
			return "", fmt.Errorf("isolate file: %w; restore original permissions: %v", err, restoreErr)
		}
		if restoreErr := writeQuarantineAttrs(file, attrs); restoreErr != nil {
			return "", fmt.Errorf("isolate file: %w; restore original attributes: %v", err, restoreErr)
		}
		return "", fmt.Errorf("isolate file: %w", err)
	}
	if err := os.Chmod(target, 0o600); err != nil {
		return target, fmt.Errorf("lock quarantine file permissions: %w", err)
	}
	return target, nil
}

// moveRegularFile handles the common same-filesystem rename and the
// cross-filesystem case (for example a scan under a mounted data volume).
// The source was already verified and made non-executable by the caller.
func moveRegularFile(source, target string, src *os.File, info os.FileInfo, expectedSHA string) error {
	if err := os.Link(source, target); err == nil {
		linked, statErr := os.Lstat(target)
		if statErr != nil || !os.SameFile(info, linked) {
			_ = os.Remove(target)
			return errors.New("source changed while isolating file")
		}
	} else if !errors.Is(err, syscall.EXDEV) {
		return err
	} else {
		dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		copyErr := func() error {
			hash := sha256.New()
			n, err := io.Copy(io.MultiWriter(dst, hash), io.NewSectionReader(src, 0, info.Size()+1))
			if err != nil {
				return err
			}
			if n != info.Size() || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedSHA) {
				return errors.New("source changed while copying into quarantine")
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
	}
	current, err := os.Lstat(source)
	if err != nil || !os.SameFile(info, current) {
		_ = os.Remove(target)
		return errors.New("source changed before removing original path")
	}
	if err := verifyTrustedSourceParents(source); err != nil {
		_ = os.Remove(target)
		return fmt.Errorf("source parent changed before isolation: %w", err)
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(src, 0, info.Size()+1))
	if err != nil || n != info.Size() || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedSHA) {
		_ = os.Remove(target)
		return errors.New("source changed before removing original path")
	}
	if err := os.Remove(source); err != nil {
		_ = os.Remove(target)
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
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("cannot read deleted executable ownership")
	}
	if stat.Nlink != 0 {
		return "", errors.New("deleted executable still has hard links; cannot safely isolate all paths")
	}
	attrs, err := readQuarantineAttrs(src)
	if err != nil {
		return "", fmt.Errorf("read deleted executable attributes: %w", err)
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
	if err := os.Link(tmpPath, target); err != nil {
		return "", fmt.Errorf("store deleted process executable: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		_ = os.Remove(target)
		return "", fmt.Errorf("remove temporary executable snapshot: %w", err)
	}
	removeTemp = false
	metadata := quarantineMetadata{
		OriginalPath:     strings.TrimSuffix(strings.TrimSpace(finding.Executable), " (deleted)"),
		Restorable:       true,
		ScanID:           scanID,
		FindingID:        finding.ID,
		Rule:             finding.Rule,
		Severity:         finding.Severity,
		SHA256:           actualSHA,
		OriginalMode:     info.Mode().Perm().String(),
		OriginalModeBits: uint32(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)),
		ModeKnown:        true,
		OriginalUID:      int(stat.Uid),
		OriginalGID:      int(stat.Gid),
		OwnerKnown:       true,
		Attributes:       attrs,
		QuarantineMode:   "0600",
		Source:           "deleted-process-executable",
		DetectedAt:       finding.DetectedAt,
		QuarantinedAt:    time.Now().UTC(),
	}
	metadataFile, err := os.OpenFile(quarantineMetadataPath(target), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = os.Remove(target)
		return "", fmt.Errorf("create quarantine metadata: %w", err)
	}
	_, writeErr := metadataFile.Write(marshalQuarantineMetadata(metadata))
	if writeErr == nil {
		writeErr = metadataFile.Sync()
	}
	if closeErr := metadataFile.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(quarantineMetadataPath(target))
		_ = os.Remove(target)
		return "", fmt.Errorf("write quarantine metadata: %w", writeErr)
	}
	return target, nil
}

type quarantineMetadata struct {
	OriginalPath       string                   `json:"original_path"`
	Restorable         bool                     `json:"restorable"`
	ScanID             string                   `json:"scan_id"`
	FindingID          string                   `json:"finding_id"`
	Rule               string                   `json:"rule,omitempty"`
	Severity           string                   `json:"severity,omitempty"`
	SHA256             string                   `json:"sha256,omitempty"`
	OriginalMode       string                   `json:"original_mode,omitempty"`
	OriginalModeBits   uint32                   `json:"original_mode_bits,omitempty"`
	ModeKnown          bool                     `json:"mode_known,omitempty"`
	OriginalUID        int                      `json:"original_uid,omitempty"`
	OriginalGID        int                      `json:"original_gid,omitempty"`
	OwnerKnown         bool                     `json:"owner_known,omitempty"`
	Attributes         map[string][]byte        `json:"attributes,omitempty"`
	QuarantineMode     string                   `json:"quarantine_mode,omitempty"`
	Source             string                   `json:"source,omitempty"`
	StartupMaskPath    string                   `json:"startup_mask_path,omitempty"`
	StartupMaskOwned   bool                     `json:"startup_mask_owned,omitempty"`
	StartupBlockKind   string                   `json:"startup_block_kind,omitempty"`
	StartupBlockModule string                   `json:"startup_block_module,omitempty"`
	StartupLinks       []quarantinedStartupLink `json:"startup_links,omitempty"`
	ModuleName         string                   `json:"module_name,omitempty"`
	DetectedAt         time.Time                `json:"detected_at,omitempty"`
	QuarantinedAt      time.Time                `json:"quarantined_at,omitempty"`
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

func isStartupBlockFinding(finding securityscan.Finding) bool {
	if finding.Source != "file" || !securityscan.IsSystemdUnitPath(finding.Path) {
		return false
	}
	return isStartupPersistenceRule(finding.Rule)
}

func isStartupPersistenceRule(rule string) bool {
	switch rule {
	case "loader-persistence", "malware-persistence", "startup-loader", "startup-payload", "scheduled-miner", "suspicious-startup", "system-file-tamper", "clamav-signature":
		return true
	default:
		return false
	}
}

func isManualStartupFinding(finding securityscan.Finding) bool {
	if finding.Source != "file" || finding.Severity != securityscan.SeverityHigh || !isStartupPersistenceRule(finding.Rule) {
		return false
	}
	// Vendor systemd directories are package-owned and therefore excluded from
	// automatic quarantine, but an explicit operator action must still be able
	// to move a high-confidence malicious unit out of the boot path. A related
	// startup-payload finding receives the same guarded manual path.
	return securityscan.IsOperatorManagedStartupPath(finding.Path) ||
		securityscan.IsSystemdUnitPath(finding.Path) ||
		(strings.TrimSpace(finding.RelatedTo) != "" &&
			(finding.Rule == "startup-payload" || finding.Rule == "clamav-signature" || finding.Rule == "cryptominer"))
}

// sameStartupChainFinding joins duplicate systemd unit files that represent
// the same persisted payload. /lib and /usr/lib can contain both a real copy
// and a compatibility link, while package upgrades can temporarily leave two
// copies with the same bytes. An explicit quarantine of one high-confidence
// unit must handle those copies together; otherwise the remaining unit can
// recreate the process after reboot and the operator is forced to repeat a
// destructive action that was already confirmed.
func sameStartupChainFinding(parent, child securityscan.Finding) bool {
	if child.RelatedTo == parent.ID {
		return true
	}
	if parent.Source != "file" || child.Source != "file" ||
		!securityscan.IsSystemdUnitPath(parent.Path) || !securityscan.IsSystemdUnitPath(child.Path) {
		return false
	}
	if filepath.Base(filepath.Clean(parent.Path)) != filepath.Base(filepath.Clean(child.Path)) {
		return false
	}
	if parent.Rule != child.Rule || parent.Severity != child.Severity {
		return false
	}
	// Without a verified hash, two units with the same name may be an ordinary
	// vendor unit plus an operator override. Never remove both on name alone.
	return strings.TrimSpace(parent.SHA256) != "" &&
		strings.EqualFold(parent.SHA256, child.SHA256)
}

// normalizeManualSystemdFinding resolves a systemd unit symlink before the
// inode and hash checks. The symlink remains in place and becomes dangling
// while the target is quarantined; restoring the target therefore restores the
// original unit without manufacturing a new startup link.
func normalizeManualSystemdFinding(finding securityscan.Finding) (securityscan.Finding, error) {
	if finding.Source != "file" || !securityscan.IsSystemdUnitPath(finding.Path) {
		return finding, nil
	}
	path := filepath.Clean(strings.TrimSpace(finding.Path))
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return finding, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return finding, err
	}
	resolved = filepath.Clean(resolved)
	if !securityscan.IsSystemdUnitPath(resolved) {
		return finding, errors.New("systemd unit link resolves outside the systemd unit tree")
	}
	targetInfo, err := os.Lstat(resolved)
	if err != nil {
		return finding, err
	}
	if targetInfo.Mode()&os.ModeSymlink != 0 || !targetInfo.Mode().IsRegular() {
		return finding, errors.New("systemd unit link target is not a regular file")
	}
	finding.RelatedPaths = appendUniqueFindingPath(finding.RelatedPaths, path)
	finding.Path = resolved
	return finding, nil
}

func appendUniqueFindingPath(paths []string, path string) []string {
	for _, existing := range paths {
		if filepath.Clean(existing) == filepath.Clean(path) {
			return paths
		}
	}
	return append(paths, path)
}

// linkedStartupUnitAlreadyIsolated recognizes a second finding that is only a
// symlink to a unit already moved by the same quarantine action. It is safe to
// mark that row as handled because the dangling link cannot start anything;
// the target quarantine entry remains the single reversible artifact.
func linkedStartupUnitAlreadyIsolated(child, parent securityscan.Finding) bool {
	if !securityscan.IsSystemdUnitPath(child.Path) || parent.QuarantinePath == "" {
		return false
	}
	info, err := os.Lstat(child.Path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(child.Path)
	if err != nil {
		return false
	}
	resolved := filepath.Clean(target)
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Clean(filepath.Join(filepath.Dir(child.Path), resolved))
	}
	return resolved == filepath.Clean(parent.Path) ||
		(filepath.Base(resolved) == filepath.Base(filepath.Clean(parent.Path)) &&
			strings.EqualFold(child.SHA256, parent.SHA256))
}

func removeRecordedStartupBlock(metadata quarantineMetadata) error {
	if !metadata.StartupMaskOwned || strings.TrimSpace(metadata.StartupMaskPath) == "" {
		return nil
	}
	if metadata.StartupBlockKind == "modprobe" {
		return removeKernelModuleBlock(metadata.StartupMaskPath)
	}
	// Empty kind is the format used by older metadata and means systemd.
	return unblockSystemdStartup(metadata.StartupMaskPath)
}

func recreateRecordedStartupBlock(metadata quarantineMetadata, originalPath string) {
	// Older quarantine metadata may contain a NodeWall-owned mask. Restore
	// never recreates it: bringing the original startup file back must not
	// silently add a second persistence policy. The caller already removes an
	// owned legacy mask before restoring the file.
	_ = metadata
	_ = originalPath
}

type quarantineEntry struct {
	ID               string    `json:"id"`
	RelativePath     string    `json:"relative_path"`
	OriginalPath     string    `json:"original_path,omitempty"`
	Source           string    `json:"source,omitempty"`
	Restorable       bool      `json:"restorable"`
	QuarantinePath   string    `json:"quarantine_path"`
	ScanID           string    `json:"scan_id"`
	Name             string    `json:"name"`
	Size             int64     `json:"size"`
	Mode             string    `json:"mode"`
	OriginalModeBits uint32    `json:"original_mode_bits,omitempty"`
	ModuleName       string    `json:"module_name,omitempty"`
	ModuleLoadable   bool      `json:"module_loadable,omitempty"`
	ModuleLoaded     bool      `json:"module_loaded,omitempty"`
	ModifiedAt       time.Time `json:"modified_at"`
	QuarantinedAt    time.Time `json:"quarantined_at"`
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
		quarantinedAt := info.ModTime().UTC()
		// Older sidecars do not have quarantined_at, but their own mtime is
		// written when the quarantine operation completes. Prefer it over the
		// preserved payload mtime so upgraded installations also sort correctly.
		if metadataInfo, metadataStatErr := os.Stat(quarantineMetadataPath(path)); metadataStatErr == nil {
			quarantinedAt = metadataInfo.ModTime().UTC()
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
			QuarantinedAt:  quarantinedAt,
		}
		if metadata, metadataErr := readQuarantineMetadata(path); metadataErr == nil {
			quarantineItem.OriginalPath = metadata.OriginalPath
			quarantineItem.Source = metadata.Source
			quarantineItem.ModuleName = metadata.ModuleName
			quarantineItem.ModuleLoadable = metadata.Source == "kernel-module" && validKernelModuleName(metadata.ModuleName)
			quarantineItem.ModuleLoaded = quarantineItem.ModuleLoadable && kernelModuleLoaded(metadata.ModuleName)
			// Older metadata did not persist the restorable flag. An absolute
			// original path is sufficient evidence for the guarded restore path;
			// keep those entries recoverable after an upgrade. Evidence artifacts
			// are explicitly non-restorable even though they retain the source
			// path for audit display.
			quarantineItem.Restorable = metadata.Restorable ||
				(metadata.Source != "scan-evidence" && strings.TrimSpace(metadata.OriginalPath) != "")
			quarantineItem.OriginalModeBits = metadata.OriginalModeBits
			if !metadata.QuarantinedAt.IsZero() {
				quarantineItem.QuarantinedAt = metadata.QuarantinedAt.UTC()
			}
		}
		// Evidence artifacts remain identifiable even if an interrupted write
		// left their sidecar metadata incomplete. They are still audit-only and
		// must never become eligible for restore.
		if quarantineItem.Source == "" && strings.HasSuffix(entry.Name(), "-evidence.json") {
			quarantineItem.Source = "scan-evidence"
			quarantineItem.Restorable = false
		}
		entries = append(entries, quarantineItem)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].QuarantinedAt.Equal(entries[j].QuarantinedAt) {
			if entries[i].ModifiedAt.Equal(entries[j].ModifiedAt) {
				return entries[i].RelativePath < entries[j].RelativePath
			}
			return entries[i].ModifiedAt.After(entries[j].ModifiedAt)
		}
		return entries[i].QuarantinedAt.After(entries[j].QuarantinedAt)
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
	metadata, metadataErr := readQuarantineMetadata(path)
	if metadataErr == nil && metadata.StartupMaskOwned && metadata.StartupMaskPath != "" {
		if err := removeRecordedStartupBlock(metadata); err != nil {
			writeError(w, http.StatusConflict, fmt.Errorf("remove startup block before permanent delete: %w", err))
			return
		}
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
	metadata, err := readQuarantineMetadata(path)
	if err != nil {
		writeError(w, http.StatusConflict, fmt.Errorf("read quarantine metadata: %w", err))
		return
	}
	blockRemoved := false
	if metadata.StartupMaskOwned && metadata.StartupMaskPath != "" {
		if err := removeRecordedStartupBlock(metadata); err != nil {
			writeError(w, http.StatusConflict, fmt.Errorf("remove startup block before restore: %w", err))
			return
		}
		blockRemoved = true
	}
	recreateMask := func() {
		if blockRemoved {
			recreateRecordedStartupBlock(metadata, originalPath)
		}
	}
	if info, statErr := os.Lstat(originalPath); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			recreateMask()
			writeError(w, http.StatusConflict, errors.New("restore target exists and is not a regular file"))
			return
		}
		recreateMask()
		writeError(w, http.StatusConflict, errors.New("restore target already exists; remove it or choose manual recovery"))
		return
	} else if !errors.Is(statErr, os.ErrNotExist) {
		recreateMask()
		writeError(w, http.StatusInternalServerError, statErr)
		return
	}
	if info, statErr := os.Lstat(path); statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		recreateMask()
		writeError(w, http.StatusNotFound, errors.New("quarantine entry is no longer a regular file"))
		return
	}
	if err := restoreQuarantineFile(path, originalPath, metadata); err != nil {
		recreateMask()
		writeError(w, http.StatusInternalServerError, fmt.Errorf("restore file: %w", err))
		return
	}
	// Restoring a quarantined unit also restores its former enablement links,
	// but daemon-reload never starts the service. The operator must explicitly
	// start it after reviewing the restored payload.
	if err := restoreSystemdStartupLinks(metadata); err != nil {
		writeError(w, http.StatusConflict, fmt.Errorf("restore systemd enablement links: %w", err))
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
				h.securityJob.Findings[index].StartupBlocked = false
				h.securityJob.Findings[index].StartupBlockPath = ""
				h.securityJob.Findings[index].ModuleUnloaded = false
			}
		}
		_ = h.archiveCurrentScan()
	}
	h.securityMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"node_id": h.nodeID, "status": "restored", "original_path": originalPath, "entry": entry})
}

// verifyQuarantinePayload checks the sidecar hash immediately before a
// quarantined kernel module is loaded. The module remains in the quarantine
// directory; loading it never republishes an untrusted payload into a boot or
// module search path.
func verifyQuarantinePayload(path string, metadata quarantineMetadata) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("隔离条目不是普通文件")
	}
	if info.Size() > maxDeletedProcessSnapshot {
		return fmt.Errorf("隔离模块超过 %d 字节，拒绝加载", maxDeletedProcessSnapshot)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return err
	}
	if metadata.SHA256 == "" || written != info.Size() || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), metadata.SHA256) {
		return errors.New("隔离模块校验值已变化，拒绝加载")
	}
	return nil
}

func (h *AgentHandler) updateQuarantinedModuleState(path string, loaded bool, method string) {
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil {
		return
	}
	for index := range h.securityJob.Findings {
		finding := &h.securityJob.Findings[index]
		if finding.QuarantinePath != path {
			continue
		}
		finding.ModuleUnloaded = !loaded
		if loaded {
			finding.ContainmentEvidence = fmt.Sprintf("已从隔离区使用 %s 加载模块；模块文件仍保留在隔离区", method)
		} else {
			finding.ContainmentEvidence = fmt.Sprintf("已使用 %s 卸载模块；模块文件仍保留在隔离区", method)
		}
		_ = h.archiveCurrentScan()
		return
	}
}

// handleSecurityQuarantineModuleLoad explicitly loads a quarantined module
// for rollback or controlled investigation. It is intentionally separate from
// file restore so the original path and boot configuration are never changed.
func (h *AgentHandler) handleSecurityQuarantineModuleLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
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
	metadata, err := readQuarantineMetadata(path)
	if err != nil || metadata.Source != "kernel-module" || !validKernelModuleName(metadata.ModuleName) {
		writeError(w, http.StatusConflict, errors.New("只有带有可信模块元数据的隔离模块才能加载"))
		return
	}
	if err := verifyQuarantinePayload(path, metadata); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	securityKernelModuleMu.Lock()
	method, err := loadKernelModule(metadata.ModuleName, path)
	securityKernelModuleMu.Unlock()
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	h.updateQuarantinedModuleState(path, true, method)
	entry.ModuleLoaded = true
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": h.nodeID, "status": "module_loaded", "module_name": metadata.ModuleName,
		"method": method, "entry": entry,
	})
}

// handleSecurityQuarantineModuleUnload is the inverse of module loading. The
// quarantined payload is retained, so a later explicit load can reproduce the
// same rollback/investigation state.
func (h *AgentHandler) handleSecurityQuarantineModuleUnload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
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
	metadata, err := readQuarantineMetadata(path)
	if err != nil || metadata.Source != "kernel-module" || !validKernelModuleName(metadata.ModuleName) {
		writeError(w, http.StatusConflict, errors.New("只有带有可信模块元数据的隔离模块才能卸载"))
		return
	}
	securityKernelModuleMu.Lock()
	if !kernelModuleLoaded(metadata.ModuleName) {
		securityKernelModuleMu.Unlock()
		entry.ModuleLoaded = false
		writeJSON(w, http.StatusOK, map[string]any{"node_id": h.nodeID, "status": "already_unloaded", "module_name": metadata.ModuleName, "entry": entry})
		return
	}
	method, err := unloadKernelModule(metadata.ModuleName, filepath.Join("/sys/module", metadata.ModuleName))
	securityKernelModuleMu.Unlock()
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	h.updateQuarantinedModuleState(path, false, method)
	entry.ModuleLoaded = false
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": h.nodeID, "status": "module_unloaded", "module_name": metadata.ModuleName,
		"method": method, "entry": entry,
	})
}

func (h *AgentHandler) handleSecurityQuarantine(w http.ResponseWriter, r *http.Request) {
	findingID := strings.TrimSpace(r.PathValue("finding"))
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil || (h.securityJob.Status != "completed" && h.securityJob.Status != "cancelled" && h.securityJob.Status != "failed") {
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
	if finding.Quarantined {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "already_quarantined",
			"path":   finding.QuarantinePath,
			"scan":   cloneSecurityScanView(h.securityJob),
		})
		return
	}
	if finding.Rule == "hidden-kernel-module" {
		target, startupPath, unloadMethod, isolateErr, unloadErr := containKernelModuleAction(finding, scanID)
		if isolateErr != nil && unloadErr != nil {
			writeError(w, http.StatusConflict, isolateErr)
			return
		}
		if index < len(h.securityJob.Findings) && h.securityJob.Findings[index].ID == findingID {
			updated := &h.securityJob.Findings[index]
			updated.StartupBlocked = false
			updated.StartupBlockPath = startupPath
			updated.StartupBlockOwned = false
			updated.ModuleUnloaded = unloadErr == nil
			updated.ContainmentEvidence = fmt.Sprintf("sysfs 对象 %s 仅作为运行态证据；未写入新的启动阻断策略", finding.Path)
			if unloadErr == nil {
				updated.ContainmentEvidence += fmt.Sprintf("；已由扫描器执行 %s 卸载当前内存模块", unloadMethod)
			}
			if isolateErr == nil && target != "" {
				updated.Quarantined = true
				updated.QuarantinePath = target
				updated.ContainmentEvidence += fmt.Sprintf("；已隔离模块文件 %s", target)
			} else if isolateErr != nil && unloadErr == nil {
				updated.ContainmentBlockedReason = isolateErr.Error()
				updated.ContainmentEvidence += "；未保存磁盘样本"
			} else if isolateErr != nil {
				updated.ContainmentBlockedReason = isolateErr.Error()
			}
			if unloadErr != nil {
				if updated.ContainmentBlockedReason == "" {
					updated.ContainmentBlockedReason = unloadErr.Error()
				} else {
					updated.ContainmentBlockedReason += "；" + unloadErr.Error()
				}
			}
			_ = h.archiveCurrentScan()
		}
		view := cloneSecurityScanView(h.securityJob)
		status := "module_unloaded"
		switch {
		case target != "" && unloadErr == nil:
			status = "quarantined"
		case target != "" && unloadErr != nil:
			status = "quarantined_module_running"
		case unloadErr != nil:
			status = "containment_incomplete"
		}
		response := map[string]any{"status": status, "path": target, "startup_block": "", "module_unloaded": unloadErr == nil, "scan": view}
		if isolateErr != nil {
			response["containment_warning"] = isolateErr.Error()
		}
		if unloadErr != nil {
			response["module_unload_warning"] = unloadErr.Error()
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if normalized, normalizeErr := normalizeManualSystemdFinding(finding); normalizeErr != nil {
		writeError(w, http.StatusConflict, fmt.Errorf("resolve systemd unit before isolation: %w", normalizeErr))
		return
	} else {
		finding = normalized
		h.securityJob.Findings[index] = normalized
	}
	if finding.Source != "file" && !(finding.Source == "" && finding.PID == 0 && strings.TrimSpace(finding.Path) != "") {
		writeError(w, http.StatusConflict, errors.New("only regular file findings can be manually isolated; process evidence requires process handling"))
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
	target, err := isolateFindingManually(finding, scanID)
	if target != "" && h.securityJob != nil && index < len(h.securityJob.Findings) && h.securityJob.Findings[index].ID == findingID {
		h.securityJob.Findings[index].Quarantined = true
		h.securityJob.Findings[index].QuarantinePath = target
		h.securityJob.Findings[index].ContainmentEvidence = containmentEvidence(finding, target)
		h.securityJob.Findings[index].StartupBlocked = false
		h.securityJob.Findings[index].StartupBlockPath = ""
		h.securityJob.Findings[index].StartupBlockOwned = false
		// A suspicious systemd unit and its ExecStart payload form one
		// persistence chain. Moving only the unit leaves a root executable on
		// disk that another loader can invoke, while moving only the executable
		// leaves a boot entry that can be repopulated. Explicit quarantine of the
		// unit therefore also moves related file findings when they are present.
		var chainErrors []string
		if securityscan.IsSystemdUnitPath(finding.Path) {
			for childIndex := range h.securityJob.Findings {
				child := h.securityJob.Findings[childIndex]
				if child.ID == finding.ID || child.Source != "file" || child.Quarantined || !sameStartupChainFinding(finding, child) {
					continue
				}
				if linkedStartupUnitAlreadyIsolated(child, finding) {
					h.securityJob.Findings[childIndex].Quarantined = true
					h.securityJob.Findings[childIndex].QuarantinePath = target
					h.securityJob.Findings[childIndex].ContainmentEvidence = "同一启动单元的软链接已随目标文件处置；恢复目标文件即可恢复该链接"
					continue
				}
				normalizedChild, normalizeErr := normalizeManualSystemdFinding(child)
				if normalizeErr != nil {
					chainErrors = append(chainErrors, fmt.Sprintf("%s: %v", child.Path, normalizeErr))
					continue
				}
				child = normalizedChild
				h.securityJob.Findings[childIndex] = normalizedChild
				childTarget, childErr := isolateFindingManually(child, scanID)
				if childErr != nil {
					chainErrors = append(chainErrors, fmt.Sprintf("%s: %v", child.Path, childErr))
					continue
				}
				if childTarget == "" {
					continue
				}
				h.securityJob.Findings[childIndex].Quarantined = true
				h.securityJob.Findings[childIndex].QuarantinePath = childTarget
				h.securityJob.Findings[childIndex].ContainmentEvidence = containmentEvidence(child, childTarget)
			}
		}
		_ = h.archiveCurrentScan()
		view := cloneSecurityScanView(h.securityJob)
		response := map[string]any{"status": "quarantined", "path": target, "scan": view}
		if len(chainErrors) > 0 {
			response["chain_warnings"] = chainErrors
		}
		writeJSON(w, http.StatusOK, response)
		return
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
		Mode:       job.Mode,
		FinishedAt: job.FinishedAt, FilesScanned: job.FilesScanned, BytesScanned: job.BytesScanned,
		FilesSkipped: job.FilesSkipped, MountsSkipped: job.MountsSkipped, ReadErrors: job.ReadErrors, Phase: job.Phase,
		Findings: cloneSecurityFindings(job.Findings), Truncated: job.Truncated, Error: job.Error, ArchiveError: job.ArchiveError,
		CoverageGaps: append([]securityscan.CoverageGap(nil), job.CoverageGaps...), CoverageGapsOmitted: job.CoverageGapsOmitted,
		SignatureEngine: job.SignatureEngine,
		AutoQuarantine:  job.AutoQuarantine, AutoTerminateProcesses: job.AutoTerminateProcesses,
		QuarantineErrors: append([]string(nil), job.QuarantineErrors...),
	}
}

func cloneSecurityFindings(findings []securityscan.Finding) []securityscan.Finding {
	result := append([]securityscan.Finding(nil), findings...)
	for i := range result {
		result[i].RelatedPaths = append([]string(nil), findings[i].RelatedPaths...)
		result[i].Indicators = append([]string(nil), findings[i].Indicators...)
		result[i].StartupBlocks = append([]securityscan.StartupBlock(nil), findings[i].StartupBlocks...)
		result[i].StartupCandidates = append([]string(nil), findings[i].StartupCandidates...)
	}
	return result
}

// publishSecurityScan keeps only the latest snapshot for each subscriber. A
// slow client must receive a terminal status instead of a queue of stale updates.
func (h *AgentHandler) publishSecurityScan(jobID string) {
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil || h.securityJob.ID != jobID || len(h.securityScanSubscribers) == 0 {
		return
	}
	view := cloneSecurityScanView(h.securityJob)
	view.NodeID = h.nodeID
	for subscriber := range h.securityScanSubscribers {
		select {
		case subscriber <- view:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- view:
			default:
			}
		}
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
