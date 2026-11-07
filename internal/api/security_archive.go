package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var scanReportID = regexp.MustCompile(`^scan-[a-zA-Z0-9_-]{1,80}$`)

// Reports are bounded by count rather than silently overwritten by the next
// scan. Only files matching NodeWall's own report IDs are retention targets.
const scanReportLimit = 500

type scanReportSummary struct {
	ID            string     `json:"id"`
	Status        string     `json:"status"`
	Root          string     `json:"root"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	FilesScanned  uint64     `json:"files_scanned"`
	FindingsCount int        `json:"findings_count"`
	Truncated     bool       `json:"truncated"`
}

// ConfigureSecurityArchive is called before serving requests. An interrupted
// job is retained as failed rather than forever appearing to be running.
func (h *AgentHandler) ConfigureSecurityArchive(dir string) (resultErr error) {
	defer func() {
		if resultErr != nil {
			h.securityArchiveUnavailable = resultErr.Error()
			h.securityArchiveDir = ""
			h.securityReports = nil
			h.securityJob = nil
		}
	}()
	if strings.TrimSpace(dir) == "" {
		return errors.New("scan report directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	h.securityArchiveDir = dir
	h.securityArchiveUnavailable = ""
	h.securityReports = make(map[string]scanReportSummary)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var latest securityScanReport
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !strings.HasSuffix(entry.Name(), ".json") || !scanReportID.MatchString(id) {
			continue
		}
		report, err := h.readArchivedScan(id)
		if err != nil {
			// A damaged report must not stop the firewall/SSH agent. Keep the
			// original file for recovery and make the archive warning visible.
			h.securityArchiveWarning = "some scan reports could not be loaded; check the agent log"
			log.Printf("warning: load scan report %s: %v", id, err)
			continue
		}
		if report.Status == "running" {
			now := time.Now().UTC()
			report.Status, report.Error, report.FinishedAt = "failed", "agent restarted before the scan completed", &now
			if err := h.saveScanReport(report); err != nil {
				return err
			}
		}
		h.securityReports[id] = summarizeScan(report)
		if latest.ReportID == "" || report.StartedAt.After(latest.StartedAt) {
			latest = report
		}
	}
	if latest.ReportID != "" {
		view := scanReportView(latest)
		h.securityJob = scanViewJob(view)
	}
	return h.pruneScanReports()
}

func scanReportView(report securityScanReport) securityScanView {
	return securityScanView{NodeID: report.NodeID, ID: report.ReportID, Status: report.Status, Root: report.Root,
		StartedAt: report.StartedAt, FinishedAt: report.FinishedAt, FilesScanned: report.FilesScanned,
		BytesScanned: report.BytesScanned, FilesSkipped: report.FilesSkipped, ReadErrors: report.ReadErrors,
		Findings: report.Findings, Truncated: report.Truncated, Error: report.Error,
		AutoQuarantine: report.AutoQuarantine, AutoTerminateProcesses: report.AutoTerminateProcesses,
		QuarantineErrors: append([]string(nil), report.QuarantineErrors...)}
}

func scanViewJob(view securityScanView) *securityScanJob {
	return &securityScanJob{NodeID: view.NodeID, ID: view.ID, Status: view.Status, Root: view.Root,
		StartedAt: view.StartedAt, FinishedAt: view.FinishedAt, FilesScanned: view.FilesScanned,
		BytesScanned: view.BytesScanned, FilesSkipped: view.FilesSkipped, ReadErrors: view.ReadErrors,
		Findings: view.Findings, Truncated: view.Truncated, Error: view.Error,
		AutoQuarantine: view.AutoQuarantine, AutoTerminateProcesses: view.AutoTerminateProcesses,
		QuarantineErrors: append([]string(nil), view.QuarantineErrors...)}
}

func summarizeScan(report securityScanReport) scanReportSummary {
	return scanReportSummary{ID: report.ReportID, Status: report.Status, Root: report.Root,
		StartedAt: report.StartedAt, FinishedAt: report.FinishedAt, FilesScanned: report.FilesScanned,
		FindingsCount: report.FindingsCount, Truncated: report.Truncated}
}

// saveScanReport must run under securityMu once the handler is serving. The
// temporary file is synced and renamed before the report index is updated.
func (h *AgentHandler) saveScanReport(report securityScanReport) error {
	if h.securityArchiveDir == "" {
		return nil // In-memory handlers remain useful in unit tests and demos.
	}
	if !scanReportID.MatchString(report.ReportID) {
		return errors.New("invalid scan report ID")
	}
	file, err := os.CreateTemp(h.securityArchiveDir, ".scan-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	err = json.NewEncoder(file).Encode(report)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(h.securityArchiveDir, report.ReportID+".json")); err != nil {
		return err
	}
	dir, err := os.Open(h.securityArchiveDir)
	if err != nil {
		return err
	}
	err = errors.Join(dir.Sync(), dir.Close())
	if err != nil {
		return err
	}
	h.securityReports[report.ReportID] = summarizeScan(report)
	return nil
}

func (h *AgentHandler) readArchivedScan(id string) (securityScanReport, error) {
	var report securityScanReport
	if !scanReportID.MatchString(id) {
		return report, errors.New("invalid scan report ID")
	}
	if h.securityArchiveDir == "" {
		return report, os.ErrNotExist
	}
	path := filepath.Join(h.securityArchiveDir, id+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return report, err
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return report, errors.New("scan report is not a regular file or exceeds the size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return report, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, (8<<20)+1))
	if err := decoder.Decode(&report); err != nil {
		return report, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return report, errors.New("scan report contains trailing or invalid data")
	}
	if report.ReportID != id || report.NodeID != h.nodeID {
		return report, errors.New("scan report identity does not match this node")
	}
	return report, nil
}

func (h *AgentHandler) scanReportList() []scanReportSummary {
	result := make([]scanReportSummary, 0, len(h.securityReports))
	for _, report := range h.securityReports {
		result = append(result, report)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].StartedAt.Equal(result[j].StartedAt) {
			return result[i].ID > result[j].ID
		}
		return result[i].StartedAt.After(result[j].StartedAt)
	})
	return result
}

func (h *AgentHandler) pruneScanReports() error {
	list := h.scanReportList()
	for _, report := range list[min(len(list), scanReportLimit):] {
		if report.Status == "running" {
			continue
		}
		if err := os.Remove(filepath.Join(h.securityArchiveDir, report.ID+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		delete(h.securityReports, report.ID)
	}
	return nil
}

func (h *AgentHandler) archiveCurrentScan() error {
	err := h.saveScanReport(buildSecurityScanReport(h.nodeID, cloneSecurityScanView(h.securityJob)))
	if err == nil {
		err = h.pruneScanReports()
	}
	if err != nil {
		h.securityJob.ArchiveError = err.Error()
	} else {
		h.securityJob.ArchiveError = ""
	}
	return err
}
