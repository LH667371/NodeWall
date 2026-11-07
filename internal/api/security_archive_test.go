package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodewall/internal/securityscan"
	"nodewall/internal/xdp"
)

func TestScanReportsSurviveRestartAndDownloadByID(t *testing.T) {
	dir := t.TempDir()
	newHandler := func() *AgentHandler {
		h := NewAgentHandler("node-a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
		if err := h.ConfigureSecurityArchive(dir); err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := newHandler()
	for i, id := range []string{"scan-first", "scan-second"} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "example.php"), []byte("<?php eval(base64_decode($_POST['x'])); ?>"), 0o600); err != nil {
			t.Fatal(err)
		}
		h.securityJob = &securityScanJob{ID: id, Root: root, Status: "running", StartedAt: time.Now().Add(time.Duration(i-2) * time.Minute)}
		if err := h.archiveCurrentScan(); err != nil {
			t.Fatal(err)
		}
		h.runSecurityScan(id, root)
		if h.securityJob.Status != "completed" || h.securityJob.ArchiveError != "" {
			t.Fatalf("scan was not persisted: %#v", h.securityJob)
		}
	}
	h = newHandler()
	if h.securityJob.ID != "scan-second" || len(h.securityJob.Findings) != 1 {
		t.Fatal("latest result was not restored")
	}
	routes := h.Routes()
	response := httptest.NewRecorder()
	routes.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/security/scan/reports", nil))
	var list struct {
		Reports []scanReportSummary `json:"reports"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Reports) != 2 || list.Reports[0].ID != "scan-second" {
		t.Fatalf("lost historical reports: %s", response.Body.String())
	}
	for _, format := range []string{"json", "html"} {
		response = httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/security/scan/reports/scan-first?format="+format, nil))
		if response.Code != 200 || !strings.Contains(response.Header().Get("Content-Disposition"), "scan-first."+format) || !strings.Contains(response.Body.String(), "example.php") {
			t.Fatalf("wrong historical download: %d %s", response.Code, response.Body.String())
		}
	}
	response = httptest.NewRecorder()
	routes.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/security/scan/reports/scan-missing", nil))
	if response.Code != 404 {
		t.Fatalf("missing report returned %d", response.Code)
	}
}

func TestScanArchiveRetentionPreservesUnrelatedFilesAndDamagedReports(t *testing.T) {
	dir := t.TempDir()
	h := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := h.ConfigureSecurityArchive(dir); err != nil {
		t.Fatal(err)
	}
	for i := range scanReportLimit + 1 {
		h.securityReports[fmt.Sprintf("scan-%d", i)] = scanReportSummary{ID: fmt.Sprintf("scan-%d", i), StartedAt: time.Unix(int64(i), 0), Status: "completed"}
	}
	old := filepath.Join(dir, "scan-0.json")
	if err := os.WriteFile(old, []byte("oldest"), 0o600); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(dir, "operator-notes.txt")
	if err := os.WriteFile(notes, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.pruneScanReports(); err != nil {
		t.Fatal(err)
	}
	if len(h.securityReports) != scanReportLimit {
		t.Fatal("report retention limit ignored")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("oldest managed report not pruned")
	}
	if err := os.WriteFile(filepath.Join(dir, "scan-damaged.json"), []byte("interrupted-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := restarted.ConfigureSecurityArchive(dir); err != nil {
		t.Fatal("a damaged report prevented agent startup:", err)
	}
	if restarted.securityArchiveWarning == "" {
		t.Fatal("archive damage was hidden")
	}
	for _, path := range []string{notes, filepath.Join(dir, "scan-damaged.json")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("unrelated or damaged data was deleted:", err)
		}
	}
}

func TestScanArchivePreservesSkippedCounts(t *testing.T) {
	dir := t.TempDir()
	h := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := h.ConfigureSecurityArchive(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "too-large")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	h.securityScanner.MaxFileSize = 10
	h.securityJob = &securityScanJob{ID: "scan-skipped", Status: "running", Root: path, StartedAt: time.Now().UTC()}
	h.runSecurityScan("scan-skipped", path)
	report, err := h.readArchivedScan("scan-skipped")
	if err != nil || report.FilesScanned != 0 || report.FilesSkipped != 1 || !report.Truncated {
		t.Fatalf("skipped coverage lost: %#v %v", report, err)
	}
}

func TestScanArchiveMarksInterruptedJobAndRejectsForeignFiles(t *testing.T) {
	dir := t.TempDir()
	h := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := h.ConfigureSecurityArchive(dir); err != nil {
		t.Fatal(err)
	}
	h.securityJob = &securityScanJob{ID: "scan-interrupted", Status: "running", StartedAt: time.Now().UTC(), Findings: []securityscan.Finding{}}
	if err := h.archiveCurrentScan(); err != nil {
		t.Fatal(err)
	}
	restarted := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := restarted.ConfigureSecurityArchive(dir); err != nil {
		t.Fatal(err)
	}
	if restarted.securityJob.Status != "failed" || restarted.securityJob.FinishedAt == nil || !strings.Contains(restarted.securityJob.Error, "restarted") {
		t.Fatal("interrupted scan still appears to be running")
	}
	if _, err := h.readArchivedScan("../../secrets"); err == nil {
		t.Fatal("path traversal was accepted")
	}
	foreign := buildSecurityScanReport("another-node", cloneSecurityScanView(h.securityJob))
	foreign.ReportID = "scan-foreign"
	if err := h.saveScanReport(foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := h.readArchivedScan("scan-foreign"); err == nil {
		t.Fatal("another node's report was accepted")
	}
}

func TestScanStartRequiresDurableArchive(t *testing.T) {
	dir := t.TempDir()
	h := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := h.ConfigureSecurityArchive(dir); err != nil {
		t.Fatal(err)
	}
	h.securityJob = &securityScanJob{ID: "scan-previous", Status: "completed"}
	// A file in place of the directory reliably fails even when tests run as root.
	h.securityArchiveDir = filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(h.securityArchiveDir, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"path": t.TempDir()})
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/security/scan", strings.NewReader(string(body))))
	if response.Code != 500 || h.securityJob.ID != "scan-previous" {
		t.Fatal("failed persistence lost the previous scan or started untracked work")
	}
}

func TestUnavailableScanStorageDoesNotDisableAgent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := h.ConfigureSecurityArchive(path); err == nil {
		t.Fatal("invalid storage was accepted")
	}
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil))
	if response.Code != 200 {
		t.Fatal("report storage failure disabled agent health")
	}
	response = httptest.NewRecorder()
	h.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/security/scan", strings.NewReader(`{"path":"/"}`)))
	if response.Code != 503 || h.securityJob != nil {
		t.Fatal("a scan started without durable tracking")
	}
}
