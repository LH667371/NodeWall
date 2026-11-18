package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"nodewall/internal/securityscan"
	"nodewall/internal/xdp"
)

func TestSecurityScanRoutesUseBuiltInScanner(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "shell.php")
	if err := os.WriteFile(path, []byte("<?php eval(base64_decode($_POST['x'])); ?>"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)

	start := httptest.NewRequest(http.MethodPost, "/security/scan", strings.NewReader(`{"path":"`+root+`"}`))
	started := httptest.NewRecorder()
	handler.Routes().ServeHTTP(started, start)
	if started.Code != http.StatusAccepted {
		t.Fatalf("unexpected start status: %d body=%s", started.Code, started.Body.String())
	}

	var status struct {
		Status   string `json:"status"`
		Findings []struct {
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	for attempt := 0; attempt < 50; attempt++ {
		get := httptest.NewRequest(http.MethodGet, "/security/scan", nil)
		response := httptest.NewRecorder()
		handler.Routes().ServeHTTP(response, get)
		if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status.Status != "completed" || len(status.Findings) != 1 || status.Findings[0].Rule != "webshell" {
		t.Fatalf("unexpected scan result: %#v", status)
	}

	jsonReport := httptest.NewRecorder()
	handler.Routes().ServeHTTP(jsonReport, httptest.NewRequest(http.MethodGet, "/security/scan/report?format=json", nil))
	if jsonReport.Code != http.StatusOK {
		t.Fatalf("unexpected json report status: %d body=%s", jsonReport.Code, jsonReport.Body.String())
	}
	if got := jsonReport.Header().Get("Content-Disposition"); !strings.Contains(got, "attachment") || !strings.HasSuffix(got, ".json\"") {
		t.Fatalf("unexpected json report disposition: %q", got)
	}
	var report struct {
		FindingsCount  int            `json:"findings_count"`
		SeverityCounts map[string]int `json:"severity_counts"`
	}
	if err := json.Unmarshal(jsonReport.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.FindingsCount != 1 || report.SeverityCounts["high"] != 1 {
		t.Fatalf("unexpected json report: %#v", report)
	}

	htmlReport := httptest.NewRecorder()
	handler.Routes().ServeHTTP(htmlReport, httptest.NewRequest(http.MethodGet, "/security/scan/report?format=html", nil))
	if htmlReport.Code != http.StatusOK || !strings.Contains(htmlReport.Body.String(), "NodeWall 扫描报告") || !strings.Contains(htmlReport.Body.String(), "shell.php") {
		t.Fatalf("unexpected html report: status=%d body=%s", htmlReport.Code, htmlReport.Body.String())
	}
	if got := htmlReport.Header().Get("Content-Disposition"); !strings.Contains(got, ".html\"") {
		t.Fatalf("unexpected html report disposition: %q", got)
	}

}

func TestIsolateFindingRemovesExecutePermission(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	path := filepath.Join(t.TempDir(), "payload.sh")
	payload := []byte("#!/bin/sh\necho quarantined\n")
	if err := os.WriteFile(path, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	finding := securityscan.Finding{
		ID: "f-permission", Path: path, Rule: "download-and-execute", Severity: securityscan.SeverityHigh,
		SHA256: hex.EncodeToString(sum[:]), Size: info.Size(), Mode: info.Mode().Perm().String(),
		Quarantinable: true,
	}
	target, err := isolateFinding(finding, "scan-permission")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("original payload still exists: %v", err)
	}
	quarantineInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := quarantineInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("quarantine payload mode = %04o, want 0600", got)
	}
	if quarantineInfo.Mode().Perm()&0o111 != 0 {
		t.Fatalf("quarantine payload remains executable: %v", quarantineInfo.Mode())
	}
}

func TestManualQuarantineAllowsEvidenceOnlyFile(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	path := filepath.Join(t.TempDir(), "evidence.sh")
	payload := []byte("#!/bin/sh\necho review\n")
	if err := os.WriteFile(path, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{
		ID: "scan-manual", Status: "completed",
		Findings: []securityscan.Finding{{
			ID: "f-manual", Path: path, Rule: "dangerous-command", Severity: securityscan.SeverityMedium,
			SHA256: hex.EncodeToString(sum[:]), Size: info.Size(), Mode: info.Mode().Perm().String(), Source: "file",
		}},
	}
	request := httptest.NewRequest(http.MethodPost, "/security/scan/f-manual/quarantine", nil)
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("manual quarantine status = %d body=%s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("manual quarantine left the original file: %v", err)
	}
	if !h.securityJob.Findings[0].Quarantined || h.securityJob.Findings[0].QuarantinePath == "" {
		t.Fatalf("manual quarantine did not update finding: %#v", h.securityJob.Findings[0])
	}
}

func TestIgnoreSecurityFinding(t *testing.T) {
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{
		ID: "scan-ignore", Status: "completed",
		Findings: []securityscan.Finding{{ID: "f-ignore", Path: "/tmp/evidence", Source: "file"}},
	}
	request := httptest.NewRequest(http.MethodPost, "/security/scan/f-ignore/ignore", nil)
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ignore status = %d body=%s", response.Code, response.Body.String())
	}
	if !h.securityJob.Findings[0].Ignored {
		t.Fatal("ignore did not update finding")
	}
}

func TestQuarantineFindingIsIdempotentAfterAnotherWebAlreadyHandledIt(t *testing.T) {
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{
		ID: "scan-idempotent", Status: "completed",
		Findings: []securityscan.Finding{{
			ID: "f-already", Path: "/usr/lib/systemd/system/8a6589cd.service", Source: "file",
			Rule: "malware-persistence", Severity: securityscan.SeverityHigh,
			Quarantined: true, QuarantinePath: "/var/lib/nodewall/quarantine/scan-idempotent/f-already-unit",
		}},
	}
	request := httptest.NewRequest(http.MethodPost, "/security/scan/f-already/quarantine", nil)
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("idempotent quarantine status = %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "already_quarantined") {
		t.Fatalf("idempotent quarantine response did not report existing containment: %s", response.Body.String())
	}
}

func TestProcessFindingsRemainEvidenceWithoutStableIdentity(t *testing.T) {
	for _, finding := range []securityscan.Finding{
		{Rule: "cgroup-hidden-process", Executable: "/var/lib/zstack/virtualenv/kvm/bin/python2"},
		{Rule: "hidden-process", Executable: "/opt/service/bin/worker"},
		{Rule: "high-cpu-process", Executable: "/opt/service/bin/worker", Severity: securityscan.SeverityHigh, Quarantinable: true},
		{Rule: "cryptominer", Executable: "/b7a390bb", Severity: securityscan.SeverityHigh, Deleted: true, SHA256: strings.Repeat("a", 64)},
		{Rule: "deleted-executable", Executable: "/usr/lib/systemd/systemd-journald", Deleted: true},
	} {
		finding.Source, finding.PID = "process", 42
		if automaticProcessContainmentEligible(finding) {
			t.Errorf("finding without stable process identity was eligible: %#v", finding)
		}
	}
}

func TestStaleAutomaticContainmentRequestDoesNotIsolateExecutable(t *testing.T) {
	payload := filepath.Join(t.TempDir(), "python2")
	if err := os.WriteFile(payload, []byte("legitimate service"), 0o700); err != nil {
		t.Fatal(err)
	}
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{
		ID: "scan-containment", Status: "running", AutoTerminateProcesses: true,
		Findings: []securityscan.Finding{{
			ID: "p-test", Path: payload, Executable: payload, Rule: "cgroup-hidden-process",
			Severity: securityscan.SeverityHigh, Source: "process", PID: 42, Quarantinable: true,
		}},
	}
	h.containProcessFinding("scan-containment", "p-test")
	if _, err := os.Stat(payload); err != nil {
		t.Fatalf("evidence-only process executable was changed: %v", err)
	}
	if finding := h.securityJob.Findings[0]; finding.Terminated || finding.Quarantined || finding.Termination != nil {
		t.Fatalf("stale automatic action changed process finding: %#v", finding)
	}
}

func TestQuickScanEnablesVerifiedMinerContainment(t *testing.T) {
	if runtime.GOOS == "linux" && os.Getenv("NODEWALL_SCAN_ISOLATED_TEST") != "1" {
		t.Skip("quick scan may act on other processes; run only in an isolated PID namespace")
	}
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	request := httptest.NewRequest(http.MethodPost, "/security/scan", strings.NewReader(`{"path":"/","mode":"process","auto_terminate_processes":true}`))
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("start scan: status=%d body=%s", response.Code, response.Body.String())
	}
	var view securityScanView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.AutoTerminateProcesses {
		t.Fatal("quick scan did not enable verified miner containment")
	}
	if !view.AutoQuarantine {
		t.Fatal("quick scan did not enable recoverable file/evidence isolation")
	}
	for attempt := 0; attempt < 300; attempt++ {
		h.securityMu.RLock()
		running := h.securityJob.Status == "running"
		h.securityMu.RUnlock()
		if !running {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("quick scan did not finish")
}

func TestAutomaticContainmentRequiresVerifiedIdentity(t *testing.T) {
	valid := securityscan.Finding{
		Source: "process", PID: 42, Executable: "/b7a390bb", Deleted: true,
		Rule: "cryptominer", Severity: securityscan.SeverityHigh,
		SHA256: strings.Repeat("a", 64), Size: 100, ProcessStartTime: "123",
	}
	if !automaticProcessContainmentEligible(valid) {
		t.Fatal("verified process finding was not eligible")
	}
	signatureMatch := valid
	signatureMatch.Rule = "clamav-signature"
	if !automaticProcessContainmentEligible(signatureMatch) {
		t.Fatal("verified signature match for a deleted executable was not eligible")
	}
	for name, mutate := range map[string]func(*securityscan.Finding){
		"missing start time": func(f *securityscan.Finding) { f.ProcessStartTime = "" },
		"invalid hash":       func(f *securityscan.Finding) { f.SHA256 = strings.Repeat("z", 64) },
		"missing size":       func(f *securityscan.Finding) { f.Size = 0 },
		"NodeWall path":      func(f *securityscan.Finding) { f.Executable = "/opt/nodewall/bin/nodewall" },
		"agent":              func(f *securityscan.Finding) { f.PID = os.Getpid() },
	} {
		t.Run(name, func(t *testing.T) {
			finding := valid
			mutate(&finding)
			if automaticProcessContainmentEligible(finding) {
				t.Fatalf("unexpected eligible finding: %#v", finding)
			}
		})
	}
	for _, rule := range []string{"high-cpu-process", "cgroup-hidden-process", "deleted-executable"} {
		finding := valid
		finding.Rule = rule
		if automaticProcessContainmentEligible(finding) {
			t.Errorf("automatic containment unexpectedly allowed evidence-only rule %s", rule)
		}
	}
	systemFile := valid
	systemFile.Executable = "/usr/bin/mysqld"
	if automaticProcessContainmentEligible(systemFile) {
		t.Fatal("system-package executable was eligible for automatic containment")
	}
	hidden := valid
	hidden.Rule = "hidden-process"
	if automaticProcessContainmentEligible(hidden) {
		t.Fatal("PID-only visibility evidence should remain review-only")
	}
	systemd := valid
	systemd.Rule = "deleted-executable"
	systemd.Deleted = true
	systemd.Executable = "/usr/lib/systemd/systemd-journald (deleted)"
	if automaticProcessContainmentEligible(systemd) {
		t.Fatal("systemd upgrade evidence should remain review-only")
	}
}

func TestManualProcessActionDoesNotOfferSystemHighCPUIsolation(t *testing.T) {
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{
		ID: "scan-high-cpu", Status: "completed",
		Findings: []securityscan.Finding{{
			ID: "p-mysql", Source: "process", PID: 2, Rule: "high-cpu-process",
			Executable: "/usr/sbin/mysqld", SystemFile: true,
		}},
	}
	request := httptest.NewRequest(http.MethodPost, "/security/scan/p-mysql/terminate", nil)
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "evidence-only") {
		t.Fatalf("system high-CPU process was offered destructive isolation: status=%d body=%s", response.Code, response.Body.String())
	}
}

func startDeletedMinerFixture(t *testing.T) (*exec.Cmd, securityscan.Finding) {
	t.Helper()
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("xmrig stratum+tcp randomx hashrate worker-id")...)
	path := filepath.Join(t.TempDir(), "miner-fixture")
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	startTime, err := securityscan.ReadProcessStartTime(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	finding := securityscan.Finding{
		ID: "p-fixture", Path: path, Executable: path, Deleted: true, Source: "process",
		PID: cmd.Process.Pid, Rule: "cryptominer", Severity: securityscan.SeverityHigh,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), ProcessStartTime: startTime,
	}
	return cmd, finding
}

func TestVerifiedDeletedMinerContainment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux /proc")
	}
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })
	cmd, finding := startDeletedMinerFixture(t)
	cancelled := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	cancelled.securityJob = &securityScanJob{ID: "scan-cancelled", Status: "running", Findings: []securityscan.Finding{finding}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled.containProcessFindingContext(ctx, "scan-cancelled", finding.ID)
	if cancelled.securityJob.Findings[0].Terminated || cancelled.securityJob.Findings[0].TerminationError == "" {
		t.Fatalf("cancelled action did not stop: %#v", cancelled.securityJob.Findings[0])
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("cancelled action nevertheless terminated process: %v", err)
	}
	// A full or inaccessible quarantine must not turn a verified finding into
	// an unrecorded signal against the process.
	validRoot := securityQuarantineRoot
	securityQuarantineRoot = filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(securityQuarantineRoot, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	blocked.securityJob = &securityScanJob{ID: "scan-blocked", Status: "running", Findings: []securityscan.Finding{finding}}
	blocked.containProcessFinding("scan-blocked", finding.ID)
	if blocked.securityJob.Findings[0].Terminated || blocked.securityJob.Findings[0].TerminationError == "" {
		t.Fatalf("snapshot failure did not block termination: %#v", blocked.securityJob.Findings[0])
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("snapshot failure nevertheless terminated process: %v", err)
	}
	securityQuarantineRoot = validRoot

	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{ID: "scan-miner", Status: "running", Findings: []securityscan.Finding{finding}}
	h.containProcessFinding("scan-miner", finding.ID)
	result := h.securityJob.Findings[0]
	if !result.Terminated || !result.Quarantined || result.Termination == nil || !result.Termination.Exited {
		t.Fatalf("miner containment was incomplete: %#v", result)
	}
	if snapshot, err := os.ReadFile(result.QuarantinePath); err != nil || !strings.Contains(string(snapshot), "stratum+tcp") {
		t.Fatalf("miner evidence not saved: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("miner fixture did not terminate")
	}
}

func TestAutomaticContainmentSharedExecutableAndRestore(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux /proc")
	}
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "shared-executable")
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	start := func() *exec.Cmd {
		t.Helper()
		cmd := exec.Command(path, "60")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}
	first, second := start(), start()
	sum := sha256.Sum256(data)
	makeFinding := func(id string, cmd *exec.Cmd) securityscan.Finding {
		t.Helper()
		startTime, err := securityscan.ReadProcessStartTime(cmd.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		return securityscan.Finding{ID: id, Path: path, Executable: path, Source: "process", PID: cmd.Process.Pid,
			Rule: "clamav-signature", Severity: securityscan.SeverityHigh, Quarantinable: true,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), Mode: "-rwx------", ProcessStartTime: startTime}
	}
	finding1, finding2 := makeFinding("p-first", first), makeFinding("p-second", second)
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{ID: "scan-shared", Status: "running", Findings: []securityscan.Finding{finding1, finding2}}
	h.containProcessFinding("scan-shared", finding1.ID)
	h.containProcessFinding("scan-shared", finding2.ID)
	for _, result := range h.securityJob.Findings {
		if !result.Terminated || !result.Quarantined || result.Termination == nil || !result.Termination.Exited {
			t.Fatalf("shared process not contained: %#v", result)
		}
	}
	if h.securityJob.Findings[0].QuarantinePath != h.securityJob.Findings[1].QuarantinePath {
		t.Fatal("shared inode was isolated more than once")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("original executable was not moved into quarantine: %v", err)
	}
	entries, err := listQuarantineEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("list quarantined executable: %v, %#v", err, entries)
	}
	if !entries[0].Restorable || entries[0].OriginalPath != path {
		t.Fatalf("quarantine entry is not fully restorable: %#v", entries[0])
	}
	request := httptest.NewRequest(http.MethodPost, "/security/quarantine/"+entries[0].ID+"/restore", nil)
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", response.Code, response.Body.String())
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("original permissions not restored: %v, %#v", err, info)
	}
	restored, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(restored) != sum {
		t.Fatalf("restored contents changed: %v", err)
	}
}

func TestFullScanContainsDirectlyExecutingFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux /proc")
	}
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("xmrig stratum+tcp randomx hashrate worker-id")...)
	path := filepath.Join(t.TempDir(), "file-miner")
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{ID: "scan-file-process", Status: "running", Mode: "full", AutoTerminateProcesses: true}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h.runSecurityScanContext(ctx, "scan-file-process", path, "full", true)
	if h.securityJob.Status != "completed" || len(h.securityJob.QuarantineErrors) != 0 {
		t.Fatalf("full scan failed: %#v", h.securityJob)
	}
	var foundFile, foundProcess bool
	for _, finding := range h.securityJob.Findings {
		if finding.Source == "file" && finding.Path == path {
			foundFile = finding.Quarantined
		}
		if finding.Source == "process" && finding.PID == cmd.Process.Pid {
			foundProcess = finding.Quarantined && finding.Terminated && finding.Termination != nil && finding.Termination.Exited
		}
	}
	if !foundFile || !foundProcess {
		t.Fatalf("file/process containment incomplete: %#v", h.securityJob.Findings)
	}
}

// This test must run in a private PID namespace: quick scan intentionally
// acts on any verified miner it finds, including other processes in /proc.
func TestQuickScanContainsDeletedMinerEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("NODEWALL_SCAN_ISOLATED_TEST") != "1" {
		t.Skip("requires Linux in an isolated PID namespace")
	}
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })
	cmd, _ := startDeletedMinerFixture(t)
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{ID: "scan-miner", Status: "running", Mode: "process", AutoTerminateProcesses: true, processActions: map[string]bool{}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h.runSecurityScanContext(ctx, "scan-miner", "/", "process")
	if h.securityJob.Status != "completed" {
		t.Fatalf("scan did not complete: %#v", h.securityJob)
	}
	for _, finding := range h.securityJob.Findings {
		if finding.PID != cmd.Process.Pid {
			continue
		}
		if finding.Rule != "cryptominer" || !finding.Terminated || !finding.Quarantined || finding.Termination == nil || !finding.Termination.Exited {
			t.Fatalf("miner containment was incomplete: %#v", finding)
		}
		if snapshot, err := os.ReadFile(finding.QuarantinePath); err != nil || !strings.Contains(string(snapshot), "stratum+tcp") {
			t.Fatalf("miner evidence not saved: %v", err)
		}
		if err := cmd.Wait(); err == nil {
			t.Fatal("miner fixture did not terminate")
		}
		return
	}
	t.Fatalf("miner process was not reported: %#v", h.securityJob.Findings)
}

func TestDeletedProcessExecutableIsSnapshottedBeforeTermination(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc executable snapshots are Linux-only")
	}
	if os.Getenv("NODEWALL_DELETED_EXECUTABLE_HELPER") == "1" {
		for {
			time.Sleep(time.Second)
		}
	}

	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	payload := filepath.Join(t.TempDir(), "deleted-payload")
	if source, err := os.ReadFile(os.Args[0]); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(payload, source, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(payload)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(source)
	cmd := exec.Command(payload, "-test.run=TestDeletedProcessExecutableIsSnapshottedBeforeTermination")
	cmd.Env = append(os.Environ(), "NODEWALL_DELETED_EXECUTABLE_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	ready := false
	for attempt := 0; attempt < 200; attempt++ {
		if executable, readErr := os.Readlink(filepath.Join("/proc", fmt.Sprint(cmd.Process.Pid), "exe")); readErr == nil && filepath.Clean(executable) == filepath.Clean(payload) {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("helper process did not expose the copied executable through /proc")
	}
	if err := os.Remove(payload); err != nil {
		t.Fatal(err)
	}

	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{
		ID: "scan-deleted", Status: "completed",
		Findings: []securityscan.Finding{{
			ID: "p-deleted", Path: payload, Rule: "deleted-executable", Severity: securityscan.SeverityMedium, Deleted: true,
			SHA256: hex.EncodeToString(sum[:]), Size: info.Size(), Mode: info.Mode().Perm().String(),
			Source: "process", PID: cmd.Process.Pid, Executable: payload + " (deleted)",
		}},
	}
	request := httptest.NewRequest(http.MethodPost, "/security/scan/p-deleted/terminate", nil)
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("manual deleted-process termination failed: status=%d body=%s", response.Code, response.Body.String())
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("deleted executable process was not terminated")
	}
	finding := h.securityJob.Findings[0]
	if !finding.Terminated || !finding.Quarantined {
		t.Fatalf("deleted process containment was incomplete: %#v", finding)
	}
	quarantineInfo, err := os.Stat(finding.QuarantinePath)
	if err != nil {
		t.Fatalf("snapshotted executable missing: %v", err)
	}
	if got := quarantineInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("snapshotted executable mode = %04o, want 0600", got)
	}
	quarantined, err := os.ReadFile(finding.QuarantinePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(quarantined); got != sum {
		t.Fatal("snapshotted executable hash does not match the deleted process")
	}
	var metadata quarantineMetadata
	metadataBytes, err := os.ReadFile(quarantineMetadataPath(finding.QuarantinePath))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		t.Fatal(err)
	}
	if !metadata.Restorable {
		t.Fatal("deleted executable snapshot should be restorable after explicit operator action")
	}
}

func TestProcessExitRemainsRecordedWhenFileIsolationFails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux /proc")
	}
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test-executable")
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	// A second link makes moving only the scanned path unsafe, after the
	// verified process has already been stopped and its sample preserved.
	if err := os.Link(path, filepath.Join(dir, "second-link")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	start, err := securityscan.ReadProcessStartTime(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	finding := securityscan.Finding{
		ID: "p-multiple-links", Path: path, Executable: path, Source: "process", PID: cmd.Process.Pid,
		Rule: "clamav-signature", Severity: securityscan.SeverityHigh, Quarantinable: true,
		SHA256: hex.EncodeToString(digest[:]), Size: int64(len(data)), ProcessStartTime: start,
	}
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{ID: "scan-multiple-links", Status: "running", Findings: []securityscan.Finding{finding}}
	h.containProcessFinding("scan-multiple-links", finding.ID)

	result := h.securityJob.Findings[0]
	if !result.Terminated || result.Termination == nil || !result.Termination.Exited || !strings.Contains(result.TerminationError, "multiple hard links") {
		t.Fatalf("partial containment must report both the exit and file isolation failure: %#v", result)
	}
	metadata, err := readQuarantineMetadata(result.QuarantinePath)
	if err != nil || metadata.Source != "process-pre-snapshot" {
		t.Fatalf("recorded sample must remain available: %#v %v", metadata, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unsafe hard-linked original must remain in place: %v", err)
	}
}
