package api

import (
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

func TestAutomaticProcessContainmentTerminatesAndQuarantines(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel process containment is Linux-only")
	}
	payload := filepath.Join(t.TempDir(), "miner")
	if err := os.WriteFile(payload, []byte("inert miner evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("inert miner evidence"))
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()

	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{
		ID: "scan-containment", Status: "running", AutoTerminateProcesses: true,
		Findings: []securityscan.Finding{{
			ID: "p-test", Path: payload, Rule: "cryptominer", Severity: securityscan.SeverityHigh,
			SHA256: hex.EncodeToString(sum[:]), Size: info.Size(), Mode: info.Mode().Perm().String(),
			Source: "process", PID: cmd.Process.Pid, Executable: payload, Quarantinable: true,
		}},
		processActions: map[string]bool{"p-test": true},
	}
	h.containProcessFinding("scan-containment", "p-test")
	if err := cmd.Wait(); err == nil {
		t.Fatal("process was not terminated")
	}
	finding := h.securityJob.Findings[0]
	if !finding.Terminated || finding.Termination == nil || !finding.Quarantined {
		t.Fatalf("process containment was incomplete: %#v", finding)
	}
	if _, err := os.Stat(payload); !os.IsNotExist(err) {
		t.Fatalf("original executable was not isolated: %v", err)
	}
	quarantineInfo, err := os.Stat(finding.QuarantinePath)
	if err != nil {
		t.Fatalf("quarantine payload missing: %v", err)
	}
	if got := quarantineInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("quarantine payload mode = %04o, want 0600", got)
	}
	if quarantineInfo.Mode().Perm()&0o111 != 0 {
		t.Fatalf("quarantine payload remains executable: %v", quarantineInfo.Mode())
	}
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
		ID: "scan-deleted", Status: "running", AutoTerminateProcesses: true,
		Findings: []securityscan.Finding{{
			ID: "p-deleted", Path: payload + " (deleted)", Rule: "deleted-executable", Severity: securityscan.SeverityMedium,
			SHA256: hex.EncodeToString(sum[:]), Size: info.Size(), Mode: info.Mode().Perm().String(),
			Source: "process", PID: cmd.Process.Pid, Executable: payload + " (deleted)",
		}},
		processActions: map[string]bool{"p-deleted": true},
	}
	h.containProcessFinding("scan-deleted", "p-deleted")
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
	if metadata.Restorable {
		t.Fatal("deleted executable was incorrectly marked restorable")
	}
}
