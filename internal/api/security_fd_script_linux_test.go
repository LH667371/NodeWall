//go:build linux

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"nodewall/internal/securityscan"
	"nodewall/internal/xdp"
)

func TestFDScriptContainmentPreservesSampleBeforeStoppingShell(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })
	path := filepath.Join(t.TempDir(), "test-script.sh")
	script := []byte("#!/bin/bash\ninsmod() { :; }\njournalctl() { :; }\ninsmod /tmp/a/renamed-driver.ko\njournalctl --vacuum-time=1s\nsleep 30 &\nwait\n")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := exec.Command("/bin/bash", "/dev/fd/3")
	cmd.ExtraFiles = []*os.File{file}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	})
	procDir := filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid))
	var executable string
	var executableBytes []byte
	var start string
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		executable, err = os.Readlink(filepath.Join(procDir, "exe"))
		if err == nil && filepath.Base(executable) == "bash" {
			executableBytes, err = os.ReadFile(filepath.Join(procDir, "exe"))
			start, _ = securityscan.ReadProcessStartTime(cmd.Process.Pid)
			if err == nil && start != "" {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(executableBytes) == 0 || start == "" {
		t.Fatal("test shell did not start")
	}
	scriptHash, exeHash := sha256.Sum256(script), sha256.Sum256(executableBytes)
	finding := securityscan.Finding{
		ID: "d-test", Path: filepath.Join(procDir, "fd", "3"), Rule: "malicious-fd-script", Source: "fd-script",
		PID: cmd.Process.Pid, ProcessStartTime: start, Executable: executable,
		ExecutableSHA256: hex.EncodeToString(exeHash[:]), ExecutableSize: int64(len(executableBytes)),
		ScriptFD: 3, ScriptFDTarget: path, SHA256: hex.EncodeToString(scriptHash[:]), Size: int64(len(script)),
	}
	h := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityJob = &securityScanJob{ID: "scan-fd", Findings: []securityscan.Finding{finding}}
	h.containFDScriptFinding(context.Background(), "scan-fd", finding.ID)
	result := h.securityJob.Findings[0]
	if !result.Terminated || result.EvidenceArchived || !result.Quarantined || result.TerminationError != "" {
		t.Fatalf("unexpected containment result: %#v", result)
	}
	if data, err := os.ReadFile(result.QuarantinePath); err != nil || string(data) != string(script) {
		t.Fatalf("script sample missing or changed: %q %v", data, err)
	}
	metadata, err := readQuarantineMetadata(result.QuarantinePath)
	if err != nil || metadata.Restorable || metadata.Source != "fd-script-sample" {
		t.Fatalf("unexpected descriptor sample metadata: %#v %v", metadata, err)
	}
	if _, err := os.Stat(executable); err != nil {
		t.Fatalf("shared shell executable must remain in place: %v", err)
	}
}

func TestFDScriptSampleRequiresQuarantineRecord(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	const scanID = "scan-fd-record"
	sample := []byte("malicious descriptor script")
	digest := sha256.Sum256(sample)
	finding := securityscan.Finding{ID: "d-test", Path: "/proc/123/fd/3", Size: int64(len(sample)), SHA256: hex.EncodeToString(digest[:])}
	dir := filepath.Join(securityQuarantineRoot, scanID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, finding.ID+"-fd-script")
	metadataPath := quarantineMetadataPath(target)
	if err := os.WriteFile(metadataPath, []byte("existing record"), 0o600); err != nil {
		t.Fatal(err)
	}

	stored, err := archiveFDScriptSample(finding, scanID, sample)
	if err == nil || stored != "" {
		t.Fatalf("sample without a new record must not be reported as stored: path=%q err=%v", stored, err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("unrecorded duplicate must be removed: %v", err)
	}
	if data, err := os.ReadFile(metadataPath); err != nil || string(data) != "existing record" {
		t.Fatalf("preexisting record must remain intact: %q %v", data, err)
	}
}
