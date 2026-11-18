//go:build linux

package securityscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func startMinerFixture(t *testing.T) (int, string) {
	return startExecutableFixture(t, true)
}

func startExecutableFixture(t *testing.T, miner bool) (int, string) {
	t.Helper()
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(sleepPath)
	if err != nil {
		t.Fatal(err)
	}
	// Appending inert indicators to a real executable exercises the live proc
	// path and complete executable hash without executing any mining code.
	if miner {
		payload = append(payload, []byte(" xmrig stratum+tcp randomx ")...)
	}
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(2 * time.Second)
	for {
		link, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe"))
		if link == path {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fixture did not exec: %q", link)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cmd.Process.Pid, path
}

func TestDeletedOrdinaryExecutableBindsIdentity(t *testing.T) {
	pid, path := startExecutableFixture(t, false)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	evidence, ok := deletedExecutableEvidence(pid)
	if !ok || evidence.rule != "deleted-executable" || evidence.startTime == "" || evidence.sha256 == "" || evidence.size == 0 || evidence.mode == "" {
		t.Fatalf("ordinary deleted executable missing complete evidence: %#v", evidence)
	}
	finding := processIntegrityFinding(evidence.rule, evidence.severity, evidence.exe, pid, evidence.detail)
	if finding.ProcessStartTime != evidence.startTime || finding.SHA256 != evidence.sha256 || finding.Size != evidence.size {
		t.Fatalf("finding does not match inspected executable: %#v", finding)
	}
	if err := VerifyProcessFinding(finding); err != nil {
		t.Fatalf("verify ordinary deleted executable: %v", err)
	}
}

func TestDeletedMinerEvidenceBindsExecutableAndProcessIdentity(t *testing.T) {
	pid, path := startMinerFixture(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	evidence, ok := deletedExecutableEvidence(pid)
	if !ok || evidence.rule != "cryptominer" || evidence.startTime == "" {
		t.Fatalf("miner evidence missing identity: %#v", evidence)
	}
	finding := processIntegrityFinding(evidence.rule, evidence.severity, evidence.exe, pid, evidence.detail)
	if finding.ProcessStartTime != evidence.startTime || finding.SHA256 != evidence.sha256 || !finding.Deleted {
		t.Fatalf("finding does not match inspected evidence: %#v", finding)
	}
	if err := VerifyProcessFinding(finding); err != nil {
		t.Fatalf("verify live finding: %v", err)
	}
}

func TestVerifiedTerminationRejectsStaleIdentity(t *testing.T) {
	pid, path := startMinerFixture(t)
	finding := EnrichProcessFinding(Finding{PID: pid, Source: "process", Path: path})
	if finding.Rule != "cryptominer" || finding.ProcessStartTime == "" {
		t.Fatalf("live miner was not identified: %#v", finding)
	}
	stale := finding
	stale.ProcessStartTime += "0"
	if _, err := TerminateProcessVerified(stale); err == nil {
		t.Fatal("stale PID identity was accepted")
	}
	if _, err := terminateLegacyProcessWithFinding(pid, 10*time.Millisecond, time.Second, &stale); err == nil {
		t.Fatal("legacy path accepted stale PID identity")
	}
	stale = finding
	stale.SHA256 = strings.Repeat("0", 64)
	if _, err := TerminateProcessVerified(stale); err == nil {
		t.Fatal("changed executable hash was accepted")
	}
	if err := unix.Kill(pid, 0); err != nil {
		t.Fatalf("process was signaled despite identity mismatch: %v", err)
	}
}

func TestProcessFindingCanBeVerifiedAfterExecutableIsolation(t *testing.T) {
	pid, path := startMinerFixture(t)
	finding := EnrichProcessFinding(Finding{PID: pid, Source: "process", Path: path})
	if finding.ProcessStartTime == "" {
		t.Fatalf("fixture lacks stable identity: %#v", finding)
	}
	if err := VerifyProcessExecutablePath(finding); err != nil {
		t.Fatalf("verify original executable: %v", err)
	}
	target := filepath.Join(filepath.Dir(path), "isolated")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	updated, err := ProcessFindingAfterIsolation(finding, target)
	if err != nil {
		t.Fatalf("verify isolated executable: %v", err)
	}
	if updated.Executable != target || updated.Deleted {
		t.Fatalf("unexpected isolated process identity: %#v", updated)
	}
	result, err := TerminateProcessVerified(updated)
	if err != nil || !result.Exited {
		t.Fatalf("terminate isolated process: %#v, %v", result, err)
	}
}

func TestProcessExecutablePathRejectsReplacement(t *testing.T) {
	pid, path := startMinerFixture(t)
	finding := EnrichProcessFinding(Finding{PID: pid, Source: "process", Path: path})
	if finding.ProcessStartTime == "" {
		t.Fatalf("fixture lacks stable identity: %#v", finding)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unrelated executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyProcessExecutablePath(finding); err == nil {
		t.Fatal("replacement executable path was accepted")
	}
	if _, err := ProcessFindingAfterIsolation(finding, path); err == nil {
		t.Fatal("replacement quarantine target was accepted")
	}
}

func TestProcessFindingCanBeVerifiedAfterCrossFilesystemIsolation(t *testing.T) {
	pid, path := startMinerFixture(t)
	finding := EnrichProcessFinding(Finding{PID: pid, Source: "process", Path: path})
	if finding.ProcessStartTime == "" {
		t.Fatalf("fixture lacks stable identity: %#v", finding)
	}
	var srcFS, dstFS unix.Statfs_t
	if unix.Statfs(path, &srcFS) != nil || unix.Statfs("/dev/shm", &dstFS) != nil || srcFS.Fsid == dstFS.Fsid {
		t.Skip("separate /dev/shm filesystem is unavailable")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp("/dev/shm", "nodewall-identity-*")
	if err != nil {
		t.Skipf("cannot create cross-filesystem fixture: %v", err)
	}
	target := file.Name()
	t.Cleanup(func() { _ = os.Remove(target) })
	if _, err := file.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	updated, err := ProcessFindingAfterIsolation(finding, target)
	if err != nil || !updated.Deleted || updated.Executable != path {
		t.Fatalf("verify cross-filesystem isolation: %#v, %v", updated, err)
	}
	result, err := TerminateProcessVerified(updated)
	if err != nil || !result.Exited {
		t.Fatalf("terminate isolated process: %#v, %v", result, err)
	}
}
