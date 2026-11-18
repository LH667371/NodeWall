//go:build linux

package securityscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func scannedMinerFile(t *testing.T, path string) Finding {
	t.Helper()
	report, err := New().Scan(context.Background(), path, nil)
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("scan test executable: %#v, %v", report, err)
	}
	return report.Findings[0]
}

func TestCorrelateFileWithDirectExecutableProcess(t *testing.T) {
	pid, path := startMinerFixture(t)
	finding := scannedMinerFile(t, path)
	matches, err := FindProcessesForFileFinding(context.Background(), finding)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range matches {
		if match.PID == pid {
			if match.ProcessStartTime == "" || match.SHA256 != finding.SHA256 || match.Size != finding.Size {
				t.Fatalf("process was returned without bound identity: %#v", match)
			}
			return
		}
	}
	t.Fatalf("directly executing PID %d was not correlated: %#v", pid, matches)
}

func TestCorrelationRejectsDifferentInodeWithIdenticalContent(t *testing.T) {
	pid, original := startMinerFixture(t)
	content, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "same-bytes")
	if err := os.WriteFile(copyPath, content, 0o700); err != nil {
		t.Fatal(err)
	}
	finding := scannedMinerFile(t, copyPath)
	matches, err := FindProcessesForFileFinding(context.Background(), finding)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range matches {
		if match.PID == pid {
			t.Fatal("matched process executing a different inode with identical content")
		}
	}
}

func TestCorrelationDoesNotAssociateInterpreterScripts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nxmrig stratum+tcp randomx\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	finding := scannedMinerFile(t, path)
	matches, err := FindProcessesForFileFinding(context.Background(), finding)
	if err != nil || len(matches) != 0 {
		t.Fatalf("script should not associate interpreter process: %#v, %v", matches, err)
	}
}
