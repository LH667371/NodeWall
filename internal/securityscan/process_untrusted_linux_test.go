//go:build linux

package securityscan

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestQuickScanReportsLowCPUExecutableInTemporaryDirectory(t *testing.T) {
	source, err := os.Open("/bin/sleep")
	if err != nil {
		t.Skipf("sleep fixture unavailable: %v", err)
	}
	defer source.Close()
	path := filepath.Join(t.TempDir(), "background-worker")
	target, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		findings, err := collectTemporaryProcessFindings(context.Background(), 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings {
			if finding.PID == cmd.Process.Pid {
				if finding.Rule != "suspicious-runtime-path" || finding.Quarantinable || finding.ProcessStartTime == "" || finding.SHA256 == "" {
					t.Fatalf("temporary process needs review, not automatic termination: %#v", finding)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("low-CPU temporary executable was not reported")
}
