//go:build linux

package securityscan

import (
	"context"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestQuickScanMatchesRunningExecutableByItsBytes(t *testing.T) {
	content, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Skipf("sleep executable unavailable: %v", err)
	}
	path := filepath.Join(t.TempDir(), "running-fixture")
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "30")
	// On BusyBox-based test images /bin/sleep is a multi-call executable.
	cmd.Args[0] = "sleep"
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	want := sha256.Sum256(content)
	socket := fakeClamAV(t, func(data string) string {
		if sha256.Sum256([]byte(data)) == want {
			return "stream: Mock.Process FOUND"
		}
		return "stream: OK"
	})
	scanner := New()
	scanner.signatures = newClamAVEngine(context.Background(), socket)
	findings, _, err := scanProcessSignatures(context.Background(), scanner, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.PID == cmd.Process.Pid && finding.Rule == "clamav-signature" && finding.ProcessStartTime != "" {
			if err := VerifyProcessFinding(finding); err != nil {
				t.Fatalf("signature finding lost its process identity: %v", err)
			}
			return
		}
	}
	t.Fatalf("running executable signature missing for PID %d: %#v", cmd.Process.Pid, findings)
}
