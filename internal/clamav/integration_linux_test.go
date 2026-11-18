//go:build linux

package clamav_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodewall/internal/clamav"
	"nodewall/internal/securityscan"
)

// This opt-in test uses the actual bundled engine and official signature set.
// It is run in an isolated, network-disabled Linux environment by the release
// validation workflow; ordinary unit tests need no external engine or data.
func TestClamAVOfflineIntegration(t *testing.T) {
	assets := os.Getenv("NODEWALL_CLAMAV_INTEGRATION_ASSETS")
	if assets == "" {
		t.Skip("set NODEWALL_CLAMAV_INTEGRATION_ASSETS to test the offline bundle")
	}
	data := t.TempDir()
	socket := filepath.Join(data, "clamd.sock")
	t.Setenv("NODEWALL_CLAMAV_DIR", data)
	t.Setenv("NODEWALL_CLAMD_SOCKET", socket)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		clamav.Run(ctx, clamav.Options{
			AssetsDir: assets, DataDir: data, Socket: socket,
			// No manager contact is attempted without credentials; this tests
			// that the bundled databases still work completely offline.
			ManagerURL: func() string { return "https://127.0.0.1:1" },
		})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("ClamAV supervisor did not stop")
		}
	}()
	ready := false
	for deadline := time.Now().Add(5 * time.Minute); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("unix", socket, time.Second)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(conn, "zPING\x00")
			reply, _ := bufio.NewReader(conn).ReadString(0)
			_ = conn.Close()
			if reply == "PONG\x00" {
				ready = true
				break
			}
		}
		time.Sleep(time.Second)
	}
	if !ready {
		t.Fatal("offline ClamAV daemon did not become ready")
	}
	// EICAR is an industry-standard harmless test string, not live malware.
	sample := "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	path := filepath.Join(t.TempDir(), "eicar.txt")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := securityscan.New().Scan(context.Background(), path, nil)
	if err != nil || report.SignatureEngine.Status != "available" || len(report.Findings) != 1 || report.Findings[0].Rule != "clamav-signature" || !strings.Contains(report.Findings[0].Detail, "Eicar") {
		t.Fatalf("offline signature scan: report=%#v err=%v", report, err)
	}
}
