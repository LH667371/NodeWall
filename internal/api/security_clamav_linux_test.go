//go:build linux

package api

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"nodewall/internal/xdp"
)

func TestFullScanContainsVerifiedClamAVMatch(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })
	socketDir, err := os.MkdirTemp("/tmp", "nw-api-clam-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "clamd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				command, err := reader.ReadString(0)
				if err != nil {
					return
				}
				if command == "zVERSION\x00" {
					_, _ = io.WriteString(conn, "ClamAV 1.0/mock/database\x00")
					return
				}
				if command != "zINSTREAM\x00" {
					return
				}
				for {
					var size [4]byte
					if _, err := io.ReadFull(reader, size[:]); err != nil {
						return
					}
					length := binary.BigEndian.Uint32(size[:])
					if length == 0 {
						break
					}
					if length > 64<<10 {
						return
					}
					if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
						return
					}
				}
				_, _ = io.WriteString(conn, "stream: Mock.Signature FOUND\x00")
			}()
		}
	}()
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Skipf("sleep fixture unavailable: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sample-process")
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	h := NewAgentHandler("node-test", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityScanner.ClamAVSocket = socket
	h.securityJob = &securityScanJob{ID: "scan-clam", Status: "running", Mode: "full", AutoTerminateProcesses: true}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h.runSecurityScanContext(ctx, "scan-clam", path, "full", true)
	if h.securityJob.Status != "completed" || h.securityJob.SignatureEngine.Status != "available" || len(h.securityJob.QuarantineErrors) != 0 {
		t.Fatalf("signature scan failed: %#v", h.securityJob)
	}
	var fileIsolated, processStopped bool
	for _, finding := range h.securityJob.Findings {
		if finding.Source == "file" && finding.Rule == "clamav-signature" && finding.Path == path {
			fileIsolated = finding.Quarantined && finding.QuarantinePath != ""
		}
		if finding.Source == "process" && finding.PID == cmd.Process.Pid {
			processStopped = finding.Terminated && finding.Quarantined
		}
	}
	if !fileIsolated || !processStopped {
		t.Fatalf("signature match was not safely contained: %#v", h.securityJob.Findings)
	}
}
