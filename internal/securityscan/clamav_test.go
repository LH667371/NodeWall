package securityscan

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fake daemon returns deterministic verdicts for harmless fixture bytes;
// no malware sample or external daemon is needed by the test.
func fakeClamAV(t *testing.T, verdict func(string) string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nw-clam-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "clamd.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.RemoveAll(dir) })
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
				var content strings.Builder
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
					if _, err := io.CopyN(&content, reader, int64(length)); err != nil {
						return
					}
				}
				_, _ = io.WriteString(conn, verdict(content.String())+"\x00")
			}()
		}
	}()
	return path
}

func TestClamAVFullScanReportsSignatureAndCleanFiles(t *testing.T) {
	socket := fakeClamAV(t, func(content string) string {
		if content == "harmless mock sample" {
			return "stream: Mock.Signature FOUND"
		}
		return "stream: OK"
	})
	root := t.TempDir()
	for name, content := range map[string]string{"match.txt": "harmless mock sample", "clean.txt": "ordinary text"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scanner := New()
	scanner.ClamAVSocket = socket
	report, err := scanner.Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.SignatureEngine.Status != "available" || report.SignatureEngine.FilesScanned != 2 || !strings.Contains(report.SignatureEngine.Version, "mock") {
		t.Fatalf("unexpected signature engine status: %#v", report.SignatureEngine)
	}
	if len(report.Findings) != 1 || report.Findings[0].Rule != "clamav-signature" || !strings.Contains(report.Findings[0].Detail, "Mock.Signature") {
		t.Fatalf("signature verdict missing: %#v", report.Findings)
	}
}

func TestClamAVFailureAndMissingConfigurationAreVisible(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sample"), []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, socket, want string
		truncated          bool
	}{
		{"disabled", "", "not-configured", false},
		{"missing socket", filepath.Join(root, "missing.sock"), "failed", true},
		{"stream limit", fakeClamAV(t, func(string) string { return "INSTREAM size limit exceeded. ERROR" }), "failed", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scanner := New()
			scanner.ClamAVSocket = tc.socket
			report, err := scanner.Scan(context.Background(), root, nil)
			if err != nil {
				t.Fatal(err)
			}
			if report.SignatureEngine.Status != tc.want || report.Truncated != tc.truncated {
				t.Fatalf("status=%#v truncated=%t gaps=%#v", report.SignatureEngine, report.Truncated, report.CoverageGaps)
			}
		})
	}
}
