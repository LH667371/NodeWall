package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/xdp"
)

func TestParseSSHFailureSource(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"sshd: Failed password for invalid user deploy from 203.0.113.7 port 41222 ssh2", "203.0.113.7"},
		{"sshd: Invalid user admin from 198.51.100.9 port 40222", "198.51.100.9"},
		{"sshd: pam_unix(sshd:auth): authentication failure; rhost=192.0.2.8 user=root", "192.0.2.8"},
	}
	for _, test := range tests {
		if got, ok := parseSSHFailureSource(test.line); !ok || got != test.want {
			t.Fatalf("parseSSHFailureSource(%q) = %q, %t; want %q, true", test.line, got, ok, test.want)
		}
	}
}

func TestSSHProtectionAcceptsJournaldSource(t *testing.T) {
	settings, err := normalizeSSHProtectionSettings(models.SSHProtectionSettings{
		LogPath: "journalctl",
	}, "journalctl")
	if err != nil {
		t.Fatalf("journald source was rejected: %v", err)
	}
	if settings.LogPath != "journalctl" {
		t.Fatalf("unexpected journald source: %q", settings.LogPath)
	}
}

func TestReadSSHJournalLines(t *testing.T) {
	previous := runJournalctl
	runJournalctl = func(args ...string) ([]byte, error) {
		if len(args) == 0 || args[len(args)-2] != "--since" {
			t.Fatalf("journalctl command did not include an incremental since cursor: %#v", args)
		}
		since := args[len(args)-1]
		if strings.Contains(since, "T") || strings.HasSuffix(since, "Z") {
			t.Fatalf("journalctl since cursor must use the portable timestamp form: %q", since)
		}
		return []byte("sshd: Failed password for invalid user deploy from 203.0.113.7 port 41222 ssh2\n"), nil
	}
	defer func() { runJournalctl = previous }()

	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil, SSHProtectionOptions{LogPath: "journalctl"})
	lines, err := handler.readSSHLogLines("journalctl")
	if err != nil {
		t.Fatalf("read journal lines: %v", err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "203.0.113.7") {
		t.Fatalf("unexpected journal lines: %#v", lines)
	}
}

func TestDetectListeningSSHPortsUsesRunningSSHDListeners(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Port 2222 (0x08AE) is a listening socket with inode 41001. A second
	// listener exists, but belongs to a different process and must be ignored.
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 41001 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 41002 1 0000000000000000 100 0 0 10 0\n"
	if err := os.WriteFile(filepath.Join(proc, "net", "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(proc, "321", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "321", "comm"), []byte("sshd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[41001]", filepath.Join(proc, "321", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(proc, "654", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "654", "comm"), []byte("nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[41002]", filepath.Join(proc, "654", "fd", "4")); err != nil {
		t.Fatal(err)
	}

	ports := detectListeningSSHPorts(proc)
	if len(ports) != 1 || ports[0] != 2222 {
		t.Fatalf("unexpected sshd listener ports: %#v", ports)
	}
}

func TestDetectConfiguredSSHPortsDoesNotAddDefaultWhenCustomPortExists(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(config, []byte("Port 2202\n# Port 22\nPort 2203\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ports := detectConfiguredSSHPorts(config)
	if len(ports) != 2 || ports[0] != 2202 || ports[1] != 2203 {
		t.Fatalf("unexpected configured ssh ports: %#v", ports)
	}
}

func TestSSHActivityEndpointReturnsConnectionAndCommandRecords(t *testing.T) {
	activityPath := filepath.Join(t.TempDir(), "ssh-activity.log")
	if err := os.WriteFile(activityPath, []byte("ts=1700000000 event=command user=root source=192.0.2.5 source_port=4122 transfer= action=executed scan= files=0 findings=0 path_b64= command_b64=ZWNobyBoaQ==\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil, SSHProtectionOptions{ActivityLogPath: activityPath})
	req := httptest.NewRequest(http.MethodGet, "/ssh-protection/activity?limit=10", nil)
	rec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "echo hi") {
		t.Fatalf("unexpected activity response: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSSHProtectionAutomaticallyBlocksAfterThreshold(t *testing.T) {
	dataplane := xdp.NewMockManager()
	handler := NewAgentHandler("node-01", dataplane, memoryStateStore{}, time.Second, nil, nil)
	attachReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/attach", strings.NewReader(`{"mode":"generic"}`))
	attachRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(attachRec, attachReq)
	if attachRec.Code != http.StatusOK {
		t.Fatalf("unexpected attach status: %d", attachRec.Code)
	}

	handler.sshProtectionMu.Lock()
	handler.sshProtectionSettings = models.SSHProtectionSettings{
		Enabled:            true,
		MaxFailures:        2,
		WindowSeconds:      60,
		BanDurationSeconds: 60,
		LogPath:            "/var/log/auth.log",
	}
	handler.sshProtectionMu.Unlock()
	handler.processSSHFailure(context.Background(), "198.51.100.7")
	handler.processSSHFailure(context.Background(), "198.51.100.7")

	blocked, err := dataplane.ListBlockedCIDRs("nw-test0")
	if err != nil {
		t.Fatalf("list blocked cidrs: %v", err)
	}
	if len(blocked) != 1 || blocked[0] != "198.51.100.7/32" {
		t.Fatalf("unexpected SSH block list: %#v", blocked)
	}
	status := handler.sshProtectionStatus()
	if len(status.ActiveBlocks) != 1 || status.TotalBans != 1 {
		t.Fatalf("unexpected SSH protection status: %#v", status)
	}
}

func TestSSHProtectionDoesNotBlockTrustedSource(t *testing.T) {
	dataplane := xdp.NewMockManager()
	handler := NewAgentHandler("node-01", dataplane, memoryStateStore{}, time.Second, nil, nil)
	attachReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/attach", strings.NewReader(`{"mode":"generic"}`))
	attachRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(attachRec, attachReq)

	handler.sshProtectionMu.Lock()
	handler.sshProtectionSettings = models.SSHProtectionSettings{
		Enabled:            true,
		MaxFailures:        1,
		WindowSeconds:      60,
		BanDurationSeconds: 60,
		TrustedCIDRs:       []string{"198.51.100.0/24"},
		LogPath:            "/var/log/auth.log",
	}
	handler.sshProtectionMu.Unlock()
	handler.processSSHFailure(context.Background(), "198.51.100.7")

	blocked, err := dataplane.ListBlockedCIDRs("nw-test0")
	if err != nil {
		t.Fatalf("list blocked cidrs: %v", err)
	}
	if len(blocked) != 0 {
		t.Fatalf("trusted source was blocked: %#v", blocked)
	}
}
