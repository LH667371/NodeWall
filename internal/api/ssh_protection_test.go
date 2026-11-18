package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"nodewall/internal/models"
	"nodewall/internal/sshconsole"
	"nodewall/internal/xdp"
)

type recordingSSHAuthenticationApplier struct {
	values []bool
}

func (a *recordingSSHAuthenticationApplier) ApplyPasswordAuthentication(_ context.Context, allow bool) error {
	a.values = append(a.values, allow)
	return nil
}

func (a *recordingSSHAuthenticationApplier) ClearPasswordAuthentication(context.Context) error {
	return nil
}

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

func TestSSHAuthenticationPolicyEndpointPersistsChoice(t *testing.T) {
	applier := &recordingSSHAuthenticationApplier{}
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil, SSHProtectionOptions{AuthenticationPolicyApplier: applier})
	req := httptest.NewRequest(http.MethodPut, "/ssh-protection/authentication", strings.NewReader(`{"allow_password_login":false}`))
	rec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || len(applier.values) != 1 || applier.values[0] {
		t.Fatalf("password-login policy was not applied: %d %#v %s", rec.Code, applier.values, rec.Body.String())
	}
	if handler.sshProtectionSettings.AllowPasswordLogin == nil || *handler.sshProtectionSettings.AllowPasswordLogin {
		t.Fatalf("password-login choice was not stored: %#v", handler.sshProtectionSettings.AllowPasswordLogin)
	}
}

func TestSSHAuthorizedKeyEndpointProtectsLastKeyWhenPasswordLoginDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	applier := &recordingSSHAuthenticationApplier{}
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil, SSHProtectionOptions{AuthenticationPolicyApplier: applier, AuthorizedKeysPath: path})
	addReq := httptest.NewRequest(http.MethodPost, "/ssh-protection/keys", strings.NewReader(`{"public_key":"`+line+`","comment":"ops"}`))
	addRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(addRec, addReq)
	if addRec.Code != http.StatusOK {
		t.Fatalf("public key was not added: %d %s", addRec.Code, addRec.Body.String())
	}
	var listed struct {
		Keys []models.SSHAuthorizedKey `json:"keys"`
	}
	if err := json.Unmarshal(addRec.Body.Bytes(), &listed); err != nil || len(listed.Keys) != 1 {
		t.Fatalf("unexpected public key response: %s (%v)", addRec.Body.String(), err)
	}
	choice := false
	handler.sshProtectionSettings.AllowPasswordLogin = &choice
	deleteReq := httptest.NewRequest(http.MethodDelete, "/ssh-protection/keys/"+url.PathEscape(listed.Keys[0].Fingerprint), nil)
	deleteRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusConflict {
		t.Fatalf("last key removal was not blocked: %d %s", deleteRec.Code, deleteRec.Body.String())
	}
	confirmedReq := httptest.NewRequest(http.MethodDelete, "/ssh-protection/keys/"+url.PathEscape(listed.Keys[0].Fingerprint), strings.NewReader(`{"confirmed":true}`))
	confirmedRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(confirmedRec, confirmedReq)
	if confirmedRec.Code != http.StatusOK {
		t.Fatalf("confirmed last key removal was rejected: %d %s", confirmedRec.Code, confirmedRec.Body.String())
	}
}

func TestSSHAuthorizedKeyEndpointIdentifiesCurrentAndHistoricalConsoleKeys(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ssh", "id_ed25519")
	currentPublic, err := sshconsole.NewWithKeyPath(keyPath).PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	oldPublic, err := sshconsole.NewWithKeyPath(filepath.Join(dir, "old", "id_ed25519")).PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(strings.TrimSpace(oldPublic)+" nodewall-console\n"+strings.TrimSpace(currentPublic)+" nodewall-console\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil, SSHProtectionOptions{
		AuthorizedKeysPath:    authorized,
		ManagedConsoleKeyPath: keyPath,
	})
	getReq := httptest.NewRequest(http.MethodGet, "/ssh-protection/keys", nil)
	getRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("key list failed: %d %s", getRec.Code, getRec.Body.String())
	}
	var listed struct {
		Keys []models.SSHAuthorizedKey `json:"keys"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &listed); err != nil || len(listed.Keys) != 2 {
		t.Fatalf("unexpected key list: %s (%v)", getRec.Body.String(), err)
	}
	var historical, current models.SSHAuthorizedKey
	for _, key := range listed.Keys {
		if key.NodeWallActive {
			current = key
		} else {
			historical = key
		}
	}
	if !current.NodeWallActive || !current.NodeWallActiveKnown || !historical.NodeWallManaged || historical.NodeWallActive || !historical.NodeWallActiveKnown {
		t.Fatalf("current/historical annotations are wrong: %#v", listed.Keys)
	}
	deleteReq := httptest.NewRequest(http.MethodDelete, "/ssh-protection/keys/"+url.PathEscape(historical.Fingerprint), nil)
	deleteRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("historical console key could not be removed without confirmation: %d %s", deleteRec.Code, deleteRec.Body.String())
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
