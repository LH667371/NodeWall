package sshpolicy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nodewall/internal/models"
	"nodewall/internal/sshactivity"
)

func TestApplyTransferPolicyIsReversible(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "sshd_config")
	dropIn := filepath.Join(root, "sshd_config.d", "99-nodewall-transfer.conf")
	wrapper := filepath.Join(root, "nodewall-ssh-transfer-policy")
	sftp := filepath.Join(root, "nodewall-sftp-deny")
	state := filepath.Join(root, "ssh-transfer-state.json")
	original := []byte("Port 22\nSubsystem sftp /usr/lib/openssh/sftp-server\n")
	if err := os.WriteFile(config, original, 0o644); err != nil {
		t.Fatal(err)
	}

	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "sshd" && len(args) > 0 && args[0] == "-T" {
			return []byte("forcecommand " + wrapper + "\n"), nil
		}
		if name == "systemctl" && len(args) > 1 && args[0] == "reload" && args[1] == "sshd" {
			return nil, errors.New("sshd service name not found")
		}
		return nil, nil
	}
	applier := NewWithPaths(config, dropIn, wrapper, sftp, state, runner)
	policy := models.SSHTransferPolicy{BlockSFTP: true, BlockSCP: true, AuditTransfers: true}
	if err := applier.Apply(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	changed, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(changed) == string(original) || !strings.Contains(string(changed), sftp) {
		t.Fatalf("expected SFTP subsystem to be replaced: %q", changed)
	}
	if data, err := os.ReadFile(dropIn); err != nil || !strings.Contains(string(data), "ForceCommand") {
		t.Fatalf("expected managed drop-in, err=%v data=%q", err, data)
	}

	if err := applier.Apply(context.Background(), models.SSHTransferPolicy{}); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Fatalf("expected original sshd config, got %q", restored)
	}
	for _, path := range []string{dropIn, wrapper, sftp, state} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected managed file %s to be removed, err=%v", path, err)
		}
	}
}

func TestRestoreWithoutNodeWallArtifactsIsNoOp(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(config, []byte("Port 22\nSubsystem sftp internal-sftp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	a := NewWithPaths(config, filepath.Join(dir, "drop-in"), filepath.Join(dir, "wrapper"), filepath.Join(dir, "sftp"), filepath.Join(dir, "state"), func(context.Context, string, ...string) ([]byte, error) {
		calls++
		return nil, nil
	})
	if err := a.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("no-op SSH restore invoked external commands: %d", calls)
	}
}

func TestRestoreRefusesToDeleteHelpersWhenSSHDConfigIsMissing(t *testing.T) {
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "wrapper")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nNODEWALL_SSH_SESSION_ID=\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := NewWithPaths(filepath.Join(dir, "missing-sshd_config"), filepath.Join(dir, "drop-in"), wrapper, filepath.Join(dir, "sftp"), filepath.Join(dir, "state"), func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("restore should not invoke sshd commands with a missing config")
		return nil, nil
	})
	if err := a.Restore(context.Background()); err == nil {
		t.Fatal("missing sshd config was silently accepted")
	}
	if _, err := os.Stat(wrapper); err != nil {
		t.Fatalf("helper was deleted after an incomplete recovery: %v", err)
	}
}

func TestApplyRestoresConfigWithoutTrailingNewlineExactly(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sshd_config")
	original := []byte("Port 22\nSubsystem sftp internal-sftp")
	if err := os.WriteFile(config, original, 0o600); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(dir, "wrapper")
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "sshd" && len(args) > 0 && args[0] == "-T" {
			return []byte("forcecommand " + wrapper + "\nsubsystem sftp internal-sftp\n"), nil
		}
		return nil, nil
	}
	a := NewWithPaths(config, filepath.Join(dir, "drop-in"), wrapper, filepath.Join(dir, "sftp"), filepath.Join(dir, "state"), runner)
	if err := a.Apply(context.Background(), models.SSHTransferPolicy{BlockSFTP: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(context.Background(), models.SSHTransferPolicy{}); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(config)
	if err != nil || string(restored) != string(original) {
		t.Fatalf("configuration trailing newline changed: %q (%v)", restored, err)
	}
}

func TestWrapperScriptHasValidShellSyntax(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrapper")
	script := wrapperScript(path, models.SSHTransferPolicy{
		AuditTransfers: true,
		AuditSessions:  true,
		AuditCommands:  true,
		ScanUploads:    true,
	}, "/var/log/nodewall/ssh activity.log", "/opt/nodewall/bin/nodewall")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("generated SSH wrapper has invalid shell syntax: %v (%s)", err, output)
	}
}

func TestWrapperRecordsExecCommand(t *testing.T) {
	root := t.TempDir()
	scriptPath := filepath.Join(root, "wrapper")
	activityPath := filepath.Join(root, "activity.log")
	helperPath := filepath.Join(root, "helper")
	marker := filepath.Join(root, "helper-calls")
	if err := os.WriteFile(helperPath, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+shellQuote(marker)+"\ncat >> "+shellQuote(marker)+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := wrapperScript(scriptPath, models.SSHTransferPolicy{AuditSessions: true, AuditCommands: true}, activityPath, helperPath)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"USER=root",
		"SSH_CONNECTION=192.0.2.5 4122 192.0.2.10 22",
		"SSH_ORIGINAL_COMMAND=printf hello",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wrapper command failed: %v (%s)", err, output)
	}
	data, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(data), "--event=command") || !strings.Contains(string(data), "printf hello") || !strings.Contains(string(data), "--exit-code=0") {
		t.Fatalf("exec command was not submitted to the journal: %s %v", data, err)
	}
}

func TestWrapperFailsOpenWhenInstalledBinaryWasRemoved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrapper")
	script := wrapperScript(path, models.SSHTransferPolicy{AuditCommands: true}, filepath.Join(dir, "activity"), filepath.Join(dir, "missing-nodewall"))
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", path)
	cmd.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND=printf recovered")
	output, err := cmd.CombinedOutput()
	if err != nil || string(output) != "recovered" {
		t.Fatalf("wrapper did not preserve SSH command after binary removal: %q (%v)", output, err)
	}
}

func TestWrapperRoutesSFTPToPerFileGuardWithoutScanningHome(t *testing.T) {
	root := t.TempDir()
	scriptPath := filepath.Join(root, "wrapper")
	activityPath := filepath.Join(root, "activity.log")
	scannerPath := filepath.Join(root, "scanner")
	scannerMarker := filepath.Join(root, "scanner-called")
	sftpPath := filepath.Join(root, "sftp-server-fake")
	if err := os.WriteFile(scannerPath, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+shellQuote(scannerMarker)+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sftpPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := wrapperScript(scriptPath, models.SSHTransferPolicy{
		AuditTransfers: true,
		ScanUploads:    true,
	}, activityPath, scannerPath)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"USER=root",
		"HOME="+root,
		"SSH_CONNECTION=192.0.2.5 4122 192.0.2.10 22",
		"SSH_ORIGINAL_COMMAND=internal-sftp",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wrapper SFTP command failed: %v (%s)", err, output)
	}
	marker, err := os.ReadFile(scannerMarker)
	guardLine := ""
	for _, line := range strings.Split(string(marker), "\n") {
		if strings.HasPrefix(line, "sftp-guard ") {
			guardLine = line
		}
	}
	if err != nil || !strings.Contains(guardLine, "sftp-guard --scan-uploads=1") || strings.Contains(guardLine, "--path") {
		t.Fatalf("SFTP was not routed to the file-level guard: %s %v", marker, err)
	}
	records, err := sshactivity.Read(activityPath, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Event == "upload_scan" {
			t.Fatal("wrapper fabricated a scan instead of recording real file checks")
		}
	}
}

func TestSupportedSFTPSubsystemAllowsLoggingOnlyArguments(t *testing.T) {
	if !supportedSFTPSubsystem([]byte("subsystem sftp /usr/lib/sftp-server -f AUTHPRIV -l INFO\n")) {
		t.Fatal("expected standard SFTP logging arguments to be supported")
	}
	if supportedSFTPSubsystem([]byte("subsystem sftp /usr/lib/sftp-server -d /srv\n")) {
		t.Fatal("directory-changing SFTP arguments must remain unsupported")
	}
}

func TestWrapperRoutesConfiguredSFTPCommandToGuard(t *testing.T) {
	root := t.TempDir()
	scriptPath := filepath.Join(root, "wrapper")
	activityPath := filepath.Join(root, "activity.log")
	scannerPath := filepath.Join(root, "scanner")
	markerPath := filepath.Join(root, "scanner-called")
	if err := os.WriteFile(scannerPath, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+shellQuote(markerPath)+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := wrapperScript(scriptPath, models.SSHTransferPolicy{AuditTransfers: true, ScanUploads: true}, activityPath, scannerPath, "", "/usr/lib/sftp-server -f AUTHPRIV -l INFO")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"USER=root",
		"SSH_CONNECTION=192.0.2.5 4122 192.0.2.10 22",
		"SSH_ORIGINAL_COMMAND=/usr/lib/sftp-server -f AUTHPRIV -l INFO",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wrapper custom SFTP command failed: %v (%s)", err, output)
	}
	marker, err := os.ReadFile(markerPath)
	if err != nil || !strings.Contains(string(marker), "sftp-guard --scan-uploads=1") {
		t.Fatalf("configured SFTP command was not routed to guard: %s %v", marker, err)
	}
}

func TestApplyRestoresFilesWhenSSHDValidationFails(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "sshd_config")
	dropIn := filepath.Join(root, "sshd_config.d", "99-nodewall-transfer.conf")
	wrapper := filepath.Join(root, "nodewall-ssh-transfer-policy")
	sftp := filepath.Join(root, "nodewall-sftp-deny")
	state := filepath.Join(root, "ssh-transfer-state.json")
	original := []byte("Subsystem sftp internal-sftp\n")
	if err := os.WriteFile(config, original, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "sshd" {
			return nil, errors.New("invalid configuration")
		}
		return nil, nil
	}
	applier := NewWithPaths(config, dropIn, wrapper, sftp, state, runner)
	if err := applier.Apply(context.Background(), models.SSHTransferPolicy{BlockSFTP: true}); err == nil {
		t.Fatal("expected sshd validation failure")
	}
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Fatalf("expected config rollback, got %q", data)
	}
}

func TestPasswordAuthenticationPolicyIsReversible(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sshd_config")
	original := []byte("Port 22\nPasswordAuthentication yes\n")
	if err := os.WriteFile(config, original, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "sshd" && len(args) > 0 && args[0] == "-T" {
			value := "no"
			data, _ := os.ReadFile(config)
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && strings.EqualFold(fields[0], "PasswordAuthentication") {
					value = strings.ToLower(fields[1])
					break
				}
			}
			return []byte("passwordauthentication " + value + "\nkbdinteractiveauthentication " + value + "\nchallengeresponseauthentication " + value + "\n"), nil
		}
		return nil, nil
	}
	a := NewWithPaths(config, filepath.Join(dir, "drop-in"), filepath.Join(dir, "wrapper"), filepath.Join(dir, "sftp"), filepath.Join(dir, "state"), runner)
	if err := a.ApplyPasswordAuthentication(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	changed, err := os.ReadFile(config)
	if err != nil || !strings.Contains(string(changed), "PasswordAuthentication no") {
		t.Fatalf("password policy was not written: %q (%v)", changed, err)
	}
	if err := a.ClearPasswordAuthentication(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(config)
	if err != nil || string(restored) != string(original) {
		t.Fatalf("password policy did not restore original config: %q (%v)", restored, err)
	}
}

func TestPasswordAuthenticationPolicyRejectsIncompleteMarkers(t *testing.T) {
	if _, err := managedPasswordAuthentication([]byte(passwordBegin), boolPtr(true)); err == nil {
		t.Fatal("expected incomplete password policy markers to be rejected")
	}
}

func boolPtr(value bool) *bool { return &value }
