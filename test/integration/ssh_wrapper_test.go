package integration

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"nodewall/internal/models"
	"nodewall/internal/sshactivity"
	"nodewall/internal/sshpolicy"
)

// Build the shipped entry point, then exercise the generated ForceCommand
// wrapper. The injected sshd/systemctl runner touches only the test config.
func TestUnifiedBinaryAndGeneratedSSHWrapper(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "nodewall")
	build := exec.Command("go", "build", "-o", binary, "nodewall/cmd/nodewall")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build unified helper: %v %s", err, output)
	}
	config, wrapper := filepath.Join(dir, "sshd_config"), filepath.Join(dir, "wrapper")
	if err := os.WriteFile(config, []byte("Port 22\nSubsystem sftp internal-sftp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == binary {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
		if name == "sshd" && args[0] == "-T" {
			return []byte("forcecommand " + wrapper + "\nsubsystem sftp internal-sftp\n"), nil
		}
		if name == "sshd" || name == "systemctl" {
			return nil, nil
		}
		return nil, errors.New("unexpected test command")
	}
	applier := sshpolicy.NewWithPaths(config, filepath.Join(dir, "drop-in"), wrapper, filepath.Join(dir, "sftp-deny"), filepath.Join(dir, "state"), runner)
	applier.ScannerPath = binary
	if err := applier.Apply(context.Background(), models.SSHTransferPolicy{AuditSessions: true, AuditCommands: true, ScanUploads: true}); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", wrapper)
	command.Env = append(os.Environ(), "SSH_CONNECTION=192.0.2.1 45678 192.0.2.2 22", "SSH_ORIGINAL_COMMAND=printf verified-helper")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil || stdout.String() != "verified-helper" {
		t.Fatalf("generated wrapper/helper failed: %v %s %s", err, stdout.String(), stderr.String())
	}
	records, err := sshactivity.Read(applier.ActivityLogPath, 100)
	if err != nil {
		t.Fatal(err)
	}
	var commandSeen, opened, closed bool
	session := ""
	for _, record := range records {
		if record.Event == "command" && record.Command == "printf verified-helper" {
			commandSeen = true
			session = record.SessionID
			if record.ExitCode == nil || *record.ExitCode != 0 {
				t.Fatal("exec exit status lost")
			}
		}
		opened = opened || record.Event == "session_open"
		closed = closed || record.Event == "session_close"
	}
	if !commandSeen || !opened || !closed || session == "" {
		t.Fatalf("wrapper audit lifecycle missing: %#v", records)
	}
	for _, record := range records {
		if record.SessionID != session {
			t.Fatal("generated wrapper session IDs diverged")
		}
	}
}
