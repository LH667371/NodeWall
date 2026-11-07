package sshaudit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodewall/internal/sshactivity"
)

func TestBashCommandAuditPreservesStatusAndDoesNotRecordPasswordInput(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	for _, interactive := range []bool{false, true} {
		t.Run(map[bool]string{true: "interactive", false: "script"}[interactive], func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			t.Setenv("BASH_ENV", "")
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := Run(ctx, Options{Shell: bash, Interactive: interactive, ActivityLog: filepath.Join(dir, "audit"), Identity: sshactivity.Record{SessionID: "session-a", User: "root"},
				Stdin: strings.NewReader("printf 'hello\\n'\nfalse\nprintf 'status=%s\\n' \"$?\"\nread -rs secret\nvery-private-password\nprintf 'done\\n'\nexit 7\n"), Stdout: &stdout, Stderr: &stderr})
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 7 {
				t.Fatalf("shell exit changed: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "status=1") {
				t.Fatalf("DEBUG hook changed last command status: %s", stdout.String())
			}
			records, err := sshactivity.Read(filepath.Join(dir, "audit"), 100)
			if err != nil {
				t.Fatal(err)
			}
			var hello, exitSeen bool
			for _, record := range records {
				if strings.Contains(record.Command, "very-private-password") {
					t.Fatal("password input was logged as a command")
				}
				if record.Event == "command" {
					hello = hello || strings.Contains(record.Command, "hello")
					exitSeen = exitSeen || record.Command == "exit 7"
					if record.SessionID != "session-a" {
						t.Fatal("session association lost")
					}
				}
			}
			if !hello || !exitSeen {
				t.Fatalf("shell commands missing: %#v stderr=%s", records, stderr.String())
			}
		})
	}
}

func TestAuditFailureDoesNotRemoveSSHAccess(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-directory")
	if err := os.WriteFile(bad, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", bad)
	var stdout, stderr bytes.Buffer
	err = Run(context.Background(), Options{Shell: bash, ActivityLog: filepath.Join(dir, "audit"), Stdin: strings.NewReader("printf available\n"), Stdout: &stdout, Stderr: &stderr})
	if err != nil || stdout.String() != "available" {
		t.Fatalf("audit setup failure disconnected SSH: %v %s", err, stderr.String())
	}
	records, _ := sshactivity.Read(filepath.Join(dir, "audit"), 10)
	if len(records) != 1 || records[0].Event != "audit_status" || records[0].Action != "unavailable" {
		t.Fatal("degraded audit was hidden")
	}
}

func TestUnsupportedShellIsPreservedAndReported(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	err := Run(context.Background(), Options{Shell: "/bin/sh", ActivityLog: filepath.Join(dir, "audit"), Stdin: strings.NewReader("printf preserved\n"), Stdout: &stdout})
	if err != nil || stdout.String() != "preserved" {
		t.Fatal("account shell behavior changed", err)
	}
	records, _ := sshactivity.Read(filepath.Join(dir, "audit"), 10)
	if len(records) != 1 || records[0].Event != "audit_status" {
		t.Fatal("unsupported shell was presented as audited")
	}
}

func TestLongCommandsAreBoundedWithoutCorruptingNextEvent(t *testing.T) {
	var commands []string
	var shortened []bool
	readCommands(strings.NewReader(strings.Repeat("x", 200000)+"\x00echo next\x00"), func(command string, truncated bool) {
		commands = append(commands, command)
		shortened = append(shortened, truncated)
	})
	if len(commands) != 2 || len(commands[0]) != 4096 || !shortened[0] || commands[1] != "echo next" || shortened[1] {
		t.Fatal("oversized command corrupted audit framing")
	}
}

func TestExistingDebugTrapIsNotOverwritten(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	dir := t.TempDir()
	original := filepath.Join(dir, "existing-init")
	if err := os.WriteFile(original, []byte("trap 'printf user-trap >&2' DEBUG\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", original)
	var stdout, stderr bytes.Buffer
	err = Run(context.Background(), Options{Shell: bash, ActivityLog: filepath.Join(dir, "audit"), Stdin: strings.NewReader("printf preserved\n"), Stdout: &stdout, Stderr: &stderr})
	if err != nil || !strings.Contains(stdout.String(), "preserved") || !strings.Contains(stderr.String(), "user-trap") {
		t.Fatal("existing shell trap behavior changed", err)
	}
	records, _ := sshactivity.Read(filepath.Join(dir, "audit"), 100)
	var unavailable bool
	for _, record := range records {
		unavailable = unavailable || record.Event == "audit_status"
	}
	if !unavailable {
		t.Fatal("audit coverage conflict was hidden")
	}
}

func TestDebugModeDoesNotSkipCommandsAfterFailure(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	var stdout, stderr bytes.Buffer
	err = Run(context.Background(), Options{Shell: bash, ActivityLog: filepath.Join(t.TempDir(), "audit"), Stdin: strings.NewReader("shopt -s extdebug\nfalse\nprintf 'status=%s\\n' \"$?\"\n"), Stdout: &stdout, Stderr: &stderr})
	if err != nil || !strings.Contains(stdout.String(), "status=1") {
		t.Fatalf("audit hook changed extdebug execution: %v %s %s", err, stdout.String(), stderr.String())
	}
}
