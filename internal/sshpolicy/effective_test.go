package sshpolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nodewall/internal/models"
)

func TestPolicyRefusesConflictsIneffectiveHooksAndCustomSubsystemArguments(t *testing.T) {
	for _, mode := range []string{"conflict", "ineffective", "custom-subsystem", "valid"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			config := filepath.Join(dir, "sshd_config")
			wrapper := filepath.Join(dir, "wrapper")
			original := "Port 22\nSubsystem sftp internal-sftp\n"
			if mode == "conflict" {
				original += "ForceCommand internal-sftp\n"
			}
			if err := os.WriteFile(config, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			reloads := 0
			run := func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "sshd" && args[0] == "-T" {
					force := wrapper
					if mode == "ineffective" {
						force = "none"
					}
					sub := "internal-sftp"
					if mode == "custom-subsystem" {
						sub += " -R"
					}
					return []byte("forcecommand " + force + "\nsubsystem sftp " + sub + "\n"), nil
				}
				if name == "systemctl" {
					reloads++
				}
				return nil, nil
			}
			a := NewWithPaths(config, filepath.Join(dir, "drop-in"), wrapper, filepath.Join(dir, "sftp-deny"), filepath.Join(dir, "state"), run)
			err := a.Apply(context.Background(), models.SSHTransferPolicy{ScanUploads: true})
			data, _ := os.ReadFile(config)
			if mode == "valid" {
				if err != nil || reloads != 1 || !strings.HasPrefix(string(data), forceBegin) {
					t.Fatalf("global hook was not installed without Include: %s %v", data, err)
				}
			} else {
				if err == nil || reloads != 0 || string(data) != original {
					t.Fatalf("unsafe configuration applied: %s %v", data, err)
				}
			}
			info, _ := os.Stat(config)
			if info.Mode().Perm() != 0o600 {
				t.Fatal("sshd config permissions were widened")
			}
		})
	}
}

func TestReloadFailureRestoresOriginalFiles(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sshd_config")
	wrapper := filepath.Join(dir, "wrapper")
	original := []byte("Port 22\nSubsystem sftp internal-sftp\n")
	if err := os.WriteFile(config, original, 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithPaths(config, filepath.Join(dir, "drop-in"), wrapper, filepath.Join(dir, "sftp"), filepath.Join(dir, "state"), func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "sshd" && args[0] == "-T" {
			return []byte("forcecommand " + wrapper + "\n"), nil
		}
		if name == "systemctl" {
			return nil, errors.New("simulated reload failure")
		}
		return nil, nil
	})
	if err := a.Apply(context.Background(), models.SSHTransferPolicy{AuditCommands: true}); err == nil {
		t.Fatal("reload failure hidden")
	}
	data, _ := os.ReadFile(config)
	if string(data) != string(original) {
		t.Fatal("sshd config was not restored")
	}
}

func TestIncompatibleHelperCannotChangeSSHD(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sshd_config")
	original := []byte("Port 22\nSubsystem sftp internal-sftp\n")
	if err := os.WriteFile(config, original, 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	a := NewWithPaths(config, filepath.Join(dir, "drop-in"), filepath.Join(dir, "wrapper"), filepath.Join(dir, "sftp"), filepath.Join(dir, "state"), func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil })
	a.ScannerPath = "/bin/true"
	if err := a.Apply(context.Background(), models.SSHTransferPolicy{AuditCommands: true}); err == nil || calls != 0 {
		t.Fatal("incompatible helper was executed or allowed to change sshd")
	}
	data, _ := os.ReadFile(config)
	if string(data) != string(original) {
		t.Fatal("helper rejection changed sshd config")
	}
}

func TestIncludedMatchRestrictionsAreNotSilentlyOverridden(t *testing.T) {
	for _, directive := range []string{"ChrootDirectory /srv/sftp", "ForceCommand internal-sftp -R"} {
		dir := t.TempDir()
		include := filepath.Join(dir, "users.conf")
		config := filepath.Join(dir, "sshd_config")
		if err := os.WriteFile(include, []byte("Match User restricted\n  "+directive+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		data := []byte("Include " + include + "\nPort 22\nSubsystem sftp internal-sftp\n")
		if err := verifySSHDScopes(config, data, filepath.Join(dir, "wrapper"), filepath.Join(dir, "owned.conf")); err == nil {
			t.Fatal("included user restrictions were ignored")
		}
	}
}

func TestHelpersRemainAvailableUntilSSHDReloads(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sshd_config")
	wrapper := filepath.Join(dir, "wrapper")
	if err := os.WriteFile(config, []byte("Port 22\nSubsystem sftp internal-sftp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "sshd" && args[0] == "-T" {
			return []byte("forcecommand " + wrapper + "\n"), nil
		}
		if name == "sshd" || name == "systemctl" {
			if _, err := os.Stat(wrapper); err != nil {
				t.Error("sshd could reference a missing helper during configuration transition")
			}
		}
		return nil, nil
	}
	a := NewWithPaths(config, filepath.Join(dir, "drop-in"), wrapper, filepath.Join(dir, "sftp"), filepath.Join(dir, "state"), runner)
	if err := a.Apply(context.Background(), models.SSHTransferPolicy{AuditSessions: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(context.Background(), models.SSHTransferPolicy{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wrapper); !os.IsNotExist(err) {
		t.Fatal("disabled helper was not cleaned after reload")
	}
}

func TestMissingSFTPRecoveryStateCannotRemoveAnActiveHelper(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sshd_config")
	helper := filepath.Join(dir, "sftp-deny")
	original := []byte("Port 22\nSubsystem sftp " + helper + "\n")
	if err := os.WriteFile(config, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 126\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := NewWithPaths(config, filepath.Join(dir, "drop-in"), filepath.Join(dir, "wrapper"), helper, filepath.Join(dir, "missing-state"), func(context.Context, string, ...string) ([]byte, error) { return nil, nil })
	if err := a.Apply(context.Background(), models.SSHTransferPolicy{}); err == nil {
		t.Fatal("missing subsystem recovery state was ignored")
	}
	data, _ := os.ReadFile(config)
	if string(data) != string(original) {
		t.Fatal("uncertain subsystem was changed")
	}
	if _, err := os.Stat(helper); err != nil {
		t.Fatal("active SFTP helper was deleted")
	}
}
