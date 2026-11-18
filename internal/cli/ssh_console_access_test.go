package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nodewall/internal/sshconsole"
)

func TestConsoleKeyInstallAndRestorePreservesAdministratorKeys(t *testing.T) {
	root := t.TempDir()
	sshDir := filepath.Join(root, "ssh")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(sshDir, "authorized_keys")
	original := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7admin administrator\n"
	if err := os.WriteFile(authorized, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "nodewall", "id_ed25519")
	publicKey, err := sshconsole.NewWithKeyPath(keyPath).PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeConsoleKey(publicKey, sshDir, configDir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(authorized)
	if err != nil || !strings.HasPrefix(string(data), original) || !strings.Contains(string(data), "nodewall-console") {
		t.Fatalf("console key was not appended safely: %q (%v)", data, err)
	}
	if err := restoreConsoleAccess(sshDir, configDir, keyPath); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(authorized)
	if err != nil || string(restored) != original {
		t.Fatalf("authorized_keys was not restored exactly: %q (%v)", restored, err)
	}
	if info, statErr := os.Stat(authorized); statErr != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("authorized_keys mode was not restored: %v %v", info, statErr)
	}
	if _, err := os.Stat(filepath.Join(configDir, "ssh-console-access.json")); !os.IsNotExist(err) {
		t.Fatalf("SSH recovery journal remains: %v", err)
	}
}

func TestConsoleKeyRestoreKeepsKeysAddedAfterInstall(t *testing.T) {
	root := t.TempDir()
	sshDir := filepath.Join(root, "ssh")
	configDir := filepath.Join(root, "config")
	keyPath := filepath.Join(root, "nodewall", "id_ed25519")
	publicKey, err := sshconsole.NewWithKeyPath(keyPath).PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeConsoleKey(publicKey, sshDir, configDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDir, "authorized_keys")
	data, _ := os.ReadFile(path)
	data = append(data, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7new later-admin\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreConsoleAccess(sshDir, configDir, keyPath); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(path)
	if !strings.Contains(string(restored), "later-admin") || strings.Contains(string(restored), "nodewall-console") {
		t.Fatalf("restore removed an administrator key or retained NodeWall key: %q", restored)
	}
}

func TestLegacyConsoleKeyRestoreRemovesAllReservedKeys(t *testing.T) {
	root := t.TempDir()
	sshDir := filepath.Join(root, "ssh")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := sshconsole.NewWithKeyPath(filepath.Join(root, "first", "id_ed25519")).PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := sshconsole.NewWithKeyPath(filepath.Join(root, "second", "id_ed25519")).PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDir, "authorized_keys")
	data := []byte(strings.TrimSpace(first) + " nodewall-console\n" + strings.TrimSpace(second) + " nodewall-console\n" + "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7admin administrator\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// No recovery journal models an installation created by an older version.
	if err := restoreConsoleAccess(sshDir, configDir, filepath.Join(root, "missing", "id_ed25519")); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(restored), "nodewall-console") || !strings.Contains(string(restored), "administrator") {
		t.Fatalf("legacy NodeWall keys were not removed safely: %q", restored)
	}
}
