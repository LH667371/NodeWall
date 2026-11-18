package sshkeys

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestAddListAndRemovePreserveComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte("# administrator note\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	entry, err := Add(path, line, "ops laptop")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Comment != "ops laptop" || entry.Fingerprint == "" {
		t.Fatalf("unexpected entry: %#v", entry)
	}
	entries, err := List(path)
	if err != nil || len(entries) != 1 || entries[0].Fingerprint != entry.Fingerprint {
		t.Fatalf("unexpected key list: %#v (%v)", entries, err)
	}
	if _, err := Add(path, line, "different comment"); err != nil {
		t.Fatal(err)
	}
	entries, _ = List(path)
	if len(entries) != 1 || entries[0].Comment != "ops laptop" {
		t.Fatalf("duplicate key changed existing comment: %#v", entries)
	}
	if err := Remove(path, entry.Fingerprint); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "# administrator note\n" {
		t.Fatalf("authorized_keys comments were not preserved: %q (%v)", data, err)
	}
}

func TestAddRejectsAuthorizedKeyOptions(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if _, err := Add(filepath.Join(t.TempDir(), "authorized_keys"), "restrict "+line, ""); err == nil {
		t.Fatal("authorized key options were accepted")
	}
}

func TestRemoveRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(target, []byte("ssh-ed25519 invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path, "SHA256:missing"); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("symlink was not rejected: %v", err)
	}
}

func TestFingerprintForPrivateKeyDoesNotCreateMissingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh", "id_ed25519")
	if _, err := FingerprintForPrivateKey(path); !os.IsNotExist(err) {
		t.Fatalf("missing private key was not reported without creation: %v", err)
	}
}
