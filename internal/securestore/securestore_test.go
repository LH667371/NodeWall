package securestore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "cluster.key")
	t.Setenv(defaultKeyEnv, keyPath)
	path := filepath.Join(dir, "state.json")
	payload := []byte(`{"nodes":{"node-a":{"id":"node-a"}}}`)
	if err := Write(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) == string(payload) {
		t.Fatal("encrypted state was written as plaintext")
	}
	read, encrypted, recovered, err := ReadValid(path, func(data []byte) error {
		var value map[string]any
		return json.Unmarshal(data, &value)
	})
	if err != nil || !encrypted || recovered || string(read) != string(payload) {
		t.Fatalf("unexpected encrypted read: encrypted=%v recovered=%v err=%v data=%s", encrypted, recovered, err, read)
	}
}

func TestDamagedPrimaryRecoversFromRotatedBackup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(defaultKeyEnv, filepath.Join(dir, "cluster.key"))
	path := filepath.Join(dir, "state.json")
	first := []byte(`{"generation":1}`)
	second := []byte(`{"generation":2}`)
	if err := Write(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, second, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"format":"nodewall-encrypted-v1","nonce":"bad","ciphertext":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	read, _, recovered, err := ReadValid(path, func(data []byte) error {
		var value map[string]any
		return json.Unmarshal(data, &value)
	})
	if err != nil || !recovered || string(read) != string(first) {
		t.Fatalf("backup recovery failed: recovered=%v err=%v data=%s", recovered, err, read)
	}
}

func TestLegacyPlaintextCanBeReadWithConfiguredKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(defaultKeyEnv, filepath.Join(dir, "cluster.key"))
	path := filepath.Join(dir, "state.json")
	payload := []byte(`{"legacy":true}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	read, needsRewrite, recovered, err := ReadValid(path, func(data []byte) error {
		var value map[string]any
		return json.Unmarshal(data, &value)
	})
	if err != nil || !needsRewrite || recovered || string(read) != string(payload) {
		t.Fatalf("legacy read failed: rewrite=%v recovered=%v err=%v data=%s", needsRewrite, recovered, err, read)
	}
}
