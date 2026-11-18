package runtime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nodewall/internal/nodeauth"
	"nodewall/internal/securestore"
)

func TestClamAVPeersRefreshesEncryptedRegistryWithoutWritingOrCreatingKeys(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "node-credentials.json")
	key := filepath.Join(root, "cluster.key")
	t.Setenv("NODEWALL_CLUSTER_KEY_FILE", key)
	peers := clamAVPeers(path)
	if got, err := peers(); err != nil || len(got) != 0 {
		t.Fatalf("missing registry: %v %v", got, err)
	}
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatalf("peer discovery generated a cluster key: %v", err)
	}
	if _, err := securestore.EnsureKey(key); err != nil {
		t.Fatal(err)
	}
	credentials := map[string]nodeauth.Credential{
		"node-b": {NodeID: "node-b", AgentURL: "https://192.0.2.2:9080", Token: strings.Repeat("b", 64), Certificate: "enrolled-b"},
	}
	write := func() []byte {
		t.Helper()
		data, err := json.Marshal(credentials)
		if err != nil {
			t.Fatal(err)
		}
		if err := securestore.Write(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	write()
	if got, err := peers(); err != nil || len(got) != 1 || got[0] != credentials["node-b"] {
		t.Fatalf("initial registry: %v %v", got, err)
	}
	credentials["node-a"] = nodeauth.Credential{NodeID: "node-a", AgentURL: "https://192.0.2.1:9080", Token: strings.Repeat("a", 64), Certificate: "enrolled-a"}
	before := write()
	if got, err := peers(); err != nil || len(got) != 2 || got[0].NodeID != "node-a" || got[1].NodeID != "node-b" {
		t.Fatalf("later enrollment was not discovered: %v %v", got, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("peer discovery rewrote the registry: %v", err)
	}
	if _, err := os.Stat(path + ".bak.2"); !os.IsNotExist(err) {
		t.Fatalf("peer discovery rotated registry backups: %v", err)
	}
	if err := os.WriteFile(path, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := peers(); err != nil || len(got) != 1 || got[0].NodeID != "node-b" {
		t.Fatalf("encrypted backup recovery: %v %v", got, err)
	}
	broken, _ := os.ReadFile(path)
	if string(broken) != "broken" {
		t.Fatal("read-only discovery replaced a damaged registry")
	}
}

func TestClamAVPeersRejectsDamagedAndMismatchedEntries(t *testing.T) {
	t.Setenv("NODEWALL_CLUSTER_KEY_FILE", "")
	path := filepath.Join(t.TempDir(), "node-credentials.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	peers := clamAVPeers(path)
	if _, err := peers(); err == nil {
		t.Fatal("damaged registry was accepted")
	}
	data, _ := json.Marshal(map[string]nodeauth.Credential{
		"different": {NodeID: "node-a", AgentURL: "https://192.0.2.1:9080", Token: strings.Repeat("a", 64), Certificate: "enrolled"},
		"no-cert":   {NodeID: "no-cert", AgentURL: "https://192.0.2.2:9080", Token: strings.Repeat("b", 64)},
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := peers(); err != nil || len(got) != 0 {
		t.Fatalf("invalid registry entries were accepted: %v %v", got, err)
	}
}
