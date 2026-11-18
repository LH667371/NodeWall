package cli

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nodewall/internal/nodeauth"
)

func TestPromoteAgentToStandbySynchronizesManagerResources(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	token, err := nodeauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(configDir, "agent-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(nodeauth.NodeHeader) != "node-a" || r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "bad node auth", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/join/bootstrap/state":
			_, _ = w.Write([]byte(`{"nodes":{},"policies":{},"history":{}}`))
		case "/join/bootstrap/credentials":
			_, _ = w.Write([]byte(`{}`))
		case "/join/bootstrap/auth":
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer manager.Close()
	caPath := filepath.Join(dir, "manager.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: manager.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(configDir, "nodewall.env")
	if err := os.WriteFile(envPath, []byte(strings.Join([]string{
		"NODEWALL_INSTALL_MODE=agent-only",
		"NODEWALL_NODE_ID=node-a",
		"NODEWALL_MANAGER_URL=" + manager.URL,
		"NODEWALL_AGENT_TOKEN_FILE=" + tokenPath,
		"NODEWALL_TLS_CA=" + caPath,
		"NODEWALL_SERVER_STATE=" + filepath.Join(configDir, "server-state.json"),
		"NODEWALL_NODE_CREDENTIALS_FILE=" + filepath.Join(configDir, "node-credentials.json"),
		"NODEWALL_AUTH_FILE=" + filepath.Join(configDir, "auth.json"),
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	promoted, err := promoteAgentToStandby(envPath, configDir)
	if err != nil || !promoted {
		t.Fatalf("standby promotion failed: promoted=%v err=%v", promoted, err)
	}
	if got := readEnvValue(envPath, "NODEWALL_INSTALL_MODE", ""); got != "all-in-one" {
		t.Fatalf("install mode was not promoted: %q", got)
	}
	for _, path := range []string{"server-state.json", "node-credentials.json", "auth.json"} {
		if _, err := os.Stat(filepath.Join(configDir, path)); err != nil {
			t.Fatalf("standby resource %s was not written: %v", path, err)
		}
	}
}
