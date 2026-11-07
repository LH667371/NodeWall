package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"nodewall/internal/nodeauth"
)

func TestExistingAgentEnrollmentPreservesIdentityAndListeningPort(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("installer integration requires Linux")
	}
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "rejected-ticket"}[success], func(t *testing.T) {
			t.Setenv("NODEWALL_NODE_ID", "")
			t.Setenv("NODEWALL_TLS_ENABLED", "true")
			dir := t.TempDir()
			configDir := filepath.Join(dir, "config")
			installDir := filepath.Join(dir, "install")
			if err := os.MkdirAll(configDir, 0o700); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			previous := []byte("NODEWALL_INSTALL_MODE=agent-only\nNODEWALL_NODE_ID=stable-node-id\nNODEWALL_AGENT_ADDR=" + listener.Addr().String() + "\nNODEWALL_SERVER_ADDR=127.0.0.1:0\nNODEWALL_TLS_CERT=" + filepath.Join(configDir, "tls", "agent.crt") + "\nNODEWALL_TLS_KEY=" + filepath.Join(configDir, "tls", "agent.key") + "\n")
			envPath := filepath.Join(configDir, "nodewall.env")
			if err := os.WriteFile(envPath, previous, 0o600); err != nil {
				t.Fatal(err)
			}
			var enrolled nodeauth.Credential
			manager := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/join/enroll" || r.Header.Get("Authorization") != "Bearer temporary-ticket" {
					t.Error("invalid enrollment request")
				}
				_ = json.NewDecoder(r.Body).Decode(&enrolled)
				if success {
					w.WriteHeader(http.StatusCreated)
				} else {
					http.Error(w, "ticket rejected", http.StatusUnauthorized)
				}
			}))
			defer manager.Close()
			caFile := filepath.Join(dir, "manager.crt")
			if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: manager.Certificate().Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			err = runInstall([]string{"--mode", "agent-only", "--dataplane", "real", "--enable-services=false", "--config-dir", configDir, "--install-dir", installDir, "--systemd-dir", filepath.Join(dir, "systemd"), "--manager-url", manager.URL, "--manager-ca", caFile, "--join-token", "temporary-ticket", "--advertise-addr", "127.0.0.1:9080"})
			if success {
				if err != nil {
					t.Fatal(err)
				}
				if enrolled.NodeID != "stable-node-id" || enrolled.AgentURL != "https://"+listener.Addr().String() {
					t.Fatalf("re-enrollment changed identity or port: %#v", enrolled)
				}
				if readEnvValue(envPath, "NODEWALL_MANAGER_URL", "") != manager.URL {
					t.Fatal("manager address was not updated")
				}
			} else {
				if err == nil {
					t.Fatal("rejected enrollment succeeded")
				}
				actual, _ := os.ReadFile(envPath)
				if !bytes.Equal(actual, previous) {
					t.Fatal("failed enrollment changed the existing environment")
				}
			}
		})
	}
}

func TestEnrollmentCannotReplaceManagerInstallation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("installer integration requires Linux")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nodewall.env"), []byte("NODEWALL_INSTALL_MODE=all-in-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runInstall([]string{"--mode", "agent-only", "--enable-services=false", "--config-dir", dir, "--manager-url", "https://127.0.0.1:8080", "--manager-ca", "unused", "--join-token", "unused", "--advertise-addr", "127.0.0.1:9080"})
	if err == nil || !strings.Contains(err.Error(), "do not register the manager") {
		t.Fatalf("manager was allowed to become an agent: %v", err)
	}
}
