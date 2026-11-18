//go:build linux

package clamav

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"nodewall/internal/nodeauth"
)

// The real signed databases are intentionally supplied by the packaging
// workflow, keeping the normal test suite small and network independent.
func TestClamAVOfflineClusterIntegration(t *testing.T) {
	assets := os.Getenv("NODEWALL_CLAMAV_INTEGRATION_ASSETS")
	if assets == "" {
		t.Skip("set NODEWALL_CLAMAV_INTEGRATION_ASSETS to test the offline bundle")
	}
	root := t.TempDir()
	managerData := filepath.Join(root, "manager")
	engine, err := prepareEngine(assets, managerData, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if err := seedDatabase(context.Background(), assets, managerData, engine, runtime.GOARCH, ""); err != nil {
		t.Fatalf("seed manager offline: %v", err)
	}
	var unavailable atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" || r.Header.Get("X-Nodewall-Node-ID") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if unavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/clamav/manifest" {
			manifest, err := CurrentManifest(assets, managerData, r.URL.Query().Get("arch"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(manifest)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/clamav/"), "/")
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		path, err := PublishedFile(assets, managerData, parts[0], parts[1], r.URL.Query().Get("sha256"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.ServeFile(w, r, path)
	}))
	defer server.Close()
	ca := filepath.Join(root, "manager.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	node := func(name string) Options {
		return Options{
			AssetsDir: filepath.Join(root, name, "assets"), DataDir: filepath.Join(root, name, "data"),
			NodeID: name, Token: "fixture-token", TLSCAFile: ca,
			Peers: func() ([]nodeauth.Credential, error) {
				return []nodeauth.Credential{{
					NodeID: "offline-peer", AgentURL: server.URL, Token: "fixture-token",
					Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
				}}, nil
			},
		}
	}
	first, second := node("node-a"), node("node-b")
	if _, _, err := syncFromCluster(context.Background(), first, ""); err != nil {
		t.Fatalf("first node sync: %v", err)
	}
	unavailable.Store(true)
	if _, _, err := syncFromCluster(context.Background(), second, ""); err == nil {
		t.Fatal("offline manager unexpectedly succeeded")
	}
	unavailable.Store(false)
	if _, _, err := syncFromCluster(context.Background(), second, ""); err != nil {
		t.Fatalf("second node did not recover after reconnect: %v", err)
	}
	for _, opts := range []Options{first, second} {
		versions, err := currentVersions(opts.DataDir)
		if err != nil || versions["main"] == 0 || versions["daily"] == 0 || versions["bytecode"] == 0 {
			t.Fatalf("incomplete database on %s: %v %v", opts.NodeID, versions, err)
		}
		for _, arch := range []string{"amd64", "arm64"} {
			if info, err := os.Stat(filepath.Join(opts.AssetsDir, "engines", arch+".tar.gz")); err != nil || info.Size() == 0 {
				t.Fatalf("standby %s lacks %s engine: %v", opts.NodeID, arch, err)
			}
		}
	}
}
