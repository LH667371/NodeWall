package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nodewall/internal/clamav"
	"nodewall/internal/nodeauth"
	"nodewall/internal/transporttls"
	"nodewall/internal/xdp"
)

func TestClamAVDistributionRequiresNodeCredentialsAndHTTPS(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NODEWALL_CLAMAV_ASSETS_DIR", filepath.Join(dir, "assets"))
	t.Setenv("NODEWALL_CLAMAV_DIR", filepath.Join(dir, "data"))
	certFile := filepath.Join(dir, "node.crt")
	if err := transporttls.EnsureCertificate(certFile, filepath.Join(dir, "node.key"), "127.0.0.1:9080"); err != nil {
		t.Fatal(err)
	}
	certificate, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	token, err := nodeauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := nodeauth.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Put(nodeauth.Credential{NodeID: "node-a", AgentURL: "https://127.0.0.1:9080", Token: token, Certificate: string(certificate)}); err != nil {
		t.Fatal(err)
	}
	handler := &ServerHandler{nodeCredentials: registry}
	for _, tc := range []struct {
		url, token string
		want       int
	}{
		{"http://manager/join/clamav/manifest?arch=amd64", token, http.StatusBadRequest},
		{"https://manager/join/clamav/manifest?arch=amd64", "incorrect", http.StatusUnauthorized},
		// A valid node gets past authentication and receives the real asset
		// availability error instead of an anonymous manifest.
		{"https://manager/join/clamav/manifest?arch=amd64", token, http.StatusServiceUnavailable},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.url, nil)
		req.Header.Set(nodeauth.NodeHeader, "node-a")
		req.Header.Set("Authorization", "Bearer "+tc.token)
		rec := httptest.NewRecorder()
		handler.handleJoinClamAVManifest(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: status=%d want=%d body=%s", tc.url, rec.Code, tc.want, rec.Body.String())
		}
	}
}

func TestAgentClamAVPublishesOfflineAssetsBeforeDaemonInitialization(t *testing.T) {
	root := t.TempDir()
	assets := filepath.Join(root, "assets")
	t.Setenv("NODEWALL_CLAMAV_ASSETS_DIR", assets)
	t.Setenv("NODEWALL_CLAMAV_DIR", filepath.Join(root, "uninitialized"))
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	inventory := "clamav-libs-1.4.6-r0\n"
	if err := tw.WriteHeader(&tar.Header{Name: "PACKAGES.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(inventory))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(inventory)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"engines/amd64.tar.gz": archive.Bytes(), "database/main.cvd": []byte("ClamAV-VDB:today:10:1:90:test\n"),
		"database/daily.cvd": []byte("ClamAV-VDB:today:11:1:90:test\n"), "database/bytecode.cvd": []byte("ClamAV-VDB:today:12:1:90:test\n"),
	} {
		path := filepath.Join(assets, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	agent := NewAgentHandler("node-a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	token := "enrolled-agent-token"
	routes := nodeauth.RequireToken(token, agent.Routes())
	request := func(endpoint, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec
	}
	for _, endpoint := range []string{"/clamav/manifest?arch=amd64", "/clamav/engine/amd64?sha256=bad", "/clamav/database/daily.cvd?sha256=bad"} {
		if rec := request("https://agent"+endpoint, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s: %d", endpoint, rec.Code)
		}
		if rec := request("http://agent"+endpoint, token); rec.Code != http.StatusBadRequest {
			t.Fatalf("HTTP %s: %d", endpoint, rec.Code)
		}
	}
	rec := request("https://agent/clamav/manifest?arch=amd64", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("offline manifest unavailable: %d %s", rec.Code, rec.Body.String())
	}
	var manifest clamav.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Engine.Release != "1.4.6-r0" || len(manifest.Database) != 3 {
		t.Fatalf("incomplete offline manifest: %+v", manifest)
	}
	for _, item := range append([]clamav.Artifact{manifest.Engine}, manifest.Database...) {
		kind := "database"
		if item.Name == "amd64" {
			kind = "engine"
		}
		rec := request(fmt.Sprintf("https://agent/clamav/%s/%s?sha256=%s", kind, item.Name, item.SHA256), token)
		if rec.Code != http.StatusOK || int64(rec.Body.Len()) != item.Size || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("offline download %s: %d %s", item.Name, rec.Code, rec.Body.String())
		}
	}
	if rec := request("https://agent/clamav/database/daily.cvd?sha256=outdated", token); rec.Code != http.StatusConflict {
		t.Fatalf("stale manifest digest accepted: %d", rec.Code)
	}
}
