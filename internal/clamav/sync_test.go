package clamav

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func testEngineArchive(t *testing.T, evil bool) []byte {
	return testEngineReleaseArchive(t, "", nil, evil)
}

func testEngineReleaseArchive(t *testing.T, release string, overrides map[string]string, evil bool) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engine.tgz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	entries := map[string]string{
		"lib/" + loaderName(runtime.GOARCH): "#!/bin/sh\nshift; shift; exec \"$@\"\n",
		"usr/sbin/clamd":                    "#!/bin/sh\nexit 0\n",
		"usr/bin/freshclam":                 "#!/bin/sh\nexit 0\n",
		"usr/bin/clamscan":                  "#!/bin/sh\nexit 0\n",
		"usr/bin/sigtool":                   "#!/bin/sh\necho 'Verification OK.'\n",
		"etc/ssl/cert.pem":                  "test certificate bundle\n",
	}
	entries["lib/"+loaderName(otherArchitecture())] = "#!/bin/sh\nshift; shift; exec \"$@\"\n"
	if release != "" {
		entries["PACKAGES.txt"] = "clamav-libs-" + release + " - ClamAV runtime libraries\n"
	}
	for name, content := range overrides {
		entries[name] = content
	}
	if evil {
		entries["../escape"] = "bad"
	}
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testArtifact(name string, version uint64, data []byte) Artifact {
	hash := sha256.Sum256(data)
	return Artifact{Name: name, Version: version, SHA256: hex.EncodeToString(hash[:]), Size: int64(len(data))}
}

func TestManagerSyncRejectsCorruptionAndDowngrade(t *testing.T) {
	engine := testEngineArchive(t, false)
	database := map[string][]byte{}
	for _, name := range databaseNames {
		database[name+".cvd"] = []byte("ClamAV-VDB:today:10:1:90:test\n")
	}
	var mode atomic.Int32
	var http2Seen atomic.Bool
	manifest := func(arch string) Manifest {
		result := Manifest{Engine: testArtifact(arch, 0, engine)}
		for _, name := range databaseNames {
			file := name + ".cvd"
			version := uint64(10)
			if name == "daily" && mode.Load() != 0 {
				version = 11
			}
			content := database[file]
			if version == 11 {
				content = []byte("ClamAV-VDB:today:11:1:90:test\n")
			}
			result.Database = append(result.Database, testArtifact(file, version, content))
		}
		return result
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			http2Seen.Store(true)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("X-Nodewall-Node-ID") != "test-node" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if mode.Load() == 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/join/clamav/manifest" {
			_ = json.NewEncoder(w).Encode(manifest(r.URL.Query().Get("arch")))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/join/clamav/engine/") {
			_, _ = w.Write(engine)
			return
		}
		name := filepath.Base(r.URL.Path)
		if name == "daily.cvd" && mode.Load() == 2 {
			_, _ = w.Write([]byte("ClamAV-VDB:today:11:1:90:test\n"))
			return
		}
		_, _ = w.Write(database[name]) // Mode 1 corrupts the advertised v11 download.
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	root := t.TempDir()
	ca := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{AssetsDir: filepath.Join(root, "assets"), DataDir: filepath.Join(root, "data"), NodeID: "test-node", Token: "test-token", TLSCAFile: ca}
	if _, err := syncFromManager(context.Background(), opts, server.URL); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if !http2Seen.Load() {
		t.Fatal("manager sync did not negotiate HTTP/2")
	}
	before, err := os.Readlink(filepath.Join(opts.DataDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	mode.Store(1)
	if _, err := syncFromManager(context.Background(), opts, server.URL); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("corrupt database was accepted: %v", err)
	}
	after, err := os.Readlink(filepath.Join(opts.DataDir, "current"))
	if err != nil || after != before {
		t.Fatalf("corrupt update changed the active database: %q %v", after, err)
	}
	mode.Store(3)
	if _, err := syncFromManager(context.Background(), opts, server.URL); err == nil {
		t.Fatal("offline manager was accepted")
	}
	mode.Store(2)
	if _, err := syncFromManager(context.Background(), opts, server.URL); err != nil {
		t.Fatalf("retry after reconnect: %v", err)
	}
	current, err := currentVersions(opts.DataDir)
	if err != nil || current["daily"] != 11 {
		t.Fatalf("node did not catch up after reconnect: %v %v", current, err)
	}
	if _, err := compareVersions(map[string]uint64{"main": 10, "daily": 11, "bytecode": 10}, map[string]uint64{"main": 10, "daily": 10, "bytecode": 10}); err == nil {
		t.Fatal("database downgrade was accepted")
	}
}

func TestEngineArchiveCannotEscapeItsDirectory(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "engine.tgz")
	if err := os.WriteFile(archive, testEngineArchive(t, true), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := extractEngine(archive, root); err == nil {
		t.Fatal("archive traversal was accepted")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape")); !os.IsNotExist(err) {
		t.Fatalf("archive escaped destination: %v", err)
	}
}

func TestBundleInstallPreservesPreviousAssetsOnFailure(t *testing.T) {
	root := t.TempDir()
	release := filepath.Join(root, "release")
	executable := filepath.Join(release, "bin", "nodewall")
	installed := filepath.Join(root, "installed")
	old := filepath.Join(installed, "clamav", "engines", "amd64.tar.gz")
	if err := os.MkdirAll(filepath.Dir(old), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(release, "clamav"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InstallBundle(executable, installed); err == nil {
		t.Fatal("incomplete offline bundle was accepted")
	}
	content, err := os.ReadFile(old)
	if err != nil || string(content) != "previous" {
		t.Fatalf("previous bundle was changed: %q %v", content, err)
	}
}

func TestBundleInstallWithoutOfflineAssetsPreservesPreviousBundle(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "update", "bin", "nodewall")
	installed := filepath.Join(root, "installed")
	old := filepath.Join(installed, "clamav", "engines", "amd64.tar.gz")
	if err := os.MkdirAll(filepath.Dir(old), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallBundle(executable, installed); err != nil {
		t.Fatalf("install update without an offline bundle: %v", err)
	}
	content, err := os.ReadFile(old)
	if err != nil || string(content) != "previous" {
		t.Fatalf("previous bundle was changed: %q %v", content, err)
	}
}

func TestFailedReloadRestoresPreviousDatabase(t *testing.T) {
	root := t.TempDir()
	assets := filepath.Join(root, "assets")
	archive := filepath.Join(assets, "engines", runtime.GOARCH+".tar.gz")
	if err := os.MkdirAll(filepath.Dir(archive), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, testEngineArchive(t, false), 0o600); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	engine, err := prepareEngine(assets, data, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	stage := func(version int) string {
		dir, err := newDatabaseStage(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range databaseNames {
			content := fmt.Sprintf("ClamAV-VDB:today:%d:1:90:test\n", version)
			if err := os.WriteFile(filepath.Join(dir, name+".cvd"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	if err := validateAndCommit(context.Background(), data, stage(10), engine, runtime.GOARCH, ""); err != nil {
		t.Fatal(err)
	}
	before, err := os.Readlink(filepath.Join(data, "current"))
	if err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("/tmp", "nw-clam-sock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "clamd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = io.CopyN(io.Discard, conn, int64(len("zRELOAD\x00")))
			_, _ = io.WriteString(conn, "ERROR\x00")
			_ = conn.Close()
		}
	}()
	if err := validateAndCommit(context.Background(), data, stage(11), engine, runtime.GOARCH, socket); err == nil {
		t.Fatal("failed reload was accepted")
	}
	after, err := os.Readlink(filepath.Join(data, "current"))
	if err != nil || after != before {
		t.Fatalf("previous database was not restored: %q %v", after, err)
	}
}

func TestDatabaseVersionRejectsIncompleteHeaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daily.cvd")
	for _, tc := range []struct {
		content string
		want    uint64
	}{
		{"ClamAV-VDB:today:28179:1:90:test", 28179},
		{"ClamAV-VDB:today:nope:1:90:test", 0},
		{"not a database", 0},
	} {
		if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := databaseVersion(path)
		if got != tc.want || (err != nil) != (tc.want == 0) {
			t.Fatal(fmt.Sprintf("version(%q) = %d, %v", tc.content, got, err))
		}
	}
}

func TestFreshclamUsesPrivateCertificateBundle(t *testing.T) {
	t.Setenv("CURL_CA_BUNDLE", "/old/curl.pem")
	t.Setenv("SSL_CERT_FILE", "/old/ssl.pem")
	for _, tc := range []struct{ configured, want string }{
		{"", "/engine/etc/ssl/cert.pem"},
		{"/etc/company/roots.pem", "/etc/company/roots.pem"},
	} {
		t.Setenv("NODEWALL_CLAMAV_CA_FILE", tc.configured)
		command := engineCommand(context.Background(), "/engine", runtime.GOARCH, "bin/freshclam")
		values := map[string]string{}
		for _, item := range command.Env {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) == 2 && (parts[0] == "CURL_CA_BUNDLE" || parts[0] == "SSL_CERT_FILE") {
				values[parts[0]] = parts[1]
			}
		}
		if values["CURL_CA_BUNDLE"] != tc.want || values["SSL_CERT_FILE"] != tc.want {
			t.Fatalf("certificate bundle = %#v, want %q", values, tc.want)
		}
	}
}
