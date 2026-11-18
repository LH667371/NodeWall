package clamav

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nodewall/internal/nodeauth"
)

type clusterPeerFixture struct {
	mu          sync.RWMutex
	opts        Options
	server      *httptest.Server
	credential  nodeauth.Credential
	downloads   atomic.Int32
	corrupt     bool
	fakeRelease string
}

func newClusterPeerFixture(t *testing.T, id string, opts Options, certificates ...tls.Certificate) *clusterPeerFixture {
	t.Helper()
	if opts.AssetsDir == "" {
		root := t.TempDir()
		opts = Options{AssetsDir: filepath.Join(root, "assets"), DataDir: filepath.Join(root, "data"), NodeID: id}
	}
	fixture := &clusterPeerFixture{opts: opts, credential: nodeauth.Credential{NodeID: id, Token: strings.Repeat(id, 32)}}
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.RLock()
		defer fixture.mu.RUnlock()
		if r.Header.Get(nodeauth.NodeHeader) != id || r.Header.Get("Authorization") != "Bearer "+fixture.credential.Token {
			http.Error(w, "wrong peer credential", http.StatusUnauthorized)
			return
		}
		prefix := "/clamav/"
		if strings.HasPrefix(r.URL.Path, "/join/") {
			prefix = "/join/clamav/"
		}
		if r.URL.Path == prefix+"manifest" {
			manifest, err := CurrentManifest(opts.AssetsDir, opts.DataDir, r.URL.Query().Get("arch"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			if fixture.fakeRelease != "" {
				manifest.Engine.Release = fixture.fakeRelease
			}
			_ = json.NewEncoder(w).Encode(manifest)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		path, err := PublishedFile(opts.AssetsDir, opts.DataDir, parts[0], parts[1], r.URL.Query().Get("sha256"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		fixture.downloads.Add(1)
		if fixture.corrupt && parts[0] == "database" {
			_, _ = w.Write([]byte("corrupted database"))
			return
		}
		http.ServeFile(w, r, path)
	}))
	fixture.server.EnableHTTP2 = true
	if len(certificates) != 0 {
		fixture.server.TLS = &tls.Config{Certificates: certificates}
	}
	fixture.server.StartTLS()
	t.Cleanup(fixture.server.Close)
	fixture.credential.AgentURL = fixture.server.URL
	fixture.credential.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.server.Certificate().Raw}))
	return fixture
}

func (fixture *clusterPeerFixture) bundle(t *testing.T, release string, versions map[string]uint64, overrides map[string]string) {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	archive := testEngineReleaseArchive(t, release, overrides, false)
	for _, arch := range []string{"amd64", "arm64"} {
		writeClusterFixtureFile(t, filepath.Join(fixture.opts.AssetsDir, "engines", arch+".tar.gz"), archive)
	}
	for _, name := range databaseNames {
		content := fmt.Sprintf("ClamAV-VDB:today:%d:1:90:test\n", versions[name])
		writeClusterFixtureFile(t, filepath.Join(fixture.opts.AssetsDir, "database", name+".cvd"), []byte(content))
	}
}

func writeClusterFixtureFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".fixture-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		t.Fatal(err)
	}
}

func fixtureVersions(main, daily, bytecode uint64) map[string]uint64 {
	return map[string]uint64{"main": main, "daily": daily, "bytecode": bytecode}
}

func clusterReceiver(t *testing.T, id string, peers ...*clusterPeerFixture) Options {
	t.Helper()
	root := t.TempDir()
	return Options{
		AssetsDir: filepath.Join(root, "assets"), DataDir: filepath.Join(root, "data"), NodeID: id,
		Peers: func() ([]nodeauth.Credential, error) {
			result := make([]nodeauth.Credential, 0, len(peers))
			for _, peer := range peers {
				result = append(result, peer.credential)
			}
			return result, nil
		},
	}
}

func assertClusterVersions(t *testing.T, opts Options, want map[string]uint64) {
	t.Helper()
	got, err := currentVersions(opts.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	for name, version := range want {
		if got[name] != version {
			t.Fatalf("%s version = %d, want %d (all=%v)", name, got[name], version, got)
		}
	}
}

func TestClusterSyncBootstrapsOriginalManagerFromAnyPeerAndRedistributes(t *testing.T) {
	peer := newClusterPeerFixture(t, "offline-node", Options{})
	peer.bundle(t, "1.4.6-r0", fixtureVersions(10, 10, 10), nil)
	manager := clusterReceiver(t, "original-manager", peer)
	if _, _, err := syncFromCluster(t.Context(), manager, ""); err != nil {
		t.Fatalf("manager without assets could not pull an uninitialized offline bundle: %v", err)
	}
	assertClusterVersions(t, manager, fixtureVersions(10, 10, 10))
	downloads := peer.downloads.Load()
	if downloads != 5 {
		t.Fatalf("downloaded %d artifacts, want two engines and three databases", downloads)
	}
	if _, _, err := syncFromCluster(t.Context(), manager, ""); err != nil {
		t.Fatal(err)
	}
	if peer.downloads.Load() != downloads {
		t.Fatal("unchanged assets were downloaded again")
	}
	relay := newClusterPeerFixture(t, "original-manager", manager)
	third := clusterReceiver(t, "new-node", relay)
	if _, _, err := syncFromCluster(t.Context(), third, ""); err != nil {
		t.Fatalf("new node could not pull previously synchronized resources: %v", err)
	}
	assertClusterVersions(t, third, fixtureVersions(10, 10, 10))
	for _, arch := range []string{"amd64", "arm64"} {
		manifest, err := CurrentManifest(third.AssetsDir, third.DataDir, arch)
		if err != nil || manifest.Engine.Release != "1.4.6-r0" {
			t.Fatalf("redistributed %s engine: %+v, %v", arch, manifest.Engine, err)
		}
	}
}

func TestClusterSyncMergesNewestFilesAndPropagatesEngineUpgrade(t *testing.T) {
	first := newClusterPeerFixture(t, "first", Options{})
	first.bundle(t, "1.4.6-r0", fixtureVersions(10, 12, 10), nil)
	second := newClusterPeerFixture(t, "second", Options{})
	second.bundle(t, "1.4.7-r1", fixtureVersions(11, 11, 11), nil)
	local := newClusterPeerFixture(t, "local", Options{})
	local.bundle(t, "1.4.8-r0", fixtureVersions(12, 10, 10), nil)
	opts := local.opts
	opts.Peers = clusterReceiver(t, "local", first, second, local).Peers
	engine, err := prepareEngine(opts.AssetsDir, opts.DataDir, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if err := seedDatabase(t.Context(), opts.AssetsDir, opts.DataDir, engine, runtime.GOARCH, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := syncFromCluster(t.Context(), opts, ""); err != nil {
		t.Fatal(err)
	}
	assertClusterVersions(t, opts, fixtureVersions(12, 12, 11))
	manifest, err := CurrentManifest(opts.AssetsDir, opts.DataDir, runtime.GOARCH)
	if err != nil || manifest.Engine.Release != "1.4.8-r0" {
		t.Fatalf("newer local engine was replaced: %+v %v", manifest.Engine, err)
	}
	second.bundle(t, "1.4.9-r1", fixtureVersions(11, 11, 11), nil)
	upgraded, _, err := syncFromCluster(t.Context(), opts, "")
	if err != nil || upgraded == engine {
		t.Fatalf("engine-only upgrade was not applied: %q %v", upgraded, err)
	}
	assertClusterVersions(t, opts, fixtureVersions(12, 12, 11))
	for _, arch := range []string{"amd64", "arm64"} {
		manifest, err := CurrentManifest(opts.AssetsDir, opts.DataDir, arch)
		if err != nil || manifest.Engine.Release != "1.4.9-r1" {
			t.Fatalf("engine upgrade %s: %+v %v", arch, manifest.Engine, err)
		}
	}
	downloads := second.downloads.Load()
	// Same-release rebuilds have a different digest but must not oscillate.
	second.bundle(t, "1.4.9-r1", fixtureVersions(11, 11, 11), map[string]string{"build.txt": "rebuilt"})
	if _, _, err := syncFromCluster(t.Context(), opts, ""); err != nil {
		t.Fatal(err)
	}
	if second.downloads.Load() != downloads {
		t.Fatal("same-release rebuild replaced a working engine")
	}
}

func TestClusterSyncFallsBackFromUnavailableManagerAndPinsPeerTLS(t *testing.T) {
	manager := newClusterPeerFixture(t, "empty-manager", Options{})
	peer := newClusterPeerFixture(t, "peer", Options{})
	peer.bundle(t, "1.4.6-r0", fixtureVersions(10, 10, 10), nil)
	opts := clusterReceiver(t, "receiver", peer)
	opts.NodeID, opts.Token = manager.credential.NodeID, manager.credential.Token
	ca := filepath.Join(t.TempDir(), "manager.pem")
	if err := os.WriteFile(ca, []byte(manager.credential.Certificate), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.TLSCAFile = ca
	if _, _, err := syncFromCluster(t.Context(), opts, manager.server.URL); err != nil {
		t.Fatalf("unavailable manager blocked a healthy peer: %v", err)
	}
	assertClusterVersions(t, opts, fixtureVersions(10, 10, 10))
	bad := peer.credential
	bad.Certificate = "not an enrolled certificate"
	opts.Peers = func() ([]nodeauth.Credential, error) { return []nodeauth.Credential{bad}, nil }
	if _, _, err := syncFromCluster(t.Context(), opts, ""); err == nil {
		t.Fatal("unverified peer certificate was accepted")
	}
	assertClusterVersions(t, opts, fixtureVersions(10, 10, 10))
}

func TestClusterSyncSupportsLegacyPinnedLeafAndRejectsDifferentCertificate(t *testing.T) {
	certificate := func(serial int64) tls.Certificate {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	}
	peer := newClusterPeerFixture(t, "legacy", Options{}, certificate(1))
	peer.bundle(t, "1.4.6-r0", fixtureVersions(10, 10, 10), nil)
	opts := clusterReceiver(t, "receiver", peer)
	if _, _, err := syncFromCluster(t.Context(), opts, ""); err != nil {
		t.Fatalf("enrolled legacy leaf certificate was rejected: %v", err)
	}
	other := certificate(2)
	bad := peer.credential
	bad.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Certificate[0]}))
	opts.Peers = func() ([]nodeauth.Credential, error) { return []nodeauth.Credential{bad}, nil }
	if _, _, err := syncFromCluster(t.Context(), opts, ""); err == nil {
		t.Fatal("peer presenting a different valid certificate was accepted")
	}
	assertClusterVersions(t, opts, fixtureVersions(10, 10, 10))
}

func TestClusterSyncRejectsBadUpdatesAndPreservesWorkingSet(t *testing.T) {
	for _, tc := range []struct {
		name      string
		corrupt   bool
		fake      string
		overrides map[string]string
	}{
		{name: "corrupt download", corrupt: true},
		{name: "forged release", fake: "9.0.0-r0"},
		{name: "signature verification", overrides: map[string]string{"usr/bin/sigtool": "#!/bin/sh\nexit 1\n"}},
		{name: "database loading", overrides: map[string]string{"usr/bin/clamscan": "#!/bin/sh\nexit 2\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newClusterPeerFixture(t, "source", Options{})
			peer.bundle(t, "1.4.6-r0", fixtureVersions(10, 10, 10), nil)
			opts := clusterReceiver(t, "receiver", peer)
			if _, _, err := syncFromCluster(t.Context(), opts, ""); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Readlink(filepath.Join(opts.DataDir, "current"))
			archive := filepath.Join(opts.AssetsDir, "engines", runtime.GOARCH+".tar.gz")
			oldDigest, _, _ := fileDigest(archive)
			peer.bundle(t, "1.4.7-r0", fixtureVersions(10, 11, 10), tc.overrides)
			peer.mu.Lock()
			peer.corrupt, peer.fakeRelease = tc.corrupt, tc.fake
			peer.mu.Unlock()
			if _, _, err := syncFromCluster(t.Context(), opts, ""); err == nil {
				t.Fatal("bad update was accepted")
			}
			after, _ := os.Readlink(filepath.Join(opts.DataDir, "current"))
			newDigest, _, _ := fileDigest(archive)
			if after != before || newDigest != oldDigest {
				t.Fatal("failed update replaced the working engine or database")
			}
			assertClusterVersions(t, opts, fixtureVersions(10, 10, 10))
		})
	}
}

func TestClamAVSupervisorDiscoversLaterEnrollmentAndRestartsUpgradedEngine(t *testing.T) {
	peer := newClusterPeerFixture(t, "later-peer", Options{})
	logPath := filepath.Join(t.TempDir(), "daemon.log")
	updateLog := filepath.Join(t.TempDir(), "updates.log")
	t.Setenv("NODEWALL_TEST_CLAMD_LOG", logPath)
	t.Setenv("NODEWALL_TEST_FRESHCLAM_LOG", updateLog)
	commands := func(release string) map[string]string {
		return map[string]string{
			"usr/sbin/clamd":    "#!/bin/sh\nprintf '%s\\n' '" + release + "' >> \"$NODEWALL_TEST_CLAMD_LOG\"\nexec sleep 3600\n",
			"usr/bin/freshclam": "#!/bin/sh\necho update >> \"$NODEWALL_TEST_FRESHCLAM_LOG\"\nexit 0\n",
		}
	}
	peer.bundle(t, "1.4.6-r0", fixtureVersions(10, 10, 10), commands("1.4.6"))
	opts := clusterReceiver(t, "original", peer)
	var enrolled atomic.Bool
	peers := opts.Peers
	opts.Peers = func() ([]nodeauth.Credential, error) {
		if !enrolled.Load() {
			return nil, nil
		}
		return peers()
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runManaged(ctx, opts, 20*time.Millisecond)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("ClamAV supervisor did not stop")
		}
	})
	waitForCluster(t, func() bool {
		_, err := os.Stat(filepath.Join(opts.DataDir, "managed"))
		return err == nil
	})
	select {
	case <-done:
		t.Fatal("manager without assets stopped checking for later enrollments")
	default:
	}
	enrolled.Store(true)
	waitForCluster(t, func() bool {
		data, _ := os.ReadFile(logPath)
		return strings.Contains(string(data), "1.4.6")
	})
	peer.bundle(t, "1.4.7-r0", fixtureVersions(10, 11, 10), commands("1.4.7"))
	waitForCluster(t, func() bool {
		data, _ := os.ReadFile(logPath)
		return strings.Contains(string(data), "1.4.7") && !readUpdateStatus(opts.DataDir).LastSuccess.IsZero()
	})
	assertClusterVersions(t, opts, fixtureVersions(10, 11, 10))
	cancel()
	<-done
	updates, err := os.ReadFile(updateLog)
	if err != nil || strings.Count(string(updates), "update") != 1 {
		t.Fatalf("cluster polling repeated upstream updates: %q %v", updates, err)
	}
}

func waitForCluster(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for ClamAV cluster synchronization")
}

func TestClamAVSupervisorRetainsUpstreamFailureBetweenHourlyRetries(t *testing.T) {
	local := newClusterPeerFixture(t, "standalone", Options{})
	local.bundle(t, "1.4.6-r0", fixtureVersions(10, 10, 10), map[string]string{
		"usr/sbin/clamd":    "#!/bin/sh\nexec sleep 3600\n",
		"usr/bin/freshclam": "#!/bin/sh\necho mirror-unavailable >&2\nexit 1\n",
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runManaged(ctx, local.opts, 20*time.Millisecond)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("standalone supervisor did not stop")
		}
	})
	waitForCluster(t, func() bool { return strings.Contains(readUpdateStatus(local.opts.DataDir).Error, "mirror-unavailable") })
	first := readUpdateStatus(local.opts.DataDir)
	waitForCluster(t, func() bool { return readUpdateStatus(local.opts.DataDir).LastAttempt.After(first.LastAttempt) })
	status := readUpdateStatus(local.opts.DataDir)
	if status.Error != first.Error || status.Source != "upstream" || !status.LastSuccess.IsZero() {
		t.Fatalf("idle discovery hid an upstream failure: %+v", status)
	}
}
