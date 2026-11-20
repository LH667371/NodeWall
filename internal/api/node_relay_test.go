package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/store"
	"nodewall/internal/transporttls"
)

type relayRoundTripFunc func(*http.Request) (*http.Response, error)

func (f relayRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type relayFixture struct {
	source    *ServerHandler
	manager   *ServerHandler
	server    *httptest.Server
	agent     *httptest.Server
	registry  *nodeauth.Registry
	state     *store.Store
	transport *nodeRelayTransport
}

func newRelayFixture(t *testing.T, target http.Handler) relayFixture {
	t.Helper()
	agent := httptest.NewTLSServer(target)
	t.Cleanup(agent.Close)
	state := store.New()
	manager := newConsoleSyncHandler(t, state, "manager")
	server := httptest.NewUnstartedServer(manager.Routes())
	server.EnableHTTP2 = true
	// A generic NodeWall TLS config also supports QUIC. TCP clients must
	// negotiate h2/http/1.1 even when a listener advertises h3 first.
	server.TLS = &tls.Config{NextProtos: []string{"h3", "h2", "http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	registry, _ := nodeauth.Open("")
	certificate := func(s *httptest.Server) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	}
	for _, c := range []nodeauth.Credential{
		{NodeID: "target", AgentURL: agent.URL, Certificate: certificate(agent)},
		{NodeID: "manager", AgentURL: server.URL, Certificate: certificate(server)},
		{NodeID: "standby", AgentURL: "https://127.0.0.1:15001", Certificate: certificate(agent)},
	} {
		c.Token, _ = nodeauth.NewToken()
		if err := registry.Put(c); err != nil {
			t.Fatal(err)
		}
		state.UpsertNode(t.Context(), models.Node{ID: c.NodeID, AgentURL: c.AgentURL, LastSeenAt: time.Now()})
	}
	state.UpsertNode(t.Context(), models.Node{ID: "manager", AgentURL: server.URL, ServerHTTPAddr: server.URL, LastSeenAt: time.Now()})
	manager.ConfigureNodeAuth(registry)
	source := newConsoleSyncHandler(t, state, "standby")
	source.relayManagerURL = server.URL
	// Separate registries exercise the actual replicated trust boundary.
	copy, _ := nodeauth.Open("")
	snapshot, _ := registry.ExportJSON()
	if err := copy.ReplaceJSON(snapshot); err != nil {
		t.Fatal(err)
	}
	source.ConfigureNodeAuth(copy)
	transport := source.reverseHTTP.Transport.(*nodeRelayTransport)
	direct := transport.direct
	transport.direct = relayRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == agent.URL {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("host INPUT policy blocks this standby")}
		}
		return direct.RoundTrip(r)
	})
	t.Cleanup(source.reverseHTTP.CloseIdleConnections)
	return relayFixture{source: source, manager: manager, server: server, agent: agent, registry: registry, state: state, transport: transport}
}

func TestNodeRelayMakesPartitionedWebReadAndWriteSameAgent(t *testing.T) {
	var writes atomic.Int32
	f := newRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || r.Header.Get(nodeauth.NodeHeader) != "target" {
			t.Error("relay leaked cookie or changed target identity")
		}
		switch r.URL.Path {
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{NodeID: "target", AgentOK: true, Status: "ok", Interfaces: []models.InterfaceHealth{{Interface: "ens3", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: true, EnforcementOK: true}}})
		case "/interfaces":
			writeJSON(w, http.StatusOK, models.InterfaceInventory{Recommended: "ens3", Interfaces: []models.DetectedInterface{{Name: "ens3", IsPhysical: true, Attached: true}}})
		case "/security/scan":
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"quick":true}` {
				t.Errorf("mutation body changed: %q", body)
			}
			writes.Add(1)
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "running"})
		default:
			http.NotFound(w, r)
		}
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var health models.HealthStatus
	if err := f.source.nodeJSON(ctx, "target", http.MethodGet, "/health", nil, &health); err != nil {
		t.Fatal(err)
	}
	if health.NodeID != "target" {
		t.Fatal(health)
	}
	client, _, err := f.source.nodeHTTPClient("target")
	if err != nil || client != f.source.reverseHTTP {
		t.Fatal("per-node requests did not reuse the shared client")
	}
	for _, web := range []*ServerHandler{f.source, f.manager} {
		request := httptest.NewRequest(http.MethodGet, "/nodes/target/protection-status", nil)
		request.SetPathValue("node", "target")
		rec := httptest.NewRecorder()
		web.handleNodeProtectionStatus(rec, request)
		var result map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result["node_status"] != "online" || result["connection_status"] != "reachable" || result["protection_status"] != "enforced" {
			t.Fatalf("Webs disagree: %s, %v", rec.Body, err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/nodes/target/security/scan", strings.NewReader(`{"quick":true}`))
	req.Header.Set("Cookie", "browser-secret")
	rec := httptest.NewRecorder()
	f.source.proxyNode(rec, req, "target", "/security/scan")
	if rec.Code != http.StatusAccepted || writes.Load() != 1 {
		t.Fatalf("mutation status=%d writes=%d: %s", rec.Code, writes.Load(), rec.Body)
	}
}

func TestNodeRelayRejectsAnonymousTicketsAndUnsafeTargets(t *testing.T) {
	var calls atomic.Int32
	f := newRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	caller, _ := f.registry.Get("standby")
	f.manager.enrollmentTickets = map[string]enrollmentTicket{"ticket": {ExpiresAt: time.Now().Add(time.Minute)}}
	cases := []struct {
		name, token, target, method, path string
		want                              int
	}{
		{"anonymous", "", "target", "GET", "/health", 401},
		{"ticket", "", "target", "GET", "/health", 401},
		{"wrong token", "wrong", "target", "GET", "/health", 401},
		{"absolute URL", caller.Token, "target", "GET", "https://external.invalid/health", 400},
		{"authority", caller.Token, "target", "GET", "//external.invalid/health", 400},
		{"traversal", caller.Token, "target", "GET", "/interfaces/../join/bootstrap/key", 400},
		{"encoded traversal", caller.Token, "target", "GET", "/interfaces/%2e%2e/join/bootstrap/key", 400},
		{"bootstrap", caller.Token, "target", "GET", "/join/bootstrap/credentials", 400},
		{"unknown target", caller.Token, "missing", "GET", "/health", 404},
		{"tunnel", caller.Token, "target", "CONNECT", "/health", 400},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			data, _ := json.Marshal(nodeRelayRequest{NodeID: test.target, Method: test.method, Path: test.path})
			req := httptest.NewRequest(http.MethodPost, "https://manager/join/relay?token=ticket", bytes.NewReader(data))
			req.Header.Set(nodeauth.NodeHeader, "standby")
			req.Header.Set("Authorization", "Bearer "+test.token)
			rec := httptest.NewRecorder()
			f.manager.handleNodeRelay(rec, req)
			if rec.Code != test.want {
				t.Fatalf("status=%d want=%d: %s", rec.Code, test.want, rec.Body)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid relay reached an agent")
	}
	standby := false
	caller.Standby = &standby
	if err := f.registry.Put(caller); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://manager/join/relay", nil)
	req.Header.Set(nodeauth.NodeHeader, caller.NodeID)
	req.Header.Set("Authorization", "Bearer "+caller.Token)
	rec := httptest.NewRecorder()
	f.manager.handleNodeRelay(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ordinary agent relay permission returned %d", rec.Code)
	}
}

func TestNodeRelayNeverReplaysUncertainMutation(t *testing.T) {
	var calls atomic.Int32
	f := newRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	for _, failure := range []error{io.ErrUnexpectedEOF, context.DeadlineExceeded, errors.New("TLS certificate changed")} {
		f.transport.direct = relayRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, failure })
		req, _ := http.NewRequest(http.MethodPost, f.agent.URL+"/security/scan", strings.NewReader(`{}`))
		if _, err := f.source.reverseHTTP.Do(req); err == nil {
			t.Fatal("uncertain write was accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("uncertain mutation was retried through a relay")
	}
}

func TestNodeRelayDoesNotReplayMutationAfterMissingResponseMarker(t *testing.T) {
	var targetCalls atomic.Int32
	f := newRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	credential, _ := f.registry.Get("manager")
	key := fmt.Sprintf("%s|%x", f.server.URL, sha256.Sum256([]byte(credential.Certificate)))
	var delivered atomic.Int32
	f.transport.clients = map[string]*http.Client{key: {Transport: relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		delivered.Add(1)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
	})}}
	req, _ := http.NewRequest(http.MethodPost, f.agent.URL+"/security/scan", strings.NewReader(`{}`))
	if _, err := f.source.reverseHTTP.Do(req); err == nil {
		t.Fatal("unmarked write response was treated as success")
	}
	if delivered.Load() != 1 || targetCalls.Load() != 0 {
		t.Fatal("unmarked write was replayed")
	}
}

func TestNodeRelayRejectsChangedPeerCertificate(t *testing.T) {
	var calls atomic.Int32
	f := newRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "other.crt"), filepath.Join(dir, "other.key")
	if err := transporttls.EnsureCertificate(certFile, keyFile, "127.0.0.1:8086"); err != nil {
		t.Fatal(err)
	}
	certificate, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := f.source.nodeCredentials.Get("manager")
	credential.Certificate = string(certificate)
	if err := f.source.nodeCredentials.Put(credential); err != nil {
		t.Fatal(err)
	}
	if err := f.source.nodeJSON(t.Context(), "target", http.MethodGet, "/health", nil, &models.HealthStatus{}); err == nil {
		t.Fatal("different peer certificate was accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("untrusted relay received target credentials")
	}
}

func TestNodeRelayNeverRecursesThroughOtherWebs(t *testing.T) {
	f := newRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("blocked target was reached")
		w.WriteHeader(http.StatusNoContent)
	}))
	var directCalls atomic.Int32
	transport := f.manager.reverseHTTP.Transport.(*nodeRelayTransport)
	transport.direct = relayRoundTripFunc(func(*http.Request) (*http.Response, error) {
		directCalls.Add(1)
		return nil, &net.OpError{Op: "dial", Err: errors.New("also blocked from manager")}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := f.source.nodeJSON(ctx, "target", http.MethodGet, "/health", nil, &models.HealthStatus{}); err == nil {
		t.Fatal("unreachable target succeeded")
	}
	if directCalls.Load() != 1 {
		t.Fatalf("relay loop: %d target dials", directCalls.Load())
	}
}

func TestNodeRelaySSEClosesWhenPageCancels(t *testing.T) {
	stopped := make(chan struct{})
	f := newRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: scan\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(stopped)
	}))
	ctx, cancel := context.WithCancel(t.Context())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.agent.URL+"/security/scan/events", nil)
	res, err := f.source.reverseHTTP.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	data := make([]byte, 6)
	if _, err := io.ReadFull(res.Body, data); err != nil || string(data) != "event:" {
		cancel()
		t.Fatalf("stream was buffered: %q %v", data, err)
	}
	cancel()
	res.Body.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("leaving the page retained the relayed scan stream")
	}
}

func TestNodeRelaySkipsUnavailablePrimaryForReachablePeer(t *testing.T) {
	f := newRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, models.HealthStatus{NodeID: "target", AgentOK: true})
	}))
	// The peer metadata uses a non-loopback address. Its test dialer maps that
	// address back to the local TLS listener without weakening certificate trust.
	credential, _ := f.registry.Get("manager")
	credential.NodeID = "peer"
	credential.AgentURL = "https://example.com:9080"
	if err := f.source.nodeCredentials.Put(credential); err != nil {
		t.Fatal(err)
	}
	f.state.UpsertNode(t.Context(), models.Node{ID: "peer", AgentURL: credential.AgentURL, ServerHTTPAddr: "https://example.com:8086"})
	peerURL := "https://example.com:8086"
	backup := httptest.NewTLSServer(f.manager.Routes())
	t.Cleanup(backup.Close)
	client := backup.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backup.Listener.Addr().String())
	}
	client = &http.Client{Transport: transport}
	t.Cleanup(client.CloseIdleConnections)
	f.transport.clients = map[string]*http.Client{fmt.Sprintf("%s|%x", peerURL, sha256.Sum256([]byte(credential.Certificate))): client}
	f.transport.directReachability = map[string]bool{credential.AgentURL: true}
	f.server.Close()
	var health models.HealthStatus
	if err := f.source.nodeJSON(t.Context(), "target", http.MethodGet, "/health", nil, &health); err != nil {
		t.Fatal(err)
	}
	if health.NodeID != "target" {
		t.Fatal("reachable peer did not deliver target health")
	}
}
