package api

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/service"
	"nodewall/internal/store"
)

func TestNewServerHandlerUsesTLSClientForPolicyApply(t *testing.T) {
	var attachCalls, applyCalls int
	agent := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interfaces/eth0/attach":
			attachCalls++
			writeJSON(w, http.StatusOK, map[string]any{"attached": true})
		case "/interfaces/eth0/apply":
			applyCalls++
			writeJSON(w, http.StatusOK, map[string]any{})
		case "/interfaces/eth0/confirm":
			writeJSON(w, http.StatusOK, map[string]any{})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		}
	}))
	defer agent.Close()

	caFile := filepath.Join(t.TempDir(), "agent-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: agent.Certificate().Raw,
	}), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(agent.Certificate().Raw); err != nil {
		t.Fatalf("test certificate is invalid: %v", err)
	}

	st := store.New()
	st.UpsertNode(t.Context(), models.Node{ID: "node-a", Name: "node-a", AgentURL: agent.URL})
	svc := service.NewPolicyService(st)
	if _, err := NewServerHandler(config.ServerConfig{
		NodeID:                "node-a",
		AuthEnabled:           false,
		TLSEnabled:            true,
		TLSCAFile:             caFile,
		TLSInsecureSkipVerify: false,
	}, svc, st); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.UpdatePolicyAndApply(t.Context(), models.InterfacePolicy{
		NodeID:    "node-a",
		Interface: "eth0",
		Ingress:   models.DirectionPolicy{Enabled: true},
	}); err != nil {
		t.Fatalf("policy apply through the configured TLS client failed: %v", err)
	}
	if attachCalls != 1 || applyCalls != 2 {
		t.Fatalf("unexpected agent calls: attach=%d apply=%d", attachCalls, applyCalls)
	}
}

func TestNodeJSONUsesPerNodeEnrollmentCertificate(t *testing.T) {
	agent := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(nodeauth.NodeHeader) != "node-a" || r.Header.Get("Authorization") == "" {
			t.Fatalf("node authentication headers were not forwarded")
		}
		writeJSON(w, http.StatusOK, models.HealthStatus{Status: "ok"})
	}))
	defer agent.Close()

	registry, err := nodeauth.Open("")
	if err != nil {
		t.Fatal(err)
	}
	token, err := nodeauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Put(nodeauth.Credential{
		NodeID:      "node-a",
		AgentURL:    agent.URL,
		Token:       token,
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agent.Certificate().Raw})),
	}); err != nil {
		t.Fatal(err)
	}

	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: agent.URL})
	handler, err := NewServerHandler(config.ServerConfig{AuthEnabled: false, TLSEnabled: false}, service.NewPolicyService(state), state)
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureNodeAuth(registry)
	var health models.HealthStatus
	if err := handler.nodeJSON(t.Context(), "node-a", http.MethodGet, "/health", nil, &health); err != nil {
		t.Fatalf("nodeJSON did not use the enrolled certificate: %v", err)
	}
	if health.Status != "ok" {
		t.Fatalf("unexpected health response: %#v", health)
	}
}

func TestNodeJSONResolvesCredentialByAgentURLAfterNodeIDChange(t *testing.T) {
	agent := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(nodeauth.NodeHeader) != "new-node-id" || r.Header.Get("Authorization") == "" {
			t.Fatalf("re-enrolled node credentials were not forwarded")
		}
		writeJSON(w, http.StatusOK, models.HealthStatus{Status: "ok"})
	}))
	defer agent.Close()

	registry, err := nodeauth.Open("")
	if err != nil {
		t.Fatal(err)
	}
	token, err := nodeauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Put(nodeauth.Credential{
		NodeID:      "new-node-id",
		AgentURL:    agent.URL,
		Token:       token,
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agent.Certificate().Raw})),
	}); err != nil {
		t.Fatal(err)
	}

	state := store.New()
	// The durable node row still has the old ID, while the enrolled credential
	// was replaced under the new ID. URL matching must keep health and policy
	// proxy requests on the node's pinned certificate during that transition.
	state.UpsertNode(t.Context(), models.Node{ID: "old-node-id", AgentURL: agent.URL})
	handler, err := NewServerHandler(config.ServerConfig{AuthEnabled: false, TLSEnabled: false}, service.NewPolicyService(state), state)
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureNodeAuth(registry)
	var health models.HealthStatus
	if err := handler.nodeJSON(t.Context(), "old-node-id", http.MethodGet, "/health", nil, &health); err != nil {
		t.Fatalf("nodeJSON did not resolve the re-enrolled credential: %v", err)
	}
	if health.Status != "ok" {
		t.Fatalf("unexpected health response: %#v", health)
	}
}

func TestRemoteNodeCannotProxyToManagerLoopback(t *testing.T) {
	registry, err := nodeauth.Open("")
	if err != nil {
		t.Fatal(err)
	}
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "manager", AgentURL: "https://192.0.2.10:9080"})
	state.UpsertNode(t.Context(), models.Node{ID: "peer", AgentURL: "https://127.0.0.1:9080"})
	h := &ServerHandler{nodeID: "manager", service: service.NewPolicyService(state), nodeCredentials: registry}
	if _, _, err := h.nodeHTTPClient("peer"); err == nil || !strings.Contains(err.Error(), "loopback Agent URL") {
		t.Fatalf("remote loopback endpoint was not rejected: %v", err)
	}
}
