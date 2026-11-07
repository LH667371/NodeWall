package api

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"nodewall/internal/config"
	"nodewall/internal/models"
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
