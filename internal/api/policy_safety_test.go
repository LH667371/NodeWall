package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
	"nodewall/internal/xdp"
)

type rejectEgress struct{ *xdp.MockManager }

func (d rejectEgress) ApplyDirectionPolicy(_ string, direction models.PolicyDirection, policy xdp.DirectionPolicy) error {
	if direction == models.DirectionEgress && !policy.ObserveOnly {
		return errors.New("egress enforcement unavailable")
	}
	return nil
}

func TestBidirectionalFailureRestoresIngressAndStoredPolicy(t *testing.T) {
	dataplane := rejectEgress{xdp.NewMockManager()}
	agent := NewAgentHandler("node-a", dataplane, memoryStateStore{}, time.Minute, nil, nil)
	server := httptest.NewServer(agent.Routes())
	defer server.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: server.URL})
	svc := service.NewPolicyService(state)
	initial := models.InterfacePolicy{NodeID: "node-a", Interface: "nw-test0", Ingress: models.DirectionPolicy{Enabled: true, Mode: "whitelist", PublicPorts: []uint16{22}}}
	if _, err := svc.UpdatePolicyAndApply(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	before, _ := state.GetPolicy(t.Context(), "node-a", "nw-test0")
	next := before
	next.Ingress.DeniedPorts = []uint16{443}
	next.Ingress.DeniedPortRules = nil
	next.Egress.ObserveOnly = false
	next.Egress.DeniedPorts = []uint16{443}
	if _, err := svc.UpdatePolicyAndApply(t.Context(), next); err == nil {
		t.Fatal("failed egress update was reported as successful")
	}
	runtime, err := dataplane.Runtime("nw-test0")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(runtime.PublicPorts, uint16(22)) || slices.Contains(runtime.DeniedPorts, uint16(443)) {
		t.Fatalf("partial ingress policy survived: %#v", runtime)
	}
	after, _ := state.GetPolicy(t.Context(), "node-a", "nw-test0")
	if len(after.Ingress.DeniedPorts) != 0 {
		t.Fatal("failed update replaced durable policy")
	}
	if len(agent.ensureRuntime("nw-test0").Recovery) != 0 {
		t.Fatal("recovery snapshot was not cleared")
	}
}

func TestAutomaticSafetySurvivesAgentRestart(t *testing.T) {
	state := store.NewFileStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	manager := xdp.NewMockManager()
	handler := NewAgentHandler("node-a", manager, state, time.Minute, nil, nil)
	if err := manager.Attach("nw-test0", xdp.AttachModeGeneric); err != nil {
		t.Fatal(err)
	}
	initial := `{"immediate":true,"public_ports":[22],"non_ipv4_action":"drop"}`
	apply := func(body string) {
		req := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/apply", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
		}
	}
	apply(initial)
	apply(`{"immediate":true,"publish_id":"safe-restart","safety_timeout":30,"denied_ports":[22],"non_ipv4_action":"drop"}`)
	defer handler.rollback.Confirm("safe-restart")
	restartedDataplane := xdp.NewMockManager()
	restarted := NewAgentHandler("node-a", restartedDataplane, state, time.Minute, nil, nil)
	if err := restarted.LoadState(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime, err := restartedDataplane.Runtime("nw-test0")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(runtime.PublicPorts, uint16(22)) || slices.Contains(runtime.DeniedPorts, uint16(22)) {
		t.Fatal("restart loaded unconfirmed SSH denial")
	}
}

func TestAutomaticSafetyRestoresUnacknowledgedPolicy(t *testing.T) {
	manager := xdp.NewMockManager()
	handler := NewAgentHandler("node-a", manager, memoryStateStore{}, time.Minute, nil, nil)
	_ = manager.Attach("nw-test0", xdp.AttachModeGeneric)
	for _, body := range []string{`{"immediate":true,"public_ports":[22]}`, `{"immediate":true,"publish_id":"safe-timeout","safety_timeout":1,"denied_ports":[22]}`} {
		req := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/apply", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatal(rec.Body.String())
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime, _ := manager.Runtime("nw-test0")
		if slices.Contains(runtime.PublicPorts, uint16(22)) && len(runtime.DeniedPorts) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("lost manager acknowledgement did not restore SSH access")
}

func TestSSHSourceBlockRequiresConfirmation(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, sshAccessInfo{Ports: []uint16{2222}, Clients: []string{"192.0.2.25"}})
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: agent.URL})
	handler := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: agent.Client(), auth: &authManager{enabled: true}}
	before := models.InterfacePolicy{NodeID: "node-a", Interface: "nw-test0", Ingress: models.DirectionPolicy{Enabled: true, Mode: "whitelist", PublicPorts: []uint16{2222}}}
	after := before
	after.Ingress.BlockedCIDRs = []string{"192.0.2.0/24"}
	req := httptest.NewRequest(http.MethodPut, "/policy", nil)
	rec := httptest.NewRecorder()
	if !handler.blockUnsafeSSHPolicy(rec, req, before, after, "") || rec.Code != http.StatusConflict {
		t.Fatal("active SSH source was blocked without confirmation")
	}
	var payload map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)
	if payload["code"] != "SSH_CONFIRM_REQUIRED" {
		t.Fatal(payload)
	}
}

func TestSSHAllowPolicyChangeDoesNotRequireConfirmation(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, sshAccessInfo{Ports: []uint16{22}})
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: agent.URL})
	handler := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: agent.Client(), auth: &authManager{enabled: true}}
	before := models.InterfacePolicy{NodeID: "node-a", Interface: "nw-test0", Ingress: models.DirectionPolicy{
		Enabled: true, Mode: "whitelist", DeniedPorts: []uint16{22},
	}}
	after := before
	after.Ingress.DeniedPorts = nil
	after.Ingress.PublicPorts = []uint16{22}
	req := httptest.NewRequest(http.MethodPut, "/policy", nil)
	rec := httptest.NewRecorder()
	if handler.blockUnsafeSSHPolicy(rec, req, before, after, "") {
		t.Fatalf("allowing SSH access unexpectedly required confirmation: %s", rec.Body.String())
	}
}

func TestSSHAllowPortMutationDoesNotRequireConfirmation(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, sshAccessInfo{Ports: []uint16{22}})
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: agent.URL})
	handler := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: agent.Client(), auth: &authManager{enabled: true}}
	policy := models.InterfacePolicy{NodeID: "node-a", Interface: "nw-test0", Ingress: models.DirectionPolicy{
		Enabled: true, Mode: "whitelist", DeniedPorts: []uint16{22},
	}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-a/interfaces/nw-test0/public-ports", strings.NewReader(`{"port":22,"protocol":"tcp"}`))
	req.SetPathValue("node", "node-a")
	rec := httptest.NewRecorder()
	if handler.sshMutationBlocked(rec, req, policy, 22, "allow", "") {
		t.Fatalf("allowing SSH port unexpectedly required confirmation: %s", rec.Body.String())
	}
}

func TestSSHDeniedPortMutationStillRequiresConfirmation(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, sshAccessInfo{Ports: []uint16{22}})
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: agent.URL})
	handler := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: agent.Client(), auth: &authManager{enabled: true}}
	policy := models.InterfacePolicy{NodeID: "node-a", Interface: "nw-test0", Ingress: models.DirectionPolicy{
		Enabled: true, Mode: "whitelist", PublicPorts: []uint16{22},
	}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-a/interfaces/nw-test0/denied-ports", strings.NewReader(`{"port":22,"protocol":"tcp"}`))
	req.SetPathValue("node", "node-a")
	rec := httptest.NewRecorder()
	if !handler.sshMutationBlocked(rec, req, policy, 22, "deny", "") || rec.Code != http.StatusConflict {
		t.Fatalf("denying SSH port did not require confirmation: %s", rec.Body.String())
	}
}

func TestManagerRestartRecoversInterruptedPolicyTransaction(t *testing.T) {
	dataplane := xdp.NewMockManager()
	agent := NewAgentHandler("node-a", dataplane, memoryStateStore{}, time.Minute, nil, nil)
	server := httptest.NewServer(agent.Routes())
	defer server.Close()
	path := filepath.Join(t.TempDir(), "server-state.json")
	state, err := store.NewPersistent(path)
	if err != nil {
		t.Fatal(err)
	}
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: server.URL})
	svc := service.NewPolicyService(state)
	initial := models.InterfacePolicy{NodeID: "node-a", Interface: "nw-test0", Ingress: models.DirectionPolicy{Enabled: true, Mode: "whitelist", PublicPorts: []uint16{22}}}
	if _, err := svc.UpdatePolicyAndApply(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	previous, _ := state.GetPolicy(t.Context(), "node-a", "nw-test0")
	if err := state.BeginPolicyUpdate(t.Context(), "node-a", "nw-test0"); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after remote confirmation but before the manager
	// removed its durable recovery record.
	next := previous
	next.Ingress.DeniedPorts = []uint16{22}
	next.Ingress.DeniedPortRules = nil
	if _, err := state.PutPolicyChecked(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/apply", strings.NewReader(`{"immediate":true,"denied_ports":[22]}`))
	response := httptest.NewRecorder()
	agent.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	restartedStore, err := store.NewPersistent(path)
	if err != nil {
		t.Fatal(err)
	}
	restartedService := service.NewPolicyService(restartedStore)
	if err := restartedService.RecoverPendingPolicies(t.Context()); err != nil {
		t.Fatal(err)
	}
	runtime, _ := dataplane.Runtime("nw-test0")
	if !slices.Contains(runtime.PublicPorts, uint16(22)) || len(runtime.DeniedPorts) != 0 {
		t.Fatal("manager restart did not restore SSH access")
	}
	persisted, _ := restartedStore.GetPolicy(t.Context(), "node-a", "nw-test0")
	if len(persisted.Ingress.DeniedPorts) != 0 || len(restartedStore.PendingPolicyUpdates()) != 0 {
		t.Fatal("manager retained an interrupted policy transaction")
	}
}
