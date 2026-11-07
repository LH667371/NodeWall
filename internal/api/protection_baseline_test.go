package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
	"nodewall/internal/xdp"
)

func TestProtectionBaselineAppliesRecoveryAccessBeforeEnforcement(t *testing.T) {
	var mu sync.Mutex
	published := map[models.PolicyDirection]map[string]any{}
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/system/ssh":
			writeJSON(w, http.StatusOK, map[string]any{"ports": []uint16{22, 2222}})
		case r.Method == http.MethodPost && r.URL.Path == "/interfaces/ens3/attach":
			writeJSON(w, http.StatusOK, map[string]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/interfaces/ens3/apply":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode apply payload: %v", err)
			}
			direction, _ := payload["direction"].(string)
			mu.Lock()
			published[models.PolicyDirection(direction)] = payload
			mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/interfaces/ens3/confirm":
			writeJSON(w, http.StatusOK, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	ctx := context.Background()
	state := store.New()
	state.UpsertNode(ctx, models.Node{
		ID:          "manager-1",
		Name:        "manager-1",
		AgentURL:    agent.URL,
		AdvertiseIP: "192.0.2.10",
	})
	svc := service.NewPolicyService(state)
	handler := &ServerHandler{
		nodeID:      "manager-1",
		service:     svc,
		store:       state,
		reverseHTTP: agent.Client(),
		controlPortRules: []models.PortRule{
			{Protocol: models.PortProtocolTCP, Port: 8443},
			{Protocol: models.PortProtocolUDP, Port: 50052},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/nodes/manager-1/interfaces/ens3/protection-baseline", nil)
	req.SetPathValue("node", "manager-1")
	req.SetPathValue("iface", "ens3")
	rec := httptest.NewRecorder()
	handler.handleEnableProtectionBaseline(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	ingress := published[models.DirectionIngress]
	egress := published[models.DirectionEgress]
	mu.Unlock()
	if ingress == nil || egress == nil {
		t.Fatalf("expected both direction payloads, got %#v", published)
	}
	if immediate, _ := ingress["immediate"].(bool); !immediate {
		t.Fatalf("baseline must take effect immediately, got %#v", ingress)
	}
	if observeOnly, _ := ingress["observe_only"].(bool); observeOnly {
		t.Fatalf("baseline must enforce ingress rules, got %#v", ingress)
	}
	if !hasPortRule(ingress["public_port_rules"], models.PortProtocolTCP, 22) ||
		!hasPortRule(ingress["public_port_rules"], models.PortProtocolTCP, 2222) ||
		!hasPortRule(ingress["public_port_rules"], models.PortProtocolTCP, 53) ||
		!hasPortRule(ingress["public_port_rules"], models.PortProtocolUDP, 53) ||
		!hasPortRule(ingress["public_port_rules"], models.PortProtocolUDP, 123) ||
		!hasPortRule(ingress["public_port_rules"], models.PortProtocolTCP, 8443) ||
		!hasPortRule(ingress["public_port_rules"], models.PortProtocolUDP, 50052) {
		t.Fatalf("baseline ports missing from ingress payload: %#v", ingress["public_port_rules"])
	}
	if !hasString(ingress["allowlist"], "192.0.2.10/32") {
		t.Fatalf("cluster member address missing from ingress allowlist: %#v", ingress["allowlist"])
	}
}

func TestControlPlanePortRulesAlwaysIncludeZStackHTTPSPort(t *testing.T) {
	rules := controlPlanePortRules(config.ServerConfig{ListenAddr: "0.0.0.0:8080"})
	if !containsPortRule(rules, models.PortRule{Protocol: models.PortProtocolTCP, Port: 8082}) {
		t.Fatalf("manager control rules omitted the default ZStack HTTPS port: %#v", rules)
	}
}

func TestProtectionStatusForInterface(t *testing.T) {
	cases := []struct {
		name   string
		health models.HealthStatus
		want   string
	}{
		{
			name:   "not attached",
			health: models.HealthStatus{Interfaces: []models.InterfaceHealth{{Interface: "ens3"}}},
			want:   "not_enabled",
		},
		{
			name: "enforced",
			health: models.HealthStatus{Interfaces: []models.InterfaceHealth{{
				Interface: "ens3", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: true, EnforcementOK: true,
			}}},
			want: "enforced",
		},
		{
			name: "degraded",
			health: models.HealthStatus{Interfaces: []models.InterfaceHealth{{
				Interface: "ens3", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: false, EnforcementOK: true,
			}}},
			want: "degraded",
		},
		{
			name: "observe-only",
			health: models.HealthStatus{Interfaces: []models.InterfaceHealth{{
				Interface: "ens3", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: false, ObserveOnly: true, EnforcementOK: true,
			}}},
			want: "not_enabled",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := protectionStatusForInterface(tc.health, "ens3"); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestReconcileActiveClusterInterconnectStagesControlPortOnExistingNodes(t *testing.T) {
	ctx := context.Background()
	state := store.New()
	state.UpsertNode(ctx, models.Node{ID: "node-a", Name: "node-a", AdvertiseIP: "192.0.2.10"})
	state.UpsertNode(ctx, models.Node{ID: "node-b", Name: "node-b", AdvertiseIP: "192.0.2.11"})
	for _, nodeID := range []string{"node-a", "node-b"} {
		state.PutPolicy(ctx, models.InterfacePolicy{
			NodeID: nodeID, Interface: "ens3", Enabled: true, Mode: "observe", DefaultAction: "pass",
			Ingress: models.DirectionPolicy{Enabled: true, Mode: "observe", DefaultAction: "pass", NonIPv4Action: models.NonIPv4Drop},
			Egress:  models.DefaultDirectionPolicy(models.DirectionEgress),
		})
	}
	h := &ServerHandler{
		service: svcForTest(state),
		store:   state,
		controlPortRules: []models.PortRule{
			{Protocol: models.PortProtocolTCP, Port: 8082},
		},
	}
	if err := h.ReconcileActiveClusterInterconnect(ctx); err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []string{"node-a", "node-b"} {
		policy, err := state.GetPolicy(ctx, nodeID, "ens3")
		if err != nil {
			t.Fatal(err)
		}
		ingress := models.DirectionPolicyFor(policy, models.DirectionIngress)
		if !containsPortRule(ingress.PublicPortRules, models.PortRule{Protocol: models.PortProtocolTCP, Port: 8082}) {
			t.Fatalf("node %s did not receive the manager control port: %#v", nodeID, ingress.PublicPortRules)
		}
		if !hasAllowRule(ingress.Rules, "192.0.2.10/32") || !hasAllowRule(ingress.Rules, "192.0.2.11/32") {
			t.Fatalf("node %s did not receive all cluster interconnect addresses: %#v", nodeID, ingress.Rules)
		}
	}
}

func TestProtectionBaselineTrialRestoresAnUnattachedInterface(t *testing.T) {
	dataplane := xdp.NewMockManager()
	agent := NewAgentHandler("node-a", dataplane, memoryStateStore{}, time.Minute, nil, nil)
	agentServer := httptest.NewServer(agent.Routes())
	defer agentServer.Close()

	ctx := context.Background()
	state := store.New()
	state.UpsertNode(ctx, models.Node{ID: "node-a", Name: "node-a", AgentURL: agentServer.URL, AdvertiseIP: "192.0.2.10"})
	state.PutPolicy(ctx, models.InterfacePolicy{
		NodeID: "node-a", Interface: "ens3", Enabled: true, Mode: "observe", DefaultAction: "pass",
		Ingress: models.DirectionPolicy{Enabled: true, Mode: "observe", DefaultAction: "pass", NonIPv4Action: models.NonIPv4Drop, ObserveOnly: true},
		Egress:  models.DefaultDirectionPolicy(models.DirectionEgress),
	})
	svc := service.NewPolicyService(state)
	h := &ServerHandler{
		nodeID:           "manager-1",
		service:          svc,
		store:            state,
		reverseHTTP:      agentServer.Client(),
		controlPortRules: []models.PortRule{{Protocol: models.PortProtocolTCP, Port: 8082}},
	}
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-a/interfaces/ens3/protection-baseline", strings.NewReader(`{"trial_seconds":1}`))
	req.SetPathValue("node", "node-a")
	req.SetPathValue("iface", "ens3")
	rec := httptest.NewRecorder()
	h.handleEnableProtectionBaseline(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start trial: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := state.PendingPolicyUpdate("node-a", "ens3"); !ok {
		t.Fatal("trial did not persist a recovery record")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := svc.RecoverPendingPolicies(ctx); err != nil {
			t.Logf("recovery error: %v", err)
		}
		if _, ok := state.PendingPolicyUpdate("node-a", "ens3"); !ok {
			runtime, err := dataplane.Runtime("ens3")
			if err == nil && runtime.Config.ObserveOnly {
				policy, policyErr := state.GetPolicy(ctx, "node-a", "ens3")
				if policyErr != nil {
					t.Fatal(policyErr)
				}
				if ingress := models.DirectionPolicyFor(policy, models.DirectionIngress); !ingress.ObserveOnly {
					t.Fatalf("expired trial left enforcement enabled: %#v", ingress)
				}
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("protection trial did not restore the unattached interface")
}

func svcForTest(state *store.Store) *service.PolicyService {
	return service.NewPolicyService(state)
}

func hasAllowRule(rules []models.ACLRule, cidr string) bool {
	for _, rule := range rules {
		if rule.CIDR == cidr && (rule.Action == "" || rule.Action == "allow") {
			return true
		}
	}
	return false
}

func TestRecoverPolicyFromActiveAgentRules(t *testing.T) {
	serverPolicy := models.InterfacePolicy{
		NodeID: "rancher", Interface: "ens3", Enabled: true, Mode: "observe", DefaultAction: "pass",
		NonIPv4Action: models.NonIPv4Drop,
		Ingress:       models.DirectionPolicy{Enabled: true, Mode: "observe", DefaultAction: "pass", NonIPv4Action: models.NonIPv4Drop},
		Egress:        models.DefaultDirectionPolicy(models.DirectionEgress),
	}
	recovered, ok := recoverPolicyFromAgent(serverPolicy, models.DirectionIngress,
		models.HealthStatus{Interfaces: []models.InterfaceHealth{{Interface: "ens3", XDPAttached: true, PolicyEnforced: true}}},
		[]string{"106.15.202.48/32"},
		nil, nil, nil, nil, // bypass, blocked, ICMP allow, ICMP block
		nil, nil, // public ports and rules
		nil, nil, // denied ports and rules
		[]uint16{22, 443, 8080, 8082}, []models.PortRule{
			{Protocol: models.PortProtocolTCP, Port: 22},
			{Protocol: models.PortProtocolTCP, Port: 443},
			{Protocol: models.PortProtocolTCP, Port: 8080},
			{Protocol: models.PortProtocolTCP, Port: 8082},
		})
	if !ok {
		t.Fatal("expected active agent rules to recover the empty manager policy")
	}
	ingress := models.DirectionPolicyFor(recovered, models.DirectionIngress)
	if ingress.Mode != "whitelist" || ingress.DefaultAction != "drop" || ingress.ObserveOnly {
		t.Fatalf("unexpected recovered enforcement mode: %#v", ingress)
	}
	if len(ingress.Rules) != 1 || ingress.Rules[0].CIDR != "106.15.202.48/32" {
		t.Fatalf("unexpected recovered source rules: %#v", ingress.Rules)
	}
	if len(ingress.AllowedPortRules) != 4 || len(ingress.AllowedPorts) != 4 {
		t.Fatalf("unexpected recovered port rules: %#v / %#v", ingress.AllowedPortRules, ingress.AllowedPorts)
	}
}

func TestRecoverPolicyDoesNotOverwriteConfiguredPolicy(t *testing.T) {
	policy := models.InterfacePolicy{
		NodeID: "rancher", Interface: "ens3",
		Ingress: models.DirectionPolicy{Enabled: true, Mode: "whitelist", DefaultAction: "drop", NonIPv4Action: models.NonIPv4Drop,
			Rules: []models.ACLRule{{CIDR: "192.0.2.0/24", Action: "allow"}}},
		Egress: models.DefaultDirectionPolicy(models.DirectionEgress),
	}
	if _, ok := recoverPolicyFromAgent(policy, models.DirectionIngress, models.HealthStatus{}, []string{"203.0.113.8/32"}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil); ok {
		t.Fatal("configured whitelist policy should not be replaced by an agent fallback")
	}
}

func hasPortRule(value any, protocol models.PortProtocol, port uint16) bool {
	raw, ok := value.([]any)
	if !ok {
		return false
	}
	for _, entry := range raw {
		rule, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if rule["protocol"] == string(protocol) && uint16(rule["port"].(float64)) == port {
			return true
		}
	}
	return false
}

func hasString(value any, expected string) bool {
	raw, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range raw {
		if item == expected {
			return true
		}
	}
	return false
}
