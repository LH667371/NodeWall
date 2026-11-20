package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
	"nodewall/internal/xdp"
)

func newConsoleSyncHandler(t *testing.T, state *store.Store, nodeID string) *ServerHandler {
	t.Helper()
	dir := t.TempDir()
	h, err := NewServerHandler(config.ServerConfig{
		NodeID: nodeID, WebAccessMode: "public", DevMode: "mock",
		AuthSettingsFile:    filepath.Join(dir, "auth-settings.json"),
		SMTPSettingsFile:    filepath.Join(dir, "smtp-settings.json"),
		ClusterKeyFile:      filepath.Join(dir, "cluster.key"),
		NodeCredentialsFile: filepath.Join(dir, "node-credentials.json"),
	}, service.NewPolicyService(state), state)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestConsoleSnapshotsCoalesceWithoutBlockingOtherPages(t *testing.T) {
	h := &ServerHandler{}
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan map[string]any, 2)
	var collections atomic.Int32
	collect := func(cachedPageSnapshot, bool) map[string]any {
		if collections.Add(1) == 1 {
			close(started)
		}
		<-release
		return map[string]any{"node": "slow"}
	}
	go func() { finished <- h.cachedConsoleSnapshot(context.Background(), "slow", collect) }()
	<-started
	go func() { finished <- h.cachedConsoleSnapshot(context.Background(), "slow", collect) }()
	fast := make(chan map[string]any, 1)
	go func() {
		fast <- h.cachedConsoleSnapshot(context.Background(), "settings", func(cachedPageSnapshot, bool) map[string]any { return map[string]any{"ready": true} })
	}()
	select {
	case result := <-fast:
		if result["ready"] != true {
			t.Fatal(result)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("slow node blocked an unrelated configuration page")
	}
	close(release)
	<-finished
	<-finished
	if collections.Load() != 1 {
		t.Fatalf("same target collected %d times", collections.Load())
	}
}

func TestConsoleSnapshotInvalidationRejectsInflightCacheFill(t *testing.T) {
	h := &ServerHandler{}
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan map[string]any, 1)
	go func() {
		finished <- h.cachedConsoleSnapshot(context.Background(), "settings", func(cachedPageSnapshot, bool) map[string]any {
			close(started)
			<-release
			return map[string]any{"value": "old"}
		})
	}()
	<-started
	h.invalidateConsoleSnapshots()
	close(release)
	if result := <-finished; result["revision"] != uint64(0) {
		t.Fatal(result)
	}
	result := h.cachedConsoleSnapshot(context.Background(), "settings", func(cachedPageSnapshot, bool) map[string]any { return map[string]any{"value": "new"} })
	if result["value"] != "new" || result["revision"] != uint64(1) {
		t.Fatalf("stale collection re-entered cache: %#v", result)
	}
}

func TestOverviewAndGlobalEventFeedPublishIndependently(t *testing.T) {
	const iface = "nw-test0"
	dp := xdp.NewMockManager()
	if err := dp.Attach(iface, xdp.AttachModeGeneric); err != nil {
		t.Fatal(err)
	}
	if err := dp.UpsertCIDR(iface, "192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := dp.WriteConfig(iface, xdp.Config{PolicyEnforced: true, NonIPv4Action: models.NonIPv4Pass}); err != nil {
		t.Fatal(err)
	}
	routes := NewAgentHandler("a", dp, memoryStateStore{}, time.Second, nil, nil).Routes()
	releaseLogs := make(chan struct{})
	var healthReads atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logs/drop" {
			select {
			case <-releaseLogs:
			case <-r.Context().Done():
				return
			}
		}
		if r.URL.Path == "/health" {
			healthReads.Add(1)
		}
		routes.ServeHTTP(w, r)
	}))
	defer agent.Close()
	state := store.New()
	for _, id := range []string{"a", "b"} {
		state.UpsertNode(t.Context(), models.Node{ID: id, AgentURL: agent.URL, LastSeenAt: time.Now()})
	}
	state.PutPolicy(t.Context(), models.InterfacePolicy{NodeID: "a", Interface: iface,
		Ingress: models.DirectionPolicy{Mode: "whitelist", Rules: []models.ACLRule{{CIDR: "192.0.2.0/24", Action: "allow"}}}})
	h := newConsoleSyncHandler(t, state, "a")
	server := httptest.NewServer(h.Routes())
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/events/cluster?section=overview&node=a&event_feed=1&overview=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	for {
		frame, err := readSSEFrame(reader)
		if err != nil {
			t.Fatalf("overview was held by the slow event feed: %v", err)
		}
		if strings.HasPrefix(frame, "event: overview_data\n") {
			if !strings.Contains(frame, `"protection_status":"enforced"`) {
				t.Fatal("healthy firewall state missing from overview")
			}
			break
		}
	}
	reads := healthReads.Load()
	initial := httptest.NewRecorder()
	h.Routes().ServeHTTP(initial, httptest.NewRequest(http.MethodGet, "/overview/snapshot?node=a&direction=ingress", nil))
	if initial.Code != http.StatusOK || healthReads.Load() != reads || !strings.Contains(initial.Body.String(), `"protection_status":"enforced"`) {
		t.Fatalf("HTTP overview did not share the SSE snapshot: status=%d health=%d→%d", initial.Code, reads, healthReads.Load())
	}
	close(releaseLogs)
	for {
		frame, err := readSSEFrame(reader)
		if err != nil {
			t.Fatalf("overview never received its independent cluster events: %v", err)
		}
		if strings.HasPrefix(frame, "event: events\n") {
			if !strings.Contains(frame, `"node_id":"a"`) || !strings.Contains(frame, `"node_id":"b"`) {
				t.Fatalf("selected node restricted overview events: %s", frame)
			}
			break
		}
	}
}

func TestOfflineNodeCannotRetainEnforcedProtection(t *testing.T) {
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "offline", LastSeenAt: time.Now().Add(-2 * time.Minute)})
	h := newConsoleSyncHandler(t, state, "offline")
	h.pageSnapshotCache = map[string]cachedPageSnapshot{"node-protection:offline": {
		fetchedAt: time.Now().Add(-time.Minute),
		value: map[string]any{
			"node_id": "offline", "protection_status": "enforced",
			"dataplane_modes": map[string]string{"eth0": "generic"},
		},
	}}
	result := h.protectionStreamSnapshot(context.Background())["offline"].(map[string]any)
	if result["protection_status"] != "unavailable" || result["dataplane_modes"] != nil {
		t.Fatalf("offline node retained live firewall state: %#v", result)
	}
}

func TestNodeProtectionHTTPAndStreamShareLiveDataplaneModes(t *testing.T) {
	const nodeID = "agent"
	dataplane := inventoryMockDataplane{
		xdp.NewMockManager(),
		[]models.DetectedInterface{
			{Name: "em1", IsPhysical: true},
			{Name: "em2", IsPhysical: true},
			{Name: "em3", IsPhysical: true},
			{Name: "em4", IsPhysical: true},
		},
	}
	expected := map[string]string{"em1": "generic", "em2": "native", "em3": "iptables"}
	for iface, mode := range expected {
		if err := dataplane.Attach(iface, xdp.AttachMode(mode)); err != nil {
			t.Fatal(err)
		}
	}
	var probes atomic.Int32
	routes := NewAgentHandler(nodeID, dataplane, memoryStateStore{}, time.Second, nil, nil).Routes()
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		routes.ServeHTTP(w, r)
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: nodeID, AgentURL: agent.URL})
	h := newConsoleSyncHandler(t, state, nodeID)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nodes/agent/protection-status", nil)
	h.Routes().ServeHTTP(rec, req)
	var result struct {
		DataplaneModes map[string]string `json:"dataplane_modes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || !maps.Equal(result.DataplaneModes, expected) {
		t.Fatalf("HTTP did not report live attachments: %s, %v", rec.Body, err)
	}
	status := h.protectionStreamSnapshot(t.Context())[nodeID].(map[string]any)
	modes, ok := status["dataplane_modes"].(map[string]string)
	if !ok || !maps.Equal(modes, expected) || probes.Load() != 2 {
		t.Fatalf("stream did not reuse the bounded HTTP probe: status=%#v requests=%d", status, probes.Load())
	}
	for iface := range expected {
		if err := dataplane.Detach(iface); err != nil {
			t.Fatal(err)
		}
	}
	h.invalidateConsoleSnapshots()
	status = h.protectionStreamSnapshot(t.Context())[nodeID].(map[string]any)
	modes, ok = status["dataplane_modes"].(map[string]string)
	if !ok || len(modes) != 0 || status["reachable"] != true {
		t.Fatalf("reachable node without attachments did not report an empty mode map: %#v", status)
	}
}

func TestProtectionStreamProbesStaleHeartbeatBeforeMarkingNodeOffline(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interfaces":
			writeJSON(w, http.StatusOK, models.InterfaceInventory{Recommended: "ens3", Interfaces: []models.DetectedInterface{{Name: "ens3", IsPhysical: true, Attached: true}}})
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{NodeID: "stale", Status: "ok", AgentOK: true, Interfaces: []models.InterfaceHealth{{
				Interface: "ens3", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: true, EnforcementOK: true,
			}}})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		}
	}))
	defer agent.Close()

	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "stale", AgentURL: agent.URL, LastSeenAt: time.Now().Add(-2 * time.Minute)})
	h := newConsoleSyncHandler(t, state, "stale")
	result := h.protectionStreamSnapshot(context.Background())
	status, ok := result["stale"].(map[string]any)
	if !ok || status["protection_status"] != "enforced" || status["reachable"] != true {
		t.Fatalf("stale heartbeat incorrectly hid reachable node: %#v", result)
	}
}

func TestProtectionSnapshotKeepsHeartbeatOnlineWhenOnlyLocalPathFails(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unreachable through this Web", http.StatusServiceUnavailable)
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "active", AgentURL: agent.URL, LastSeenAt: time.Now()})
	h := newConsoleSyncHandler(t, state, "standby")
	result := h.protectionStreamSnapshot(t.Context())["active"].(map[string]any)
	if result["node_status"] != "online" || result["reachable"] != false || result["protection_status"] != "unavailable" || result["reason"] == "" {
		t.Fatalf("a path failure became a cluster-wide offline status: %#v", result)
	}
	state.UpsertNode(t.Context(), models.Node{ID: "active", LastSeenAt: time.Now().Add(-2 * time.Minute)})
	h.invalidateConsoleSnapshots()
	result = h.protectionStreamSnapshot(t.Context())["active"].(map[string]any)
	if result["node_status"] != "offline" {
		t.Fatalf("expired heartbeat with failed probe stayed online: %#v", result)
	}
}

func TestProtectionStreamUsesHealthWhenInventoryIsTemporarilyUnavailable(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interfaces":
			// The health probe must not wait behind a slow inventory refresh.
			time.Sleep(2200 * time.Millisecond)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "inventory warming up"})
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{
				NodeID:  "node-a",
				Status:  "ok",
				AgentOK: true,
				Interfaces: []models.InterfaceHealth{{
					Interface: "ens3", XDPAttached: true, MapOK: true, StatsOK: true,
					PolicyEnforced: true, EnforcementOK: true,
				}},
			})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		}
	}))
	defer agent.Close()

	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a", AgentURL: agent.URL, LastSeenAt: time.Now()})
	h := newConsoleSyncHandler(t, state, "node-a")
	result := h.protectionStreamSnapshot(context.Background())
	status, ok := result["node-a"].(map[string]any)
	if !ok {
		t.Fatalf("missing node protection snapshot: %#v", result)
	}
	if status["interface"] != "ens3" || status["protection_status"] != "enforced" {
		t.Fatalf("health fallback did not preserve protection status: %#v", status)
	}
}

func TestSecurityInterfaceSnapshotUsesHealthFocusWhenInventoryFails(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interfaces":
			time.Sleep(2200 * time.Millisecond)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "inventory warming up"})
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{
				NodeID: "node-a", Status: "ok", AgentOK: true,
				Interfaces: []models.InterfaceHealth{{
					Interface: "ens3", XDPAttached: true, MapOK: true, StatsOK: true,
					PolicyEnforced: true, EnforcementOK: true,
				}},
			})
		case "/interfaces/ens3/allowlist":
			writeJSON(w, http.StatusOK, map[string]any{"allowlist": []string{"192.0.2.1/32"}})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		}
	}))
	defer agent.Close()

	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a", AgentURL: agent.URL, LastSeenAt: time.Now()})
	h := newConsoleSyncHandler(t, state, "node-a")
	result := h.securityInterfaceStreamSnapshot(context.Background(), "node-a", "", models.DirectionIngress)
	if result["interface"] != "ens3" || result["interface_status"] != "ready" || result["protection_status"] != "enforced" {
		t.Fatalf("security snapshot did not use health fallback: %#v", result)
	}
}

func TestOverviewStreamKeepsFirewallSummaryAfterSlowInventory(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interfaces":
			// Inventory collection can be slow while Docker or a bridge is
			// changing. The overview must still get a separate summary budget.
			time.Sleep(2200 * time.Millisecond)
			writeJSON(w, http.StatusOK, models.InterfaceInventory{
				Recommended: "ens3",
				Interfaces:  []models.DetectedInterface{{Name: "ens3", IsPhysical: true, Attached: true}},
			})
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{
				NodeID: "node-a", Status: "ok", AgentOK: true,
				Interfaces: []models.InterfaceHealth{{
					Interface: "ens3", XDPAttached: true, MapOK: true, StatsOK: true,
					PolicyEnforced: true, EnforcementOK: true,
				}},
			})
		case "/interfaces/ens3/allowlist":
			writeJSON(w, http.StatusOK, map[string]any{"allowlist": []string{"192.0.2.1/32"}})
		case "/security/summary":
			writeJSON(w, http.StatusOK, map[string]any{"node_id": "node-a", "engine": "nodewall"})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		}
	}))
	defer agent.Close()

	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a", AgentURL: agent.URL, LastSeenAt: time.Now()})
	h := newConsoleSyncHandler(t, state, "node-a")
	result := h.overviewStreamSnapshot(context.Background(), "node-a", "", models.DirectionIngress)
	if result["interface"] != "ens3" {
		t.Fatalf("overview did not resolve the attached interface: %#v", result)
	}
	if _, ok := result["current"]; !ok {
		t.Fatalf("slow inventory consumed the firewall summary budget: %#v", result)
	}
}

func TestOverviewResolvesStaleNICAndKeepsDurablePolicyWhenAgentAuxiliaryFails(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{NodeID: "node-b", Status: "ok", AgentOK: true,
				Interfaces: []models.InterfaceHealth{{Interface: "eth9", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: true, EnforcementOK: true}}})
		case "/interfaces":
			t.Error("overview must not repeat device inventory for a known interface")
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{})
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "summary temporarily unavailable"})
		}
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-b", AgentURL: agent.URL, LastSeenAt: time.Now()})
	state.PutPolicy(t.Context(), models.InterfacePolicy{NodeID: "node-b", Interface: "eth9", Ingress: models.DirectionPolicy{Mode: "whitelist", Rules: []models.ACLRule{{CIDR: "10.0.0.0/8", Action: "allow"}}}})
	h := newConsoleSyncHandler(t, state, "node-b")
	result := h.overviewStreamSnapshot(t.Context(), "node-b", "ens3", models.DirectionIngress)
	if result["interface"] != "eth9" || result["protection_status"] != "enforced" || result["reachable"] != true {
		t.Fatalf("new node kept old NIC or lost independent health: %#v", result)
	}
	current, ok := result["current"].(map[string]any)
	if !ok || len(current["policy"].(models.InterfacePolicy).Ingress.Rules) != 1 || result["interface_status"] != "ready" {
		t.Fatalf("manager policy disappeared with unavailable auxiliary metrics: %#v", result)
	}
	if health, ok := result["health"].(models.HealthStatus); !ok || len(health.Interfaces) != 1 || !health.Interfaces[0].PolicyEnforced {
		t.Fatalf("overview discarded healthy firewall state: %#v", result)
	}
}

func TestPageStreamsUseRealAgentRoutesAndShareHTTPInterfaceSummary(t *testing.T) {
	const iface = "nw-test0"
	dataplane := xdp.NewMockManager()
	if err := dataplane.Attach(iface, xdp.AttachModeGeneric); err != nil {
		t.Fatal(err)
	}
	if err := dataplane.UpsertCIDR(iface, "10.42.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := dataplane.WriteConfig(iface, xdp.Config{PolicyEnforced: true, NonIPv4Action: models.NonIPv4Pass}); err != nil {
		t.Fatal(err)
	}
	agent := NewAgentHandler("real-agent", dataplane, memoryStateStore{}, time.Second, nil, nil)
	routes := agent.Routes()
	missing := httptest.NewRecorder()
	routes.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/interfaces/"+iface+"/summary", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatal("test must use an Agent without a fictional summary route")
	}
	var phantomCalls, statsCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/interfaces/"+iface+"/summary" {
			phantomCalls.Add(1)
		}
		if r.URL.Path == "/interfaces/"+iface+"/stats" {
			statsCalls.Add(1)
		}
		routes.ServeHTTP(w, r)
	}))
	defer server.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "real-agent", AgentURL: server.URL, LastSeenAt: time.Now()})
	state.PutPolicy(t.Context(), models.InterfacePolicy{NodeID: "real-agent", Interface: iface, Ingress: models.DirectionPolicy{Mode: "whitelist", Rules: []models.ACLRule{{CIDR: "10.42.0.0/16", Action: "allow"}}}})
	h := newConsoleSyncHandler(t, state, "real-agent")
	overview := h.overviewStreamSnapshot(t.Context(), "real-agent", iface, models.DirectionIngress)
	current, ok := overview["current"].(map[string]any)
	if !ok || overview["interface_status"] != "ready" || overview["protection_status"] != "enforced" {
		t.Fatalf("overview failed against actual Agent routes: %#v", overview)
	}
	if len(current["policy"].(models.InterfacePolicy).Ingress.Rules) != 1 || current["stats"].(models.InterfaceStats).Passed == 0 {
		t.Fatalf("overview lost manager rules or real Agent counters: %#v", current)
	}
	security := h.securityInterfaceStreamSnapshot(t.Context(), "real-agent", iface, models.DirectionIngress)
	if security["current"] == nil || security["interface_status"] != "ready" {
		t.Fatalf("firewall stream failed against actual Agent routes: %#v", security)
	}
	req := httptest.NewRequest(http.MethodGet, "/nodes/real-agent/interfaces/"+iface+"/summary", nil)
	req.SetPathValue("node", "real-agent")
	req.SetPathValue("iface", iface)
	response := httptest.NewRecorder()
	h.handleProxyInterfaceSummary(response, req)
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["policy"] == nil {
		t.Fatalf("HTTP summary was not preserved: %v %s", err, response.Body.String())
	}
	if phantomCalls.Load() != 0 || statsCalls.Load() != 1 {
		t.Fatalf("HTTP and SSE did not share the collector: nonexistent route=%d counter probes=%d", phantomCalls.Load(), statsCalls.Load())
	}
}

func TestFirewallDeletesReturnConfirmedRulesAndInvalidateSummary(t *testing.T) {
	const iface = "nw-test0"
	const base = "/nodes/agent/interfaces/" + iface
	dataplane := xdp.NewMockManager()
	agent := httptest.NewServer(NewAgentHandler("agent", dataplane, memoryStateStore{}, time.Second, nil, nil).Routes())
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "agent", AgentURL: agent.URL, LastSeenAt: time.Now()})
	h := newConsoleSyncHandler(t, state, "agent")
	routes := h.Routes()
	call := func(method, path, payload string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, httptest.NewRequest(method, base+path, strings.NewReader(payload)))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
		}
		return rec
	}
	call(http.MethodPost, "/allowlist", `{"cidr":"192.0.2.1/32"}`)
	call(http.MethodPost, "/allowlist", `{"cidr":"192.0.2.2/32","comment":"keep this note"}`)
	call(http.MethodPost, "/public-ports", `{"port":18080}`)
	call(http.MethodGet, "/summary", "") // Populate the shared cache before deleting.

	removed := call(http.MethodDelete, "/allowlist?cidr=192.0.2.1%2F32&direction=ingress", "")
	var saved models.InterfacePolicy
	if err := json.Unmarshal(removed.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Ingress.Rules) != 1 || saved.Ingress.Rules[0].CIDR != "192.0.2.2/32" || saved.Ingress.Rules[0].Comment != "keep this note" {
		t.Fatalf("DELETE lost other rule data: %#v", saved.Ingress.Rules)
	}
	call(http.MethodDelete, "/allowlist?cidr=192.0.2.2%2F32&direction=ingress", "")
	port := call(http.MethodDelete, "/public-ports/18080?protocol=tcp&direction=ingress", "")
	revision, err := strconv.ParseUint(port.Header().Get("X-NodeWall-Revision"), 10, 64)
	if err != nil {
		t.Fatalf("no revision for confirmed delete: %v", err)
	}
	var summary struct {
		Policy   models.InterfacePolicy `json:"policy"`
		Revision uint64                 `json:"revision"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "/summary", "").Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Revision != revision || len(summary.Policy.Ingress.Rules) != 0 {
		t.Fatalf("HTTP returned a stale summary: %#v", summary)
	}
	tcp := models.PortRule{Protocol: models.PortProtocolTCP, Port: 18080}
	udp := models.PortRule{Protocol: models.PortProtocolUDP, Port: 18080}
	if rules := summary.Policy.Ingress.PublicPortRules; containsPortRule(rules, tcp) || !containsPortRule(rules, udp) {
		t.Fatalf("protocol-specific delete returned the wrong rules: %#v", rules)
	}
	stream := h.securityStreamSnapshotFor(t.Context(), "firewall", "agent", iface, models.DirectionIngress)
	current := stream["nodes"].([]map[string]any)[0]["current"].(map[string]any)
	if current["revision"] != revision || len(current["policy"].(models.InterfacePolicy).Ingress.Rules) != 0 {
		t.Fatalf("SSE collector kept the removed rule: %#v", current)
	}
	if rules, err := dataplane.ListCIDRs(iface); err != nil || len(rules) != 0 {
		t.Fatalf("Agent kept a removed CIDR: %v %v", rules, err)
	}
}

func TestUnconfiguredNodeKeepsInventoryNICWithoutActiveHealthInterfaces(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{NodeID: "new-node", Status: "ok", AgentOK: true})
		case "/interfaces":
			writeJSON(w, http.StatusOK, models.InterfaceInventory{Recommended: "eth8", Interfaces: []models.DetectedInterface{{Name: "eth8", IsPhysical: true}}})
		default:
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "new-node", AgentURL: agent.URL, LastSeenAt: time.Now()})
	h := newConsoleSyncHandler(t, state, "new-node")
	for _, result := range []map[string]any{
		h.overviewStreamSnapshot(t.Context(), "new-node", "", models.DirectionIngress),
		h.securityInterfaceStreamSnapshot(t.Context(), "new-node", "", models.DirectionIngress),
	} {
		if result["interface"] != "eth8" || result["protection_status"] != "not_enabled" || result["interface_status"] != "ready" || result["current"] == nil {
			t.Fatalf("new node became unknown or lost its usable NIC: %#v", result)
		}
	}
}

type inventoryMockDataplane struct {
	*xdp.MockManager
	interfaces []models.DetectedInterface
}

func (m inventoryMockDataplane) DiscoverInterfaces() (models.InterfaceInventory, error) {
	return models.InterfaceInventory{
		Recommended: "em1",
		Interfaces:  append([]models.DetectedInterface(nil), m.interfaces...),
	}, nil
}

func TestSecurityStreamKeepsSelectedUnattachedInterface(t *testing.T) {
	const nodeID = "zstack"
	for _, tc := range []struct {
		name                 string
		inventoryUnavailable bool
	}{
		{name: "listed in inventory"},
		{name: "inventory temporarily unavailable", inventoryUnavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataplane := inventoryMockDataplane{xdp.NewMockManager(), []models.DetectedInterface{
				{Name: "em1", IsPhysical: true, IsUp: true},
				{Name: "em2", IsPhysical: true},
			}}
			if err := dataplane.Attach("em1", xdp.AttachModeGeneric); err != nil {
				t.Fatal(err)
			}
			if err := dataplane.UpsertCIDR("em1", "192.0.2.1/32"); err != nil {
				t.Fatal(err)
			}
			if err := dataplane.WriteConfig("em1", xdp.Config{PolicyEnforced: true, NonIPv4Action: models.NonIPv4Pass}); err != nil {
				t.Fatal(err)
			}
			routes := NewAgentHandler(nodeID, dataplane, memoryStateStore{}, time.Second, nil, nil).Routes()
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/interfaces" && tc.inventoryUnavailable {
					http.Error(w, "inventory temporarily unavailable", http.StatusServiceUnavailable)
					return
				}
				routes.ServeHTTP(w, r)
			}))
			defer agent.Close()
			state := store.New()
			state.UpsertNode(t.Context(), models.Node{ID: nodeID, AgentURL: agent.URL, LastSeenAt: time.Now()})
			state.PutPolicy(t.Context(), models.InterfacePolicy{
				NodeID: nodeID, Interface: "em2",
				Egress: models.DirectionPolicy{
					Mode: "observe", ObserveOnly: true, Rules: []models.ACLRule{{CIDR: "192.0.2.10/32", Action: "allow"}},
				},
			})
			result := newConsoleSyncHandler(t, state, nodeID).securityInterfaceStreamSnapshot(t.Context(), nodeID, "em2", models.DirectionEgress)
			health, ok := result["health"].(models.HealthStatus)
			if !ok || health.Status != "ok" || len(health.Interfaces) != 1 || health.Interfaces[0].Interface != "em1" || !health.Interfaces[0].PolicyEnforced {
				t.Fatalf("fixture must report only active em1 in health: %#v", result["health"])
			}
			if result["interface"] != "em2" || result["protection_status"] != "not_enabled" || result["interface_status"] != "ready" {
				t.Fatalf("wrong interface snapshot: interface=%q protection=%q data=%q", result["interface"], result["protection_status"], result["interface_status"])
			}
			current, _ := result["current"].(map[string]any)
			policy, ok := current["policy"].(models.InterfacePolicy)
			if !ok || policy.Interface != "em2" || len(policy.Egress.Rules) != 1 || policy.Egress.Rules[0].CIDR != "192.0.2.10/32" {
				t.Fatalf("the snapshot did not preserve em2's egress policy: %#v", policy)
			}
		})
	}
}

func TestOverviewDoesNotReuseActiveSummaryWhenAgentBecomesUnreachable(t *testing.T) {
	var unavailable atomic.Bool
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unreachable"})
			return
		}
		health := models.HealthStatus{NodeID: "node-a", Status: "ok", AgentOK: true, Interfaces: []models.InterfaceHealth{{Interface: "eth0", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: true, EnforcementOK: true}}}
		switch r.URL.Path {
		case "/health":
			writeJSON(w, http.StatusOK, health)
		case "/interfaces/eth0/allowlist":
			writeJSON(w, http.StatusOK, map[string]any{"allowlist": []string{"192.0.2.1/32"}})
		default:
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: agent.URL, LastSeenAt: time.Now()})
	h := newConsoleSyncHandler(t, state, "node-a")
	first := h.overviewStreamSnapshot(t.Context(), "node-a", "eth0", models.DirectionIngress)
	if first["protection_status"] != "enforced" {
		t.Fatalf("baseline did not become ready: %#v", first)
	}
	unavailable.Store(true)
	h.pageSnapshotMu.Lock()
	for key, value := range h.pageSnapshotCache {
		value.fetchedAt = time.Time{}
		h.pageSnapshotCache[key] = value
	}
	h.pageSnapshotMu.Unlock()
	result := h.overviewStreamSnapshot(t.Context(), "node-a", "eth0", models.DirectionIngress)
	if result["protection_status"] != "unavailable" || result["reachable"] != false {
		t.Fatalf("unreachable node retained an active status: %#v", result)
	}
	if _, ok := result["current"]; ok {
		t.Fatal("unreachable node reused an old active summary")
	}
}

func TestSecurityStreamProbesStaleHeartbeatBeforeMarkingFirewallOffline(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{NodeID: "stale", Status: "ok", AgentOK: true, Interfaces: []models.InterfaceHealth{{
				Interface: "ens3", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: true, EnforcementOK: true,
			}}})
		case "/interfaces":
			writeJSON(w, http.StatusOK, models.InterfaceInventory{Recommended: "ens3", Interfaces: []models.DetectedInterface{{Name: "ens3", IsPhysical: true, Attached: true}}})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		}
	}))
	defer agent.Close()

	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "stale", Name: "stale", AgentURL: agent.URL, LastSeenAt: time.Now().Add(-2 * time.Minute)})
	h := newConsoleSyncHandler(t, state, "stale")
	result := h.securityStreamSnapshot(context.Background(), "firewall", "stale")
	items, ok := result["nodes"].([]map[string]any)
	if !ok || len(items) != 1 || items[0]["status"] == "offline" || items[0]["interface"] != "ens3" {
		t.Fatalf("stale firewall stream incorrectly hid reachable node: %#v", result)
	}
}

func TestSettingsLogTargetMatchesSaveTarget(t *testing.T) {
	manager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"log_dir": "/manager/logs", "enabled": true})
	}))
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("global settings probed selected worker: %s", r.URL.Path)
		writeJSON(w, 200, map[string]any{})
	}))
	defer manager.Close()
	defer worker.Close()
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "manager", AgentURL: manager.URL})
	state.UpsertNode(context.Background(), models.Node{ID: "worker", AgentURL: worker.URL})
	h := newConsoleSyncHandler(t, state, "manager")
	result := h.settingsStreamSnapshot(context.Background(), "worker")
	if result["logging_node_id"] != "manager" || result["logging"].(map[string]any)["log_dir"] != "/manager/logs" {
		t.Fatal(result)
	}
}

func TestConfigurationCompareAndSaveRejectsStaleWeb(t *testing.T) {
	h := newConsoleSyncHandler(t, store.New(), "")
	handler := h.Routes()
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest("GET", "/settings/auth", nil))
	tag := get.Header().Get("ETag")
	if tag == "" {
		t.Fatal("GET omitted configuration tag")
	}
	save := func(failures int) *httptest.ResponseRecorder {
		request := httptest.NewRequest("PUT", "/settings/auth", strings.NewReader(`{"max_failures":`+strconv.Itoa(failures)+`,"window_seconds":600,"lock_duration_seconds":900,"allowed_mfa_methods":["otp"]}`))
		request.Header.Set("If-Match", tag)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first := save(4)
	if first.Code != 200 || first.Header().Get("X-NodeWall-Revision") == "" {
		t.Fatalf("first save failed: %d %s", first.Code, first.Body.String())
	}
	second := save(3)
	if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), "CONFIG_CHANGED") {
		t.Fatalf("stale Web replaced newer configuration: %d %s", second.Code, second.Body.String())
	}
	if h.auth.authSettings().MaxFailures != 4 {
		t.Fatal("conflicting write changed stored settings")
	}
}

func TestSettingsSSEBroadcastsSuccessfulSaveToEveryWeb(t *testing.T) {
	h := newConsoleSyncHandler(t, store.New(), "")
	server := httptest.NewServer(h.Routes())
	defer server.Close()
	client := &http.Client{Timeout: 4 * time.Second}
	open := func() (*http.Response, *bufio.Reader) {
		response, err := client.Get(server.URL + "/events/cluster?section=management&overview=0")
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(response.Body)
		for {
			frame, err := readSSEFrame(reader)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(frame, "event: settings") {
				break
			}
		}
		return response, reader
	}
	first, firstReader := open()
	defer first.Body.Close()
	second, secondReader := open()
	defer second.Body.Close()
	request, _ := http.NewRequest("PUT", server.URL+"/settings/auth", strings.NewReader(`{"max_failures":4,"window_seconds":600,"lock_duration_seconds":900,"allowed_mfa_methods":["otp"]}`))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	for _, reader := range []*bufio.Reader{firstReader, secondReader} {
		for {
			frame, err := readSSEFrame(reader)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(frame, "event: settings") {
				continue
			}
			if !strings.Contains(frame, `"max_failures":4`) || !strings.Contains(frame, `"revision":1`) {
				t.Fatalf("Web received old snapshot: %s", frame)
			}
			break
		}
	}
}

func TestSSHPageStreamIncludesKeysWithoutCollectingOtherModules(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/ssh-protection") {
			t.Errorf("SSH page collected unrelated module: %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/ssh-protection/keys":
			writeJSON(w, 200, map[string]any{"keys": []map[string]string{{"fingerprint": "new-key"}}})
		case "/ssh-protection":
			writeJSON(w, 200, map[string]any{"settings": map[string]bool{"enabled": true}})
		default:
			writeJSON(w, 200, map[string]any{"records": []any{}})
		}
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "a", AgentURL: agent.URL, LastSeenAt: time.Now()})
	h := newConsoleSyncHandler(t, state, "a")
	result := h.securityStreamSnapshot(context.Background(), "ssh", "a")
	data, _ := json.Marshal(result)
	if !strings.Contains(string(data), `"fingerprint":"new-key"`) || !strings.Contains(string(data), "ssh_settings_etag") {
		t.Fatalf("SSH keys omitted: %s", data)
	}
}

func TestSecretOnlyConfigurationSaveChangesPublicETag(t *testing.T) {
	h := newConsoleSyncHandler(t, store.New(), "")
	routes := h.Routes()
	save := func(password, etag string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"enabled": false, "host": "smtp.example.test", "from_email": "review@example.test", "password": password})
		request := httptest.NewRequest("PUT", "/settings/smtp", strings.NewReader(string(body)))
		if etag != "" {
			request.Header.Set("If-Match", etag)
		}
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, request)
		return response
	}
	first := save("fixture-secret-one", "")
	second := save("fixture-secret-two", first.Header().Get("ETag"))
	if first.Code != 200 || second.Code != 200 {
		t.Fatalf("SMTP save failed: %d %s / %d %s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	if first.Header().Get("ETag") == second.Header().Get("ETag") {
		t.Fatal("secret replacement did not advance the public ETag")
	}
	if strings.Contains(second.Body.String(), "fixture-secret") {
		t.Fatal("public settings exposed the secret")
	}
	if stale := save("fixture-secret-three", first.Header().Get("ETag")); stale.Code != 409 {
		t.Fatalf("stale secret replacement returned %d", stale.Code)
	}
}

func TestFailedConfigurationSaveKeepsSnapshotAndCanRetry(t *testing.T) {
	h := newConsoleSyncHandler(t, store.New(), "")
	routes := h.Routes()
	get := httptest.NewRecorder()
	routes.ServeHTTP(get, httptest.NewRequest("GET", "/settings/auth", nil))
	tag := get.Header().Get("ETag")
	previousPath := h.auth.settingsFile
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	h.auth.settingsFile = filepath.Join(blocked, "auth.json")
	save := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest("PUT", "/settings/auth", strings.NewReader(`{"max_failures":3,"window_seconds":600,"lock_duration_seconds":900,"allowed_mfa_methods":["otp"]}`))
		request.Header.Set("If-Match", tag)
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, request)
		return response
	}
	if failed := save(); failed.Code == 200 {
		t.Fatal("unwritable settings unexpectedly saved")
	}
	if h.auth.authSettings().MaxFailures != 5 {
		t.Fatal("failed save leaked unpersisted configuration into SSE state")
	}
	h.auth.settingsFile = previousPath
	if retried := save(); retried.Code != 200 {
		t.Fatalf("retry failed: %d %s", retried.Code, retried.Body.String())
	}
	if h.auth.authSettings().MaxFailures != 3 {
		t.Fatal("retry did not save the draft")
	}
}
