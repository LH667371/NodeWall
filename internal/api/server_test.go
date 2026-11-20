package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
)

func TestHandleUpdateNodeTriggersRemoteAgent(t *testing.T) {
	var called bool
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/maintenance/update" {
			t.Fatalf("unexpected agent request: %s %s", r.Method, r.URL.Path)
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode update request: %v", err)
		}
		if payload["manager_url"] != "http://example.com" {
			t.Fatalf("manager URL = %q, want current request origin", payload["manager_url"])
		}
		called = true
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "started"})
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "node-a", AgentURL: agent.URL})
	handler := &ServerHandler{
		service:     service.NewPolicyService(st),
		store:       st,
		reverseHTTP: &http.Client{Timeout: 2 * time.Second},
	}
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-a/update", strings.NewReader(`{}`))
	req.SetPathValue("node", "node-a")
	rec := httptest.NewRecorder()
	handler.handleUpdateNode(rec, req)
	if rec.Code != http.StatusAccepted || !called {
		t.Fatalf("expected update trigger, status=%d called=%v body=%s", rec.Code, called, rec.Body.String())
	}
}

func TestProxySSHKeyDeleteSkipsPasswordForOrdinaryKey(t *testing.T) {
	deleted := false
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssh-protection/keys":
			writeJSON(w, http.StatusOK, map[string]any{"keys": []models.SSHAuthorizedKey{
				{Fingerprint: "SHA256:ordinary", Type: "ssh-ed25519", Comment: "ops-laptop"},
				{Fingerprint: "SHA256:other", Type: "ssh-ed25519", Comment: "backup"},
			}})
		case "/ssh-protection/keys/SHA256:ordinary":
			deleted = true
			writeJSON(w, http.StatusOK, map[string]any{"keys": []models.SSHAuthorizedKey{{Fingerprint: "SHA256:other"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "node-a", AgentURL: agent.URL})
	h := &ServerHandler{service: service.NewPolicyService(st), store: st, reverseHTTP: agent.Client()}
	req := httptest.NewRequest(http.MethodDelete, "/nodes/node-a/ssh-protection/keys/SHA256%3Aordinary", nil)
	req.SetPathValue("node", "node-a")
	req.SetPathValue("fingerprint", "SHA256:ordinary")
	rec := httptest.NewRecorder()
	h.handleProxySSHAuthorizedKeyDelete(rec, req)
	if rec.Code != http.StatusOK || !deleted {
		t.Fatalf("ordinary SSH key deletion was blocked: status=%d deleted=%v body=%s", rec.Code, deleted, rec.Body.String())
	}
}

func TestProxySSHKeyDeleteAllowsHistoricalNodeWallKey(t *testing.T) {
	deleted := false
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssh-protection/keys":
			writeJSON(w, http.StatusOK, map[string]any{"keys": []models.SSHAuthorizedKey{
				{Fingerprint: "SHA256:history", Type: "ssh-ed25519", Comment: "nodewall-console", NodeWallManaged: true, NodeWallActiveKnown: true},
				{Fingerprint: "SHA256:active", Type: "ssh-ed25519", Comment: "nodewall-console", NodeWallManaged: true, NodeWallActive: true},
			}})
		case "/ssh-protection/keys/SHA256:history":
			deleted = true
			writeJSON(w, http.StatusOK, map[string]any{"keys": []models.SSHAuthorizedKey{{Fingerprint: "SHA256:active"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "node-a", AgentURL: agent.URL})
	h := &ServerHandler{service: service.NewPolicyService(st), store: st, reverseHTTP: agent.Client()}
	req := httptest.NewRequest(http.MethodDelete, "/nodes/node-a/ssh-protection/keys/SHA256%3Ahistory", nil)
	req.SetPathValue("node", "node-a")
	req.SetPathValue("fingerprint", "SHA256:history")
	rec := httptest.NewRecorder()
	h.handleProxySSHAuthorizedKeyDelete(rec, req)
	if rec.Code != http.StatusOK || !deleted {
		t.Fatalf("historical NodeWall key was not removable without password: status=%d deleted=%v body=%s", rec.Code, deleted, rec.Body.String())
	}
}

func TestProxySSHKeyDeleteProtectsNodeWallConsoleKey(t *testing.T) {
	deleted := false
	allowPassword := false
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssh-protection/keys":
			writeJSON(w, http.StatusOK, map[string]any{"keys": []models.SSHAuthorizedKey{{Fingerprint: "SHA256:console", Type: "ssh-ed25519", Comment: "nodewall-console"}}})
		case "/ssh-protection":
			writeJSON(w, http.StatusOK, models.SSHProtectionStatus{Settings: models.SSHProtectionSettings{AllowPasswordLogin: &allowPassword}})
		case "/ssh-protection/keys/SHA256:console":
			deleted = true
			writeJSON(w, http.StatusOK, map[string]any{"keys": []models.SSHAuthorizedKey{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "node-a", AgentURL: agent.URL})
	h := &ServerHandler{service: service.NewPolicyService(st), store: st, reverseHTTP: agent.Client()}
	req := httptest.NewRequest(http.MethodDelete, "/nodes/node-a/ssh-protection/keys/SHA256%3Aconsole", nil)
	req.SetPathValue("node", "node-a")
	req.SetPathValue("fingerprint", "SHA256:console")
	rec := httptest.NewRecorder()
	h.handleProxySSHAuthorizedKeyDelete(rec, req)
	if rec.Code != http.StatusUnauthorized || deleted {
		t.Fatalf("console SSH key deletion was not protected: status=%d deleted=%v body=%s", rec.Code, deleted, rec.Body.String())
	}
}

func TestClusterAggregateDoesNotProbeOfflineNode(t *testing.T) {
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{
		ID:         "offline-node",
		Name:       "offline-node",
		AgentURL:   "http://192.0.2.250:9080",
		LastSeenAt: time.Now().Add(-10 * time.Minute),
	})
	handler := &ServerHandler{store: state, service: service.NewPolicyService(state)}
	result := handler.buildClusterAggregate(context.Background(), models.DirectionIngress)
	rows, ok := result["nodes"].([]clusterNodeAggregate)
	if !ok || len(rows) != 1 || rows[0].Status != "offline" {
		t.Fatalf("offline node was not rendered without probing: %#v", result["nodes"])
	}
}

func TestClusterProtectionDoesNotWaitForSystemMetrics(t *testing.T) {
	metricsStarted := make(chan struct{})
	releaseMetrics := make(chan struct{})
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/system/metrics":
			close(metricsStarted)
			<-releaseMetrics
			writeJSON(w, http.StatusOK, models.SystemMetrics{Memory: models.MemoryMetrics{TotalBytes: 1}})
		case "/interfaces":
			writeJSON(w, http.StatusOK, models.InterfaceInventory{Recommended: "eth0", Interfaces: []models.DetectedInterface{{Name: "eth0", IsPhysical: true}}})
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{Interfaces: []models.InterfaceHealth{{
				Interface: "eth0", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: true, EnforcementOK: true,
			}}})
		default:
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	}))
	defer agent.Close()
	state := store.New()
	node := models.Node{ID: "node-a", AgentURL: agent.URL, LastSeenAt: time.Now()}
	state.UpsertNode(context.Background(), node)
	h := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: agent.Client()}
	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		_, _ = h.readSystemMetrics(context.Background(), node)
	}()
	defer func() { close(releaseMetrics); <-metricsDone }()
	<-metricsStarted

	results := make(chan map[string]any, 1)
	go func() { results <- h.buildClusterAggregate(context.Background(), models.DirectionIngress) }()
	select {
	case result := <-results:
		rows := result["nodes"].([]clusterNodeAggregate)
		if len(rows) != 1 || rows[0].ProtectionStatus != "enforced" {
			t.Fatalf("healthy node was not reported as enforced: %#v", rows)
		}
	case <-time.After(time.Second):
		t.Fatal("cluster protection waited for a blocked system metrics request")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := h.readSystemMetrics(ctx, node); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting metrics request did not honor its deadline: %v", err)
	}
}

func TestClusterEventsDeliverNodesBeforeSlowOverview(t *testing.T) {
	probeStarted := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case probeStarted <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a", AgentURL: agent.URL, LastSeenAt: time.Now()})
	h := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: agent.Client()}
	server := httptest.NewServer(http.HandlerFunc(h.handleClusterEvents))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("node event was blocked by the overview: %v", err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "event: nodes" {
		t.Fatalf("first event = %q, error = %v; want nodes", line, err)
	}
}

func TestClusterEventsMonitoringSendsCachedSnapshotWithoutCollecting(t *testing.T) {
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a"})
	h := &ServerHandler{store: state, service: service.NewPolicyService(state), metricsArchiveError: "archive unavailable"}
	server := httptest.NewServer(http.HandlerFunc(h.handleClusterEvents))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"?section=monitoring&overview=0&range=900", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	for index := 0; index < 3; index++ {
		if _, err := readSSEFrame(reader); err != nil {
			t.Fatalf("initial monitoring frame %d: %v", index, err)
		}
	}
	frame, err := readSSEFrame(reader)
	if err != nil || !strings.Contains(frame, "event: monitoring") || !strings.Contains(frame, `"scope":"cluster"`) || !strings.Contains(frame, `"storage_error":"archive unavailable"`) {
		t.Fatalf("monitoring snapshot frame = %q (%v)", frame, err)
	}
	// A successful write can clear the warning after a snapshot has already
	// been sent for this round. Publish that change without another sample.
	h.systemMetricsMu.Lock()
	h.metricsArchiveError = ""
	h.systemMetricsMu.Unlock()
	h.invalidateConsoleSnapshots()
	for {
		frame, err := readSSEFrame(reader)
		if err != nil {
			t.Fatalf("missing archive recovery frame: %v", err)
		}
		if strings.Contains(frame, "event: monitoring") {
			if strings.Contains(frame, `"storage_error"`) {
				t.Fatalf("recovered archive still reports a write failure: %q", frame)
			}
			break
		}
	}
}

func TestEventDispositionSSEBroadcastsToEveryBrowser(t *testing.T) {
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a"})
	h := &ServerHandler{store: state, service: service.NewPolicyService(state)}
	server := httptest.NewServer(http.HandlerFunc(h.handleClusterEvents))
	defer server.Close()

	type stream struct {
		cancel context.CancelFunc
		body   *http.Response
		reader *bufio.Reader
	}
	open := func() stream {
		ctx, cancel := context.WithCancel(context.Background())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"?overview=0", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(response.Body)
		for index := 0; index < 3; index++ {
			if _, err := readSSEFrame(reader); err != nil {
				response.Body.Close()
				cancel()
				t.Fatal(err)
			}
		}
		return stream{cancel: cancel, body: response, reader: reader}
	}
	first, second := open(), open()
	defer func() {
		first.cancel()
		second.cancel()
		first.body.Body.Close()
		second.body.Body.Close()
	}()

	request := httptest.NewRequest(http.MethodPut, "/events/dispositions/firewall-node-a-event", strings.NewReader(`{"node_id":"node-a","source":"firewall","status":"handled"}`))
	response := httptest.NewRecorder()
	h.handleEventDispositions(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("disposition update returned %d: %s", response.Code, response.Body.String())
	}
	for _, browser := range []stream{first, second} {
		frame, err := readSSEFrame(browser.reader)
		if err != nil || !strings.Contains(frame, "event: event_dispositions") || !strings.Contains(frame, `"revision":1`) || !strings.Contains(frame, `"status":"handled"`) {
			t.Fatalf("browser did not receive disposition update: %q (%v)", frame, err)
		}
	}
}

func readSSEFrame(reader *bufio.Reader) (string, error) {
	var frame strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return frame.String(), err
		}
		frame.WriteString(line)
		if line == "\n" {
			return frame.String(), nil
		}
	}
}

func TestClusterAggregateProbesNodesConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/interfaces" {
			started <- struct{}{}
			<-release
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	}))
	defer agent.Close()
	state := store.New()
	for _, id := range []string{"node-a", "node-b"} {
		state.UpsertNode(context.Background(), models.Node{ID: id, AgentURL: agent.URL, LastSeenAt: time.Now()})
	}
	h := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: agent.Client()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.buildClusterAggregate(context.Background(), models.DirectionIngress)
	}()
	defer func() { close(release); <-done }()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("one node waited for another node's slow probe")
		}
	}
}

func TestNodeProtectionStatusUsesOnlyHealthAndInventory(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interfaces":
			writeJSON(w, http.StatusOK, models.InterfaceInventory{Recommended: "eth0", Interfaces: []models.DetectedInterface{{Name: "eth0", IsPhysical: true}}})
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{Interfaces: []models.InterfaceHealth{{
				Interface: "eth0", XDPAttached: true, MapOK: true, StatsOK: true, PolicyEnforced: true, EnforcementOK: true,
			}}})
		default:
			t.Errorf("unexpected request for unrelated data: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a", AgentURL: agent.URL})
	h := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: agent.Client()}
	req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/protection-status", nil)
	req.SetPathValue("node", "node-a")
	recorder := httptest.NewRecorder()
	h.handleNodeProtectionStatus(recorder, req)
	var result map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil || result["protection_status"] != "enforced" {
		t.Fatalf("unexpected protection response: %s, error: %v", recorder.Body, err)
	}
}

func TestProtectionStatusFollowsAttachedInterfaceWhenRecommendationDiffers(t *testing.T) {
	inventory := models.InterfaceInventory{
		Recommended: "ens3",
		Interfaces: []models.DetectedInterface{
			{Name: "ens3", IsPhysical: true},
			{Name: "eth1", IsPhysical: true, Attached: true},
		},
	}
	if got := clusterFocusInterface(inventory); got != "eth1" {
		t.Fatalf("cluster focus ignored attached interface: %q", got)
	}

	health := models.HealthStatus{
		Status: "ok",
		Interfaces: []models.InterfaceHealth{{
			Interface: "eth1", XDPAttached: true, MapOK: true, StatsOK: true,
			PolicyEnforced: true, EnforcementOK: true,
		}},
	}
	if got := protectionStatusForInterface(health, "ens3", true); got != "enforced" {
		t.Fatalf("healthy attached interface was hidden by stale recommendation: %q", got)
	}
}

func TestNodeProtectionStatusFallsBackToHealthWhenInventoryIsUnavailable(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interfaces":
			http.Error(w, "inventory temporarily unavailable", http.StatusServiceUnavailable)
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{Interfaces: []models.InterfaceHealth{{
				Interface: "eth1", XDPAttached: true, MapOK: true, StatsOK: true,
				PolicyEnforced: true, EnforcementOK: true,
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a", AgentURL: agent.URL})
	h := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: agent.Client()}
	req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/protection-status", nil)
	req.SetPathValue("node", "node-a")
	recorder := httptest.NewRecorder()
	h.handleNodeProtectionStatus(recorder, req)
	var result map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil || result["protection_status"] != "enforced" || result["interface"] != "eth1" {
		t.Fatalf("health status was hidden by inventory failure: %s, error: %v", recorder.Body, err)
	}
}

func TestHandleDeleteNodeForceCleansStaleAgent(t *testing.T) {
	var cleanupCalls, deleteCalls int
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/maintenance/cleanup":
			cleanupCalls++
		case "/maintenance/delete":
			deleteCalls++
		default:
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{
		ID:         "node-stale",
		Name:       "node-stale",
		AgentURL:   agent.URL,
		LastSeenAt: time.Now().Add(-10 * time.Minute),
	})
	handler := &ServerHandler{
		service:     service.NewPolicyService(st),
		store:       st,
		reverseHTTP: &http.Client{Timeout: 2 * time.Second},
	}
	req := httptest.NewRequest(http.MethodDelete, "/nodes/node-stale?force=true", nil)
	req.SetPathValue("node", "node-stale")
	rec := httptest.NewRecorder()
	handler.handleDeleteNode(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected delete status: %d body=%s", rec.Code, rec.Body.String())
	}
	if cleanupCalls != 1 || deleteCalls != 1 {
		t.Fatalf("expected forced cleanup and uninstall, got cleanup=%d delete=%d", cleanupCalls, deleteCalls)
	}
	if _, ok := service.FindNode(st.ListNodes(context.Background()), "node-stale"); ok {
		t.Fatal("expected stale node to be removed from the manager")
	}
}

func TestHandleProxyRecentDropLogsAggregatesBlockedLogs(t *testing.T) {
	t.Parallel()

	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/logs/drop"):
			writeJSON(w, http.StatusOK, map[string]any{
				"logs": []models.DropLogRecord{{
					Timestamp: time.Now().UTC(),
					Interface: "eth0",
					SourceIP:  "10.0.0.8",
					Port:      443,
					Reason:    "blocked",
					Drops:     1,
				}},
			})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"temporary_blocks": []any{}, "rate_limits": []any{}})
		}
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{
		ID:       "node-a",
		Name:     "node-a",
		AgentURL: agent.URL,
	})
	svc := service.NewPolicyService(st)
	svc.UpdatePolicy(context.Background(), models.InterfacePolicy{
		NodeID:    "node-a",
		Interface: "eth0",
		Ingress: models.DirectionPolicy{
			BlockedCIDRs: []string{"10.0.0.8/32"},
		},
	})

	handler := &ServerHandler{
		service:     svc,
		store:       st,
		reverseHTTP: &http.Client{Timeout: 2 * time.Second},
	}
	req := httptest.NewRequest(http.MethodGet, "/logs/drop", nil)
	rec := httptest.NewRecorder()

	handler.handleProxyRecentDropLogs(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Logs []models.DropLogRecord `json:"logs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Logs) != 1 {
		t.Fatalf("unexpected logs: %#v", payload.Logs)
	}
	if payload.Logs[0].Disposition == nil {
		t.Fatalf("expected non-nil disposition, got %#v", payload.Logs[0].Disposition)
	}
}

func TestHandleProxyInterfacesDoesNotAttachAsReadSideEffect(t *testing.T) {
	attachCalls := 0
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/attach") {
			attachCalls++
		}
		if r.URL.Path == "/interfaces" {
			writeJSON(w, http.StatusOK, map[string]any{
				"interfaces":  []models.DetectedInterface{{Name: "ens3", IsPhysical: true}},
				"recommended": "ens3",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "node-a", AgentURL: agent.URL})
	handler := &ServerHandler{
		service:     service.NewPolicyService(st),
		store:       st,
		reverseHTTP: &http.Client{Timeout: 2 * time.Second},
	}
	req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/interfaces", nil)
	rec := httptest.NewRecorder()
	handler.handleProxyInterfaces(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if attachCalls != 0 {
		t.Fatalf("reading interfaces unexpectedly attached %d interfaces", attachCalls)
	}
}

func TestHandleProxyInterfacesFallbackPrefersAttachedHealthInterface(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interfaces":
			writeError(w, http.StatusServiceUnavailable, errors.New("inventory busy"))
		case "/health":
			writeJSON(w, http.StatusOK, models.HealthStatus{
				NodeID: "node-a", Status: "ok", AgentOK: true,
				Interfaces: []models.InterfaceHealth{{Interface: "ens3", XDPAttached: true, PolicyEnforced: true}},
			})
		default:
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "node-a", AgentURL: agent.URL})
	st.PutPolicy(context.Background(), models.InterfacePolicy{NodeID: "node-a", Interface: "eno1"})
	st.PutPolicy(context.Background(), models.InterfacePolicy{NodeID: "node-a", Interface: "ens3"})
	handler := &ServerHandler{service: service.NewPolicyService(st), store: st, reverseHTTP: agent.Client()}
	req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/interfaces", nil)
	req.SetPathValue("node", "node-a")
	rec := httptest.NewRecorder()
	handler.handleProxyInterfaces(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Interfaces  []models.DetectedInterface `json:"interfaces"`
		Recommended string                     `json:"recommended"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Interfaces) == 0 || payload.Interfaces[0].Name != "ens3" || payload.Recommended != "ens3" || !payload.Interfaces[0].Attached {
		t.Fatalf("fallback did not prefer attached health interface: %#v", payload)
	}
}

func TestPortMutationFailsWhenAgentCannotApply(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/attach") {
			writeError(w, http.StatusInternalServerError, errors.New("attach failed"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "node-a", AgentURL: agent.URL})
	handler := &ServerHandler{service: service.NewPolicyService(st), store: st, reverseHTTP: agent.Client()}
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-a/interfaces/ens3/denied-ports", strings.NewReader(`{"port":25006,"protocol":"tcp"}`))
	req.SetPathValue("node", "node-a")
	req.SetPathValue("iface", "ens3")
	rec := httptest.NewRecorder()

	handler.handleProxyDeniedPortsUpsert(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected apply failure status, got %d: %s", rec.Code, rec.Body.String())
	}
	policy, err := st.GetPolicy(context.Background(), "node-a", "ens3")
	if err != nil {
		t.Fatal(err)
	}
	if len(models.DirectionPolicyFor(policy, models.DirectionIngress).DeniedPortRules) != 0 {
		t.Fatalf("failed policy apply persisted deny rule: %#v", policy)
	}
}

func TestHandleProxyStatsPreservesDirectionQuery(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"direction": r.URL.Query().Get("direction")})
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "node-a", AgentURL: agent.URL})
	handler := &ServerHandler{
		service:     service.NewPolicyService(st),
		store:       st,
		reverseHTTP: &http.Client{Timeout: 2 * time.Second},
	}
	req := httptest.NewRequest(http.MethodGet, "/nodes/node-a/interfaces/ens3/stats?direction=egress", nil)
	req.SetPathValue("node", "node-a")
	req.SetPathValue("iface", "ens3")
	rec := httptest.NewRecorder()
	handler.handleProxyStats(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["direction"] != "egress" {
		t.Fatalf("expected egress query to reach agent, got %#v", payload)
	}
}

func TestMonitoringHistoryPublishesOnlyCompletedRounds(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	fastReturned, slowStarted, releaseSlow := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSlow) }) }
	newAgent := func(slow bool, skew time.Duration) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/system/metrics" {
				http.NotFound(w, r)
				return
			}
			calls.Add(1)
			if slow {
				select {
				case slowStarted <- struct{}{}:
				default:
				}
				select {
				case <-releaseSlow:
				case <-r.Context().Done():
					return
				}
			}
			writeJSON(w, http.StatusOK, models.SystemMetrics{
				CapturedAt: time.Now().UTC().Add(skew),
				CPU:        models.CPUMetrics{UsagePercent: 40},
				Memory:     models.MemoryMetrics{TotalBytes: 1024, UsedPercent: 60},
				Network:    models.NetworkMetrics{RxBytesPerSecond: 1024, TxBytesPerSecond: 2048},
			})
			if !slow {
				select {
				case fastReturned <- struct{}{}:
				default:
				}
			}
		}))
	}
	fast, slow := newAgent(false, -time.Minute), newAgent(true, time.Minute)
	defer fast.Close()
	defer slow.Close()
	defer release()

	now := time.Now().UTC()
	st := store.New()
	st.UpsertNode(t.Context(), models.Node{ID: "node-a", Name: "Node A", AgentURL: fast.URL, LastSeenAt: now})
	st.UpsertNode(t.Context(), models.Node{ID: "node-b", Name: "Node B", AgentURL: slow.URL, LastSeenAt: now})
	handler := &ServerHandler{
		service: service.NewPolicyService(st), store: st,
		reverseHTTP: &http.Client{Timeout: 3 * time.Second},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.collectSystemMetrics(t.Context(), st.ListNodes(t.Context()), now)
	}()
	for _, ready := range []chan struct{}{fastReturned, slowStarted} {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("agents were not sampled concurrently")
		}
	}

	partial := httptest.NewRecorder()
	handler.handleMonitoringHistory(partial, httptest.NewRequest(http.MethodGet, "/monitoring/history?range=300", nil))
	var before models.SystemMetricsHistory
	if err := json.Unmarshal(partial.Body.Bytes(), &before); err != nil || len(before.Points) != 0 || !before.SampledAt.IsZero() {
		t.Fatalf("HTTP exposed part of an unfinished batch: %s (%v)", partial.Body.String(), err)
	}
	streamBefore := handler.monitoringStreamSnapshot(t.Context(), "", 300, "", "")
	if len(streamBefore.Points) != 0 || !streamBefore.SampledAt.IsZero() {
		t.Fatal("SSE exposed part of an unfinished batch")
	}
	if samples, err := handler.recentMonitoringSamples(t.Context(), now.Add(-time.Minute), now); err != nil || len(samples) != 0 {
		t.Fatalf("standby sync exposed part of an unfinished round: %v (%v)", samples, err)
	}
	release()
	<-done
	if samples, err := handler.recentMonitoringSamples(t.Context(), now.Add(-time.Minute), now); err != nil || len(samples) != 2 {
		t.Fatalf("standby sync did not reuse the completed round: %v (%v)", samples, err)
	}

	req := httptest.NewRequest(http.MethodGet, "/monitoring/history?range=300", nil)
	rec := httptest.NewRecorder()
	handler.handleMonitoringHistory(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var cluster models.SystemMetricsHistory
	if err := json.Unmarshal(rec.Body.Bytes(), &cluster); err != nil {
		t.Fatalf("decode cluster history: %v", err)
	}
	if cluster.Scope != "cluster" || len(cluster.Points) != 1 || len(cluster.Nodes) != 2 {
		t.Fatalf("unexpected cluster history: %#v", cluster)
	}
	if cluster.Points[0].CPUPercent != 40 || cluster.Points[0].RxBytesPerSecond != 2048 {
		t.Fatalf("unexpected aggregated point: %#v", cluster.Points[0])
	}
	wantAt := now.Truncate(systemMetricsSampleInterval)
	if !cluster.SampledAt.Equal(wantAt) || cluster.SampleIntervalSeconds != 15 ||
		len(cluster.NodePoints["node-a"]) != 1 || len(cluster.NodePoints["node-b"]) != 1 ||
		!cluster.NodePoints["node-a"][0].Timestamp.Equal(wantAt) || !cluster.NodePoints["node-b"][0].Timestamp.Equal(wantAt) {
		t.Fatalf("node clock skew split one scheduled round: %#v", cluster.NodePoints)
	}

	nodeReq := httptest.NewRequest(http.MethodGet, "/monitoring/history?node=node-a&range=300", nil)
	nodeRec := httptest.NewRecorder()
	handler.handleMonitoringHistory(nodeRec, nodeReq)
	if nodeRec.Code != http.StatusOK {
		t.Fatalf("unexpected node status: %d body=%s", nodeRec.Code, nodeRec.Body.String())
	}
	var nodeHistory models.SystemMetricsHistory
	if err := json.Unmarshal(nodeRec.Body.Bytes(), &nodeHistory); err != nil {
		t.Fatalf("decode node history: %v", err)
	}
	if nodeHistory.Scope != "node" || nodeHistory.NodeID != "node-a" || len(nodeHistory.Points) != 1 || len(nodeHistory.Nodes) != 1 {
		t.Fatalf("unexpected node history: %#v", nodeHistory)
	}
	if calls.Load() != 2 {
		t.Fatalf("HTTP or SSE initiated extra Agent probes: %d", calls.Load())
	}
}

func TestMonitoringTimeWindowSupportsCustomRange(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	fromInput := now.Add(-2 * time.Hour).Format(time.RFC3339)
	toInput := now.Add(-30 * time.Minute).Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/monitoring/history?from="+url.QueryEscape(fromInput)+"&to="+url.QueryEscape(toInput), nil)

	from, to, seconds, err := monitoringTimeWindow(req, now)
	if err != nil {
		t.Fatalf("unexpected custom range error: %v", err)
	}
	if !from.Equal(now.Add(-2*time.Hour)) || !to.Equal(now.Add(-30*time.Minute)) || seconds != 90*60 {
		t.Fatalf("unexpected custom range: from=%s to=%s seconds=%d", from, to, seconds)
	}

	invalid := httptest.NewRequest(http.MethodGet, "/monitoring/history?from="+url.QueryEscape(fromInput), nil)
	if _, _, _, err := monitoringTimeWindow(invalid, now); err == nil {
		t.Fatal("expected an error when the custom range has no end")
	}
}

func TestContainsCIDRMatchesSingleIPAndPrefix(t *testing.T) {
	t.Parallel()

	if !containsCIDR([]string{"192.168.5.125"}, "192.168.5.125") {
		t.Fatal("expected a single-IP policy to match")
	}
	if !containsCIDR([]string{"192.168.5.0/24"}, "192.168.5.125") {
		t.Fatal("expected a CIDR policy to match an address in the prefix")
	}
	if containsCIDR([]string{"192.168.5.125"}, "192.168.5.126") {
		t.Fatal("did not expect a different address to match")
	}
}

func TestEffectiveTCPPortAction(t *testing.T) {
	t.Parallel()

	base := models.DirectionPolicy{PublicPorts: []uint16{22}}
	if got := effectiveTCPPortAction(base, 22); got != "allow" {
		t.Fatalf("expected default public port to allow, got %q", got)
	}
	base.DeniedPorts = []uint16{22}
	if got := effectiveTCPPortAction(base, 22); got != "deny" {
		t.Fatalf("expected denied port to deny, got %q", got)
	}
	base.DeniedPorts = nil
	base.AllowedPorts = []uint16{443}
	if got := effectiveTCPPortAction(base, 80); got != "deny" {
		t.Fatalf("expected restricted policy to deny an unspecified port, got %q", got)
	}
}

func TestHandleUpdateNodeNamePreservesCustomNameAcrossHeartbeats(t *testing.T) {
	t.Parallel()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{
		ID:       "node-a",
		Name:     "node-a",
		AgentURL: "http://127.0.0.1:19080",
	})
	handler := &ServerHandler{store: st}
	req := httptest.NewRequest(http.MethodPut, "/nodes/node-a/name", strings.NewReader(`{"name":"生产节点"}`))
	req.SetPathValue("node", "node-a")
	rec := httptest.NewRecorder()
	handler.handleUpdateNodeName(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected rename status: %d body=%s", rec.Code, rec.Body.String())
	}

	st.UpsertNode(context.Background(), models.Node{
		ID:            "node-a",
		Name:          "tool01",
		AgentURL:      "http://127.0.0.1:19080",
		LastSeenAt:    time.Now().UTC(),
		AdvertiseIP:   "192.168.5.126",
		AgentHTTPAddr: "192.168.5.126:19080",
	})
	rows := st.ListNodes(context.Background())
	if len(rows) != 1 || rows[0].Name != "生产节点" || !rows[0].NameCustomized {
		t.Fatalf("custom name was not preserved: %#v", rows)
	}
}

func TestHandleProxyRuleDescriptionPersistsForSourceAndPortRules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := store.New()
	st.PutPolicy(ctx, models.InterfacePolicy{
		NodeID:    "node-a",
		Interface: "ens3",
		Ingress: models.DirectionPolicy{
			Mode:            "whitelist",
			Rules:           []models.ACLRule{{CIDR: "192.0.2.0/24", Action: "allow"}},
			PublicPortRules: []models.PortRule{{Protocol: models.PortProtocolTCP, Port: 443}},
		},
	})
	handler := &ServerHandler{store: st, service: service.NewPolicyService(st)}

	for _, input := range []struct {
		body string
		want models.RuleDescription
	}{
		{body: `{"kind":"allowlist","value":"192.0.2.0/24","description":"管理网段"}`, want: models.RuleDescription{Kind: "source", Value: "192.0.2.0/24", Description: "管理网段"}},
		{body: `{"kind":"public","value":"443","protocol":"tcp","description":"HTTPS 服务"}`, want: models.RuleDescription{Kind: "port", Value: "443", Protocol: models.PortProtocolTCP, Description: "HTTPS 服务"}},
	} {
		req := httptest.NewRequest(http.MethodPut, "/nodes/node-a/interfaces/ens3/rule-description?direction=ingress", strings.NewReader(input.body))
		req.SetPathValue("node", "node-a")
		req.SetPathValue("iface", "ens3")
		rec := httptest.NewRecorder()
		handler.handleProxyRuleDescription(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
		}
		policy, err := st.GetPolicy(ctx, "node-a", "ens3")
		if err != nil {
			t.Fatalf("read policy: %v", err)
		}
		found := false
		for _, item := range policy.Ingress.RuleDescriptions {
			if item == input.want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("description %#v was not persisted: %#v", input.want, policy.Ingress.RuleDescriptions)
		}
	}
}
