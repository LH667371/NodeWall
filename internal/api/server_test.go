package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
)

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

func TestHandleMonitoringHistoryCollectsAndAggregatesNodeSamples(t *testing.T) {
	t.Parallel()

	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/system/metrics" {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.SystemMetrics{
			CapturedAt: time.Now().UTC(),
			CPU:        models.CPUMetrics{UsagePercent: 40},
			Memory:     models.MemoryMetrics{TotalBytes: 1024, UsedPercent: 60},
			Network: models.NetworkMetrics{
				RxBytesPerSecond: 1024,
				TxBytesPerSecond: 2048,
			},
		})
	}))
	defer agent.Close()

	now := time.Now().UTC()
	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "Node A", AgentURL: agent.URL, LastSeenAt: now})
	st.UpsertNode(context.Background(), models.Node{ID: "node-b", Name: "Node B", AgentURL: agent.URL, LastSeenAt: now})
	handler := &ServerHandler{
		service:     service.NewPolicyService(st),
		store:       st,
		reverseHTTP: &http.Client{Timeout: 2 * time.Second},
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
