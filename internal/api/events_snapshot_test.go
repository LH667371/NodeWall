package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nodewall/internal/droplog"
	"nodewall/internal/models"
	"nodewall/internal/securityscan"
	"nodewall/internal/service"
	"nodewall/internal/store"
	"nodewall/internal/xdp"
)

type eventAuditDataplane struct {
	*xdp.MockManager
}

func (eventAuditDataplane) ReadDropLogs(string, int) ([]models.InterceptLogEntry, error) {
	return []models.InterceptLogEntry{
		{SourceCIDR: "0.0.0.0/0", Reason: "nodewall:default_deny", Count: 12, Drops: 12,
			Traffic: &models.FirewallTraffic{Evidence: models.FirewallRuleCounter, Hook: "input"}},
		{SourceCIDR: "192.0.2.0/24", Reason: "nodewall:blocked_source", Count: 198,
			Traffic: &models.FirewallTraffic{Evidence: models.FirewallRuleCounter, Hook: "input"}},
	}, nil
}

func TestEventsSnapshotPreservesAgentFirewallAuditEvidence(t *testing.T) {
	dir := t.TempDir()
	recorder, err := droplog.New(dir, filepath.Join(dir, "drop-log-state.json"), models.DropLogSettings{Enabled: true, LogDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	dp := eventAuditDataplane{xdp.NewMockManager()}
	if err := dp.Attach("eno1", xdp.AttachModeGeneric); err != nil {
		t.Fatal(err)
	}
	traffic := models.FirewallTraffic{
		Evidence: models.FirewallPacketSample, Hook: "input", Origin: "vm", Device: "vnic12.0",
		Bridge: "br_eno1", Guest: "guest-a", Basis: "ingress_device", LocalIP: "192.0.2.16", Protocol: "tcp",
	}
	recorder.RecordPacketAudit(models.DropLogRecord{
		Timestamp: time.Now().UTC(), Interface: "eno1", Direction: models.DirectionIngress,
		SourceIP: "192.0.2.19", Port: 8080, Reason: "nodewall:default_deny", Count: 1, Drops: 1, Traffic: &traffic,
	})
	if err := recorder.Flush(dp); err != nil {
		t.Fatal(err)
	}
	handler := NewAgentHandler("zstack", dp, memoryStateStore{}, time.Second, recorder, nil, SSHProtectionOptions{
		ActivityLogPath: filepath.Join(dir, "ssh-activity.log"),
	})
	handler.dnsResolver = nil
	agent := httptest.NewServer(handler.Routes())
	defer agent.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "zstack", AgentURL: agent.URL})
	manager := newConsoleSyncHandler(t, state, "zstack")
	response := httptest.NewRecorder()
	manager.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/events/snapshot?node=other&direction=egress", nil))
	var payload struct {
		Logs []models.DropLogRecord `json:"logs"`
	}
	err = json.Unmarshal(response.Body.Bytes(), &payload)
	if err != nil || response.Code != http.StatusOK || len(payload.Logs) != 3 {
		t.Fatalf("firewall history did not reach the event snapshot: %d %s (%v)", response.Code, response.Body, err)
	}
	for _, record := range payload.Logs {
		if record.NodeID != "zstack" || record.Interface != "eno1" || record.Direction != models.DirectionIngress || record.Traffic == nil {
			t.Fatalf("missing firewall provenance: %+v", record)
		}
		switch record.Count {
		case 1:
			if *record.Traffic != traffic || record.SourceIP != "192.0.2.19" || record.Port != 8080 || record.Drops != 1 {
				t.Fatalf("packet evidence changed in transit: %+v", record)
			}
		case 12:
			if record.Traffic.Evidence != models.FirewallRuleCounter || record.SourceCIDR != "0.0.0.0/0" || record.SourceIP != "" || record.Drops != 12 {
				t.Fatalf("rule counter changed in transit: %+v", record)
			}
		case 198:
			if record.Traffic.Evidence != models.FirewallRuleCounter || record.Drops != 0 {
				t.Fatalf("rule observation became a drop: %+v", record)
			}
		default:
			t.Fatalf("unexpected firewall count: %+v", record)
		}
	}
}

func TestEventSnapshotCollectsAllNodesAndScanHistoryWithoutSecurityForms(t *testing.T) {
	state := store.New()
	var activityCalls atomic.Int32
	for _, id := range []string{"a", "b"} {
		agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/logs/drop":
				writeJSON(w, http.StatusOK, map[string]any{"logs": []models.DropLogRecord{
					{NodeID: "wrong-node", SourceIP: "0.0.0.0", Port: 67, Reason: "dhcp_broadcast", Count: 2, Drops: 2},
					{SourceCIDR: "0.0.0.0/0", Port: 67, Reason: "nodewall:default_deny", Count: 3, Drops: 3},
					{SourceCIDR: "10.42.0.0/16", Port: 67, Reason: "nodewall:default_deny", Count: 4},
				}})
			case "/ssh-protection/activity":
				activityCalls.Add(1)
				writeJSON(w, http.StatusOK, map[string]any{"records": []any{map[string]any{"command": id, "action": "failed", "at": time.Now()}}})
			case "/security/scan/reports":
				writeJSON(w, http.StatusOK, map[string]any{"reports": []any{
					map[string]any{"id": "scan-old", "status": "completed", "findings_count": 3, "started_at": time.Now().Add(-time.Hour)},
					map[string]any{"id": "scan-new", "status": "completed", "findings_count": 2, "started_at": time.Now()},
				}})
			case "/security/scan":
				if r.URL.Query().Get("summary") != "1" {
					t.Error("event collector requested complete scan findings")
				}
				// Exercise the older Agent response as well as archive de-duplication.
				writeJSON(w, http.StatusOK, map[string]any{"id": "scan-new", "status": "completed", "started_at": time.Now(), "findings": []any{map[string]any{"id": "finding"}}})
			default:
				t.Errorf("event collector fetched unrelated security data: %s", r.URL.Path)
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(agent.Close)
		state.UpsertNode(t.Context(), models.Node{ID: id, Name: id, AgentURL: agent.URL})
	}
	h := newConsoleSyncHandler(t, state, "a")
	results := make(chan map[string]any, 2)
	for range 2 {
		go func() { results <- h.eventsStreamSnapshot(t.Context()) }()
	}
	for range 2 {
		result := <-results
		items := result["nodes"].([]eventNodeSnapshot)
		if result["scope"] != "cluster" || len(items) != 2 {
			t.Fatalf("event scope is not cluster-wide: %#v", result)
		}
		logs := result["logs"].([]models.DropLogRecord)
		if len(logs) != 6 {
			t.Fatalf("firewall audit metadata lost: %+v", logs)
		}
		for _, entry := range logs {
			if entry.NodeID != "a" && entry.NodeID != "b" {
				t.Fatalf("untrusted log provenance: %+v", entry)
			}
			if entry.SourceCIDR != "" && entry.SourceIP != "" {
				t.Fatalf("aggregate became a packet source: %+v", entry)
			}
			if entry.SourceCIDR == "10.42.0.0/16" && (entry.Count != 4 || entry.Drops != 0) {
				t.Fatalf("observation became a drop: %+v", entry)
			}
		}
		for _, item := range items {
			if len(item.Scans) != 2 || len(item.SSHActivity) != 1 || item.SSHActivity[0].Command != item.NodeID {
				t.Fatalf("lost or duplicated node history: %#v", item)
			}
		}
	}
	if activityCalls.Load() != 2 {
		t.Fatalf("multiple Webs duplicated collection: calls=%d", activityCalls.Load())
	}
	manager := httptest.NewServer(h.Routes())
	defer manager.Close()
	response, err := manager.Client().Get(manager.URL + "/events/snapshot?node=b")
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Scope string                 `json:"scope"`
		Nodes []eventNodeSnapshot    `json:"nodes"`
		Logs  []models.DropLogRecord `json:"logs"`
	}
	err = json.NewDecoder(response.Body).Decode(&payload)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || payload.Scope != "cluster" || len(payload.Nodes) != 2 {
		t.Fatalf("snapshot HTTP route lost cluster scope: status=%d payload=%#v error=%v", response.StatusCode, payload, err)
	}
	if len(payload.Logs) != 6 {
		t.Fatalf("HTTP snapshot lost firewall audit fields: %+v", payload.Logs)
	}
	var ruleScopes, observations int
	for _, record := range payload.Logs {
		if record.SourceCIDR != "" && record.SourceIP == "" {
			ruleScopes++
		}
		if record.SourceCIDR == "10.42.0.0/16" && record.Count == 4 && record.Drops == 0 {
			observations++
		}
	}
	if ruleScopes != 4 || observations != 2 {
		t.Fatalf("HTTP audit semantics lost: %+v", payload.Logs)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, manager.URL+"/events/cluster?section=events&node=b&iface=unrelated&direction=egress", nil)
	stream, err := manager.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	reader := bufio.NewReader(stream.Body)
	for {
		frame, err := readSSEFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(frame, "event: events") {
			if !strings.Contains(frame, `"scope":"cluster"`) || !strings.Contains(frame, `"node_id":"a"`) || !strings.Contains(frame, `"node_id":"b"`) {
				t.Fatalf("security query narrowed the event SSE frame: %s", frame)
			}
			break
		}
	}
}

func TestEventSnapshotPreservesFailedNodeHistoryAndRemovesDeletedNodes(t *testing.T) {
	state := store.New()
	var fail atomic.Bool
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/security/scan/reports":
			writeJSON(w, http.StatusOK, map[string]any{"reports": []any{map[string]any{"id": "scan-persisted", "status": "completed", "findings_count": 5}}})
		case "/security/scan":
			writeJSON(w, http.StatusOK, map[string]any{"status": "idle"})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"records": []any{}, "logs": []any{}})
		}
	}))
	defer agent.Close()
	state.UpsertNode(t.Context(), models.Node{ID: "a", AgentURL: agent.URL})
	h := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: http.DefaultClient}
	h.eventsStreamSnapshot(t.Context())
	expire := func() {
		h.pageSnapshotMu.Lock()
		cached := h.pageSnapshotCache["events:cluster"]
		cached.fetchedAt = time.Now().Add(-time.Minute)
		h.pageSnapshotCache["events:cluster"] = cached
		h.pageSnapshotMu.Unlock()
	}
	fail.Store(true)
	h.invalidateConsoleSnapshots()
	items := h.eventsStreamSnapshot(t.Context())["nodes"].([]eventNodeSnapshot)
	if len(items[0].Scans) != 1 || len(items[0].Errors) == 0 {
		t.Fatalf("temporary failure erased history or hid its error: %#v", items)
	}
	state.DeleteNode(context.Background(), "a")
	expire()
	if items = h.eventsStreamSnapshot(t.Context())["nodes"].([]eventNodeSnapshot); len(items) != 0 {
		t.Fatalf("deleted node reappeared: %#v", items)
	}
}

func TestScanSummaryOmitsFindingPayload(t *testing.T) {
	h := &AgentHandler{nodeID: "a", securityJob: &securityScanJob{ID: "scan-large", Status: "completed", Findings: make([]securityscan.Finding, 5000)}}
	response := httptest.NewRecorder()
	h.handleSecurityScanStatus(response, httptest.NewRequest(http.MethodGet, "/security/scan?summary=1", nil))
	var summary map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["findings_count"] != float64(5000) || strings.Contains(response.Body.String(), `"findings":`) || response.Body.Len() > 1024 {
		t.Fatalf("event summary includes heavy scan evidence: %s", response.Body)
	}
}
