package api

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
)

func TestScanEventsProxyFlushesBeforeAgentCloses(t *testing.T) {
	next := make(chan struct{})
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: scan\ndata: {\"status\":\"running\"}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-next:
		case <-r.Context().Done():
			return
		}
		_, _ = fmt.Fprint(w, "event: scan\ndata: {\"status\":\"completed\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer agent.Close()
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a", AgentURL: agent.URL})
	h := &ServerHandler{store: state, service: service.NewPolicyService(state), reverseHTTP: &http.Client{Timeout: 50 * time.Millisecond}}
	manager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("node", "node-a")
		h.handleProxySecurityScanEvents(w, r)
	}))
	defer manager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, manager.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	readEvent := func() string {
		t.Helper()
		var lines strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("stream ended before event: %v", err)
			}
			lines.WriteString(line)
			if line == "\n" {
				return lines.String()
			}
		}
	}
	if got := readEvent(); !strings.Contains(got, "running") {
		t.Fatalf("initial event = %q", got)
	}
	// The manager's ordinary 50 ms request deadline must not end an event stream.
	time.Sleep(150 * time.Millisecond)
	close(next)
	if got := readEvent(); !strings.Contains(got, "completed") {
		t.Fatalf("terminal event = %q", got)
	}
}

func TestSlowScanSubscriberReceivesLatestTerminalStatus(t *testing.T) {
	ch := make(chan securityScanView, 1)
	h := &AgentHandler{nodeID: "node-a", securityJob: &securityScanJob{ID: "scan-test", Status: "running"}, securityScanSubscribers: map[chan securityScanView]struct{}{ch: {}}}
	h.publishSecurityScan("scan-test")
	h.securityJob.Status = "completed"
	h.publishSecurityScan("scan-test")
	view := <-ch
	if view.Status != "completed" || view.NodeID != "node-a" {
		t.Fatalf("slow subscriber received %#v", view)
	}
}
