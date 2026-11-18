package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
)

func TestEventDispositionAPIIsSharedAndIdempotent(t *testing.T) {
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a", AgentURL: "http://127.0.0.1:1"})
	h, err := NewServerHandler(config.ServerConfig{AuthEnabled: false, TLSEnabled: false}, service.NewPolicyService(state), state)
	if err != nil {
		t.Fatal(err)
	}

	put := func(status string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/events/dispositions/firewall-node-a-1", strings.NewReader(`{"node_id":"node-a","source":"firewall","status":"`+status+`"}`))
		response := httptest.NewRecorder()
		h.handleEventDispositions(response, req)
		return response
	}
	if response := put("handled"); response.Code != http.StatusOK {
		t.Fatalf("first update returned %d: %s", response.Code, response.Body.String())
	}
	if response := put("handled"); response.Code != http.StatusOK {
		t.Fatalf("retry update returned %d: %s", response.Code, response.Body.String())
	}
	get := httptest.NewRecorder()
	h.handleEventDispositions(get, httptest.NewRequest(http.MethodGet, "/events/dispositions", nil))
	var payload struct {
		Dispositions []models.EventDisposition `json:"dispositions"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if get.Code != http.StatusOK || len(payload.Dispositions) != 1 || payload.Dispositions[0].Status != models.EventDispositionHandled {
		t.Fatalf("unexpected dispositions: %d %+v", get.Code, payload)
	}

	invalid := put("unknown")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid status returned %d", invalid.Code)
	}
	unknownNode := httptest.NewRequest(http.MethodPut, "/events/dispositions/firewall-node-b-1", strings.NewReader(`{"node_id":"node-b","source":"firewall","status":"handled"}`))
	unknownResponse := httptest.NewRecorder()
	h.handleEventDispositions(unknownResponse, unknownNode)
	if unknownResponse.Code != http.StatusNotFound {
		t.Fatalf("unknown node returned %d", unknownResponse.Code)
	}

	if response := put("open"); response.Code != http.StatusOK {
		t.Fatalf("clearing update returned %d: %s", response.Code, response.Body.String())
	}
	get = httptest.NewRecorder()
	h.handleEventDispositions(get, httptest.NewRequest(http.MethodGet, "/events/dispositions?node_id=node-a", nil))
	payload = struct {
		Dispositions []models.EventDisposition `json:"dispositions"`
	}{}
	if err := json.Unmarshal(get.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Dispositions) != 0 {
		t.Fatalf("open did not clear disposition: %+v", payload.Dispositions)
	}
}

func TestConcurrentEventDispositionWritesKeepOneAuthoritativeRecord(t *testing.T) {
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a"})
	h := &ServerHandler{store: state, service: service.NewPolicyService(state)}
	statuses := []string{"handled", "deferred"}
	var group sync.WaitGroup
	for index := 0; index < 32; index++ {
		status := statuses[index%len(statuses)]
		group.Add(1)
		go func() {
			defer group.Done()
			request := httptest.NewRequest(http.MethodPut, "/events/dispositions/firewall-node-a-concurrent", strings.NewReader(`{"node_id":"node-a","source":"firewall","status":"`+status+`"}`))
			response := httptest.NewRecorder()
			h.handleEventDispositions(response, request)
			if response.Code != http.StatusOK {
				t.Errorf("concurrent update returned %d: %s", response.Code, response.Body.String())
			}
		}()
	}
	group.Wait()

	items := state.ListEventDispositions(context.Background(), "node-a")
	if len(items) != 1 || (items[0].Status != models.EventDispositionHandled && items[0].Status != models.EventDispositionDeferred) {
		t.Fatalf("concurrent writes produced inconsistent state: %+v", items)
	}
}
