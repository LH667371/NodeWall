package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/xdp"
)

type memoryStateStore struct{}

// Mock scenarios use nw-test0 instead of depending on whether the host's eth0
// is a physical NIC or a container veth. No test attaches a real interface.

func (memoryStateStore) Save(context.Context, map[string]models.InterfaceRuntime) error {
	return nil
}

func (memoryStateStore) Load(context.Context) (map[string]models.InterfaceRuntime, error) {
	return map[string]models.InterfaceRuntime{}, nil
}

func TestHealthEndpoint(t *testing.T) {
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rec.Code)
	}
}

func TestConfirmMissingPublish(t *testing.T) {
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/confirm", strings.NewReader(`{"publish_id":"missing"}`))
	rec := httptest.NewRecorder()

	handler.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unexpected status code: %d", rec.Code)
	}
}

func TestAttachAndAllowlistWithMockDataplane(t *testing.T) {
	dataplane := xdp.NewMockManager()
	handler := NewAgentHandler("node-01", dataplane, memoryStateStore{}, time.Second, nil, nil)

	attachReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/attach", strings.NewReader(`{"mode":"native"}`))
	attachRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(attachRec, attachReq)
	if attachRec.Code != http.StatusOK {
		t.Fatalf("unexpected attach status: %d", attachRec.Code)
	}

	allowReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/allowlist", strings.NewReader(`{"cidr":"10.0.0.0/8"}`))
	allowRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(allowRec, allowReq)
	if allowRec.Code != http.StatusOK {
		t.Fatalf("unexpected allowlist status: %d", allowRec.Code)
	}

	cfg, err := dataplane.ReadConfig("nw-test0")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !cfg.PolicyEnforced {
		t.Fatal("expected direct allowlist update to enable policy enforcement")
	}
	if !cfg.ObserveOnly {
		t.Fatal("a newly attached interface must remain observe-only until an explicit baseline publish")
	}
}

func TestNewInterfaceRuntimeDefaultsToObserveOnly(t *testing.T) {
	runtime := newInterfaceRuntime("nw-test0")
	if !runtime.ObserveOnly || runtime.EnforcementConfirmed {
		t.Fatalf("unexpected new interface safety state: %#v", runtime)
	}
}

func TestDirectRuleDeletesDisablePolicyEnforcement(t *testing.T) {
	dataplane := xdp.NewMockManager()
	handler := NewAgentHandler("node-01", dataplane, memoryStateStore{}, time.Second, nil, nil)

	attachReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/attach", strings.NewReader(`{"mode":"generic"}`))
	attachRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(attachRec, attachReq)
	if attachRec.Code != http.StatusOK {
		t.Fatalf("unexpected attach status: %d", attachRec.Code)
	}

	addReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/block", strings.NewReader(`{"cidr":"203.0.113.7/32"}`))
	addRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(addRec, addReq)
	if addRec.Code != http.StatusOK {
		t.Fatalf("unexpected block status: %d body=%s", addRec.Code, addRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/interfaces/nw-test0/block/203.0.113.7%2F32", nil)
	deleteRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("unexpected delete status: %d body=%s", deleteRec.Code, deleteRec.Body.String())
	}

	cfg, err := dataplane.ReadConfig("nw-test0")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if cfg.PolicyEnforced {
		t.Fatal("expected deleting the last direct rule to disable policy enforcement")
	}
}

func TestRateLimitAndTemporaryBlockEnableDataplaneProtection(t *testing.T) {
	dataplane := xdp.NewMockManager()
	handler := NewAgentHandler("node-01", dataplane, memoryStateStore{}, time.Second, nil, nil)

	attachReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/attach", strings.NewReader(`{"mode":"generic"}`))
	attachRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(attachRec, attachReq)
	if attachRec.Code != http.StatusOK {
		t.Fatalf("unexpected attach status: %d", attachRec.Code)
	}

	rateReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/rate-limits", strings.NewReader(`{"source_ip":"203.0.113.7","protocol":"tcp","port":443,"requests_per_minute":60,"burst":2}`))
	rateRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(rateRec, rateReq)
	if rateRec.Code != http.StatusOK {
		t.Fatalf("unexpected rate limit status: %d body=%s", rateRec.Code, rateRec.Body.String())
	}
	cfg, err := dataplane.ReadConfig("nw-test0")
	if err != nil {
		t.Fatalf("read config after rate limit: %v", err)
	}
	if !cfg.RateLimitEnabled {
		t.Fatal("expected rate limit enforcement to be enabled")
	}

	blockReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/temporary-blocks", strings.NewReader(`{"source_ip":"198.51.100.8","duration_minutes":1}`))
	blockRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(blockRec, blockReq)
	if blockRec.Code != http.StatusOK {
		t.Fatalf("unexpected temporary block status: %d body=%s", blockRec.Code, blockRec.Body.String())
	}
	cfg, err = dataplane.ReadConfig("nw-test0")
	if err != nil {
		t.Fatalf("read config after temporary block: %v", err)
	}
	if !cfg.PolicyEnforced {
		t.Fatal("expected temporary block to enable policy enforcement")
	}
}

func TestPublishUsesRequestedConfirmTimeout(t *testing.T) {
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, 180*time.Second, nil, nil)

	attachReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/attach", strings.NewReader(`{"mode":"generic"}`))
	attachRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(attachRec, attachReq)
	if attachRec.Code != http.StatusOK {
		t.Fatalf("unexpected attach status: %d", attachRec.Code)
	}

	publishReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/publish", strings.NewReader(`{"publish_id":"timeout-test","allowlist":["10.0.0.0/8"],"confirm_timeout":7}`))
	publishRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(publishRec, publishReq)
	if publishRec.Code != http.StatusOK {
		t.Fatalf("unexpected publish status: %d body=%s", publishRec.Code, publishRec.Body.String())
	}
	if !strings.Contains(publishRec.Body.String(), `"expires_in":7`) {
		t.Fatalf("expected requested timeout in response, got %s", publishRec.Body.String())
	}

	confirmReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/confirm", strings.NewReader(`{"publish_id":"timeout-test"}`))
	confirmRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(confirmRec, confirmReq)
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("unexpected confirm status: %d body=%s", confirmRec.Code, confirmRec.Body.String())
	}
}

func TestHealthReportsPersistedAttachWithoutDataplane(t *testing.T) {
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	handler.runtimes["nw-test0"] = models.InterfaceRuntime{Interface: "nw-test0", Attached: true}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected health status: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"degraded"`) {
		t.Fatalf("expected degraded health, got %s", rec.Body.String())
	}
}

func TestListInterfacesWithMockDataplane(t *testing.T) {
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/interfaces", nil)
	rec := httptest.NewRecorder()

	handler.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rec.Code)
	}
	var payload models.InterfaceInventory
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	if len(payload.Interfaces) == 0 {
		t.Fatal("expected at least one interface")
	}
	for _, item := range payload.Interfaces {
		if item.Egress.Attached {
			t.Fatalf("unattached interface %s was reported with active egress tracker", item.Name)
		}
	}
}

func TestInsightsWithMockDataplane(t *testing.T) {
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	attachReq := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/attach", strings.NewReader(`{"mode":"native"}`))
	attachRec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(attachRec, attachReq)

	req := httptest.NewRequest(http.MethodGet, "/interfaces/nw-test0/insights", nil)
	rec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rec.Code)
	}
}

func TestDefaultActionDeniesIPv6WhenUnset(t *testing.T) {
	if got := defaultAction(""); got != models.NonIPv4Drop {
		t.Fatalf("expected unset IPv6 policy to default to drop, got %q", got)
	}
	if got := defaultAction(models.NonIPv4Pass); got != models.NonIPv4Pass {
		t.Fatalf("expected explicit IPv6 allow to be preserved, got %q", got)
	}
}
