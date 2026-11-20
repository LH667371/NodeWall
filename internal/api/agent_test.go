package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/store"
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

type bootDataplane struct {
	*xdp.MockManager
	attachErrors map[string]error
	attachCalls  map[string]int
}

func (m bootDataplane) Attach(iface string, mode xdp.AttachMode) error {
	if m.attachCalls != nil {
		m.attachCalls[iface]++
	}
	if err := m.attachErrors[iface]; err != nil {
		return err
	}
	return m.MockManager.Attach(iface, mode)
}

func (m bootDataplane) DiscoverInterfaces() (models.InterfaceInventory, error) {
	return models.InterfaceInventory{Interfaces: []models.DetectedInterface{
		{Name: "nw-test0", IsPhysical: true},
		{Name: "nw-test1", IsPhysical: true},
	}}, nil
}

func TestAgentBootKeepsPolicyWhenFirewallCannotAttach(t *testing.T) {
	state := store.NewFileStateStore(filepath.Join(t.TempDir(), "agent.json"))
	context := t.Context()
	desired := models.InterfaceRuntime{
		Attached: true, AttachMode: "generic", ObserveOnly: true,
		Allowlist: []string{"192.0.2.0/24"},
		TemporaryBlocks: []models.TemporaryBlock{
			{SourceIP: "192.0.2.8", ExpiresAt: time.Now().Add(-time.Minute)},
		},
	}
	if err := state.Save(context, map[string]models.InterfaceRuntime{"nw-test0": desired, "nw-test1": desired}); err != nil {
		t.Fatal(err)
	}
	agent := NewAgentHandler("node-01", bootDataplane{
		MockManager: xdp.NewMockManager(), attachErrors: map[string]error{"nw-test0": syscall.ENOSYS},
	}, state, time.Second, nil, nil)
	if err := agent.LoadState(context); !errors.Is(err, syscall.ENOSYS) {
		t.Fatalf("boot error = %v", err)
	}
	for _, route := range []string{"/health", "/interfaces"} {
		response := httptest.NewRecorder()
		agent.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s returned %d", route, response.Code)
		}
		if route == "/health" {
			var health models.HealthStatus
			err := json.Unmarshal(response.Body.Bytes(), &health)
			if err != nil || !health.AgentOK || health.Status != "degraded" {
				t.Fatalf("health: %v %s", err, response.Body)
			}
			for _, item := range health.Interfaces {
				if item.Interface == "nw-test0" && (item.XDPAttached || !strings.Contains(item.LastError, syscall.ENOSYS.Error())) {
					t.Fatalf("failed interface health: %+v", item)
				}
			}
		} else {
			var inventory models.InterfaceInventory
			if err := json.Unmarshal(response.Body.Bytes(), &inventory); err != nil || len(inventory.Interfaces) != 2 ||
				inventory.Interfaces[0].Attached || !inventory.Interfaces[1].Attached {
				t.Fatalf("inventory: %v %s", err, response.Body)
			}
		}
	}
	onDisk, err := state.Load(context)
	if err != nil || !onDisk["nw-test0"].Attached {
		t.Fatalf("saved attachment was lost: %v", err)
	}
	restarted := NewAgentHandler("node-01", bootDataplane{MockManager: xdp.NewMockManager()}, state, time.Second, nil, nil)
	if err := restarted.LoadState(context); err != nil {
		t.Fatal(err)
	}
	if runtime := restarted.ensureRuntime("nw-test0"); !runtime.Attached || len(runtime.Allowlist) != 1 || len(runtime.TemporaryBlocks) != 0 {
		t.Fatalf("restored interface: %+v", runtime)
	}
}

func TestAgentBootRestoresPolicyWhenInterfaceAppears(t *testing.T) {
	ctx := t.Context()
	state := store.NewFileStateStore(filepath.Join(t.TempDir(), "agent.json"))
	saved := models.InterfaceRuntime{
		Attached: true, AttachMode: "generic", EnforcementConfirmed: true,
		PublicPorts: []uint16{8080}, DeniedPorts: []uint16{18080},
	}
	trial := saved
	trial.PublicPorts = []uint16{8081}
	trial.Recovery = map[models.PolicyDirection]models.DirectionRuntime{
		models.DirectionIngress: directionStateFor(saved, models.DirectionIngress),
	}
	if err := state.Save(ctx, map[string]models.InterfaceRuntime{
		"nw-test0": trial, "nw-test1": saved, "nw-permission": saved, "nw-cancel": saved,
	}); err != nil {
		t.Fatal(err)
	}
	dataplane := bootDataplane{
		MockManager: xdp.NewMockManager(),
		attachErrors: map[string]error{
			"nw-test0": xdp.ErrInterfaceNotPresent, "nw-cancel": xdp.ErrInterfaceNotPresent,
			"nw-permission": syscall.EPERM,
		},
		attachCalls: map[string]int{},
	}
	agent := NewAgentHandler("node-01", dataplane, state, time.Second, nil, nil)
	if err := agent.LoadState(ctx); !errors.Is(err, xdp.ErrInterfaceNotPresent) || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("boot errors: %v", err)
	}
	if !agent.retryBootInterfaces(ctx) || !errors.Is(agent.interfaceRestoreError("nw-test0"), xdp.ErrInterfaceNotPresent) {
		t.Fatal("an absent interface must stay pending")
	}
	response := httptest.NewRecorder()
	agent.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/interfaces/nw-cancel/detach", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("detach pending interface: %d %s", response.Code, response.Body)
	}
	clear(dataplane.attachErrors)
	if agent.retryBootInterfaces(ctx) {
		t.Fatal("recovery kept retrying after the interface was restored")
	}
	if got := dataplane.attachCalls; got["nw-test0"] != 3 || got["nw-test1"] != 1 || got["nw-permission"] != 1 || got["nw-cancel"] != 2 {
		t.Fatalf("attach attempts: %v", got)
	}
	if err := agent.interfaceRestoreError("nw-test0"); err != nil {
		t.Fatalf("restored interface is still degraded: %v", err)
	}
	if err := agent.interfaceRestoreError("nw-permission"); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("permission failure was lost: %v", err)
	}
	config, err := dataplane.ReadConfig("nw-test0")
	if err != nil || !config.PolicyEnforced || config.ObserveOnly {
		t.Fatalf("restored enforcement: %+v (%v)", config, err)
	}
	public, err := dataplane.ListPublicPortRules("nw-test0")
	ports := models.CollapsePortRules(public)
	if err != nil || len(ports) != 1 || ports[0] != 8080 {
		t.Fatalf("restored the wrong policy after an interrupted trial: %v (%v)", public, err)
	}
	onDisk, err := state.Load(ctx)
	if err != nil || onDisk["nw-cancel"].Attached || !onDisk["nw-test0"].Attached || len(onDisk["nw-test0"].Recovery) != 0 {
		t.Fatalf("wrong persisted recovery state: %+v (%v)", onDisk, err)
	}
}

func TestMaintenanceUpdateStartsConfiguredCallback(t *testing.T) {
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	var calls atomic.Int32
	done := make(chan struct{})
	handler.SetMaintenanceUpdateFunc(func(context.Context) error {
		calls.Add(1)
		close(done)
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/maintenance/update", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("maintenance update callback was not started")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one update callback, got %d", calls.Load())
	}
}

func TestMaintenanceUpdateUsesRequestManagerURLDuringPortMigration(t *testing.T) {
	handler := NewAgentHandler("node-01", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	managerURL := make(chan string, 1)
	done := make(chan struct{})
	handler.SetMaintenanceUpdateTargetFunc(func(_ context.Context, target string) error {
		managerURL <- target
		close(done)
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/maintenance/update", strings.NewReader(`{"manager_url":"https://192.168.201.17:8086"}`))
	rec := httptest.NewRecorder()
	handler.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("target update callback was not started")
	}
	select {
	case got := <-managerURL:
		if got != "https://192.168.201.17:8086" {
			t.Fatalf("manager URL = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("target manager URL was not received")
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
