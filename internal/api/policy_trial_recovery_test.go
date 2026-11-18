package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/rollback"
	"nodewall/internal/service"
	"nodewall/internal/store"
	"nodewall/internal/xdp"
)

// The real dataplane cannot write TC maps before XDP attach or after detach.
// The ordinary mock accepts both, hiding first-install and rollback failures.
type attachedDirectionDataplane struct{ *xdp.MockManager }

func (d attachedDirectionDataplane) Attach(iface string, mode xdp.AttachMode) error {
	if runtime, err := d.Runtime(iface); err == nil && runtime.Attached {
		return nil
	}
	return d.MockManager.Attach(iface, mode)
}

func (d attachedDirectionDataplane) ApplyDirectionPolicy(iface string, direction models.PolicyDirection, policy xdp.DirectionPolicy) error {
	runtime, err := d.Runtime(iface)
	if err != nil {
		return err
	}
	if !runtime.Attached {
		return errors.New("xdp program not attached")
	}
	return d.MockManager.ApplyDirectionPolicy(iface, direction, policy)
}

func TestPolicyTrialFromUnattachedInterfaceCanBeRepeated(t *testing.T) {
	dataplane := attachedDirectionDataplane{xdp.NewMockManager()}
	agent := NewAgentHandler("node-a", dataplane, memoryStateStore{}, time.Minute, nil, nil)
	server := httptest.NewServer(agent.Routes())
	defer server.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: server.URL})
	svc := service.NewPolicyService(state)
	policy := models.InterfacePolicy{
		NodeID: "node-a", Interface: "nw-test0",
		Ingress: models.DirectionPolicy{Enabled: true, Mode: "whitelist", PublicPorts: []uint16{22}},
		Egress:  models.DefaultDirectionPolicy(models.DirectionEgress),
	}
	for attempt := range 2 {
		if _, _, err := svc.BeginPolicyTrial(t.Context(), policy, time.Second); err != nil {
			t.Fatalf("trial %d: %v", attempt+1, err)
		}
		if attempt == 0 {
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				agent.policyMu.Lock()
				runtime := agent.ensureRuntime(policy.Interface)
				agent.policyMu.Unlock()
				if !runtime.Attached && len(runtime.Recovery) == 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := svc.RecoverPendingPolicies(t.Context()); err != nil {
				t.Fatal(err)
			}
		} else if err := svc.RollbackPolicyTrial(t.Context(), policy.NodeID, policy.Interface); err != nil {
			t.Fatal(err)
		}
		runtime := agent.ensureRuntime(policy.Interface)
		actual, _ := dataplane.Runtime(policy.Interface)
		if runtime.Attached || runtime.Egress.Attached || actual.Attached || len(runtime.Recovery) != 0 {
			t.Fatalf("trial %d did not restore the detached baseline: runtime=%#v actual=%#v", attempt+1, runtime, actual)
		}
	}
}

func TestRestoreEgressAfterIngressDetachClearsRecovery(t *testing.T) {
	dataplane := attachedDirectionDataplane{xdp.NewMockManager()}
	agent := NewAgentHandler("node-a", dataplane, memoryStateStore{}, time.Minute, nil, nil)
	runtime := newInterfaceRuntime("nw-test0")
	runtime.Recovery = map[models.PolicyDirection]models.DirectionRuntime{
		models.DirectionEgress: {Attached: true, ObserveOnly: true},
	}
	agent.setRuntime(runtime.Interface, runtime)
	if err := agent.restoreSnapshot(t.Context(), rollback.Snapshot{
		Interface: runtime.Interface, Direction: models.DirectionEgress, Attached: true, ObserveOnly: true,
	}); err != nil {
		t.Fatal(err)
	}
	runtime = agent.ensureRuntime(runtime.Interface)
	if runtime.Egress.Attached || len(runtime.Recovery) != 0 {
		t.Fatalf("detached maps left a stale verification lock: %#v", runtime)
	}
}

func TestPolicyTrialPreservesExistingNativeAndGenericAttachments(t *testing.T) {
	for _, mode := range []xdp.AttachMode{xdp.AttachModeNative, xdp.AttachModeGeneric} {
		t.Run(string(mode), func(t *testing.T) {
			dataplane := attachedDirectionDataplane{xdp.NewMockManager()}
			agent := NewAgentHandler("node-a", dataplane, memoryStateStore{}, time.Minute, nil, nil)
			server := httptest.NewServer(agent.Routes())
			defer server.Close()
			attach := httptest.NewRecorder()
			agent.Routes().ServeHTTP(attach, httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/attach", strings.NewReader(`{"mode":"`+string(mode)+`"}`)))
			if attach.Code != http.StatusOK {
				t.Fatal(attach.Body.String())
			}
			state := store.New()
			state.UpsertNode(t.Context(), models.Node{ID: "node-a", AgentURL: server.URL})
			svc := service.NewPolicyService(state)
			before := models.InterfacePolicy{NodeID: "node-a", Interface: "nw-test0", Ingress: models.DirectionPolicy{Enabled: true, Mode: "whitelist", PublicPorts: []uint16{22}}}
			if _, err := svc.UpdatePolicyAndApply(t.Context(), before); err != nil {
				t.Fatal(err)
			}
			trial := before
			trial.Ingress.DeniedPorts = []uint16{8443}
			if _, _, err := svc.BeginPolicyTrial(t.Context(), trial, time.Minute); err != nil {
				t.Fatal(err)
			}
			if err := svc.RollbackPolicyTrial(t.Context(), "node-a", "nw-test0"); err != nil {
				t.Fatal(err)
			}
			actual, err := dataplane.Runtime("nw-test0")
			if err != nil || !actual.Attached || actual.Mode != mode || len(actual.DeniedPorts) != 0 || len(actual.PublicPorts) != 1 || actual.PublicPorts[0] != 22 {
				t.Fatalf("rollback lost the pre-existing attachment or policy: %+v %v", actual, err)
			}
			if runtime := agent.ensureRuntime("nw-test0"); len(runtime.Recovery) != 0 || !runtime.Attached {
				t.Fatalf("stale recovery after rollback: %+v", runtime)
			}
		})
	}
}

func TestFailedUnattachedEgressApplyDoesNotLeaveVerificationLock(t *testing.T) {
	dataplane := attachedDirectionDataplane{xdp.NewMockManager()}
	agent := NewAgentHandler("node-a", dataplane, memoryStateStore{}, time.Minute, nil, nil)
	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/apply", strings.NewReader(`{"immediate":true,"publish_id":"unattached","safety_timeout":1,"direction":"egress"}`))
		rec := httptest.NewRecorder()
		agent.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected actionable attach failure, got %d: %s", rec.Code, rec.Body.String())
		}
		if len(agent.ensureRuntime("nw-test0").Recovery) != 0 {
			t.Fatal("failed apply left a permanent verification lock")
		}
		if _, pending := agent.rollback.Pending("unattached"); pending {
			t.Fatal("successfully restored failure retained its rollback session")
		}
	}
}

type failingRecoveryStore struct {
	memoryStateStore
	fail bool
}

func (s *failingRecoveryStore) Save(ctx context.Context, runtimes map[string]models.InterfaceRuntime) error {
	if s.fail {
		return errors.New("state disk unavailable")
	}
	return s.memoryStateStore.Save(ctx, runtimes)
}

func TestRecoveryPersistenceFailureRetainsVerificationSnapshot(t *testing.T) {
	state := &failingRecoveryStore{fail: true}
	agent := NewAgentHandler("node-a", attachedDirectionDataplane{xdp.NewMockManager()}, state, time.Minute, nil, nil)
	runtime := newInterfaceRuntime("nw-test0")
	runtime.Recovery = map[models.PolicyDirection]models.DirectionRuntime{models.DirectionEgress: runtime.Egress}
	agent.setRuntime(runtime.Interface, runtime)
	snapshot := rollback.Snapshot{Interface: runtime.Interface, Direction: models.DirectionEgress, ObserveOnly: true}
	if err := agent.restoreSnapshot(t.Context(), snapshot); err == nil {
		t.Fatal("persistence failure was ignored")
	}
	if len(agent.ensureRuntime(runtime.Interface).Recovery) == 0 {
		t.Fatal("persistence failure discarded the only durable recovery marker")
	}
	state.fail = false
	if err := agent.restoreSnapshot(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	if len(agent.ensureRuntime(runtime.Interface).Recovery) != 0 {
		t.Fatal("retry did not finish recovery")
	}
}

type failingDirectionDataplane struct {
	attachedDirectionDataplane
	fail atomic.Bool
}

func (d *failingDirectionDataplane) ApplyDirectionPolicy(iface string, direction models.PolicyDirection, policy xdp.DirectionPolicy) error {
	if d.fail.Load() {
		return errors.New("temporary TC update failure")
	}
	return d.attachedDirectionDataplane.ApplyDirectionPolicy(iface, direction, policy)
}

func TestApplyAndRestoreFailureRetainsSessionUntilAutomaticRetry(t *testing.T) {
	dataplane := &failingDirectionDataplane{attachedDirectionDataplane: attachedDirectionDataplane{xdp.NewMockManager()}}
	agent := NewAgentHandler("node-a", dataplane, memoryStateStore{}, time.Minute, nil, nil)
	request := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		agent.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/apply", strings.NewReader(body)))
		return rec
	}
	attached := httptest.NewRecorder()
	agent.Routes().ServeHTTP(attached, httptest.NewRequest(http.MethodPost, "/interfaces/nw-test0/attach", strings.NewReader(`{"mode":"generic"}`)))
	if attached.Code != http.StatusOK {
		t.Fatal(attached.Body.String())
	}
	dataplane.fail.Store(true)
	if rec := request(`{"direction":"egress","immediate":true,"publish_id":"failed-recovery","safety_timeout":30}`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("restore failure not reported: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := agent.rollback.Pending("failed-recovery"); !ok {
		t.Fatal("failed apply canceled its only recovery timer")
	}
	if rec := request(`{"direction":"egress","immediate":true}`); rec.Code != http.StatusConflict {
		t.Fatalf("pending recovery was overwritten: %d %s", rec.Code, rec.Body.String())
	}
	dataplane.fail.Store(false)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		agent.policyMu.Lock()
		pending := len(agent.ensureRuntime("nw-test0").Recovery) > 0
		agent.policyMu.Unlock()
		if !pending {
			if rec := request(`{"direction":"egress","immediate":true}`); rec.Code != http.StatusOK {
				t.Fatalf("retry left a stale verification lock: %d %s", rec.Code, rec.Body.String())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("failed apply did not automatically retry recovery")
}
