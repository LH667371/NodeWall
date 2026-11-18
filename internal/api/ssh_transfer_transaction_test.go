package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/security"
	"nodewall/internal/sshpolicy"
	"nodewall/internal/store"
	"nodewall/internal/xdp"
)

type failingSSHSettings struct{}

func (failingSSHSettings) Load(context.Context) (models.SSHProtectionSettings, error) {
	return models.SSHProtectionSettings{}, nil
}
func (failingSSHSettings) Save(context.Context, models.SSHProtectionSettings) error {
	return errors.New("simulated storage failure")
}

type recordingSSHApplier struct{ policies []models.SSHTransferPolicy }

func (a *recordingSSHApplier) Apply(_ context.Context, p models.SSHTransferPolicy) error {
	a.policies = append(a.policies, p)
	return nil
}

func TestSSHTransferPersistenceFailureRestoresEffectivePolicy(t *testing.T) {
	applier := &recordingSSHApplier{}
	h := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil, SSHProtectionOptions{StateStore: failingSSHSettings{}, TransferPolicyApplier: applier})
	previous := h.sshProtectionSettings.Transfer
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/ssh-protection/transfer", strings.NewReader(`{"scan_uploads":true,"audit_commands":true}`)))
	if response.Code != 500 || len(applier.policies) != 2 || !applier.policies[0].ScanUploads || !reflect.DeepEqual(applier.policies[1], previous) || !reflect.DeepEqual(h.sshProtectionSettings.Transfer, previous) {
		t.Fatalf("SSH policy diverged after failed save: %d %#v", response.Code, applier.policies)
	}
}

func TestSSHTransferSaveUsesAuthorizedSessionWithoutPassword(t *testing.T) {
	agent := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil, SSHProtectionOptions{TransferPolicyApplier: &recordingSSHApplier{}}).Routes()
	var writes atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			writes.Add(1)
		}
		agent.ServeHTTP(w, r)
	}))
	defer peer.Close()
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "a", AgentURL: peer.URL, LastSeenAt: time.Now()})
	h := newConsoleSyncHandler(t, state, "a")
	h.auth.enabled = true
	h.auth.sessions = map[string]sessionState{
		"operator": {Role: security.RoleOperator, CSRFToken: "operator-token"},
		"viewer":   {Role: security.RoleViewer, CSRFToken: "viewer-token"},
	}
	routes := h.Routes()
	call := func(method, suffix, role, csrf, etag, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/nodes/a/ssh-protection"+suffix, strings.NewReader(body))
		if role != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: role})
		}
		r.Header.Set("X-NodeWall-CSRF", csrf)
		r.Header.Set("If-Match", etag)
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, r)
		return response
	}

	const policy = `{"block_scp":true,"scan_uploads":true}`
	for _, test := range []struct {
		name, role, csrf, etag string
		status                 int
	}{
		{name: "anonymous", status: http.StatusUnauthorized},
		{name: "viewer", role: "viewer", csrf: "viewer-token", status: http.StatusForbidden},
		{name: "missing CSRF", role: "operator", status: http.StatusForbidden},
		{name: "stale revision", role: "operator", csrf: "operator-token", etag: `"stale"`, status: http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := call(http.MethodPut, "/transfer", test.role, test.csrf, test.etag, policy)
			if response.Code != test.status || writes.Load() != 0 {
				t.Fatalf("transfer guard allowed an invalid write: %d %s", response.Code, response.Body.String())
			}
		})
	}

	initial := call(http.MethodGet, "", "operator", "", "", "")
	etag := initial.Header().Get("ETag")
	if initial.Code != http.StatusOK || etag == "" {
		t.Fatalf("initial settings are unavailable: %d %s", initial.Code, initial.Body.String())
	}
	saved := call(http.MethodPut, "/transfer", "operator", "operator-token", etag, policy)
	var result models.SSHProtectionStatus
	if err := json.Unmarshal(saved.Body.Bytes(), &result); saved.Code != http.StatusOK || err != nil || writes.Load() != 1 || !result.TransferEffective || !result.Settings.Transfer.BlockSCP || !result.Settings.Transfer.ScanUploads || saved.Header().Get("ETag") == etag {
		t.Fatalf("transfer did not reach the Agent with a new revision: %d %s", saved.Code, saved.Body.String())
	}
	login := call(http.MethodPut, "/authentication", "operator", "operator-token", "", `{"allow_password_login":true}`)
	if login.Code != http.StatusUnauthorized || writes.Load() != 1 {
		t.Fatalf("changing SSH authentication lost its password confirmation: %d %s", login.Code, login.Body.String())
	}
}

func TestSSHReconcileOnlyTouchesPreviouslyEnabledControls(t *testing.T) {
	applier := &recordingSSHApplier{}
	h := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil, SSHProtectionOptions{TransferPolicyApplier: applier})
	if err := h.ReconcileSSHTransferPolicy(context.Background()); err != nil || len(applier.policies) != 0 {
		t.Fatal("clean installation changed sshd")
	}
	h.sshProtectionSettings.Transfer.AuditCommands = true
	if err := h.ReconcileSSHTransferPolicy(context.Background()); err != nil || len(applier.policies) != 1 || !h.sshTransferApplied {
		t.Fatal("previously enabled hook was not upgraded")
	}
}

func TestSSHWrapperAndAPIUseConfiguredJournalPath(t *testing.T) {
	path := t.TempDir() + "/custom-activity.log"
	h := NewAgentHandler("a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil, SSHProtectionOptions{ActivityLogPath: path})
	applier, ok := h.sshTransferApplier.(*sshpolicy.Applier)
	if !ok || applier.ActivityLogPath != h.sshActivityLogPath || applier.ActivityLogPath != path {
		t.Fatal("SSH helper journal and console log source diverged")
	}
}
