package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/sshpolicy"
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
