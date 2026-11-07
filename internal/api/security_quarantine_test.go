package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodewall/internal/xdp"
)

func TestQuarantineEntriesCanBeListedAndDeleted(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	path := filepath.Join(securityQuarantineRoot, "scan-1", "f-test-payload.sh")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(quarantineMetadataPath(path), marshalQuarantineMetadata(quarantineMetadata{
		OriginalPath: "/srv/uploads/f-test-payload.sh",
		Restorable:   true,
		ScanID:       "scan-1",
		FindingID:    "f-test-payload",
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	h := NewAgentHandler("node-a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	routes := h.Routes()
	response := httptest.NewRecorder()
	routes.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/security/quarantine", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("list returned %d: %s", response.Code, response.Body.String())
	}
	var listed struct {
		Entries []quarantineEntry `json:"entries"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Entries) != 1 || listed.Entries[0].RelativePath != "scan-1/f-test-payload.sh" {
		t.Fatalf("unexpected entries: %#v", listed.Entries)
	}
	if listed.Entries[0].OriginalPath != "/srv/uploads/f-test-payload.sh" || !listed.Entries[0].Restorable {
		t.Fatalf("original path was not retained: %#v", listed.Entries[0])
	}

	entryID := listed.Entries[0].ID
	response = httptest.NewRecorder()
	routes.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/security/quarantine/"+entryID, nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("delete without confirmation returned %d", response.Code)
	}

	response = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/security/quarantine/"+entryID, strings.NewReader(`{"confirm":"DELETE_QUARANTINE"}`))
	routes.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("delete returned %d: %s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("quarantine file still exists: %v", err)
	}
	if _, err := os.Stat(quarantineMetadataPath(path)); !os.IsNotExist(err) {
		t.Fatalf("quarantine metadata still exists: %v", err)
	}
}

func TestQuarantineEntryCanBeRestoredToOriginalPath(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	originalDir := t.TempDir()
	originalPath := filepath.Join(originalDir, "payload.sh")
	path := filepath.Join(securityQuarantineRoot, "scan-restore", "f-restore-payload.sh")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(quarantineMetadataPath(path), marshalQuarantineMetadata(quarantineMetadata{
		OriginalPath: originalPath,
		Restorable:   true,
		ScanID:       "scan-restore",
		FindingID:    "f-restore",
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	h := NewAgentHandler("node-restore", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	routes := h.Routes()
	response := httptest.NewRecorder()
	routes.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/security/quarantine", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("list returned %d: %s", response.Code, response.Body.String())
	}
	var listed struct {
		Entries []quarantineEntry `json:"entries"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Entries) != 1 || listed.Entries[0].OriginalPath != originalPath || listed.Entries[0].QuarantinePath != path {
		t.Fatalf("unexpected restore metadata: %#v", listed.Entries)
	}

	entryID := listed.Entries[0].ID
	request := httptest.NewRequest(http.MethodPost, "/security/quarantine/"+entryID+"/restore", strings.NewReader(`{"confirm":"RESTORE_QUARANTINE"}`))
	response = httptest.NewRecorder()
	routes.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("restore returned %d: %s", response.Code, response.Body.String())
	}
	if payload, err := os.ReadFile(originalPath); err != nil || string(payload) != "evidence" {
		t.Fatalf("restored file mismatch: %v %q", err, payload)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("quarantine file still exists after restore: %v", err)
	}
	if _, err := os.Stat(quarantineMetadataPath(path)); !os.IsNotExist(err) {
		t.Fatalf("quarantine metadata still exists after restore: %v", err)
	}
}
