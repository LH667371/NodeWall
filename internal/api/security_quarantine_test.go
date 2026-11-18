package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"nodewall/internal/securityscan"
	"nodewall/internal/xdp"
)

func TestManualStartupFindingAllowsVendorUnitAndRelatedPayload(t *testing.T) {
	unit := securityscan.Finding{
		Source:   "file",
		Path:     "/lib/systemd/system/5ddf18af.service",
		Rule:     "malware-persistence",
		Severity: securityscan.SeverityHigh,
	}
	if !isManualStartupFinding(unit) {
		t.Fatal("high-confidence vendor systemd unit must be manually quarantinable")
	}
	payload := securityscan.Finding{
		Source:    "file",
		Path:      "/usr/bin/5ddf18af1006a658",
		Rule:      "startup-payload",
		Severity:  securityscan.SeverityHigh,
		RelatedTo: "f-unit",
	}
	if !isManualStartupFinding(payload) {
		t.Fatal("startup payload linked to a suspicious unit must be manually quarantinable")
	}
	ordinary := payload
	ordinary.RelatedTo = ""
	if isManualStartupFinding(ordinary) {
		t.Fatal("unlinked system executable must remain outside the manual startup bypass")
	}
}

func TestSameStartupChainFindingJoinsDuplicateUnitCopiesByHash(t *testing.T) {
	parent := securityscan.Finding{
		ID: "f-parent", Source: "file", Path: "/lib/systemd/system/8a6589cd.service",
		Rule: "malware-persistence", Severity: securityscan.SeverityHigh,
		SHA256: "deadbeef",
	}
	duplicate := parent
	duplicate.ID = "f-duplicate"
	duplicate.Path = "/usr/lib/systemd/system/8a6589cd.service"
	if !sameStartupChainFinding(parent, duplicate) {
		t.Fatal("same-hash unit copies should be handled as one startup chain")
	}
	differentContent := duplicate
	differentContent.SHA256 = "different"
	if sameStartupChainFinding(parent, differentContent) {
		t.Fatal("different unit content must not be quarantined by name alone")
	}
	payload := securityscan.Finding{ID: "f-payload", Source: "file", Path: "/usr/bin/8a6589cd3942efe0", RelatedTo: parent.ID}
	if !sameStartupChainFinding(parent, payload) {
		t.Fatal("directly related startup payload should remain in the chain")
	}
}

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

func TestQuarantineEntriesSortByQuarantinedAtDescending(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	olderQuarantine := time.Now().UTC().Add(-2 * time.Hour)
	newerQuarantine := olderQuarantine.Add(time.Hour)
	write := func(scanID, name string, quarantinedAt, modifiedAt time.Time) string {
		path := filepath.Join(securityQuarantineRoot, scanID, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modifiedAt, modifiedAt); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(quarantineMetadataPath(path), marshalQuarantineMetadata(quarantineMetadata{
			OriginalPath: "/tmp/" + name, Restorable: true, ScanID: scanID, FindingID: name,
			QuarantinedAt: quarantinedAt,
		}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// Give the older quarantine a newer payload mtime to prove ordering uses
	// the operation time rather than the preserved source-file mtime.
	write("scan-old", "old-payload", olderQuarantine, newerQuarantine)
	newPath := write("scan-new", "new-payload", newerQuarantine, olderQuarantine)

	entries, err := listQuarantineEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].QuarantinePath != newPath {
		t.Fatalf("quarantine entries were not sorted by latest operation: %#v", entries)
	}
	if !entries[0].QuarantinedAt.Equal(newerQuarantine) {
		t.Fatalf("new quarantine timestamp not exposed: %v", entries[0].QuarantinedAt)
	}
}

func TestQuarantineEntryExposesReversibleKernelModuleControls(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	payload := []byte("module payload")
	path := filepath.Join(securityQuarantineRoot, "scan-module", "k-test-module.ko")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	if err := os.WriteFile(quarantineMetadataPath(path), marshalQuarantineMetadata(quarantineMetadata{
		OriginalPath: "/tmp/test-module.ko",
		Restorable:   true,
		ScanID:       "scan-module",
		FindingID:    "k-test-module",
		Source:       "kernel-module",
		ModuleName:   "test_module",
		SHA256:       hex.EncodeToString(sum[:]),
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	h := NewAgentHandler("node-module", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/security/quarantine", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("list returned %d: %s", response.Code, response.Body.String())
	}
	var listed struct {
		Entries []quarantineEntry `json:"entries"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Entries) != 1 || !listed.Entries[0].Restorable || listed.Entries[0].ModuleName != "test_module" || listed.Entries[0].ModuleLoaded {
		t.Fatalf("unexpected reversible module entry: %#v", listed.Entries)
	}
	if runtime.GOOS == "linux" && !listed.Entries[0].ModuleLoadable {
		t.Fatalf("linux did not expose reversible module controls: %#v", listed.Entries[0])
	}
}

func TestQuarantineModuleLoadRejectsNonModuleOrChangedPayload(t *testing.T) {
	previousRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = previousRoot })

	path := filepath.Join(securityQuarantineRoot, "scan-file", "f-payload")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(quarantineMetadataPath(path), marshalQuarantineMetadata(quarantineMetadata{
		OriginalPath: "/tmp/payload",
		Restorable:   true,
		ScanID:       "scan-file",
		FindingID:    "f-payload",
		Source:       "file",
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewAgentHandler("node-module-load", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	entries, err := listQuarantineEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("list entries: %v %#v", err, entries)
	}
	request := httptest.NewRequest(http.MethodPost, "/security/quarantine/"+entries[0].ID+"/load", nil)
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("non-module load returned %d: %s", response.Code, response.Body.String())
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
		// Simulate metadata written by an older agent before the explicit
		// restorable flag was added. The original path still permits guarded
		// recovery after an upgrade.
		Restorable: false,
		ScanID:     "scan-restore",
		FindingID:  "f-restore",
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
	request := httptest.NewRequest(http.MethodPost, "/security/quarantine/"+entryID+"/restore", nil)
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
