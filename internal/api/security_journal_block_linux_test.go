//go:build linux

package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nodewall/internal/securityscan"
	"nodewall/internal/xdp"
)

func TestJournalStartupReviewDoesNotCreateMask(t *testing.T) {
	oldRoot, oldRefresh, oldQuarantine := systemdMaskRoot, refreshSystemdUnit, securityQuarantineRoot
	systemdMaskRoot, securityQuarantineRoot = t.TempDir(), t.TempDir()
	refreshSystemdUnit = func(string) { t.Fatal("startup review must not invoke systemd") }
	t.Cleanup(func() {
		systemdMaskRoot, refreshSystemdUnit, securityQuarantineRoot = oldRoot, oldRefresh, oldQuarantine
	})
	preexisting := filepath.Join(systemdMaskRoot, "abcdef55.service")
	if err := os.Symlink("/dev/null", preexisting); err != nil {
		t.Fatal(err)
	}
	h := NewAgentHandler("node-a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := h.ConfigureSecurityArchive(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	finding := securityscan.Finding{ID: "j-test", Source: "journal", Rule: "malware-persistence", Severity: securityscan.SeverityHigh,
		StartupCandidates: []string{"/run/systemd/transient/abcd1234.service", "/run/systemd/transient/abcdef55.service"}}
	h.securityJob = &securityScanJob{ID: "scan-journal", Status: "running", StartedAt: time.Now(), Findings: []securityscan.Finding{finding}}
	h.markStartupReview(context.Background(), "scan-journal", finding)
	report, err := h.readArchivedScan("scan-journal")
	if err != nil {
		t.Fatal(err)
	}
	blocks := report.Findings[0].StartupBlocks
	if len(blocks) != 2 || blocks[0].Owned || blocks[1].Owned || blocks[0].Status != "review" || blocks[1].Status != "review" {
		t.Fatalf("startup review was not persisted: %#v", blocks)
	}
	if report.Findings[0].StartupBlocked || reportHasOwnedStartupMask(report) {
		t.Fatalf("startup review unexpectedly created a mask: %#v", report.Findings[0])
	}
	if target, err := os.Readlink(preexisting); err != nil || target != "/dev/null" {
		t.Fatalf("pre-existing administrator mask was changed: target=%q err=%v", target, err)
	}
}

func TestTransientFileFindingIsMarkedForRealFileRemoval(t *testing.T) {
	oldRoot, oldRefresh, oldQuarantine := systemdMaskRoot, refreshSystemdUnit, securityQuarantineRoot
	systemdMaskRoot, securityQuarantineRoot = t.TempDir(), t.TempDir()
	refreshSystemdUnit = func(string) { t.Fatal("startup review must not invoke systemd") }
	t.Cleanup(func() {
		systemdMaskRoot, refreshSystemdUnit, securityQuarantineRoot = oldRoot, oldRefresh, oldQuarantine
	})
	h := NewAgentHandler("node-a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := h.ConfigureSecurityArchive(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	path := "/run/systemd/transient/5ddf18af1006a658.service"
	finding := securityscan.Finding{ID: "f-transient", Path: path, Source: "file", Rule: "malware-persistence", Severity: securityscan.SeverityHigh}
	h.securityJob = &securityScanJob{ID: "scan-transient", Status: "running", StartedAt: time.Now(), Findings: []securityscan.Finding{finding}}
	h.markStartupReview(context.Background(), "scan-transient", finding)
	if _, err := os.Lstat(filepath.Join(systemdMaskRoot, filepath.Base(path))); !os.IsNotExist(err) {
		t.Fatalf("a synthetic mask was created: %v", err)
	}
	updated := h.securityJob.Findings[0]
	if updated.StartupBlocked || len(updated.StartupBlocks) != 1 || updated.StartupBlocks[0].Status != "review" {
		t.Fatalf("transient startup item was not marked for review: %#v", updated)
	}
}

func TestOperatorManagedServiceIsMarkedForExplicitQuarantine(t *testing.T) {
	h := NewAgentHandler("node-a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	if err := h.ConfigureSecurityArchive(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	path := "/etc/systemd/system/maintenance.service"
	finding := securityscan.Finding{ID: "f-service", Path: path, Source: "file", Rule: "malware-persistence", Severity: securityscan.SeverityHigh}
	h.securityJob = &securityScanJob{ID: "scan-service", Status: "running", StartedAt: time.Now(), Findings: []securityscan.Finding{finding}}
	h.markStartupReview(context.Background(), "scan-service", finding)
	updated := h.securityJob.Findings[0]
	if updated.StartupBlocked || len(updated.StartupBlocks) != 1 || updated.StartupBlocks[0].Status != "review" {
		t.Fatalf("operator-managed startup item was not left for explicit quarantine: %#v", updated)
	}
}
