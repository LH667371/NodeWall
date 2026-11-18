package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"nodewall/internal/securityscan"
	"nodewall/internal/xdp"
)

func TestCleanupMigratesLegacyEvidenceAndPreservesSamples(t *testing.T) {
	oldRoot := securityQuarantineRoot
	securityQuarantineRoot = t.TempDir()
	t.Cleanup(func() { securityQuarantineRoot = oldRoot })
	reports := t.TempDir()
	writeArtifact := func(scanID, name string, meta quarantineMetadata) string {
		t.Helper()
		path := filepath.Join(securityQuarantineRoot, scanID, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("stored data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(quarantineMetadataPath(path), marshalQuarantineMetadata(meta), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	mask := "/etc/systemd/system/abcd1234.service"
	evidence := writeArtifact("scan-legacy", "j-test-evidence.json", quarantineMetadata{ScanID: "scan-legacy", FindingID: "j-test", Rule: "malware-persistence", Source: "scan-evidence", StartupMaskPath: mask, StartupMaskOwned: true})
	orphan := writeArtifact("scan-orphan", "j-orphan-evidence.json", quarantineMetadata{ScanID: "scan-orphan", FindingID: "j-orphan", Rule: "malware-persistence", Source: "scan-evidence", StartupMaskPath: mask, StartupMaskOwned: true})
	sample := writeArtifact("scan-legacy", "d-sample-script", quarantineMetadata{ScanID: "scan-legacy", FindingID: "d-sample", Rule: "malicious-fd-script", Source: "fd-script-sample", SHA256: "1234"})
	payload := writeArtifact("scan-legacy", "f-malware-payload", quarantineMetadata{ScanID: "scan-legacy", FindingID: "f-malware", Rule: "cryptominer", Source: "process"})
	h := NewAgentHandler("node-a", xdp.NewMockManager(), memoryStateStore{}, time.Second, nil, nil)
	h.securityArchiveDir, h.securityReports = reports, make(map[string]scanReportSummary)
	report := securityScanReport{ReportID: "scan-legacy", NodeID: "node-a", Status: "completed", StartedAt: time.Now(), Findings: []securityscan.Finding{
		{ID: "j-test", Source: "journal", Rule: "malware-persistence", EvidenceArchived: true, EvidencePath: evidence, Quarantined: true, QuarantinePath: evidence, Detail: "detection context"},
		{ID: "d-sample", Source: "fd-script", Rule: "malicious-fd-script", EvidenceArchived: true, EvidencePath: sample, SHA256: "1234"},
		{ID: "f-malware", Source: "process", Rule: "cryptominer", Quarantined: true, QuarantinePath: payload},
	}}
	if err := h.saveScanReport(report); err != nil {
		t.Fatal(err)
	}
	if err := h.ConfigureSecurityArchive(reports); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(evidence); !os.IsNotExist(err) {
		t.Fatalf("migrated evidence still exists: %v", err)
	}
	if _, err := os.Stat(quarantineMetadataPath(evidence)); !os.IsNotExist(err) {
		t.Fatalf("evidence metadata still exists: %v", err)
	}
	for _, path := range []string{orphan, sample, payload} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("important artifact was removed: %s: %v", path, err)
		}
	}
	got, err := h.readArchivedScan("scan-legacy")
	if err != nil {
		t.Fatal(err)
	}
	f := got.Findings[0]
	if f.Quarantined || f.EvidenceArchived || f.StartupBlockPath != mask || !f.StartupBlockOwned || f.Detail != "detection context" {
		t.Fatalf("report did not preserve detection and ownership: %#v", f)
	}
	if f = got.Findings[1]; !f.Quarantined || f.QuarantinePath != sample || f.EvidenceArchived {
		t.Fatalf("script sample was not migrated to quarantine: %#v", f)
	}
	if h.securityArchiveWarning == "" {
		t.Fatal("skipped orphan must be reported")
	}
}
