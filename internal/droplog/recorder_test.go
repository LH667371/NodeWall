package droplog

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/xdp"
)

func TestRecorderRestoresCheckpointAfterInterruptedWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "drop-log-state.json")
	defaults := models.DropLogSettings{Enabled: true, LogDir: dir, RetentionDays: 7}
	recorder, err := New(dir, path, defaults)
	if err != nil {
		t.Fatal(err)
	}
	custom := defaults
	custom.RetentionDays = 20
	for range 2 {
		if err := recorder.UpdateSettings(custom); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	recovered, err := New(dir, path, defaults)
	if err != nil || recovered.Settings().RetentionDays != 20 {
		t.Fatalf("valid backup was not restored: %v", err)
	}

	path = filepath.Join(dir, "empty-checkpoint.json")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fallback, err := New(dir, path, defaults)
	if err == nil || fallback.Settings().RetentionDays != defaults.RetentionDays {
		t.Fatalf("damaged state did not return the default recorder: %v", err)
	}
	if err := fallback.Flush(&auditDataplane{}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, path, defaults); err != nil {
		t.Fatalf("failed to start with repaired checkpoint: %v", err)
	}
}

type auditDataplane struct {
	xdp.Dataplane
	entries []models.InterceptLogEntry
}

func (*auditDataplane) Interfaces() []string { return []string{"eth0"} }
func (d *auditDataplane) ReadDropLogs(string, int) ([]models.InterceptLogEntry, error) {
	return d.entries, nil
}

func TestAuditRoundTripPreservesRuleScopesAndObservationCounters(t *testing.T) {
	dir := t.TempDir()
	recorder, err := New(dir, filepath.Join(dir, "state.json"), models.DropLogSettings{Enabled: true, LogDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	dp := &auditDataplane{entries: []models.InterceptLogEntry{
		{SourceCIDR: "0.0.0.0/0", Port: 67, Reason: "nodewall:default_deny", Count: 3, Drops: 3},
		{SourceCIDR: "10.42.0.0/16", Port: 67, Reason: "nodewall:default_deny", Count: 4},
		{SourceIP: "0.0.0.0", Port: 67, Reason: "dhcp_broadcast", Count: 2, Drops: 2},
	}}
	if err := recorder.Flush(dp); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Flush(dp); err != nil {
		t.Fatal(err)
	}
	records, err := recorder.Recent(20)
	if err != nil || len(records) != 3 {
		t.Fatalf("audit records=%+v err=%v", records, err)
	}
	for _, record := range records {
		switch record.SourceCIDR {
		case "0.0.0.0/0":
			if record.SourceIP != "" || record.Count != 3 || record.Drops != 3 {
				t.Fatalf("aggregate lost: %+v", record)
			}
		case "10.42.0.0/16":
			if record.SourceIP != "" || record.Count != 4 || record.Drops != 0 {
				t.Fatalf("observation lost: %+v", record)
			}
		default:
			if record.SourceIP != "0.0.0.0" || record.Reason != "dhcp_broadcast" || record.Drops != 2 {
				t.Fatalf("packet source lost: %+v", record)
			}
		}
	}
	// A new observation counter can be smaller than its previous real-drop
	// counterpart. It must not disappear, nor reset the real-drop baseline.
	dp.entries = []models.InterceptLogEntry{{SourceCIDR: "0.0.0.0/0", Port: 67, Reason: "nodewall:default_deny", Count: 1}}
	if err := recorder.Flush(dp); err != nil {
		t.Fatal(err)
	}
	dp.entries[0].Count, dp.entries[0].Drops = 4, 4
	if err := recorder.Flush(dp); err != nil {
		t.Fatal(err)
	}
	records, err = recorder.Recent(20)
	if err != nil || len(records) != 5 {
		t.Fatalf("mode change lost deltas: %+v %v", records, err)
	}
}

func TestIPTablesCounterResetUsesNewEpochAndKeepsPacketSamplesSeparate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	settings := models.DropLogSettings{Enabled: true, LogDir: dir}
	r, err := New(dir, path, settings)
	if err != nil {
		t.Fatal(err)
	}
	dp := &auditDataplane{entries: []models.InterceptLogEntry{{
		SourceCIDR: "0.0.0.0/0", Reason: "nodewall:default_deny", CounterEpoch: "first", Count: 20, Drops: 20,
		Traffic: &models.FirewallTraffic{Evidence: models.FirewallRuleCounter, Hook: "input"},
	}}}
	if err := r.Flush(dp); err != nil {
		t.Fatal(err)
	}
	r, err = New(dir, path, settings)
	if err != nil {
		t.Fatal(err)
	}
	// A rebuilt chain may already exceed the previous value by the next poll.
	dp.entries[0].CounterEpoch, dp.entries[0].Count, dp.entries[0].Drops = "second", 23, 23
	sample := models.DropLogRecord{Timestamp: time.Now(), Interface: "eth0", Direction: models.DirectionIngress,
		SourceIP: "192.0.2.42", Count: 1, Drops: 1, Reason: "nodewall:default_deny",
		Traffic: &models.FirewallTraffic{Evidence: models.FirewallPacketSample, Origin: "vm", Guest: "guest-a"}}
	r.RecordPacketAudit(sample)
	r.RecordPacketAudit(sample)
	for range 2 {
		if err := r.Flush(dp); err != nil {
			t.Fatal(err)
		}
	}
	logs, err := r.Recent(10)
	if err != nil || len(logs) != 3 || logs[0].Drops != 23 || logs[1].Drops != 2 || logs[1].Traffic.Origin != "vm" {
		t.Fatalf("unexpected counter/sample history: %+v (%v)", logs, err)
	}
}

type directionalAuditDataplane struct {
	*auditDataplane
	xdp.DirectionalStats
	egress []models.InterceptLogEntry
}

func (d *directionalAuditDataplane) ReadDirectionDropLogs(_ string, direction models.PolicyDirection, _ int) ([]models.InterceptLogEntry, error) {
	if direction != models.DirectionEgress {
		panic("expected egress counter read")
	}
	return d.egress, nil
}

func TestRecorderCheckpointsIngressAndEgressIndependently(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	settings := models.DropLogSettings{Enabled: true, LogDir: dir}
	recorder, err := New(dir, path, settings)
	if err != nil {
		t.Fatal(err)
	}
	entry := models.InterceptLogEntry{
		SourceCIDR: "0.0.0.0/0", Reason: "nodewall:default_deny", CounterEpoch: "same-epoch",
		Count: 4, Drops: 4,
	}
	observed := entry
	observed.Count, observed.Drops = 7, 0
	dp := &directionalAuditDataplane{
		auditDataplane: &auditDataplane{entries: []models.InterceptLogEntry{entry}},
		egress:         []models.InterceptLogEntry{entry, observed},
	}
	if err := recorder.Flush(dp); err != nil {
		t.Fatal(err)
	}
	recorder, err = New(dir, path, settings)
	if err != nil {
		t.Fatal(err)
	}
	dp.egress[0].Count, dp.egress[0].Drops = 6, 6
	dp.egress[1].Count = 10
	if err := recorder.Flush(dp); err != nil {
		t.Fatal(err)
	}
	records, err := recorder.Recent(20)
	if err != nil || len(records) != 5 {
		t.Fatalf("direction changes duplicated or lost deltas: %+v (%v)", records, err)
	}
	var ingressDrops, egressDrops, egressObserved uint64
	for _, record := range records {
		switch {
		case record.Direction == models.DirectionIngress:
			ingressDrops += record.Drops
		case record.Direction == models.DirectionEgress && record.Drops != 0:
			egressDrops += record.Drops
		case record.Direction == models.DirectionEgress:
			egressObserved += record.Count
		}
	}
	if ingressDrops != 4 || egressDrops != 6 || egressObserved != 10 {
		t.Fatalf("got ingress drops=%d, egress drops=%d, egress observes=%d", ingressDrops, egressDrops, egressObserved)
	}
}
