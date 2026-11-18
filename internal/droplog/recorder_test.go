package droplog

import (
	"path/filepath"
	"testing"

	"nodewall/internal/models"
	"nodewall/internal/xdp"
)

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
