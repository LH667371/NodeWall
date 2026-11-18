package store

import (
	"context"
	"testing"
	"time"

	"nodewall/internal/models"
)

func TestEventDispositionPersistsAndFiltersByNode(t *testing.T) {
	path := t.TempDir() + "/state.json"
	state, err := NewPersistent(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	first, err := state.UpsertEventDisposition(context.Background(), models.EventDisposition{
		EventID:   "firewall-node-a-1",
		NodeID:    "node-a",
		Source:    "firewall",
		Status:    models.EventDispositionHandled,
		UpdatedAt: now,
	})
	if err != nil || first.Status != models.EventDispositionHandled {
		t.Fatalf("upsert disposition: %+v %v", first, err)
	}
	if _, err := state.UpsertEventDisposition(context.Background(), models.EventDisposition{
		EventID: "ssh-node-b-1",
		NodeID:  "node-b",
		Source:  "ssh",
		Status:  models.EventDispositionDeferred,
	}); err != nil {
		t.Fatal(err)
	}
	if got := state.ListEventDispositions(context.Background(), "node-a"); len(got) != 1 || got[0].EventID != "firewall-node-a-1" {
		t.Fatalf("node filter returned %+v", got)
	}

	restarted, err := NewPersistent(path)
	if err != nil {
		t.Fatal(err)
	}
	all := restarted.ListEventDispositions(context.Background(), "")
	if len(all) != 2 {
		t.Fatalf("persisted dispositions = %+v", all)
	}
	if _, err := restarted.UpsertEventDisposition(context.Background(), models.EventDisposition{
		EventID: "firewall-node-a-1",
		NodeID:  "node-a",
		Source:  "firewall",
		Status:  models.EventDispositionOpen,
	}); err != nil {
		t.Fatal(err)
	}
	if got := restarted.ListEventDispositions(context.Background(), "node-a"); len(got) != 0 {
		t.Fatalf("open disposition was not removed: %+v", got)
	}
}

func TestReplaceJSONCarriesEventDispositionsToStandby(t *testing.T) {
	active := New()
	if _, err := active.UpsertEventDisposition(context.Background(), models.EventDisposition{
		EventID: "malware-node-a-1",
		NodeID:  "node-a",
		Source:  "malware",
		Status:  models.EventDispositionHandled,
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := active.ExportJSON()
	if err != nil {
		t.Fatal(err)
	}
	standby := New()
	if err := standby.ReplaceJSON(snapshot); err != nil {
		t.Fatal(err)
	}
	got := standby.ListEventDispositions(context.Background(), "node-a")
	if len(got) != 1 || got[0].Status != models.EventDispositionHandled {
		t.Fatalf("standby did not receive disposition: %+v", got)
	}
}
