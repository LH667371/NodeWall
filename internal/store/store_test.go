package store

import (
	"os"
	"path/filepath"
	"testing"

	"nodewall/internal/models"
)

func TestFailedPolicyPersistenceKeepsLastDurablePolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state, err := NewPersistent(path)
	if err != nil {
		t.Fatal(err)
	}
	initial := models.InterfacePolicy{NodeID: "node-a", Interface: "eth0", PublicPorts: []uint16{22}}
	if _, err := state.PutPolicyChecked(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	// An existing directory makes rename fail even when tests run as root.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	next := initial
	next.DeniedPorts = []uint16{22}
	if _, err := state.PutPolicyChecked(t.Context(), next); err == nil {
		t.Fatal("disk failure was not returned")
	}
	actual, err := state.GetPolicy(t.Context(), "node-a", "eth0")
	if err != nil || len(actual.DeniedPorts) != 0 {
		t.Fatalf("undurable policy became visible: %#v %v", actual, err)
	}
}

func TestRestoredPolicyHasANewerVersionThanTheRevertedPolicy(t *testing.T) {
	ctx := t.Context()
	state := New()
	const node, iface = "node-a", "eth0"
	before := state.PutPolicy(ctx, models.InterfacePolicy{NodeID: node, Interface: iface, PublicPorts: []uint16{22}})
	if err := state.BeginPolicyUpdate(ctx, node, iface); err != nil {
		t.Fatal(err)
	}
	draft := before
	draft.PublicPorts = nil
	reverted := state.PutPolicy(ctx, draft)
	if err := state.FinishPolicyUpdate(ctx, node, iface, true); err != nil {
		t.Fatal(err)
	}
	actual, err := state.GetPolicy(ctx, node, iface)
	if err != nil || !actual.UpdatedAt.After(reverted.UpdatedAt) || len(actual.PublicPorts) != 1 || actual.PublicPorts[0] != 22 {
		t.Fatalf("restoration did not publish the previous rules as a new version: %#v %v", actual, err)
	}
}
