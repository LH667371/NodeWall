package service

import (
	"context"
	"errors"
	"nodewall/internal/models"
	"nodewall/internal/store"
	"testing"
)

func TestConcurrentWebPolicySavesRejectStaleVersion(t *testing.T) {
	ctx := context.Background()
	state := store.New()
	original := state.PutPolicy(ctx, models.InterfacePolicy{NodeID: "node-a", Interface: "ens3"})
	svc := NewPolicyService(state)
	results := make(chan error, 2)
	for _, action := range []models.NonIPv4Action{models.NonIPv4Pass, models.NonIPv4Drop} {
		draft := original
		draft.NonIPv4Action = action
		go func() { _, err := svc.UpdatePolicyAndApplyIfCurrent(ctx, draft, original.UpdatedAt); results <- err }()
	}
	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrPolicyChanged) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results: %d saves, %d conflicts", successes, conflicts)
	}
}

func TestPolicySnapshotsCannotReplaceAConfirmedOrRecoveringPolicy(t *testing.T) {
	ctx := t.Context()
	state := store.New()
	svc := NewPolicyService(state)
	const node, iface = "node-a", "ens3"
	before := state.PutPolicy(ctx, models.InterfacePolicy{NodeID: node, Interface: iface})
	draft := models.NormalizeInterfacePolicy(before)
	draft.Ingress.BlockedCIDRs = []string{"192.0.2.1/32"}
	saved, err := svc.UpdatePolicyAndApplyIfCurrent(ctx, draft, before.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := svc.SavePolicySnapshotIfCurrent(ctx, before); !errors.Is(err, ErrPolicyChanged) || !actual.UpdatedAt.Equal(saved.UpdatedAt) {
		t.Fatalf("late snapshot could replace a newer save: %#v %v", actual, err)
	}
	if err := state.BeginPolicyUpdate(ctx, node, iface); err != nil {
		t.Fatal(err)
	}
	saved.Ingress.BlockedCIDRs = nil
	if actual, err := svc.SavePolicySnapshotIfCurrent(ctx, saved); !errors.Is(err, ErrPolicyChanged) || len(actual.Ingress.BlockedCIDRs) != 1 {
		t.Fatalf("snapshot could overwrite a recovering policy: %#v %v", actual, err)
	}
}
