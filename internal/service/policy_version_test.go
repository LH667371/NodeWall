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
