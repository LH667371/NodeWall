package rollback

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRollbackOnTimeout(t *testing.T) {
	var restored atomic.Int32
	manager := NewManager(20*time.Millisecond, func(context.Context, Snapshot) error {
		restored.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	manager.Begin(ctx, "pub-1", Snapshot{Interface: "eth0"})
	cancel()
	time.Sleep(40 * time.Millisecond)

	if got := restored.Load(); got != 1 {
		t.Fatalf("expected restore once, got %d", got)
	}
}

func TestConfirmCancelsRollback(t *testing.T) {
	var restored atomic.Int32
	manager := NewManager(40*time.Millisecond, func(context.Context, Snapshot) error {
		restored.Add(1)
		return nil
	})

	manager.Begin(context.Background(), "pub-1", Snapshot{Interface: "eth0"})
	if ok := manager.Confirm("pub-1"); !ok {
		t.Fatalf("confirm returned false")
	}
	time.Sleep(60 * time.Millisecond)

	if got := restored.Load(); got != 0 {
		t.Fatalf("expected no restore, got %d", got)
	}
}
