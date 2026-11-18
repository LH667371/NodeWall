package rollback

import (
	"context"
	"errors"
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

func TestFailedTimeoutRollbackKeepsSnapshotAndRetries(t *testing.T) {
	var attempts atomic.Int32
	retried := make(chan struct{})
	manager := NewManager(10*time.Millisecond, func(context.Context, Snapshot) error {
		if attempts.Add(1) == 1 {
			return errors.New("temporary dataplane failure")
		}
		close(retried)
		return nil
	})
	manager.Begin(t.Context(), "retry-timeout", Snapshot{Interface: "eth0"})
	defer manager.Confirm("retry-timeout")
	select {
	case <-retried:
	case <-time.After(3 * time.Second):
		t.Fatal("failed timeout discarded the snapshot instead of retrying")
	}
}

func TestFailedManualRollbackCannotBeConfirmedAndRetries(t *testing.T) {
	var attempts atomic.Int32
	retried := make(chan struct{})
	manager := NewManager(time.Minute, func(context.Context, Snapshot) error {
		if attempts.Add(1) == 1 {
			return errors.New("temporary dataplane failure")
		}
		close(retried)
		return nil
	})
	manager.Begin(t.Context(), "retry-manual", Snapshot{Interface: "eth0"})
	if err := manager.RollbackNow(t.Context(), "retry-manual"); err == nil {
		t.Fatal("manual rollback failure was ignored")
	}
	if _, ok := manager.Pending("retry-manual"); !ok {
		t.Fatal("failed manual rollback discarded its snapshot")
	}
	if manager.Confirm("retry-manual") {
		t.Fatal("a failed rollback was confirmable")
	}
	select {
	case <-retried:
	case <-time.After(3 * time.Second):
		t.Fatal("failed manual rollback did not retry before the original deadline")
	}
}

func TestFailedConfirmationCommitPreservesRollback(t *testing.T) {
	restored := make(chan struct{})
	manager := NewManager(20*time.Millisecond, func(context.Context, Snapshot) error {
		close(restored)
		return nil
	})
	manager.Begin(t.Context(), "failed-confirm", Snapshot{Interface: "eth0"})
	if ok, err := manager.ConfirmWith("failed-confirm", func() error { return errors.New("disk full") }); ok || err == nil {
		t.Fatalf("failed durable confirmation was accepted: %t %v", ok, err)
	}
	if _, ok := manager.Pending("failed-confirm"); !ok {
		t.Fatal("failed durable confirmation discarded recovery")
	}
	select {
	case <-restored:
	case <-time.After(time.Second):
		t.Fatal("failed durable confirmation canceled the safety timer")
	}
}

func TestConcurrentManualRollbackAndTimeoutRestoreOnce(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var attempts atomic.Int32
	manager := NewManager(20*time.Millisecond, func(context.Context, Snapshot) error {
		attempts.Add(1)
		close(entered)
		<-release
		return nil
	})
	manager.Begin(t.Context(), "concurrent-restore", Snapshot{Interface: "eth0"})
	done := make(chan error, 1)
	go func() { done <- manager.RollbackNow(t.Context(), "concurrent-restore") }()
	<-entered
	joined := make(chan error, 1)
	go func() { joined <- manager.RollbackNow(t.Context(), "concurrent-restore") }()
	if manager.Confirm("concurrent-restore") {
		t.Fatal("in-progress rollback accepted confirmation")
	}
	select {
	case err := <-joined:
		t.Fatalf("concurrent rollback did not wait for recovery: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-joined; err != nil {
		t.Fatalf("joined rollback failed: %v", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("restored concurrently %d times", got)
	}
}

func TestCanceledRollbackWaiterDoesNotCancelRestore(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	manager := NewManager(time.Minute, func(context.Context, Snapshot) error {
		close(entered)
		<-release
		return nil
	})
	manager.Begin(t.Context(), "canceled-waiter", Snapshot{Interface: "eth0"})
	done := make(chan error, 1)
	go func() { done <- manager.RollbackNow(t.Context(), "canceled-waiter") }()
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := manager.RollbackNow(ctx, "canceled-waiter"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter did not leave promptly: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("waiter cancellation stopped recovery: %v", err)
	}
	if _, ok := manager.Pending("canceled-waiter"); ok {
		t.Fatal("successful restore retained its session")
	}
}
