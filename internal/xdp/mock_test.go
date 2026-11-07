package xdp

import (
	"testing"

	"nodewall/internal/models"
)

func TestMockManagerLifecycle(t *testing.T) {
	manager := NewMockManager()

	if err := manager.Attach("eth0", AttachModeNative); err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	if err := manager.UpsertCIDR("eth0", "10.0.0.0/8"); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if err := manager.WriteConfig("eth0", Config{NonIPv4Action: models.NonIPv4Drop}); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	runtime, err := manager.Runtime("eth0")
	if err != nil {
		t.Fatalf("runtime failed: %v", err)
	}
	if !runtime.Attached {
		t.Fatalf("expected attached runtime")
	}
	if runtime.Config.NonIPv4Action != models.NonIPv4Drop {
		t.Fatalf("unexpected config action: %s", runtime.Config.NonIPv4Action)
	}

	stats, err := manager.ReadStats("eth0")
	if err != nil {
		t.Fatalf("stats failed: %v", err)
	}
	if stats.Passed == 0 {
		t.Fatalf("expected non-zero passed stats")
	}
}

func TestNewDataplane(t *testing.T) {
	dp, err := NewDataplane("mock", "ignored")
	if err != nil {
		t.Fatalf("new dataplane failed: %v", err)
	}
	if _, ok := dp.(*MockManager); !ok {
		t.Fatalf("expected mock dataplane")
	}
}

func TestMockReadSourceStats(t *testing.T) {
	manager := NewMockManager()
	_ = manager.Attach("eth0", AttachModeNative)

	items, err := manager.ReadSourceStats("eth0", 10)
	if err != nil {
		t.Fatalf("read source stats failed: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected source stats")
	}
}
