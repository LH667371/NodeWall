package xdp

import (
	"os"
	"path/filepath"
	"testing"

	"nodewall/internal/models"
)

func TestRecommendInterfacePrefersPhysicalUpNIC(t *testing.T) {
	items := []models.DetectedInterface{
		{Name: "lo", IsUp: true, IsLoopback: true},
		{Name: "docker0", IsUp: true},
		{Name: "eth0", IsUp: true, IsPhysical: true, Addresses: []string{"10.0.0.2/24"}},
	}

	if got := recommendInterface(items); got != "eth0" {
		t.Fatalf("unexpected recommended interface: %s", got)
	}
}

func TestPhysicalFromSysfsRejectsVirtualLayers(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		"em1/device",
		"br_em1/bridge",
		"bond0/bonding",
		"vnic15.0",
	} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatalf("create fixture %s: %v", path, err)
		}
	}

	if !physicalFromSysfs(root, "em1") {
		t.Fatal("expected PCI-backed em1 to be a physical candidate")
	}
	for _, name := range []string{"br_em1", "bond0", "vnic15.0"} {
		if physicalFromSysfs(root, name) {
			t.Fatalf("did not expect %s to be a physical candidate", name)
		}
	}
}
