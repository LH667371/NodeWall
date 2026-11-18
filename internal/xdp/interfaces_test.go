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

func TestInterfaceIPv4AssociationFollowsOnlyActualMasterLinks(t *testing.T) {
	items := []models.DetectedInterface{
		{Name: "em1", Addresses: []string{"fe80::1/64"}},
		{Name: "em2"},
		{Name: "bond0", Addresses: []string{"fe80::2/64"}},
		{Name: "bridge-business", Addresses: []string{"fe80::3/64", "192.168.2.168/24"}},
		{Name: "direct0", Addresses: []string{"10.0.0.2/24"}},
	}
	associateInterfaceAddresses(items, map[string]string{"em1": "bond0", "bond0": "bridge-business", "direct0": "bridge-business"})
	if items[0].AddressInterface != "bridge-business" || len(items[0].RelatedAddresses) != 2 || len(items[0].Addresses) != 1 {
		t.Fatal("bridge IPv4 must remain an explicit association", items[0])
	}
	if items[1].AddressInterface != "" || len(items[1].RelatedAddresses) != 0 || items[4].AddressInterface != "" {
		t.Fatal("unrelated or directly addressed interfaces inherited another address")
	}
	associateInterfaceAddresses(items, map[string]string{"em2": "missing", "em1": "bond0", "bond0": "em1"})
}
