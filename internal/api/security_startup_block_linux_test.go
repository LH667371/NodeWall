//go:build linux

package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdMaskOwnershipPreservesExistingAdministratorMask(t *testing.T) {
	previousRoot := systemdMaskRoot
	previousRefresh := refreshSystemdUnit
	systemdMaskRoot = t.TempDir()
	refreshSystemdUnit = func(string) {}
	t.Cleanup(func() {
		systemdMaskRoot = previousRoot
		refreshSystemdUnit = previousRefresh
	})

	existing := filepath.Join(systemdMaskRoot, "q7m2x91k.service")
	if err := os.Symlink("/dev/null", existing); err != nil {
		t.Fatal(err)
	}
	maskPath, owned, err := blockSystemdStartup("/etc/systemd/system/q7m2x91k.service")
	if err != nil || maskPath != existing || owned {
		t.Fatalf("existing mask ownership = %q, %t, %v; want existing and unowned", maskPath, owned, err)
	}
	if owned {
		if err := unblockSystemdStartup(maskPath); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Lstat(existing); err != nil {
		t.Fatalf("existing administrator mask was removed: %v", err)
	}
}

func TestSystemdMaskCanBeRemovedWhenNodeWallCreatedIt(t *testing.T) {
	previousRoot := systemdMaskRoot
	previousRefresh := refreshSystemdUnit
	systemdMaskRoot = t.TempDir()
	refreshSystemdUnit = func(string) {}
	t.Cleanup(func() {
		systemdMaskRoot = previousRoot
		refreshSystemdUnit = previousRefresh
	})

	maskPath, owned, err := blockSystemdStartup("/etc/systemd/system/q7m2x91k.service")
	if err != nil || !owned {
		t.Fatalf("new mask ownership = %q, %t, %v; want NodeWall-owned mask", maskPath, owned, err)
	}
	if err := unblockSystemdStartup(maskPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(maskPath); !os.IsNotExist(err) {
		t.Fatalf("NodeWall mask still exists after unblock: %v", err)
	}
}
