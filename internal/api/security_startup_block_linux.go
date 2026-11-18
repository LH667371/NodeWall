//go:build linux

package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nodewall/internal/securityscan"
)

var systemdMaskRoot = "/etc/systemd/system"

// blockSystemdStartup creates the standard systemd /dev/null mask. The mask
// is written only after the unit file has been verified and isolated by the
// caller, so a suspicious unit cannot be started again at the next boot.
func blockSystemdStartup(unitPath string) (string, bool, error) {
	if !securityscan.IsSystemdUnitPath(unitPath) {
		return "", false, errors.New("finding is not a systemd unit")
	}
	unit := filepath.Base(filepath.Clean(unitPath))
	if unit == "." || unit == "" || strings.ContainsAny(unit, "/\\") {
		return "", false, errors.New("invalid systemd unit name")
	}
	maskPath := filepath.Join(systemdMaskRoot, unit)
	if err := os.MkdirAll(systemdMaskRoot, 0o755); err != nil {
		return "", false, err
	}
	if info, err := os.Lstat(maskPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return "", false, fmt.Errorf("systemd mask path already contains a non-symlink: %s", maskPath)
		}
		target, readErr := os.Readlink(maskPath)
		if readErr != nil || target != "/dev/null" {
			return "", false, fmt.Errorf("systemd mask path is not a /dev/null systemd mask: %s", maskPath)
		}
		// A pre-existing /dev/null mask may belong to the administrator or a
		// package. Report that startup is blocked but never claim ownership;
		// restore must leave it in place.
		refreshSystemdUnit(unit)
		return maskPath, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	if err := os.Symlink("/dev/null", maskPath); err != nil {
		return "", false, fmt.Errorf("create systemd startup mask: %w", err)
	}
	refreshSystemdUnit(unit)
	return maskPath, true, nil
}

func unblockSystemdStartup(maskPath string) error {
	if strings.TrimSpace(maskPath) == "" {
		return nil
	}
	clean := filepath.Clean(maskPath)
	if clean != filepath.Join(systemdMaskRoot, filepath.Base(clean)) {
		return errors.New("refusing to remove a mask outside /etc/systemd/system")
	}
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return errors.New("startup mask is not a symlink")
	}
	target, err := os.Readlink(clean)
	if err != nil || target != "/dev/null" {
		return errors.New("refusing to remove a non-NodeWall startup mask")
	}
	if err := os.Remove(clean); err != nil {
		return err
	}
	refreshSystemdUnit(filepath.Base(clean))
	return nil
}

var refreshSystemdUnit = func(unit string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
	_ = exec.CommandContext(ctx, "systemctl", "stop", unit).Run()
}
