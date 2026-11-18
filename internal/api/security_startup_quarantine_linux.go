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

// prepareSystemdUnitIsolation stops a suspicious unit and removes only its
// enablement links before the unit file is moved. The unit itself is still
// preserved by the normal quarantine path, so restore can put it back without
// losing the operator's original enablement state.
func prepareSystemdUnitIsolation(unitPath string) ([]quarantinedStartupLink, error) {
	if !securityscan.IsSystemdUnitPath(unitPath) {
		return nil, nil
	}
	unitPath = filepath.Clean(unitPath)
	unit := filepath.Base(unitPath)
	if unit == "." || unit == "" || strings.ContainsAny(unit, `/\\`) {
		return nil, errors.New("invalid systemd unit path")
	}
	if unit == "nodewall-agent.service" || unit == "nodewall-server.service" {
		return nil, errors.New("refusing to quarantine a NodeWall service unit")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	active := strings.TrimSpace(stringOutput(ctx, "systemctl", "show", "--value", "-p", "ActiveState", unit))
	if active == "active" || active == "activating" || active == "deactivating" {
		if err := exec.CommandContext(ctx, "systemctl", "stop", unit).Run(); err != nil {
			return nil, fmt.Errorf("stop systemd unit %s: %w", unit, err)
		}
	}

	links, err := collectSystemdEnablementLinks(unit)
	if err != nil {
		return nil, err
	}
	removed := make([]quarantinedStartupLink, 0, len(links))
	for _, link := range links {
		if err := os.Remove(link.Path); err != nil {
			restoreSystemdEnablementLinks(removed)
			return nil, fmt.Errorf("remove systemd enablement link %s: %w", link.Path, err)
		}
		removed = append(removed, link)
	}
	if err := exec.CommandContext(ctx, "systemctl", "daemon-reload").Run(); err != nil {
		restoreSystemdEnablementLinks(removed)
		return nil, fmt.Errorf("reload systemd after removing %s: %w", unit, err)
	}
	return removed, nil
}

func rollbackSystemdUnitIsolation(links []quarantinedStartupLink) {
	if len(links) == 0 {
		return
	}
	restoreSystemdEnablementLinks(links)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
}

func collectSystemdEnablementLinks(unit string) ([]quarantinedStartupLink, error) {
	var result []quarantinedStartupLink
	for _, root := range []string{"/etc/systemd/system", "/run/systemd/system"} {
		info, err := os.Stat(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			continue
		}
		err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if path != root && !strings.HasSuffix(path, ".wants") && !strings.HasSuffix(path, ".requires") {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink == 0 || (strings.HasSuffix(filepath.Dir(path), ".wants") == false && strings.HasSuffix(filepath.Dir(path), ".requires") == false) {
				return nil
			}
			if filepath.Base(path) != unit {
				return nil
			}
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if filepath.Base(filepath.Clean(target)) != unit {
				return nil
			}
			result = append(result, quarantinedStartupLink{Path: path, Target: target})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func restoreSystemdEnablementLinks(links []quarantinedStartupLink) error {
	var firstErr error
	for _, link := range links {
		if link.Path == "" || link.Target == "" {
			continue
		}
		if info, err := os.Lstat(link.Path); err == nil {
			if info.Mode()&os.ModeSymlink == 0 {
				if firstErr == nil {
					firstErr = fmt.Errorf("enablement path is no longer a symlink: %s", link.Path)
				}
				continue
			}
			current, readErr := os.Readlink(link.Path)
			if readErr != nil || current != link.Target {
				if firstErr == nil {
					firstErr = fmt.Errorf("enablement path changed: %s", link.Path)
				}
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(link.Path), 0o755); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := os.Symlink(link.Target, link.Path); err != nil && !errors.Is(err, os.ErrExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func restoreSystemdStartupLinks(metadata quarantineMetadata) error {
	if len(metadata.StartupLinks) == 0 {
		return nil
	}
	if err := restoreSystemdEnablementLinks(metadata.StartupLinks); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	return nil
}

func stringOutput(ctx context.Context, name string, args ...string) string {
	output, _ := exec.CommandContext(ctx, name, args...).Output()
	return string(output)
}
