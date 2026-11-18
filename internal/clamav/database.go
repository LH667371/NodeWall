package clamav

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func versions(dir string) (map[string]uint64, error) {
	result := make(map[string]uint64, len(databaseNames))
	for _, name := range databaseNames {
		path, err := databasePath(dir, name)
		if err != nil {
			return nil, err
		}
		result[name], err = databaseVersion(path)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func compareVersions(current, candidate map[string]uint64) (bool, error) {
	changed := len(current) == 0
	for _, name := range databaseNames {
		if candidate[name] == 0 {
			return false, fmt.Errorf("missing %s database version", name)
		}
		if candidate[name] < current[name] {
			return false, fmt.Errorf("refusing %s database downgrade from %d to %d", name, current[name], candidate[name])
		}
		changed = changed || candidate[name] > current[name]
	}
	return changed, nil
}

func currentVersions(data string) (map[string]uint64, error) {
	current := filepath.Join(data, "current")
	if _, err := os.Lstat(current); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	result, err := versions(current)
	if err != nil {
		return nil, fmt.Errorf("current ClamAV database is incomplete: %w", err)
	}
	return result, nil
}

func newDatabaseStage(data string) (string, error) {
	dir := filepath.Join(data, "sets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(dir, ".incoming-*")
}

func seedDatabase(ctx context.Context, assets, data, engine, arch, socket string) error {
	seed := filepath.Join(assets, "database")
	current, err := currentVersions(data)
	if err != nil {
		return err
	}
	candidate, err := versions(seed)
	if err != nil {
		if len(current) != 0 {
			return nil
		}
		return fmt.Errorf("offline ClamAV database unavailable: %w", err)
	}
	changed, err := compareVersions(current, candidate)
	if err != nil {
		// An older offline package must never replace a newer installed set.
		if len(current) != 0 {
			return nil
		}
		return err
	}
	if !changed {
		return nil
	}
	stage, err := newDatabaseStage(data)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, name := range databaseNames {
		if err := copyAtomic(filepath.Join(seed, name+".cvd"), filepath.Join(stage, name+".cvd"), 0o600); err != nil {
			return err
		}
	}
	return validateAndCommit(ctx, data, stage, engine, arch, socket)
}

func validateSet(ctx context.Context, stage, engine, arch string) error {
	if _, err := versions(stage); err != nil {
		return err
	}
	for _, name := range databaseNames {
		path, _ := databasePath(stage, name)
		if !strings.HasSuffix(path, ".cvd") {
			// CLD files are produced only by verified FreshClam incremental
			// updates and travel from the manager over authenticated TLS.
			continue
		}
		verifyCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		output, err := engineCommand(verifyCtx, engine, arch, "bin/sigtool", "--info", path).CombinedOutput()
		cancel()
		if err != nil || !strings.Contains(string(output), "Verification OK.") {
			return fmt.Errorf("ClamAV signature verification failed for %s: %s", name, strings.TrimSpace(string(output)))
		}
	}
	// A signed database can still be unusable with this engine. Load all three
	// together before changing the active pointer, retaining the old set on error.
	probe := filepath.Join(stage, ".nodewall-healthcheck")
	if err := os.WriteFile(probe, []byte("NodeWall ClamAV database health check\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(probe)
	loadCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	output, err := engineCommand(loadCtx, engine, arch, "bin/clamscan", "--database="+stage, "--no-summary", probe).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ClamAV database load failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func validateAndCommit(ctx context.Context, data, stage, engine, arch, socket string) error {
	candidate, err := versions(stage)
	if err != nil {
		return err
	}
	current, err := currentVersions(data)
	if err != nil {
		return err
	}
	changed, err := compareVersions(current, candidate)
	if err != nil || !changed {
		return err
	}
	if err := validateSet(ctx, stage, engine, arch); err != nil {
		return err
	}
	oldTarget, _ := os.Readlink(filepath.Join(data, "current"))
	final := filepath.Join(data, "sets", fmt.Sprintf("set-%d", time.Now().UnixNano()))
	if err := os.Rename(stage, final); err != nil {
		return err
	}
	target := filepath.Join("sets", filepath.Base(final))
	if err := swapCurrent(data, target); err != nil {
		return err
	}
	if socket != "" {
		if err := reloadDatabase(ctx, socket, candidate["daily"]); err != nil {
			if oldTarget != "" {
				if restoreErr := swapCurrent(data, oldTarget); restoreErr != nil {
					return fmt.Errorf("reload ClamAV: %v; restore previous database: %w", err, restoreErr)
				}
				_, _ = clamCommand(socket, "RELOAD")
			}
			return fmt.Errorf("reload ClamAV database: %w", err)
		}
	}
	pruneSets(data, target, oldTarget)
	return nil
}

func swapCurrent(data, target string) error {
	link := filepath.Join(data, fmt.Sprintf(".current-%d", time.Now().UnixNano()))
	if err := os.Symlink(target, link); err != nil {
		return err
	}
	defer os.Remove(link)
	return os.Rename(link, filepath.Join(data, "current"))
}

func pruneSets(data, current, previous string) {
	entries, err := os.ReadDir(filepath.Join(data, "sets"))
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() > entries[j].Name() })
	for _, entry := range entries {
		relative := filepath.Join("sets", entry.Name())
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "set-") || relative == current || relative == previous {
			continue
		}
		_ = os.RemoveAll(filepath.Join(data, relative))
	}
}

func clamCommand(socket, command string) (string, error) {
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "z"+command+"\x00"); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString(0)
	return strings.TrimSuffix(reply, "\x00"), err
}

func reloadDatabase(ctx context.Context, socket string, daily uint64) error {
	if _, err := os.Stat(socket); errors.Is(err, os.ErrNotExist) {
		return nil // clamd will load the new set on its next start.
	}
	reply, err := clamCommand(socket, "RELOAD")
	if err != nil || !strings.Contains(strings.ToUpper(reply), "RELOADING") {
		return fmt.Errorf("reload request failed: %s %v", reply, err)
	}
	deadline := time.NewTimer(3 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("daemon did not report the updated daily database")
		case <-ticker.C:
			version, err := clamCommand(socket, "VERSION")
			parts := strings.Split(version, "/")
			if err == nil && len(parts) >= 2 {
				loaded, _ := strconv.ParseUint(parts[1], 10, 64)
				if loaded >= daily {
					return nil
				}
			}
		}
	}
}

func updateFromUpstream(ctx context.Context, data, engine, arch, socket string) error {
	stage, err := newDatabaseStage(data)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	current := filepath.Join(data, "current")
	for _, name := range databaseNames {
		path, err := databasePath(current, name)
		if err != nil {
			return err
		}
		if err := copyAtomic(path, filepath.Join(stage, filepath.Base(path)), 0o600); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(data, "freshclam.dat")); err == nil {
		if err := copyAtomic(filepath.Join(data, "freshclam.dat"), filepath.Join(stage, "freshclam.dat"), 0o600); err != nil {
			return err
		}
	}
	config := fmt.Sprintf("DatabaseDirectory %s\nDatabaseOwner root\nDatabaseMirror database.clamav.net\nScriptedUpdates yes\nCompressLocalDatabase yes\nTestDatabases yes\n", stage)
	configFile := filepath.Join(stage, "freshclam.conf")
	if err := os.WriteFile(configFile, []byte(config), 0o600); err != nil {
		return err
	}
	updateCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	output, err := engineCommand(updateCtx, engine, arch, "bin/freshclam", "--config-file="+configFile).CombinedOutput()
	// FreshClam records mirror cooldowns here, including after a failed fetch.
	// Keep them outside the temporary set so retries respect upstream limits.
	if _, statErr := os.Stat(filepath.Join(stage, "freshclam.dat")); statErr == nil {
		if saveErr := copyAtomic(filepath.Join(stage, "freshclam.dat"), filepath.Join(data, "freshclam.dat"), 0o600); saveErr != nil {
			return fmt.Errorf("save FreshClam state: %w", saveErr)
		}
	}
	if err != nil {
		if len(output) > 4096 {
			output = output[len(output)-4096:]
		}
		return fmt.Errorf("FreshClam update failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return validateAndCommit(ctx, data, stage, engine, arch, socket)
}
