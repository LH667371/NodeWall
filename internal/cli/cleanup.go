package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nodewall/internal/sshpolicy"
	"nodewall/internal/xdp"
)

func cleanupInstallation(installDir, configDir, systemdDir string) error {
	installDir = filepath.Clean(strings.TrimSpace(installDir))
	configDir = filepath.Clean(strings.TrimSpace(configDir))
	systemdDir = filepath.Clean(strings.TrimSpace(systemdDir))
	for label, path := range map[string]string{"install": installDir, "config": configDir, "systemd": systemdDir} {
		if path == "." || path == string(filepath.Separator) || !filepath.IsAbs(path) {
			return fmt.Errorf("refusing cleanup of unsafe %s path %q", label, path)
		}
	}
	envPath := filepath.Join(configDir, "nodewall.env")
	manager := serviceManagerFromEnv(envPath)
	if err := stopInstalledServices(manager, systemdDir); err != nil {
		return err
	}
	if err := stopDirectProcesses(installDir); err != nil {
		return err
	}
	// Restore sshd while the installed helper and its recovery state still
	// exist. A failed validation or reload leaves all files in place so a
	// later local-console retry has a recovery path.
	restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer restoreCancel()
	if err := sshpolicy.New().Restore(restoreCtx); err != nil {
		return fmt.Errorf("restore SSH configuration: %w", err)
	}
	if err := detachPersistedDataplane(envPath, configDir, installDir); err != nil {
		return fmt.Errorf("detach NodeWall dataplane: %w", err)
	}
	keyPath := readEnvValue(envPath, "NODEWALL_SSH_KEY", filepath.Join(configDir, "ssh", "id_ed25519"))
	if err := restoreConsoleAccess("/root/.ssh", configDir, keyPath); err != nil {
		return fmt.Errorf("restore root SSH authorized_keys: %w", err)
	}
	if err := removeSysVArtifacts(manager, systemdDir); err != nil {
		return err
	}
	if err := removeOwnedDir(installDir, nodewallOwnedRuntimeEntries()); err != nil {
		return fmt.Errorf("remove NodeWall runtime: %w", err)
	}
	ownedConfigEntries, err := nodewallOwnedConfigEntries(configDir, envPath)
	if err != nil {
		return fmt.Errorf("collect NodeWall configuration ownership: %w", err)
	}
	if err := removeOwnedDir(configDir, ownedConfigEntries); err != nil {
		return fmt.Errorf("remove NodeWall configuration: %w", err)
	}
	return nil
}

func nodewallOwnedRuntimeEntries() map[string]bool {
	return map[string]bool{"bin": true, "bpf": true, "web": true, "clamav": true, "VERSION": true, "PACKAGE_VERSION": true}
}

// nodewallOwnedConfigEntries is the single cleanup ownership list. In
// addition to the known persisted files, it derives paths from NODEWALL_*
// settings so a new version's explicitly configured state file is removed on
// uninstall without widening cleanup to arbitrary administrator data.
func nodewallOwnedConfigEntries(configDir, envPath string) (map[string]bool, error) {
	allowed := map[string]bool{
		"nodewall.env":                true,
		"agent-state.json":            true,
		"server-state.json":           true,
		"agent-token":                 true,
		"node-credentials.json":       true,
		"auth.json":                   true,
		"auth-settings.json":          true,
		"smtp-settings.json":          true,
		"cluster.key":                 true,
		"drop-log-state.json":         true,
		"ssh-protection.json":         true,
		"ssh-transfer-state.json":     true,
		"ssh-transfer-integrity.json": true,
		"ssh-console-access.json":     true,
		"ssh":                         true,
		"tls":                         true,
	}
	data, err := os.ReadFile(envPath)
	if errors.Is(err, os.ErrNotExist) {
		return allowed, nil
	}
	if err != nil {
		return nil, err
	}
	configDir = filepath.Clean(configDir)
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "NODEWALL_") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "\"'")
		if !filepath.IsAbs(value) {
			continue
		}
		relative, relErr := filepath.Rel(configDir, filepath.Clean(value))
		if relErr != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		first := strings.Split(relative, string(filepath.Separator))[0]
		if first != "" && first != "." {
			allowed[first] = true
		}
	}
	return allowed, nil
}

func stopInstalledServices(manager, systemdDir string) error {
	var errs []error
	if manager == serviceManagerSystemd {
		for _, unit := range []string{"nodewall-server.service", "nodewall-agent.service"} {
			unitPath := filepath.Join(systemdDir, unit)
			wantsPath := filepath.Join(systemdDir, "multi-user.target.wants", unit)
			if _, unitErr := os.Stat(unitPath); errors.Is(unitErr, os.ErrNotExist) {
				if _, wantsErr := os.Lstat(wantsPath); errors.Is(wantsErr, os.ErrNotExist) {
					continue
				}
			}
			if _, err := runCommandOutput("systemctl", "disable", "--now", unit); err != nil {
				errs = append(errs, fmt.Errorf("stop %s: %w", unit, err))
			}
		}
		if len(errs) == 0 {
			if err := runCommand("systemctl", "daemon-reload"); err != nil {
				errs = append(errs, fmt.Errorf("reload systemd after NodeWall removal: %w", err))
			}
		}
	}
	if manager == serviceManagerSysV {
		for _, role := range []string{"agent", "server"} {
			path := serviceScriptPath(role)
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				continue
			}
			if _, err := runCommandOutput(path, "stop"); err != nil {
				errs = append(errs, fmt.Errorf("stop %s: %w", path, err))
			}
		}
	}
	return errors.Join(errs...)
}

func stopDirectProcesses(installDir string) error {
	var errs []error
	for _, role := range []string{"agent", "server"} {
		for _, pidPath := range []string{filepath.Join("/var/run", "nodewall-"+role+".pid"), filepath.Join("/run/nodewall", role+".pid")} {
			pidData, err := os.ReadFile(pidPath)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("read %s: %w", pidPath, err))
				continue
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
			if err != nil || pid <= 1 {
				_ = os.Remove(pidPath)
				continue
			}
			if !managedProcess(pid, installDir, role) {
				// Never signal a process merely because a stale pid file exists.
				_ = os.Remove(pidPath)
				continue
			}
			process, err := os.FindProcess(pid)
			if err == nil {
				_ = process.Signal(syscall.SIGTERM)
			}
			if !waitProcessExit(pid, 15*time.Second) {
				if managedProcess(pid, installDir, role) && err == nil {
					_ = process.Signal(syscall.SIGKILL)
				}
				if !waitProcessExit(pid, 5*time.Second) {
					errs = append(errs, fmt.Errorf("NodeWall %s process %d did not stop", role, pid))
					continue
				}
			}
			_ = os.Remove(pidPath)
		}
	}
	return errors.Join(errs...)
}

func managedProcess(pid int, installDir, role string) bool {
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return false
	}
	expected := filepath.Join(installDir, "bin", "nodewall")
	if exe != expected && exe != expected+" (deleted)" {
		return false
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	return err == nil && slices.Contains(strings.Fields(string(bytesReplaceNUL(cmdline))), role)
}

func bytesReplaceNUL(data []byte) []byte {
	return []byte(strings.ReplaceAll(string(data), "\x00", " "))
}

func waitProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); errors.Is(err, os.ErrNotExist) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func detachPersistedDataplane(envPath, configDir, installDir string) error {
	statePath := readEnvValue(envPath, "NODEWALL_AGENT_STATE", filepath.Join(configDir, "agent-state.json"))
	data, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var runtimes map[string]json.RawMessage
	if err := json.Unmarshal(data, &runtimes); err != nil {
		return fmt.Errorf("decode agent state: %w", err)
	}
	if len(runtimes) == 0 {
		return nil
	}
	mode := strings.ToLower(readEnvValue(envPath, "NODEWALL_DATAPLANE", "real"))
	var plane interface {
		Detach(string) error
	}
	if mode == "iptables" || mode == "legacy" || mode == "zstack-iptables" {
		plane = xdp.NewIPTablesManager()
	} else {
		object := readEnvValue(envPath, "NODEWALL_BPF_OBJECT", filepath.Join(installDir, "bpf", "gen", "xdpacl_bpfel.o"))
		dataplane, err := xdp.NewDataplane(mode, object)
		if err != nil {
			return fmt.Errorf("open dataplane for recovery: %w", err)
		}
		plane = dataplane
	}
	var errs []error
	for iface := range runtimes {
		if err := plane.Detach(iface); err != nil {
			errs = append(errs, fmt.Errorf("detach %s: %w", iface, err))
		}
	}
	return errors.Join(errs...)
}

func removeSysVArtifacts(manager, systemdDir string) error {
	if manager == serviceManagerSysV {
		removeSysVServices()
		for _, role := range []string{"agent", "server"} {
			path := serviceScriptPath(role)
			backup := path + ".nodewall-backup"
			if data, err := os.ReadFile(backup); err == nil {
				if writeErr := os.WriteFile(path, data, 0o755); writeErr != nil {
					return writeErr
				}
				if info, statErr := os.Stat(backup); statErr == nil {
					if chmodErr := os.Chmod(path, info.Mode().Perm()); chmodErr != nil {
						return chmodErr
					}
				} else {
					return statErr
				}
				if removeErr := os.Remove(backup); removeErr != nil {
					return removeErr
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		cronPath := filepath.Join(envOr("NODEWALL_CRON_DIR", "/etc/cron.d"), "nodewall")
		if data, err := os.ReadFile(cronPath + ".nodewall-backup"); err == nil {
			if writeErr := os.WriteFile(cronPath, data, 0o644); writeErr != nil {
				return writeErr
			}
			if info, statErr := os.Stat(cronPath + ".nodewall-backup"); statErr == nil {
				if chmodErr := os.Chmod(cronPath, info.Mode().Perm()); chmodErr != nil {
					return chmodErr
				}
			} else {
				return statErr
			}
			if removeErr := os.Remove(cronPath + ".nodewall-backup"); removeErr != nil {
				return removeErr
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	var errs []error
	if manager == serviceManagerSystemd {
		for _, unit := range []string{"nodewall-server.service", "nodewall-agent.service"} {
			path := filepath.Join(systemdDir, unit)
			backup := path + ".nodewall-backup"
			restored := false
			if data, err := os.ReadFile(backup); err == nil {
				backupInfo, statErr := os.Stat(backup)
				if statErr != nil {
					errs = append(errs, statErr)
					continue
				}
				if err := os.WriteFile(path, data, 0o644); err != nil {
					errs = append(errs, err)
					continue
				}
				if err := os.Chmod(path, backupInfo.Mode().Perm()); err != nil {
					errs = append(errs, err)
					continue
				}
				if err := os.Remove(backup); err != nil {
					errs = append(errs, err)
				}
				restored = true
			} else if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
				continue
			}
			if !restored {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
			}
			if !restored {
				wants := filepath.Join(systemdDir, "multi-user.target.wants", unit)
				if target, err := os.Readlink(wants); err == nil {
					resolved := target
					if !filepath.IsAbs(resolved) {
						resolved = filepath.Join(filepath.Dir(wants), resolved)
					}
					if filepath.Clean(resolved) == filepath.Clean(path) {
						if err := os.Remove(wants); err != nil && !errors.Is(err, os.ErrNotExist) {
							errs = append(errs, err)
						}
					}
				} else if !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

func removeOwnedDir(root string, allowed map[string]bool) error {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] && !isOwnedBackupName(entry.Name(), allowed) {
			return fmt.Errorf("refusing to delete unknown file %s; remove it or pass a corrected installation path", filepath.Join(root, entry.Name()))
		}
	}
	return os.RemoveAll(root)
}

func isOwnedBackupName(name string, allowed map[string]bool) bool {
	for generation := 1; generation <= 3; generation++ {
		suffix := fmt.Sprintf(".bak.%d", generation)
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		return allowed[strings.TrimSuffix(name, suffix)]
	}
	return false
}
