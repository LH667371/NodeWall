package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	serviceManagerAuto    = "auto"
	serviceManagerSystemd = "systemd"
	serviceManagerSysV    = "sysv"
	serviceManagerNone    = "none"
)

// resolveServiceManager selects the first boot supervisor that is actually
// usable. A broken systemctl must not prevent an installation from using
// traditional init scripts and cron's @reboot hook.
func resolveServiceManager(requested string) (string, error) {
	manager := strings.ToLower(strings.TrimSpace(requested))
	if manager == "" {
		manager = serviceManagerAuto
	}
	if manager != serviceManagerAuto && manager != serviceManagerSystemd && manager != serviceManagerSysV && manager != serviceManagerNone {
		return "", fmt.Errorf("invalid service manager %q; expected auto|systemd|sysv|none", requested)
	}
	if manager == serviceManagerNone {
		return manager, nil
	}
	if manager == serviceManagerSystemd || manager == serviceManagerAuto {
		if systemdUsable() {
			return serviceManagerSystemd, nil
		}
		if manager == serviceManagerSystemd {
			return "", fmt.Errorf("systemd is not available; use --service-manager=sysv or repair systemd")
		}
	}
	if manager == serviceManagerSysV || manager == serviceManagerAuto {
		if _, err := os.Stat("/etc/init.d"); err == nil {
			return serviceManagerSysV, nil
		}
		if manager == serviceManagerSysV {
			return "", fmt.Errorf("SysV init directory /etc/init.d is unavailable")
		}
	}
	return "", fmt.Errorf("no usable service manager found; install systemd, SysV init, or use --enable-services=false")
}

func systemdUsable() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// systemd 219 (CentOS 7) does not implement the newer --value flag.
	// The property-only form is supported by both old and new systemctl
	// versions and returns either `SystemState=running` or the bare value.
	output, err := exec.CommandContext(ctx, "systemctl", "show", "--property=SystemState").CombinedOutput()
	if err != nil {
		return false
	}
	switch parseSystemdStateOutput(string(output)) {
	case "", "offline", "unknown":
		return false
	default:
		return true
	}
}

func parseSystemdStateOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SystemState=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "SystemState="))
		}
	}
	return strings.TrimSpace(output)
}

func serviceManagerFromEnv(envPath string) string {
	manager := strings.ToLower(strings.TrimSpace(readEnvValue(envPath, "NODEWALL_SERVICE_MANAGER", serviceManagerSystemd)))
	// Older enrollment scripts wrote `none` after misdetecting CentOS 7's
	// systemd 219, but still created an enabled NodeWall unit. Once the probe is
	// fixed, converge that legacy state back to systemd automatically. An
	// explicit `none` install has no enabled unit and therefore remains direct.
	if manager == serviceManagerNone && hasEnabledSystemdNodeWallUnit() && systemdUsable() {
		return serviceManagerSystemd
	}
	if manager == serviceManagerAuto || manager == "" {
		if resolved, err := resolveServiceManager(serviceManagerAuto); err == nil {
			return resolved
		}
	}
	return manager
}

func hasEnabledSystemdNodeWallUnit() bool {
	wantsDir := filepath.Join(envOr("NODEWALL_SYSTEMD_DIR", defaultSystemdDir), "multi-user.target.wants")
	for _, role := range []string{"agent", "server"} {
		if _, err := os.Stat(filepath.Join(wantsDir, "nodewall-"+role+".service")); err == nil {
			return true
		}
	}
	return false
}

func serviceInitDir() string {
	return envOr("NODEWALL_INIT_DIR", "/etc/init.d")
}

func serviceScriptPath(name string) string {
	return filepath.Join(serviceInitDir(), "nodewall-"+name)
}

func installSysVServices(installDir, configDir, mode string) error {
	initDir := serviceInitDir()
	if err := os.MkdirAll(initDir, 0o755); err != nil {
		return err
	}
	if mode != "server-only" {
		if err := backupOrCheckSysVScript(serviceScriptPath("agent"), "agent"); err != nil {
			return err
		}
		if err := writeFileAtomic(serviceScriptPath("agent"), []byte(sysVServiceScript(installDir, configDir, "agent")), 0o755); err != nil {
			return err
		}
		if err := registerSysVService("nodewall-agent"); err != nil {
			return err
		}
	} else {
		if err := backupOrCheckSysVScript(serviceScriptPath("agent"), "agent"); err != nil {
			return err
		}
		_ = unregisterSysVService("nodewall-agent")
		_ = os.Remove(serviceScriptPath("agent"))
	}
	if mode != "agent-only" {
		if err := backupOrCheckSysVScript(serviceScriptPath("server"), "server"); err != nil {
			return err
		}
		if err := writeFileAtomic(serviceScriptPath("server"), []byte(sysVServiceScript(installDir, configDir, "server")), 0o755); err != nil {
			return err
		}
		if err := registerSysVService("nodewall-server"); err != nil {
			return err
		}
	} else {
		if err := backupOrCheckSysVScript(serviceScriptPath("server"), "server"); err != nil {
			return err
		}
		_ = unregisterSysVService("nodewall-server")
		_ = os.Remove(serviceScriptPath("server"))
	}
	return installCronRebootHook(mode)
}

func registerSysVService(name string) error {
	if command, err := exec.LookPath("chkconfig"); err == nil {
		if _, err := runCommandOutput(command, "--add", name); err != nil {
			return err
		}
		_, err = runCommandOutput(command, name, "on")
		return err
	}
	if command, err := exec.LookPath("update-rc.d"); err == nil {
		_, err = runCommandOutput(command, name, "defaults")
		return err
	}
	// Cron is a useful final fallback on hosts whose traditional init tooling
	// is damaged but whose cron daemon still starts at boot.
	return nil
}

func unregisterSysVService(name string) error {
	if command, err := exec.LookPath("chkconfig"); err == nil {
		_, _ = runCommandOutput(command, name, "off")
		_, _ = runCommandOutput(command, "--del", name)
		return nil
	}
	if command, err := exec.LookPath("update-rc.d"); err == nil {
		_, _ = runCommandOutput(command, "-f", name, "remove")
	}
	return nil
}

func installCronRebootHook(mode string) error {
	cronDir := envOr("NODEWALL_CRON_DIR", "/etc/cron.d")
	if err := os.MkdirAll(cronDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(cronDir, "nodewall")
	if data, err := os.ReadFile(path); err == nil {
		if !strings.Contains(string(data), "nodewall-agent") && !strings.Contains(string(data), "nodewall-server") {
			return fmt.Errorf("refusing to overwrite existing non-NodeWall cron file %s", path)
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			return statErr
		}
		backup := path + ".nodewall-backup"
		if _, statErr := os.Stat(backup); os.IsNotExist(statErr) {
			if err := os.WriteFile(backup, data, info.Mode().Perm()); err != nil {
				return err
			}
			if err := os.Chmod(backup, info.Mode().Perm()); err != nil {
				return err
			}
		} else if statErr != nil {
			return statErr
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	lines := []string{"SHELL=/bin/sh", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", ""}
	if mode != "server-only" {
		lines = append(lines, "@reboot root "+serviceScriptPath("agent")+" start")
	}
	if mode != "agent-only" {
		lines = append(lines, "@reboot root "+serviceScriptPath("server")+" start")
	}
	return writeFileAtomic(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func backupOrCheckSysVScript(path, role string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.Contains(string(data), "# Provides:          nodewall-"+role) {
		return fmt.Errorf("refusing to overwrite existing non-NodeWall init script %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	backup := path + ".nodewall-backup"
	if _, statErr := os.Stat(backup); os.IsNotExist(statErr) {
		if err := os.WriteFile(backup, data, info.Mode().Perm()); err != nil {
			return err
		}
		return os.Chmod(backup, info.Mode().Perm())
	} else if statErr != nil {
		return statErr
	}
	return nil
}

func removeSysVServices() {
	for _, name := range []string{"nodewall-agent", "nodewall-server"} {
		_, _ = runCommandOutput(serviceScriptPath(strings.TrimPrefix(name, "nodewall-")), "stop")
		_ = unregisterSysVService(name)
		_ = os.Remove(serviceScriptPath(strings.TrimPrefix(name, "nodewall-")))
	}
	_ = os.Remove(filepath.Join(envOr("NODEWALL_CRON_DIR", "/etc/cron.d"), "nodewall"))
}

func startSysVServices(mode string) error {
	if mode != "server-only" {
		if _, err := runCommandOutput(serviceScriptPath("agent"), "start"); err != nil {
			return err
		}
	}
	if mode != "agent-only" {
		if _, err := runCommandOutput(serviceScriptPath("server"), "start"); err != nil {
			return err
		}
	}
	return nil
}

func restartSysVServices(mode string) error {
	if mode != "server-only" {
		if _, err := runCommandOutput(serviceScriptPath("agent"), "restart"); err != nil {
			return err
		}
	}
	if mode != "agent-only" {
		if _, err := runCommandOutput(serviceScriptPath("server"), "restart"); err != nil {
			return err
		}
	}
	return nil
}

// restartSystemdServices converges both the boot units and processes left
// behind by an older installer. `systemctl try-restart` is intentionally a
// no-op for an inactive unit, but older CentOS installations could have a
// manually launched NodeWall process still listening on the service port.
// Starting the new unit in that state would fail and leave the old binary
// serving the web console forever. Stop only NodeWall processes whose command
// line is explicitly `agent` or `server`, then enable and start the units.
func restartSystemdServices(installDir, mode string) error {
	if err := runCommandWithProgress("重载 systemd 配置", 30*time.Second, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	active := make(map[string]bool)
	needsOrphanCleanup := false
	for _, role := range []string{"agent", "server"} {
		if (role == "agent" && mode == "server-only") || (role == "server" && mode == "agent-only") {
			continue
		}
		unit := "nodewall-" + role + ".service"
		active[role] = systemdUnitActive(unit)
		if !active[role] {
			needsOrphanCleanup = true
		}
	}
	if needsOrphanCleanup {
		if err := stopOrphanNodeWallProcesses(installDir); err != nil {
			return err
		}
	}
	for _, role := range []string{"agent", "server"} {
		if (role == "agent" && mode == "server-only") || (role == "server" && mode == "agent-only") {
			continue
		}
		unit := "nodewall-" + role + ".service"
		if active[role] {
			if err := runCommandWithProgress("重启 NodeWall "+role+" 服务", 120*time.Second, "systemctl", "restart", unit); err != nil {
				return err
			}
		} else if err := runCommandWithProgress("启用并启动 NodeWall "+role+" 服务", 120*time.Second, "systemctl", "enable", "--now", unit); err != nil {
			return err
		}
	}
	return nil
}

// restartDirectServices is used for hosts where systemd is present on disk but
// its bus is unavailable (a common CentOS rescue/container setup). The
// enrollment script can still keep NodeWall reachable with direct processes;
// updates must replace those processes as well or the web console remains on
// the old embedded assets indefinitely.
func restartDirectServices(installDir, configDir, mode string) error {
	if err := stopOrphanNodeWallProcesses(installDir); err != nil {
		return err
	}
	for _, role := range []string{"agent", "server"} {
		if (role == "agent" && mode == "server-only") || (role == "server" && mode == "agent-only") {
			continue
		}
		bin := shellQuote(filepath.Join(installDir, "bin", "nodewall"))
		envFile := shellQuote(filepath.Join(configDir, "nodewall.env"))
		logFile := shellQuote(filepath.Join("/var/log/nodewall", role+".log"))
		pidFile := shellQuote(filepath.Join("/var/run/nodewall", role+".pid"))
		script := fmt.Sprintf("set -a; [ ! -r %s ] || . %s; set +a; mkdir -p %s %s; nohup %s %s >>%s 2>&1 </dev/null & echo $! >%s", envFile, envFile, shellQuote("/var/run/nodewall"), shellQuote("/var/log/nodewall"), bin, role, logFile, pidFile)
		if err := runCommandWithProgress("直接启动 NodeWall "+role+" 服务", 30*time.Second, "sh", "-c", script); err != nil {
			return err
		}
		if err := waitForDirectService(filepath.Join("/var/run/nodewall", role+".pid"), filepath.Join(installDir, "bin", "nodewall"), role, 5*time.Second); err != nil {
			logPath := filepath.Join("/var/log/nodewall", role+".log")
			if logData, readErr := os.ReadFile(logPath); readErr == nil {
				lines := strings.Split(strings.TrimSpace(string(logData)), "\n")
				if len(lines) > 40 {
					lines = lines[len(lines)-40:]
				}
				return fmt.Errorf("direct NodeWall %s failed to stay running: %w; recent log:\n%s", role, err, strings.Join(lines, "\n"))
			}
			return err
		}
	}
	return nil
}

func waitForDirectService(pidPath, installDir, role string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		pidData, err := os.ReadFile(pidPath)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(pidData)))
			if parseErr == nil && pid > 1 && processMatchesRole(pid, installDir, role) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pid file %s does not reference a running %s process", pidPath, role)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func processMatchesRole(pid int, installDir, role string) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	fields := strings.Fields(strings.ReplaceAll(string(cmdline), "\x00", " "))
	if len(fields) < 2 || fields[1] != role {
		return false
	}
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return false
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	return filepath.Clean(exe) == filepath.Clean(installDir) || strings.HasPrefix(filepath.Clean(exe), filepath.Clean(installDir)+string(filepath.Separator))
}

// nodeWallRoleRunning detects a role that was started outside the currently
// recorded service manager. This matters during upgrades from legacy
// agent-only installs: a local standby server may still own port 8086 even
// though the env file says only the Agent should be managed.
func nodeWallRoleRunning(installDir, role string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		if processMatchesRole(pid, installDir, role) {
			return true
		}
	}
	return false
}

func systemdUnitActive(unit string) bool {
	command, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, command, "is-active", "--quiet", unit).Run() == nil
}

func stopOrphanNodeWallProcesses(installDir string) error {
	if strings.TrimSpace(installDir) == "" || !strings.HasPrefix(filepath.Clean(installDir), string(filepath.Separator)) {
		return fmt.Errorf("invalid NodeWall install directory %q", installDir)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	root := filepath.Clean(installDir) + string(filepath.Separator)
	type process struct {
		pid int
		cmd string
	}
	var targets []process
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		exe, readErr := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if readErr != nil {
			continue
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		base := filepath.Base(exe)
		// Atomic replacement can leave a running process attached to an old
		// `/opt/nodewall/bin/nodewall.tmp.* (deleted)` inode. Treat those
		// updater-owned names as NodeWall too; otherwise a direct CentOS process
		// survives every update even though the installed path is current.
		if !strings.HasPrefix(filepath.Clean(exe), root) || !strings.HasPrefix(base, "nodewall") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if readErr != nil {
			continue
		}
		fields := strings.Fields(strings.ReplaceAll(string(data), "\x00", " "))
		if len(fields) < 2 || (fields[1] != "agent" && fields[1] != "server") {
			continue
		}
		targets = append(targets, process{pid: pid, cmd: strings.Join(fields, " ")})
	}
	for _, target := range targets {
		proc, findErr := os.FindProcess(target.pid)
		if findErr != nil {
			continue
		}
		if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("stop stale NodeWall process %d (%s): %w", target.pid, target.cmd, err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(targets) > 0 && time.Now().Before(deadline) {
		remaining := targets[:0]
		for _, target := range targets {
			if err := syscall.Kill(target.pid, 0); err == nil {
				remaining = append(remaining, target)
			}
		}
		if len(remaining) == 0 {
			return nil
		}
		targets = remaining
		time.Sleep(100 * time.Millisecond)
	}
	for _, target := range targets {
		if err := syscall.Kill(target.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("force stop stale NodeWall process %d (%s): %w", target.pid, target.cmd, err)
		}
	}
	return nil
}

func runCommandOutput(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(output)), fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func sysVServiceScript(installDir, configDir, role string) string {
	bin := shellQuote(filepath.Join(installDir, "bin", "nodewall"))
	envFile := shellQuote(filepath.Join(configDir, "nodewall.env"))
	pidFile := shellQuote(filepath.Join("/run/nodewall", role+".pid"))
	logFile := shellQuote(filepath.Join("/var/log/nodewall", role+".log"))
	return fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          nodewall-%[1]s
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: NodeWall %[1]s
### END INIT INFO

BIN=%[2]s
ENV_FILE=%[3]s
PID_FILE=%[4]s
LOG_FILE=%[5]s
mkdir -p "$(dirname "$PID_FILE")" "$(dirname "$LOG_FILE")"

is_running() {
  [ -s "$PID_FILE" ] || return 1
  kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null
}

start() {
  is_running && return 0
  rm -f "$PID_FILE"
  runner="$(command -v setsid 2>/dev/null || true)"
  if [ -n "$runner" ]; then
    "$runner" /bin/sh -c 'set -a; [ ! -r "$1" ] || . "$1"; set +a; trap "exit 0" TERM INT HUP; while :; do "$2" %[1]s; status=$?; [ "$status" -eq 0 ] && exit 0; sleep 2; done' nodewall "$ENV_FILE" "$BIN" >>"$LOG_FILE" 2>&1 </dev/null &
  else
    /bin/sh -c 'set -a; [ ! -r "$1" ] || . "$1"; set +a; trap "exit 0" TERM INT HUP; while :; do "$2" %[1]s; status=$?; [ "$status" -eq 0 ] && exit 0; sleep 2; done' nodewall "$ENV_FILE" "$BIN" >>"$LOG_FILE" 2>&1 </dev/null &
  fi
  echo $! >"$PID_FILE"
  sleep 1
  is_running
}

stop() {
  is_running || { rm -f "$PID_FILE"; return 0; }
  pid=$(cat "$PID_FILE")
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  i=0
  while [ $i -lt 20 ] && kill -0 "$pid" 2>/dev/null; do sleep 1; i=$((i+1)); done
  kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
}

status() { is_running; }

case "$1" in
  start) start ;;
  stop) stop ;;
  restart|force-reload) stop; start ;;
  status) status ;;
  *) echo "usage: $0 {start|stop|restart|status}" >&2; exit 2 ;;
esac
`, role, bin, envFile, pidFile, logFile)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
