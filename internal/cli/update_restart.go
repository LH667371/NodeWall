package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// updateRestartNeedsIsolation identifies updaters launched by an agent. A
// systemd service kills every process in its cgroup when restarted, even if a
// child has its own session; SysV scripts can similarly kill a process group.
func updateRestartNeedsIsolation(installDir string) (bool, bool) {
	data, _ := os.ReadFile("/proc/self/cgroup")
	agentCgroup, serviceCgroup := updateCgroupMembership(string(data))
	parentIsAgent := processMatchesRole(os.Getppid(), installDir, "agent")
	return agentCgroup || parentIsAgent, serviceCgroup
}

func updateCgroupMembership(contents string) (agent, service bool) {
	for _, line := range strings.Split(contents, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		for _, component := range strings.Split(fields[2], "/") {
			if strings.HasSuffix(component, ".service") {
				service = true
			}
			if component == "nodewall-agent.service" {
				agent = true
			}
		}
	}
	return agent, service
}

// scheduleUpdateServiceRestart starts the final restart from a separate
// supervisor unit when systemd is active. A new process session alone cannot
// escape a service cgroup. On SysV/direct installs it creates a new session so
// the init script's process-group signal does not also kill the updater.
func scheduleUpdateServiceRestart(installDir, configDir, systemdDir string, inServiceCgroup bool) error {
	binary := filepath.Join(installDir, "bin", "nodewall")
	args := []string{"update", "--internal-finalize-update", "--install-dir=" + installDir, "--config-dir=" + configDir, "--systemd-dir=" + systemdDir}
	if systemdUsable() {
		runner, err := exec.LookPath("systemd-run")
		if err != nil {
			return fmt.Errorf("cannot safely restart NodeWall services: systemd-run is unavailable: %w", err)
		}
		unit := fmt.Sprintf("nodewall-update-restart-%d-%d.service", os.Getpid(), time.Now().UnixNano())
		runnerArgs := []string{"--unit=" + unit, "--description=NodeWall update service restart"}
		// The system manager does not inherit an agent's environment. Preserve
		// these explicit installation overrides without copying credentials.
		for _, key := range []string{"NODEWALL_INIT_DIR", "NODEWALL_SYSTEMD_DIR"} {
			if value, ok := os.LookupEnv(key); ok {
				runnerArgs = append(runnerArgs, "--setenv="+key+"="+value)
			}
		}
		runnerArgs = append(runnerArgs, binary)
		runnerArgs = append(runnerArgs, args...)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(ctx, runner, runnerArgs...).CombinedOutput(); err != nil {
			return fmt.Errorf("schedule isolated NodeWall service restart: %w: %s", err, strings.TrimSpace(string(output)))
		}
		fmt.Printf("[NodeWall] 服务重启任务：%s（journalctl -u %s）\n", unit, unit)
		return nil
	}
	if inServiceCgroup {
		return fmt.Errorf("cannot safely restart NodeWall services while systemd is unavailable and the updater is inside a service cgroup")
	}
	return startUpdateRestartSession(binary, args, filepath.Join("/var/log/nodewall", "update-services.log"))
}

func startUpdateRestartSession(binary string, args []string, logPath string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("prepare update restart log: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open update restart log: %w", err)
	}
	defer logFile.Close()
	cmd := exec.Command(binary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start isolated NodeWall service restart: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("detach NodeWall service restart: %w", err)
	}
	fmt.Printf("[NodeWall] 服务重启日志：%s\n", logPath)
	return nil
}

func finishUpdateServiceRestart(installDir, configDir string) error {
	envPath := filepath.Join(configDir, "nodewall.env")
	if _, err := os.Stat(envPath); err != nil {
		return fmt.Errorf("read NodeWall installation configuration: %w", err)
	}
	manager := serviceManagerFromEnv(envPath)
	if manager != serviceManagerSystemd && manager != serviceManagerSysV && manager != serviceManagerNone {
		manager = serviceManagerSystemd
	}
	mode := readEnvValue(envPath, "NODEWALL_INSTALL_MODE", "all-in-one")
	// Older standby installations sometimes say agent-only even though their
	// management server is active. Restart the observed server as well.
	if strings.EqualFold(strings.TrimSpace(mode), "agent-only") && nodeWallRoleRunning(installDir, "server") {
		mode = "all-in-one"
		if err := upsertEnvValue(envPath, "NODEWALL_INSTALL_MODE", mode); err != nil {
			return err
		}
	}
	switch manager {
	case serviceManagerSystemd:
		if systemdUsable() {
			return restartSystemdServices(installDir, mode)
		}
		// Older installers could record systemd while its bus was offline and
		// launch services directly. Preserve their existing recovery path.
		if err := upsertEnvValue(envPath, "NODEWALL_SERVICE_MANAGER", serviceManagerNone); err != nil {
			return err
		}
		return restartDirectServices(installDir, configDir, mode)
	case serviceManagerSysV:
		if err := installSysVServices(installDir, configDir, mode); err != nil {
			return err
		}
		return restartSysVServices(mode)
	default:
		return restartDirectServices(installDir, configDir, mode)
	}
}
