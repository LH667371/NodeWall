package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestUpdateCgroupMembership(t *testing.T) {
	for _, tt := range []struct {
		name, contents string
		agent, service bool
	}{
		{"unified agent", "0::/system.slice/nodewall-agent.service\n", true, true},
		{"centos agent", "12:devices:/system.slice/nodewall-agent.service\n1:name=systemd:/system.slice/nodewall-agent.service\n", true, true},
		{"different supervisor", "0::/system.slice/other.service\n", false, true},
		{"unrelated scope", "0::/user.slice/session-7.scope\n", false, false},
		{"misleading unit name", "0::/system.slice/not-nodewall-agent.service\n", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			agent, service := updateCgroupMembership(tt.contents)
			if agent != tt.agent || service != tt.service {
				t.Fatalf("membership = (%t, %t), want (%t, %t)", agent, service, tt.agent, tt.service)
			}
		})
	}
}

func TestSystemdRestartIsScheduledAsIndependentUnit(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "args")
	for name, script := range map[string]string{
		"systemctl":   "#!/bin/sh\nprintf 'SystemState=running\\n'\n",
		"systemd-run": "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$NODEWALL_TEST_ARGS\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("NODEWALL_TEST_ARGS", capture)
	t.Setenv("NODEWALL_INIT_DIR", "/test/init dir")
	t.Setenv("NODEWALL_SYSTEMD_DIR", "/test/systemd dir")
	if err := scheduleUpdateServiceRestart("/test/install dir", "/test/config dir", "/test/systemd dir", true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, want := range []string{
		"--setenv=NODEWALL_INIT_DIR=/test/init dir", "--setenv=NODEWALL_SYSTEMD_DIR=/test/systemd dir",
		"/test/install dir/bin/nodewall", "update", "--internal-finalize-update",
		"--install-dir=/test/install dir", "--config-dir=/test/config dir", "--systemd-dir=/test/systemd dir",
	} {
		found := false
		for _, arg := range args {
			found = found || arg == want
		}
		if !found {
			t.Errorf("missing argument %q in %#v", want, args)
		}
	}
	if len(args) == 0 || !strings.HasPrefix(args[0], "--unit=nodewall-update-restart-") {
		t.Fatalf("a separate transient service was not requested: %#v", args)
	}
}

func TestRestartRefusesUnsafeSystemdFallback(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := scheduleUpdateServiceRestart("/unused", "/unused", "/unused", true); err == nil || !strings.Contains(err.Error(), "service cgroup") {
		t.Fatalf("expected an error instead of an unsafe in-cgroup restart, got %v", err)
	}
}

// Model the SysV init script terminating its old process group. The restart
// helper must survive that signal and continue after the original updater dies.
func TestRestartSessionSurvivesParentProcessGroupTermination(t *testing.T) {
	if os.Getenv("NODEWALL_TEST_RESTART_PARENT") == "1" {
		gate := os.Getenv("NODEWALL_TEST_RESTART_GATE")
		result := os.Getenv("NODEWALL_TEST_RESTART_RESULT")
		script := `while [ ! -e "$1" ]; do sleep 0.05; done; printf survived > "$2"`
		if err := startUpdateRestartSession("/bin/sh", []string{"-c", script, "restart-test", gate, result}, os.Getenv("NODEWALL_TEST_RESTART_LOG")); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		fmt.Println("restart-test-ready")
		time.Sleep(30 * time.Second)
		return
	}
	dir := t.TempDir()
	gate := filepath.Join(dir, "gate")
	result := filepath.Join(dir, "result")
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestartSessionSurvivesParentProcessGroupTermination$")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = append(os.Environ(), "NODEWALL_TEST_RESTART_PARENT=1", "NODEWALL_TEST_RESTART_GATE="+gate, "NODEWALL_TEST_RESTART_RESULT="+result, "NODEWALL_TEST_RESTART_LOG="+filepath.Join(dir, "restart.log"))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	reader := bufio.NewReader(stdout)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("updater did not start its helper: %v", err)
		}
		if strings.Contains(line, "restart-test-ready") {
			break
		}
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(result); err == nil && string(data) == "survived" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("restart helper did not survive termination of its original process group")
}

func TestFinalizerRestartsBothSystemdServices(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "systemctl.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$NODEWALL_TEST_SYSTEMCTL_LOG\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("NODEWALL_TEST_SYSTEMCTL_LOG", capture)
	if err := restartSystemdServices("/nonexistent/nodewall", "all-in-one"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	for _, want := range []string{"daemon-reload\n", "restart nodewall-agent.service\n", "restart nodewall-server.service\n"} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q in systemctl calls: %s", want, log)
		}
	}
}
