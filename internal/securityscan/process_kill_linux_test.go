//go:build linux

package securityscan

import (
	"bufio"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestTerminateProcessUsesKernelHandleForLiveChild(t *testing.T) {
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	result, err := TerminateProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("terminate process: %v", err)
	}
	if result.Method != "pidfd" && result.Method != "kill-syscall" {
		t.Fatalf("unexpected termination method: %#v", result)
	}
	if !result.Exited {
		t.Fatalf("termination succeeded without confirming exit: %#v", result)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child exited successfully after termination")
	}
}

func TestLegacyTerminationEscalatesWhenTermIgnored(t *testing.T) {
	cmd := exec.Command("sh", "-c", "trap '' TERM; echo ready; exec sleep 30")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("child not ready: %q, %v", line, err)
	}
	result, err := terminateLegacyProcess(cmd.Process.Pid, 100*time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatalf("terminate legacy process: %v", err)
	}
	if result.Method != "kill-syscall" || !result.Forced || result.Signal != "SIGKILL" || !result.Exited {
		t.Fatalf("unexpected legacy termination result: %#v", result)
	}
}

func TestLegacyIdentityDetectsPIDReuse(t *testing.T) {
	identity, err := readLegacyProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	identity.startTime += "0"
	exited, err := legacyProcessExited(os.Getpid(), identity)
	if err != nil || !exited {
		t.Fatalf("changed identity should stop further signals: exited=%t err=%v", exited, err)
	}
}
