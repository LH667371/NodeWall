//go:build linux

package securityscan

import (
	"os/exec"
	"testing"
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
	if err := cmd.Wait(); err == nil {
		t.Fatal("child exited successfully after termination")
	}
}
