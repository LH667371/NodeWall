//go:build linux

package securityscan

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// ProcessTermination describes a kernel-mediated process action. pidfd keeps
// the target tied to the process that was inspected, avoiding a PID reuse race
// between a scan result and an operator's confirmed kill request.
type ProcessTermination struct {
	PID    int    `json:"pid"`
	Method string `json:"method"`
	Signal string `json:"signal"`
	Forced bool   `json:"forced"`
	Exited bool   `json:"exited"`
}

func kernelProcessExists(pid int) bool {
	if pid <= 1 {
		return false
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err == nil {
		_ = unix.Close(fd)
		return true
	}
	if err != unix.ENOSYS && err != unix.EINVAL {
		return false
	}
	// Kernels before pidfd support still perform the query in the kernel. The
	// fallback is only used when the modern API is unavailable.
	err = unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}

func terminateProcess(pid int) (ProcessTermination, error) {
	result := ProcessTermination{PID: pid, Signal: "SIGTERM"}
	if pid <= 1 {
		return result, fmt.Errorf("refusing to terminate protected PID %d", pid)
	}

	fd, err := unix.PidfdOpen(pid, 0)
	if err == nil {
		defer unix.Close(fd)
		result.Method = "pidfd"
		if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
			return result, fmt.Errorf("send SIGTERM through pidfd: %w", err)
		}
		if waitPidfdExit(fd, 2*time.Second) {
			result.Exited = true
			return result, nil
		}
		result.Forced = true
		result.Signal = "SIGKILL"
		if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && err != unix.ESRCH {
			return result, fmt.Errorf("send SIGKILL through pidfd: %w", err)
		}
		result.Exited = waitPidfdExit(fd, 500*time.Millisecond)
		return result, nil
	}
	if err != unix.ENOSYS && err != unix.EINVAL {
		return result, fmt.Errorf("open pidfd for PID %d: %w", pid, err)
	}

	// Compatibility path for older kernels. It remains kernel-mediated but
	// cannot provide pidfd's PID-reuse guarantee, so the response identifies it.
	result.Method = "kill-syscall"
	if err := unix.Kill(pid, unix.SIGTERM); err != nil {
		return result, fmt.Errorf("send SIGTERM: %w", err)
	}
	return result, nil
}

// TerminateProcess is the operator-confirmed process action used by the API.
func TerminateProcess(pid int) (ProcessTermination, error) {
	return terminateProcess(pid)
}

func waitPidfdExit(fd int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		err := unix.PidfdSendSignal(fd, 0, nil, 0)
		if err == unix.ESRCH {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}
