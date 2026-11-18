//go:build linux

package securityscan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ProcessTermination describes a kernel-mediated process action. pidfd keeps
// signals tied to the same process during termination; callers must separately
// verify that the process still matches the original scan result.
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
	if err != unix.ENOSYS && err != unix.EINVAL && err != unix.EPERM {
		return false
	}
	// Kernels before pidfd support, and containers whose seccomp profile blocks
	// pidfd_open, still perform the query in the kernel. The fallback is only
	// used when the modern API is unavailable.
	err = unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}

func terminateProcess(pid int) (ProcessTermination, error) {
	return terminateProcessWithFinding(pid, nil)
}

func terminateProcessWithFinding(pid int, finding *Finding) (ProcessTermination, error) {
	result := ProcessTermination{PID: pid, Signal: "SIGTERM"}
	if pid <= 1 {
		return result, fmt.Errorf("refusing to terminate protected PID %d", pid)
	}

	fd, err := unix.PidfdOpen(pid, 0)
	if err == nil {
		defer unix.Close(fd)
		result.Method = "pidfd"
		if finding != nil {
			if err := VerifyProcessFinding(*finding); err != nil {
				return result, err
			}
		}
		if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
			if err == unix.ESRCH {
				// The process exited after verification but before the signal;
				// pidfd guarantees this cannot be a reused PID.
				result.Exited = true
				return result, nil
			}
			return result, fmt.Errorf("send SIGTERM through pidfd: %w", err)
		}
		if waitPidfdExit(fd, 2*time.Second) {
			result.Exited = true
			return result, nil
		}
		if finding != nil {
			if err := VerifyProcessFinding(*finding); err != nil {
				return result, err
			}
		}
		result.Forced = true
		result.Signal = "SIGKILL"
		if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && err != unix.ESRCH {
			return result, fmt.Errorf("send SIGKILL through pidfd: %w", err)
		}
		// A miner may be stuck in a brief uninterruptible I/O wait when SIGKILL is
		// delivered. Give the kernel enough time to publish pidfd readiness before
		// reporting an incomplete stop; callers still receive an error if the
		// process remains alive after the bounded wait.
		result.Exited = waitPidfdExit(fd, 2*time.Second)
		if !result.Exited {
			return result, fmt.Errorf("PID %d did not exit after SIGKILL", pid)
		}
		return result, nil
	}
	if err != unix.ENOSYS && err != unix.EINVAL && err != unix.EPERM {
		return result, fmt.Errorf("open pidfd for PID %d: %w", pid, err)
	}

	return terminateLegacyProcessWithFinding(pid, 2*time.Second, 2*time.Second, finding)
}

// TerminateProcess is the operator-confirmed process action used by the API.
func TerminateProcess(pid int) (ProcessTermination, error) {
	return terminateProcess(pid)
}

// TerminateProcessVerified checks the original scan evidence immediately
// before each signal. Older kernels cannot make procfs validation and kill
// atomic, so callers must still account for a small PID reuse race.
func TerminateProcessVerified(finding Finding) (ProcessTermination, error) {
	return terminateProcessWithFinding(finding.PID, &finding)
}

func waitPidfdExit(fd int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, int((remaining+time.Millisecond-1)/time.Millisecond))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false
		}
		if n > 0 && fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			return true
		}
	}
}

// legacyProcessIdentity binds the fallback to the kernel's start time, which
// distinguishes a reused PID. Without pidfd there is still a small race
// between checking /proc and sending a signal; fail closed if the identity
// cannot be checked, and never escalate against a different process.
type legacyProcessIdentity struct {
	startTime string
	state     string
}

func readLegacyProcessIdentity(pid int) (legacyProcessIdentity, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return legacyProcessIdentity{}, err
	}
	closeParen := strings.LastIndexByte(string(data), ')')
	if closeParen < 0 {
		return legacyProcessIdentity{}, fmt.Errorf("malformed process stat for PID %d", pid)
	}
	fields := strings.Fields(string(data[closeParen+1:]))
	// The first field after comm is state (field 3), and starttime is field 22.
	if len(fields) <= 19 {
		return legacyProcessIdentity{}, fmt.Errorf("short process stat for PID %d", pid)
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return legacyProcessIdentity{}, fmt.Errorf("invalid start time for PID %d: %w", pid, err)
	}
	return legacyProcessIdentity{state: fields[0], startTime: fields[19]}, nil
}

func legacyProcessExited(pid int, initial legacyProcessIdentity) (bool, error) {
	current, err := readLegacyProcessIdentity(pid)
	if errors.Is(err, os.ErrNotExist) {
		// A missing /proc entry alone is not proof of exit on a host where
		// proc visibility may be filtered. Confirm with the kernel first.
		if killErr := unix.Kill(pid, 0); killErr == unix.ESRCH {
			return true, nil
		} else if killErr != nil && killErr != unix.EPERM {
			return false, fmt.Errorf("check PID %d: %w", pid, killErr)
		}
		return false, fmt.Errorf("cannot verify identity of live PID %d", pid)
	}
	if err != nil {
		return false, fmt.Errorf("verify identity of PID %d: %w", pid, err)
	}
	// Zombies have exited even though kill(pid, 0) succeeds until reaped.
	return current.startTime != initial.startTime || current.state == "Z" || current.state == "X" || current.state == "x", nil
}

func waitLegacyExit(pid int, initial legacyProcessIdentity, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		exited, err := legacyProcessExited(pid, initial)
		if exited || err != nil {
			return exited, err
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func terminateLegacyProcess(pid int, termTimeout, killTimeout time.Duration) (ProcessTermination, error) {
	return terminateLegacyProcessWithFinding(pid, termTimeout, killTimeout, nil)
}

func terminateLegacyProcessWithFinding(pid int, termTimeout, killTimeout time.Duration, finding *Finding) (ProcessTermination, error) {
	result := ProcessTermination{PID: pid, Method: "kill-syscall", Signal: "SIGTERM"}
	initial, err := readLegacyProcessIdentity(pid)
	if err != nil {
		return result, fmt.Errorf("identify PID %d before termination: %w", pid, err)
	}
	if finding != nil && (finding.ProcessStartTime == "" || initial.startTime != finding.ProcessStartTime) {
		return result, fmt.Errorf("PID %d no longer matches the scanned process", pid)
	}
	if initial.state == "Z" || initial.state == "X" || initial.state == "x" {
		result.Exited = true
		return result, nil
	}
	if finding != nil {
		if err := VerifyProcessFinding(*finding); err != nil {
			return result, err
		}
	}
	if err := unix.Kill(pid, unix.SIGTERM); err != nil {
		if err == unix.ESRCH {
			result.Exited = true
			return result, nil
		}
		return result, fmt.Errorf("send SIGTERM: %w", err)
	}
	result.Exited, err = waitLegacyExit(pid, initial, termTimeout)
	if err != nil || result.Exited {
		return result, err
	}
	// Recheck immediately before escalation. PID reuse cannot be made atomic
	// on kernels without pidfd, but identity changes must never be ignored.
	result.Exited, err = legacyProcessExited(pid, initial)
	if err != nil || result.Exited {
		return result, err
	}
	if finding != nil {
		if err := VerifyProcessFinding(*finding); err != nil {
			return result, err
		}
	}
	result.Forced = true
	result.Signal = "SIGKILL"
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		if err == unix.ESRCH {
			result.Exited = true
			return result, nil
		}
		return result, fmt.Errorf("send SIGKILL: %w", err)
	}
	result.Exited, err = waitLegacyExit(pid, initial, killTimeout)
	if err != nil {
		return result, err
	}
	if !result.Exited {
		return result, fmt.Errorf("PID %d did not exit after SIGKILL", pid)
	}
	return result, nil
}
