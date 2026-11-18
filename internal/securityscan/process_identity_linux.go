//go:build linux

package securityscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// processIdentity ties a bounded, complete executable hash to one process
// instance. It is unavailable if procfs or the executable cannot be verified.
type processIdentity struct {
	start, executable, sha256, mode string
	size                            int64
	deleted                         bool
}

// ReadProcessStartTime returns the kernel start time in clock ticks since boot.
func ReadProcessStartTime(pid int) (string, error) {
	if pid <= 1 {
		return "", fmt.Errorf("invalid process PID %d", pid)
	}
	identity, err := readLegacyProcessIdentity(pid)
	if err != nil {
		return "", fmt.Errorf("read PID %d start time: %w", pid, err)
	}
	if identity.state == "Z" || identity.state == "X" || identity.state == "x" {
		return "", fmt.Errorf("PID %d has exited", pid)
	}
	return identity.startTime, nil
}

func captureProcessIdentity(pid int) (processIdentity, error) {
	start, err := ReadProcessStartTime(pid)
	if err != nil {
		return processIdentity{}, err
	}
	procExe := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	path, err := os.Readlink(procExe)
	if err != nil {
		return processIdentity{}, fmt.Errorf("read PID %d executable: %w", pid, err)
	}
	file, err := os.Open(procExe)
	if err != nil {
		return processIdentity{}, fmt.Errorf("open PID %d executable: %w", pid, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > processHashLimit {
		return processIdentity{}, fmt.Errorf("PID %d executable cannot be fully verified", pid)
	}
	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(file, processHashLimit+1))
	if err != nil || n != info.Size() {
		return processIdentity{}, fmt.Errorf("hash PID %d executable: incomplete read", pid)
	}
	// Reopen procfs rather than a pathname, so an exec or a PID reuse cannot
	// silently associate the hash with a different executable.
	again, err := os.Stat(procExe)
	if err != nil || !os.SameFile(info, again) || again.Size() != info.Size() {
		return processIdentity{}, fmt.Errorf("PID %d executable changed while inspecting", pid)
	}
	end, err := ReadProcessStartTime(pid)
	if err != nil || end != start {
		return processIdentity{}, fmt.Errorf("PID %d identity changed while inspecting", pid)
	}
	endPath, err := os.Readlink(procExe)
	if err != nil || endPath != path {
		return processIdentity{}, fmt.Errorf("PID %d executable path changed while inspecting", pid)
	}
	display, deleted := normalizeDeletedExecutablePath(path)
	return processIdentity{start: start, executable: display, sha256: hex.EncodeToString(hasher.Sum(nil)), mode: info.Mode().Perm().String(), size: n, deleted: deleted}, nil
}

// VerifyProcessFinding rejects stale or incomplete evidence before any action.
func VerifyProcessFinding(finding Finding) error {
	if finding.Source == "fd-script" {
		_, err := ReadFDScriptSample(finding)
		return err
	}
	if finding.Source != "process" || finding.PID <= 1 || finding.ProcessStartTime == "" || finding.SHA256 == "" || finding.Size <= 0 || finding.Executable == "" {
		return fmt.Errorf("process finding lacks verified identity; run a new scan")
	}
	identity, err := captureProcessIdentity(finding.PID)
	if err != nil {
		return err
	}
	executable, _ := normalizeDeletedExecutablePath(finding.Executable)
	if identity.start != finding.ProcessStartTime || identity.executable != executable || identity.deleted != finding.Deleted || identity.sha256 != finding.SHA256 || identity.size != finding.Size {
		return fmt.Errorf("PID %d no longer matches the scanned process", finding.PID)
	}
	return nil
}

// VerifyProcessExecutablePath checks that the original pathname still names
// the executable opened by the process. This cannot make a later rename atomic
// with the check; callers must verify the moved inode and restore it on error.
func VerifyProcessExecutablePath(finding Finding) error {
	if finding.Deleted {
		return fmt.Errorf("PID %d executable is already deleted", finding.PID)
	}
	if err := VerifyProcessFinding(finding); err != nil {
		return err
	}
	file, err := os.OpenFile(finding.Executable, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open executable path: %w", err)
	}
	defer file.Close()
	pathInfo, err := file.Stat()
	if err != nil || !pathInfo.Mode().IsRegular() {
		return fmt.Errorf("executable path is not a regular file")
	}
	procInfo, err := os.Stat(filepath.Join("/proc", strconv.Itoa(finding.PID), "exe"))
	if err != nil || !os.SameFile(pathInfo, procInfo) {
		return fmt.Errorf("PID %d executable and path are different files", finding.PID)
	}
	// Check the path still resolves to the open inode after comparing procfs.
	current, err := os.Lstat(finding.Executable)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(pathInfo, current) {
		return fmt.Errorf("executable path changed during verification")
	}
	return VerifyProcessFinding(finding)
}

// ProcessFindingAfterIsolation updates a verified finding to the executable's
// new procfs path after isolation. The preserved target must still contain the
// exact bytes that were scanned; a renamed inode must match the running image.
func ProcessFindingAfterIsolation(finding Finding, target string) (Finding, error) {
	if finding.Deleted || target == "" {
		return Finding{}, fmt.Errorf("invalid isolation transition")
	}
	file, err := os.OpenFile(target, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return Finding{}, fmt.Errorf("open isolated executable: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != finding.Size || info.Size() <= 0 || info.Size() > processHashLimit {
		return Finding{}, fmt.Errorf("isolated executable size or type changed")
	}
	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(file, processHashLimit+1))
	if err != nil || n != finding.Size || hex.EncodeToString(hasher.Sum(nil)) != finding.SHA256 {
		return Finding{}, fmt.Errorf("isolated executable hash changed")
	}
	identity, err := captureProcessIdentity(finding.PID)
	if err != nil {
		return Finding{}, err
	}
	original, _ := normalizeDeletedExecutablePath(finding.Executable)
	if identity.start != finding.ProcessStartTime || identity.sha256 != finding.SHA256 || identity.size != finding.Size {
		return Finding{}, fmt.Errorf("PID %d no longer matches the scanned process", finding.PID)
	}
	if identity.deleted {
		// Cross-filesystem isolation copies the payload then unlinks the
		// original path; the running image keeps the unlinked original inode.
		if identity.executable != original {
			return Finding{}, fmt.Errorf("PID %d executable path changed unexpectedly", finding.PID)
		}
	} else {
		procInfo, statErr := os.Stat(filepath.Join("/proc", strconv.Itoa(finding.PID), "exe"))
		if statErr != nil || identity.executable != filepath.Clean(target) || !os.SameFile(info, procInfo) {
			return Finding{}, fmt.Errorf("isolated file is not PID %d executable", finding.PID)
		}
	}
	current, err := os.Lstat(target)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) {
		return Finding{}, fmt.Errorf("isolated executable changed during verification")
	}
	updated := finding
	updated.Executable = identity.executable
	updated.Deleted = identity.deleted
	if err := VerifyProcessFinding(updated); err != nil {
		return Finding{}, err
	}
	return updated, nil
}
