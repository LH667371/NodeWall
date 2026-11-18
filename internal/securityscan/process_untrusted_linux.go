//go:build linux

package securityscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// collectTemporaryProcessFindings inspects low-CPU executables in transient
// locations. The path by itself is a review signal, never a malware verdict.
func collectTemporaryProcessFindings(ctx context.Context, limit int) ([]Finding, error) {
	if limit <= 0 {
		return nil, nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return findings, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		procExe := filepath.Join("/proc", entry.Name(), "exe")
		executable, err := os.Readlink(procExe)
		if err != nil || strings.HasSuffix(executable, " (deleted)") || !isTransientExecutablePath(executable) || isNodeWallArtifactPath(executable) {
			continue
		}
		pathInfo, err := os.Lstat(executable)
		if err != nil || !pathInfo.Mode().IsRegular() || isSystemPackageFile(executable) {
			continue
		}
		procInfo, err := os.Stat(procExe)
		if err != nil || !os.SameFile(pathInfo, procInfo) {
			continue
		}
		finding := processIntegrityFinding("suspicious-runtime-path", SeverityMedium, executable, pid,
			fmt.Sprintf("PID %d executes a file in a temporary directory; investigate its origin and startup chain", pid))
		if finding.ProcessStartTime == "" || finding.Executable != executable || finding.Deleted {
			continue
		}
		// A temporary location is not itself sufficient for automatic action.
		if finding.Rule == "suspicious-runtime-path" {
			finding.Quarantinable = false
		}
		finding.ParentPID, finding.ParentExecutable, finding.Cgroup = scriptProcessProvenance(pid)
		if start, startErr := ReadProcessStartTime(pid); startErr != nil || start != finding.ProcessStartTime {
			continue
		}
		findings = append(findings, finding)
		if len(findings) >= limit {
			break
		}
	}
	return findings, nil
}

func isTransientExecutablePath(path string) bool {
	clean := filepath.Clean(path)
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
