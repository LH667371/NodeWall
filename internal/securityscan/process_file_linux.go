//go:build linux

package securityscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// FindProcessesForFileFinding correlates a scanned ELF inode with live
// processes directly executing that inode. Interpreter arguments and matching
// names or hashes alone do not establish a safe process association.
func FindProcessesForFileFinding(ctx context.Context, finding Finding) ([]Finding, error) {
	if finding.Source != "file" || finding.Path == "" || finding.SHA256 == "" || finding.Size <= 0 || finding.Size > processHashLimit {
		return nil, fmt.Errorf("file finding lacks a complete executable hash and size")
	}
	if isNodeWallArtifactPath(finding.Path) {
		return nil, fmt.Errorf("refusing to correlate a NodeWall-owned file")
	}
	file, err := os.OpenFile(finding.Path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open scanned file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != finding.Size {
		return nil, fmt.Errorf("scanned file is no longer the expected regular file")
	}
	pathInfo, err := os.Lstat(finding.Path)
	if err != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		return nil, fmt.Errorf("scanned file path changed")
	}
	var magic [4]byte
	if n, _ := file.ReadAt(magic[:], 0); n != len(magic) || string(magic[:]) != "\x7fELF" {
		return nil, nil
	}
	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(file, processHashLimit+1))
	if err != nil || n != finding.Size || hex.EncodeToString(hasher.Sum(nil)) != finding.SHA256 {
		return nil, fmt.Errorf("scanned file content changed")
	}
	procPIDs, err := listNumericEntries("/proc")
	if err != nil {
		return nil, fmt.Errorf("enumerate process view: %w", err)
	}
	// A hidden process can be absent from /proc's directory listing while its
	// numeric proc entry remains accessible and its PID appears in cgroups.
	if err := collectCorrelationCgroupPIDs(ctx, procPIDs); err != nil {
		return nil, err
	}
	var matches []Finding
	for _, pid := range sortedPIDMap(procPIDs) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pid <= 1 || pid == os.Getpid() {
			continue
		}
		procExe := filepath.Join("/proc", strconv.Itoa(pid), "exe")
		procInfo, err := os.Stat(procExe)
		if err != nil || !os.SameFile(info, procInfo) {
			continue
		}
		process := processIntegrityFinding(finding.Rule, finding.Severity, finding.Path, pid,
			fmt.Sprintf("PID %d directly executes the scanned file %s", pid, finding.Path))
		if process.ProcessStartTime == "" || process.Deleted || process.SHA256 != finding.SHA256 || process.Size != finding.Size {
			continue
		}
		// Recheck the inode after enrichment: exec or PID reuse during the
		// metadata reads must not bind the scan finding to another process.
		procInfo, err = os.Stat(procExe)
		if err != nil || !os.SameFile(info, procInfo) || VerifyProcessFinding(process) != nil {
			continue
		}
		matches = append(matches, process)
	}
	pathInfo, err = os.Lstat(finding.Path)
	if err != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		return nil, fmt.Errorf("scanned file path changed during process correlation")
	}
	return matches, nil
}

func collectCorrelationCgroupPIDs(ctx context.Context, pids map[int]struct{}) error {
	err := filepath.WalkDir("/sys/fs/cgroup", func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil || entry == nil {
			return nil
		}
		if entry.IsDir() || entry.Name() != "cgroup.procs" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, field := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(field)
			if err == nil && pid > 1 {
				pids[pid] = struct{}{}
			}
		}
		return nil
	})
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	// Hosts without cgroup access still have the ordinary /proc view.
	return nil
}
