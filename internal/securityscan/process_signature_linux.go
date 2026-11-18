//go:build linux

package securityscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// scanProcessSignatures inspects the opened executable inode rather than a
// path from the command line. Its limits keep the quick scan bounded; the
// report exposes a coverage gap when more candidates remain.
func scanProcessSignatures(ctx context.Context, scanner Scanner, limit int) ([]Finding, bool, error) {
	return scanProcessSignaturesWithProgress(ctx, scanner, limit, nil)
}

// scanProcessSignaturesWithProgress keeps the quick scan observable while it
// checks live executable inodes. ClamAV only exposes a verdict after each
// stream, so the callback publishes the engine counters at a throttled rate.
func scanProcessSignaturesWithProgress(ctx context.Context, scanner Scanner, limit int, onProgress func(Progress)) ([]Finding, bool, error) {
	if limit <= 0 || scanner.signatures == nil || scanner.signatures.status.Status != "available" {
		return nil, false, nil
	}
	if scanner.MaxFileSize <= 0 {
		scanner.MaxFileSize = defaultMaxFileSize
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false, err
	}
	deadline := time.Now().Add(45 * time.Second)
	seen := make(map[string]*Finding)
	var findings []Finding
	checked := 0
	partial := false
	lastProgress := time.Time{}
	emitProgress := func(force bool) {
		if onProgress == nil {
			return
		}
		if !force && !lastProgress.IsZero() && time.Since(lastProgress) < 250*time.Millisecond {
			return
		}
		lastProgress = time.Now()
		onProgress(Progress{
			FilesScanned:    scanner.signatures.status.FilesScanned,
			BytesScanned:    scanner.signatures.status.BytesScanned,
			Phase:           "process",
			SignatureEngine: scanner.signatures.status,
		})
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return findings, partial, err
		}
		if checked >= 256 || time.Now().After(deadline) || len(findings) >= limit {
			partial = true
			break
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		procExe := filepath.Join("/proc", entry.Name(), "exe")
		path, err := os.Readlink(procExe)
		if err != nil {
			continue
		}
		display, _ := normalizeDeletedExecutablePath(path)
		if isNodeWallArtifactPath(display) {
			continue
		}
		file, err := os.Open(procExe)
		if err != nil {
			continue
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > scanner.MaxFileSize {
			_ = file.Close()
			if err == nil && info.Mode().IsRegular() && info.Size() > scanner.MaxFileSize {
				partial = true
			}
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			_ = file.Close()
			continue
		}
		key := fmt.Sprintf("%d:%d:%d:%d", stat.Dev, stat.Ino, info.Size(), info.ModTime().UnixNano())
		finding, exists := seen[key]
		if !exists {
			checked++
			finding, _, err = scanner.scanDescriptor(ctx, file, display, info)
			emitProgress(false)
			if err != nil && scanner.signatures.status.Status == "failed" {
				_ = file.Close()
				return findings, true, err
			}
			if err != nil || finding == nil || finding.Rule != "clamav-signature" {
				if err != nil {
					partial = true
				}
				finding = nil
			}
			seen[key] = finding
		}
		_ = file.Close()
		if finding == nil {
			continue
		}
		identity, err := captureProcessIdentity(pid)
		if err != nil || identity.sha256 != finding.SHA256 || identity.size != finding.Size {
			continue
		}
		result := *finding
		result.Source, result.PID = "process", pid
		result.Path, result.Executable = identity.executable, identity.executable
		result.ProcessStartTime, result.Deleted = identity.start, identity.deleted
		result.SystemFile = isSystemPackageFile(identity.executable)
		result.Quarantinable = !identity.deleted && quarantineEligible(identity.executable, result.Rule, info)
		result.ParentPID, result.ParentExecutable, result.Cgroup = scriptProcessProvenance(pid)
		id := sha256.Sum256([]byte(fmt.Sprintf("clamav-process|%d|%s|%s", pid, identity.start, identity.sha256)))
		result.ID = "p-" + hex.EncodeToString(id[:8])
		findings = append(findings, result)
	}
	emitProgress(true)
	return findings, partial, nil
}
