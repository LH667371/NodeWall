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
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// collectProcessIntegrityFindings looks for process visibility mismatches that
// a normal CPU sample cannot see. A userspace miner can be hidden from one
// listing, but the kernel still has to account for its PID in the PID
// namespace or its cgroup. When the executable can be resolved, the API can
// snapshot or move the verified executable before terminating the process.
func collectProcessIntegrityFindings(ctx context.Context, limit int) ([]Finding, error) {
	if limit <= 0 {
		return nil, nil
	}
	visible, err := listNumericEntries("/proc")
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0)
	if comparableProcViews() {
		if rooted, rootErr := listNumericEntries("/proc/1/root/proc"); rootErr == nil {
			for _, pid := range sortedPIDDifference(rooted, visible) {
				if !processStillExists(filepath.Join("/proc/1/root/proc", strconv.Itoa(pid))) {
					continue
				}
				finding := processIntegrityFinding(
					"hidden-process", SeverityHigh, "/proc/1/root/proc/"+strconv.Itoa(pid), pid,
					"PID is visible from PID 1's proc view but absent from the host proc view; inspect for proc filtering or kernel tampering",
				)
				if trace, traceErr := TraceProcess(pid); traceErr == nil {
					finding.Executable = trace.Executable
					finding.Command = trace.Command
					finding.ContainerID = containerID(trace.Cgroup)
				}
				findings = append(findings, finding)
				if len(findings) >= limit {
					return findings, nil
				}
			}
		}
	}

	// cgroup.procs is populated by the kernel independently of proc directory
	// enumeration. Ignore exited PIDs to avoid turning normal task teardown
	// races into alerts.
	if cgroupPIDs, cgErr := listCgroupPIDs(); cgErr == nil {
		for _, pid := range sortedPIDDifference(cgroupPIDs, visible) {
			// /proc may deliberately hide the task (hidepid, a different
			// namespace, or a proc-filtering rootkit). Ask the kernel for a
			// pidfd instead of dropping the evidence merely because the path is
			// absent.
			if !kernelProcessExists(pid) {
				continue
			}
			finding := processIntegrityFinding(
				"cgroup-hidden-process", SeverityHigh, "/sys/fs/cgroup/*/cgroup.procs", pid,
				"cgroup.procs references a live PID that is absent from /proc; inspect for proc hiding or namespace tampering",
			)
			if trace, traceErr := TraceProcess(pid); traceErr == nil {
				finding.Executable = trace.Executable
				finding.Command = trace.Command
				finding.ContainerID = containerID(trace.Cgroup)
			}
			findings = append(findings, finding)
			if len(findings) >= limit {
				return findings, nil
			}
		}
	}

	// A deleted executable can continue running after the on-disk file is
	// removed. It is a useful rootkit/miner signal even when the process is not
	// currently consuming enough CPU to cross the high-CPU threshold.
	for _, pid := range sortedPIDMap(visible) {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		evidence, ok := deletedExecutableEvidence(pid)
		if !ok {
			continue
		}
		finding := processIntegrityFinding(evidence.rule, evidence.severity, evidence.exe, pid, evidence.detail)
		finding.SHA256 = evidence.sha256
		finding.Size = evidence.size
		finding.Mode = evidence.mode
		findings = append(findings, finding)
		if len(findings) >= limit {
			break
		}
	}

	return findings, nil
}

type processEvidence struct {
	exe      string
	detail   string
	rule     string
	severity string
	sha256   string
	size     int64
	mode     string
}

// ProcessTrace describes the executable that belongs to a live PID. The
// normal /proc view is tried first; PID 1's proc root is also checked because
// cgroup evidence can outlive or bypass the scanner's proc view.
type ProcessTrace struct {
	PID        int    `json:"pid"`
	Executable string `json:"executable,omitempty"`
	Command    string `json:"command,omitempty"`
	Cgroup     string `json:"cgroup,omitempty"`
	Deleted    bool   `json:"deleted,omitempty"`
}

// TraceProcess resolves the executable path for a kernel-live process. It is
// intentionally separate from finding generation so containment can first
// identify the payload, then terminate the process, and finally isolate the
// still-present file when it is safe to do so.
func TraceProcess(pid int) (ProcessTrace, error) {
	if !kernelProcessExists(pid) {
		return ProcessTrace{PID: pid}, fmt.Errorf("process %d is no longer live", pid)
	}
	for _, procRoot := range []string{"/proc", "/proc/1/root/proc"} {
		procDir := filepath.Join(procRoot, strconv.Itoa(pid))
		exe, err := os.Readlink(filepath.Join(procDir, "exe"))
		if err != nil || strings.TrimSpace(exe) == "" {
			continue
		}
		command := strings.TrimSpace(strings.ReplaceAll(readProcTextLimited(filepath.Join(procDir, "cmdline"), maxProcMetadataBytes), "\x00", " "))
		cgroup := strings.TrimSpace(readProcTextLimited(filepath.Join(procDir, "cgroup"), maxProcMetadataBytes))
		deleted := strings.HasSuffix(exe, " (deleted)")
		return ProcessTrace{PID: pid, Executable: exe, Command: command, Cgroup: cgroup, Deleted: deleted}, nil
	}
	return ProcessTrace{PID: pid}, fmt.Errorf("process %d is live but its executable is not visible", pid)
}

func deletedExecutableEvidence(pid int) (processEvidence, bool) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	exe, err := os.Readlink(filepath.Join(procDir, "exe"))
	if err != nil || !strings.HasSuffix(exe, " (deleted)") {
		return processEvidence{}, false
	}
	// A normal NodeWall update replaces the on-disk binary before systemd
	// restarts the service. The old inode is reported as "(deleted)" for a
	// short period; never turn that expected upgrade state into a finding.
	if isNodeWallTrustedPath(exe) {
		return processEvidence{}, false
	}
	comm := strings.TrimSpace(readProcText(filepath.Join(procDir, "comm")))
	command := strings.TrimSpace(strings.ReplaceAll(readProcText(filepath.Join(procDir, "cmdline")), "\x00", " "))
	// bpfilter_umh and other kernel helper threads legitimately expose a
	// deleted pseudo-executable. Do not report those normal kernel tasks.
	if isKernelHelper(comm, command, exe) {
		return processEvidence{}, false
	}
	if threat, ok := inspectProcessExecutable(pid, exe); ok {
		return processEvidence{
			exe:      exe,
			detail:   fmt.Sprintf("PID %d 的已删除可执行文件匹配 %s 特征（%s）", pid, threat.detail, exe),
			rule:     threat.rule,
			severity: threat.severity,
			sha256:   threat.sha256,
			size:     threat.size,
			mode:     threat.mode,
		}, true
	}
	detail := fmt.Sprintf("PID %d is still executing a deleted file (%s); verify the process origin and restart it from a trusted package", pid, exe)
	return processEvidence{exe: exe, detail: detail, rule: "deleted-executable", severity: SeverityMedium}, true
}

type executableThreat struct {
	rule     string
	severity string
	detail   string
	sha256   string
	size     int64
	mode     string
}

// inspectProcessExecutable scans the open executable referenced by /proc/PID/exe.
// This catches miners that unlink their on-disk file after launch, which a
// pathname walk can never see. The descriptor is opened through procfs so the
// check remains valid even though the original directory entry is gone.
func inspectProcessExecutable(pid int, displayPath string) (executableThreat, bool) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return executableThreat{}, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > processHashLimit {
		return executableThreat{}, false
	}
	return inspectExecutableFile(file, displayPath, info)
}

func inspectExecutableFile(file *os.File, displayPath string, info os.FileInfo) (executableThreat, bool) {
	hasher := sha256.New()
	detector := contentDetector{}
	reader := io.NewSectionReader(file, 0, processHashLimit+1)
	buffer := make([]byte, 64<<10)
	binaryFile := false
	var total int64
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			if total == 0 {
				binaryFile = isBinaryExecutable(buffer[:n])
			}
			_, _ = hasher.Write(buffer[:n])
			detector.observe(string(buffer[:n]))
			total += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil || total > processHashLimit {
			return executableThreat{}, false
		}
	}
	rule, severity, detail := detector.result(displayPath, info.Mode(), binaryFile)
	if rule != "cryptominer" {
		return executableThreat{}, false
	}
	return executableThreat{
		rule:     rule,
		severity: severity,
		detail:   detail,
		sha256:   hex.EncodeToString(hasher.Sum(nil)),
		size:     total,
		mode:     info.Mode().Perm().String(),
	}, true
}

func isKernelHelper(comm, command, exe string) bool {
	if exe != "/ (deleted)" || command != "" {
		return false
	}
	for _, prefix := range []string{"bpfilter", "kworker", "ksoftirqd", "migration", "rcu", "watchdog", "cpuhp"} {
		if strings.HasPrefix(comm, prefix) {
			return true
		}
	}
	return false
}

func processIntegrityFinding(rule, severity, path string, pid int, detail string) Finding {
	seed := fmt.Sprintf("process-integrity|%s|%d|%s", rule, pid, path)
	idBytes := sha256.Sum256([]byte(seed))
	finding := Finding{
		ID:            "p-" + hex.EncodeToString(idBytes[:8]),
		Path:          path,
		Rule:          rule,
		Severity:      severity,
		Detail:        detail,
		DetectedAt:    time.Now().UTC(),
		Source:        "process",
		Quarantinable: false,
		PID:           pid,
		Executable:    path,
	}
	return EnrichProcessFinding(finding)
}

// EnrichProcessFinding follows a PID to its executable and records enough
// inode evidence for quarantine before process termination. A cgroup-only path
// is replaced with the actual executable when the kernel/proc lookup allows
// it, while an inaccessible process remains evidence-only.
func EnrichProcessFinding(finding Finding) Finding {
	if finding.Source != "process" || finding.PID <= 1 {
		return finding
	}
	trace, err := TraceProcess(finding.PID)
	if err != nil || trace.Executable == "" {
		return finding
	}
	finding.Executable = trace.Executable
	finding.Command = trace.Command
	finding.ContainerID = containerID(trace.Cgroup)
	if isNodeWallTrustedPath(trace.Executable) {
		return finding
	}
	if strings.Contains(finding.Path, "cgroup.procs") || strings.HasPrefix(finding.Path, "/proc/") {
		finding.Path = trace.Executable
	}
	if strings.HasSuffix(trace.Executable, " (deleted)") {
		if threat, ok := inspectProcessExecutable(finding.PID, trace.Executable); ok {
			finding.Rule = threat.rule
			finding.Severity = threat.severity
			finding.Detail = fmt.Sprintf("PID %d 的已删除可执行文件匹配 %s 特征（%s）", finding.PID, threat.detail, trace.Executable)
			finding.SHA256 = threat.sha256
			finding.Size = threat.size
			finding.Mode = threat.mode
		}
		return finding
	}
	info, err := os.Stat(trace.Executable)
	if err != nil || !info.Mode().IsRegular() {
		return finding
	}
	sum, size, mode, ok := hashProcessPath(trace.Executable, info)
	if !ok {
		return finding
	}
	finding.SHA256 = sum
	finding.Size = size
	finding.Mode = mode
	finding.Quarantinable = processQuarantineEligible(trace.Executable, info)
	return finding
}

func hashProcessPath(path string, info os.FileInfo) (string, int64, string, bool) {
	if info == nil || info.Size() <= 0 || info.Size() > processHashLimit {
		return "", 0, "", false
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", 0, "", false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", 0, "", false
	}
	hasher := sha256.New()
	if _, err := io.CopyN(hasher, file, processHashLimit+1); err != nil && err != io.EOF {
		return "", 0, "", false
	}
	if opened.Size() > processHashLimit {
		return "", 0, "", false
	}
	return hex.EncodeToString(hasher.Sum(nil)), opened.Size(), opened.Mode().Perm().String(), true
}

func listNumericEntries(root string) (map[int]struct{}, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	pids := make(map[int]struct{})
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err == nil && pid > 0 {
			pids[pid] = struct{}{}
		}
	}
	return pids, nil
}

func listCgroupPIDs() (map[int]struct{}, error) {
	pids := make(map[int]struct{})
	err := filepath.WalkDir("/sys/fs/cgroup", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
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
			if err == nil && pid > 0 {
				pids[pid] = struct{}{}
			}
		}
		return nil
	})
	return pids, err
}

func comparableProcViews() bool {
	selfPIDNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return false
	}
	initPIDNS, err := os.Readlink("/proc/1/ns/pid")
	if err != nil || selfPIDNS != initPIDNS {
		return false
	}
	procInfo, err := os.Stat("/proc")
	if err != nil {
		return false
	}
	rootProcInfo, err := os.Stat("/proc/1/root/proc")
	if err != nil {
		return false
	}
	// A different device/inode means PID 1 is looking at a different proc
	// mount (common in containers); in that case a mismatch is expected.
	return os.SameFile(procInfo, rootProcInfo)
}

func processStillExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func sortedPIDDifference(left, right map[int]struct{}) []int {
	result := make([]int, 0)
	for pid := range left {
		if _, ok := right[pid]; !ok {
			result = append(result, pid)
		}
	}
	sort.Ints(result)
	return result
}

func sortedPIDMap(values map[int]struct{}) []int {
	result := make([]int, 0, len(values))
	for pid := range values {
		result = append(result, pid)
	}
	sort.Ints(result)
	return result
}
