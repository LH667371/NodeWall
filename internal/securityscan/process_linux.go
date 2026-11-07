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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	highCPUThreshold   = 80.0
	processSampleDelay = 750 * time.Millisecond
	processHashLimit   = 32 << 20
)

type processSnapshot struct {
	pid     int
	ticks   uint64
	command string
	exe     string
	cgroup  string
}

func collectHighCPUFindings(ctx context.Context, limit int) ([]Finding, error) {
	if limit <= 0 {
		return nil, nil
	}
	before, totalBefore, err := snapshotProcesses()
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(processSampleDelay)
	select {
	case <-ctx.Done():
		timer.Stop()
		return nil, ctx.Err()
	case <-timer.C:
	}
	after, totalAfter, err := snapshotProcesses()
	if err != nil {
		return nil, err
	}
	totalDelta := totalAfter - totalBefore
	if totalDelta == 0 {
		return nil, nil
	}

	rows := make([]processCPU, 0)
	for pid, current := range after {
		previous, ok := before[pid]
		if !ok || current.ticks < previous.ticks {
			continue
		}
		percent := float64(current.ticks-previous.ticks) / float64(totalDelta) * 100 * float64(runtime.NumCPU())
		if percent < highCPUThreshold {
			continue
		}
		// Read untrusted /proc metadata only after a process has crossed the
		// threshold. A host with thousands of tasks should spend the sample
		// interval measuring CPU, rather than serially reading every cmdline
		// and cgroup. The metadata reads are bounded and a disappearing process
		// is ignored, which also makes scans resilient to short-lived tasks.
		current = enrichProcessSnapshot(current)
		if current.exe == "" || isNodeWallTrustedPath(current.exe) {
			continue
		}
		rows = append(rows, processCPU{snapshot: current, percent: percent})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].percent > rows[j].percent })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	findings := make([]Finding, 0, len(rows))
	for _, row := range rows {
		findings = append(findings, processFinding(row))
	}
	return findings, nil
}

type processCPU struct {
	snapshot processSnapshot
	percent  float64
}

func processFinding(row processCPU) Finding {
	command := row.snapshot.command
	if command == "" {
		command = filepath.Base(row.snapshot.exe)
	}
	detail := fmt.Sprintf("PID %d (%s) used %.1f%% CPU during the sample; executable=%s", row.snapshot.pid, commandName(command), row.percent, row.snapshot.exe)
	if row.snapshot.cgroup != "" {
		detail += "; cgroup=" + row.snapshot.cgroup
	}
	sum, size, mode := hashProcessExecutable(row.snapshot.pid)
	seed := fmt.Sprintf("process|%d|%s|%.2f", row.snapshot.pid, row.snapshot.exe, row.percent)
	idBytes := sha256.Sum256([]byte(seed))
	finding := Finding{
		ID:            "p-" + hex.EncodeToString(idBytes[:8]),
		Path:          row.snapshot.exe,
		Rule:          "high-cpu-process",
		Severity:      processSeverity(row.percent),
		Detail:        detail,
		SHA256:        sum,
		Size:          size,
		Mode:          mode,
		DetectedAt:    time.Now().UTC(),
		Source:        "process",
		Quarantinable: false,
		PID:           row.snapshot.pid,
		CPUPercent:    row.percent,
		Command:       row.snapshot.command,
		Executable:    row.snapshot.exe,
		ContainerID:   containerID(row.snapshot.cgroup),
	}
	return EnrichProcessFinding(finding)
}

func processSeverity(percent float64) string {
	if percent >= 200 {
		return SeverityHigh
	}
	return SeverityMedium
}

func commandName(command string) string {
	if command == "" {
		return "unknown"
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "unknown"
	}
	return filepath.Base(fields[0])
}

func snapshotProcesses() (map[int]processSnapshot, uint64, error) {
	total, err := procCPUTime()
	if err != nil {
		return nil, 0, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0, err
	}
	result := make(map[int]processSnapshot)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		ticks, err := procProcessTime(pid)
		if err != nil {
			continue
		}
		result[pid] = processSnapshot{pid: pid, ticks: ticks}
	}
	return result, total, nil
}

const maxProcMetadataBytes = 16 << 10

func enrichProcessSnapshot(snapshot processSnapshot) processSnapshot {
	procDir := filepath.Join("/proc", strconv.Itoa(snapshot.pid))
	command := readProcTextLimited(filepath.Join(procDir, "cmdline"), maxProcMetadataBytes)
	snapshot.command = strings.TrimSpace(strings.ReplaceAll(command, "\x00", " "))
	snapshot.exe, _ = os.Readlink(filepath.Join(procDir, "exe"))
	snapshot.cgroup = strings.TrimSpace(readProcTextLimited(filepath.Join(procDir, "cgroup"), maxProcMetadataBytes))
	return snapshot
}

func procCPUTime() (uint64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		var total uint64
		for _, field := range strings.Fields(line)[1:] {
			value, parseErr := strconv.ParseUint(field, 10, 64)
			if parseErr == nil {
				total += value
			}
		}
		return total, nil
	}
	return 0, fmt.Errorf("aggregate CPU line missing from /proc/stat")
}

func procProcessTime(pid int) (uint64, error) {
	// htop can display individual threads while top usually aggregates them
	// under the process leader. Summing /task/*/stat keeps the scanner aligned
	// with the thread-level view and catches a busy worker hidden by a quiet
	// process leader (for example, a JVM or a packet-processing service).
	taskDir := filepath.Join("/proc", strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return 0, err
	}

	var total uint64
	readable := 0
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil || tid <= 0 {
			continue
		}
		data, err := os.ReadFile(filepath.Join(taskDir, entry.Name(), "stat"))
		if err != nil {
			// A thread may exit between ReadDir and ReadFile. Keep the other
			// threads' evidence instead of dropping the whole process sample.
			continue
		}
		ticks, err := parseProcStatCPUTime(data, fmt.Sprintf("/proc/%d/task/%d/stat", pid, tid))
		if err != nil {
			continue
		}
		total += ticks
		readable++
	}
	if readable == 0 {
		return 0, fmt.Errorf("no readable threads for process %d", pid)
	}
	return total, nil
}

func parseProcStatCPUTime(data []byte, path string) (uint64, error) {
	text := string(data)
	closing := strings.LastIndexByte(text, ')')
	if closing < 0 || closing+2 > len(text) {
		return 0, fmt.Errorf("malformed %s", path)
	}
	fields := strings.Fields(text[closing+2:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("short %s", path)
	}
	user, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse user time in %s: %w", path, err)
	}
	system, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse system time in %s: %w", path, err)
	}
	return user + system, nil
}

func readProcText(path string) string {
	return readProcTextLimited(path, maxProcMetadataBytes)
}

func readProcTextLimited(path string, limit int64) string {
	if limit <= 0 {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return ""
	}
	return string(data)
}

func containerID(cgroup string) string {
	for _, field := range strings.FieldsFunc(cgroup, func(r rune) bool { return r == '/' || r == ':' || r == '\n' }) {
		clean := strings.TrimSuffix(field, ".scope")
		if len(clean) >= 12 && len(clean) <= 128 && isHex(clean) {
			return clean
		}
		if strings.HasPrefix(clean, "docker-") {
			id := strings.TrimPrefix(clean, "docker-")
			if isHex(id) {
				return id
			}
		}
	}
	return ""
}

func isHex(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') && !(r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func hashProcessExecutable(pid int) (string, int64, string) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return "", 0, ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, ""
	}
	hasher := sha256.New()
	_, _ = io.CopyN(hasher, file, processHashLimit)
	return hex.EncodeToString(hasher.Sum(nil)), info.Size(), info.Mode().Perm().String()
}
