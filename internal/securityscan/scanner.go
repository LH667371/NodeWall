// Package securityscan contains NodeWall's dependency-free host file scanner.
// It deliberately reports suspicious files instead of silently deleting them.
package securityscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nodewall/internal/clamav"
)

const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"

	defaultMaxFileSize      = 32 << 20
	defaultMaxFiles         = 200000
	defaultMaxFindings      = 200
	quickPersistenceReserve = 32
	maxCoverageGaps         = 100
)

var errFileSkipped = errors.New("file is not regular or exceeds the scan size limit")

func normalizeDeletedExecutablePath(path string) (string, bool) {
	path = strings.TrimSpace(path)
	if strings.HasSuffix(path, " (deleted)") {
		path = strings.TrimSpace(strings.TrimSuffix(path, " (deleted)"))
		// Some older overlayfs/procfs combinations append an inode marker such
		// as ";6af13621" before the deleted suffix. It is metadata emitted by
		// the kernel, not part of the executable pathname. Strip only a
		// delimiter followed by a sufficiently long hexadecimal token so a
		// legitimate semicolon in a filename remains intact.
		if separator := strings.LastIndexByte(path, ';'); separator >= 0 && separator+9 <= len(path) && isHexToken(path[separator+1:]) {
			path = strings.TrimSpace(path[:separator])
		}
		return path, true
	}
	return path, false
}

func isHexToken(value string) bool {
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

type Finding struct {
	ID                string              `json:"id"`
	Path              string              `json:"path"`
	Rule              string              `json:"rule"`
	Severity          string              `json:"severity"`
	Detail            string              `json:"detail"`
	SHA256            string              `json:"sha256"`
	Size              int64               `json:"size"`
	Mode              string              `json:"mode"`
	DetectedAt        time.Time           `json:"detected_at"`
	Quarantined       bool                `json:"quarantined,omitempty"`
	Ignored           bool                `json:"ignored,omitempty"`
	QuarantinePath    string              `json:"quarantine_path,omitempty"`
	EvidenceArchived  bool                `json:"evidence_archived,omitempty"`
	EvidencePath      string              `json:"evidence_path,omitempty"`
	Source            string              `json:"source,omitempty"`
	Quarantinable     bool                `json:"quarantinable,omitempty"`
	PID               int                 `json:"pid,omitempty"`
	ParentPID         int                 `json:"parent_pid,omitempty"`
	ParentExecutable  string              `json:"parent_executable,omitempty"`
	Cgroup            string              `json:"cgroup,omitempty"`
	ProcessStartTime  string              `json:"process_start_time,omitempty"`
	CPUPercent        float64             `json:"cpu_percent,omitempty"`
	Command           string              `json:"command,omitempty"`
	Executable        string              `json:"executable,omitempty"`
	ExecutableSHA256  string              `json:"executable_sha256,omitempty"`
	ExecutableSize    int64               `json:"executable_size,omitempty"`
	ScriptFD          int                 `json:"script_fd,omitempty"`
	ScriptArgument    string              `json:"script_argument,omitempty"`
	ScriptFDTarget    string              `json:"script_fd_target,omitempty"`
	Deleted           bool                `json:"deleted,omitempty"`
	SystemFile        bool                `json:"system_file,omitempty"`
	StartupBlocked    bool                `json:"startup_blocked,omitempty"`
	StartupBlockPath  string              `json:"startup_block_path,omitempty"`
	StartupBlockOwned bool                `json:"startup_block_owned,omitempty"`
	ModuleUnloaded    bool                `json:"module_unloaded,omitempty"`
	StartupBlocks     []StartupBlock      `json:"startup_blocks,omitempty"`
	StartupCandidates []string            `json:"startup_candidates,omitempty"`
	ModuleName        string              `json:"module_name,omitempty"`
	ModulePath        string              `json:"module_path,omitempty"`
	RelatedTo         string              `json:"related_to,omitempty"`
	RelatedPaths      []string            `json:"related_paths,omitempty"`
	Indicators        []string            `json:"indicators,omitempty"`
	ContainerID       string              `json:"container_id,omitempty"`
	Terminated        bool                `json:"terminated,omitempty"`
	Termination       *ProcessTermination `json:"termination,omitempty"`
	TerminationError  string              `json:"termination_error,omitempty"`
	// ContainmentBlockedReason explains why an automatic process action was
	// intentionally skipped. It is separate from TerminationError so a normal
	// high-CPU service is shown as evidence instead of a failed response.
	ContainmentBlockedReason string `json:"containment_blocked_reason,omitempty"`
	// ContainmentEvidence records the checks that justified a successful
	// isolation. It remains in the scan report after the payload is moved.
	ContainmentEvidence string `json:"containment_evidence,omitempty"`
}

// StartupBlock records a journal-associated systemd mask independently of
// quarantine artifacts, including whether NodeWall may safely undo it.
type StartupBlock struct {
	UnitPath string `json:"unit_path"`
	MaskPath string `json:"mask_path,omitempty"`
	Owned    bool   `json:"owned,omitempty"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

// ScanProcesses performs the fast process-integrity, CPU, and persistence pass
// used by the operator's hidden-PID/deleted-executable/high-CPU check. The
// persistence pass is deliberately bounded to known startup locations and
// related absolute payload references; it never walks the whole filesystem.
func (s Scanner) ScanProcesses(ctx context.Context, onProgress func(Progress)) (Report, error) {
	if s.MaxFindings <= 0 {
		s.MaxFindings = defaultMaxFindings
	}
	report := Report{Findings: make([]Finding, 0)}
	s.signatures = newClamAVEngine(ctx, s.signatureSocket())
	report.SignatureEngine = s.signatures.status
	emitProcessProgress := func(progress Progress) {
		if onProgress == nil {
			return
		}
		// The process pass has no filesystem walk of its own. Keep the
		// counters sourced from the ClamAV stream so the UI can distinguish
		// verified signature samples from heuristic process checks.
		progress.FilesScanned = s.signatures.status.FilesScanned
		progress.BytesScanned = s.signatures.status.BytesScanned
		progress.SignatureEngine = s.signatures.status
		if progress.Phase == "" {
			progress.Phase = "process"
		}
		onProgress(progress)
	}
	emitProcessProgress(Progress{})
	report.Findings = appendUniqueFindings(report.Findings, collectSystemIntegrityFindings(), s.MaxFindings)
	moduleFindings, moduleErr := collectHiddenKernelModuleFindings(ctx, s.MaxFindings-len(report.Findings))
	report.Findings = appendUniqueFindings(report.Findings, moduleFindings, s.MaxFindings)
	if moduleErr != nil && ctx.Err() == nil {
		report.ReadErrors++
		report.Truncated = true
	}
	processLimit := s.MaxFindings - len(report.Findings)
	if processLimit > 1 {
		processLimit -= min(quickPersistenceReserve, processLimit-1)
	}
	findings, err := collectFDScriptFindings(ctx, s, processLimit)
	report.SignatureEngine = s.signatures.status
	if len(findings) > 0 && ctx.Err() == nil {
		// A descriptor can vanish while slower process and startup scans run.
		// Publish the verified script immediately so the API can preserve it
		// before the interpreter exits, then merge its action into the report.
		ready := append(append([]Finding(nil), report.Findings...), findings...)
		emitProcessProgress(Progress{
			Findings: len(ready), FindingsReady: true,
			ProcessFindings: ready, Truncated: report.Truncated,
			CoverageGaps: append([]CoverageGap(nil), report.CoverageGaps...), CoverageGapsOmitted: report.CoverageGapsOmitted,
		})
	} else {
		// Emit a stage boundary even when no descriptor was found. Without this
		// update a quick scan with no ClamAV match looks idle until completion.
		emitProcessProgress(Progress{Findings: len(report.Findings)})
	}
	if err == nil && len(findings) < processLimit {
		signatureFindings, partial, signatureErr := scanProcessSignaturesWithProgress(ctx, s, processLimit-len(findings), func(progress Progress) {
			progress.Findings = len(report.Findings) + len(findings)
			emitProcessProgress(progress)
		})
		findings = mergeProcessFindings(findings, signatureFindings, processLimit)
		if partial {
			appendCoverageGap(&report, CoverageGap{Path: "/proc", Reason: "signature-process-limit"})
		}
		if signatureErr != nil && ctx.Err() != nil {
			err = signatureErr
		}
	}
	if err == nil && len(findings) < processLimit {
		var processFindings []Finding
		processFindings, err = collectProcessIntegrityFindings(ctx, processLimit-len(findings))
		findings = appendUniqueFindings(findings, processFindings, processLimit)
	}
	if err == nil && len(findings) < processLimit {
		var temporaryFindings []Finding
		temporaryFindings, err = collectTemporaryProcessFindings(ctx, processLimit-len(findings))
		findings = mergeProcessFindings(findings, temporaryFindings, processLimit)
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		report.ReadErrors++
		report.Truncated = true
	}
	// The quick pass also samples CPU usage. This keeps a miner that has not
	// hidden its PID in the same fast path as hidden/deleted executables, while
	// the API containment gate decides whether the process is safe to isolate.
	if err == nil && len(findings) < processLimit {
		cpuFindings, cpuErr := collectHighCPUFindings(ctx, processLimit-len(findings))
		findings = mergeProcessFindings(findings, cpuFindings, processLimit)
		if cpuErr != nil && !errors.Is(cpuErr, context.Canceled) && !errors.Is(cpuErr, context.DeadlineExceeded) {
			err = cpuErr
			report.ReadErrors++
			report.Truncated = true
		}
	}
	if processLimit > 0 && len(findings) >= processLimit {
		appendCoverageGap(&report, CoverageGap{Path: "/proc", Reason: "finding-count-limit"})
	}
	remaining := s.MaxFindings - len(report.Findings) - len(findings)
	if !errors.Is(ctx.Err(), context.Canceled) && !errors.Is(ctx.Err(), context.DeadlineExceeded) && remaining > 0 {
		persistenceFindings, persistenceGaps, omitted, persistenceErr := collectPersistenceFindings(ctx, s, remaining)
		findings = append(findings, persistenceFindings...)
		for _, gap := range persistenceGaps {
			appendCoverageGap(&report, gap)
		}
		report.CoverageGapsOmitted += omitted
		if persistenceErr != nil && !errors.Is(persistenceErr, context.Canceled) && !errors.Is(persistenceErr, context.DeadlineExceeded) {
			err = persistenceErr
			report.ReadErrors++
			report.Truncated = true
		}
	}
	if len(findings) > s.MaxFindings-len(report.Findings) {
		findings = findings[:s.MaxFindings-len(report.Findings)]
		report.Truncated = true
	}
	report.Findings = append(report.Findings, findings...)
	report.SignatureEngine = s.signatures.status
	report.FilesScanned = report.SignatureEngine.FilesScanned
	report.BytesScanned = report.SignatureEngine.BytesScanned
	if report.SignatureEngine.Status == "failed" {
		appendCoverageGap(&report, CoverageGap{Path: "/", Reason: "signature-engine-incomplete"})
	}
	emitProcessProgress(Progress{
		FilesScanned:        report.FilesScanned,
		BytesScanned:        report.BytesScanned,
		Findings:            len(report.Findings),
		Truncated:           report.Truncated,
		CoverageGaps:        append([]CoverageGap(nil), report.CoverageGaps...),
		CoverageGapsOmitted: report.CoverageGapsOmitted,
		FindingsReady:       true,
		ProcessFindings:     append([]Finding(nil), report.Findings...),
	})
	if err != nil {
		return report, err
	}
	return report, nil
}

func appendUniqueFindings(existing, extra []Finding, limit int) []Finding {
	seen := make(map[string]struct{}, len(existing)+len(extra))
	for _, finding := range existing {
		seen[finding.ID] = struct{}{}
	}
	for _, finding := range extra {
		if limit > 0 && len(existing) >= limit {
			break
		}
		if _, ok := seen[finding.ID]; ok {
			continue
		}
		seen[finding.ID] = struct{}{}
		existing = append(existing, finding)
	}
	return existing
}

// mergeProcessFindings keeps one actionable row per PID. A hidden process can
// also cross the CPU threshold; retaining the stronger integrity rule avoids
// two concurrent containment requests for the same process while preserving
// the CPU evidence on the row.
func mergeProcessFindings(findings, extra []Finding, limit int) []Finding {
	if len(extra) == 0 {
		return findings
	}
	byPID := make(map[int]int, len(findings))
	for index, finding := range findings {
		if finding.PID > 0 {
			byPID[finding.PID] = index
		}
	}
	for _, finding := range extra {
		if finding.PID > 0 {
			if index, ok := byPID[finding.PID]; ok {
				if finding.Rule == "clamav-signature" && findings[index].Source == "process" && findings[index].Rule != "clamav-signature" {
					finding.CPUPercent = findings[index].CPUPercent
					findings[index] = finding
					continue
				}
				if finding.CPUPercent > findings[index].CPUPercent {
					findings[index].CPUPercent = finding.CPUPercent
				}
				if finding.Rule == "high-cpu-process" && findings[index].Rule != finding.Rule {
					findings[index].Detail += fmt.Sprintf("; high CPU sample %.1f%%", finding.CPUPercent)
				}
				continue
			}
		}
		if limit > 0 && len(findings) >= limit {
			break
		}
		if finding.PID > 0 {
			byPID[finding.PID] = len(findings)
		}
		findings = append(findings, finding)
	}
	return findings
}

type Progress struct {
	FilesScanned        uint64                `json:"files_scanned"`
	FilesSkipped        uint64                `json:"files_skipped"`
	MountsSkipped       uint64                `json:"mounts_skipped"`
	ReadErrors          uint64                `json:"read_errors"`
	BytesScanned        uint64                `json:"bytes_scanned"`
	Findings            int                   `json:"findings"`
	Phase               string                `json:"phase,omitempty"`
	Truncated           bool                  `json:"truncated"`
	CoverageGaps        []CoverageGap         `json:"coverage_gaps,omitempty"`
	CoverageGapsOmitted uint64                `json:"coverage_gaps_omitted,omitempty"`
	SignatureEngine     SignatureEngineStatus `json:"signature_engine"`
	// FindingsReady marks a progress frame whose findings slice is current.
	// ProcessFindings is kept for wire compatibility with the agent API, but
	// it now carries the complete finding snapshot for file-walk progress too.
	FindingsReady   bool      `json:"findings_ready,omitempty"`
	ProcessFindings []Finding `json:"process_findings,omitempty"`
}

type CoverageGap struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func appendCoverageGap(report *Report, gap CoverageGap) {
	report.Truncated = true
	if len(report.CoverageGaps) < maxCoverageGaps {
		report.CoverageGaps = append(report.CoverageGaps, gap)
	} else {
		report.CoverageGapsOmitted++
	}
}

type Report struct {
	FilesScanned        uint64                `json:"files_scanned"`
	FilesSkipped        uint64                `json:"files_skipped"`
	MountsSkipped       uint64                `json:"mounts_skipped"`
	ReadErrors          uint64                `json:"read_errors"`
	BytesScanned        uint64                `json:"bytes_scanned"`
	Findings            []Finding             `json:"findings"`
	Truncated           bool                  `json:"truncated"`
	CoverageGaps        []CoverageGap         `json:"coverage_gaps,omitempty"`
	CoverageGapsOmitted uint64                `json:"coverage_gaps_omitted,omitempty"`
	SignatureEngine     SignatureEngineStatus `json:"signature_engine"`
}

type Scanner struct {
	MaxFileSize int64
	MaxFiles    uint64
	MaxFindings int
	// SkipMounts excludes remote, virtual and duplicate mounts, while retaining
	// separately mounted local filesystems as part of a full scan.
	// The caller can disable it for an explicit mounted-filesystem audit.
	SkipMounts   bool
	ClamAVSocket string
	signatures   *clamAVEngine
}

func New() Scanner {
	return Scanner{
		MaxFileSize:  defaultMaxFileSize,
		MaxFiles:     defaultMaxFiles,
		MaxFindings:  defaultMaxFindings,
		SkipMounts:   true,
		ClamAVSocket: strings.TrimSpace(os.Getenv("NODEWALL_CLAMD_SOCKET")),
	}
}

func (s Scanner) signatureSocket() string {
	if strings.TrimSpace(s.ClamAVSocket) != "" {
		return s.ClamAVSocket
	}
	if clamav.Managed() {
		return clamav.SocketPath()
	}
	return ""
}

func ValidateRoot(root string) (string, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "." || !filepath.IsAbs(root) {
		return "", errors.New("scan path must be an absolute path")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve scan path: %w", err)
	}
	root = resolved
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("scan path is not accessible: %w", err)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return "", errors.New("scan path must be a regular file or directory")
	}
	return root, nil
}

func (s Scanner) Scan(ctx context.Context, root string, onProgress func(Progress)) (Report, error) {
	root, err := ValidateRoot(root)
	if err != nil {
		return Report{}, err
	}
	if s.MaxFileSize <= 0 {
		s.MaxFileSize = defaultMaxFileSize
	}
	if s.MaxFiles == 0 {
		s.MaxFiles = defaultMaxFiles
	}
	if s.MaxFindings <= 0 {
		s.MaxFindings = defaultMaxFindings
	}

	report := Report{Findings: make([]Finding, 0)}
	addGap := func(path, reason string) {
		appendCoverageGap(&report, CoverageGap{Path: path, Reason: reason})
	}
	s.signatures = newClamAVEngine(ctx, s.signatureSocket())
	report.SignatureEngine = s.signatures.status
	if report.SignatureEngine.Status == "failed" {
		addGap(root, "signature-engine-incomplete")
	}
	var lastFileProgress time.Time
	progress := func(phase string, findingsReady bool) {
		if onProgress != nil {
			report.SignatureEngine = s.signatures.status
			if phase == "files" && time.Since(lastFileProgress) < 250*time.Millisecond {
				return
			}
			if phase == "files" {
				lastFileProgress = time.Now()
			}
			// Once the first file finding exists, include the full snapshot in
			// subsequent throttled progress frames. This lets the UI render
			// findings while a large scan is still walking the filesystem.
			findingsReady = findingsReady || len(report.Findings) > 0
			var processFindings []Finding
			if findingsReady {
				processFindings = append([]Finding(nil), report.Findings...)
			}
			onProgress(Progress{
				FilesScanned:        report.FilesScanned,
				FilesSkipped:        report.FilesSkipped,
				MountsSkipped:       report.MountsSkipped,
				ReadErrors:          report.ReadErrors,
				BytesScanned:        report.BytesScanned,
				Findings:            len(report.Findings),
				Phase:               phase,
				Truncated:           report.Truncated,
				CoverageGaps:        append([]CoverageGap(nil), report.CoverageGaps...),
				CoverageGapsOmitted: report.CoverageGapsOmitted,
				SignatureEngine:     report.SignatureEngine,
				FindingsReady:       findingsReady,
				ProcessFindings:     processFindings,
			})
		}
	}

	// Process evidence is deliberately collected before the file walk. A root
	// scan can cover mounted data for hours, but a high-CPU/deleted executable
	// finding must be visible quickly enough for an operator to contain it.
	if root == "/" {
		report.Findings = appendUniqueFindings(report.Findings, collectSystemIntegrityFindings(), s.MaxFindings)
		moduleFindings, moduleErr := collectHiddenKernelModuleFindings(ctx, s.MaxFindings-len(report.Findings))
		report.Findings = appendUniqueFindings(report.Findings, moduleFindings, s.MaxFindings)
		if moduleErr != nil && ctx.Err() == nil {
			report.ReadErrors++
			report.Truncated = true
		}
		processCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		processFindings, processErr := collectFDScriptFindings(processCtx, s, s.MaxFindings-len(report.Findings))
		if processErr == nil && len(processFindings)+len(report.Findings) < s.MaxFindings {
			var integrityFindings []Finding
			integrityFindings, processErr = collectProcessIntegrityFindings(processCtx, s.MaxFindings-len(report.Findings)-len(processFindings))
			processFindings = appendUniqueFindings(processFindings, integrityFindings, s.MaxFindings-len(report.Findings))
		}
		if processErr == nil && len(processFindings)+len(report.Findings) < s.MaxFindings {
			var temporaryFindings []Finding
			temporaryFindings, processErr = collectTemporaryProcessFindings(processCtx, s.MaxFindings-len(report.Findings)-len(processFindings))
			processFindings = mergeProcessFindings(processFindings, temporaryFindings, s.MaxFindings-len(report.Findings))
		}
		// Publish integrity evidence as soon as it is available. CPU sampling
		// deliberately follows it, so a hidden/deleted process can be acted on
		// while the second sample is still running.
		if len(processFindings) > 0 || processErr == nil {
			report.Findings = append(report.Findings, processFindings...)
			progress("process", true)
		}
		if processErr == nil && len(report.Findings) < s.MaxFindings {
			cpuFindings, cpuErr := collectHighCPUFindings(processCtx, s.MaxFindings-len(report.Findings))
			processFindings = append(processFindings, cpuFindings...)
			if cpuErr != nil && !errors.Is(cpuErr, context.Canceled) && !errors.Is(cpuErr, context.DeadlineExceeded) {
				processErr = cpuErr
			}
			if len(cpuFindings) > 0 {
				report.Findings = append(report.Findings, cpuFindings...)
				progress("process", true)
			}
		}
		cancel()
		if processErr != nil && ctx.Err() == nil {
			report.ReadErrors++
			addGap("/proc", "process-scan-incomplete")
		}
		if processErr != nil {
			// Keep any integrity findings already published, and expose the
			// process phase even when the CPU sample could not complete.
			progress("process", true)
		}
	}

	mounts := map[string]string{}
	if s.SkipMounts {
		var mountErr error
		mounts, mountErr = scanMountPoints(root)
		if mountErr != nil {
			// Without the mount table a root walk could traverse network and
			// container mounts. Fail closed instead of silently crossing them.
			addGap(root, "mount-table-unavailable")
			return report, fmt.Errorf("read mount table: %w", mountErr)
		}
	}

	fileLimitReached := false
	walk := func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			report.ReadErrors++
			addGap(path, "unreadable")
			progress("files", false)
			// A protected directory should not make a whole-host scan fail.
			if errors.Is(walkErr, os.ErrPermission) {
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			return nil
		}
		if entry.IsDir() {
			if path != root {
				if reason, mounted := mounts[filepath.Clean(path)]; mounted {
					report.MountsSkipped++
					addGap(path, reason)
					progress("files", false)
					return filepath.SkipDir
				}
			}
			if root == "/" && isVirtualSystemDirectory(path) && !isSharedMemoryPath(path) {
				addGap(path, "virtual-filesystem")
				return filepath.SkipDir
			}
			// Container image/layer stores are often on the root filesystem, so
			// mount-point filtering alone still walks every duplicated layer.
			// They remain available as explicit scan roots; the global recovery
			// pass skips them so process evidence and host paths return quickly.
			if root == "/" && isContainerStorageDirectory(path) {
				report.MountsSkipped++
				addGap(path, "container-storage")
				progress("files", false)
				return filepath.SkipDir
			}
			if isNodeWallTrustedPath(path) {
				report.FilesSkipped++
				addGap(path, "nodewall-owned")
				progress("files", false)
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		if isNodeWallArtifactPath(path) {
			report.FilesSkipped++
			progress("files", false)
			return nil
		}
		if report.FilesScanned+report.FilesSkipped+report.ReadErrors >= s.MaxFiles {
			addGap(path, "file-count-limit")
			fileLimitReached = true
			return filepath.SkipAll
		}

		finding, size, scanErr := s.scanFile(ctx, path)
		if scanErr != nil {
			if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
				return scanErr
			}
			if errors.Is(scanErr, errFileSkipped) {
				report.FilesSkipped++
				addGap(path, "file-size-or-type-limit")
			} else {
				report.ReadErrors++
				addGap(path, "unreadable-or-changed")
			}
			progress("files", false)
			return nil
		}
		report.FilesScanned++
		report.BytesScanned += uint64(size)
		if finding != nil {
			if len(report.Findings) < s.MaxFindings {
				report.Findings = append(report.Findings, *finding)
			} else {
				addGap(path, "finding-count-limit")
			}
		}
		progress("files", false)
		return nil
	}
	// /dev is skipped as a virtual filesystem, but /dev/shm is commonly used
	// for real payloads. Inspect it first so the global file cap cannot hide it.
	if root == "/" {
		if info, statErr := os.Lstat("/dev/shm"); statErr == nil {
			if info.IsDir() {
				err = filepath.WalkDir("/dev/shm", walk)
			} else {
				addGap("/dev/shm", "unreadable")
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			addGap("/dev/shm", "unreadable")
		}
	}
	if err == nil && !fileLimitReached {
		err = filepath.WalkDir(root, walk)
	}
	report.SignatureEngine = s.signatures.status
	if report.SignatureEngine.Status == "failed" && len(report.CoverageGaps) == 0 {
		addGap(root, "signature-engine-incomplete")
	} else if report.SignatureEngine.Status == "failed" {
		found := false
		for _, gap := range report.CoverageGaps {
			found = found || gap.Reason == "signature-engine-incomplete"
		}
		if !found {
			addGap(root, "signature-engine-incomplete")
		}
	}
	if err != nil {
		return report, err
	}
	// The global walk intentionally skips virtual filesystems and container
	// storage. Re-run the bounded persistence collector so transient systemd
	// units, Kubernetes manifests, and Docker restart metadata are still
	// inspected during a full host scan.
	if root == "/" && len(report.Findings) < s.MaxFindings {
		persistenceFindings, persistenceGaps, omitted, persistenceErr := collectPersistenceFindings(ctx, s, s.MaxFindings-len(report.Findings))
		report.Findings = appendUniqueFindings(report.Findings, persistenceFindings, s.MaxFindings)
		for _, gap := range persistenceGaps {
			appendCoverageGap(&report, gap)
		}
		report.CoverageGapsOmitted += omitted
		if persistenceErr != nil && !errors.Is(persistenceErr, context.Canceled) && !errors.Is(persistenceErr, context.DeadlineExceeded) {
			report.ReadErrors++
			addGap("startup-paths", "persistence-scan-incomplete")
		}
		progress("persistence", false)
	}
	return report, nil
}

func (s Scanner) scanFile(ctx context.Context, path string) (*Finding, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > s.MaxFileSize {
		return nil, 0, errFileSkipped
	}
	// Refuse symlink replacement and avoid blocking forever if an attacker
	// swaps a regular file for a FIFO between Lstat and Open.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !os.SameFile(info, opened) {
		return nil, 0, errors.New("file changed while opening it for scanning")
	}
	return s.scanDescriptor(ctx, file, path, info)
}

// ScanOpenFile checks the already-open upload inode, not a pathname that may
// be swapped after validation. The caller retains ownership of the file.
func (s Scanner) ScanOpenFile(ctx context.Context, file *os.File, displayPath string) (Report, error) {
	if s.MaxFileSize <= 0 {
		s.MaxFileSize = defaultMaxFileSize
	}
	info, err := file.Stat()
	if err != nil {
		return Report{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > s.MaxFileSize {
		return Report{}, errFileSkipped
	}
	finding, size, err := s.scanDescriptor(ctx, file, displayPath, info)
	if err != nil {
		return Report{}, err
	}
	report := Report{FilesScanned: 1, BytesScanned: uint64(size), Findings: []Finding{}}
	if finding != nil {
		report.Findings = append(report.Findings, *finding)
	}
	return report, nil
}

func (s Scanner) scanDescriptor(ctx context.Context, file *os.File, path string, info os.FileInfo) (*Finding, int64, error) {
	opened := info

	hasher := sha256.New()
	detector := contentDetector{}
	binaryFile := false
	buffer := make([]byte, 64<<10)
	reader := io.NewSectionReader(file, 0, s.MaxFileSize+1)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, total, err
		}
		n, readErr := reader.Read(buffer)
		if n > 0 {
			if total == 0 {
				binaryFile = isBinaryExecutable(buffer[:n])
			}
			_, _ = hasher.Write(buffer[:n])
			total += int64(n)
			if total > s.MaxFileSize {
				return nil, total, errFileSkipped
			}
			detector.observe(string(buffer[:n]))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, total, readErr
		}
	}

	finished, err := file.Stat()
	if err != nil {
		return nil, total, err
	}
	if finished.Size() != total || !finished.ModTime().Equal(opened.ModTime()) {
		return nil, total, errors.New("file changed during scanning; retry the scan")
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	signature, signatureErr := s.signatures.scan(ctx, file, opened, sum)
	if signatureErr != nil && (s.signatures == nil || s.signatures.status.Status != "failed") {
		return nil, total, signatureErr
	}
	rule, severity, detail := detector.result(filepath.ToSlash(path), info.Mode(), binaryFile)
	if signature != "" {
		rule, severity, detail = "clamav-signature", SeverityHigh, "ClamAV signature: "+signature
	}
	if rule == "" {
		return nil, total, nil
	}
	systemFile := isSystemPackageFile(path)
	if systemFile {
		detail = "系统目录文件命中规则；请使用 dpkg -V、rpm -V 或可信软件包哈希进一步确认是否被篡改；" + detail
	}
	idBytes := sha256.Sum256([]byte(path + "|" + sum + "|" + rule))
	var indicators []string
	if !binaryFile {
		indicators, _ = behaviorIndicators(detector)
	}
	return &Finding{
		ID:            "f-" + hex.EncodeToString(idBytes[:8]),
		Path:          path,
		Rule:          rule,
		Severity:      severity,
		Detail:        detail,
		SHA256:        sum,
		Size:          total,
		Mode:          info.Mode().Perm().String(),
		DetectedAt:    time.Now().UTC(),
		Indicators:    indicators,
		Source:        "file",
		SystemFile:    systemFile,
		Quarantinable: quarantineEligible(path, rule, info),
	}, total, nil
}

func detect(sample, path string, mode os.FileMode) (string, string, string) {
	detector := contentDetector{}
	detector.observe(sample)
	return detector.result(path, mode, isBinaryExecutable([]byte(sample)))
}

func isBinaryExecutable(sample []byte) bool {
	if len(sample) >= 4 && string(sample[:4]) == "\x7fELF" {
		return true
	}
	if len(sample) >= 2 && sample[0] == 'M' && sample[1] == 'Z' {
		return true
	}
	if len(sample) >= 4 && ((sample[0] == 0xcf && sample[1] == 0xfa && sample[2] == 0xed && sample[3] == 0xfe) ||
		(sample[0] == 0xfe && sample[1] == 0xed && sample[2] == 0xfa && sample[3] == 0xcf)) {
		return true
	}
	for _, b := range sample {
		if b == 0 {
			return true
		}
	}
	return false
}

// Indicators are accumulated across all chunks, including boundary overlap.
// A downloader or a normal service-enablement command alone is not malware.
type contentDetector struct {
	tail                                                                                        string
	webshell, reverse, miner, minerName, minerProtocol, minerRuntime, downloader, pipe, encoded bool
	persistence, preloadFile, writer, temporary, dangerous                                      bool
	transientKernelModule, journalVacuum, randomSystemdExec                                     bool
	temporaryModule, logTamper, auditDisable                                                    bool
	cronEntry, systemdTimer, startupExec, temporaryExec                                         bool
	scheduledMinerCommand, scheduledDownloadMinerCommand, scheduledSuspiciousCommand            bool
	systemdUnitWrite, randomSystemdUnit, suspiciousSystemdExec, systemFileMutation              bool
	containerHostMutation, containerHostAccess, containerSuspiciousPayload                      bool
	serviceRestartAlways, serviceRunsAsRoot, serviceKillModeProcess                             bool
	systemdExecStart                                                                            string
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

// containsShellPipe recognizes an actual pipe into a shell command. Looking
// for a bare "|sh" substring is unsafe because ordinary regular expressions
// and prose commonly contain alternatives such as "overlay|shm".
func containsShellPipe(text string) bool {
	for start := 0; start < len(text); {
		relative := strings.IndexByte(text[start:], '|')
		if relative < 0 {
			return false
		}
		pipe := start + relative
		candidate := strings.TrimLeft(text[pipe+1:], " \t\r\n")
		for _, shell := range []string{"sh", "bash", "/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash"} {
			if !strings.HasPrefix(candidate, shell) {
				continue
			}
			rest := candidate[len(shell):]
			if rest == "" || strings.ContainsRune(" \t\r\n;|&()", rune(rest[0])) {
				return true
			}
		}
		start = pipe + 1
	}
	return false
}

func (d *contentDetector) observe(chunk string) {
	lower := strings.ToLower(d.tail + chunk)
	d.webshell = d.webshell || containsAny(lower, "eval(base64_decode(", "assert($_", "shell_exec($_", "passthru($_")
	d.reverse = d.reverse || containsAny(lower, "/dev/tcp/", "nc -e", "ncat -e", "socat exec:", "bash -i >&")
	// A single miner name or protocol is insufficient for a cryptominer
	// decision. Security utilities often embed example strings such as
	// "xmrig" and "stratum+tcp" in their help text. Keep three independent
	// classes of evidence (known miner name, pool protocol, and a runtime
	// characteristic) so an executable process is not terminated merely
	// because it contains documentation or a generic protocol parser.
	minerName := containsAny(lower, "xmrig", "minerd", "coinminer", "cpuminer", "xmr-stak", "t-rex", "nbminer", "lolminer")
	minerProtocol := containsAny(lower, "stratum+tcp", "stratum+ssl", "stratum+tls", "stratum://")
	minerRuntime := containsAny(lower, "randomx", "cryptonight", "hashrate", "monero", "donate-level", "pool_address", "pool-url")
	d.minerName = d.minerName || minerName
	d.minerProtocol = d.minerProtocol || minerProtocol
	d.minerRuntime = d.minerRuntime || minerRuntime
	// Keep this derived flag for the text-rule path. It intentionally uses the
	// same strict evidence gate as the binary path; otherwise a script that
	// merely mentions "stratum" could become an automatic containment target.
	d.miner = d.miner || (d.minerName && d.minerProtocol && d.minerRuntime)
	d.downloader = d.downloader || containsAny(lower, "curl ", "wget ")
	d.pipe = d.pipe || containsShellPipe(lower)
	d.encoded = d.encoded || containsAny(lower, "base64 -d", "base64 --decode")
	d.persistence = d.persistence || containsAny(lower, "/etc/rc.local", "crontab -e", "systemctl enable")
	d.preloadFile = d.preloadFile || strings.Contains(lower, "/etc/ld.so.preload")
	d.writer = d.writer || containsAny(lower, "echo ", "tee ")
	d.temporary = d.temporary || strings.Contains(lower, "/tmp/")
	d.dangerous = d.dangerous || containsAny(lower, "chmod 777", "chattr +i", "python -c", "perl -e")
	d.systemFileMutation = d.systemFileMutation || hasSystemFileMutation(lower)
	d.temporaryModule = d.temporaryModule || temporaryModulePattern.MatchString(lower)
	d.logTamper = d.logTamper || logTamperPattern.MatchString(lower)
	d.auditDisable = d.auditDisable || auditDisablePattern.MatchString(lower)
	d.containerHostAccess = d.containerHostAccess || containsAny(lower, "\"privileged\":true", "privileged: true", "hostpath", "\"hostpid\":true", "\"hostnetwork\":true", "/var/run/docker.sock")
	d.containerSuspiciousPayload = d.containerSuspiciousPayload || d.systemFileMutation || containsAny(lower, "xmrig", "minerd", "cpuminer", "stratum", "randomx", "cryptonight", "curl ", "wget ", "/tmp/", "/dev/shm/")
	// Track behavior rather than the module, directory, or service names seen in
	// one incident. The same persistence chain remains detectable when every
	// generated name changes on the next boot.
	d.transientKernelModule = d.transientKernelModule || hasKernelModuleActivity(lower)
	d.journalVacuum = d.journalVacuum || journalCleanupPattern.MatchString(lower)
	d.randomSystemdExec = d.randomSystemdExec || hasRandomSystemdExec(lower)
	if execStart := systemdExecStartValue(lower); execStart != "" {
		d.systemdExecStart = execStart
	}
	d.systemdUnitWrite = d.systemdUnitWrite || containsAny(lower,
		"systemctl enable", "systemctl link", "systemctl preset", "systemctl daemon-reload", "multi-user.target.wants", "default.target.wants",
		"tee /etc/systemd/", "tee /lib/systemd/", "tee /usr/lib/systemd/",
		"cat > /etc/systemd/", "cat >/etc/systemd/", "printf > /etc/systemd/",
		"install -m", "cp /tmp/", "mv /tmp/")
	// Cron and systemd timer files are configuration, so they are not
	// executable themselves. Track scheduler directives separately from the
	// generic script rules; otherwise a miner command in /etc/cron.d or a
	// timer unit would be invisible when the file has mode 0644.
	d.cronEntry = d.cronEntry || hasCronSchedule(lower)
	d.systemdTimer = d.systemdTimer || containsAny(lower,
		"[timer]", "onbootsec=", "onstartupsec=", "onunitactivesec=", "onunitinactivesec=", "oncalendar=")
	d.startupExec = d.startupExec || containsAny(lower,
		"execstart=", "wantedby=multi-user.target", "wantedby=default.target", "@reboot")
	// A random unit that runs as root and survives every exit is materially
	// different from a normal vendor helper. Keep these lifecycle directives as
	// separate evidence so a random unit can be promoted to high confidence
	// without treating every generated-looking service name as malware.
	d.serviceRestartAlways = d.serviceRestartAlways || containsAny(lower, "restart=always", "restart=on-failure")
	d.serviceRunsAsRoot = d.serviceRunsAsRoot || containsAny(lower, "user=root", "user=0")
	d.serviceKillModeProcess = d.serviceKillModeProcess || strings.Contains(lower, "killmode=process")
	d.temporaryExec = d.temporaryExec || hasTemporarySystemdCommand(lower)
	d.suspiciousSystemdExec = d.suspiciousSystemdExec || hasSuspiciousSystemdExec(lower)
	// A module loader in a startup command is suspicious only when its command
	// context points to an external or runtime module. Ordinary modprobe units
	// remain outside this signal.
	d.temporaryExec = d.temporaryExec || (hasKernelModuleActivity(lower) && temporaryModulePattern.MatchString(lower))
	if miner, download, suspicious := scheduledCommandEvidence(lower); miner {
		d.scheduledMinerCommand = true
		d.scheduledDownloadMinerCommand = d.scheduledDownloadMinerCommand || download
		d.scheduledSuspiciousCommand = d.scheduledSuspiciousCommand || suspicious
	} else if suspicious {
		d.scheduledSuspiciousCommand = true
	}
	d.tail = lower[max(0, len(lower)-256):]
}

func (d *contentDetector) result(path string, mode os.FileMode, binaryFile bool) (string, string, string) {
	startupPath := isStartupConfigurationPath(path)
	unitPath := isSystemdUnitPath(path)
	randomUnitPath := isRandomSystemdUnitPath(path)
	if isContainerStartupPath(path) {
		d.containerHostMutation = d.containerHostAccess && d.containerSuspiciousPayload
	}
	if unitPath {
		d.randomSystemdUnit = randomUnitPath
	}
	scheduledPath := isScheduledTaskPath(path) && ((isCronPath(path) && d.cronEntry) ||
		(isSystemdUnitPath(path) && (d.startupExec || d.systemdTimer)))
	if startupPath && d.transientKernelModule && d.journalVacuum {
		return "malware-persistence", SeverityHigh, startupFindingDetail(path, d, "file combines temporary kernel-module loading with journal cleanup")
	}
	if startupPath && d.transientKernelModule && (d.systemFileMutation || d.temporaryExec) {
		return "malware-persistence", SeverityHigh, startupFindingDetail(path, d, "startup configuration combines external kernel-module activity with a runtime payload or protected-file mutation")
	}
	if startupPath && d.journalVacuum && (d.systemFileMutation || d.temporaryExec) {
		return "malware-persistence", SeverityHigh, startupFindingDetail(path, d, "startup configuration combines log cleanup with a runtime payload or protected-file mutation")
	}
	if startupPath && d.transientKernelModule && d.randomSystemdExec {
		return "malware-persistence", SeverityHigh, startupFindingDetail(path, d, "file combines temporary kernel-module loading with a randomly named systemd executable")
	}
	if startupPath && d.journalVacuum && d.randomSystemdExec {
		return "malware-persistence", SeverityHigh, startupFindingDetail(path, d, "file combines journal cleanup with a randomly named systemd executable")
	}
	if startupPath && d.containerHostMutation {
		return "malware-persistence", SeverityHigh, startupFindingDetail(path, d, "container startup configuration combines host access with a system-mutating payload")
	}
	if startupPath && d.systemFileMutation {
		return "system-file-tamper", SeverityHigh, startupFindingDetail(path, d, "startup configuration mutates a protected system command or firewall binary")
	}
	if unitPath && randomUnitPath && d.randomSystemdExec &&
		(d.serviceRestartAlways || d.serviceRunsAsRoot || d.serviceKillModeProcess) {
		return "malware-persistence", SeverityHigh, startupFindingDetail(path, d, "randomly named root systemd service keeps an untrusted executable persistent")
	}
	if unitPath && randomUnitPath && (d.temporaryExec || d.transientKernelModule || d.journalVacuum) {
		return "malware-persistence", SeverityHigh, startupFindingDetail(path, d, "randomly named systemd unit starts a suspicious payload")
	}
	if unitPath && (d.transientKernelModule || d.journalVacuum) && (d.temporaryExec || d.suspiciousSystemdExec || d.systemFileMutation) {
		return "malware-persistence", SeverityHigh, startupFindingDetail(path, d, "systemd unit combines runtime module or log-cleanup activity with an untrusted startup action")
	}
	if startupPath && d.systemdUnitWrite && (d.downloader || d.temporary || d.minerName || d.dangerous) {
		return "startup-loader", SeverityHigh, startupFindingDetail(path, d, "startup script writes or enables a systemd unit while preparing a payload")
	}
	// A scheduled command that invokes a known miner is high-confidence even
	// when the scheduler file is not executable and therefore cannot enter the
	// normal script rule path. Requiring the miner name plus a protocol/runtime
	// marker keeps comments and generic cron examples from becoming findings.
	if scheduledPath && d.scheduledMinerCommand {
		return "scheduled-miner", SeverityHigh, "scheduled task invokes a known cryptocurrency miner"
	}
	if scheduledPath && d.scheduledDownloadMinerCommand {
		return "scheduled-miner", SeverityHigh, "scheduled task downloads a known cryptocurrency miner"
	}
	if isCronPath(path) && d.scheduledSuspiciousCommand {
		return "suspicious-startup", SeverityHigh, "scheduled task executes a temporary payload or mutates a protected system command"
	}
	// A randomly named executable in a systemd unit is useful startup evidence,
	// but it is not by itself enough to call the file malware. The combined
	// persistence chains above remain high risk; this single signal stays at
	// medium severity for operator review.
	if unitPath && d.randomSystemdExec {
		return "suspicious-startup", SeverityMedium, startupFindingDetail(path, d, "systemd unit starts a randomly named executable")
	}
	if unitPath && d.suspiciousSystemdExec && !d.temporaryExec {
		return "suspicious-startup", SeverityHigh, startupFindingDetail(path, d, "systemd unit starts an executable from an untrusted startup path")
	}
	if unitPath && d.temporaryExec && (d.downloader || d.minerName || d.transientKernelModule) {
		return "suspicious-startup", SeverityHigh, startupFindingDetail(path, d, "systemd unit starts a temporary executable or kernel module")
	}
	if unitPath && d.temporaryExec {
		return "suspicious-startup", SeverityMedium, startupFindingDetail(path, d, "systemd unit starts an executable from a temporary runtime path")
	}
	// Strings embedded in ELF/PE/shared-library files are not shell commands.
	// Only a strong, miner-specific marker is meaningful for binary content;
	// text-oriented rules are restricted to scripts and documents. Both paths
	// use the same independent evidence gate above.
	if binaryFile {
		if d.minerName && d.minerProtocol && d.minerRuntime {
			return "cryptominer", SeverityHigh, "binary contains a known cryptocurrency-mining indicator"
		}
		if mode.Perm()&0o002 != 0 && mode&0o111 != 0 {
			return "world-writable-executable", SeverityMedium, "executable file is writable by every local user"
		}
		return "", "", ""
	}
	// Text rules are meaningful for scripts and executable files. Restricting
	// them to that context prevents ordinary documentation, shell completion,
	// and command reference files from being treated as malware merely because
	// they quote a dangerous command.
	scriptLike := isScriptLikePath(path, mode)
	switch {
	case scriptLike && d.temporaryModule && (d.systemFileMutation || d.journalVacuum || d.logTamper || d.auditDisable):
		return "behavioral-threat", SeverityHigh, "script combines a temporary kernel module with security or log tampering; review the full source and startup chain"
	case scriptLike && d.webshell:
		return "webshell", SeverityHigh, "file contains a common webshell execution pattern"
	case scriptLike && d.reverse:
		return "reverse-shell", SeverityHigh, "file contains a reverse-shell pattern"
	case scriptLike && d.pipe && (d.downloader || d.encoded):
		return "download-and-execute", SeverityHigh, "file combines downloading or decoding content with pipe-to-shell execution"
	case scriptLike && d.miner:
		return "cryptominer", SeverityHigh, "file contains a known cryptocurrency-mining indicator"
	case (scriptLike || strings.EqualFold(filepath.Ext(path), ".service")) && d.transientKernelModule:
		return "malware-persistence", SeverityHigh, "file contains a temporary kernel-module loading persistence pattern"
	case scriptLike && ((d.preloadFile && d.writer) || (d.persistence && (d.downloader || d.temporary))):
		return "loader-persistence", SeverityHigh, "file combines persistence configuration with preload writes, downloading, or temporary payloads"
	case scriptLike && d.dangerous:
		return "dangerous-command", SeverityMedium, "file contains a command frequently used by intrusion tooling"
	}

	ext := strings.ToLower(filepath.Ext(path))
	if strings.Contains(lowerPath(path), "/upload") && (ext == ".php" || ext == ".jsp" || ext == ".asp" || ext == ".aspx" || ext == ".cgi") {
		return "script-in-upload-directory", SeverityMedium, "executable script found below an upload directory"
	}
	if mode.Perm()&0o002 != 0 && mode&0o111 != 0 {
		return "world-writable-executable", SeverityMedium, "executable file is writable by every local user"
	}
	return "", "", ""
}

func startupFindingDetail(path string, detector *contentDetector, reason string) string {
	detail := fmt.Sprintf("%s; unit=%s", reason, filepath.Base(path))
	if detector.systemdExecStart != "" {
		detail += "; ExecStart=" + detector.systemdExecStart
	}
	return detail + "; inspect the writer/downloader and the unit enablement source"
}

func hasRandomSystemdExec(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "execstart=") && !strings.HasPrefix(line, "execstartpre=") && !strings.HasPrefix(line, "execstartpost=") {
			continue
		}
		for _, field := range strings.Fields(strings.TrimSpace(strings.SplitN(line, "=", 2)[1])) {
			field = strings.Trim(field, "\"'")
			field = strings.TrimLeft(field, "-+@!")
			if !strings.HasPrefix(field, "/") || isSystemdLauncherPath(field) {
				continue
			}
			base := filepath.Base(field)
			if looksRandomStartupName(base) {
				return true
			}
			break
		}
	}
	return false
}

func hasTemporarySystemdCommand(text string) bool {
	return hasSystemdCommandPath(text, isTemporaryStartupPath)
}

// isSuspiciousStartupPath describes locations where a startup executable or
// scheduler payload is normally writable at runtime. A unit name is easy for
// malware to randomize, while this behavior remains observable across boots.
func isSuspiciousStartupPath(path string) bool {
	path = filepath.Clean(strings.Trim(path, "\"'"))
	for _, root := range []string{
		"/tmp", "/var/tmp", "/dev/shm", "/var/spool/cron", "/home",
		"/root/.cache", "/root/.config", "/root/.local",
	} {
		if path == root || strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func isTemporaryStartupPath(path string) bool {
	path = filepath.Clean(strings.Trim(path, "\"'"))
	// /run contains both attacker-controlled runtime payloads and normal
	// systemd-generated helpers (for example lxd-agent). Treat the durable
	// writable locations as automatic evidence; transient /run units are
	// correlated through journal evidence instead of path-name heuristics.
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if path == root || strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func hasSuspiciousSystemdExec(text string) bool {
	return hasSystemdCommandPath(text, isSuspiciousStartupPath)
}

func hasSystemdCommandPath(text string, predicate func(string) bool) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "execstart=") && !strings.HasPrefix(line, "execstartpre=") && !strings.HasPrefix(line, "execstartpost=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		commandSeen := false
		for _, field := range strings.Fields(parts[1]) {
			field = strings.TrimLeft(strings.Trim(field, "\"'"), "-+@!")
			if field == "" || strings.HasPrefix(field, "VAR=") || strings.Contains(field, "=") && !strings.HasPrefix(field, "/") {
				continue
			}
			if !strings.HasPrefix(field, "/") {
				// A bare first token is the command name (for example find in
				// atd.service), so later absolute arguments are not payloads.
				if !commandSeen {
					break
				}
				continue
			}
			if predicate(field) {
				return true
			}
			commandSeen = true
			if !isSystemdLauncherPath(field) {
				break
			}
		}
	}
	return false
}

// hasSystemFileMutation detects commands that remove or overwrite protected
// host controls. A plain firewall or service invocation is harmless. The
// mutation verb and protected target must occur on the same command line.
func hasSystemFileMutation(text string) bool {
	mutators := []string{"rm ", "unlink ", "shred ", "truncate ", "wipe ", "mv ", "cp ", "install ", "chmod ", "chattr ", "sed -i", "tee ", "dd ", ">/", "> /"}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Writing a service definition is startup persistence evidence and is
		// classified by the startup-loader rules. Do not downgrade that event to
		// a generic protected-file mutation merely because /etc/systemd is a
		// protected directory.
		if containsAny(line, "install ", "cp ", "mv ", "tee ") &&
			(strings.Contains(line, "/etc/systemd/") || strings.Contains(line, "/lib/systemd/") || strings.Contains(line, "/usr/lib/systemd/")) &&
			strings.Contains(line, ".service") {
			continue
		}
		if !containsAny(line, mutators...) || !containsProtectedMutationPath(line) {
			continue
		}
		return true
	}
	return false
}

// containsProtectedMutationPath recognizes protected control-plane and
// security resources by their path class. The executable name can be changed
// or replaced, so matching a short allowlist such as iptables is insufficient.
func containsProtectedMutationPath(line string) bool {
	for _, raw := range strings.FieldsFunc(line, func(r rune) bool {
		return strings.ContainsRune(" \t\r\n\"'()[]{};,|&", r)
	}) {
		path := strings.TrimSpace(raw)
		if !strings.HasPrefix(path, "/") {
			continue
		}
		clean := filepath.Clean(path)
		for _, root := range []string{
			"/etc/systemd", "/etc/modprobe.d", "/etc/ld.so.preload", "/etc/cron",
			"/var/spool/cron", "/var/log", "/run/log", "/run/systemd",
			"/lib/modules", "/usr/lib/modules",
		} {
			if clean == root || strings.HasPrefix(clean, root+string(os.PathSeparator)) {
				return true
			}
		}
		base := strings.ToLower(filepath.Base(clean))
		commandPath := false
		for _, root := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/etc", "/lib", "/usr/lib"} {
			if clean == root || strings.HasPrefix(clean, root+string(os.PathSeparator)) {
				commandPath = true
				break
			}
		}
		if commandPath && (strings.Contains(base, "iptables") || strings.Contains(base, "ip6tables") ||
			strings.Contains(base, "nft") || strings.Contains(base, "firewall") ||
			strings.Contains(base, "netfilter") || base == "ufw" || base == "ebtables" ||
			base == "arptables" || base == "systemctl" || base == "sshd" || base == "auditd") {
			return true
		}
	}
	return false
}

func isSystemdLauncherPath(path string) bool {
	switch filepath.Base(path) {
	case "sh", "bash", "dash", "zsh", "ksh", "fish", "env", "python", "python2", "python3", "perl", "ruby", "node", "java", "true", "false", "sleep", "systemd-notify":
		return true
	default:
		return false
	}
}

func looksRandomStartupName(base string) bool {
	base = strings.ToLower(strings.TrimSpace(base))
	if len(base) < 8 || len(base) > 32 || strings.ContainsAny(base, "-_.") {
		return false
	}
	if isHexToken(base) {
		return true
	}
	hasLetter, hasDigit := false, false
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			return false
		}
	}
	return hasLetter && hasDigit
}

func systemdExecStartValue(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "execstart=") && !strings.HasPrefix(line, "execstartpre=") && !strings.HasPrefix(line, "execstartpost=") {
			continue
		}
		value := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
		if separator := strings.IndexAny(value, ";\r"); separator >= 0 {
			value = strings.TrimSpace(value[:separator])
		}
		if len(value) > 512 {
			value = value[:512]
		}
		return value
	}
	return ""
}

func hasCronSchedule(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "@reboot", "@hourly", "@daily", "@weekly", "@monthly", "@annually":
				return true
			}
		}
		if len(fields) < 6 {
			continue
		}
		valid := true
		for _, field := range fields[:5] {
			if !isCronField(field) {
				valid = false
				break
			}
		}
		if valid {
			return true
		}
	}
	return false
}

// scheduledCommandEvidence inspects only commands that a scheduler would
// execute. This prevents a comment or a unit Description mentioning "xmrig"
// from becoming a scheduled-miner finding.
func scheduledCommandEvidence(text string) (miner, download, suspicious bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lowerLine := strings.ToLower(line)
		command := ""
		for _, key := range []string{"execstart=", "execstartpre=", "execstartpost="} {
			if strings.HasPrefix(lowerLine, key) {
				command = strings.TrimSpace(line[len(key):])
				break
			}
		}
		if command == "" {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				switch fields[0] {
				case "@reboot", "@hourly", "@daily", "@weekly", "@monthly", "@annually":
					command = strings.Join(fields[1:], " ")
				}
			}
			if command == "" && len(fields) >= 6 {
				valid := true
				for _, field := range fields[:5] {
					if !isCronField(field) {
						valid = false
						break
					}
				}
				if valid {
					command = strings.Join(fields[5:], " ")
				}
			}
		}
		if command == "" {
			continue
		}
		lowerCommand := strings.ToLower(command)
		if suspiciousScheduledCommand(lowerCommand) {
			suspicious = true
		}
		name := containsAny(lowerCommand, "xmrig", "minerd", "coinminer", "cpuminer", "xmr-stak", "t-rex", "nbminer", "lolminer")
		if !name {
			continue
		}
		if containsAny(lowerCommand, "stratum+tcp", "stratum+ssl", "stratum+tls", "stratum://", "randomx", "cryptonight", "hashrate", "monero", "donate-level", "pool_address", "pool-url") {
			return true, false, suspicious
		}
		if containsAny(lowerCommand, "curl ", "wget ") {
			return true, true, suspicious
		}
	}
	return false, false, suspicious
}

func suspiciousScheduledCommand(command string) bool {
	if hasSystemFileMutation(command) {
		return true
	}
	if containsAny(command, "curl ", "wget ") && (containsShellPipe(command) || strings.Contains(command, "/tmp/") || strings.Contains(command, "/var/tmp/") || strings.Contains(command, "/dev/shm/")) {
		return true
	}
	for _, field := range strings.Fields(command) {
		if isSuspiciousStartupPath(strings.Trim(field, "\"'")) {
			return true
		}
	}
	return false
}

func isCronField(field string) bool {
	if field == "" {
		return false
	}
	for _, r := range field {
		if !(r == '*' || r == ',' || r == '-' || r == '/' || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return strings.ContainsAny(field, "*0123456789")
}

func isScheduledTaskPath(path string) bool {
	return isCronPath(path) || isSystemdUnitPath(path)
}

func isCronPath(path string) bool {
	clean := lowerPath(path)
	if clean == "/etc/crontab" {
		return true
	}
	for _, root := range []string{
		"/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/",
		"/etc/cron.monthly/", "/var/spool/cron/", "/var/spool/cron/crontabs/",
	} {
		if strings.HasPrefix(clean, root) {
			return true
		}
	}
	return false
}

func isSystemdUnitPath(path string) bool {
	clean := lowerPath(path)
	if !strings.HasSuffix(clean, ".service") && !strings.HasSuffix(clean, ".timer") &&
		!strings.HasSuffix(clean, ".path") && !strings.HasSuffix(clean, ".socket") &&
		!strings.HasSuffix(clean, ".mount") {
		return false
	}
	for _, root := range []string{"/etc/systemd/", "/run/systemd/", "/lib/systemd/", "/usr/lib/systemd/", "/usr/local/lib/systemd/"} {
		if strings.HasPrefix(clean, root) {
			return true
		}
	}
	if strings.HasPrefix(clean, "/root/.config/systemd/user/") {
		return true
	}
	if strings.HasPrefix(clean, "/home/") {
		parts := strings.Split(strings.TrimPrefix(clean, "/home/"), "/")
		return len(parts) >= 5 && parts[0] != "" && parts[1] == ".config" && parts[2] == "systemd" && parts[3] == "user"
	}
	return false
}

// IsSystemdUnitPath identifies system-manager units eligible for the API's
// system-wide mask. User-manager units must not mask an unrelated system unit
// with the same name.
func IsSystemdUnitPath(path string) bool {
	if !isSystemdUnitPath(path) {
		return false
	}
	clean := lowerPath(path)
	for _, root := range []string{
		"/etc/systemd/system/", "/etc/systemd/system.control/", "/etc/systemd/system.extra/",
		"/run/systemd/system/", "/run/systemd/transient/", "/run/systemd/generator/",
		"/run/systemd/generator.early/", "/run/systemd/generator.late/",
		"/lib/systemd/system/", "/usr/lib/systemd/system/", "/usr/local/lib/systemd/system/",
	} {
		if strings.HasPrefix(clean, root) {
			return true
		}
	}
	return false
}

// IsTransientSystemdUnitPath identifies a random unit created below systemd's
// runtime transient directory. The scanner only uses this for a high-confidence
// journal finding that also records kernel-module loading and host tampering;
// ordinary vendor units remain outside the automatic mask path.
func IsTransientSystemdUnitPath(path string) bool {
	clean := lowerPath(path)
	if !strings.HasPrefix(clean, "/run/systemd/transient/") || !isSystemdUnitPath(clean) {
		return false
	}
	base := strings.TrimSuffix(filepath.Base(clean), ".service")
	return looksRandomStartupName(base)
}

// IsTransientSystemdRuntimePath recognizes every transient service path. The
// random-name predicate above is useful for heuristic scoring, while response
// handling must also contain an ordinary unit name when journal metadata and
// unit behavior identify the same malicious startup chain.
func IsTransientSystemdRuntimePath(path string) bool {
	clean := lowerPath(path)
	if !strings.HasPrefix(clean, "/run/systemd/transient/") || !isSystemdUnitPath(clean) {
		return false
	}
	base := filepath.Base(clean)
	return strings.HasSuffix(base, ".service") && len(strings.TrimSuffix(base, ".service")) > 0
}

func isRandomSystemdUnitPath(path string) bool {
	if !isSystemdUnitPath(path) {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	for _, suffix := range []string{".service", ".timer", ".path", ".socket", ".mount"} {
		base = strings.TrimSuffix(base, suffix)
	}
	return looksRandomStartupName(base)
}

func isStartupConfigurationPath(path string) bool {
	clean := lowerPath(path)
	if isSystemdUnitPath(path) || isContainerStartupPath(path) || clean == "/etc/rc.local" ||
		strings.HasPrefix(clean, "/etc/init/") || strings.HasPrefix(clean, "/etc/init.d/") ||
		strings.HasPrefix(clean, "/etc/rc.d/") || isShellProfilePath(clean) ||
		isModulesLoadPath(clean) || isDesktopAutostartPath(clean) || isDispatcherStartupPath(clean) ||
		isUdevStartupPath(clean) || isCloudStartupPath(clean) || isSupervisorStartupPath(clean) {
		return true
	}
	for _, root := range []string{"/etc/rc0.d/", "/etc/rc1.d/", "/etc/rc2.d/", "/etc/rc3.d/", "/etc/rc4.d/", "/etc/rc5.d/", "/etc/rc6.d/", "/etc/rcs.d/"} {
		if strings.HasPrefix(clean, root) {
			return true
		}
	}
	return isCronPath(path)
}

func isModulesLoadPath(path string) bool {
	clean := lowerPath(path)
	return clean == "/etc/modules" || strings.HasPrefix(clean, "/etc/modules-load.d/") ||
		strings.HasPrefix(clean, "/run/modules-load.d/") || strings.HasPrefix(clean, "/usr/lib/modules-load.d/") ||
		strings.HasPrefix(clean, "/usr/local/lib/modules-load.d/")
}

func isDesktopAutostartPath(path string) bool {
	clean := lowerPath(path)
	return strings.HasPrefix(clean, "/etc/xdg/autostart/") || strings.HasPrefix(clean, "/usr/share/xdg/autostart/") ||
		strings.HasSuffix(clean, "/.config/autostart") || strings.Contains(clean, "/.config/autostart/")
}

func isDispatcherStartupPath(path string) bool {
	clean := lowerPath(path)
	return strings.HasPrefix(clean, "/etc/network/if-") || strings.HasPrefix(clean, "/etc/network/dispatcher.d/") ||
		strings.HasPrefix(clean, "/etc/network/if-pre-up.d/") || strings.HasPrefix(clean, "/etc/network/if-up.d/") ||
		strings.HasPrefix(clean, "/etc/network/if-down.d/") || strings.HasPrefix(clean, "/etc/network/if-post-down.d/") ||
		strings.HasPrefix(clean, "/etc/networkmanager/dispatcher.d/")
}

func isUdevStartupPath(path string) bool {
	return strings.HasPrefix(lowerPath(path), "/etc/udev/rules.d/")
}

func isCloudStartupPath(path string) bool {
	clean := lowerPath(path)
	return strings.HasPrefix(clean, "/var/lib/cloud/scripts/")
}

func isSupervisorStartupPath(path string) bool {
	clean := lowerPath(path)
	return strings.HasPrefix(clean, "/etc/supervisor/") || clean == "/etc/supervisord.conf" ||
		strings.HasPrefix(clean, "/etc/monit/") || strings.HasPrefix(clean, "/etc/pm2/") ||
		strings.HasPrefix(clean, "/etc/containers/systemd/") || strings.HasPrefix(clean, "/usr/share/containers/systemd/")
}

func isContainerStartupPath(path string) bool {
	clean := lowerPath(path)
	for _, root := range []string{
		"/etc/kubernetes/manifests/", "/etc/rancher/", "/var/lib/rancher/rke2/agent/pod-manifests/",
		"/var/lib/rancher/k3s/server/manifests/", "/var/lib/kubelet/manifests/",
	} {
		if strings.HasPrefix(clean, root) {
			return true
		}
	}
	// Docker's config.v2.json is restart metadata. The sibling *-json.log
	// files are runtime output and may quote commands from an unrelated
	// container; treating those logs as startup configuration creates noisy
	// findings and can make an operator quarantine evidence instead of the
	// actual container definition.
	return strings.HasPrefix(clean, "/var/lib/docker/containers/") && strings.HasSuffix(clean, "/config.v2.json")
}

func isDockerRuntimeLogPath(path string) bool {
	clean := lowerPath(path)
	return strings.HasPrefix(clean, "/var/lib/docker/containers/") && strings.HasSuffix(clean, "-json.log")
}

func isShellProfilePath(path string) bool {
	clean := lowerPath(path)
	for _, exact := range []string{"/etc/profile", "/etc/bash.bashrc", "/root/.profile", "/root/.bash_profile", "/root/.bashrc", "/root/.zshrc"} {
		if clean == exact {
			return true
		}
	}
	return strings.HasPrefix(clean, "/etc/profile.d/") || strings.HasSuffix(clean, "/.profile") ||
		strings.HasSuffix(clean, "/.bash_profile") || strings.HasSuffix(clean, "/.bashrc") || strings.HasSuffix(clean, "/.zshrc")
}

func isScriptLikePath(path string, mode os.FileMode) bool {
	if mode&0o111 != 0 {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".asp", ".aspx", ".bash", ".cgi", ".fish", ".js", ".jsp", ".lua", ".php", ".pl", ".ps1", ".py", ".rb", ".sh", ".ts", ".zsh":
		return true
	default:
		return false
	}
}

func lowerPath(path string) string {
	return strings.ToLower(filepath.ToSlash(path))
}

func isVirtualSystemDirectory(path string) bool {
	clean := filepath.Clean(path)
	for _, prefix := range []string{"/proc", "/sys", "/dev", "/run"} {
		if clean == prefix || strings.HasPrefix(clean, prefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func isSharedMemoryPath(path string) bool {
	clean := filepath.Clean(path)
	return clean == "/dev/shm" || strings.HasPrefix(clean, "/dev/shm/")
}

func isContainerStorageDirectory(path string) bool {
	clean := filepath.Clean(path)
	for _, prefix := range []string{
		"/var/lib/docker",
		"/var/lib/containerd",
		"/var/lib/kubelet",
		"/var/lib/rancher",
	} {
		if clean == prefix || strings.HasPrefix(clean, prefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
