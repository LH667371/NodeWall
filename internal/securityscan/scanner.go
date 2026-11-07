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
)

const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"

	defaultMaxFileSize = 32 << 20
	defaultMaxFiles    = 200000
	defaultMaxFindings = 200
)

var errFileSkipped = errors.New("file is not regular or exceeds the scan size limit")

type Finding struct {
	ID               string              `json:"id"`
	Path             string              `json:"path"`
	Rule             string              `json:"rule"`
	Severity         string              `json:"severity"`
	Detail           string              `json:"detail"`
	SHA256           string              `json:"sha256"`
	Size             int64               `json:"size"`
	Mode             string              `json:"mode"`
	DetectedAt       time.Time           `json:"detected_at"`
	Quarantined      bool                `json:"quarantined,omitempty"`
	QuarantinePath   string              `json:"quarantine_path,omitempty"`
	Source           string              `json:"source,omitempty"`
	Quarantinable    bool                `json:"quarantinable,omitempty"`
	PID              int                 `json:"pid,omitempty"`
	CPUPercent       float64             `json:"cpu_percent,omitempty"`
	Command          string              `json:"command,omitempty"`
	Executable       string              `json:"executable,omitempty"`
	ContainerID      string              `json:"container_id,omitempty"`
	Terminated       bool                `json:"terminated,omitempty"`
	Termination      *ProcessTermination `json:"termination,omitempty"`
	TerminationError string              `json:"termination_error,omitempty"`
}

type Progress struct {
	FilesScanned  uint64 `json:"files_scanned"`
	FilesSkipped  uint64 `json:"files_skipped"`
	MountsSkipped uint64 `json:"mounts_skipped"`
	ReadErrors    uint64 `json:"read_errors"`
	BytesScanned  uint64 `json:"bytes_scanned"`
	Findings      int    `json:"findings"`
	Phase         string `json:"phase,omitempty"`
	// FindingsReady is set for the process phase so the API can expose fast
	// process evidence while the much slower file walk continues.
	FindingsReady   bool      `json:"findings_ready,omitempty"`
	ProcessFindings []Finding `json:"process_findings,omitempty"`
}

type Report struct {
	FilesScanned  uint64    `json:"files_scanned"`
	FilesSkipped  uint64    `json:"files_skipped"`
	MountsSkipped uint64    `json:"mounts_skipped"`
	ReadErrors    uint64    `json:"read_errors"`
	BytesScanned  uint64    `json:"bytes_scanned"`
	Findings      []Finding `json:"findings"`
	Truncated     bool      `json:"truncated"`
}

type Scanner struct {
	MaxFileSize int64
	MaxFiles    uint64
	MaxFindings int
	// SkipMounts prevents a root scan from walking NFS shares, container
	// overlay mounts, and virtual filesystems that are separate scan scopes.
	// The caller can disable it for an explicit mounted-filesystem audit.
	SkipMounts bool
}

func New() Scanner {
	return Scanner{
		MaxFileSize: defaultMaxFileSize,
		MaxFiles:    defaultMaxFiles,
		MaxFindings: defaultMaxFindings,
		SkipMounts:  true,
	}
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
	progress := func(phase string, findingsReady bool) {
		if onProgress != nil {
			var processFindings []Finding
			if findingsReady {
				processFindings = append([]Finding(nil), report.Findings...)
			}
			onProgress(Progress{
				FilesScanned:    report.FilesScanned,
				FilesSkipped:    report.FilesSkipped,
				MountsSkipped:   report.MountsSkipped,
				ReadErrors:      report.ReadErrors,
				BytesScanned:    report.BytesScanned,
				Findings:        len(report.Findings),
				Phase:           phase,
				FindingsReady:   findingsReady,
				ProcessFindings: processFindings,
			})
		}
	}

	// Process evidence is deliberately collected before the file walk. A root
	// scan can cover mounted data for hours, but a high-CPU/deleted executable
	// finding must be visible quickly enough for an operator to contain it.
	if root == "/" {
		processCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		processFindings, processErr := collectProcessIntegrityFindings(processCtx, s.MaxFindings)
		// Publish integrity evidence as soon as it is available. CPU sampling
		// deliberately follows it, so a hidden/deleted process can be acted on
		// while the second sample is still running.
		if processErr == nil {
			report.Findings = append(report.Findings, processFindings...)
			progress("process", true)
		}
		if processErr == nil && len(processFindings) < s.MaxFindings {
			cpuFindings, cpuErr := collectHighCPUFindings(processCtx, s.MaxFindings-len(processFindings))
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
		if processErr != nil && !errors.Is(processErr, context.Canceled) && !errors.Is(processErr, context.DeadlineExceeded) {
			report.ReadErrors++
			report.Truncated = true
		}
		if processErr != nil {
			// Keep any integrity findings already published, and expose the
			// process phase even when the CPU sample could not complete.
			progress("process", true)
		}
	}

	mounts := map[string]struct{}{}
	if s.SkipMounts {
		mounts = scanMountPoints(root)
	}

	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			report.ReadErrors++
			report.Truncated = true
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
				if _, mounted := mounts[filepath.Clean(path)]; mounted {
					report.MountsSkipped++
					progress("files", false)
					return filepath.SkipDir
				}
			}
			if root == "/" && isVirtualSystemDirectory(path) {
				return filepath.SkipDir
			}
			// Container image/layer stores are often on the root filesystem, so
			// mount-point filtering alone still walks every duplicated layer.
			// They remain available as explicit scan roots; the global recovery
			// pass skips them so process evidence and host paths return quickly.
			if root == "/" && isContainerStorageDirectory(path) {
				report.MountsSkipped++
				progress("files", false)
				return filepath.SkipDir
			}
			if isNodeWallTrustedPath(path) {
				report.FilesSkipped++
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
			report.Truncated = true
			return filepath.SkipAll
		}

		finding, size, scanErr := s.scanFile(ctx, path)
		if scanErr != nil {
			if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
				return scanErr
			}
			if errors.Is(scanErr, errFileSkipped) {
				report.FilesSkipped++
			} else {
				report.ReadErrors++
			}
			report.Truncated = true
			progress("files", false)
			return nil
		}
		report.FilesScanned++
		report.BytesScanned += uint64(size)
		if finding != nil {
			if len(report.Findings) < s.MaxFindings {
				report.Findings = append(report.Findings, *finding)
			} else {
				report.Truncated = true
			}
		}
		progress("files", false)
		return nil
	})
	if err != nil {
		return report, err
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
	rule, severity, detail := detector.result(filepath.ToSlash(path), info.Mode(), binaryFile)
	if rule == "" {
		return nil, total, nil
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	idBytes := sha256.Sum256([]byte(path + "|" + sum + "|" + rule))
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
		Source:        "file",
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
	tail                                                                             string
	webshell, reverse, miner, minerProtocol, minerRuntime, downloader, pipe, encoded bool
	persistence, preloadFile, writer, temporary, dangerous                           bool
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
	// A single miner name is insufficient for an ELF decision. Security
	// utilities often embed example strings such as "xmrig" and
	// "stratum+tcp" in their help text. Require an independent protocol
	// marker and a runtime-miner characteristic before treating a binary as
	// a cryptominer; text scripts retain the broader indicator rule below.
	minerName := containsAny(lower, "xmrig", "minerd", "coinminer")
	minerProtocol := containsAny(lower, "stratum+tcp", "stratum+ssl", "stratum+tls", "stratum://")
	minerRuntime := containsAny(lower, "randomx", "cryptonight", "hashrate", "monero", "donate-level", "pool_address", "pool-url", "worker-id", "json_rpc", "getwork")
	d.miner = d.miner || minerName || minerProtocol
	d.minerProtocol = d.minerProtocol || minerProtocol
	d.minerRuntime = d.minerRuntime || minerRuntime
	d.downloader = d.downloader || containsAny(lower, "curl ", "wget ")
	d.pipe = d.pipe || containsShellPipe(lower)
	d.encoded = d.encoded || containsAny(lower, "base64 -d", "base64 --decode")
	d.persistence = d.persistence || containsAny(lower, "/etc/rc.local", "crontab -e", "systemctl enable")
	d.preloadFile = d.preloadFile || strings.Contains(lower, "/etc/ld.so.preload")
	d.writer = d.writer || containsAny(lower, "echo ", "tee ")
	d.temporary = d.temporary || strings.Contains(lower, "/tmp/")
	d.dangerous = d.dangerous || containsAny(lower, "chmod 777", "chattr +i", "python -c", "perl -e")
	d.tail = lower[max(0, len(lower)-256):]
}

func (d *contentDetector) result(path string, mode os.FileMode, binaryFile bool) (string, string, string) {
	// Strings embedded in ELF/PE/shared-library files are not shell commands.
	// Only a strong, miner-specific marker is meaningful for binary content;
	// text-oriented rules are restricted to scripts and documents.
	if binaryFile {
		if d.miner && d.minerProtocol && d.minerRuntime {
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
	case scriptLike && d.webshell:
		return "webshell", SeverityHigh, "file contains a common webshell execution pattern"
	case scriptLike && d.reverse:
		return "reverse-shell", SeverityHigh, "file contains a reverse-shell pattern"
	case scriptLike && d.pipe && (d.downloader || d.encoded):
		return "download-and-execute", SeverityHigh, "file combines downloading or decoding content with pipe-to-shell execution"
	case scriptLike && d.miner:
		return "cryptominer", SeverityHigh, "file contains a known cryptocurrency-mining indicator"
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
