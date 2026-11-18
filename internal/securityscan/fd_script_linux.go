//go:build linux

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
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxFDScriptBytes = 4 << 20

// A /dev/fd path belongs to the process that opened it. Only inspect a
// descriptor actually passed to a shell, and never read pipes: doing so
// would consume data intended for the running process.
func collectFDScriptFindings(ctx context.Context, scanner Scanner, limit int) ([]Finding, error) {
	if limit <= 0 {
		return nil, nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	if scanner.MaxFileSize <= 0 {
		scanner.MaxFileSize = defaultMaxFileSize
	}
	findings := make([]Finding, 0)
	for _, entry := range entries {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		procDir := filepath.Join("/proc", entry.Name())
		exe, exeErr := os.Readlink(filepath.Join(procDir, "exe"))
		if exeErr != nil || !isSupportedScriptShell(exe) {
			continue
		}
		args := strings.Split(readProcTextLimited(filepath.Join(procDir, "cmdline"), maxProcMetadataBytes), "\x00")
		fd, argument, ok := shellScriptDescriptor(pid, args)
		if !ok {
			continue
		}
		// Most process-substitution descriptors are pipes. Do not hash the
		// interpreter or open a pipe unless a regular script is actually present.
		fdPath := filepath.Join("/proc", entry.Name(), "fd", strconv.Itoa(fd))
		if info, statErr := os.Stat(fdPath); statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		identity, sample, info, target, captureErr := captureFDScript(pid, fd, argument)
		indicators, suspicious := scriptBehavior(sample)
		if captureErr != nil {
			continue
		}
		signature, _ := scanner.signatures.scanSample(ctx, sample)
		if !suspicious && signature == "" {
			continue
		}
		rule := "malicious-fd-script"
		detail := fmt.Sprintf("PID %d is executing a descriptor-backed shell script with combined indicators: %s; preserve the script before stopping the verified interpreter", pid, strings.Join(indicators, ", "))
		if signature != "" {
			rule = "clamav-fd-script"
			detail = fmt.Sprintf("PID %d is executing a descriptor-backed script matching ClamAV signature %s; preserve the script before stopping the verified interpreter", pid, signature)
		}
		scriptHash := sha256.Sum256(sample)
		id := sha256.Sum256([]byte(fmt.Sprintf("fd-script|%d|%s|%d|%x", pid, identity.start, fd, scriptHash)))
		finding := Finding{
			ID: "d-" + hex.EncodeToString(id[:8]), Path: fmt.Sprintf("/proc/%d/fd/%d", pid, fd),
			Rule: rule, Severity: SeverityHigh, Source: "fd-script", PID: pid,
			ProcessStartTime: identity.start, Executable: identity.executable,
			ExecutableSHA256: identity.sha256, ExecutableSize: identity.size,
			ScriptFD: fd, ScriptArgument: argument, ScriptFDTarget: target, SHA256: hex.EncodeToString(scriptHash[:]),
			Size: int64(len(sample)), Mode: info.Mode().Perm().String(), DetectedAt: time.Now().UTC(),
			Indicators: indicators,
			Detail:     detail,
		}
		// These fields are investigative leads, never authorization to signal
		// the parent. Discard them if this PID changed while reading procfs.
		finding.ParentPID, finding.ParentExecutable, finding.Cgroup = scriptProcessProvenance(pid)
		if start, startErr := ReadProcessStartTime(pid); startErr != nil || start != identity.start {
			continue
		}
		findings = append(findings, finding)
		if len(findings) >= limit {
			break
		}
		// If the descriptor still has a normal pathname, submit the exact same
		// inode to the ordinary file-quarantine checks as a separate finding.
		if filepath.IsAbs(target) && !strings.HasSuffix(target, " (deleted)") && !strings.HasPrefix(target, "/proc/") && !strings.HasPrefix(target, "/dev/") {
			pathInfo, statErr := os.Lstat(target)
			if statErr == nil && pathInfo.Mode().IsRegular() && os.SameFile(info, pathInfo) {
				fileFinding, _, scanErr := scanner.scanFile(ctx, target)
				if scanErr == nil && fileFinding != nil && fileFinding.Rule == "behavioral-threat" &&
					!isNodeWallArtifactPath(target) && !isSystemPackageFile(target) && suspiciousWritableContext(target, pathInfo) {
					// This extra eligibility applies only when the same inode is a
					// verified live script with the stronger combined behavior gate.
					fileFinding.Quarantinable = true
				}
				if scanErr == nil && fileFinding != nil && fileFinding.Quarantinable && fileFinding.SHA256 == finding.SHA256 && fileFinding.Size == finding.Size {
					fileFinding.RelatedTo = finding.ID
					findings = appendUniqueFindings(findings, []Finding{*fileFinding}, limit)
				}
			}
		}
		if len(findings) >= limit {
			break
		}
	}
	return findings, nil
}

func scriptProcessProvenance(pid int) (int, string, string) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	status := readProcTextLimited(filepath.Join(procDir, "status"), maxProcMetadataBytes)
	parentPID := 0
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "PPid:") {
			parentPID, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			break
		}
	}
	parentExecutable := ""
	if parentPID > 0 {
		parentExecutable, _ = os.Readlink(filepath.Join("/proc", strconv.Itoa(parentPID), "exe"))
	}
	cgroup := strings.TrimSpace(readProcTextLimited(filepath.Join(procDir, "cgroup"), maxProcMetadataBytes))
	return parentPID, parentExecutable, cgroup
}

func isSupportedScriptShell(path string) bool {
	switch filepath.Base(path) {
	case "bash", "sh", "dash", "zsh", "ksh":
		return true
	default:
		return false
	}
}

func shellScriptArgument(args []string) (string, bool) {
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if arg == "" {
			continue
		}
		if arg == "--" && index+1 < len(args) {
			return args[index+1], args[index+1] != ""
		}
		if strings.HasPrefix(arg, "-") {
			// With -c the next value is program text, not a script pathname.
			if arg == "--command" || (!strings.HasPrefix(arg, "--") && strings.Contains(arg, "c")) {
				return "", false
			}
			if arg == "--rcfile" || arg == "--init-file" || arg == "-o" || arg == "-O" {
				index++
			}
			continue
		}
		return arg, true
	}
	return "", false
}

func scriptFDFromArgs(args []string) (int, bool) {
	arg, ok := shellScriptArgument(args)
	if !ok {
		return 0, false
	}
	for _, prefix := range []string{"/dev/fd/", "/proc/self/fd/"} {
		if strings.HasPrefix(arg, prefix) {
			value := strings.TrimPrefix(arg, prefix)
			fd, err := strconv.Atoi(value)
			return fd, err == nil && fd >= 0 && fd <= 65535 && strconv.Itoa(fd) == value
		}
	}
	return 0, false
}

// A normal shell script can remain open on fd 255 even though argv names the
// original path. Require the open descriptor and that path to name the same
// inode; a command-line string alone is not enough to authorize a signal.
func shellScriptDescriptor(pid int, args []string) (int, string, bool) {
	argument, ok := shellScriptArgument(args)
	if !ok {
		return 0, "", false
	}
	if fd, direct := scriptFDFromArgs(args); direct {
		return fd, argument, true
	}
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	var path string
	if filepath.IsAbs(argument) {
		path = filepath.Join(procDir, "root", strings.TrimPrefix(filepath.Clean(argument), "/"))
	} else {
		path = filepath.Join(procDir, "cwd", argument)
	}
	wanted, err := os.Stat(path)
	if err != nil || !wanted.Mode().IsRegular() {
		return 0, "", false
	}
	entries, err := os.ReadDir(filepath.Join(procDir, "fd"))
	if err != nil {
		return 0, "", false
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd < 0 || fd > 65535 {
			continue
		}
		info, err := os.Stat(filepath.Join(procDir, "fd", entry.Name()))
		if err == nil && info.Mode().IsRegular() && os.SameFile(wanted, info) {
			return fd, argument, true
		}
	}
	return 0, "", false
}

func isMaliciousFDScript(sample []byte) bool {
	_, strong := scriptBehavior(sample)
	return strong
}

func captureFDScript(pid, fd int, argument string) (processIdentity, []byte, os.FileInfo, string, error) {
	var empty processIdentity
	identity, err := captureProcessIdentity(pid)
	if err != nil || identity.deleted {
		return empty, nil, nil, "", errors.New("cannot verify the shell process")
	}
	if !isSupportedScriptShell(identity.executable) {
		return empty, nil, nil, "", errors.New("descriptor owner is not a supported shell")
	}
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	args := strings.Split(readProcTextLimited(filepath.Join(procDir, "cmdline"), maxProcMetadataBytes), "\x00")
	currentFD, currentArgument, ok := shellScriptDescriptor(pid, args)
	if !ok || currentFD != fd || (argument != "" && currentArgument != argument) {
		return empty, nil, nil, "", errors.New("shell no longer references the descriptor")
	}
	path := filepath.Join(procDir, "fd", strconv.Itoa(fd))
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxFDScriptBytes {
		return empty, nil, nil, "", errors.New("descriptor is not a bounded regular file")
	}
	target, err := os.Readlink(path)
	if err != nil {
		return empty, nil, nil, "", err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return empty, nil, nil, "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return empty, nil, nil, "", errors.New("descriptor changed while opening")
	}
	sample, err := io.ReadAll(io.NewSectionReader(file, 0, maxFDScriptBytes+1))
	if err != nil || int64(len(sample)) != info.Size() {
		return empty, nil, nil, "", errors.New("descriptor script changed during reading")
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return empty, nil, nil, "", errors.New("descriptor changed while scanning")
	}
	endIdentity, err := captureProcessIdentity(pid)
	if err != nil || endIdentity != identity {
		return empty, nil, nil, "", errors.New("shell identity changed while scanning")
	}
	return identity, sample, info, target, nil
}

// ReadFDScriptSample verifies both the interpreter and the still-open script
// every time it is used for evidence or before sending a signal.
func ReadFDScriptSample(finding Finding) ([]byte, error) {
	if finding.Source != "fd-script" || finding.PID <= 1 || finding.ProcessStartTime == "" || finding.SHA256 == "" || finding.ExecutableSHA256 == "" || finding.ScriptFD < 0 {
		return nil, errors.New("descriptor finding lacks verified identity")
	}
	identity, sample, _, target, err := captureFDScript(finding.PID, finding.ScriptFD, finding.ScriptArgument)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(sample)
	if identity.start != finding.ProcessStartTime || identity.executable != finding.Executable || identity.sha256 != finding.ExecutableSHA256 || identity.size != finding.ExecutableSize ||
		target != finding.ScriptFDTarget || int64(len(sample)) != finding.Size || hex.EncodeToString(sum[:]) != finding.SHA256 ||
		(finding.Rule != "clamav-fd-script" && !isMaliciousFDScript(sample)) {
		return nil, errors.New("descriptor or interpreter no longer matches the scan")
	}
	return sample, nil
}
