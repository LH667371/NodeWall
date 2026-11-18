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
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	maxPersistenceFiles       = 4096
	maxPersistenceEntries     = 16384
	maxPersistenceFileSize    = 4 << 20
	maxRelatedPayloadsPerUnit = 8
)

var persistenceRoots = []string{
	"/etc/systemd/system",
	"/etc/systemd/system.control",
	"/etc/systemd/system.extra",
	"/etc/systemd/user",
	"/etc/systemd/user.control",
	"/etc/systemd/user.extra",
	"/etc/systemd/system-generators",
	"/etc/systemd/user-generators",
	"/run/systemd/system",
	"/run/systemd/transient",
	"/run/systemd/generator",
	"/run/systemd/generator.early",
	"/run/systemd/generator.late",
	"/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/usr/local/lib/systemd/system",
	"/var/lib/systemd/linger",
	"/etc/init.d",
	"/etc/init",
	"/etc/rc.d",
	"/etc/rc0.d",
	"/etc/rc1.d",
	"/etc/rc2.d",
	"/etc/rc3.d",
	"/etc/rc4.d",
	"/etc/rc5.d",
	"/etc/rc6.d",
	"/etc/rcS.d",
	"/etc/cron.d",
	"/etc/crontab",
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/var/spool/cron",
	"/var/spool/cron/crontabs",
	"/var/spool/at",
	"/etc/rc.local",
	"/etc/modules",
	"/etc/modules-load.d",
	"/run/modules-load.d",
	"/usr/lib/modules-load.d",
	"/usr/local/lib/modules-load.d",
	"/etc/xdg/autostart",
	"/usr/share/xdg/autostart",
	"/etc/network/if-pre-up.d",
	"/etc/network/if-up.d",
	"/etc/network/if-down.d",
	"/etc/NetworkManager/dispatcher.d",
	"/etc/udev/rules.d",
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/profile.d",
	"/root/.profile",
	"/root/.bash_profile",
	"/root/.bashrc",
	"/root/.zshrc",
	// Kubernetes and container runtimes can recreate a host-side payload on
	// reboot even when the process is absent from the host process table.
	"/etc/kubernetes/manifests",
	"/etc/rancher",
	"/var/lib/rancher/rke2/agent/pod-manifests",
	"/var/lib/rancher/k3s/server/manifests",
	"/var/lib/kubelet/manifests",
	"/var/lib/docker/containers",
	"/etc/containers/systemd",
	"/usr/share/containers/systemd",
	"/etc/supervisor",
	"/etc/supervisord.conf",
	"/etc/monit",
	"/etc/pm2",
	"/var/lib/cloud/scripts",
}

// collectPersistenceFindings is the bounded filesystem part of the quick
// scan. It follows only known startup directories, then follows absolute
// ExecStart/script references from a suspicious unit. This gives the operator
// the service, its payload, and the related writer/downloader without walking
// the entire root filesystem.
func collectPersistenceFindings(ctx context.Context, scanner Scanner, limit int) ([]Finding, []CoverageGap, uint64, error) {
	if limit <= 0 {
		return nil, nil, 0, nil
	}
	if scanner.MaxFileSize <= 0 || scanner.MaxFileSize > maxPersistenceFileSize {
		scanner.MaxFileSize = maxPersistenceFileSize
	}
	candidates, aliases, gaps, gapsOmitted := collectPersistencePaths(ctx)
	addGap := func(path, reason string) {
		if len(gaps) < maxCoverageGaps {
			gaps = append(gaps, CoverageGap{Path: path, Reason: reason})
		} else {
			gapsOmitted++
		}
	}
	findings := make([]Finding, 0, min(limit, len(candidates)))
	byPath := make(map[string]int, len(candidates))
	for _, path := range candidates {
		if err := ctx.Err(); err != nil {
			return findings, gaps, gapsOmitted, err
		}
		if len(findings) >= limit {
			addGap(path, "startup-finding-limit")
			break
		}
		info, data, err := readPersistenceFile(path, scanner.MaxFileSize)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return findings, gaps, gapsOmitted, err
			}
			addGap(path, "startup-file-unreadable")
			continue
		}
		rule, severity, detail := detect(string(data), path, info.Mode())
		if signature, scanErr := scanner.signatures.scanSample(ctx, data); scanErr == nil && signature != "" {
			rule, severity, detail = "clamav-signature", SeverityHigh, "ClamAV signature: "+signature
		}
		// Evaluate an enabled symlink in its startup context, but keep the
		// actual inode as the finding so isolation never moves a symlink.
		for _, alias := range aliases[path] {
			if aliasRule, aliasSeverity, aliasDetail := detect(string(data), alias, info.Mode()); rule != "clamav-signature" && aliasRule != "" && (rule == "" || aliasSeverity == SeverityHigh) {
				rule, severity, detail = aliasRule, aliasSeverity, aliasDetail
			}
		}
		if isSystemdUnitPath(path) && abnormalSystemdUnit(path, data) && rule == "" {
			rule, severity = "suspicious-startup", SeverityMedium
			detail = fmt.Sprintf("systemd unit has a random or temporary startup chain; unit=%s; inspect ExecStart and its writer", filepath.Base(path))
		}
		if rule == "" {
			continue
		}
		finding := persistenceFinding(path, info, data, rule, severity, detail)
		finding.RelatedPaths = append([]string(nil), aliases[path]...)
		byPath[path] = len(findings)
		findings = append(findings, finding)
	}
	if ctx.Err() != nil {
		return findings, gaps, gapsOmitted, ctx.Err()
	}
	// Link each suspicious unit to the executable/script references it starts
	// and to a startup writer that names the unit. The links are evidence for
	// review; an ordinary /usr/bin/mysqld reference is never promoted to a
	// payload finding by itself.
	for index := 0; index < len(findings) && index < limit; index++ {
		finding := &findings[index]
		unitPath := finding.Path
		if !isSystemdUnitPath(unitPath) {
			for _, alias := range aliases[unitPath] {
				if isSystemdUnitPath(alias) {
					unitPath = alias
					break
				}
			}
		}
		if !isSystemdUnitPath(unitPath) || !isStartupRule(finding.Rule) {
			continue
		}
		_, unitData, err := readPersistenceFile(finding.Path, scanner.MaxFileSize)
		if err != nil {
			continue
		}
		relatedPaths := append([]string(nil), finding.RelatedPaths...)
		for _, related := range systemdRelatedPaths(unitData) {
			relatedPaths = appendUniquePath(relatedPaths, related)
		}
		for _, candidate := range candidates {
			if err := ctx.Err(); err != nil {
				return findings, gaps, gapsOmitted, err
			}
			if candidate == finding.Path || !isStartupConfigurationPath(candidate) || isSystemdUnitPath(candidate) {
				continue
			}
			if len(relatedPaths) >= maxRelatedPayloadsPerUnit {
				break
			}
			_, data, readErr := readPersistenceFile(candidate, scanner.MaxFileSize)
			if readErr == nil && startupWriterReferencesUnit(data, filepath.Base(unitPath)) {
				relatedPaths = appendUniquePath(relatedPaths, candidate)
			}
		}
		finding.RelatedPaths = append([]string(nil), relatedPaths...)
		for _, related := range relatedPaths {
			if relatedIndex, ok := byPath[related]; ok {
				if findings[relatedIndex].RelatedTo == "" {
					findings[relatedIndex].RelatedTo = finding.ID
				}
				continue
			}
			if len(findings) >= limit {
				break
			}
			relatedFinding, ok := relatedPersistenceFinding(ctx, scanner, related, finding.ID, filepath.Base(unitPath))
			if !ok {
				continue
			}
			byPath[related] = len(findings)
			findings = append(findings, relatedFinding)
		}
	}
	if len(findings) < limit {
		journalFindings, journalErr := collectJournalFindings(ctx, limit-len(findings))
		// A journal record may be all that remains after a transient unit has
		// removed its startup file. If a referenced temporary payload still
		// exists, inspect it as a normal finding so the API can verify and
		// quarantine that inode instead of archiving only the log record.
		for index := range journalFindings {
			journalFinding := &journalFindings[index]
			relatedPaths := append([]string(nil), journalFinding.RelatedPaths...)
			for _, related := range relatedPaths {
				// /dev/fd/N is a process-local descriptor. Opening it here would
				// inspect the scanner's own file descriptor rather than the exited
				// malware process, so retain it as evidence without treating it as a
				// quarantinable file.
				if IsTransientSystemdUnitPath(related) || isVirtualEvidencePath(related) || len(findings)+len(journalFindings) >= limit {
					continue
				}
				payloadFinding, ok := relatedPersistenceFinding(ctx, scanner, related, journalFinding.ID, "journal evidence")
				if !ok {
					continue
				}
				journalFindings = append(journalFindings, payloadFinding)
			}
		}
		findings = append(findings, journalFindings...)
		if journalErr != nil && !errors.Is(journalErr, context.Canceled) && !errors.Is(journalErr, context.DeadlineExceeded) {
			return findings, gaps, gapsOmitted, journalErr
		}
	}
	return findings, gaps, gapsOmitted, nil
}

func isVirtualEvidencePath(path string) bool {
	clean := filepath.Clean(strings.TrimSpace(path))
	return clean == "/dev/fd" || strings.HasPrefix(clean, "/dev/fd/")
}

func collectPersistencePaths(ctx context.Context) ([]string, map[string][]string, []CoverageGap, uint64) {
	paths := make([]string, 0, maxPersistenceFiles)
	seen := make(map[string]struct{})
	aliases := make(map[string][]string)
	var gaps []CoverageGap
	var gapsOmitted uint64
	visitedEntries := 0
	addGap := func(path, reason string) {
		if len(gaps) < maxCoverageGaps {
			gaps = append(gaps, CoverageGap{Path: path, Reason: reason})
		} else {
			gapsOmitted++
		}
	}
	roots := append([]string(nil), persistenceRoots...)
	roots = append(roots,
		"/root/.config/systemd/user",
		"/root/.config/autostart",
		"/root/.local/share/systemd/user",
		"/root/.config/environment.d",
	)
	if homes, err := os.ReadDir("/home"); err == nil {
		for _, home := range homes {
			if home.IsDir() && home.Type()&os.ModeSymlink == 0 {
				base := filepath.Join("/home", home.Name())
				roots = append(roots,
					filepath.Join(base, ".config/systemd/user"),
					filepath.Join(base, ".config/autostart"),
					filepath.Join(base, ".local/share/systemd/user"),
					filepath.Join(base, ".config/environment.d"),
				)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		addGap("/home", "startup-directory-unreadable")
	}
	for _, root := range roots {
		select {
		case <-ctx.Done():
			return paths, aliases, gaps, gapsOmitted
		default:
		}
		info, err := os.Lstat(root)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				addGap(root, "startup-directory-unreadable")
			}
			continue
		}
		if info.Mode().IsRegular() {
			clean := filepath.Clean(root)
			if _, ok := seen[clean]; !ok {
				seen[clean] = struct{}{}
				paths = append(paths, clean)
			}
			continue
		}
		if !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if len(paths) >= maxPersistenceFiles || visitedEntries >= maxPersistenceEntries || walkErr != nil {
				if len(paths) >= maxPersistenceFiles || visitedEntries >= maxPersistenceEntries {
					addGap(path, "startup-file-count-limit")
					return filepath.SkipAll
				}
				addGap(path, "startup-directory-unreadable")
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			visitedEntries++
			if entry.Type()&os.ModeSymlink != 0 {
				if !isSystemdUnitPath(path) {
					return nil
				}
				resolved, resolveErr := filepath.EvalSymlinks(path)
				if resolveErr != nil {
					if !errors.Is(resolveErr, os.ErrNotExist) {
						addGap(path, "startup-link-unreadable")
					}
					return nil
				}
				resolved = filepath.Clean(resolved)
				info, statErr := os.Lstat(resolved)
				if statErr != nil || !info.Mode().IsRegular() || isNodeWallArtifactPath(resolved) {
					return nil
				}
				if len(aliases[resolved]) < maxRelatedPayloadsPerUnit {
					aliases[resolved] = appendUniquePath(aliases[resolved], filepath.Clean(path))
				} else {
					addGap(path, "startup-link-count-limit")
				}
				if _, ok := seen[resolved]; !ok {
					seen[resolved] = struct{}{}
					paths = append(paths, resolved)
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			clean := filepath.Clean(path)
			if isDockerRuntimeLogPath(clean) {
				return nil
			}
			if _, ok := seen[clean]; !ok {
				seen[clean] = struct{}{}
				paths = append(paths, clean)
			}
			return nil
		})
	}
	collectHomeProfilePaths(ctx, &paths, seen)
	sort.Strings(paths)
	return paths, aliases, gaps, gapsOmitted
}

func collectHomeProfilePaths(ctx context.Context, paths *[]string, seen map[string]struct{}) {
	entries, err := os.ReadDir("/home")
	if err != nil {
		return
	}
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		for _, name := range []string{".profile", ".bash_profile", ".bashrc", ".zshrc"} {
			path := filepath.Join("/home", entry.Name(), name)
			info, statErr := os.Lstat(path)
			if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			*paths = append(*paths, path)
			if len(*paths) >= maxPersistenceFiles {
				return
			}
		}
	}
}

func readPersistenceFile(path string, maxSize int64) (os.FileInfo, []byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSize {
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errFileSkipped
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil || int64(len(data)) > maxSize {
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errFileSkipped
	}
	finished, err := file.Stat()
	if err != nil || finished.Size() != int64(len(data)) || !finished.ModTime().Equal(info.ModTime()) {
		return nil, nil, errors.New("startup file changed during scanning")
	}
	return info, data, nil
}

func persistenceFinding(path string, info os.FileInfo, data []byte, rule, severity, detail string) Finding {
	if isSystemPackageFile(path) {
		detail = "系统目录文件命中启动持久化规则；请核验软件包和文件哈希；" + detail
	}
	sum := sha256.Sum256(data)
	idSum := sha256.Sum256([]byte(path + "|" + hex.EncodeToString(sum[:]) + "|" + rule))
	indicators, _ := scriptBehavior(data)
	return Finding{
		ID: "f-" + hex.EncodeToString(idSum[:8]), Path: path, Rule: rule, Severity: severity,
		Detail: detail, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)),
		Mode: info.Mode().Perm().String(), DetectedAt: time.Now().UTC(), Source: "file",
		Indicators: indicators,
		SystemFile: isSystemPackageFile(path), Quarantinable: quarantineEligible(path, rule, info),
	}
}

func relatedPersistenceFinding(ctx context.Context, scanner Scanner, path, parentID, unit string) (Finding, bool) {
	select {
	case <-ctx.Done():
		return Finding{}, false
	default:
	}
	maxSize := scanner.MaxFileSize
	if maxSize <= 0 || maxSize > maxPersistenceFileSize {
		maxSize = maxPersistenceFileSize
	}
	info, data, err := readPersistenceFile(path, maxSize)
	if err != nil {
		return Finding{}, false
	}
	rule, severity, detail := detect(string(data), path, info.Mode())
	if signature, scanErr := scanner.signatures.scanSample(ctx, data); scanErr == nil && signature != "" {
		rule, severity, detail = "clamav-signature", SeverityHigh, "ClamAV signature: "+signature
	}
	if rule == "" {
		if !likelyStartupPayload(path) {
			return Finding{}, false
		}
		rule, severity = "startup-payload", SeverityHigh
		detail = fmt.Sprintf("file is referenced by suspicious systemd unit %s; inspect before allowing startup", unit)
	} else {
		detail = fmt.Sprintf("file is referenced by suspicious systemd unit %s; %s", unit, detail)
	}
	finding := persistenceFinding(path, info, data, rule, severity, detail)
	if unit == "journal evidence" && rule == "startup-payload" {
		// A path extracted from aggregated journal lines is normally only a
		// lead. A verified ELF or compressed external module in a writable
		// runtime tree is the exception because the journal already supplied the
		// independent module-and-tamper chain and the inode can be rechecked.
		if isExternalKernelModulePath(path) && isKernelModuleBinary(data) {
			finding.Rule = "malware-persistence"
			finding.Severity = SeverityHigh
			finding.Detail = "journal-correlated external kernel-module payload; the exact inode and hash will be verified before isolation"
			finding.Quarantinable = quarantineEligible(path, finding.Rule, info)
		} else {
			finding.Quarantinable = false
			finding.ContainmentBlockedReason = "日志关联路径缺少独立恶意特征，未自动隔离；请继续核查"
		}
	}
	finding.RelatedTo = parentID
	return finding, true
}

func isExternalKernelModulePath(path string) bool {
	clean := filepath.Clean(path)
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm", "/run/user"} {
		if clean != root && !strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			continue
		}
		base := strings.ToLower(filepath.Base(clean))
		return strings.HasSuffix(base, ".ko") || strings.Contains(base, ".ko.") || strings.HasSuffix(base, ".o")
	}
	return false
}

func isKernelModuleBinary(data []byte) bool {
	if len(data) >= 4 && string(data[:4]) == "\x7fELF" {
		return true
	}
	// Keep compressed module support bounded to their standard magic bytes.
	return len(data) >= 2 && ((data[0] == 0x1f && data[1] == 0x8b) || (data[0] == 0xfd && data[1] == 0x37))
}

func abnormalSystemdUnit(path string, data []byte) bool {
	text := strings.ToLower(string(data))
	// Unit names are only one weak signal. A random name can change on every
	// reboot, so behavior such as a writable payload path or a command that
	// mutates a protected binary is the durable indicator.
	return hasSuspiciousSystemdExec(text) || hasSystemFileMutation(text) ||
		(isRandomSystemdUnitPath(path) && (hasRandomSystemdExec(text) || strings.Contains(text, "restart=always")))
}

func isStartupRule(rule string) bool {
	switch rule {
	case "malware-persistence", "startup-loader", "scheduled-miner", "suspicious-startup", "system-file-tamper":
		return true
	default:
		return false
	}
}

func systemdRelatedPaths(data []byte) []string {
	paths := make([]string, 0, 4)
	seen := make(map[string]struct{})
	for _, originalLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(originalLine)
		lowerLine := strings.ToLower(line)
		if !strings.HasPrefix(lowerLine, "execstart=") && !strings.HasPrefix(lowerLine, "execstartpre=") && !strings.HasPrefix(lowerLine, "execstartpost=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		for _, field := range systemdCommandFields(parts[1]) {
			if _, ok := seen[field]; ok {
				continue
			}
			seen[field] = struct{}{}
			paths = append(paths, field)
		}
	}
	return paths
}

func systemdCommandFields(command string) []string {
	fields := strings.Fields(command)
	paths := make([]string, 0, 4)
	for index := 0; index < len(fields) && len(paths) < maxRelatedPayloadsPerUnit; index++ {
		field := strings.Trim(fields[index], "\"'")
		field = strings.TrimLeft(field, "-+@!")
		if field == "" || strings.Contains(field, "%") {
			continue
		}
		if field == "/usr/bin/env" || field == "/bin/env" {
			continue
		}
		if isSystemdShell(field) {
			continue
		}
		if strings.HasPrefix(field, "VAR=") || (strings.Contains(field, "=") && !filepath.IsAbs(field)) {
			continue
		}
		if !filepath.IsAbs(field) {
			continue
		}
		paths = append(paths, filepath.Clean(field))
		// The first non-wrapper absolute command is the ExecStart target. Do
		// not turn absolute config arguments such as /var/tmp/foo.conf into
		// independent payload findings.
		break
	}
	return paths
}

func isSystemdShell(path string) bool {
	switch filepath.Base(path) {
	case "sh", "bash", "dash", "zsh", "ksh", "fish", "env", "python", "python2", "python3", "perl", "ruby", "node", "java", "true", "false", "sleep", "systemd-notify":
		return true
	default:
		return false
	}
}

func startupWriterReferencesUnit(data []byte, unit string) bool {
	text := strings.ToLower(string(data))
	unit = strings.ToLower(strings.TrimSpace(unit))
	if unit == "" || !strings.Contains(text, unit) {
		return false
	}
	return containsAny(text,
		"systemctl enable", "systemctl link", "systemctl preset", "systemctl start", "systemctl daemon-reload",
		"/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/",
		"multi-user.target.wants", "default.target.wants")
}

func appendUniquePath(paths []string, path string) []string {
	for _, existing := range paths {
		if existing == path {
			return paths
		}
	}
	return append(paths, path)
}

func likelyStartupPayload(path string) bool {
	clean := filepath.Clean(path)
	if isSuspiciousStartupPath(clean) {
		return true
	}
	base := strings.ToLower(filepath.Base(clean))
	return looksRandomStartupName(base)
}
