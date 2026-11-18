//go:build linux

package securityscan

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"
)

// collectSystemIntegrityFindings checks for dangerous partial package
// deletion: a command required by an installed firewall or service unit is
// gone while the surrounding package files remain. These are system evidence
// findings; the scanner records them but never fabricates or moves a system
// binary it cannot safely restore.
func collectSystemIntegrityFindings() []Finding {
	commandPaths := []string{"/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"}
	backendPaths := []string{
		"/usr/sbin/iptables-nft", "/usr/sbin/iptables-legacy", "/usr/sbin/xtables-nft-multi", "/usr/sbin/xtables-legacy-multi",
		"/sbin/iptables-nft", "/sbin/iptables-legacy", "/sbin/xtables-nft-multi", "/sbin/xtables-legacy-multi",
		"/usr/bin/iptables-nft", "/usr/bin/iptables-legacy",
	}
	commandExists := anyPathExists(commandPaths)
	backendExists := anyPathExists(backendPaths)
	findings := make([]Finding, 0, 2)
	if !commandExists && backendExists {
		findings = append(findings, systemFileIntegrityFinding(
			"/usr/sbin/iptables",
			"iptables command is missing while an nftables/legacy backend is present; verify the package and alternatives before changing firewall rules",
		))
	}
	// A service unit can remain enabled after its package executable has been
	// removed. Report that broken package boundary as evidence so the scan can
	// archive it alongside the journal chain; the scanner never fabricates a
	// replacement or quarantines a system path it cannot safely restore.
	if anyPathExists([]string{"/lib/systemd/system/cron.service", "/usr/lib/systemd/system/cron.service"}) &&
		!anyPathExists([]string{"/usr/sbin/cron", "/sbin/cron"}) {
		findings = append(findings, systemFileIntegrityFinding(
			"/usr/sbin/cron",
			"cron.service is installed but its ExecStart binary is missing; verify package integrity and preserve this as scan evidence",
		))
	}
	return findings
}

func anyPathExists(paths []string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func systemFileIntegrityFinding(path, detail string) Finding {
	sum := sha256.Sum256([]byte("missing-system-file|" + path))
	return Finding{
		ID:         "i-" + hex.EncodeToString(sum[:8]),
		Path:       path,
		Rule:       "system-file-tamper",
		Severity:   SeverityHigh,
		Detail:     detail,
		DetectedAt: time.Now().UTC(),
		Source:     "integrity",
		SystemFile: true,
	}
}
