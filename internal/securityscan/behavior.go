package securityscan

import (
	"path/filepath"
	"regexp"
	"strings"
)

var (
	temporaryModulePattern   = regexp.MustCompile(`(?i)(?:^|[\s"'=])(?:/tmp/|/var/tmp/|/dev/shm/|/run/user/[0-9]+/)[^\s"';&|]*\.(?:ko|o)(?:\.[a-z0-9]+)?\b`)
	kernelModuleBuildPattern = regexp.MustCompile(`(?i)(?:\b(?:make|gmake|cc|gcc|clang|ld|ld\.bfd|modpost|depmod)\b[^\n]*(?:\[m\]|/lib/modules/[^\s]+/build|\bmodules?\b|\bM=|\.ko(?:\b|\.)))|(?:\b(?:out[- ]of[- ]tree|external)\s+(?:linux\s+)?(?:kernel\s+)?module\b)`)
	kernelModuleLoadPattern  = regexp.MustCompile(`(?i)\b(?:insmod|modprobe)\b[^\n]*(?:(?:/tmp|/var/tmp|/dev/shm|/run/user/[0-9]+)[/\s]|\.(?:ko|o)(?:\.[a-z0-9]+)?\b|\b(?:out[- ]of[- ]tree|external)\b)`)
	moduleTaintPattern       = regexp.MustCompile(`(?i)\b(?:loading|loaded)\b[^\n]*\b(?:out[- ]of[- ]tree|external)\s+(?:linux\s+)?(?:kernel\s+)?module\b|\bmodule\b[^\n]*\b(?:taint|verification failed|unknown symbol)\b`)
	logTamperPattern         = regexp.MustCompile(`(?i)\b(?:rm|shred|truncate|unlink|wipe|dd|sed)\b[^\n]*(?:/var/log/|/run/log/|/var/lib/systemd/[^\s]*journal|\.bash_history|\.zsh_history|\.history\b)`)
	auditDisablePattern      = regexp.MustCompile(`(?i)\b(?:systemctl|service)\s+(?:stop|disable|mask|kill)\s+(?:[^\s]+\s+)?(?:auditd|rsyslog|syslog|journald|fail2ban|firewalld|nftables)\b`)
	journalCleanupPattern    = regexp.MustCompile(`(?i)\b(?:journalctl|systemd-journal-remote|rm|shred|truncate|unlink|wipe)\b[^\n]*(?:--vacuum(?:-|\s)|/var/log/|/run/log/|journal)`)
	firewallTamperPattern    = regexp.MustCompile(`(?i)\b(?:iptables|ip6tables|nft|ebtables|arptables|ufw|firewalld|pfctl|netfilter)\b[^\n]*(?:\b(?:flush|delete|destroy|clear|reset|stop|disable|mask|remove|not[ -]?found|command[ -]?not[ -]?found)\b)`)
)

// hasKernelModuleActivity detects a module build or load from the command
// context. A module filename is only evidence when it is tied to a build,
// loader, or kernel diagnostic, so a filename in ordinary documentation does
// not become a persistence finding.
func hasKernelModuleActivity(text string) bool {
	for _, line := range strings.Split(strings.ToLower(text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if kernelModuleBuildPattern.MatchString(line) || kernelModuleLoadPattern.MatchString(line) || moduleTaintPattern.MatchString(line) {
			return true
		}
	}
	return false
}

// hasHostDefenseTamper combines log, audit, firewall, and protected-file
// mutation signals. The command or target may change between incidents, so
// the test is based on the operation and the protected resource class.
func hasHostDefenseTamper(text string) bool {
	text = strings.ToLower(text)
	if logTamperPattern.MatchString(text) || auditDisablePattern.MatchString(text) || journalCleanupPattern.MatchString(text) || firewallTamperPattern.MatchString(text) {
		return true
	}
	return hasSystemFileMutation(text)
}

// scriptBehavior combines independent behaviors rather than treating a
// filename, a downloader, or a normal service action as malware. It is still
// a heuristic and does not establish that unmatched content is safe.
func scriptBehavior(sample []byte) ([]string, bool) {
	if len(sample) == 0 || isBinaryExecutable(sample) {
		return nil, false
	}
	var lines strings.Builder
	for _, line := range strings.Split(string(sample), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") && !isOutputOnlyShellLine(trimmed) {
			lines.WriteString(line)
			lines.WriteByte('\n')
		}
	}
	text := strings.ToLower(lines.String())
	d := contentDetector{}
	d.observe(text)
	indicators, _ := behaviorIndicators(d)
	return indicators, hasExecutableBehavior(text)
}

// Printed examples are not execution evidence; output piped to a shell is.
func isOutputOnlyShellLine(line string) bool {
	if containsShellPipe(line) {
		return false
	}
	return strings.HasPrefix(line, "echo ") || strings.HasPrefix(line, "printf ") || strings.HasPrefix(line, "logger ")
}

// Automatic process actions use actual command positions, not strings merely
// quoted in documentation or assignments. Complex shell syntax is retained as
// review evidence but is deliberately not sufficient to stop a process.
func hasExecutableBehavior(text string) bool {
	var moduleLoad, tamper, downloadExec, persistence, reverse, miner bool
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		for len(fields) > 1 && (fields[0] == "sudo" || fields[0] == "exec" || fields[0] == "command") {
			fields = fields[1:]
		}
		command := filepath.Base(fields[0])
		switch command {
		case "insmod", "modprobe":
			moduleLoad = moduleLoad || kernelModuleLoadPattern.MatchString(line) || temporaryModulePattern.MatchString(line)
		case "rm", "shred", "truncate", "unlink", "mv", "cp", "install", "chmod", "chattr", "sed", "tee", "dd":
			tamper = tamper || hasHostDefenseTamper(line)
		case "systemctl", "service":
			tamper = tamper || hasHostDefenseTamper(line)
			persistence = persistence || containsAny(line, "systemctl enable", "systemctl link", "systemctl preset")
		case "curl", "wget", "base64":
			downloadExec = downloadExec || containsShellPipe(line)
		case "crontab":
			persistence = true
		case "sh", "bash", "dash", "zsh", "ksh", "nc", "ncat", "socat":
			reverse = reverse || containsAny(line, "/dev/tcp/", "nc -e", "ncat -e", "socat exec:")
		case "xmrig", "minerd", "cpuminer", "xmr-stak", "t-rex", "nbminer", "lolminer":
			var detector contentDetector
			detector.observe(line)
			miner = miner || detector.miner
		}
		if !moduleLoad && kernelModuleBuildPattern.MatchString(line) {
			moduleLoad = true
		}
		if !tamper && hasHostDefenseTamper(line) {
			tamper = true
		}
	}
	return (moduleLoad && tamper) || (downloadExec && tamper && (persistence || reverse)) ||
		(miner && (downloadExec || persistence || tamper))
}

func behaviorIndicators(d contentDetector) ([]string, bool) {
	temporaryModule := d.temporaryModule
	tamper := d.systemFileMutation || d.journalVacuum || d.logTamper || d.auditDisable
	downloadExec := (d.downloader || d.encoded) && d.pipe
	persistence := d.persistence || d.preloadFile || d.systemdUnitWrite || d.cronEntry
	var indicators []string
	if temporaryModule {
		indicators = append(indicators, "temporary-kernel-module")
	}
	if tamper {
		indicators = append(indicators, "defense-or-log-tamper")
	}
	if downloadExec {
		indicators = append(indicators, "download-or-decode-execute")
	}
	if persistence {
		indicators = append(indicators, "persistence")
	}
	if d.reverse {
		indicators = append(indicators, "reverse-shell")
	}
	if d.miner {
		indicators = append(indicators, "miner-indicators")
	}
	strong := (temporaryModule && tamper) ||
		(downloadExec && tamper && (persistence || d.reverse)) ||
		(d.miner && (downloadExec || persistence || tamper))
	return indicators, strong
}
