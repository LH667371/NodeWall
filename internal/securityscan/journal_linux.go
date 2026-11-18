//go:build linux

package securityscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxJournalEvidenceBytes = 512 << 10

const (
	// Journal evidence can contain many historical random unit names. Query a
	// small bounded set of the newest candidates so a scan cannot turn into a
	// systemctl process storm on a busy host.
	maxJournalExecQueries = 8
	journalExecQueryWait  = 750 * time.Millisecond
)

var (
	transientServicePattern = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9_.@:-]{0,127}\.service)\b`)
	transientProcessPattern = regexp.MustCompile(`(?i)\b([a-z0-9_.@:-]{2,127})\[[0-9]+\]`)
	// journalctl --grep matches MESSAGE, which omits the "systemd[1]:"
	// identifier shown by short-iso output. Keep the service alternative
	// independent of that identifier so completed transient units are retained.
	journalPayloadPathPattern = regexp.MustCompile(`(?i)/(?:tmp|var/tmp|dev/shm|run/user/[0-9]+|opt|usr/local|var/lib)/[^\s"'(),;]+`)
	journalModulePathPattern  = regexp.MustCompile(`(?i)/(?:[^\s"'(),;]+\.(?:ko|o)(?:\.[a-z0-9]+)?)\b`)
	// systemctl show formats ExecStart as "{ path=/usr/bin/payload ;
	// argv[]=/usr/bin/payload ... }". Keep this parser limited to command
	// fields so an arbitrary path mentioned in a log message is not treated as
	// an executable payload.
	systemdShowExecPathPattern = regexp.MustCompile(`(?i)\b(?:path|argv\[\])=(/[^;\s]+)`)
	// /dev/fd/N is a process-local descriptor exposed as a procfs symlink. It
	// can be the script fed to bash, but it is not a persistent inode that a
	// scanner can move to quarantine after the process exits.
	journalFDPathPattern = regexp.MustCompile(`(?i)/dev/fd/[0-9]+\b`)
)

// collectJournalFindings reads only journal lines matching the persistence
// indicators that survive after a malware unit removes its own files. The
// recent window is bounded, and classification is based on behavior so a
// renamed module, service, or payload remains discoverable.
func collectJournalFindings(ctx context.Context, limit int) ([]Finding, error) {
	if limit <= 0 {
		return nil, nil
	}
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Read a bounded recent window and classify it locally. A grep expression
	// containing one incident's module or service name would miss the next
	// generated payload name before the scanner gets a chance to correlate it.
	args := []string{"--no-pager", "--since=-7d", "--lines=20000", "-o", "json"}
	output, err := exec.CommandContext(commandCtx, "journalctl", args...).Output()
	if err != nil {
		if errors.Is(commandCtx.Err(), context.Canceled) || errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
			return nil, commandCtx.Err()
		}
		// Older journalctl versions may not support JSON output. Retry with the
		// portable short format and apply the same generic classifier locally.
		fallbackArgs := []string{"--no-pager", "--since=-7d", "--lines=20000", "-o", "short-iso"}
		fallback, fallbackErr := exec.CommandContext(commandCtx, "journalctl", fallbackArgs...).Output()
		if fallbackErr != nil {
			// journalctl is optional in minimal containers. A missing command or
			// unavailable journal should not make the process scan fail.
			return nil, nil
		}
		output = fallback
	} else {
		output = normalizeJournalJSON(output)
	}
	if len(output) > maxJournalEvidenceBytes {
		output = output[len(output)-maxJournalEvidenceBytes:]
	}
	finding, ok := journalPersistenceFindingContext(commandCtx, string(output))
	if !ok {
		return nil, nil
	}
	return []Finding{finding}, nil
}

// normalizeJournalJSON preserves systemd's unit and process metadata in a
// compact text form. The metadata is what lets containment follow a renamed
// transient service without knowing its name in advance.
func normalizeJournalJSON(output []byte) []byte {
	if len(output) == 0 {
		return nil
	}
	var normalized bytes.Buffer
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var record map[string]json.RawMessage
		if json.Unmarshal(line, &record) != nil {
			continue
		}
		message := journalJSONField(record, "MESSAGE")
		unit := journalJSONField(record, "_SYSTEMD_UNIT")
		if unit == "" {
			unit = journalUnitFromCgroup(journalJSONField(record, "_SYSTEMD_CGROUP"))
		}
		comm := journalJSONField(record, "_COMM")
		pid := journalJSONField(record, "_PID")
		if message == "" && unit == "" {
			continue
		}
		if unit != "" {
			normalized.WriteString("_SYSTEMD_UNIT=")
			normalized.WriteString(unit)
			normalized.WriteByte(' ')
		}
		if comm != "" {
			normalized.WriteString(comm)
			if pid != "" {
				normalized.WriteByte('[')
				normalized.WriteString(pid)
				normalized.WriteByte(']')
			}
			normalized.WriteString(": ")
		}
		normalized.WriteString(message)
		normalized.WriteByte('\n')
	}
	if normalized.Len() == 0 {
		return output
	}
	return normalized.Bytes()
}

func journalUnitFromCgroup(cgroup string) string {
	for _, field := range strings.FieldsFunc(cgroup, func(r rune) bool {
		return strings.ContainsRune("/:", r)
	}) {
		if strings.HasSuffix(strings.ToLower(field), ".service") && transientServicePattern.MatchString(field) {
			return field
		}
	}
	return ""
}

func journalJSONField(record map[string]json.RawMessage, key string) string {
	raw, ok := record[key]
	if !ok {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return strings.TrimSpace(value)
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

func filterJournalEvidence(output []byte) []byte {
	if len(output) == 0 {
		return nil
	}
	lines := bytes.Split(output, []byte{'\n'})
	filtered := make([]byte, 0, len(output))
	for _, line := range lines {
		text := string(line)
		if hasKernelModuleActivity(text) || hasHostDefenseTamper(text) || journalFDPathPattern.Match(line) || transientServicePattern.MatchString(text) {
			filtered = append(filtered, line...)
			filtered = append(filtered, '\n')
		}
	}
	return filtered
}

func journalPersistenceFinding(text string) (Finding, bool) {
	return journalPersistenceFindingContext(context.Background(), text)
}

func journalPersistenceFindingContext(ctx context.Context, text string) (Finding, bool) {
	if !hasKernelModuleActivity(text) || !hasHostDefenseTamper(text) {
		return Finding{}, false
	}
	compact := strings.Join(strings.Fields(text), " ")
	if len(compact) > 1800 {
		compact = compact[len(compact)-1800:]
	}
	detail := fmt.Sprintf("recent system journal records external kernel-module activity together with host log, firewall, audit, or protected-file tampering; review the boot source, systemd units, cron entries, and container manifests. Evidence: %s", compact)
	sum := sha256.Sum256([]byte("journal-persistence|" + compact))
	finding := Finding{
		ID:         "j-" + hex.EncodeToString(sum[:8]),
		Path:       "/var/log/journal",
		Rule:       "malware-persistence",
		Severity:   SeverityHigh,
		Detail:     detail,
		DetectedAt: time.Now().UTC(),
		Source:     "journal",
	}
	finding.StartupCandidates = correlatedJournalUnits(text)
	if len(finding.StartupCandidates) == 0 {
		// Older journal formats split the module, firewall, and cleanup lines
		// across different processes. When the high-confidence persistence chain
		// points to exactly one transient unit, retain that single candidate so
		// the response layer can mask it even though the unit name was not printed
		// on every line.
		for _, candidate := range transientUnitPaths(text) {
			if len(finding.StartupCandidates) > 0 {
				finding.StartupCandidates = nil
				break
			}
			finding.StartupCandidates = append(finding.StartupCandidates, candidate)
		}
	}
	unitPaths := transientUnitPaths(text)
	if len(unitPaths) > maxJournalExecQueries {
		unitPaths = unitPaths[:maxJournalExecQueries]
	}
	for _, unitPath := range unitPaths {
		finding.RelatedPaths = append(finding.RelatedPaths, unitPath)
	}
	for _, payloadPath := range journalPayloadPaths(text) {
		finding.RelatedPaths = appendUniquePath(finding.RelatedPaths, payloadPath)
	}
	// A self-deleting unit leaves its journal identity behind while the unit
	// file disappears. Ask systemd for the still-loaded ExecStart path so the
	// scanner can surface and contain the actual payload even when its name is
	// regenerated on every boot. The helper only queries random-looking units
	// recovered from the same high-confidence kernel/tamper evidence.
	for _, payloadPath := range journalStartupExecutablePaths(ctx, text) {
		finding.RelatedPaths = appendUniquePath(finding.RelatedPaths, payloadPath)
	}
	if strings.Contains(strings.ToLower(text), "/dev/fd/") {
		detail += "; execution used an ephemeral /dev/fd script descriptor; the descriptor is not a persistent file and appears only in historical journal output"
		finding.Detail = detail
	}
	if len(finding.RelatedPaths) > 0 {
		detail += "; related evidence=" + strings.Join(finding.RelatedPaths, ",")
		finding.Detail = detail
	}
	return finding, true
}

func journalStartupExecutablePaths(ctx context.Context, text string) []string {
	paths := make([]string, 0, 4)
	seen := make(map[string]struct{})
	unitPaths := correlatedJournalUnits(text)
	for _, unitPath := range transientUnitPaths(text) {
		unitPaths = appendUniquePath(unitPaths, unitPath)
	}
	if len(unitPaths) > maxJournalExecQueries {
		unitPaths = unitPaths[:maxJournalExecQueries]
	}
	for _, unitPath := range unitPaths {
		if err := ctx.Err(); err != nil {
			return paths
		}
		unit := filepath.Base(unitPath)
		if unit == "." || unit == "" {
			continue
		}
		queryCtx, cancel := context.WithTimeout(ctx, journalExecQueryWait)
		output, err := exec.CommandContext(queryCtx, "systemctl", "show", unit, "--no-pager", "-p", "ExecStart", "-p", "ExecStartPre", "-p", "ExecStartPost", "--value").Output()
		cancel()
		if err != nil {
			continue
		}
		for _, path := range systemdShowExecPaths(string(output)) {
			if _, ok := seen[path]; ok || isSystemdShell(path) {
				continue
			}
			seen[path] = struct{}{}
			paths = append(paths, path)
		}
	}
	return paths
}

func systemdShowExecPaths(output string) []string {
	paths := make([]string, 0, 4)
	seen := make(map[string]struct{})
	for _, match := range systemdShowExecPathPattern.FindAllStringSubmatch(output, -1) {
		if len(match) != 2 {
			continue
		}
		path := filepath.Clean(strings.TrimSpace(match[1]))
		if path == "." || !filepath.IsAbs(path) {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	return paths
}

// correlatedJournalUnits only marks a service for automatic blocking when
// both types of suspicious behavior are attributed to that exact service in
// the log. A random service name elsewhere in a seven-day journal window is
// useful for investigation, but is not sufficient evidence for changing it.
func correlatedJournalUnits(text string) []string {
	type signals struct{ payload, tamper bool }
	units := make(map[string]signals)
	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(line)
		payload := hasKernelModuleActivity(lower)
		tamper := hasHostDefenseTamper(lower)
		if !payload && !tamper {
			continue
		}
		lineUnits := make(map[string]struct{})
		for _, match := range transientServicePattern.FindAllStringSubmatch(line, -1) {
			if len(match) != 2 {
				continue
			}
			unit := filepath.Join("/run/systemd/transient", strings.ToLower(match[1]))
			if !IsTransientSystemdRuntimePath(unit) {
				continue
			}
			lineUnits[unit] = struct{}{}
		}
		// Some journal formats identify the transient unit's command process
		// as the syslog program (for example 5ddf18af[3574]) and never print
		// the unit name. The scanner already maps that random process token to
		// its corresponding transient unit, so use the same narrow mapping for
		// attribution when multiple indicators share that process identity.
		for _, match := range transientProcessPattern.FindAllStringSubmatch(line, -1) {
			if len(match) != 2 {
				continue
			}
			unit := filepath.Join("/run/systemd/transient", strings.ToLower(match[1])+".service")
			if IsTransientSystemdUnitPath(unit) {
				lineUnits[unit] = struct{}{}
			}
		}
		for unit := range lineUnits {
			signal := units[unit]
			signal.payload = signal.payload || payload
			signal.tamper = signal.tamper || tamper
			units[unit] = signal
		}
	}
	var result []string
	for unit, signal := range units {
		if signal.payload && signal.tamper {
			result = append(result, unit)
		}
	}
	sort.Strings(result)
	return result
}

// journalPayloadPaths extracts only paths in temporary writable trees. The
// journal finding is already gated by both kernel-module and host-tampering
// indicators; retaining these paths lets the persistence pass inspect a
// payload that still exists before its cleanup trap runs.
func journalPayloadPaths(text string) []string {
	paths := make([]string, 0, 4)
	seen := make(map[string]struct{})
	for _, raw := range journalPayloadPathPattern.FindAllString(text, -1) {
		path := filepath.Clean(strings.TrimRight(raw, ".:!?"))
		if path == "/tmp" || path == "/var/tmp" || path == "/dev/shm" || path == "." {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	for _, raw := range journalModulePathPattern.FindAllString(text, -1) {
		path := filepath.Clean(strings.TrimRight(raw, ".:!?"))
		if path == "." {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	for _, raw := range journalFDPathPattern.FindAllString(text, -1) {
		path := filepath.Clean(raw)
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	return paths
}

// transientUnitPaths recovers the name of a self-deleting systemd unit from
// journal fields that survive after its unit file is gone. Build messages often
// use the process name (for example 5ddf18af1006a658[3574]) instead of printing
// the unit name, so the random hexadecimal process name is also mapped to the
// corresponding transient unit path. The caller only uses these paths for a
// high-confidence journal finding that already combines kernel-module loading
// with firewall tampering and journal cleanup.
func transientUnitPaths(text string) []string {
	servicePaths := make([]string, 0, 2)
	processPaths := make([]string, 0, 2)
	seen := make(map[string]struct{})
	add := func(paths *[]string, name string, requireRandom bool) {
		name = strings.ToLower(strings.TrimSpace(name))
		name = strings.TrimSuffix(name, ".service")
		if name == "" || strings.ContainsAny(name, "/\\") || (requireRandom && !looksRandomStartupName(name)) {
			return
		}
		path := "/run/systemd/transient/" + name + ".service"
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		*paths = append(*paths, path)
	}
	for _, match := range transientServicePattern.FindAllStringSubmatch(text, -1) {
		if len(match) == 2 {
			// The fallback path has no per-line attribution. Keep it limited to
			// generated-looking names, while correlatedJournalUnits handles an
			// ordinary unit name when the suspicious signals occur on its lines.
			add(&servicePaths, match[1], true)
		}
	}
	for _, match := range transientProcessPattern.FindAllStringSubmatch(text, -1) {
		if len(match) == 2 {
			add(&processPaths, match[1], true)
		}
	}
	// The unit name in _SYSTEMD_UNIT or the systemd completion message is
	// authoritative. The process logger identifier may be a longer random
	// token from the injected script; using both would create a second mask for
	// a unit that never existed.
	if len(servicePaths) > 0 {
		return servicePaths
	}
	return processPaths
}
