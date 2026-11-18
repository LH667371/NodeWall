//go:build linux

package securityscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalPersistenceFindingKeepsTransientBootEvidence(t *testing.T) {
	text := strings.Join([]string{
		"2026-11-09T11:45:05 rancher 31b06da81846f30e[3727]: CC [M] /tmp/a/graphic_card.o",
		"2026-11-09T11:45:06 rancher kernel: graphic_card: loading out-of-tree module taints kernel",
		"2026-11-09T11:45:06 rancher dockerd[3243]: failed to create NAT chain: Iptables not found",
		"2026-11-09T11:45:06 rancher 31b06da81846f30e[3811]: journalctl --vacuum-time=1s",
		"2026-11-09T11:45:06 rancher 31b06da81846f30e[3727]: /dev/fd/3: line 608: kill: (10000000) - No such process",
	}, "\n")
	finding, ok := journalPersistenceFinding(text)
	if !ok || finding.Rule != "malware-persistence" || finding.Severity != SeverityHigh || finding.Source != "journal" {
		t.Fatalf("journal persistence evidence was missed: %#v, %t", finding, ok)
	}
	if !strings.Contains(finding.Detail, "graphic_card") || !strings.Contains(strings.ToLower(finding.Detail), "iptables") {
		t.Fatalf("journal evidence detail was incomplete: %s", finding.Detail)
	}
	if !containsPath(finding.RelatedPaths, "/run/systemd/transient/31b06da81846f30e.service") {
		t.Fatalf("transient unit was not recovered from journal evidence: %#v", finding.RelatedPaths)
	}
	if len(finding.StartupCandidates) != 1 || finding.StartupCandidates[0] != "/run/systemd/transient/31b06da81846f30e.service" {
		t.Fatalf("single transient startup candidate was not retained: %#v", finding.StartupCandidates)
	}
	if !containsPath(finding.RelatedPaths, "/tmp/a/graphic_card.o") {
		t.Fatalf("temporary payload was not recovered from journal evidence: %#v", finding.RelatedPaths)
	}
	if !containsPath(finding.RelatedPaths, "/dev/fd/3") || !strings.Contains(finding.Detail, "ephemeral /dev/fd") {
		t.Fatalf("ephemeral script descriptor was not retained as evidence: %#v detail=%s", finding.RelatedPaths, finding.Detail)
	}
}

func TestTransientServiceMessageIsRecoveredFromJournalEvidence(t *testing.T) {
	paths := transientUnitPaths("5ddf18af.service: Succeeded.")
	if len(paths) != 1 || paths[0] != "/run/systemd/transient/5ddf18af.service" {
		t.Fatalf("transient service message was not recovered: %#v", paths)
	}
}

func TestJournalPayloadCanBecomeFileFinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "graphic_card.ko")
	if err := os.WriteFile(path, []byte("kernel module payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	finding, ok := relatedPersistenceFinding(context.Background(), New(), path, "j-evidence", "journal evidence")
	if !ok || finding.Source != "file" || finding.Rule != "startup-payload" || finding.RelatedTo != "j-evidence" {
		t.Fatalf("journal payload was not promoted to a file finding: %#v, %t", finding, ok)
	}
}

func TestVirtualEvidencePathIsNeverOpenedAsPayload(t *testing.T) {
	if !isVirtualEvidencePath("/dev/fd/3") || isVirtualEvidencePath("/tmp/a/graphic_card.ko") {
		t.Fatalf("unexpected virtual evidence path classification")
	}
}

func containsPath(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}

func TestTransientUnitPathsRecoverRandomProcessName(t *testing.T) {
	paths := transientUnitPaths("5ddf18af1006a658[3574]: CC [M] /tmp/a/graphic_card.o")
	if len(paths) != 1 || paths[0] != "/run/systemd/transient/5ddf18af1006a658.service" {
		t.Fatalf("random process name was not mapped to a transient unit: %#v", paths)
	}
}

func TestTransientUnitPathsPreferRecordedServiceName(t *testing.T) {
	paths := transientUnitPaths("5ddf18af1006a658[2032]: /dev/fd/3; systemd: 5ddf18af.service: Succeeded")
	if len(paths) != 1 || paths[0] != "/run/systemd/transient/5ddf18af.service" {
		t.Fatalf("recorded service name did not win over process identifier: %#v", paths)
	}
}

func TestSystemdShowExecPathsRecoversRandomPayload(t *testing.T) {
	output := `{ path=/usr/bin/8a6589cd3942efe0 ; argv[]=/usr/bin/8a6589cd3942efe0 8a6589cd ; ignore_errors=no ; }`
	paths := systemdShowExecPaths(output)
	if len(paths) != 1 || paths[0] != "/usr/bin/8a6589cd3942efe0" {
		t.Fatalf("systemctl ExecStart payload was not recovered: %#v", paths)
	}
}

func TestSystemdShowExecPathsSkipsOnlyMalformedFields(t *testing.T) {
	output := `{ path=/bin/bash ; argv[]=/bin/bash /dev/fd/3 ; }\n{ path=/usr/local/bin/loader ; argv[]=/usr/local/bin/loader --start ; }`
	paths := systemdShowExecPaths(output)
	if len(paths) != 2 || paths[0] != "/bin/bash" || paths[1] != "/usr/local/bin/loader" {
		t.Fatalf("systemctl ExecStart parser changed command paths: %#v", paths)
	}
}

func TestJournalStartupExecutablePathsQueriesGeneratedUnit(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\n' '{ path=/usr/bin/7e4a91c0d2b84f16 ; argv[]=/usr/bin/7e4a91c0d2b84f16 7e4a91c0d2b84f16 ; }'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	paths := journalStartupExecutablePaths(context.Background(), "7e4a91c0d2b84f16[2032]: CC [M] /tmp/a/graphic_card.o")
	if len(paths) != 1 || paths[0] != "/usr/bin/7e4a91c0d2b84f16" {
		t.Fatalf("generated unit ExecStart path was not queried: %#v", paths)
	}
}

func TestJournalStartupExecutablePathsAcceptsNonRandomUnitWhenCorrelated(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\n' '{ path=/usr/local/bin/maintenance-loader ; argv[]=/usr/local/bin/maintenance-loader --start ; }'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	text := strings.Join([]string{
		"_SYSTEMD_UNIT=maintenance.service builder[3574]: CC [M] /var/tmp/driver.ko",
		"_SYSTEMD_UNIT=maintenance.service builder[3574]: iptables: command not found",
	}, "\n")
	paths := journalStartupExecutablePaths(context.Background(), text)
	if len(paths) != 1 || paths[0] != "/usr/local/bin/maintenance-loader" {
		t.Fatalf("correlated non-random unit ExecStart path was not queried: %#v", paths)
	}
}

func TestJournalPersistenceFindingIgnoresUnrelatedLogs(t *testing.T) {
	if finding, ok := journalPersistenceFinding("systemd[1]: Started normal.service"); ok || finding.ID != "" {
		t.Fatalf("ordinary journal entry became a finding: %#v, %t", finding, ok)
	}
}

func TestJournalPersistenceFindingAcceptsCentOSMissingIPTablesMessage(t *testing.T) {
	text := strings.Join([]string{
		"zstack-imagestorebackupstorage: /etc/rc.d/init.d/zstack-imagestorebackupstorage: line 86: iptables: command not found",
		"c0dde55ca0a06b74[2416]: /dev/fd/3: line 608: kill: (10000000) - No such process",
		"c0dde55ca0a06b74[2416]: CC [M] /tmp/a/graphic_card.o",
		"kernel: graphic_card: loading out-of-tree module taints kernel",
		"sudo: COMMAND=/bin/journalctl --vacuum-time=1s",
	}, "\n")
	if finding, ok := journalPersistenceFinding(text); !ok || finding.Source != "journal" {
		t.Fatalf("CentOS missing-iptables evidence was missed: %#v, %t", finding, ok)
	}
}

func TestFilterJournalEvidenceSupportsOldJournalctl(t *testing.T) {
	input := []byte(strings.Join([]string{
		"ordinary boot message",
		"worker: /dev/fd/3: line 608: kill: (10000000) - No such process",
		"make: CC [M] /tmp/a/graphic_card.o",
		"ordinary trailing message",
	}, "\n"))
	filtered := string(filterJournalEvidence(input))
	if strings.Contains(filtered, "ordinary boot message") || !strings.Contains(filtered, "/dev/fd/3") || !strings.Contains(filtered, "graphic_card.o") {
		t.Fatalf("old journalctl fallback filtered the wrong lines: %q", filtered)
	}
}

func TestJournalStartupCandidatesRequireDirectAttribution(t *testing.T) {
	text := strings.Join([]string{
		"abcd1234.service: CC [M] /tmp/a/graphic_card.o",
		"abcd1234.service: journalctl --vacuum-time=1s",
		"abcdef55.service: Succeeded.",
		"99999999[123]: CC [M] /tmp/a/graphic_card.o",
		"dockerd: iptables not found",
	}, "\n")
	finding, ok := journalPersistenceFinding(text)
	if !ok || len(finding.StartupCandidates) != 1 || finding.StartupCandidates[0] != "/run/systemd/transient/abcd1234.service" {
		t.Fatalf("unexpected correlated startup candidates: %#v", finding.StartupCandidates)
	}
}

func TestJournalStartupCandidateSupportsOrdinaryGeneratedServiceName(t *testing.T) {
	text := strings.Join([]string{
		"_SYSTEMD_UNIT=maintenance.service builder[3574]: CC [M] /var/tmp/.cache/driver-renamed.ko",
		"_SYSTEMD_UNIT=maintenance.service builder[3574]: truncate -s 0 /var/log/messages",
	}, "\n")
	finding, ok := journalPersistenceFinding(text)
	want := "/run/systemd/transient/maintenance.service"
	if !ok || len(finding.StartupCandidates) != 1 || finding.StartupCandidates[0] != want {
		t.Fatalf("ordinary generated service name was not correlated: %#v, %t", finding.StartupCandidates, ok)
	}
}

func TestNormalizeJournalJSONKeepsUnitFromCgroup(t *testing.T) {
	input := []byte(`{"MESSAGE":"CC [M] /var/tmp/driver-renamed.ko","_SYSTEMD_CGROUP":"0::/system.slice/maintenance.service","_COMM":"builder","_PID":3574}` + "\n")
	normalized := string(normalizeJournalJSON(input))
	if !strings.Contains(normalized, "_SYSTEMD_UNIT=maintenance.service") || !strings.Contains(normalized, "CC [M] /var/tmp/driver-renamed.ko") {
		t.Fatalf("journal cgroup metadata was lost: %q", normalized)
	}
}

func TestJournalStartupCandidateCanBeCorrelatedByTransientProcessIdentity(t *testing.T) {
	text := strings.Join([]string{
		"5ddf18af1006a658[3574]: CC [M] /tmp/a/graphic_card.o",
		"5ddf18af1006a658[3811]: journalctl --vacuum-time=1s",
		"5ddf18af1006a658[3812]: iptables: command not found",
	}, "\n")
	finding, ok := journalPersistenceFinding(text)
	want := "/run/systemd/transient/5ddf18af1006a658.service"
	if !ok || len(finding.StartupCandidates) != 1 || finding.StartupCandidates[0] != want {
		t.Fatalf("transient process identity was not correlated to its startup unit: %#v, %t", finding.StartupCandidates, ok)
	}
}

func TestJournalOnlyPayloadIsNotQuarantinedAutomatically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "driver.ko")
	if err := os.WriteFile(path, []byte("kernel module payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	finding, ok := relatedPersistenceFinding(context.Background(), New(), path, "j-evidence", "journal evidence")
	if !ok || finding.Quarantinable || finding.ContainmentBlockedReason == "" {
		t.Fatalf("a weak journal association must not isolate a file: %#v", finding)
	}
}

func TestJournalCorrelatedExternalModuleCanBeQuarantined(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-renamed.ko")
	if err := os.WriteFile(path, append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 32)...), 0o700); err != nil {
		t.Fatal(err)
	}
	finding, ok := relatedPersistenceFinding(context.Background(), New(), path, "j-evidence", "journal evidence")
	if !ok || !finding.Quarantinable || finding.Rule != "malware-persistence" {
		t.Fatalf("verified journal-correlated module was not eligible: %#v, %t", finding, ok)
	}
}
