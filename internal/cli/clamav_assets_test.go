package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeployClamAVAssetsReportsOfflineInstallation(t *testing.T) {
	root := t.TempDir()
	release := filepath.Join(root, "release")
	executable := filepath.Join(release, "bin", "nodewall")
	if err := os.MkdirAll(filepath.Join(release, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(release, "clamav", "engines"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(release, "clamav", "database"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("nodewall"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"engines/amd64.tar.gz",
		"engines/arm64.tar.gz",
		"database/main.cvd",
		"database/daily.cvd",
		"database/bytecode.cvd",
		"NOTICE.md",
	} {
		path := filepath.Join(release, "clamav", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	installDir := filepath.Join(root, "installed")
	output, err := captureCLIStdout(t, func() error {
		return deployClamAVAssets(executable, installDir)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"检测到离线 ClamAV 资源",
		"安装离线 ClamAV 引擎和病毒库",
		"病毒库安装完成",
		"服务启动后将校验引擎并加载病毒库",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
	if _, err := os.Stat(filepath.Join(installDir, "clamav", "database", "daily.cvd")); err != nil {
		t.Fatalf("offline database was not installed: %v", err)
	}
}

func TestDeployClamAVAssetsReportsRetainedBundle(t *testing.T) {
	root := t.TempDir()
	installDir := filepath.Join(root, "installed")
	executable := filepath.Join(installDir, "bin", "nodewall")
	if err := os.MkdirAll(filepath.Dir(executable), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("nodewall"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range requiredClamAVBundleFiles {
		path := filepath.Join(installDir, "clamav", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	output, err := captureCLIStdout(t, func() error {
		return deployClamAVAssets(executable, installDir)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "保留现有引擎和病毒库") {
		t.Fatalf("retained bundle was not reported:\n%s", output)
	}
	if strings.Contains(output, "安装离线 ClamAV 引擎和病毒库") {
		t.Fatalf("binary-only update was reported as an offline installation:\n%s", output)
	}
}

func TestDeployClamAVAssetsReportsAutomaticClusterSyncWhenBundleMissing(t *testing.T) {
	root := t.TempDir()
	output, err := captureCLIStdout(t, func() error {
		return deployClamAVAssets(filepath.Join(root, "download", "nodewall"), filepath.Join(root, "installed"))
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"当前安装包未携带", "自动从已注册集群节点同步 ClamAV 引擎和病毒库", "每 2 分钟检查更新"} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing synchronization guidance %q: %s", want, output)
		}
	}
}

func captureCLIStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	result := fn()
	_ = writer.Close()
	os.Stdout = original
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(output), result
}
