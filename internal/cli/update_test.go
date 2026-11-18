package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeUpdateManagerURL(t *testing.T) {
	if got, err := normalizeUpdateManagerURL(" https://192.168.201.17:8086/ "); err != nil || got != "https://192.168.201.17:8086" {
		t.Fatalf("normalized manager URL = %q, %v", got, err)
	}
	for _, raw := range []string{
		"https://192.168.201.17:8086/nodewall",
		"https://user:password@192.168.201.17:8086",
		"ssh://192.168.201.17:8086",
	} {
		if _, err := normalizeUpdateManagerURL(raw); err == nil {
			t.Fatalf("normalizeUpdateManagerURL(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestDeployRuntimeAssetsHonorsConfiguredWebDirectory(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc")
	installDir := filepath.Join(root, "install")
	legacyWebDir := filepath.Join(root, "legacy-web")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "nodewall.env"), []byte("NODEWALL_WEB_DIR="+legacyWebDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The helper copies the currently embedded bundle. A fake executable is
	// sufficient because this test targets the configured web destination; the
	// optional ClamAV bundle is intentionally absent for an update package.
	executable := filepath.Join(root, "release", "nodewall")
	if err := os.MkdirAll(filepath.Dir(executable), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := deployRuntimeAssets(executable, installDir, configDir); err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(filepath.Join(legacyWebDir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), "NodeWall") {
		t.Fatalf("configured web directory was not populated: %s", legacyWebDir)
	}
	if _, err := os.Stat(filepath.Join(installDir, "web", "dist", "index.html")); !os.IsNotExist(err) {
		t.Fatalf("unexpected default web directory write: err=%v", err)
	}
}
