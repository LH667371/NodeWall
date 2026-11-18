package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveOwnedDirAllowsNodeWallRotatedBackups(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"auth.json", "auth.json.bak.1", "cluster.key.bak.3"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("nodewall"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeOwnedDir(dir, map[string]bool{"auth.json": true, "cluster.key": true}); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveOwnedDirRefusesUnknownFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "administrator-data"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedDir(dir, map[string]bool{"auth.json": true}); err == nil {
		t.Fatal("unknown file was deleted during cleanup")
	}
	if _, err := os.Stat(filepath.Join(dir, "administrator-data")); err != nil {
		t.Fatal("unknown file was not preserved")
	}
}

func TestCleanupOwnsSynchronizedClamAVAssetsAndRemainsRepeatable(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"clamav/engines/amd64.tar.gz", "clamav/engines/arm64.tar.gz", "clamav/database/main.cvd", "clamav/.incoming-engine-interrupted/engines/arm64.tar.gz"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("nodewall"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unknown := filepath.Join(root, "administrator-data")
	if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedDir(root, nodewallOwnedRuntimeEntries()); err == nil {
		t.Fatal("cleanup accepted unrelated administrator data")
	}
	if _, err := os.Stat(filepath.Join(root, "clamav", "engines", "amd64.tar.gz")); err != nil {
		t.Fatal("refused cleanup partially removed ClamAV assets")
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := removeOwnedDir(root, nodewallOwnedRuntimeEntries()); err != nil {
			t.Fatalf("repeatable ClamAV cleanup: %v", err)
		}
	}
}

func TestNodeWallOwnedConfigEntriesIncludesStatePathsFromEnvironment(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, "nodewall.env")
	custom := filepath.Join(root, "new-settings.json")
	if err := os.WriteFile(envPath, []byte("NODEWALL_NEW_SETTINGS_FILE="+custom+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := nodewallOwnedConfigEntries(root, envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !entries["new-settings.json"] {
		t.Fatalf("environment-referenced NodeWall state was not owned: %#v", entries)
	}
}
