package integrity

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAndCompareManifest(t *testing.T) {
	root := t.TempDir()
	changed := filepath.Join(root, "changed.txt")
	deleted := filepath.Join(root, "deleted.txt")
	if err := os.WriteFile(changed, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deleted, []byte("gone"), 0o644); err != nil {
		t.Fatal(err)
	}
	base, err := Build(context.Background(), []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Entries) != 2 {
		t.Fatalf("expected two baseline entries, got %d", len(base.Entries))
	}
	if err := os.WriteFile(changed, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}
	added := filepath.Join(root, "added.txt")
	if err := os.WriteFile(added, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := Build(context.Background(), []string{root})
	if err != nil {
		t.Fatal(err)
	}
	difference := Compare(base, current)
	if len(difference.Added) != 1 || len(difference.Changed) != 1 || len(difference.Deleted) != 1 {
		t.Fatalf("unexpected difference: %#v", difference)
	}
}

func TestManifestSaveAndLoad(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "manifest.json")
	manifest := Manifest{Version: 1, Paths: []string{"/var/www"}}
	if err := Save(path, manifest); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != manifest.Version || len(loaded.Paths) != 1 || loaded.Paths[0] != "/var/www" {
		t.Fatalf("unexpected loaded manifest: %#v", loaded)
	}
}
