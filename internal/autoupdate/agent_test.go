package autoupdate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalizeManagerURL(t *testing.T) {
	for _, test := range []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "trim trailing slash", input: " https://manager.example:8086/// ", want: "https://manager.example:8086"},
		{name: "http is supported for development", input: "http://127.0.0.1:8086", want: "http://127.0.0.1:8086"},
		{name: "reject path", input: "https://manager.example/nodewall", wantErr: true},
		{name: "reject credentials", input: "https://user:pass@manager.example:8086", wantErr: true},
		{name: "reject unsupported scheme", input: "ssh://manager.example:8086", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeManagerURL(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("normalizeManagerURL(%q) unexpectedly succeeded with %q", test.input, got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("normalizeManagerURL(%q) = %q, %v; want %q", test.input, got, err, test.want)
			}
		})
	}
}

func TestReplaceEnvValueReplacesAllExistingEntries(t *testing.T) {
	got := replaceEnvValue([]string{"PATH=/usr/bin", "NODEWALL_MANAGER_URL=https://old:8080", "NODEWALL_MANAGER_URL=https://duplicate:8080"}, "NODEWALL_MANAGER_URL", "https://new:8086")
	want := []string{"PATH=/usr/bin", "NODEWALL_MANAGER_URL=https://new:8086"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("replaceEnvValue() = %#v, want %#v", got, want)
	}
}

func TestManagementServerOutdated(t *testing.T) {
	root := t.TempDir()
	installDir := filepath.Join(root, "nodewall")
	binDir := filepath.Join(installDir, "bin")
	procDir := filepath.Join(root, "proc", "42")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(binDir, "nodewall")
	old := filepath.Join(binDir, "nodewall.tmp.old")
	for _, path := range []string{installed, old} {
		if err := os.WriteFile(path, []byte(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte(installed+"\x00server\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(procDir, "exe")
	if err := os.Symlink(old, exe); err != nil {
		t.Fatal(err)
	}
	if !managementServerOutdated(filepath.Join(root, "proc"), installDir) {
		t.Fatal("old server executable was not detected")
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(installed, exe); err != nil {
		t.Fatal(err)
	}
	if managementServerOutdated(filepath.Join(root, "proc"), installDir) {
		t.Fatal("current server was considered outdated")
	}
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte(installed+"\x00agent\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(old, exe); err != nil {
		t.Fatal(err)
	}
	if managementServerOutdated(filepath.Join(root, "proc"), installDir) {
		t.Fatal("an agent-only process was mistaken for a stale server")
	}
}
