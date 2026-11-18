//go:build linux

package securityscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHiddenKernelModuleRequiresLiveStableSysfsEntry(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "sys")
	proc := filepath.Join(root, "modules")
	for name, state := range map[string]string{"visible": "live", "hidden": "live", "loading": "coming", "builtin": ""} {
		dir := filepath.Join(sys, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if state != "" {
			if err := os.WriteFile(filepath.Join(dir, "initstate"), []byte(state+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(sys, "hidden", "taint"), []byte("OE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proc, []byte("visible 123 0 - Live 0x0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := scanHiddenKernelModules(context.Background(), sys, proc, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Rule != "hidden-kernel-module" || findings[0].Path != filepath.Join(sys, "hidden") {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	if findings[0].Quarantinable || findings[0].Quarantined || findings[0].ContainmentBlockedReason == "" || !strings.Contains(findings[0].Detail, "taint=OE") {
		t.Fatalf("live module must remain an unresolved integrity finding: %#v", findings[0])
	}
}

func TestHiddenKernelModuleDoesNotAssumeUnreadableProcIsEmpty(t *testing.T) {
	_, err := scanHiddenKernelModules(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "missing"), 10)
	if err == nil {
		t.Fatal("an unreadable module list must be reported instead of generating false hidden-module findings")
	}
}

func TestSearchKernelModulePathsFindsRenamedRuntimePayload(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "nested", "runtime_driver.ko")
	if err := os.MkdirAll(filepath.Dir(payload), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("module"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := searchKernelModulePaths(context.Background(), "runtime_driver", []string{root})
	if len(paths) != 1 || paths[0] != payload {
		t.Fatalf("runtime module payload was not located: %#v", paths)
	}
}
