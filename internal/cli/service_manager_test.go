package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSysVServiceScriptIsValidShell(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodewall-agent")
	if err := os.WriteFile(path, []byte(sysVServiceScript("/opt/nodewall", "/etc/nodewall", "agent")), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("generated SysV script is invalid: %v: %s", err, output)
	}
}

func TestResolveServiceManagerNone(t *testing.T) {
	manager, err := resolveServiceManager("none")
	if err != nil || manager != serviceManagerNone {
		t.Fatalf("resolveServiceManager(none) = %q, %v", manager, err)
	}
}

func TestParseSystemdStateOutputSupportsCentOS219AndModernSystemctl(t *testing.T) {
	for input, expected := range map[string]string{
		"SystemState=degraded\n": "degraded",
		"SystemState=running\n":  "running",
		"running\n":              "running",
	} {
		if actual := parseSystemdStateOutput(input); actual != expected {
			t.Fatalf("parseSystemdStateOutput(%q) = %q, want %q", input, actual, expected)
		}
	}
}
