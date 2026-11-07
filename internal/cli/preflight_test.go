package cli

import (
	"net"
	"os"
	"strings"
	"testing"

	"nodewall/internal/models"
)

func healthyPreflightDeps() preflightDeps {
	return preflightDeps{
		goos: "linux",
		euid: func() int { return 0 },
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/etc/os-release":
				return []byte("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n"), nil
			case "/proc/sys/kernel/osrelease":
				return []byte("6.8.0-40-generic\n"), nil
			default:
				return nil, os.ErrNotExist
			}
		},
		lookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		runCommand: func(name string, _ ...string) (string, error) {
			switch name {
			case "systemctl":
				return "running", nil
			case "iptables":
				return "", nil
			default:
				return "", nil
			}
		},
		discoverInterfaces: func() (models.InterfaceInventory, error) {
			return models.InterfaceInventory{
				Recommended: "ens18",
				Interfaces: []models.DetectedInterface{{
					Name:       "ens18",
					MTU:        1500,
					Addresses:  []string{"192.0.2.10/24"},
					IsUp:       true,
					IsPhysical: true,
				}},
			}, nil
		},
		listenTCP: net.Listen,
		listenUDP: net.ListenPacket,
		probeBPF:  func([]byte) error { return nil },
	}
}

func TestPreflightHealthyHostCanInstall(t *testing.T) {
	report := checkPreflight(preflightOptions{
		Dataplane:        "real",
		InstallMode:      "all-in-one",
		EnableServices:   true,
		DefaultInterface: "ens18",
		AgentAddr:        "127.0.0.1:0",
		ServerAddr:       "127.0.0.1:0",
		ServerGRPCAddr:   "127.0.0.1:0",
		ServerQUICAddr:   "127.0.0.1:0",
		BPFObject:        []byte{1},
	}, healthyPreflightDeps())
	if report.failed() {
		t.Fatalf("healthy preflight failed: %s", report.failureSummary())
	}
	var output strings.Builder
	report.render(&output)
	text := output.String()
	if !strings.Contains(text, "结论: 可以安装") {
		t.Fatalf("preflight output did not contain success conclusion: %s", text)
	}
	for _, name := range []string{"Ubuntu 版本", "权限", "Linux 内核", "systemd", "端口", "网卡", "BPF/XDP", "iptables", "SSH 日志"} {
		if !strings.Contains(text, name) {
			t.Fatalf("preflight output did not contain %q: %s", name, text)
		}
	}
}

func TestPreflightRejectsUnsupportedKernelAndInterface(t *testing.T) {
	deps := healthyPreflightDeps()
	deps.readFile = func(path string) ([]byte, error) {
		switch path {
		case "/etc/os-release":
			return []byte("ID=ubuntu\nVERSION_ID=16.04\n"), nil
		case "/proc/sys/kernel/osrelease":
			return []byte("4.17.0-generic\n"), nil
		default:
			return nil, os.ErrNotExist
		}
	}
	deps.discoverInterfaces = func() (models.InterfaceInventory, error) {
		return models.InterfaceInventory{Interfaces: []models.DetectedInterface{{
			Name:       "docker0",
			IsUp:       true,
			IsPhysical: false,
		}}}, nil
	}
	report := checkPreflight(preflightOptions{
		Dataplane:        "real",
		InstallMode:      "agent-only",
		EnableServices:   false,
		DefaultInterface: "docker0",
		AgentAddr:        "127.0.0.1:0",
		BPFObject:        []byte{1},
	}, deps)
	if !report.failed() {
		t.Fatal("unsupported host unexpectedly passed preflight")
	}
	summary := report.failureSummary()
	for _, expected := range []string{"Ubuntu 版本", "Linux 内核", "网卡"} {
		if !strings.Contains(summary, expected) {
			t.Fatalf("failure summary %q did not contain %q", summary, expected)
		}
	}
}

func TestPreflightAllowsExistingAgentPortDuringReenrollment(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	deps := healthyPreflightDeps()
	report := checkPreflight(preflightOptions{
		Dataplane:        "real",
		InstallMode:      "agent-only",
		EnableServices:   false,
		DefaultInterface: "ens18",
		AgentAddr:        listener.Addr().String(),
		AllowPortReuse:   true,
		BPFObject:        []byte{1},
	}, deps)
	if report.failed() {
		t.Fatalf("re-enrollment should allow the current agent port: %s", report.failureSummary())
	}
	if report.Checks[4].Status != preflightWarn {
		t.Fatalf("expected port warning, got %#v", report.Checks[4])
	}
}

func TestParseUbuntuVersion(t *testing.T) {
	for _, test := range []struct {
		value        string
		major, minor int
		ok           bool
	}{
		{value: "24.04", major: 24, minor: 4, ok: true},
		{value: "18.04.7", major: 18, minor: 4, ok: true},
		{value: "unknown", ok: false},
		{value: "24", ok: false},
	} {
		major, minor, ok := parseUbuntuVersion(test.value)
		if major != test.major || minor != test.minor || ok != test.ok {
			t.Fatalf("parseUbuntuVersion(%q) = (%d, %d, %t), want (%d, %d, %t)", test.value, major, minor, ok, test.major, test.minor, test.ok)
		}
	}
}
