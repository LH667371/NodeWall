package cli

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestKernelNeedsIPTablesCompatibility(t *testing.T) {
	tests := []struct {
		release string
		want    bool
	}{
		{release: "3.10.0-693.11.1.el7.x86_64", want: true},
		{release: "4.18.0-348.23.1.el7.x86_64", want: false},
		{release: "5.14.0-503.el9.x86_64", want: false},
		{release: "unknown", want: false},
	}
	for _, test := range tests {
		t.Run(test.release, func(t *testing.T) {
			if got := kernelNeedsIPTablesCompatibility(test.release); got != test.want {
				t.Fatalf("kernelNeedsIPTablesCompatibility(%q) = %t, want %t", test.release, got, test.want)
			}
		})
	}
}

func TestResolveInstallDataplane(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "real", want: "real"},
		{input: "", want: "real"},
		{input: "auto", want: "real"},
		{input: "iptables", want: "iptables"},
		{input: "legacy", want: "iptables"},
	} {
		t.Run(test.input, func(t *testing.T) {
			got, err := resolveInstallDataplane(test.input)
			if err != nil {
				t.Fatalf("resolveInstallDataplane(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("resolveInstallDataplane(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
	if _, err := resolveInstallDataplane("unsupported"); err == nil {
		t.Fatal("expected unsupported dataplane to fail")
	}
}

func TestInstallServerHTTPAddrUsesReachableEnrollmentHost(t *testing.T) {
	if got := installServerHTTPAddr("0.0.0.0:8082", "", "192.168.201.16:9080"); got != "192.168.201.16:8082" {
		t.Fatalf("unexpected enrollment web address: %q", got)
	}
	if got := installServerHTTPAddr("0.0.0.0:8086", "https://192.0.2.20:9080", ""); got != "192.0.2.20:8086" {
		t.Fatalf("unexpected agent-url web address: %q", got)
	}
	if got := installServerHTTPAddr("127.0.0.1:8080", "", ""); got != "127.0.0.1:8080" {
		t.Fatalf("unexpected loopback web address: %q", got)
	}
}

func TestClusterInstallAgentAddress(t *testing.T) {
	tests := []struct {
		name, mode, listen, agentURL, ip string
		secure, explicit                 bool
		wantListen, wantAdvertised       string
	}{
		{"secure default", "all-in-one", "127.0.0.1:9080", "", "192.0.2.17", true, false, "0.0.0.0:9080", "192.0.2.17:9080"},
		{"explicit loopback", "all-in-one", "127.0.0.1:9080", "", "192.0.2.17", true, true, "127.0.0.1:9080", ""},
		{"explicit wildcard", "all-in-one", "0.0.0.0:9080", "", "192.0.2.17", true, true, "0.0.0.0:9080", "192.0.2.17:9080"},
		{"insecure runtime", "all-in-one", "127.0.0.1:9080", "", "192.0.2.17", false, false, "127.0.0.1:9080", ""},
		{"no usable IP", "all-in-one", "127.0.0.1:9080", "", "127.0.0.1", true, false, "127.0.0.1:9080", ""},
		{"explicit URL", "all-in-one", "127.0.0.1:9080", "https://127.0.0.1:9080", "192.0.2.17", true, false, "127.0.0.1:9080", ""},
		{"agent only", "agent-only", "127.0.0.1:9080", "", "192.0.2.17", true, false, "127.0.0.1:9080", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listen, advertised := clusterInstallAgentAddress(tc.mode, tc.listen, tc.agentURL, tc.ip, tc.secure, tc.explicit)
			if listen != tc.wantListen || advertised != tc.wantAdvertised {
				t.Fatalf("got listen=%q advertised=%q, want %q %q", listen, advertised, tc.wantListen, tc.wantAdvertised)
			}
		})
	}
}

func TestInstallServerHTTPAddrPreservesConcreteBind(t *testing.T) {
	for _, bind := range []string{"127.0.0.1:8086", "192.0.2.10:8086"} {
		if got := installServerHTTPAddr(bind, "https://192.0.2.17:9080", "192.0.2.17:9080"); got != bind {
			t.Errorf("bind %q advertised as %q", bind, got)
		}
	}
}

func TestChooseManagementServerAddrStartsAtNewDefault(t *testing.T) {
	selected, changed, err := chooseManagementServerAddr("0.0.0.0:8080")
	if err != nil {
		t.Fatal(err)
	}
	if selected == "0.0.0.0:8080" || !changed {
		t.Fatalf("standby selected the default application port: %q changed=%t", selected, changed)
	}
	if host, port, splitErr := net.SplitHostPort(selected); splitErr != nil || host != "0.0.0.0" {
		t.Fatalf("unexpected standby address: %q", selected)
	} else if portNumber, parseErr := strconv.Atoi(port); parseErr != nil || portNumber < 8086 {
		t.Fatalf("standby address did not start at 8086: %q", selected)
	}
}

func TestChooseManagementServerAddrMigratesLegacyFallbackPort(t *testing.T) {
	selected, changed, err := chooseManagementServerAddr("0.0.0.0:8081")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatalf("legacy standby port was not migrated: %q changed=%t", selected, changed)
	}
	_, port, splitErr := net.SplitHostPort(selected)
	portNumber, parseErr := strconv.Atoi(port)
	if splitErr != nil || parseErr != nil || portNumber < 8086 {
		t.Fatalf("legacy standby port was not moved to the 8086 range: %q", selected)
	}
}

func TestMigrateLegacyServerPortUpdatesMainNodeAndHTTPAddress(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), "nodewall.env")
	legacy := strings.Join([]string{
		"NODEWALL_SERVER_ADDR=127.0.0.1:8080",
		"NODEWALL_SERVER_HTTP_ADDR=192.0.2.20:8080",
		"NODEWALL_AGENT_URL=https://192.0.2.20:9080",
		"NODEWALL_INSTALL_MODE=all-in-one",
		"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	changed, err := migrateLegacyServerPort(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy main-node web port was not migrated")
	}
	serverAddr := readEnvValue(envPath, "NODEWALL_SERVER_ADDR", "")
	serverHTTPAddr := readEnvValue(envPath, "NODEWALL_SERVER_HTTP_ADDR", "")
	_, serverPort, serverErr := net.SplitHostPort(serverAddr)
	_, httpPort, httpErr := net.SplitHostPort(serverHTTPAddr)
	serverPortNumber, parseErr := strconv.Atoi(serverPort)
	if serverErr != nil || httpErr != nil || parseErr != nil || serverPortNumber < 8086 {
		t.Fatalf("legacy main-node port was not moved to 8086+: server=%q http=%q", serverAddr, serverHTTPAddr)
	}
	if httpPort != serverPort {
		t.Fatalf("HTTP address did not follow migrated server port: server=%q http=%q", serverAddr, serverHTTPAddr)
	}
}
