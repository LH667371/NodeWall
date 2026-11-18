//go:build linux

package xdp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"nodewall/internal/models"
)

// The real legacy dataplane is tested in two disposable network namespaces.
// No NIC, firewall chain, or network namespace belonging to the host is changed.
func TestIPTablesHostConnections(t *testing.T) {
	if os.Getenv("NODEWALL_IPTABLES_TEST") != "1" {
		t.Skip("set NODEWALL_IPTABLES_TEST=1 on Linux with network namespace privileges")
	}
	role := os.Getenv("NODEWALL_IPTABLES_TEST_ROLE")
	if role == "" {
		parent, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		cmd := iptablesTestProcess("host")
		cmd.Env = append(cmd.Env, "NODEWALL_IPTABLES_TEST_PARENT_NET="+parent)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated dataplane test: %v\n%s", err, output)
		}
		return
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || os.Getenv("NODEWALL_IPTABLES_TEST_PARENT_NET") == "" || current == os.Getenv("NODEWALL_IPTABLES_TEST_PARENT_NET") {
		t.Fatal("refusing to run dataplane tests in the original host network namespace")
	}
	if role == "peer" {
		runIPTablesTestPeer(t)
		return
	}

	runNetworkCommand(t, "ip", "link", "set", "lo", "up")
	runNetworkCommand(t, "ip", "link", "add", "nwhost", "type", "veth", "peer", "name", "nwpeer")
	runNetworkCommand(t, "ip", "addr", "add", "192.0.2.1/30", "dev", "nwhost")
	runNetworkCommand(t, "ip", "link", "set", "nwhost", "up")
	peer := iptablesTestProcess("peer")
	input, err := peer.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := peer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	peer.Stderr = os.Stderr
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		_ = peer.Process.Kill()
		_ = peer.Wait()
	}()
	runNetworkCommand(t, "ip", "link", "set", "nwpeer", "netns", fmt.Sprint(peer.Process.Pid))
	fmt.Fprintln(input, "start")
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "ready" {
		t.Fatalf("peer failed to initialize: %q %v", scanner.Text(), scanner.Err())
	}
	callPeer := func(port int) error {
		fmt.Fprintln(input, port)
		if !scanner.Scan() {
			return fmt.Errorf("peer response ended: %v", scanner.Err())
		}
		var result string
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			return err
		}
		if result != "" {
			return fmt.Errorf("peer connection: %s", result)
		}
		return nil
	}
	for _, port := range []int{18081, 18082} {
		listenTestEcho(t, fmt.Sprintf("192.0.2.1:%d", port))
	}

	// Simulate a deployed raw/mangle version plus unrelated ZStack rules.
	runNetworkCommand(t, "iptables", "-t", "raw", "-A", "PREROUTING", "-p", "253", "-m", "comment", "--comment", "zstack-network", "-j", "RETURN")
	rawBefore := runNetworkCommand(t, "iptables", "-t", "raw", "-S")
	runNetworkCommand(t, "iptables", "-t", "filter", "-A", "INPUT", "-m", "comment", "--comment", "administrator-input", "-j", "RETURN")
	for _, item := range []struct{ table, parent, chain, flag string }{
		{"raw", "PREROUTING", iptablesChainName("nwhost"), "-i"},
		{"raw", "OUTPUT", iptablesEgressChainName("nwhost"), "-o"},
		{"mangle", "FORWARD", iptablesForwardEgressChainName("nwhost"), "-o"},
	} {
		runNetworkCommand(t, "iptables", "-t", item.table, "-N", item.chain)
		runNetworkCommand(t, "iptables", "-t", item.table, "-A", item.chain, "-j", "RETURN")
		runNetworkCommand(t, "iptables", "-t", item.table, "-I", item.parent, "1", item.flag, "nwhost", "-j", item.chain)
	}
	manager := newIPTablesManager(execIPTablesRunner{path: "iptables"}, nil)
	if err := manager.Attach("nwhost", AttachModeIPTables); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach("nwhost")
	if after := runNetworkCommand(t, "iptables", "-t", "raw", "-S"); after != rawBefore {
		t.Fatalf("legacy migration did not preserve the original raw table:\n%s", after)
	}
	if err := manager.ReplaceAllowlist("nwhost", []string{"198.51.100.254/32"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.ReplacePublicPortRules("nwhost", []models.PortRule{{Protocol: models.PortProtocolTCP, Port: 18081}}); err != nil {
		t.Fatal(err)
	}
	if err := manager.WriteConfig("nwhost", Config{PolicyEnforced: true}); err != nil {
		t.Fatal(err)
	}
	egress := DirectionPolicy{PolicyEnforced: true, AllowedPortRules: []models.PortRule{{Protocol: models.PortProtocolTCP, Port: 18080}, {Protocol: models.PortProtocolUDP, Port: 18053}}}
	if err := manager.ApplyDirectionPolicy("nwhost", models.DirectionEgress, egress); err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct{ network, endpoint string }{{"tcp", "192.0.2.2:18080"}, {"udp", "192.0.2.2:18053"}} {
		if err := probeTestEcho(probe.network, probe.endpoint); err != nil {
			t.Fatalf("host-initiated %s reply was blocked: %v", probe.network, err)
		}
	}
	if err := callPeer(18081); err != nil {
		t.Fatalf("response to an inbound service was blocked by egress: %v", err)
	}
	for _, direction := range []models.PolicyDirection{models.DirectionIngress, models.DirectionEgress} {
		stats, err := manager.ReadDirectionStats("nwhost", direction)
		if err != nil || stats.Dropped != 0 || stats.Passed == 0 {
			t.Fatalf("normal %s replies misclassified: stats=%+v err=%v", direction, stats, err)
		}
	}
	// Exercise the installed vendor's save/parse/restore code, if explicitly
	// supplied. The subprocess inherits this disposable network namespace.
	if python := os.Getenv("NODEWALL_ZSTACK_RESTORE_PYTHON"); python != "" {
		for range 3 {
			runNetworkCommand(t, python, "-c", "from zstacklib.utils import iptables; iptables.from_iptables_save().iptable_restore()")
			if err := manager.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if err := probeTestEcho("tcp", "192.0.2.2:18080"); err != nil {
				t.Fatalf("vendor restore broke the host connection: %v", err)
			}
		}
	}
	for _, direction := range []models.PolicyDirection{models.DirectionIngress, models.DirectionEgress} {
		chain, parent, flag := iptablesChainName("nwhost"), "INPUT", "-i"
		if direction == models.DirectionEgress {
			chain, parent, flag = iptablesEgressChainName("nwhost"), "OUTPUT", "-o"
		}
		for _, mutation := range []string{"empty", "bypass", "reordered", "deleted"} {
			expected := manager.chainDigests[chain]
			switch mutation {
			case "empty":
				runNetworkCommand(t, "iptables", "-t", "filter", "-F", chain)
			case "bypass":
				runNetworkCommand(t, "iptables", "-t", "filter", "-I", chain, "1", "-j", "RETURN")
			case "reordered":
				rules := ruleLines(runNetworkCommand(t, "iptables", "-t", "filter", "-S", chain))
				first, err := splitIPTablesArgs(rules[0])
				if err != nil {
					t.Fatal(err)
				}
				runNetworkCommand(t, "iptables", "-t", "filter", "-D", chain, "1")
				runNetworkCommand(t, "iptables", append([]string{"-t", "filter"}, first...)...)
			case "deleted":
				runNetworkCommand(t, "iptables", "-t", "filter", "-D", parent, flag, "nwhost", "-j", chain)
				runNetworkCommand(t, "iptables", "-t", "filter", "-F", chain)
				runNetworkCommand(t, "iptables", "-t", "filter", "-X", chain)
			}
			if _, err := manager.Runtime("nwhost"); err == nil {
				t.Fatalf("%s/%s: external overwrite was reported healthy", direction, mutation)
			}
			if err := manager.Reconcile(); err != nil {
				t.Fatalf("%s/%s repair: %v", direction, mutation, err)
			}
			if _, err := manager.Runtime("nwhost"); err != nil || manager.chainDigests[chain] != expected {
				t.Fatalf("%s/%s failed to restore the original policy: %v", direction, mutation, err)
			}
			if err := probeTestEcho("tcp", "192.0.2.2:18080"); err != nil {
				t.Fatalf("%s/%s broke allowed replies: %v", direction, mutation, err)
			}
			if err := probeTestEcho("tcp", "192.0.2.2:18082"); err == nil {
				t.Fatalf("%s/%s left outbound enforcement ineffective", direction, mutation)
			}
			if err := callPeer(18082); err == nil {
				t.Fatalf("%s/%s left inbound enforcement ineffective", direction, mutation)
			}
		}
	}
	if err := probeTestEcho("tcp", "192.0.2.2:18082"); err == nil {
		t.Fatal("unsolicited outbound connection bypassed default deny")
	}
	if err := callPeer(18082); err == nil {
		t.Fatal("unsolicited inbound connection bypassed default deny")
	}

	connection, err := net.DialTimeout("tcp", "192.0.2.2:18080", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := exchangeTestEcho(connection); err != nil {
		t.Fatal(err)
	}
	if err := manager.ReplaceBlockedCIDRs("nwhost", []string{"192.0.2.2/32"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.WriteConfig("nwhost", Config{PolicyEnforced: true}); err != nil {
		t.Fatal(err)
	}
	if err := exchangeTestEcho(connection); err == nil {
		t.Fatal("established reply bypassed an explicit source revocation")
	}
	if err := manager.ReplaceBlockedCIDRs("nwhost", nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.WriteConfig("nwhost", Config{PolicyEnforced: true, ObserveOnly: true}); err != nil {
		t.Fatal(err)
	}
	egress.ObserveOnly = true
	if err := manager.ApplyDirectionPolicy("nwhost", models.DirectionEgress, egress); err != nil {
		t.Fatal(err)
	}
	if err := probeTestEcho("tcp", "192.0.2.2:18082"); err != nil {
		t.Fatalf("observe mode blocked traffic: %v", err)
	}
	if err := callPeer(18082); err != nil {
		t.Fatalf("observe mode blocked inbound traffic: %v", err)
	}
	for range 2 {
		if err := manager.Detach("nwhost"); err != nil {
			t.Fatalf("repeatable cleanup: %v", err)
		}
	}
	filter := runNetworkCommand(t, "iptables", "-t", "filter", "-S")
	if strings.Contains(filter, "NWRAW_") || !strings.Contains(filter, "administrator-input") {
		t.Fatalf("cleanup left private rules or removed an administrator rule:\n%s", filter)
	}
	if after := runNetworkCommand(t, "iptables", "-t", "raw", "-S"); after != rawBefore {
		t.Fatalf("cleanup changed ZStack raw rules:\n%s", after)
	}
}

func iptablesTestProcess(role string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestIPTablesHostConnections$", "-test.timeout=45s")
	cmd.Env = append(os.Environ(), "NODEWALL_IPTABLES_TEST_ROLE="+role)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	return cmd
}

func runNetworkCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, output)
	}
	return string(output)
}

func listenTestEcho(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
}

func runIPTablesTestPeer(t *testing.T) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		t.Fatal("peer bootstrap ended")
	}
	runNetworkCommand(t, "ip", "link", "set", "lo", "up")
	runNetworkCommand(t, "ip", "addr", "add", "192.0.2.2/30", "dev", "nwpeer")
	runNetworkCommand(t, "ip", "link", "set", "nwpeer", "up")
	listenTestEcho(t, "192.0.2.2:18080")
	listenTestEcho(t, "192.0.2.2:18082")
	udp, err := net.ListenPacket("udp", "192.0.2.2:18053")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 512)
		for {
			n, remote, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buffer[:n], remote)
		}
	}()
	fmt.Println("ready")
	for scanner.Scan() {
		message := ""
		if err := probeTestEcho("tcp", "192.0.2.1:"+scanner.Text()); err != nil {
			message = err.Error()
		}
		_ = json.NewEncoder(os.Stdout).Encode(message)
	}
}

func probeTestEcho(network, endpoint string) error {
	connection, err := net.DialTimeout(network, endpoint, 700*time.Millisecond)
	if err != nil {
		return err
	}
	defer connection.Close()
	return exchangeTestEcho(connection)
}

func exchangeTestEcho(connection net.Conn) error {
	_ = connection.SetDeadline(time.Now().Add(700 * time.Millisecond))
	if _, err := connection.Write([]byte("reply-check")); err != nil {
		return err
	}
	buffer := make([]byte, len("reply-check"))
	if _, err := io.ReadFull(connection, buffer); err != nil {
		return err
	}
	if string(buffer) != "reply-check" {
		return fmt.Errorf("unexpected reply %q", buffer)
	}
	return nil
}
