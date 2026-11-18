//go:build linux

package xdp

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Model a routed CNI without enslaving the physical uplink to a bridge. All
// links, routes and sysctls live in a disposable network/mount namespace.
func TestRoutedContainerIngress(t *testing.T) {
	if os.Getenv("NODEWALL_BPF_TEST") != "1" {
		t.Skip("requires Linux BPF and network namespace privileges")
	}
	if os.Getenv("NODEWALL_ROUTED_TEST_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		object, err := filepath.Abs("../../bpf/gen/xdpacl_bpfel.o")
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "--net", "--mount", exe, "-test.run=^TestRoutedContainerIngress$", "-test.v")
		cmd.Env = append(os.Environ(), "NODEWALL_ROUTED_TEST_CHILD=1", "NODEWALL_ROUTED_TEST_OBJECT="+object)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("routed fixture: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("sysfs", "/sys", "sysfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "nc-up", "type", "veth", "peer", "name", "nc-ext")
	run("ip", "link", "add", "nc-pod", "type", "veth", "peer", "name", "nc-peer")
	run("ip", "link", "set", "nc-up", "address", "02:00:00:00:00:11")
	run("ip", "link", "set", "nc-peer", "address", "02:00:00:00:00:22")
	run("ip", "addr", "add", "192.0.2.1/24", "dev", "nc-up")
	run("ip", "addr", "add", "10.244.0.1/24", "dev", "nc-pod")
	for _, name := range []string{"nc-up", "nc-ext", "nc-pod", "nc-peer"} {
		run("ip", "link", "set", name, "up")
	}
	run("ip", "neigh", "replace", "10.244.0.2", "lladdr", "02:00:00:00:00:22", "nud", "permanent", "dev", "nc-pod")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(os.Getenv("NODEWALL_ROUTED_TEST_OBJECT"))
	if err := manager.Attach("nc-up", AttachModeGeneric); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Detach("nc-up"); err != nil {
			t.Error(err)
		}
	})
	if err := manager.WriteConfig("nc-up", Config{PolicyEnforced: true, NonIPv4Action: "drop"}); err != nil {
		t.Fatal(err)
	}
	ext, _ := net.InterfaceByName("nc-ext")
	peer, _ := net.InterfaceByName("nc-peer")
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	readFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(readFD)
	if err := unix.Bind(readFD, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: peer.Index}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptTimeval(readFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 300000}); err != nil {
		t.Fatal(err)
	}
	send := func(dst []byte) {
		t.Helper()
		packet := bridgeProbePacket([]byte{2, 0, 0, 0, 0, 17}, dst)
		if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ext.Index}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("routed-pod-request-survives-host-default-deny", func(t *testing.T) {
		send([]byte{10, 244, 0, 2})
		buffer := make([]byte, 2048)
		for range 20 {
			n, _, err := unix.Recvfrom(readFD, buffer, 0)
			if err != nil {
				t.Fatalf("routed pod traffic was blocked: %v", err)
			}
			if bytes.Contains(buffer[:n], []byte("nodewall-bridge-probe")) {
				return
			}
		}
		t.Fatal("routed probe not received")
	})
	t.Run("host-local-request-still-denied", func(t *testing.T) {
		listener, err := net.ListenPacket("udp4", "192.0.2.1:49321")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		send([]byte{192, 0, 2, 1})
		listener.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if _, _, err := listener.ReadFrom(make([]byte, 256)); err == nil {
			t.Fatal("routed bypass opened a host port")
		}
	})
}
