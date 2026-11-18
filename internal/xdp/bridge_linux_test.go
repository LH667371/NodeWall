//go:build linux

package xdp

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"nodewall/internal/models"
)

// Run the real XDP -> Linux bridge -> TC path in a disposable network
// namespace. No physical NIC, host firewall, guest disk or service is changed.
func TestBridgeGuestForwarding(t *testing.T) {
	if os.Getenv("NODEWALL_BPF_TEST") != "1" {
		t.Skip("requires Linux BPF and network namespace privileges")
	}
	if os.Getenv("NODEWALL_BRIDGE_TEST_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		object, err := filepath.Abs("../../bpf/gen/xdpacl_bpfel.o")
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "--net", "--mount", exe, "-test.run=^TestBridgeGuestForwarding$", "-test.v")
		cmd.Env = append(os.Environ(), "NODEWALL_BRIDGE_TEST_CHILD=1", "NODEWALL_BRIDGE_TEST_OBJECT="+object)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("bridge fixture: %v\n%s", err, out)
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
	run := func(t *testing.T, args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run(t, "ip", "link", "set", "lo", "up")
	run(t, "ip", "link", "add", "nw-br", "type", "bridge")
	run(t, "ip", "link", "add", "nw-up", "type", "veth", "peer", "name", "nw-ext")
	run(t, "ip", "link", "add", "nw-up2", "type", "veth", "peer", "name", "nw-ext2")
	run(t, "ip", "link", "add", "nw-tap", "type", "veth", "peer", "name", "nw-guest")
	for _, name := range []string{"nw-up", "nw-up2", "nw-tap"} {
		run(t, "ip", "link", "set", name, "master", "nw-br")
	}
	run(t, "ip", "link", "set", "nw-up", "address", "02:00:00:00:00:01")
	run(t, "ip", "link", "set", "nw-br", "address", "02:00:00:00:00:01")
	run(t, "ip", "link", "set", "nw-guest", "address", "02:00:00:00:00:22")
	run(t, "ip", "addr", "add", "192.0.2.1/24", "dev", "nw-br")
	for _, name := range []string{"nw-br", "nw-up", "nw-ext", "nw-up2", "nw-ext2", "nw-tap", "nw-guest"} {
		run(t, "ip", "link", "set", name, "up")
	}
	// Disable multicast snooping in this isolated fixture so the test also
	// covers unknown multicast/broadcast forwarding before guest discovery.
	if err := os.WriteFile("/sys/class/net/nw-br/bridge/multicast_snooping", []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(os.Getenv("NODEWALL_BRIDGE_TEST_OBJECT"))
	if err := manager.Attach("nw-up", AttachModeGeneric); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Detach("nw-up"); err != nil {
			t.Error(err)
		}
	})
	guest, err := net.InterfaceByName("nw-guest")
	if err != nil {
		t.Fatal(err)
	}
	ext, err := net.InterfaceByName("nw-ext")
	if err != nil {
		t.Fatal(err)
	}
	guestFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(guestFD)
	if err = unix.Bind(guestFD, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: guest.Index}); err != nil {
		t.Fatal(err)
	}
	if err = unix.SetsockoptTimeval(guestFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 250000}); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	host, err := net.ListenPacket("udp4", "0.0.0.0:49321")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	// External/guest veth peers share this namespace with the test process.
	// Bind to the bridge so their independently delivered broadcast copies
	// cannot masquerade as a packet that bypassed the host's TC policy.
	raw, err := host.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "nw-br")
	}); err != nil {
		t.Fatal(err)
	}
	if bindErr != nil {
		t.Fatal(bindErr)
	}
	send := func(t *testing.T, packet []byte) {
		t.Helper()
		if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ext.Index}); err != nil {
			t.Fatal(err)
		}
	}
	readHost := func(t *testing.T, want bool) {
		t.Helper()
		host.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 512)
		n, _, err := host.ReadFrom(buf)
		got := err == nil && bytes.Contains(buf[:n], []byte("nodewall-bridge-probe"))
		if got != want {
			t.Fatalf("host delivery=%t want=%t err=%v", got, want, err)
		}
	}
	readGuest := func(t *testing.T) {
		t.Helper()
		buf := make([]byte, 2048)
		for i := 0; i < 30; i++ {
			n, _, err := unix.Recvfrom(guestFD, buf, 0)
			if err != nil {
				t.Fatalf("guest did not receive forwarded frame: %v", err)
			}
			if bytes.Contains(buf[:n], []byte("nodewall-bridge-probe")) {
				return
			}
		}
		t.Fatal("guest packet not found")
	}
	broadcast := bridgeProbePacket([]byte{255, 255, 255, 255, 255, 255}, []byte{255, 255, 255, 255})
	send(t, broadcast)
	readHost(t, true)
	readGuest(t)
	if err := manager.WriteConfig("nw-up", Config{PolicyEnforced: true, NonIPv4Action: "drop"}); err != nil {
		t.Fatal(err)
	}
	t.Run("guest-unicast-default-deny", func(t *testing.T) {
		send(t, bridgeProbePacket(guest.HardwareAddr, []byte{192, 0, 2, 22}))
		readGuest(t)
	})
	t.Run("broadcast-guest-copy-survives-host-deny", func(t *testing.T) { send(t, broadcast); readGuest(t); readHost(t, false) })
	t.Run("host-unicast-still-denied", func(t *testing.T) {
		send(t, bridgeProbePacket([]byte{2, 0, 0, 0, 0, 1}, []byte{192, 0, 2, 1}))
		readHost(t, false)
	})
	t.Run("host-allow-port-still-works", func(t *testing.T) {
		if err := manager.UpsertPublicPortRule("nw-up", models.PortRule{Protocol: models.PortProtocolUDP, Port: 49321}); err != nil {
			t.Fatal(err)
		}
		send(t, bridgeProbePacket([]byte{2, 0, 0, 0, 0, 1}, []byte{192, 0, 2, 1}))
		readHost(t, true)
	})
	t.Run("ipv6-multicast-reaches-guest", func(t *testing.T) {
		packet := make([]byte, 14+40+len("nodewall-bridge-probe"))
		copy(packet, []byte{0x33, 0x33, 0, 0, 0, 1})
		copy(packet[6:], ext.HardwareAddr)
		binary.BigEndian.PutUint16(packet[12:], unix.ETH_P_IPV6)
		packet[14], packet[20], packet[21] = 0x60, 59, 64 // IPv6, no next header.
		binary.BigEndian.PutUint16(packet[18:], uint16(len(packet)-54))
		copy(packet[22:], net.ParseIP("fe80::9").To16())
		copy(packet[38:], net.ParseIP("ff02::1").To16())
		copy(packet[54:], "nodewall-bridge-probe")
		send(t, packet)
		readGuest(t)
	})
	t.Run("uplinks-keep-independent-host-policies", func(t *testing.T) {
		if err := manager.Attach("nw-up2", AttachModeGeneric); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := manager.Detach("nw-up2"); err != nil {
				t.Error(err)
			}
		})
		if err := manager.WriteConfig("nw-up2", Config{PolicyEnforced: true, NonIPv4Action: "drop"}); err != nil {
			t.Fatal(err)
		}
		ext2, err := net.InterfaceByName("nw-ext2")
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Sendto(fd, broadcast, 0, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ext2.Index}); err != nil {
			t.Fatal(err)
		}
		// The first uplink allows this port; its TC filter must continue to
		// the second uplink's filter instead of accepting an unrelated frame.
		readGuest(t)
		readHost(t, false)
	})
	t.Run("platform-filter-still-runs-and-survives-detach", func(t *testing.T) {
		// TCX does not create clsact; add it without replacing any filter.
		conn, err := openTCNetlink()
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.AddClsactQdisc(manager.states["nw-up"].bridgeIndex); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn.Close()
		run(t, "tc", "filter", "add", "dev", "nw-br", "ingress", "pref", "60000", "protocol", "all", "u32", "match", "u32", "0", "0", "action", "drop")
		send(t, broadcast)
		readGuest(t)
		readHost(t, false)
		for _, name := range []string{"nw-up", "nw-up2"} {
			if err := manager.Detach(name); err != nil {
				t.Fatal(err)
			}
		}
		out, err := exec.Command("tc", "filter", "show", "dev", "nw-br", "ingress").CombinedOutput()
		if err != nil || !bytes.Contains(out, []byte("60000")) || bytes.Contains(out, []byte(tcHostProgramName)) {
			t.Fatalf("platform filter lost or NodeWall filter stranded: %s %v", out, err)
		}
	})
}

func bridgeProbePacket(mac, dst []byte) []byte {
	payload := []byte("nodewall-bridge-probe")
	packet := make([]byte, 14+20+8+len(payload))
	copy(packet, mac)
	copy(packet[6:], []byte{2, 0, 0, 0, 0, 9})
	binary.BigEndian.PutUint16(packet[12:], 0x0800)
	ip := packet[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:], []byte{192, 0, 2, 9})
	copy(ip[16:], dst)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp, 41234)
	binary.BigEndian.PutUint16(udp[2:], 49321)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	return packet
}
