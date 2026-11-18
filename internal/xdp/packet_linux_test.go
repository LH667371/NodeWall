//go:build linux

package xdp

import (
	"encoding/binary"
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestXDPReplyFlowDirections(t *testing.T) {
	if !hostPacketTestNamespace(t) {
		return
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec("../../bpf/gen/xdpacl_bpfel.o")
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	config := configValue{}
	config.Reserved[0], config.Reserved[2], config.Reserved[7] = 1, 1, 4
	if err := collection.Maps["config_map"].Put(uint32(0), config); err != nil {
		t.Fatal(err)
	}
	verdict := func(t *testing.T, program string, packet []byte, want uint32) {
		t.Helper()
		got, _, err := collection.Programs[program].Test(packet)
		if err != nil || got != want {
			t.Fatalf("%s verdict=%d want=%d err=%v", program, got, want, err)
		}
	}
	request := testEthernetPacket(0, 0x0800)
	response := append([]byte(nil), request...)
	copy(response[26:30], request[30:34])
	copy(response[30:34], request[26:30])
	copy(response[34:36], request[36:38])
	copy(response[36:38], request[34:36])
	t.Run("denied-egress-cannot-authorize-itself-or-a-reply", func(t *testing.T) {
		verdict(t, "tc_egress_track", request, 2)
		verdict(t, "tc_egress_track", request, 2)
		verdict(t, "xdp_acl", response, 1)
	})
	t.Run("denied-dns-cannot-open-a-service-wildcard", func(t *testing.T) {
		dns := append([]byte(nil), request...)
		dns[23] = 17
		binary.BigEndian.PutUint16(dns[36:38], 53)
		verdict(t, "tc_egress_track", dns, 2)
		reply := append([]byte(nil), response...)
		reply[23] = 17
		binary.BigEndian.PutUint16(reply[34:36], 53)
		binary.BigEndian.PutUint16(reply[36:38], 42001)
		verdict(t, "xdp_acl", reply, 1)
	})
	t.Run("allowed-outbound-opens-ingress-reply-without-bypassing-egress", func(t *testing.T) {
		key, _, err := CIDRToKey("192.0.2.2/32")
		if err != nil {
			t.Fatal(err)
		}
		if err := collection.Maps["egress_allow_ipv4"].Put(key, allowValue{Allow: 1}); err != nil {
			t.Fatal(err)
		}
		verdict(t, "tc_egress_track", request, ^uint32(0))
		verdict(t, "xdp_acl", response, 2)
		if err := collection.Maps["egress_allow_ipv4"].Delete(key); err != nil {
			t.Fatal(err)
		}
		verdict(t, "tc_egress_track", request, 2)
	})
	t.Run("accepted-ingress-allows-only-its-egress-reply", func(t *testing.T) {
		if err := collection.Maps["public_ports"].Put(portRuleKey{Protocol: 6, Port: 22}, portValue{Allow: 1}); err != nil {
			t.Fatal(err)
		}
		verdict(t, "xdp_acl", request, 2)
		verdict(t, "tc_egress_track", response, ^uint32(0))
		if err := collection.Maps["egress_deny_ports"].Put(portRuleKey{Protocol: 6, Port: 41000}, portValue{Allow: 1}); err != nil {
			t.Fatal(err)
		}
		verdict(t, "tc_egress_track", response, 2)
	})
	t.Run("ingress-observation-still-tracks-egress-replies", func(t *testing.T) {
		config.Reserved[0] = 0
		if err := collection.Maps["config_map"].Put(uint32(0), config); err != nil {
			t.Fatal(err)
		}
		incoming := append([]byte(nil), request...)
		binary.BigEndian.PutUint16(incoming[34:36], 42000)
		binary.BigEndian.PutUint16(incoming[36:38], 2222)
		outgoing := append([]byte(nil), response...)
		binary.BigEndian.PutUint16(outgoing[34:36], 2222)
		binary.BigEndian.PutUint16(outgoing[36:38], 42000)
		verdict(t, "xdp_acl", incoming, 2)
		verdict(t, "tc_egress_track", outgoing, ^uint32(0))
	})
}

// These tests execute the real compiled program with BPF_PROG_TEST_RUN. They
// never attach to a NIC or alter host networking; opt in on a Linux test host.
func TestXDPVLANEnforcement(t *testing.T) {
	if !hostPacketTestNamespace(t) {
		return
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec("../../bpf/gen/xdpacl_bpfel.o")
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	config := configValue{NonIPv4Action: 1}
	config.Reserved[0] = 1
	if err := collection.Maps["config_map"].Put(uint32(0), config); err != nil {
		t.Fatal(err)
	}
	program := collection.Programs["xdp_acl"]
	for _, tc := range []struct {
		name     string
		tags     int
		protocol uint16
		want     uint32
	}{
		{"untagged-default-deny", 0, 0x0800, 1},
		{"vlan-default-deny", 1, 0x0800, 1},
		{"qinq-default-deny", 2, 0x0800, 1},
		{"excess-vlan-depth", 3, 0x0800, 1},
		{"vlan-ipv6-deny", 1, 0x86dd, 1},
		{"arp-remains-available", 1, 0x0806, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, _, err := program.Test(testEthernetPacket(tc.tags, tc.protocol))
			if err != nil {
				t.Fatal(err)
			}
			if result != tc.want {
				t.Fatalf("verdict=%d want=%d", result, tc.want)
			}
		})
	}
	if err := collection.Maps["public_ports"].Put(portRuleKey{Protocol: 6, Port: 22}, portValue{Allow: 1}); err != nil {
		t.Fatal(err)
	}
	for _, tags := range []int{0, 1, 2} {
		result, _, err := program.Test(testEthernetPacket(tags, 0x0800))
		if err != nil || result != 2 {
			t.Fatalf("allowed SSH tags=%d verdict=%d err=%v", tags, result, err)
		}
	}
	if err := collection.Maps["deny_ports"].Put(portRuleKey{Protocol: 6, Port: 22}, portValue{Allow: 1}); err != nil {
		t.Fatal(err)
	}
	result, _, err := program.Test(testEthernetPacket(2, 0x0800))
	if err != nil || result != 1 {
		t.Fatalf("deny must override allow: verdict=%d err=%v", result, err)
	}
	truncated := testEthernetPacket(1, 0x0800)[:16]
	result, _, err = program.Test(truncated)
	if err != nil || result != 1 {
		t.Fatalf("truncated VLAN verdict=%d err=%v", result, err)
	}
}

// Packet test-run uses the caller's FIB. Give its synthetic host addresses
// local routes so a Docker/default route cannot turn host-policy checks into
// forwarding checks. Reexec avoids changing the Go test process's namespace.
func hostPacketTestNamespace(t *testing.T) bool {
	t.Helper()
	if os.Getenv("NODEWALL_BPF_TEST") != "1" {
		t.Skip("set NODEWALL_BPF_TEST=1 on Linux with BPF privileges")
	}
	if os.Getenv("NODEWALL_PACKET_TEST_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "--net", exe, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v")
		cmd.Env = append(os.Environ(), "NODEWALL_PACKET_TEST_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("host packet fixture: %v\n%s", err, out)
		}
		t.Log(string(out))
		return false
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "192.0.2.1/32", "dev", "lo"},
		{"addr", "add", "192.0.2.2/32", "dev", "lo"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v\n%s", args, err, out)
		}
	}
	return true
}

func TestXDPDHCPBroadcastAudit(t *testing.T) {
	if !hostPacketTestNamespace(t) {
		return
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec("../../bpf/gen/xdpacl_bpfel.o")
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	config := configValue{}
	config.Reserved[0] = 1
	if err := collection.Maps["config_map"].Put(uint32(0), config); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
		want   uint8
	}{
		{"complete-client-broadcast", nil, dropReasonDHCPBroadcast},
		{"renewing-client-broadcast", func(p []byte) []byte { copy(p[26:30], []byte{192, 0, 2, 99}); return p }, dropReasonDHCPBroadcast},
		{"wrong-client-port", func(p []byte) []byte { p[35] = 69; return p }, dropReasonSourceNotAllowed},
		{"server-reply", func(p []byte) []byte { p[42] = 2; return p }, dropReasonSourceNotAllowed},
		{"missing-cookie", func(p []byte) []byte { p[278] = 0; return p }, dropReasonSourceNotAllowed},
		{"mismatched-client-mac", func(p []byte) []byte { p[70] = 7; return p }, dropReasonSourceNotAllowed},
		{"fragmented-request", func(p []byte) []byte { p[20] = 0x20; return p }, dropReasonSourceNotAllowed},
		{"truncated-bootp", func(p []byte) []byte { return p[:len(p)-1] }, dropReasonSourceNotAllowed},
		{"invalid-udp-length", func(p []byte) []byte { binary.BigEndian.PutUint16(p[38:], 8); return p }, dropReasonSourceNotAllowed},
		{"oversize-ipv4-udp-length", func(p []byte) []byte { binary.BigEndian.PutUint16(p[38:], 65535); return p }, dropReasonSourceNotAllowed},
		{"invalid-ip-length", func(p []byte) []byte { binary.BigEndian.PutUint16(p[16:], 40); return p }, dropReasonSourceNotAllowed},
		{"not-broadcast-ethernet", func(p []byte) []byte { p[0] = 2; return p }, dropReasonSourceNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := testDHCPBroadcast()
			if tc.mutate != nil {
				packet = tc.mutate(packet)
			}
			got, _, err := collection.Programs["xdp_acl"].Test(packet)
			if err != nil || got != 1 {
				t.Fatalf("DHCP classification changed the deny verdict: %d %v", got, err)
			}
			iter := collection.Maps["drop_logs"].Iterate()
			var key dropLogKey
			var value dropLogValue
			if !iter.Next(&key, &value) || key.Reason != tc.want || key.DestPort != 67 || value.Drops != 1 {
				t.Fatalf("audit reason=%+v count=%+v want=%d err=%v", key, value, tc.want, iter.Err())
			}
			if err := collection.Maps["drop_logs"].Delete(key); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Classification cannot override an explicit deny or an allowed service.
	port := portRuleKey{Protocol: 17, Port: 67}
	if err := collection.Maps["deny_ports"].Put(port, portValue{Allow: 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := collection.Programs["xdp_acl"].Test(testDHCPBroadcast()); err != nil {
		t.Fatal(err)
	}
	var value dropLogValue
	key := dropLogKey{DestPort: 67, Reason: dropReasonDeniedPort}
	if err := collection.Maps["drop_logs"].Lookup(key, &value); err != nil || value.Drops != 1 {
		t.Fatalf("explicit deny was relabeled: %+v %v", value, err)
	}
	if err := collection.Maps["deny_ports"].Delete(port); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["public_ports"].Put(port, portValue{Allow: 1}); err != nil {
		t.Fatal(err)
	}
	if got, _, err := collection.Programs["xdp_acl"].Test(testDHCPBroadcast()); err != nil || got != 2 {
		t.Fatalf("allowed DHCP service was blocked: %d %v", got, err)
	}
}

func testDHCPBroadcast() []byte {
	packet := make([]byte, 14+20+8+240)
	copy(packet[:6], []byte{255, 255, 255, 255, 255, 255})
	copy(packet[6:12], []byte{2, 0, 0, 0, 0, 9})
	binary.BigEndian.PutUint16(packet[12:], 0x0800)
	ip := packet[14:]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	copy(ip[16:20], []byte{255, 255, 255, 255})
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:], 68)
	binary.BigEndian.PutUint16(udp[2:], 67)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	bootp := udp[8:]
	bootp[0], bootp[1], bootp[2] = 1, 1, 6
	copy(bootp[28:34], packet[6:12])
	copy(bootp[236:], []byte{99, 130, 83, 99})
	return packet
}

func TestXDPObservationAudit(t *testing.T) {
	if !hostPacketTestNamespace(t) {
		return
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec("../../bpf/gen/xdpacl_bpfel.o")
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	config := configValue{}
	config.Reserved[0], config.Reserved[2], config.Reserved[7] = 1, 1, 4
	packet := testEthernetPacket(0, 0x0800)
	for _, observe := range []uint8{1, 0} {
		config.Reserved[4], config.Reserved[5] = observe, observe
		if err := collection.Maps["config_map"].Put(uint32(0), config); err != nil {
			t.Fatal(err)
		}
		for _, direction := range []struct {
			program, logs string
			remote        uint32
			want          uint32
		}{
			{"xdp_acl", "drop_logs", 0x010200c0, 1},
			{"tc_egress_track", "egress_drop_logs", 0x020200c0, 2},
		} {
			want := direction.want
			if observe == 1 {
				want = 2
				if direction.program == "tc_egress_track" {
					want = ^uint32(0)
				}
			}
			if got, _, err := collection.Programs[direction.program].Test(packet); err != nil || got != want {
				t.Fatalf("%s observe=%d verdict=%d want=%d err=%v", direction.program, observe, got, want, err)
			}
			key := dropLogKey{SourceIP: direction.remote, DestPort: 22, Reason: dropReasonSourceNotAllowed, Reserved: observe}
			var value dropLogValue
			if err := collection.Maps[direction.logs].Lookup(key, &value); err != nil || value.Drops != 1 {
				t.Fatalf("%s observe=%d audit key/count=%+v/%+v err=%v", direction.program, observe, key, value, err)
			}
		}
	}
}

func testEthernetPacket(tags int, protocol uint16) []byte {
	packet := make([]byte, 64+4*tags)
	offset := 12
	for tag := 0; tag < tags; tag++ {
		binary.BigEndian.PutUint16(packet[offset:], 0x8100)
		binary.BigEndian.PutUint16(packet[offset+2:], uint16(tag+1))
		offset += 4
	}
	binary.BigEndian.PutUint16(packet[offset:], protocol)
	ip := packet[offset+2:]
	ip[0] = 0x45
	ip[8], ip[9] = 64, 6
	binary.BigEndian.PutUint16(ip[2:], 40)
	copy(ip[12:], []byte{192, 0, 2, 1})
	copy(ip[16:], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint16(ip[20:], 41000)
	binary.BigEndian.PutUint16(ip[22:], 22)
	ip[32] = 0x50
	return packet
}
