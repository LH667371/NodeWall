//go:build linux

package xdp

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// These tests execute the real compiled program with BPF_PROG_TEST_RUN. They
// never attach to a NIC or alter host networking; opt in on a Linux test host.
func TestXDPVLANEnforcement(t *testing.T) {
	if os.Getenv("NODEWALL_BPF_TEST") != "1" {
		t.Skip("set NODEWALL_BPF_TEST=1 on Linux with BPF privileges")
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
