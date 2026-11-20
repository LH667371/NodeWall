//go:build linux

package xdp

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"nodewall/internal/models"
)

func TestIPTablesAuditDecodesRealPacketAddresses(t *testing.T) {
	packet := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 19, 192, 0, 2, 16, 0, 68, 0, 67}
	sourceMAC := [6]byte{2, 1, 2, 3, 4, 5}
	input := []byte{unix.AF_INET, 0, 0, 0}
	binary.BigEndian.PutUint16(input[2:], firewallAuditGroup)
	args := defaultDenyAuditRule("eno1", models.DirectionIngress, false)
	prefix := args[slices.Index(args, "--nflog-prefix")+1]
	attrs := [][]byte{
		marshalLegacyAttr(nflogHeader, []byte{8, 0, 1, 0}), marshalLegacyAttr(nflogInDev, []byte{0, 0, 0, 7}),
		marshalLegacyAttr(nflogPhysIn, []byte{0, 0, 0, 12}), marshalLegacyAttr(nflogHWAddr, append([]byte{0, 6, 0, 0}, sourceMAC[:]...)),
		marshalLegacyAttr(nflogPrefix, append([]byte(prefix), 0)), marshalLegacyAttr(nflogData, packet),
	}
	for _, attr := range attrs {
		input = append(input, attr...)
	}
	sample, ok := decodeAuditPacket(input, time.Now())
	if !ok || sample.record.SourceIP != "192.0.2.19" || sample.record.Port != 67 || sample.record.Drops != 1 || sample.record.Interface != "eno1" || sample.input != 7 || sample.port != 12 || sample.mac != sourceMAC {
		t.Fatalf("incorrect audit sample: %+v", sample)
	}
	if traffic := sample.record.Traffic; traffic.LocalIP != "192.0.2.16" || traffic.Delivery != "" || traffic.Protocol != "udp" {
		t.Fatalf("a destination port alone was mistaken for a broadcast: %+v", traffic)
	}
	ethernet := append(slices.Clone(input), marshalLegacyAttr(nflogHWType, []byte{0, unix.ARPHRD_ETHER})...)
	ethernet = append(ethernet, marshalLegacyAttr(nflogHWHeader, []byte{255, 255, 255, 255, 255, 255, 2, 1, 2, 3, 4, 5, 8, 0})...)
	if sample, ok := decodeAuditPacket(ethernet, time.Now()); !ok || !sample.linkBroadcast || sample.record.Traffic.Delivery != "" {
		t.Fatalf("Ethernet destination must be recorded without guessing the IPv4 delivery: %+v", sample)
	}
	input[3] ^= 1
	if _, ok := decodeAuditPacket(input, time.Now()); ok {
		t.Fatal("accepted traffic from a different NFLOG group")
	}
}

func TestIPTablesAuditConfirmsDirectedBroadcastOnTheInputLink(t *testing.T) {
	now := time.Now()
	topology := packetAuditTopology{
		expires: now.Add(time.Minute),
		links:   map[int]auditLink{7: {name: "br_eno1", kind: "bridge"}},
		broadcasts: map[auditBroadcastKey]bool{
			{device: 7, address: "192.0.2.127"}: true,
			{device: 8, address: "192.0.2.255"}: true,
		},
	}
	for address, want := range map[string]string{"192.0.2.127": "broadcast", "192.0.2.255": "", "192.0.2.16": ""} {
		traffic := &models.FirewallTraffic{LocalIP: address}
		topology.attribute(packetAuditObservation{
			input: 7, linkBroadcast: true,
			record: models.DropLogRecord{Timestamp: now, Direction: models.DirectionIngress, Traffic: traffic},
		})
		if traffic.Delivery != want {
			t.Fatalf("incorrect IPv4 delivery for %s: %+v", address, traffic)
		}
	}
}

func TestIPTablesAuditRequiresLinkAndGuestEvidence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "guest.xml"), []byte(`<domstatus><domain><name>guest-a</name><devices><interface><mac address="02:01:02:03:04:05"/><target dev="vnic12.0"/></interface></devices></domain></domstatus>`), 0o600); err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 1, 2, 3, 4, 5}
	now := time.Now()
	topology := packetAuditTopology{expires: now.Add(time.Minute), guests: readAuditGuests(dir), links: map[int]auditLink{
		2: {name: "eno1", kind: "physical", master: 7}, 7: {name: "br_eno1", kind: "bridge"},
		10: {name: "outer0", kind: "veth", master: 7}, 12: {name: "vnic12.0", kind: "tap", master: 7},
	}, fdb: map[auditMACKey]int{{bridge: 7, mac: mac}: 12}}
	for _, check := range []struct {
		port           int
		mac            [6]byte
		origin, device string
	}{
		{2, mac, "uplink", "eno1"}, {10, mac, "veth", "outer0"}, {12, mac, "vm", "vnic12.0"},
		{12, [6]byte{}, "tap", "vnic12.0"}, {0, mac, "vm", "vnic12.0"}, {0, [6]byte{}, "", ""},
	} {
		traffic := &models.FirewallTraffic{Evidence: models.FirewallPacketSample}
		topology.attribute(packetAuditObservation{input: 7, port: check.port, mac: check.mac, record: models.DropLogRecord{Timestamp: now, Direction: models.DirectionIngress, Traffic: traffic}})
		if traffic.Origin != check.origin || traffic.Device != check.device || traffic.Bridge != "br_eno1" || (check.origin == "vm" && traffic.Guest != "guest-a") {
			t.Fatalf("port %d: %+v, want %+v", check.port, traffic, check)
		}
	}
}
