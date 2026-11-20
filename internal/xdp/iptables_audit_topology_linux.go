//go:build linux

package xdp

import (
	"encoding/binary"
	"encoding/xml"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nodewall/internal/models"
)

type auditLink struct {
	name, kind string
	master     int
}

type auditMACKey struct {
	bridge int
	mac    [6]byte
}

type auditGuestKey struct {
	device string
	mac    [6]byte
}

type auditBroadcastKey struct {
	device  int
	address string
}

type packetAuditTopology struct {
	expires    time.Time
	links      map[int]auditLink
	fdb        map[auditMACKey]int
	guests     map[auditGuestKey]string
	broadcasts map[auditBroadcastKey]bool
}

func (t *packetAuditTopology) attribute(sample packetAuditObservation) {
	if !sample.record.Timestamp.Before(t.expires) {
		t.expires = sample.record.Timestamp.Add(2 * time.Second)
		t.links = readAuditLinks()
		t.fdb, t.guests, t.broadcasts = nil, nil, nil
	}
	traffic := sample.record.Traffic
	if sample.record.Direction == models.DirectionEgress {
		traffic.Device = t.links[sample.output].name
		return
	}
	input := t.links[sample.input]
	if input.kind == "bridge" {
		traffic.Bridge = input.name
	}
	if sample.linkBroadcast && traffic.Delivery == "" {
		// Confirm directed broadcasts against the kernel's configured
		// address. An Ethernet broadcast can still carry unicast IPv4.
		if t.broadcasts == nil {
			t.broadcasts = readAuditBroadcasts()
		}
		if t.broadcasts[auditBroadcastKey{sample.input, traffic.LocalIP}] {
			traffic.Delivery = "broadcast"
		}
	}
	port := t.links[sample.port]
	if port.name != "" && port.kind != "bridge" {
		traffic.Basis = "ingress_device"
	} else if input.kind != "bridge" {
		port = input
		if port.name != "" {
			traffic.Basis = "ingress_device"
		}
	} else if sample.mac != ([6]byte{}) {
		if t.fdb == nil {
			t.fdb = readAuditFDB(t.links)
		}
		port = t.links[t.fdb[auditMACKey{sample.input, sample.mac}]]
		if port.name != "" {
			traffic.Basis = "bridge_fdb"
		}
	}
	traffic.Device = port.name
	switch port.kind {
	case "physical":
		traffic.Origin = "uplink"
	case "veth":
		// A veth proves a namespace link, which can also be a ZStack service.
		traffic.Origin = "veth"
	case "tap":
		traffic.Origin = "tap"
		if t.guests == nil {
			t.guests = readAuditGuests("/run/libvirt/qemu")
		}
		if guest := t.guests[auditGuestKey{port.name, sample.mac}]; guest != "" {
			traffic.Origin, traffic.Guest = "vm", guest
		}
	}
}

func readAuditBroadcasts() map[auditBroadcastKey]bool {
	broadcasts := make(map[auditBroadcastKey]bool)
	for _, msg := range auditRouteMessages(unix.RTM_GETADDR, unix.AF_INET) {
		if msg.Header.Type != unix.RTM_NEWADDR || len(msg.Data) < unix.SizeofIfAddrmsg || msg.Data[0] != unix.AF_INET {
			continue
		}
		device := int(binary.NativeEndian.Uint32(msg.Data[4:8]))
		walkAuditAttrs(msg.Data[unix.SizeofIfAddrmsg:], func(kind uint16, value []byte) {
			if kind == unix.IFA_BROADCAST && len(value) == 4 {
				address := netip.AddrFrom4([4]byte(value)).String()
				broadcasts[auditBroadcastKey{device, address}] = true
			}
		})
	}
	return broadcasts
}

func readAuditLinks() map[int]auditLink {
	links := make(map[int]auditLink)
	for _, msg := range auditRouteMessages(unix.RTM_GETLINK, unix.AF_UNSPEC) {
		if msg.Header.Type != unix.RTM_NEWLINK || len(msg.Data) < unix.SizeofIfInfomsg {
			continue
		}
		index := int(binary.NativeEndian.Uint32(msg.Data[4:8]))
		var link auditLink
		if !walkAuditAttrs(msg.Data[unix.SizeofIfInfomsg:], func(kind uint16, value []byte) {
			switch kind {
			case unix.IFLA_IFNAME:
				link.name = strings.TrimRight(string(value), "\x00")
			case unix.IFLA_MASTER:
				if len(value) == 4 {
					link.master = int(binary.NativeEndian.Uint32(value))
				}
			case unix.IFLA_LINKINFO:
				walkAuditAttrs(value, func(kind uint16, value []byte) {
					if kind == unix.IFLA_INFO_KIND {
						link.kind = strings.TrimRight(string(value), "\x00")
					}
				})
			}
		}) || link.name == "" {
			continue
		}
		if link.kind == "" && physicalFromSysfs("/sys/class/net", link.name) {
			link.kind = "physical"
		}
		if link.kind == "tun" || link.kind == "" {
			flags, _ := os.ReadFile(filepath.Join("/sys/class/net", link.name, "tun_flags"))
			value, _ := strconv.ParseUint(strings.TrimSpace(string(flags)), 0, 32)
			if value&unix.IFF_TAP != 0 {
				link.kind = "tap"
			}
		}
		links[index] = link
	}
	return links
}

func readAuditFDB(links map[int]auditLink) map[auditMACKey]int {
	fdb := make(map[auditMACKey]int)
	for _, msg := range auditRouteMessages(unix.RTM_GETNEIGH, unix.AF_BRIDGE) {
		if msg.Header.Type != unix.RTM_NEWNEIGH || len(msg.Data) < unix.SizeofNdMsg || msg.Data[0] != unix.AF_BRIDGE {
			continue
		}
		state := binary.NativeEndian.Uint16(msg.Data[8:10])
		if msg.Data[10]&unix.NTF_SELF != 0 || state&(unix.NUD_PERMANENT|unix.NUD_FAILED) != 0 {
			continue
		}
		port := int(binary.NativeEndian.Uint32(msg.Data[4:8]))
		bridge := links[port].master
		if links[bridge].kind != "bridge" {
			continue
		}
		var mac [6]byte
		if !walkAuditAttrs(msg.Data[unix.SizeofNdMsg:], func(kind uint16, value []byte) {
			if kind == unix.NDA_LLADDR && len(value) == len(mac) {
				copy(mac[:], value)
			}
		}) || mac == ([6]byte{}) {
			continue
		}
		key := auditMACKey{bridge, mac}
		if old, exists := fdb[key]; exists && old != port {
			fdb[key] = 0 // Conflicting VLAN/port learning is ambiguous.
		} else {
			fdb[key] = port
		}
	}
	return fdb
}

func auditRouteMessages(request, family int) []syscall.NetlinkMessage {
	data, err := syscall.NetlinkRIB(request, family)
	if err != nil {
		return nil
	}
	messages, _ := syscall.ParseNetlinkMessage(data)
	return messages
}

type auditDomain struct {
	Name       string `xml:"name"`
	Interfaces []struct {
		Target struct {
			Device string `xml:"dev,attr"`
		} `xml:"target"`
		MAC struct {
			Address string `xml:"address,attr"`
		} `xml:"mac"`
	} `xml:"devices>interface"`
}

func readAuditGuests(dir string) map[auditGuestKey]string {
	guests := make(map[auditGuestKey]string)
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".xml") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		// libvirt's live state is either a domain or a domstatus wrapper.
		decoder := xml.NewDecoder(io.LimitReader(f, 2<<20))
		for {
			token, err := decoder.Token()
			if err != nil {
				break
			}
			start, ok := token.(xml.StartElement)
			if !ok || start.Name.Local != "domain" {
				continue
			}
			var domain auditDomain
			if decoder.DecodeElement(&domain, &start) == nil {
				for _, iface := range domain.Interfaces {
					mac, err := net.ParseMAC(iface.MAC.Address)
					if err == nil && len(mac) == 6 && iface.Target.Device != "" {
						guests[auditGuestKey{iface.Target.Device, [6]byte(mac)}] = domain.Name
					}
				}
			}
			break
		}
		f.Close()
	}
	return guests
}
