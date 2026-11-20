//go:build linux

package xdp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nodewall/internal/models"
)

// Linux uapi: netfilter/nfnetlink.h and netfilter/nfnetlink_log.h.
const (
	nflogPacket   = 4 << 8
	nflogConfig   = nflogPacket | 1
	nflogHeader   = 1
	nflogInDev    = 4
	nflogOutDev   = 5
	nflogPhysIn   = 6
	nflogHWAddr   = 8
	nflogData     = 9
	nflogPrefix   = 10
	nflogHWType   = 15
	nflogHWHeader = 16
)

type packetAuditObservation struct {
	record        models.DropLogRecord
	input         int
	output        int
	port          int
	mac           [6]byte
	linkBroadcast bool
}

// StartPacketAudit binds only NodeWall's group. In particular it does not
// bind/unbind a protocol-family logger or change ZStack's NFLOG group.
func (m *IPTablesManager) StartPacketAudit(ctx context.Context, record func(models.DropLogRecord)) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	if err := configureAuditSocket(fd); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("bind NFLOG group %d: %w", firewallAuditGroup, err)
	}
	m.applyMu.Lock()
	m.packetAudit = true
	m.applyMu.Unlock()
	go func() {
		defer unix.Close(fd)
		topology := packetAuditTopology{}
		for ctx.Err() == nil {
			var data [16384]byte
			n, err := readAuditSocket(fd, data[:])
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) {
				continue
			}
			if err != nil {
				log.Printf("warning: read firewall packet audit: %v", err)
				return
			}
			messages, err := syscall.ParseNetlinkMessage(data[:n])
			if err != nil {
				continue
			}
			for _, msg := range messages {
				if msg.Header.Type != nflogPacket {
					continue
				}
				if sample, ok := decodeAuditPacket(msg.Data, time.Now().UTC()); ok {
					topology.attribute(sample)
					record(sample.record)
				}
			}
		}
	}()
	return nil
}

func configureAuditSocket(fd int) error {
	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, addr); err != nil {
		return err
	}
	timeout := unix.NsecToTimeval((500 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return err
	}
	// Copy up to an IPv4 header with options and the two transport ports.
	mode := []byte{0, 0, 0, 64, 2, 0}
	data := []byte{unix.AF_INET, 0, 0, 0}
	binary.BigEndian.PutUint16(data[2:4], firewallAuditGroup)
	data = append(data, marshalLegacyAttr(1, []byte{1})...) // NFULA_CFG_CMD: bind group
	data = append(data, marshalLegacyAttr(2, mode)...)      // NFULA_CFG_MODE: copy packet prefix
	request := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)+len(data)))
	binary.NativeEndian.PutUint16(request[4:6], nflogConfig)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	if err := unix.Sendto(fd, append(request, data...), 0, addr); err != nil {
		return err
	}
	var reply [16384]byte
	for {
		n, err := readAuditSocket(fd, reply[:])
		if err != nil {
			return err
		}
		messages, err := syscall.ParseNetlinkMessage(reply[:n])
		if err != nil {
			return err
		}
		for _, msg := range messages {
			if msg.Header.Type != unix.NLMSG_ERROR || msg.Header.Seq != 1 || len(msg.Data) < 4 {
				continue
			}
			code := int32(binary.NativeEndian.Uint32(msg.Data[:4]))
			if code == 0 {
				return nil
			}
			return unix.Errno(-code)
		}
	}
}

func readAuditSocket(fd int, data []byte) (int, error) {
	n, sender, err := unix.Recvfrom(fd, data, 0)
	if err != nil {
		return 0, err
	}
	if peer, ok := sender.(*unix.SockaddrNetlink); !ok || peer.Pid != 0 {
		return 0, nil
	}
	return n, nil
}

func decodeAuditPacket(data []byte, at time.Time) (packetAuditObservation, bool) {
	var sample packetAuditObservation
	if len(data) < 4 || data[0] != unix.AF_INET || binary.BigEndian.Uint16(data[2:4]) != firewallAuditGroup {
		return sample, false
	}
	var packet []byte
	var prefix string
	var hook byte
	var hwType uint16
	var broadcastMAC bool
	if !walkAuditAttrs(data[4:], func(kind uint16, value []byte) {
		switch kind {
		case nflogHeader:
			if len(value) >= 3 {
				hook = value[2]
			}
		case nflogInDev, nflogOutDev, nflogPhysIn:
			if len(value) != 4 {
				return
			}
			index := int(binary.BigEndian.Uint32(value))
			switch kind {
			case nflogInDev:
				sample.input = index
			case nflogOutDev:
				sample.output = index
			case nflogPhysIn:
				sample.port = index
			}
		case nflogHWAddr:
			if len(value) >= 10 && binary.BigEndian.Uint16(value[:2]) == 6 {
				copy(sample.mac[:], value[4:10])
			}
		case nflogData:
			packet = value
		case nflogPrefix:
			prefix = strings.TrimRight(string(value), "\x00")
		case nflogHWType:
			if len(value) == 2 {
				hwType = binary.BigEndian.Uint16(value)
			}
		case nflogHWHeader:
			broadcastMAC = len(value) >= 14 && [6]byte(value[:6]) == [6]byte{255, 255, 255, 255, 255, 255}
		}
	}) {
		return sample, false
	}
	parts := strings.Split(prefix, ":")
	if len(parts) != 4 || parts[0] != "nodewall" || (parts[3] != "drop" && parts[3] != "observe") {
		return sample, false
	}
	iface, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(iface) == 0 || len(iface) >= unix.IFNAMSIZ || strings.ContainsAny(string(iface), "/\x00") {
		return sample, false
	}
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return sample, false
	}
	headerLen := int(packet[0]&15) * 4
	if headerLen < 20 || len(packet) < headerLen || int(binary.BigEndian.Uint16(packet[2:4])) < headerLen {
		return sample, false
	}
	peerIP := netip.AddrFrom4([4]byte(packet[12:16])).String()
	localIP := netip.AddrFrom4([4]byte(packet[16:20])).String()
	direction := models.PolicyDirection(parts[2])
	traffic := &models.FirewallTraffic{Evidence: models.FirewallPacketSample, LocalIP: localIP}
	if packet[16] >= 224 && packet[16] < 240 {
		traffic.Delivery = "multicast"
	} else if localIP == "255.255.255.255" {
		traffic.Delivery = "broadcast"
	}
	switch {
	case direction == models.DirectionIngress && hook == 1: // NF_INET_LOCAL_IN
		traffic.Hook = "input"
		sample.linkBroadcast = hwType == unix.ARPHRD_ETHER && broadcastMAC
	case direction == models.DirectionEgress && hook == 3: // NF_INET_LOCAL_OUT
		peerIP, traffic.LocalIP = localIP, peerIP
		traffic.Hook, traffic.Origin = "output", "host"
	default:
		return sample, false
	}
	var port uint16
	switch packet[9] {
	case 6:
		traffic.Protocol = "tcp"
	case 17:
		traffic.Protocol = "udp"
	case 1:
		traffic.Protocol = "icmp"
	default:
		traffic.Protocol = strconv.Itoa(int(packet[9]))
	}
	if (packet[9] == 6 || packet[9] == 17) && len(packet) >= headerLen+4 && int(binary.BigEndian.Uint16(packet[2:4])) >= headerLen+4 && binary.BigEndian.Uint16(packet[6:8])&0x1fff == 0 {
		port = binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
	}
	sample.record = models.DropLogRecord{
		Timestamp: at, Interface: string(iface), Direction: direction, SourceIP: peerIP,
		Port: port, Reason: "nodewall:default_deny", Count: 1, Traffic: traffic,
	}
	if parts[3] == "drop" {
		sample.record.Drops = 1
	}
	return sample, true
}

func walkAuditAttrs(data []byte, visit func(uint16, []byte)) bool {
	for len(data) >= 4 {
		size := int(binary.NativeEndian.Uint16(data[:2]))
		aligned := (size + 3) &^ 3
		if size < 4 || aligned > len(data) {
			return false
		}
		visit(binary.NativeEndian.Uint16(data[2:4])&0x3fff, data[4:size])
		data = data[aligned:]
	}
	return len(data) == 0
}
