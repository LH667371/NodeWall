//go:build linux

package xdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	tcHandleRoot       = 0xFFFFFFFF
	tcHandleClsact     = 0xFFFFFFF1
	tcHandleMinorMask  = 0x0000FFFF
	tcHandleMajorMask  = 0xFFFF0000
	tcHandleQdisc      = 0xFFFF0000
	tcHandleMinEgress  = 0xFFF3
	tcParentEgress     = (tcHandleQdisc & tcHandleMajorMask) | (tcHandleMinEgress & tcHandleMinorMask)
	tcFilterHandle     = 0x00000001
	tcFilterPriority   = 0x0001
	tcAttrKind         = 1
	tcAttrOptions      = 2
	tcBpfAttrFD        = 6
	tcBpfAttrName      = 7
	tcBpfAttrFlags     = 8
	tcBpfFlagActDirect = 1
)

type tcmsg struct {
	Family  uint8
	Pad1    uint8
	Pad2    uint16
	Ifindex int32
	Handle  uint32
	Parent  uint32
	Info    uint32
}

type tcNetlinkClient interface {
	AddClsactQdisc(ifaceIndex int) error
	ReplaceEgressBPF(ifaceIndex int, progFD int, progName string) error
	DeleteEgressBPF(ifaceIndex int) error
}

type tcNetlinkConn struct {
	fd  int
	seq uint32
}

type tcFilterLink struct {
	client     tcNetlinkClient
	ifaceIndex int
}

func attachTCEgressFallback(ifaceIndex int, prog *ebpf.Program) (tcCloser, error) {
	conn, err := openTCNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.AddClsactQdisc(ifaceIndex); err != nil {
		return nil, err
	}
	if err := conn.ReplaceEgressBPF(ifaceIndex, prog.FD(), "nodewall_egress"); err != nil {
		return nil, err
	}

	return &tcFilterLink{
		client:     &tcNetlinkOnce{ifaceIndex: ifaceIndex},
		ifaceIndex: ifaceIndex,
	}, nil
}

func (l *tcFilterLink) Close() error {
	if l == nil || l.client == nil {
		return nil
	}
	return l.client.DeleteEgressBPF(l.ifaceIndex)
}

type tcNetlinkOnce struct {
	ifaceIndex int
}

func (c *tcNetlinkOnce) AddClsactQdisc(ifaceIndex int) error {
	return errors.New("unsupported operation")
}

func (c *tcNetlinkOnce) ReplaceEgressBPF(ifaceIndex int, progFD int, progName string) error {
	return errors.New("unsupported operation")
}

func (c *tcNetlinkOnce) DeleteEgressBPF(ifaceIndex int) error {
	conn, err := openTCNetlink()
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.DeleteEgressBPF(ifaceIndex)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func openTCNetlink() (*tcNetlinkConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open netlink route socket: %w", err)
	}
	conn := &tcNetlinkConn{fd: fd, seq: 1}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind netlink route socket: %w", err)
	}
	return conn, nil
}

func (c *tcNetlinkConn) Close() error {
	if c == nil || c.fd == 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = 0
	return err
}

func (c *tcNetlinkConn) AddClsactQdisc(ifaceIndex int) error {
	msg := tcmsg{
		Family:  unix.AF_UNSPEC,
		Ifindex: int32(ifaceIndex),
		Handle:  tcHandleQdisc,
		Parent:  tcHandleClsact,
	}
	payload := append(marshalTCMsg(msg), marshalTCAttrs(
		marshalTCAttr(tcAttrKind, append([]byte("clsact"), 0)),
	)...)
	err := c.send(unix.RTM_NEWQDISC, unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, payload)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func (c *tcNetlinkConn) ReplaceEgressBPF(ifaceIndex int, progFD int, progName string) error {
	msg := tcmsg{
		Family:  unix.AF_UNSPEC,
		Ifindex: int32(ifaceIndex),
		Handle:  tcFilterHandle,
		Parent:  tcParentEgress,
		Info:    tcFilterInfo(tcFilterPriority, unix.ETH_P_ALL),
	}
	options := marshalTCAttrs(
		marshalTCAttr(tcBpfAttrFD, nativeUint32(uint32(progFD))),
		marshalTCAttr(tcBpfAttrName, append([]byte(progName), 0)),
		marshalTCAttr(tcBpfAttrFlags, nativeUint32(tcBpfFlagActDirect)),
	)
	payload := append(marshalTCMsg(msg), marshalTCAttrs(
		marshalTCAttr(tcAttrKind, append([]byte("bpf"), 0)),
		marshalTCAttr(tcAttrOptions, options),
	)...)
	return c.send(unix.RTM_NEWTFILTER, unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_REPLACE|unix.NLM_F_ACK, payload)
}

func (c *tcNetlinkConn) DeleteEgressBPF(ifaceIndex int) error {
	msg := tcmsg{
		Family:  unix.AF_UNSPEC,
		Ifindex: int32(ifaceIndex),
		Handle:  tcFilterHandle,
		Parent:  tcParentEgress,
		Info:    tcFilterInfo(tcFilterPriority, unix.ETH_P_ALL),
	}
	return c.send(unix.RTM_DELTFILTER, unix.NLM_F_REQUEST|unix.NLM_F_ACK, marshalTCMsg(msg))
}

func (c *tcNetlinkConn) send(msgType uint16, flags uint16, payload []byte) error {
	header := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRLEN + len(payload)),
		Type:  msgType,
		Flags: flags,
		Seq:   c.seq,
	}
	c.seq++

	req := make([]byte, unix.NLMSG_HDRLEN, header.Len)
	nativeEndian().PutUint32(req[0:4], header.Len)
	nativeEndian().PutUint16(req[4:6], header.Type)
	nativeEndian().PutUint16(req[6:8], header.Flags)
	nativeEndian().PutUint32(req[8:12], header.Seq)
	nativeEndian().PutUint32(req[12:16], header.Pid)
	req = append(req, payload...)

	if err := unix.Sendto(c.fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send tc netlink request: %w", err)
	}

	reply := make([]byte, os.Getpagesize())
	n, _, err := unix.Recvfrom(c.fd, reply, 0)
	if err != nil {
		return fmt.Errorf("read tc netlink reply: %w", err)
	}
	for offset := 0; offset+unix.SizeofNlMsghdr <= n; {
		header := parseNlMsghdr(reply[offset : offset+unix.SizeofNlMsghdr])
		if header.Len < unix.SizeofNlMsghdr || offset+int(header.Len) > n {
			return fmt.Errorf("parse tc netlink reply: malformed message")
		}
		data := reply[offset+unix.SizeofNlMsghdr : offset+int(header.Len)]
		switch header.Type {
		case unix.NLMSG_ERROR:
			if len(data) < 4 {
				return fmt.Errorf("tc netlink error reply too short")
			}
			code := int32(nativeEndian().Uint32(data[:4]))
			if code == 0 {
				return nil
			}
			return unix.Errno(-code)
		case unix.NLMSG_DONE:
			return nil
		}
		offset += nlMsgAlign(int(header.Len))
	}
	return nil
}

func marshalTCMsg(msg tcmsg) []byte {
	out := make([]byte, unsafe.Sizeof(msg))
	out[0] = msg.Family
	out[1] = msg.Pad1
	nativeEndian().PutUint16(out[2:4], msg.Pad2)
	nativeEndian().PutUint32(out[4:8], uint32(msg.Ifindex))
	nativeEndian().PutUint32(out[8:12], msg.Handle)
	nativeEndian().PutUint32(out[12:16], msg.Parent)
	nativeEndian().PutUint32(out[16:20], msg.Info)
	return out
}

func marshalTCAttrs(attrs ...[]byte) []byte {
	var out []byte
	for _, attr := range attrs {
		out = append(out, attr...)
	}
	return out
}

func marshalTCAttr(kind uint16, data []byte) []byte {
	length := unix.SizeofRtAttr + len(data)
	padded := nlAlign(length)
	out := make([]byte, padded)
	nativeEndian().PutUint16(out[0:2], uint16(length))
	nativeEndian().PutUint16(out[2:4], kind)
	copy(out[unix.SizeofRtAttr:], data)
	return out
}

func tcFilterInfo(priority uint16, protocol uint16) uint32 {
	return uint32(priority)<<16 | uint32(htons(protocol))
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return nativeEndian().Uint16(b[:])
}

func nativeUint32(v uint32) []byte {
	out := make([]byte, 4)
	nativeEndian().PutUint32(out, v)
	return out
}

func nlAlign(length int) int {
	return (length + unix.NLA_ALIGNTO - 1) & ^(unix.NLA_ALIGNTO - 1)
}

func nlMsgAlign(length int) int {
	return (length + unix.NLMSG_ALIGNTO - 1) & ^(unix.NLMSG_ALIGNTO - 1)
}

func parseNlMsghdr(data []byte) unix.NlMsghdr {
	return unix.NlMsghdr{
		Len:   nativeEndian().Uint32(data[0:4]),
		Type:  nativeEndian().Uint16(data[4:6]),
		Flags: nativeEndian().Uint16(data[6:8]),
		Seq:   nativeEndian().Uint32(data[8:12]),
		Pid:   nativeEndian().Uint32(data[12:16]),
	}
}

func nativeEndian() binary.ByteOrder {
	return binary.NativeEndian
}
