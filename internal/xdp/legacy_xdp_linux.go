//go:build linux

package xdp

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Linux 5.4 supports XDP through RTM_SETLINK, but not through bpf_link. The
// cilium/ebpf link package intentionally uses bpf_link, so NodeWall needs this
// small compatibility path for the Ubuntu 20.04 kernels it supports.
const (
	rtmSetlink         = 19
	iflaXDP            = 43
	iflaXDPFD          = 1
	iflaXDPFlags       = 3
	nlaFNested         = 1 << 15
	xdpFlagsUpdateIfNo = 1 << 0
	xdpFlagsSKBMode    = 1 << 1
	xdpFlagsDriverMode = 1 << 2
	xdpFlagsHardware   = 1 << 3
)

type legacyXDPLink struct {
	ifaceIndex int
	flags      uint32
	mu         sync.Mutex
	closed     bool
}

func attachLegacyXDP(program *ebpf.Program, ifaceIndex int, mode link.XDPAttachFlags) (xdpAttachment, error) {
	if program == nil {
		return nil, errors.New("legacy xdp attach requires a program")
	}
	flags, err := legacyXDPFlags(mode)
	if err != nil {
		return nil, err
	}
	flags |= xdpFlagsUpdateIfNo
	if err := setLegacyXDP(ifaceIndex, program.FD(), flags); err != nil {
		return nil, err
	}
	return &legacyXDPLink{ifaceIndex: ifaceIndex, flags: flags &^ xdpFlagsUpdateIfNo}, nil
}

func legacyXDPFlags(mode link.XDPAttachFlags) (uint32, error) {
	switch mode {
	case link.XDPGenericMode:
		return xdpFlagsSKBMode, nil
	case link.XDPDriverMode:
		return xdpFlagsDriverMode, nil
	case link.XDPOffloadMode:
		return xdpFlagsHardware, nil
	default:
		return 0, fmt.Errorf("unsupported legacy XDP attach mode %#x", mode)
	}
}

func (l *legacyXDPLink) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	// A file descriptor of -1 asks the kernel to detach the XDP program.
	err := setLegacyXDP(l.ifaceIndex, -1, l.flags)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		err = nil
	}
	if err == nil {
		l.closed = true
	}
	return err
}

func setLegacyXDP(ifaceIndex, programFD int, flags uint32) error {
	if ifaceIndex < 1 {
		return fmt.Errorf("invalid interface index: %d", ifaceIndex)
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open XDP netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind XDP netlink socket: %w", err)
	}

	msg := ifinfomsg{Family: unix.AF_UNSPEC, Index: int32(ifaceIndex)}
	data := marshalIfInfo(msg)
	xdpAttrs := marshalLegacyAttrs(
		marshalLegacyAttr(iflaXDPFD, nativeInt32(int32(programFD))),
		marshalLegacyAttr(iflaXDPFlags, nativeUint32(flags)),
	)
	data = append(data, marshalLegacyAttr(iflaXDP|nlaFNested, xdpAttrs)...)

	seq := uint32(os.Getpid())
	header := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRLEN + len(data)),
		Type:  rtmSetlink,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
	}
	request := make([]byte, unix.NLMSG_HDRLEN, header.Len)
	nativeEndian().PutUint32(request[0:4], header.Len)
	nativeEndian().PutUint16(request[4:6], header.Type)
	nativeEndian().PutUint16(request[6:8], header.Flags)
	nativeEndian().PutUint32(request[8:12], header.Seq)
	request = append(request, data...)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send XDP netlink request: %w", err)
	}

	reply := make([]byte, os.Getpagesize())
	n, _, err := unix.Recvfrom(fd, reply, 0)
	if err != nil {
		return fmt.Errorf("read XDP netlink reply: %w", err)
	}
	for offset := 0; offset+unix.SizeofNlMsghdr <= n; {
		h := parseNlMsghdr(reply[offset : offset+unix.SizeofNlMsghdr])
		if h.Len < unix.SizeofNlMsghdr || offset+int(h.Len) > n {
			return errors.New("malformed XDP netlink reply")
		}
		payload := reply[offset+unix.SizeofNlMsghdr : offset+int(h.Len)]
		if h.Type == unix.NLMSG_ERROR {
			if len(payload) < 4 {
				return errors.New("short XDP netlink error reply")
			}
			code := int32(nativeEndian().Uint32(payload[:4]))
			if code == 0 {
				return nil
			}
			return unix.Errno(-code)
		}
		if h.Type == unix.NLMSG_DONE {
			return nil
		}
		offset += nlMsgAlign(int(h.Len))
	}
	return nil
}

type ifinfomsg struct {
	Family uint8
	Pad    uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
}

func marshalIfInfo(msg ifinfomsg) []byte {
	out := make([]byte, 16)
	out[0] = msg.Family
	out[1] = msg.Pad
	nativeEndian().PutUint16(out[2:4], msg.Type)
	nativeEndian().PutUint32(out[4:8], uint32(msg.Index))
	nativeEndian().PutUint32(out[8:12], msg.Flags)
	nativeEndian().PutUint32(out[12:16], msg.Change)
	return out
}

func marshalLegacyAttrs(attrs ...[]byte) []byte {
	var out []byte
	for _, attr := range attrs {
		out = append(out, attr...)
	}
	return out
}

func marshalLegacyAttr(kind uint16, data []byte) []byte {
	length := unix.SizeofRtAttr + len(data)
	out := make([]byte, nlAlign(length))
	nativeEndian().PutUint16(out[0:2], uint16(length))
	nativeEndian().PutUint16(out[2:4], kind)
	copy(out[unix.SizeofRtAttr:], data)
	return out
}

func nativeInt32(value int32) []byte {
	out := make([]byte, 4)
	nativeEndian().PutUint32(out, uint32(value))
	return out
}
