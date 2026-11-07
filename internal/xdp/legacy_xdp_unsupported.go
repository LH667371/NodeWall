//go:build !linux

package xdp

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func attachLegacyXDP(*ebpf.Program, int, link.XDPAttachFlags) (xdpAttachment, error) {
	return nil, errors.New("legacy XDP attach is only available on Linux")
}
