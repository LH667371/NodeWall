//go:build !linux

package xdp

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func attachTCEgressFallback(ifaceIndex int, prog *ebpf.Program) (tcCloser, error) {
	return nil, link.ErrNotSupported
}
