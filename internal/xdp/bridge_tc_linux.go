//go:build linux

package xdp

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	tcParentIngress   = uint32(0xfffffff2)
	tcHostPriority    = uint16(49150)
	tcHostProgramName = "nodewall_host"
)

type bridgeTCLink struct {
	bridgeIndex int
	portIndex   int
}

func attachTCBridgeHostFilter(bridgeIndex, portIndex int, program *ebpf.Program) (tcCloser, error) {
	lnk, err := link.AttachTCX(link.TCXOptions{Program: program, Interface: bridgeIndex, Attach: ebpf.AttachTCXIngress})
	if err == nil {
		return lnk, nil
	}
	if !shouldIgnoreTCXAttachError(err) {
		return nil, err
	}
	conn, err := openTCNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.AddClsactQdisc(bridgeIndex); err != nil {
		return nil, err
	}
	msg := bridgeHostTCMsg(bridgeIndex, portIndex)
	options := marshalTCAttrs(
		marshalTCAttr(tcBpfAttrFD, nativeUint32(uint32(program.FD()))),
		marshalTCAttr(tcBpfAttrName, append([]byte(tcHostProgramName), 0)),
		marshalTCAttr(tcBpfAttrFlags, nativeUint32(tcBpfFlagActDirect)),
	)
	payload := append(marshalTCMsg(msg), marshalTCAttrs(
		marshalTCAttr(tcAttrKind, append([]byte("bpf"), 0)),
		marshalTCAttr(tcAttrOptions, options),
	)...)
	// EXCL refuses to overwrite another owner's filter. Each physical port
	// gets its own handle, so two uplinks can share a bridge without replacing
	// one another's policy or a platform filter.
	if err := conn.send(unix.RTM_NEWTFILTER, unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, payload); err != nil {
		return nil, fmt.Errorf("add host filter on bridge index %d: %w", bridgeIndex, err)
	}
	return &bridgeTCLink{bridgeIndex: bridgeIndex, portIndex: portIndex}, nil
}

func bridgeHostTCMsg(bridgeIndex, portIndex int) tcmsg {
	return tcmsg{
		Family: unix.AF_UNSPEC, Ifindex: int32(bridgeIndex),
		Handle: uint32(portIndex), Parent: tcParentIngress,
		Info: tcFilterInfo(tcHostPriority, unix.ETH_P_ALL),
	}
}

func (lnk *bridgeTCLink) Close() error {
	conn, err := openTCNetlink()
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.send(unix.RTM_DELTFILTER, unix.NLM_F_REQUEST|unix.NLM_F_ACK, marshalTCMsg(bridgeHostTCMsg(lnk.bridgeIndex, lnk.portIndex)))
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		return nil
	}
	return err
}
