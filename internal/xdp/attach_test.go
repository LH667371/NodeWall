package xdp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/link"
)

func TestAttachModeAvoidsI40EQueueReset(t *testing.T) {
	for _, test := range []struct {
		name, driver        string
		requested, expected AttachMode
	}{
		{"i40e native", "i40e", AttachModeNative, AttachModeGeneric},
		{"i40e generic", "i40e", AttachModeGeneric, AttachModeGeneric},
		{"other driver", "mlx5_core", AttachModeNative, AttachModeNative},
		{"ixgbe native", "ixgbe", AttachModeNative, AttachModeNative},
		{"igb native", "igb", AttachModeNative, AttachModeNative},
		{"virtio capability negotiated at attach", "virtio_net", AttachModeNative, AttachModeNative},
		{"vmxnet3 capability negotiated at attach", "vmxnet3", AttachModeNative, AttachModeNative},
		{"missing driver", "", AttachModeNative, AttachModeNative},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.driver != "" {
				device := filepath.Join(root, "eno3", "device")
				if err := os.MkdirAll(device, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join("/sys/bus/pci/drivers", test.driver), filepath.Join(device, "driver")); err != nil {
					t.Fatal(err)
				}
			}
			if got := attachModeForInterface(root, "eno3", test.requested); got != test.expected {
				t.Fatalf("got %s, want %s", got, test.expected)
			}
		})
	}
}

type testXDPAttachment struct{}

func (*testXDPAttachment) Close() error { return nil }

func TestXDPAttachCompatibilityMatrix(t *testing.T) {
	type step struct {
		api   string
		flags link.XDPAttachFlags
		err   error
	}
	native, generic := link.XDPDriverMode, link.XDPGenericMode
	for _, test := range []struct {
		name              string
		requested, actual AttachMode
		steps             []step
		failure           error
	}{
		{"modern native", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, nil}}, nil},
		{"old kernel native via netlink", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, link.ErrNotSupported}, {"netlink", native, nil}}, nil},
		{"missing syscall uses netlink", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, syscall.ENOSYS}, {"netlink", native, nil}}, nil},
		{"driver lacks native", AttachModeNative, AttachModeGeneric, []step{{"bpf_link", native, syscall.EOPNOTSUPP}, {"netlink", native, syscall.EOPNOTSUPP}, {"bpf_link", generic, nil}}, nil},
		{"old kernel and generic-only driver", AttachModeNative, AttachModeGeneric, []step{{"bpf_link", native, link.ErrNotSupported}, {"netlink", native, syscall.EINVAL}, {"bpf_link", generic, link.ErrNotSupported}, {"netlink", generic, nil}}, nil},
		{"requested generic", AttachModeGeneric, AttachModeGeneric, []step{{"bpf_link", generic, nil}}, nil},
		{"old kernel requested generic", AttachModeGeneric, AttachModeGeneric, []step{{"bpf_link", generic, link.ErrNotSupported}, {"netlink", generic, nil}}, nil},
		{"permission denied", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, syscall.EPERM}}, syscall.EPERM},
		{"netlink permission denied stops generic retry", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, link.ErrNotSupported}, {"netlink", native, syscall.EACCES}}, syscall.EACCES},
		{"existing program is not replaced", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, syscall.EBUSY}}, syscall.EBUSY},
		{"netlink ownership conflict", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, link.ErrNotSupported}, {"netlink", native, syscall.EBUSY}}, syscall.EBUSY},
		{"device disappeared", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, syscall.ENODEV}}, syscall.ENODEV},
		{"resource exhaustion", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, syscall.ENOMEM}}, syscall.ENOMEM},
		{"canceled operation", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, context.Canceled}}, context.Canceled},
		{"no XDP API available", AttachModeNative, AttachModeNative, []step{{"bpf_link", native, link.ErrNotSupported}, {"netlink", native, syscall.EOPNOTSUPP}, {"bpf_link", generic, link.ErrNotSupported}, {"netlink", generic, syscall.EOPNOTSUPP}}, syscall.EOPNOTSUPP},
		{"generic does not escalate to native", AttachModeGeneric, AttachModeGeneric, []step{{"bpf_link", generic, link.ErrNotSupported}, {"netlink", generic, syscall.EOPNOTSUPP}}, syscall.EOPNOTSUPP},
		{"iptables is not an XDP attach mode", AttachModeIPTables, AttachModeIPTables, nil, errors.New("invalid mode")},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			success := &testXDPAttachment{}
			attach := func(api string) xdpAttachFunc {
				return func(flags link.XDPAttachFlags) (xdpAttachment, error) {
					if calls >= len(test.steps) {
						t.Fatalf("unexpected extra %s attempt with flags %d", api, flags)
					}
					step := test.steps[calls]
					calls++
					if api != step.api || flags != step.flags {
						t.Fatalf("attempt %d: %s/%d, want %s/%d", calls, api, flags, step.api, step.flags)
					}
					if step.err != nil {
						return nil, step.err
					}
					return success, nil
				}
			}
			lnk, actual, err := attachXDPWithFallback(test.requested, attach("bpf_link"), attach("netlink"))
			if calls != len(test.steps) || actual != test.actual {
				t.Fatalf("calls=%d mode=%s; want %d/%s", calls, actual, len(test.steps), test.actual)
			}
			if test.failure == nil {
				if err != nil || lnk != success {
					t.Fatalf("attach failed: link=%v error=%v", lnk, err)
				}
			} else if err == nil || lnk != nil {
				t.Fatalf("failure was accepted: link=%v error=%v", lnk, err)
			} else if len(test.steps) > 0 && !errors.Is(err, test.failure) {
				t.Fatalf("lost original failure: %v", err)
			}
		})
	}
}
