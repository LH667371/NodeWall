package xdp

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func TestShouldIgnoreTCXAttachError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "link not supported",
			err:  fmt.Errorf("attach failed: %w", link.ErrNotSupported),
			want: true,
		},
		{
			name: "ebpf not supported",
			err:  fmt.Errorf("attach failed: %w", ebpf.ErrNotSupported),
			want: true,
		},
		{
			name: "kernel syscall unavailable",
			err:  fmt.Errorf("attach failed: %w", syscall.ENOSYS),
			want: true,
		},
		{
			name: "hook unavailable",
			err:  fmt.Errorf("attach failed: %w", syscall.EOPNOTSUPP),
			want: true,
		},
		{
			name: "permission denied",
			err:  syscall.EPERM,
		},
		{
			name: "existing hook conflict",
			err:  syscall.EBUSY,
		},
		{
			name: "invalid TCX configuration",
			err:  syscall.EINVAL,
		},
		{
			name: "other error",
			err:  errors.New("permission denied"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldIgnoreTCXAttachError(tt.err); got != tt.want {
				t.Fatalf("shouldIgnoreTCXAttachError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestShouldFallbackToGenericXDP(t *testing.T) {
	if !shouldFallbackToGenericXDP(fmt.Errorf("native attach: %w", syscall.EOPNOTSUPP)) {
		t.Fatal("expected operation-not-supported to trigger generic fallback")
	}
	if !shouldFallbackToGenericXDP(fmt.Errorf("native attach: %w", syscall.EINVAL)) {
		t.Fatal("expected invalid-argument native attach failure to trigger generic fallback")
	}
	if shouldFallbackToGenericXDP(errors.New("permission denied")) {
		t.Fatal("permission errors must not be hidden by a generic fallback")
	}
}
