package xdp

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestBridgeScopeTopology(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"port0", "bond0", "br0"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	lookup := func(name string) (*net.Interface, error) {
		mac, _ := net.ParseMAC("02:00:00:00:00:01")
		return &net.Interface{Name: name, Index: 7, HardwareAddr: mac}, nil
	}
	value, err := discoverBridgeScopeAt(root, "port0", 3, lookup)
	if err != nil || value.BridgeIndex != 0 {
		t.Fatalf("standalone: %+v %v", value, err)
	}
	if err := os.Symlink("../bond0", filepath.Join(root, "port0", "master")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../br0", filepath.Join(root, "bond0", "master")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "br0", "bridge"), 0o755); err != nil {
		t.Fatal(err)
	}
	value, err = discoverBridgeScopeAt(root, "port0", 3, lookup)
	if err != nil || value.BridgeIndex != 7 || value.IngressIndex != 3 || value.BridgeMAC != value.InterfaceMAC {
		t.Fatalf("bond/bridge scope: %+v %v", value, err)
	}
	if got := binary.Size(value); got != 20 {
		t.Fatalf("BPF bridge scope size=%d", got)
	}
}

type retryBridgeCloser struct {
	calls int
	fail  bool
}

func (c *retryBridgeCloser) Close() error {
	c.calls++
	if c.fail {
		c.fail = false
		return errors.New("transient close error")
	}
	return nil
}

func TestDetachReleasesIndependentLinksAndRetriesBridgeFailure(t *testing.T) {
	xdpLink, egress, bridge := &retryBridgeCloser{}, &retryBridgeCloser{}, &retryBridgeCloser{fail: true}
	state := &interfaceState{ifaceName: "test0", link: xdpLink, tcLink: egress, bridgeLink: bridge, programLoaded: true}
	manager := NewManager("")
	manager.states["test0"] = state
	if manager.Detach("test0") == nil {
		t.Fatal("expected bridge close failure")
	}
	if state.link != nil || state.tcLink != nil || state.bridgeLink == nil || state.programLoaded {
		t.Fatalf("successful closes must be committed while failed bridge remains retryable: %+v", state)
	}
	if err := manager.Detach("test0"); err != nil {
		t.Fatal(err)
	}
	if xdpLink.calls != 1 || egress.calls != 1 || bridge.calls != 2 || state.bridgeLink != nil {
		t.Fatal("detach retried already-closed links or lost the remaining bridge link")
	}
}
