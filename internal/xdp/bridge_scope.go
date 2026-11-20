package xdp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// bridgeScopeValue mirrors bridge_scope_value. It is runtime topology, not
// operator policy: a guest must not require an entry in the host allowlist.
type bridgeScopeValue struct {
	IngressIndex uint32
	BridgeIndex  uint32
	InterfaceMAC [6]byte
	BridgeMAC    [6]byte
}

func discoverBridgeScope(name string, index int) (bridgeScopeValue, error) {
	return discoverBridgeScopeAt("/sys/class/net", name, index, lookupInterface)
}

func discoverBridgeScopeAt(root, name string, index int, lookup func(string) (*net.Interface, error)) (bridgeScopeValue, error) {
	original := name
	seen := make(map[string]bool)
	for depth := 0; depth < 16; depth++ {
		master, err := os.Readlink(filepath.Join(root, name, "master"))
		if errors.Is(err, os.ErrNotExist) {
			return bridgeScopeValue{}, nil
		}
		if err != nil {
			return bridgeScopeValue{}, fmt.Errorf("read master of %s: %w", name, err)
		}
		name = filepath.Base(master)
		if seen[name] {
			return bridgeScopeValue{}, fmt.Errorf("cyclic interface masters at %s", name)
		}
		seen[name] = true
		if _, err := os.Stat(filepath.Join(root, name, "bridge")); errors.Is(err, os.ErrNotExist) {
			continue // Physical ports may reach the bridge through a bond.
		} else if err != nil {
			return bridgeScopeValue{}, err
		}
		port, err := lookup(original)
		if err != nil {
			return bridgeScopeValue{}, err
		}
		bridge, err := lookup(name)
		if err != nil {
			return bridgeScopeValue{}, err
		}
		if len(port.HardwareAddr) != 6 || len(bridge.HardwareAddr) != 6 {
			return bridgeScopeValue{}, fmt.Errorf("bridge host filtering requires Ethernet MACs on %s and %s", original, name)
		}
		value := bridgeScopeValue{IngressIndex: uint32(index), BridgeIndex: uint32(bridge.Index)}
		copy(value.InterfaceMAC[:], port.HardwareAddr)
		copy(value.BridgeMAC[:], bridge.HardwareAddr)
		return value, nil
	}
	return bridgeScopeValue{}, fmt.Errorf("too many interface masters above %s", original)
}
