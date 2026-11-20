package xdp

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func ParseAttachMode(value string) AttachMode {
	if value == string(AttachModeIPTables) {
		return AttachModeIPTables
	}
	if value == string(AttachModeGeneric) {
		return AttachModeGeneric
	}

	return AttachModeNative
}

func attachModeForInterface(sysfsRoot, iface string, requested AttachMode) AttachMode {
	if requested != AttachModeNative {
		return requested
	}
	device := filepath.Join(sysfsRoot, iface, "device")
	driver, err := os.Readlink(filepath.Join(device, "driver"))
	if err != nil {
		return requested
	}
	switch filepath.Base(driver) {
	case "i40e":
		// Native i40e attach/detach rebuilds hardware queues. On deployed 2.8.20-k
		// drivers rollback produced XDP Tx ring disable timeouts and lost management
		// traffic for seconds. Apply this before the first attach to avoid that reset.
		log.Printf("interface %s uses i40e; selecting generic XDP to preserve connectivity during attach and rollback", iface)
		return AttachModeGeneric
	case "virtio_net":
		// A virtio backend can deliver partially checksummed packets from a
		// peer guest even when native attach succeeds. Generic XDP runs after
		// the driver has converted the virtio checksum metadata into an skb.
		guestChecksum, err := virtioGuestChecksum(device)
		if err != nil {
			log.Printf("interface %s: cannot read virtio receive checksum capability; selecting generic XDP: %v", iface, err)
			return AttachModeGeneric
		}
		if guestChecksum {
			log.Printf("interface %s uses virtio receive checksum offload; selecting generic XDP to preserve guest connectivity", iface)
			return AttachModeGeneric
		}
	}
	return requested
}

func virtioGuestChecksum(device string) (bool, error) {
	// Linux exports the negotiated features with bit zero first. Bit 1
	// (VIRTIO_NET_F_GUEST_CSUM) describes receive, independent of bit 0 (TX).
	const guestChecksumBit = 1
	data, err := os.ReadFile(filepath.Join(device, "features"))
	if err != nil {
		return false, err
	}
	features := strings.TrimSpace(string(data))
	if len(features) <= guestChecksumBit || strings.Trim(features, "01") != "" {
		return false, errors.New("invalid virtio feature bitmap")
	}
	return features[guestChecksumBit] == '1', nil
}
