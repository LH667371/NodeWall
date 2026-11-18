package xdp

import (
	"log"
	"os"
	"path/filepath"
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
	driver, err := os.Readlink(filepath.Join(sysfsRoot, iface, "device", "driver"))
	if err != nil || requested != AttachModeNative || filepath.Base(driver) != "i40e" {
		return requested
	}
	// Native i40e attach/detach rebuilds hardware queues. On deployed 2.8.20-k
	// drivers rollback produced XDP Tx ring disable timeouts and lost management
	// traffic for seconds. Generic XDP keeps the same BPF policy without that NIC
	// reset. Apply this before the first attach, never by replacing a live link.
	log.Printf("interface %s uses i40e; selecting generic XDP to preserve connectivity during attach and rollback", iface)
	return AttachModeGeneric
}
