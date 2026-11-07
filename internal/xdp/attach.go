package xdp

func ParseAttachMode(value string) AttachMode {
	if value == string(AttachModeIPTables) {
		return AttachModeIPTables
	}
	if value == string(AttachModeGeneric) {
		return AttachModeGeneric
	}

	return AttachModeNative
}
