package api

// quarantinedStartupLink records an enablement link removed with a suspicious
// systemd unit. Restoring the file can restore the link as well, without
// silently starting the service during recovery.
type quarantinedStartupLink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}
