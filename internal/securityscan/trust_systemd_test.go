package securityscan

import "testing"

func TestIsSystemdUpdatePath(t *testing.T) {
	for _, path := range []string{
		"/usr/lib/systemd/systemd-journald (deleted)",
		"/usr/lib/systemd/systemd-journald;6af13621 (deleted)",
		"/lib/systemd/systemd (deleted)",
		"/usr/lib/systemd/systemd-resolved",
	} {
		if !IsSystemdUpdatePath(path) {
			t.Errorf("IsSystemdUpdatePath(%q) = false", path)
		}
	}
	for _, path := range []string{
		"/usr/lib/systemd-networkd",
		"/opt/systemd/systemd-malware",
		"/usr/lib/systemd/cron",
		"/usr/bin/systemd-helper",
	} {
		if IsSystemdUpdatePath(path) {
			t.Errorf("IsSystemdUpdatePath(%q) = true", path)
		}
	}
}

func TestOperatorManagedStartupPathPolicy(t *testing.T) {
	for _, path := range []string{
		"/etc/systemd/system/suspicious.service",
		"/etc/cron.d/system-update",
		"/var/spool/cron/crontabs/root",
		"/etc/rc.local",
	} {
		if !IsOperatorManagedStartupPath(path) {
			t.Errorf("startup path was not recognized: %s", path)
		}
	}
	for _, path := range []string{
		"/lib/systemd/system/atd.service",
		"/usr/sbin/mysqld",
		"/usr/lib/systemd/systemd-journald",
	} {
		if IsOperatorManagedStartupPath(path) {
			t.Errorf("vendor/system path was treated as operator-managed startup: %s", path)
		}
	}
}

func TestTransientSystemdUnitPathPolicy(t *testing.T) {
	for _, path := range []string{
		"/run/systemd/transient/5ddf18af1006a658.service",
		"/run/systemd/transient/31b06da81846f30e.service",
	} {
		if !IsTransientSystemdUnitPath(path) {
			t.Errorf("transient random unit was not recognized: %s", path)
		}
	}
	for _, path := range []string{
		"/run/systemd/transient/docker.service",
		"/etc/systemd/system/5ddf18af.service",
		"/run/systemd/system/5ddf18af.service",
	} {
		if IsTransientSystemdUnitPath(path) {
			t.Errorf("ordinary unit was treated as transient random unit: %s", path)
		}
	}
}
