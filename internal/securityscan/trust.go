package securityscan

import (
	"os"
	"path/filepath"
	"strings"
)

// NodeWall owns these paths. Scanning the agent's binary, generated BPF
// object, TLS material, or reports would produce false positives because the
// binary itself contains the scanner's indicator strings.
var nodeWallTrustedRoots = []string{
	"/opt/nodewall",
	"/etc/nodewall",
	"/var/lib/nodewall",
}

func isNodeWallTrustedPath(path string) bool {
	clean := trustedExecutablePath(path)
	for _, root := range nodeWallTrustedRoots {
		if clean == root || strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// IsTrustedPath lets the API layer exclude NodeWall-owned executables from
// automatic process containment while keeping the path policy centralized.
func IsTrustedPath(path string) bool { return isNodeWallTrustedPath(path) }

// trustedExecutablePath removes the kernel's transient " (deleted)" suffix.
// Replacing /opt/nodewall/bin/nodewall during an in-place update leaves the
// already-running process pointing at that inode until systemd restarts it.
// That state is expected and must not become a self-detection or termination
// candidate.
func trustedExecutablePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimSuffix(path, " (deleted)")
	// Older overlayfs/procfs combinations append an inode marker such as
	// ";6af13621" before the deleted suffix. Strip only a delimiter followed
	// by a sufficiently long hexadecimal token; a real semicolon in a
	// filename must remain part of the trusted-path check.
	if separator := strings.LastIndexByte(path, ';'); separator >= 0 && separator+9 <= len(path) && isHexToken(path[separator+1:]) {
		path = strings.TrimSpace(path[:separator])
	}
	return filepath.Clean(path)
}

func isNodeWallPackagePath(path string) bool {
	clean := filepath.Clean(path)
	base := strings.ToLower(filepath.Base(clean))
	if !strings.HasPrefix(base, "nodewall") {
		return false
	}
	if !(strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".tgz") || strings.HasSuffix(base, ".tar.xz")) {
		return false
	}
	return strings.HasPrefix(clean, "/tmp/") || strings.HasPrefix(clean, "/private/tmp/") || strings.HasPrefix(clean, "/var/tmp/") || strings.HasPrefix(clean, "/root/")
}

func isNodeWallArtifactPath(path string) bool {
	return isNodeWallTrustedPath(path) || isNodeWallPackagePath(trustedExecutablePath(path)) || isNodeWallBuildBinaryPath(trustedExecutablePath(path))
}

// isNodeWallBuildBinaryPath covers the unpacked deployment/build trees that
// are commonly left in /tmp or /opt while an operator verifies a package. The
// NodeWall binary embeds its own detection signatures, so scanning that exact
// binary as an untrusted payload would produce a self-match. Keep this
// exception narrow: only the generated binary (or its temporary .new copy)
// below a clearly named NodeWall staging directory is trusted; arbitrary
// files elsewhere remain fully scanned.
func isNodeWallBuildBinaryPath(path string) bool {
	clean := filepath.Clean(path)
	base := strings.ToLower(filepath.Base(clean))
	if base != "nodewall" && base != "nodewall.new" {
		return false
	}
	for _, root := range []string{"/tmp", "/private/tmp", "/var/tmp", "/root", "/opt"} {
		if clean != root && !strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			continue
		}
		rel, err := filepath.Rel(root, clean)
		if err != nil {
			continue
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		for _, part := range parts[:len(parts)-1] {
			lower := strings.ToLower(part)
			if strings.HasPrefix(lower, "nodewall-") || strings.HasPrefix(lower, "nodewall_") {
				return true
			}
		}
	}
	return false
}

// quarantineEligible deliberately requires context in addition to a high
// severity rule. Package-owned service files and the operating system's
// normal binaries must never be moved automatically just because a heuristic
// string appears in them.
func quarantineEligible(path, rule string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || isNodeWallArtifactPath(path) {
		return false
	}
	if rule != "webshell" && rule != "reverse-shell" && rule != "cryptominer" &&
		rule != "scheduled-miner" && rule != "download-and-execute" &&
		rule != "loader-persistence" && rule != "malware-persistence" && rule != "startup-loader" && rule != "startup-payload" && rule != "clamav-signature" {
		return false
	}
	if isSystemPackageFile(path) {
		return false
	}
	// A history file or a read-only source document can quote miner strings
	// without being executable malware. Automatic isolation requires an
	// executable file for miner/reverse-shell evidence, while scheduler,
	// webshell, and loader rules also require a user-writable deployment area.
	switch rule {
	case "cryptominer", "reverse-shell":
		return (info.Mode().Perm()&0o111 != 0 || isScriptLikePath(path, info.Mode())) &&
			(info.Mode().Perm()&0o002 != 0 || isUserControlledPath(path))
	case "scheduled-miner":
		return info.Mode().Perm()&0o002 != 0 || isUserControlledPath(path)
	case "webshell", "download-and-execute", "loader-persistence", "malware-persistence", "startup-loader", "startup-payload", "clamav-signature":
		return suspiciousWritableContext(path, info)
	}
	return false
}

func processQuarantineEligible(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return false
	}
	if IsProtectedProcessPath(path) {
		return false
	}
	return true
}

// IsProtectedProcessPath identifies executables that a fast process scan may
// observe during normal platform operation. They remain evidence for review;
// the quick containment path must not terminate a Kubernetes runtime or the
// NodeWall agent merely because its PID view is unusual.
func IsProtectedProcessPath(path string) bool {
	if isNodeWallArtifactPath(path) || isSystemPackageFile(path) {
		return true
	}
	base := strings.ToLower(filepath.Base(strings.TrimSuffix(strings.TrimSpace(path), " (deleted)")))
	for _, name := range []string{
		"rke2", "rke2-server", "rke2-agent", "k3s", "k3s-server", "k3s-agent",
		"kubelet", "kube-proxy", "containerd", "containerd-shim", "containerd-shim-runc-v2",
		"dockerd", "crio", "crictl", "flanneld", "calico-node",
	} {
		if base == name || strings.HasPrefix(base, name+"-") {
			return true
		}
	}
	return false
}

// IsOperatorManagedStartupPath identifies startup configuration locations that
// may be quarantined after explicit operator confirmation. Vendor binaries and
// package-owned unit files remain protected even when a heuristic references
// them.
func IsOperatorManagedStartupPath(path string) bool {
	clean := filepath.Clean(strings.TrimSpace(strings.TrimSuffix(path, " (deleted)")))
	if clean == "/etc/crontab" || clean == "/etc/rc.local" {
		return true
	}
	for _, root := range []string{
		"/etc/systemd/system/", "/etc/systemd/system.control/", "/etc/systemd/system.extra/", "/etc/systemd/user/", "/etc/cron.d/", "/etc/cron.hourly/",
		"/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.monthly/", "/var/spool/cron/",
		"/var/spool/cron/crontabs/", "/etc/init.d/", "/etc/rc0.d/", "/etc/rc1.d/",
		"/etc/rc2.d/", "/etc/rc3.d/", "/etc/rc4.d/", "/etc/rc5.d/", "/etc/rc6.d/", "/etc/rcS.d/",
		"/etc/rc.d/", "/etc/init/", "/etc/modules-load.d/", "/run/modules-load.d/", "/usr/lib/modules-load.d/",
		"/usr/local/lib/modules-load.d/", "/etc/xdg/autostart/", "/usr/share/xdg/autostart/", "/etc/network/",
		"/etc/networkmanager/dispatcher.d/", "/etc/udev/rules.d/", "/etc/supervisor/", "/etc/containers/systemd/",
	} {
		if strings.HasPrefix(clean, root) {
			return true
		}
	}
	return clean == "/etc/crontab" || clean == "/etc/rc.local" || clean == "/etc/modules" ||
		strings.HasSuffix(clean, "/.config/autostart") || strings.HasPrefix(clean, "/var/lib/cloud/scripts/") ||
		clean == "/etc/supervisord.conf"
}

// IsSystemdUpdatePath identifies the executable locations used by systemd.
// During a package upgrade systemd replaces these files while services keep
// the old inode open; the resulting "(deleted)" proc entry is expected
// upgrade evidence and must not trigger automatic termination.
func IsSystemdUpdatePath(path string) bool {
	clean := trustedExecutablePath(path)
	base := strings.ToLower(filepath.Base(clean))
	if !strings.HasPrefix(base, "systemd") {
		return false
	}
	for _, root := range []string{"/usr/lib/systemd", "/lib/systemd"} {
		if clean == root || strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func suspiciousWritableContext(path string, info os.FileInfo) bool {
	clean := filepath.Clean(path)
	if info.Mode().Perm()&0o002 != 0 {
		return true
	}
	return isUserControlledPath(clean)
}

func isUserControlledPath(path string) bool {
	clean := filepath.Clean(path)
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv", "/home", "/var/spool/cron"} {
		if clean == root || strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func isSystemPackageFile(path string) bool {
	for _, root := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/share", "/usr/src", "/lib", "/lib64", "/etc", "/snap"} {
		clean := filepath.Clean(path)
		if clean != root && !strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			continue
		}
		// Files in the base system trees are protected from automatic
		// quarantine. They are still reported when a strong signature or a
		// running-process correlation identifies them for operator review.
		return true
	}
	return false
}

// IsSystemFilePath exposes the package-tree guard to the API containment
// layer. A process action must never move a normal system executable such as
// mysqld merely because it crossed a CPU threshold.
func IsSystemFilePath(path string) bool { return isSystemPackageFile(path) }
