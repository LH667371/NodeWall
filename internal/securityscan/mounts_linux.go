//go:build linux

package securityscan

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// scanMountPoints excludes remote, virtual and duplicate bind mounts. Local
// block-backed filesystems are included so a separate /home or /data is not
// silently omitted from a full host scan.
func scanMountPoints(root string) (map[string]string, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return parseScanMountPoints(root, file)
}

func parseScanMountPoints(root string, reader io.Reader) (map[string]string, error) {
	mounts := make(map[string]string)
	root = filepath.Clean(root)
	scanner := bufio.NewScanner(reader)
	type mountDevice struct{ path, device string }
	var localMounts []mountDevice
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// mountinfo has: id parent major:minor root mountpoint options ... - fstype.
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if len(fields) < 6 || separator < 6 || separator+1 >= len(fields) {
			continue
		}
		mountpoint := filepath.Clean(decodeMountInfoField(fields[4]))
		fsType := fields[separator+1]
		local := isLocalScanFilesystem(fsType)
		duplicate := false
		if local {
			for _, parent := range localMounts {
				if parent.device == fields[2] && parent.path != mountpoint && pathWithin(parent.path, mountpoint) {
					duplicate = true
					break
				}
			}
			localMounts = append(localMounts, mountDevice{path: mountpoint, device: fields[2]})
		}
		if mountpoint == "/" || mountpoint == root {
			continue
		}
		if root != "/" && !pathWithin(root, mountpoint) {
			continue
		}
		// Temporary filesystems at these paths frequently contain active or
		// dormant payloads. They are bounded by the same file and size limits
		// as the rest of the scan, unlike arbitrary tmpfs mounts.
		if fsType == "tmpfs" && (mountpoint == "/tmp" || mountpoint == "/var/tmp" || mountpoint == "/dev/shm") {
			continue
		}
		if !local {
			mounts[mountpoint] = "excluded-mount:" + fsType
		} else if duplicate {
			mounts[mountpoint] = "duplicate-local-mount:" + fsType
		}
	}
	return mounts, scanner.Err()
}

func isLocalScanFilesystem(fsType string) bool {
	switch fsType {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3":
		return true
	default:
		return false
	}
}

func decodeMountInfoField(value string) string {
	// Linux mountinfo escapes space, tab, and backslash as octal sequences.
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(value)
}

func pathWithin(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	if root == string(os.PathSeparator) {
		return filepath.IsAbs(candidate)
	}
	return candidate == root || strings.HasPrefix(candidate, root+string(os.PathSeparator))
}
