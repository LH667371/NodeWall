//go:build linux

package securityscan

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// scanMountPoints reads the kernel's mount table once per scan. Root scans
// otherwise recurse into every NFS share and container overlay mounted below
// '/', repeatedly hashing data that belongs to another scan scope.
func scanMountPoints(root string) map[string]struct{} {
	mounts := make(map[string]struct{})
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return mounts
	}
	defer file.Close()

	root = filepath.Clean(root)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// mountinfo has: id parent major:minor root mountpoint options ... - fstype.
		if len(fields) < 6 {
			continue
		}
		mountpoint := filepath.Clean(decodeMountInfoField(fields[4]))
		if mountpoint == "/" || mountpoint == root {
			continue
		}
		if root != "/" && !pathWithin(root, mountpoint) {
			continue
		}
		mounts[mountpoint] = struct{}{}
	}
	return mounts
}

func decodeMountInfoField(value string) string {
	// Linux mountinfo escapes space, tab, and backslash as octal sequences.
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(value)
}

func pathWithin(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	return candidate == root || strings.HasPrefix(candidate, root+string(os.PathSeparator))
}
