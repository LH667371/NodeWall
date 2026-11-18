package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// remoteInstallPathError prevents an install or update from entering a
// potentially uninterruptible filesystem syscall on a disconnected NFS share.
// NodeWall writes binaries, web assets, and state atomically; those writes
// must live on a local filesystem so a failed remote mount cannot leave a
// half-updated installation or a command that appears to hang forever.
func ensureLocalInstallPaths(paths ...string) error {
	for _, path := range paths {
		mountPoint, fsType, err := remoteMountForPath(path)
		if err != nil {
			return fmt.Errorf("检查安装路径 %s: %w", path, err)
		}
		if mountPoint == "" || !isRemoteFilesystem(fsType) {
			continue
		}
		return fmt.Errorf("路径 %s 位于远程文件系统 %s（挂载点 %s）；为避免 NFS 不可达时安装或升级永久等待，请将 --install-dir/--config-dir 指向本地磁盘", path, fsType, mountPoint)
	}
	return nil
}

func remoteMountForPath(path string) (mountPoint, fsType string, err error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		// Non-Linux callers never reach install, but keeping this helper
		// conservative lets tests and other commands run on non-Linux hosts.
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}
	mountPoint, fsType = remoteMountFromMountInfo(path, string(data))
	return mountPoint, fsType, nil
}

func remoteMountFromMountInfo(path, mountInfo string) (mountPoint, fsType string) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		if absolute, err := filepath.Abs(path); err == nil {
			path = filepath.Clean(absolute)
		}
	}
	bestLength := -1
	scanner := bufio.NewScanner(strings.NewReader(mountInfo))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || separator+1 >= len(fields) {
			continue
		}
		candidate := filepath.Clean(decodeMountInfoPath(fields[4]))
		if candidate != "/" && !pathWithin(candidate, path) {
			continue
		}
		if len(candidate) <= bestLength {
			continue
		}
		bestLength = len(candidate)
		mountPoint = candidate
		fsType = strings.ToLower(strings.TrimSpace(fields[separator+1]))
	}
	return mountPoint, fsType
}

func decodeMountInfoPath(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(value)
}

func pathWithin(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	return candidate == root || strings.HasPrefix(candidate, root+string(os.PathSeparator))
}

func isRemoteFilesystem(fsType string) bool {
	fsType = strings.ToLower(strings.TrimSpace(fsType))
	if strings.HasPrefix(fsType, "nfs") || strings.HasPrefix(fsType, "cifs") || strings.HasPrefix(fsType, "smb") {
		return true
	}
	switch fsType {
	case "sshfs", "fuse.sshfs", "9p", "ceph", "ceph-fuse", "glusterfs":
		return true
	default:
		return false
	}
}
