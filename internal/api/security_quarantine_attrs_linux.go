//go:build linux

package api

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Older kernels cannot atomically verify an inode and remove its name. Restrict
// removal to directories that unprivileged users cannot rename or replace.
func verifyTrustedSourceParents(path string) error {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	parent = filepath.Clean(parent)
	for current := parent; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != 0 {
			return fmt.Errorf("source parent %s is not a root-owned directory", current)
		}
		if info.Mode().Perm()&0o022 != 0 && (current == parent || info.Mode()&os.ModeSticky == 0) {
			return fmt.Errorf("source parent %s is writable by unprivileged users", current)
		}
		if current == "/" {
			return nil
		}
	}
}

// Preserve access-control attributes before chmod changes the POSIX ACL mask.
func readQuarantineAttrs(file *os.File) (map[string][]byte, error) {
	fd := int(file.Fd())
	size, err := unix.Flistxattr(fd, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if size > 65536 {
		return nil, errors.New("file attribute list exceeds 64 KiB")
	}
	list := make([]byte, size)
	if size == 0 {
		return nil, nil
	}
	n, err := unix.Flistxattr(fd, list)
	if err != nil {
		return nil, err
	}
	attrs := make(map[string][]byte)
	total := 0
	for _, raw := range bytes.Split(list[:n], []byte{0}) {
		name := string(raw)
		if name == "" {
			continue
		}
		if name != "security.selinux" && name != "security.capability" && name != "system.posix_acl_access" && !strings.HasPrefix(name, "user.") {
			return nil, fmt.Errorf("cannot guarantee recovery of unsupported file attribute %s", name)
		}
		size, err := unix.Fgetxattr(fd, name, nil)
		if err != nil {
			return nil, fmt.Errorf("read attribute %s: %w", name, err)
		}
		if size > 65536 {
			return nil, fmt.Errorf("attribute %s exceeds 64 KiB", name)
		}
		total += size
		if total > 1<<20 {
			return nil, errors.New("file attributes exceed 1 MiB")
		}
		value := make([]byte, size)
		n, err := unix.Fgetxattr(fd, name, value)
		if err != nil {
			return nil, fmt.Errorf("read attribute %s: %w", name, err)
		}
		attrs[name] = value[:n]
	}
	return attrs, nil
}

func writeQuarantineAttrs(file *os.File, attrs map[string][]byte) error {
	for name, value := range attrs {
		if name != "security.selinux" && name != "security.capability" && name != "system.posix_acl_access" && !strings.HasPrefix(name, "user.") {
			return fmt.Errorf("unsupported stored attribute %q", name)
		}
		if err := unix.Fsetxattr(int(file.Fd()), name, value, 0); err != nil {
			return fmt.Errorf("restore attribute %s: %w", name, err)
		}
	}
	return nil
}
