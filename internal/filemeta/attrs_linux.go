//go:build linux

// Package filemeta preserves access metadata during managed atomic replacement.
package filemeta

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// CopyAccessAttrs preserves SELinux labels and POSIX ACLs. Capabilities are
// deliberately not copied: replacement content must not inherit executable
// privileges merely because the old inode had them.
func CopyAccessAttrs(source, destination *os.File) error {
	fd := int(source.Fd())
	size, err := unix.Flistxattr(fd, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil {
		return err
	}
	if size > 65536 {
		return errors.New("file attribute list exceeds the supported limit")
	}
	list := make([]byte, size)
	n, err := unix.Flistxattr(fd, list)
	if err != nil {
		return err
	}
	for _, raw := range bytes.Split(list[:n], []byte{0}) {
		name := string(raw)
		if name != "security.selinux" && name != "system.posix_acl_access" && !strings.HasPrefix(name, "user.") {
			continue
		}
		size, err := unix.Fgetxattr(fd, name, nil)
		if err != nil {
			return err
		}
		if size > 65536 {
			return fmt.Errorf("file attribute %s is too large", name)
		}
		value := make([]byte, size)
		n, err := unix.Fgetxattr(fd, name, value)
		if err != nil {
			return err
		}
		if err := unix.Fsetxattr(int(destination.Fd()), name, value[:n], 0); err != nil {
			return fmt.Errorf("preserve file attribute %s: %w", name, err)
		}
	}
	return nil
}
