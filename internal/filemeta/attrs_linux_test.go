//go:build linux

package filemeta

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAtomicReplacementPreservesExtendedMetadata(t *testing.T) {
	dir := t.TempDir()
	source, err := os.Create(filepath.Join(dir, "source"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.Create(filepath.Join(dir, "target"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	err = unix.Fsetxattr(int(source.Fd()), "user.nodewall-test", []byte("preserved"), 0)
	if errors.Is(err, unix.ENOTSUP) {
		t.Skip("filesystem has no xattr support")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := CopyAccessAttrs(source, target); err != nil {
		t.Fatal(err)
	}
	value := make([]byte, 64)
	n, err := unix.Fgetxattr(int(target.Fd()), "user.nodewall-test", value)
	if err != nil || string(value[:n]) != "preserved" {
		t.Fatal("extended metadata lost", err)
	}
}
