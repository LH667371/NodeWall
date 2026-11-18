package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// restoreQuarantineFile copies via a temporary file on the destination device.
// Linking it into place is atomic and refuses a newly-created target, including
// when isolation and recovery use different filesystems.
func restoreQuarantineFile(source, destination string, metadata quarantineMetadata) error {
	if err := verifyTrustedSourceParents(destination); err != nil {
		return fmt.Errorf("refusing unsafe restore path: %w", err)
	}
	in, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("quarantine entry is no longer a regular file")
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".nodewall-restore-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer tmp.Close()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, hash), in)
	if err != nil {
		return err
	}
	if written != info.Size() || (metadata.SHA256 != "" && !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), metadata.SHA256)) {
		return errors.New("quarantine entry changed or hash does not match")
	}
	if metadata.OwnerKnown {
		if err := tmp.Chown(metadata.OriginalUID, metadata.OriginalGID); err != nil {
			return fmt.Errorf("restore ownership: %w", err)
		}
	}
	mode := os.FileMode(metadata.OriginalModeBits)
	if !metadata.ModeKnown && mode == 0 {
		mode = 0o600 // Legacy entries without mode metadata remain non-executable.
	}
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("restore permissions: %w", err)
	}
	if err := writeQuarantineAttrs(tmp, metadata.Attributes); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := verifyTrustedSourceParents(destination); err != nil {
		return fmt.Errorf("restore parent changed: %w", err)
	}
	if err := os.Link(tmpPath, destination); err != nil {
		return fmt.Errorf("publish restored file without overwriting target: %w", err)
	}
	if err := os.Remove(source); err != nil {
		return fmt.Errorf("restored file exists at %s, but removing quarantine copy failed: %w", destination, err)
	}
	return nil
}
