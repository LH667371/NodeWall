// Package clamav manages NodeWall's private ClamAV runtime and signature data.
// It never alters a system ClamAV installation or the host package manager.
package clamav

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const defaultDataDir = "/var/lib/nodewall/clamav"

func DataDir() string {
	if path := strings.TrimSpace(os.Getenv("NODEWALL_CLAMAV_DIR")); path != "" {
		return filepath.Clean(path)
	}
	return defaultDataDir
}

func AssetsDir() string {
	if path := strings.TrimSpace(os.Getenv("NODEWALL_CLAMAV_ASSETS_DIR")); path != "" {
		return filepath.Clean(path)
	}
	return "/opt/nodewall/clamav"
}

func SocketPath() string {
	if path := strings.TrimSpace(os.Getenv("NODEWALL_CLAMD_SOCKET")); path != "" {
		return path
	}
	return filepath.Join(DataDir(), "clamd.sock")
}

// InstallBundle copies the sibling release assets, if present. Update archives
// and binary-only upgrades retain the existing bundle; enrolled nodes can fetch
// missing assets from their manager after registration.
func InstallBundle(executable, installDir string) error {
	if filepath.Base(filepath.Dir(executable)) != "bin" {
		return nil
	}
	source := filepath.Join(filepath.Dir(filepath.Dir(executable)), "clamav")
	if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	destination := filepath.Join(installDir, "clamav")
	if filepath.Clean(source) == filepath.Clean(destination) {
		return nil
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(installDir, ".clamav-bundle-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"engines/amd64.tar.gz", "engines/arm64.tar.gz", "database/main.cvd", "database/daily.cvd", "database/bytecode.cvd", "NOTICE.md"} {
		if err := copyAtomic(filepath.Join(source, name), filepath.Join(stage, name), 0o644); err != nil {
			return fmt.Errorf("install ClamAV asset %s: %w", name, err)
		}
	}
	backup := stage + ".previous"
	hadPrevious := false
	if err := os.Rename(destination, backup); err == nil {
		hadPrevious = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		if hadPrevious {
			if restoreErr := os.Rename(backup, destination); restoreErr != nil {
				return errors.Join(err, fmt.Errorf("restore previous ClamAV bundle: %w", restoreErr))
			}
		}
		return err
	}
	if hadPrevious {
		_ = os.RemoveAll(backup)
	}
	return nil
}

func copyAtomic(source, destination string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(destination), ".nodewall-clamav-*")
	if err != nil {
		return err
	}
	name := out.Name()
	defer os.Remove(name)
	if err = out.Chmod(mode); err == nil {
		_, err = io.Copy(out, in)
	}
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, destination)
}

func fileDigest(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

// extractEngine accepts only regular files and directories from our runtime
// archive. In particular, links and path traversal cannot escape the staging
// directory when a damaged or malicious archive is received from a manager.
func extractEngine(archive, destination string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	var total int64
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		name := filepath.Clean(header.Name)
		if name == "." && header.Typeflag == tar.TypeDir {
			continue
		}
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("invalid engine archive path %q", header.Name)
		}
		path := filepath.Join(destination, name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > 128<<20 {
				return fmt.Errorf("invalid engine file size for %q", name)
			}
			total += header.Size
			if total > 512<<20 {
				return errors.New("engine archive exceeds size limit")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(header.Mode)&0o755)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, reader)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("unsupported engine archive entry %q", header.Name)
		}
	}
	return nil
}
