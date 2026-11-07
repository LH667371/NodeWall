package sftpguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
	"nodewall/internal/filemeta"
	"nodewall/internal/securityscan"
)

type upload struct {
	mu                         sync.Mutex
	fs                         *filesystem
	file, parent, stage        *os.File
	path, base, stageName      string
	original                   os.FileInfo
	ctx                        context.Context
	appendMode, failed, closed bool
	closeErr                   error
}

func (fs *filesystem) newUpload(r *sftp.Request, path string) (*upload, error) {
	fs.mu.Lock()
	if len(fs.uploads) >= maxOpenUploads || fs.uploads[path] != nil {
		fs.mu.Unlock()
		return nil, errors.New("too many uploads or destination is busy")
	}
	// Reserve the path before opening files; SFTP requests run concurrently.
	u := &upload{fs: fs, path: path, base: filepath.Base(path), ctx: r.Context(), appendMode: r.Pflags().Append}
	u.mu.Lock()
	defer u.mu.Unlock()
	fs.uploads[path] = u
	fs.mu.Unlock()
	if err := u.prepare(r); err != nil {
		u.closed = true
		u.cleanup()
		fs.mu.Lock()
		delete(fs.uploads, path)
		fs.mu.Unlock()
		return nil, err
	}
	return u, nil
}

func (u *upload) prepare(r *sftp.Request) error {
	parent, err := os.Open(filepath.Dir(u.path))
	if err != nil {
		return err
	}
	u.parent = parent
	info, err := parent.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("upload parent is not a directory")
	}
	fd := int(parent.Fd())
	var stat unix.Stat_t
	err = unix.Fstatat(fd, u.base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("upload destination must be a regular file, not a symlink or device")
		}
		if r.Pflags().Excl && r.Pflags().Creat {
			return os.ErrExist
		}
		originalFD, err := unix.Openat(fd, u.base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		original := os.NewFile(uintptr(originalFD), u.path)
		defer original.Close()
		if err := unix.Fstat(originalFD, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("upload destination changed to a non-regular file")
		}
		if stat.Nlink > 1 {
			return errors.New("checked uploads cannot replace multiply linked files")
		}
		u.original, err = original.Stat()
		if err != nil {
			return err
		}
		if u.original.Size() > MaxUploadSize && !r.Pflags().Trunc {
			return errors.New("existing file exceeds 32 MiB; use a full replacement")
		}
		if err := u.createStage(); err != nil {
			return err
		}
		if !r.Pflags().Trunc {
			if _, err := io.Copy(u.file, io.LimitReader(original, MaxUploadSize+1)); err != nil {
				return err
			}
			info, err := u.file.Stat()
			if err != nil {
				return err
			}
			if info.Size() > MaxUploadSize {
				return errors.New("existing file grew beyond 32 MiB")
			}
		}
		if err := u.file.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
		if err := u.file.Chmod(u.original.Mode().Perm()); err != nil {
			return err
		}
		return filemeta.CopyAccessAttrs(original, u.file)
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if !r.Pflags().Creat {
		return os.ErrNotExist
	}
	return u.createStage()
}

func (u *upload) createStage() error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	u.stageName = stagePrefix + hex.EncodeToString(random[:])
	fd := int(u.parent.Fd())
	if err := unix.Mkdirat(fd, u.stageName, 0o700); err != nil {
		return err
	}
	stageFD, err := unix.Openat(fd, u.stageName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	u.stage = os.NewFile(uintptr(stageFD), u.stageName)
	var stat unix.Stat_t
	if err := unix.Fstat(stageFD, &stat); err != nil {
		return err
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o700 {
		return errors.New("upload staging directory was replaced")
	}
	payloadFD, err := unix.Openat(stageFD, "payload", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	u.file = os.NewFile(uintptr(payloadFD), "payload")
	return nil
}

func (u *upload) ReadAt(p []byte, off int64) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, os.ErrClosed
	}
	return u.file.ReadAt(p, off)
}

func (u *upload) WriteAt(p []byte, off int64) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || u.failed {
		return 0, os.ErrClosed
	}
	if u.appendMode {
		info, err := u.file.Stat()
		if err != nil {
			u.failed = true
			return 0, err
		}
		off = info.Size()
	}
	if off < 0 || off > MaxUploadSize || int64(len(p)) > MaxUploadSize-off {
		u.failed = true
		return 0, errors.New("upload exceeds 32 MiB")
	}
	n, err := u.file.WriteAt(p, off)
	if err != nil {
		u.failed = true
	}
	return n, err
}

// RequestServer invokes TransferError before closing a disconnected handle.
// Treat it as an abort, not an implicit successful CLOSE/commit.
func (u *upload) TransferError(error) { u.mu.Lock(); u.failed = true; u.mu.Unlock() }

func (u *upload) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return u.closeErr
	}
	u.closed = true
	defer func() {
		u.cleanup()
		u.fs.mu.Lock()
		delete(u.fs.uploads, u.path)
		u.fs.mu.Unlock()
	}()
	var report securityscan.Report
	status, action := "unavailable", "blocked"
	defer func() {
		detail := ""
		if u.closeErr != nil {
			detail = u.closeErr.Error()
		}
		u.fs.record("upload_scan", action, u.path, status, report, int64(report.BytesScanned), detail)
	}()
	if u.failed {
		u.closeErr = errors.New("upload was interrupted; original file retained")
		return u.closeErr
	}
	ctx, cancel := context.WithTimeout(u.ctx, 30*time.Second)
	defer cancel()
	report, u.closeErr = securityscan.New().ScanOpenFile(ctx, u.file, u.path)
	if u.closeErr != nil {
		return u.closeErr
	}
	if report.Truncated || report.FilesScanned != 1 || report.FilesSkipped != 0 || report.ReadErrors != 0 {
		u.closeErr = errors.New("upload could not be completely checked")
		return u.closeErr
	}
	if len(report.Findings) > 0 {
		status = "suspicious"
		u.closeErr = errors.New("upload matches a security rule; original file retained")
		return u.closeErr
	}
	if err := ctx.Err(); err != nil {
		u.closeErr = err
		return err
	}
	if err := u.file.Sync(); err != nil {
		u.closeErr = err
		return err
	}
	// Both ends of the publish use pinned directory descriptors. Renaming the
	// parent or replacing a visible staging name cannot swap in unscanned data.
	parentFD, stageFD := int(u.parent.Fd()), int(u.stage.Fd())
	if u.original == nil {
		u.closeErr = unix.Linkat(stageFD, "payload", parentFD, u.base, 0)
	} else {
		fd, err := unix.Openat(parentFD, u.base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			u.closeErr = err
			return err
		}
		current := os.NewFile(uintptr(fd), u.base)
		info, err := current.Stat()
		current.Close()
		if err != nil {
			u.closeErr = err
			return err
		}
		if !os.SameFile(u.original, info) || u.original.Size() != info.Size() || !u.original.ModTime().Equal(info.ModTime()) {
			u.closeErr = errors.New("destination changed during upload; retry without overwriting concurrent changes")
			return u.closeErr
		}
		u.closeErr = unix.Renameat(stageFD, "payload", parentFD, u.base)
	}
	if u.closeErr != nil {
		return u.closeErr
	}
	status, action = "clean", "uploaded"
	u.closeErr = u.parent.Sync()
	return u.closeErr
}

func (u *upload) cleanup() {
	if u.file != nil {
		u.file.Close()
	}
	if u.stage != nil {
		_ = unix.Unlinkat(int(u.stage.Fd()), "payload", 0)
		if u.parent != nil {
			var current, pinned unix.Stat_t
			if unix.Fstatat(int(u.parent.Fd()), u.stageName, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && unix.Fstat(int(u.stage.Fd()), &pinned) == nil && current.Ino == pinned.Ino && current.Dev == pinned.Dev {
				_ = unix.Unlinkat(int(u.parent.Fd()), u.stageName, unix.AT_REMOVEDIR)
			}
		}
		u.stage.Close()
	}
	if u.parent != nil {
		u.parent.Close()
	}
}
