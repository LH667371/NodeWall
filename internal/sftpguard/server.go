// Package sftpguard serves SSH's SFTP subsystem in the authenticated user's
// process. It does not grant filesystem permissions beyond that SSH account.
package sftpguard

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
	"nodewall/internal/securityscan"
	"nodewall/internal/sshactivity"
)

const MaxUploadSize = 32 << 20
const maxOpenUploads = 8
const stagePrefix = ".nodewall-upload-"

type Options struct {
	ScanUploads    bool
	Audit          bool
	ActivityLog    string
	Identity       sshactivity.Record
	StartDirectory string
}

type filesystem struct {
	options  Options
	mu       sync.Mutex
	uploads  map[string]*upload
	logError bool
}

// Serve uses the existing SSH channel's stdin/stdout; diagnostics must never be
// written to stdout because it carries binary SFTP packets.
func Serve(channel io.ReadWriteCloser, options Options) error {
	fs := &filesystem{options: options, uploads: make(map[string]*upload)}
	server := sftp.NewRequestServer(channel, sftp.Handlers{FileGet: fs, FilePut: fs, FileCmd: fs, FileList: fs}, sftp.WithStartDirectory(options.StartDirectory))
	defer server.Close()
	err := server.Serve()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func safePath(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return "", os.ErrInvalid
	}
	path = filepath.Clean(path)
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if strings.HasPrefix(part, stagePrefix) {
			return "", os.ErrPermission
		}
	}
	return path, nil
}

func (fs *filesystem) record(event, action, path, status string, report securityscan.Report, size int64, detail string) {
	if !fs.options.Audit && event != "upload_scan" {
		return
	}
	r := fs.options.Identity
	r.Event, r.Action, r.Path, r.ScanStatus = event, action, path, status
	r.Transfer, r.Files, r.Findings, r.Bytes, r.Detail = "sftp", int(report.FilesScanned), len(report.Findings), size, detail
	if err := sshactivity.Append(fs.options.ActivityLog, r); err != nil {
		fs.mu.Lock()
		if !fs.logError {
			fmt.Fprintf(os.Stderr, "NodeWall: SSH audit journal unavailable: %v\n", err)
			fs.logError = true
		}
		fs.mu.Unlock()
	}
}

func (fs *filesystem) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path, err := safePath(r.Filepath)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("only regular files can be downloaded")
	}
	return &download{File: file, fs: fs, path: path}, nil
}

type download struct {
	*os.File
	fs             *filesystem
	path           string
	bytes          int64
	mu             sync.Mutex
	failed, closed bool
}

func (d *download) ReadAt(p []byte, off int64) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, err := d.File.ReadAt(p, off)
	if err != nil && !errors.Is(err, io.EOF) {
		d.failed = true
	}
	d.bytes += int64(n)
	return n, err
}
func (d *download) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	err := d.File.Close()
	action := "downloaded"
	if d.failed || err != nil {
		action = "incomplete"
	}
	d.fs.record("transfer", action, d.path, "", securityscan.Report{}, d.bytes, "")
	return err
}
func (d *download) TransferError(error) { d.mu.Lock(); d.failed = true; d.mu.Unlock() }

func (fs *filesystem) Filewrite(r *sftp.Request) (io.WriterAt, error) { return fs.OpenFile(r) }

func (fs *filesystem) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	path, err := safePath(r.Filepath)
	if err != nil {
		return nil, err
	}
	flags := r.Pflags()
	if !flags.Write {
		return nil, os.ErrPermission
	}
	if fs.options.ScanUploads {
		return fs.newUpload(r, path)
	}
	mode := os.O_WRONLY
	if flags.Read {
		mode = os.O_RDWR
	}
	if flags.Creat {
		mode |= os.O_CREATE
	}
	if flags.Trunc {
		mode |= os.O_TRUNC
	}
	if flags.Excl {
		mode |= os.O_EXCL
	}
	file, err := os.OpenFile(path, mode|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("only regular files can be uploaded")
	}
	return &directUpload{File: file, fs: fs, path: path, appendMode: flags.Append}, nil
}

type directUpload struct {
	*os.File
	fs         *filesystem
	path       string
	bytes      int64
	appendMode bool
	failed     bool
	closed     bool
	mu         sync.Mutex
}

func (u *directUpload) WriteAt(p []byte, off int64) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.appendMode {
		info, err := u.File.Stat()
		if err != nil {
			return 0, err
		}
		off = info.Size()
	}
	n, err := u.File.WriteAt(p, off)
	u.bytes += int64(n)
	if err != nil {
		u.failed = true
	}
	return n, err
}
func (u *directUpload) TransferError(error) { u.mu.Lock(); u.failed = true; u.mu.Unlock() }
func (u *directUpload) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	err := u.File.Close()
	action := "uploaded"
	if u.failed || err != nil {
		action = "incomplete"
	}
	u.fs.record("transfer", action, u.path, "", securityscan.Report{}, u.bytes, "")
	return err
}

type fileList []os.FileInfo

func (list fileList) ListAt(dst []os.FileInfo, off int64) (int, error) {
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if off >= int64(len(list)) {
		return 0, io.EOF
	}
	n := copy(dst, list[off:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}

type directoryList struct {
	file   *os.File
	mu     sync.Mutex
	offset int64
}

func (list *directoryList) ListAt(dst []os.FileInfo, off int64) (int, error) {
	list.mu.Lock()
	defer list.mu.Unlock()
	if off != list.offset {
		return 0, errors.New("invalid directory offset")
	}
	n := 0
	for n < len(dst) {
		entries, err := list.file.Readdir(len(dst) - n)
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), stagePrefix) {
				dst[n] = entry
				n++
				list.offset++
			}
		}
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
func (list *directoryList) Close() error { return list.file.Close() }

func (fs *filesystem) pending(path string) *upload {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.uploads[path]
}

func (fs *filesystem) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	path, err := safePath(r.Filepath)
	if err != nil {
		return nil, err
	}
	if r.Method != "List" {
		if u := fs.pending(path); u != nil {
			u.mu.Lock()
			defer u.mu.Unlock()
			if u.closed || u.file == nil {
				return nil, os.ErrClosed
			}
			info, err := u.file.Stat()
			return fileList{info}, err
		}
		info, err := os.Stat(path)
		return fileList{info}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		file.Close()
		return nil, errors.New("requested path is not a directory")
	}
	return &directoryList{file: file}, nil
}
func (fs *filesystem) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	path, err := safePath(r.Filepath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	return fileList{info}, err
}
func (fs *filesystem) Readlink(path string) (string, error) {
	path, err := safePath(path)
	if err != nil {
		return "", err
	}
	return os.Readlink(path)
}
func (fs *filesystem) RealPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(fs.options.StartDirectory, path)
	}
	path, err := safePath(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil
	}
	return resolved, err
}

func (fs *filesystem) Filecmd(r *sftp.Request) error {
	path, err := safePath(r.Filepath)
	if err != nil {
		return err
	}
	if r.Method == "Setstat" {
		return fs.setstat(r, path)
	}
	if fs.pending(path) != nil {
		return errors.New("file upload is still open")
	}
	var target string
	if r.Method == "Rename" || r.Method == "PosixRename" || r.Method == "Link" || r.Method == "Symlink" {
		target, err = safePath(r.Target)
		if err != nil {
			return err
		}
		if fs.pending(target) != nil {
			return errors.New("destination upload is still open")
		}
	}
	switch r.Method {
	case "Mkdir":
		return os.Mkdir(path, 0o755)
	case "Rmdir":
		return unix.Rmdir(path)
	case "Remove":
		return unix.Unlink(path)
	case "Rename", "PosixRename":
		if r.Method == "Rename" {
			if _, err := os.Lstat(target); err == nil {
				return os.ErrExist
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return os.Rename(path, target)
	case "Link", "Symlink":
		if fs.options.ScanUploads {
			return errors.New("links are not supported while upload checks are enabled")
		}
		if r.Method == "Link" {
			return os.Link(path, target)
		}
		return os.Symlink(path, target)
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (fs *filesystem) PosixRename(r *sftp.Request) error { return fs.Filecmd(r) }

func (fs *filesystem) setstat(r *sftp.Request, path string) error {
	flags, attrs := r.AttrFlags(), r.Attributes()
	if u := fs.pending(path); u != nil {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.closed {
			return os.ErrClosed
		}
		if flags.Size {
			if attrs.Size > MaxUploadSize {
				u.failed = true
				return errors.New("upload exceeds 32 MiB")
			}
			if err := u.file.Truncate(int64(attrs.Size)); err != nil {
				u.failed = true
				return err
			}
		}
		return applyAttributes(u.file, r)
	}
	if flags.Size && fs.options.ScanUploads {
		if attrs.Size > MaxUploadSize {
			return errors.New("upload exceeds 32 MiB")
		}
		u, err := fs.newUpload(&sftp.Request{Flags: 2}, path)
		if err != nil {
			return err
		}
		if err := u.file.Truncate(int64(attrs.Size)); err != nil {
			u.TransferError(err)
			_ = u.Close()
			return err
		}
		if err := applyAttributes(u.file, r); err != nil {
			u.TransferError(err)
			_ = u.Close()
			return err
		}
		return u.Close()
	}
	openFlags := os.O_RDONLY
	if flags.Size {
		openFlags = os.O_WRONLY
	}
	file, err := os.OpenFile(path, openFlags|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if flags.Size {
		if err := file.Truncate(int64(attrs.Size)); err != nil {
			return err
		}
	}
	return applyAttributes(file, r)
}

func applyAttributes(file *os.File, r *sftp.Request) error {
	flags, attrs := r.AttrFlags(), r.Attributes()
	if flags.Permissions {
		if err := file.Chmod(attrs.FileMode().Perm()); err != nil {
			return err
		}
	}
	if flags.UidGid {
		if err := file.Chown(int(attrs.UID), int(attrs.GID)); err != nil {
			return err
		}
	}
	if flags.Acmodtime {
		return unix.Futimes(int(file.Fd()), []unix.Timeval{unix.NsecToTimeval(time.Unix(int64(attrs.Atime), 0).UnixNano()), unix.NsecToTimeval(time.Unix(int64(attrs.Mtime), 0).UnixNano())})
	}
	return nil
}
