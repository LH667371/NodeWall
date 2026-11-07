package sftpguard

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"nodewall/internal/sshactivity"
)

func clientForTest(t *testing.T, dir string) (*sftp.Client, <-chan error) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- Serve(serverConn, Options{ScanUploads: true, Audit: true, ActivityLog: filepath.Join(dir, "activity.log"), StartDirectory: dir, Identity: sshactivity.Record{SessionID: "test-session", User: "root"}})
	}()
	client, err := sftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); clientConn.Close(); serverConn.Close() })
	return client, done
}

func TestSFTPChecksEveryUploadBeforeReplacingOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.php")
	if err := os.WriteFile(path, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	client, _ := clientForTest(t, dir)
	file, err := client.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("<?php eval(base64_decode($_POST['x'])); ?>")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "original" {
		t.Fatal("unvalidated bytes replaced the destination")
	}
	if err := file.Close(); err == nil {
		t.Fatal("suspicious upload was accepted")
	}
	if data, _ := os.ReadFile(path); string(data) != "original" {
		t.Fatal("blocked upload destroyed the original")
	}
	file, err = client.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(file, "clean replacement"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "clean replacement" {
		t.Fatal("clean upload was not committed")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Fatal("original permissions were lost")
	}
	download, err := client.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(download)
	download.Close()
	if err != nil || string(data) != "clean replacement" {
		t.Fatal("download failed", err)
	}
	records, err := sshactivity.Read(filepath.Join(dir, "activity.log"), 100)
	if err != nil {
		t.Fatal(err)
	}
	var clean, blocked bool
	for _, record := range records {
		if record.SessionID != "test-session" {
			t.Fatal("session identity was lost")
		}
		clean = clean || record.ScanStatus == "clean"
		blocked = blocked || record.ScanStatus == "suspicious"
	}
	if !clean || !blocked {
		t.Fatalf("per-file decisions not audited: %#v", records)
	}
}

func TestSFTPDisconnectAndOversizeDoNotPublish(t *testing.T) {
	for _, mode := range []string{"disconnect", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "file.txt")
			if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			client, done := clientForTest(t, dir)
			file, err := client.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write([]byte("incomplete")); err != nil {
				t.Fatal(err)
			}
			if mode == "oversize" {
				if _, err := file.WriteAt([]byte("x"), MaxUploadSize); err == nil {
					t.Fatal("size limit ignored")
				}
				if err := file.Close(); err == nil {
					t.Fatal("failed upload was committed")
				}
			} else {
				client.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("disconnected server did not stop")
				}
			}
			if data, _ := os.ReadFile(path); string(data) != "original" {
				t.Fatal("failed upload changed original")
			}
			entries, _ := os.ReadDir(dir)
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), stagePrefix) {
					t.Fatal("aborted staging directory was not cleaned")
				}
			}
		})
	}
}

func TestSFTPDirectoryOperationsAndAppend(t *testing.T) {
	dir := t.TempDir()
	client, _ := clientForTest(t, dir)
	sub := filepath.Join(dir, "sub")
	if err := client.Mkdir(sub); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "file.txt")
	file, err := client.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("first"))
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = client.OpenFile(path, os.O_APPEND|os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte(" second"))
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "first second" {
		t.Fatal("append lost original data")
	}
	if err := client.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	entries, err := client.ReadDir(sub)
	if err != nil || len(entries) != 1 {
		t.Fatalf("listing failed: %v %v", entries, err)
	}
	target := filepath.Join(sub, "renamed.txt")
	if err := client.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := client.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveDirectory(sub); err != nil {
		t.Fatal(err)
	}
}

func TestUploadCommitPinsDirectoriesAndRejectsSymlinkTargets(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	moved := filepath.Join(dir, "moved")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	fs := &filesystem{options: Options{ScanUploads: true, ActivityLog: filepath.Join(dir, "audit")}, uploads: make(map[string]*upload)}
	path := filepath.Join(parent, "safe.txt")
	u, err := fs.newUpload(&sftp.Request{Flags: 2 | 8 | 16}, path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = u.WriteAt([]byte("clean"), 0)
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "untouched" {
		t.Fatal("replacement directory was overwritten")
	}
	if data, _ := os.ReadFile(filepath.Join(moved, "safe.txt")); string(data) != "clean" {
		t.Fatal("pinned destination did not receive checked file")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.newUpload(&sftp.Request{Flags: 2 | 8 | 16}, link); err == nil {
		t.Fatal("symlink destination was accepted")
	}
}

func TestCanceledUploadCannotCommit(t *testing.T) {
	dir := t.TempDir()
	fs := &filesystem{options: Options{ScanUploads: true, ActivityLog: filepath.Join(dir, "audit")}, uploads: make(map[string]*upload)}
	ctx, cancel := context.WithCancel(context.Background())
	path := filepath.Join(dir, "safe.txt")
	u, err := fs.newUpload((&sftp.Request{Flags: 2 | 8 | 16}).WithContext(ctx), path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = u.WriteAt([]byte("clean"), 0)
	cancel()
	if err := u.Close(); err == nil {
		t.Fatal("canceled upload was accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("canceled file was published")
	}
}
