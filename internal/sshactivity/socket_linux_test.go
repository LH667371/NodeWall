//go:build linux

package sshactivity

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestJournalUnprivilegedChild(t *testing.T) {
	if os.Getenv("NODEWALL_JOURNAL_CHILD") != "1" {
		return
	}
	if err := Append(os.Getenv("NODEWALL_JOURNAL_TEST_PATH"), Record{User: "forged-root", Event: "command", SessionID: "unprivileged", Command: "echo ordinary-user"}); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func TestJournalSocketAuthenticatesUnprivilegedSSHAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root only inside isolated Linux test container")
	}
	dir := t.TempDir()
	if err := os.Chmod(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "activity.log")
	if err := Append(path, Record{Event: "session_open", User: "root"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeJournal(ctx, path) }()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		if _, err := os.Stat(path + ".sock"); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	helper := filepath.Join(dir, "helper.test")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(helper, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(target, source)
	target.Close()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(helper, "-test.run=^TestJournalUnprivilegedChild$")
	// Never pass the root test runner's environment to a lower-privilege child.
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "NODEWALL_JOURNAL_CHILD=1", "NODEWALL_JOURNAL_TEST_PATH=" + path}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ordinary SSH account could not journal: %v %s", err, output)
	}
	records, err := ReadFiltered(path, 10, Filter{SessionID: "unprivileged"})
	if err != nil {
		t.Fatal(err)
	}
	expected := strconv.Itoa(65534)
	if account, err := user.LookupId(expected); err == nil {
		expected = account.Username
	}
	if len(records) != 1 || records[0].User != expected {
		t.Fatalf("kernel identity was not enforced: %#v", records)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("root journal permissions were widened")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("journal socket did not shut down")
	}
}
