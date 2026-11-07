package sshactivity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const journalLimit = 10 << 20

var journalWriters = make(chan struct{}, 8)

// Append serializes concurrent SSH helpers and bounds disk usage to four
// journals. Text is JSON-escaped so newlines cannot forge additional events.
func Append(path string, record Record) error {
	return boundedAppend(func() error {
		err := appendDirect(path, record)
		if errors.Is(err, os.ErrPermission) {
			return appendViaSocket(path, record)
		}
		return err
	})
}

// A stalled logging filesystem must not stall SSH. Bound both the waiting
// budget and the number of outstanding filesystem calls within each helper.
func boundedAppend(write func() error) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case journalWriters <- struct{}{}:
	case <-timer.C:
		return errors.New("SSH audit writer is busy")
	}
	done := make(chan error, 1)
	go func() { defer func() { <-journalWriters }(); done <- write() }()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return errors.New("SSH audit write timed out; journal result is unconfirmed")
	}
}

func appendDirect(path string, record Record) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("SSH activity journal path is required")
	}
	if record.At.IsZero() {
		record.At = time.Now().UTC()
	}
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	record.ID = hex.EncodeToString(id[:])
	for _, field := range []*string{&record.Command, &record.Path, &record.Detail} {
		if len(*field) > 4096 {
			*field = (*field)[:4096]
			record.Truncated = true
		}
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("SSH journal lock is not a regular file")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("SSH journal is not a regular file")
		}
		if info.Size()+int64(len(data)) > journalLimit {
			for i := 3; i >= 1; i-- {
				previous := path
				if i > 1 {
					previous = fmt.Sprintf("%s.%d", path, i-1)
				}
				if err := os.Rename(previous, fmt.Sprintf("%s.%d", path, i)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("SSH journal is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

// Identity binds helper events to the SSH channel rather than a browser tab.
func Identity() Record {
	fields := strings.Fields(os.Getenv("SSH_CONNECTION"))
	record := Record{User: strconv.Itoa(os.Geteuid()), SessionID: os.Getenv("NODEWALL_SSH_SESSION_ID")}
	if account, err := user.Current(); err == nil {
		record.User = account.Username
	}
	if len(fields) == 4 {
		record.SourceIP = fields[0]
		var port uint16
		if _, err := fmt.Sscan(fields[1], &port); err == nil {
			record.SourcePort = port
		}
	}
	return record
}
