//go:build linux

package sshactivity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		credErr = e
		if e == nil {
			uid = cred.Uid
		}
	})
	return uid, errors.Join(err, credErr)
}

// ServeJournal accepts only local Unix peers and derives their user identity
// from kernel credentials. Unprivileged SSH accounts never need write access
// to the root-owned journal or its containing directory.
func ServeJournal(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	socket := path + ".sock"
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("SSH journal socket path is occupied by a non-socket file")
		}
		probe, err := net.DialTimeout("unix", socket, 200*time.Millisecond)
		if err == nil {
			probe.Close()
			return errors.New("SSH journal socket is already serving")
		}
		if !errors.Is(err, unix.ECONNREFUSED) {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) {
			return errors.New("refusing to replace another user's SSH journal socket")
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0o666); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	sem := make(chan struct{}, 16)
	var workers sync.WaitGroup
	type quota struct {
		second int64
		count  int
	}
	quotas := make(map[uint32]quota)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			workers.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		uid, err := peerUID(conn)
		if err != nil {
			conn.Close()
			continue
		}
		q, known := quotas[uid]
		second := time.Now().Unix()
		if q.second != second {
			q = quota{second: second}
		}
		if q.count >= 100 || (len(quotas) >= 4096 && !known) {
			conn.Close()
			continue
		}
		q.count++
		quotas[uid] = q
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		workers.Go(func() {
			defer func() { conn.Close(); <-sem }()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			var record Record
			err := json.NewDecoder(io.LimitReader(conn, 128<<10)).Decode(&record)
			if err == nil {
				record.User = strconv.FormatUint(uint64(uid), 10)
				if account, e := user.LookupId(record.User); e == nil {
					record.User = account.Username
				}
				record.At = time.Now().UTC()
				err = appendDirect(path, record)
			}
			message := ""
			if err != nil {
				message = err.Error()
			}
			_ = json.NewEncoder(conn).Encode(struct {
				Error string `json:"error"`
			}{message})
		})
	}
}

func appendViaSocket(path string, record Record) error {
	conn, err := net.DialTimeout("unix", path+".sock", time.Second)
	if err != nil {
		return fmt.Errorf("SSH journal is not writable and its local service is unavailable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("SSH journal requires a Unix socket")
	}
	uid, err := peerUID(unixConn)
	if err != nil {
		return err
	}
	if uid != 0 && uid != uint32(os.Geteuid()) {
		return errors.New("SSH journal service belongs to an unexpected user")
	}
	if err := json.NewEncoder(conn).Encode(record); err != nil {
		return err
	}
	var reply struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&reply); err != nil {
		return err
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	return nil
}
