// Package sshaudit captures Bash's top-level commands, not terminal keystrokes.
// It is an operational audit trail, not tamper-proof containment of root.
package sshaudit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nodewall/internal/sshactivity"
)

type Options struct {
	Shell, ActivityLog string
	Interactive        bool
	Identity           sshactivity.Record
	Stdin              io.Reader
	Stdout, Stderr     io.Writer
}

const bashInit = `# NodeWall: preserve user startup files before installing the audit hook.
if [[ $- == *i* ]]; then
  [[ ! -r /etc/profile ]] || . /etc/profile
  for __nw_profile in "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
    if [[ -r "$__nw_profile" ]]; then . "$__nw_profile"; break; fi
  done
  unset __nw_profile
elif [[ -n ${NODEWALL_ORIGINAL_BASH_ENV:-} && -r $NODEWALL_ORIGINAL_BASH_ENV ]]; then
  . "$NODEWALL_ORIGINAL_BASH_ENV"
fi
if [[ -n $(trap -p DEBUG) ]]; then
  builtin printf '%s\0' '@nodewall:audit-unavailable:existing DEBUG trap' >&3 || :
else
  __nw_record_command() {
    local LC_ALL=C
    local __nw_command=$1
    case "$1" in __nw_* ) return 0 ;; esac
    if [[ ${#__nw_command} -gt 3000 ]]; then __nw_command="@nodewall:truncated:${__nw_command:0:3000}"; fi
    builtin printf '%s\0' "$__nw_command" >&3 2>/dev/null || :
    return 0
  }
  trap '__nw_record_command "$BASH_COMMAND"' DEBUG
fi
`

// Run preserves the account shell for unsupported shells and emits an explicit
// audit-unavailable event. It never substitutes raw input capture for commands.
func Run(ctx context.Context, options Options) error {
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if options.Stdout == nil {
		options.Stdout = os.Stdout
	}
	if options.Stderr == nil {
		options.Stderr = os.Stderr
	}
	var outputMu sync.Mutex
	options.Stdout = lockedWriter{&outputMu, options.Stdout}
	options.Stderr = lockedWriter{&outputMu, options.Stderr}
	var logOnce sync.Once
	record := func(event, action, command, detail string, truncated bool) {
		r := options.Identity
		r.Event, r.Action, r.Command, r.Detail, r.Truncated = event, action, command, detail, truncated
		if err := sshactivity.Append(options.ActivityLog, r); err != nil {
			logOnce.Do(func() { fmt.Fprintf(options.Stderr, "NodeWall: SSH command audit unavailable: %v\n", err) })
		}
	}
	args := []string{"-s"}
	if options.Interactive {
		args = []string{"-l"}
	}
	cmd := exec.CommandContext(ctx, options.Shell, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = options.Stdin, options.Stdout, options.Stderr
	var auditReader, auditWriter *os.File
	drained := make(chan struct{})
	if filepath.Base(options.Shell) == "bash" {
		hookPath := ""
		setup := func() error {
			hook, err := os.CreateTemp("", "nodewall-bash-audit-*.bash")
			if err != nil {
				return err
			}
			hookPath = hook.Name()
			// Cleanup belongs to this call, not the setup closure.
			defer func() {
				if auditWriter == nil {
					os.Remove(hook.Name())
				}
			}()
			_, err = hook.WriteString(bashInit)
			err = errors.Join(err, hook.Close())
			if err != nil {
				return err
			}
			auditReader, auditWriter, err = os.Pipe()
			if err != nil {
				return err
			}
			cmd.ExtraFiles = []*os.File{auditWriter}
			if options.Interactive {
				cmd.Args = []string{options.Shell, "--noprofile", "--rcfile", hook.Name(), "-i"}
			} else {
				cmd.Env = replaceEnv(os.Environ(), "NODEWALL_ORIGINAL_BASH_ENV", os.Getenv("BASH_ENV"))
				cmd.Env = replaceEnv(cmd.Env, "BASH_ENV", hook.Name())
			}
			return nil
		}
		if err := setup(); err != nil {
			record("audit_status", "unavailable", "", err.Error(), false)
			fmt.Fprintf(options.Stderr, "NodeWall: command audit setup unavailable; preserving SSH access: %v\n", err)
			close(drained)
		} else {
			defer os.Remove(hookPath)
			defer auditReader.Close()
			defer auditWriter.Close()
			go func() {
				defer close(drained)
				readCommands(auditReader, func(command string, truncated bool) {
					if strings.HasPrefix(command, "@nodewall:audit-unavailable:") {
						record("audit_status", "unavailable", "", strings.TrimPrefix(command, "@nodewall:audit-unavailable:"), false)
					} else {
						if strings.HasPrefix(command, "@nodewall:truncated:") {
							command = strings.TrimPrefix(command, "@nodewall:truncated:")
							truncated = true
						}
						record("command", "executing", command, "bash top-level command", truncated)
					}
				})
			}()
		}
	} else {
		record("audit_status", "unavailable", "", "command capture supports Bash only; account shell was preserved", false)
		close(drained)
	}
	if err := cmd.Start(); err != nil {
		if auditWriter != nil {
			auditWriter.Close()
		}
		return err
	}
	if auditWriter != nil {
		// Keep each hook write under PIPE_BUF and nonblocking: a stalled journal
		// must not backpressure the user's terminal through this pipe.
		if err := unix.SetNonblock(int(auditWriter.Fd()), true); err != nil {
			auditReader.Close()
		}
		auditWriter.Close()
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	finished := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
			case <-finished:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(finished)
	signal.Stop(signals)
	// Background jobs can inherit fd 3. Do not keep the SSH channel alive just
	// because an unrelated background descendant still holds the audit pipe.
	select {
	case <-drained:
	case <-time.After(500 * time.Millisecond):
		if auditReader != nil {
			auditReader.Close()
		}
	}
	return err
}

type lockedWriter struct {
	mu     *sync.Mutex
	writer io.Writer
}

func (w lockedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(data)
}

func replaceEnv(env []string, key, value string) []string {
	result := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, key+"=") {
			result = append(result, item)
		}
	}
	return append(result, key+"="+value)
}

func readCommands(reader io.Reader, emit func(string, bool)) {
	buffer := bufio.NewReaderSize(reader, 64<<10)
	var prefix []byte
	truncated := false
	for {
		part, err := buffer.ReadSlice(0)
		if len(prefix) < 4096 {
			prefix = append(prefix, part[:min(len(part), 4096-len(prefix))]...)
		}
		if len(part) > 4096 || len(prefix) >= 4096 {
			truncated = true
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			truncated = true
			continue
		}
		if err != nil {
			return
		}
		prefix = bytes.TrimSuffix(prefix, []byte{0})
		if len(prefix) > 0 {
			emit(string(prefix), truncated)
		}
		prefix = nil
		truncated = false
	}
}
