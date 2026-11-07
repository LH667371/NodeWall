package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"nodewall/internal/sshactivity"
	"nodewall/internal/sshaudit"
)

type sshShellExit struct{ code int }

func (e *sshShellExit) Error() string { return fmt.Sprintf("SSH shell exited with status %d", e.code) }

func runSSHShell(args []string) error {
	flags := flag.NewFlagSet("ssh-shell", flag.ContinueOnError)
	interactive := flags.Bool("interactive", false, "interactive SSH shell")
	activity := flags.String("activity-log", "/var/log/nodewall/ssh-activity.log", "SSH activity journal")
	if err := flags.Parse(args); err != nil {
		return err
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	err := sshaudit.Run(context.Background(), sshaudit.Options{Shell: shell, ActivityLog: *activity, Interactive: *interactive, Identity: sshactivity.Identity()})
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code := exit.ExitCode()
		if code < 0 {
			code = 128
			if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				code += int(status.Signal())
			}
		}
		return &sshShellExit{code}
	}
	return err
}
