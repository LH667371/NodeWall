package cli

import (
	"flag"
	"io"
	"os"

	"nodewall/internal/sshactivity"
)

// Commands arrive over stdin, not argv, to avoid shell quoting and per-argument
// size limits. The journal stores only a bounded prefix and escapes newlines.
func runSSHActivity(args []string) error {
	flags := flag.NewFlagSet("ssh-activity", flag.ContinueOnError)
	path := flags.String("activity-log", "/var/log/nodewall/ssh-activity.log", "SSH activity journal")
	event := flags.String("event", "", "activity event")
	action := flags.String("action", "", "activity result")
	transfer := flags.String("transfer", "", "transfer protocol")
	scan := flags.String("scan-status", "", "upload check result")
	files := flags.Int("files", 0, "checked files")
	findings := flags.Int("findings", 0, "risk findings")
	target := flags.String("path", "", "file path")
	exit := flags.Int("exit-code", 0, "command exit status")
	if err := flags.Parse(args); err != nil {
		return err
	}
	command, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	record := sshactivity.Identity()
	record.Event, record.Action, record.Transfer, record.ScanStatus = *event, *action, *transfer, *scan
	record.Files, record.Findings, record.Path, record.ExitCode = *files, *findings, *target, exit
	record.Command = string(command)
	return sshactivity.Append(*path, record)
}
