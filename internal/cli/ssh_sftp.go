package cli

import (
	"flag"
	"io"
	"os"

	"nodewall/internal/sftpguard"
	"nodewall/internal/sshactivity"
)

type sftpChannel struct {
	io.Reader
	io.WriteCloser
}

func (s sftpChannel) Close() error { return s.WriteCloser.Close() }

func runSFTPGuard(args []string) error {
	flags := flag.NewFlagSet("sftp-guard", flag.ContinueOnError)
	scan := flags.Bool("scan-uploads", false, "check uploaded files before publishing")
	audit := flags.Bool("audit-transfers", false, "record file transfers")
	activity := flags.String("activity-log", "/var/log/nodewall/ssh-activity.log", "SSH activity journal")
	if err := flags.Parse(args); err != nil {
		return err
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	return sftpguard.Serve(sftpChannel{os.Stdin, os.Stdout}, sftpguard.Options{ScanUploads: *scan, Audit: *audit,
		ActivityLog: *activity, Identity: sshactivity.Identity(), StartDirectory: dir})
}
