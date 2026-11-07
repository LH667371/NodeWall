//go:build !linux

package sshactivity

import (
	"context"
	"errors"
)

func ServeJournal(context.Context, string) error { return nil }
func appendViaSocket(string, Record) error {
	return errors.New("privileged SSH journal forwarding requires Linux")
}
