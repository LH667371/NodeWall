//go:build !linux

package api

import "errors"

func blockSystemdStartup(string) (string, bool, error) {
	return "", false, errors.New("systemd startup blocking is only supported on Linux")
}

func unblockSystemdStartup(string) error { return nil }
