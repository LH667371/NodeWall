//go:build !linux

package securityscan

import "context"

func collectJournalFindings(context.Context, int) ([]Finding, error) { return nil, nil }
