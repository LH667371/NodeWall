//go:build !linux

package securityscan

import "context"

func collectPersistenceFindings(context.Context, Scanner, int) ([]Finding, []CoverageGap, uint64, error) {
	return nil, nil, 0, nil
}
