//go:build !linux

package securityscan

import "context"

func collectHiddenKernelModuleFindings(context.Context, int) ([]Finding, error) {
	return nil, nil
}
