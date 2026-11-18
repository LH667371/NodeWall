//go:build !linux

package securityscan

import (
	"context"
	"errors"
)

func collectFDScriptFindings(context.Context, Scanner, int) ([]Finding, error) { return nil, nil }

func ReadFDScriptSample(Finding) ([]byte, error) {
	return nil, errors.New("descriptor script scanning is only supported on Linux")
}
