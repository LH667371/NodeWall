//go:build !linux

package securityscan

import (
	"context"
	"fmt"
)

func FindProcessesForFileFinding(context.Context, Finding) ([]Finding, error) {
	return nil, fmt.Errorf("file-to-process correlation is only supported on Linux")
}
