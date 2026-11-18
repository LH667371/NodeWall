//go:build !linux

package securityscan

import (
	"context"
	"fmt"
)

type ProcessTrace struct {
	PID        int    `json:"pid"`
	Executable string `json:"executable,omitempty"`
	Command    string `json:"command,omitempty"`
	Cgroup     string `json:"cgroup,omitempty"`
	Deleted    bool   `json:"deleted,omitempty"`
}

func TraceProcess(pid int) (ProcessTrace, error) {
	return ProcessTrace{PID: pid}, fmt.Errorf("process tracing is only supported on Linux")
}

func collectHighCPUFindings(context.Context, int) ([]Finding, error) {
	return nil, nil
}

func collectTemporaryProcessFindings(context.Context, int) ([]Finding, error) {
	return nil, nil
}

func collectProcessIntegrityFindings(context.Context, int) ([]Finding, error) {
	return nil, nil
}

func scanProcessSignatures(context.Context, Scanner, int) ([]Finding, bool, error) {
	return nil, false, nil
}

// scanProcessSignaturesWithProgress keeps the scanner API portable. Process
// executable signature inspection is Linux-specific, so other platforms
// report no candidates without pretending that a scan was performed.
func scanProcessSignaturesWithProgress(context.Context, Scanner, int, func(Progress)) ([]Finding, bool, error) {
	return nil, false, nil
}
