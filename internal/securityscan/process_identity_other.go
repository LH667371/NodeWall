//go:build !linux

package securityscan

import "fmt"

func ReadProcessStartTime(int) (string, error) {
	return "", fmt.Errorf("process identity is only supported on Linux")
}

func VerifyProcessFinding(Finding) error {
	return fmt.Errorf("process identity is only supported on Linux")
}

// EnrichProcessFinding is kept available on every target so API code can use
// the same identity-validation path when building for non-Linux hosts. A
// non-Linux scanner never produces actionable process findings, therefore the
// original evidence is returned unchanged and its start time remains empty.
func EnrichProcessFinding(finding Finding) Finding {
	return finding
}

func VerifyProcessExecutablePath(Finding) error {
	return fmt.Errorf("process identity is only supported on Linux")
}

func ProcessFindingAfterIsolation(Finding, string) (Finding, error) {
	return Finding{}, fmt.Errorf("process identity is only supported on Linux")
}
