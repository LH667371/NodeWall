//go:build linux

package securityscan

import "testing"

func TestMissingSystemFileFindingIsReviewOnly(t *testing.T) {
	finding := systemFileIntegrityFinding("/usr/sbin/iptables", "iptables command is missing while a backend is present")
	if finding.Rule != "system-file-tamper" || finding.Severity != SeverityHigh || finding.Source != "integrity" || !finding.SystemFile {
		t.Fatalf("unexpected system integrity finding: %#v", finding)
	}
	if finding.Quarantinable || finding.Terminated {
		t.Fatalf("system integrity finding became actionable: %#v", finding)
	}
}
