package clamav

import "testing"

func TestEngineReleaseOrderingDoesNotDowngradeOrOscillate(t *testing.T) {
	for _, tc := range []struct {
		current, candidate string
		want               bool
	}{
		{"1.4.6-r0", "1.4.7-r0", true},
		{"1.4.6-r0", "1.4.6-r1", true},
		{"1.4.9-r0", "1.4.10-r0", true},
		{"1.4.6-r1", "1.4.6-r0", false},
		{"1.4.7-r0", "1.4.6-r2", false},
		{"1.4.7-r0", "1.4.7-r0", false},
		{"", "1.4.6-r0", true},
		{"1.4.6-r0", "", false},
		{"", "", false},
	} {
		current := Artifact{SHA256: "local", Release: tc.current}
		candidate := Artifact{SHA256: "different", Release: tc.candidate}
		if got := newerEngine(current, candidate); got != tc.want {
			t.Errorf("newerEngine(%q, %q) = %v, want %v", tc.current, tc.candidate, got, tc.want)
		}
	}
	for _, value := range []string{"1.4", "1.4.6-r", "1.4.6-r-1", "1.4.6-r1-extra", "1.4.6+build", "1.4.6.7", "1.4.-6", "99999999999999999999.0.0"} {
		if _, valid := parseEngineRelease(value); valid {
			t.Errorf("invalid release %q accepted", value)
		}
	}
}
