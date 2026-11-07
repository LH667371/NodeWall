package cli

import "testing"

func TestKernelNeedsIPTablesCompatibility(t *testing.T) {
	tests := []struct {
		release string
		want    bool
	}{
		{release: "3.10.0-693.11.1.el7.x86_64", want: true},
		{release: "4.18.0-348.23.1.el7.x86_64", want: false},
		{release: "5.14.0-503.el9.x86_64", want: false},
		{release: "unknown", want: false},
	}
	for _, test := range tests {
		t.Run(test.release, func(t *testing.T) {
			if got := kernelNeedsIPTablesCompatibility(test.release); got != test.want {
				t.Fatalf("kernelNeedsIPTablesCompatibility(%q) = %t, want %t", test.release, got, test.want)
			}
		})
	}
}

func TestResolveInstallDataplane(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "real", want: "real"},
		{input: "iptables", want: "iptables"},
		{input: "legacy", want: "iptables"},
	} {
		t.Run(test.input, func(t *testing.T) {
			got, err := resolveInstallDataplane(test.input)
			if err != nil {
				t.Fatalf("resolveInstallDataplane(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("resolveInstallDataplane(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
	if _, err := resolveInstallDataplane("unsupported"); err == nil {
		t.Fatal("expected unsupported dataplane to fail")
	}
}
