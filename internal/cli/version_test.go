package cli

import "testing"

func TestVersionAliases(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-V"}} {
		if err := Run(args); err != nil {
			t.Fatalf("Run(%v) returned error: %v", args, err)
		}
	}
}
