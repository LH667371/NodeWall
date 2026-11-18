package version

import (
	"os"
	"strings"
	"testing"

	assets "nodewall"
)

func TestCurrentReportsEmbeddedVersionWhenLocalMarkersAreStale(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, name := range []string{"VERSION", "PACKAGE_VERSION"} {
		if err := os.WriteFile(name, []byte("0.0.0-stale\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want := strings.TrimSpace(assets.ReleaseVersion)
	if got := Current(); want == "" || got.AppVersion != want || got.PackageVersion != want {
		t.Fatalf("Current() = %+v, want embedded version %q", got, want)
	}
}
