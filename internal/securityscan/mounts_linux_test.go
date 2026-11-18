//go:build linux

package securityscan

import (
	"strings"
	"testing"
)

func TestMountPolicyIncludesSeparateLocalDisksAndRecordsExcludedMounts(t *testing.T) {
	mountinfo := `1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 8:2 / /home rw - ext4 /dev/sdb1 rw
3 1 8:3 / /data rw - xfs /dev/sdc1 rw
4 1 8:1 /var/lib /mirror rw - ext4 /dev/sda1 rw
5 1 0:42 / /remote rw - nfs server:/share rw
6 1 0:43 / /var/lib/docker/overlay2 rw - overlay overlay rw
7 1 0:44 / /tmp rw - tmpfs tmpfs rw
8 1 0:45 / /dev/shm rw - tmpfs tmpfs rw
9 1 0:46 / /other-tmpfs rw - tmpfs tmpfs rw
`
	skipped, err := parseScanMountPoints("/", strings.NewReader(mountinfo))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/home", "/data", "/tmp", "/dev/shm"} {
		if reason := skipped[path]; reason != "" {
			t.Fatalf("local filesystem %s excluded: %s", path, reason)
		}
	}
	for path, reason := range map[string]string{"/mirror": "duplicate-local-mount:ext4", "/remote": "excluded-mount:nfs", "/var/lib/docker/overlay2": "excluded-mount:overlay", "/other-tmpfs": "excluded-mount:tmpfs"} {
		if skipped[path] != reason {
			t.Errorf("%s: got %q, want %q", path, skipped[path], reason)
		}
	}
}
