package cli

import "testing"

func TestRemoteMountFromMountInfoSelectsDeepestMount(t *testing.T) {
	mountInfo := "" +
		"30 1 0:30 / / rw,relatime - ext4 /dev/sda rw\n" +
		"31 30 0:31 / /srv rw,relatime - nfs4 10.0.0.2:/srv rw\n" +
		"32 31 0:32 / /srv/nodewall rw,relatime - ext4 /dev/loop0 rw\n"
	if got, fs := remoteMountFromMountInfo("/srv/nodewall/bin/nodewall", mountInfo); got != "/srv/nodewall" || fs != "ext4" {
		t.Fatalf("remoteMountFromMountInfo() = %q, %q; want deepest mount", got, fs)
	}
	if got, fs := remoteMountFromMountInfo("/srv/shared/data", mountInfo); got != "/srv" || fs != "nfs4" {
		t.Fatalf("remoteMountFromMountInfo() = %q, %q; want NFS mount", got, fs)
	}
}

func TestIsRemoteFilesystem(t *testing.T) {
	for _, fs := range []string{"nfs", "nfs4", "cifs", "smb3", "sshfs", "9p"} {
		if !isRemoteFilesystem(fs) {
			t.Fatalf("isRemoteFilesystem(%q) = false", fs)
		}
	}
	for _, fs := range []string{"ext4", "xfs", "overlay", "tmpfs"} {
		if isRemoteFilesystem(fs) {
			t.Fatalf("isRemoteFilesystem(%q) = true", fs)
		}
	}
}
