package assets

import (
	"embed"
	"io/fs"
)

//go:embed web/dist deployments/systemd/*.service bpf/gen/xdpacl_bpfel.o
var FS embed.FS

// ReleaseVersion is embedded from the repository's single product version file.
//
//go:embed VERSION
var ReleaseVersion string

func ReadFile(name string) ([]byte, error) {
	return FS.ReadFile(name)
}

func Sub(dir string) (fs.FS, error) {
	return fs.Sub(FS, dir)
}
