package assets

import (
	"embed"
	"io/fs"
)

//go:embed web/dist deployments/systemd/*.service bpf/gen/xdpacl_bpfel.o
var FS embed.FS

func ReadFile(name string) ([]byte, error) {
	return FS.ReadFile(name)
}

func Sub(dir string) (fs.FS, error) {
	return fs.Sub(FS, dir)
}
