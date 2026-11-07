package version

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	AppVersion     = "dev"
	PackageVersion = "dev"
)

type Info struct {
	AppVersion     string `json:"app_version"`
	PackageVersion string `json:"package_version"`
}

func Current() Info {
	app := strings.TrimSpace(AppVersion)
	pkg := strings.TrimSpace(PackageVersion)
	if app == "" || app == "dev" {
		if v, ok := readVersionFile("VERSION"); ok {
			app = v
		}
	}
	if pkg == "" || pkg == "dev" {
		if v, ok := readVersionFile("PACKAGE_VERSION"); ok {
			pkg = v
		}
	}
	if app == "" {
		app = "dev"
	}
	if pkg == "" {
		pkg = app
	}
	return Info{AppVersion: app, PackageVersion: pkg}
}

func WriteInstallFiles(installDir string) error {
	info := Current()
	if err := writeFileAtomic(filepath.Join(installDir, "VERSION"), []byte(info.AppVersion+"\n"), 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(installDir, "PACKAGE_VERSION"), []byte(info.PackageVersion+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}

func String() string {
	info := Current()
	return fmt.Sprintf("app=%s package=%s", info.AppVersion, info.PackageVersion)
}

func readVersionFile(name string) (string, bool) {
	candidates := []string{
		filepath.Join("/opt/nodewall", name),
		filepath.Join(exeDir(), "..", name),
		name,
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(data))
		if value != "" {
			return value, true
		}
	}
	return "", false
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
