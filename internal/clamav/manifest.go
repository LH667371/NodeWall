package clamav

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type Artifact struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Version uint64 `json:"version,omitempty"`
	Release string `json:"release,omitempty"`
}

type Manifest struct {
	Engine   Artifact   `json:"engine"`
	Database []Artifact `json:"database"`
}

var databaseNames = []string{"main", "daily", "bytecode"}

type cachedDigest struct {
	info    os.FileInfo
	digest  string
	release string
}

var digestCache sync.Map

func artifact(path, name string, database bool) (Artifact, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Artifact{}, err
	}
	if !info.Mode().IsRegular() {
		return Artifact{}, fmt.Errorf("%s is not a regular file", name)
	}
	var digest, release string
	if cached, ok := digestCache.Load(path); ok {
		value := cached.(cachedDigest)
		if os.SameFile(value.info, info) && value.info.Size() == info.Size() && value.info.ModTime().Equal(info.ModTime()) {
			digest = value.digest
			release = value.release
		}
	}
	if digest == "" {
		digest, _, err = fileDigest(path)
		if err != nil {
			return Artifact{}, err
		}
		if !database && (name == "amd64" || name == "arm64") {
			release, err = engineRelease(path)
			if err != nil {
				return Artifact{}, err
			}
		}
		digestCache.Store(path, cachedDigest{info: info, digest: digest, release: release})
	}
	result := Artifact{Name: name, SHA256: digest, Size: info.Size(), Release: release}
	if database {
		result.Version, err = databaseVersion(path)
	}
	return result, err
}

func databaseVersion(path string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, 512))
	header, err := reader.ReadString(':')
	if err != nil || header != "ClamAV-VDB:" {
		return 0, errors.New("invalid ClamAV database header")
	}
	if _, err = reader.ReadString(':'); err != nil {
		return 0, errors.New("invalid ClamAV database timestamp")
	}
	version, err := reader.ReadString(':')
	if err != nil {
		return 0, errors.New("invalid ClamAV database version")
	}
	result, err := strconv.ParseUint(strings.TrimSuffix(version, ":"), 10, 64)
	if err != nil || result == 0 {
		return 0, errors.New("invalid ClamAV database version")
	}
	return result, nil
}

func databasePath(dir, name string) (string, error) {
	if !validDatabaseName(name) {
		return "", errors.New("invalid ClamAV database name")
	}
	for _, suffix := range []string{".cld", ".cvd"} {
		path := filepath.Join(dir, name+suffix)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("ClamAV database %s is missing", name)
}

func validDatabaseName(name string) bool {
	for _, allowed := range databaseNames {
		if name == allowed {
			return true
		}
	}
	return false
}

// CurrentManifest publishes only a complete local set. Clients always check
// the digest again after download, including when an update races a request.
func CurrentManifest(assets, data, arch string) (Manifest, error) {
	if arch != "amd64" && arch != "arm64" {
		return Manifest{}, errors.New("unsupported ClamAV architecture")
	}
	engine, err := artifact(filepath.Join(assets, "engines", arch+".tar.gz"), arch, false)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{Engine: engine}
	for _, name := range databaseNames {
		path, err := publishedDatabasePath(assets, data, name)
		if err != nil {
			return Manifest{}, err
		}
		item, err := artifact(path, filepath.Base(path), true)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Database = append(manifest.Database, item)
	}
	return manifest, nil
}

// PublishedFile resolves a fixed logical name and requires the digest requested
// by the client. A generation change therefore triggers a retry, never a
// partially mixed database set.
func PublishedFile(assets, data, kind, name, digest string) (string, error) {
	var path string
	switch kind {
	case "engine":
		if name != "amd64" && name != "arm64" {
			return "", errors.New("invalid engine architecture")
		}
		path = filepath.Join(assets, "engines", name+".tar.gz")
	case "database":
		base := strings.TrimSuffix(strings.TrimSuffix(name, ".cvd"), ".cld")
		if !validDatabaseName(base) || (name != base+".cvd" && name != base+".cld") {
			return "", errors.New("invalid database name")
		}
		path, err := publishedDatabasePath(assets, data, base)
		if err != nil {
			return "", err
		}
		if filepath.Base(path) != name {
			return "", errors.New("ClamAV artifact changed; retry the manifest")
		}
		return publishedArtifact(path, name, digest)
	default:
		return "", errors.New("invalid ClamAV artifact type")
	}
	return publishedArtifact(path, name, digest)
}

func publishedArtifact(path, name, digest string) (string, error) {
	item, err := artifact(path, name, false)
	if err != nil {
		return "", err
	}
	if item.SHA256 != digest {
		return "", errors.New("ClamAV artifact changed; retry the manifest")
	}
	return path, nil
}

// A freshly installed offline bundle is distributable before clamd has loaded
// it. Receivers still verify CVD signatures and load the full set before use.
// Compare each database separately so an upgraded bundle is visible even while
// the local daemon is still using a previous generation.
func publishedDatabasePath(assets, data, name string) (string, error) {
	current, currentErr := databasePath(filepath.Join(data, "current"), name)
	var currentVersion uint64
	if currentErr == nil {
		currentVersion, currentErr = databaseVersion(current)
	}
	bundled, bundledErr := databasePath(filepath.Join(assets, "database"), name)
	if bundledErr == nil {
		version, err := databaseVersion(bundled)
		if err == nil && (currentErr != nil || version > currentVersion) {
			return bundled, nil
		}
	}
	if currentErr != nil {
		return "", currentErr
	}
	return current, nil
}
