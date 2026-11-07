// Package integrity builds and compares SHA-256 file manifests.
package integrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxFiles    = 200000
	maxFileSize = 256 << 20
)

type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
}

type Manifest struct {
	Version   int       `json:"version"`
	Paths     []string  `json:"paths"`
	CreatedAt time.Time `json:"created_at"`
	Entries   []Entry   `json:"entries"`
	Skipped   int       `json:"skipped,omitempty"`
}

type Difference struct {
	CheckedAt time.Time `json:"checked_at"`
	Added     []Entry   `json:"added"`
	Changed   []Entry   `json:"changed"`
	Deleted   []Entry   `json:"deleted"`
}

func Build(ctx context.Context, paths []string) (Manifest, error) {
	roots, err := normalizePaths(paths)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{Version: 1, Paths: roots, CreatedAt: time.Now().UTC(), Entries: make([]Entry, 0)}
	seen := make(map[string]struct{})
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return Manifest{}, fmt.Errorf("stat integrity path %q: %w", root, err)
		}
		walkErr := filepath.WalkDir(root, func(path string, item os.DirEntry, err error) error {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if err != nil {
				if errors.Is(err, os.ErrPermission) && item != nil && item.IsDir() {
					manifest.Skipped++
					return filepath.SkipDir
				}
				manifest.Skipped++
				return nil
			}
			if item.IsDir() {
				if isVirtualDirectory(path) {
					manifest.Skipped++
					return filepath.SkipDir
				}
				return nil
			}
			if item.Type()&os.ModeSymlink != 0 || !item.Type().IsRegular() {
				manifest.Skipped++
				return nil
			}
			clean := filepath.Clean(path)
			if _, ok := seen[clean]; ok {
				return nil
			}
			if len(manifest.Entries) >= maxFiles {
				return filepath.SkipAll
			}
			entry, ok, err := hashFile(clean)
			if err != nil {
				manifest.Skipped++
				return nil
			}
			if !ok {
				manifest.Skipped++
				return nil
			}
			seen[clean] = struct{}{}
			manifest.Entries = append(manifest.Entries, entry)
			return nil
		})
		if walkErr != nil {
			return Manifest{}, walkErr
		}
		_ = info
	}
	sort.Slice(manifest.Entries, func(i, j int) bool { return manifest.Entries[i].Path < manifest.Entries[j].Path })
	return manifest, nil
}

// NormalizePaths validates and deduplicates configured integrity roots without
// touching the filesystem. The baseline operation performs the existence
// check when it actually starts hashing files.
func NormalizePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	return normalizePaths(paths)
}

func Compare(base, current Manifest) Difference {
	previous := make(map[string]Entry, len(base.Entries))
	for _, entry := range base.Entries {
		previous[entry.Path] = entry
	}
	currentEntries := make(map[string]Entry, len(current.Entries))
	result := Difference{CheckedAt: time.Now().UTC(), Added: make([]Entry, 0), Changed: make([]Entry, 0), Deleted: make([]Entry, 0)}
	for _, entry := range current.Entries {
		currentEntries[entry.Path] = entry
		old, ok := previous[entry.Path]
		if !ok {
			result.Added = append(result.Added, entry)
		} else if old.SHA256 != entry.SHA256 || old.Size != entry.Size || old.Mode != entry.Mode {
			result.Changed = append(result.Changed, entry)
		}
	}
	for _, entry := range base.Entries {
		if _, ok := currentEntries[entry.Path]; !ok {
			result.Deleted = append(result.Deleted, entry)
		}
	}
	return result
}

func Save(path string, manifest Manifest) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("integrity manifest path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodewall-integrity-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Manifest{}, nil
		}
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func normalizePaths(paths []string) ([]string, error) {
	unique := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, raw := range paths {
		path := filepath.Clean(strings.TrimSpace(raw))
		if path == "." || !filepath.IsAbs(path) {
			return nil, fmt.Errorf("integrity path %q must be absolute", raw)
		}
		if _, ok := unique[path]; ok {
			continue
		}
		unique[path] = struct{}{}
		result = append(result, path)
	}
	if len(result) == 0 {
		return nil, errors.New("at least one integrity path is required")
	}
	sort.Strings(result)
	return result, nil
}

func hashFile(path string) (Entry, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Entry{}, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return Entry{}, false, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return Entry{}, false, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return Entry{}, false, err
	}
	return Entry{Path: path, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: info.Size(), Mode: info.Mode().Perm().String()}, true, nil
}

func isVirtualDirectory(path string) bool {
	clean := filepath.Clean(path)
	for _, prefix := range []string{"/proc", "/sys", "/dev", "/run"} {
		if clean == prefix || strings.HasPrefix(clean, prefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
