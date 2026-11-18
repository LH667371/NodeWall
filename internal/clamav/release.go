package clamav

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Existing offline archives already contain apk's package inventory. Derive
// the engine release from it so upgrades also work with previously installed
// bundles, without using file timestamps that differ between cluster nodes.
func engineRelease(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	reader := tar.NewReader(io.LimitReader(gz, 512<<20+1))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return "", nil // Compatibility with older bundles without metadata.
		}
		if err != nil {
			return "", err
		}
		if filepath.Clean(header.Name) != "PACKAGES.txt" || header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size > 64<<10 {
			return "", errors.New("ClamAV package inventory exceeds size limit")
		}
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			if release, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "clamav-libs-"); ok {
				// apk info -vv appends a human-readable package description.
				fields := strings.Fields(release)
				if len(fields) == 0 {
					return "", errors.New("invalid ClamAV engine release")
				}
				release = fields[0]
				if _, valid := parseEngineRelease(release); !valid {
					return "", errors.New("invalid ClamAV engine release")
				}
				return release, nil
			}
		}
		return "", scanner.Err()
	}
}

func parseEngineRelease(value string) ([4]uint64, bool) {
	var result [4]uint64
	version, revision, hasRevision := strings.Cut(value, "-r")
	parts := strings.Split(version, ".")
	if len(parts) != 3 || (hasRevision && revision == "") {
		return result, false
	}
	if hasRevision {
		parts = append(parts, revision)
	}
	for i, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return result, false
		}
		var err error
		result[i], err = strconv.ParseUint(part, 10, 32)
		if err != nil {
			return result, false
		}
	}
	return result, true
}

func newerEngine(current, candidate Artifact) bool {
	if current.SHA256 == "" {
		return true
	}
	left, leftOK := parseEngineRelease(current.Release)
	right, rightOK := parseEngineRelease(candidate.Release)
	if !rightOK {
		return false
	}
	if !leftOK {
		return true
	}
	for i := range left {
		if left[i] != right[i] {
			return right[i] > left[i]
		}
	}
	// Rebuilt archives of the same release can have different gzip digests.
	// Retaining the local one prevents peers from continuously replacing them.
	return false
}
