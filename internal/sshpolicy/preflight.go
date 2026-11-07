package sshpolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Check includes conservatively, including directives inside Match blocks.
// Probing only the default sshd -T context misses restrictions for other users;
// a global wrapper must not break a chroot or replace their ForceCommand.
func verifySSHDScopes(config string, data []byte, wrapper, managedDropIn string) error {
	seen := make(map[string]bool)
	remaining := 1 << 20
	var inspect func(string, []byte) error
	inspect = func(path string, content []byte) error {
		path = filepath.Clean(path)
		if seen[path] {
			return nil
		}
		seen[path] = true
		remaining -= len(content)
		if remaining < 0 || len(seen) > 64 {
			return errors.New("SSH include configuration exceeds the preflight limit")
		}
		for _, line := range strings.Split(string(content), "\n") {
			fields := activeFields(line)
			if len(fields) == 0 {
				continue
			}
			switch strings.ToLower(fields[0]) {
			case "forcecommand":
				if len(fields) != 2 || fields[1] != wrapper {
					return fmt.Errorf("existing ForceCommand in %s requires compatibility review", path)
				}
			case "chrootdirectory":
				if len(fields) != 2 || fields[1] != "none" {
					return fmt.Errorf("ChrootDirectory in %s is not supported by the SSH helper; no configuration was changed", path)
				}
			case "include":
				// Ambiguous quoting must fail before any edits, not be interpreted
				// differently from sshd and accidentally skip an included policy.
				if strings.ContainsAny(line, "\"'\\") {
					return fmt.Errorf("quoted or escaped SSH Include in %s requires compatibility review", path)
				}
				for _, pattern := range fields[1:] {
					if !filepath.IsAbs(pattern) {
						pattern = filepath.Join("/etc/ssh", pattern)
					}
					matches, err := filepath.Glob(pattern)
					if err != nil {
						return err
					}
					for _, include := range matches {
						if filepath.Clean(include) == filepath.Clean(managedDropIn) {
							continue
						}
						info, err := os.Stat(include)
						if err != nil {
							return err
						}
						if !info.Mode().IsRegular() || info.Size() > int64(remaining) {
							return fmt.Errorf("SSH include %s is not a bounded regular config file", include)
						}
						data, err := os.ReadFile(include)
						if err != nil {
							return err
						}
						if err := inspect(include, data); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	}
	return inspect(config, data)
}
