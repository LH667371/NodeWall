package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"

	"nodewall/internal/filemeta"
	"nodewall/internal/sshconsole"
)

type consoleKeyEntry struct {
	Line           string `json:"line"`
	AddedSeparator bool   `json:"added_separator,omitempty"`
}

type consoleAccessState struct {
	SSHDirCreated   bool              `json:"ssh_dir_created"`
	FileCreated     bool              `json:"file_created"`
	OriginalMode    uint32            `json:"original_mode,omitempty"`
	HasMode         bool              `json:"has_mode,omitempty"`
	OriginalDirMode uint32            `json:"original_dir_mode,omitempty"`
	HasDirMode      bool              `json:"has_dir_mode,omitempty"`
	Keys            []consoleKeyEntry `json:"keys"`
}

func configureLocalSSHAccess(keyPath string, configDirs ...string) error {
	if strings.TrimSpace(keyPath) == "" {
		return errors.New("SSH key path is empty")
	}
	publicKey, err := sshconsole.NewWithKeyPath(keyPath).PublicKey()
	if err != nil {
		return err
	}
	configDir := defaultConfigDir
	if len(configDirs) > 0 && strings.TrimSpace(configDirs[0]) != "" {
		configDir = configDirs[0]
	}
	return authorizeConsoleKey(publicKey, "/root/.ssh", configDir)
}

func authorizeConsoleKey(publicKey, sshDir, configDir string) error {
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("invalid SSH console public key")
	}
	keyText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	path := filepath.Join(sshDir, "authorized_keys")
	data, err := readRegularOptional(path)
	if err != nil {
		return err
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		existing, _, _, _, parseErr := ssh.ParseAuthorizedKey(line)
		if parseErr == nil && bytes.Equal(existing.Marshal(), key.Marshal()) {
			return nil
		}
	}
	statePath := filepath.Join(configDir, "ssh-console-access.json")
	var state consoleAccessState
	saved, err := os.ReadFile(statePath)
	if err == nil {
		if err := json.Unmarshal(saved, &state); err != nil {
			return fmt.Errorf("read SSH console recovery state: %w", err)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		dirInfo, dirErr := os.Stat(sshDir)
		fileInfo, fileErr := os.Stat(path)
		state.SSHDirCreated = errors.Is(dirErr, os.ErrNotExist)
		state.FileCreated = errors.Is(fileErr, os.ErrNotExist)
		if dirErr == nil {
			state.OriginalDirMode = uint32(dirInfo.Mode().Perm())
			state.HasDirMode = true
		}
		if fileErr == nil {
			state.OriginalMode = uint32(fileInfo.Mode().Perm())
			state.HasMode = true
		}
	} else {
		return err
	}
	entry := consoleKeyEntry{Line: keyText + " nodewall-console\n", AddedSeparator: len(data) > 0 && data[len(data)-1] != '\n'}
	state.Keys = append(state.Keys, entry)
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	// Persist recovery information before creating or modifying authorized_keys.
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(statePath, encoded, 0o600); err != nil {
		return err
	}
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		return err
	}
	if entry.AddedSeparator {
		data = append(data, '\n')
	}
	data = append(data, entry.Line...)
	if err := writeAuthorizedKeys(path, data); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func restoreConsoleAccess(sshDir, configDir, keyPath string) error {
	statePath := filepath.Join(configDir, "ssh-console-access.json")
	var state consoleAccessState
	encoded, err := os.ReadFile(statePath)
	if err == nil {
		if err := json.Unmarshal(encoded, &state); err != nil {
			return fmt.Errorf("read SSH console recovery state: %w", err)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		// Legacy installs did not record ownership. If the private key still
		// exists, include its exact entry; the reserved-comment sweep below also
		// handles removed config directories and duplicate historical keys.
		privateKey, readErr := os.ReadFile(keyPath)
		if errors.Is(readErr, os.ErrNotExist) {
			privateKey = nil
		} else if readErr != nil {
			return readErr
		} else {
			signer, parseErr := ssh.ParsePrivateKey(privateKey)
			if parseErr != nil {
				return fmt.Errorf("read legacy SSH console key: %w", parseErr)
			}
			state.Keys = []consoleKeyEntry{{Line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " nodewall-console\n"}}
		}
	} else {
		return err
	}
	path := filepath.Join(sshDir, "authorized_keys")
	data, err := readRegularOptional(path)
	if err != nil {
		return err
	}
	for _, entry := range state.Keys {
		lines := strings.SplitAfter(string(data), "\n")
		for i, line := range lines {
			if line != entry.Line {
				continue
			}
			if entry.AddedSeparator && i > 0 && strings.Join(lines[i+1:], "") == "" {
				lines[i-1] = strings.TrimSuffix(lines[i-1], "\n")
			}
			lines = append(lines[:i], lines[i+1:]...)
			data = []byte(strings.Join(lines, ""))
			break
		}
	}
	// The recovery journal was introduced after older installers had already
	// written reserved keys. During uninstall, remove every exact
	// nodewall-console entry so repeated install/uninstall cycles cannot leave
	// unusable console keys behind. This reserved comment is owned by NodeWall;
	// administrator keys with other comments are preserved.
	data = removeReservedConsoleKeys(data)
	if state.FileCreated && len(data) == 0 {
		if err := removeOptional(path); err != nil {
			return err
		}
	} else if _, err := os.Stat(path); err == nil {
		if err := writeAuthorizedKeys(path, data); err != nil {
			return err
		}
		if state.HasMode {
			if err := os.Chmod(path, os.FileMode(state.OriginalMode)); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if state.SSHDirCreated {
		// Remove only an empty directory: administrators may have added keys.
		if err := os.Remove(sshDir); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) {
			return err
		}
	} else if state.HasDirMode {
		if err := os.Chmod(sshDir, os.FileMode(state.OriginalDirMode)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return removeOptional(statePath)
}

func removeReservedConsoleKeys(data []byte) []byte {
	lines := bytes.SplitAfter(data, []byte("\n"))
	kept := make([][]byte, 0, len(lines))
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || bytes.HasPrefix(trimmed, []byte("#")) {
			kept = append(kept, line)
			continue
		}
		_, comment, _, _, err := ssh.ParseAuthorizedKey(trimmed)
		if err == nil && strings.EqualFold(strings.TrimSpace(comment), "nodewall-console") {
			continue
		}
		kept = append(kept, line)
	}
	return bytes.Join(kept, nil)
}

func readRegularOptional(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to replace non-regular file %s", path)
	}
	return os.ReadFile(path)
}

func removeOptional(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeAuthorizedKeys(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodewall-authorized-keys-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if source, err := os.Open(path); err == nil {
		defer source.Close()
		info, err := source.Stat()
		if err != nil {
			return err
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if err := tmp.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
				return err
			}
		}
		if err := tmp.Chmod(info.Mode().Perm()); err != nil {
			return err
		}
		if err := filemeta.CopyAccessAttrs(source, tmp); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
