// Package sshkeys provides the small, deliberately constrained authorized_keys
// editor used by the node agent. It only handles public keys and writes the
// file atomically so a failed management request cannot leave a partial file.
package sshkeys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"nodewall/internal/filemeta"
)

var ErrNotFound = errors.New("SSH public key was not found")

// Entry is the API-safe representation of one authorized key.
type Entry struct {
	Fingerprint         string   `json:"fingerprint"`
	Type                string   `json:"type"`
	Comment             string   `json:"comment,omitempty"`
	PublicKey           string   `json:"public_key"`
	Options             []string `json:"options,omitempty"`
	NodeWallManaged     bool     `json:"nodewall_managed,omitempty"`
	NodeWallActive      bool     `json:"nodewall_active,omitempty"`
	NodeWallActiveKnown bool     `json:"nodewall_active_known,omitempty"`
}

// FingerprintForPrivateKey reads an existing private key without creating one.
// Rendering the key list must never generate or replace a console key.
func FingerprintForPrivateKey(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("SSH private key path is required")
	}
	privatePEM, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(privatePEM)
	if err != nil {
		return "", fmt.Errorf("parse SSH private key: %w", err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey()), nil
}

// List reads a regular authorized_keys file. Missing files are treated as an
// empty list because a new server may not have created the file yet.
func List(path string) ([]Entry, error) {
	data, _, err := read(path)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0)
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}
		entry, ok, err := parseLine(line)
		if err != nil {
			return nil, err
		}
		if ok {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// Add appends a normalized public key unless the same key already exists.
// options are rejected intentionally: this endpoint manages a server access
// list and must not silently grant forced commands or tunnel permissions.
func Add(path, publicKey, comment string) (Entry, error) {
	key, parsedComment, options, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKey)))
	if err != nil {
		return Entry{}, fmt.Errorf("invalid SSH public key: %w", err)
	}
	if len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return Entry{}, errors.New("SSH public key options are not accepted; provide a plain public key")
	}
	comment = strings.TrimSpace(comment)
	if comment == "" {
		comment = strings.TrimSpace(parsedComment)
	}
	if strings.ContainsAny(comment, "\r\n") {
		return Entry{}, errors.New("SSH public key comment must be a single line")
	}
	if len(comment) > 256 {
		return Entry{}, errors.New("SSH public key comment is too long")
	}
	entry := entryFor(key, comment, nil)
	data, mode, err := read(path)
	if err != nil {
		return Entry{}, err
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}
		existing, ok, parseErr := parseLine(line)
		if parseErr != nil {
			return Entry{}, parseErr
		}
		if ok && existing.Fingerprint == entry.Fingerprint {
			return existing, nil
		}
	}
	line := entry.PublicKey
	if entry.Comment != "" {
		line += " " + entry.Comment
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, line+"\n"...)
	if err := write(path, data, mode); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// Remove deletes all entries with the requested fingerprint. Removing a
// duplicate in one operation keeps the list deterministic for administrators.
func Remove(path, fingerprint string) error {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return errors.New("SSH key fingerprint is required")
	}
	data, mode, err := read(path)
	if err != nil {
		return err
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	kept := make([][]byte, 0, len(lines))
	found := false
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || bytes.HasPrefix(trimmed, []byte("#")) {
			kept = append(kept, line)
			continue
		}
		entry, ok, parseErr := parseLine(trimmed)
		if parseErr != nil {
			return parseErr
		}
		if ok && entry.Fingerprint == fingerprint {
			found = true
			continue
		}
		kept = append(kept, line)
	}
	if !found {
		return ErrNotFound
	}
	return write(path, bytes.Join(kept, nil), mode)
}

func parseLine(line []byte) (Entry, bool, error) {
	key, comment, options, rest, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return Entry{}, false, fmt.Errorf("invalid authorized_keys entry: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return Entry{}, false, errors.New("invalid authorized_keys entry: trailing data")
	}
	return entryFor(key, strings.TrimSpace(comment), options), true, nil
}

func entryFor(key ssh.PublicKey, comment string, options []string) Entry {
	return Entry{
		Fingerprint: ssh.FingerprintSHA256(key),
		Type:        key.Type(),
		Comment:     comment,
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		Options:     append([]string(nil), options...),
	}
}

func read(path string) ([]byte, os.FileMode, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return nil, 0, errors.New("authorized_keys path must be absolute")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0o600, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("refusing to modify non-regular authorized_keys file %s", path)
	}
	data, err := os.ReadFile(path)
	return data, info.Mode().Perm(), err
}

func write(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o600
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodewall-authorized-keys-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if source, sourceErr := os.Open(path); sourceErr == nil {
		if err := filemeta.CopyAccessAttrs(source, tmp); err != nil {
			source.Close()
			_ = tmp.Close()
			return err
		}
		_ = source.Close()
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
