// Package securestore provides small encrypted, atomically replaced files for
// NodeWall's local control-plane state. It is designed for crash recovery and
// disk-at-rest protection; a process with unrestricted root access can still
// remove both the data and its key, so cluster replicas remain part of the
// recovery design.
package securestore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	format        = "nodewall-encrypted-v1"
	backupCount   = 3
	keySize       = 32
	defaultKeyEnv = "NODEWALL_CLUSTER_KEY_FILE"
)

type envelope struct {
	Format     string `json:"format"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// KeyPath returns the configured cluster key path, or an empty path when
// plaintext compatibility is explicitly in use (primarily unit tests and
// development mode).
func KeyPath() string {
	return strings.TrimSpace(os.Getenv(defaultKeyEnv))
}

// EnsureKey creates a private random key if the path does not exist.
func EnsureKey(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("cluster key path is empty")
	}
	if data, err := os.ReadFile(path); err == nil {
		return normalizeKey(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := writeAtomic(path, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		if data, readErr := os.ReadFile(path); readErr == nil {
			return normalizeKey(data)
		}
		return nil, err
	}
	return key, nil
}

func normalizeKey(data []byte) ([]byte, error) {
	if len(data) == keySize {
		return append([]byte(nil), data...), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err == nil && len(decoded) == keySize {
		return decoded, nil
	}
	return nil, errors.New("cluster key must be 32 bytes or base64-encoded 32 bytes")
}

// Read returns the decrypted payload. If the primary file is damaged, up to
// three rotated backups are tried and recovered is set to true.
func Read(path string) (data []byte, encrypted bool, recovered bool, err error) {
	return ReadValid(path, nil)
}

// ReadValid is Read with an optional payload validator. It is useful for
// JSON-backed state because a damaged plaintext primary must not prevent trying
// an authenticated backup generation.
func ReadValid(path string, validate func([]byte) error) (data []byte, encrypted bool, recovered bool, err error) {
	keyPath := KeyPath()
	paths := append([]string{path}, backupPaths(path)...)
	var lastErr error
	for index, candidate := range paths {
		raw, readErr := os.ReadFile(candidate)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				continue
			}
			lastErr = readErr
			continue
		}
		decoded, wasEncrypted, decodeErr := decode(raw, keyPath)
		if decodeErr == nil {
			if validate != nil {
				if validateErr := validate(decoded); validateErr != nil {
					lastErr = validateErr
					continue
				}
			}
			// A valid legacy plaintext payload is also marked for rewrite when a
			// cluster key is configured, so callers transparently migrate it.
			needsRewrite := wasEncrypted || strings.TrimSpace(keyPath) != ""
			return decoded, needsRewrite, index > 0, nil
		}
		lastErr = decodeErr
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, false, false, lastErr
}

// Write atomically replaces path, rotating the previous file through three
// backups. With a cluster key configured the on-disk payload is AES-GCM
// authenticated and encrypted; without one it remains JSON-compatible.
func Write(path string, data []byte, mode os.FileMode) error {
	keyPath := KeyPath()
	encoded, err := encode(data, keyPath)
	if err != nil {
		return err
	}
	return writeWithBackups(path, encoded, mode)
}

// WritePlain preserves a legacy file format while using the same crash-safe
// replacement and backup rotation as encrypted state.
func WritePlain(path string, data []byte, mode os.FileMode) error {
	return writeWithBackups(path, data, mode)
}

func writeWithBackups(path string, data []byte, mode os.FileMode) error {
	for i := backupCount; i >= 1; i-- {
		from := path
		if i > 1 {
			from = backupPath(path, i-1)
		}
		to := backupPath(path, i)
		info, statErr := os.Stat(from)
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		_ = os.Remove(to)
		if err := os.Rename(from, to); err != nil {
			// A backup failure must not prevent the primary update; another
			// replica and the remaining backup generations still provide recovery.
			continue
		}
	}
	return writeAtomic(path, data, mode)
}

func encode(data []byte, keyPath string) ([]byte, error) {
	if strings.TrimSpace(keyPath) == "" {
		return data, nil
	}
	key, err := EnsureKey(keyPath)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return json.Marshal(envelope{Format: format, Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)})
}

func decode(raw []byte, keyPath string) ([]byte, bool, error) {
	var item envelope
	var marker map[string]json.RawMessage
	markerErr := json.Unmarshal(raw, &marker)
	_, hasFormat := marker["format"]
	_, hasNonce := marker["nonce"]
	_, hasCiphertext := marker["ciphertext"]
	if markerErr == nil && (hasFormat || hasNonce || hasCiphertext) {
		if err := json.Unmarshal(raw, &item); err != nil || item.Format != format {
			return nil, false, errors.New("invalid encrypted NodeWall file envelope")
		}
	} else if json.Unmarshal(raw, &item) != nil || item.Format != format {
		if strings.TrimSpace(keyPath) != "" {
			// A plaintext legacy file is accepted once, then rewritten by the
			// caller's normal save path using the configured cluster key.
			return raw, false, nil
		}
		return raw, false, nil
	}
	if strings.TrimSpace(keyPath) == "" {
		return nil, false, errors.New("encrypted NodeWall file requires a cluster key")
	}
	key, err := EnsureKey(keyPath)
	if err != nil {
		return nil, false, err
	}
	nonce, err := base64.StdEncoding.DecodeString(item.Nonce)
	if err != nil {
		return nil, false, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(item.Ciphertext)
	if err != nil {
		return nil, false, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt NodeWall file: %w", err)
	}
	return plaintext, true, nil
}

func backupPaths(path string) []string {
	paths := make([]string, 0, backupCount)
	for i := 1; i <= backupCount; i++ {
		paths = append(paths, backupPath(path, i))
	}
	return paths
}

func backupPath(path string, generation int) string {
	return fmt.Sprintf("%s.bak.%d", path, generation)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
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
	if err := tmp.Chmod(mode); err != nil {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
