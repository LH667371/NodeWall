package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const defaultIterations = 120000

type PasswordRecord struct {
	Salt       string    `json:"salt"`
	Hash       string    `json:"hash"`
	Iterations int       `json:"iterations"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func NewPasswordRecord(password string) (PasswordRecord, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return PasswordRecord{}, err
	}

	iterations := defaultIterations
	hash := hashPassword(password, salt[:], iterations)
	return PasswordRecord{
		Salt:       hex.EncodeToString(salt[:]),
		Hash:       hex.EncodeToString(hash),
		Iterations: iterations,
		UpdatedAt:  time.Now().UTC(),
	}, nil
}

func SavePasswordFile(path string, record PasswordRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func LoadPasswordFile(path string) (PasswordRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PasswordRecord{}, err
	}
	var record PasswordRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return PasswordRecord{}, err
	}
	if record.Iterations <= 0 {
		record.Iterations = defaultIterations
	}
	return record, nil
}

func VerifyPassword(password string, record PasswordRecord) bool {
	salt, err := hex.DecodeString(record.Salt)
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(record.Hash)
	if err != nil {
		return false
	}
	computed := hashPassword(password, salt, record.Iterations)
	return subtle.ConstantTimeCompare(expected, computed) == 1
}

func hashPassword(password string, salt []byte, iterations int) []byte {
	payload := append([]byte(password), salt...)
	sum := sha256.Sum256(payload)
	digest := sum[:]

	for i := 1; i < iterations; i++ {
		payload = append(digest[:0:0], digest...)
		payload = append(payload, salt...)
		next := sha256.Sum256(payload)
		digest = next[:]
	}

	out := make([]byte, len(digest))
	copy(out, digest)
	return out
}

func EnsurePasswordFile(path string, password string) error {
	record, err := NewPasswordRecord(password)
	if err != nil {
		return fmt.Errorf("create password record: %w", err)
	}
	return SavePasswordFile(path, record)
}
