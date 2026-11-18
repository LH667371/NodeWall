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
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id makes offline password guessing substantially more expensive for
	// attackers using GPUs/ASICs while keeping interactive login practical.
	defaultAlgorithm = "argon2id"
	defaultMemory    = 64 * 1024 // KiB
	defaultTime      = 3
	defaultThreads   = 2
	defaultKeyLength = 32
	legacyIterations = 120000
	maxPasswordBytes = 1024
)

type PasswordRecord struct {
	Salt       string    `json:"salt"`
	Hash       string    `json:"hash"`
	Iterations int       `json:"iterations"`
	Algorithm  string    `json:"algorithm,omitempty"`
	Memory     uint32    `json:"memory,omitempty"`
	Time       uint32    `json:"time,omitempty"`
	Threads    uint8     `json:"threads,omitempty"`
	KeyLength  uint32    `json:"key_length,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func NewPasswordRecord(password string) (PasswordRecord, error) {
	if len([]byte(password)) < 8 {
		return PasswordRecord{}, fmt.Errorf("password must be at least 8 bytes")
	}
	if len([]byte(password)) > maxPasswordBytes {
		return PasswordRecord{}, fmt.Errorf("password must be no more than %d bytes", maxPasswordBytes)
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return PasswordRecord{}, err
	}

	hash := argon2.IDKey([]byte(password), salt[:], defaultTime, defaultMemory, defaultThreads, defaultKeyLength)
	return PasswordRecord{
		Salt:      hex.EncodeToString(salt[:]),
		Hash:      hex.EncodeToString(hash),
		Algorithm: defaultAlgorithm,
		Memory:    defaultMemory,
		Time:      defaultTime,
		Threads:   defaultThreads,
		KeyLength: defaultKeyLength,
		UpdatedAt: time.Now().UTC(),
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
		record.Iterations = legacyIterations
	}
	return record, nil
}

func VerifyPassword(password string, record PasswordRecord) bool {
	if len([]byte(password)) > maxPasswordBytes {
		return false
	}
	salt, err := hex.DecodeString(record.Salt)
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(record.Hash)
	if err != nil {
		return false
	}
	var computed []byte
	if strings.EqualFold(record.Algorithm, defaultAlgorithm) {
		if !validArgon2Parameters(record.Memory, record.Time, record.Threads, record.KeyLength) {
			return false
		}
		computed = argon2.IDKey([]byte(password), salt, record.Time, record.Memory, record.Threads, record.KeyLength)
	} else {
		// Legacy records remain verifiable so upgrades do not lock out existing
		// installations. A successful login upgrades the record to Argon2id.
		computed = hashPassword(password, salt, record.Iterations)
	}
	return subtle.ConstantTimeCompare(expected, computed) == 1
}

func NeedsRehash(record PasswordRecord) bool {
	return !strings.EqualFold(record.Algorithm, defaultAlgorithm) ||
		record.Memory < defaultMemory || record.Time < defaultTime ||
		record.Threads < defaultThreads || record.KeyLength < defaultKeyLength
}

var dummyPasswordRecord struct {
	sync.Once
	record PasswordRecord
}

// DummyPasswordRecord gives login handlers a real password hash to verify when
// the username does not exist, reducing username-enumeration timing leaks.
func DummyPasswordRecord() PasswordRecord {
	dummyPasswordRecord.Do(func() {
		record, err := NewPasswordRecord("NodeWall-dummy-login-password")
		if err == nil {
			dummyPasswordRecord.record = record
		}
	})
	return dummyPasswordRecord.record
}

func validArgon2Parameters(memory, duration uint32, threads uint8, keyLength uint32) bool {
	return memory >= 16*1024 && memory <= 256*1024 && duration >= 1 && duration <= 10 && threads >= 1 && threads <= 8 && keyLength >= 16 && keyLength <= 64
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
