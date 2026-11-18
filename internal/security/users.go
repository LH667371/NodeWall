package security

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"nodewall/internal/securestore"
)

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

type UserRecord struct {
	Username      string         `json:"username"`
	Role          string         `json:"role"`
	Enabled       bool           `json:"enabled"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	MFA           MFAMethods     `json:"mfa,omitempty"`
	Password      PasswordRecord `json:"password"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	LastLogin     *time.Time     `json:"last_login,omitempty"`
}

// MFAMethods is kept inside the encrypted user store. OTP secrets are never
// returned by API responses; passkey records contain only public credential
// material and ceremony metadata, never an authenticator private key.
type MFAMethods struct {
	OTPSecret          string              `json:"otp_secret,omitempty"`
	OTPEnabled         bool                `json:"otp_enabled,omitempty"`
	OTPVerifiedAt      *time.Time          `json:"otp_verified_at,omitempty"`
	RecoveryCodeHashes []string            `json:"recovery_code_hashes,omitempty"`
	Passkeys           []PasskeyCredential `json:"passkeys,omitempty"`
}

type PasskeyCredential struct {
	ID             string     `json:"id"`
	Name           string     `json:"name,omitempty"`
	CredentialJSON string     `json:"credential_json"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

type UserStore struct {
	Users []UserRecord `json:"users"`
}

func NormalizeRole(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case RoleAdmin:
		return RoleAdmin
	case RoleOperator:
		return RoleOperator
	default:
		return RoleViewer
	}
}

func (s *UserStore) Find(username string) (*UserRecord, int) {
	name := strings.TrimSpace(strings.ToLower(username))
	for i := range s.Users {
		if strings.ToLower(strings.TrimSpace(s.Users[i].Username)) == name {
			return &s.Users[i], i
		}
	}
	return nil, -1
}

func LoadUserStore(path string) (UserStore, error) {
	data, encrypted, recovered, err := securestore.ReadValid(path, validateUserPayload)
	if err != nil {
		return UserStore{}, err
	}

	var store UserStore
	if err := json.Unmarshal(data, &store); err == nil && len(store.Users) > 0 {
		for i := range store.Users {
			store.Users[i].Role = NormalizeRole(store.Users[i].Role)
			if store.Users[i].Username == "" {
				store.Users[i].Username = "admin"
			}
		}
		if encrypted || recovered {
			if err := SaveUserStore(path, store); err != nil {
				return UserStore{}, err
			}
		}
		return store, nil
	}

	// Backward compatibility: legacy single-password file.
	var legacy PasswordRecord
	if err := json.Unmarshal(data, &legacy); err == nil && legacy.Hash != "" {
		now := time.Now().UTC()
		store := UserStore{
			Users: []UserRecord{{
				Username:  "admin",
				Role:      RoleAdmin,
				Enabled:   true,
				Password:  legacy,
				CreatedAt: now,
				UpdatedAt: now,
			}},
		}
		if encrypted || recovered {
			if err := SaveUserStore(path, store); err != nil {
				return UserStore{}, err
			}
		}
		return store, nil
	}

	return UserStore{}, errors.New("invalid user store format")
}

func SaveUserStore(path string, store UserStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return securestore.Write(path, data, 0o600)
}

func validateUserPayload(data []byte) error {
	var store UserStore
	if err := json.Unmarshal(data, &store); err == nil && len(store.Users) > 0 {
		return nil
	}
	var legacy PasswordRecord
	if err := json.Unmarshal(data, &legacy); err == nil && strings.TrimSpace(legacy.Hash) != "" {
		return nil
	}
	return errors.New("invalid user store format")
}

func EnsureAdminUser(path, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		username = "admin"
	}
	role := RoleAdmin
	now := time.Now().UTC()

	store, err := LoadUserStore(path)
	if err != nil {
		if !os.IsNotExist(err) {
			// if legacy parsing failed, overwrite with explicit admin bootstrap
		}
		record, err := NewPasswordRecord(password)
		if err != nil {
			return err
		}
		return SaveUserStore(path, UserStore{
			Users: []UserRecord{{
				Username:  username,
				Role:      role,
				Enabled:   true,
				Password:  record,
				CreatedAt: now,
				UpdatedAt: now,
			}},
		})
	}

	user, idx := store.Find(username)
	if user == nil {
		record, err := NewPasswordRecord(password)
		if err != nil {
			return err
		}
		store.Users = append(store.Users, UserRecord{
			Username:  username,
			Role:      role,
			Enabled:   true,
			Password:  record,
			CreatedAt: now,
			UpdatedAt: now,
		})
		return SaveUserStore(path, store)
	}
	record, err := NewPasswordRecord(password)
	if err != nil {
		return err
	}
	user.Role = role
	user.Enabled = true
	user.Password = record
	user.UpdatedAt = now
	store.Users[idx] = *user
	return SaveUserStore(path, store)
}
