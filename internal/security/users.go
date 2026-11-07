package security

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

type UserRecord struct {
	Username  string         `json:"username"`
	Role      string         `json:"role"`
	Enabled   bool           `json:"enabled"`
	Password  PasswordRecord `json:"password"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	LastLogin *time.Time     `json:"last_login,omitempty"`
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
	data, err := os.ReadFile(path)
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
		return store, nil
	}

	// Backward compatibility: legacy single-password file.
	var legacy PasswordRecord
	if err := json.Unmarshal(data, &legacy); err == nil && legacy.Hash != "" {
		now := time.Now().UTC()
		return UserStore{
			Users: []UserRecord{{
				Username:  "admin",
				Role:      RoleAdmin,
				Enabled:   true,
				Password:  legacy,
				CreatedAt: now,
				UpdatedAt: now,
			}},
		}, nil
	}

	return UserStore{}, errors.New("invalid user store format")
}

func SaveUserStore(path string, store UserStore) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
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
