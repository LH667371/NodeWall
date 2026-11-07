package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"nodewall/internal/models"
)

// SSHProtectionStore persists only guard settings. Active bans remain in the
// agent runtime state so policy and temporary-block recovery stay together.
type SSHProtectionStore struct {
	mu   sync.Mutex
	path string
}

func NewSSHProtectionStore(path string) *SSHProtectionStore {
	return &SSHProtectionStore{path: path}
}

func (s *SSHProtectionStore) Save(_ context.Context, settings models.SSHProtectionSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".ssh-protection-*")
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
	return os.Rename(tmpName, s.path)
}

func (s *SSHProtectionStore) Load(_ context.Context) (models.SSHProtectionSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return models.SSHProtectionSettings{}, nil
		}
		return models.SSHProtectionSettings{}, err
	}
	var settings models.SSHProtectionSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return models.SSHProtectionSettings{}, err
	}
	return settings, nil
}
