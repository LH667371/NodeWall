package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"nodewall/internal/models"
)

type FileStateStore struct {
	path string
}

func NewFileStateStore(path string) *FileStateStore {
	return &FileStateStore{path: path}
}

func (s *FileStateStore) Save(_ context.Context, runtimes map[string]models.InterfaceRuntime) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(runtimes, "", "  ")
	if err != nil {
		return err
	}

	file, err := os.CreateTemp(filepath.Dir(s.path), ".agent-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), s.path)
}

func (s *FileStateStore) Load(_ context.Context) (map[string]models.InterfaceRuntime, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]models.InterfaceRuntime{}, nil
		}
		return nil, err
	}

	out := make(map[string]models.InterfaceRuntime)
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}
