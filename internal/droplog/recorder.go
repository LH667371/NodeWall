package droplog

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/xdp"
)

type Recorder struct {
	mu        sync.RWMutex
	logDir    string
	statePath string
	settings  models.DropLogSettings
	lastSeen  map[string]uint64
}

type persistedState struct {
	Settings models.DropLogSettings `json:"settings"`
	LastSeen map[string]uint64      `json:"last_seen"`
}

func New(logDir, statePath string, defaults models.DropLogSettings) (*Recorder, error) {
	r := &Recorder{
		logDir:    logDir,
		statePath: statePath,
		settings:  normalizeSettings(defaults),
		lastSeen:  make(map[string]uint64),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Recorder) Settings() models.DropLogSettings {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.settings
}

func (r *Recorder) UpdateSettings(settings models.DropLogSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings = normalizeSettings(settings)
	r.logDir = r.settings.LogDir
	return r.saveLocked()
}

func (r *Recorder) Flush(dp xdp.Dataplane) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	settings := r.settings
	if !settings.Enabled {
		return r.saveLocked()
	}
	now := time.Now().UTC()
	for _, iface := range dp.Interfaces() {
		items, err := dp.ReadDropLogs(iface, 256)
		if err != nil {
			if xdp.IsNotAttached(err) {
				continue
			}
			return err
		}
		for _, item := range items {
			key := counterKey(iface, item)
			prev := r.lastSeen[key]
			current := itemCount(item)
			if current <= prev {
				continue
			}
			delta := current - prev
			record := models.DropLogRecord{
				Timestamp: now,
				Interface: iface,
				Direction: models.DirectionIngress,
				SourceIP:  item.SourceIP,
				Port:      item.Port,
				Reason:    item.Reason,
				Count:     delta,
			}
			if item.Drops > 0 {
				record.Drops = delta
			}
			if err := appendJSONL(filepath.Join(r.logDir, fileNameFor(now)), record); err != nil {
				return err
			}
			r.lastSeen[key] = current
		}
	}
	if err := pruneFiles(r.logDir, settings.RetentionDays, now); err != nil {
		return err
	}
	return r.saveLocked()
}

func (r *Recorder) Recent(limit int) ([]models.DropLogRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}
	files, err := os.ReadDir(r.logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []models.DropLogRecord{}, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), "drop-") || !strings.HasSuffix(file.Name(), ".jsonl") {
			continue
		}
		names = append(names, filepath.Join(r.logDir, file.Name()))
	}
	slices.Sort(names)
	slices.Reverse(names)

	out := make([]models.DropLogRecord, 0, limit)
	for _, path := range names {
		records, err := readJSONL(path)
		if err != nil {
			return nil, err
		}
		for i := len(records) - 1; i >= 0; i-- {
			out = append(out, records[i])
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

func (r *Recorder) Clear() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	files, err := os.ReadDir(r.logDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), "drop-") || !strings.HasSuffix(file.Name(), ".jsonl") {
			continue
		}
		if err := os.Remove(filepath.Join(r.logDir, file.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	r.lastSeen = make(map[string]uint64)
	return r.saveLocked()
}

func (r *Recorder) Run(ctx context.Context, dp xdp.Dataplane) {
	ticker := time.NewTicker(time.Duration(r.Settings().FlushIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Flush(dp); err != nil {
				log.Printf("warning: drop log flush failed: %v", err)
			}
			ticker.Reset(time.Duration(r.Settings().FlushIntervalSeconds) * time.Second)
		}
	}
}

func (r *Recorder) load() error {
	data, err := os.ReadFile(r.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.Settings.LogDir != "" {
		r.settings = normalizeSettings(state.Settings)
		r.logDir = r.settings.LogDir
	}
	if state.LastSeen != nil {
		r.lastSeen = state.LastSeen
	}
	return nil
}

func (r *Recorder) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(r.statePath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(r.logDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(persistedState{
		Settings: r.settings,
		LastSeen: r.lastSeen,
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.statePath), filepath.Base(r.statePath)+".tmp.*")
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
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, r.statePath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func normalizeSettings(settings models.DropLogSettings) models.DropLogSettings {
	if strings.TrimSpace(settings.LogDir) == "" {
		settings.LogDir = "/var/lib/nodewall/logs"
	}
	if settings.RetentionDays <= 0 {
		settings.RetentionDays = 7
	}
	if settings.FlushIntervalSeconds <= 0 {
		settings.FlushIntervalSeconds = 30
	}
	if settings.ReplyFlowTimeoutSeconds <= 0 {
		settings.ReplyFlowTimeoutSeconds = 60
	}
	if settings.ReplyFlowTimeoutSeconds > 255 {
		settings.ReplyFlowTimeoutSeconds = 255
	}
	return settings
}

func counterKey(iface string, item models.InterceptLogEntry) string {
	return fmt.Sprintf("%s|%s|%d|%s", iface, item.SourceIP, item.Port, item.Reason)
}

func itemCount(item models.InterceptLogEntry) uint64 {
	if item.Count > 0 {
		return item.Count
	}
	return item.Drops
}

func fileNameFor(now time.Time) string {
	return fmt.Sprintf("drop-%s.jsonl", now.Format("2006-01-02"))
}

func appendJSONL(path string, record models.DropLogRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	return err
}

func readJSONL(path string) ([]models.DropLogRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := make([]models.DropLogRecord, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item models.DropLogRecord
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func pruneFiles(logDir string, retentionDays int, now time.Time) error {
	files, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cutoff := now.AddDate(0, 0, -retentionDays)
	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), "drop-") || !strings.HasSuffix(file.Name(), ".jsonl") {
			continue
		}
		dateText := strings.TrimSuffix(strings.TrimPrefix(file.Name(), "drop-"), ".jsonl")
		day, err := time.Parse("2006-01-02", dateText)
		if err != nil {
			continue
		}
		if day.Before(cutoff) {
			_ = os.Remove(filepath.Join(logDir, file.Name()))
		}
	}
	return nil
}
