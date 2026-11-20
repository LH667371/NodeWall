package droplog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/securestore"
	"nodewall/internal/xdp"
)

type Recorder struct {
	mu        sync.RWMutex
	logDir    string
	statePath string
	settings  models.DropLogSettings
	lastSeen  map[string]uint64
	epochs    map[string]string
	packetMu  sync.Mutex
	packets   map[packetAuditKey]models.DropLogRecord
	auditOn   bool
}

type persistedState struct {
	Settings models.DropLogSettings `json:"settings"`
	LastSeen map[string]uint64      `json:"last_seen"`
	Epochs   map[string]string      `json:"counter_epochs,omitempty"`
}

func New(logDir, statePath string, defaults models.DropLogSettings) (*Recorder, error) {
	r := &Recorder{
		logDir:    logDir,
		statePath: statePath,
		settings:  normalizeSettings(defaults),
		lastSeen:  make(map[string]uint64),
		epochs:    make(map[string]string),
	}
	err := r.load()
	r.auditOn = r.settings.Enabled
	if err != nil {
		return r, fmt.Errorf("load drop log state %s: %w", statePath, err)
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
	r.packetMu.Lock()
	r.auditOn = r.settings.Enabled
	if !r.auditOn {
		clear(r.packets)
	}
	r.packetMu.Unlock()
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
	if err := r.flushPackets(now); err != nil {
		return err
	}
	directions := []models.PolicyDirection{models.DirectionIngress}
	directional, hasDirection := dp.(xdp.DirectionalStats)
	if hasDirection {
		directions = append(directions, models.DirectionEgress)
	}
	var readErrors []error
	for _, iface := range dp.Interfaces() {
		for _, direction := range directions {
			var items []models.InterceptLogEntry
			var err error
			if direction == models.DirectionEgress {
				items, err = directional.ReadDirectionDropLogs(iface, direction, 256)
			} else {
				items, err = dp.ReadDropLogs(iface, 256)
			}
			if err != nil {
				if !xdp.IsNotAttached(err) {
					readErrors = append(readErrors, fmt.Errorf("read %s firewall counters for %s: %w", direction, iface, err))
				}
				continue
			}
			if err := r.persistCounters(now, iface, direction, items); err != nil {
				return errors.Join(errors.Join(readErrors...), err, r.saveLocked())
			}
		}
	}
	return errors.Join(errors.Join(readErrors...), pruneFiles(r.logDir, settings.RetentionDays, now), r.saveLocked())
}

func (r *Recorder) persistCounters(now time.Time, iface string, direction models.PolicyDirection, items []models.InterceptLogEntry) error {
	path := filepath.Join(r.logDir, fileNameFor(now))
	for _, item := range items {
		key := counterKey(iface, direction, item)
		prev := r.lastSeen[key]
		current := itemCount(item)
		sameCounter := r.epochs[key] == item.CounterEpoch
		if current == 0 || (sameCounter && current == prev) {
			continue
		}
		delta := current
		if sameCounter && current > prev {
			delta -= prev
		}
		record := models.DropLogRecord{
			Timestamp:  now,
			Interface:  iface,
			Direction:  direction,
			SourceIP:   item.SourceIP,
			SourceCIDR: item.SourceCIDR,
			Port:       item.Port,
			Reason:     item.Reason,
			Count:      delta,
			Traffic:    item.Traffic,
		}
		if item.Drops > 0 {
			record.Drops = delta
		}
		if err := appendJSONL(path, record); err != nil {
			return err
		}
		r.lastSeen[key] = current
		if item.CounterEpoch != "" {
			r.epochs[key] = item.CounterEpoch
		} else {
			delete(r.epochs, key)
		}
	}
	return nil
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
	clear(r.epochs)
	r.packetMu.Lock()
	clear(r.packets)
	r.packetMu.Unlock()
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
	var state persistedState
	_, _, _, err := securestore.ReadValid(r.statePath, func(data []byte) error {
		var candidate persistedState
		if err := json.Unmarshal(data, &candidate); err != nil {
			return err
		}
		state = candidate
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if state.Settings.LogDir != "" {
		r.settings = normalizeSettings(state.Settings)
		r.logDir = r.settings.LogDir
	}
	if state.LastSeen != nil {
		r.lastSeen = state.LastSeen
	}
	if state.Epochs != nil {
		r.epochs = state.Epochs
	}
	return nil
}

func (r *Recorder) saveLocked() error {
	if err := os.MkdirAll(r.logDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(persistedState{
		Settings: r.settings,
		LastSeen: r.lastSeen,
		Epochs:   r.epochs,
	}, "", "  ")
	if err != nil {
		return err
	}
	return securestore.WritePlain(r.statePath, data, 0o644)
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

func counterKey(iface string, direction models.PolicyDirection, item models.InterceptLogEntry) string {
	key := fmt.Sprintf("%s|%s|%d|%s", iface, item.SourceIP+item.SourceCIDR, item.Port, item.Reason)
	// Preserve ingress checkpoints written before egress was archived.
	if direction == models.DirectionEgress {
		key += "|egress"
	}
	if item.Drops == 0 && item.Count > 0 {
		key += "|observed"
	}
	return key
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
