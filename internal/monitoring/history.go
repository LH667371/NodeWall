package monitoring

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
)

const HistoryRetention = 7 * 24 * time.Hour

type historySegment struct {
	name string
	at   time.Time
	size int64
}

// History stores hourly append-only segments. Queries stream from disk instead
// of loading a week of metrics into memory; only chart-sized buckets are kept.
type History struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	segments []historySegment
	bytes    int64
	prepared string
}

func OpenHistory(dir string, maxBytes int64) (*History, error) {
	if maxBytes <= 0 {
		return nil, errors.New("monitoring history byte limit must be positive")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	h := &History{dir: dir, maxBytes: maxBytes}
	for _, entry := range entries {
		at, err := time.Parse("20060102T15.jsonl", entry.Name())
		if err != nil {
			continue // Never prune unrelated files placed in the data directory.
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("monitoring segment %q is not a regular file", entry.Name())
		}
		h.segments = append(h.segments, historySegment{entry.Name(), at, info.Size()})
		h.bytes += info.Size()
	}
	sort.Slice(h.segments, func(i, j int) bool { return h.segments[i].at.Before(h.segments[j].at) })
	return h, h.prune(time.Now().UTC(), "", 0)
}

// Append fsyncs each sample. A partial last line left by a crash is truncated
// before the next append, so one interrupted write cannot poison later samples.
func (h *History) Append(point models.SystemMetricPoint) error {
	if strings.TrimSpace(point.NodeID) == "" || point.Timestamp.IsZero() {
		return errors.New("monitoring sample requires a node and timestamp")
	}
	data, err := json.Marshal(point)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	now := time.Now().UTC()
	if point.Timestamp.Before(now.Add(-HistoryRetention)) || point.Timestamp.After(now.Add(time.Minute)) {
		return errors.New("monitoring sample timestamp is outside the retention window")
	}
	name := point.Timestamp.UTC().Format("20060102T15.jsonl")
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.prune(now, name, int64(len(data))); err != nil {
		return err
	}
	path := filepath.Join(h.dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if h.prepared != name {
		if err := repairHistoryTail(file, info.Size()); err != nil {
			return err
		}
		h.prepared = name
	}
	start, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Truncate(start)
		return err
	}
	if err := file.Sync(); err != nil {
		h.prepared = ""
		return err
	}
	for i := range h.segments {
		if h.segments[i].name == name {
			h.bytes += start + int64(len(data)) - h.segments[i].size
			h.segments[i].size = start + int64(len(data))
			return nil
		}
	}
	h.segments = append(h.segments, historySegment{name, point.Timestamp.UTC().Truncate(time.Hour), start + int64(len(data))})
	sort.Slice(h.segments, func(i, j int) bool { return h.segments[i].at.Before(h.segments[j].at) })
	h.bytes += start + int64(len(data))
	dir, err := os.Open(h.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func repairHistoryTail(file *os.File, size int64) error {
	if size == 0 {
		return nil
	}
	tail := make([]byte, min(size, 64<<10))
	if _, err := file.ReadAt(tail, size-int64(len(tail))); err != nil {
		return err
	}
	if tail[len(tail)-1] == '\n' {
		return nil
	}
	last := bytes.LastIndexByte(tail, '\n')
	if last < 0 && size > int64(len(tail)) {
		return errors.New("monitoring segment has an oversized incomplete record")
	}
	return file.Truncate(size - int64(len(tail)) + int64(last+1))
}

func (h *History) prune(now time.Time, active string, incoming int64) error {
	if incoming > h.maxBytes {
		return errors.New("monitoring sample exceeds the history storage quota")
	}
	cutoff := now.Add(-HistoryRetention).Truncate(time.Hour)
	for len(h.segments) > 0 {
		segment := h.segments[0]
		if !segment.at.Before(cutoff) && h.bytes+incoming <= h.maxBytes {
			break
		}
		if segment.name == active {
			return errors.New("monitoring history quota exhausted by the current hourly segment")
		}
		if err := os.Remove(filepath.Join(h.dir, segment.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		h.bytes -= segment.size
		h.segments = h.segments[1:]
	}
	if h.bytes+incoming > h.maxBytes {
		return errors.New("monitoring sample exceeds the history storage quota")
	}
	return nil
}

// Query returns the last real sample in each time bucket, not interpolated or
// zero-filled values. Offline nodes therefore leave gaps instead of fake zeros.
func (h *History) Query(ctx context.Context, nodes []string, from, to time.Time, step time.Duration) (map[string][]models.SystemMetricPoint, error) {
	if step < time.Second || !to.After(from) {
		return nil, errors.New("invalid monitoring history interval")
	}
	h.mu.Lock()
	segments := append([]historySegment(nil), h.segments...)
	h.mu.Unlock()
	selected := make(map[string]map[int64]models.SystemMetricPoint, len(nodes))
	for _, node := range nodes {
		selected[node] = make(map[int64]models.SystemMetricPoint)
	}
	for _, segment := range segments {
		if segment.at.After(to) || !segment.at.Add(time.Hour).After(from) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := os.Open(filepath.Join(h.dir, segment.name))
		if errors.Is(err, os.ErrNotExist) {
			continue // Retention may rotate a segment after the snapshot above.
		}
		if err != nil {
			return nil, err
		}
		err = readHistorySegment(ctx, file, selected, from, to, step)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("read monitoring history %s: %w", segment.name, err)
		}
	}
	result := make(map[string][]models.SystemMetricPoint, len(nodes))
	for node, buckets := range selected {
		points := make([]models.SystemMetricPoint, 0, len(buckets))
		for _, point := range buckets {
			point.Timestamp = point.Timestamp.UTC().Truncate(step)
			points = append(points, point)
		}
		sort.Slice(points, func(i, j int) bool { return points[i].Timestamp.Before(points[j].Timestamp) })
		result[node] = points
	}
	return result, nil
}

func readHistorySegment(ctx context.Context, file *os.File, selected map[string]map[int64]models.SystemMetricPoint, from, to time.Time, step time.Duration) error {
	reader := bufio.NewReaderSize(file, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) {
			return nil // Ignore a last, uncommitted partial record after a crash.
		}
		if err != nil {
			return err
		}
		var point models.SystemMetricPoint
		if err := json.Unmarshal(line, &point); err != nil {
			return err
		}
		buckets, ok := selected[point.NodeID]
		if !ok || point.Timestamp.Before(from) || point.Timestamp.After(to) {
			continue
		}
		bucket := point.Timestamp.UTC().Truncate(step).UnixNano()
		if previous, ok := buckets[bucket]; !ok || previous.Timestamp.Before(point.Timestamp) {
			buckets[bucket] = point
		}
	}
}
