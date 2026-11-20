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

const (
	HistoryRetention  = 7 * 24 * time.Hour
	historyReadBuffer = 64 << 10
	// The standby polls every 15 seconds. Overlap makes recent missed syncs
	// recoverable without copying the entire retention window on each poll.
	StandbyCopyWindow   = 2 * time.Minute
	StandbyCopyMaxBytes = 8 << 20
)

type historySegment struct {
	name  string
	at    time.Time
	size  int64
	nodes map[string]*historyNodeIndex
}

type historyNodeIndex struct {
	source models.MonitoringArchiveNode
	times  map[int64]struct{}
}

// History stores hourly append-only segments. Queries stream from disk instead
// of loading a week of metrics into memory; only chart-sized buckets are kept.
type History struct {
	mu        sync.Mutex
	catalogMu sync.Mutex
	dir       string
	maxBytes  int64
	segments  []historySegment
	bytes     int64
	prepared  string
	opened    bool
}

// OpenHistory returns a retryable archive on filesystem errors. The next
// append can reopen it when the directory or volume becomes available again.
func OpenHistory(dir string, maxBytes int64) (*History, error) {
	if maxBytes <= 0 {
		return nil, errors.New("monitoring history byte limit must be positive")
	}
	h := &History{dir: dir, maxBytes: maxBytes}
	return h, h.open()
}

// Called at construction or with mu held by the writer.
func (h *History) open() error {
	if h.opened {
		return nil
	}
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return err
	}
	var segments []historySegment
	var size int64
	for _, entry := range entries {
		at, err := time.Parse("20060102T15.jsonl", entry.Name())
		if err != nil {
			continue // Never prune unrelated files placed in the data directory.
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("monitoring segment %q is not a regular file", entry.Name())
		}
		segments = append(segments, historySegment{name: entry.Name(), at: at, size: info.Size()})
		size += info.Size()
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].at.Before(segments[j].at) })
	h.segments, h.bytes = segments, size
	if err := h.prune(time.Now().UTC(), "", 0); err != nil {
		return err
	}
	h.opened = true
	return nil
}

func (h *History) Append(point models.SystemMetricPoint) error {
	return h.AppendBatch([]models.SystemMetricPoint{point})
}

// AppendBatch commits new samples in a round to one hourly segment. The first
// durable sample for a node and timestamp wins, so a standby can retry a copy
// or independently collect the same round without growing the archive twice.
func (h *History) AppendBatch(points []models.SystemMetricPoint) error {
	if len(points) == 0 {
		return nil
	}
	at := points[0].Timestamp.UTC()
	now := time.Now().UTC()
	if at.IsZero() || at.Before(now.Add(-HistoryRetention)) || at.After(now.Add(time.Minute)) {
		return errors.New("monitoring sample timestamp is outside the retention window")
	}
	for _, point := range points {
		if strings.TrimSpace(point.NodeID) == "" || !point.Timestamp.Equal(at) {
			return errors.New("monitoring batch requires a node and the same timestamp for each sample")
		}
	}
	name := at.Format("20060102T15.jsonl")
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.open(); err != nil {
		return fmt.Errorf("open monitoring history: %w", err)
	}
	var nodes map[string]*historyNodeIndex
	var file *os.File
	var start int64
	for i := range h.segments {
		segment := &h.segments[i]
		if segment.name != name {
			continue
		}
		var err error
		file, start, err = h.openForAppend(name)
		if err != nil {
			return err
		}
		defer file.Close()
		// Account for an interrupted append before evicting any older history.
		if start != segment.size {
			h.bytes += start - segment.size
			segment.size, segment.nodes = start, nil
		}
		if segment.nodes == nil {
			loaded, err := h.readIndex(context.Background(), *segment)
			if err != nil {
				return err
			}
			segment.nodes = loaded
		}
		nodes = segment.nodes
		break
	}
	if nodes == nil {
		nodes = make(map[string]*historyNodeIndex)
	}
	var batch bytes.Buffer
	encoder := json.NewEncoder(&batch)
	newPoints := make([]models.SystemMetricPoint, 0, len(points))
	seen := make(map[string]bool, len(points))
	for _, point := range points {
		if seen[point.NodeID] {
			continue
		}
		seen[point.NodeID] = true
		if node := nodes[point.NodeID]; node != nil {
			if _, exists := node.times[at.UnixNano()]; exists {
				continue
			}
		}
		if err := encoder.Encode(point); err != nil {
			return err
		}
		newPoints = append(newPoints, point)
	}
	if len(newPoints) == 0 {
		return nil
	}
	data := batch.Bytes()
	if err := h.prune(now, name, int64(len(data))); err != nil {
		return err
	}
	if file == nil {
		var err error
		file, start, err = h.openForAppend(name)
		if err != nil {
			return err
		}
		defer file.Close()
	}
	if _, err := file.Write(data); err != nil {
		h.prepared = ""
		return errors.Join(err, file.Truncate(start))
	}
	if err := file.Sync(); err != nil {
		h.prepared = ""
		return errors.Join(err, file.Truncate(start))
	}
	for _, point := range newPoints {
		indexSample(nodes, point.NodeID, point.NodeName, at)
	}
	for i := range h.segments {
		if h.segments[i].name == name {
			h.bytes += start + int64(len(data)) - h.segments[i].size
			h.segments[i].size = start + int64(len(data))
			return nil
		}
	}
	h.segments = append(h.segments, historySegment{
		name: name, at: at.Truncate(time.Hour), size: start + int64(len(data)), nodes: nodes,
	})
	sort.Slice(h.segments, func(i, j int) bool { return h.segments[i].at.Before(h.segments[j].at) })
	h.bytes += start + int64(len(data))
	dir, err := os.Open(h.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (h *History) openForAppend(name string) (*os.File, int64, error) {
	file, err := os.OpenFile(filepath.Join(h.dir, name), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, 0, err
	}
	end, err := file.Seek(0, io.SeekEnd)
	if err == nil && h.prepared != name {
		end, err = repairHistoryTail(file, end)
	}
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	h.prepared = name
	return file, end, nil
}

func indexSample(nodes map[string]*historyNodeIndex, id, name string, at time.Time) {
	entry := nodes[id]
	if entry == nil {
		entry = &historyNodeIndex{source: models.MonitoringArchiveNode{NodeID: id}, times: make(map[int64]struct{})}
		nodes[id] = entry
	}
	entry.times[at.UnixNano()] = struct{}{}
	if at.After(entry.source.LastSampleAt) {
		entry.source.LastSampleAt = at
		if name != "" {
			entry.source.Name = name
		}
	} else if entry.source.Name == "" {
		entry.source.Name = name
	}
}

func (h *History) readIndex(ctx context.Context, segment historySegment) (map[string]*historyNodeIndex, error) {
	file, err := os.Open(filepath.Join(h.dir, segment.name))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	nodes := make(map[string]*historyNodeIndex)
	_, err = scanHistorySegment(ctx, file, segment.size, func(line []byte) error {
		var sample struct {
			NodeID    string    `json:"node_id"`
			NodeName  string    `json:"node_name"`
			Timestamp time.Time `json:"timestamp"`
		}
		if err := json.Unmarshal(line, &sample); err != nil {
			return err
		}
		if sample.NodeID != "" && !sample.Timestamp.IsZero() {
			indexSample(nodes, sample.NodeID, sample.NodeName, sample.Timestamp)
		}
		return nil
	})
	return nodes, err
}

// RecordedNodes is independent of the current cluster membership and time
// filter. Rebuild the index for old segments lazily, without holding the
// writer lock while reading the retained archive after a restart.
func (h *History) RecordedNodes(ctx context.Context) (map[string]models.MonitoringArchiveNode, error) {
	h.catalogMu.Lock()
	defer h.catalogMu.Unlock()
	h.mu.Lock()
	pending := make([]historySegment, 0)
	for _, segment := range h.segments {
		if segment.nodes == nil {
			pending = append(pending, segment)
		}
	}
	h.mu.Unlock()
	var indexErr error
	for _, segment := range pending {
		nodes, err := h.readIndex(ctx, segment)
		if errors.Is(err, os.ErrNotExist) {
			continue // The sampling writer may have pruned this hour.
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			indexErr = errors.Join(indexErr, fmt.Errorf("index monitoring segment %s: %w", segment.name, err))
			continue
		}
		h.mu.Lock()
		for i := range h.segments {
			current := &h.segments[i]
			if current.name == segment.name && current.size == segment.size && current.nodes == nil {
				current.nodes = nodes
				break
			}
		}
		h.mu.Unlock()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().UTC().Add(-HistoryRetention)
	result := make(map[string]models.MonitoringArchiveNode)
	for _, segment := range h.segments {
		for id, node := range segment.nodes {
			entry := node.source
			if entry.LastSampleAt.Before(cutoff) {
				continue
			}
			previous := result[id]
			if entry.LastSampleAt.After(previous.LastSampleAt) {
				if entry.Name == "" {
					entry.Name = previous.Name
				}
				result[id] = entry
			}
		}
	}
	return result, indexErr
}

func repairHistoryTail(file *os.File, size int64) (int64, error) {
	if size == 0 {
		return 0, nil
	}
	var tail [historyReadBuffer]byte
	for end := size; end > 0; {
		start := max(0, end-int64(len(tail)))
		chunk := tail[:end-start]
		if _, err := file.ReadAt(chunk, start); err != nil {
			return 0, err
		}
		if last := bytes.LastIndexByte(chunk, '\n'); last >= 0 {
			end = start + int64(last+1)
			if end == size {
				return size, nil
			}
			return end, file.Truncate(end)
		}
		end = start
	}
	return 0, file.Truncate(0)
}

func (h *History) prune(now time.Time, active string, incoming int64) error {
	if incoming > h.maxBytes {
		return errors.New("monitoring sample exceeds the history storage quota")
	}
	if active != "" && h.bytes+incoming > h.maxBytes {
		// A late standby copy must not evict the current hour or any newer
		// segment. Check that eligible older hours can make room before pruning.
		available := h.maxBytes - h.bytes
		for _, segment := range h.segments {
			if segment.name >= active {
				break
			}
			available += segment.size
		}
		if available < incoming {
			return errors.New("monitoring history quota exhausted by this hour or newer segments")
		}
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

// Query returns the last real sample in each time bucket. A damaged segment or
// record can return an error alongside samples from the readable portions.
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
	var readErr error
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
			readErr = errors.Join(readErr, fmt.Errorf("open monitoring segment %s: %w", segment.name, err))
			continue
		}
		err = readHistorySegment(ctx, file, segment.size, selected, from, to, step)
		file.Close()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			readErr = errors.Join(readErr, fmt.Errorf("read monitoring history %s: %w", segment.name, err))
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
	return result, readErr
}

func readHistorySegment(ctx context.Context, file io.ReaderAt, size int64, selected map[string]map[int64]models.SystemMetricPoint, from, to time.Time, step time.Duration) error {
	skipped, err := scanHistorySegment(ctx, file, size, func(line []byte) error {
		var point models.SystemMetricPoint
		if err := json.Unmarshal(line, &point); err != nil {
			return err
		}
		buckets, ok := selected[point.NodeID]
		if !ok || point.Timestamp.Before(from) || point.Timestamp.After(to) {
			return nil
		}
		bucket := point.Timestamp.UTC().Truncate(step).UnixNano()
		if previous, ok := buckets[bucket]; !ok || !point.Timestamp.Before(previous.Timestamp) {
			buckets[bucket] = point
		}
		return nil
	})
	if skipped > 0 {
		return errors.Join(err, fmt.Errorf("skipped %d unreadable monitoring records", skipped))
	}
	return err
}

func scanHistorySegment(ctx context.Context, file io.ReaderAt, size int64, visit func([]byte) error) (int, error) {
	reader := bufio.NewReaderSize(io.NewSectionReader(file, 0, size), historyReadBuffer)
	var offset, recordSize int64
	var longRecord []byte
	skipped := 0
	for {
		if err := ctx.Err(); err != nil {
			return skipped, err
		}
		line, err := reader.ReadSlice('\n')
		if err == io.EOF {
			return skipped, nil // Only newline-terminated records are committed.
		}
		recordSize += int64(len(line))
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return skipped, err
		}
		if recordSize > int64(len(line)) {
			// Only allocate for complete large samples. A torn tail may span
			// many buffers and can be skipped without assembling it in memory.
			if int64(cap(longRecord)) < recordSize {
				longRecord = make([]byte, recordSize)
			}
			line = longRecord[:recordSize]
			if _, err := file.ReadAt(line, offset); err != nil {
				return skipped, err
			}
		}
		offset += recordSize
		recordSize = 0
		if err := visit(line); err != nil {
			skipped++ // Skip the damaged record, keeping the rest of the hour readable.
		}
	}
}
