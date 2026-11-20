package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/monitoring"
)

const (
	systemMetricsSampleInterval = 15 * time.Second
	systemMetricsRoundTimeout   = 10 * time.Second
	systemMetricsNodeTimeout    = 5 * time.Second
)

func monitoringHistoryStep(rangeSeconds int) time.Duration {
	step := max(systemMetricsSampleInterval, time.Duration((rangeSeconds+1199)/1200)*time.Second)
	return ((step + systemMetricsSampleInterval - 1) / systemMetricsSampleInterval) * systemMetricsSampleInterval
}

// Keep the newest real sample in each display bucket after merging live and
// archived data. Otherwise the live ring defeats archive downsampling, and a
// many-core host can send thousands of points per CPU to every browser.
func resampleMonitoringPoints(source []models.SystemMetricPoint, step time.Duration) []models.SystemMetricPoint {
	buckets := make(map[time.Time]models.SystemMetricPoint)
	for _, point := range source {
		at := point.Timestamp.UTC().Truncate(step)
		if previous, exists := buckets[at]; !exists || !point.Timestamp.Before(previous.Timestamp) {
			buckets[at] = point
		}
	}
	points := make([]models.SystemMetricPoint, 0, len(buckets))
	for at, point := range buckets {
		point.Timestamp = at
		points = append(points, point)
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Timestamp.Before(points[j].Timestamp) })
	return points
}

// RunMonitoring is the only writer of live history. Each round shares one
// manager timestamp so Agent clock skew and response order cannot split it.
func (h *ServerHandler) RunMonitoring(ctx context.Context) {
	ticker := time.NewTicker(systemMetricsSampleInterval)
	defer ticker.Stop()
	scheduled := time.Now()
	for {
		h.collectSystemMetrics(ctx, h.service.ListNodes(ctx), scheduled)
		select {
		case <-ctx.Done():
			return
		case scheduled = <-ticker.C:
		}
	}
}

func (h *ServerHandler) collectSystemMetrics(ctx context.Context, nodes []models.Node, scheduled time.Time) {
	round, cancel := context.WithTimeout(ctx, systemMetricsRoundTimeout)
	defer cancel()
	samples := make([]*models.SystemMetrics, len(nodes))
	jobs := make(chan int, len(nodes))
	for index := range nodes {
		jobs <- index
	}
	close(jobs)
	var workers sync.WaitGroup
	for range min(16, len(nodes)) {
		workers.Go(func() {
			for index := range jobs {
				if round.Err() != nil {
					return
				}
				requestCtx, stop := context.WithTimeout(round, systemMetricsNodeTimeout)
				samples[index], _ = h.readSystemMetrics(requestCtx, nodes[index])
				stop()
			}
		})
	}
	workers.Wait()
	if ctx.Err() != nil {
		return
	}
	at := scheduled.UTC().Truncate(systemMetricsSampleInterval)
	finished := time.Now()
	points := make([]models.SystemMetricPoint, 0, len(samples))
	h.systemMetricsMu.Lock()
	if !at.After(h.monitoringSampledAt) {
		h.systemMetricsMu.Unlock()
		return
	}
	if h.systemMetricsCache == nil {
		h.systemMetricsCache = make(map[string]cachedSystemMetric)
	}
	if h.systemMetricsHistory == nil {
		h.systemMetricsHistory = make(map[string][]models.SystemMetricPoint)
	}
	for index, metrics := range samples {
		if metrics == nil {
			continue
		}
		id := nodes[index].ID
		point := systemMetricPoint(id, *metrics)
		point.Timestamp = at
		point.NodeName = nodes[index].Name
		points = append(points, point)
		h.systemMetricsCache[id] = cachedSystemMetric{metrics: *metrics, fetchedAt: finished}
		history := append(h.systemMetricsHistory[id], point)
		cutoff := at.Add(-6 * time.Hour)
		start := max(0, len(history)-systemMetricsHistoryLimit)
		for start < len(history) && history[start].Timestamp.Before(cutoff) {
			start++
		}
		h.systemMetricsHistory[id] = history[start:]
	}
	// Refreshes during the round keep reading the last complete batch.
	if h.monitoringFirstRound.IsZero() {
		h.monitoringFirstRound = at
	}
	h.monitoringSampledAt = at
	h.systemMetricsMu.Unlock()

	if h.metricsArchive == nil || len(points) == 0 {
		return
	}
	storageError := ""
	if err := h.metricsArchive.AppendBatch(points); err != nil {
		storageError = err.Error()
	}
	h.systemMetricsMu.Lock()
	previousError := h.metricsArchiveError
	h.metricsArchiveError = storageError
	h.systemMetricsMu.Unlock()
	if storageError != "" && storageError != previousError {
		log.Printf("warning: persist monitoring history: %s", storageError)
	}
}

func (h *ServerHandler) monitoringArchiveNodes(ctx context.Context, registered []models.Node) (map[string]models.MonitoringArchiveNode, error) {
	if h.metricsArchive == nil {
		return nil, nil
	}
	archived, err := h.metricsArchive.RecordedNodes(ctx)
	for _, node := range registered {
		if source, ok := archived[node.ID]; ok {
			source.Registered = true
			if node.Name != "" {
				source.Name = node.Name
			}
			archived[node.ID] = source
		}
	}
	return archived, err
}

func (h *ServerHandler) recentMonitoringSamples(ctx context.Context, from, to time.Time) ([]models.SystemMetricPoint, error) {
	h.systemMetricsMu.Lock()
	var samples []models.SystemMetricPoint
	for _, history := range h.systemMetricsHistory {
		for i := len(history) - 1; i >= 0 && !history[i].Timestamp.Before(from); i-- {
			if !history[i].Timestamp.After(to) {
				samples = append(samples, history[i])
			}
		}
	}
	firstRound := h.monitoringFirstRound
	h.systemMetricsMu.Unlock()
	// Reuse completed batches for the regular sync. Read disk only for the
	// part of the overlap before this process could have collected samples.
	if h.metricsArchive == nil || (!firstRound.IsZero() && !firstRound.After(from)) {
		return samples, nil
	}
	if !firstRound.IsZero() && !firstRound.After(to) {
		to = firstRound.Add(-time.Nanosecond)
	}
	if !to.After(from) {
		return samples, nil
	}
	archived, catalogErr := h.metricsArchive.RecordedNodes(ctx)
	nodes := make([]models.Node, 0, len(archived))
	for id, record := range archived {
		if !record.LastSampleAt.Before(from) {
			nodes = append(nodes, models.Node{ID: id})
		}
	}
	byNode, err := h.monitoringArchivePoints(ctx, nodes, from, to, int(monitoring.StandbyCopyWindow/time.Second))
	for _, points := range byNode {
		samples = append(samples, points...)
	}
	return samples, errors.Join(catalogErr, err)
}

// The bootstrap route has already authenticated this caller as a standby.
// Export recent completed samples without contacting any Agents.
func (h *ServerHandler) handleJoinMonitoring(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	samples, err := h.recentMonitoringSamples(r.Context(), now.Add(-monitoring.StandbyCopyWindow), now)
	if err != nil && len(samples) == 0 {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Timestamp.Equal(samples[j].Timestamp) {
			return samples[i].NodeID < samples[j].NodeID
		}
		return samples[i].Timestamp.After(samples[j].Timestamp)
	})
	var payload bytes.Buffer
	payload.WriteByte('[')
	for _, sample := range samples {
		encoded, err := json.Marshal(sample)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if payload.Len()+len(encoded)+2 > monitoring.StandbyCopyMaxBytes {
			break // Keep the most recent evidence when the overlap is large.
		}
		if payload.Len() > 1 {
			payload.WriteByte(',')
		}
		payload.Write(encoded)
	}
	payload.WriteByte(']')
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload.Bytes())
}

// ImportMonitoringHistory stores the samples received by the authenticated
// standby sync locally. It can be retried after an interrupted transfer.
func (h *ServerHandler) ImportMonitoringHistory(ctx context.Context, samples []models.SystemMetricPoint) error {
	if h.metricsArchive == nil {
		return nil
	}
	now := time.Now().UTC()
	for _, sample := range samples {
		if strings.TrimSpace(sample.NodeID) == "" || sample.Timestamp.Before(now.Add(-monitoring.HistoryRetention)) || sample.Timestamp.After(now.Add(time.Minute)) {
			return errors.New("invalid standby monitoring sample")
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].Timestamp.Before(samples[j].Timestamp) })
	for len(samples) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := 1
		for end < len(samples) && samples[end].Timestamp.Equal(samples[0].Timestamp) {
			end++
		}
		if err := h.metricsArchive.AppendBatch(samples[:end]); err != nil {
			return fmt.Errorf("save standby monitoring samples: %w", err)
		}
		samples = samples[end:]
	}
	return nil
}
