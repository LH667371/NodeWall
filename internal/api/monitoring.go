package api

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"

	"nodewall/internal/models"
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
