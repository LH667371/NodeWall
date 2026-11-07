package api

import (
	"context"
	"sync"
	"time"

	"nodewall/internal/models"
)

// RunMonitoring samples registered agents even when no browser or SSE stream
// is connected. A bounded worker pool isolates slow/offline nodes.
func (h *ServerHandler) RunMonitoring(ctx context.Context) {
	ticker := time.NewTicker(systemMetricsSampleInterval)
	defer ticker.Stop()
	for {
		h.collectSystemMetrics(ctx, h.service.ListNodes(ctx))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (h *ServerHandler) collectSystemMetrics(ctx context.Context, nodes []models.Node) {
	jobs := make(chan models.Node)
	var workers sync.WaitGroup
	for range min(8, len(nodes)) {
		workers.Go(func() {
			for node := range jobs {
				requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				_, _ = h.readSystemMetrics(requestCtx, node)
				cancel()
			}
		})
	}
	for _, node := range nodes {
		select {
		case jobs <- node:
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return
		}
	}
	close(jobs)
	workers.Wait()
}
