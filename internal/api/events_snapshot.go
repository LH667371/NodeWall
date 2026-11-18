package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/sshactivity"
)

type eventScanSummary struct {
	scanReportSummary
	Error string `json:"error,omitempty"`
}

type eventNodeSnapshot struct {
	NodeID      string                 `json:"node_id"`
	Name        string                 `json:"name"`
	SSHActivity []sshactivity.Record   `json:"ssh_activity"`
	Scans       []eventScanSummary     `json:"scans"`
	Errors      map[string]string      `json:"errors,omitempty"`
	Logs        []models.DropLogRecord `json:"-"`
}

// Event history belongs to the cluster, not the security workspace's selected
// node. Collect only bounded event metadata; no keys, quarantine, inventory,
// protection configuration, or complete scan findings are needed here.
func (h *ServerHandler) eventsStreamSnapshot(ctx context.Context) map[string]any {
	return h.cachedConsoleSnapshot(ctx, "events:cluster", func(previous cachedPageSnapshot, hadPrevious bool) map[string]any {
		items := []eventNodeSnapshot{}
		logs := []models.DropLogRecord{}
		if h.service == nil {
			return map[string]any{"scope": "cluster", "nodes": items, "logs": logs}
		}
		previousNodes := map[string]eventNodeSnapshot{}
		if old, ok := previous.value["nodes"].([]eventNodeSnapshot); ok {
			for _, item := range old {
				previousNodes[item.NodeID] = item
			}
		}
		nodes := h.service.ListNodes(ctx)
		items = make([]eventNodeSnapshot, len(nodes))
		var workers sync.WaitGroup
		semaphore := make(chan struct{}, 4)
		for index, node := range nodes {
			workers.Go(func() {
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-ctx.Done():
					items[index] = eventNodeSnapshot{NodeID: node.ID, Name: node.Name, Errors: map[string]string{"collection": ctx.Err().Error()}}
					return
				}
				items[index] = h.eventNodeSnapshot(ctx, node, previousNodes[node.ID])
			})
		}
		workers.Wait()
		if ctx.Err() != nil && hadPrevious {
			return previous.value
		}
		// Only enrolled nodes from this collection are retained. Keeping the old
		// whole snapshot on an empty response resurrected removed nodes/events.
		for _, item := range items {
			logs = append(logs, item.Logs...)
		}
		sort.SliceStable(logs, func(i, j int) bool { return logs[i].Timestamp.After(logs[j].Timestamp) })
		return map[string]any{"scope": "cluster", "nodes": items, "logs": logs, "generated_at": time.Now().UTC()}
	})
}

func (h *ServerHandler) eventNodeSnapshot(ctx context.Context, node models.Node, previous eventNodeSnapshot) eventNodeSnapshot {
	item := eventNodeSnapshot{NodeID: node.ID, Name: node.Name, SSHActivity: []sshactivity.Record{}, Scans: []eventScanSummary{}}
	var activity struct {
		Records []sshactivity.Record `json:"records"`
	}
	var firewall struct {
		Logs []models.DropLogRecord `json:"logs"`
	}
	var reports struct {
		Reports      []scanReportSummary `json:"reports"`
		ArchiveError string              `json:"archive_error"`
	}
	// Older Agents ignore summary=1 and return a full scan. Decode findings
	// only for their count, without forwarding them to every event subscriber.
	var latest struct {
		eventScanSummary
		Findings []json.RawMessage `json:"findings"`
	}
	var activityErr, reportsErr, latestErr, firewallErr error
	requestCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	var probes sync.WaitGroup
	probes.Go(func() {
		firewallErr = h.nodeJSON(requestCtx, node.ID, http.MethodGet, "/logs/drop?limit=500", nil, &firewall)
	})
	probes.Go(func() {
		activityErr = h.nodeJSON(requestCtx, node.ID, http.MethodGet, "/ssh-protection/activity?limit=500", nil, &activity)
	})
	probes.Go(func() {
		reportsErr = h.nodeJSON(requestCtx, node.ID, http.MethodGet, "/security/scan/reports", nil, &reports)
	})
	probes.Go(func() {
		latestErr = h.nodeJSON(requestCtx, node.ID, http.MethodGet, "/security/scan?summary=1", nil, &latest)
	})
	probes.Wait()
	item.Errors = map[string]string{}
	if firewallErr != nil {
		item.Errors["firewall"] = firewallErr.Error()
		item.Logs = previous.Logs
	} else {
		item.Logs = firewall.Logs
		for index := range item.Logs {
			item.Logs[index].NodeID = node.ID
		}
	}
	if activityErr != nil {
		item.Errors["ssh"] = activityErr.Error()
		item.SSHActivity = previous.SSHActivity
	} else {
		item.SSHActivity = activity.Records
	}
	if reportsErr != nil {
		item.Errors["scans"] = reportsErr.Error()
		item.Scans = append(item.Scans, previous.Scans...)
	} else {
		for _, report := range reports.Reports {
			item.Scans = append(item.Scans, eventScanSummary{scanReportSummary: report})
		}
	}
	if reports.ArchiveError != "" {
		item.Errors["archive"] = reports.ArchiveError
	}
	if latestErr != nil {
		item.Errors["latest_scan"] = latestErr.Error()
	} else if latest.ID != "" && scanIsTerminal(latest.Status) {
		latest.FindingsCount = max(latest.FindingsCount, len(latest.Findings))
		// Replace an archived summary of this job rather than emitting a second
		// notification when it transitions from live state to the archive.
		found := false
		for index, scan := range item.Scans {
			if scan.ID == latest.ID {
				latest.FindingsCount = max(latest.FindingsCount, scan.FindingsCount)
				item.Scans[index] = latest.eventScanSummary
				found = true
				break
			}
		}
		if !found {
			item.Scans = append(item.Scans, latest.eventScanSummary)
		}
	}
	sort.SliceStable(item.Scans, func(i, j int) bool { return item.Scans[i].StartedAt.After(item.Scans[j].StartedAt) })
	return item
}

func scanIsTerminal(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled" || status == "canceled" || status == "stopped"
}

func (h *ServerHandler) handleEventsSnapshot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.eventsStreamSnapshot(r.Context()))
}
