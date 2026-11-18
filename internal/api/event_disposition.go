package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/service"
)

type eventDispositionRequest struct {
	NodeID string                        `json:"node_id"`
	Source string                        `json:"source"`
	Status models.EventDispositionStatus `json:"status"`
}

func validEventDispositionSource(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "firewall", "ssh", "malware", "scan":
		return true
	default:
		return false
	}
}

func validEventDispositionStatus(status models.EventDispositionStatus) bool {
	switch status {
	case models.EventDispositionOpen, models.EventDispositionHandled, models.EventDispositionDeferred:
		return true
	default:
		return false
	}
}

func (h *ServerHandler) handleEventDispositions(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("event disposition store unavailable"))
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Cache-Control", "no-store")
		nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
		writeJSON(w, http.StatusOK, map[string]any{
			"revision":     h.currentEventDispositionRevision(),
			"dispositions": h.store.ListEventDispositions(r.Context(), nodeID),
		})
		return
	}
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPut)
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}

	eventID := strings.TrimSpace(r.PathValue("event"))
	// Unit callers may invoke the handler directly without net/http's pattern
	// matcher, so retain a safe fallback for that case.
	if eventID == "" {
		eventID = strings.TrimPrefix(strings.TrimSpace(r.URL.Path), "/events/dispositions/")
	}
	if decoded, err := url.PathUnescape(eventID); err == nil {
		eventID = decoded
	}
	if eventID == "" || len(eventID) > 512 {
		writeError(w, http.StatusBadRequest, errors.New("event id is required"))
		return
	}
	var req eventDispositionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	req.Source = strings.ToLower(strings.TrimSpace(req.Source))
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node id is required"))
		return
	}
	if !validEventDispositionSource(req.Source) {
		writeError(w, http.StatusBadRequest, errors.New("unsupported event source"))
		return
	}
	if !validEventDispositionStatus(req.Status) {
		writeError(w, http.StatusBadRequest, errors.New("unsupported event disposition status"))
		return
	}
	nodes := h.store.ListNodes(r.Context())
	if h.service != nil {
		nodes = h.service.ListNodes(r.Context())
	}
	if _, ok := service.FindNode(nodes, req.NodeID); !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	updatedBy := ""
	if h.auth != nil {
		if session, ok := h.auth.sessionFromRequest(r); ok {
			updatedBy = session.Username
		}
	}
	disposition, err := h.store.UpsertEventDisposition(r.Context(), models.EventDisposition{
		EventID:   eventID,
		NodeID:    req.NodeID,
		Source:    req.Source,
		Status:    req.Status,
		UpdatedAt: time.Now().UTC(),
		UpdatedBy: updatedBy,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	revision := h.bumpEventDispositionRevision()
	h.notifyEventDispositionSubscribers()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "updated",
		"revision":    revision,
		"disposition": disposition,
	})
}
