package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// cachedConsoleSnapshot coalesces collection for the same page and target.
// Never hold the cache lock during Agent I/O: a slow host must not block other
// hosts, configuration saves, or a different browser's page subscription.
func (h *ServerHandler) cachedConsoleSnapshot(ctx context.Context, key string, collect func(cachedPageSnapshot, bool) map[string]any) map[string]any {
	h.pageSnapshotMu.Lock()
	previous, hadPrevious := h.pageSnapshotCache[key]
	if hadPrevious && time.Since(previous.fetchedAt) < pageSnapshotTTL {
		h.pageSnapshotMu.Unlock()
		return previous.value
	}
	if pending := h.pageSnapshotPending[key]; pending != nil {
		h.pageSnapshotMu.Unlock()
		select {
		case <-pending:
			return h.cachedConsoleSnapshot(ctx, key, collect)
		case <-ctx.Done():
			return previous.value
		}
	}
	if h.pageSnapshotPending == nil {
		h.pageSnapshotPending = make(map[string]chan struct{})
	}
	pending := make(chan struct{})
	h.pageSnapshotPending[key] = pending
	revision := atomic.LoadUint64(&h.consoleRevision)
	h.pageSnapshotMu.Unlock()

	value := collect(previous, hadPrevious)
	if value == nil {
		value = map[string]any{}
	}
	// Keep cached maps immutable; a cancelled collector can return a previous
	// snapshot still being marshalled for another Web client.
	if key != "node-protection" {
		copy := make(map[string]any, len(value)+1)
		for name, item := range value {
			copy[name] = item
		}
		copy["revision"] = revision
		value = copy
	}
	h.pageSnapshotMu.Lock()
	if ctx.Err() == nil && revision == atomic.LoadUint64(&h.consoleRevision) {
		if h.pageSnapshotCache == nil {
			h.pageSnapshotCache = make(map[string]cachedPageSnapshot)
		}
		h.pageSnapshotCache[key] = cachedPageSnapshot{value: value, fetchedAt: time.Now()}
	}
	delete(h.pageSnapshotPending, key)
	close(pending)
	h.pageSnapshotMu.Unlock()
	return value
}

func (h *ServerHandler) invalidateConsoleSnapshots() uint64 {
	h.pageSnapshotMu.Lock()
	revision := atomic.AddUint64(&h.consoleRevision, 1)
	for key, snapshot := range h.pageSnapshotCache {
		if key == "events:cluster" {
			// Expire collection without discarding known event history. A policy
			// save on one node must not erase another temporarily unreachable
			// node's scan/SSH records. The collector still prunes deleted nodes.
			snapshot.fetchedAt = time.Time{}
			h.pageSnapshotCache[key] = snapshot
		} else {
			delete(h.pageSnapshotCache, key)
		}
	}
	h.pageSnapshotMu.Unlock()
	h.consoleUpdateMu.Lock()
	for subscriber := range h.consoleUpdateSubscribers {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
	h.consoleUpdateMu.Unlock()
	return revision
}

func (h *ServerHandler) subscribeConsoleUpdates() (chan struct{}, func()) {
	channel := make(chan struct{}, 1)
	h.consoleUpdateMu.Lock()
	if h.consoleUpdateSubscribers == nil {
		h.consoleUpdateSubscribers = make(map[chan struct{}]struct{})
	}
	h.consoleUpdateSubscribers[channel] = struct{}{}
	h.consoleUpdateMu.Unlock()
	return channel, func() {
		h.consoleUpdateMu.Lock()
		delete(h.consoleUpdateSubscribers, channel)
		h.consoleUpdateMu.Unlock()
	}
}

func (h *ServerHandler) withConsoleMutationSync(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&consoleMutationWriter{ResponseWriter: w, handler: h}, r)
	})
}

type consoleMutationWriter struct {
	http.ResponseWriter
	handler *ServerHandler
	written bool
}

func (w *consoleMutationWriter) WriteHeader(status int) {
	if w.written {
		return
	}
	w.written = true
	if status >= 200 && status < 300 && w.Header().Get("X-NodeWall-Revision") == "" {
		w.Header().Set("X-NodeWall-Revision", fmt.Sprint(w.handler.invalidateConsoleSnapshots()))
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *consoleMutationWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// Configuration tags describe editable values, excluding changing counters.
// They let two Web clients detect an intervening save before replacing a form.
func configurationTag(value any) string {
	data, _ := json.Marshal(value)
	var object map[string]any
	if json.Unmarshal(data, &object) == nil && object != nil {
		delete(object, "active_locks")
		delete(object, "restart_required")
		if settings, ok := object["settings"]; ok {
			object = map[string]any{"settings": settings}
		}
		data, _ = json.Marshal(object)
	}
	return fmt.Sprintf(`"%x"`, sha256.Sum256(data))
}

func configurationKey(r *http.Request) string {
	if r.URL.Path == "/settings/auth" || r.URL.Path == "/settings/passkey" {
		return "web-auth"
	}
	if r.PathValue("node") != "" {
		return "ssh:" + r.PathValue("node")
	}
	return r.URL.Path
}

func (h *ServerHandler) configurationETag(key string, value any) string {
	var revision uint64
	if counter, ok := h.configurationVersions.Load(key); ok {
		revision = counter.(*atomic.Uint64).Load()
	}
	// A password/key replacement can leave the public view unchanged. Include
	// its save generation without putting any secret in the public snapshot.
	return configurationTag(map[string]any{"value": configurationTag(value), "revision": revision})
}

func (h *ServerHandler) configurationValue(r *http.Request) (any, error) {
	switch r.URL.Path {
	case "/settings/auth":
		return h.auth.authSettings(), nil
	case "/settings/passkey":
		return h.auth.passkeySettingsView(), nil
	case "/settings/smtp":
		return h.auth.smtpSettingsView(), nil
	case "/settings/logging":
		var value any
		ctx, cancel := context.WithTimeout(r.Context(), 2500*time.Millisecond)
		defer cancel()
		err := h.nodeJSON(ctx, h.nodeID, http.MethodGet, "/settings/logging", nil, &value)
		return value, err
	}
	if strings.HasPrefix(r.URL.Path, "/nodes/") && strings.Contains(r.URL.Path, "/ssh-protection") {
		var value any
		ctx, cancel := context.WithTimeout(r.Context(), 2500*time.Millisecond)
		defer cancel()
		err := h.nodeJSON(ctx, r.PathValue("node"), http.MethodGet, "/ssh-protection", nil, &value)
		return value, err
	}
	return nil, nil
}

func (h *ServerHandler) withConfigurationSync(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auth and Passkey share a settings file, so compare-and-save must be
		// serialized across those endpoints as well as across Web clients.
		mutex := &h.configurationMu
		key := configurationKey(r)
		if r.URL.Path != "/settings/auth" && r.URL.Path != "/settings/passkey" {
			stored, _ := h.configurationLocks.LoadOrStore(key, &sync.Mutex{})
			mutex = stored.(*sync.Mutex)
		}
		mutex.Lock()
		defer mutex.Unlock()
		if expected := strings.TrimSpace(r.Header.Get("If-Match")); expected != "" && r.Method != http.MethodGet {
			value, err := h.configurationValue(r)
			if err != nil {
				writeError(w, http.StatusBadGateway, err)
				return
			}
			if h.configurationETag(key, value) != expected {
				writeJSON(w, http.StatusConflict, map[string]any{"code": "CONFIG_CHANGED", "error": "configuration changed in another Web session; review the latest values before saving"})
				return
			}
		}
		writer := &configurationResponseWriter{header: make(http.Header), status: http.StatusOK}
		next(writer, r)
		for name, values := range writer.header {
			w.Header()[name] = values
		}
		if writer.status >= 200 && writer.status < 300 {
			if r.Method != http.MethodGet {
				counter, _ := h.configurationVersions.LoadOrStore(key, &atomic.Uint64{})
				counter.(*atomic.Uint64).Add(1)
				h.invalidateConsoleSnapshots()
			}
			var value any
			if json.Unmarshal(writer.body.Bytes(), &value) == nil {
				w.Header().Set("ETag", h.configurationETag(key, value))
			}
			w.Header().Set("X-NodeWall-Revision", fmt.Sprint(atomic.LoadUint64(&h.consoleRevision)))
			w.Header().Set("Cache-Control", "no-store")
		}
		w.WriteHeader(writer.status)
		_, _ = w.Write(writer.body.Bytes())
	}
}

// These configuration endpoints return small JSON documents. Buffering the
// response computes its ETag without probing the same Agent a second time.
type configurationResponseWriter struct {
	header  http.Header
	body    bytes.Buffer
	status  int
	written bool
}

func (w *configurationResponseWriter) Header() http.Header { return w.header }
func (w *configurationResponseWriter) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
	}
}
func (w *configurationResponseWriter) Write(data []byte) (int, error) {
	w.written = true
	return w.body.Write(data)
}
