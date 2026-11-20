package api

import (
	"errors"
	"net/http"
	"strings"

	"nodewall/internal/clamav"
)

func (h *ServerHandler) clamAVAuthorized(w http.ResponseWriter, r *http.Request) bool {
	if h.nodeCredentials != nil && r.TLS == nil {
		writeError(w, http.StatusBadRequest, errors.New("ClamAV synchronization requires HTTPS"))
		return false
	}
	if _, ok := h.enrolledNode(r); !ok {
		writeError(w, http.StatusUnauthorized, errors.New("enrolled HTTPS node credential required"))
		return false
	}
	return true
}

func (h *ServerHandler) handleJoinClamAVManifest(w http.ResponseWriter, r *http.Request) {
	if !h.clamAVAuthorized(w, r) {
		return
	}
	serveClamAVManifest(w, r)
}

func (h *AgentHandler) handleClamAVManifest(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		writeError(w, http.StatusBadRequest, errors.New("ClamAV synchronization requires HTTPS"))
		return
	}
	serveClamAVManifest(w, r)
}

func serveClamAVManifest(w http.ResponseWriter, r *http.Request) {
	manifest, err := clamav.CurrentManifest(clamav.AssetsDir(), clamav.DataDir(), strings.ToLower(r.URL.Query().Get("arch")))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, manifest)
}

func (h *ServerHandler) handleJoinClamAVFile(w http.ResponseWriter, r *http.Request) {
	if !h.clamAVAuthorized(w, r) {
		return
	}
	serveClamAVFile(w, r)
}

func (h *AgentHandler) handleClamAVFile(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		writeError(w, http.StatusBadRequest, errors.New("ClamAV synchronization requires HTTPS"))
		return
	}
	serveClamAVFile(w, r)
}

func serveClamAVFile(w http.ResponseWriter, r *http.Request) {
	path, err := clamav.PublishedFile(clamav.AssetsDir(), clamav.DataDir(), r.PathValue("kind"), r.PathValue("name"), r.URL.Query().Get("sha256"))
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, path)
}
