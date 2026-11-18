package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/service"
	"nodewall/internal/transporttls"
)

const (
	nodeRelayHeader      = "X-Nodewall-Relay"
	nodeRelayRetryHeader = "X-Nodewall-Relay-Retryable"
	nodeRelayBodyLimit   = 2 << 20
	nodeDialTimeout      = 750 * time.Millisecond
)

type directNodeRequest struct{}

type nodeRelayRequest struct {
	NodeID      string `json:"node_id"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ContentType string `json:"content_type,omitempty"`
	Body        []byte `json:"body,omitempty"`
}

type relayPeer struct {
	ID          string
	URL         string
	Certificate string
}

// nodeRelayTransport preserves direct agent access while allowing a standby
// console to use another enrolled manager when host firewall rules partition
// the mesh. Relays are one hop only and never select arbitrary request URLs.
type nodeRelayTransport struct {
	handler            *ServerHandler
	direct             http.RoundTripper
	mu                 sync.Mutex
	clients            map[string]*http.Client
	unsupported        map[string]time.Time
	directReachability map[string]bool
}

func (t *nodeRelayTransport) CloseIdleConnections() {
	if closer, ok := t.direct.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, client := range t.clients {
		client.CloseIdleConnections()
	}
}

func (t *nodeRelayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, directErr := t.direct.RoundTrip(req)
	if req.URL != nil {
		t.mu.Lock()
		if t.directReachability == nil {
			t.directReachability = make(map[string]bool)
		}
		t.directReachability[req.URL.Scheme+"://"+req.URL.Host] = directErr == nil
		t.mu.Unlock()
	}
	if directErr == nil || req.Context().Err() != nil || req.Context().Value(directNodeRequest{}) != nil {
		return response, directErr
	}
	// Only a failed TCP dial proves that a mutation has not reached its target.
	// A lost response or TLS failure must not replay a scan, quarantine, policy
	// publish, or cleanup operation on a different path.
	var opError *net.OpError
	if !errors.As(directErr, &opError) || opError.Op != "dial" {
		return nil, directErr
	}
	h := t.handler
	if h.nodeCredentials == nil || h.service == nil || h.nodeID == "" {
		return nil, directErr
	}
	caller, ok := h.nodeCredentials.Get(h.nodeID)
	if !ok {
		return nil, directErr
	}
	origin := req.URL.Scheme + "://" + req.URL.Host
	var target models.Node
	for _, node := range h.service.ListNodes(req.Context()) {
		if strings.EqualFold(strings.TrimRight(node.AgentURL, "/"), origin) {
			target = node
			break
		}
	}
	if target.ID == "" || !validNodeRelayPath(req.URL.RequestURI()) {
		return nil, directErr
	}
	payload := nodeRelayRequest{NodeID: target.ID, Method: req.Method, Path: req.URL.RequestURI(), ContentType: req.Header.Get("Content-Type")}
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, directErr
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, directErr
		}
		payload.Body, err = io.ReadAll(io.LimitReader(body, nodeRelayBodyLimit+1))
		body.Close()
		if err != nil || len(payload.Body) > nodeRelayBodyLimit {
			return nil, directErr
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, directErr
	}
	failures := []error{fmt.Errorf("direct agent connection: %w", directErr)}
	attempts := 0
	for _, peer := range t.peers(req.Context(), target.ID) {
		if attempts >= 2 || req.Context().Err() != nil {
			break
		}
		t.mu.Lock()
		unsupported := time.Now().Before(t.unsupported[peer.URL])
		t.mu.Unlock()
		if unsupported {
			continue
		}
		attempts++
		client, err := t.peerClient(peer)
		if err != nil {
			failures = append(failures, fmt.Errorf("relay %s: %w", peer.ID, err))
			continue
		}
		relay, _ := http.NewRequestWithContext(req.Context(), http.MethodPost, peer.URL+"/join/relay", bytes.NewReader(data))
		relay.Header.Set("Content-Type", "application/json")
		setNodeAuthHeaders(relay, caller)
		res, err := client.Do(relay)
		if err != nil {
			failures = append(failures, fmt.Errorf("relay %s: %w", peer.ID, err))
			// Once the relay request may have been delivered, a mutation's result
			// is uncertain. Return the error and let the caller inspect/retry.
			if req.Method != http.MethodGet && (!errors.As(err, &opError) || opError.Op != "dial") {
				break
			}
			continue
		}
		if res.Header.Get(nodeRelayHeader) != "1" {
			res.Body.Close()
			t.mu.Lock()
			if t.unsupported == nil {
				t.unsupported = make(map[string]time.Time)
			}
			t.unsupported[peer.URL] = time.Now().Add(30 * time.Second)
			t.mu.Unlock()
			failures = append(failures, fmt.Errorf("relay %s is unavailable or requires an update (HTTP %d)", peer.ID, res.StatusCode))
			if req.Method != http.MethodGet {
				// An unexpected proxy may have stripped the response marker after
				// delivery. Missing metadata is not proof a write never ran.
				break
			}
			continue
		}
		if res.Header.Get(nodeRelayRetryHeader) == "1" {
			res.Body.Close()
			failures = append(failures, fmt.Errorf("relay %s cannot connect to the target Agent", peer.ID))
			continue
		}
		return res, nil
	}
	return nil, errors.Join(failures...)
}

func (t *nodeRelayTransport) peers(ctx context.Context, targetID string) []relayPeer {
	h := t.handler
	var peers []relayPeer
	reachable := make(map[string]bool)
	t.mu.Lock()
	for origin, ok := range t.directReachability {
		reachable[origin] = ok
	}
	t.mu.Unlock()
	prefer := make(map[string]bool)
	for _, node := range h.service.ListNodes(ctx) {
		if node.ID == h.nodeID || node.ID == targetID || node.ServerHTTPAddr == "" {
			continue
		}
		credential, ok := h.nodeCredentials.Get(node.ID)
		if !ok || credential.Certificate == "" {
			continue
		}
		endpoint := strings.TrimRight(strings.TrimSpace(node.ServerHTTPAddr), "/")
		if !strings.Contains(endpoint, "://") {
			endpoint = "https://" + endpoint
		}
		origin, err := nodeauth.Origin(endpoint)
		if err != nil || !strings.HasPrefix(origin, "https://") {
			continue
		}
		server, _ := url.Parse(origin)
		agent, err := url.Parse(credential.AgentURL)
		if err != nil || !strings.EqualFold(server.Hostname(), agent.Hostname()) {
			continue
		}
		ip := net.ParseIP(server.Hostname())
		if origin != h.relayManagerURL && (strings.EqualFold(server.Hostname(), "localhost") || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified()))) {
			continue
		}
		peers = append(peers, relayPeer{ID: node.ID, URL: origin, Certificate: credential.Certificate})
		prefer[node.ID] = reachable[strings.TrimRight(node.AgentURL, "/")]
	}
	// Prefer the configured manager; other enrolled Webs remain available if
	// that manager is down. Stable ordering avoids probing every peer per page.
	sort.SliceStable(peers, func(i, j int) bool {
		if prefer[peers[i].ID] != prefer[peers[j].ID] {
			return prefer[peers[i].ID]
		}
		left, right := peers[i].URL == h.relayManagerURL, peers[j].URL == h.relayManagerURL
		if left != right {
			return left
		}
		return peers[i].ID < peers[j].ID
	})
	return peers
}

func (t *nodeRelayTransport) peerClient(peer relayPeer) (*http.Client, error) {
	certificate := []byte(peer.Certificate)
	if peer.URL == t.handler.relayManagerURL && t.handler.relayManagerCA != "" {
		var err error
		certificate, err = os.ReadFile(t.handler.relayManagerCA)
		if err != nil {
			return nil, err
		}
	}
	key := fmt.Sprintf("%s|%x", peer.URL, sha256.Sum256(certificate))
	t.mu.Lock()
	defer t.mu.Unlock()
	if client := t.clients[key]; client != nil {
		return client, nil
	}
	u, _ := url.Parse(peer.URL)
	tls, err := transporttls.ClientConfigFromPEM(certificate, u.Hostname(), false)
	if err != nil {
		return nil, err
	}
	tls.NextProtos = []string{"h2", "http/1.1"}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tls, ForceAttemptHTTP2: true,
		DialContext:         (&net.Dialer{Timeout: nodeDialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second, IdleConnTimeout: 60 * time.Second, MaxIdleConnsPerHost: 8,
	}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("node relay redirects are not allowed")
	}}
	if t.clients == nil {
		t.clients = make(map[string]*http.Client)
	}
	for oldKey, old := range t.clients {
		if strings.HasPrefix(oldKey, peer.URL+"|") {
			old.CloseIdleConnections()
			delete(t.clients, oldKey)
		}
	}
	t.clients[key] = client
	return client, nil
}

func validNodeRelayPath(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || path.Clean(u.Path) != u.Path || strings.ContainsAny(u.Path, "\\\x00\r\n") {
		return false
	}
	root := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")[0]
	switch root {
	case "health", "system", "interfaces", "security", "ssh-protection", "logs", "maintenance":
		return true
	case "settings":
		return u.Path == "/settings/logging"
	default:
		return false
	}
}

// handleNodeRelay accepts only a fully enrolled node token, never an enrollment
// ticket or a browser cookie. Target credentials are resolved locally and all
// forwarded requests bypass relay fallback, preventing loops and open proxies.
func (h *ServerHandler) handleNodeRelay(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || h.nodeCredentials == nil || !h.nodeCredentials.Authenticate(r.Header.Get(nodeauth.NodeHeader), nodeauth.Bearer(r.Header.Get("Authorization"))) {
		writeError(w, http.StatusUnauthorized, errors.New("node relay requires authenticated TLS node access"))
		return
	}
	w.Header().Set(nodeRelayHeader, "1")
	r.Body = http.MaxBytesReader(w, r.Body, 3<<20)
	var payload nodeRelayRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || len(payload.Body) > nodeRelayBodyLimit || !validNodeRelayPath(payload.Path) {
		writeError(w, http.StatusBadRequest, errors.New("invalid node relay request"))
		return
	}
	switch payload.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		writeError(w, http.StatusBadRequest, errors.New("unsupported node relay method"))
		return
	}
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), payload.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("relay target is not enrolled"))
		return
	}
	client, credential, err := h.nodeHTTPClient(node.ID)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	ctx := context.WithValue(r.Context(), directNodeRequest{}, true)
	req, err := http.NewRequestWithContext(ctx, payload.Method, strings.TrimRight(node.AgentURL, "/")+payload.Path, bytes.NewReader(payload.Body))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if payload.ContentType != "" {
		req.Header.Set("Content-Type", payload.ContentType)
	}
	setNodeAuthHeaders(req, credential)
	// SSE responses may run until the initiating page is closed. Other API
	// calls retain the normal agent request timeout.
	if strings.HasSuffix(req.URL.Path, "/security/scan/events") {
		copy := *client
		copy.Timeout = 0
		client = &copy
	}
	res, err := client.Do(req)
	if err != nil {
		var opError *net.OpError
		if errors.As(err, &opError) && opError.Op == "dial" {
			// Tell the caller only when it is certain the target operation did
			// not start; a different peer may have a working network path.
			w.Header().Set(nodeRelayRetryHeader, "1")
		}
		writeError(w, http.StatusBadGateway, fmt.Errorf("relay target %s: %w", node.ID, err))
		return
	}
	defer res.Body.Close()
	for _, name := range []string{"Content-Type", "Cache-Control", "Content-Disposition", "ETag", "X-Nodewall-Revision"} {
		if value := res.Header.Get(name); value != "" {
			w.Header().Set(name, value)
		}
	}
	w.WriteHeader(res.StatusCode)
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		_ = http.NewResponseController(w).Flush()
		_, _ = io.Copy(flushingResponseWriter{ResponseWriter: w}, res.Body)
		return
	}
	_, _ = io.Copy(w, res.Body)
}
