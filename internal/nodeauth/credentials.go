// Package nodeauth authenticates node APIs independently of browser sessions.
// Each enrolled node has a separate token and a pinned self-signed certificate.
package nodeauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nodewall/internal/securestore"
	"nodewall/internal/transporttls"
)

const NodeHeader = "X-Nodewall-Node-ID"

type Credential struct {
	NodeID      string `json:"node_id"`
	AgentURL    string `json:"agent_url"`
	Token       string `json:"token"`
	Certificate string `json:"certificate"`
}

type Registry struct {
	mu    sync.RWMutex
	path  string
	nodes map[string]Credential
}

// ExportJSON returns all enrolled node credentials for a standby manager
// snapshot. The endpoint exposing this data must require node authentication.
func (r *Registry) ExportJSON() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return json.MarshalIndent(r.nodes, "", "  ")
}

// ReplaceJSON atomically replaces the registry with a manager snapshot. Basic
// credential shape validation prevents a damaged response from disabling all
// node-to-node access on the standby.
func (r *Registry) ReplaceJSON(data []byte) error {
	var next map[string]Credential
	if err := json.Unmarshal(data, &next); err != nil {
		return err
	}
	if next == nil {
		next = make(map[string]Credential)
	}
	for id, credential := range next {
		if strings.TrimSpace(id) == "" || id != credential.NodeID || len(strings.TrimSpace(credential.Token)) < 32 {
			return errors.New("invalid node credential snapshot")
		}
		origin, err := Origin(credential.AgentURL)
		if err != nil || origin != credential.AgentURL {
			return errors.New("invalid node credential endpoint")
		}
		if credential.Certificate == "" {
			return errors.New("node credential certificate is required")
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.nodes
	r.nodes = next
	if r.path != "" {
		encoded, err := json.MarshalIndent(r.nodes, "", "  ")
		if err == nil {
			err = writePrivate(r.path, encoded)
		}
		if err != nil {
			r.nodes = previous
			return err
		}
	}
	return nil
}

func NewToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func LoadOrCreateToken(path string) (string, error) {
	for index, candidate := range append([]string{path}, tokenBackupPaths(path)...) {
		data, err := os.ReadFile(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if index == 0 {
				return "", err
			}
			continue
		}
		token := strings.TrimSpace(string(data))
		if len(token) < 32 {
			continue
		}
		if index > 0 {
			if err := writeTokenAtomic(path, token, true); err != nil {
				return "", err
			}
		} else if err := os.Chmod(path, 0o600); err != nil {
			return "", err
		}
		return token, nil
	}
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	// Another starter may have published the token between the initial scan
	// and generation. Re-read before replacing an existing regular file so all
	// concurrent services converge on the first credential.
	if data, readErr := os.ReadFile(path); readErr == nil {
		if existing := strings.TrimSpace(string(data)); len(existing) >= 32 {
			_ = os.Chmod(path, 0o600)
			return existing, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	_, primaryErr := os.Stat(path)
	rotate := primaryErr == nil
	if err := writeTokenAtomic(path, token, rotate); err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadOrCreateToken(path)
		}
		return "", err
	}
	return token, nil
}

func tokenBackupPaths(path string) []string {
	return []string{path + ".bak.1", path + ".bak.2", path + ".bak.3"}
}

func writeTokenAtomic(path, token string, rotate bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if rotate {
		if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
			return os.ErrExist
		}
	}
	if rotate {
		paths := append([]string{path}, tokenBackupPaths(path)...)
		for i := len(paths) - 1; i >= 1; i-- {
			if info, err := os.Stat(paths[i-1]); err == nil && info.Mode().IsRegular() {
				_ = os.Remove(paths[i])
				_ = os.Rename(paths[i-1], paths[i])
			}
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".node-token-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if !rotate {
		// An exclusive link preserves the stable-token property when multiple
		// services first start at the same time.
		if err := os.Link(tmpPath, path); err != nil {
			return err
		}
		return nil
	}
	return os.Rename(tmpPath, path)
}

func Open(path string) (*Registry, error) {
	r := &Registry{path: path, nodes: make(map[string]Credential)}
	if path == "" {
		return r, nil
	}
	data, encrypted, recovered, err := securestore.ReadValid(path, func(payload []byte) error {
		var candidate map[string]Credential
		return json.Unmarshal(payload, &candidate)
	})
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r.nodes); err != nil {
		return r, err
	}
	if encrypted || recovered {
		if err := writePrivate(path, data); err != nil {
			return r, err
		}
	}
	return r, nil
}

func (r *Registry) Put(c Credential) error {
	if strings.TrimSpace(c.NodeID) == "" || len(c.Token) < 32 {
		return errors.New("node ID and a strong node token are required")
	}
	origin, err := Origin(c.AgentURL)
	if err != nil {
		return err
	}
	c.AgentURL = origin
	u, _ := url.Parse(origin)
	if u.Scheme == "https" {
		block, _ := pem.Decode([]byte(c.Certificate))
		if block == nil {
			return errors.New("agent certificate is required")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		if err := cert.VerifyHostname(u.Hostname()); err != nil {
			return fmt.Errorf("agent certificate hostname: %w", err)
		}
		if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return errors.New("agent certificate is not currently valid")
		}
	} else {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return errors.New("remote node APIs require HTTPS")
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, other := range r.nodes {
		if id != c.NodeID && other.AgentURL == c.AgentURL {
			return errors.New("agent endpoint already belongs to another node")
		}
	}
	previous, existed := r.nodes[c.NodeID]
	r.nodes[c.NodeID] = c
	if r.path != "" {
		data, err := json.MarshalIndent(r.nodes, "", "  ")
		if err == nil {
			err = writePrivate(r.path, data)
		}
		if err != nil {
			if existed {
				r.nodes[c.NodeID] = previous
			} else {
				delete(r.nodes, c.NodeID)
			}
			return err
		}
	}
	return nil
}

func (r *Registry) Get(nodeID string) (Credential, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.nodes[nodeID]
	return c, ok
}

// GetByAgentURL resolves a credential when a re-enrollment changed the node
// ID but the manager's durable node row still carries the same Agent endpoint.
// Endpoint identity is stable across that transition and keeps reverse proxy
// health checks from falling back to the manager certificate.
func (r *Registry) GetByAgentURL(agentURL string) (Credential, bool) {
	want, err := Origin(agentURL)
	if err != nil {
		want = strings.TrimRight(strings.TrimSpace(agentURL), "/")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, credential := range r.nodes {
		candidate, candidateErr := Origin(credential.AgentURL)
		if candidateErr != nil {
			candidate = strings.TrimRight(strings.TrimSpace(credential.AgentURL), "/")
		}
		if candidate == want {
			return credential, true
		}
	}
	return Credential{}, false
}

// Revoke prevents a removed agent from registering itself again on its next
// heartbeat. A new administrator-issued enrollment ticket is required.
func (r *Registry) Revoke(nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous, exists := r.nodes[nodeID]
	if !exists {
		return nil
	}
	delete(r.nodes, nodeID)
	if r.path != "" {
		data, err := json.MarshalIndent(r.nodes, "", "  ")
		if err == nil {
			err = writePrivate(r.path, data)
		}
		if err != nil {
			r.nodes[nodeID] = previous
			return err
		}
	}
	return nil
}

func EqualToken(actual, expected string) bool {
	if expected == "" {
		return false
	}
	a, b := sha256.Sum256([]byte(actual)), sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func Bearer(header string) string {
	prefix, value, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(prefix, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

func (r *Registry) Authenticate(nodeID, token string) bool {
	c, ok := r.Get(nodeID)
	return ok && EqualToken(token, c.Token)
}

func RequireToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !EqualToken(Bearer(req.Header.Get("Authorization")), token) {
			http.Error(w, "node authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func Origin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid node API origin")
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

type Transport struct {
	Registry    *Registry
	DialTimeout time.Duration
	mu          sync.Mutex
	clients     map[string]*http.Transport
}

func (t *Transport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, transport := range t.clients {
		transport.CloseIdleConnections()
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	origin, err := Origin(req.URL.Scheme + "://" + req.URL.Host)
	if err != nil {
		return nil, err
	}
	t.Registry.mu.RLock()
	var credential Credential
	for _, c := range t.Registry.nodes {
		if c.AgentURL == origin {
			credential = c
			break
		}
	}
	t.Registry.mu.RUnlock()
	if credential.Token == "" {
		return nil, errors.New("node is not enrolled; register it before accessing its API")
	}
	// A different certificate creates a different transport, so re-enrollment
	// cannot accidentally reuse a connection trusted by an older certificate.
	cacheKey := origin + "|" + credential.Certificate
	t.mu.Lock()
	if t.clients == nil {
		t.clients = make(map[string]*http.Transport)
	}
	transport := t.clients[cacheKey]
	if transport == nil {
		var tlsConfig *tls.Config
		if req.URL.Scheme == "https" {
			var tlsErr error
			tlsConfig, tlsErr = transporttls.ClientConfigFromPEM([]byte(credential.Certificate), req.URL.Hostname(), false)
			if tlsErr != nil {
				t.mu.Unlock()
				return nil, fmt.Errorf("invalid pinned node certificate: %w", tlsErr)
			}
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		}
		transport = &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
			DialContext:         (&net.Dialer{Timeout: t.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second, IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 8}
		for key, old := range t.clients {
			if strings.HasPrefix(key, origin+"|") {
				old.CloseIdleConnections()
				delete(t.clients, key)
			}
		}
		t.clients[cacheKey] = transport
	}
	t.mu.Unlock()
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Del("Cookie")
	clone.Header.Set("Authorization", "Bearer "+credential.Token)
	clone.Header.Set(NodeHeader, credential.NodeID)
	return transport.RoundTrip(clone)
}

func writePrivate(path string, data []byte) error {
	return securestore.Write(path, data, 0o600)
}
