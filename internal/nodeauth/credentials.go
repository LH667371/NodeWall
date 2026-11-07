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

func NewToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func LoadOrCreateToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if len(token) < 32 {
			return "", errors.New("node token must contain at least 32 characters")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return "", err
		}
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	// Publish a fully written token with an exclusive hard link. Concurrent
	// server/agent startup must never observe an empty credential file.
	file, err := os.CreateTemp(filepath.Dir(path), ".node-token-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.WriteString(token + "\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := os.Link(file.Name(), path); errors.Is(err, os.ErrExist) {
		return LoadOrCreateToken(path)
	} else if err != nil {
		return "", err
	}
	return token, nil
}

func Open(path string) (*Registry, error) {
	r := &Registry{path: path, nodes: make(map[string]Credential)}
	if path == "" {
		return r, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &r.nodes); err != nil {
		return nil, err
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
	Registry *Registry
	mu       sync.Mutex
	clients  map[string]*http.Transport
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
		roots := x509.NewCertPool()
		if req.URL.Scheme == "https" && !roots.AppendCertsFromPEM([]byte(credential.Certificate)) {
			t.mu.Unlock()
			return nil, errors.New("invalid pinned node certificate")
		}
		transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second, IdleConnTimeout: 90 * time.Second}
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
	return transport.RoundTrip(clone)
}

func writePrivate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".nodewall-credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
