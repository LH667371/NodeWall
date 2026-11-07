// Package sshconsole owns short-lived SSH sessions created by the web console.
// The service uses its own Ed25519 key; private material never leaves the
// server and is not included in the browser session.
package sshconsole

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultSessionTTL = 30 * time.Minute
	maxSessions       = 32
)

var ErrSessionNotFound = errors.New("ssh session not found")

// HostKeyConfirmationError is returned on the first connection so the UI can
// show the server fingerprint before a session is created. This avoids silently
// accepting an unexpected SSH host key.
type HostKeyConfirmationError struct {
	Fingerprint string
}

func (e *HostKeyConfirmationError) Error() string {
	return "ssh host key confirmation required"
}

type HostKeyMismatchError struct {
	Expected string
	Actual   string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("ssh host key mismatch: expected %s, got %s", e.Expected, e.Actual)
}

type Credentials struct {
	Owner       string
	NodeID      string
	Host        string
	Port        uint16
	User        string
	Fingerprint string
	// Password is retained only for source compatibility with older callers.
	// It is deliberately ignored: NodeWall SSH sessions authenticate solely
	// with the server-owned public key.
	Password string
}

type Info struct {
	Owner       string    `json:"-"`
	ID          string    `json:"id"`
	NodeID      string    `json:"node_id"`
	Host        string    `json:"host"`
	Port        uint16    `json:"port"`
	User        string    `json:"user"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type Session struct {
	Info   Info
	Client *ssh.Client

	mu       sync.Mutex
	lastUsed time.Time
}

type Manager struct {
	mu                sync.Mutex
	sessions          map[string]*Session
	ttl               time.Duration
	keyPath           string
	knownHostsPath    string
	knownFingerprints map[string]string
	signer            ssh.Signer
}

func New() *Manager {
	return NewWithKeyPath("")
}

func NewWithKeyPath(keyPath string) *Manager {
	keyPath = strings.TrimSpace(keyPath)
	knownHostsPath := ""
	if keyPath != "" {
		knownHostsPath = filepath.Join(filepath.Dir(keyPath), "known-hosts.json")
	}
	return &Manager{
		sessions:          make(map[string]*Session),
		ttl:               defaultSessionTTL,
		keyPath:           keyPath,
		knownHostsPath:    knownHostsPath,
		knownFingerprints: make(map[string]string),
	}
}

func (m *Manager) Create(ctx context.Context, credentials Credentials) (*Session, error) {
	if err := validateCredentials(credentials); err != nil {
		return nil, err
	}
	signer, err := m.ensureSigner()
	if err != nil {
		return nil, fmt.Errorf("load NodeWall SSH key: %w", err)
	}

	fingerprint := ""
	var hostKeyError error
	address := net.JoinHostPort(credentials.Host, strconv.Itoa(int(credentials.Port)))
	knownFingerprint, err := m.knownHostFingerprint(address)
	if err != nil {
		return nil, fmt.Errorf("load SSH known hosts: %w", err)
	}
	expectedFingerprint := knownFingerprint
	if expectedFingerprint == "" {
		expectedFingerprint = strings.TrimSpace(credentials.Fingerprint)
	}
	config := &ssh.ClientConfig{
		User:    credentials.User,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
		Timeout: 10 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint = ssh.FingerprintSHA256(key)
			if expectedFingerprint == "" {
				hostKeyError = &HostKeyConfirmationError{Fingerprint: fingerprint}
				return hostKeyError
			}
			if fingerprint != expectedFingerprint {
				hostKeyError = &HostKeyMismatchError{Expected: expectedFingerprint, Actual: fingerprint}
				return hostKeyError
			}
			return nil
		},
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial SSH server: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		if hostKeyError != nil {
			return nil, hostKeyError
		}
		return nil, fmt.Errorf("SSH authentication failed: %w", err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	_ = conn.SetDeadline(time.Time{})
	if err := m.rememberKnownHost(address, fingerprint); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("save SSH known host: %w", err)
	}
	now := time.Now().UTC()
	session := &Session{
		Info: Info{
			Owner:       credentials.Owner,
			ID:          newSessionID(),
			NodeID:      credentials.NodeID,
			Host:        credentials.Host,
			Port:        credentials.Port,
			User:        credentials.User,
			Fingerprint: fingerprint,
			CreatedAt:   now,
			ExpiresAt:   now.Add(m.ttl),
		},
		Client:   client,
		lastUsed: now,
	}

	m.mu.Lock()
	m.pruneLocked(now)
	if len(m.sessions) >= maxSessions {
		m.mu.Unlock()
		_ = client.Close()
		return nil, errors.New("too many active SSH sessions")
	}
	m.sessions[session.Info.ID] = session
	m.mu.Unlock()
	return session, nil
}

// knownHostFingerprint returns the previously confirmed host key fingerprint
// for one SSH endpoint. Keeping this on the server avoids prompting the
// browser again whenever the short-lived web-console session is recreated.
func (m *Manager) knownHostFingerprint(address string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fingerprint := m.knownFingerprints[address]; fingerprint != "" {
		return fingerprint, nil
	}
	if m.knownHostsPath == "" {
		return "", nil
	}
	data, err := os.ReadFile(m.knownHostsPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var hosts map[string]string
	if err := json.Unmarshal(data, &hosts); err != nil {
		return "", err
	}
	for host, fingerprint := range hosts {
		m.knownFingerprints[host] = strings.TrimSpace(fingerprint)
	}
	return m.knownFingerprints[address], nil
}

func (m *Manager) rememberKnownHost(address, fingerprint string) error {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return errors.New("empty SSH host fingerprint")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.knownFingerprints[address] = fingerprint
	if m.knownHostsPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(m.knownFingerprints, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.knownHostsPath), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.knownHostsPath), ".known-hosts-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, m.knownHostsPath); err != nil {
		return err
	}
	return nil
}

func (m *Manager) Get(id string) (*Session, error) {
	id = strings.TrimSpace(id)
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[id]
	if !ok || time.Now().After(session.Info.ExpiresAt) {
		if ok {
			delete(m.sessions, id)
			_ = session.Client.Close()
		}
		return nil, ErrSessionNotFound
	}
	session.mu.Lock()
	session.lastUsed = time.Now().UTC()
	session.mu.Unlock()
	return session, nil
}

func (m *Manager) Close(id string) error {
	m.mu.Lock()
	session, ok := m.sessions[strings.TrimSpace(id)]
	if ok {
		delete(m.sessions, strings.TrimSpace(id))
	}
	m.mu.Unlock()
	if !ok {
		return ErrSessionNotFound
	}
	return session.Client.Close()
}

func (m *Manager) CloseAll() {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for id, session := range m.sessions {
		delete(m.sessions, id)
		sessions = append(sessions, session)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		_ = session.Client.Close()
	}
}

func (m *Manager) pruneLocked(now time.Time) {
	for id, session := range m.sessions {
		session.mu.Lock()
		expired := now.After(session.Info.ExpiresAt) || now.Sub(session.lastUsed) > m.ttl
		session.mu.Unlock()
		if expired {
			delete(m.sessions, id)
			_ = session.Client.Close()
		}
	}
}

func validateCredentials(credentials Credentials) error {
	if strings.TrimSpace(credentials.NodeID) == "" {
		return errors.New("node id is required")
	}
	if strings.TrimSpace(credentials.Host) == "" || strings.ContainsAny(credentials.Host, " /\\\t\r\n") {
		return errors.New("SSH host is invalid")
	}
	if credentials.Port == 0 {
		return errors.New("SSH port must be between 1 and 65535")
	}
	if strings.TrimSpace(credentials.User) == "" || strings.ContainsAny(credentials.User, " \t\r\n") {
		return errors.New("SSH user is invalid")
	}
	return nil
}

func (m *Manager) PublicKey() (string, error) {
	signer, err := m.ensureSigner()
	if err != nil {
		return "", err
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
}

func (m *Manager) ensureSigner() (ssh.Signer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signer != nil {
		return m.signer, nil
	}
	if m.keyPath == "" {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.NewSignerFromKey(privateKey)
		if err != nil {
			return nil, err
		}
		m.signer = signer
		return signer, nil
	}

	privatePEM, err := os.ReadFile(m.keyPath)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(m.keyPath), 0o700); err != nil {
			return nil, err
		}
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(m.keyPath, privatePEM, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(privatePEM)
	if err != nil {
		return nil, err
	}
	m.signer = signer
	return signer, nil
}

func newSessionID() string {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(raw[:])
}
