package rollback

import (
	"context"
	"errors"
	"sync"
	"time"

	"nodewall/internal/models"
)

type RestoreFunc func(context.Context, Snapshot) error

var ErrPendingNotFound = errors.New("pending publish not found")

type Snapshot struct {
	Direction        models.PolicyDirection
	Interface        string
	Attached         bool
	AttachMode       string
	BypassCIDRs      []string
	BlockedCIDRs     []string
	ICMPAllowCIDRs   []string
	ICMPBlockedCIDRs []string
	Allowlist        []string
	PublicPorts      []uint16
	DeniedPorts      []uint16
	AllowedPorts     []uint16
	PublicPortRules  []models.PortRule
	DeniedPortRules  []models.PortRule
	AllowedPortRules []models.PortRule
	RateLimitRules   []models.RateLimitRule
	TemporaryBlocks  []models.TemporaryBlock
	NonIPv4Action    models.NonIPv4Action
	Challenge        models.ChallengeSpec
	ObserveOnly      bool
}

type Session struct {
	PublishID string
	Snapshot  Snapshot
	ExpiresAt time.Time
	Cancel    context.CancelFunc
}

type Manager struct {
	mu       sync.Mutex
	timeout  time.Duration
	restore  RestoreFunc
	sessions map[string]Session
}

func NewManager(timeout time.Duration, restore RestoreFunc) *Manager {
	return &Manager{
		timeout:  timeout,
		restore:  restore,
		sessions: make(map[string]Session),
	}
}

func (m *Manager) Begin(ctx context.Context, publishID string, snapshot Snapshot) Session {
	return m.BeginWithTimeout(ctx, publishID, snapshot, m.timeout)
}

func (m *Manager) BeginWithTimeout(ctx context.Context, publishID string, snapshot Snapshot, timeout time.Duration) Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if timeout <= 0 {
		timeout = m.timeout
	}

	// The publish request context is canceled as soon as the HTTP handler
	// returns. A rollback session must outlive that request until it is
	// confirmed or its safety timeout expires, so detach the watcher from the
	// request cancellation while retaining any context values.
	if previous, ok := m.sessions[publishID]; ok {
		previous.Cancel()
	}
	sessionCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	session := Session{
		PublishID: publishID,
		Snapshot:  snapshot,
		ExpiresAt: time.Now().Add(timeout),
		Cancel:    cancel,
	}

	m.sessions[publishID] = session

	go m.watch(sessionCtx, session)
	return session
}

func (m *Manager) Confirm(publishID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[publishID]
	if !ok {
		return false
	}

	session.Cancel()
	delete(m.sessions, publishID)
	return true
}

func (m *Manager) RollbackNow(ctx context.Context, publishID string) error {
	m.mu.Lock()
	session, ok := m.sessions[publishID]
	if ok {
		delete(m.sessions, publishID)
	}
	m.mu.Unlock()

	if !ok {
		return ErrPendingNotFound
	}

	session.Cancel()
	return m.restore(ctx, session.Snapshot)
}

func (m *Manager) Pending(publishID string) (Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[publishID]
	return session, ok
}

func (m *Manager) watch(ctx context.Context, session Session) {
	timer := time.NewTimer(time.Until(session.ExpiresAt))
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		m.mu.Lock()
		current, ok := m.sessions[session.PublishID]
		if !ok || !current.ExpiresAt.Equal(session.ExpiresAt) {
			m.mu.Unlock()
			return
		}
		delete(m.sessions, session.PublishID)
		m.mu.Unlock()
		_ = m.restore(context.Background(), session.Snapshot)
	}
}
