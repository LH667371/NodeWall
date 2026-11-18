package rollback

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"nodewall/internal/models"
)

type RestoreFunc func(context.Context, Snapshot) error

var ErrPendingNotFound = errors.New("pending publish not found")

type Snapshot struct {
	PublishID        string
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
	sessions map[string]*pendingSession
}

type pendingSession struct {
	Session
	reverting bool
	restoring bool
	wake      chan struct{}
	attempt   *restoreAttempt
}

type restoreAttempt struct {
	done chan struct{}
	err  error
}

func NewManager(timeout time.Duration, restore RestoreFunc) *Manager {
	return &Manager{
		timeout:  timeout,
		restore:  restore,
		sessions: make(map[string]*pendingSession),
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
	snapshot.PublishID = publishID
	session := Session{
		PublishID: publishID,
		Snapshot:  snapshot,
		ExpiresAt: time.Now().Add(timeout),
		Cancel:    cancel,
	}

	pending := &pendingSession{Session: session, wake: make(chan struct{}, 1)}
	m.sessions[publishID] = pending

	go m.watch(sessionCtx, pending)
	return session
}

func (m *Manager) Confirm(publishID string) bool {
	confirmed, _ := m.ConfirmWith(publishID, nil)
	return confirmed
}

// ConfirmWith makes durable confirmation atomic with claiming the safety
// deadline. The commit must not call Manager methods; a failed save leaves the
// snapshot and timer available rather than confirming a volatile policy.
func (m *Manager) ConfirmWith(publishID string, commit func() error) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[publishID]
	if !ok || session.reverting || !session.ExpiresAt.After(time.Now()) {
		return false, nil
	}
	if commit != nil {
		if err := commit(); err != nil {
			return false, err
		}
	}

	session.Cancel()
	delete(m.sessions, publishID)
	return true, nil
}

// CompleteRollback removes a snapshot only after the caller has restored and
// persisted it under its own policy lock. Unlike Confirm, expiry is expected.
func (m *Manager) CompleteRollback(publishID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, ok := m.sessions[publishID]; ok {
		session.Cancel()
		delete(m.sessions, publishID)
	}
}

// RetryRollback schedules recovery without invoking a callback while the caller
// still holds its policy lock. Failed apply handlers use it to avoid deadlock.
func (m *Manager) RetryRollback(publishID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, ok := m.sessions[publishID]; ok {
		session.reverting = true
		select {
		case session.wake <- struct{}{}:
		default:
		}
	}
}

func (m *Manager) RollbackNow(ctx context.Context, publishID string) error {
	m.mu.Lock()
	session, ok := m.sessions[publishID]
	m.mu.Unlock()

	if !ok {
		return ErrPendingNotFound
	}

	return m.restoreSession(ctx, session)
}

func (m *Manager) Pending(publishID string) (Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[publishID]
	if !ok {
		return Session{}, false
	}
	return session.Session, true
}

func (m *Manager) watch(ctx context.Context, session *pendingSession) {
	timer := time.NewTimer(time.Until(session.ExpiresAt))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-session.wake:
			// A manual restore failed before its original timeout. Retain the
			// same snapshot and retry promptly even if the HTTP client left.
			timer.Reset(time.Second)
			continue
		case <-timer.C:
		}
		attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		err := m.restoreSession(attempt, session)
		cancel()
		if err == nil || errors.Is(err, ErrPendingNotFound) {
			return
		}
		timer.Reset(time.Second)
	}
}

func (m *Manager) restoreSession(ctx context.Context, session *pendingSession) error {
	m.mu.Lock()
	if m.sessions[session.PublishID] != session {
		m.mu.Unlock()
		return ErrPendingNotFound
	}
	session.reverting = true
	if session.restoring {
		attempt := session.attempt
		m.mu.Unlock()
		// The safety timer and a manager cancellation can arrive together.
		// Join that restore instead of returning a spurious HTTP conflict or
		// writing the same maps twice. One canceled waiter must not stop it.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-attempt.done:
			return attempt.err
		}
	}
	session.restoring = true
	attempt := &restoreAttempt{done: make(chan struct{})}
	session.attempt = attempt
	m.mu.Unlock()

	// Never hold the manager lock while calling the dataplane: the callback
	// takes the agent's policy lock, and confirmation takes those in reverse.
	err := m.restore(ctx, session.Snapshot)
	m.mu.Lock()
	defer m.mu.Unlock()
	attempt.err = err
	close(attempt.done)
	if m.sessions[session.PublishID] != session {
		return err
	}
	session.restoring = false
	if err == nil {
		delete(m.sessions, session.PublishID)
		session.Cancel()
		return nil
	}
	log.Printf("warning: rollback %s on %s/%s failed; retaining snapshot for retry: %v", session.PublishID, session.Snapshot.Interface, session.Snapshot.Direction, err)
	select {
	case session.wake <- struct{}{}:
	default:
	}
	return err
}
