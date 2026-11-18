package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/securestore"
	"nodewall/internal/security"
)

const sessionCookieName = "nodewall_session"
const csrfCookieName = "nodewall_csrf"
const loginOTPChallengeCookieName = "nodewall_login_otp"
const localeCookieName = "nodewall_locale"

const (
	authSessionTTL = 12 * time.Hour
	// Captcha challenges are deliberately short-lived and bound to the source
	// address that rendered the login page. The challenge is still one-time,
	// but source binding prevents a copied challenge from being replayed from a
	// different client while the legitimate login page is open.
	loginCaptchaTTL           = 3 * time.Minute
	loginCaptchaLimit         = 4096
	loginPageRateLimit        = 20
	loginRefreshRateLimit     = 8
	loginSubmitRateLimit      = 10
	loginRequestRateWindow    = time.Minute
	loginRateLimitSourceLimit = 8192
	loginAttemptSourceLimit   = 8192
	loginOTPChallengeTTL      = 5 * time.Minute
	loginOTPChallengeLimit    = 8192
	loginOTPMaxAttempts       = 8
	passwordVerifyConcurrency = 4
	// A source lock stops a single client quickly. The higher account threshold
	// also covers distributed password guessing while making it harder for one
	// mistaken client to deny a legitimate account.
	loginAccountMaxFailures = 20
)

type authManager struct {
	enabled           bool
	authFile          string
	settingsFile      string
	smtpFile          string
	webAccess         string
	secureCookie      bool
	trustProxyHeaders bool
	allowedNets       []netip.Prefix
	allowedMACs       map[string]struct{}

	mu                  sync.RWMutex
	sessions            map[string]sessionState
	loginAttempts       map[string]loginAttempt
	loginCaptchas       map[string]loginCaptchaState
	loginOTP            map[string]loginOTPChallenge
	loginRates          map[string]loginRateWindow
	passwordVerifySlots chan struct{}
	otpSetups           map[string]otpSetupState
	settings            models.AuthSecuritySettings
	smtpMu              sync.RWMutex
	smtp                models.SMTPSettings
	mailSender          func(context.Context, string, string, string) error
	emailMu             sync.Mutex
	emailChallenges     map[string]emailChallenge
	webauthnRPID        string
	webauthnOrigins     []string
	webauthnTLSMode     string
	tlsEnabled          bool
	tlsCertFile         string
	tlsKeyFile          string
	webauthnMu          sync.Mutex
	webauthnSessions    map[string]webauthnSession
}

type sessionState struct {
	ExpiresAt time.Time
	Username  string
	Role      string
	CSRFToken string
}

type loginAttempt struct {
	Failures    int
	FirstFailed time.Time
	LockedUntil time.Time
}

type loginRateWindow struct {
	StartedAt time.Time
	Window    time.Duration
	Requests  int
}

type loginCaptchaState struct {
	Kind        string
	Answer      string
	TracePoints []loginCaptchaPoint
	Source      string
	ExpiresAt   time.Time
}

type loginOTPChallenge struct {
	Username  string
	Source    string
	ExpiresAt time.Time
	Attempts  int
}

type otpSetupState struct {
	Secret    string
	ExpiresAt time.Time
}

type webauthnSession struct {
	Data      webauthnlib.SessionData
	Username  string
	Purpose   string
	Label     string
	Source    string
	ExpiresAt time.Time
}

type loginCaptchaPoint struct {
	Step  int
	Label int
	X     int
	Y     int
	Decoy bool
}

type loginCaptchaView struct {
	ID        string
	Kind      string
	Prompt    string
	Image     template.URL
	Points    []loginCaptchaPoint
	Sequence  []int
	ExpiresIn int
}

type loginCaptchaResult uint8

const (
	loginCaptchaInvalid loginCaptchaResult = iota
	loginCaptchaValid
	loginCaptchaExpired
	loginCaptchaSourceChanged
)

func newAuthManager(cfg config.ServerConfig) (*authManager, error) {
	settingsFile := cfg.AuthSettingsFile
	if strings.TrimSpace(settingsFile) == "" {
		settingsFile = "/etc/nodewall/auth-settings.json"
	}
	manager := &authManager{
		enabled:             cfg.AuthEnabled,
		authFile:            cfg.AuthFile,
		settingsFile:        settingsFile,
		smtpFile:            cfg.SMTPSettingsFile,
		webAccess:           strings.ToLower(strings.TrimSpace(cfg.WebAccessMode)),
		secureCookie:        cfg.TLSEnabled || cfg.TrustProxyHeaders,
		trustProxyHeaders:   cfg.TrustProxyHeaders,
		allowedMACs:         make(map[string]struct{}),
		sessions:            make(map[string]sessionState),
		loginAttempts:       make(map[string]loginAttempt),
		loginCaptchas:       make(map[string]loginCaptchaState),
		loginOTP:            make(map[string]loginOTPChallenge),
		loginRates:          make(map[string]loginRateWindow),
		passwordVerifySlots: make(chan struct{}, passwordVerifyConcurrency),
		otpSetups:           make(map[string]otpSetupState),
		emailChallenges:     make(map[string]emailChallenge),
		webauthnRPID:        strings.TrimSpace(cfg.WebAuthnRPID),
		webauthnOrigins:     append([]string(nil), cfg.WebAuthnOrigins...),
		webauthnTLSMode:     "local",
		tlsEnabled:          cfg.TLSEnabled,
		tlsCertFile:         strings.TrimSpace(cfg.TLSCertFile),
		tlsKeyFile:          strings.TrimSpace(cfg.TLSKeyFile),
		webauthnSessions:    make(map[string]webauthnSession),
		settings: normalizeAuthSettings(models.AuthSecuritySettings{
			MaxFailures:         5,
			WindowSeconds:       int((10 * time.Minute) / time.Second),
			LockDurationSeconds: int((15 * time.Minute) / time.Second),
			PasskeyRPID:         strings.TrimSpace(cfg.WebAuthnRPID),
			PasskeyOrigins:      append([]string(nil), cfg.WebAuthnOrigins...),
			// Passkey is an explicit opt-in feature. Keeping configured RP/Origin
			// values is useful for the administrator's prerequisite view, but they
			// must not expose a login method until the setting is enabled.
			PasskeyEnabled: false,
		}),
	}

	for _, cidr := range cfg.AllowedCIDRs {
		prefix, err := parseAllowedPrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse allowed cidr %q: %w", cidr, err)
		}
		manager.allowedNets = append(manager.allowedNets, prefix.Masked())
	}

	for _, ip := range cfg.AllowedIPs {
		prefix, err := parseAllowedPrefix(ip)
		if err != nil {
			return nil, fmt.Errorf("parse allowed ip %q: %w", ip, err)
		}
		manager.allowedNets = append(manager.allowedNets, prefix.Masked())
	}

	for _, mac := range cfg.AllowedMACs {
		normalized := strings.ToLower(strings.TrimSpace(mac))
		if normalized != "" {
			manager.allowedMACs[normalized] = struct{}{}
		}
	}

	if err := manager.loadSettings(); err != nil {
		// Authentication settings are auxiliary to the login database. If a
		// damaged copy and all backups are unavailable, keep the conservative
		// defaults so the management server still starts and an administrator can
		// repair the file through the authenticated settings endpoint.
		log.Printf("warning: load authentication settings failed: %v; using defaults", err)
	}
	if err := manager.loadSMTPSettings(); err != nil {
		log.Printf("warning: load SMTP settings failed: %v; using defaults", err)
	}

	return manager, nil
}

func (a *authManager) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.allowRemote(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}

		switch r.URL.Path {
		case "/login":
			if r.Method == http.MethodGet {
				if a.rejectLoginRate(w, r, "page", loginPageRateLimit) {
					return
				}
				a.serveLogin(w, r, "", "")
				return
			}
			if r.Method == http.MethodPost {
				a.handleLogin(w, r)
				return
			}
		case "/login/otp":
			if r.Method == http.MethodGet {
				a.serveLoginOTP(w, r, "")
				return
			}
			if r.Method == http.MethodPost {
				a.handleLoginOTP(w, r)
				return
			}
		case "/login/forgot":
			if r.Method == http.MethodGet {
				a.serveForgotPassword(w, r)
				return
			}
		case "/login/captcha/refresh":
			if r.Method == http.MethodPost {
				a.handleLoginCaptchaRefresh(w, r)
				return
			}
		case "/logout":
			if r.Method != http.MethodGet {
				if session, ok := a.sessionFromRequest(r); ok && !a.validSessionCSRF(r, session) {
					writeError(w, http.StatusForbidden, errors.New("csrf validation failed"))
					return
				}
			}
			a.handleLogout(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/join/") || r.URL.Path == "/version" ||
			strings.HasPrefix(r.URL.Path, "/auth/forgot-password/") ||
			strings.HasPrefix(r.URL.Path, "/auth/passkey/login/") {
			next.ServeHTTP(w, r)
			return
		}
		// The favicon is part of the login page shell, so it must remain
		// reachable before a session exists. Only this single static asset is
		// public; all application resources and APIs stay behind auth.
		if r.URL.Path == "/nodewall-mark.svg" {
			next.ServeHTTP(w, r)
			return
		}

		session, ok := a.sessionFromRequest(r)
		if ok {
			if isStateChangingMethod(r.Method) && !a.validSessionCSRF(r, session) {
				writeError(w, http.StatusForbidden, errors.New("csrf validation failed"))
				return
			}
			if !a.authorize(session.Role, r) {
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error": "permission denied",
				})
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if strings.Contains(r.Header.Get("Accept"), "text/html") || r.URL.Path == "/" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "authentication required",
		})
	})
}

func (a *authManager) hasSession(r *http.Request) bool {
	_, ok := a.sessionFromRequest(r)
	return ok
}

func (a *authManager) verifyCurrentPassword(r *http.Request, password string) bool {
	if !a.enabled {
		// Development installations have no password database; still require an
		// explicit confirmation value so a risky port change is never accidental.
		return strings.TrimSpace(password) != ""
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return false
	}
	session, ok := a.sessionFromRequest(r)
	if !ok {
		return false
	}
	users, err := security.LoadUserStore(a.authFile)
	if err != nil {
		return false
	}
	user, _ := users.Find(session.Username)
	return user != nil && user.Enabled && security.VerifyPassword(password, user.Password)
}

func (a *authManager) sessionFromRequest(r *http.Request) (sessionState, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return sessionState{}, false
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.sessions[cookie.Value]
	if !ok {
		return sessionState{}, false
	}
	if !session.ExpiresAt.IsZero() && session.ExpiresAt.Before(time.Now()) {
		delete(a.sessions, cookie.Value)
		return sessionState{}, false
	}
	return session, true
}

func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func (a *authManager) validSessionCSRF(r *http.Request, session sessionState) bool {
	token := strings.TrimSpace(r.Header.Get("X-NodeWall-CSRF"))
	if token == "" || session.CSRFToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(session.CSRFToken)) == 1
}

// requestIsHTTPS only accepts a forwarded scheme when the administrator has
// explicitly declared that the listener is behind a trusted TLS proxy. A
// client can otherwise send X-Forwarded-Proto directly and incorrectly make a
// plain HTTP request look like a secure WebAuthn origin.
func (a *authManager) requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return a.trustProxyHeaders && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// verifyLoginPassword bounds concurrent Argon2 work. Without a small global
// budget, an attacker can rotate source addresses and turn the deliberately
// expensive password hash into a memory exhaustion primitive.
func (a *authManager) verifyLoginPassword(ctx context.Context, password string, record security.PasswordRecord) bool {
	if a.passwordVerifySlots == nil {
		return security.VerifyPassword(password, record)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case a.passwordVerifySlots <- struct{}{}:
		defer func() { <-a.passwordVerifySlots }()
		return security.VerifyPassword(password, record)
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

func (a *authManager) issueSession(w http.ResponseWriter, username, role string) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	csrfToken, err := randomToken()
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.sessions == nil {
		a.sessions = make(map[string]sessionState)
	}
	a.sessions[token] = sessionState{
		ExpiresAt: time.Now().Add(authSessionTTL),
		Username:  username,
		Role:      security.NormalizeRole(role),
		CSRFToken: csrfToken,
	}
	a.mu.Unlock()
	a.setSessionCookies(w, token, csrfToken)
	return nil
}

func (a *authManager) setSessionCookies(w http.ResponseWriter, token, csrfToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   a.secureCookie,
		MaxAge:   int(authSessionTTL / time.Second),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
		Secure:   a.secureCookie,
		MaxAge:   int(authSessionTTL / time.Second),
	})
}

func clearSessionCookies(w http.ResponseWriter, secure bool) {
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: name == sessionCookieName,
			SameSite: http.SameSiteStrictMode,
			Secure:   secure,
		})
	}
}

func (a *authManager) revokeUserSessions(username, keepToken string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for token, session := range a.sessions {
		if strings.EqualFold(session.Username, username) && token != keepToken {
			delete(a.sessions, token)
		}
	}
}

func (a *authManager) authorize(role string, r *http.Request) bool {
	path := r.URL.Path
	role = security.NormalizeRole(role)
	if path == "/settings/auth" || strings.HasPrefix(path, "/settings/smtp") {
		return role == security.RoleAdmin
	}
	if path == "/settings/passkey" {
		return role == security.RoleAdmin
	}
	if path == "/auth/users" || strings.HasPrefix(path, "/auth/users/") {
		return role == security.RoleAdmin
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if path == "/auth/session" || path == "/logout" {
		return true
	}
	if role == security.RoleAdmin {
		return true
	}
	if strings.HasPrefix(path, "/auth/users") {
		return false
	}
	if path == "/settings/auth" {
		return false
	}
	if path == "/auth/password" {
		return true
	}
	if strings.HasPrefix(path, "/account/") {
		return true
	}
	if path == "/settings/logging" {
		return role == security.RoleOperator
	}
	if role == security.RoleViewer {
		return false
	}
	return true
}

func (a *authManager) handleLogin(w http.ResponseWriter, r *http.Request) {
	if a.rejectLoginRate(w, r, "submit", loginSubmitRateLimit) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		a.serveLogin(w, r, "loginErrorInvalidForm", "")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		username = "admin"
	}
	sourceKey := loginSourceKey(r)
	accountKey := loginAccountKey(username)
	if _, blocked := a.loginLockedUntil(sourceKey); blocked {
		a.serveLogin(w, r, "loginErrorLocked", username)
		return
	}
	if accountKey != "" {
		if _, blocked := a.loginLockedUntil(accountKey); blocked {
			a.serveLogin(w, r, "loginErrorLocked", username)
			return
		}
	}
	if result := a.validateLoginCaptchaForSource(r.FormValue("captcha_id"), r.FormValue("captcha_answer"), sourceKey); result != loginCaptchaValid {
		// Expired, refreshed, or mistyped challenges are not password guesses.
		// The independent submit limiter still bounds automated captcha attempts.
		errorKey := "loginErrorCaptcha"
		if result == loginCaptchaExpired {
			errorKey = "loginErrorCaptchaExpired"
		} else if result == loginCaptchaSourceChanged {
			errorKey = "loginErrorCaptchaSourceChanged"
		}
		a.serveLogin(w, r, errorKey, username)
		return
	}

	password := r.FormValue("password")
	store, err := security.LoadUserStore(a.authFile)
	user, userIndex := store.Find(username)
	passwordRecord := security.DummyPasswordRecord()
	if user != nil {
		passwordRecord = user.Password
	}
	passwordValid := a.verifyLoginPassword(r.Context(), password, passwordRecord)
	// Legacy SHA-256 records are intentionally supported for migration, but
	// their verification is much faster than Argon2id. Run the dummy Argon2id
	// work as well so an attacker cannot enumerate accounts by timing old versus
	// migrated password records.
	if user != nil && security.NeedsRehash(user.Password) {
		_ = a.verifyLoginPassword(r.Context(), password, security.DummyPasswordRecord())
	}
	if err != nil || user == nil || !user.Enabled || !passwordValid {
		a.recordLoginFailure(sourceKey)
		if accountKey != "" {
			a.recordLoginFailureWithLimit(accountKey, loginAccountMaxFailures)
		}
		time.Sleep(400 * time.Millisecond)
		a.serveLogin(w, r, "loginErrorInvalidCredentials", username)
		return
	}
	if security.NeedsRehash(user.Password) {
		if upgraded, upgradeErr := security.NewPasswordRecord(password); upgradeErr == nil {
			user.Password = upgraded
			store.Users[userIndex] = *user
			if saveErr := security.SaveUserStore(a.authFile, store); saveErr != nil {
				log.Printf("warning: upgrade password hash for %q: %v", user.Username, saveErr)
			}
		}
	}
	a.mu.RLock()
	securitySettings := a.settings
	a.mu.RUnlock()
	policyRequiresMFA := securitySettings.MFARequired || (securitySettings.RequireMFAForAdmin && security.NormalizeRole(user.Role) == security.RoleAdmin)
	otpAllowed := false
	for _, method := range securitySettings.AllowedMFAMethods {
		if method == "otp" {
			otpAllowed = true
			break
		}
	}
	if policyRequiresMFA && (!user.MFA.OTPEnabled || !otpAllowed) {
		a.recordLoginFailure(sourceKey)
		a.serveLogin(w, r, "loginErrorMFA", username)
		return
	}
	if user.MFA.OTPEnabled && otpAllowed {
		challengeID, challengeErr := a.createLoginOTPChallenge(user.Username, sourceKey)
		if challengeErr != nil {
			a.serveLogin(w, r, "loginErrorSessionCreate", username)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     loginOTPChallengeCookieName,
			Value:    challengeID,
			Path:     "/login/otp",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   a.secureCookie,
			MaxAge:   int(loginOTPChallengeTTL / time.Second),
		})
		locale := loginLocaleFromRequest(r)
		location := "/login/otp?lang=" + url.QueryEscape(locale)
		http.Redirect(w, r, location, http.StatusSeeOther)
		return
	}

	if err := a.issueSession(w, user.Username, user.Role); err != nil {
		a.serveLogin(w, r, "loginErrorSessionCreate", username)
		return
	}

	a.mu.Lock()
	delete(a.loginAttempts, sourceKey)
	if accountKey != "" {
		delete(a.loginAttempts, accountKey)
	}
	a.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *authManager) createLoginOTPChallenge(username, source string) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loginOTP == nil {
		a.loginOTP = make(map[string]loginOTPChallenge)
	}
	for id, challenge := range a.loginOTP {
		if !challenge.ExpiresAt.After(now) {
			delete(a.loginOTP, id)
		}
	}
	if len(a.loginOTP) >= loginOTPChallengeLimit {
		return "", errors.New("too many pending OTP login challenges")
	}
	a.loginOTP[token] = loginOTPChallenge{
		Username:  username,
		Source:    source,
		ExpiresAt: now.Add(loginOTPChallengeTTL),
	}
	return token, nil
}

func (a *authManager) takeLoginOTPChallenge(r *http.Request) (string, loginOTPChallenge, bool) {
	cookie, err := r.Cookie(loginOTPChallengeCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", loginOTPChallenge{}, false
	}
	token := strings.TrimSpace(cookie.Value)
	a.mu.Lock()
	defer a.mu.Unlock()
	challenge, ok := a.loginOTP[token]
	if !ok || !challenge.ExpiresAt.After(time.Now()) {
		delete(a.loginOTP, token)
		return token, loginOTPChallenge{}, false
	}
	if challenge.Source != "" && challenge.Source != loginSourceKey(r) {
		return token, loginOTPChallenge{}, false
	}
	return token, challenge, true
}

func clearLoginOTPChallengeCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginOTPChallengeCookieName,
		Value:    "",
		Path:     "/login/otp",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	})
}

func (a *authManager) handleLoginOTP(w http.ResponseWriter, r *http.Request) {
	if a.rejectLoginRate(w, r, "otp-login", loginSubmitRateLimit) {
		return
	}
	token, challenge, ok := a.takeLoginOTPChallenge(r)
	if !ok {
		clearLoginOTPChallengeCookie(w, a.secureCookie)
		a.serveLoginOTP(w, r, "loginOTPExpired")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		a.serveLoginOTP(w, r, "loginErrorInvalidForm")
		return
	}
	code := strings.TrimSpace(r.FormValue("otp_code"))
	store, err := security.LoadUserStore(a.authFile)
	user, userIndex := store.Find(challenge.Username)
	valid := err == nil && user != nil && user.Enabled && user.MFA.OTPEnabled && security.VerifyTOTPCode(user.MFA.OTPSecret, code, time.Now())
	if !valid && err == nil && user != nil && user.Enabled && user.MFA.OTPEnabled {
		var remaining []string
		remaining, valid = security.ConsumeRecoveryCode(code, user.MFA.RecoveryCodeHashes)
		if valid {
			user.MFA.RecoveryCodeHashes = remaining
			if userIndex >= 0 {
				store.Users[userIndex] = *user
			}
			if saveErr := security.SaveUserStore(a.authFile, store); saveErr != nil {
				valid = false
			}
		}
	}
	if !valid {
		var pending loginOTPChallenge
		var exists bool
		a.mu.Lock()
		pending, exists = a.loginOTP[token]
		if exists {
			pending.Attempts++
			if pending.Attempts >= loginOTPMaxAttempts {
				delete(a.loginOTP, token)
			} else {
				a.loginOTP[token] = pending
			}
		}
		a.mu.Unlock()
		a.recordLoginFailure(challenge.Source)
		a.recordLoginFailureWithLimit(loginAccountKey(challenge.Username), loginAccountMaxFailures)
		if !exists || pending.Attempts >= loginOTPMaxAttempts {
			clearLoginOTPChallengeCookie(w, a.secureCookie)
			a.serveLoginOTP(w, r, "loginOTPExpired")
			return
		}
		a.serveLoginOTP(w, r, "loginErrorMFA")
		return
	}

	a.mu.Lock()
	delete(a.loginOTP, token)
	delete(a.loginAttempts, challenge.Source)
	delete(a.loginAttempts, loginAccountKey(challenge.Username))
	a.mu.Unlock()
	if err := a.issueSession(w, user.Username, user.Role); err != nil {
		clearLoginOTPChallengeCookie(w, a.secureCookie)
		a.serveLoginOTP(w, r, "loginErrorSessionCreate")
		return
	}
	clearLoginOTPChallengeCookie(w, a.secureCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *authManager) serveLoginOTP(w http.ResponseWriter, r *http.Request, errorKey string) {
	locale := loginLocaleFromRequest(r)
	msg := loginMessages(locale)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	tmpl := template.Must(template.New("login-otp").Parse(loginOTPHTML))
	_ = tmpl.Execute(w, map[string]any{
		"Locale": locale, "Title": msg["otpLoginTitle"], "Hint": msg["otpLoginHint"],
		"Code": msg["otpLoginCode"], "Submit": msg["otpLoginSubmit"],
		"Back": msg["otpLoginBack"], "Error": msg[errorKey],
	})
}

func (a *authManager) handleLoginCaptchaRefresh(w http.ResponseWriter, r *http.Request) {
	source := loginSourceKey(r)
	if until, blocked := a.loginLockedUntil(source); blocked {
		writeLoginRateLimited(w, r, time.Until(until), "loginLockedRetry")
		return
	}
	if a.rejectLoginRate(w, r, "captcha-refresh", loginRefreshRateLimit) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid captcha refresh request", http.StatusBadRequest)
		return
	}
	challengeID := strings.TrimSpace(r.FormValue("captcha_id"))
	if challengeID == "" || len(challengeID) > 128 {
		http.Error(w, "invalid captcha refresh request", http.StatusBadRequest)
		return
	}
	a.discardLoginCaptcha(challengeID)
	a.serveLogin(w, r, "", "")
}

func (a *authManager) discardLoginCaptcha(id string) {
	a.mu.Lock()
	delete(a.loginCaptchas, id)
	a.mu.Unlock()
}

func (a *authManager) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	clearSessionCookies(w, a.secureCookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *authManager) serveLogin(w http.ResponseWriter, r *http.Request, errorKey, username string) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	locale := loginLocaleFromRequest(r)
	msg := loginMessages(locale)
	retryAfter := 0
	for _, key := range []string{loginSourceKey(r), loginAccountKey(username)} {
		if until, locked := a.loginLockedUntil(key); locked {
			if seconds := loginRetrySeconds(time.Until(until)); seconds > retryAfter {
				retryAfter = seconds
			}
		}
	}
	lockedMessage := msg["loginErrorLocked"]
	if retryAfter > 0 {
		errorKey = "loginErrorLocked"
		lockedMessage = fmt.Sprintf(msg["loginLockedRetry"], retryAfter)
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	captcha, err := a.newLoginCaptchaForSource(loginSourceKey(r))
	if err != nil {
		http.Error(w, "unable to prepare login verification", http.StatusInternalServerError)
		return
	}
	if captcha.Kind == "trace" {
		labels := make([]string, len(captcha.Sequence))
		for i, label := range captcha.Sequence {
			labels[i] = fmt.Sprint(label)
		}
		captcha.Prompt = fmt.Sprintf(msg["captchaTracePrompt"], strings.Join(labels, " → "))
	}
	w.Header().Set("Cache-Control", "no-store")
	if queryLocale := strings.TrimSpace(r.URL.Query().Get("lang")); queryLocale != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     localeCookieName,
			Value:    normalizeLoginLocale(queryLocale),
			Path:     "/",
			MaxAge:   31536000,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Secure:   a.secureCookie,
		})
	}
	tmpl := template.Must(template.New("login").Parse(loginPageHTML))
	_ = tmpl.Execute(w, map[string]any{
		"Locale":                         locale,
		"Title":                          msg["title"],
		"UsernamePlaceholder":            msg["usernamePlaceholder"],
		"PasswordPlaceholder":            msg["passwordPlaceholder"],
		"Submit":                         msg["submit"],
		"LocaleLabel":                    msg["localeLabel"],
		"LocaleChinese":                  msg["localeChinese"],
		"LocaleEnglish":                  msg["localeEnglish"],
		"ForgotLink":                     msg["forgotLink"],
		"PasskeyLogin":                   msg["passkeyLogin"],
		"LoginErrorInvalidForm":          msg["loginErrorInvalidForm"],
		"LoginErrorLocked":               lockedMessage,
		"LoginErrorInvalidCreds":         msg["loginErrorInvalidCredentials"],
		"LoginErrorCaptcha":              msg["loginErrorCaptcha"],
		"LoginErrorCaptchaExpired":       msg["loginErrorCaptchaExpired"],
		"LoginErrorCaptchaSourceChanged": msg["loginErrorCaptchaSourceChanged"],
		"LoginErrorMFA":                  msg["loginErrorMFA"],
		"LoginErrorSessionCreate":        msg["loginErrorSessionCreate"],
		"PasskeyLoginUnavailable":        msg["passkeyLoginUnavailable"],
		"PasskeyLoginFailed":             msg["passkeyLoginFailed"],
		"PasskeyLoginOrigin":             msg["passkeyLoginOrigin"],
		"PasskeyLoginUnsupported":        msg["passkeyLoginUnsupported"],
		"PasskeyLoginDisabled":           msg["passkeyLoginDisabled"],
		"CaptchaRefreshFailed":           msg["captchaRefreshFailed"],
		"LoginRequestFailed":             msg["loginRequestFailed"],
		"LoginNetworkFailed":             msg["loginNetworkFailed"],
		"MFALabel":                       msg["mfaLabel"],
		"MFAPlaceholder":                 msg["mfaPlaceholder"],
		"MFAHint":                        msg["mfaHint"],
		"CaptchaLabel":                   msg["captchaLabel"],
		"CaptchaPlaceholder":             msg["captchaPlaceholder"],
		"CaptchaMathPlaceholder":         msg["captchaMathPlaceholder"],
		"CaptchaLettersLabel":            msg["captchaLettersLabel"],
		"CaptchaMathLabel":               msg["captchaMathLabel"],
		"CaptchaRefresh":                 msg["captchaRefresh"],
		"CaptchaTraceHint":               msg["captchaTraceHint"],
		"CaptchaTraceDone":               msg["captchaTraceDone"],
		"CaptchaTraceReset":              msg["captchaTraceReset"],
		"CaptchaImageAlt":                msg["captchaImageAlt"],
		"BrandSubtitle":                  msg["brandSubtitle"],
		"BrandCopy":                      msg["brandCopy"],
		"BrandDescription":               msg["brandDescription"],
		"BrandMeta":                      msg["brandMeta"],
		"PasskeyEnabled":                 a.passkeyEnabled(),
		"ErrorKey":                       errorKey,
		"Username":                       username,
		"Captcha":                        captcha,
		"RetryAfter":                     retryAfter,
	})
}

func (a *authManager) newLoginCaptcha() (loginCaptchaView, error) {
	return a.newLoginCaptchaForSource("")
}

func (a *authManager) newLoginCaptchaForSource(source string) (loginCaptchaView, error) {
	id, err := randomToken()
	if err != nil {
		return loginCaptchaView{}, err
	}
	kindIndex, err := secureRandomInt(3)
	if err != nil {
		return loginCaptchaView{}, err
	}
	view := loginCaptchaView{ID: id, ExpiresIn: int(loginCaptchaTTL / time.Second)}
	state := loginCaptchaState{ExpiresAt: time.Now().Add(loginCaptchaTTL)}
	switch kindIndex {
	case 0:
		left, err := secureRandomInt(8)
		if err != nil {
			return loginCaptchaView{}, err
		}
		right, err := secureRandomInt(8)
		if err != nil {
			return loginCaptchaView{}, err
		}
		// Two-digit operands keep the visual challenge human-solvable while
		// avoiding the tiny answer space of the old 2..9 arithmetic puzzle.
		left += 10
		right += 10
		subtract, err := secureRandomInt(2)
		if err != nil {
			return loginCaptchaView{}, err
		}
		if subtract == 1 {
			if left < right {
				left, right = right, left
			}
			view.Prompt = fmt.Sprintf("%d − %d = ?", left, right)
			state.Answer = fmt.Sprint(left - right)
		} else {
			view.Prompt = fmt.Sprintf("%d + %d = ?", left, right)
			state.Answer = fmt.Sprint(left + right)
		}
		view.Kind = "math"
		view.Image, err = makeLoginCaptchaImage(view.Prompt)
		if err != nil {
			return loginCaptchaView{}, err
		}
	case 1:
		const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
		var code strings.Builder
		for i := 0; i < 6; i++ {
			index, err := secureRandomInt(int64(len(alphabet)))
			if err != nil {
				return loginCaptchaView{}, err
			}
			code.WriteByte(alphabet[index])
		}
		view.Kind = "letters"
		state.Answer = code.String()
		view.Image, err = makeLoginCaptchaImage(state.Answer)
		if err != nil {
			return loginCaptchaView{}, err
		}
	case 2:
		view.Kind = "trace"
		patterns := [][]loginCaptchaPoint{
			{{Step: 1, X: 12, Y: 68}, {Step: 2, X: 31, Y: 23}, {Step: 3, X: 51, Y: 70}, {Step: 4, X: 71, Y: 28}, {Step: 5, X: 88, Y: 66}},
			{{Step: 1, X: 15, Y: 25}, {Step: 2, X: 34, Y: 70}, {Step: 3, X: 52, Y: 30}, {Step: 4, X: 70, Y: 72}, {Step: 5, X: 86, Y: 24}},
			{{Step: 1, X: 14, Y: 52}, {Step: 2, X: 34, Y: 23}, {Step: 3, X: 50, Y: 76}, {Step: 4, X: 69, Y: 30}, {Step: 5, X: 87, Y: 58}},
			{{Step: 1, X: 14, Y: 72}, {Step: 2, X: 31, Y: 35}, {Step: 3, X: 51, Y: 22}, {Step: 4, X: 70, Y: 40}, {Step: 5, X: 87, Y: 72}},
		}
		patternIndex, err := secureRandomInt(int64(len(patterns)))
		if err != nil {
			return loginCaptchaView{}, err
		}
		sequence := []int{1, 2, 3, 4, 5}
		for i := len(sequence) - 1; i > 0; i-- {
			j, err := secureRandomInt(int64(i + 1))
			if err != nil {
				return loginCaptchaView{}, err
			}
			sequence[i], sequence[j] = sequence[j], sequence[i]
		}
		view.Sequence = sequence
		answer := make([]string, len(sequence))
		for i, label := range sequence {
			point := patterns[patternIndex][label-1]
			target := loginCaptchaPoint{
				Step: i + 1, Label: label, X: point.X, Y: point.Y,
			}
			view.Points = append(view.Points, target)
			state.TracePoints = append(state.TracePoints, target)
			answer[i] = fmt.Sprint(label)
		}
		state.Answer = strings.Join(answer, "-")
		for i := 0; i < 3; i++ {
			point, err := randomTraceDecoy(view.Points)
			if err != nil {
				return loginCaptchaView{}, err
			}
			view.Points = append(view.Points, point)
		}
		view.Image, err = makeLoginTraceCaptchaImage(view.Points)
		if err != nil {
			return loginCaptchaView{}, err
		}
	}
	state.Kind = view.Kind
	state.Source = strings.TrimSpace(source)

	now := time.Now()
	a.mu.Lock()
	if a.loginCaptchas == nil {
		a.loginCaptchas = make(map[string]loginCaptchaState)
	}
	for challengeID, challenge := range a.loginCaptchas {
		if !challenge.ExpiresAt.After(now) {
			delete(a.loginCaptchas, challengeID)
		}
	}
	for len(a.loginCaptchas) >= loginCaptchaLimit {
		var oldestID string
		var oldest time.Time
		for challengeID, challenge := range a.loginCaptchas {
			if oldestID == "" || challenge.ExpiresAt.Before(oldest) {
				oldestID, oldest = challengeID, challenge.ExpiresAt
			}
		}
		delete(a.loginCaptchas, oldestID)
	}
	a.loginCaptchas[id] = state
	a.mu.Unlock()
	return view, nil
}

func (a *authManager) consumeLoginCaptcha(id, answer string) bool {
	return a.consumeLoginCaptchaForSource(id, answer, "")
}

func (a *authManager) consumeLoginCaptchaForSource(id, answer, source string) bool {
	return a.validateLoginCaptchaForSource(id, answer, source) == loginCaptchaValid
}

func (a *authManager) validateLoginCaptchaForSource(id, answer, source string) loginCaptchaResult {
	a.mu.Lock()
	challenge, ok := a.loginCaptchas[id]
	if ok && challenge.Source != "" && challenge.Source != strings.TrimSpace(source) {
		a.mu.Unlock()
		return loginCaptchaSourceChanged
	}
	if ok {
		delete(a.loginCaptchas, id)
	}
	a.mu.Unlock()
	if !ok || !challenge.ExpiresAt.After(time.Now()) {
		return loginCaptchaExpired
	}
	if len(answer) > 256 {
		return loginCaptchaInvalid
	}
	if challenge.Kind == "trace" {
		if validateLoginTraceAnswer(answer, challenge.TracePoints) {
			return loginCaptchaValid
		}
		return loginCaptchaInvalid
	}
	answer = strings.ToUpper(strings.TrimSpace(answer))
	if challenge.Kind == "math" {
		// Chinese IMEs can produce full-width digits; compare the numeric result
		// so equivalent input such as 03 and ３ is accepted for arithmetic only.
		answer = strings.Map(func(char rune) rune {
			if char >= '０' && char <= '９' {
				return char - '０' + '0'
			}
			return char
		}, answer)
		value, err := strconv.ParseUint(answer, 10, 32)
		if err != nil {
			return loginCaptchaInvalid
		}
		answer = strconv.FormatUint(value, 10)
	}
	if subtle.ConstantTimeCompare([]byte(answer), []byte(challenge.Answer)) == 1 {
		return loginCaptchaValid
	}
	return loginCaptchaInvalid
}

func (a *authManager) allowLoginRequest(source, action string, limit int, window time.Duration) (bool, time.Duration) {
	return a.allowLoginRequestAt(source, action, limit, window, time.Now())
}

func (a *authManager) allowLoginRequestAt(source, action string, limit int, window time.Duration, now time.Time) (bool, time.Duration) {
	if limit <= 0 || window <= 0 {
		return false, window
	}
	if strings.TrimSpace(source) == "" {
		source = "unknown"
	}
	key := source + "\x00" + action
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loginRates == nil {
		a.loginRates = make(map[string]loginRateWindow)
	}
	for existingKey, state := range a.loginRates {
		if now.Sub(state.StartedAt) >= state.Window {
			delete(a.loginRates, existingKey)
		}
	}
	state, exists := a.loginRates[key]
	if !exists || now.Sub(state.StartedAt) >= window {
		if !exists && len(a.loginRates) >= loginRateLimitSourceLimit {
			var oldestKey string
			var oldest time.Time
			for candidate, entry := range a.loginRates {
				if oldestKey == "" || entry.StartedAt.Before(oldest) {
					oldestKey, oldest = candidate, entry.StartedAt
				}
			}
			delete(a.loginRates, oldestKey)
		}
		state = loginRateWindow{StartedAt: now, Window: window}
	}
	if state.Requests >= limit {
		return false, state.StartedAt.Add(state.Window).Sub(now)
	}
	state.Requests++
	a.loginRates[key] = state
	return true, 0
}

func (a *authManager) rejectLoginRate(w http.ResponseWriter, r *http.Request, action string, limit int) bool {
	allowed, retryAfter := a.allowLoginRequest(loginSourceKey(r), action, limit, loginRequestRateWindow)
	if allowed {
		return false
	}
	messageKey := "loginRateLimited"
	if action == "captcha-refresh" {
		messageKey = "captchaRefreshRateLimited"
	}
	writeLoginRateLimited(w, r, retryAfter, messageKey)
	return true
}

func loginRetrySeconds(retryAfter time.Duration) int {
	seconds := int(retryAfter.Seconds())
	if time.Duration(seconds)*time.Second < retryAfter {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return seconds
}

func writeLoginRateLimited(w http.ResponseWriter, r *http.Request, retryAfter time.Duration, messageKey string) {
	seconds := loginRetrySeconds(retryAfter)
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	message := loginMessages(loginLocaleFromRequest(r))[messageKey]
	if strings.Contains(message, "%d") {
		message = fmt.Sprintf(message, seconds)
	}
	http.Error(w, message, http.StatusTooManyRequests)
}

const (
	loginTraceImageWidth  = 320
	loginTraceImageHeight = 150
)

func validateLoginTraceAnswer(answer string, expected []loginCaptchaPoint) bool {
	if len(expected) == 0 {
		return false
	}
	clicks := strings.Split(strings.TrimSpace(answer), ";")
	if len(clicks) != len(expected) {
		return false
	}
	for i, click := range clicks {
		coordinates := strings.Split(click, ",")
		if len(coordinates) != 2 {
			return false
		}
		x, errX := strconv.ParseFloat(coordinates[0], 64)
		y, errY := strconv.ParseFloat(coordinates[1], 64)
		if errX != nil || errY != nil || x < 0 || x > 100 || y < 0 || y > 100 {
			return false
		}
		// Compare in the image's pixel space so the click tolerance stays
		// consistent when the responsive image is rendered at different sizes.
		dx := (x - float64(expected[i].X)) * float64(loginTraceImageWidth) / 100
		dy := (y - float64(expected[i].Y)) * float64(loginTraceImageHeight) / 100
		if dx*dx+dy*dy > 24*24 {
			return false
		}
	}
	return true
}

func encodeLoginTraceAnswer(points []loginCaptchaPoint) string {
	coordinates := make([]string, len(points))
	for i, point := range points {
		coordinates[i] = fmt.Sprintf("%.2f,%.2f", float64(point.X), float64(point.Y))
	}
	return strings.Join(coordinates, ";")
}

func secureRandomInt(max int64) (int64, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return value.Int64(), nil
}

func randomTraceDecoy(existing []loginCaptchaPoint) (loginCaptchaPoint, error) {
	for attempt := 0; attempt < 100; attempt++ {
		xOffset, err := secureRandomInt(80)
		if err != nil {
			return loginCaptchaPoint{}, err
		}
		yOffset, err := secureRandomInt(70)
		if err != nil {
			return loginCaptchaPoint{}, err
		}
		point := loginCaptchaPoint{X: 10 + int(xOffset), Y: 15 + int(yOffset), Decoy: true}
		separated := true
		for _, other := range existing {
			dx := (point.X - other.X) * 3
			dy := (point.Y - other.Y) * 13 / 10
			if dx*dx+dy*dy < 38*38 {
				separated = false
				break
			}
		}
		if separated {
			return point, nil
		}
	}
	return loginCaptchaPoint{}, fmt.Errorf("unable to position trace captcha decoy")
}

func normalizeLoginLocale(locale string) string {
	switch strings.ToLower(strings.TrimSpace(locale)) {
	case "en", "en-us":
		return "en-US"
	default:
		return "zh-CN"
	}
}

func loginLocaleFromRequest(r *http.Request) string {
	if locale := strings.TrimSpace(r.URL.Query().Get("lang")); locale != "" {
		return normalizeLoginLocale(locale)
	}
	if locale := strings.TrimSpace(r.FormValue("locale")); locale != "" {
		return normalizeLoginLocale(locale)
	}
	if cookie, err := r.Cookie(localeCookieName); err == nil {
		return normalizeLoginLocale(cookie.Value)
	}
	header := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language")))
	if strings.HasPrefix(header, "en") {
		return "en-US"
	}
	return "zh-CN"
}

func loginMessages(locale string) map[string]string {
	if normalizeLoginLocale(locale) == "en-US" {
		return map[string]string{
			"title":                          "NodeWall Sign In",
			"brandSubtitle":                  "Host protection center",
			"brandCopy":                      "Host protection and network control",
			"brandDescription":               "Manage node security, network policy, and recoverable changes from one trusted console.",
			"brandMeta":                      "Encrypted state · auditable policy · recoverable changes",
			"usernamePlaceholder":            "Username",
			"passwordPlaceholder":            "Password",
			"submit":                         "Sign In",
			"localeLabel":                    "Language",
			"localeChinese":                  "简体中文",
			"localeEnglish":                  "English",
			"loginErrorInvalidForm":          "Invalid form data.",
			"loginErrorLocked":               "Too many attempts. Please try again later.",
			"loginErrorInvalidCredentials":   "Invalid username or password.",
			"loginErrorCaptcha":              "Verification failed. Please try the new challenge.",
			"loginErrorCaptchaExpired":       "The previous challenge expired or was replaced. Complete the new one.",
			"loginErrorCaptchaSourceChanged": "Your network source changed. Complete the new challenge.",
			"loginLockedRetry":               "Too many attempts. Retry in %d seconds.",
			"loginErrorMFA":                  "This account requires a valid OTP/recovery code or Passkey login.",
			"loginErrorSessionCreate":        "Unable to create session.",
			"loginOTPTitle":                  "Additional verification",
			"otpLoginTitle":                  "Additional verification",
			"otpLoginHint":                   "Enter the one-time code from your authenticator app or a recovery code to finish signing in.",
			"otpLoginCode":                   "6-digit OTP or recovery code",
			"otpLoginSubmit":                 "Verify and sign in",
			"otpLoginBack":                   "Return to sign in",
			"loginOTPExpired":                "This verification step expired. Sign in again.",
			"passkeyLoginUnavailable":        "This account has no registered Passkey.",
			"passkeyLoginFailed":             "Passkey sign-in failed. Check the browser, HTTPS origin, and credential, then try again.",
			"passkeyLoginOrigin":             "Passkey requires an HTTPS DNS host name. Open NodeWall through its configured host name instead of an IP address.",
			"passkeyLoginDisabled":           "Passkey login is disabled in NodeWall System Settings.",
			"captchaRefreshFailed":           "Captcha refresh failed. Try again.",
			"loginRequestFailed":             "Sign-in request failed. Try again.",
			"loginNetworkFailed":             "The sign-in result could not be confirmed. Try a new challenge before retrying; your account and password are kept in this form.",
			"mfaLabel":                       "Additional verification (if enabled)",
			"mfaPlaceholder":                 "6-digit OTP or recovery code",
			"mfaHint":                        "Leave blank unless this account has additional verification enabled.",
			"forgotTitle":                    "Reset NodeWall password",
			"forgotHeading":                  "Reset password",
			"forgotLink":                     "Forgot password?",
			"forgotCode":                     "Email verification code",
			"forgotNewPassword":              "New password",
			"forgotConfirmPassword":          "Confirm new password",
			"forgotRequest":                  "Send reset code",
			"forgotReset":                    "Reset password",
			"forgotResetStep":                "Set new password",
			"forgotStepsLabel":               "Password recovery steps",
			"forgotBack":                     "Back to sign in",
			"forgotEditAccount":              "Change account",
			"forgotResend":                   "Resend code",
			"forgotResendAccepted":           "The resend request was accepted.",
			"forgotHint":                     "Enter the username for an account with a verified email address.",
			"forgotRequestSent":              "If the account has a verified email address, check that inbox for the reset code.",
			"forgotSendPending":              "Sending code…",
			"forgotResetPending":             "Resetting password…",
			"forgotResetSuccess":             "Password reset. Redirecting to sign in...",
			"forgotRequestFailed":            "The reset request failed. Try again.",
			"forgotUsernameRequired":         "Enter your username.",
			"forgotResetFailed":              "Password reset failed. Check the code and try again.",
			"forgotCodeInvalid":              "The reset code is invalid or expired.",
			"forgotPasswordsMismatch":        "The new passwords do not match.",
			"forgotPasswordTooShort":         "Use at least 8 characters for the new password.",
			"forgotRateLimited":              "Too many requests. Try again later.",
			"forgotResetUncertain":           "The result could not be confirmed. Return to sign in or request a new code.",
			"passkeyLogin":                   "Sign in with Passkey",
			"passkeyLoginUnsupported":        "Passkey is unavailable in this browser or origin.",
			"captchaLabel":                   "Security check",
			"captchaPlaceholder":             "Code",
			"captchaMathPlaceholder":         "Answer",
			"captchaImageAlt":                "Security verification image",
			"captchaLettersLabel":            "Enter the characters in the image",
			"captchaMathLabel":               "Enter the result of the calculation",
			"captchaRefresh":                 "Try another",
			"loginRateLimited":               "Too many requests. Retry in %d seconds.",
			"captchaRefreshRateLimited":      "Captcha refresh is temporarily limited. Retry in %d seconds.",
			"captchaTracePrompt":             "Click the numbered dots in this order: %s",
			"captchaTraceHint":               "Click each dot in order; avoid the unnumbered decoys.",
			"captchaTraceDone":               "Five points selected",
			"captchaTraceReset":              "Reset",
		}
	}
	return map[string]string{
		"title":                          "NodeWall 登录",
		"brandSubtitle":                  "主机防护中心",
		"brandCopy":                      "主机防护与网络控制",
		"brandDescription":               "统一管理节点安全、网络策略与可恢复的变更。",
		"brandMeta":                      "加密状态 · 可审计策略 · 可恢复变更",
		"usernamePlaceholder":            "账号",
		"passwordPlaceholder":            "密码",
		"submit":                         "登录",
		"localeLabel":                    "语言",
		"localeChinese":                  "简体中文",
		"localeEnglish":                  "English",
		"loginErrorInvalidForm":          "表单格式无效。",
		"loginErrorLocked":               "尝试次数过多，请稍后重试。",
		"loginErrorInvalidCredentials":   "账号或密码错误。",
		"loginErrorCaptcha":              "人机验证未通过，请完成新的验证。",
		"loginErrorCaptchaExpired":       "原验证码已失效，已换新题，请重新验证。",
		"loginErrorCaptchaSourceChanged": "网络来源已变化，请完成新的验证。",
		"loginLockedRetry":               "尝试次数过多，请 %d 秒后重试。",
		"loginErrorMFA":                  "此账号需要有效的 OTP、恢复码或使用 Passkey 登录。",
		"loginErrorSessionCreate":        "会话创建失败。",
		"otpLoginTitle":                  "辅助验证",
		"otpLoginHint":                   "请输入验证器应用中的一次性验证码或恢复码，完成登录。",
		"otpLoginCode":                   "6 位 OTP 或恢复码",
		"otpLoginSubmit":                 "验证并登录",
		"otpLoginBack":                   "返回登录",
		"loginOTPExpired":                "本次辅助验证已过期，请重新登录。",
		"passkeyLoginUnavailable":        "此账号尚未登记可用的 Passkey。",
		"passkeyLoginFailed":             "Passkey 登录失败，请确认浏览器、HTTPS 来源和凭证后重试。",
		"passkeyLoginOrigin":             "Passkey 需要 HTTPS DNS 主机名，请使用已配置的主机名访问 NodeWall，不要直接使用 IP 地址。",
		"passkeyLoginDisabled":           "Passkey 登录尚未在 NodeWall 系统设置中启用。",
		"captchaRefreshFailed":           "验证码刷新失败，请重试。",
		"loginRequestFailed":             "登录请求失败，请重试。",
		"loginNetworkFailed":             "网络异常，尚未确认登录结果。请换一题后重试，账号和密码已保留。",
		"mfaLabel":                       "辅助验证（如已启用）",
		"mfaPlaceholder":                 "6 位 OTP 或恢复码",
		"mfaHint":                        "只有账号启用了辅助验证时才需要填写。",
		"forgotTitle":                    "找回 NodeWall 密码",
		"forgotHeading":                  "找回密码",
		"forgotLink":                     "忘记密码？",
		"forgotCode":                     "邮箱验证码",
		"forgotNewPassword":              "新密码",
		"forgotConfirmPassword":          "确认新密码",
		"forgotRequest":                  "发送验证码",
		"forgotReset":                    "重置密码",
		"forgotResetStep":                "设置新密码",
		"forgotStepsLabel":               "找回密码步骤",
		"forgotBack":                     "返回登录",
		"forgotEditAccount":              "修改账号",
		"forgotResend":                   "重新发送",
		"forgotResendAccepted":           "重发请求已受理。",
		"forgotHint":                     "输入已绑定并验证邮箱的账号。",
		"forgotRequestSent":              "如果账号符合条件，找回验证码已发送到已验证的邮箱。",
		"forgotSendPending":              "正在发送…",
		"forgotResetPending":             "正在重置…",
		"forgotResetSuccess":             "密码已重置，正在返回登录页……",
		"forgotRequestFailed":            "找回请求失败，请重试。",
		"forgotUsernameRequired":         "请输入账号。",
		"forgotResetFailed":              "密码重置失败，请检查验证码后重试。",
		"forgotCodeInvalid":              "找回验证码无效或已过期。",
		"forgotPasswordsMismatch":        "两次输入的新密码不一致。",
		"forgotPasswordTooShort":         "新密码至少需要 8 个字符。",
		"forgotRateLimited":              "请求过于频繁，请稍后再试。",
		"forgotResetUncertain":           "未能确认重置结果。可以返回登录，或重新发送验证码。",
		"passkeyLogin":                   "使用 Passkey 登录",
		"passkeyLoginUnsupported":        "当前浏览器或页面来源不支持 Passkey。",
		"captchaLabel":                   "安全验证码",
		"captchaPlaceholder":             "验证码",
		"captchaMathPlaceholder":         "计算结果",
		"captchaImageAlt":                "安全验证码图片",
		"captchaLettersLabel":            "输入图中的字符",
		"captchaMathLabel":               "输入算式的结果",
		"captchaRefresh":                 "换一题",
		"loginRateLimited":               "请求过于频繁，请 %d 秒后重试。",
		"captchaRefreshRateLimited":      "验证码切换太频繁，请 %d 秒后重试。",
		"captchaTracePrompt":             "按 %s 顺序点击圆点",
		"captchaTraceHint":               "按顺序点击编号圆点，避开无编号干扰点。",
		"captchaTraceDone":               "已选中 5 个点",
		"captchaTraceReset":              "重选",
	}
}

func (a *authManager) sessionState(r *http.Request) map[string]any {
	session, ok := a.sessionFromRequest(r)
	return map[string]any{
		"auth_enabled":  a.enabled,
		"authenticated": ok,
		"username":      session.Username,
		"role":          security.NormalizeRole(session.Role),
	}
}

func (a *authManager) authSettings() models.AuthSecuritySettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	active := 0
	for key, attempt := range a.loginAttempts {
		if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
			active++
			continue
		}
		if !attempt.LockedUntil.IsZero() && !attempt.LockedUntil.After(now) {
			delete(a.loginAttempts, key)
		}
	}
	settings := a.settings
	settings.ActiveLocks = active
	return settings
}

func (a *authManager) updateAuthSettings(settings models.AuthSecuritySettings) error {
	settings = normalizeAuthSettings(settings)
	if err := a.validatePasskeySettings(settings, nil); err != nil {
		return err
	}
	if settings.MFARequired || settings.RequireMFAForAdmin {
		otpAllowed := false
		passkeyAllowed := false
		for _, method := range settings.AllowedMFAMethods {
			if method == "otp" {
				otpAllowed = true
			}
			if method == "passkey" {
				passkeyAllowed = true
			}
		}
		if !otpAllowed && !passkeyAllowed {
			return fmt.Errorf("at least one additional verification method must be allowed")
		}
		if passkeyAllowed && !otpAllowed && !settings.PasskeyEnabled {
			return fmt.Errorf("Passkey must be enabled and ready before it is the only allowed MFA method")
		}
		store, err := security.LoadUserStore(a.authFile)
		if err != nil {
			return fmt.Errorf("cannot validate MFA policy: %w", err)
		}
		for _, user := range store.Users {
			if !user.Enabled {
				continue
			}
			if settings.RequireMFAForAdmin && security.NormalizeRole(user.Role) != security.RoleAdmin && !settings.MFARequired {
				continue
			}
			hasAllowedMethod := (otpAllowed && user.MFA.OTPEnabled) || (passkeyAllowed && len(user.MFA.Passkeys) > 0)
			if !hasAllowedMethod {
				return fmt.Errorf("user %q must enroll an allowed MFA method before MFA is required", user.Username)
			}
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	previous := a.settings
	a.settings = settings
	if err := a.saveSettingsLocked(); err != nil {
		a.settings = previous
		return err
	}
	return nil
}

func (a *authManager) loginLockedUntil(source string) (time.Time, bool) {
	if source == "" {
		return time.Time{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	attempt, ok := a.loginAttempts[source]
	if !ok {
		return time.Time{}, false
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return attempt.LockedUntil, true
	}
	if !attempt.LockedUntil.IsZero() && !attempt.LockedUntil.After(now) {
		delete(a.loginAttempts, source)
	}
	return time.Time{}, false
}

func (a *authManager) recordLoginFailure(source string) {
	a.mu.RLock()
	maxFailures := a.settings.MaxFailures
	a.mu.RUnlock()
	a.recordLoginFailureWithLimit(source, maxFailures)
}

func (a *authManager) recordLoginFailureWithLimit(source string, maxFailures int) {
	if source == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.loginAttempts == nil {
		a.loginAttempts = make(map[string]loginAttempt)
	}
	settings := a.settings
	if settings.MaxFailures <= 0 {
		settings.MaxFailures = 5
	}
	if settings.WindowSeconds <= 0 {
		settings.WindowSeconds = int((10 * time.Minute) / time.Second)
	}
	if settings.LockDurationSeconds <= 0 {
		settings.LockDurationSeconds = int((15 * time.Minute) / time.Second)
	}
	window := time.Duration(settings.WindowSeconds) * time.Second
	if _, exists := a.loginAttempts[source]; !exists && len(a.loginAttempts) >= loginAttemptSourceLimit {
		var oldestKey string
		var oldest time.Time
		for key, entry := range a.loginAttempts {
			if entry.LockedUntil.IsZero() || !entry.LockedUntil.After(now) {
				if entry.FirstFailed.IsZero() || now.Sub(entry.FirstFailed) > window {
					delete(a.loginAttempts, key)
					continue
				}
				if oldestKey == "" || entry.FirstFailed.Before(oldest) {
					oldestKey, oldest = key, entry.FirstFailed
				}
			}
		}
		if len(a.loginAttempts) >= loginAttemptSourceLimit {
			if oldestKey == "" {
				return
			}
			delete(a.loginAttempts, oldestKey)
		}
	}
	attempt := a.loginAttempts[source]
	lockDuration := time.Duration(settings.LockDurationSeconds) * time.Second
	if attempt.FirstFailed.IsZero() || now.Sub(attempt.FirstFailed) > window {
		attempt = loginAttempt{Failures: 0, FirstFailed: now}
	}
	attempt.Failures++
	if attempt.FirstFailed.IsZero() {
		attempt.FirstFailed = now
	}
	if maxFailures <= 0 {
		maxFailures = settings.MaxFailures
	}
	if attempt.Failures >= maxFailures {
		attempt.LockedUntil = now.Add(lockDuration)
	}
	a.loginAttempts[source] = attempt
}

func (a *authManager) loadSettings() error {
	data, needsRewrite, recovered, err := securestore.ReadValid(a.settingsFile, func(payload []byte) error {
		var settings models.AuthSecuritySettings
		return json.Unmarshal(payload, &settings)
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var settings models.AuthSecuritySettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}
	var storedFields map[string]json.RawMessage
	_ = json.Unmarshal(data, &storedFields)
	if _, present := storedFields["passkey_rp_id"]; !present {
		settings.PasskeyRPID = strings.TrimSpace(a.webauthnRPID)
		settings.PasskeyOrigins = append([]string(nil), a.webauthnOrigins...)
	}
	// Older settings files did not persist an explicit feature switch. Treat
	// those files as disabled so importing a legacy RP ID cannot silently expose
	// Passkey login; the administrator can enable it after reviewing the checks.
	if _, present := storedFields["passkey_enabled"]; !present {
		settings.PasskeyEnabled = false
	}
	a.settings = normalizeAuthSettings(settings)
	if strings.TrimSpace(a.settings.PasskeyRPID) != "" {
		a.webauthnRPID = strings.TrimSpace(a.settings.PasskeyRPID)
	}
	if len(a.settings.PasskeyOrigins) > 0 {
		a.webauthnOrigins = append([]string(nil), a.settings.PasskeyOrigins...)
	}
	if strings.TrimSpace(a.settings.PasskeyTLSMode) != "" {
		a.webauthnTLSMode = a.settings.PasskeyTLSMode
	}
	if needsRewrite || recovered {
		return a.saveSettingsLocked()
	}
	return nil
}

func (a *authManager) saveSettingsLocked() error {
	payload := a.settings
	payload.ActiveLocks = 0
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return securestore.Write(a.settingsFile, data, 0o600)
}

func normalizeAuthSettings(settings models.AuthSecuritySettings) models.AuthSecuritySettings {
	if settings.MaxFailures <= 0 {
		settings.MaxFailures = 5
	}
	if settings.WindowSeconds <= 0 {
		settings.WindowSeconds = int((10 * time.Minute) / time.Second)
	}
	if settings.LockDurationSeconds <= 0 {
		settings.LockDurationSeconds = int((15 * time.Minute) / time.Second)
	}
	methods := make([]string, 0, len(settings.AllowedMFAMethods))
	seen := make(map[string]struct{})
	for _, method := range settings.AllowedMFAMethods {
		method = strings.ToLower(strings.TrimSpace(method))
		if method == "otp" || method == "passkey" {
			if _, exists := seen[method]; exists {
				continue
			}
			seen[method] = struct{}{}
			methods = append(methods, method)
		}
	}
	if !settings.PasskeyEnabled {
		filtered := methods[:0]
		for _, method := range methods {
			if method != "passkey" {
				filtered = append(filtered, method)
			}
		}
		methods = filtered
	}
	if len(methods) == 0 {
		// OTP is the established fallback. Passkey remains an explicit method
		// choice after the administrator enables and configures it.
		methods = []string{"otp"}
	}
	settings.AllowedMFAMethods = methods
	settings.PasskeyRPID = strings.TrimSpace(settings.PasskeyRPID)
	settings.PasskeyTLSMode = strings.ToLower(strings.TrimSpace(settings.PasskeyTLSMode))
	if settings.PasskeyTLSMode != "proxy" {
		settings.PasskeyTLSMode = "local"
	}
	origins := make([]string, 0, len(settings.PasskeyOrigins))
	seenOrigins := make(map[string]struct{})
	for _, origin := range settings.PasskeyOrigins {
		origin = strings.TrimRight(strings.TrimSpace(origin), "/")
		if origin == "" {
			continue
		}
		if _, exists := seenOrigins[origin]; exists {
			continue
		}
		seenOrigins[origin] = struct{}{}
		origins = append(origins, origin)
	}
	settings.PasskeyOrigins = origins
	settings.ActiveLocks = 0
	return settings
}

func (a *authManager) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeJSON(w, http.StatusOK, map[string]any{
			"auth_enabled": false,
			"status":       "disabled",
		})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	req.CurrentPassword = strings.TrimSpace(req.CurrentPassword)
	req.NewPassword = strings.TrimSpace(req.NewPassword)
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("current and new password are required"))
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("new password must be at least 8 characters"))
		return
	}

	session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("authentication required"))
		return
	}
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user, idx := store.Find(session.Username)
	if user == nil {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("current user not found"))
		return
	}
	if !security.VerifyPassword(req.CurrentPassword, user.Password) {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("current password is invalid"))
		return
	}

	next, err := security.NewPasswordRecord(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user.Password = next
	user.UpdatedAt = time.Now().UTC()
	store.Users[idx] = *user
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	keepToken := ""
	if cookie, cookieErr := r.Cookie(sessionCookieName); cookieErr == nil {
		keepToken = cookie.Value
	}
	a.revokeUserSessions(user.Username, keepToken)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "updated",
		"message": "password updated",
	})
}

func (a *authManager) accountUser(r *http.Request) (security.UserStore, *security.UserRecord, int, error) {
	session, ok := a.sessionFromRequest(r)
	if !ok {
		return security.UserStore{}, nil, -1, fmt.Errorf("authentication required")
	}
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		return security.UserStore{}, nil, -1, err
	}
	user, index := store.Find(session.Username)
	if user == nil || !user.Enabled {
		return security.UserStore{}, nil, -1, fmt.Errorf("current user not found")
	}
	return store, user, index, nil
}

func (a *authManager) handleAccountSecurity(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeJSON(w, http.StatusOK, map[string]any{"auth_enabled": false, "otp_enabled": false, "passkeys": 0})
		return
	}
	_, user, _, err := a.accountUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	a.mu.RLock()
	settings := a.settings
	a.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_enabled":             true,
		"username":                 user.Username,
		"email":                    user.Email,
		"email_verified":           user.EmailVerified,
		"otp_enabled":              user.MFA.OTPEnabled,
		"recovery_codes_remaining": len(user.MFA.RecoveryCodeHashes),
		"passkeys":                 len(user.MFA.Passkeys),
		"passkey_enabled":          settings.PasskeyEnabled,
		"passkey_rp_id":            settings.PasskeyRPID,
		"passkey_origins":          settings.PasskeyOrigins,
		"passkey_tls_mode":         settings.PasskeyTLSMode,
		"mfa_required":             settings.MFARequired,
		"require_mfa_for_admin":    settings.RequireMFAForAdmin,
		"allowed_methods":          settings.AllowedMFAMethods,
	})
}

func (a *authManager) handleOTPSetup(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeError(w, http.StatusNotImplemented, fmt.Errorf("authentication is disabled"))
		return
	}
	if a.rejectLoginRate(w, r, "otp-setup", 5) {
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	_, user, _, err := a.accountUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if !security.VerifyPassword(strings.TrimSpace(req.CurrentPassword), user.Password) {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("current password is invalid"))
		return
	}
	if user.MFA.OTPEnabled {
		writeError(w, http.StatusBadRequest, fmt.Errorf("OTP is already enabled"))
		return
	}
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Keep the secret in memory until the user proves that the authenticator
	// was configured correctly. The encrypted user store is not changed by the
	// setup request, so abandoned setup attempts cannot enable MFA accidentally.
	a.mu.Lock()
	if a.otpSetups == nil {
		a.otpSetups = make(map[string]otpSetupState)
	}
	a.otpSetups[user.Username] = otpSetupState{Secret: secret, ExpiresAt: time.Now().Add(10 * time.Minute)}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"username":    user.Username,
		"secret":      secret,
		"otpauth_uri": security.OTPAuthURI(secret, "NodeWall", user.Username),
		"expires_at":  time.Now().Add(10 * time.Minute),
	})
}

func (a *authManager) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeError(w, http.StatusNotImplemented, fmt.Errorf("authentication is disabled"))
		return
	}
	if a.rejectLoginRate(w, r, "otp-verify", 10) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	store, user, index, err := a.accountUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	a.mu.Lock()
	setup, ok := a.otpSetups[user.Username]
	if ok && !setup.ExpiresAt.After(time.Now()) {
		delete(a.otpSetups, user.Username)
		ok = false
	}
	if ok {
		delete(a.otpSetups, user.Username)
	}
	a.mu.Unlock()
	if !ok || !security.VerifyTOTPCode(setup.Secret, strings.TrimSpace(req.Code), time.Now()) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("OTP verification failed or setup expired"))
		return
	}
	codes, hashes, err := security.GenerateRecoveryCodes(10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	now := time.Now().UTC()
	user.MFA.OTPSecret = setup.Secret
	user.MFA.OTPEnabled = true
	user.MFA.OTPVerifiedAt = &now
	user.MFA.RecoveryCodeHashes = hashes
	store.Users[index] = *user
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "enabled",
		"recovery_codes": codes,
	})
}

func (a *authManager) handleOTPDisable(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeError(w, http.StatusNotImplemented, fmt.Errorf("authentication is disabled"))
		return
	}
	if a.rejectLoginRate(w, r, "otp-disable", 5) {
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		Code            string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	store, user, index, err := a.accountUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	a.mu.RLock()
	settings := a.settings
	a.mu.RUnlock()
	policyRequiresMFA := settings.MFARequired || (settings.RequireMFAForAdmin && security.NormalizeRole(user.Role) == security.RoleAdmin)
	passkeyAllowed := false
	for _, method := range settings.AllowedMFAMethods {
		if method == "passkey" {
			passkeyAllowed = true
			break
		}
	}
	if policyRequiresMFA && !(passkeyAllowed && len(user.MFA.Passkeys) > 0) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("MFA policy prevents disabling the last verification method"))
		return
	}
	if !security.VerifyPassword(strings.TrimSpace(req.CurrentPassword), user.Password) {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("current password is invalid"))
		return
	}
	valid := security.VerifyTOTPCode(user.MFA.OTPSecret, strings.TrimSpace(req.Code), time.Now())
	if !valid {
		var remaining []string
		remaining, valid = security.ConsumeRecoveryCode(req.Code, user.MFA.RecoveryCodeHashes)
		if valid {
			user.MFA.RecoveryCodeHashes = remaining
		}
	}
	if !valid {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("valid OTP or recovery code is required"))
		return
	}
	user.MFA = security.MFAMethods{Passkeys: user.MFA.Passkeys}
	store.Users[index] = *user
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "disabled"})
}

func (a *authManager) listUsers(w http.ResponseWriter, r *http.Request) {
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	type userInfo struct {
		Username      string     `json:"username"`
		Role          string     `json:"role"`
		Enabled       bool       `json:"enabled"`
		Email         string     `json:"email,omitempty"`
		EmailVerified bool       `json:"email_verified"`
		OTPEnabled    bool       `json:"otp_enabled"`
		Passkeys      int        `json:"passkeys"`
		CreatedAt     time.Time  `json:"created_at"`
		UpdatedAt     time.Time  `json:"updated_at"`
		LastLogin     *time.Time `json:"last_login,omitempty"`
	}
	items := make([]userInfo, 0, len(store.Users))
	for _, user := range store.Users {
		items = append(items, userInfo{
			Username:      user.Username,
			Role:          security.NormalizeRole(user.Role),
			Enabled:       user.Enabled,
			Email:         user.Email,
			EmailVerified: user.EmailVerified,
			OTPEnabled:    user.MFA.OTPEnabled,
			Passkeys:      len(user.MFA.Passkeys),
			CreatedAt:     user.CreatedAt,
			UpdatedAt:     user.UpdatedAt,
			LastLogin:     user.LastLogin,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": items})
}

func (a *authManager) createUser(w http.ResponseWriter, r *http.Request) {
	session, ok := a.sessionFromRequest(r)
	if !ok || security.NormalizeRole(session.Role) != security.RoleAdmin {
		writeError(w, http.StatusForbidden, fmt.Errorf("admin role required"))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	req.Role = security.NormalizeRole(req.Role)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("username and password are required"))
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("password must be at least 8 characters"))
		return
	}
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if existing, _ := store.Find(req.Username); existing != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("user already exists"))
		return
	}
	record, err := security.NewPasswordRecord(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	now := time.Now().UTC()
	store.Users = append(store.Users, security.UserRecord{
		Username:  req.Username,
		Role:      req.Role,
		Enabled:   true,
		Password:  record,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "created"})
}

func (a *authManager) updateUser(w http.ResponseWriter, r *http.Request) {
	session, ok := a.sessionFromRequest(r)
	if !ok || security.NormalizeRole(session.Role) != security.RoleAdmin {
		writeError(w, http.StatusForbidden, fmt.Errorf("admin role required"))
		return
	}
	username := strings.TrimSpace(r.PathValue("username"))
	var req struct {
		Role    string `json:"role"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user, idx := store.Find(username)
	if user == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("user not found"))
		return
	}
	if req.Role != "" {
		user.Role = security.NormalizeRole(req.Role)
	}
	if req.Enabled != nil {
		user.Enabled = *req.Enabled
	}
	user.UpdatedAt = time.Now().UTC()
	store.Users[idx] = *user
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.revokeUserSessions(user.Username, "")
	a.mu.Lock()
	delete(a.loginAttempts, loginAccountKey(user.Username))
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

func (a *authManager) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	session, ok := a.sessionFromRequest(r)
	if !ok || security.NormalizeRole(session.Role) != security.RoleAdmin {
		writeError(w, http.StatusForbidden, fmt.Errorf("admin role required"))
		return
	}
	username := strings.TrimSpace(r.PathValue("username"))
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.NewPassword = strings.TrimSpace(req.NewPassword)
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("new password must be at least 8 characters"))
		return
	}
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user, idx := store.Find(username)
	if user == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("user not found"))
		return
	}
	next, err := security.NewPasswordRecord(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user.Password = next
	user.UpdatedAt = time.Now().UTC()
	store.Users[idx] = *user
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.revokeUserSessions(user.Username, "")
	a.mu.Lock()
	delete(a.loginAttempts, loginAccountKey(user.Username))
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

func (a *authManager) deleteUser(w http.ResponseWriter, r *http.Request) {
	session, ok := a.sessionFromRequest(r)
	if !ok || security.NormalizeRole(session.Role) != security.RoleAdmin {
		writeError(w, http.StatusForbidden, fmt.Errorf("admin role required"))
		return
	}
	username := strings.TrimSpace(r.PathValue("username"))
	if strings.EqualFold(username, session.Username) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("cannot delete current user"))
		return
	}
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]security.UserRecord, 0, len(store.Users))
	removed := false
	for _, user := range store.Users {
		if strings.EqualFold(strings.TrimSpace(user.Username), username) {
			removed = true
			continue
		}
		out = append(out, user)
	}
	if !removed {
		writeError(w, http.StatusNotFound, fmt.Errorf("user not found"))
		return
	}
	if len(out) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("at least one user must remain"))
		return
	}
	store.Users = out
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.revokeUserSessions(username, "")
	a.mu.Lock()
	delete(a.loginAttempts, loginAccountKey(username))
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (a *authManager) allowRemote(r *http.Request) bool {
	// Enrollment endpoints perform their own authentication with a short-lived,
	// single-use ticket and a pinned manager certificate. They must be reachable
	// from a new node before that node can appear in the ordinary web allowlist;
	// invalid or expired tickets are still rejected by the /join handlers.
	if strings.HasPrefix(r.URL.Path, "/join/") {
		return true
	}

	// Public is the default deployment mode. In that mode the HTTP server is
	// intentionally reachable from external networks and authentication is
	// handled by the login/session layer below. CIDR/MAC lists are enforced only
	// when the operator explicitly selects restricted mode; otherwise an
	// installer-provided node/network allowlist can unexpectedly turn a healthy
	// management listener into a plain 403 response.
	if a.webAccess == "public" {
		return true
	}

	if a.webAccess == "drop" {
		source, ok := requestSourceAddr(r)
		return ok && source.IsLoopback()
	}
	if a.webAccess != "restricted" && a.webAccess != "allowlist" && a.webAccess != "drop" {
		// Preserve the legacy behavior for direct zero-value authManager tests or
		// deployments that predate NODEWALL_WEB_ACCESS.
		if a.webAccess == "" {
			return a.remoteMatchesConfiguredAllowlist(r)
		}
		return true
	}
	return a.remoteMatchesConfiguredAllowlist(r)
}

func (a *authManager) remoteMatchesConfiguredAllowlist(r *http.Request) bool {
	if len(a.allowedNets) == 0 && len(a.allowedMACs) == 0 {
		return true
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err == nil {
		for _, prefix := range a.allowedNets {
			if prefix.Contains(addr) {
				return true
			}
		}
	}

	if len(a.allowedMACs) == 0 || err != nil {
		return false
	}

	mac := resolveRemoteMAC(addr.String())
	if mac == "" {
		return false
	}
	_, ok := a.allowedMACs[strings.ToLower(mac)]
	return ok
}

func resolveRemoteMAC(ip string) string {
	out, err := exec.Command("ip", "neigh", "show", ip).CombinedOutput()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "lladdr" {
			return fields[i+1]
		}
	}
	return ""
}

func parseAllowedPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("empty allowlist entry")
	}
	if strings.Contains(value, "/") {
		return netip.ParsePrefix(value)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
}

func loginSourceKey(r *http.Request) string {
	if source, ok := requestSourceAddr(r); ok {
		return source.String()
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

func loginAccountKey(username string) string {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || len(username) > 256 {
		return ""
	}
	return "account:" + username
}

func randomToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

const loginPageHTML = `<!DOCTYPE html>
<html lang="{{.Locale}}">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{{.Title}}</title>
    <link rel="icon" type="image/svg+xml" href="/nodewall-mark.svg" />
    <style>` + authBackdropCSS + `
      :root{color-scheme:dark}
      *{box-sizing:border-box}
      body{margin:0;min-height:100vh;background:#0a121d;color:#f8fafc;font-family:"IBM Plex Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
      .login-shell{position:relative;isolation:isolate;min-height:100vh;display:grid;grid-template-columns:minmax(300px,.9fr) minmax(420px,1.1fr);overflow:hidden}
      .brand-panel{position:relative;display:flex;flex-direction:column;justify-content:space-between;min-height:100vh;padding:clamp(32px,6vw,80px)}
      .brand-top,.brand-body,.brand-meta{position:relative;z-index:1}
      .brand-top{display:flex;align-items:center;gap:14px}
      .brand-mark{display:grid;place-items:center;width:54px;height:54px;padding:8px;border:1px solid rgba(94,234,212,.52);border-radius:16px;background:linear-gradient(145deg,rgba(15,118,110,.34),rgba(15,23,42,.16));box-shadow:0 0 0 7px rgba(20,184,166,.06),0 14px 34px rgba(20,184,166,.16),inset 0 1px 0 rgba(255,255,255,.12)}
      .brand-mark img{display:block;width:100%;height:100%}
      .brand-eyebrow{margin:0;color:#99f6e4;font-size:.8rem;letter-spacing:.16em;text-transform:uppercase}
      .brand-name{margin:2px 0 0;font-size:1.4rem;letter-spacing:-.03em}
      .brand-body{position:relative;max-width:400px;margin-top:auto;margin-bottom:auto;padding:42px 0 24px}
      .brand-body:before{content:"";position:absolute;left:-26px;top:38px;width:2px;height:116px;border-radius:2px;background:linear-gradient(180deg,#5eead4,rgba(94,234,212,0));box-shadow:0 0 20px rgba(94,234,212,.55);opacity:.72}
      .brand-subtitle{margin:0 0 16px;color:#cbd5e1;font-size:1rem;letter-spacing:.04em}
      .brand-copy{margin:0;color:#e8fffc;font-size:clamp(1.65rem,2.6vw,2.8rem);font-weight:650;line-height:1.25;letter-spacing:-.04em;text-shadow:0 2px 24px rgba(45,212,191,.1)}
      .brand-description{max-width:330px;margin:16px 0 0;color:#b8c7d5;font-size:.98rem;line-height:1.65}
      .brand-signal{display:block;width:min(100%,360px);height:auto;margin:24px 0 0;overflow:visible;pointer-events:none}
      .signal-wire{fill:none;stroke:url(#signal-wire-gradient);stroke-width:1.2}
      .signal-node{fill:#102c3b;stroke:#67e8df;stroke-width:1.3}
      .signal-pulse{fill:none;stroke:#5eead4;stroke-width:1;opacity:.3;animation:signalPulse 3.2s steps(4,end) infinite}
      .signal-pulse-alt{animation-delay:-1.6s;stroke:#a5b4fc}
      .login-shell:focus-within .signal-pulse{animation-play-state:paused}
      .brand-meta{margin:0;color:#94a3b8;font-size:.82rem;line-height:1.5}
      .login-main{position:relative;display:flex;align-items:center;justify-content:center;min-width:0;padding:clamp(24px,5vw,72px)}
      .login-form{position:relative;z-index:1;isolation:isolate;width:min(100%,470px);margin:0;color:#f8fafc}
      .login-form:before{content:"";position:absolute;z-index:-1;inset:-30px;pointer-events:none;border:1px solid transparent;border-radius:22px;background:linear-gradient(#101f2e,#0e1c2a) padding-box,linear-gradient(135deg,rgba(94,234,212,.65),rgba(56,189,248,.12) 43%,rgba(167,139,250,.42)) border-box;box-shadow:0 24px 64px rgba(2,6,23,.32),0 0 32px rgba(20,184,166,.035)}
      .login-form:after{content:"";position:absolute;left:0;top:-30px;width:100px;height:2px;border-radius:2px;pointer-events:none;background:linear-gradient(90deg,transparent,#67e8df,transparent);box-shadow:0 0 12px rgba(94,234,212,.32)}
      .login-heading{margin:0 0 22px}
      .login-kicker{margin:0 0 8px;color:#5eead4;font-size:.82rem;font-weight:650;letter-spacing:.12em;text-transform:uppercase}
      h2{margin:0;font-size:clamp(1.7rem,3vw,2.4rem);letter-spacing:-.04em}
      .field-label{display:block;margin:0 0 8px;color:#cbd5e1;font-size:.84rem;font-weight:600}
      .field{margin-bottom:16px}
      input,button{display:block;width:100%;max-width:100%;padding:13px 15px;border-radius:10px;font:inherit}
      input{border:1px solid #304357;background:#172536;color:#f8fafc;outline:none}
      input::placeholder{color:#7890a2}
      input:focus{border-color:#5eead4;background:#182b3e;box-shadow:0 0 0 3px rgba(45,212,191,.14)}
      button{border:1px solid transparent;background:linear-gradient(100deg,#0f766e,#14b8a6);color:#fff;font-weight:700;cursor:pointer}
      button:hover:not(:disabled){border-color:#5eead4}
      button:disabled{opacity:.62;cursor:wait}
      /* Reserve feedback inside the fixed challenge so errors cannot move the form. */
      .challenge{display:grid;grid-template-rows:auto minmax(0,1fr) 36px;gap:10px;height:304px;min-height:304px;margin:16px 0 14px;padding:12px 14px;border:1px solid #304357;border-radius:12px;background:#0c1927}
      .challenge-header{display:flex;align-items:center;justify-content:space-between;gap:12px}
      .challenge-label{margin:0;color:#f8fafc;font-size:.93rem;font-weight:650}
      .captcha-refresh{width:auto;padding:6px 10px;border-color:#3b5063;background:transparent;color:#cbd5e1;font-size:.78rem;font-weight:600}
      .captcha-refresh:hover:not(:disabled){border-color:#5eead4;color:#99f6e4}
      .captcha-content{min-width:0;min-height:0}
      .captcha-content input{min-width:0;padding:12px}
      .captcha-text{display:flex;flex-wrap:wrap;align-content:center;align-items:center;gap:12px}
      .captcha-image{display:block;flex:none;width:min(100%,224px);height:auto;border:1px solid #304357;border-radius:9px;background:#e8eef5}
      .captcha-entry{flex:1 1 156px;min-width:0}
      .trace-content{display:grid;grid-template-rows:auto minmax(0,1fr) auto;gap:6px}
      .trace-prompt{margin:0;color:#f8fafc;font-size:.9rem;font-weight:650;line-height:1.35}
      .trace-image-wrap{position:relative;min-height:0;overflow:hidden;border:1px solid #304357;border-radius:10px;background:#172033}
      .trace-image{display:block;width:100%;height:100%;object-fit:contain;cursor:crosshair;touch-action:manipulation;user-select:none}
      .trace-markers{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}
      .trace-markers polyline{fill:none;stroke:url(#trace-selection-gradient);stroke-width:3.2;stroke-linecap:round;stroke-linejoin:round;filter:drop-shadow(0 1px 1px rgba(2,6,23,.5))}
      .trace-markers circle{fill:#0f172a;stroke-width:3}
      .trace-markers text{fill:#fff;font:700 14px sans-serif;text-anchor:middle;dominant-baseline:central;paint-order:stroke;stroke:#0f172a;stroke-width:2px}
      .trace-markers .trace-marker-1{stroke:#22d3ee}
      .trace-markers .trace-marker-2{stroke:#fbbf24}
      .trace-markers .trace-marker-3{stroke:#f472b6}
      .trace-markers .trace-marker-4{stroke:#a78bfa}
      .trace-markers .trace-marker-5{stroke:#34d399}
      .trace-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px}
      .trace-status{min-width:0;margin:0;color:#aabccc;font-size:.78rem;line-height:1.35}
      .trace-reset{display:inline-flex;flex:none;width:auto;padding:6px 10px;border-color:#3b5063;background:transparent;color:#cbd5e1;font-size:.78rem;font-weight:600}
      .error{min-height:0;overflow:auto;color:#fca5a5;font-size:.82rem;line-height:1.35;overflow-wrap:anywhere}
      #login-submit{margin-top:2px;position:relative;border-color:rgba(94,234,212,.28);background:linear-gradient(105deg,#0d9488,#0891b2);box-shadow:inset 0 1px 0 rgba(255,255,255,.16),0 4px 18px rgba(8,145,178,.16)}
      #login-submit:hover:not(:disabled){border-color:#99f6e4;background:linear-gradient(105deg,#0faaa0,#089ab9)}
      .passkey-login{margin-top:10px;background:rgba(15,23,42,.18);border-color:rgba(94,234,212,.55);color:#99f6e4;box-shadow:inset 0 1px 0 rgba(255,255,255,.04)}
      .login-footer{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-top:24px;color:#94a3b8;font-size:.82rem}
      .locale{display:flex;align-items:center;gap:8px}
      .locale select{border:1px solid #304357;background:#172536;color:#f8fafc;padding:7px 10px;border-radius:8px;font:inherit}
      .forgot-link{color:#99f6e4;text-decoration:none}
      .forgot-link:hover{text-decoration:underline}
      @keyframes signalPulse{0%,100%{opacity:.18}50%{opacity:.6}}
      @media(prefers-reduced-motion:reduce){.signal-pulse{animation:none}}
      @media(max-height:780px){.brand-signal{max-width:280px;margin-top:12px}.brand-body{padding:28px 0 18px}}
      @media(max-width:820px){.login-shell{display:block}.brand-panel{min-height:270px;padding:28px 26px 29px}.brand-body{max-width:600px;margin:38px 0 24px;padding:0}.brand-body:before{left:-14px;top:14px;height:88px}.brand-copy{max-width:600px;font-size:clamp(1.35rem,5vw,1.9rem)}.brand-signal{display:none}.login-main{min-height:calc(100vh - 270px);padding:56px 38px 64px}.login-form:before{inset:-24px}.login-form:after{top:-24px}}
      @media(max-width:430px){.login-main{padding:48px 28px 56px}.login-form:before{inset:-16px;border-radius:16px}.login-form:after{top:-16px}.challenge{height:284px;min-height:284px;padding-inline:10px}.login-footer{align-items:flex-start;flex-direction:column;gap:12px}}
    </style>
  </head>
  <body>
    <div class="login-shell">
      <aside class="brand-panel">
        <div class="brand-top">
          <div class="brand-mark" aria-hidden="true"><img src="/nodewall-mark.svg" alt="" /></div>
          <div><p class="brand-eyebrow">NodeWall</p><p class="brand-name">{{.BrandSubtitle}}</p></div>
        </div>
        <div class="brand-body">
          <p class="brand-subtitle">{{.BrandSubtitle}}</p>
          <h1 class="brand-copy">{{.BrandCopy}}</h1>
          <p class="brand-description">{{.BrandDescription}}</p>
          <svg class="brand-signal" viewBox="0 0 360 228" aria-hidden="true" focusable="false">
            <defs>
              <linearGradient id="signal-wire-gradient" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#5eead4" stop-opacity=".7"/><stop offset=".55" stop-color="#38bdf8" stop-opacity=".24"/><stop offset="1" stop-color="#a78bfa" stop-opacity=".65"/></linearGradient>
              <linearGradient id="signal-core-gradient" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#123e49"/><stop offset="1" stop-color="#18223f"/></linearGradient>
              <radialGradient id="signal-field-gradient"><stop stop-color="#2dd4bf" stop-opacity=".12"/><stop offset="1" stop-color="#2dd4bf" stop-opacity="0"/></radialGradient>
            </defs>
            <ellipse cx="180" cy="114" rx="154" ry="104" fill="url(#signal-field-gradient)"/>
            <g fill="none" stroke="url(#signal-wire-gradient)">
              <ellipse cx="180" cy="114" rx="145" ry="77" transform="rotate(-12 180 114)" opacity=".45"/>
              <path d="M180 20 262 67v94l-82 47-82-47V67Z" opacity=".28"/>
              <path d="M180 41 244 78v73l-64 37-64-37V78Z" stroke-dasharray="3 8" opacity=".45"/>
            </g>
            <g class="signal-wire">
              <path d="M35 114h51l35-35h34M77 45l31 32M282 47l-38 31h-37M324 145h-55l-31-31h-24M280 201l-39-39h-33M91 195l37-37h28"/>
              <path d="M145 71h-9V59M215 71h9V59M145 157h-9v12M215 157h9v12" stroke-width="2"/>
            </g>
            <path d="m180 65 39 16v35c0 27-21 43-39 52-18-9-39-25-39-52V81Z" fill="url(#signal-core-gradient)" stroke="#5eead4" stroke-opacity=".6"/>
            <image href="/nodewall-mark.svg" x="155" y="86" width="50" height="60"/>
            <g class="signal-node"><circle cx="35" cy="114" r="4"/><circle cx="77" cy="45" r="3"/><circle cx="282" cy="47" r="4"/><circle cx="324" cy="145" r="3"/><circle cx="280" cy="201" r="4"/><circle cx="91" cy="195" r="3"/></g>
            <circle class="signal-pulse" cx="35" cy="114" r="9"/>
            <circle class="signal-pulse signal-pulse-alt" cx="280" cy="201" r="9"/>
          </svg>
        </div>
        <p class="brand-meta">{{.BrandMeta}}</p>
      </aside>
      <main class="login-main">
        <form class="login-form" id="login-form" method="post" action="/login" data-retry-after="{{.RetryAfter}}">
          <div class="login-heading"><p class="login-kicker">{{.BrandSubtitle}}</p><h2>{{.Title}}</h2></div>
      <input type="hidden" name="locale" value="{{.Locale}}" />
      <input type="hidden" name="captcha_id" id="login-captcha-id" value="{{.Captcha.ID}}" />
          <div class="field"><label class="field-label" for="login-username">{{.UsernamePlaceholder}}</label><input id="login-username" type="text" name="username" value="{{.Username}}" placeholder="{{.UsernamePlaceholder}}" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" autofocus required /></div>
          <div class="field"><label class="field-label" for="login-password">{{.PasswordPlaceholder}}</label><input id="login-password" type="password" name="password" placeholder="{{.PasswordPlaceholder}}" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false" required /></div>
      <section class="challenge" id="login-challenge" data-expires-in="{{.Captcha.ExpiresIn}}" aria-label="{{.CaptchaLabel}}">
        <div class="challenge-header"><p class="challenge-label">{{.CaptchaLabel}}</p><button class="captcha-refresh" id="captcha-refresh" type="button">{{.CaptchaRefresh}}</button></div>
        {{if or (eq .Captcha.Kind "math") (eq .Captcha.Kind "letters")}}
          <div class="captcha-content captcha-text" id="captcha-content">
            <img class="captcha-image" data-kind="{{.Captcha.Kind}}" src="{{.Captcha.Image}}" alt="{{.CaptchaImageAlt}}" width="240" height="72" />
            <div class="captcha-entry">
              <label class="field-label" for="captcha-answer">{{if eq .Captcha.Kind "math"}}{{.CaptchaMathLabel}}{{else}}{{.CaptchaLettersLabel}}{{end}}</label>
              <input type="text" id="captcha-answer" name="captcha_answer" maxlength="12" {{if eq .Captcha.Kind "math"}}inputmode="numeric" placeholder="{{.CaptchaMathPlaceholder}}"{{else}}autocapitalize="characters" spellcheck="false" inputmode="text" placeholder="{{.CaptchaPlaceholder}}"{{end}} autocomplete="off" required />
            </div>
          </div>
        {{else}}
          <div class="captcha-content trace-content" id="captcha-content">
            <p class="trace-prompt" tabindex="-1">{{.Captcha.Prompt}}</p>
            <div class="trace-image-wrap">
              <img class="trace-image" id="trace-image" src="{{.Captcha.Image}}" alt="{{.CaptchaTraceHint}}" draggable="false" />
              <svg class="trace-markers" id="trace-markers" viewBox="0 0 320 150" preserveAspectRatio="xMidYMid meet" aria-hidden="true"><defs><linearGradient id="trace-selection-gradient" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#22d3ee"/><stop offset=".48" stop-color="#fbbf24"/><stop offset="1" stop-color="#f472b6"/></linearGradient></defs><polyline points=""></polyline></svg>
            </div>
            <div class="trace-toolbar"><p class="trace-status" id="trace-status" aria-live="polite">{{.CaptchaTraceHint}}</p><button class="trace-reset" id="trace-reset" type="button">{{.CaptchaTraceReset}}</button></div>
            <input type="hidden" id="captcha-answer" name="captcha_answer" />
          </div>
        {{end}}
        <div class="error" id="login-error" role="alert" aria-live="polite">{{if eq .ErrorKey "loginErrorInvalidForm"}}{{.LoginErrorInvalidForm}}{{else if eq .ErrorKey "loginErrorLocked"}}{{.LoginErrorLocked}}{{else if eq .ErrorKey "loginErrorInvalidCredentials"}}{{.LoginErrorInvalidCreds}}{{else if eq .ErrorKey "loginErrorCaptcha"}}{{.LoginErrorCaptcha}}{{else if eq .ErrorKey "loginErrorCaptchaExpired"}}{{.LoginErrorCaptchaExpired}}{{else if eq .ErrorKey "loginErrorCaptchaSourceChanged"}}{{.LoginErrorCaptchaSourceChanged}}{{else if eq .ErrorKey "loginErrorMFA"}}{{.LoginErrorMFA}}{{else if eq .ErrorKey "loginErrorSessionCreate"}}{{.LoginErrorSessionCreate}}{{end}}</div>
      </section>
      <button type="submit" id="login-submit">{{.Submit}}</button>
      {{if .PasskeyEnabled}}<button type="button" id="passkey-login" class="passkey-login">{{.PasskeyLogin}}</button>{{end}}
          <div class="login-footer"><div class="locale"><label for="login-locale">{{.LocaleLabel}}</label><select id="login-locale" onchange="window.location.href='/login?lang='+encodeURIComponent(this.value)"><option value="zh-CN" {{if eq .Locale "zh-CN"}}selected{{end}}>{{.LocaleChinese}}</option><option value="en-US" {{if eq .Locale "en-US"}}selected{{end}}>{{.LocaleEnglish}}</option></select></div><a class="forgot-link" href="/login/forgot?lang={{.Locale}}">{{.ForgotLink}}</a></div>
        </form>
      </main>
    </div>
    <script>
      (() => {
        const form = document.getElementById('login-form');
        const traceHint = {{.CaptchaTraceHint}};
        const traceDone = {{.CaptchaTraceDone}};
        const passkeyUnavailable = {{.PasskeyLoginUnavailable}};
        const passkeyFailed = {{.PasskeyLoginFailed}};
        const passkeyOrigin = {{.PasskeyLoginOrigin}};
        const passkeyDisabled = {{.PasskeyLoginDisabled}};
        const passkeyUnsupported = {{.PasskeyLoginUnsupported}};
        const usernamePlaceholder = {{.UsernamePlaceholder}};
        const captchaRefreshFailed = {{.CaptchaRefreshFailed}};
        const loginRequestFailed = {{.LoginRequestFailed}};
        const loginNetworkFailed = {{.LoginNetworkFailed}};
        const captchaExpiredMessage = {{.LoginErrorCaptchaExpired}};
        const formError = form.querySelector('#login-error');
        const setupTrace = (root) => {
          const image = root.querySelector('#trace-image');
          if (!image) return;
          const answer = root.querySelector('#captcha-answer');
          const status = root.querySelector('#trace-status');
          const overlay = root.querySelector('#trace-markers');
          const line = overlay.querySelector('polyline');
          const resetButton = root.querySelector('#trace-reset');
          const clicks = [];
          const ns = 'http://www.w3.org/2000/svg';
          const traceWidth = 320;
          const traceHeight = 150;
          // The SVG keeps its 320x150 aspect ratio inside the responsive
          // image box. Use that inner rendered rectangle for hit testing so
          // letterboxing does not shift every horizontal click.
          const traceContentRect = () => {
            const rect = image.getBoundingClientRect();
            const scale = Math.min(rect.width / traceWidth, rect.height / traceHeight);
            const width = traceWidth * scale;
            const height = traceHeight * scale;
            return {
              left: rect.left + (rect.width - width) / 2,
              top: rect.top + (rect.height - height) / 2,
              width,
              height,
            };
          };
          const reset = () => {
            clicks.length = 0;
            answer.value = '';
            line.setAttribute('points', '');
            overlay.querySelectorAll('circle, text').forEach((marker) => marker.remove());
            status.textContent = traceHint;
          };
          const addMarker = (point, index) => {
            const circle = document.createElementNS(ns, 'circle');
            circle.setAttribute('cx', point.markerX);
            circle.setAttribute('cy', point.markerY);
            circle.setAttribute('r', '9');
            circle.classList.add('trace-marker-' + (index + 1));
            const label = document.createElementNS(ns, 'text');
            label.setAttribute('x', point.markerX);
            label.setAttribute('y', point.markerY);
            label.classList.add('trace-marker-' + (index + 1));
            label.textContent = String(index + 1);
            overlay.append(circle, label);
          };
          image.addEventListener('click', (event) => {
            const rect = traceContentRect();
            if (!rect.width || !rect.height) return;
            const x = (event.clientX - rect.left) / rect.width * 100;
            const y = (event.clientY - rect.top) / rect.height * 100;
            if (x < 0 || x > 100 || y < 0 || y > 100) return;
            if (clicks.length === 5) reset();
            const point = { x: Number(x.toFixed(2)), y: Number(y.toFixed(2)), markerX: Number((x * traceWidth / 100).toFixed(2)), markerY: Number((y * traceHeight / 100).toFixed(2)) };
            clicks.push(point);
            line.setAttribute('points', clicks.map((item) => item.markerX + ',' + item.markerY).join(' '));
            addMarker(point, clicks.length - 1);
            answer.value = clicks.map((item) => item.x.toFixed(2) + ',' + item.y.toFixed(2)).join(';');
            if (clicks.length === 5) {
              status.textContent = traceDone;
            } else {
              status.textContent = traceHint + ' (' + clicks.length + '/5)';
            }
          });
          resetButton.addEventListener('click', reset);
        };

        let requestPending = false;
        let captchaUnavailable = false;
        let captchaDeadline = 0;
        const retryDeadlines = { submit: 0, refresh: 0 };
        const updateControls = () => {
          const now = Date.now();
          form.querySelector('#login-submit').disabled = requestPending || captchaUnavailable || now < retryDeadlines.submit;
          form.querySelector('#captcha-refresh').disabled = requestPending || now < retryDeadlines.refresh;
        };
        const resetChallengeDeadline = (challenge) => {
          const seconds = Number(challenge.dataset.expiresIn) || 0;
          captchaDeadline = Date.now() + seconds * 1000;
          captchaUnavailable = false;
        };
        const applyFormCooldown = (page) => {
          const seconds = Number(page.querySelector('#login-form')?.dataset.retryAfter);
          if (!Number.isFinite(seconds) || seconds < 1) return;
          retryDeadlines.submit = retryDeadlines.refresh = Date.now() + seconds * 1000;
          window.setTimeout(updateControls, seconds * 1000);
        };
        const replaceChallenge = (page) => {
          const nextChallenge = page.querySelector('#login-challenge');
          const nextContent = page.querySelector('#captcha-content');
          const nextID = page.querySelector('#login-captcha-id');
          if (!nextChallenge || !nextContent || !nextID?.value) return false;
          form.querySelector('#login-captcha-id').value = nextID.value;
          form.querySelector('#captcha-content').replaceWith(nextContent);
          setupTrace(form);
          resetChallengeDeadline(nextChallenge);
          applyFormCooldown(page);
          return true;
        };
        const focusChallenge = () => {
          form.querySelector('.trace-prompt, #captcha-answer:not([type="hidden"])')?.focus({ preventScroll: true });
        };

        const deferRetry = (action, response) => {
          if (response.status !== 429) return false;
          const seconds = Number.parseInt(response.headers.get('Retry-After') || '', 10);
          if (!Number.isFinite(seconds) || seconds < 1) return false;
          retryDeadlines[action] = Date.now() + seconds * 1000;
          window.setTimeout(updateControls, seconds * 1000);
          return true;
        };

        setupTrace(form);
        resetChallengeDeadline(form.querySelector('#login-challenge'));
        applyFormCooldown(document);
        updateControls();
        window.addEventListener('pageshow', (event) => {
          if (!event.persisted) return;
          // A history-restored image may have been consumed on the server.
          captchaDeadline = 0;
          captchaUnavailable = false;
          updateControls();
        });
        const refreshChallenge = async (message = '') => {
          if (requestPending || Date.now() < retryDeadlines.refresh) return;
          // Refresh invalidates the current server-side ID. Keep it mutually
          // exclusive with login, including Enter and programmatic submits.
          requestPending = true;
          updateControls();
          try {
            const locale = form.querySelector('[name="locale"]').value;
            const response = await fetch('/login/captcha/refresh?lang=' + encodeURIComponent(locale), {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({ captcha_id: form.querySelector('#login-captcha-id').value, locale }),
              credentials: 'same-origin'
            });
            const body = await response.text();
            if (!response.ok) {
              deferRetry('refresh', response);
              if (response.status !== 429) captchaUnavailable = true;
              formError.textContent = body.trim() || captchaRefreshFailed;
              return;
            }
            const page = new DOMParser().parseFromString(body, 'text/html');
            if (!replaceChallenge(page)) {
              captchaUnavailable = true;
              formError.textContent = captchaRefreshFailed;
              return;
            }
            formError.textContent = page.querySelector('#login-error')?.textContent.trim() || message;
            if (message) focusChallenge();
          } catch (_) {
            captchaUnavailable = true;
            formError.textContent = loginNetworkFailed;
          } finally {
            requestPending = false;
            updateControls();
          }
        };
        form.addEventListener('click', (event) => {
          if (event.target.closest('#captcha-refresh')) return refreshChallenge();
        });

        form.addEventListener('submit', async (event) => {
          event.preventDefault();
          if (requestPending || captchaUnavailable || Date.now() < retryDeadlines.submit) return;
          // An expired image needs a new answer. Only send its ID to refresh,
          // and let the next explicit submit send the password with that answer.
          if (Date.now() >= captchaDeadline) return refreshChallenge(captchaExpiredMessage);
          requestPending = true;
          updateControls();
          try {
            const response = await fetch(form.action, {
              method: 'POST',
              body: new URLSearchParams(new FormData(form)),
              credentials: 'same-origin',
              redirect: 'follow'
            });
            if (response.redirected) {
              const redirectedPath = new URL(response.url).pathname;
              if (redirectedPath === '/login/otp') {
                captchaUnavailable = true;
                window.location.assign(response.url);
                return;
              }
              if (redirectedPath !== '/login') {
                captchaUnavailable = true;
                window.location.assign('/');
                return;
              }
            }
            const body = await response.text();
            if (!response.ok) {
              deferRetry('submit', response);
              if (response.status !== 429) captchaUnavailable = true;
              formError.textContent = body.trim() || loginRequestFailed;
              return;
            }
            const page = new DOMParser().parseFromString(body, 'text/html');
            if (!replaceChallenge(page)) {
              captchaUnavailable = true;
              formError.textContent = loginRequestFailed;
              return;
            }
            formError.textContent = page.querySelector('#login-error')?.textContent.trim() || '';
            focusChallenge();
          } catch (_) {
            // The server may have consumed this one-time challenge even when
            // the response was lost. Never silently replay a password POST.
            captchaUnavailable = true;
            formError.textContent = loginNetworkFailed;
          } finally {
            requestPending = false;
            updateControls();
          }
        });

        const passkeyButton = form.querySelector('#passkey-login');
        const passkeyBytes = (value) => {
          const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
          const binary = window.atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
          return Uint8Array.from(binary, (char) => char.charCodeAt(0));
        };
        const passkeyBase64 = (value) => {
          const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value || []);
          let binary = '';
          bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
          return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        };
        const passkeyOptions = (payload) => {
          const options = JSON.parse(JSON.stringify(payload.publicKey || payload));
          if (options.challenge) options.challenge = passkeyBytes(options.challenge);
          (options.allowCredentials || []).forEach((item) => { if (item.id) item.id = passkeyBytes(item.id); });
          return options;
        };
        const passkeyResponse = (credential) => {
          const response = credential.response || {};
          const result = { id: credential.id, rawId: passkeyBase64(response.rawId), type: credential.type, response: {} };
          ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle'].forEach((key) => { if (response[key]) result.response[key] = passkeyBase64(response[key]); });
          return result;
        };
        passkeyButton?.addEventListener('click', async () => {
          if (!window.PublicKeyCredential || !navigator.credentials) {
            formError.textContent = passkeyUnsupported;
            return;
          }
          const hostname = String(window.location.hostname || '');
          if (!window.isSecureContext || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
            formError.textContent = passkeyOrigin;
            return;
          }
          const username = form.querySelector('[name="username"]').value.trim();
          if (!username) {
            formError.textContent = usernamePlaceholder;
            return;
          }
          passkeyButton.disabled = true;
          try {
            const optionsResponse = await fetch('/auth/passkey/login/options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }), credentials: 'same-origin' });
            const optionsBody = await optionsResponse.json();
            if (!optionsResponse.ok) {
              const raw = String(optionsBody.error || '').toLowerCase();
              throw new Error(raw.includes('passkey login is unavailable') ? passkeyUnavailable : (raw.includes('passkey is disabled') ? passkeyDisabled : (raw.includes('dns host') || raw.includes('https origin') ? passkeyOrigin : passkeyFailed)));
            }
            let credential;
            try {
              credential = await navigator.credentials.get({ publicKey: passkeyOptions(optionsBody) });
            } catch (error) {
              const name = String(error?.name || '');
              if (name === 'SecurityError' || name === 'NotSupportedError') throw new Error(passkeyOrigin);
              throw error;
            }
            if (!credential) throw new Error(passkeyFailed);
            const verifyResponse = await fetch('/auth/passkey/login/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(passkeyResponse(credential)), credentials: 'same-origin' });
            if (!verifyResponse.ok) {
              const verifyBody = await verifyResponse.json().catch(() => ({}));
              throw new Error(passkeyFailed);
            }
            window.location.assign('/');
          } catch (error) {
            const raw = String(error?.message || '').toLowerCase();
            const localized = error?.message === passkeyUnavailable || error?.message === passkeyOrigin || error?.message === passkeyDisabled || error?.message === passkeyFailed;
            formError.textContent = raw.includes('passkey login is unavailable') ? passkeyUnavailable : (localized ? error.message : passkeyFailed);
          } finally {
            passkeyButton.disabled = false;
          }
        });
      })();
    </script>
  </body>
</html>`

const loginOTPHTML = `<!DOCTYPE html>
<html lang="{{.Locale}}"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/><title>{{.Title}}</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:linear-gradient(135deg,#111827,#1f2937 55%,#7c2d12);font-family:"IBM Plex Sans",sans-serif;color:#f9fafb}.card{width:min(440px,100%);padding:28px;border-radius:24px;background:rgba(17,24,39,.9);box-shadow:0 24px 60px rgba(0,0,0,.32);border:1px solid rgba(255,255,255,.08)}h1{margin:0 0 12px;font-size:1.7rem}.hint{margin:0 0 18px;color:#cbd5e1;line-height:1.5}.message{min-height:1.4em;margin:0 0 12px;color:#fca5a5;line-height:1.4}input,button{display:block;width:100%;padding:13px 15px;margin:0 0 10px;border-radius:12px;border:none;font:inherit}input{background:#f8fafc;color:#111827}button{background:linear-gradient(90deg,#0f766e,#14b8a6);color:#fff;font-weight:600;cursor:pointer}.back{display:block;margin-top:12px;color:#99f6e4;text-align:center}
</style></head><body><main class="card"><h1>{{.Title}}</h1><p class="hint">{{.Hint}}</p><p class="message" role="alert">{{.Error}}</p><form id="login-otp-form" method="post" action="/login/otp"><input type="hidden" name="locale" value="{{.Locale}}"/><input name="otp_code" inputmode="numeric" autocomplete="one-time-code" placeholder="{{.Code}}" autofocus required/><button type="submit">{{.Submit}}</button></form><a class="back" href="/login?lang={{.Locale}}">{{.Back}}</a></main></body></html>`
