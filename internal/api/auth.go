package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/security"
)

const sessionCookieName = "nodewall_session"
const localeCookieName = "nodewall_locale"

const (
	loginCaptchaTTL           = 5 * time.Minute
	loginCaptchaLimit         = 4096
	loginPageRateLimit        = 20
	loginRefreshRateLimit     = 8
	loginSubmitRateLimit      = 10
	loginRequestRateWindow    = time.Minute
	loginRateLimitSourceLimit = 8192
	loginAttemptSourceLimit   = 8192
)

type authManager struct {
	enabled      bool
	authFile     string
	settingsFile string
	webAccess    string
	secureCookie bool
	allowedNets  []netip.Prefix
	allowedMACs  map[string]struct{}

	mu            sync.RWMutex
	sessions      map[string]sessionState
	loginAttempts map[string]loginAttempt
	loginCaptchas map[string]loginCaptchaState
	loginRates    map[string]loginRateWindow
	settings      models.AuthSecuritySettings
}

type sessionState struct {
	ExpiresAt time.Time
	Username  string
	Role      string
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
	ExpiresAt   time.Time
}

type loginCaptchaPoint struct {
	Step  int
	Label int
	X     int
	Y     int
	Decoy bool
}

type loginCaptchaView struct {
	ID       string
	Kind     string
	Prompt   string
	Image    template.URL
	Points   []loginCaptchaPoint
	Sequence []int
}

func newAuthManager(cfg config.ServerConfig) (*authManager, error) {
	settingsFile := cfg.AuthSettingsFile
	if strings.TrimSpace(settingsFile) == "" {
		settingsFile = "/etc/nodewall/auth-settings.json"
	}
	manager := &authManager{
		enabled:       cfg.AuthEnabled,
		authFile:      cfg.AuthFile,
		settingsFile:  settingsFile,
		webAccess:     strings.ToLower(strings.TrimSpace(cfg.WebAccessMode)),
		secureCookie:  cfg.TLSEnabled,
		allowedMACs:   make(map[string]struct{}),
		sessions:      make(map[string]sessionState),
		loginAttempts: make(map[string]loginAttempt),
		loginCaptchas: make(map[string]loginCaptchaState),
		loginRates:    make(map[string]loginRateWindow),
		settings: normalizeAuthSettings(models.AuthSecuritySettings{
			MaxFailures:         5,
			WindowSeconds:       int((10 * time.Minute) / time.Second),
			LockDurationSeconds: int((15 * time.Minute) / time.Second),
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
		return nil, err
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
		case "/login/captcha/refresh":
			if r.Method == http.MethodPost {
				a.handleLoginCaptchaRefresh(w, r)
				return
			}
		case "/logout":
			a.handleLogout(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/join/") || r.URL.Path == "/version" {
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

func (a *authManager) authorize(role string, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	path := r.URL.Path
	if path == "/auth/session" || path == "/logout" {
		return true
	}
	role = security.NormalizeRole(role)
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
	if _, blocked := a.loginLockedUntil(sourceKey); blocked {
		a.serveLogin(w, r, "loginErrorLocked", username)
		return
	}

	if !a.consumeLoginCaptcha(r.FormValue("captcha_id"), r.FormValue("captcha_answer")) {
		a.recordLoginFailure(sourceKey)
		a.serveLogin(w, r, "loginErrorCaptcha", username)
		return
	}

	password := r.FormValue("password")
	store, err := security.LoadUserStore(a.authFile)
	user, _ := store.Find(username)
	if err != nil || user == nil || !user.Enabled || !security.VerifyPassword(password, user.Password) {
		a.recordLoginFailure(sourceKey)
		time.Sleep(400 * time.Millisecond)
		a.serveLogin(w, r, "loginErrorInvalidCredentials", username)
		return
	}

	token, err := randomToken()
	if err != nil {
		a.serveLogin(w, r, "loginErrorSessionCreate", username)
		return
	}

	a.mu.Lock()
	a.sessions[token] = sessionState{
		ExpiresAt: time.Now().Add(12 * time.Hour),
		Username:  user.Username,
		Role:      security.NormalizeRole(user.Role),
	}
	delete(a.loginAttempts, sourceKey)
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.secureCookie,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *authManager) handleLoginCaptchaRefresh(w http.ResponseWriter, r *http.Request) {
	source := loginSourceKey(r)
	if until, blocked := a.loginLockedUntil(source); blocked {
		writeLoginRateLimited(w, r, time.Until(until), "loginLocked")
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
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.secureCookie,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *authManager) serveLogin(w http.ResponseWriter, r *http.Request, errorKey, username string) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	locale := loginLocaleFromRequest(r)
	msg := loginMessages(locale)
	captcha, err := a.newLoginCaptcha()
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
		"Locale":                  locale,
		"Title":                   msg["title"],
		"UsernamePlaceholder":     msg["usernamePlaceholder"],
		"PasswordPlaceholder":     msg["passwordPlaceholder"],
		"Submit":                  msg["submit"],
		"LocaleLabel":             msg["localeLabel"],
		"LocaleChinese":           msg["localeChinese"],
		"LocaleEnglish":           msg["localeEnglish"],
		"LoginErrorInvalidForm":   msg["loginErrorInvalidForm"],
		"LoginErrorLocked":        msg["loginErrorLocked"],
		"LoginErrorInvalidCreds":  msg["loginErrorInvalidCredentials"],
		"LoginErrorCaptcha":       msg["loginErrorCaptcha"],
		"LoginErrorSessionCreate": msg["loginErrorSessionCreate"],
		"CaptchaLabel":            msg["captchaLabel"],
		"CaptchaPlaceholder":      msg["captchaPlaceholder"],
		"CaptchaRefresh":          msg["captchaRefresh"],
		"CaptchaTraceHint":        msg["captchaTraceHint"],
		"CaptchaTraceDone":        msg["captchaTraceDone"],
		"CaptchaTraceReset":       msg["captchaTraceReset"],
		"ErrorKey":                errorKey,
		"Username":                username,
		"Captcha":                 captcha,
	})
}

func (a *authManager) newLoginCaptcha() (loginCaptchaView, error) {
	id, err := randomToken()
	if err != nil {
		return loginCaptchaView{}, err
	}
	kindIndex, err := secureRandomInt(3)
	if err != nil {
		return loginCaptchaView{}, err
	}
	view := loginCaptchaView{ID: id}
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
		left += 2
		right += 2
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
		for i := 0; i < 5; i++ {
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
	a.mu.Lock()
	challenge, ok := a.loginCaptchas[id]
	if ok {
		delete(a.loginCaptchas, id)
	}
	a.mu.Unlock()
	if !ok || !challenge.ExpiresAt.After(time.Now()) || len(answer) > 256 {
		return false
	}
	if challenge.Kind == "trace" {
		return validateLoginTraceAnswer(answer, challenge.TracePoints)
	}
	answer = strings.ToUpper(strings.TrimSpace(answer))
	return subtle.ConstantTimeCompare([]byte(answer), []byte(challenge.Answer)) == 1
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

func writeLoginRateLimited(w http.ResponseWriter, r *http.Request, retryAfter time.Duration, messageKey string) {
	seconds := int(retryAfter.Seconds())
	if time.Duration(seconds)*time.Second < retryAfter {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
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
		dx := (x - float64(expected[i].X)) * 3.2
		dy := (y - float64(expected[i].Y)) * 1.5
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

func makeLoginCaptchaImage(code string) (template.URL, error) {
	const width, height = 240, 72
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-−=? "
	runes := []rune(code)
	if len(runes) == 0 || len(runes) > 12 {
		return "", fmt.Errorf("captcha text length is invalid")
	}
	for _, char := range runes {
		if !strings.ContainsRune(allowed, char) {
			return "", fmt.Errorf("captcha contains an unsupported character")
		}
	}

	var svg strings.Builder
	fmt.Fprintf(&svg, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d"><rect width="%d" height="%d" rx="10" fill="#e8eef5"/>`, width, height, width, height, width, height)
	colors := []string{"#174f70", "#8a3d5d", "#365c3b", "#754d20", "#4338ca"}
	for i := 0; i < 13; i++ {
		x1, err := secureRandomInt(width)
		if err != nil {
			return "", err
		}
		y1, err := secureRandomInt(height)
		if err != nil {
			return "", err
		}
		x2, err := secureRandomInt(width)
		if err != nil {
			return "", err
		}
		y2, err := secureRandomInt(height)
		if err != nil {
			return "", err
		}
		color, err := secureRandomInt(int64(len(colors)))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&svg, `<path d="M%d %d L%d %d" stroke="%s" stroke-opacity=".28" stroke-width="1.2"/>`, x1, y1, x2, y2, colors[color])
	}
	for i := 0; i < 30; i++ {
		x, err := secureRandomInt(width)
		if err != nil {
			return "", err
		}
		y, err := secureRandomInt(height)
		if err != nil {
			return "", err
		}
		radius, err := secureRandomInt(2)
		if err != nil {
			return "", err
		}
		color, err := secureRandomInt(int64(len(colors)))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity=".34"/>`, x, y, radius+1, colors[color])
	}
	slot := float64(width-24) / float64(len(runes))
	fontSize := 31
	if len(runes) > 7 {
		fontSize = 24
	}
	for i, char := range runes {
		if char == ' ' {
			continue
		}
		rotation, err := secureRandomInt(31)
		if err != nil {
			return "", err
		}
		yOffset, err := secureRandomInt(9)
		if err != nil {
			return "", err
		}
		color, err := secureRandomInt(int64(len(colors)))
		if err != nil {
			return "", err
		}
		x := 12 + slot*(float64(i)+0.5)
		y := 42 + int(yOffset) - 4
		fmt.Fprintf(&svg, `<text x="%.1f" y="%d" transform="rotate(%d %.1f 36)" text-anchor="middle" font-family="monospace" font-size="%d" font-weight="700" fill="%s">%c</text>`, x, y, rotation-15, x, fontSize, colors[color], char)
	}
	svg.WriteString(`</svg>`)
	encoded := base64.StdEncoding.EncodeToString([]byte(svg.String()))
	return template.URL("data:image/svg+xml;base64," + encoded), nil
}

func makeLoginTraceCaptchaImage(points []loginCaptchaPoint) (template.URL, error) {
	const width, height = 320, 150
	var svg strings.Builder
	fmt.Fprintf(&svg, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d"><defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#1e293b"/><stop offset="1" stop-color="#111827"/></linearGradient></defs><rect width="%d" height="%d" rx="12" fill="url(#bg)"/>`, width, height, width, height, width, height)
	colors := []string{"#38bdf8", "#a78bfa", "#f472b6", "#fbbf24", "#34d399"}
	for i := 0; i < 12; i++ {
		x1, err := secureRandomInt(width)
		if err != nil {
			return "", err
		}
		y1, err := secureRandomInt(height)
		if err != nil {
			return "", err
		}
		x2, err := secureRandomInt(width)
		if err != nil {
			return "", err
		}
		y2, err := secureRandomInt(height)
		if err != nil {
			return "", err
		}
		color, err := secureRandomInt(int64(len(colors)))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&svg, `<path d="M%d %d Q%d %d %d %d" fill="none" stroke="%s" stroke-opacity=".24" stroke-width="1.4"/>`, x1, y1, (x1+x2)/2, (y1+y2)/2+12, x2, y2, colors[color])
	}
	for i := 0; i < 38; i++ {
		x, err := secureRandomInt(width)
		if err != nil {
			return "", err
		}
		y, err := secureRandomInt(height)
		if err != nil {
			return "", err
		}
		radius, err := secureRandomInt(3)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="%d" fill="#cbd5e1" fill-opacity=".24"/>`, x, y, radius+1)
	}
	for _, point := range points {
		cx, cy := point.X*width/100, point.Y*height/100
		if point.Decoy {
			fmt.Fprintf(&svg, `<circle class="decoy" cx="%d" cy="%d" r="16" fill="#475569" fill-opacity=".72" stroke="#94a3b8" stroke-width="2"/><circle cx="%d" cy="%d" r="3" fill="#cbd5e1" fill-opacity=".8"/>`, cx, cy, cx, cy)
			continue
		}
		fmt.Fprintf(&svg, `<circle class="target" cx="%d" cy="%d" r="17" fill="#0f766e" stroke="#5eead4" stroke-width="2.5"/><text x="%d" y="%d" text-anchor="middle" dominant-baseline="central" font-family="sans-serif" font-size="18" font-weight="700" fill="#f8fafc">%d</text>`, cx, cy, cx, cy, point.Label)
	}
	svg.WriteString(`</svg>`)
	encoded := base64.StdEncoding.EncodeToString([]byte(svg.String()))
	return template.URL("data:image/svg+xml;base64," + encoded), nil
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
			"title":                        "NodeWall Sign In",
			"usernamePlaceholder":          "Username",
			"passwordPlaceholder":          "Password",
			"submit":                       "Sign In",
			"localeLabel":                  "Language",
			"localeChinese":                "简体中文",
			"localeEnglish":                "English",
			"loginErrorInvalidForm":        "Invalid form data.",
			"loginErrorLocked":             "Too many attempts. Please try again later.",
			"loginErrorInvalidCredentials": "Invalid username or password.",
			"loginErrorCaptcha":            "Verification failed. Please try the new challenge.",
			"loginErrorSessionCreate":      "Unable to create session.",
			"captchaLabel":                 "Human verification",
			"captchaPlaceholder":           "Code",
			"captchaRefresh":               "Try another",
			"loginRateLimited":             "Too many requests. Retry in %d seconds.",
			"captchaRefreshRateLimited":    "Captcha refresh is temporarily limited. Retry in %d seconds.",
			"captchaTracePrompt":           "Click the numbered dots in this order: %s",
			"captchaTraceHint":             "Click each dot in order; avoid the unnumbered decoys.",
			"captchaTraceDone":             "Five points selected",
			"captchaTraceReset":            "Reset",
		}
	}
	return map[string]string{
		"title":                        "NodeWall 登录",
		"usernamePlaceholder":          "账号",
		"passwordPlaceholder":          "密码",
		"submit":                       "登录",
		"localeLabel":                  "语言",
		"localeChinese":                "简体中文",
		"localeEnglish":                "English",
		"loginErrorInvalidForm":        "表单格式无效。",
		"loginErrorLocked":             "尝试次数过多，请稍后重试。",
		"loginErrorInvalidCredentials": "账号或密码错误。",
		"loginErrorCaptcha":            "人机验证未通过，请完成新的验证。",
		"loginErrorSessionCreate":      "会话创建失败。",
		"captchaLabel":                 "人机验证",
		"captchaPlaceholder":           "验证码",
		"captchaRefresh":               "换一题",
		"loginRateLimited":             "请求过于频繁，请 %d 秒后重试。",
		"captchaRefreshRateLimited":    "验证码切换太频繁，请 %d 秒后重试。",
		"captchaTracePrompt":           "按 %s 顺序点击圆点",
		"captchaTraceHint":             "按顺序点击编号圆点，避开无编号干扰点。",
		"captchaTraceDone":             "已选中 5 个点",
		"captchaTraceReset":            "重选",
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
	a.mu.Lock()
	defer a.mu.Unlock()
	a.settings = normalizeAuthSettings(settings)
	return a.saveSettingsLocked()
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
	if attempt.Failures >= settings.MaxFailures {
		attempt.LockedUntil = now.Add(lockDuration)
	}
	a.loginAttempts[source] = attempt
}

func (a *authManager) loadSettings() error {
	data, err := os.ReadFile(a.settingsFile)
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
	a.settings = normalizeAuthSettings(settings)
	return nil
}

func (a *authManager) saveSettingsLocked() error {
	if err := os.MkdirAll(filepath.Dir(a.settingsFile), 0o755); err != nil {
		return err
	}
	payload := a.settings
	payload.ActiveLocks = 0
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.settingsFile), filepath.Base(a.settingsFile)+".tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, a.settingsFile); err != nil {
		return err
	}
	cleanup = false
	return nil
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

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "updated",
		"message": "password updated",
	})
}

func (a *authManager) listUsers(w http.ResponseWriter, r *http.Request) {
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	type userInfo struct {
		Username  string     `json:"username"`
		Role      string     `json:"role"`
		Enabled   bool       `json:"enabled"`
		CreatedAt time.Time  `json:"created_at"`
		UpdatedAt time.Time  `json:"updated_at"`
		LastLogin *time.Time `json:"last_login,omitempty"`
	}
	items := make([]userInfo, 0, len(store.Users))
	for _, user := range store.Users {
		items = append(items, userInfo{
			Username:  user.Username,
			Role:      security.NormalizeRole(user.Role),
			Enabled:   user.Enabled,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			LastLogin: user.LastLogin,
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
		if source, ok := requestSourceAddr(r); ok && !source.IsLoopback() {
			return false
		}
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
    <style>
      *{box-sizing:border-box}
      body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:linear-gradient(135deg,#111827,#1f2937 55%,#7c2d12);font-family:"IBM Plex Sans",sans-serif;color:#f9fafb}
      .card{width:min(420px,100%);max-width:420px;padding:28px;border-radius:24px;background:rgba(17,24,39,.82);box-shadow:0 24px 60px rgba(0,0,0,.32);border:1px solid rgba(255,255,255,.08)}
      h1{margin:0 0 18px;font-size:2rem}
      input,button{display:block;width:100%;max-width:100%;padding:13px 15px;border-radius:12px;border:none;font:inherit}
      input{margin-bottom:10px;background:#f8fafc;color:#111827}
      button{background:linear-gradient(90deg,#0f766e,#14b8a6);color:#fff;font-weight:600;cursor:pointer}
      button:disabled{opacity:.65;cursor:wait}
      .challenge{margin:4px 0 12px;padding:12px;border:1px solid rgba(255,255,255,.12);border-radius:14px;background:rgba(15,23,42,.62)}
      .challenge-header{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px}
      .challenge-label{margin:0;color:#cbd5e1;font-size:.88rem}
      .captcha-refresh{width:auto;padding:5px 9px;border:1px solid rgba(255,255,255,.16);background:transparent;color:#cbd5e1;font-size:.8rem;font-weight:500}
      .captcha-row{display:grid;grid-template-columns:166px minmax(0,1fr);gap:10px;align-items:center}
      .captcha-row input{min-width:0;margin:0;padding:12px}
      .captcha-image{display:block;width:166px;height:50px;max-width:100%;margin:0;border:1px solid rgba(255,255,255,.15);border-radius:8px;background:#e8eef5;object-fit:fill}
      .trace-prompt{margin:0 0 8px;font-size:1rem;font-weight:650;letter-spacing:.02em}
      .trace-image-wrap{position:relative;width:100%;margin:8px 0 4px;overflow:hidden;border:1px solid rgba(255,255,255,.12);border-radius:11px;background:#172033;aspect-ratio:320/150}
      .trace-image{display:block;width:100%;height:100%;object-fit:fill;cursor:crosshair;touch-action:manipulation;user-select:none}
      .trace-markers{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}
      .trace-markers polyline{fill:none;stroke:#5eead4;stroke-width:1.3;stroke-linecap:round;stroke-linejoin:round}
      .trace-markers circle{fill:#0f766e;stroke:#99f6e4;stroke-width:.8}
      .trace-markers text{fill:#fff;font:700 4px sans-serif;text-anchor:middle;dominant-baseline:central}
      .trace-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px}
      .trace-status{min-height:1.25em;margin:4px 0 10px;color:#cbd5e1;font-size:.82rem}
      .trace-reset{display:inline-flex;width:auto;padding:5px 9px;border:1px solid rgba(255,255,255,.16);background:transparent;color:#cbd5e1;font-size:.8rem;font-weight:500}
      .error{margin:0 0 12px;color:#fca5a5;line-height:1.5;word-break:break-word}
      .error:empty{display:none}
      .locale{margin-top:12px;display:flex;align-items:center;gap:8px;color:#cbd5e1}
      .locale select{background:#0f172a;color:#f8fafc;border:1px solid rgba(255,255,255,.16);padding:8px 10px;border-radius:10px}
      @media(max-width:390px){.card{padding:22px}.captcha-row{grid-template-columns:132px minmax(0,1fr);gap:8px}.captcha-image{width:132px;height:40px}.captcha-row input{padding:11px}}
    </style>
  </head>
  <body>
    <form class="card" id="login-form" method="post" action="/login">
      <h1>NodeWall</h1>
      <input type="hidden" name="locale" value="{{.Locale}}" />
      <input type="hidden" name="captcha_id" id="login-captcha-id" value="{{.Captcha.ID}}" />
      <input type="text" name="username" value="{{.Username}}" placeholder="{{.UsernamePlaceholder}}" autocomplete="username" autofocus required />
      <input type="password" name="password" placeholder="{{.PasswordPlaceholder}}" autocomplete="current-password" required />
      <div class="error" id="login-error" role="alert" aria-live="polite">{{if eq .ErrorKey "loginErrorInvalidForm"}}{{.LoginErrorInvalidForm}}{{else if eq .ErrorKey "loginErrorLocked"}}{{.LoginErrorLocked}}{{else if eq .ErrorKey "loginErrorInvalidCredentials"}}{{.LoginErrorInvalidCreds}}{{else if eq .ErrorKey "loginErrorCaptcha"}}{{.LoginErrorCaptcha}}{{else if eq .ErrorKey "loginErrorSessionCreate"}}{{.LoginErrorSessionCreate}}{{end}}</div>
      <section class="challenge" id="login-challenge" aria-label="{{.CaptchaLabel}}">
        <div class="challenge-header"><p class="challenge-label">{{.CaptchaLabel}}</p><button class="captcha-refresh" id="captcha-refresh" type="button">{{.CaptchaRefresh}}</button></div>
        {{if or (eq .Captcha.Kind "math") (eq .Captcha.Kind "letters")}}
          <div class="captcha-row">
            <img class="captcha-image" data-kind="{{.Captcha.Kind}}" src="{{.Captcha.Image}}" alt="验证码图片" />
            <input type="text" id="captcha-answer" name="captcha_answer" {{if eq .Captcha.Kind "math"}}inputmode="numeric" pattern="[0-9]+"{{else}}autocapitalize="characters" spellcheck="false"{{end}} placeholder="{{.CaptchaPlaceholder}}" autocomplete="off" required />
          </div>
        {{else}}
          <p class="trace-prompt">{{.Captcha.Prompt}}</p>
          <div class="trace-image-wrap">
            <img class="trace-image" id="trace-image" src="{{.Captcha.Image}}" alt="{{.CaptchaTraceHint}}" draggable="false" />
            <svg class="trace-markers" id="trace-markers" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true"><polyline points=""></polyline></svg>
          </div>
          <div class="trace-toolbar"><p class="trace-status" id="trace-status" aria-live="polite">{{.CaptchaTraceHint}}</p><button class="trace-reset" id="trace-reset" type="button">{{.CaptchaTraceReset}}</button></div>
          <input type="hidden" id="captcha-answer" name="captcha_answer" />
        {{end}}
      </section>
      <button type="submit" id="login-submit">{{.Submit}}</button>
      <div class="locale">
        <label for="login-locale">{{.LocaleLabel}}</label>
        <select id="login-locale" onchange="window.location.href='/login?lang='+encodeURIComponent(this.value)">
          <option value="zh-CN" {{if eq .Locale "zh-CN"}}selected{{end}}>{{.LocaleChinese}}</option>
          <option value="en-US" {{if eq .Locale "en-US"}}selected{{end}}>{{.LocaleEnglish}}</option>
        </select>
      </div>
    </form>
    <script>
      (() => {
        const form = document.getElementById('login-form');
        const traceHint = {{printf "%q" .CaptchaTraceHint}};
        const traceDone = {{printf "%q" .CaptchaTraceDone}};
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
          const reset = () => {
            clicks.length = 0;
            answer.value = '';
            line.setAttribute('points', '');
            overlay.querySelectorAll('circle, text').forEach((marker) => marker.remove());
            status.textContent = traceHint;
          };
          const addMarker = (point, index) => {
            const circle = document.createElementNS(ns, 'circle');
            circle.setAttribute('cx', point.x);
            circle.setAttribute('cy', point.y);
            circle.setAttribute('r', '3.2');
            const label = document.createElementNS(ns, 'text');
            label.setAttribute('x', point.x);
            label.setAttribute('y', point.y);
            label.textContent = String(index + 1);
            overlay.append(circle, label);
          };
          image.addEventListener('click', (event) => {
            if (clicks.length === 5) reset();
            const rect = image.getBoundingClientRect();
            const x = Math.max(0, Math.min(100, (event.clientX - rect.left) / rect.width * 100));
            const y = Math.max(0, Math.min(100, (event.clientY - rect.top) / rect.height * 100));
            const point = { x: Number(x.toFixed(2)), y: Number(y.toFixed(2)) };
            clicks.push(point);
            line.setAttribute('points', clicks.map((item) => item.x + ',' + item.y).join(' '));
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

        const replaceChallenge = (page) => {
          const nextChallenge = page.querySelector('#login-challenge');
          const nextID = page.querySelector('#login-captcha-id');
          if (!nextChallenge || !nextID) return false;
          form.querySelector('#login-captcha-id').value = nextID.value;
          form.querySelector('#login-challenge').replaceWith(nextChallenge);
          const nextUsername = page.querySelector('[name="username"]');
          if (nextUsername && nextUsername.value !== '') form.querySelector('[name="username"]').value = nextUsername.value;
          setupTrace(form);
          return true;
        };

        const deferRetry = (button, response) => {
          if (response.status !== 429) return false;
          const seconds = Number.parseInt(response.headers.get('Retry-After') || '', 10);
          if (!Number.isFinite(seconds) || seconds < 1) return false;
          button.disabled = true;
          window.setTimeout(() => { button.disabled = false; }, seconds * 1000);
          return true;
        };

        setupTrace(form);
        form.addEventListener('click', async (event) => {
          const button = event.target.closest('#captcha-refresh');
          if (!button) return;
          button.disabled = true;
          let cooldown = false;
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
              cooldown = deferRetry(button, response);
              formError.textContent = body.trim() || '验证码暂时无法切换，请稍后重试。';
              return;
            }
            const page = new DOMParser().parseFromString(body, 'text/html');
            if (!replaceChallenge(page)) {
              formError.textContent = '验证码刷新失败，请重试。';
              return;
            }
            formError.textContent = '';
          } catch (_) {
            formError.textContent = '验证码刷新失败，请检查网络后重试。';
          } finally {
            if (!cooldown) button.disabled = false;
          }
        });

        form.addEventListener('submit', async (event) => {
          event.preventDefault();
          const submit = form.querySelector('#login-submit');
          submit.disabled = true;
          let cooldown = false;
          try {
            const response = await fetch(form.action, {
              method: 'POST',
              body: new URLSearchParams(new FormData(form)),
              credentials: 'same-origin',
              redirect: 'follow'
            });
            if (response.redirected && new URL(response.url).pathname !== '/login') {
              window.location.assign('/');
              return;
            }
            const body = await response.text();
            if (!response.ok) {
              cooldown = deferRetry(submit, response);
              formError.textContent = body.trim() || '登录请求过于频繁，请稍后重试。';
              return;
            }
            const page = new DOMParser().parseFromString(body, 'text/html');
            if (!replaceChallenge(page)) {
              formError.textContent = '登录请求失败，请重试。';
              return;
            }
            formError.textContent = page.querySelector('#login-error')?.textContent.trim() || '';
          } catch (_) {
            HTMLFormElement.prototype.submit.call(form);
          } finally {
            if (!cooldown) submit.disabled = false;
          }
        });
      })();
    </script>
  </body>
</html>`
