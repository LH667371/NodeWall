package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/security"
)

func TestParseAllowedPrefixAcceptsPlainIPv4(t *testing.T) {
	prefix, err := parseAllowedPrefix("192.168.1.10")
	if err != nil {
		t.Fatalf("parse allowed prefix: %v", err)
	}
	if got := prefix.String(); got != "192.168.1.10/32" {
		t.Fatalf("unexpected prefix: %s", got)
	}
}

func TestParseAllowedPrefixAcceptsCIDR(t *testing.T) {
	prefix, err := parseAllowedPrefix("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parse allowed prefix: %v", err)
	}
	if got := prefix.String(); got != "10.0.0.0/24" {
		t.Fatalf("unexpected prefix: %s", got)
	}
}

func TestAllowRemoteLetsEnrollmentReachTicketValidation(t *testing.T) {
	prefix, err := netip.ParsePrefix("106.15.202.48/32")
	if err != nil {
		t.Fatal(err)
	}
	manager := &authManager{allowedNets: []netip.Prefix{prefix}}

	joinRequest := httptest.NewRequest(http.MethodGet, "/join/script?token=short-lived", nil)
	joinRequest.RemoteAddr = "192.168.201.19:43210"
	if !manager.allowRemote(joinRequest) {
		t.Fatal("enrollment request must reach its ticket validator")
	}

	webRequest := httptest.NewRequest(http.MethodGet, "/nodes", nil)
	webRequest.RemoteAddr = "192.168.201.19:43210"
	if manager.allowRemote(webRequest) {
		t.Fatal("ordinary web requests must still honor the remote allowlist")
	}
}

func TestAllowRemotePublicModeIgnoresLegacyNetworkList(t *testing.T) {
	prefix, err := netip.ParsePrefix("192.168.201.0/24")
	if err != nil {
		t.Fatal(err)
	}
	manager := &authManager{
		webAccess:   "public",
		allowedNets: []netip.Prefix{prefix},
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.20:43210"
	if !manager.allowRemote(request) {
		t.Fatal("public web access must not reject an external source because of a legacy allowlist")
	}
}

func TestAllowRemoteRestrictedModeUsesNetworkList(t *testing.T) {
	prefix, err := netip.ParsePrefix("192.168.201.0/24")
	if err != nil {
		t.Fatal(err)
	}
	manager := &authManager{
		webAccess:   "restricted",
		allowedNets: []netip.Prefix{prefix},
	}
	allowed := httptest.NewRequest(http.MethodGet, "/", nil)
	allowed.RemoteAddr = "192.168.201.17:43210"
	if !manager.allowRemote(allowed) {
		t.Fatal("restricted mode rejected an allowed source")
	}
	denied := httptest.NewRequest(http.MethodGet, "/", nil)
	denied.RemoteAddr = "203.0.113.20:43210"
	if manager.allowRemote(denied) {
		t.Fatal("restricted mode accepted a source outside the network list")
	}
}

func TestLoginSourceKeyIgnoresUntrustedForwardingHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.Header.Set("X-Forwarded-For", "192.168.5.200, 10.0.0.1")
	req.RemoteAddr = "127.0.0.1:12345"
	if got := loginSourceKey(req); got != "127.0.0.1" {
		t.Fatalf("unexpected source key: %s", got)
	}
}

func TestLoginRequestRateLimitUsesBoundedWindowsPerSourceAndAction(t *testing.T) {
	manager := &authManager{}
	start := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for i := 0; i < 2; i++ {
		if allowed, _ := manager.allowLoginRequestAt("192.0.2.10", "refresh", 2, time.Minute, start); !allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if allowed, retry := manager.allowLoginRequestAt("192.0.2.10", "refresh", 2, time.Minute, start.Add(10*time.Second)); allowed || retry != 50*time.Second {
		t.Fatalf("expected rate limit with 50s retry, got allowed=%v retry=%s", allowed, retry)
	}
	if allowed, _ := manager.allowLoginRequestAt("192.0.2.10", "page", 1, time.Minute, start.Add(10*time.Second)); !allowed {
		t.Fatal("a separate action should have an independent limit")
	}
	if allowed, _ := manager.allowLoginRequestAt("192.0.2.11", "refresh", 1, time.Minute, start.Add(10*time.Second)); !allowed {
		t.Fatal("a separate source should have an independent limit")
	}
	if allowed, _ := manager.allowLoginRequestAt("192.0.2.10", "refresh", 2, time.Minute, start.Add(time.Minute)); !allowed {
		t.Fatal("request should be allowed after the window expires")
	}
}

func TestLoginPageRateLimitAndCaptchaRefreshEndpoint(t *testing.T) {
	manager := &authManager{enabled: true, loginCaptchas: make(map[string]loginCaptchaState)}
	initial, err := manager.newLoginCaptcha()
	if err != nil {
		t.Fatalf("create initial captcha: %v", err)
	}
	currentID := initial.ID
	handler := manager.wrap(http.NotFoundHandler())
	for i := 0; i < loginRefreshRateLimit; i++ {
		form := url.Values{"captcha_id": {currentID}, "locale": {"zh-CN"}}
		req := httptest.NewRequest(http.MethodPost, "/login/captcha/refresh?lang=zh-CN", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.0.2.22:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("refresh %d failed: status=%d body=%s", i+1, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `id="captcha-refresh"`) || !strings.Contains(rec.Body.String(), "换一题") {
			t.Fatal("login page should expose the captcha refresh control")
		}
		if rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatal("login page is missing security response headers")
		}
		manager.mu.RLock()
		_, oldStillValid := manager.loginCaptchas[currentID]
		manager.mu.RUnlock()
		if oldStillValid {
			t.Fatal("refresh should invalidate the previous challenge")
		}
		match := regexp.MustCompile(`id="login-captcha-id" value="([a-f0-9]+)"`).FindStringSubmatch(rec.Body.String())
		if len(match) != 2 || match[1] == currentID {
			t.Fatal("refresh should issue a new challenge id")
		}
		currentID = match[1]
	}

	form := url.Values{"captcha_id": {currentID}, "locale": {"zh-CN"}}
	req := httptest.NewRequest(http.MethodPost, "/login/captcha/refresh?lang=zh-CN", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.22:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "验证码切换太频繁") {
		t.Fatalf("expected localized refresh rate limit, got status=%d headers=%v body=%q", rec.Code, rec.Header(), rec.Body.String())
	}
	manager.mu.RLock()
	currentChallenge, stillAvailable := manager.loginCaptchas[currentID]
	manager.mu.RUnlock()
	if !stillAvailable {
		t.Fatal("rate-limited refresh must not invalidate the current challenge")
	}
	currentAnswer := currentChallenge.Answer
	if currentChallenge.Kind == "trace" {
		currentAnswer = encodeLoginTraceAnswer(currentChallenge.TracePoints)
	}
	if !manager.consumeLoginCaptchaForSource(currentID, currentAnswer, "192.0.2.22") {
		t.Fatal("the current challenge must remain usable after refresh is rate-limited")
	}

	key := "192.0.2.23\x00page"
	manager.mu.Lock()
	manager.loginRates[key] = loginRateWindow{StartedAt: time.Now(), Window: loginRequestRateWindow, Requests: loginPageRateLimit}
	manager.mu.Unlock()
	pageRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	pageRequest.RemoteAddr = "192.0.2.23:12345"
	pageResponse := httptest.NewRecorder()
	handler.ServeHTTP(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("expected login page rate limit, got status=%d", pageResponse.Code)
	}
}

func TestAuthWrapAllowsLoginFaviconWithoutSession(t *testing.T) {
	manager := &authManager{enabled: true}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/nodewall-mark.svg", nil)
	rec := httptest.NewRecorder()

	manager.wrap(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected favicon to be public, got status %d", rec.Code)
	}
}

func TestAuthWrapRequiresCSRFForAuthenticatedMutation(t *testing.T) {
	manager := &authManager{
		enabled: true,
		sessions: map[string]sessionState{
			"session-token": {
				Username:  "admin",
				Role:      security.RoleAdmin,
				CSRFToken: "csrf-token",
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := manager.wrap(next)

	request := httptest.NewRequest(http.MethodPost, "/auth/password", strings.NewReader(`{}`))
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("mutation without CSRF token should be rejected, got %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/auth/password", strings.NewReader(`{}`))
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	request.Header.Set("X-NodeWall-CSRF", "csrf-token")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("mutation with a valid CSRF token should reach the handler, got %d", response.Code)
	}
}

func TestAuthorizeKeepsUserDirectoryAdminOnlyForReads(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/auth/users", nil)
	if manager := (&authManager{}); manager.authorize(security.RoleViewer, request) {
		t.Fatal("viewer must not read the user directory")
	}
	if manager := (&authManager{}); !manager.authorize(security.RoleAdmin, request) {
		t.Fatal("admin should read the user directory")
	}
}

func TestIssueSessionUsesStrictSecureCookiesAndCSRFToken(t *testing.T) {
	manager := &authManager{secureCookie: true, sessions: make(map[string]sessionState)}
	response := httptest.NewRecorder()
	if err := manager.issueSession(response, "admin", security.RoleAdmin); err != nil {
		t.Fatalf("issue session: %v", err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected session and CSRF cookies, got %d", len(cookies))
	}
	seenSession, seenCSRF := false, false
	for _, cookie := range cookies {
		if cookie.SameSite != http.SameSiteStrictMode || !cookie.Secure || cookie.MaxAge <= 0 {
			t.Fatalf("cookie has unsafe attributes: %+v", cookie)
		}
		switch cookie.Name {
		case sessionCookieName:
			seenSession = cookie.HttpOnly
		case csrfCookieName:
			seenCSRF = !cookie.HttpOnly && cookie.Value != ""
		}
	}
	if !seenSession || !seenCSRF {
		t.Fatal("session cookie must be HttpOnly and CSRF cookie must be readable by the client")
	}
	if len(manager.sessions) != 1 || manager.sessions[response.Result().Cookies()[0].Value].CSRFToken == "" {
		t.Fatal("issued session must have a server-side CSRF token")
	}
}

func TestLoginSecurityErrorsUseSelectedLocale(t *testing.T) {
	manager := &authManager{
		enabled:       true,
		loginCaptchas: make(map[string]loginCaptchaState),
		settings:      models.AuthSecuritySettings{PasskeyEnabled: true},
	}
	handler := manager.wrap(http.NotFoundHandler())

	for _, test := range []struct {
		locale string
		want   string
		avoid  string
	}{
		{locale: "zh-CN", want: "此账号尚未登记可用的 Passkey。", avoid: "This account has no registered Passkey."},
		{locale: "en-US", want: "This account has no registered Passkey.", avoid: "此账号尚未登记可用的 Passkey。"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/login?lang="+test.locale, nil)
		req.RemoteAddr = "192.0.2.90:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("locale %s login page failed: status=%d", test.locale, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, test.want) {
			t.Fatalf("locale %s missing localized Passkey error %q", test.locale, test.want)
		}
		if strings.Contains(body, test.avoid) {
			t.Fatalf("locale %s leaked the other locale's Passkey error", test.locale)
		}
	}
}

func TestForgotPasswordPageUsesSelectedLocale(t *testing.T) {
	manager := &authManager{enabled: true}
	handler := manager.wrap(http.NotFoundHandler())
	req := httptest.NewRequest(http.MethodGet, "/login/forgot?lang=zh-CN", nil)
	req.RemoteAddr = "192.0.2.91:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("forgot-password page failed: status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "如果账号符合条件，找回验证码已发送") || !strings.Contains(body, "密码重置失败，请检查验证码后重试") {
		t.Fatalf("forgot-password page is missing localized status messages: %q", body)
	}
	if strings.Contains(body, "Password reset failed") || strings.Contains(body, "Request failed") {
		t.Fatal("forgot-password page leaked English fallback text in Chinese mode")
	}
	for _, want := range []string{
		`method="post" action="/auth/forgot-password/request?lang=zh-CN"`,
		`method="post" action="/auth/forgot-password/reset?lang=zh-CN" hidden`,
		`href="/login?lang=zh-CN"`,
		`src="/nodewall-mark.svg"`,
		`data-resend-seconds="30"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("forgot-password page missing %q", want)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "img-src 'self'") {
		t.Fatal("forgot-password page should serve its own logo without caching the page")
	}
}

func TestLoginLockoutAfterRepeatedFailures(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "auth.json")
	if err := security.EnsurePasswordFile(authFile, "correct-password"); err != nil {
		t.Fatalf("ensure password file: %v", err)
	}
	manager, err := newAuthManager(config.ServerConfig{
		AuthEnabled: true,
		AuthFile:    authFile,
	})
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}

	for i := 0; i < normalizeAuthSettings(models.AuthSecuritySettings{}).MaxFailures; i++ {
		captchaID, captchaAnswer := issueLoginCaptcha(t, manager)
		form := url.Values{
			"username":       {"admin"},
			"password":       {"wrong-password"},
			"captcha_id":     {captchaID},
			"captcha_answer": {captchaAnswer},
		}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.5.10:12345"
		rec := httptest.NewRecorder()
		manager.handleLogin(rec, req)
	}

	until, blocked := manager.loginLockedUntil("192.168.5.10")
	if !blocked {
		t.Fatal("expected source to be locked")
	}
	if time.Until(until) <= 0 {
		t.Fatal("expected positive lock duration")
	}

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"password": {"correct-password"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.5.10:12345"
	rec := httptest.NewRecorder()
	manager.handleLogin(rec, req)
	if rec.Code != http.StatusOK {
		// template write defaults to 200; redirect would be 303 if not blocked.
		if rec.Code == http.StatusSeeOther {
			t.Fatal("expected locked source to stay blocked")
		}
	}
	body := rec.Body.String()
	if !strings.Contains(body, "too many attempts") && !strings.Contains(body, "尝试次数过多") {
		t.Fatalf("expected lockout message, got %q", rec.Body.String())
	}
}

func TestLoginAccountLockoutCoversRotatingSources(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "auth.json")
	if err := security.EnsurePasswordFile(authFile, "correct-password"); err != nil {
		t.Fatalf("ensure password file: %v", err)
	}
	manager, err := newAuthManager(config.ServerConfig{AuthEnabled: true, AuthFile: authFile})
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}
	for i := 0; i < loginAccountMaxFailures; i++ {
		captchaID, captchaAnswer := issueLoginCaptcha(t, manager)
		form := url.Values{
			"username":       {"admin"},
			"password":       {"wrong-password"},
			"captcha_id":     {captchaID},
			"captcha_answer": {captchaAnswer},
		}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:12345", 10+i)
		rec := httptest.NewRecorder()
		manager.handleLogin(rec, req)
	}
	if _, blocked := manager.loginLockedUntil(loginAccountKey("admin")); !blocked {
		t.Fatal("expected account lock after failures from rotating sources")
	}
}

func TestLoginCaptchaIsOneTimeAndExpires(t *testing.T) {
	manager := &authManager{loginCaptchas: make(map[string]loginCaptchaState)}
	view, err := manager.newLoginCaptcha()
	if err != nil {
		t.Fatalf("create captcha: %v", err)
	}
	manager.mu.RLock()
	challenge := manager.loginCaptchas[view.ID]
	manager.mu.RUnlock()
	answer := challenge.Answer
	if challenge.Kind == "trace" {
		answer = encodeLoginTraceAnswer(challenge.TracePoints)
	}
	if answer == "" {
		t.Fatal("captcha answer was not stored")
	}
	if !manager.consumeLoginCaptcha(view.ID, answer) {
		t.Fatal("expected valid answer to pass")
	}
	if manager.consumeLoginCaptcha(view.ID, answer) {
		t.Fatal("captcha must not be reusable")
	}

	view, err = manager.newLoginCaptcha()
	if err != nil {
		t.Fatalf("create expiring captcha: %v", err)
	}
	manager.mu.Lock()
	challenge = manager.loginCaptchas[view.ID]
	challenge.ExpiresAt = time.Now().Add(-time.Second)
	manager.loginCaptchas[view.ID] = challenge
	manager.mu.Unlock()
	expiredAnswer := challenge.Answer
	if challenge.Kind == "trace" {
		expiredAnswer = encodeLoginTraceAnswer(challenge.TracePoints)
	}
	if manager.consumeLoginCaptcha(view.ID, expiredAnswer) {
		t.Fatal("expired captcha must fail")
	}
}

func TestLoginCaptchaRendersOneChallengeAndKeepsUsernameOnFailure(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "auth.json")
	if err := security.EnsurePasswordFile(authFile, "correct-password"); err != nil {
		t.Fatalf("ensure password file: %v", err)
	}
	manager, err := newAuthManager(config.ServerConfig{AuthEnabled: true, AuthFile: authFile})
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}

	captchaID, captchaAnswer := issueLoginCaptcha(t, manager)
	form := url.Values{
		"username":       {"admin"},
		"password":       {"wrong-password"},
		"captcha_id":     {captchaID},
		"captcha_answer": {captchaAnswer},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.5.10:12345"
	rec := httptest.NewRecorder()
	manager.handleLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected login page after invalid credentials, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `value="admin"`) {
		t.Fatal("username should remain populated after failed login")
	}
	if strings.Contains(body, "wrong-password") {
		t.Fatal("password must not be reflected into the server response")
	}
	if !strings.Contains(body, "账号或密码错误") {
		t.Fatal("expected invalid-credentials message")
	}
	if !strings.Contains(body, `id="login-challenge"`) || !strings.Contains(body, `id="captcha-answer"`) {
		t.Fatal("expected a fresh challenge in the retry form")
	}
	if !strings.Contains(body, `form.querySelector('#captcha-content').replaceWith(nextContent)`) {
		t.Fatal("retry flow should replace only the challenge and preserve the password in the live form")
	}
	if strings.Contains(body, `type="password" name="password" value=`) || strings.Contains(body, "form.reset()") {
		t.Fatal("retry response must not echo or clear the password")
	}
}

func TestLoginRequiresOTPWhenUserHasEnabledIt(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "auth.json")
	if err := security.EnsurePasswordFile(authFile, "correct-password"); err != nil {
		t.Fatalf("ensure password file: %v", err)
	}
	store, err := security.LoadUserStore(authFile)
	if err != nil {
		t.Fatalf("load user store: %v", err)
	}
	user, index := store.Find("admin")
	if user == nil {
		t.Fatal("bootstrap admin missing")
	}
	user.MFA.OTPSecret = "JBSWY3DPEHPK3PXP"
	user.MFA.OTPEnabled = true
	store.Users[index] = *user
	if err := security.SaveUserStore(authFile, store); err != nil {
		t.Fatalf("save user store: %v", err)
	}
	manager, err := newAuthManager(config.ServerConfig{AuthEnabled: true, AuthFile: authFile})
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}

	login := func() *httptest.ResponseRecorder {
		captchaID, captchaAnswer := issueLoginCaptcha(t, manager)
		form := url.Values{
			"username":       {"admin"},
			"password":       {"correct-password"},
			"captcha_id":     {captchaID},
			"captcha_answer": {captchaAnswer},
		}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.0.2.44:12345"
		rec := httptest.NewRecorder()
		manager.handleLogin(rec, req)
		return rec
	}

	challenge := login()
	if challenge.Code != http.StatusSeeOther || challenge.Header().Get("Location") != "/login/otp?lang=zh-CN" {
		t.Fatalf("password login should redirect to the separate OTP page: status=%d location=%q body=%q", challenge.Code, challenge.Header().Get("Location"), challenge.Body.String())
	}
	var challengeCookie *http.Cookie
	for _, cookie := range challenge.Result().Cookies() {
		if cookie.Name == loginOTPChallengeCookieName {
			challengeCookie = cookie
			break
		}
	}
	if challengeCookie == nil {
		t.Fatal("password login did not issue an OTP challenge cookie")
	}
	code, err := security.TOTPCode("JBSWY3DPEHPK3PXP", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	otpRequest := httptest.NewRequest(http.MethodPost, "/login/otp", strings.NewReader(url.Values{"otp_code": {code}, "locale": {"zh-CN"}}.Encode()))
	otpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	otpRequest.RemoteAddr = "192.0.2.44:12345"
	otpRequest.AddCookie(challengeCookie)
	accepted := httptest.NewRecorder()
	manager.handleLoginOTP(accepted, otpRequest)
	if accepted.Code != http.StatusSeeOther {
		t.Fatalf("valid OTP should create a session, got status=%d body=%q", accepted.Code, accepted.Body.String())
	}
}

func TestOTPSetupVerifyAndDisable(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "auth.json")
	if err := security.EnsurePasswordFile(authFile, "correct-password"); err != nil {
		t.Fatalf("ensure password file: %v", err)
	}
	manager, err := newAuthManager(config.ServerConfig{AuthEnabled: true, AuthFile: authFile})
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}
	manager.sessions["session-token"] = sessionState{Username: "admin", Role: security.RoleAdmin, ExpiresAt: time.Now().Add(time.Hour)}
	setupReq := httptest.NewRequest(http.MethodPost, "/account/otp/setup", strings.NewReader(`{"current_password":"correct-password"}`))
	setupReq.Header.Set("Content-Type", "application/json")
	setupReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	setupRec := httptest.NewRecorder()
	manager.handleOTPSetup(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("OTP setup failed: status=%d body=%s", setupRec.Code, setupRec.Body.String())
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(setupRec.Body.Bytes(), &setup); err != nil || setup.Secret == "" {
		t.Fatalf("setup did not return a secret: %v body=%s", err, setupRec.Body.String())
	}
	code, err := security.TOTPCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verifyReq := httptest.NewRequest(http.MethodPost, "/account/otp/verify", strings.NewReader(fmt.Sprintf(`{"code":"%s"}`, code)))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	verifyRec := httptest.NewRecorder()
	manager.handleOTPVerify(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("OTP verify failed: status=%d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	store, err := security.LoadUserStore(authFile)
	if err != nil || !store.Users[0].MFA.OTPEnabled {
		t.Fatalf("OTP was not persisted: err=%v", err)
	}

	disableCode, err := security.TOTPCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	disableReq := httptest.NewRequest(http.MethodPost, "/account/otp/disable", strings.NewReader(fmt.Sprintf(`{"current_password":"correct-password","code":"%s"}`, disableCode)))
	disableReq.Header.Set("Content-Type", "application/json")
	disableReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	disableRec := httptest.NewRecorder()
	manager.handleOTPDisable(disableRec, disableReq)
	if disableRec.Code != http.StatusOK {
		t.Fatalf("OTP disable failed: status=%d body=%s", disableRec.Code, disableRec.Body.String())
	}
	store, err = security.LoadUserStore(authFile)
	if err != nil || store.Users[0].MFA.OTPEnabled {
		t.Fatalf("OTP was not disabled: err=%v", err)
	}
}

func TestEmailVerificationAndPasswordReset(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "auth.json")
	smtpFile := filepath.Join(t.TempDir(), "smtp.json")
	if err := security.EnsurePasswordFile(authFile, "correct-password"); err != nil {
		t.Fatalf("ensure password file: %v", err)
	}
	store, err := security.LoadUserStore(authFile)
	if err != nil {
		t.Fatal(err)
	}
	user, index := store.Find("admin")
	user.Email = "old@example.com"
	user.EmailVerified = true
	store.Users[index] = *user
	if err := security.SaveUserStore(authFile, store); err != nil {
		t.Fatal(err)
	}
	manager, err := newAuthManager(config.ServerConfig{AuthEnabled: true, AuthFile: authFile, SMTPSettingsFile: smtpFile})
	if err != nil {
		t.Fatal(err)
	}
	manager.sessions["session-token"] = sessionState{Username: "admin", Role: security.RoleAdmin, ExpiresAt: time.Now().Add(time.Hour)}
	var sentBody string
	manager.mailSender = func(_ context.Context, _, _, body string) error {
		sentBody = body
		return nil
	}
	disabledRequest := httptest.NewRequest(http.MethodPost, "/account/email/request", strings.NewReader(`{"current_password":"correct-password","email":"new@example.com"}`))
	disabledRequest.Header.Set("Content-Type", "application/json")
	disabledRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	disabledResponse := httptest.NewRecorder()
	manager.handleEmailVerificationRequest(disabledResponse, disabledRequest)
	if disabledResponse.Code != http.StatusBadRequest || !strings.Contains(disabledResponse.Body.String(), "SMTP must be enabled") {
		t.Fatalf("email binding should require SMTP: status=%d body=%s", disabledResponse.Code, disabledResponse.Body.String())
	}
	if err := manager.updateSMTPSettings(models.SMTPSettings{Enabled: true, Host: "localhost", Port: 2525, Security: "plain", FromEmail: "nodewall@example.com"}); err != nil {
		t.Fatal(err)
	}

	requestBody := `{"current_password":"correct-password","email":"new@example.com"}`
	request := httptest.NewRequest(http.MethodPost, "/account/email/request", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.55:12345"
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	response := httptest.NewRecorder()
	manager.handleEmailVerificationRequest(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("email verification request failed: %d %s", response.Code, response.Body.String())
	}
	var verification struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &verification); err != nil || verification.RequestID == "" {
		t.Fatalf("missing verification request id: %s", response.Body.String())
	}
	code := regexp.MustCompile(`\b[0-9]{6}\b`).FindString(sentBody)
	if code == "" {
		t.Fatalf("verification code was not sent: %q", sentBody)
	}
	confirm := httptest.NewRequest(http.MethodPost, "/account/email/confirm", strings.NewReader(fmt.Sprintf(`{"request_id":"%s","code":"%s"}`, verification.RequestID, code)))
	confirm.Header.Set("Content-Type", "application/json")
	confirm.RemoteAddr = "192.0.2.55:12345"
	confirm.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	confirmResponse := httptest.NewRecorder()
	manager.handleEmailVerificationConfirm(confirmResponse, confirm)
	if confirmResponse.Code != http.StatusOK {
		t.Fatalf("email verification confirm failed: %d %s", confirmResponse.Code, confirmResponse.Body.String())
	}
	store, err = security.LoadUserStore(authFile)
	if err != nil || store.Users[0].Email != "new@example.com" || !store.Users[0].EmailVerified {
		t.Fatalf("email was not verified: err=%v users=%#v", err, store.Users)
	}

	forgot := httptest.NewRequest(http.MethodPost, "/auth/forgot-password/request", strings.NewReader(`{"username":"admin"}`))
	forgot.Header.Set("Content-Type", "application/json")
	forgot.RemoteAddr = "192.0.2.56:12345"
	forgotResponse := httptest.NewRecorder()
	manager.handleForgotPasswordRequest(forgotResponse, forgot)
	if forgotResponse.Code != http.StatusOK {
		t.Fatalf("forgot request failed: %d", forgotResponse.Code)
	}
	var reset struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(forgotResponse.Body.Bytes(), &reset); err != nil || reset.RequestID == "" {
		t.Fatalf("missing reset request id: %s", forgotResponse.Body.String())
	}
	resetCode := regexp.MustCompile(`\b[0-9]{6}\b`).FindString(sentBody)
	resetRequest := httptest.NewRequest(http.MethodPost, "/auth/forgot-password/reset", strings.NewReader(fmt.Sprintf(`{"request_id":"%s","code":"%s","new_password":"new-password-123"}`, reset.RequestID, resetCode)))
	resetRequest.Header.Set("Content-Type", "application/json")
	resetRequest.RemoteAddr = "192.0.2.56:12345"
	resetResponse := httptest.NewRecorder()
	manager.handleForgotPasswordReset(resetResponse, resetRequest)
	if resetResponse.Code != http.StatusOK {
		t.Fatalf("forgot reset failed: %d %s", resetResponse.Code, resetResponse.Body.String())
	}
	store, err = security.LoadUserStore(authFile)
	if err != nil || !security.VerifyPassword("new-password-123", store.Users[0].Password) {
		t.Fatalf("password reset was not persisted: err=%v", err)
	}
}

func TestLoginCaptchaChallengeKindsAndImageSafety(t *testing.T) {
	manager := &authManager{loginCaptchas: make(map[string]loginCaptchaState)}
	seen := make(map[string]bool)
	for i := 0; i < 90; i++ {
		view, err := manager.newLoginCaptcha()
		if err != nil {
			t.Fatalf("create captcha: %v", err)
		}
		if view.Kind != "math" && view.Kind != "letters" && view.Kind != "trace" {
			t.Fatalf("unexpected captcha type %q", view.Kind)
		}
		seen[view.Kind] = true
		if view.Kind == "trace" {
			picture := decodeCaptchaPNG(t, view.Image, loginTraceImageWidth, loginTraceImageHeight)
			if len(view.Sequence) != 5 {
				t.Fatalf("trace route should contain five labels, got %v", view.Sequence)
			}
			labels := make(map[int]bool, len(view.Sequence))
			for _, label := range view.Sequence {
				labels[label] = true
			}
			for label := 1; label <= 5; label++ {
				if !labels[label] {
					t.Fatalf("trace route is missing label %d: %v", label, view.Sequence)
				}
			}
			decoys := 0
			for _, point := range view.Points {
				if point.Decoy {
					decoys++
				}
				centerX := point.X * loginTraceImageWidth / 100
				centerY := point.Y * loginTraceImageHeight / 100
				numbered := false
				for y := centerY - 8; y <= centerY+8; y++ {
					for x := centerX - 8; x <= centerX+8; x++ {
						r, g, b, _ := picture.At(x, y).RGBA()
						numbered = numbered || min(r, g, b) >= 0xe000
					}
				}
				if numbered == point.Decoy {
					t.Fatalf("unexpected number rendering at trace point %+v", point)
				}
			}
			if decoys != 3 {
				t.Fatalf("expected 3 trace decoys, got %d", decoys)
			}
			manager.mu.RLock()
			challenge := manager.loginCaptchas[view.ID]
			manager.mu.RUnlock()
			if len(challenge.TracePoints) != 5 {
				t.Fatalf("expected five server-side coordinate targets, got %d", len(challenge.TracePoints))
			}
			want := make([]string, len(view.Sequence))
			for i, label := range view.Sequence {
				want[i] = fmt.Sprint(label)
			}
			if challenge.Answer != strings.Join(want, "-") {
				t.Fatalf("trace route %q does not match sequence %v", challenge.Answer, view.Sequence)
			}
			if !validateLoginTraceAnswer(encodeLoginTraceAnswer(challenge.TracePoints), challenge.TracePoints) {
				t.Fatal("exact image coordinates should pass server validation")
			}
		} else {
			decodeCaptchaPNG(t, view.Image, loginTextImageWidth, loginTextImageHeight)
		}
	}
	for _, kind := range []string{"math", "letters", "trace"} {
		if !seen[kind] {
			t.Fatalf("random captcha selection never produced %q", kind)
		}
	}
}

func TestLoginTraceCaptchaValidatesImageCoordinatesAndOrder(t *testing.T) {
	expected := []loginCaptchaPoint{
		{Step: 1, Label: 4, X: 20, Y: 30},
		{Step: 2, Label: 1, X: 45, Y: 42},
		{Step: 3, Label: 5, X: 68, Y: 55},
		{Step: 4, Label: 2, X: 77, Y: 30},
		{Step: 5, Label: 3, X: 38, Y: 72},
	}
	valid := encodeLoginTraceAnswer(expected)
	if !validateLoginTraceAnswer(valid, expected) {
		t.Fatal("expected image coordinates should pass")
	}
	if validateLoginTraceAnswer("45,42;20,30;68,55;77,30;38,72", expected) {
		t.Fatal("coordinates submitted in the wrong order must fail")
	}
	if validateLoginTraceAnswer("15,80;45,42;68,55;77,30;38,72", expected) {
		t.Fatal("a decoy or unrelated coordinate must fail")
	}
	if validateLoginTraceAnswer("20,30;45,42;68,55;77,30;101,72", expected) {
		t.Fatal("out-of-image coordinates must fail")
	}
	if validateLoginTraceAnswer("20,30;45,42", expected) {
		t.Fatal("incomplete coordinate sequences must fail")
	}
	if !validateLoginTraceAnswer("26,30;45,42;68,55;77,30;38,72", expected) {
		t.Fatal("clicks within the visible target radius should pass")
	}
}

func issueLoginCaptcha(t *testing.T, manager *authManager) (string, string) {
	t.Helper()
	view, err := manager.newLoginCaptcha()
	if err != nil {
		t.Fatalf("create login captcha: %v", err)
	}
	manager.mu.RLock()
	challenge, ok := manager.loginCaptchas[view.ID]
	manager.mu.RUnlock()
	if !ok {
		t.Fatal("new captcha missing from server state")
	}
	answer := challenge.Answer
	if challenge.Kind == "trace" {
		answer = encodeLoginTraceAnswer(challenge.TracePoints)
	}
	return view.ID, answer
}

func TestLoginGetIssuesNoStoreFormAndCaptcha(t *testing.T) {
	manager, err := newAuthManager(config.ServerConfig{AuthEnabled: true, AuthFile: filepath.Join(t.TempDir(), "auth.json")})
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	manager.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected login page, got %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login page must not be cached, got %q", rec.Header().Get("Cache-Control"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="captcha_id"`) || !strings.Contains(body, `Security check`) && !strings.Contains(body, `安全验证码`) {
		t.Fatal(fmt.Sprintf("login page is missing its captcha controls: %s", rec.Body.String()))
	}
	if strings.Contains(body, `class="card"`) {
		t.Fatal("login page should use the flat split layout instead of a card container")
	}
	if !strings.Contains(body, `src="/nodewall-mark.svg"`) {
		t.Fatal("login page should include the brand mark")
	}
	if strings.Contains(body, `id="trace-image"`) && !strings.Contains(body, `viewBox="0 0 320 150" preserveAspectRatio="xMidYMid meet"`) {
		t.Fatal("trace challenges must match the overlay and image aspect ratios")
	}
	if !strings.Contains(body, `data-expires-in="180"`) || strings.Contains(body, "验证码有效期") {
		t.Fatal("the three-minute challenge lifetime should be available to the controller without a visible expiry hint")
	}
	if rec.Header().Get("X-Robots-Tag") != "noindex, nofollow" || rec.Header().Get("Permissions-Policy") == "" {
		t.Fatal("login page is missing anti-indexing or permissions security headers")
	}
	if strings.Contains(body, `name="otp_code"`) {
		t.Fatal("the password login page must not embed the OTP field")
	}
	otpReq := httptest.NewRequest(http.MethodGet, "/login/otp?lang=zh-CN", nil)
	otpReq.RemoteAddr = "192.0.2.30:12345"
	otpRec := httptest.NewRecorder()
	manager.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(otpRec, otpReq)
	if otpRec.Code != http.StatusOK || !strings.Contains(otpRec.Body.String(), `id="login-otp-form"`) || !strings.Contains(otpRec.Body.String(), "辅助验证") {
		t.Fatalf("OTP verification page should be separate and localized: status=%d body=%q", otpRec.Code, otpRec.Body.String())
	}
}

func TestLoginPageHidesPasskeyUntilSystemSettingIsEnabled(t *testing.T) {
	manager := &authManager{enabled: true, loginCaptchas: make(map[string]loginCaptchaState)}
	handler := manager.wrap(http.NotFoundHandler())
	request := httptest.NewRequest(http.MethodGet, "/login?lang=zh-CN", nil)
	request.RemoteAddr = "192.0.2.32:12345"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("login page failed: %d", response.Code)
	}
	if strings.Contains(response.Body.String(), `id="passkey-login"`) {
		t.Fatal("Passkey login must remain hidden while the system setting is disabled")
	}

	manager.mu.Lock()
	manager.settings.PasskeyEnabled = true
	manager.mu.Unlock()
	request = httptest.NewRequest(http.MethodGet, "/login?lang=zh-CN", nil)
	request.RemoteAddr = "192.0.2.32:12345"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), `id="passkey-login"`) {
		t.Fatal("Passkey login should appear after the system setting is enabled")
	}
}

func TestLoginCaptchaIsBoundToSource(t *testing.T) {
	manager := &authManager{loginCaptchas: make(map[string]loginCaptchaState)}
	view, err := manager.newLoginCaptchaForSource("192.0.2.40")
	if err != nil {
		t.Fatalf("create source-bound captcha: %v", err)
	}
	manager.mu.RLock()
	challenge := manager.loginCaptchas[view.ID]
	manager.mu.RUnlock()
	answer := challenge.Answer
	if challenge.Kind == "trace" {
		answer = encodeLoginTraceAnswer(challenge.TracePoints)
	}
	if manager.consumeLoginCaptchaForSource(view.ID, answer, "192.0.2.41") {
		t.Fatal("captcha from another source must be rejected")
	}
	if !manager.consumeLoginCaptchaForSource(view.ID, answer, "192.0.2.40") {
		t.Fatal("captcha from its original source must remain usable")
	}
}

func TestLoginFailureResponseHasFreshChallengeID(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "auth.json")
	if err := security.EnsurePasswordFile(authFile, "correct-password"); err != nil {
		t.Fatalf("ensure password file: %v", err)
	}
	manager, err := newAuthManager(config.ServerConfig{AuthEnabled: true, AuthFile: authFile})
	if err != nil {
		t.Fatalf("new auth manager: %v", err)
	}
	oldID, answer := issueLoginCaptcha(t, manager)
	form := url.Values{"username": {"admin"}, "password": {"incorrect"}, "captcha_id": {oldID}, "captcha_answer": {answer}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	manager.handleLogin(rec, req)
	match := regexp.MustCompile(`id="login-captcha-id" value="([a-f0-9]+)"`).FindStringSubmatch(rec.Body.String())
	if len(match) != 2 || match[1] == oldID {
		t.Fatalf("failed login should issue a new captcha id, got %q", match)
	}
}
