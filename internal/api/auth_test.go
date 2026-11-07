package api

import (
	"encoding/base64"
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
	if !manager.consumeLoginCaptcha(currentID, currentAnswer) {
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
	if !strings.Contains(body, `form.querySelector('#login-challenge').replaceWith(nextChallenge)`) {
		t.Fatal("retry flow should replace only the challenge and preserve the password in the live form")
	}
	if strings.Contains(body, `type="password" name="password" value=`) || strings.Contains(body, "form.reset()") {
		t.Fatal("retry response must not echo or clear the password")
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
			}
			if decoys != 3 {
				t.Fatalf("expected 3 trace decoys, got %d", decoys)
			}
			manager.mu.RLock()
			challenge := manager.loginCaptchas[view.ID]
			manager.mu.RUnlock()
			if !strings.HasPrefix(string(view.Image), "data:image/svg+xml;base64,") {
				t.Fatal("trace captcha should be rendered as an image")
			}
			encodedImage := strings.TrimPrefix(string(view.Image), "data:image/svg+xml;base64,")
			svg, err := base64.StdEncoding.DecodeString(encodedImage)
			if err != nil {
				t.Fatalf("decode trace captcha image: %v", err)
			}
			if strings.Count(string(svg), `class="target"`) != 5 || strings.Count(string(svg), `class="decoy"`) != 3 {
				t.Fatal("trace image must render five numbered targets and three decoys")
			}
			if strings.Count(string(svg), "<path") < 10 || strings.Count(string(svg), "<circle") < 40 {
				t.Fatal("trace image is missing interference lines or texture")
			}
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
		}
	}
	for _, kind := range []string{"math", "letters", "trace"} {
		if !seen[kind] {
			t.Fatalf("random captcha selection never produced %q", kind)
		}
	}

	imageURL, err := makeLoginCaptchaImage("A2BCD")
	if err != nil {
		t.Fatalf("render captcha image: %v", err)
	}
	if !strings.HasPrefix(string(imageURL), "data:image/svg+xml;base64,") {
		t.Fatalf("unexpected captcha image URI: %q", imageURL)
	}
	encoded := strings.TrimPrefix(string(imageURL), "data:image/svg+xml;base64,")
	svg, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode captcha image: %v", err)
	}
	if strings.Count(string(svg), "<path") < 10 || strings.Count(string(svg), "<circle") < 20 {
		t.Fatal("captcha image is missing visual interference")
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
	if !strings.Contains(rec.Body.String(), `name="captcha_id"`) || !strings.Contains(rec.Body.String(), `Human verification`) && !strings.Contains(rec.Body.String(), `人机验证`) {
		t.Fatal(fmt.Sprintf("login page is missing its captcha controls: %s", rec.Body.String()))
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
