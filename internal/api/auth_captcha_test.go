package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"nodewall/internal/config"
	"nodewall/internal/security"
)

func postCaptchaLogin(manager *authManager, source, id, answer, password string) *httptest.ResponseRecorder {
	form := url.Values{"username": {"admin"}, "password": {password}, "captcha_id": {id}, "captcha_answer": {answer}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = source + ":12345"
	w := httptest.NewRecorder()
	manager.handleLogin(w, r)
	return w
}

func TestCaptchaFailuresDoNotLockPasswordLogin(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "auth.json")
	if err := security.EnsurePasswordFile(authFile, "correct-password"); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"wrong-answer", "expired", "refreshed", "source-changed"} {
		t.Run(reason, func(t *testing.T) {
			manager, err := newAuthManager(config.ServerConfig{AuthEnabled: true, AuthFile: authFile})
			if err != nil {
				t.Fatal(err)
			}
			manager.settings.MaxFailures = 2
			const source = "192.0.2.45"
			for i := 0; i < 3; i++ {
				id, answer := issueLoginCaptcha(t, manager)
				state := manager.loginCaptchas[id]
				switch reason {
				case "wrong-answer":
					answer = "definitely-incorrect"
				case "expired":
					state.ExpiresAt = time.Now().Add(-time.Second)
					manager.loginCaptchas[id] = state
				case "refreshed":
					manager.discardLoginCaptcha(id)
				case "source-changed":
					state.Source = "192.0.2.46"
					manager.loginCaptchas[id] = state
				}
				w := postCaptchaLogin(manager, source, id, answer, "correct-password")
				if w.Code != http.StatusOK {
					t.Fatalf("captcha rejection status=%d", w.Code)
				}
			}
			if attempt := manager.loginAttempts[source]; attempt.Failures != 0 {
				t.Fatalf("captcha errors counted as password failures: %+v", attempt)
			}
			id, answer := issueLoginCaptcha(t, manager)
			if w := postCaptchaLogin(manager, source, id, answer, "correct-password"); w.Code != http.StatusSeeOther {
				t.Fatalf("fresh correct challenge must allow login: status=%d", w.Code)
			}
		})
	}
}

func TestCaptchaFailuresStillHaveRequestRateProtection(t *testing.T) {
	manager := &authManager{}
	for i := 0; i <= loginSubmitRateLimit; i++ {
		w := postCaptchaLogin(manager, "192.0.2.47", "stale-challenge", "0", "unused")
		if i == loginSubmitRateLimit && (w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "") {
			t.Fatalf("captcha requests must remain rate limited: status=%d headers=%v", w.Code, w.Header())
		}
	}
	if manager.loginAttempts["192.0.2.47"].Failures != 0 {
		t.Fatal("request throttling must stay separate from password lockout")
	}
}

func TestMathCaptchaAnswerMatchesPrompt(t *testing.T) {
	manager := &authManager{}
	math := regexp.MustCompile(`^(\d+)([+−])(\d+)=\?$`)
	seen := make(map[string]bool)
	for i, checked := 0, 0; i < 180 && (checked < 30 || len(seen) < 2); i++ {
		view, err := manager.newLoginCaptcha()
		if err != nil {
			t.Fatal(err)
		}
		if view.Kind != "math" {
			continue
		}
		parts := math.FindStringSubmatch(strings.Join(strings.Fields(view.Prompt), ""))
		if len(parts) != 4 {
			t.Fatalf("unreadable expression: %q", view.Prompt)
		}
		left, _ := strconv.Atoi(parts[1])
		right, _ := strconv.Atoi(parts[3])
		answer := left + right
		if parts[2] == "−" {
			answer = left - right
		}
		seen[parts[2]] = true
		if !manager.consumeLoginCaptcha(view.ID, fmt.Sprint(answer)) {
			t.Fatalf("expression %q rejected its correct answer %d", view.Prompt, answer)
		}
		checked++
	}
	if len(seen) != 2 {
		t.Fatal("both arithmetic operators must be exercised")
	}
}

func decodeCaptchaPNG(t *testing.T, url template.URL, width, height int) image.Image {
	t.Helper()
	encoded, ok := strings.CutPrefix(string(url), "data:image/png;base64,")
	if !ok {
		t.Fatal("captcha must be a raster PNG")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode captcha payload: %v", err)
	}
	picture, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode captcha PNG: %v", err)
	}
	if want := image.Rect(0, 0, width, height); picture.Bounds() != want {
		t.Fatalf("captcha bounds = %v, want %v", picture.Bounds(), want)
	}
	return picture
}

func TestMathCaptchaAcceptsNumericInputVariants(t *testing.T) {
	for _, answer := range []string{"3", "03", " 3 ", "３", "　０３　", "0"} {
		t.Run(answer, func(t *testing.T) {
			want := "3"
			if answer == "0" {
				want = "0"
			}
			manager := &authManager{loginCaptchas: map[string]loginCaptchaState{
				"math": {Kind: "math", Answer: want, ExpiresAt: time.Now().Add(time.Minute)},
			}}
			if !manager.consumeLoginCaptcha("math", answer) {
				t.Fatal("equivalent numeric answer rejected")
			}
		})
	}
}

func TestLoginLockoutIncludesRecoveryTime(t *testing.T) {
	manager := &authManager{loginAttempts: map[string]loginAttempt{
		"192.0.2.48": {LockedUntil: time.Now().Add(42 * time.Second)},
	}}
	w := postCaptchaLogin(manager, "192.0.2.48", "unused", "0", "unused")
	seconds, err := strconv.Atoi(w.Header().Get("Retry-After"))
	if err != nil || seconds < 41 || seconds > 42 {
		t.Fatalf("locked response must include remaining time: %q", w.Header().Get("Retry-After"))
	}
	if !strings.Contains(w.Body.String(), `data-retry-after="`) {
		t.Fatal("login form must expose its actual cooldown")
	}
	r := httptest.NewRequest(http.MethodPost, "/login/captcha/refresh", strings.NewReader("captcha_id=unused"))
	r.RemoteAddr = "192.0.2.48:12345"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	manager.handleLoginCaptchaRefresh(w, r)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "尝试次数过多") {
		t.Fatalf("locked refresh must explain its cooldown: %d %q", w.Code, w.Body.String())
	}
}

func TestLoginScriptMessagesAreSingleEscapedStrings(t *testing.T) {
	manager := &authManager{}
	r := httptest.NewRequest(http.MethodGet, "/login?lang=zh-CN", nil)
	w := httptest.NewRecorder()
	manager.serveLogin(w, r, "", "")
	match := regexp.MustCompile(`const loginNetworkFailed = ([^\n]+);`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("network error message missing from login script")
	}
	var message string
	if err := json.Unmarshal([]byte(match[1]), &message); err != nil {
		t.Fatal(err)
	}
	if message != loginMessages("zh-CN")["loginNetworkFailed"] {
		t.Fatalf("login script message is double escaped: %q", message)
	}
}
