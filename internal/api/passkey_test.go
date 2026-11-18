package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"nodewall/internal/security"
)

func TestWebAuthnForRequestRejectsIPAddress(t *testing.T) {
	manager := &authManager{}
	request := httptest.NewRequest(http.MethodPost, "https://192.168.5.126:8080/account/passkeys/register/options", nil)
	request.Host = "192.168.5.126:8080"
	request.Header.Set("X-Forwarded-Proto", "https")
	if _, err := manager.webAuthnForRequest(request); err == nil || !strings.Contains(strings.ToLower(err.Error()), "dns host") {
		t.Fatalf("expected DNS host validation error, got %v", err)
	}
}

func TestWebAuthnForRequestRequiresHTTPS(t *testing.T) {
	manager := &authManager{webauthnRPID: "nodewall.example.test"}
	request := httptest.NewRequest(http.MethodPost, "http://nodewall.example.test:8080/account/passkeys/register/options", nil)
	request.Host = "nodewall.example.test:8080"
	if _, err := manager.webAuthnForRequest(request); err == nil || !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Fatalf("expected HTTPS validation error, got %v", err)
	}
}

func TestWebAuthnForRequestAcceptsDNSHostOverHTTPS(t *testing.T) {
	manager := &authManager{trustProxyHeaders: true}
	request := httptest.NewRequest(http.MethodPost, "https://nodewall.example.test:8080/account/passkeys/register/options", nil)
	request.Host = "nodewall.example.test:8080"
	request.Header.Set("X-Forwarded-Proto", "https")
	if _, err := manager.webAuthnForRequest(request); err != nil {
		t.Fatalf("expected DNS HTTPS request to be accepted, got %v", err)
	}
}

func TestWebAuthnForRequestRejectsForgedForwardedProtoByDefault(t *testing.T) {
	manager := &authManager{webauthnRPID: "nodewall.example.test"}
	request := httptest.NewRequest(http.MethodPost, "http://nodewall.example.test:8080/account/passkeys/register/options", nil)
	request.Host = "nodewall.example.test:8080"
	request.Header.Set("X-Forwarded-Proto", "https")
	if _, err := manager.webAuthnForRequest(request); err == nil || !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Fatalf("expected forged forwarded scheme to be rejected, got %v", err)
	}
}

func TestSavePasskeyAppendsDistinctCredentials(t *testing.T) {
	t.Setenv("NODEWALL_CLUSTER_KEY_FILE", "")
	manager := &authManager{authFile: filepath.Join(t.TempDir(), "users.json")}
	store := security.UserStore{Users: []security.UserRecord{{Username: "admin", Enabled: true}}}
	user := &passkeyWebUser{record: &store.Users[0]}
	first := webauthnlib.Credential{ID: []byte("first"), PublicKey: []byte("public-key-1")}
	second := webauthnlib.Credential{ID: []byte("second"), PublicKey: []byte("public-key-2")}
	if err := manager.savePasskey(store, user, 0, first, "laptop", false); err != nil {
		t.Fatalf("save first passkey: %v", err)
	}
	store.Users[0] = *user.record
	if err := manager.savePasskey(store, user, 0, second, "security key", false); err != nil {
		t.Fatalf("save second passkey: %v", err)
	}
	if got := len(user.record.MFA.Passkeys); got != 2 {
		t.Fatalf("expected two passkeys, got %d", got)
	}
	if user.record.MFA.Passkeys[0].Name != "laptop" || user.record.MFA.Passkeys[1].Name != "security key" {
		t.Fatalf("passkey labels were not preserved: %+v", user.record.MFA.Passkeys)
	}
	if err := manager.savePasskey(store, user, 0, first, "duplicate", false); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate passkey rejection, got %v", err)
	}
}
