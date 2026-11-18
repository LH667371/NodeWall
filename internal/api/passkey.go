package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"nodewall/internal/security"
)

const webauthnCookieName = "nodewall_webauthn"

type passkeyWebUser struct {
	record      *security.UserRecord
	credentials []webauthnlib.Credential
}

func (u *passkeyWebUser) WebAuthnID() []byte {
	sum := sha256.Sum256([]byte("nodewall-webauthn-user:" + strings.ToLower(strings.TrimSpace(u.record.Username))))
	return sum[:]
}

func (u *passkeyWebUser) WebAuthnName() string        { return u.record.Username }
func (u *passkeyWebUser) WebAuthnDisplayName() string { return u.record.Username }
func (u *passkeyWebUser) WebAuthnCredentials() []webauthnlib.Credential {
	return u.credentials
}

func (a *authManager) webAuthnForRequest(r *http.Request) (*webauthnlib.WebAuthn, error) {
	host := strings.TrimSpace(r.Host)
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}
	if host == "" {
		host = "localhost"
	}
	a.mu.RLock()
	rpID := strings.TrimSpace(a.webauthnRPID)
	origins := append([]string(nil), a.webauthnOrigins...)
	a.mu.RUnlock()
	if rpID == "" {
		rpID = host
	}
	if net.ParseIP(rpID) != nil {
		return nil, errors.New("Passkey requires a DNS host name and HTTPS; configure NODEWALL_WEBAUTHN_RP_ID before registering a credential")
	}
	if !a.requestIsHTTPS(r) {
		return nil, errors.New("Passkey requires an HTTPS origin; open NodeWall through HTTPS before registering a credential")
	}
	if len(origins) == 0 {
		scheme := "http"
		if a.requestIsHTTPS(r) {
			scheme = "https"
		}
		origins = []string{scheme + "://" + strings.TrimSpace(r.Host)}
	}
	return webauthnlib.New(&webauthnlib.Config{
		RPID:          rpID,
		RPDisplayName: "NodeWall",
		RPOrigins:     origins,
		Timeouts: webauthnlib.TimeoutsConfig{
			Login:        webauthnlib.TimeoutConfig{Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute, Enforce: true},
			Registration: webauthnlib.TimeoutConfig{Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute, Enforce: true},
		},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		},
	})
}

func (a *authManager) loadPasskeyUser(username string) (security.UserStore, *passkeyWebUser, int, error) {
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		return security.UserStore{}, nil, -1, err
	}
	record, index := store.Find(username)
	if record == nil || !record.Enabled {
		return security.UserStore{}, nil, -1, errors.New("user not found")
	}
	user := &passkeyWebUser{record: record}
	for _, item := range record.MFA.Passkeys {
		if strings.TrimSpace(item.CredentialJSON) == "" {
			continue
		}
		var credential webauthnlib.Credential
		if err := json.Unmarshal([]byte(item.CredentialJSON), &credential); err != nil {
			return security.UserStore{}, nil, -1, fmt.Errorf("load passkey %s: %w", item.ID, err)
		}
		user.credentials = append(user.credentials, credential)
	}
	return store, user, index, nil
}

func (a *authManager) savePasskey(store security.UserStore, user *passkeyWebUser, index int, credential webauthnlib.Credential, label string, update bool) error {
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if update {
		found := false
		for i := range user.record.MFA.Passkeys {
			if user.record.MFA.Passkeys[i].ID == credentialID {
				user.record.MFA.Passkeys[i].CredentialJSON = string(credentialJSON)
				user.record.MFA.Passkeys[i].LastUsedAt = &now
				found = true
				break
			}
		}
		if !found {
			return errors.New("passkey credential is not registered")
		}
	} else {
		for _, existing := range user.record.MFA.Passkeys {
			if existing.ID == credentialID {
				return errors.New("passkey credential is already registered")
			}
		}
		user.record.MFA.Passkeys = append(user.record.MFA.Passkeys, security.PasskeyCredential{
			ID:             credentialID,
			Name:           strings.TrimSpace(label),
			CredentialJSON: string(credentialJSON),
			CreatedAt:      now,
		})
	}
	store.Users[index] = *user.record
	return security.SaveUserStore(a.authFile, store)
}

func (a *authManager) setWebAuthnSession(w http.ResponseWriter, session webauthnSession) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	a.webauthnMu.Lock()
	if a.webauthnSessions == nil {
		a.webauthnSessions = make(map[string]webauthnSession)
	}
	a.webauthnSessions[token] = session
	a.webauthnMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: webauthnCookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.secureCookie, MaxAge: int(5 * time.Minute / time.Second)})
	return nil
}

func (a *authManager) takeWebAuthnSession(r *http.Request, purpose string) (webauthnSession, bool) {
	cookie, err := r.Cookie(webauthnCookieName)
	if err != nil {
		return webauthnSession{}, false
	}
	a.webauthnMu.Lock()
	defer a.webauthnMu.Unlock()
	session, ok := a.webauthnSessions[cookie.Value]
	if !ok || session.Purpose != purpose || !session.ExpiresAt.After(time.Now()) {
		delete(a.webauthnSessions, cookie.Value)
		return webauthnSession{}, false
	}
	if session.Source != "" && session.Source != loginSourceKey(r) {
		delete(a.webauthnSessions, cookie.Value)
		return webauthnSession{}, false
	}
	delete(a.webauthnSessions, cookie.Value)
	return session, true
}

func clearWebAuthnCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: webauthnCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure})
}

func (a *authManager) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeJSON(w, http.StatusOK, map[string]any{"passkeys": []any{}})
		return
	}
	session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	_, user, _, err := a.loadPasskeyUser(session.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	items := make([]map[string]any, 0, len(user.record.MFA.Passkeys))
	for _, item := range user.record.MFA.Passkeys {
		items = append(items, map[string]any{"id": item.ID, "name": item.Name, "created_at": item.CreatedAt, "last_used_at": item.LastUsedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": items})
}

func (a *authManager) handlePasskeyRegistrationOptions(w http.ResponseWriter, r *http.Request) {
	if !a.passkeyEnabled() {
		writeError(w, http.StatusBadRequest, errors.New("Passkey is disabled in system settings; configure an HTTPS DNS origin before enabling it"))
		return
	}
	session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	if a.rejectLoginRate(w, r, "passkey-register-options", 5) {
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		Name            string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	store, user, _, err := a.loadPasskeyUser(session.Username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if !security.VerifyPassword(strings.TrimSpace(req.CurrentPassword), user.record.Password) {
		writeError(w, http.StatusUnauthorized, errors.New("current password is invalid"))
		return
	}
	webAuthn, err := a.webAuthnForRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	creation, data, err := webAuthn.BeginRegistration(user,
		webauthnlib.WithExclusions(webauthnlib.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.setWebAuthnSession(w, webauthnSession{Data: *data, Username: user.record.Username, Purpose: "register", Source: loginSourceKey(r), ExpiresAt: time.Now().Add(5 * time.Minute), Label: strings.TrimSpace(req.Name)}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = store
	writeJSON(w, http.StatusOK, creation)
}

func (a *authManager) handlePasskeyRegistrationVerify(w http.ResponseWriter, r *http.Request) {
	if a.rejectLoginRate(w, r, "passkey-register-verify", 8) {
		return
	}
	ceremony, ok := a.takeWebAuthnSession(r, "register")
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("passkey registration session is missing or expired"))
		return
	}
	clearWebAuthnCookie(w, a.secureCookie)
	store, user, index, err := a.loadPasskeyUser(ceremony.Username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	webAuthn, err := a.webAuthnForRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	credential, err := webAuthn.FinishRegistration(user, ceremony.Data, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.savePasskey(store, user, index, *credential, ceremony.Label, false); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "registered", "id": base64.RawURLEncoding.EncodeToString(credential.ID)})
}

func (a *authManager) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	if a.rejectLoginRate(w, r, "passkey-delete", 5) {
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	store, user, index, err := a.loadPasskeyUser(session.Username)
	if err != nil || !security.VerifyPassword(strings.TrimSpace(req.CurrentPassword), user.record.Password) {
		writeError(w, http.StatusUnauthorized, errors.New("current password is invalid"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	remaining := make([]security.PasskeyCredential, 0, len(user.record.MFA.Passkeys))
	removed := false
	for _, item := range user.record.MFA.Passkeys {
		if item.ID == id {
			removed = true
			continue
		}
		remaining = append(remaining, item)
	}
	if !removed {
		writeError(w, http.StatusNotFound, errors.New("passkey not found"))
		return
	}
	user.record.MFA.Passkeys = remaining
	store.Users[index] = *user.record
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (a *authManager) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeError(w, http.StatusNotImplemented, errors.New("authentication is disabled"))
		return
	}
	if !a.passkeyEnabled() {
		writeError(w, http.StatusBadRequest, errors.New("Passkey is disabled in system settings; configure an HTTPS DNS origin before enabling it"))
		return
	}
	if a.rejectLoginRate(w, r, "passkey-login-options", 8) {
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	_, user, _, err := a.loadPasskeyUser(strings.TrimSpace(req.Username))
	if err != nil || len(user.credentials) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("passkey login is unavailable for this account"))
		return
	}
	webAuthn, err := a.webAuthnForRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	assertion, data, err := webAuthn.BeginLogin(user)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.setWebAuthnSession(w, webauthnSession{Data: *data, Username: user.record.Username, Purpose: "login", Source: loginSourceKey(r), ExpiresAt: time.Now().Add(5 * time.Minute)}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (a *authManager) handlePasskeyLoginVerify(w http.ResponseWriter, r *http.Request) {
	if a.rejectLoginRate(w, r, "passkey-login-verify", 8) {
		return
	}
	ceremony, ok := a.takeWebAuthnSession(r, "login")
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("passkey login session is missing or expired"))
		return
	}
	if _, locked := a.loginLockedUntil(loginAccountKey(ceremony.Username)); locked {
		writeError(w, http.StatusUnauthorized, errors.New("passkey login is temporarily locked"))
		return
	}
	clearWebAuthnCookie(w, a.secureCookie)
	store, user, index, err := a.loadPasskeyUser(ceremony.Username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	webAuthn, err := a.webAuthnForRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	credential, err := webAuthn.FinishLogin(user, ceremony.Data, r)
	if err != nil {
		a.recordLoginFailure(loginSourceKey(r))
		a.recordLoginFailureWithLimit(loginAccountKey(ceremony.Username), loginAccountMaxFailures)
		// Do not return library details to an unauthenticated caller; they can
		// reveal ceremony state and are not actionable without server logs.
		writeError(w, http.StatusUnauthorized, errors.New("passkey assertion was rejected"))
		return
	}
	if err := a.savePasskey(store, user, index, *credential, "", true); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.issueSession(w, user.record.Username, user.record.Role); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.mu.Lock()
	delete(a.loginAttempts, loginSourceKey(r))
	delete(a.loginAttempts, loginAccountKey(user.record.Username))
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"status": "authenticated", "username": user.record.Username})
}
