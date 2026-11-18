package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/securestore"
	"nodewall/internal/security"
)

const (
	emailCodeTTL           = 10 * time.Minute
	emailMaxAttempts       = 8
	emailChallengeLimit    = 8192
	emailChallengeCooldown = 30 * time.Second
	defaultSMTPSubject     = "NodeWall verification code"
)

type emailChallenge struct {
	Username  string
	Email     string
	CodeHash  string
	Purpose   string
	CreatedAt time.Time
	ExpiresAt time.Time
	Attempts  int
}

func defaultSMTPSettings() models.SMTPSettings {
	return models.SMTPSettings{
		Enabled:        false,
		Port:           587,
		Security:       "starttls",
		SubjectPrefix:  "[NodeWall]",
		ResetSubject:   "Password reset code",
		ResetTemplate:  "Hello {{.Username}},\\n\\nYour NodeWall password reset code is {{.Code}}. It expires in {{.ExpiresMinutes}} minutes.\\n\\nIf you did not request this, ignore this message.",
		VerifySubject:  "Email verification code",
		VerifyTemplate: "Hello {{.Username}},\\n\\nYour NodeWall email verification code is {{.Code}}. It expires in {{.ExpiresMinutes}} minutes.",
	}
}

func (a *authManager) loadSMTPSettings() error {
	a.smtpMu.Lock()
	defer a.smtpMu.Unlock()
	a.smtp = defaultSMTPSettings()
	if strings.TrimSpace(a.smtpFile) == "" {
		return nil
	}
	data, needsRewrite, recovered, err := securestore.ReadValid(a.smtpFile, validateSMTPPayload)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var settings models.SMTPSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}
	settings = normalizeSMTPSettings(settings)
	a.smtp = settings
	if needsRewrite || recovered {
		return a.saveSMTPSettingsLocked()
	}
	return nil
}

func (a *authManager) saveSMTPSettingsLocked() error {
	if strings.TrimSpace(a.smtpFile) == "" {
		return errors.New("SMTP settings file is not configured")
	}
	data, err := json.MarshalIndent(a.smtp, "", "  ")
	if err != nil {
		return err
	}
	return securestore.Write(a.smtpFile, data, 0o600)
}

func validateSMTPPayload(data []byte) error {
	var settings models.SMTPSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}
	_ = normalizeSMTPSettings(settings)
	return nil
}

func normalizeSMTPSettings(settings models.SMTPSettings) models.SMTPSettings {
	settings.Host = strings.TrimSpace(settings.Host)
	settings.Username = strings.TrimSpace(settings.Username)
	settings.FromEmail = strings.TrimSpace(settings.FromEmail)
	settings.FromName = strings.TrimSpace(settings.FromName)
	settings.Security = strings.ToLower(strings.TrimSpace(settings.Security))
	if settings.Security == "" {
		settings.Security = "starttls"
	}
	if settings.Port <= 0 {
		if settings.Security == "smtps" {
			settings.Port = 465
		} else {
			settings.Port = 587
		}
	}
	if strings.TrimSpace(settings.SubjectPrefix) == "" {
		settings.SubjectPrefix = "[NodeWall]"
	}
	if strings.TrimSpace(settings.ResetSubject) == "" {
		settings.ResetSubject = "Password reset code"
	}
	if strings.TrimSpace(settings.ResetTemplate) == "" {
		settings.ResetTemplate = defaultSMTPSettings().ResetTemplate
	}
	if strings.TrimSpace(settings.VerifySubject) == "" {
		settings.VerifySubject = "Email verification code"
	}
	if strings.TrimSpace(settings.VerifyTemplate) == "" {
		settings.VerifyTemplate = defaultSMTPSettings().VerifyTemplate
	}
	return settings
}

func validateSMTPSettings(settings models.SMTPSettings) error {
	settings = normalizeSMTPSettings(settings)
	if settings.Host == "" {
		return errors.New("SMTP host is required")
	}
	if settings.Port < 1 || settings.Port > 65535 {
		return errors.New("SMTP port is invalid")
	}
	if settings.Security != "starttls" && settings.Security != "smtps" && settings.Security != "plain" {
		return errors.New("SMTP security must be starttls, smtps, or plain")
	}
	if settings.FromEmail == "" {
		return errors.New("SMTP sender address is required")
	}
	if _, err := mail.ParseAddress(settings.FromEmail); err != nil {
		return fmt.Errorf("SMTP sender address is invalid: %w", err)
	}
	if settings.Security == "plain" && settings.Enabled && !strings.EqualFold(settings.Host, "localhost") && !strings.EqualFold(settings.Host, "127.0.0.1") {
		return errors.New("plain SMTP is only allowed for localhost")
	}
	return nil
}

func smtpSettingsView(settings models.SMTPSettings) map[string]any {
	return map[string]any{
		"enabled":         settings.Enabled,
		"host":            settings.Host,
		"port":            settings.Port,
		"security":        settings.Security,
		"username":        settings.Username,
		"from_email":      settings.FromEmail,
		"from_name":       settings.FromName,
		"subject_prefix":  settings.SubjectPrefix,
		"reset_subject":   settings.ResetSubject,
		"reset_template":  settings.ResetTemplate,
		"verify_subject":  settings.VerifySubject,
		"verify_template": settings.VerifyTemplate,
		"has_password":    strings.TrimSpace(settings.Password) != "",
	}
}

func (a *authManager) smtpSettingsView() map[string]any {
	a.smtpMu.RLock()
	defer a.smtpMu.RUnlock()
	return smtpSettingsView(a.smtp)
}

func (a *authManager) updateSMTPSettings(settings models.SMTPSettings) error {
	a.smtpMu.Lock()
	defer a.smtpMu.Unlock()
	if strings.TrimSpace(settings.Password) == "" {
		settings.Password = a.smtp.Password
	}
	settings = normalizeSMTPSettings(settings)
	if err := validateSMTPSettings(settings); err != nil {
		return err
	}
	previous := a.smtp
	a.smtp = settings
	if err := a.saveSMTPSettingsLocked(); err != nil {
		a.smtp = previous
		return err
	}
	return nil
}

func (a *authManager) smtpSettings() models.SMTPSettings {
	a.smtpMu.RLock()
	defer a.smtpMu.RUnlock()
	return a.smtp
}

func (a *authManager) sendMail(ctx context.Context, to, subject, body string) error {
	if a.mailSender == nil {
		return errors.New("SMTP mail sender is not configured")
	}
	return a.mailSender(ctx, to, subject, body)
}

func randomEmailCode() (string, error) {
	var bytes [4]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	return fmt.Sprintf("%06d", value%1000000), nil
}

func renderEmailTemplate(template, username, email, code string) string {
	value := strings.ReplaceAll(template, "{{.Username}}", username)
	value = strings.ReplaceAll(value, "{{.Email}}", email)
	value = strings.ReplaceAll(value, "{{.Code}}", code)
	value = strings.ReplaceAll(value, "{{.ExpiresMinutes}}", fmt.Sprintf("%d", int(emailCodeTTL/time.Minute)))
	value = strings.ReplaceAll(value, `\n`, "\n")
	return value
}

func (a *authManager) createEmailChallenge(username, email, purpose string) (string, string, error) {
	code, err := randomEmailCode()
	if err != nil {
		return "", "", err
	}
	requestID, err := randomToken()
	if err != nil {
		return "", "", err
	}
	a.emailMu.Lock()
	now := time.Now()
	if a.emailChallenges == nil {
		a.emailChallenges = make(map[string]emailChallenge)
	}
	for id, challenge := range a.emailChallenges {
		if !challenge.ExpiresAt.After(now) {
			delete(a.emailChallenges, id)
		}
	}
	for id, challenge := range a.emailChallenges {
		if strings.EqualFold(challenge.Username, username) && challenge.Purpose == purpose {
			if now.Sub(challenge.CreatedAt) < emailChallengeCooldown {
				a.emailMu.Unlock()
				return "", "", errors.New("email verification is temporarily limited")
			}
			delete(a.emailChallenges, id)
		}
	}
	for len(a.emailChallenges) >= emailChallengeLimit {
		oldestID := ""
		var oldest time.Time
		for id, challenge := range a.emailChallenges {
			if oldestID == "" || challenge.CreatedAt.Before(oldest) {
				oldestID, oldest = id, challenge.CreatedAt
			}
		}
		if oldestID == "" {
			break
		}
		delete(a.emailChallenges, oldestID)
	}
	a.emailChallenges[requestID] = emailChallenge{
		Username:  username,
		Email:     email,
		CodeHash:  security.HashRecoveryCode(code),
		Purpose:   purpose,
		CreatedAt: now,
		ExpiresAt: now.Add(emailCodeTTL),
	}
	a.emailMu.Unlock()
	return requestID, code, nil
}

func (a *authManager) consumeEmailChallenge(requestID, code, purpose string, expectedUsername ...string) (emailChallenge, bool) {
	a.emailMu.Lock()
	defer a.emailMu.Unlock()
	normalizedID := strings.TrimSpace(requestID)
	challenge, ok := a.emailChallenges[normalizedID]
	if !ok || challenge.Purpose != purpose || !challenge.ExpiresAt.After(time.Now()) || challenge.Attempts >= emailMaxAttempts {
		return emailChallenge{}, false
	}
	if len(expectedUsername) > 0 && !strings.EqualFold(challenge.Username, strings.TrimSpace(expectedUsername[0])) {
		return emailChallenge{}, false
	}
	challenge.Attempts++
	if subtle.ConstantTimeCompare([]byte(security.HashRecoveryCode(code)), []byte(challenge.CodeHash)) != 1 {
		a.emailChallenges[normalizedID] = challenge
		return emailChallenge{}, false
	}
	delete(a.emailChallenges, normalizedID)
	return challenge, true
}

func (a *authManager) deleteEmailChallenge(requestID string) {
	a.emailMu.Lock()
	delete(a.emailChallenges, requestID)
	a.emailMu.Unlock()
}

func (a *authManager) handleEmailVerificationRequest(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeError(w, http.StatusNotImplemented, errors.New("authentication is disabled"))
		return
	}
	if a.rejectLoginRate(w, r, "email-verify", 3) {
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		Email           string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	store, user, _, err := a.accountUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if !security.VerifyPassword(strings.TrimSpace(req.CurrentPassword), user.Password) {
		writeError(w, http.StatusUnauthorized, errors.New("current password is invalid"))
		return
	}
	settings := a.smtpSettings()
	if !settings.Enabled {
		writeError(w, http.StatusBadRequest, errors.New("SMTP must be enabled before binding an email address"))
		return
	}
	if err := validateSMTPSettings(settings); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("SMTP configuration invalid: %w", err))
		return
	}
	address := strings.TrimSpace(req.Email)
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Address != address {
		writeError(w, http.StatusBadRequest, errors.New("email address is invalid"))
		return
	}
	requestID, code, err := a.createEmailChallenge(user.Username, address, "email-verify")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	subject := strings.TrimSpace(settings.SubjectPrefix + " " + settings.VerifySubject)
	body := renderEmailTemplate(settings.VerifyTemplate, user.Username, address, code)
	if err := a.sendMail(r.Context(), address, subject, body); err != nil {
		a.deleteEmailChallenge(requestID)
		writeError(w, http.StatusBadGateway, err)
		return
	}
	_ = store
	writeJSON(w, http.StatusOK, map[string]any{"status": "sent", "request_id": requestID, "expires_in": int(emailCodeTTL / time.Second)})
}

func (a *authManager) handleEmailVerificationConfirm(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeError(w, http.StatusNotImplemented, errors.New("authentication is disabled"))
		return
	}
	if a.rejectLoginRate(w, r, "email-verify-confirm", 8) {
		return
	}
	var req struct {
		RequestID string `json:"request_id"`
		Code      string `json:"code"`
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
	challenge, ok := a.consumeEmailChallenge(req.RequestID, req.Code, "email-verify", user.Username)
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("email verification code is invalid or expired"))
		return
	}
	user.Email = challenge.Email
	user.EmailVerified = true
	store.Users[index] = *user
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "verified", "email": user.Email})
}

func (a *authManager) handleForgotPasswordRequest(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeJSON(w, http.StatusOK, map[string]any{"status": "accepted"})
		return
	}
	if a.rejectLoginRate(w, r, "forgot-password", 3) {
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	requestID, tokenErr := randomToken()
	if tokenErr != nil {
		writeError(w, http.StatusInternalServerError, tokenErr)
		return
	}
	store, err := security.LoadUserStore(a.authFile)
	if err == nil {
		user, _ := store.Find(strings.TrimSpace(req.Username))
		if user != nil && user.Enabled && user.EmailVerified && strings.TrimSpace(user.Email) != "" {
			challengeID, code, challengeErr := a.createEmailChallenge(user.Username, user.Email, "password-reset")
			if challengeErr == nil {
				settings := a.smtpSettings()
				subject := strings.TrimSpace(settings.SubjectPrefix + " " + settings.ResetSubject)
				body := renderEmailTemplate(settings.ResetTemplate, user.Username, user.Email, code)
				if sendErr := a.sendMail(r.Context(), user.Email, subject, body); sendErr != nil {
					a.deleteEmailChallenge(challengeID)
					log.Printf("password reset mail failed for %q: %v", user.Username, sendErr)
				} else {
					requestID = challengeID
				}
			}
		}
	}
	// The same response is returned for an unknown account, an unverified
	// email, and a failed SMTP delivery so the endpoint cannot enumerate users.
	writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "request_id": requestID, "expires_in": int(emailCodeTTL / time.Second)})
}

func (a *authManager) handleForgotPasswordReset(w http.ResponseWriter, r *http.Request) {
	if !a.enabled {
		writeError(w, http.StatusNotImplemented, errors.New("authentication is disabled"))
		return
	}
	if a.rejectLoginRate(w, r, "forgot-password-reset", 8) {
		return
	}
	var req struct {
		RequestID   string `json:"request_id"`
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(strings.TrimSpace(req.NewPassword)) < 8 {
		writeError(w, http.StatusBadRequest, errors.New("new password must be at least 8 characters"))
		return
	}
	challenge, ok := a.consumeEmailChallenge(req.RequestID, req.Code, "password-reset")
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("password reset code is invalid or expired"))
		return
	}
	store, err := security.LoadUserStore(a.authFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user, index := store.Find(challenge.Username)
	if user == nil || !user.Enabled || !user.EmailVerified || !strings.EqualFold(user.Email, challenge.Email) {
		writeError(w, http.StatusBadRequest, errors.New("password reset request is no longer valid"))
		return
	}
	record, err := security.NewPasswordRecord(strings.TrimSpace(req.NewPassword))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user.Password = record
	user.UpdatedAt = time.Now().UTC()
	store.Users[index] = *user
	if err := security.SaveUserStore(a.authFile, store); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.mu.Lock()
	for token, session := range a.sessions {
		if strings.EqualFold(session.Username, user.Username) {
			delete(a.sessions, token)
		}
	}
	delete(a.loginAttempts, loginAccountKey(user.Username))
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"status": "reset"})
}
