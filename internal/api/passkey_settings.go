package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nodewall/internal/models"
)

type passkeySettingsUpdate struct {
	Enabled        bool     `json:"enabled"`
	RPID           string   `json:"rp_id"`
	Origins        []string `json:"origins"`
	TLSMode        string   `json:"tls_mode"`
	CertificatePEM string   `json:"certificate_pem,omitempty"`
	PrivateKeyPEM  string   `json:"private_key_pem,omitempty"`
}

type passkeyCertificateStatus struct {
	Present     bool
	Valid       bool
	Error       string
	DNSNames    []string
	IPAddresses []string
	NotAfter    time.Time
}

func (a *authManager) passkeyEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.settings.PasskeyEnabled
}

func (a *authManager) passkeySettingsView() map[string]any {
	settings := a.authSettings()
	certificate := a.passkeyCertificateStatus()
	checkSettings := settings
	checkSettings.PasskeyEnabled = true
	ready := a.validatePasskeySettings(checkSettings, nil) == nil
	return map[string]any{
		"enabled":                   settings.PasskeyEnabled,
		"rp_id":                     settings.PasskeyRPID,
		"origins":                   append([]string(nil), settings.PasskeyOrigins...),
		"tls_mode":                  settings.PasskeyTLSMode,
		"tls_enabled":               a.tlsEnabled,
		"requirements_met":          ready,
		"certificate_present":       certificate.Present,
		"certificate_valid":         certificate.Valid,
		"certificate_error":         certificate.Error,
		"certificate_dns_names":     certificate.DNSNames,
		"certificate_ip_addresses":  certificate.IPAddresses,
		"certificate_ip_compatible": len(certificate.IPAddresses) > 0,
		"certificate_not_after":     certificate.NotAfter,
		"restart_required":          false,
	}
}

func (a *authManager) passkeyCertificateStatus() passkeyCertificateStatus {
	status := passkeyCertificateStatus{}
	certPath := strings.TrimSpace(a.tlsCertFile)
	keyPath := strings.TrimSpace(a.tlsKeyFile)
	if certPath == "" || keyPath == "" {
		status.Error = "TLS certificate and key paths are not configured"
		return status
	}
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		status.Error = "TLS certificate or key file is unavailable"
		return status
	}
	status.Present = true
	_, certificate, err := parseTLSMaterial(certPEM, keyPEM)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Valid = !certificate.NotBefore.After(time.Now()) && certificate.NotAfter.After(time.Now())
	status.DNSNames = append([]string(nil), certificate.DNSNames...)
	for _, address := range certificate.IPAddresses {
		status.IPAddresses = append(status.IPAddresses, address.String())
	}
	status.NotAfter = certificate.NotAfter
	if !status.Valid {
		status.Error = "TLS certificate is expired or not yet valid"
	}
	return status
}

func parseTLSMaterial(certPEM, keyPEM []byte) (tls.Certificate, *x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("TLS certificate and key do not match: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return tls.Certificate{}, nil, errors.New("TLS certificate is empty")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse TLS certificate: %w", err)
	}
	pair.Leaf = certificate
	return pair, certificate, nil
}

func (a *authManager) validatePasskeySettings(settings models.AuthSecuritySettings, candidate *x509.Certificate) error {
	if !settings.PasskeyEnabled {
		return nil
	}
	rpID := strings.TrimSpace(settings.PasskeyRPID)
	if rpID == "" {
		return errors.New("Passkey RP ID is required")
	}
	if net.ParseIP(rpID) != nil {
		return errors.New("Passkey RP ID must be a DNS host name, not an IP address")
	}
	rpID = strings.ToLower(strings.TrimSuffix(rpID, "."))
	if len(settings.PasskeyOrigins) == 0 {
		return errors.New("at least one HTTPS Passkey origin is required")
	}
	for _, rawOrigin := range settings.PasskeyOrigins {
		origin, err := url.Parse(strings.TrimRight(strings.TrimSpace(rawOrigin), "/"))
		if err != nil || !strings.EqualFold(origin.Scheme, "https") || origin.Hostname() == "" || (origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil {
			return fmt.Errorf("Passkey origin must be a valid HTTPS URL: %s", rawOrigin)
		}
		host := strings.ToLower(strings.TrimSuffix(origin.Hostname(), "."))
		if net.ParseIP(host) != nil {
			return errors.New("Passkey origin must use a DNS host name, not an IP address")
		}
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return fmt.Errorf("Passkey origin host %s is outside RP ID %s", host, rpID)
		}
	}

	if strings.ToLower(strings.TrimSpace(settings.PasskeyTLSMode)) == "proxy" {
		return nil
	}
	if !a.tlsEnabled {
		return errors.New("NodeWall HTTPS must be enabled for local Passkey TLS")
	}
	if candidate == nil {
		status := a.passkeyCertificateStatus()
		if !status.Valid {
			if status.Error == "" {
				return errors.New("a valid local TLS certificate is required for Passkey")
			}
			return fmt.Errorf("a valid local TLS certificate is required for Passkey: %s", status.Error)
		}
		certPEM, certErr := os.ReadFile(a.tlsCertFile)
		keyPEM, keyErr := os.ReadFile(a.tlsKeyFile)
		if certErr != nil || keyErr != nil {
			return errors.New("local TLS certificate and key files are required for Passkey")
		}
		_, candidate, certErr = parseTLSMaterial(certPEM, keyPEM)
		if certErr != nil {
			return certErr
		}
	}
	now := time.Now()
	if candidate.NotBefore.After(now) || !candidate.NotAfter.After(now) {
		return errors.New("TLS certificate is expired or not yet valid")
	}
	if err := candidate.VerifyHostname(rpID); err != nil {
		return fmt.Errorf("local TLS certificate does not contain RP ID %s: %w", rpID, err)
	}
	return nil
}

func writeTLSMaterial(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return errors.New("TLS certificate and key paths are not configured")
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	certTemp, err := os.CreateTemp(filepath.Dir(certPath), ".nodewall-cert-*")
	if err != nil {
		return err
	}
	certTempPath := certTemp.Name()
	defer os.Remove(certTempPath)
	if err := certTemp.Chmod(0o644); err != nil {
		_ = certTemp.Close()
		return err
	}
	if _, err := certTemp.Write(certPEM); err != nil {
		_ = certTemp.Close()
		return err
	}
	if err := certTemp.Close(); err != nil {
		return err
	}
	keyTemp, err := os.CreateTemp(filepath.Dir(keyPath), ".nodewall-key-*")
	if err != nil {
		return err
	}
	keyTempPath := keyTemp.Name()
	defer os.Remove(keyTempPath)
	if err := keyTemp.Chmod(0o600); err != nil {
		_ = keyTemp.Close()
		return err
	}
	if _, err := keyTemp.Write(keyPEM); err != nil {
		_ = keyTemp.Close()
		return err
	}
	if err := keyTemp.Close(); err != nil {
		return err
	}
	certBackup := certPath + ".nodewall-backup"
	keyBackup := keyPath + ".nodewall-backup"
	_ = os.Remove(certBackup)
	_ = os.Remove(keyBackup)
	certHadOld := false
	keyHadOld := false
	if _, err := os.Stat(certPath); err == nil {
		if err := os.Rename(certPath, certBackup); err != nil {
			return err
		}
		certHadOld = true
	}
	if _, err := os.Stat(keyPath); err == nil {
		if err := os.Rename(keyPath, keyBackup); err != nil {
			if certHadOld {
				_ = os.Rename(certBackup, certPath)
			}
			return err
		}
		keyHadOld = true
	}
	restore := func() {
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
		if certHadOld {
			_ = os.Rename(certBackup, certPath)
		}
		if keyHadOld {
			_ = os.Rename(keyBackup, keyPath)
		}
	}
	if err := os.Rename(certTempPath, certPath); err != nil {
		restore()
		return err
	}
	if err := os.Rename(keyTempPath, keyPath); err != nil {
		restore()
		return err
	}
	_ = os.Remove(certBackup)
	_ = os.Remove(keyBackup)
	return nil
}

func (a *authManager) updatePasskeySettings(request passkeySettingsUpdate) error {
	a.mu.RLock()
	settings := a.settings
	a.mu.RUnlock()
	settings.PasskeyEnabled = request.Enabled
	settings.PasskeyRPID = strings.TrimSpace(request.RPID)
	settings.PasskeyOrigins = append([]string(nil), request.Origins...)
	settings.PasskeyTLSMode = strings.TrimSpace(request.TLSMode)
	settings = normalizeAuthSettings(settings)

	var candidate *x509.Certificate
	if strings.TrimSpace(request.CertificatePEM) != "" || strings.TrimSpace(request.PrivateKeyPEM) != "" {
		if strings.EqualFold(settings.PasskeyTLSMode, "proxy") {
			return errors.New("certificate import is not used when TLS is terminated by an Ingress or reverse proxy")
		}
		var err error
		_, candidate, err = parseTLSMaterial([]byte(request.CertificatePEM), []byte(request.PrivateKeyPEM))
		if err != nil {
			return err
		}
		if !a.tlsEnabled {
			return errors.New("NodeWall HTTPS must be enabled before importing a local Passkey certificate")
		}
	}
	if err := a.validatePasskeySettings(settings, candidate); err != nil {
		return err
	}
	if candidate != nil {
		if err := writeTLSMaterial(a.tlsCertFile, a.tlsKeyFile, []byte(request.CertificatePEM), []byte(request.PrivateKeyPEM)); err != nil {
			return fmt.Errorf("install TLS certificate: %w", err)
		}
	}
	a.mu.Lock()
	previous := a.settings
	a.settings = settings
	if err := a.saveSettingsLocked(); err != nil {
		a.settings = previous
		a.mu.Unlock()
		return err
	}
	a.webauthnRPID = settings.PasskeyRPID
	a.webauthnOrigins = append([]string(nil), settings.PasskeyOrigins...)
	a.webauthnTLSMode = settings.PasskeyTLSMode
	a.mu.Unlock()
	return nil
}

func (a *authManager) handlePasskeySettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		writeJSON(w, 200, a.passkeySettingsView())
		return
	}
	var request passkeySettingsUpdate
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&request); err != nil {
		writeError(w, 400, err)
		return
	}
	if strings.TrimSpace(request.PrivateKeyPEM) != "" && !a.requestIsHTTPS(r) {
		writeError(w, http.StatusBadRequest, errors.New("private key import requires an HTTPS management connection"))
		return
	}
	if err := a.updatePasskeySettings(request); err != nil {
		writeError(w, 400, err)
		return
	}
	view := a.passkeySettingsView()
	view["restart_required"] = false
	writeJSON(w, 200, view)
}
