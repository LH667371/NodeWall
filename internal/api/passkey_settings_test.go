package api

import (
	"path/filepath"
	"testing"

	"nodewall/internal/models"
	"nodewall/internal/transporttls"
)

func TestValidatePasskeySettingsAllowsIngressTerminationWithoutLocalCertificate(t *testing.T) {
	manager := &authManager{tlsEnabled: false}
	settings := models.AuthSecuritySettings{
		PasskeyEnabled: true,
		PasskeyRPID:    "nodewall.example.test",
		PasskeyOrigins: []string{"https://nodewall.example.test:443"},
		PasskeyTLSMode: "proxy",
	}
	if err := manager.validatePasskeySettings(settings, nil); err != nil {
		t.Fatalf("proxy-terminated Passkey settings should not require a local certificate: %v", err)
	}
}

func TestValidatePasskeySettingsRequiresCertificateForLocalTLS(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	if err := transporttls.EnsureCertificate(certFile, keyFile, "nodewall.example.test:8080"); err != nil {
		t.Fatal(err)
	}
	manager := &authManager{tlsEnabled: true, tlsCertFile: certFile, tlsKeyFile: keyFile}
	settings := models.AuthSecuritySettings{
		PasskeyEnabled: true,
		PasskeyRPID:    "nodewall.example.test",
		PasskeyOrigins: []string{"https://nodewall.example.test:8080"},
		PasskeyTLSMode: "local",
	}
	if err := manager.validatePasskeySettings(settings, nil); err != nil {
		t.Fatalf("generated certificate should satisfy local TLS settings: %v", err)
	}
}

func TestUpdatePasskeySettingsPersistsProxyConfiguration(t *testing.T) {
	t.Setenv("NODEWALL_CLUSTER_KEY_FILE", "")
	manager := &authManager{
		settingsFile: filepath.Join(t.TempDir(), "auth-settings.json"),
		settings:     normalizeAuthSettings(models.AuthSecuritySettings{}),
	}
	request := passkeySettingsUpdate{
		Enabled: true,
		RPID:    "nodewall.example.test",
		Origins: []string{"https://nodewall.example.test:443"},
		TLSMode: "proxy",
	}
	if err := manager.updatePasskeySettings(request); err != nil {
		t.Fatalf("update passkey settings: %v", err)
	}
	if !manager.passkeyEnabled() || manager.webauthnRPID != request.RPID || manager.webauthnTLSMode != "proxy" {
		t.Fatalf("passkey runtime state was not updated: enabled=%v rp=%q mode=%q", manager.passkeyEnabled(), manager.webauthnRPID, manager.webauthnTLSMode)
	}
	view := manager.passkeySettingsView()
	if view["requirements_met"] != true || view["tls_mode"] != "proxy" {
		t.Fatalf("unexpected Passkey settings view: %+v", view)
	}
}
