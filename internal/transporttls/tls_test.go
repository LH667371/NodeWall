package transporttls

import (
	"crypto/tls"
	"path/filepath"
	"testing"
)

func TestServerTLSVersionsKeepLegacyTCPAndQUICCompatible(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	tcpConfig, err := ServerConfig(certFile, keyFile, "127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}
	if tcpConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TCP TLS minimum version = %d, want TLS 1.2", tcpConfig.MinVersion)
	}

	quicConfig, err := QUICServerConfig(certFile, keyFile, "127.0.0.1:8444")
	if err != nil {
		t.Fatal(err)
	}
	if quicConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("QUIC TLS minimum version = %d, want TLS 1.3", quicConfig.MinVersion)
	}
}
