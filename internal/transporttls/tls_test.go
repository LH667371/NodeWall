package transporttls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if tcpConfig.GetCertificate == nil {
		t.Fatal("TCP TLS config must reload certificates for new handshakes")
	}
	certificate, err := tcpConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || certificate == nil || len(certificate.Certificate) == 0 {
		t.Fatalf("load reloading TCP certificate: cert=%v err=%v", certificate, err)
	}
	otherCert := filepath.Join(dir, "other.crt")
	otherKey := filepath.Join(dir, "other.key")
	if err := EnsureCertificate(otherCert, otherKey, "other.example.test:8443"); err != nil {
		t.Fatal(err)
	}
	otherCertPEM, err := os.ReadFile(otherCert)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPEM, err := os.ReadFile(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, otherCertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, otherKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := tcpConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || reloaded == nil || bytes.Equal(certificate.Certificate[0], reloaded.Certificate[0]) {
		t.Fatalf("certificate callback did not reload replacement: cert=%v err=%v", reloaded, err)
	}

	quicConfig, err := QUICServerConfig(certFile, keyFile, "127.0.0.1:8444")
	if err != nil {
		t.Fatal(err)
	}
	if quicConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("QUIC TLS minimum version = %d, want TLS 1.3", quicConfig.MinVersion)
	}
}

func TestEnsureCertificateForAddressRotatesAfterIPChange(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "agent.crt")
	keyFile := filepath.Join(dir, "agent.key")
	if err := EnsureCertificate(certFile, keyFile, "192.0.2.10:9080"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}

	if err := EnsureCertificateForAddress(certFile, keyFile, "198.51.100.20:9080"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("certificate was not rotated after the advertised IP changed")
	}
	covered, err := certificateCoversAddress(certFile, keyFile, "198.51.100.20:9080")
	if err != nil {
		t.Fatal(err)
	}
	if !covered {
		t.Fatal("rotated certificate does not cover the new advertised IP")
	}

	unchanged, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureCertificateForAddress(certFile, keyFile, "198.51.100.20:9080"); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, current) {
		t.Fatal("certificate rotated again even though the advertised IP was unchanged")
	}
}

func TestClientConfigPinsLegacySelfSignedLeaf(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "legacy-nodewall"},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()

	config, err := ClientConfigFromPEM(certPEM, "", false)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("legacy self-signed leaf was not accepted by exact pinning: %v", err)
	}
	_ = response.Body.Close()
}
