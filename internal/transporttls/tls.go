// Package transporttls contains the small, shared TLS setup used by the web
// server, node agent, and HTTP/3 control channel.
package transporttls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EnsureCertificate creates a local self-signed certificate on first start.
// The private key stays on the host; only the certificate may be shared with
// operators who want strict client-side verification of the self-signed peer.
func EnsureCertificate(certFile, keyFile, listenAddr string) error {
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if certFile == "" || keyFile == "" {
		return errors.New("TLS certificate and key paths are required")
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(certFile+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if _, certErr := os.Stat(certFile); certErr == nil {
		if _, keyErr := os.Stat(keyFile); keyErr == nil {
			return nil
		}
	} else if !errors.Is(certErr, os.ErrNotExist) {
		return certErr
	}

	dir := filepath.Dir(certFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create TLS directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return fmt.Errorf("create TLS key directory: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return fmt.Errorf("generate TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return fmt.Errorf("generate TLS certificate serial: %w", err)
	}
	now := time.Now().UTC()
	hosts := certificateHosts(listenAddr)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "NodeWall self-signed",
			Organization: []string{"NodeWall"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              hosts.dns,
		IPAddresses:           hosts.ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create self-signed TLS certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := writePrivateFile(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("write TLS certificate: %w", err)
	}
	if err := writePrivateFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write TLS key: %w", err)
	}
	return nil
}

func ServerConfig(certFile, keyFile, listenAddr string) (*tls.Config, error) {
	// TCP HTTPS and gRPC keep TLS 1.2 available for legacy curl/NSS clients.
	// QUIC callers use QUICServerConfig, which enforces TLS 1.3 below.
	return serverConfig(certFile, keyFile, listenAddr, tls.VersionTLS12)
}

// QUICServerConfig keeps the HTTP/3 endpoints on TLS 1.3 as required by QUIC.
// The TCP HTTPS/gRPC listeners use ServerConfig so older curl/NSS clients can
// bootstrap over TLS 1.2 without weakening the certificate or public-key
// verification performed by the enrollment flow.
func QUICServerConfig(certFile, keyFile, listenAddr string) (*tls.Config, error) {
	return serverConfig(certFile, keyFile, listenAddr, tls.VersionTLS13)
}

func serverConfig(certFile, keyFile, listenAddr string, minVersion uint16) (*tls.Config, error) {
	if err := EnsureCertificate(certFile, keyFile, listenAddr); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   minVersion,
		Certificates: []tls.Certificate{certificate},
		// Keep all protocols used by NodeWall on the same certificate. HTTP/3
		// uses h3, the browser fallback uses HTTP/1.1, and the cluster
		// heartbeat/control channel uses gRPC over HTTP/2. Omitting h2 makes
		// the TLS handshake succeed only far enough to be closed by grpc-go,
		// leaving joined agents stuck in the offline state.
		NextProtos: []string{"h3", "h2", "http/1.1"},
	}, nil
}

// ClientConfig trusts a configured CA/certificate when supplied. During the
// first self-signed deployment there is no shared CA yet, so the compatibility
// default encrypts the channel while allowing the generated peer certificate.
// Set insecureSkipVerify=false and provide caFile for strict verification.
func ClientConfig(caFile, serverName string, insecureSkipVerify bool) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         strings.TrimSpace(serverName),
		InsecureSkipVerify: insecureSkipVerify, // explicitly configurable for self-signed bootstrap
		// The same client config is shared by browser/API HTTP, QUIC, and the
		// gRPC heartbeat. Advertising h2 is required for the latter; callers
		// using HTTP/3 still negotiate h3 as before.
		NextProtos: []string{"h3", "h2", "http/1.1"},
	}
	if strings.TrimSpace(caFile) == "" {
		return config, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("TLS CA file contains no certificates")
	}
	config.RootCAs = pool
	config.InsecureSkipVerify = false
	return config, nil
}

type hostSet struct {
	dns []string
	ips []net.IP
}

func certificateHosts(listenAddr string) hostSet {
	if u, err := url.Parse(listenAddr); err == nil && u.Host != "" {
		listenAddr = u.Host
	}
	host := ""
	if parsedHost, _, err := net.SplitHostPort(strings.TrimSpace(listenAddr)); err == nil {
		host = parsedHost
	}
	set := hostSet{dns: []string{"localhost"}}
	addHost := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || value == "0.0.0.0" || value == "::" {
			return
		}
		if ip := net.ParseIP(value); ip != nil {
			for _, existing := range set.ips {
				if existing.Equal(ip) {
					return
				}
			}
			set.ips = append(set.ips, ip)
			return
		}
		for _, existing := range set.dns {
			if strings.EqualFold(existing, value) {
				return
			}
		}
		set.dns = append(set.dns, value)
	}
	addHost(host)
	if hostname, err := os.Hostname(); err == nil {
		addHost(hostname)
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addresses, _ := iface.Addrs()
			for _, address := range addresses {
				if parsed, _, err := net.ParseCIDR(address.String()); err == nil {
					addHost(parsed.String())
				}
			}
		}
	}
	return set
}

func writePrivateFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodewall-tls-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
