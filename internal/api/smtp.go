package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/service"
)

func (h *ServerHandler) smtpInterface(ctx context.Context) string {
	if iface := strings.TrimSpace(h.defaultInterface); iface != "" {
		return iface
	}
	if h.service != nil {
		if interfaces := h.service.ListPolicyInterfaces(ctx, h.nodeID); len(interfaces) > 0 {
			return interfaces[0]
		}
	}
	return ""
}

func smtpResolverAddresses() []netipAddr {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	result := make([]netipAddr, 0, 3)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil || ip.To4() == nil {
			continue
		}
		value := ip.To4().String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, netipAddr{value})
	}
	return result
}

// netipAddr avoids importing net/netip in this file's DNS parsing helper;
// conversion happens at the lease boundary where only IPv4 is supported by
// the current egress dataplane.
type netipAddr struct{ value string }

func netipFromIP(ip net.IP) netip.Addr {
	addr, _ := netip.ParseAddr(ip.String())
	return addr
}

func (h *ServerHandler) acquireSMTPLease(ctx context.Context, targets []service.EgressLeaseTarget, ttl time.Duration) (*service.EgressLease, error) {
	if h.service == nil || len(targets) == 0 {
		return &service.EgressLease{}, nil
	}
	iface := h.smtpInterface(ctx)
	if iface == "" {
		return &service.EgressLease{}, nil
	}
	lease, _, err := h.service.AcquireTemporaryEgressLease(ctx, h.nodeID, iface, targets, ttl)
	return lease, err
}

func (h *ServerHandler) sendSMTPMail(ctx context.Context, to, subject, body string) error {
	settings := h.auth.smtpSettings()
	if !settings.Enabled {
		return errors.New("SMTP is not enabled")
	}
	if err := validateSMTPSettings(settings); err != nil {
		return err
	}
	recipient, err := mail.ParseAddress(strings.TrimSpace(to))
	if err != nil || recipient.Address != strings.TrimSpace(to) {
		return errors.New("recipient email address is invalid")
	}
	if strings.ContainsAny(subject, "\r\n") {
		return errors.New("email subject contains invalid characters")
	}

	host := strings.TrimSpace(settings.Host)
	var resolved []net.IP
	if ip := net.ParseIP(host); ip != nil {
		resolved = []net.IP{ip}
	} else {
		resolverTargets := make([]service.EgressLeaseTarget, 0, 6)
		for _, resolver := range smtpResolverAddresses() {
			ip := net.ParseIP(resolver.value)
			if ip == nil {
				continue
			}
			resolverTargets = append(resolverTargets,
				service.EgressLeaseTarget{IP: netipFromIP(ip), Port: 53, Protocol: models.PortProtocolUDP},
				service.EgressLeaseTarget{IP: netipFromIP(ip), Port: 53, Protocol: models.PortProtocolTCP},
			)
		}
		dnsLease, leaseErr := h.acquireSMTPLease(ctx, resolverTargets, 30*time.Second)
		if leaseErr != nil {
			return fmt.Errorf("temporarily allow DNS for SMTP: %w", leaseErr)
		}
		resolved, err = net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if releaseErr := dnsLease.Release(); leaseErr == nil && releaseErr != nil {
			return fmt.Errorf("restore DNS egress policy: %w", releaseErr)
		}
		if err != nil {
			return fmt.Errorf("resolve SMTP host: %w", err)
		}
	}
	if len(resolved) == 0 {
		return errors.New("SMTP host has no IPv4 address")
	}

	targets := make([]service.EgressLeaseTarget, 0, len(resolved))
	for _, ip := range resolved {
		if ip.To4() == nil {
			continue
		}
		targets = append(targets, service.EgressLeaseTarget{IP: netipFromIP(ip), Port: uint16(settings.Port), Protocol: models.PortProtocolTCP})
	}
	lease, err := h.acquireSMTPLease(ctx, targets, 45*time.Second)
	if err != nil {
		return fmt.Errorf("temporarily allow SMTP egress: %w", err)
	}
	defer func() { _ = lease.Release() }()

	// Dial the address returned while the DNS lease is active. Dialing the
	// hostname again here would perform a second lookup after the temporary
	// DNS rule had already been restored, which fails on a default-deny egress
	// policy and could also select a different address than the one checked.
	dialer := &net.Dialer{Timeout: 12 * time.Second}
	var conn net.Conn
	var lastDialErr error
	for _, ip := range resolved {
		if ip.To4() == nil {
			continue
		}
		address := net.JoinHostPort(ip.To4().String(), strconv.Itoa(settings.Port))
		conn, lastDialErr = dialer.DialContext(ctx, "tcp", address)
		if lastDialErr == nil {
			break
		}
	}
	if conn == nil {
		if lastDialErr == nil {
			lastDialErr = errors.New("SMTP host has no IPv4 address")
		}
		return fmt.Errorf("connect to SMTP server: %w", lastDialErr)
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if settings.Security == "smtps" {
		// SMTPS uses implicit TLS before the SMTP greeting. STARTTLS is only
		// used for the explicit starttls mode below.
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return fmt.Errorf("SMTP TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("create SMTP client: %w", err)
	}
	defer client.Close()

	switch settings.Security {
	case "starttls":
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server does not support STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("SMTP STARTTLS failed: %w", err)
		}
	case "plain":
		// validateSMTPSettings restricts plain mode to localhost.
	default:
		return fmt.Errorf("unsupported SMTP security mode %q", settings.Security)
	}
	if settings.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", settings.Username, settings.Password, host)); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}
	from := settings.FromEmail
	if settings.FromName != "" {
		from = (&mail.Address{Name: settings.FromName, Address: settings.FromEmail}).String()
	}
	message := strings.Join([]string{
		"From: " + from,
		"To: " + recipient.String(),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")
	if err := client.Mail(settings.FromEmail); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA failed: %w", err)
	}
	if _, err := writer.Write([]byte(message)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	return client.Quit()
}
