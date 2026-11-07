package xdp

import (
	"testing"

	"nodewall/internal/models"
)

func TestCIDRToKey(t *testing.T) {
	key, normalized, err := CIDRToKey("10.1.2.3/24")
	if err != nil {
		t.Fatalf("CIDRToKey returned error: %v", err)
	}

	if normalized != "10.1.2.0/24" {
		t.Fatalf("unexpected normalized cidr: %s", normalized)
	}

	if key.PrefixLen != 24 {
		t.Fatalf("unexpected prefix len: %d", key.PrefixLen)
	}
}

func TestCIDRToKeyAcceptsSingleIPv4Address(t *testing.T) {
	key, normalized, err := CIDRToKey("192.168.1.10")
	if err != nil {
		t.Fatalf("CIDRToKey returned error: %v", err)
	}

	if normalized != "192.168.1.10/32" {
		t.Fatalf("unexpected normalized cidr: %s", normalized)
	}

	if key.PrefixLen != 32 {
		t.Fatalf("unexpected prefix len: %d", key.PrefixLen)
	}
	if key.Addr != 0x0a01a8c0 {
		t.Fatalf("unexpected key addr: %#x", key.Addr)
	}
}

func TestConfigConversion(t *testing.T) {
	value, err := configToValue(Config{
		NonIPv4Action:        models.NonIPv4Drop,
		PortPolicyEnabled:    true,
		PolicyEnforced:       true,
		EgressPolicyEnforced: true,
		ObserveOnly:          true,
	})
	if err != nil {
		t.Fatalf("configToValue returned error: %v", err)
	}

	got := configFromValue(value)
	if got.NonIPv4Action != models.NonIPv4Drop {
		t.Fatalf("unexpected action: %s", got.NonIPv4Action)
	}
	if !got.PortPolicyEnabled {
		t.Fatalf("expected port policy to be enabled")
	}
	if !got.PolicyEnforced {
		t.Fatalf("expected policy enforcement to be enabled")
	}
	if !got.EgressPolicyEnforced {
		t.Fatalf("expected egress policy enforcement to be enabled")
	}
	if !got.ObserveOnly {
		t.Fatalf("expected observe-only mode to round-trip")
	}
}

func TestSourceIPFromUint32UsesHostOrderForMapKeys(t *testing.T) {
	got := sourceIPFromUint32(0x7c05a8c0)
	if got != "192.168.5.124" {
		t.Fatalf("unexpected source ip: %s", got)
	}
}

func TestNormalizeRateLimitRules(t *testing.T) {
	rules, err := normalizeRateLimitRules([]models.RateLimitRule{
		{SourceIP: "203.0.113.7", Protocol: models.PortProtocolTCP, Port: 443, RequestsPerMinute: 60, Burst: 2},
		{SourceIP: "203.0.113.7", Protocol: models.PortProtocolTCP, Port: 443, RequestsPerMinute: 120, Burst: 4},
	})
	if err != nil {
		t.Fatalf("normalize rate limits: %v", err)
	}
	if len(rules) != 1 || rules[0].SourceIP != "203.0.113.7" {
		t.Fatalf("expected one canonical rule, got %#v", rules)
	}
}

func TestNormalizeRateLimitRulesRejectsUnsupportedValues(t *testing.T) {
	_, err := normalizeRateLimitRules([]models.RateLimitRule{{
		SourceIP:          "203.0.113.7",
		Protocol:          models.PortProtocolICMP,
		Port:              443,
		RequestsPerMinute: 60,
		Burst:             2,
	}})
	if err == nil {
		t.Fatal("expected ICMP rate limit to be rejected")
	}
}
