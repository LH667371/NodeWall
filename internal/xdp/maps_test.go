package xdp

import (
	"encoding/binary"
	"testing"

	"nodewall/internal/models"
)

func TestDropMapAuditCompatibility(t *testing.T) {
	if binary.Size(dropLogKey{}) != 8 || binary.Size(dropLogValue{}) != 16 {
		t.Fatal("drop-log map ABI changed")
	}
	for _, direction := range []models.PolicyDirection{models.DirectionIngress, models.DirectionEgress} {
		for _, observed := range []uint8{0, 1} {
			entry := interceptLogFromMap(dropLogKey{SourceIP: 0x010200c0, DestPort: 67, Reason: dropReasonDHCPBroadcast, Reserved: observed}, dropLogValue{Drops: 3}, direction)
			wantDrops := uint64(3)
			if observed == 1 {
				wantDrops = 0
			}
			if entry.Count != 3 || entry.Drops != wantDrops || entry.Direction != direction || entry.Reason != "dhcp_broadcast" || entry.SourceIP != "192.0.2.1" {
				t.Fatalf("incorrect map audit conversion: %+v", entry)
			}
		}
	}
}

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
		NonIPv4Action:           models.NonIPv4Drop,
		PortPolicyEnabled:       true,
		PolicyEnforced:          true,
		EgressPolicyEnforced:    true,
		ObserveOnly:             true,
		EgressObserveOnly:       true,
		EgressNonIPv4Action:     models.NonIPv4Drop,
		EgressPortPolicyEnabled: true,
		EgressRateLimitEnabled:  true,
		EgressDefaultDeny:       true,
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
	if !got.EgressObserveOnly || got.EgressNonIPv4Action != models.NonIPv4Drop ||
		!got.EgressPortPolicyEnabled || !got.EgressRateLimitEnabled || !got.EgressDefaultDeny {
		t.Fatalf("expected egress config flags to round-trip: %#v", got)
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
