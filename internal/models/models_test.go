package models

import (
	"testing"
	"time"
)

func TestNormalizeInterfacePolicyMigratesLegacyIngressFields(t *testing.T) {
	policy := InterfacePolicy{
		NodeID:        "node-01",
		Interface:     "ens3",
		Enabled:       true,
		Mode:          "whitelist",
		DefaultAction: "drop",
		NonIPv4Action: NonIPv4Drop,
		BypassCIDRs:   []string{"192.168.5.10/32"},
		BlockedCIDRs:  []string{"10.0.0.0/8"},
		PublicPorts:   []uint16{443},
		DeniedPorts:   []uint16{22},
		AllowedPorts:  []uint16{8443},
		Rules:         []ACLRule{{CIDR: "192.168.5.0/24", Action: "allow"}},
	}

	normalized := NormalizeInterfacePolicy(policy)

	if normalized.Ingress.Mode != "whitelist" {
		t.Fatalf("expected ingress mode to migrate, got %q", normalized.Ingress.Mode)
	}
	if normalized.Ingress.NonIPv4Action != NonIPv4Drop {
		t.Fatalf("expected ingress non-ipv4 action to migrate, got %q", normalized.Ingress.NonIPv4Action)
	}
	if len(normalized.Ingress.BypassCIDRs) != 1 || normalized.Ingress.BypassCIDRs[0] != "192.168.5.10/32" {
		t.Fatalf("expected ingress bypass cidrs to migrate, got %#v", normalized.Ingress.BypassCIDRs)
	}
	if len(normalized.Ingress.AllowedPorts) != 1 || normalized.Ingress.AllowedPorts[0] != 8443 {
		t.Fatalf("expected ingress allowed ports to migrate, got %#v", normalized.Ingress.AllowedPorts)
	}
	if normalized.Egress.Mode == "" {
		t.Fatal("expected default egress policy to be initialized")
	}
	if !normalized.Egress.ObserveOnly {
		t.Fatal("expected default egress policy to start in observe mode")
	}
}

func TestNormalizeInterfacePolicyKeepsPendingPublish(t *testing.T) {
	now := time.Now().UTC()
	policy := InterfacePolicy{
		NodeID:    "node-01",
		Interface: "ens3",
		PendingPublish: &PublishRecord{
			PublishID: "pub-1",
			Status:    PublishPendingConfirm,
			CreatedAt: now,
			ExpiresIn: 30,
		},
	}

	normalized := NormalizeInterfacePolicy(policy)
	if normalized.PendingPublish == nil || normalized.PendingPublish.PublishID != "pub-1" {
		t.Fatalf("expected top-level pending publish to be preserved, got %#v", normalized.PendingPublish)
	}
	if normalized.Ingress.PendingPublish == nil || normalized.Ingress.PendingPublish.PublishID != "pub-1" {
		t.Fatalf("expected ingress pending publish to be preserved, got %#v", normalized.Ingress.PendingPublish)
	}
}

func TestNormalizeInterfacePolicyDefaultsIPv6ToDropAndPreservesExplicitPass(t *testing.T) {
	defaults := NormalizeInterfacePolicy(InterfacePolicy{})
	if defaults.Ingress.NonIPv4Action != NonIPv4Drop || defaults.Egress.NonIPv4Action != NonIPv4Drop {
		t.Fatalf("expected IPv6 deny defaults, got ingress=%q egress=%q", defaults.Ingress.NonIPv4Action, defaults.Egress.NonIPv4Action)
	}

	explicit := NormalizeInterfacePolicy(InterfacePolicy{
		Ingress: DirectionPolicy{Mode: "whitelist", NonIPv4Action: NonIPv4Pass},
		Egress:  DirectionPolicy{Mode: "whitelist", NonIPv4Action: NonIPv4Pass},
	})
	if explicit.Ingress.NonIPv4Action != NonIPv4Pass || explicit.Egress.NonIPv4Action != NonIPv4Pass {
		t.Fatalf("expected explicit allow settings to be retained, got ingress=%q egress=%q", explicit.Ingress.NonIPv4Action, explicit.Egress.NonIPv4Action)
	}
}

func TestNormalizeInterfacePolicyMigratesLegacyRuleComments(t *testing.T) {
	policy := NormalizeInterfacePolicy(InterfacePolicy{
		Ingress: DirectionPolicy{
			Mode:  "whitelist",
			Rules: []ACLRule{{CIDR: "192.0.2.0/24", Action: "allow", Comment: "管理网段"}},
		},
	})
	if len(policy.Ingress.RuleDescriptions) != 1 {
		t.Fatalf("expected legacy comment to migrate, got %#v", policy.Ingress.RuleDescriptions)
	}
	got := policy.Ingress.RuleDescriptions[0]
	if got.Kind != "source" || got.Value != "192.0.2.0/24" || got.Description != "管理网段" {
		t.Fatalf("unexpected migrated description: %#v", got)
	}
}
