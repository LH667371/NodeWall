package api

import (
	"testing"

	"nodewall/internal/models"
)

func TestMergeCopiedDirectionPolicyDeduplicatesRules(t *testing.T) {
	target := models.DirectionPolicy{
		Rules:            []models.ACLRule{{CIDR: "192.0.2.0/24", Action: "allow"}},
		AllowedPortRules: []models.PortRule{{Protocol: models.PortProtocolTCP, Port: 443}},
		AllowedPorts:     []uint16{443},
		RuleDescriptions: []models.RuleDescription{{Kind: "port", Value: "443", Protocol: models.PortProtocolTCP, Description: "old"}},
	}
	source := models.DirectionPolicy{
		Rules:            []models.ACLRule{{CIDR: "192.0.2.0/24", Action: "allow"}, {CIDR: "198.51.100.0/24", Action: "allow"}},
		AllowedPortRules: []models.PortRule{{Protocol: models.PortProtocolTCP, Port: 443}, {Protocol: models.PortProtocolUDP, Port: 53}},
		RuleDescriptions: []models.RuleDescription{{Kind: "port", Value: "443", Protocol: models.PortProtocolTCP, Description: "copied"}},
	}
	merged := mergeCopiedDirectionPolicy(target, source)
	if len(merged.Rules) != 2 {
		t.Fatalf("expected duplicate CIDR to be removed, got %#v", merged.Rules)
	}
	if len(merged.AllowedPortRules) != 2 {
		t.Fatalf("expected duplicate port rule to be removed, got %#v", merged.AllowedPortRules)
	}
	if len(merged.AllowedPorts) != 2 || merged.AllowedPorts[0] != 443 || merged.AllowedPorts[1] != 53 {
		t.Fatalf("expected collapsed port list, got %#v", merged.AllowedPorts)
	}
	if len(merged.RuleDescriptions) != 1 || merged.RuleDescriptions[0].Description != "copied" {
		t.Fatalf("expected copied description to replace target description, got %#v", merged.RuleDescriptions)
	}
}
