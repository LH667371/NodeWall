package service

import (
	"context"
	"testing"

	"nodewall/internal/models"
	"nodewall/internal/store"
)

func TestNodeCIDRsExcludeLoopbackAgentEndpoint(t *testing.T) {
	node := models.Node{
		AdvertiseIP:   "192.0.2.10",
		AgentHTTPAddr: "127.0.0.1:9080",
		AgentURL:      "https://127.0.0.1:9080",
	}

	got := nodeCIDRs(node)
	if len(got) != 1 || got[0] != "192.0.2.10/32" {
		t.Fatalf("unexpected node CIDRs: %#v", got)
	}
}

func TestWithClusterInterconnectStagesManagerControlPort(t *testing.T) {
	state := store.New()
	state.UpsertNode(context.Background(), models.Node{ID: "node-a", AdvertiseIP: "192.0.2.10"})
	service := NewPolicyService(state)
	service.SetControlPortRules([]models.PortRule{{Protocol: models.PortProtocolTCP, Port: 8082}})
	policy := service.WithClusterInterconnect(context.Background(), models.InterfacePolicy{
		NodeID: "node-a", Interface: "ens3", Enabled: true, Mode: "observe", DefaultAction: "pass",
		Ingress: models.DirectionPolicy{Enabled: true, Mode: "observe", DefaultAction: "pass", ObserveOnly: true},
		Egress:  models.DefaultDirectionPolicy(models.DirectionEgress),
	})
	ingress := models.DirectionPolicyFor(policy, models.DirectionIngress)
	if !containsPortRule(ingress.PublicPortRules, models.PortRule{Protocol: models.PortProtocolTCP, Port: 8082}) {
		t.Fatalf("manager control port missing from staged policy: %#v", ingress.PublicPortRules)
	}
}

func TestClusterInterconnectRemovesLegacyLoopbackRule(t *testing.T) {
	rules := ensureClusterInterconnectRules([]models.ACLRule{
		{CIDR: "127.0.0.1/32", Action: "allow"},
		{CIDR: "192.0.2.25/32", Action: "allow"},
	}, []models.Node{{AdvertiseIP: "192.0.2.10"}}, nil)

	for _, rule := range rules {
		if isLoopbackIPv4CIDR(rule.CIDR) {
			t.Fatalf("loopback rule leaked into physical interface policy: %#v", rules)
		}
	}
	if !containsAllowRule(rules, "192.0.2.10/32") {
		t.Fatalf("cluster node address missing from rules: %#v", rules)
	}
}

func containsAllowRule(rules []models.ACLRule, cidr string) bool {
	for _, rule := range rules {
		if rule.CIDR == cidr && (rule.Action == "" || rule.Action == "allow") {
			return true
		}
	}
	return false
}

func containsPortRule(rules []models.PortRule, target models.PortRule) bool {
	for _, rule := range rules {
		if rule == target {
			return true
		}
	}
	return false
}
