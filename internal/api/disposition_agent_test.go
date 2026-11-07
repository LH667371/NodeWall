package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
)

func TestExtractIPv4Candidate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain ipv4", input: "192.168.0.1", want: "192.168.0.1"},
		{name: "ip with iface suffix", input: "192.168.0.1ens3", want: "192.168.0.1"},
		{name: "ip in noise", input: "src=10.0.0.8 dev=eth0", want: "10.0.0.8"},
		{name: "invalid", input: "ens3", want: "ens3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractIPv4Candidate(tt.input); got != tt.want {
				t.Fatalf("extractIPv4Candidate(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPolicyAfterLogActionReplacesExactConflictingRules(t *testing.T) {
	base := models.InterfacePolicy{
		Ingress: models.DirectionPolicy{
			Rules:        []models.ACLRule{{CIDR: "192.168.5.125/32", Action: "allow"}, {CIDR: "10.0.0.0/8", Action: "allow"}},
			BypassCIDRs:  []string{"192.168.5.125", "198.51.100.0/24"},
			BlockedCIDRs: []string{"192.168.5.125/32", "203.0.113.0/24"},
		},
	}

	blocked := models.DirectionPolicyFor(policyAfterLogAction(base, models.DirectionIngress, "192.168.5.125/32", "block", ""), models.DirectionIngress)
	if containsCIDR(blocked.BypassCIDRs, "192.168.5.125") || containsCIDR(extractCIDRs(blocked.Rules), "192.168.5.125") {
		t.Fatalf("block action kept an exact allow rule: %#v", blocked)
	}
	if !containsCIDR(blocked.BlockedCIDRs, "192.168.5.125") {
		t.Fatalf("block action did not add source: %#v", blocked.BlockedCIDRs)
	}

	allowed := models.DirectionPolicyFor(policyAfterLogAction(blockedPolicy(base), models.DirectionIngress, "192.168.5.125", "allow", "allowlist"), models.DirectionIngress)
	if containsCIDR(allowed.BlockedCIDRs, "192.168.5.125") || !containsCIDR(extractCIDRs(allowed.Rules), "192.168.5.125") {
		t.Fatalf("allow action did not replace exact block: %#v", allowed)
	}

	limited := models.DirectionPolicyFor(policyAfterLogAction(base, models.DirectionIngress, "192.168.5.125", "rate-limit", ""), models.DirectionIngress)
	if containsCIDR(limited.BypassCIDRs, "192.168.5.125") || containsCIDR(extractCIDRs(limited.Rules), "192.168.5.125") || containsCIDR(limited.BlockedCIDRs, "192.168.5.125") {
		t.Fatalf("rate-limit action kept an exact source policy: %#v", limited)
	}
}

func blockedPolicy(policy models.InterfacePolicy) models.InterfacePolicy {
	selected := models.DirectionPolicyFor(policy, models.DirectionIngress)
	selected.Rules = nil
	selected.BypassCIDRs = nil
	selected.BlockedCIDRs = []string{"192.168.5.125/32"}
	return models.WithDirectionPolicy(policy, models.DirectionIngress, selected)
}

func TestSameCIDRNormalizesSingleIP(t *testing.T) {
	if !sameCIDR("192.168.5.125", "192.168.5.125/32") {
		t.Fatal("expected single IP and /32 to be treated as the same rule")
	}
	if sameCIDR("192.168.5.125/32", "192.168.5.126/32") {
		t.Fatal("did not expect different IPs to match")
	}
}

func TestLogTemporaryBlockOnDetectedSSHPortRequiresConfirmation(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/system/ssh" {
			writeJSON(w, http.StatusOK, map[string]any{"service": "sshd", "ports": []uint16{2202}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	}))
	defer agent.Close()

	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", AgentURL: agent.URL})
	handler := &ServerHandler{
		service:     service.NewPolicyService(st),
		store:       st,
		reverseHTTP: &http.Client{Timeout: time.Second},
		auth:        &authManager{enabled: true},
	}
	req := httptest.NewRequest(http.MethodPost, "/logs/actions/temp-block", nil)
	rec := httptest.NewRecorder()

	_, applied := handler.applyLogPolicyAction(rec, req, "node-a", "ens3", models.DirectionIngress, 2202, "198.51.100.8/32", "temp-block", "", "")
	if applied {
		t.Fatal("temporary block on the detected SSH port applied without confirmation")
	}
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "SSH_CONFIRM_REQUIRED") {
		t.Fatalf("expected SSH confirmation response, got %d: %s", rec.Code, rec.Body.String())
	}
}
