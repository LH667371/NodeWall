package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/store"
)

type PolicyService struct {
	applyLocks       sync.Map
	store            *store.Store
	httpClient       *http.Client
	controlPortRules []models.PortRule
}

func NewPolicyService(store *store.Store) *PolicyService {
	return &PolicyService{
		store:      store,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// SetHTTPClient lets the server wire the same transport used by its reverse
// proxy into policy mutations. Agent URLs can use the self-signed TLS
// certificate configured for the control plane, so a plain http.Client is not
// sufficient for attach/apply/temporary-block operations.
func (s *PolicyService) SetHTTPClient(client *http.Client) {
	if client == nil {
		return
	}
	s.httpClient = client
}

// SetControlPortRules configures the manager ports that must remain reachable
// whenever a policy is edited. Keeping this in the service covers UI edits,
// reconciliation, and automatic baseline updates through one path.
func (s *PolicyService) SetControlPortRules(rules []models.PortRule) {
	s.controlPortRules = append([]models.PortRule(nil), rules...)
}

func (s *PolicyService) ListNodes(ctx context.Context) []models.Node {
	return s.store.ListNodes(ctx)
}

func (s *PolicyService) ListPolicyInterfaces(ctx context.Context, nodeID string) []string {
	return s.store.ListPolicyInterfaces(ctx, nodeID)
}

func (s *PolicyService) GetPolicy(ctx context.Context, nodeID, iface string) (models.InterfacePolicy, error) {
	policy, err := s.store.GetPolicy(ctx, nodeID, iface)
	if err != nil {
		return policy, err
	}
	return models.NormalizeInterfacePolicy(policy), nil
}

// WithClusterInterconnect adds the currently registered node addresses to an
// ingress policy. Keeping this in the service makes the safety baseline and
// ordinary rule edits use the same membership-derived allow rules.
func (s *PolicyService) WithClusterInterconnect(ctx context.Context, policy models.InterfacePolicy) models.InterfacePolicy {
	policy = models.NormalizeInterfacePolicy(policy)
	policy.Ingress.Rules = ensureClusterInterconnectRules(
		policy.Ingress.Rules,
		s.store.ListNodes(ctx),
		policy.Ingress.BlockedCIDRs,
	)
	policy = ensureControlPortRules(policy, s.controlPortRules)
	return models.NormalizeInterfacePolicy(policy)
}

func (s *PolicyService) UpdatePolicy(ctx context.Context, policy models.InterfacePolicy) (models.InterfacePolicy, error) {
	return s.UpdatePolicyAndApply(ctx, policy)
}

// PolicyTrial describes a temporary enforcing policy. The agent owns the
// safety timer; the manager persists the previous policy so a restart can
// still complete the rollback.
type PolicyTrial struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// BeginPolicyTrial applies a policy without confirming the agent's safety
// publish. Unless the caller confirms it before the timeout, the agent restores
// its previous runtime automatically and the manager recovery loop restores the
// previous durable policy as well.
func (s *PolicyService) BeginPolicyTrial(ctx context.Context, policy models.InterfacePolicy, timeout time.Duration) (models.InterfacePolicy, PolicyTrial, error) {
	if timeout <= 0 {
		return policy, PolicyTrial{}, errors.New("policy trial timeout must be positive")
	}
	if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}
	lock, _ := s.applyLocks.LoadOrStore(policy.NodeID+"/"+policy.Interface, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()

	policy = s.WithClusterInterconnect(ctx, policy)
	policy.PendingPublish = nil
	policy.Ingress.PendingPublish = nil
	policy.Egress.PendingPublish = nil
	node, ok := FindNode(s.store.ListNodes(ctx), policy.NodeID)
	if !ok || strings.TrimSpace(node.AgentURL) == "" {
		return policy, PolicyTrial{}, errors.New("policy trial requires an enrolled agent")
	}
	if err := s.store.BeginPolicyUpdate(ctx, policy.NodeID, policy.Interface); err != nil {
		return policy, PolicyTrial{}, err
	}
	ids := map[models.PolicyDirection]string{
		models.DirectionIngress: "trial-" + rand.Text(),
		models.DirectionEgress:  "trial-" + rand.Text(),
	}
	recoverTrial := func(cause error) (models.InterfacePolicy, PolicyTrial, error) {
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		var failures []error
		for _, direction := range []models.PolicyDirection{models.DirectionEgress, models.DirectionIngress} {
			if err := s.postJSON(recoveryCtx, node.AgentURL+"/interfaces/"+policy.Interface+"/rollback", map[string]any{
				"publish_id": ids[direction], "direction": direction,
			}, nil); err != nil {
				// The agent may already have restored the snapshot. If it has not,
				// the durable recovery loop will retry the previous policy.
				if !strings.Contains(err.Error(), "404") {
					failures = append(failures, err)
				}
			}
		}
		if len(failures) == 0 {
			if err := s.store.FinishPolicyUpdate(recoveryCtx, policy.NodeID, policy.Interface, true); err != nil {
				failures = append(failures, err)
			}
		}
		if len(failures) > 0 {
			return policy, PolicyTrial{}, errors.Join(append([]error{cause, errors.New("policy trial recovery needs attention")}, failures...)...)
		}
		return policy, PolicyTrial{}, cause
	}
	for _, direction := range []models.PolicyDirection{models.DirectionEgress, models.DirectionIngress} {
		if err := s.applyPolicyWithSafetyTimeout(ctx, node, policy, direction, int(timeout/time.Second), ids[direction]); err != nil {
			return recoverTrial(err)
		}
	}
	updated, err := s.store.PutPolicyChecked(ctx, policy)
	if err != nil {
		return recoverTrial(err)
	}
	expiresAt := time.Now().Add(timeout).UTC()
	if err := s.store.MarkPolicyTrial(ctx, policy.NodeID, policy.Interface, expiresAt, ids); err != nil {
		return recoverTrial(err)
	}
	return updated, PolicyTrial{ExpiresAt: expiresAt}, nil
}

// ConfirmPolicyTrial keeps an active trial in force. The operation is
// deliberately separate from BeginPolicyTrial so a lost browser request cannot
// accidentally turn a connectivity check into permanent enforcement.
func (s *PolicyService) ConfirmPolicyTrial(ctx context.Context, nodeID, iface string) (models.InterfacePolicy, error) {
	lock, _ := s.applyLocks.LoadOrStore(nodeID+"/"+iface, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	recovery, ok := s.store.PendingPolicyUpdate(nodeID, iface)
	if !ok || recovery.TrialExpiresAt.IsZero() {
		return models.InterfacePolicy{}, errors.New("policy trial is not active")
	}
	if !recovery.TrialExpiresAt.After(time.Now()) {
		return models.InterfacePolicy{}, errors.New("policy trial has already expired")
	}
	node, ok := FindNode(s.store.ListNodes(ctx), nodeID)
	if !ok || strings.TrimSpace(node.AgentURL) == "" {
		return models.InterfacePolicy{}, errors.New("enrolled agent is unavailable")
	}
	for _, direction := range []models.PolicyDirection{models.DirectionEgress, models.DirectionIngress} {
		publishID := recovery.TrialPublishIDs[direction]
		if strings.TrimSpace(publishID) == "" {
			return models.InterfacePolicy{}, errors.New("policy trial publish record is incomplete")
		}
		if err := s.postJSON(ctx, node.AgentURL+"/interfaces/"+iface+"/confirm", map[string]any{
			"publish_id": publishID, "direction": direction,
		}, nil); err != nil {
			return models.InterfacePolicy{}, err
		}
	}
	if err := s.store.FinishPolicyUpdate(ctx, nodeID, iface, false); err != nil {
		return models.InterfacePolicy{}, err
	}
	return s.GetPolicy(ctx, nodeID, iface)
}

// RollbackPolicyTrial cancels a trial immediately and restores the durable
// policy. A 404 from the agent is acceptable because its own safety timer may
// already have performed the same rollback.
func (s *PolicyService) RollbackPolicyTrial(ctx context.Context, nodeID, iface string) error {
	lock, _ := s.applyLocks.LoadOrStore(nodeID+"/"+iface, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	recovery, ok := s.store.PendingPolicyUpdate(nodeID, iface)
	if !ok || recovery.TrialExpiresAt.IsZero() {
		return errors.New("policy trial is not active")
	}
	node, ok := FindNode(s.store.ListNodes(ctx), nodeID)
	if !ok || strings.TrimSpace(node.AgentURL) == "" {
		return errors.New("enrolled agent is unavailable")
	}
	for _, direction := range []models.PolicyDirection{models.DirectionEgress, models.DirectionIngress} {
		publishID := recovery.TrialPublishIDs[direction]
		if strings.TrimSpace(publishID) == "" {
			continue
		}
		err := s.postJSON(ctx, node.AgentURL+"/interfaces/"+iface+"/rollback", map[string]any{
			"publish_id": publishID, "direction": direction,
		}, nil)
		if err != nil && !strings.Contains(err.Error(), "404") {
			return err
		}
	}
	return s.store.FinishPolicyUpdate(ctx, nodeID, iface, true)
}

// UpdatePolicyAndApply persists a normalized policy and applies it to the
// node immediately. There is no separate publish or confirmation stage in
// the console workflow.
func (s *PolicyService) UpdatePolicyAndApply(ctx context.Context, policy models.InterfacePolicy) (models.InterfacePolicy, error) {
	lock, _ := s.applyLocks.LoadOrStore(policy.NodeID+"/"+policy.Interface, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	policy = s.WithClusterInterconnect(ctx, policy)
	// Immediate-apply mode has no pending confirmation record. Clear stale
	// records from policies created by the legacy publish workflow.
	policy.PendingPublish = nil
	policy.Ingress.PendingPublish = nil
	policy.Egress.PendingPublish = nil
	node, ok := FindNode(s.store.ListNodes(ctx), policy.NodeID)
	if !ok || strings.TrimSpace(node.AgentURL) == "" {
		return s.store.PutPolicyChecked(ctx, policy)
	}
	previous, previousErr := s.store.GetPolicy(ctx, policy.NodeID, policy.Interface)
	if err := s.store.BeginPolicyUpdate(ctx, policy.NodeID, policy.Interface); err != nil {
		return policy, err
	}
	ids := map[models.PolicyDirection]string{models.DirectionIngress: "safe-" + rand.Text(), models.DirectionEgress: "safe-" + rand.Text()}
	confirming := false
	recoverPolicy := func(cause error) (models.InterfacePolicy, error) {
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		var failures []error
		for _, direction := range []models.PolicyDirection{models.DirectionEgress, models.DirectionIngress} {
			rollbackErr := s.postJSON(recoveryCtx, node.AgentURL+"/interfaces/"+policy.Interface+"/rollback", map[string]any{"publish_id": ids[direction], "direction": direction}, nil)
			// A lost confirmation response may mean the snapshot was already
			// consumed. Restore the last durable policy in that case as well.
			if rollbackErr != nil && confirming && previousErr == nil {
				if err := s.applyPolicy(recoveryCtx, node, previous, direction); err != nil {
					failures = append(failures, err)
				}
			}
		}
		if len(failures) == 0 {
			if err := s.store.FinishPolicyUpdate(recoveryCtx, policy.NodeID, policy.Interface, true); err != nil {
				failures = append(failures, err)
			}
		}
		if len(failures) > 0 {
			return policy, errors.Join(append([]error{cause, errors.New("policy recovery needs attention")}, failures...)...)
		}
		return policy, cause
	}
	for _, direction := range []models.PolicyDirection{models.DirectionIngress, models.DirectionEgress} {
		if err := s.applyPolicy(ctx, node, policy, direction, ids[direction]); err != nil {
			return recoverPolicy(err)
		}
	}
	updated, err := s.store.PutPolicyChecked(ctx, policy)
	if err != nil {
		return recoverPolicy(err)
	}
	confirming = true
	for _, direction := range []models.PolicyDirection{models.DirectionEgress, models.DirectionIngress} {
		if err := s.postJSON(ctx, node.AgentURL+"/interfaces/"+policy.Interface+"/confirm", map[string]any{"publish_id": ids[direction], "direction": direction}, nil); err != nil {
			return recoverPolicy(err)
		}
	}
	if err := s.store.FinishPolicyUpdate(ctx, policy.NodeID, policy.Interface, false); err != nil {
		return recoverPolicy(err)
	}
	return updated, nil
}

func (s *PolicyService) applyPolicy(ctx context.Context, node models.Node, policy models.InterfacePolicy, direction models.PolicyDirection, safetyIDs ...string) error {
	if len(safetyIDs) > 0 {
		return s.applyPolicyWithSafetyTimeout(ctx, node, policy, direction, 30, safetyIDs[0])
	}
	return s.applyPolicyWithSafetyTimeout(ctx, node, policy, direction, 0)
}

func (s *PolicyService) applyPolicyWithSafetyTimeout(ctx context.Context, node models.Node, policy models.InterfacePolicy, direction models.PolicyDirection, safetyTimeout int, safetyIDs ...string) error {
	selected := models.DirectionPolicyFor(policy, direction)
	if direction == models.DirectionIngress {
		if err := s.attachWithFallback(ctx, node, policy.Interface); err != nil {
			return err
		}
	}

	payload := map[string]any{
		"immediate":          true,
		"direction":          direction,
		"observe_only":       selected.ObserveOnly,
		"bypass_cidrs":       selected.BypassCIDRs,
		"blocked_cidrs":      selected.BlockedCIDRs,
		"icmp_allow_cidrs":   selected.ICMPAllowCIDRs,
		"icmp_blocked_cidrs": selected.ICMPBlockedCIDRs,
		"allowlist":          extractCIDRs(selected.Rules),
		"public_ports":       selected.PublicPorts,
		"denied_ports":       selected.DeniedPorts,
		"allowed_ports":      selected.AllowedPorts,
		"public_port_rules":  models.NormalizePortRules(selected.PublicPortRules, selected.PublicPorts),
		"denied_port_rules":  models.NormalizePortRules(selected.DeniedPortRules, selected.DeniedPorts),
		"allowed_port_rules": models.NormalizePortRules(selected.AllowedPortRules, selected.AllowedPorts),
		"non_ipv4_action":    selected.NonIPv4Action,
		"challenge":          selected.Challenge,
		"confirm_timeout":    30,
	}
	if len(safetyIDs) > 0 {
		payload["publish_id"] = safetyIDs[0]
		payload["safety_timeout"] = safetyTimeout
	}
	return s.postJSON(ctx, node.AgentURL+"/interfaces/"+policy.Interface+"/apply", payload, nil)
}

func (s *PolicyService) attachWithFallback(ctx context.Context, node models.Node, iface string) error {
	attachEndpoint := node.AgentURL + "/interfaces/" + iface + "/attach"
	if err := s.postJSON(ctx, attachEndpoint, map[string]string{"mode": "native"}, nil); err == nil {
		return nil
	}
	return s.postJSON(ctx, attachEndpoint, map[string]string{"mode": "generic"}, nil)
}

func (s *PolicyService) postJSON(ctx context.Context, endpoint string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("request %s failed with status %s: %s", endpoint, resp.Status, strings.TrimSpace(string(body)))
	}

	if out == nil {
		return nil
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func (s *PolicyService) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("request %s failed with status %s: %s", endpoint, resp.Status, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (s *PolicyService) agentInterfaceAttached(ctx context.Context, node models.Node, iface string) (bool, error) {
	var payload struct {
		Interfaces []models.DetectedInterface `json:"interfaces"`
	}
	if err := s.getJSON(ctx, node.AgentURL+"/interfaces", &payload); err != nil {
		return false, err
	}
	for _, item := range payload.Interfaces {
		if item.Name == iface {
			return item.Attached, nil
		}
	}
	return false, nil
}

func FindNode(nodes []models.Node, nodeID string) (models.Node, bool) {
	for _, node := range nodes {
		if strings.EqualFold(node.ID, nodeID) {
			return node, true
		}
	}

	return models.Node{}, false
}

func extractCIDRs(rules []models.ACLRule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Action == "" || rule.Action == "allow" {
			out = append(out, rule.CIDR)
		}
	}
	return out
}

func ensureClusterInterconnectRules(rules []models.ACLRule, nodes []models.Node, blocked []string) []models.ACLRule {
	deny := make(map[string]struct{}, len(blocked))
	for _, cidr := range blocked {
		deny[strings.TrimSpace(cidr)] = struct{}{}
	}
	existing := make(map[string]struct{}, len(rules))
	out := make([]models.ACLRule, 0, len(rules)+len(nodes))
	for _, rule := range rules {
		// XDP attaches only to a physical NIC. Loopback traffic never reaches
		// that hook, so retaining a 127/8 rule here only misleads operators.
		if isLoopbackIPv4CIDR(rule.CIDR) {
			continue
		}
		out = append(out, rule)
		if strings.TrimSpace(rule.Action) == "" || strings.EqualFold(strings.TrimSpace(rule.Action), "allow") {
			existing[strings.TrimSpace(rule.CIDR)] = struct{}{}
		}
	}
	for _, node := range nodes {
		for _, cidr := range nodeCIDRs(node) {
			if _, denied := deny[cidr]; denied {
				continue
			}
			if _, ok := existing[cidr]; ok {
				continue
			}
			out = append(out, models.ACLRule{
				CIDR:   cidr,
				Action: "allow",
			})
			existing[cidr] = struct{}{}
		}
	}
	return out
}

func ensureControlPortRules(policy models.InterfacePolicy, controlPorts []models.PortRule) models.InterfacePolicy {
	if len(controlPorts) == 0 {
		return policy
	}
	policy = models.NormalizeInterfacePolicy(policy)
	ingress := models.DirectionPolicyFor(policy, models.DirectionIngress)
	ingress.PublicPortRules = models.NormalizePortRules(ingress.PublicPortRules, ingress.PublicPorts)
	ingress.DeniedPortRules = models.NormalizePortRules(ingress.DeniedPortRules, ingress.DeniedPorts)
	ingress.AllowedPortRules = models.NormalizePortRules(ingress.AllowedPortRules, ingress.AllowedPorts)
	for _, target := range controlPorts {
		found := false
		for _, rule := range ingress.DeniedPortRules {
			if rule == target {
				found = true
				break
			}
		}
		if found {
			continue
		}
		for _, rule := range append(append([]models.PortRule{}, ingress.PublicPortRules...), ingress.AllowedPortRules...) {
			if rule == target {
				found = true
				break
			}
		}
		if !found {
			ingress.PublicPortRules = append(ingress.PublicPortRules, target)
		}
	}
	ingress.PublicPortRules = models.NormalizePortRules(ingress.PublicPortRules, nil)
	ingress.PublicPorts = models.CollapsePortRules(ingress.PublicPortRules)
	return models.WithDirectionPolicy(policy, models.DirectionIngress, ingress)
}

func nodeCIDRs(node models.Node) []string {
	candidates := []string{node.AdvertiseIP, node.AgentHTTPAddr}
	if node.AgentURL != "" {
		if u, err := url.Parse(node.AgentURL); err == nil {
			candidates = append(candidates, u.Hostname())
		}
	}
	out := make([]string, 0, 2)
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if strings.Count(candidate, ":") == 1 {
			if host, _, found := strings.Cut(candidate, ":"); found {
				candidate = host
			}
		}
		addr, err := netip.ParseAddr(candidate)
		if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() {
			continue
		}
		cidr := netip.PrefixFrom(addr.Unmap(), 32).String()
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	return out
}

func isLoopbackIPv4CIDR(value string) bool {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	address := prefix.Addr()
	return address.Is4() && address.IsLoopback()
}
