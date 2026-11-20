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
	applyLocks         sync.Map
	store              *store.Store
	httpClient         *http.Client
	httpClientResolver func(string) (*http.Client, map[string]string, error)
	controlPortRules   []models.PortRule
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

// SetHTTPClientResolver lets a cluster manager select the enrolled Agent
// certificate for each endpoint. A single manager CA cannot authenticate
// independent self-signed certificates on every node.
func (s *PolicyService) SetHTTPClientResolver(resolver func(string) (*http.Client, map[string]string, error)) {
	s.httpClientResolver = resolver
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
	ExpiresAt time.Time              `json:"expires_at"`
	Direction models.PolicyDirection `json:"direction,omitempty"`
}

// BeginPolicyTrial applies a policy without confirming the agent's safety
// publish. Unless the caller confirms it before the timeout, the agent restores
// its previous runtime automatically and the manager recovery loop restores the
// previous durable policy as well.
func (s *PolicyService) BeginPolicyTrial(ctx context.Context, policy models.InterfacePolicy, timeout time.Duration) (models.InterfacePolicy, PolicyTrial, error) {
	return s.beginPolicyTrial(ctx, policy, timeout, "")
}

// BeginPolicyTrialForDirection keeps the trial label scoped to the direction
// selected in the console. Both direction publish IDs remain available for
// atomic rollback of the interface if the manager or agent loses contact.
func (s *PolicyService) BeginPolicyTrialForDirection(ctx context.Context, policy models.InterfacePolicy, timeout time.Duration, direction models.PolicyDirection) (models.InterfacePolicy, PolicyTrial, error) {
	return s.beginPolicyTrial(ctx, policy, timeout, direction)
}

func (s *PolicyService) beginPolicyTrial(ctx context.Context, policy models.InterfacePolicy, timeout time.Duration, trialDirection models.PolicyDirection) (models.InterfacePolicy, PolicyTrial, error) {
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
	// Ingress attach creates the maps shared by XDP and the TC egress hook.
	// A fresh interface cannot accept an egress policy before that succeeds.
	for _, direction := range []models.PolicyDirection{models.DirectionIngress, models.DirectionEgress} {
		if err := s.applyPolicyWithSafetyTimeout(ctx, node, policy, direction, int(timeout/time.Second), ids[direction]); err != nil {
			return recoverTrial(err)
		}
	}
	updated, err := s.store.PutPolicyChecked(ctx, policy)
	if err != nil {
		return recoverTrial(err)
	}
	expiresAt := time.Now().Add(timeout).UTC()
	if err := s.store.MarkPolicyTrialDirection(ctx, policy.NodeID, policy.Interface, expiresAt, trialDirection, ids); err != nil {
		return recoverTrial(err)
	}
	return updated, PolicyTrial{ExpiresAt: expiresAt, Direction: trialDirection}, nil
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
	return s.updatePolicyAndApplyLocked(ctx, policy)
}

var ErrPolicyChanged = errors.New("policy changed since it was loaded")

// SavePolicySnapshotIfCurrent persists metadata or reconciled Agent state
// without reapplying the dataplane. Readers must not block on an Agent apply
// or replace a policy while an apply or trial owns its recovery record.
func (s *PolicyService) SavePolicySnapshotIfCurrent(ctx context.Context, policy models.InterfacePolicy) (models.InterfacePolicy, error) {
	lock, _ := s.applyLocks.LoadOrStore(policy.NodeID+"/"+policy.Interface, &sync.Mutex{})
	mutex := lock.(*sync.Mutex)
	locked := mutex.TryLock()
	if locked {
		defer mutex.Unlock()
	}
	current, _ := s.GetPolicy(ctx, policy.NodeID, policy.Interface)
	if err := ctx.Err(); err != nil {
		return current, err
	}
	if !locked || !current.UpdatedAt.Equal(policy.UpdatedAt) {
		return current, ErrPolicyChanged
	}
	if _, pending := s.store.PendingPolicyUpdate(policy.NodeID, policy.Interface); pending {
		return current, ErrPolicyChanged
	}
	return s.store.PutPolicyChecked(ctx, policy)
}

// UpdatePolicyAndApplyIfCurrent protects a complete policy submitted by a Web
// form from replacing a newer save. Check inside the apply lock so two requests
// cannot both pass the comparison before either policy becomes durable.
func (s *PolicyService) UpdatePolicyAndApplyIfCurrent(ctx context.Context, policy models.InterfacePolicy, expected time.Time) (models.InterfacePolicy, error) {
	lock, _ := s.applyLocks.LoadOrStore(policy.NodeID+"/"+policy.Interface, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	if !expected.IsZero() {
		current, err := s.store.GetPolicy(ctx, policy.NodeID, policy.Interface)
		if err != nil || !current.UpdatedAt.Equal(expected) {
			return policy, ErrPolicyChanged
		}
	}
	return s.updatePolicyAndApplyLocked(ctx, policy)
}

// updatePolicyAndApplyLocked is the mutation primitive used by ordinary
// policy writes and temporary egress leases. Callers must hold the per-policy
// mutex so a lease can keep its snapshot and restoration atomic with the SMTP
// operation that owns it.
func (s *PolicyService) updatePolicyAndApplyLocked(ctx context.Context, policy models.InterfacePolicy) (models.InterfacePolicy, error) {
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
			if rollbackErr != nil && confirming && previousErr == nil && strings.Contains(rollbackErr.Error(), "404") {
				if err := s.applyPolicy(recoveryCtx, node, previous, direction); err != nil {
					failures = append(failures, err)
				}
			} else if rollbackErr != nil && !strings.Contains(rollbackErr.Error(), "404") {
				failures = append(failures, rollbackErr)
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

// EgressLeaseTarget is a narrowly scoped destination and service tuple used
// while an operation such as SMTP is in progress. The lease never changes a
// permanently open/observe-only policy; it is only needed when egress
// enforcement is actively denying unmatched traffic.
type EgressLeaseTarget struct {
	IP       netip.Addr
	Port     uint16
	Protocol models.PortProtocol
}

type EgressLease struct {
	releaseOnce sync.Once
	releaseFn   func() error
}

func (l *EgressLease) Release() error {
	if l == nil || l.releaseFn == nil {
		return nil
	}
	var err error
	l.releaseOnce.Do(func() { err = l.releaseFn() })
	return err
}

// AcquireTemporaryEgressLease creates a temporary allowlist entry on the
// selected node/interface. The policy mutex remains held until Release, so a
// concurrent UI edit cannot overwrite the snapshot while the operation is in
// flight. The lease also has an automatic upper bound as a recovery guard.
func (s *PolicyService) AcquireTemporaryEgressLease(ctx context.Context, nodeID, iface string, targets []EgressLeaseTarget, ttl time.Duration) (*EgressLease, bool, error) {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if ttl > 2*time.Minute {
		ttl = 2 * time.Minute
	}
	key := strings.TrimSpace(nodeID) + "/" + strings.TrimSpace(iface)
	if strings.Trim(key, "/") == "" {
		return nil, false, errors.New("egress lease requires a node and interface")
	}
	lock, _ := s.applyLocks.LoadOrStore(key, &sync.Mutex{})
	mutex := lock.(*sync.Mutex)
	mutex.Lock()

	current, err := s.store.GetPolicy(ctx, nodeID, iface)
	if err != nil {
		mutex.Unlock()
		return nil, false, err
	}
	current = models.NormalizeInterfacePolicy(current)
	egress := current.Egress
	// Ingress and egress can be enabled independently. Do not gate an outbound
	// SMTP/DNS lease on InterfacePolicy.Enabled, which is the legacy ingress
	// alias and may be false while egress protection is active.
	if !egress.Enabled || egress.ObserveOnly || !directionHasEnforcement(egress) {
		mutex.Unlock()
		return &EgressLease{}, false, nil
	}

	validTargets := make([]EgressLeaseTarget, 0, len(targets))
	for _, target := range targets {
		if !target.IP.IsValid() || !target.IP.Is4() || target.Port == 0 {
			continue
		}
		protocol := models.PortProtocol(strings.ToLower(strings.TrimSpace(string(target.Protocol))))
		if protocol != models.PortProtocolTCP && protocol != models.PortProtocolUDP {
			return nil, false, fmt.Errorf("unsupported temporary egress protocol %q", target.Protocol)
		}
		for _, blocked := range egress.BlockedCIDRs {
			if prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(blocked)); parseErr == nil && prefix.Contains(target.IP) {
				mutex.Unlock()
				return nil, false, fmt.Errorf("temporary egress target %s is blocked by the current policy", target.IP)
			}
		}
		for _, denied := range models.NormalizePortRules(egress.DeniedPortRules, egress.DeniedPorts) {
			if denied.Port == target.Port && denied.Protocol == protocol {
				mutex.Unlock()
				return nil, false, fmt.Errorf("temporary egress port %d/%s is explicitly denied", target.Port, protocol)
			}
		}
		validTargets = append(validTargets, EgressLeaseTarget{IP: target.IP, Port: target.Port, Protocol: protocol})
	}
	if len(validTargets) == 0 {
		mutex.Unlock()
		return nil, false, errors.New("temporary egress lease has no IPv4 targets")
	}

	next := current
	next.Egress = egress
	// A policy with an existing destination/port allowlist already has a
	// default-deny shape. Add the SMTP target and port to that pair. For an
	// explicit-deny policy with no allowlist, use a /32 bypass so the lease does
	// not unexpectedly convert all other outbound traffic into default deny.
	constrained := len(egress.Rules) > 0 || len(egress.AllowedPortRules) > 0 || len(egress.AllowedPorts) > 0
	for _, target := range validTargets {
		cidr := netip.PrefixFrom(target.IP, 32).String()
		if constrained {
			next.Egress.Rules = appendUniqueACLRule(next.Egress.Rules, models.ACLRule{CIDR: cidr, Action: "allow"})
			next.Egress.AllowedPortRules = appendUniquePortRule(next.Egress.AllowedPortRules, models.PortRule{Protocol: target.Protocol, Port: target.Port})
		} else {
			next.Egress.BypassCIDRs = appendUniqueString(next.Egress.BypassCIDRs, cidr)
		}
	}
	next.Egress.AllowedPorts = models.CollapsePortRules(next.Egress.AllowedPortRules)
	next = models.NormalizeInterfacePolicy(next)
	if _, err := s.updatePolicyAndApplyLocked(ctx, next); err != nil {
		mutex.Unlock()
		return nil, false, err
	}

	released := false
	var timer *time.Timer
	lease := &EgressLease{}
	lease.releaseFn = func() error {
		if timer != nil {
			timer.Stop()
		}
		if released {
			return nil
		}
		released = true
		_, restoreErr := s.updatePolicyAndApplyLocked(context.WithoutCancel(ctx), current)
		mutex.Unlock()
		return restoreErr
	}
	timer = time.AfterFunc(ttl, func() { _ = lease.Release() })
	return lease, true, nil
}

func directionHasEnforcement(policy models.DirectionPolicy) bool {
	// A pass/allow default with no explicit deny is a permanently open
	// direction. Allowed/public port entries are harmless documentation in
	// that mode and must not trigger a temporary SMTP/DNS lease.
	defaultPass := strings.EqualFold(strings.TrimSpace(policy.DefaultAction), "pass") ||
		strings.EqualFold(strings.TrimSpace(policy.DefaultAction), "allow")
	if defaultPass && len(policy.BlockedCIDRs) == 0 && len(policy.ICMPBlockedCIDRs) == 0 &&
		len(policy.DeniedPortRules) == 0 && len(policy.DeniedPorts) == 0 {
		for _, rule := range policy.Rules {
			action := strings.ToLower(strings.TrimSpace(rule.Action))
			if action == "deny" || action == "drop" || action == "block" {
				return true
			}
		}
		return false
	}
	return len(policy.Rules) > 0 || len(policy.BypassCIDRs) > 0 || len(policy.BlockedCIDRs) > 0 ||
		len(policy.ICMPAllowCIDRs) > 0 || len(policy.ICMPBlockedCIDRs) > 0 ||
		len(policy.PublicPortRules) > 0 || len(policy.DeniedPortRules) > 0 || len(policy.AllowedPortRules) > 0 ||
		len(policy.PublicPorts) > 0 || len(policy.DeniedPorts) > 0 || len(policy.AllowedPorts) > 0
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if strings.TrimSpace(existing) == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniquePortRule(values []models.PortRule, value models.PortRule) []models.PortRule {
	for _, existing := range values {
		if existing.Protocol == value.Protocol && existing.Port == value.Port {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueACLRule(values []models.ACLRule, value models.ACLRule) []models.ACLRule {
	for _, existing := range values {
		if strings.TrimSpace(existing.CIDR) == value.CIDR && strings.EqualFold(strings.TrimSpace(existing.Action), value.Action) {
			return values
		}
	}
	return append(values, value)
}

func (s *PolicyService) applyPolicy(ctx context.Context, node models.Node, policy models.InterfacePolicy, direction models.PolicyDirection, safetyIDs ...string) error {
	if len(safetyIDs) > 0 {
		return s.applyPolicyWithSafetyTimeout(ctx, node, policy, direction, 30, safetyIDs[0])
	}
	return s.applyPolicyWithSafetyTimeout(ctx, node, policy, direction, 0)
}

func (s *PolicyService) applyPolicyWithSafetyTimeout(ctx context.Context, node models.Node, policy models.InterfacePolicy, direction models.PolicyDirection, safetyTimeout int, safetyIDs ...string) error {
	selected := models.DirectionPolicyFor(policy, direction)
	previouslyAttached := true
	if direction == models.DirectionIngress {
		var err error
		previouslyAttached, err = s.attachInterface(ctx, node, policy.Interface)
		if err != nil {
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
		payload["restore_unattached"] = direction == models.DirectionIngress && !previouslyAttached
	}
	return s.postJSON(ctx, node.AgentURL+"/interfaces/"+policy.Interface+"/apply", payload, nil)
}

func (s *PolicyService) attachInterface(ctx context.Context, node models.Node, iface string) (bool, error) {
	attachEndpoint := node.AgentURL + "/interfaces/" + iface + "/attach"
	var response struct {
		PreviouslyAttached *bool `json:"previously_attached"`
	}
	err := s.postJSON(ctx, attachEndpoint, map[string]string{"mode": "native"}, &response)
	// The agent negotiates native/generic and modern/legacy kernel APIs locally.
	// Replaying this mutation after a lost response can discard the original
	// previously_attached=false baseline and invalidate the trial snapshot.
	// Older agents omit this field; retain their observe-only rollback behavior
	// during rolling upgrades instead of inventing an unattached baseline.
	return response.PreviouslyAttached == nil || *response.PreviouslyAttached, err
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
	client, headers, err := s.resolveHTTPClient(endpoint)
	if err != nil {
		return err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
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
	client, headers, err := s.resolveHTTPClient(endpoint)
	if err != nil {
		return err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
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

func (s *PolicyService) resolveHTTPClient(endpoint string) (*http.Client, map[string]string, error) {
	if s.httpClientResolver != nil {
		return s.httpClientResolver(endpoint)
	}
	return s.httpClient, nil, nil
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
