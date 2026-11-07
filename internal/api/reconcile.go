package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/service"
)

// ReconcileManagerControlPorts repairs an older manager policy after a
// control-plane listener is introduced. Observe-only policies are updated in
// durable state without attaching or enforcing anything; already-enforced
// policies are updated through the normal transactional apply path.
func (h *ServerHandler) ReconcileManagerControlPorts(ctx context.Context) error {
	if h.service == nil || h.store == nil || h.nodeID == "" || len(h.controlPortRules) == 0 {
		return nil
	}
	node, ok := service.FindNode(h.service.ListNodes(ctx), h.nodeID)
	if !ok {
		return nil
	}
	iface, err := h.managerPolicyInterface(ctx, node)
	if err != nil || iface == "" {
		return err
	}
	policy, err := h.service.GetPolicy(ctx, node.ID, iface)
	if err != nil {
		return err
	}
	updated := h.service.WithClusterInterconnect(ctx, policy)
	updated = h.ensureControlPlanePortRules(updated)
	ingress := models.DirectionPolicyFor(policy, models.DirectionIngress)
	if reflect.DeepEqual(models.NormalizeInterfacePolicy(policy), models.NormalizeInterfacePolicy(updated)) {
		return nil
	}
	if !ingress.Enabled || ingress.ObserveOnly || strings.EqualFold(strings.TrimSpace(ingress.Mode), "observe") {
		_, err = h.store.PutPolicyChecked(ctx, updated)
		return err
	}
	updated = h.ensureRecoveryAccessPolicy(ctx, updated, true)
	_, err = h.service.UpdatePolicyAndApply(ctx, updated)
	return err
}

// ReconcileActiveClusterInterconnect applies the current enrolled-node
// addresses to every already-enforced policy. Enrollment therefore becomes
// immediately reachable without copying a rule through the UI or waiting for
// the next manual policy edit.
func (h *ServerHandler) ReconcileActiveClusterInterconnect(ctx context.Context) error {
	if h.service == nil || h.store == nil {
		return nil
	}
	var failures []string
	for _, node := range h.service.ListNodes(ctx) {
		for _, iface := range h.store.ListPolicyInterfaces(ctx, node.ID) {
			policy, err := h.service.GetPolicy(ctx, node.ID, iface)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s/%s: read policy: %v", node.ID, iface, err))
				continue
			}
			updated := h.service.WithClusterInterconnect(ctx, policy)
			updated = h.ensureControlPlanePortRules(updated)
			ingress := models.DirectionPolicyFor(updated, models.DirectionIngress)
			enforcing := ingress.Enabled && !ingress.ObserveOnly && !strings.EqualFold(strings.TrimSpace(ingress.Mode), "observe")
			if enforcing {
				updated = h.ensureRecoveryAccessPolicy(ctx, updated, true)
			}
			if reflect.DeepEqual(models.NormalizeInterfacePolicy(policy), models.NormalizeInterfacePolicy(updated)) {
				continue
			}
			if enforcing {
				if _, err := h.service.UpdatePolicyAndApply(ctx, updated); err != nil {
					failures = append(failures, fmt.Sprintf("%s/%s: apply policy: %v", node.ID, iface, err))
				}
				continue
			}
			if _, err := h.store.PutPolicyChecked(ctx, updated); err != nil {
				failures = append(failures, fmt.Sprintf("%s/%s: stage policy: %v", node.ID, iface, err))
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("cluster interconnect reconciliation failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *ServerHandler) managerPolicyInterface(ctx context.Context, node models.Node) (string, error) {
	if iface := strings.TrimSpace(h.defaultInterface); iface != "" {
		return iface, nil
	}
	if interfaces := h.store.ListPolicyInterfaces(ctx, node.ID); len(interfaces) > 0 {
		return interfaces[0], nil
	}
	var payload struct {
		Recommended string `json:"recommended"`
		Interfaces  []struct {
			Name       string `json:"name"`
			IsPhysical bool   `json:"is_physical"`
		} `json:"interfaces"`
	}
	if err := h.nodeJSON(ctx, node.ID, http.MethodGet, "/interfaces", nil, &payload); err != nil {
		return "", fmt.Errorf("discover manager interface: %w", err)
	}
	if recommended := strings.TrimSpace(payload.Recommended); recommended != "" {
		return recommended, nil
	}
	for _, item := range payload.Interfaces {
		if item.IsPhysical && strings.TrimSpace(item.Name) != "" {
			return strings.TrimSpace(item.Name), nil
		}
	}
	return "", nil
}

func containsPortRule(rules []models.PortRule, target models.PortRule) bool {
	for _, rule := range rules {
		if rule.Protocol == target.Protocol && rule.Port == target.Port {
			return true
		}
	}
	return false
}

func (h *ServerHandler) reconcileEnrollmentPolicies() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := h.ReconcileActiveClusterInterconnect(ctx); err != nil {
		log.Printf("warning: enrolled-node interconnect reconciliation failed: %v", err)
	}
}
