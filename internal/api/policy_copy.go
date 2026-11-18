package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"nodewall/internal/models"
	"nodewall/internal/service"
)

// policyCopyRequest deliberately copies one direction at a time. This keeps
// a multi-node operation from overwriting the target's unrelated direction or
// its local enforcement state.
type policyCopyRequest struct {
	SourceNodeID     string                 `json:"source_node_id"`
	Interface        string                 `json:"interface"`
	Direction        models.PolicyDirection `json:"direction"`
	TargetNodeIDs    []string               `json:"target_node_ids"`
	TargetInterfaces map[string]string      `json:"target_interfaces,omitempty"`
}

type policyCopyResult struct {
	NodeID    string `json:"node_id"`
	Interface string `json:"interface"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// handleCopyPolicy merges the selected direction from one node into one or
// more target nodes. Existing target rules are retained and exact duplicates
// are removed, making the operation safe to repeat from the UI.
func (h *ServerHandler) handleCopyPolicy(w http.ResponseWriter, r *http.Request) {
	var req policyCopyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid policy copy request"))
		return
	}
	req.SourceNodeID = strings.TrimSpace(req.SourceNodeID)
	req.Interface = strings.TrimSpace(req.Interface)
	if req.SourceNodeID == "" || req.Interface == "" {
		writeError(w, http.StatusBadRequest, errors.New("source_node_id and interface are required"))
		return
	}
	if req.Direction == "" {
		req.Direction = models.DirectionIngress
	}
	if req.Direction != models.DirectionIngress && req.Direction != models.DirectionEgress {
		writeError(w, http.StatusBadRequest, errors.New("direction must be ingress or egress"))
		return
	}
	if _, ok := service.FindNode(h.service.ListNodes(r.Context()), req.SourceNodeID); !ok {
		writeError(w, http.StatusNotFound, errors.New("source node not found"))
		return
	}
	sourcePolicy := h.ensurePolicy(r.Context(), req.SourceNodeID, req.Interface)

	seen := make(map[string]struct{}, len(req.TargetNodeIDs))
	type pendingCopy struct {
		result  policyCopyResult
		policy  models.InterfacePolicy
		current models.InterfacePolicy
	}
	pending := make([]pendingCopy, 0, len(req.TargetNodeIDs))
	results := make([]policyCopyResult, 0, len(req.TargetNodeIDs))
	for _, rawID := range req.TargetNodeIDs {
		targetID := strings.TrimSpace(rawID)
		if targetID == "" || targetID == req.SourceNodeID {
			continue
		}
		if _, duplicate := seen[targetID]; duplicate {
			continue
		}
		seen[targetID] = struct{}{}
		target, exists := service.FindNode(h.service.ListNodes(r.Context()), targetID)
		if !exists {
			results = append(results, policyCopyResult{NodeID: targetID, Interface: req.Interface, Status: "failed", Error: "target node not found"})
			continue
		}
		targetIface := req.Interface
		if override := strings.TrimSpace(req.TargetInterfaces[targetID]); override != "" {
			targetIface = override
		}
		current := h.ensurePolicy(r.Context(), target.ID, targetIface)
		next := models.WithDirectionPolicy(current, req.Direction, mergeCopiedDirectionPolicy(
			models.DirectionPolicyFor(current, req.Direction),
			models.DirectionPolicyFor(sourcePolicy, req.Direction),
		))
		next.NodeID = target.ID
		next.Interface = targetIface
		// Run all safety checks before the first apply so a rejected SSH change
		// cannot leave the batch half-applied.
		if h.blockUnsafeSSHPolicy(w, r, current, next, confirmPasswordFromRequest(r)) {
			return
		}
		pending = append(pending, pendingCopy{
			result:  policyCopyResult{NodeID: target.ID, Interface: targetIface, Status: "pending"},
			policy:  next,
			current: current,
		})
	}
	for _, item := range pending {
		if _, err := h.service.UpdatePolicyAndApply(r.Context(), item.policy); err != nil {
			item.result.Status = "failed"
			item.result.Error = fmt.Sprintf("apply policy: %v", err)
		} else {
			item.result.Status = "updated"
		}
		results = append(results, item.result)
	}
	failed := 0
	updated := 0
	for _, item := range results {
		if item.Status == "failed" {
			failed++
		} else if item.Status == "updated" {
			updated++
		}
	}
	status := http.StatusOK
	if failed > 0 {
		status = http.StatusMultiStatus
	}
	writeJSON(w, status, map[string]any{
		"source_node_id": req.SourceNodeID,
		"interface":      req.Interface,
		"direction":      req.Direction,
		"updated":        updated,
		"failed":         failed,
		"results":        results,
	})
}

func mergeCopiedDirectionPolicy(target, source models.DirectionPolicy) models.DirectionPolicy {
	target.Rules = mergeACLRules(target.Rules, source.Rules)
	target.BypassCIDRs = mergeStringValues(target.BypassCIDRs, source.BypassCIDRs)
	target.BlockedCIDRs = mergeStringValues(target.BlockedCIDRs, source.BlockedCIDRs)
	target.ICMPAllowCIDRs = mergeStringValues(target.ICMPAllowCIDRs, source.ICMPAllowCIDRs)
	target.ICMPBlockedCIDRs = mergeStringValues(target.ICMPBlockedCIDRs, source.ICMPBlockedCIDRs)
	target.PublicPortRules = mergePortValues(target.PublicPortRules, target.PublicPorts, source.PublicPortRules, source.PublicPorts)
	target.DeniedPortRules = mergePortValues(target.DeniedPortRules, target.DeniedPorts, source.DeniedPortRules, source.DeniedPorts)
	target.AllowedPortRules = mergePortValues(target.AllowedPortRules, target.AllowedPorts, source.AllowedPortRules, source.AllowedPorts)
	target.PublicPorts = models.CollapsePortRules(target.PublicPortRules)
	target.DeniedPorts = models.CollapsePortRules(target.DeniedPortRules)
	target.AllowedPorts = models.CollapsePortRules(target.AllowedPortRules)
	target.RuleDescriptions = mergeRuleDescriptions(target.RuleDescriptions, source.RuleDescriptions)
	return target
}

func mergeACLRules(target, source []models.ACLRule) []models.ACLRule {
	out := make([]models.ACLRule, 0, len(target)+len(source))
	for _, item := range target {
		out = appendUniqueACLRule(out, item)
	}
	for _, item := range source {
		// A copied action is authoritative for the same CIDR. Remove the
		// previous target action before adding it to avoid contradictory rules.
		filtered := out[:0]
		for _, existing := range out {
			if strings.TrimSpace(existing.CIDR) != strings.TrimSpace(item.CIDR) {
				filtered = append(filtered, existing)
			}
		}
		out = appendUniqueACLRule(filtered, item)
	}
	return out
}

func appendUniqueACLRule(items []models.ACLRule, item models.ACLRule) []models.ACLRule {
	for _, existing := range items {
		if strings.TrimSpace(existing.CIDR) == strings.TrimSpace(item.CIDR) && strings.EqualFold(existing.Action, item.Action) {
			return items
		}
	}
	return append(items, item)
}

func mergeStringValues(target, source []string) []string {
	out := append([]string(nil), target...)
	for _, value := range source {
		value = strings.TrimSpace(value)
		if value != "" {
			out = appendUnique(out, value)
		}
	}
	return out
}

func mergePortValues(targetRules []models.PortRule, targetPorts []uint16, sourceRules []models.PortRule, sourcePorts []uint16) []models.PortRule {
	out := models.NormalizePortRules(targetRules, targetPorts)
	for _, item := range models.NormalizePortRules(sourceRules, sourcePorts) {
		out = appendUniquePortRule(out, item)
	}
	return models.NormalizePortRules(out, nil)
}

func mergeRuleDescriptions(target, source []models.RuleDescription) []models.RuleDescription {
	out := append([]models.RuleDescription(nil), target...)
	for _, item := range source {
		found := false
		for index, existing := range out {
			if existing.Kind == item.Kind && existing.Value == item.Value && existing.Protocol == item.Protocol {
				out[index] = item
				found = true
				break
			}
		}
		if !found {
			out = append(out, item)
		}
	}
	return out
}
