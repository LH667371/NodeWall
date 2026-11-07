package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/service"
)

type logActionRequest struct {
	NodeID          string                 `json:"node_id"`
	Interface       string                 `json:"interface"`
	Direction       models.PolicyDirection `json:"direction"`
	SourceIP        string                 `json:"source_ip"`
	Port            uint16                 `json:"port"`
	Scope           string                 `json:"scope"`
	DurationMinutes int                    `json:"duration_minutes"`
	ConfirmPassword string                 `json:"confirm_password"`
}

func (h *ServerHandler) handleProxyTemporaryBlocks(w http.ResponseWriter, r *http.Request) {
	if h.blockUnsafeSSHDisposition(w, r) {
		return
	}
	h.proxy(w, r, "/interfaces/"+r.PathValue("iface")+"/temporary-blocks?direction="+string(requestDirection(r)))
}

func (h *ServerHandler) handleProxyTemporaryBlockDelete(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/interfaces/"+r.PathValue("iface")+"/temporary-blocks/"+r.PathValue("id")+"?direction="+string(requestDirection(r)))
}

func (h *ServerHandler) handleProxyRateLimits(w http.ResponseWriter, r *http.Request) {
	if h.blockUnsafeSSHDisposition(w, r) {
		return
	}
	h.proxy(w, r, "/interfaces/"+r.PathValue("iface")+"/rate-limits?direction="+string(requestDirection(r)))
}

func (h *ServerHandler) handleProxyRateLimitDelete(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, "/interfaces/"+r.PathValue("iface")+"/rate-limits/"+r.PathValue("id")+"?direction="+string(requestDirection(r)))
}

func (h *ServerHandler) handleLogAllowAction(w http.ResponseWriter, r *http.Request) {
	var req logActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodeID, direction, cidr, sourceIP, err := h.normalizeLogAction(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	if scope == "" {
		scope = "allowlist"
	}
	if scope != "bypass" {
		scope = "allowlist"
	}
	policy, ok := h.applyLogPolicyAction(w, r, nodeID, req.Interface, direction, req.Port, cidr, "allow", scope, req.ConfirmPassword)
	if !ok {
		return
	}
	if err := h.clearLogDispositions(r.Context(), nodeID, req.Interface, direction, sourceIP, 0, true); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	disposition := buildServerDisposition(policy, nil, nil, direction, sourceIP, req.Port)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "updated",
		"scope":       scope,
		"policy":      policy,
		"disposition": disposition,
	})
}

func (h *ServerHandler) handleLogBlockAction(w http.ResponseWriter, r *http.Request) {
	var req logActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodeID, direction, cidr, sourceIP, err := h.normalizeLogAction(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy, ok := h.applyLogPolicyAction(w, r, nodeID, req.Interface, direction, req.Port, cidr, "block", "", req.ConfirmPassword)
	if !ok {
		return
	}
	if err := h.clearLogDispositions(r.Context(), nodeID, req.Interface, direction, sourceIP, 0, true); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	disposition := buildServerDisposition(policy, nil, nil, direction, sourceIP, req.Port)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "updated",
		"policy":      policy,
		"disposition": disposition,
	})
}

func (h *ServerHandler) handleLogTempBlockAction(w http.ResponseWriter, r *http.Request) {
	var req logActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodeID, direction, _, sourceIP, err := h.normalizeLogAction(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.DurationMinutes <= 0 {
		req.DurationMinutes = 60
	}
	policy, ok := h.applyLogPolicyAction(w, r, nodeID, req.Interface, direction, req.Port, sourceIPCIDR(sourceIP), "temp-block", "", req.ConfirmPassword)
	if !ok {
		return
	}
	if err := h.clearLogDispositions(r.Context(), nodeID, req.Interface, direction, sourceIP, req.Port, false); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	var response struct {
		TemporaryBlock models.TemporaryBlock `json:"temporary_block"`
		Disposition    models.LogDisposition `json:"disposition"`
	}
	err = h.nodeJSON(r.Context(), nodeID, http.MethodPost, "/interfaces/"+req.Interface+"/temporary-blocks", map[string]any{
		"direction":        direction,
		"source_ip":        sourceIP,
		"port":             req.Port,
		"reason":           "log_center",
		"duration_minutes": req.DurationMinutes,
	}, &response)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "updated",
		"policy":          policy,
		"temporary_block": response.TemporaryBlock,
		"disposition":     response.Disposition,
	})
}

func (h *ServerHandler) handleLogRateLimitAction(w http.ResponseWriter, r *http.Request) {
	var req logActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodeID, direction, _, sourceIP, err := h.normalizeLogAction(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	policy, ok := h.applyLogPolicyAction(w, r, nodeID, req.Interface, direction, req.Port, sourceIPCIDR(sourceIP), "rate-limit", "", req.ConfirmPassword)
	if !ok {
		return
	}
	if err := h.clearLogDispositions(r.Context(), nodeID, req.Interface, direction, sourceIP, req.Port, false); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	var response struct {
		RateLimit   models.RateLimitRule  `json:"rate_limit"`
		Disposition models.LogDisposition `json:"disposition"`
	}
	err = h.nodeJSON(r.Context(), nodeID, http.MethodPost, "/interfaces/"+req.Interface+"/rate-limits", map[string]any{
		"direction":           direction,
		"source_ip":           sourceIP,
		"port":                req.Port,
		"requests_per_minute": 120,
		"burst":               20,
		"duration_minutes":    req.DurationMinutes,
	}, &response)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "updated",
		"policy":      policy,
		"rate_limit":  response.RateLimit,
		"disposition": response.Disposition,
	})
}

// applyLogPolicyAction makes the source-level actions mutually exclusive in
// the persisted policy. The XDP agent has separate maps for allow, block,
// temporary block and rate limit, so clearing only one of those maps would
// leave a stale higher-priority rule behind.
func (h *ServerHandler) applyLogPolicyAction(w http.ResponseWriter, r *http.Request, nodeID, iface string, direction models.PolicyDirection, port uint16, cidr, action, scope, confirmPassword string) (models.InterfacePolicy, bool) {
	current := h.ensurePolicy(r.Context(), nodeID, iface)
	next := policyAfterLogAction(current, direction, cidr, action, scope)
	if h.blockUnsafeSSHPolicy(w, r, current, next, confirmPassword) {
		return models.InterfacePolicy{}, false
	}
	if node, ok := service.FindNode(h.service.ListNodes(r.Context()), nodeID); ok && (policyRequiresSSHConfirmation(r.Context(), h, node, current, next) || restrictiveLogActionTargetsSSH(r.Context(), h, node, direction, port, action)) {
		if h.auth == nil || !h.auth.verifyCurrentPassword(r, confirmPassword) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   "ssh confirmation required",
				"code":    "SSH_CONFIRM_REQUIRED",
				"service": "sshd",
				"ports":   sshPortsForNode(r.Context(), h, node),
			})
			return models.InterfacePolicy{}, false
		}
	}
	updated, err := h.service.UpdatePolicyAndApply(r.Context(), next)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return models.InterfacePolicy{}, false
	}
	return updated, true
}

// restrictiveLogActionTargetsSSH keeps log-center actions from silently
// cutting access to a real SSH listener. These actions change source-level
// maps, so comparing only the interface port policy is insufficient.
func restrictiveLogActionTargetsSSH(ctx context.Context, h *ServerHandler, node models.Node, direction models.PolicyDirection, port uint16, action string) bool {
	if direction != models.DirectionIngress || port == 0 {
		return false
	}
	switch action {
	case "block", "rate-limit", "temp-block":
	default:
		return false
	}
	for _, sshPort := range sshPortsForNode(ctx, h, node) {
		if sshPort == port {
			return true
		}
	}
	return false
}

func policyAfterLogAction(policy models.InterfacePolicy, direction models.PolicyDirection, cidr, action, scope string) models.InterfacePolicy {
	selected := models.DirectionPolicyFor(policy, direction)
	switch action {
	case "allow":
		selected.BlockedCIDRs = removeExactCIDR(selected.BlockedCIDRs, cidr)
		if scope == "bypass" {
			selected.Rules = removeAllowRuleCIDR(selected.Rules, cidr)
			selected.BypassCIDRs = appendUnique(selected.BypassCIDRs, cidr)
		} else {
			selected.BypassCIDRs = removeExactCIDR(selected.BypassCIDRs, cidr)
			selected.Rules = makeAllowRules(appendUnique(extractCIDRs(selected.Rules), cidr))
		}
	case "block", "rate-limit", "temp-block":
		selected.BypassCIDRs = removeExactCIDR(selected.BypassCIDRs, cidr)
		selected.Rules = removeAllowRuleCIDR(selected.Rules, cidr)
		if action == "block" {
			selected.BlockedCIDRs = appendUnique(selected.BlockedCIDRs, cidr)
		} else {
			selected.BlockedCIDRs = removeExactCIDR(selected.BlockedCIDRs, cidr)
		}
	}
	return models.WithDirectionPolicy(policy, direction, selected)
}

func removeAllowRuleCIDR(rules []models.ACLRule, cidr string) []models.ACLRule {
	result := make([]models.ACLRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Action == "allow" && sameCIDR(rule.CIDR, cidr) {
			continue
		}
		result = append(result, rule)
	}
	return result
}

func removeExactCIDR(items []string, cidr string) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		if sameCIDR(item, cidr) {
			continue
		}
		result = append(result, item)
	}
	return result
}

func sameCIDR(left, right string) bool {
	parse := func(value string) (netip.Prefix, bool) {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(value)); err == nil && prefix.Addr().Is4() {
			return prefix.Masked(), true
		}
		if addr, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil && addr.Is4() {
			return netip.PrefixFrom(addr.Unmap(), 32), true
		}
		return netip.Prefix{}, false
	}
	lhs, lok := parse(left)
	rhs, rok := parse(right)
	return lok && rok && lhs == rhs
}

func sourceIPCIDR(sourceIP string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(sourceIP))
	if err != nil || !addr.Is4() {
		return sourceIP
	}
	return netip.PrefixFrom(addr.Unmap(), 32).String()
}

func (h *ServerHandler) clearLogDispositions(ctx context.Context, nodeID, iface string, direction models.PolicyDirection, sourceIP string, port uint16, allPorts bool) error {
	var blocks struct {
		TemporaryBlocks []models.TemporaryBlock `json:"temporary_blocks"`
	}
	if err := h.nodeJSON(ctx, nodeID, http.MethodGet, "/interfaces/"+iface+"/temporary-blocks?direction="+string(direction), nil, &blocks); err != nil {
		return fmt.Errorf("list temporary blocks: %w", err)
	}
	for _, item := range blocks.TemporaryBlocks {
		if item.SourceIP != sourceIP || (!allPorts && item.Port != 0 && item.Port != port) {
			continue
		}
		path := "/interfaces/" + iface + "/temporary-blocks/" + item.ID + "?direction=" + string(direction)
		if err := h.nodeJSON(ctx, nodeID, http.MethodDelete, path, nil, nil); err != nil {
			return fmt.Errorf("remove temporary block %s: %w", item.ID, err)
		}
	}

	var limits struct {
		RateLimits []models.RateLimitRule `json:"rate_limits"`
	}
	if err := h.nodeJSON(ctx, nodeID, http.MethodGet, "/interfaces/"+iface+"/rate-limits?direction="+string(direction), nil, &limits); err != nil {
		return fmt.Errorf("list rate limits: %w", err)
	}
	for _, item := range limits.RateLimits {
		if item.SourceIP != sourceIP || (!allPorts && item.Port != port) {
			continue
		}
		path := "/interfaces/" + iface + "/rate-limits/" + item.ID + "?direction=" + string(direction)
		if err := h.nodeJSON(ctx, nodeID, http.MethodDelete, path, nil, nil); err != nil {
			return fmt.Errorf("remove rate limit %s: %w", item.ID, err)
		}
	}
	return nil
}

func (h *ServerHandler) normalizeLogAction(req logActionRequest) (string, models.PolicyDirection, string, string, error) {
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		nodeID = h.nodeID
	}
	if strings.TrimSpace(req.Interface) == "" {
		return "", "", "", "", fmt.Errorf("interface is required")
	}
	normalizedSource := extractIPv4Candidate(req.SourceIP)
	addr, err := netip.ParseAddr(normalizedSource)
	if err != nil || !addr.Is4() {
		return "", "", "", "", fmt.Errorf("valid IPv4 source_ip is required")
	}
	direction := req.Direction
	if direction == "" {
		direction = models.DirectionIngress
	}
	ip := addr.Unmap().String()
	return nodeID, direction, netip.PrefixFrom(addr.Unmap(), 32).String(), ip, nil
}

func (h *ServerHandler) nodeJSON(ctx context.Context, nodeID, method, path string, payload any, out any) error {
	node, ok := service.FindNode(h.service.ListNodes(ctx), nodeID)
	if !ok {
		return fmt.Errorf("node not found")
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, node.AgentURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.reverseHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("request %s failed with status %s", path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func enrichDropLogsWithDisposition(records []models.DropLogRecord, policyByIface map[string]models.InterfacePolicy, runtimeCache map[string]runtimeDispositionState) {
	for i := range records {
		record := &records[i]
		direction := record.Direction
		if direction == "" {
			direction = models.DirectionIngress
		}
		policy, ok := policyByIface[record.Interface]
		if !ok {
			disposition := models.LogDisposition{
				SourceIP:  record.SourceIP,
				Port:      record.Port,
				Direction: direction,
				Status:    models.DispositionOpen,
				Scope:     "open",
				UpdatedAt: time.Now().UTC(),
			}
			record.Disposition = &disposition
			continue
		}
		cacheKey := record.Interface + "|" + string(direction)
		runtime := runtimeCache[cacheKey]
		disposition := buildServerDisposition(policy, runtime.TempBlocks, runtime.RateLimits, direction, record.SourceIP, record.Port)
		record.Disposition = &disposition
	}
}

type runtimeDispositionState struct {
	TempBlocks []models.TemporaryBlock
	RateLimits []models.RateLimitRule
}

func buildServerDisposition(policy models.InterfacePolicy, tempBlocks []models.TemporaryBlock, rateLimits []models.RateLimitRule, direction models.PolicyDirection, sourceIP string, port uint16) models.LogDisposition {
	now := time.Now().UTC()
	selected := models.DirectionPolicyFor(policy, direction)
	cidr := sourceIP
	if addr, err := netip.ParseAddr(strings.TrimSpace(sourceIP)); err == nil && addr.Is4() {
		cidr = netip.PrefixFrom(addr.Unmap(), 32).String()
	}
	for _, item := range tempBlocks {
		if item.SourceIP == sourceIP && (item.Port == 0 || item.Port == port) && item.ExpiresAt.After(now) {
			expiresAt := item.ExpiresAt
			return models.LogDisposition{SourceIP: sourceIP, Port: port, Direction: direction, Status: models.DispositionTempBlocked, Scope: "temporary_block", Reference: item.ID, ExpiresAt: &expiresAt, UpdatedAt: now}
		}
	}
	for _, item := range rateLimits {
		if item.SourceIP == sourceIP && item.Port == port && (item.ExpiresAt == nil || item.ExpiresAt.After(now)) {
			return models.LogDisposition{SourceIP: sourceIP, Port: port, Direction: direction, Status: models.DispositionRateLimited, Scope: "rate_limit", Reference: item.ID, ExpiresAt: item.ExpiresAt, UpdatedAt: now}
		}
	}
	if containsCIDR(selected.BypassCIDRs, sourceIP) {
		return models.LogDisposition{SourceIP: sourceIP, Port: port, Direction: direction, Status: models.DispositionBypassed, Scope: "bypass", Reference: cidr, UpdatedAt: now}
	}
	if containsCIDR(extractCIDRs(selected.Rules), sourceIP) {
		return models.LogDisposition{SourceIP: sourceIP, Port: port, Direction: direction, Status: models.DispositionAllowlisted, Scope: "allowlist", Reference: cidr, UpdatedAt: now}
	}
	if containsCIDR(selected.BlockedCIDRs, sourceIP) {
		return models.LogDisposition{SourceIP: sourceIP, Port: port, Direction: direction, Status: models.DispositionBlocked, Scope: "blocked", Reference: cidr, UpdatedAt: now}
	}
	return models.LogDisposition{SourceIP: sourceIP, Port: port, Direction: direction, Status: models.DispositionOpen, Scope: "open", UpdatedAt: now}
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

// containsCIDR compares an address against policy prefixes instead of relying
// on string equality. Policies accept both a single IP (for example
// "192.168.5.125") and an explicit CIDR ("192.168.5.0/24").
func containsCIDR(items []string, sourceIP string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(sourceIP))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			if candidate, parseErr := netip.ParseAddr(value); parseErr == nil && candidate.Unmap() == addr {
				return true
			}
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
