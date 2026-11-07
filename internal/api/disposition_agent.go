package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/xdp"
)

func (h *AgentHandler) handleListTemporaryBlocks(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if err := h.pruneExpiredDispositions(r.Context(), iface); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	runtime := h.ensureRuntime(iface)
	direction := requestPolicyDirection(r)
	selected := directionStateFor(runtime, direction)
	writeJSON(w, http.StatusOK, map[string]any{"temporary_blocks": selected.TemporaryBlocks})
}

func (h *AgentHandler) handleCreateTemporaryBlock(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if err := h.pruneExpiredDispositions(r.Context(), iface); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	var req struct {
		Direction       models.PolicyDirection `json:"direction"`
		SourceIP        string                 `json:"source_ip"`
		Port            uint16                 `json:"port"`
		Reason          string                 `json:"reason"`
		DurationMinutes int                    `json:"duration_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	addr, err := parseIPv4(req.SourceIP)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	direction := req.Direction
	if direction == "" {
		direction = models.DirectionIngress
	}
	if req.DurationMinutes <= 0 {
		req.DurationMinutes = 60
	}

	previousRuntime := h.ensureRuntime(iface)
	runtime := previousRuntime
	selected := directionStateFor(runtime, direction)
	block := models.TemporaryBlock{
		ID:        fmt.Sprintf("tb-%d", time.Now().UnixNano()),
		Interface: iface,
		Direction: direction,
		SourceIP:  addr.String(),
		Port:      req.Port,
		Reason:    strings.TrimSpace(req.Reason),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Duration(req.DurationMinutes) * time.Minute),
		Status:    "active",
	}
	selected.TemporaryBlocks = append(selected.TemporaryBlocks, block)
	selected.LastUpdatedAt = time.Now().UTC()
	runtime = withDirectionState(runtime, direction, selected)
	h.setRuntime(iface, runtime)

	if err := h.applyTemporaryBlock(iface, block); err != nil {
		h.setRuntime(iface, previousRuntime)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if direction == models.DirectionIngress && runtime.Attached {
		if err := h.syncPolicyConfig(iface, runtime); err != nil {
			h.setRuntime(iface, previousRuntime)
			_ = h.removeTemporaryBlock(iface, previousRuntime, block, directionStateFor(previousRuntime, direction).TemporaryBlocks)
			_ = h.syncPolicyConfig(iface, previousRuntime)
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if err := h.persist(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"temporary_block": block,
		"disposition":     buildDispositionFor(runtime, iface, direction, block.SourceIP, block.Port),
	})
}

func (h *AgentHandler) handleDeleteTemporaryBlock(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if err := h.pruneExpiredDispositions(r.Context(), iface); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	previousRuntime := h.ensureRuntime(iface)
	runtime := previousRuntime
	direction := requestPolicyDirection(r)
	selected := directionStateFor(runtime, direction)
	targetID := r.PathValue("id")
	next := make([]models.TemporaryBlock, 0, len(selected.TemporaryBlocks))
	var removed *models.TemporaryBlock
	for i := range selected.TemporaryBlocks {
		item := selected.TemporaryBlocks[i]
		if item.ID == targetID {
			copied := item
			removed = &copied
			continue
		}
		next = append(next, item)
	}
	if removed == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("temporary block %q not found", targetID))
		return
	}

	if err := h.removeTemporaryBlock(iface, runtime, *removed, next); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	selected.TemporaryBlocks = next
	selected.LastUpdatedAt = time.Now().UTC()
	runtime = withDirectionState(runtime, direction, selected)
	h.setRuntime(iface, runtime)
	if direction == models.DirectionIngress && runtime.Attached {
		if err := h.syncPolicyConfig(iface, runtime); err != nil {
			h.setRuntime(iface, previousRuntime)
			_ = h.applyTemporaryBlock(iface, *removed)
			_ = h.syncPolicyConfig(iface, previousRuntime)
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if err := h.persist(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "released",
		"disposition": buildDispositionFor(runtime, iface, direction, removed.SourceIP, removed.Port),
	})
}

func (h *AgentHandler) handleListRateLimits(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if err := h.pruneExpiredDispositions(r.Context(), iface); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	runtime := h.ensureRuntime(iface)
	direction := requestPolicyDirection(r)
	selected := directionStateFor(runtime, direction)
	writeJSON(w, http.StatusOK, map[string]any{"rate_limits": selected.RateLimits})
}

func (h *AgentHandler) handleCreateRateLimit(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if err := h.pruneExpiredDispositions(r.Context(), iface); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	var req struct {
		Direction         models.PolicyDirection `json:"direction"`
		SourceIP          string                 `json:"source_ip"`
		Protocol          string                 `json:"protocol"`
		Port              uint16                 `json:"port"`
		RequestsPerMinute uint64                 `json:"requests_per_minute"`
		Burst             uint64                 `json:"burst"`
		DurationMinutes   int                    `json:"duration_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	addr, err := parseIPv4(req.SourceIP)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Port == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("port must be greater than 0"))
		return
	}
	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if protocol == "" {
		protocol = string(models.PortProtocolTCP)
	}
	if protocol != string(models.PortProtocolTCP) && protocol != string(models.PortProtocolUDP) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("rate limits support only tcp and udp"))
		return
	}
	if req.RequestsPerMinute == 0 {
		req.RequestsPerMinute = 120
	}
	if req.Burst == 0 {
		req.Burst = 20
	}
	direction := req.Direction
	if direction == "" {
		direction = models.DirectionIngress
	}

	var expiresAt *time.Time
	if req.DurationMinutes > 0 {
		at := time.Now().UTC().Add(time.Duration(req.DurationMinutes) * time.Minute)
		expiresAt = &at
	}

	previousRuntime := h.ensureRuntime(iface)
	runtime := previousRuntime
	selected := directionStateFor(runtime, direction)
	rule := models.RateLimitRule{
		ID:                fmt.Sprintf("rl-%d", time.Now().UnixNano()),
		Interface:         iface,
		Direction:         direction,
		SourceIP:          addr.String(),
		Protocol:          models.PortProtocol(protocol),
		Port:              req.Port,
		RequestsPerMinute: req.RequestsPerMinute,
		Burst:             req.Burst,
		Mode:              "throttle",
		CreatedAt:         time.Now().UTC(),
		ExpiresAt:         expiresAt,
		Status:            "active",
	}
	selected.RateLimits = append(selected.RateLimits, rule)
	selected.LastUpdatedAt = time.Now().UTC()
	runtime = withDirectionState(runtime, direction, selected)
	h.setRuntime(iface, runtime)
	if direction == models.DirectionIngress && runtime.Attached {
		if err := h.xdp.ReplaceRateLimitRules(iface, selected.RateLimits); err != nil {
			h.setRuntime(iface, previousRuntime)
			_ = h.xdp.ReplaceRateLimitRules(iface, directionStateFor(previousRuntime, direction).RateLimits)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.syncPolicyConfig(iface, runtime); err != nil {
			h.setRuntime(iface, previousRuntime)
			_ = h.xdp.ReplaceRateLimitRules(iface, directionStateFor(previousRuntime, direction).RateLimits)
			_ = h.syncPolicyConfig(iface, previousRuntime)
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if err := h.persist(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rate_limit":  rule,
		"disposition": buildDispositionFor(runtime, iface, direction, rule.SourceIP, rule.Port),
	})
}

func (h *AgentHandler) handleDeleteRateLimit(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if err := h.pruneExpiredDispositions(r.Context(), iface); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	previousRuntime := h.ensureRuntime(iface)
	runtime := previousRuntime
	direction := requestPolicyDirection(r)
	selected := directionStateFor(runtime, direction)
	targetID := r.PathValue("id")
	next := make([]models.RateLimitRule, 0, len(selected.RateLimits))
	var removed *models.RateLimitRule
	for i := range selected.RateLimits {
		item := selected.RateLimits[i]
		if item.ID == targetID {
			copied := item
			removed = &copied
			continue
		}
		next = append(next, item)
	}
	if removed == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("rate limit %q not found", targetID))
		return
	}
	selected.RateLimits = next
	selected.LastUpdatedAt = time.Now().UTC()
	runtime = withDirectionState(runtime, direction, selected)
	h.setRuntime(iface, runtime)
	if direction == models.DirectionIngress && runtime.Attached {
		if err := h.xdp.ReplaceRateLimitRules(iface, selected.RateLimits); err != nil {
			h.setRuntime(iface, previousRuntime)
			_ = h.xdp.ReplaceRateLimitRules(iface, directionStateFor(previousRuntime, direction).RateLimits)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.syncPolicyConfig(iface, runtime); err != nil {
			h.setRuntime(iface, previousRuntime)
			_ = h.xdp.ReplaceRateLimitRules(iface, directionStateFor(previousRuntime, direction).RateLimits)
			_ = h.syncPolicyConfig(iface, previousRuntime)
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if err := h.persist(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "released",
		"disposition": buildDispositionFor(runtime, iface, direction, removed.SourceIP, removed.Port),
	})
}

func parseIPv4(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(extractIPv4Candidate(value))
	if err != nil || !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 address %q", value)
	}
	return addr.Unmap(), nil
}

func extractIPv4Candidate(value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return raw
	}
	if addr, err := netip.ParseAddr(raw); err == nil && addr.Is4() {
		return raw
	}
	tokens := strings.FieldsFunc(raw, func(r rune) bool {
		return (r < '0' || r > '9') && r != '.'
	})
	for _, token := range tokens {
		if !strings.Contains(token, ".") {
			continue
		}
		if addr, err := netip.ParseAddr(token); err == nil && addr.Is4() {
			return token
		}
	}
	return raw
}

func (h *AgentHandler) pruneExpiredDispositions(ctx context.Context, iface string) error {
	runtime := h.ensureRuntime(iface)
	changed := false
	for _, direction := range []models.PolicyDirection{models.DirectionIngress, models.DirectionEgress} {
		selected := directionStateFor(runtime, direction)
		blocks := make([]models.TemporaryBlock, 0, len(selected.TemporaryBlocks))
		for _, block := range selected.TemporaryBlocks {
			if block.ExpiresAt.After(time.Now().UTC()) {
				block.Status = "active"
				blocks = append(blocks, block)
				continue
			}
			changed = true
			if err := h.removeTemporaryBlock(iface, runtime, block, blocks); err != nil {
				return err
			}
		}
		limits := make([]models.RateLimitRule, 0, len(selected.RateLimits))
		for _, rule := range selected.RateLimits {
			if rule.ExpiresAt == nil || rule.ExpiresAt.After(time.Now().UTC()) {
				rule.Status = "active"
				limits = append(limits, rule)
				continue
			}
			changed = true
		}
		selected.TemporaryBlocks = blocks
		selected.RateLimits = limits
		runtime = withDirectionState(runtime, direction, selected)
	}
	if changed {
		h.setRuntime(iface, runtime)
		if runtime.Attached {
			if err := h.xdp.ReplaceRateLimitRules(iface, runtime.RateLimits); err != nil {
				return err
			}
			if err := h.syncPolicyConfig(iface, runtime); err != nil {
				return err
			}
			if runtime.Egress.Attached {
				if directional, ok := h.xdp.(xdp.DirectionalDataplane); ok {
					if err := directional.ApplyDirectionPolicy(iface, models.DirectionEgress, directionPolicyFromRuntime(runtime.Egress)); err != nil {
						return err
					}
				}
			}
		}
		return h.persist(ctx)
	}
	return nil
}

func (h *AgentHandler) applyTemporaryBlock(iface string, block models.TemporaryBlock) error {
	if block.Direction == models.DirectionEgress {
		runtime := h.ensureRuntime(iface)
		if directional, ok := h.xdp.(xdp.DirectionalDataplane); ok && runtime.Egress.Attached {
			return directional.ApplyDirectionPolicy(iface, models.DirectionEgress, directionPolicyFromRuntime(runtime.Egress))
		}
		return nil
	}
	cidr := netip.PrefixFrom(netip.MustParseAddr(block.SourceIP), 32).String()
	return h.xdp.UpsertBlockedCIDR(iface, cidr)
}

func (h *AgentHandler) removeTemporaryBlock(iface string, runtime models.InterfaceRuntime, block models.TemporaryBlock, remaining []models.TemporaryBlock) error {
	if block.Direction == models.DirectionEgress {
		if directional, ok := h.xdp.(xdp.DirectionalDataplane); ok && runtime.Egress.Attached {
			selected := directionStateFor(runtime, models.DirectionEgress)
			selected.TemporaryBlocks = append([]models.TemporaryBlock(nil), remaining...)
			return directional.ApplyDirectionPolicy(iface, models.DirectionEgress, directionPolicyFromRuntime(selected))
		}
		return nil
	}
	cidr := netip.PrefixFrom(netip.MustParseAddr(block.SourceIP), 32).String()
	if slices.Contains(runtime.BlockedCIDRs, cidr) {
		return nil
	}
	for _, item := range remaining {
		if item.SourceIP == block.SourceIP {
			return nil
		}
	}
	return h.xdp.DeleteBlockedCIDR(iface, cidr)
}

func buildDispositionFor(runtime models.InterfaceRuntime, iface string, direction models.PolicyDirection, sourceIP string, port uint16) models.LogDisposition {
	selected := directionStateFor(runtime, direction)
	now := time.Now().UTC()
	cidr := sourceIP
	if addr, err := netip.ParseAddr(strings.TrimSpace(sourceIP)); err == nil && addr.Is4() {
		cidr = netip.PrefixFrom(addr.Unmap(), 32).String()
	}
	for _, item := range selected.TemporaryBlocks {
		if item.SourceIP == sourceIP && (item.Port == 0 || item.Port == port) && item.ExpiresAt.After(now) {
			expiresAt := item.ExpiresAt
			return models.LogDisposition{
				SourceIP:  sourceIP,
				Port:      port,
				Direction: direction,
				Status:    models.DispositionTempBlocked,
				Scope:     "temporary_block",
				Reference: item.ID,
				ExpiresAt: &expiresAt,
				UpdatedAt: now,
			}
		}
	}
	for _, item := range selected.RateLimits {
		if item.SourceIP == sourceIP && item.Port == port && (item.ExpiresAt == nil || item.ExpiresAt.After(now)) {
			return models.LogDisposition{
				SourceIP:  sourceIP,
				Port:      port,
				Direction: direction,
				Status:    models.DispositionRateLimited,
				Scope:     "rate_limit",
				Reference: item.ID,
				ExpiresAt: item.ExpiresAt,
				UpdatedAt: now,
			}
		}
	}
	if containsCIDR(selected.BypassCIDRs, sourceIP) {
		return models.LogDisposition{
			SourceIP:  sourceIP,
			Port:      port,
			Direction: direction,
			Status:    models.DispositionBypassed,
			Scope:     "bypass",
			Reference: cidr,
			UpdatedAt: now,
		}
	}
	if containsCIDR(extractDirectionAllowlist(selected), sourceIP) {
		return models.LogDisposition{
			SourceIP:  sourceIP,
			Port:      port,
			Direction: direction,
			Status:    models.DispositionAllowlisted,
			Scope:     "allowlist",
			Reference: cidr,
			UpdatedAt: now,
		}
	}
	if containsCIDR(selected.BlockedCIDRs, sourceIP) {
		return models.LogDisposition{
			SourceIP:  sourceIP,
			Port:      port,
			Direction: direction,
			Status:    models.DispositionBlocked,
			Scope:     "blocked",
			Reference: cidr,
			UpdatedAt: now,
		}
	}
	return models.LogDisposition{
		SourceIP:  sourceIP,
		Port:      port,
		Direction: direction,
		Status:    models.DispositionOpen,
		Scope:     "open",
		UpdatedAt: now,
	}
}

func extractDirectionAllowlist(policy models.DirectionRuntime) []string {
	return append([]string(nil), policy.Allowlist...)
}
