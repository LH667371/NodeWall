package api

import (
	"context"
	"path/filepath"

	"nodewall/internal/securityscan"
)

// markStartupReview records a startup chain that could not be tied to a
// movable file. It deliberately does not create a systemd mask: the scanner
// must either quarantine/delete the actual startup file or leave an explicit
// review item for the operator. A synthetic /dev/null policy is not malware
// removal and can be bypassed by changing the unit name or loader path.
func (h *AgentHandler) markStartupReview(ctx context.Context, jobID string, finding securityscan.Finding) {
	journalFinding := finding.Source == "journal" && finding.Rule == "malware-persistence"
	startupFileFinding := finding.Source == "file" && finding.Severity == securityscan.SeverityHigh &&
		(securityscan.IsSystemdUnitPath(finding.Path) || securityscan.IsTransientSystemdRuntimePath(finding.Path) || securityscan.IsOperatorManagedStartupPath(finding.Path)) &&
		isStartupPersistenceRule(finding.Rule)
	if (!journalFinding && !startupFileFinding) || finding.Severity != securityscan.SeverityHigh {
		return
	}
	candidates := finding.StartupCandidates
	if startupFileFinding && len(candidates) == 0 {
		// A high-confidence startup unit is itself the persistence evidence. Keep
		// it visible for explicit quarantine/delete instead of creating a mask.
		candidates = []string{finding.Path}
	}
	for _, unitPath := range candidates {
		clean := filepath.Clean(unitPath)
		if ctx.Err() != nil {
			return
		}
		if !securityscan.IsTransientSystemdRuntimePath(clean) && !securityscan.IsOperatorManagedStartupPath(clean) {
			continue
		}
		h.securityMu.Lock()
		index := h.journalFindingIndex(jobID, finding.ID)
		if index < 0 {
			h.securityMu.Unlock()
			return
		}
		item := &h.securityJob.Findings[index]
		duplicate := false
		for _, block := range item.StartupBlocks {
			if block.UnitPath == clean {
				duplicate = true
				break
			}
		}
		if duplicate {
			h.securityMu.Unlock()
			continue
		}
		if err := ctx.Err(); err != nil {
			h.securityMu.Unlock()
			return
		}
		item.StartupBlocks = append(item.StartupBlocks, securityscan.StartupBlock{
			UnitPath: clean,
			Status:   "review",
			Error:    "未创建启动阻断策略；请隔离或删除真实启动文件",
		})
		item.ContainmentBlockedReason = "未自动隔离：当前只定位到启动链证据，需处理真实启动文件"
		_ = h.archiveCurrentScan()
		h.securityMu.Unlock()
		h.publishSecurityScan(jobID)
	}
}

// journalFindingIndex must be called with securityMu held.
func (h *AgentHandler) journalFindingIndex(jobID, findingID string) int {
	if h.securityJob == nil || h.securityJob.ID != jobID {
		return -1
	}
	for i := range h.securityJob.Findings {
		if h.securityJob.Findings[i].ID == findingID {
			return i
		}
	}
	return -1
}
