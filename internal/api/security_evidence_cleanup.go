package api

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sanitizeScanReportEvidence preserves the original finding and startup-mask
// ownership before an old, non-restorable evidence archive is removed.
func sanitizeScanReportEvidence(report *securityScanReport) bool {
	changed := false
	for index := range report.Findings {
		finding := &report.Findings[index]
		path := finding.EvidencePath
		if path == "" {
			path = finding.QuarantinePath // Older releases used this field for evidence.
		}
		if !isQuarantineChild(path) {
			continue
		}
		metadata, err := readQuarantineMetadata(path)
		if err != nil || metadata.ScanID != report.ReportID || metadata.FindingID != finding.ID {
			continue
		}
		switch metadata.Source {
		case "fd-script-sample":
			if finding.EvidenceArchived && finding.EvidencePath == path {
				finding.Quarantined, finding.QuarantinePath = true, path
				finding.EvidenceArchived, finding.EvidencePath = false, ""
				if finding.ContainmentEvidence == "" && finding.SHA256 != "" {
					finding.ContainmentEvidence = fmt.Sprintf("规则 %s 命中；描述符脚本样本 SHA-256 %s 已保存", finding.Rule, finding.SHA256)
				}
				changed = true
			}
		case "scan-evidence":
			finding.EvidenceArchived, finding.EvidencePath = false, ""
			if finding.QuarantinePath == path {
				finding.Quarantined, finding.QuarantinePath = false, ""
			}
			if metadata.StartupMaskPath != "" {
				finding.StartupBlocked = true
				finding.StartupBlockPath = metadata.StartupMaskPath
				finding.StartupBlockOwned = metadata.StartupMaskOwned
			}
			switch {
			case finding.Rule == "hidden-kernel-module":
				finding.ContainmentBlockedReason = "内核模块仍在运行，sysfs 路径不是可隔离文件；请从可信环境调查并恢复"
			case finding.Source == "journal":
				finding.ContainmentBlockedReason = "日志线索本身不是可隔离文件；需要继续定位实际载荷"
			}
			changed = true
		}
	}
	return changed
}

func isQuarantineChild(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	rel, err := filepath.Rel(securityQuarantineRoot, filepath.Clean(path))
	return err == nil && rel != "." && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// cleanupArchivedScanEvidence removes only archives whose matching report has
// already been migrated and durably saved. Orphans are retained and reported:
// deleting them blindly could lose the only record of a NodeWall-owned mask.
func (h *AgentHandler) cleanupArchivedScanEvidence(root string) (removed, skipped int, err error) {
	info, err := os.Stat(root)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	if !info.IsDir() {
		return 0, 0, fmt.Errorf("quarantine root is not a directory: %s", root)
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), quarantineMetadataSuffix) {
			return nil
		}
		payload := strings.TrimSuffix(path, quarantineMetadataSuffix)
		metadata, readErr := readQuarantineMetadata(payload)
		if readErr != nil || metadata.Source != "scan-evidence" {
			return nil
		}
		if !scanReportID.MatchString(metadata.ScanID) || metadata.FindingID == "" ||
			filepath.Dir(payload) != filepath.Join(root, metadata.ScanID) ||
			filepath.Base(payload) != metadata.FindingID+"-evidence.json" {
			skipped++
			return nil
		}
		payloadInfo, statErr := os.Lstat(payload)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		if statErr == nil && !payloadInfo.Mode().IsRegular() {
			skipped++
			return nil
		}
		report, reportErr := h.readArchivedScan(metadata.ScanID)
		if reportErr != nil || !reportPreservesEvidence(report, metadata, payload) {
			skipped++
			return nil
		}
		if err := os.Remove(payload); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		removed++
		return nil
	})
	return removed, skipped, err
}

func reportPreservesEvidence(report securityScanReport, metadata quarantineMetadata, payload string) bool {
	for _, finding := range report.Findings {
		if finding.ID != metadata.FindingID || finding.Rule != metadata.Rule || finding.EvidencePath == payload || finding.QuarantinePath == payload {
			continue
		}
		if metadata.StartupMaskPath != "" && (!finding.StartupBlocked || finding.StartupBlockPath != metadata.StartupMaskPath || (metadata.StartupMaskOwned && !finding.StartupBlockOwned)) {
			return false
		}
		return finding.Source == "journal" || finding.Source == "integrity"
	}
	return false
}
