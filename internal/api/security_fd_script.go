package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nodewall/internal/securityscan"
)

// containFDScriptFinding preserves the script, then stops only the verified
// interpreter. The interpreter binary is a shared system file and is never
// moved to quarantine. A separately discovered on-disk script is handled by
// the normal file isolation path after process actions complete.
func (h *AgentHandler) containFDScriptFinding(ctx context.Context, jobID, findingID string) {
	h.securityMu.RLock()
	var finding securityscan.Finding
	if h.securityJob != nil && h.securityJob.ID == jobID {
		for _, item := range h.securityJob.Findings {
			if item.ID == findingID && item.Source == "fd-script" {
				finding = item
				break
			}
		}
	}
	h.securityMu.RUnlock()
	if finding.ID == "" {
		return
	}
	var target string
	var termination securityscan.ProcessTermination
	err := ctx.Err()
	if err == nil {
		var sample []byte
		sample, err = securityscan.ReadFDScriptSample(finding)
		if err == nil {
			target, err = archiveFDScriptSample(finding, jobID, sample)
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		// TerminateProcessVerified rechecks the interpreter and descriptor after
		// acquiring pidfd and again before any escalation.
		termination, err = securityscan.TerminateProcessVerified(finding)
	}
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	if h.securityJob == nil || h.securityJob.ID != jobID {
		return
	}
	for index := range h.securityJob.Findings {
		item := &h.securityJob.Findings[index]
		if item.ID != findingID {
			continue
		}
		if target != "" {
			item.Quarantined = true
			item.QuarantinePath = target
			item.ContainmentEvidence = fmt.Sprintf("脚本样本 SHA-256 %s 已在终止已验证解释器前保存到隔离区", finding.SHA256)
		}
		if err != nil {
			item.TerminationError = fmt.Sprintf("descriptor script containment incomplete: %v", err)
		} else {
			item.Terminated = termination.Exited
			item.Termination = &termination
			item.Detail += "; script sample preserved and verified interpreter exited; check any remaining on-disk source separately"
		}
		break
	}
	_ = h.archiveCurrentScan()
}

func archiveFDScriptSample(finding securityscan.Finding, scanID string, sample []byte) (string, error) {
	sum := sha256.Sum256(sample)
	if finding.ID == "" || scanID == "" || int64(len(sample)) != finding.Size || !strings.EqualFold(hex.EncodeToString(sum[:]), finding.SHA256) {
		return "", errors.New("descriptor script sample does not match the scan")
	}
	dir := filepath.Join(securityQuarantineRoot, scanID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".nodewall-fd-sample-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(sample); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	target := filepath.Join(dir, finding.ID+"-fd-script")
	if err := os.Link(tmpPath, target); err != nil {
		return "", fmt.Errorf("store descriptor script sample: %w", err)
	}
	metadata := quarantineMetadata{
		OriginalPath: finding.Path, Restorable: false, ScanID: scanID, FindingID: finding.ID,
		Rule: finding.Rule, Severity: finding.Severity, SHA256: finding.SHA256,
		QuarantineMode: "0600", Source: "fd-script-sample", DetectedAt: finding.DetectedAt,
		QuarantinedAt: time.Now().UTC(),
	}
	metadataPath := quarantineMetadataPath(target)
	metadataFile, err := os.OpenFile(metadataPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		// A sample without its record must not be reported as quarantined or
		// authorize terminating the interpreter. The original descriptor is untouched.
		_ = os.Remove(target)
		return "", fmt.Errorf("create descriptor sample metadata: %w", err)
	}
	_, err = metadataFile.Write(marshalQuarantineMetadata(metadata))
	if err == nil {
		err = metadataFile.Sync()
	}
	if closeErr := metadataFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(target)
		_ = os.Remove(metadataPath)
		return "", fmt.Errorf("write descriptor sample metadata: %w", err)
	}
	return target, nil
}
