//go:build linux

package securityscan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxProcModulesBytes = 4 << 20

// A live loadable module has an initstate file in sysfs. Built-in modules do
// not, so they must not be considered hidden just because /proc/modules omits
// them. Checking both views twice avoids reporting normal load/unload races.
func collectHiddenKernelModuleFindings(ctx context.Context, limit int) ([]Finding, error) {
	return scanHiddenKernelModules(ctx, "/sys/module", "/proc/modules", limit)
}

func scanHiddenKernelModules(ctx context.Context, sysRoot, procModules string, limit int) ([]Finding, error) {
	if limit <= 0 {
		return nil, nil
	}
	first, err := readLoadedModuleNames(procModules)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(sysRoot)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		name string
		info os.FileInfo
	}
	candidates := make([]candidate, 0)
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !entry.IsDir() || first[entry.Name()] {
			continue
		}
		dir := filepath.Join(sysRoot, entry.Name())
		if readModuleAttribute(dir, "initstate") != "live" {
			continue
		}
		if info, statErr := os.Stat(dir); statErr == nil {
			candidates = append(candidates, candidate{name: entry.Name(), info: info})
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	timer := time.NewTimer(75 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	second, err := readLoadedModuleNames(procModules)
	if err != nil {
		return nil, err
	}
	findings := make([]Finding, 0, min(limit, len(candidates)))
	for _, item := range candidates {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		dir := filepath.Join(sysRoot, item.name)
		info, statErr := os.Stat(dir)
		if second[item.name] || statErr != nil || !os.SameFile(item.info, info) || readModuleAttribute(dir, "initstate") != "live" {
			continue
		}
		taint := readModuleAttribute(dir, "taint")
		version := readModuleAttribute(dir, "srcversion")
		modulePaths := resolveKernelModulePaths(ctx, item.name)
		modulePath := ""
		moduleSize, moduleHash, moduleMode := int64(0), "", ""
		for _, candidatePath := range modulePaths {
			size, hash, mode := kernelModuleIdentity(candidatePath)
			if hash == "" {
				continue
			}
			modulePath, moduleSize, moduleHash, moduleMode = candidatePath, size, hash, mode
			break
		}
		related := []string{"/proc/modules"}
		for _, candidatePath := range modulePaths {
			if candidatePath == "" || modulePathContains(related, candidatePath) {
				continue
			}
			related = append(related, candidatePath)
		}
		detail := fmt.Sprintf("live kernel module %s is present in sysfs but absent from two /proc/modules snapshots; taint=%s; srcversion=%s. /sys/module/%s is a virtual kernel path; isolation targets the verified module file when modinfo can locate it", item.name, taint, version, item.name)
		sum := sha256.Sum256([]byte("hidden-kernel-module|" + item.name))
		findings = append(findings, Finding{
			ID: "k-" + hex.EncodeToString(sum[:8]), Path: dir, Rule: "hidden-kernel-module",
			Severity: SeverityHigh, Detail: detail, DetectedAt: time.Now().UTC(), Source: "integrity",
			Size: moduleSize, SHA256: moduleHash, Mode: moduleMode,
			ModuleName: item.name, ModulePath: modulePath,
			SystemFile: true, RelatedPaths: related, Quarantinable: modulePath != "" && !isSystemPackageFile(modulePath),
			ContainmentBlockedReason: "当前模块仍在内核内存中；/sys/module 只是虚拟视图，需定位并隔离真实模块文件，找不到实体文件时从可信环境恢复",
		})
		if len(findings) == limit {
			break
		}
	}
	return findings, nil
}

func kernelModuleIdentity(path string) (int64, string, string) {
	if path == "" {
		return 0, "", ""
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, "", ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 {
		return 0, "", ""
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 256<<20+1)); err != nil {
		return 0, "", ""
	}
	return info.Size(), hex.EncodeToString(hash.Sum(nil)), info.Mode().Perm().String()
}

func resolveKernelModulePaths(ctx context.Context, name string) []string {
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return nil
		}
	}
	if name == "" {
		return nil
	}
	paths := make([]string, 0, 8)
	command := exec.CommandContext(ctx, "modinfo", "-n", name)
	if output, err := command.Output(); err == nil {
		path := strings.TrimSpace(string(output))
		if filepath.IsAbs(path) {
			if info, statErr := os.Stat(path); statErr == nil && info.Mode().IsRegular() {
				paths = append(paths, filepath.Clean(path))
			}
		}
	}
	for _, path := range searchKernelModulePaths(ctx, name, []string{
		"/tmp", "/var/tmp", "/dev/shm", "/run/user", "/lib/modules", "/usr/lib/modules", "/usr/local/lib/modules", "/var/lib/dkms",
	}) {
		if !modulePathContains(paths, path) {
			paths = append(paths, path)
		}
	}
	return paths
}

func searchKernelModulePaths(ctx context.Context, name string, roots []string) []string {
	variants := map[string]struct{}{strings.ToLower(name): {}}
	variants[strings.ToLower(strings.ReplaceAll(name, "_", "-"))] = struct{}{}
	variants[strings.ToLower(strings.ReplaceAll(name, "-", "_"))] = struct{}{}
	paths := make([]string, 0, 8)
	visited := 0
	for _, root := range roots {
		if ctx.Err() != nil || visited >= 8192 {
			break
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if ctx.Err() != nil || visited >= 8192 {
				return filepath.SkipAll
			}
			if walkErr != nil {
				return nil
			}
			visited++
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || !moduleFileNameMatches(entry.Name(), variants) {
				return nil
			}
			paths = append(paths, filepath.Clean(path))
			return nil
		})
	}
	return paths
}

func moduleFileNameMatches(base string, variants map[string]struct{}) bool {
	lower := strings.ToLower(base)
	for variant := range variants {
		if lower == variant+".ko" || lower == variant+".o" || strings.HasPrefix(lower, variant+".ko.") || strings.HasPrefix(lower, variant+"-") && strings.HasSuffix(lower, ".ko") {
			return true
		}
	}
	return false
}

func modulePathContains(paths []string, target string) bool {
	for _, path := range paths {
		if path == target {
			return true
		}
	}
	return false
}

func readLoadedModuleNames(path string) (map[string]bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read loaded kernel modules: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxProcModulesBytes+1))
	if err != nil || len(data) > maxProcModulesBytes {
		return nil, fmt.Errorf("read loaded kernel modules: incomplete or oversized list")
	}
	names := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			names[fields[0]] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse loaded kernel modules: %w", err)
	}
	return names, nil
}

func readModuleAttribute(dir, name string) string {
	file, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	defer file.Close()
	data, _ := io.ReadAll(io.LimitReader(file, 256))
	return strings.TrimSpace(string(data))
}
