// Package sshpolicy applies reversible SSH file-transfer restrictions.
//
// SSH transfer controls cannot be enforced by XDP: SFTP and SCP are carried
// inside an already-authenticated, encrypted SSH connection. This package
// manages only a NodeWall-owned sshd drop-in and helper scripts, validates the
// resulting configuration before reload, and restores the previous Subsystem
// line when the policy is disabled.
package sshpolicy

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nodewall/internal/filemeta"
	"nodewall/internal/models"
)

const (
	defaultConfigPath  = "/etc/ssh/sshd_config"
	defaultDropInPath  = "/etc/ssh/sshd_config.d/99-nodewall-transfer.conf"
	defaultWrapperPath = "/usr/local/sbin/nodewall-ssh-transfer-policy"
	defaultSFTPPath    = "/usr/local/sbin/nodewall-sftp-deny"
	defaultStatePath   = "/etc/nodewall/ssh-transfer-state.json"
	defaultActivityLog = "/var/log/nodewall/ssh-activity.log"
)

// CommandRunner is injectable so policy changes can be tested without
// touching a host SSH daemon.
type CommandRunner func(context.Context, string, ...string) ([]byte, error)

type state struct {
	OriginalSubsystem string `json:"original_subsystem"`
}

// Applier owns the files and commands used to apply a transfer policy.
type Applier struct {
	ConfigPath      string
	DropInPath      string
	WrapperPath     string
	SFTPPath        string
	StatePath       string
	ActivityLogPath string
	ScannerPath     string
	Run             CommandRunner
}

// New returns an applier for a normal Linux OpenSSH installation.
func New() *Applier {
	scannerPath := "/opt/nodewall/bin/nodewall"
	if executable, err := os.Executable(); err == nil && filepath.Base(executable) == "nodewall" {
		scannerPath = executable
	}
	return &Applier{
		ConfigPath:      defaultConfigPath,
		DropInPath:      defaultDropInPath,
		WrapperPath:     defaultWrapperPath,
		SFTPPath:        defaultSFTPPath,
		StatePath:       defaultStatePath,
		ActivityLogPath: defaultActivityLog,
		ScannerPath:     scannerPath,
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
	}
}

// NewWithPaths creates an applier with explicit paths for isolated tests.
func NewWithPaths(configPath, dropInPath, wrapperPath, sftpPath, statePath string, run CommandRunner) *Applier {
	return &Applier{
		ConfigPath: configPath, DropInPath: dropInPath, WrapperPath: wrapperPath,
		SFTPPath: sftpPath, StatePath: statePath,
		ActivityLogPath: filepath.Join(filepath.Dir(wrapperPath), "ssh-activity.log"),
		ScannerPath:     "nodewall", Run: run,
	}
}

// Apply validates and reloads the requested transfer policy. If validation or
// reload fails, all files changed by this call are restored before returning.
func (a *Applier) Apply(ctx context.Context, policy models.SSHTransferPolicy) (resultErr error) {
	if a == nil {
		return errors.New("SSH transfer policy applier is not configured")
	}
	if a.Run == nil {
		return errors.New("SSH transfer policy command runner is not configured")
	}
	if strings.TrimSpace(a.ConfigPath) == "" || strings.TrimSpace(a.DropInPath) == "" {
		return errors.New("SSH transfer policy paths are incomplete")
	}
	if (policy.ScanUploads || policy.AuditTransfers || policy.AuditCommands || policy.AuditSessions || policy.BlockSCP || policy.BlockSFTP) && filepath.IsAbs(a.ScannerPath) {
		info, err := os.Stat(a.ScannerPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return errors.New("NodeWall unified SSH helper is missing or not executable; install bin/nodewall before enabling SSH controls")
		}
		// Never probe a standalone agent binary: it ignores CLI arguments and
		// could start another dataplane process instead of validating the helper.
		build, err := buildinfo.ReadFile(a.ScannerPath)
		if err != nil || build.Path != "nodewall/cmd/nodewall" {
			return errors.New("SSH controls require the unified NodeWall binary built from ./cmd/nodewall")
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		output, err := a.Run(probeCtx, a.ScannerPath, "ssh-helper-probe")
		cancel()
		if err != nil || strings.TrimSpace(string(output)) != "nodewall-ssh-helper-v1" {
			return errors.New("NodeWall SSH helper version is incompatible; update the unified binary before applying SSH controls")
		}
	}

	configBefore, err := os.ReadFile(a.ConfigPath)
	if err != nil {
		return fmt.Errorf("read sshd config: %w", err)
	}
	configInfo, err := os.Stat(a.ConfigPath)
	if err != nil {
		return err
	}
	dropBefore, dropExists, err := readOptional(a.DropInPath)
	if err != nil {
		return fmt.Errorf("read NodeWall sshd drop-in: %w", err)
	}
	wrapperBefore, wrapperExists, err := readOptional(a.WrapperPath)
	if err != nil {
		return fmt.Errorf("read SSH transfer wrapper: %w", err)
	}
	sftpBefore, sftpExists, err := readOptional(a.SFTPPath)
	if err != nil {
		return fmt.Errorf("read SFTP policy helper: %w", err)
	}
	stateBefore, stateExists, err := readOptional(a.StatePath)
	if err != nil {
		return fmt.Errorf("read SSH transfer state: %w", err)
	}

	var rollbackErr error
	rolledBack := false
	reloadAttempted := false
	rollback := func() {
		if rolledBack {
			return
		}
		rolledBack = true
		// A failed reload can still have reached sshd. Keep newly installed
		// helpers until the old configuration is positively reloaded.
		if wrapperExists || !reloadAttempted {
			rollbackErr = errors.Join(rollbackErr, restoreFile(a.WrapperPath, wrapperBefore, wrapperExists, 0o755))
		}
		if sftpExists || !reloadAttempted {
			rollbackErr = errors.Join(rollbackErr, restoreFile(a.SFTPPath, sftpBefore, sftpExists, 0o755))
		}
		rollbackErr = errors.Join(rollbackErr, restoreFile(a.StatePath, stateBefore, stateExists, 0o600), restoreFile(a.DropInPath, dropBefore, dropExists, 0o644), restoreFile(a.ConfigPath, configBefore, true, configInfo.Mode().Perm()))
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackErr) }()
	recoverReload := func(cause error) error {
		rollback()
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		err := reloadSSHD(recoveryCtx, a.Run)
		if err == nil {
			if !wrapperExists {
				err = errors.Join(err, restoreFile(a.WrapperPath, nil, false, 0o755))
			}
			if !sftpExists {
				err = errors.Join(err, restoreFile(a.SFTPPath, nil, false, 0o755))
			}
		}
		return errors.Join(cause, err)
	}

	configAfter := configBefore
	needsWrapper := policy.BlockSFTP || policy.BlockSCP || policy.AuditTransfers || policy.AuditSessions || policy.AuditCommands || policy.ScanUploads
	if needsWrapper {
		if err := verifySSHDScopes(a.ConfigPath, configBefore, a.WrapperPath, a.DropInPath); err != nil {
			return err
		}
	}
	configAfter, err = managedForceCommand(configAfter, a.WrapperPath, needsWrapper)
	if err != nil {
		return err
	}
	if policy.BlockSFTP {
		configAfter, err = enableSFTPBlock(configAfter, a.SFTPPath)
		if err != nil {
			return err
		}
	} else {
		configAfter, err = restoreSFTPBlock(configAfter, a.SFTPPath, a.StatePath)
		if err != nil {
			return err
		}
	}

	if needsWrapper {
		// Keep the active subsystem command in the wrapper so a standard
		// logging-only sftp-server configuration can be guarded without
		// accepting arbitrary command arguments at runtime.
		sftpCommand := configuredSFTPCommand(configBefore)
		if sftpCommand == "" {
			sftpCommand = "internal-sftp"
		}
		// The global directive lives in the main file: older sshd versions and
		// installations without Include must not silently ignore this policy.
		if err := writeAtomic(a.DropInPath, []byte("# Managed by NodeWall. ForceCommand is set in sshd_config.\n"), 0o644); err != nil {
			rollback()
			return fmt.Errorf("write NodeWall sshd drop-in: %w", err)
		}
		if err := writeAtomic(a.WrapperPath, []byte(wrapperScript(a.WrapperPath, policy, a.ActivityLogPath, a.ScannerPath, a.SFTPPath, sftpCommand)), 0o755); err != nil {
			rollback()
			return fmt.Errorf("write SSH transfer wrapper: %w", err)
		}
	} else {
		if err := restoreFile(a.DropInPath, nil, false, 0o644); err != nil {
			rollback()
			return fmt.Errorf("remove NodeWall sshd drop-in: %w", err)
		}
	}

	if policy.BlockSFTP {
		if err := writeAtomic(a.SFTPPath, []byte(sftpDenyScript(a.SFTPPath)), 0o755); err != nil {
			rollback()
			return fmt.Errorf("write SFTP policy helper: %w", err)
		}
	}

	if policy.BlockSFTP {
		data := stateBefore
		if !stateExists {
			original := originalSubsystem(configBefore, a.SFTPPath)
			fields := activeFields(original)
			if len(fields) >= 3 && fields[2] == a.SFTPPath {
				rollback()
				return errors.New("original SFTP subsystem state is missing; restore its configuration before updating SSH controls")
			}
			data, _ = json.Marshal(state{OriginalSubsystem: original})
		}
		if err := writeAtomic(a.StatePath, data, 0o600); err != nil {
			rollback()
			return fmt.Errorf("write SSH transfer state: %w", err)
		}
	}
	// Install helper files before publishing references to them. When disabling,
	// keep them available until sshd has reloaded the restored configuration.
	if !bytesEqual(configAfter, configBefore) {
		if err := writeAtomic(a.ConfigPath, configAfter, configInfo.Mode().Perm()); err != nil {
			rollback()
			return fmt.Errorf("write sshd config: %w", err)
		}
	}

	if _, err := a.Run(ctx, "sshd", "-t", "-f", a.ConfigPath); err != nil {
		rollback()
		return fmt.Errorf("sshd configuration check failed: %w", err)
	}
	if needsWrapper {
		output, err := a.Run(ctx, "sshd", "-T", "-f", a.ConfigPath)
		if err != nil || !effectiveForceCommand(output, a.WrapperPath) {
			rollback()
			return fmt.Errorf("NodeWall ForceCommand is not effective; check conflicting Match/Include configuration: %w", errors.Join(err, errors.New("effective sshd configuration mismatch")))
		}
		if !policy.BlockSFTP && (policy.ScanUploads || policy.AuditTransfers) && !supportedSFTPSubsystem(output) {
			rollback()
			return errors.New("SFTP subsystem has custom arguments or is missing; NodeWall refuses to weaken existing restrictions")
		}
	}
	reloadAttempted = true
	if err := reloadSSHD(ctx, a.Run); err != nil {
		return recoverReload(fmt.Errorf("reload sshd failed: %w", err))
	}
	var cleanupErr error
	if !needsWrapper {
		cleanupErr = restoreFile(a.WrapperPath, nil, false, 0o755)
	}
	if !policy.BlockSFTP {
		cleanupErr = errors.Join(cleanupErr, restoreFile(a.SFTPPath, nil, false, 0o755), restoreFile(a.StatePath, nil, false, 0o600))
	}
	if cleanupErr != nil {
		return recoverReload(fmt.Errorf("clean disabled SSH policy helpers: %w", cleanupErr))
	}
	return nil
}

func reloadSSHD(ctx context.Context, run CommandRunner) error {
	if _, err := run(ctx, "systemctl", "reload", "sshd"); err == nil {
		return nil
	}
	if _, err := run(ctx, "systemctl", "reload", "ssh"); err == nil {
		return nil
	} else {
		return err
	}
}

func enableSFTPBlock(data []byte, helperPath string) ([]byte, error) {
	lines := strings.SplitAfter(string(data), "\n")
	for i, line := range lines {
		fields := activeFields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "subsystem") && strings.EqualFold(fields[1], "sftp") {
			newline := "\n"
			if strings.HasSuffix(line, "\r\n") {
				newline = "\r\n"
			} else if !strings.HasSuffix(line, "\n") {
				newline = ""
			}
			lines[i] = "Subsystem sftp " + helperPath + newline
			return []byte(strings.Join(lines, "")), nil
		}
	}
	return []byte(strings.TrimRight(string(data), "\n") + "\nSubsystem sftp " + helperPath + "\n"), nil
}

func restoreSFTPBlock(data []byte, helperPath, statePath string) ([]byte, error) {
	content, exists, err := readOptional(statePath)
	if err != nil {
		return nil, err
	}
	if !exists {
		for _, line := range strings.Split(string(data), "\n") {
			fields := activeFields(line)
			if len(fields) >= 3 && strings.EqualFold(fields[0], "subsystem") && strings.EqualFold(fields[1], "sftp") && fields[2] == helperPath {
				return nil, errors.New("cannot remove the SFTP helper without its original subsystem state; restore the saved configuration first")
			}
		}
		return data, nil
	}
	var saved state
	if err := json.Unmarshal(content, &saved); err != nil {
		return nil, fmt.Errorf("decode SSH transfer state: %w", err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	for i, line := range lines {
		fields := activeFields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], "subsystem") && strings.EqualFold(fields[1], "sftp") && fields[2] == helperPath {
			if saved.OriginalSubsystem == "" {
				lines = append(lines[:i], lines[i+1:]...)
				return []byte(strings.Join(lines, "")), nil
			}
			newline := "\n"
			if strings.HasSuffix(line, "\r\n") {
				newline = "\r\n"
			}
			lines[i] = saved.OriginalSubsystem + newline
			return []byte(strings.Join(lines, "")), nil
		}
	}
	return data, nil
}

func originalSubsystem(data []byte, helperPath string) string {
	for _, line := range strings.SplitAfter(string(data), "\n") {
		fields := activeFields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], "subsystem") && strings.EqualFold(fields[1], "sftp") {
			return strings.TrimRight(line, "\r\n")
		}
	}
	return ""
}

func activeFields(line string) []string {
	trimmed := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
	if trimmed == "" {
		return nil
	}
	return strings.Fields(trimmed)
}

func forceCommandConfig(wrapperPath string) string {
	return "# Managed by NodeWall. Do not edit.\nForceCommand " + wrapperPath + "\n"
}

const forceBegin = "# BEGIN NODEWALL SSH POLICY\n"
const forceEnd = "# END NODEWALL SSH POLICY\n"

func managedForceCommand(data []byte, wrapper string, enabled bool) ([]byte, error) {
	content := string(data)
	if begin := strings.Index(content, forceBegin); begin >= 0 {
		end := strings.Index(content[begin:], forceEnd)
		if end < 0 {
			return nil, errors.New("NodeWall sshd policy block is incomplete; restore the config before applying")
		}
		content = content[:begin] + content[begin+end+len(forceEnd):]
	}
	if !enabled {
		return []byte(content), nil
	}
	if !filepath.IsAbs(wrapper) || strings.ContainsAny(wrapper, " \t\r\n") {
		return nil, errors.New("SSH wrapper path must be absolute and contain no whitespace")
	}
	for _, line := range strings.Split(content, "\n") {
		fields := activeFields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], "ForceCommand") {
			return nil, errors.New("existing ForceCommand conflicts with NodeWall; preserve that policy before enabling SSH controls")
		}
	}
	return []byte(forceBegin + forceCommandConfig(wrapper) + forceEnd + content), nil
}

func effectiveForceCommand(output []byte, wrapper string) bool {
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && strings.EqualFold(key, "forcecommand") && strings.TrimSpace(value) == wrapper {
			return true
		}
	}
	return false
}

func supportedSFTPSubsystem(output []byte) bool {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "subsystem" && fields[1] == "sftp" {
			command := fields[2:]
			if command[0] == "internal-sftp" || filepath.Base(command[0]) == "sftp-server" {
				return supportedSFTPLoggingArgs(command[1:])
			}
		}
	}
	return false
}

// supportedSFTPLoggingArgs accepts only OpenSSH's logging flags. Other
// subsystem arguments can change the SFTP server's access semantics and must
// remain rejected because the NodeWall guard cannot reproduce them.
func supportedSFTPLoggingArgs(args []string) bool {
	for index := 0; index < len(args); {
		switch args[index] {
		case "-f", "-l":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "-") {
				return false
			}
			index += 2
		default:
			return false
		}
	}
	return true
}

func configuredSFTPCommand(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		fields := activeFields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], "subsystem") && strings.EqualFold(fields[1], "sftp") {
			return strings.Join(fields[2:], " ")
		}
	}
	return ""
}

func sftpDenyScript(path string) string {
	return "#!/bin/sh\nlogger -t nodewall-ssh-transfer \\\"type=sftp action=blocked helper=" + path + " user=${USER:-unknown} source=${SSH_CONNECTION%% *}\\\" 2>/dev/null || true\nprintf '%s\\n' 'SFTP transfer is blocked by NodeWall' >&2\nexit 126\n"
}

func wrapperScript(_ string, policy models.SSHTransferPolicy, activityLogPath, scannerPath string, sftpHelper ...string) string {
	blockedHelper := defaultSFTPPath
	allowedSFTPCommand := "internal-sftp"
	if len(sftpHelper) > 0 {
		blockedHelper = sftpHelper[0]
	}
	if len(sftpHelper) > 1 && strings.TrimSpace(sftpHelper[1]) != "" {
		allowedSFTPCommand = strings.TrimSpace(sftpHelper[1])
	}
	flag := func(value bool) string {
		if value {
			return "1"
		}
		return "0"
	}
	return fmt.Sprintf(`#!/bin/sh
set -u
block_sftp=%q
block_scp=%q
audit_transfers=%q
audit_sessions=%q
audit_commands=%q
scan_uploads=%q
activity_log=%s
scanner_path=%s
blocked_sftp_helper=%s
allowed_sftp_command=%s
original=${SSH_ORIGINAL_COMMAND:-}
NODEWALL_SSH_SESSION_ID="nw-$$-$(date +%%s)"
export NODEWALL_SSH_SESSION_ID
record() {
  event_name=$1
  action_name=${2:-}
  transfer_name=${3:-}
  scan_name=${4:-}
	finding_count=${5:-0}
	file_count=${6:-0}
	path_name=${7:-}
	command_name=${8:-}
  printf '%%s' "$command_name" | "$scanner_path" ssh-activity --activity-log="$activity_log" \
    --event="$event_name" --action="$action_name" --transfer="$transfer_name" --scan-status="$scan_name" \
    --files="$file_count" --findings="$finding_count" --path="$path_name" --exit-code="${exit_code:-0}" >/dev/null || true
}

kind=""
case "$original" in
  "$blocked_sftp_helper") kind="sftp" ;;
  internal-sftp|internal-sftp\ *|*/sftp-server*|sftp-server*) kind="sftp" ;;
  scp|scp\ *|*/scp\ *|*/scp) kind="scp" ;;
esac
if [ "$audit_sessions" = "1" ] || [ "$audit_commands" = "1" ] || [ "$audit_transfers" = "1" ] || [ "$scan_uploads" = "1" ]; then
  record session_open connected "" "" 0 0 "" ""
fi
exit_code=0
if [ "$kind" = "sftp" ] && [ "$block_sftp" = "1" ]; then
  record transfer blocked sftp blocked 0 0 "" "$original"
  echo "SFTP transfer is blocked by NodeWall" >&2
  exit_code=126
elif [ "$kind" = "scp" ] && { [ "$block_scp" = "1" ] || [ "$scan_uploads" = "1" ]; }; then
  record transfer blocked scp blocked 0 0 "" "$original"
  echo "Legacy SCP is blocked by NodeWall; use SFTP for checked file transfer" >&2
  exit_code=126
elif [ "$kind" = "sftp" ]; then
  transfer_kind=sftp
  if [ "$audit_transfers" = "1" ] || [ "$scan_uploads" = "1" ]; then
    record transfer started sftp pending 0 0 "" "$original"
  fi
  if [ "$scan_uploads" = "1" ] || [ "$audit_transfers" = "1" ]; then
    case "$original" in
      "$allowed_sftp_command")
        "$scanner_path" sftp-guard --scan-uploads="$scan_uploads" --audit-transfers="$audit_transfers" --activity-log="$activity_log"
        exit_code=$?
        ;;
      *)
        echo "NodeWall cannot safely preserve custom SFTP arguments; this session was refused" >&2
        exit_code=126
        ;;
    esac
  elif [ "$original" = "internal-sftp" ]; then
    sftp_server=""
    for candidate in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server; do
      if [ -x "$candidate" ]; then sftp_server=$candidate; break; fi
    done
    if [ -n "$sftp_server" ]; then
      "$sftp_server"
      exit_code=$?
    else
      echo "SFTP server binary was not found by NodeWall" >&2
      exit_code=127
    fi
  else
    /bin/sh -c "$original"
    exit_code=$?
  fi
elif [ "$kind" = "scp" ]; then
  transfer_kind=scp
  if [ "$audit_transfers" = "1" ] || [ "$scan_uploads" = "1" ]; then
    record transfer started scp pending 0 0 "" "$original"
  fi
  /bin/sh -c "$original"
  exit_code=$?
elif [ -n "$original" ]; then
  /bin/sh -c "$original"
  exit_code=$?
  if [ "$audit_commands" = "1" ]; then
    record command executed none none 0 0 "" "$original"
  fi
elif [ -n "${SSH_TTY:-}" ]; then
  if [ "$audit_commands" = "1" ]; then
    "$scanner_path" ssh-shell --interactive=true --activity-log="$activity_log"
  else
    "${SHELL:-/bin/sh}" -l
  fi
  exit_code=$?
else
  if [ "$audit_commands" = "1" ]; then
    "$scanner_path" ssh-shell --interactive=false --activity-log="$activity_log"
  else
    "${SHELL:-/bin/sh}" -s
  fi
  exit_code=$?
fi
if [ "$audit_sessions" = "1" ] || [ "$audit_commands" = "1" ] || [ "$audit_transfers" = "1" ] || [ "$scan_uploads" = "1" ]; then
  record session_close closed "$kind" "" 0 0 "" ""
fi
exit "$exit_code"
`, flag(policy.BlockSFTP), flag(policy.BlockSCP), flag(policy.AuditTransfers), flag(policy.AuditSessions), flag(policy.AuditCommands), flag(policy.ScanUploads), shellQuote(activityLogPath), shellQuote(scannerPath), shellQuote(blockedHelper), shellQuote(allowedSFTPCommand))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func readOptional(path string) ([]byte, bool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, false, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return data, err == nil, err
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodewall-ssh-policy-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if source, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0); err == nil {
		info, statErr := source.Stat()
		if statErr != nil {
			source.Close()
			tmp.Close()
			return statErr
		}
		if !info.Mode().IsRegular() {
			source.Close()
			tmp.Close()
			return errors.New("refusing to replace a non-regular SSH policy file")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			current, currentErr := tmp.Stat()
			if currentErr != nil {
				source.Close()
				tmp.Close()
				return currentErr
			}
			if own, ok := current.Sys().(*syscall.Stat_t); ok && (own.Uid != stat.Uid || own.Gid != stat.Gid) {
				if err := tmp.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
					source.Close()
					tmp.Close()
					return err
				}
			}
		}
		copyErr := filemeta.CopyAccessAttrs(source, tmp)
		source.Close()
		if copyErr != nil {
			tmp.Close()
			return copyErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func restoreFile(path string, data []byte, exists bool, mode os.FileMode) error {
	if exists {
		return writeAtomic(path, data, mode)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
