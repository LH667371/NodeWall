package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	assets "nodewall"
	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/security"
	"nodewall/internal/securityscan"
	"nodewall/internal/sshconsole"
	"nodewall/internal/sshpolicy"
	"nodewall/internal/transporttls"
	"nodewall/internal/version"
)

const (
	defaultInstallDir = "/opt/nodewall"
	defaultConfigDir  = "/etc/nodewall"
	defaultSystemdDir = "/etc/systemd/system"
)

func Run(args []string) error {
	if len(args) == 0 {
		return runInstallWizard()
	}
	if strings.HasPrefix(args[0], "-") {
		return runInstall(args)
	}

	switch args[0] {
	case "server":
		return runServer()
	case "agent":
		return runAgent()
	case "set-password":
		return runSetPassword(args[1:])
	case "install":
		return runInstall(args[1:])
	case "preflight":
		return runPreflight(args[1:])
	case "update":
		return runUpdate(args[1:])
	case "cleanup":
		return runCleanup(args[1:])
	case "uninstall":
		return runCleanup(args[1:])
	case "web":
		return runWeb(args[1:])
	case "version":
		return runVersion()
	case "ssh-upload-check":
		return runSSHUploadCheck(args[1:])
	case "sftp-guard":
		return runSFTPGuard(args[1:])
	case "ssh-shell":
		return runSSHShell(args[1:])
	case "ssh-activity":
		return runSSHActivity(args[1:])
	case "ssh-helper-probe":
		fmt.Println("nodewall-ssh-helper-v1")
		return nil
	default:
		return fmt.Errorf("unknown command %q; usage: nodewall <server|agent|set-password|install|preflight|update|cleanup|uninstall|web|version|ssh-upload-check>", args[0])
	}
}

var (
	runServer = func() error { return fmt.Errorf("server runner not configured") }
	runAgent  = func() error { return fmt.Errorf("agent runner not configured") }
)

func SetRunners(server func() error, agent func() error) {
	runServer = server
	runAgent = agent
}

func runSetPassword(args []string) error {
	fs := flag.NewFlagSet("set-password", flag.ContinueOnError)
	file := fs.String("file", filepath.Join(defaultConfigDir, "auth.json"), "password file path")
	password := fs.String("password", "", "password value")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *password == "" {
		*password = os.Getenv("NODEWALL_ADMIN_PASSWORD")
	}
	if *password == "" {
		return fmt.Errorf("password is required via --password or NODEWALL_ADMIN_PASSWORD")
	}

	if err := security.EnsureAdminUser(*file, "admin", *password); err != nil {
		return err
	}
	fmt.Printf("admin password updated: %s\n", *file)
	return nil
}

// runSSHUploadCheck is intentionally a compact, local-only command used by
// the SSH ForceCommand wrapper after an upload session. It reports a verdict
// without returning file contents or automatically deleting anything.
func runSSHUploadCheck(args []string) error {
	fs := flag.NewFlagSet("ssh-upload-check", flag.ContinueOnError)
	path := fs.String("path", "", "uploaded file or directory to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*path) == "" {
		return fmt.Errorf("--path is required")
	}
	report, err := securityscan.New().Scan(context.Background(), *path, nil)
	if err != nil {
		return err
	}
	status := "clean"
	if len(report.Findings) > 0 {
		status = "suspicious"
	} else if report.Truncated {
		status = "partial"
	}
	fmt.Printf("status=%s files=%d findings=%d\n", status, report.FilesScanned, len(report.Findings))
	return nil
}

// configureLocalSSHAccess provisions the server-owned console key on the
// local host during install/update. The key is appended idempotently so an
// existing administrator-managed authorized_keys file is never replaced.
func configureLocalSSHAccess(keyPath string) error {
	keyPath = strings.TrimSpace(keyPath)
	if keyPath == "" {
		return fmt.Errorf("SSH key path is empty")
	}
	manager := sshconsole.NewWithKeyPath(keyPath)
	publicKey, err := manager.PublicKey()
	if err != nil {
		return err
	}
	fields := strings.Fields(publicKey)
	if len(fields) < 2 {
		return fmt.Errorf("generated SSH public key is invalid")
	}

	sshDir := "/root/.ssh"
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		return err
	}
	data, err := os.ReadFile(authorizedKeys)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if !bytes.Contains(data, []byte(fields[1])) {
		file, openErr := os.OpenFile(authorizedKeys, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if openErr != nil {
			return openErr
		}
		_, writeErr := fmt.Fprintf(file, "%s nodewall-console\n", strings.TrimSpace(publicKey))
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return os.Chmod(authorizedKeys, 0o600)
}

func runInstall(args []string) (resultErr error) {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("installation is only supported on Linux hosts")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("installation must run as root")
	}

	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	installDir := fs.String("install-dir", envOr("NODEWALL_INSTALL_DIR", defaultInstallDir), "install directory")
	configDir := fs.String("config-dir", envOr("NODEWALL_CONFIG_DIR", defaultConfigDir), "config directory")
	systemdDir := fs.String("systemd-dir", envOr("NODEWALL_SYSTEMD_DIR", defaultSystemdDir), "systemd unit directory")
	enableServices := fs.Bool("enable-services", envBool("NODEWALL_ENABLE_SERVICES", true), "enable and start services")
	installMode := fs.String("mode", envOr("NODEWALL_INSTALL_MODE", "all-in-one"), "install mode: all-in-one|server-only|agent-only")
	dataplane := fs.String("dataplane", envOr("NODEWALL_DATAPLANE", "auto"), "dataplane: auto|real|iptables")
	defaultInterface := fs.String("default-interface", envOr("NODEWALL_DEFAULT_INTERFACE", ""), "default interface")
	agentAddr := fs.String("agent-addr", envOr("NODEWALL_AGENT_ADDR", "127.0.0.1:9080"), "agent listen address")
	serverAddr := fs.String("server-addr", envOr("NODEWALL_SERVER_ADDR", "0.0.0.0:8080"), "server listen address")
	serverGRPCAddr := fs.String("server-grpc-addr", envOr("NODEWALL_SERVER_GRPC_ADDR", "0.0.0.0:50051"), "server gRPC listen address")
	serverQUICAddr := fs.String("server-quic-addr", envOr("NODEWALL_SERVER_QUIC_ADDR", "0.0.0.0:50052"), "server HTTP/3 control address")
	agentURL := fs.String("agent-url", envOr("NODEWALL_AGENT_URL", ""), "server-side agent URL")
	joinManagerURL := fs.String("manager-url", envOr("NODEWALL_MANAGER_URL", ""), "for agent-only mode: remote manager URL to register this node")
	managerGRPCAddr := fs.String("manager-grpc-addr", envOr("NODEWALL_MANAGER_GRPC_ADDR", ""), "for agent-only mode: remote manager gRPC address")
	managerQUICAddr := fs.String("manager-quic-addr", envOr("NODEWALL_MANAGER_QUIC_ADDR", ""), "for agent-only mode: remote manager HTTP/3 address")
	joinToken := fs.String("join-token", "", "short-lived enrollment credential from node management")
	managerCA := fs.String("manager-ca", "", "pinned manager certificate for enrollment")
	advertiseAddr := fs.String("advertise-addr", "", "reachable agent host:port for enrollment")
	authFile := fs.String("auth-file", envOr("NODEWALL_AUTH_FILE", filepath.Join(*configDir, "auth.json")), "auth file path")
	adminPassword := fs.String("password", envOr("NODEWALL_ADMIN_PASSWORD", ""), "initial admin password")
	allowedCIDRs := fs.String("allowed-cidrs", envOr("NODEWALL_ALLOWED_CIDRS", ""), "allowed CIDRs")
	allowedIPs := fs.String("allowed-ips", envOr("NODEWALL_ALLOWED_IPS", ""), "allowed IPs")
	allowedMACs := fs.String("allowed-macs", envOr("NODEWALL_ALLOWED_MACS", ""), "allowed MACs")
	tlsEnabled := envBool("NODEWALL_TLS_ENABLED", true)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(*installMode), "agent-only") && *joinManagerURL != "" && (*joinToken == "" || *managerCA == "" || *advertiseAddr == "") {
		return errors.New("remote enrollment requires --join-token, --manager-ca and --advertise-addr; generate a command in node management")
	}

	if *defaultInterface == "" {
		*defaultInterface = detectDefaultInterface()
	}
	nodeID := detectNodeID()
	envPath := filepath.Join(*configDir, "nodewall.env")
	if strings.TrimSpace(os.Getenv("NODEWALL_NODE_ID")) == "" {
		nodeID = readEnvValue(envPath, "NODEWALL_NODE_ID", nodeID)
	}
	if *authFile == "" {
		*authFile = filepath.Join(*configDir, "auth.json")
	}
	mode, err := normalizeInstallMode(*installMode)
	if err != nil {
		return err
	}
	reenroll := mode == "agent-only" && strings.TrimSpace(*joinManagerURL) != ""
	if _, err := os.Stat(envPath); err == nil && reenroll && readEnvValue(envPath, "NODEWALL_INSTALL_MODE", "") != "agent-only" {
		return errors.New("this host already has a manager or an unknown installation; do not register the manager as a remote agent")
	}
	previousEnv, envErr := os.ReadFile(envPath)
	if envErr != nil && !os.IsNotExist(envErr) {
		return envErr
	}
	newInstallation := os.IsNotExist(envErr)
	installStarted := false
	installComplete := false
	defer func() {
		if installComplete || !installStarted {
			return
		}
		var restoreErr error
		if envErr == nil {
			restoreErr = writeFileAtomic(envPath, previousEnv, 0o644)
		} else {
			restoreErr = os.Remove(envPath)
			if os.IsNotExist(restoreErr) {
				restoreErr = nil
			}
		}
		if restoreErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("restore installation environment: %w", restoreErr))
		}
	}()
	dataplaneMode, err := resolveInstallDataplane(*dataplane)
	if err != nil {
		return err
	}

	// Resolve the addresses before running preflight. New installations retain
	// the existing automatic port fallback, while upgrades must validate the
	// addresses already recorded in nodewall.env.
	resolvedAgentAddr := strings.TrimSpace(*agentAddr)
	resolvedServerAddr := strings.TrimSpace(*serverAddr)
	serverChanged := false
	if newInstallation {
		resolvedAgentAddr, _, err = chooseAvailableTCPAddr(resolvedAgentAddr)
		if err != nil {
			return fmt.Errorf("choose agent address: %w", err)
		}
		resolvedServerAddr, serverChanged, err = chooseAvailableTCPAddr(resolvedServerAddr)
		if err != nil {
			return fmt.Errorf("choose server address: %w", err)
		}
	} else {
		resolvedAgentAddr = readEnvValue(envPath, "NODEWALL_AGENT_ADDR", resolvedAgentAddr)
		resolvedServerAddr = readEnvValue(envPath, "NODEWALL_SERVER_ADDR", resolvedServerAddr)
	}
	resolvedServerGRPCAddr := strings.TrimSpace(*serverGRPCAddr)
	resolvedServerQUICAddr := strings.TrimSpace(*serverQUICAddr)
	if !newInstallation {
		resolvedServerGRPCAddr = readEnvValue(envPath, "NODEWALL_SERVER_GRPC_ADDR", resolvedServerGRPCAddr)
		resolvedServerQUICAddr = readEnvValue(envPath, "NODEWALL_SERVER_QUIC_ADDR", resolvedServerQUICAddr)
	}

	// Validate required inputs before touching the filesystem. The actual auth
	// file is still created below, after the complete host preflight passes.
	if mode != "agent-only" {
		if _, statErr := os.Stat(*authFile); os.IsNotExist(statErr) && strings.TrimSpace(*adminPassword) == "" {
			return fmt.Errorf("password is required via --password or NODEWALL_ADMIN_PASSWORD")
		}
	}
	bpfObject, bpfObjectErr := assets.ReadFile("bpf/gen/xdpacl_bpfel.o")
	if bpfObjectErr != nil && dataplaneMode == "real" && mode != "server-only" {
		return fmt.Errorf("read embedded BPF object: %w", bpfObjectErr)
	}
	report := checkPreflight(installPreflightOptions(
		mode,
		dataplaneMode,
		strings.TrimSpace(*dataplane),
		*enableServices,
		reenroll,
		strings.TrimSpace(*defaultInterface),
		resolvedAgentAddr,
		resolvedServerAddr,
		resolvedServerGRPCAddr,
		resolvedServerQUICAddr,
		bpfObject,
	), defaultPreflightDeps())
	report.render(os.Stdout)
	if report.failed() {
		return fmt.Errorf("preflight failed: %s", report.failureSummary())
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	installStarted = true
	if err := deployRuntimeAssets(exePath, *installDir, *configDir); err != nil {
		return err
	}

	if mode != "agent-only" {
		if _, err := os.Stat(*authFile); os.IsNotExist(err) {
			if *adminPassword == "" {
				return fmt.Errorf("password is required via --password or NODEWALL_ADMIN_PASSWORD")
			}
			if err := security.EnsureAdminUser(*authFile, "admin", *adminPassword); err != nil {
				return err
			}
		}
	}

	if newInstallation {
		resolvedAgentURL := *agentURL
		if strings.TrimSpace(resolvedAgentURL) == "" {
			scheme := "https"
			if !tlsEnabled {
				scheme = "http"
			}
			resolvedAgentURL = scheme + "://" + localHTTPAddr(resolvedAgentAddr)
		}
		tlsCertFile := filepath.Join(*configDir, "tls", "nodewall.crt")
		tlsKeyFile := filepath.Join(*configDir, "tls", "nodewall.key")
		strictTLS := mode == "all-in-one"
		tlsCAFile := ""
		if strictTLS {
			tlsCAFile = tlsCertFile
		}
		sshKeyPath := filepath.Join(*configDir, "ssh", "id_ed25519")
		content := fmt.Sprintf("NODEWALL_NODE_ID=%s\nNODEWALL_AGENT_ADDR=%s\nNODEWALL_SERVER_ADDR=%s\nNODEWALL_AGENT_URL=%s\nNODEWALL_BPF_OBJECT=%s\nNODEWALL_WEB_DIR=%s\nNODEWALL_DATAPLANE=%s\nNODEWALL_IPTABLES_RECONCILE_INTERVAL=5s\nNODEWALL_AGENT_STATE=%s\nNODEWALL_SERVER_STATE=%s\nNODEWALL_DROP_LOG_STATE=%s\nNODEWALL_LOG_DIR=%s\nNODEWALL_DROP_LOG_ENABLED=true\nNODEWALL_DROP_LOG_RETENTION_DAYS=7\nNODEWALL_DROP_LOG_FLUSH_INTERVAL=30s\nNODEWALL_DEFAULT_INTERFACE=%s\nNODEWALL_AUTH_ENABLED=true\nNODEWALL_AUTH_FILE=%s\nNODEWALL_AUTH_SETTINGS_FILE=%s\nNODEWALL_ALLOWED_CIDRS=%s\nNODEWALL_ALLOWED_IPS=%s\nNODEWALL_ALLOWED_MACS=%s\nNODEWALL_WEB_ACCESS=public\nNODEWALL_SSH_KEY=%s\nNODEWALL_TLS_ENABLED=%t\nNODEWALL_TLS_CERT=%s\nNODEWALL_TLS_KEY=%s\nNODEWALL_TLS_CA=%s\nNODEWALL_TLS_INSECURE_SKIP_VERIFY=%t\n",
			nodeID,
			resolvedAgentAddr,
			resolvedServerAddr,
			resolvedAgentURL,
			filepath.Join(*installDir, "bpf", "gen", "xdpacl_bpfel.o"),
			filepath.Join(*installDir, "web", "dist"),
			dataplaneMode,
			filepath.Join(*configDir, "agent-state.json"),
			filepath.Join(*configDir, "server-state.json"),
			filepath.Join(*configDir, "drop-log-state.json"),
			"/var/lib/nodewall/logs",
			*defaultInterface,
			*authFile,
			filepath.Join(*configDir, "auth-settings.json"),
			*allowedCIDRs,
			*allowedIPs,
			*allowedMACs,
			sshKeyPath,
			tlsEnabled,
			tlsCertFile,
			tlsKeyFile,
			tlsCAFile,
			!strictTLS,
		)
		resolvedManagerGRPC := strings.TrimSpace(*managerGRPCAddr)
		if resolvedManagerGRPC == "" && (mode == "all-in-one" || mode == "server-only") {
			resolvedManagerGRPC = "127.0.0.1:50051"
		}
		resolvedManagerQUIC := strings.TrimSpace(*managerQUICAddr)
		if resolvedManagerQUIC == "" && (mode == "all-in-one" || mode == "server-only") {
			resolvedManagerQUIC = "127.0.0.1:50052"
		}
		content += fmt.Sprintf("NODEWALL_SERVER_GRPC_ADDR=%s\nNODEWALL_SERVER_QUIC_ADDR=%s\nNODEWALL_INSTALL_MODE=%s\nNODEWALL_MANAGER_URL=%s\nNODEWALL_MANAGER_GRPC_ADDR=%s\nNODEWALL_MANAGER_QUIC_ADDR=%s\nNODEWALL_AGENT_HTTP_ADDR=%s\n",
			resolvedServerGRPCAddr,
			resolvedServerQUICAddr,
			mode,
			strings.TrimSpace(*joinManagerURL),
			resolvedManagerGRPC,
			resolvedManagerQUIC,
			resolvedAgentAddr,
		)
		if err := os.WriteFile(envPath, []byte(content), 0o644); err != nil {
			return err
		}
		if serverChanged {
			fmt.Printf("note: default web port was busy, selected %s instead\n", resolvedServerAddr)
		}
	} else {
		currentAgentAddr := readEnvValue(envPath, "NODEWALL_AGENT_ADDR", *agentAddr)
		currentServerAddr := readEnvValue(envPath, "NODEWALL_SERVER_ADDR", *serverAddr)
		if err := ensureTCPAddrAvailable(currentAgentAddr, "agent"); err != nil && !reenroll {
			return fmt.Errorf("%w; update %s or rerun with --agent-addr", err, envPath)
		}
		if err := ensureTCPAddrAvailable(currentServerAddr, "server"); err != nil && !reenroll {
			return fmt.Errorf("%w; update %s or rerun with --server-addr", err, envPath)
		}
	}
	if err := upsertEnvValue(envPath, "NODEWALL_AGENT_TOKEN_FILE", filepath.Join(*configDir, "agent-token")); err != nil {
		return err
	}
	if err := upsertEnvValue(envPath, "NODEWALL_NODE_CREDENTIALS_FILE", filepath.Join(*configDir, "node-credentials.json")); err != nil {
		return err
	}
	if mode == "agent-only" && *joinManagerURL != "" {
		if !tlsEnabled {
			return errors.New("remote enrollment requires TLS")
		}
		host, _, err := net.SplitHostPort(*advertiseAddr)
		if err != nil {
			return fmt.Errorf("invalid advertised agent address: %w", err)
		}
		_, port, err := net.SplitHostPort(readEnvValue(envPath, "NODEWALL_AGENT_ADDR", *agentAddr))
		if err != nil {
			return err
		}
		*advertiseAddr = net.JoinHostPort(host, port)
		for key, value := range map[string]string{
			"NODEWALL_TLS_ENABLED":       "true",
			"NODEWALL_MANAGER_URL":       strings.TrimRight(*joinManagerURL, "/"),
			"NODEWALL_MANAGER_GRPC_ADDR": *managerGRPCAddr,
			"NODEWALL_MANAGER_QUIC_ADDR": *managerQUICAddr,
		} {
			if err := upsertEnvValue(envPath, key, value); err != nil {
				return err
			}
		}
		if err := upsertEnvValue(envPath, "NODEWALL_TLS_CA", *managerCA); err != nil {
			return err
		}
		if err := upsertEnvValue(envPath, "NODEWALL_TLS_INSECURE_SKIP_VERIFY", "false"); err != nil {
			return err
		}
		if err := upsertEnvValue(envPath, "NODEWALL_AGENT_HTTP_ADDR", *advertiseAddr); err != nil {
			return err
		}
		certFile := readEnvValue(envPath, "NODEWALL_TLS_CERT", filepath.Join(*configDir, "tls", "nodewall.crt"))
		keyFile := readEnvValue(envPath, "NODEWALL_TLS_KEY", filepath.Join(*configDir, "tls", "nodewall.key"))
		if err := transporttls.EnsureCertificate(certFile, keyFile, *advertiseAddr); err != nil {
			return err
		}
		token, err := nodeauth.LoadOrCreateToken(filepath.Join(*configDir, "agent-token"))
		if err != nil {
			return err
		}
		certificate, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}
		if err := enrollNode(*joinManagerURL, *managerCA, *joinToken, nodeauth.Credential{NodeID: nodeID, AgentURL: "https://" + *advertiseAddr, Token: token, Certificate: string(certificate)}); err != nil {
			return err
		}
	}
	if mode != "agent-only" {
		sshKeyPath := readEnvValue(envPath, "NODEWALL_SSH_KEY", filepath.Join(*configDir, "ssh", "id_ed25519"))
		if strings.TrimSpace(readEnvValue(envPath, "NODEWALL_SSH_KEY", "")) == "" {
			if err := upsertEnvValue(envPath, "NODEWALL_SSH_KEY", sshKeyPath); err != nil {
				return err
			}
		}
		if err := configureLocalSSHAccess(sshKeyPath); err != nil {
			return fmt.Errorf("configure local SSH console access: %w", err)
		}
	}

	if err := os.MkdirAll(*systemdDir, 0o755); err != nil {
		return err
	}
	if err := writeSystemdUnits(*systemdDir); err != nil {
		return err
	}

	if *enableServices {
		if err := runCommand("systemctl", "daemon-reload"); err != nil {
			return err
		}
		if mode != "server-only" {
			if err := runCommand("systemctl", "enable", "--now", "nodewall-agent.service"); err != nil {
				return err
			}
			if reenroll {
				if err := runCommand("systemctl", "restart", "nodewall-agent.service"); err != nil {
					return err
				}
			}
		} else {
			_ = runCommand("systemctl", "disable", "--now", "nodewall-agent.service")
		}
		if mode != "agent-only" {
			if err := runCommand("systemctl", "enable", "--now", "nodewall-server.service"); err != nil {
				return err
			}
		} else {
			_ = runCommand("systemctl", "disable", "--now", "nodewall-server.service")
		}
	}

	installComplete = true
	fmt.Printf("nodewall installed\nmode: %s\ninstall dir: %s\nconfig dir: %s\ndefault interface: %s\nagent addr: %s\nserver addr: %s\nauth file: %s\npassword command: %s set-password --file %s\n",
		mode,
		*installDir,
		*configDir,
		*defaultInterface,
		readEnvValue(envPath, "NODEWALL_AGENT_ADDR", *agentAddr),
		readEnvValue(envPath, "NODEWALL_SERVER_ADDR", *serverAddr),
		*authFile,
		filepath.Join(*installDir, "bin", "nodewall"),
		*authFile,
	)
	return nil
}

func detectNodeID() string {
	if value := strings.TrimSpace(os.Getenv("NODEWALL_NODE_ID")); value != "" {
		return value
	}
	if host, err := os.Hostname(); err == nil {
		if trimmed := strings.TrimSpace(host); trimmed != "" {
			return trimmed
		}
	}
	return "node-01"
}

// resolveInstallDataplane turns the install-time auto mode into a concrete
// backend. The compatibility backend is selected conservatively for kernels
// older than the enterprise 4.18 baseline, where the XDP program and its tc
// tracker cannot be relied on even if a bpftool binary happens to be present.
func resolveInstallDataplane(value string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(value))
	if mode == "legacy" || mode == "zstack-iptables" {
		mode = "iptables"
	}
	switch mode {
	case "real", "iptables":
		return mode, nil
	case "", "auto":
		if kernelNeedsIPTablesCompatibility(readKernelRelease()) {
			return "iptables", nil
		}
		return "real", nil
	default:
		return "", fmt.Errorf("invalid dataplane %q, expected auto|real|iptables", value)
	}
}

func readKernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func kernelNeedsIPTablesCompatibility(release string) bool {
	parts := strings.Split(strings.TrimSpace(release), ".")
	if len(parts) < 2 {
		return false
	}
	major, ok := parseKernelVersionPart(parts[0])
	if !ok {
		return false
	}
	minor, ok := parseKernelVersionPart(parts[1])
	if !ok {
		return false
	}
	return major < 4 || (major == 4 && minor < 18)
}

func parseKernelVersionPart(value string) (int, bool) {
	value = strings.TrimSpace(value)
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	parsed, err := strconv.Atoi(value[:end])
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func runUpdate(args []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("update is only supported on Linux hosts")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("update must run as root")
	}

	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	installDir := fs.String("install-dir", envOr("NODEWALL_INSTALL_DIR", defaultInstallDir), "install directory")
	configDir := fs.String("config-dir", envOr("NODEWALL_CONFIG_DIR", defaultConfigDir), "config directory")
	systemdDir := fs.String("systemd-dir", envOr("NODEWALL_SYSTEMD_DIR", defaultSystemdDir), "systemd unit directory")
	restartServices := fs.Bool("restart-services", envBool("NODEWALL_RESTART_SERVICES", true), "restart running services after update")
	if err := fs.Parse(args); err != nil {
		return err
	}

	envPath := filepath.Join(*configDir, "nodewall.env")
	if _, err := os.Stat(envPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("existing installation not found at %s; use install first", envPath)
		}
		return err
	}
	if err := ensureSecureTransportEnv(envPath, *configDir); err != nil {
		return err
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	if err := deployRuntimeAssets(exePath, *installDir, *configDir); err != nil {
		return err
	}
	sshKeyPath := readEnvValue(envPath, "NODEWALL_SSH_KEY", filepath.Join(*configDir, "ssh", "id_ed25519"))
	if strings.TrimSpace(readEnvValue(envPath, "NODEWALL_SSH_KEY", "")) == "" {
		if err := upsertEnvValue(envPath, "NODEWALL_SSH_KEY", sshKeyPath); err != nil {
			return err
		}
	}
	if err := configureLocalSSHAccess(sshKeyPath); err != nil {
		return fmt.Errorf("configure local SSH console access: %w", err)
	}
	if err := refreshSSHTransferPolicy(*configDir, *installDir); err != nil {
		return err
	}
	if err := os.MkdirAll(*systemdDir, 0o755); err != nil {
		return err
	}
	if err := writeSystemdUnits(*systemdDir); err != nil {
		return err
	}

	if err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if *restartServices {
		for _, unit := range []string{"nodewall-agent.service", "nodewall-server.service"} {
			if err := runCommand("systemctl", "try-restart", unit); err != nil {
				return err
			}
		}
	}

	fmt.Printf("nodewall updated\ninstall dir: %s\nconfig dir: %s\nagent addr: %s\nserver addr: %s\nservices restarted: %t\n",
		*installDir,
		*configDir,
		readEnvValue(envPath, "NODEWALL_AGENT_ADDR", "127.0.0.1:9080"),
		readEnvValue(envPath, "NODEWALL_SERVER_ADDR", "0.0.0.0:8080"),
		*restartServices,
	)
	return nil
}

// refreshSSHTransferPolicy regenerates the NodeWall-owned sshd wrapper after
// an update. The update binary may be running from /tmp, so the wrapper must
// invoke the installed binary rather than os.Executable(). This also keeps
// existing SFTP/SCP blocking and audit settings active across upgrades.
func refreshSSHTransferPolicy(configDir, installDir string) error {
	settingsPath := filepath.Join(configDir, "ssh-protection.json")
	data, err := os.ReadFile(settingsPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read SSH protection settings: %w", err)
	}
	var settings models.SSHProtectionSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("decode SSH protection settings: %w", err)
	}
	applier := sshpolicy.New()
	applier.ScannerPath = filepath.Join(installDir, "bin", "nodewall")
	if err := applier.Apply(context.Background(), settings.Transfer); err != nil {
		return fmt.Errorf("refresh SSH transfer policy: %w", err)
	}
	return nil
}

func ensureSecureTransportEnv(envPath, configDir string) error {
	for key, value := range map[string]string{"NODEWALL_AGENT_TOKEN_FILE": filepath.Join(configDir, "agent-token"), "NODEWALL_NODE_CREDENTIALS_FILE": filepath.Join(configDir, "node-credentials.json")} {
		if readEnvValue(envPath, key, "") == "" {
			if err := upsertEnvValue(envPath, key, value); err != nil {
				return err
			}
		}
	}
	tlsEnabled := strings.ToLower(strings.TrimSpace(readEnvValue(envPath, "NODEWALL_TLS_ENABLED", "")))
	if tlsEnabled == "" {
		if err := upsertEnvValue(envPath, "NODEWALL_TLS_ENABLED", "true"); err != nil {
			return err
		}
		tlsEnabled = "true"
	}
	if tlsEnabled == "false" {
		return nil
	}
	for key, value := range map[string]string{
		"NODEWALL_TLS_CERT": filepath.Join(configDir, "tls", "nodewall.crt"),
		"NODEWALL_TLS_KEY":  filepath.Join(configDir, "tls", "nodewall.key"),
	} {
		if strings.TrimSpace(readEnvValue(envPath, key, "")) == "" {
			if err := upsertEnvValue(envPath, key, value); err != nil {
				return err
			}
		}
	}
	if strings.EqualFold(strings.TrimSpace(readEnvValue(envPath, "NODEWALL_INSTALL_MODE", "")), "all-in-one") {
		if strings.TrimSpace(readEnvValue(envPath, "NODEWALL_TLS_CA", "")) == "" {
			if err := upsertEnvValue(envPath, "NODEWALL_TLS_CA", filepath.Join(configDir, "tls", "nodewall.crt")); err != nil {
				return err
			}
		}
		if err := upsertEnvValue(envPath, "NODEWALL_TLS_INSECURE_SKIP_VERIFY", "false"); err != nil {
			return err
		}
	}
	if agentURL := readEnvValue(envPath, "NODEWALL_AGENT_URL", ""); strings.HasPrefix(agentURL, "http://") {
		if err := upsertEnvValue(envPath, "NODEWALL_AGENT_URL", "https://"+strings.TrimPrefix(agentURL, "http://")); err != nil {
			return err
		}
	}
	if strings.TrimSpace(readEnvValue(envPath, "NODEWALL_SERVER_QUIC_ADDR", "")) == "" {
		if err := upsertEnvValue(envPath, "NODEWALL_SERVER_QUIC_ADDR", "0.0.0.0:50052"); err != nil {
			return err
		}
	}
	if strings.TrimSpace(readEnvValue(envPath, "NODEWALL_MANAGER_QUIC_ADDR", "")) == "" {
		managerURL := strings.TrimSpace(readEnvValue(envPath, "NODEWALL_MANAGER_URL", ""))
		managerAddr := "127.0.0.1:50052"
		if parsed, err := url.Parse(managerURL); err == nil && strings.TrimSpace(parsed.Hostname()) != "" {
			managerAddr = net.JoinHostPort(parsed.Hostname(), "50052")
		}
		if err := upsertEnvValue(envPath, "NODEWALL_MANAGER_QUIC_ADDR", managerAddr); err != nil {
			return err
		}
	}
	return nil
}

func runCleanup(args []string) error {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	installDir := fs.String("install-dir", envOr("NODEWALL_INSTALL_DIR", defaultInstallDir), "install directory")
	configDir := fs.String("config-dir", envOr("NODEWALL_CONFIG_DIR", defaultConfigDir), "config directory")
	systemdDir := fs.String("systemd-dir", envOr("NODEWALL_SYSTEMD_DIR", defaultSystemdDir), "systemd unit directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		for _, unit := range []string{"nodewall-server.service", "nodewall-agent.service"} {
			_ = runCommand("systemctl", "disable", "--now", unit)
			_ = os.Remove(filepath.Join(*systemdDir, unit))
		}
		_ = runCommand("systemctl", "daemon-reload")
	}

	_ = os.RemoveAll(*installDir)
	_ = os.RemoveAll(*configDir)
	fmt.Println("nodewall cleaned up")
	return nil
}

func runWeb(args []string) error {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	configDir := fs.String("config-dir", envOr("NODEWALL_CONFIG_DIR", defaultConfigDir), "config directory")
	port := fs.Int("port", 8080, "web listen port")
	mode := fs.String("mode", "listen", "off mode: listen|drop")
	if err := fs.Parse(args); err != nil {
		return err
	}

	action := "status"
	if extra := fs.Args(); len(extra) > 0 {
		action = strings.ToLower(strings.TrimSpace(extra[0]))
	}
	if action == "" {
		action = "status"
	}
	if action != "on" && action != "off" && action != "status" {
		return fmt.Errorf("unknown web action %q; usage: nodewall web [on|off|status] [--port 8080]", action)
	}
	modeValue := strings.ToLower(strings.TrimSpace(*mode))
	if modeValue == "" {
		modeValue = "listen"
	}
	if modeValue != "listen" && modeValue != "drop" {
		return fmt.Errorf("unknown web mode %q; expected listen|drop", modeValue)
	}

	envPath := filepath.Join(*configDir, "nodewall.env")
	current := readEnvValue(envPath, "NODEWALL_SERVER_ADDR", "")
	if current == "" {
		current = fmt.Sprintf("0.0.0.0:%d", *port)
	}
	curHost, curPort := splitAddrWithFallback(current, *port)
	if curPort <= 0 {
		curPort = *port
	}

	if action == "status" {
		scope := "external"
		if curHost == "127.0.0.1" || strings.EqualFold(curHost, "localhost") {
			scope = "localhost-only"
		}
		access := readEnvValue(envPath, "NODEWALL_WEB_ACCESS", "public")
		fmt.Printf("web status: %s\nlisten: %s\nmode: %s\n", scope, net.JoinHostPort(curHost, strconv.Itoa(curPort)), access)
		return nil
	}

	targetHost := "127.0.0.1"
	targetAccess := "local"
	if action == "on" {
		targetHost = "0.0.0.0"
		targetAccess = "public"
	} else if modeValue == "drop" {
		targetHost = "0.0.0.0"
		targetAccess = "drop"
	}
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(curPort))
	if err := upsertEnvValue(envPath, "NODEWALL_SERVER_ADDR", targetAddr); err != nil {
		return err
	}
	if err := upsertEnvValue(envPath, "NODEWALL_WEB_ACCESS", targetAccess); err != nil {
		return err
	}
	if err := runCommand("systemctl", "restart", "nodewall-server.service"); err != nil {
		return err
	}
	if targetAccess == "public" {
		if err := ensureWebPortBypass(*configDir, curPort); err != nil {
			fmt.Printf("warning: web enabled but bypass update failed: %v\n", err)
		}
	}
	fmt.Printf("web updated: %s (%s)\n", targetAddr, targetAccess)
	return nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func detectDefaultInterface() string {
	if out, err := exec.Command("ip", "-o", "route", "show", "default").Output(); err == nil {
		fields := strings.Fields(string(out))
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" && fields[i+1] != "" {
				return fields[i+1]
			}
		}
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if strings.HasPrefix(iface.Name, "docker") || strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(iface.Name, "cni") {
				continue
			}
			return iface.Name
		}
	}
	return "eth0"
}

func ensureTCPAddrAvailable(addr, label string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("%s listen address is empty", label)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("%s listen address %s is unavailable: %w", label, addr, err)
	}
	return ln.Close()
}

func chooseAvailableTCPAddr(addr string) (string, bool, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", false, err
	}
	for offset := 0; offset < 100; offset++ {
		candidate := net.JoinHostPort(host, strconv.Itoa(port+offset))
		ln, listenErr := net.Listen("tcp", candidate)
		if listenErr == nil {
			_ = ln.Close()
			return candidate, offset > 0, nil
		}
	}
	return "", false, fmt.Errorf("no free port found near %s", addr)
}

func readEnvValue(path, key, fallback string) string {
	file, err := os.Open(path)
	if err != nil {
		return fallback
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	prefix := key + "="
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return fallback
}

func upsertEnvValue(path, key, value string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	prefix := key + "="
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			lines[i] = prefix + value
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, prefix+value)
	}
	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return writeFileAtomic(path, []byte(content), 0o644)
}

func splitAddrWithFallback(addr string, fallbackPort int) (string, int) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "0.0.0.0", fallbackPort
	}
	portNum, err := strconv.Atoi(portText)
	if err != nil {
		return host, fallbackPort
	}
	return host, portNum
}

func ensureWebPortBypass(configDir string, port int) error {
	envPath := filepath.Join(configDir, "nodewall.env")
	iface := strings.TrimSpace(readEnvValue(envPath, "NODEWALL_DEFAULT_INTERFACE", ""))
	if iface == "" {
		iface = detectDefaultInterface()
	}
	if iface == "" {
		return fmt.Errorf("no interface available")
	}
	scheme := "https"
	if strings.ToLower(strings.TrimSpace(readEnvValue(envPath, "NODEWALL_TLS_ENABLED", "true"))) == "false" {
		scheme = "http"
	}
	base := scheme + "://" + localHTTPAddr(readEnvValue(envPath, "NODEWALL_AGENT_ADDR", "127.0.0.1:9080")) + "/interfaces/" + iface
	credential, err := os.ReadFile(readEnvValue(envPath, "NODEWALL_AGENT_TOKEN_FILE", filepath.Join(configDir, "agent-token")))
	if err != nil {
		return err
	}
	tlsConfig, err := transporttls.ClientConfig(readEnvValue(envPath, "NODEWALL_TLS_CERT", filepath.Join(configDir, "tls", "nodewall.crt")), "", false)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}}
	call := func(method, endpoint string, payload any) error {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		req, err := http.NewRequest(method, endpoint, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(credential)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("local agent request failed: %s", resp.Status)
		}
		return nil
	}
	if err := call(http.MethodPost, base+"/attach", map[string]any{"mode": "native"}); err != nil {
		if err := call(http.MethodPost, base+"/attach", map[string]any{"mode": "generic"}); err != nil {
			return err
		}
	}
	_ = call(http.MethodDelete, fmt.Sprintf("%s/denied-ports/%d?protocol=tcp", base, port), nil)
	if err := call(http.MethodPost, base+"/public-ports", map[string]any{"port": port, "protocol": "tcp"}); err != nil {
		return err
	}
	return nil
}

func localHTTPAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "127.0.0.1:9080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1:9080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || strings.EqualFold(host, "localhost") {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return net.JoinHostPort(host, port)
}

func deployRuntimeAssets(exePath, installDir, configDir string) error {
	if err := os.MkdirAll(filepath.Join(installDir, "bin"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(installDir, "bpf", "gen"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return err
	}
	if err := copyFile(exePath, filepath.Join(installDir, "bin", "nodewall"), 0o755); err != nil {
		return err
	}
	if err := writeEmbeddedFile("bpf/gen/xdpacl_bpfel.o", filepath.Join(installDir, "bpf", "gen", "xdpacl_bpfel.o"), 0o644); err != nil {
		return err
	}
	if err := version.WriteInstallFiles(installDir); err != nil {
		return err
	}
	return writeEmbeddedTree("web/dist", filepath.Join(installDir, "web", "dist"))
}

func runVersion() error {
	info := version.Current()
	fmt.Printf("app_version=%s\npackage_version=%s\n", info.AppVersion, info.PackageVersion)
	return nil
}

func writeSystemdUnits(systemdDir string) error {
	if err := writeEmbeddedFile("deployments/systemd/nodewall-agent.service", filepath.Join(systemdDir, "nodewall-agent.service"), 0o644); err != nil {
		return err
	}
	return writeEmbeddedFile("deployments/systemd/nodewall-server.service", filepath.Join(systemdDir, "nodewall-server.service"), 0o644)
}

func writeEmbeddedTree(srcDir, dstDir string) error {
	tree, err := assets.Sub(srcDir)
	if err != nil {
		return err
	}
	return fs.WalkDir(tree, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		target := filepath.Join(dstDir, path)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := fs.ReadFile(tree, path)
		if err != nil {
			return err
		}
		return writeFileAtomic(target, data, 0o644)
	})
}

func writeEmbeddedFile(src, dst string, mode os.FileMode) error {
	data, err := assets.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(dst, data, mode)
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(dst, data, mode)
}

func writeFileAtomic(dst string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, filepath.Base(dst)+".tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runInstallWizard() error {
	reader := bufio.NewReader(os.Stdin)

	type textPack struct {
		title           string
		langPrompt      string
		welcome         string
		passPrompt      string
		serverPrompt    string
		agentPrompt     string
		agentURLHint    string
		interfacePrompt string
		modePrompt      string
		managerPrompt   string
		confirmPrompt   string
		installing      string
		cancelled       string
		usageTail       string
	}
	zh := textPack{
		title:           "NodeWall 安装向导",
		langPrompt:      "选择语言 [1] 简体中文(默认) [2] English: ",
		welcome:         "将通过交互方式执行安装。也可以直接使用参数一键安装，例如：./nodewall install --password 'xxx'",
		passPrompt:      "请输入初始管理员密码（必填）: ",
		serverPrompt:    "请输入 Server 地址（默认 0.0.0.0:8080）: ",
		agentPrompt:     "请输入 Agent 地址（默认 127.0.0.1:9080）: ",
		agentURLHint:    "请输入 Agent URL（默认自动按 Agent 地址生成）: ",
		interfacePrompt: "请输入默认网卡（留空自动探测）: ",
		modePrompt:      "安装模式 [1] 一体化(默认) [2] 仅管理节点 [3] 加入现有管理节点: ",
		managerPrompt:   "管理节点地址（如 http://10.0.0.2:8080，agent-only 时必填）: ",
		confirmPrompt:   "确认安装？[Y/n]: ",
		installing:      "开始安装...",
		cancelled:       "已取消安装。",
		usageTail:       "可用命令：nodewall <server|agent|set-password|install|preflight|update|cleanup|uninstall|version>",
	}
	en := textPack{
		title:           "NodeWall Setup Wizard",
		langPrompt:      "Select language [1] Simplified Chinese(default) [2] English: ",
		welcome:         "Interactive install will run now. You can also do one-shot install with flags, e.g. ./nodewall install --password 'xxx'",
		passPrompt:      "Enter initial admin password (required): ",
		serverPrompt:    "Server address (default 0.0.0.0:8080): ",
		agentPrompt:     "Agent address (default 127.0.0.1:9080): ",
		agentURLHint:    "Agent URL (default auto generated from Agent address): ",
		interfacePrompt: "Default interface (leave empty to auto-detect): ",
		modePrompt:      "Install mode [1] all-in-one(default) [2] server-only [3] agent-only(join existing manager): ",
		managerPrompt:   "Manager URL (e.g. http://10.0.0.2:8080, required for agent-only): ",
		confirmPrompt:   "Proceed with installation? [Y/n]: ",
		installing:      "Installing...",
		cancelled:       "Installation cancelled.",
		usageTail:       "Commands: nodewall <server|agent|set-password|install|preflight|update|cleanup|uninstall|version>",
	}

	fmt.Println(zh.title)
	fmt.Print(zh.langPrompt)
	langInput, _ := reader.ReadString('\n')
	langInput = strings.TrimSpace(langInput)
	pack := zh
	if langInput == "2" || strings.EqualFold(langInput, "en") || strings.EqualFold(langInput, "english") {
		pack = en
		fmt.Println(pack.title)
	}
	fmt.Println(pack.welcome)

	readWithDefault := func(prompt, fallback string) string {
		fmt.Print(prompt)
		raw, _ := reader.ReadString('\n')
		value := strings.TrimSpace(raw)
		if value == "" {
			return fallback
		}
		return value
	}

	password := readWithDefault(pack.passPrompt, "")
	if password == "" {
		return fmt.Errorf("password is required")
	}
	serverAddr := readWithDefault(pack.serverPrompt, "0.0.0.0:8080")
	agentAddr := readWithDefault(pack.agentPrompt, "127.0.0.1:9080")
	agentURL := readWithDefault(pack.agentURLHint, "")
	defaultInterface := readWithDefault(pack.interfacePrompt, "")
	modeInput := readWithDefault(pack.modePrompt, "1")
	mode := "all-in-one"
	if modeInput == "2" {
		mode = "server-only"
	} else if modeInput == "3" {
		mode = "agent-only"
	}
	managerURL := ""
	if mode == "agent-only" {
		managerURL = readWithDefault(pack.managerPrompt, "")
		if strings.TrimSpace(managerURL) == "" {
			return fmt.Errorf("manager url is required for agent-only mode")
		}
	}

	fmt.Print(pack.confirmPrompt)
	confirmRaw, _ := reader.ReadString('\n')
	confirm := strings.TrimSpace(confirmRaw)
	if confirm != "" && !strings.EqualFold(confirm, "y") && !strings.EqualFold(confirm, "yes") {
		fmt.Println(pack.cancelled)
		fmt.Println(pack.usageTail)
		return nil
	}

	fmt.Println(pack.installing)
	installArgs := []string{
		"--password", password,
		"--server-addr", serverAddr,
		"--agent-addr", agentAddr,
		"--mode", mode,
	}
	if agentURL != "" {
		installArgs = append(installArgs, "--agent-url", agentURL)
	}
	if defaultInterface != "" {
		installArgs = append(installArgs, "--default-interface", defaultInterface)
	}
	if managerURL != "" {
		installArgs = append(installArgs, "--manager-url", managerURL)
	}
	return runInstall(installArgs)
}

func MustRun(args []string) {
	if err := Run(args); err != nil {
		var shellExit *sshShellExit
		if errors.As(err, &shellExit) {
			os.Exit(shellExit.code)
		}
		log.Fatal(err)
	}
}
