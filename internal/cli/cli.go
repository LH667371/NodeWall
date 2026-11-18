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
	"nodewall/internal/clamav"
	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/securestore"
	"nodewall/internal/security"
	"nodewall/internal/securityscan"
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
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version" || args[0] == "-V") {
		return runVersion()
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
		return fmt.Errorf("unknown command %q; usage: nodewall <server|agent|set-password|install|preflight|update|cleanup|uninstall|web|version|ssh-upload-check> (or --version/-V)", args[0])
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
	configDir := envOr("NODEWALL_CONFIG_DIR", defaultConfigDir)
	envPath := filepath.Join(configDir, "nodewall.env")
	defaultAuthFile := envOr("NODEWALL_AUTH_FILE", readEnvValue(envPath, "NODEWALL_AUTH_FILE", filepath.Join(configDir, "auth.json")))
	file := fs.String("file", defaultAuthFile, "password file path")
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
	clusterKeyPath := strings.TrimSpace(os.Getenv("NODEWALL_CLUSTER_KEY_FILE"))
	if clusterKeyPath == "" {
		clusterKeyPath = readEnvValue(envPath, "NODEWALL_CLUSTER_KEY_FILE", filepath.Join(configDir, "cluster.key"))
	}
	previousKey, hadKey := os.LookupEnv("NODEWALL_CLUSTER_KEY_FILE")
	if err := os.Setenv("NODEWALL_CLUSTER_KEY_FILE", clusterKeyPath); err != nil {
		return err
	}
	defer func() {
		if hadKey {
			_ = os.Setenv("NODEWALL_CLUSTER_KEY_FILE", previousKey)
		} else {
			_ = os.Unsetenv("NODEWALL_CLUSTER_KEY_FILE")
		}
	}()

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
	serviceManager := fs.String("service-manager", envOr("NODEWALL_SERVICE_MANAGER", serviceManagerSystemd), "boot supervisor: systemd|sysv|none")
	installMode := fs.String("mode", envOr("NODEWALL_INSTALL_MODE", "all-in-one"), "install mode: all-in-one|server-only|agent-only")
	dataplane := fs.String("dataplane", envOr("NODEWALL_DATAPLANE", "auto"), "dataplane: auto|real|iptables")
	defaultInterface := fs.String("default-interface", envOr("NODEWALL_DEFAULT_INTERFACE", ""), "default interface")
	agentAddr := fs.String("agent-addr", envOr("NODEWALL_AGENT_ADDR", "127.0.0.1:9080"), "agent listen address")
	serverAddr := fs.String("server-addr", envOr("NODEWALL_SERVER_ADDR", "0.0.0.0:8086"), "server listen address")
	serverGRPCAddr := fs.String("server-grpc-addr", envOr("NODEWALL_SERVER_GRPC_ADDR", "0.0.0.0:50051"), "server gRPC listen address")
	serverQUICAddr := fs.String("server-quic-addr", envOr("NODEWALL_SERVER_QUIC_ADDR", "0.0.0.0:50052"), "server HTTP/3 control address")
	agentURL := fs.String("agent-url", envOr("NODEWALL_AGENT_URL", ""), "server-side agent URL")
	joinManagerURL := fs.String("manager-url", envOr("NODEWALL_MANAGER_URL", ""), "for agent-only mode: remote manager URL to register this node")
	managerGRPCAddr := fs.String("manager-grpc-addr", envOr("NODEWALL_MANAGER_GRPC_ADDR", ""), "for agent-only mode: remote manager gRPC address")
	managerQUICAddr := fs.String("manager-quic-addr", envOr("NODEWALL_MANAGER_QUIC_ADDR", ""), "for agent-only mode: remote manager HTTP/3 address")
	joinToken := fs.String("join-token", "", "short-lived enrollment credential from node management")
	consolePublicKey := fs.String("console-public-key", "", "manager SSH console public key")
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
	dataplaneExplicit := strings.TrimSpace(os.Getenv("NODEWALL_DATAPLANE")) != ""
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == "dataplane" {
			dataplaneExplicit = true
		}
	})
	resolvedServiceManager := strings.ToLower(strings.TrimSpace(*serviceManager))
	if *enableServices {
		var resolveErr error
		resolvedServiceManager, resolveErr = resolveServiceManager(resolvedServiceManager)
		if resolveErr != nil {
			return resolveErr
		}
	} else {
		// A disabled install must report and persist that no boot supervisor was
		// configured. Enrollment can explicitly switch this value back to
		// systemd after it has copied the standby snapshot and enabled the units.
		resolvedServiceManager = serviceManagerNone
	}
	if strings.EqualFold(strings.TrimSpace(*installMode), "agent-only") && *joinManagerURL != "" && (*joinToken == "" || *managerCA == "" || *advertiseAddr == "") {
		return errors.New("remote enrollment requires --join-token, --manager-ca and --advertise-addr; generate a command in node management")
	}

	if *defaultInterface == "" {
		*defaultInterface = detectDefaultInterface()
	}
	nodeID := detectNodeID()
	envPath := filepath.Join(*configDir, "nodewall.env")
	clusterKeyPath := readEnvValue(envPath, "NODEWALL_CLUSTER_KEY_FILE", filepath.Join(*configDir, "cluster.key"))
	previousClusterKey, hadClusterKey := os.LookupEnv("NODEWALL_CLUSTER_KEY_FILE")
	_ = os.Setenv("NODEWALL_CLUSTER_KEY_FILE", clusterKeyPath)
	defer func() {
		if hadClusterKey {
			_ = os.Setenv("NODEWALL_CLUSTER_KEY_FILE", previousClusterKey)
		} else {
			_ = os.Unsetenv("NODEWALL_CLUSTER_KEY_FILE")
		}
	}()
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
	if err := ensureLocalInstallPaths(*installDir, *configDir); err != nil {
		return err
	}
	fmt.Printf("[NodeWall] 准备安装：安装目录=%s，配置目录=%s\n", *installDir, *configDir)
	reenroll := mode == "agent-only" && strings.TrimSpace(*joinManagerURL) != ""
	existingInstallMode := strings.ToLower(strings.TrimSpace(readEnvValue(envPath, "NODEWALL_INSTALL_MODE", "")))
	if _, err := os.Stat(envPath); err == nil && reenroll && existingInstallMode != "agent-only" && existingInstallMode != "all-in-one" {
		return errors.New("this host already has a server-only or unknown installation; do not register it as a remote agent")
	}
	previousEnv, envErr := os.ReadFile(envPath)
	if envErr != nil && !os.IsNotExist(envErr) {
		return envErr
	}
	newInstallation := os.IsNotExist(envErr)
	if newInstallation {
		if entries, readErr := os.ReadDir(*installDir); readErr == nil && len(entries) > 0 {
			return fmt.Errorf("install directory %s already contains files; refusing to overwrite a pre-existing installation", *installDir)
		} else if readErr != nil && !os.IsNotExist(readErr) {
			return readErr
		}
	}
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
	agentAddrExplicit := strings.TrimSpace(os.Getenv("NODEWALL_AGENT_ADDR")) != ""
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == "agent-addr" {
			agentAddrExplicit = true
		}
	})
	advertisedAgentAddr := ""
	if newInstallation && mode == "all-in-one" && tlsEnabled && strings.TrimSpace(*agentURL) == "" {
		devMode := strings.TrimSpace(os.Getenv("NODEWALL_DEV_MODE"))
		secureRuntime := devMode == "" || devMode == "real"
		if secureRuntime {
			resolvedAgentAddr, advertisedAgentAddr = clusterInstallAgentAddress(mode, resolvedAgentAddr, *agentURL, detectInstallAdvertiseIP(*defaultInterface), true, agentAddrExplicit)
		}
	}
	resolvedServerAddr := strings.TrimSpace(*serverAddr)
	serverChanged := false
	if newInstallation {
		resolvedAgentAddr, _, err = chooseAvailableTCPAddr(resolvedAgentAddr)
		if err != nil {
			return fmt.Errorf("choose agent address: %w", err)
		}
		if advertisedAgentAddr != "" {
			host, _, _ := net.SplitHostPort(advertisedAgentAddr)
			_, port, _ := net.SplitHostPort(resolvedAgentAddr)
			advertisedAgentAddr = net.JoinHostPort(host, port)
		}
		if mode == "agent-only" {
			// An enrolled agent is promoted to a local standby manager after
			// registration. Do not claim the conventional 8080 application port
			// merely because the host service is temporarily stopped during
			// enrollment; it may need that port again after the next reboot.
			resolvedServerAddr, serverChanged, err = chooseManagementServerAddr(resolvedServerAddr)
		} else {
			resolvedServerAddr, serverChanged, err = chooseAvailableTCPAddr(resolvedServerAddr)
		}
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
	preflightOpts := installPreflightOptions(
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
	)
	preflightOpts.ServiceManager = resolvedServiceManager
	fmt.Println("[NodeWall] 正在执行安装预检...")
	report := checkPreflight(preflightOpts, defaultPreflightDeps())
	report.render(os.Stdout)
	if report.failed() {
		return fmt.Errorf("preflight failed: %s", report.failureSummary())
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	installStarted = true
	if serverChanged && !newInstallation {
		if err := upsertEnvValue(envPath, "NODEWALL_SERVER_ADDR", resolvedServerAddr); err != nil {
			return err
		}
		serverHTTPAddr := installServerHTTPAddr(resolvedServerAddr, *agentURL, *advertiseAddr)
		if err := upsertEnvValue(envPath, "NODEWALL_SERVER_HTTP_ADDR", serverHTTPAddr); err != nil {
			return err
		}
		fmt.Printf("note: standby web port was busy, selected %s instead\n", resolvedServerAddr)
	}
	if err := runStepWithProgress("写入 NodeWall 运行文件", func() error {
		return deployRuntimeAssets(exePath, *installDir, *configDir)
	}); err != nil {
		return err
	}
	if err := runStepWithProgress("初始化集群加密密钥", func() error {
		_, err := securestore.EnsureKey(clusterKeyPath)
		return err
	}); err != nil {
		return fmt.Errorf("initialize cluster encryption key: %w", err)
	}

	if mode != "agent-only" {
		if _, err := os.Stat(*authFile); os.IsNotExist(err) {
			if *adminPassword == "" {
				return fmt.Errorf("password is required via --password or NODEWALL_ADMIN_PASSWORD")
			}
			if err := runStepWithProgress("创建管理员账号", func() error {
				return security.EnsureAdminUser(*authFile, "admin", *adminPassword)
			}); err != nil {
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
			address := localHTTPAddr(resolvedAgentAddr)
			if advertisedAgentAddr != "" {
				address = advertisedAgentAddr
			}
			resolvedAgentURL = scheme + "://" + address
		}
		tlsCertFile := filepath.Join(*configDir, "tls", "nodewall.crt")
		tlsKeyFile := filepath.Join(*configDir, "tls", "nodewall.key")
		strictTLS := mode == "all-in-one"
		tlsCAFile := ""
		if strictTLS {
			tlsCAFile = tlsCertFile
		}
		sshKeyPath := filepath.Join(*configDir, "ssh", "id_ed25519")
		serverHTTPAddr := installServerHTTPAddr(resolvedServerAddr, resolvedAgentURL, *advertiseAddr)
		content := fmt.Sprintf("NODEWALL_NODE_ID=%s\nNODEWALL_AGENT_ADDR=%s\nNODEWALL_SERVER_ADDR=%s\nNODEWALL_SERVER_HTTP_ADDR=%s\nNODEWALL_AGENT_URL=%s\nNODEWALL_BPF_OBJECT=%s\nNODEWALL_WEB_DIR=%s\nNODEWALL_DATAPLANE=%s\nNODEWALL_IPTABLES_RECONCILE_INTERVAL=5s\nNODEWALL_AGENT_STATE=%s\nNODEWALL_SERVER_STATE=%s\nNODEWALL_CLUSTER_KEY_FILE=%s\nNODEWALL_DROP_LOG_STATE=%s\nNODEWALL_LOG_DIR=%s\nNODEWALL_DROP_LOG_ENABLED=true\nNODEWALL_DROP_LOG_RETENTION_DAYS=7\nNODEWALL_DROP_LOG_FLUSH_INTERVAL=30s\nNODEWALL_DEFAULT_INTERFACE=%s\nNODEWALL_AUTH_ENABLED=true\nNODEWALL_AUTH_FILE=%s\nNODEWALL_AUTH_SETTINGS_FILE=%s\nNODEWALL_ALLOWED_CIDRS=%s\nNODEWALL_ALLOWED_IPS=%s\nNODEWALL_ALLOWED_MACS=%s\nNODEWALL_WEB_ACCESS=public\nNODEWALL_TRUST_PROXY=false\nNODEWALL_SSH_KEY=%s\nNODEWALL_TLS_ENABLED=%t\nNODEWALL_TLS_CERT=%s\nNODEWALL_TLS_KEY=%s\nNODEWALL_TLS_CA=%s\nNODEWALL_TLS_INSECURE_SKIP_VERIFY=%t\n",
			nodeID,
			resolvedAgentAddr,
			resolvedServerAddr,
			serverHTTPAddr,
			resolvedAgentURL,
			filepath.Join(*installDir, "bpf", "gen", "xdpacl_bpfel.o"),
			filepath.Join(*installDir, "web", "dist"),
			dataplaneMode,
			filepath.Join(*configDir, "agent-state.json"),
			filepath.Join(*configDir, "server-state.json"),
			clusterKeyPath,
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
		reportedAgentAddr := resolvedAgentAddr
		if advertisedAgentAddr != "" {
			reportedAgentAddr = advertisedAgentAddr
		}
		content += fmt.Sprintf("NODEWALL_SERVER_GRPC_ADDR=%s\nNODEWALL_SERVER_QUIC_ADDR=%s\nNODEWALL_INSTALL_MODE=%s\nNODEWALL_MANAGER_URL=%s\nNODEWALL_MANAGER_GRPC_ADDR=%s\nNODEWALL_MANAGER_QUIC_ADDR=%s\nNODEWALL_AGENT_HTTP_ADDR=%s\n",
			resolvedServerGRPCAddr,
			resolvedServerQUICAddr,
			mode,
			strings.TrimSpace(*joinManagerURL),
			resolvedManagerGRPC,
			resolvedManagerQUIC,
			reportedAgentAddr,
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
		if reenroll && existingInstallMode == "agent-only" {
			// Re-enrollment promotes the agent to a local standby after the
			// bootstrap snapshot is copied. Always apply the standby-port policy:
			// a service using 8080 can be stopped during enrollment and restored
			// only at boot, so checking the live socket alone is insufficient.
			resolvedServerAddr, serverChanged, err = chooseManagementServerAddr(currentServerAddr)
			if err != nil {
				return fmt.Errorf("choose standby server address: %w", err)
			}
		} else if reenroll {
			// An existing all-in-one installation is also a valid repair target.
			// Keep its current management port while refreshing the node endpoint;
			// the join script will restart the local server after the snapshot is
			// synchronized.
			resolvedServerAddr = currentServerAddr
			serverChanged = false
		} else if err := ensureTCPAddrAvailable(currentServerAddr, "server"); err != nil {
			return fmt.Errorf("%w; update %s or rerun with --server-addr", err, envPath)
		}
	}
	if err := upsertEnvValue(envPath, "NODEWALL_AGENT_TOKEN_FILE", filepath.Join(*configDir, "agent-token")); err != nil {
		return err
	}
	if err := upsertEnvValue(envPath, "NODEWALL_NODE_CREDENTIALS_FILE", filepath.Join(*configDir, "node-credentials.json")); err != nil {
		return err
	}
	if err := upsertEnvValue(envPath, "NODEWALL_CLUSTER_KEY_FILE", clusterKeyPath); err != nil {
		return err
	}
	if err := upsertEnvValue(envPath, "NODEWALL_SERVICE_MANAGER", resolvedServiceManager); err != nil {
		return err
	}
	if !newInstallation && dataplaneExplicit {
		// Changing the dataplane is a deliberate migration. In particular,
		// `--dataplane real` must be able to move an older install away from the
		// optional iptables compatibility backend without altering the setting on
		// routine upgrades that did not mention a dataplane.
		if err := upsertEnvValue(envPath, "NODEWALL_DATAPLANE", dataplaneMode); err != nil {
			return err
		}
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
		if err := upsertEnvValue(envPath, "NODEWALL_AGENT_URL", "https://"+*advertiseAddr); err != nil {
			return err
		}
		certFile := readEnvValue(envPath, "NODEWALL_TLS_CERT", filepath.Join(*configDir, "tls", "nodewall.crt"))
		keyFile := readEnvValue(envPath, "NODEWALL_TLS_KEY", filepath.Join(*configDir, "tls", "nodewall.key"))
		if err := transporttls.EnsureCertificateForAddress(certFile, keyFile, *advertiseAddr); err != nil {
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
		if err := runStepWithProgress("向管理节点注册 Agent（超时 15 秒）", func() error {
			enrolled, enrollErr := enrollNode(*joinManagerURL, *managerCA, *joinToken, nodeauth.Credential{NodeID: nodeID, AgentURL: "https://" + *advertiseAddr, Token: token, Certificate: string(certificate)})
			if enrollErr != nil {
				return enrollErr
			}
			// A legacy command may carry the manager's reserved/default node ID.
			// The manager can return a safe replacement; persist it before the
			// standby bootstrap is downloaded so all subsequent heartbeats use the
			// same identity.
			if strings.TrimSpace(enrolled.NodeID) != strings.TrimSpace(nodeID) {
				nodeID = strings.TrimSpace(enrolled.NodeID)
				if nodeID == "" {
					return errors.New("manager returned an empty node ID after enrollment")
				}
				if err := upsertEnvValue(envPath, "NODEWALL_NODE_ID", nodeID); err != nil {
					return fmt.Errorf("persist manager-assigned node ID: %w", err)
				}
				fmt.Printf("note: manager assigned unique node ID %s\n", nodeID)
			}
			return nil
		}); err != nil {
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
		if err := runStepWithProgress("配置 NodeWall SSH 控制台密钥", func() error {
			return configureLocalSSHAccess(sshKeyPath, *configDir)
		}); err != nil {
			return fmt.Errorf("configure local SSH console access: %w", err)
		}
	}
	if strings.TrimSpace(*consolePublicKey) != "" {
		if err := authorizeConsoleKey(*consolePublicKey, "/root/.ssh", *configDir); err != nil {
			return fmt.Errorf("configure manager SSH console access: %w", err)
		}
	}

	if err := runStepWithProgress("写入服务启动配置", func() error {
		if err := os.MkdirAll(*systemdDir, 0o755); err != nil {
			return err
		}
		return writeSystemdUnits(*systemdDir)
	}); err != nil {
		return err
	}
	if *enableServices {
		switch resolvedServiceManager {
		case serviceManagerSystemd:
			if err := runCommandWithProgress("重载 systemd 配置", 30*time.Second, "systemctl", "daemon-reload"); err != nil {
				return err
			}
			if mode != "server-only" {
				if err := runCommandWithProgress("启用并启动 NodeWall Agent 服务", 120*time.Second, "systemctl", "enable", "--now", "nodewall-agent.service"); err != nil {
					return err
				}
				if reenroll {
					if err := runCommandWithProgress("重启 NodeWall Agent 服务以完成注册", 120*time.Second, "systemctl", "restart", "nodewall-agent.service"); err != nil {
						return err
					}
				}
			} else {
				_ = runCommandWithProgress("停用 NodeWall Agent 服务", 30*time.Second, "systemctl", "disable", "--now", "nodewall-agent.service")
			}
			if mode != "agent-only" {
				if err := runCommandWithProgress("启用并启动 NodeWall Server 服务", 120*time.Second, "systemctl", "enable", "--now", "nodewall-server.service"); err != nil {
					return err
				}
			} else {
				_ = runCommandWithProgress("停用 NodeWall Server 服务", 30*time.Second, "systemctl", "disable", "--now", "nodewall-server.service")
			}
		case serviceManagerSysV:
			if err := installSysVServices(*installDir, *configDir, mode); err != nil {
				return err
			}
			if err := startSysVServices(mode); err != nil {
				return err
			}
		case serviceManagerNone:
			fmt.Println("services not started; run nodewall agent/server manually")
		}
	}

	installComplete = true
	fmt.Printf("nodewall installed\nmode: %s\nservice manager: %s\ninstall dir: %s\nconfig dir: %s\ndefault interface: %s\nagent addr: %s\nserver addr: %s\nauth file: %s\npassword command: %s set-password --file %s\n",
		mode,
		resolvedServiceManager,
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

// resolveInstallDataplane turns the install-time mode into a concrete backend.
// Auto deliberately chooses the real XDP/TC dataplane and never silently falls
// back to iptables: the latter is an explicit legacy compatibility option and
// must not alter a host firewall merely because a kernel is old.
func resolveInstallDataplane(value string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(value))
	if mode == "legacy" || mode == "zstack-iptables" {
		mode = "iptables"
	}
	switch mode {
	case "real", "iptables":
		return mode, nil
	case "", "auto":
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
	managerURL := fs.String("manager-url", envOr("NODEWALL_MANAGER_URL", ""), "manager URL to retain for future heartbeats and updates")
	restartServices := fs.Bool("restart-services", envBool("NODEWALL_RESTART_SERVICES", true), "restart running services after update")
	finalizeServices := fs.Bool("internal-finalize-update", false, "complete an automatically scheduled service restart")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ensureLocalInstallPaths(*installDir, *configDir); err != nil {
		return err
	}
	if *finalizeServices {
		return finishUpdateServiceRestart(*installDir, *configDir)
	}
	fmt.Printf("[NodeWall] 准备更新：安装目录=%s，配置目录=%s\n", *installDir, *configDir)

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
	// A manager can migrate its web port while enrolled nodes are still
	// running with the legacy endpoint. The updater receives the manager URL
	// used for the current package download in its environment; persist it so
	// future heartbeats and automatic updates do not fall back to the old port.
	if normalizedManagerURL, err := normalizeUpdateManagerURL(*managerURL); err != nil {
		return err
	} else if normalizedManagerURL != "" {
		if err := upsertEnvValue(envPath, "NODEWALL_MANAGER_URL", normalizedManagerURL); err != nil {
			return fmt.Errorf("persist manager URL during update: %w", err)
		}
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	if err := runStepWithProgress("写入新版 NodeWall 运行文件", func() error {
		return deployRuntimeAssets(exePath, *installDir, *configDir)
	}); err != nil {
		return err
	}
	sshKeyPath := readEnvValue(envPath, "NODEWALL_SSH_KEY", filepath.Join(*configDir, "ssh", "id_ed25519"))
	if strings.TrimSpace(readEnvValue(envPath, "NODEWALL_SSH_KEY", "")) == "" {
		if err := upsertEnvValue(envPath, "NODEWALL_SSH_KEY", sshKeyPath); err != nil {
			return err
		}
	}
	if err := runStepWithProgress("更新 NodeWall SSH 控制台密钥", func() error {
		return configureLocalSSHAccess(sshKeyPath, *configDir)
	}); err != nil {
		return fmt.Errorf("configure local SSH console access: %w", err)
	}
	if err := runStepWithProgress("恢复 SSH 文件传输策略", func() error {
		return refreshSSHTransferPolicy(*configDir, *installDir)
	}); err != nil {
		return err
	}
	if err := runStepWithProgress("写入新版服务启动配置", func() error {
		if err := os.MkdirAll(*systemdDir, 0o755); err != nil {
			return err
		}
		return writeSystemdUnits(*systemdDir)
	}); err != nil {
		return err
	}
	serviceManager := serviceManagerFromEnv(envPath)
	if serviceManager != serviceManagerSystemd && serviceManager != serviceManagerSysV && serviceManager != serviceManagerNone {
		serviceManager = serviceManagerSystemd
	}
	var promotedToStandby bool
	err = runStepWithProgress("检查集群备用管理服务", func() error {
		var stepErr error
		if _, stepErr = migrateLegacyServerPort(envPath); stepErr != nil {
			return stepErr
		}
		promotedToStandby, stepErr = promoteAgentToStandby(envPath, *configDir)
		return stepErr
	})
	if err != nil {
		// Older managers do not expose the standby bootstrap endpoints yet. The
		// binary update itself remains valid; the next update after the manager
		// is upgraded can promote this legacy agent automatically.
		fmt.Printf("warning: standby management promotion skipped: %v\n", err)
		promotedToStandby = false
	}
	// Standby promotion may have upgraded a legacy agent-only installation from
	// a disabled service manager to systemd. Re-read the value before deciding
	// how to restart services.
	serviceManager = serviceManagerFromEnv(envPath)
	if serviceManager != serviceManagerSystemd && serviceManager != serviceManagerSysV && serviceManager != serviceManagerNone {
		serviceManager = serviceManagerSystemd
	}

	servicesRestarted := false
	if *restartServices {
		needsDetached, inServiceCgroup := updateRestartNeedsIsolation(*installDir)
		if needsDetached {
			// An updater spawned by the agent shares its systemd cgroup or SysV
			// process group. Restarting the agent from there kills the updater
			// before it can restart the management server.
			if err := scheduleUpdateServiceRestart(*installDir, *configDir, *systemdDir, inServiceCgroup); err != nil {
				return err
			}
			fmt.Println("[NodeWall] 已安排独立的服务重启；完成情况请查看重启任务日志")
		} else {
			if err := finishUpdateServiceRestart(*installDir, *configDir); err != nil {
				return err
			}
			servicesRestarted = true
		}
	}

	fmt.Printf("nodewall updated\nservice manager: %s\ninstall dir: %s\nconfig dir: %s\nagent addr: %s\nserver addr: %s\nstandby management enabled: %t\nservices restarted: %t\n",
		serviceManager,
		*installDir,
		*configDir,
		readEnvValue(envPath, "NODEWALL_AGENT_ADDR", "127.0.0.1:9080"),
		readEnvValue(envPath, "NODEWALL_SERVER_ADDR", "0.0.0.0:8086"),
		promotedToStandby,
		servicesRestarted,
	)
	return nil
}

func normalizeUpdateManagerURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid manager URL %q", raw)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid manager URL scheme %q", parsed.Scheme)
	}
	return raw, nil
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
	for key, value := range map[string]string{"NODEWALL_AGENT_TOKEN_FILE": filepath.Join(configDir, "agent-token"), "NODEWALL_NODE_CREDENTIALS_FILE": filepath.Join(configDir, "node-credentials.json"), "NODEWALL_CLUSTER_KEY_FILE": filepath.Join(configDir, "cluster.key")} {
		if readEnvValue(envPath, key, "") == "" {
			if err := upsertEnvValue(envPath, key, value); err != nil {
				return err
			}
		}
	}
	if strings.TrimSpace(readEnvValue(envPath, "NODEWALL_SERVER_HTTP_ADDR", "")) == "" {
		serverAddr := readEnvValue(envPath, "NODEWALL_SERVER_ADDR", "0.0.0.0:8086")
		serverHTTPAddr := installServerHTTPAddr(serverAddr, readEnvValue(envPath, "NODEWALL_AGENT_URL", ""), readEnvValue(envPath, "NODEWALL_AGENT_HTTP_ADDR", ""))
		if err := upsertEnvValue(envPath, "NODEWALL_SERVER_HTTP_ADDR", serverHTTPAddr); err != nil {
			return err
		}
	}
	keyPath := readEnvValue(envPath, "NODEWALL_CLUSTER_KEY_FILE", filepath.Join(configDir, "cluster.key"))
	previous, had := os.LookupEnv("NODEWALL_CLUSTER_KEY_FILE")
	if err := os.Setenv("NODEWALL_CLUSTER_KEY_FILE", keyPath); err != nil {
		return err
	}
	defer func() {
		if had {
			_ = os.Setenv("NODEWALL_CLUSTER_KEY_FILE", previous)
		} else {
			_ = os.Unsetenv("NODEWALL_CLUSTER_KEY_FILE")
		}
	}()
	if _, err := securestore.EnsureKey(keyPath); err != nil {
		return fmt.Errorf("initialize cluster encryption key: %w", err)
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
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("cleanup must run as root on Linux")
	}
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	installDir := fs.String("install-dir", envOr("NODEWALL_INSTALL_DIR", defaultInstallDir), "install directory")
	configDir := fs.String("config-dir", envOr("NODEWALL_CONFIG_DIR", defaultConfigDir), "config directory")
	systemdDir := fs.String("systemd-dir", envOr("NODEWALL_SYSTEMD_DIR", defaultSystemdDir), "systemd unit directory")
	// Older managers used this option when requesting self-removal.
	_ = fs.Bool("restart-services", false, "deprecated compatibility option")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected cleanup arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := cleanupInstallation(*installDir, *configDir, *systemdDir); err != nil {
		return err
	}
	fmt.Println("nodewall cleaned up")
	return nil
}

func runWeb(args []string) error {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	configDir := fs.String("config-dir", envOr("NODEWALL_CONFIG_DIR", defaultConfigDir), "config directory")
	port := fs.Int("port", 8086, "web listen port")
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
		return fmt.Errorf("unknown web action %q; usage: nodewall web [on|off|status] [--port 8086]", action)
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
	manager := serviceManagerFromEnv(envPath)
	if manager == serviceManagerSysV {
		if _, err := runCommandOutput(serviceScriptPath("server"), "restart"); err != nil {
			return err
		}
	} else if manager == serviceManagerSystemd {
		if err := runCommand("systemctl", "restart", "nodewall-server.service"); err != nil {
			return err
		}
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

// A clustered all-in-one manager must advertise an endpoint reachable from
// its peers. Preserve an explicit loopback bind and never expose a demo or
// non-TLS agent, since those configurations may not require authentication.
func clusterInstallAgentAddress(mode, listen, agentURL, advertiseIP string, secureRuntime, explicitListen bool) (string, string) {
	if mode != "all-in-one" || !secureRuntime || strings.TrimSpace(agentURL) != "" {
		return listen, ""
	}
	ip := net.ParseIP(strings.TrimSpace(advertiseIP))
	if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return listen, ""
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil || port == "" {
		return listen, ""
	}
	parsedHost := net.ParseIP(host)
	wildcard := host == "" || (parsedHost != nil && parsedHost.IsUnspecified())
	loopback := strings.EqualFold(host, "localhost") || (parsedHost != nil && parsedHost.IsLoopback())
	if !wildcard && (explicitListen || !loopback) {
		return listen, ""
	}
	if loopback {
		listen = net.JoinHostPort("0.0.0.0", port)
	}
	return listen, net.JoinHostPort(ip.String(), port)
}

func detectInstallAdvertiseIP(ifaceName string) string {
	// The configured interface can be a physical port enslaved to a bridge;
	// prefer its own IPv4 address, then the bridge address, before the route.
	interfaces := []string{strings.TrimSpace(ifaceName)}
	if master, err := os.Readlink(filepath.Join("/sys/class/net", strings.TrimSpace(ifaceName), "master")); err == nil {
		interfaces = append(interfaces, filepath.Base(master))
	}
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip.String()
			}
		}
	}
	// A UDP dial selects the route without sending an application packet.
	if conn, err := net.DialTimeout("udp4", "192.0.2.1:80", time.Second); err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP.To4() != nil && !addr.IP.IsLoopback() && !addr.IP.IsLinkLocalUnicast() {
			return addr.IP.String()
		}
	}
	return ""
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

// chooseManagementServerAddr reserves the legacy application port for a host
// service when a node becomes a management server. New management listeners
// start at 8086, and old 8080-8085 values are migrated into that range.
// Port availability is still checked after moving past 8086 because the
// original service may be stopped while enrollment runs and return at boot.
func chooseManagementServerAddr(addr string) (string, bool, error) {
	const standbyWebPortStart = 8086
	original := strings.TrimSpace(addr)
	host, portStr, err := net.SplitHostPort(original)
	if err != nil {
		return "", false, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", false, err
	}
	// 8080 was the old default and 8081-8085 were used by earlier fallback
	// releases. Upgrade and re-enrollment must migrate all of those legacy
	// standby values so the next reboot consistently leaves the host service's
	// port range alone.
	if port >= 8080 && port < standbyWebPortStart {
		port = standbyWebPortStart
		addr = net.JoinHostPort(host, strconv.Itoa(port))
	}
	selected, _, err := chooseAvailableTCPAddr(addr)
	if err != nil {
		return "", false, err
	}
	return selected, selected != original, nil
}

// installServerHTTPAddr converts the bind address selected during install into
// a cluster-report address. A wildcard bind is valid for the server process but
// cannot be opened by an operator, so prefer the enrollment advertise host,
// the configured agent URL host, and finally loopback in that order.
func installServerHTTPAddr(serverAddr, agentURL, advertiseAddr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(serverAddr))
	if err != nil || strings.TrimSpace(port) == "" {
		return strings.TrimSpace(serverAddr)
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		// A concrete bind address limits where the web service is reachable;
		// advertising a different interface would give peers a broken endpoint.
		return net.JoinHostPort(host, port)
	}
	for _, candidate := range []string{advertiseAddr, agentURL} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if parsed, parseErr := url.Parse(candidate); parseErr == nil && parsed.Host != "" {
			candidate = parsed.Host
		}
		candidateHost, _, splitErr := net.SplitHostPort(candidate)
		if splitErr == nil {
			candidate = candidateHost
		}
		candidate = strings.Trim(candidate, "[]")
		ip := net.ParseIP(candidate)
		if candidate != "" && candidate != "0.0.0.0" && candidate != "::" && !strings.EqualFold(candidate, "localhost") && (ip == nil || (!ip.IsLoopback() && !ip.IsUnspecified())) {
			host = candidate
			break
		}
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
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
	if err := deployClamAVAssets(exePath, installDir); err != nil {
		return err
	}
	if err := writeEmbeddedFile("bpf/gen/xdpacl_bpfel.o", filepath.Join(installDir, "bpf", "gen", "xdpacl_bpfel.o"), 0o644); err != nil {
		return err
	}
	if err := version.WriteInstallFiles(installDir); err != nil {
		return err
	}
	// Existing installations may have a custom or legacy NODEWALL_WEB_DIR.
	// Updating only the new default directory leaves the running server serving
	// its old static bundle, which makes a successful binary update look like a
	// no-op. Honor the configured path during upgrades and keep the install
	// default for a fresh installation whose env file is not written yet.
	envPath := filepath.Join(configDir, "nodewall.env")
	webDir := strings.TrimSpace(readEnvValue(envPath, "NODEWALL_WEB_DIR", ""))
	if webDir == "" {
		webDir = filepath.Join(installDir, "web", "dist")
	} else if !filepath.IsAbs(webDir) {
		webDir = filepath.Join(installDir, webDir)
	}
	return writeEmbeddedTree("web/dist", filepath.Clean(webDir))
}

// deployClamAVAssets makes the offline engine/database phase visible for both
// install and update. Copying the bundle only prepares verified input files;
// the service performs engine and database validation after it starts.
func deployClamAVAssets(exePath, installDir string) error {
	bundleDestination := filepath.Join(installDir, "clamav")
	source, bundled, err := bundledClamAVAssets(exePath, installDir)
	if err != nil {
		return fmt.Errorf("检查离线 ClamAV 引擎和病毒库: %w", err)
	}
	if bundled {
		fmt.Printf("[NodeWall] 检测到离线 ClamAV 资源：引擎 + main.cvd/daily.cvd/bytecode.cvd (%s)\n", source)
		fmt.Println("[NodeWall] 安装离线 ClamAV 引擎和病毒库...")
		if err := clamav.InstallBundle(exePath, installDir); err != nil {
			return fmt.Errorf("安装离线 ClamAV 引擎和病毒库: %w", err)
		}
		fmt.Printf("[NodeWall] 离线 ClamAV 引擎和病毒库安装完成：%s\n", bundleDestination)
		fmt.Println("[NodeWall] 当前仅完成病毒库资源落盘；服务启动后将校验引擎并加载病毒库")
		return nil
	}

	existing, err := installedClamAVAssets(bundleDestination)
	if err != nil {
		return fmt.Errorf("检查现有 ClamAV 引擎和病毒库: %w", err)
	}
	if existing {
		fmt.Printf("[NodeWall] 更新包未携带离线 ClamAV 资源，保留现有引擎和病毒库：%s\n", bundleDestination)
		fmt.Println("[NodeWall] 服务启动后将继续校验并同步病毒库")
		return nil
	}
	fmt.Println("[NodeWall] 当前安装包未携带离线 ClamAV 引擎和病毒库")
	fmt.Printf("[NodeWall] 未发现完整离线 ClamAV 资源：%s\n", bundleDestination)
	fmt.Println("[NodeWall] 服务启动后将自动从已注册集群节点同步 ClamAV 引擎和病毒库，并每 2 分钟检查更新")
	return nil
}

func bundledClamAVAssets(exePath, installDir string) (string, bool, error) {
	if filepath.Base(filepath.Dir(exePath)) != "bin" {
		return "", false, nil
	}
	source := filepath.Join(filepath.Dir(filepath.Dir(exePath)), "clamav")
	info, err := os.Stat(source)
	if errors.Is(err, os.ErrNotExist) {
		return source, false, nil
	}
	if err != nil {
		return source, false, err
	}
	if !info.IsDir() {
		return source, false, fmt.Errorf("路径不是目录: %s", source)
	}
	// An update invoked from the installed binary sees the existing bundle as
	// its sibling. It is retained, not treated as a newly supplied package.
	if filepath.Clean(source) == filepath.Clean(filepath.Join(installDir, "clamav")) {
		return source, false, nil
	}
	return source, true, nil
}

var requiredClamAVBundleFiles = []string{
	"engines/amd64.tar.gz",
	"engines/arm64.tar.gz",
	"database/main.cvd",
	"database/daily.cvd",
	"database/bytecode.cvd",
}

func installedClamAVAssets(bundle string) (bool, error) {
	info, err := os.Stat(bundle)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("路径不是目录: %s", bundle)
	}
	for _, relative := range requiredClamAVBundleFiles {
		path := filepath.Join(bundle, relative)
		fileInfo, statErr := os.Stat(path)
		if errors.Is(statErr, os.ErrNotExist) {
			return false, nil
		}
		if statErr != nil {
			return false, statErr
		}
		if !fileInfo.Mode().IsRegular() {
			return false, fmt.Errorf("资源不是普通文件: %s", path)
		}
	}
	return true, nil
}

func runVersion() error {
	info := version.Current()
	fmt.Printf("app_version=%s\npackage_version=%s\n", info.AppVersion, info.PackageVersion)
	return nil
}

func writeSystemdUnits(systemdDir string) error {
	for _, unit := range []string{"nodewall-agent.service", "nodewall-server.service"} {
		if err := backupSystemdUnit(filepath.Join(systemdDir, unit)); err != nil {
			return err
		}
	}
	if err := ensureNodeWallUnitPath(filepath.Join(systemdDir, "nodewall-agent.service")); err != nil {
		return err
	}
	if err := ensureNodeWallUnitPath(filepath.Join(systemdDir, "nodewall-server.service")); err != nil {
		return err
	}
	if err := writeEmbeddedFile("deployments/systemd/nodewall-agent.service", filepath.Join(systemdDir, "nodewall-agent.service"), 0o644); err != nil {
		return err
	}
	return writeEmbeddedFile("deployments/systemd/nodewall-server.service", filepath.Join(systemdDir, "nodewall-server.service"), 0o644)
}

func backupSystemdUnit(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !bytes.Contains(data, []byte("Description=NodeWall ")) || !bytes.Contains(data, []byte("ExecStart=")) {
		return fmt.Errorf("refusing to overwrite existing non-NodeWall service unit %s", path)
	}
	backup := path + ".nodewall-backup"
	if _, err := os.Stat(backup); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(backup, data, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Chmod(backup, info.Mode().Perm())
}

func ensureNodeWallUnitPath(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Contains(data, []byte("Description=NodeWall ")) || !bytes.Contains(data, []byte("ExecStart=")) {
		return fmt.Errorf("refusing to overwrite existing non-NodeWall service unit %s", path)
	}
	return nil
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

// runStepWithProgress keeps filesystem and network phases visible. A plain
// os.WriteFile/os.Rename or a bootstrap request can block inside the kernel
// when an administrator accidentally points NodeWall at a stalled remote
// mount; heartbeat messages make the current phase explicit while the
// remote-mount guard prevents the normal install/update paths from using NFS.
func runStepWithProgress(label string, step func() error) error {
	fmt.Printf("[NodeWall] %s...\n", label)
	startedAt := time.Now()
	done := make(chan error, 1)
	go func() { done <- step() }()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				fmt.Printf("[NodeWall] %s失败（耗时 %s）\n", label, time.Since(startedAt).Round(time.Second))
				return fmt.Errorf("%s: %w", label, err)
			}
			fmt.Printf("[NodeWall] %s完成（耗时 %s）\n", label, time.Since(startedAt).Round(time.Second))
			return nil
		case <-ticker.C:
			fmt.Printf("[NodeWall] %s仍在执行（已等待 %s）...\n", label, time.Since(startedAt).Round(time.Second))
		}
	}
}

// runCommandWithProgress keeps installation visible while a service manager
// waits for a unit to become ready. systemctl --now can legitimately spend
// time waiting for network, BPF, or TLS initialization, but a silent wait is
// indistinguishable from a hung installer. The timeout also prevents a broken
// unit from leaving the installer blocked forever.
func runCommandWithProgress(label string, timeout time.Duration, name string, args ...string) error {
	fmt.Printf("[NodeWall] %s...\n", label)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	startedAt := time.Now()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			if err != nil {
				if ctx.Err() == context.DeadlineExceeded {
					return fmt.Errorf("%s 超时（等待超过 %s），请检查 systemctl status 和 journalctl -u %s", label, timeout.Round(time.Second), strings.Join(args, " "))
				}
				return fmt.Errorf("%s 失败: %w", label, err)
			}
			fmt.Printf("[NodeWall] %s完成（耗时 %s）\n", label, time.Since(startedAt).Round(time.Second))
			return nil
		case <-ticker.C:
			fmt.Printf("[NodeWall] %s仍在执行（已等待 %s）...\n", label, time.Since(startedAt).Round(time.Second))
		}
	}
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
		serverPrompt:    "请输入 Server 地址（默认 0.0.0.0:8086）: ",
		agentPrompt:     "请输入 Agent 地址（默认 127.0.0.1:9080）: ",
		agentURLHint:    "请输入 Agent URL（默认自动按 Agent 地址生成）: ",
		interfacePrompt: "请输入默认网卡（留空自动探测）: ",
		modePrompt:      "安装模式 [1] 一体化(默认) [2] 仅管理节点 [3] 加入现有管理节点: ",
		managerPrompt:   "管理节点地址（如 http://10.0.0.2:8086，agent-only 时必填）: ",
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
		serverPrompt:    "Server address (default 0.0.0.0:8086): ",
		agentPrompt:     "Agent address (default 127.0.0.1:9080): ",
		agentURLHint:    "Agent URL (default auto generated from Agent address): ",
		interfacePrompt: "Default interface (leave empty to auto-detect): ",
		modePrompt:      "Install mode [1] all-in-one(default) [2] server-only [3] agent-only(join existing manager): ",
		managerPrompt:   "Manager URL (e.g. http://10.0.0.2:8086, required for agent-only): ",
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
	serverAddr := readWithDefault(pack.serverPrompt, "0.0.0.0:8086")
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
