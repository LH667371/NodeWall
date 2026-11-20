package runtime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"nodewall/internal/api"
	"nodewall/internal/autoupdate"
	"nodewall/internal/clamav"
	"nodewall/internal/config"
	"nodewall/internal/droplog"
	"nodewall/internal/geoip"
	"nodewall/internal/grpccontrol"
	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/securestore"
	"nodewall/internal/service"
	"nodewall/internal/sshactivity"
	"nodewall/internal/store"
	"nodewall/internal/transporttls"
	"nodewall/internal/version"
	"nodewall/internal/xdp"

	"github.com/quic-go/webtransport-go"
	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
)

func RunServer() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg := config.LoadServerConfig()
	if cfg.AuthEnabled && !cfg.TLSEnabled {
		log.Printf("warning: management authentication is exposed over plain HTTP; enable NODEWALL_TLS_ENABLED or terminate TLS at a trusted proxy")
	}
	if cfg.AuthEnabled && cfg.TLSInsecureSkipVerify {
		log.Printf("warning: outbound NodeWall TLS certificate verification is disabled; configure NODEWALL_TLS_CA and set NODEWALL_TLS_INSECURE_SKIP_VERIFY=false")
	}
	if strings.TrimSpace(cfg.ClusterKeyFile) != "" {
		if err := os.Setenv("NODEWALL_CLUSTER_KEY_FILE", cfg.ClusterKeyFile); err != nil {
			return err
		}
		if cfg.DevMode == "" || cfg.DevMode == "real" {
			if _, err := securestore.EnsureKey(cfg.ClusterKeyFile); err != nil {
				// A standby can replace a damaged local key from the active
				// manager during its first snapshot. Keep the service reachable
				// while that recovery is attempted instead of failing startup.
				log.Printf("warning: initialize cluster encryption key failed: %v; standby recovery may replace it", err)
			}
		}
	}
	if cfg.TLSEnabled {
		if err := transporttls.EnsureCertificate(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.ListenAddr); err != nil {
			return err
		}
	}
	st, err := store.NewPersistent(cfg.StateFile)
	if err != nil {
		// A damaged state file must not take the local management console down.
		// NewPersistent returns a path-backed empty store here; a later policy or
		// bootstrap write repairs the primary while the other cluster members
		// remain available for snapshot recovery.
		log.Printf("warning: load persistent server state failed: %v; starting with an empty recoverable store", err)
	}
	if cfg.InstallMode != "server-only" {
		advertiseIP := detectManagerAdvertiseIP(cfg.AgentURL)
		agentHTTPAddr := ""
		if _, port, splitErr := net.SplitHostPort(agentHostPort(cfg.AgentURL)); splitErr == nil && advertiseIP != "" {
			agentHTTPAddr = net.JoinHostPort(advertiseIP, port)
		}
		st.UpsertNode(context.Background(), models.Node{
			ID:             cfg.NodeID,
			Name:           nodeDisplayName(cfg.NodeID),
			AgentURL:       cfg.AgentURL,
			AdvertiseIP:    advertiseIP,
			AgentHTTPAddr:  agentHTTPAddr,
			ServerHTTPAddr: serverHTTPAddrForListener(cfg.ListenAddr, advertiseIP),
			PackageVersion: version.Current().PackageVersion,
			LastSeenAt:     time.Now().UTC(),
		})
	}

	policyService := service.NewPolicyService(st)
	handler, err := api.NewServerHandler(cfg, policyService, st)
	if err != nil {
		return err
	}
	var credentials *nodeauth.Registry
	if cfg.DevMode == "" || cfg.DevMode == "real" {
		credentials, err = nodeauth.Open(cfg.NodeCredentialsFile)
		if err != nil {
			log.Printf("warning: load node credential registry failed: %v; starting with an empty recoverable registry", err)
			credentials, err = nodeauth.Open("")
			if err != nil {
				return err
			}
		}
		if cfg.InstallMode != "server-only" {
			token, tokenErr := nodeauth.LoadOrCreateToken(cfg.TokenFile)
			if tokenErr != nil {
				return tokenErr
			}
			var certificate []byte
			if cfg.TLSEnabled {
				if err := transporttls.EnsureCertificate(cfg.AgentTLSCertFile, cfg.AgentTLSKeyFile, cfg.AgentURL); err != nil {
					return err
				}
				certificate, err = os.ReadFile(cfg.AgentTLSCertFile)
				if err != nil {
					return err
				}
			}
			if err := credentials.Put(nodeauth.Credential{NodeID: cfg.NodeID, AgentURL: cfg.AgentURL, Token: token, Certificate: string(certificate)}); err != nil {
				return err
			}
		}
		handler.ConfigureNodeAuth(credentials)
		if strings.TrimSpace(cfg.ManagerURL) != "" && cfg.InstallMode != "server-only" {
			go runStandbySync(ctx, cfg, st, credentials, handler)
		}
		// Repair policies created before the current control-plane ports or the
		// newest enrolled node existed. Reconciliation only touches policies that
		// are already enforced, so a protected baseline remains an explicit user
		// action.
		if err := handler.ReconcileManagerControlPorts(context.Background()); err != nil {
			log.Printf("warning: manager control-port reconciliation failed: %v", err)
		}
		if err := handler.ReconcileActiveClusterInterconnect(context.Background()); err != nil {
			log.Printf("warning: cluster interconnect reconciliation failed: %v", err)
		}
	}
	go policyService.RunPolicyRecovery(ctx)
	if cfg.InstallMode == "server-only" {
		options := clamav.Options{NodeID: cfg.NodeID}
		if credentials != nil {
			options.Peers = clamAVPeers(cfg.NodeCredentialsFile)
		}
		go clamav.Run(ctx, options)
	}
	go handler.RunMonitoring(ctx)
	routes := handler.Routes()
	if strings.TrimSpace(cfg.GRPCListenAddr) != "" {
		go func() {
			lis, err := net.Listen("tcp", cfg.GRPCListenAddr)
			if err != nil {
				log.Printf("warning: grpc listen failed on %s: %v", cfg.GRPCListenAddr, err)
				return
			}
			defer lis.Close()
			control, err := grpccontrol.NewServerWithTLS(st, cfg.AgentURL, cfg.DefaultInterface, controlAgentCAFile(cfg), cfg.TLSInsecureSkipVerify)
			if err != nil {
				log.Printf("warning: grpc control TLS client setup failed: %v", err)
				return
			}
			control.SetManagerURL(managerHTTPURL(cfg))
			control.RequireNodeAuth(credentials)
			var serverOptions []grpc.ServerOption
			if cfg.TLSEnabled {
				tlsConfig, err := transporttls.ServerConfig(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.GRPCListenAddr)
				if err != nil {
					log.Printf("gRPC TLS: %v", err)
					return
				}
				serverOptions = append(serverOptions, grpc.Creds(grpccredentials.NewTLS(tlsConfig)))
			}
			grpcServer := grpc.NewServer(serverOptions...)
			go func() {
				<-ctx.Done()
				grpcServer.Stop()
			}()
			control.Register(grpcServer)
			log.Printf("nodewall server grpc listening on %s", cfg.GRPCListenAddr)
			if err := grpcServer.Serve(lis); err != nil {
				log.Printf("warning: grpc server stopped: %v", err)
			}
		}()
	}
	if strings.TrimSpace(cfg.QUICListenAddr) != "" {
		go func() {
			control, err := grpccontrol.NewServerWithTLS(st, cfg.AgentURL, cfg.DefaultInterface, controlAgentCAFile(cfg), cfg.TLSInsecureSkipVerify)
			if err != nil {
				log.Printf("warning: QUIC control TLS client setup failed: %v", err)
				return
			}
			control.SetManagerURL(managerHTTPURL(cfg))
			control.RequireNodeAuth(credentials)
			if err := grpccontrol.ServeHTTP3WithWebTransport(ctx, cfg.QUICListenAddr, cfg.TLSCertFile, cfg.TLSKeyFile, func(transport *webtransport.Server) http.Handler {
				quicMux := http.NewServeMux()
				quicMux.Handle("/v1/report", grpccontrol.NewQUICHandler(control))
				quicMux.Handle("/", handler.RoutesWithWebTransport(transport))
				return quicMux
			}); err != nil {
				log.Printf("warning: QUIC control server stopped: %v", err)
			}
		}()
		log.Printf("nodewall server QUIC control listening on %s", cfg.QUICListenAddr)
	}
	log.Printf("nodewall server listening on %s", cfg.ListenAddr)
	return serveHTTPContext(ctx, cfg.ListenAddr, cfg.TLSEnabled, cfg.TLSCertFile, cfg.TLSKeyFile, routes)
}

// controlAgentCAFile is separate from TLSCAFile. TLSCAFile trusts the active
// manager for outbound heartbeats, while the local control server's helper
// client talks to the node agent and must trust that agent certificate. On an
// all-in-one/standby manager both services share the host, so using the manager
// CA here makes local reconciliation fail with "unknown authority" whenever
// the two self-signed certificates differ.
func controlAgentCAFile(cfg config.ServerConfig) string {
	if strings.TrimSpace(cfg.InstallMode) != "server-only" && strings.TrimSpace(cfg.AgentTLSCertFile) != "" {
		return cfg.AgentTLSCertFile
	}
	return cfg.TLSCAFile
}

func agentHostPort(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || parsed.Host == "" {
		return strings.TrimSpace(raw)
	}
	return parsed.Host
}

func managerHTTPURL(cfg config.ServerConfig) string {
	listenHost, listenPort, err := net.SplitHostPort(strings.TrimSpace(cfg.ListenAddr))
	if err != nil || strings.TrimSpace(listenPort) == "" {
		return ""
	}
	host := strings.TrimSpace(listenHost)
	if host == "" || host == "0.0.0.0" || host == "::" || strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback() || net.ParseIP(host).IsUnspecified() {
		host = detectManagerAdvertiseIP(cfg.AgentURL)
	}
	if strings.TrimSpace(host) == "" {
		return ""
	}
	scheme := "http"
	if cfg.TLSEnabled {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, listenPort)
}

func detectManagerAdvertiseIP(agentURL string) string {
	if host := strings.TrimSpace(agentHostPort(agentURL)); host != "" {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			if ip := net.ParseIP(parsed); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
				return ip.String()
			}
		} else if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
			return ip.String()
		}
	}
	// A UDP dial discovers the route-selected local address without sending a
	// packet. It is preferable to picking a Docker or bridge address by name.
	if conn, err := net.Dial("udp", "192.0.2.1:80"); err == nil {
		local := conn.LocalAddr().String()
		_ = conn.Close()
		if host, _, splitErr := net.SplitHostPort(local); splitErr == nil {
			if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip.String()
			}
		}
	}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			parsed, _, err := net.ParseCIDR(address.String())
			if err == nil && parsed.To4() != nil && !parsed.IsLinkLocalUnicast() {
				return parsed.String()
			}
		}
	}
	return ""
}

func RunAgent() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.LoadAgentConfig()
	if cfg.TLSEnabled && cfg.TLSInsecureSkipVerify {
		log.Printf("warning: agent outbound TLS certificate verification is disabled; configure NODEWALL_TLS_CA and set NODEWALL_TLS_INSECURE_SKIP_VERIFY=false")
	}
	var token string
	if cfg.DevMode == "" || cfg.DevMode == "real" {
		var err error
		token, err = nodeauth.LoadOrCreateToken(cfg.TokenFile)
		if err != nil {
			return err
		}
	}
	if cfg.TLSEnabled {
		if err := transporttls.EnsureCertificate(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.ListenAddr); err != nil {
			return err
		}
	}
	agentCertificate := ""
	if cfg.TLSEnabled {
		certificate, err := os.ReadFile(cfg.TLSCertFile)
		if err != nil {
			return fmt.Errorf("read agent TLS certificate: %w", err)
		}
		agentCertificate = string(certificate)
	}
	if token != "" && cfg.TLSCAFile == "" && cfg.ManagerURL == "" {
		cfg.TLSCAFile = cfg.TLSCertFile
	}
	xdpManager, err := xdp.NewDataplane(cfg.DataplaneMode, cfg.BPFObjectPath)
	if err != nil {
		return err
	}
	stateStore := store.NewFileStateStore(cfg.StateFile)
	recorder, err := droplog.New(cfg.DropLogDir, cfg.DropLogStateFile, models.DropLogSettings{
		Enabled:                 cfg.DropLogEnabled,
		LogDir:                  cfg.DropLogDir,
		RetentionDays:           cfg.DropLogRetention,
		FlushIntervalSeconds:    int(maxDuration(cfg.DropLogFlush, time.Second) / time.Second),
		ReplyFlowTimeoutSeconds: int(maxDuration(cfg.ReplyFlowTimeout, 60*time.Second) / time.Second),
	})
	if err != nil {
		// A corrupt audit checkpoint can result from an interrupted host
		// reboot. Keep protection and management available with defaults.
		log.Printf("warning: %v; using configured drop log defaults", err)
	}
	if legacy, ok := xdpManager.(*xdp.IPTablesManager); ok {
		if err := legacy.StartPacketAudit(ctx, recorder.RecordPacketAudit); err != nil {
			log.Printf("warning: iptables packet samples unavailable; rule counters remain active: %v", err)
		}
	}
	geoDB, err := geoip.LoadCountryDB(cfg.GeoIPDBPath)
	if err != nil {
		log.Printf("warning: failed to load GeoIP database: %v", err)
	}
	handler := api.NewAgentHandler(cfg.NodeID, xdpManager, stateStore, cfg.ConfirmTimeout, recorder, geoDB, api.SSHProtectionOptions{
		StateStore:            store.NewSSHProtectionStore(cfg.SSHProtectionStateFile),
		LogPath:               cfg.SSHAuthLogPath,
		PollInterval:          cfg.SSHProtectionPoll,
		ActivityLogPath:       cfg.SSHActivityLogPath,
		ManagedConsoleKeyPath: cfg.SSHKeyPath,
	})
	go func() {
		if err := sshactivity.ServeJournal(ctx, cfg.SSHActivityLogPath); err != nil {
			log.Printf("warning: local SSH journal service unavailable: %v", err)
		}
	}()
	if err := handler.ConfigureSecurityArchive(cfg.ScanReportDir); err != nil {
		// Report storage is auxiliary: a full or unavailable disk must not
		// prevent policy recovery or make the firewall agent unreachable.
		log.Printf("warning: scan report archive unavailable; new scans disabled: %v", err)
	}

	if err := handler.LoadState(context.Background()); err != nil {
		log.Printf("warning: failed to load persisted state: %v", err)
	}
	if err := handler.LoadSSHProtectionState(context.Background()); err != nil {
		log.Printf("warning: failed to load SSH protection state: %v", err)
	} else if cfg.DevMode == "" || cfg.DevMode == "real" {
		if err := handler.ReconcileSSHTransferPolicy(ctx); err != nil {
			log.Printf("warning: existing SSH transfer policy could not be verified: %v", err)
		}
		if err := handler.ReconcileSSHAuthenticationPolicy(ctx); err != nil {
			log.Printf("warning: existing SSH password-login policy could not be verified: %v", err)
		}
	}

	go recorder.Run(ctx, xdpManager)
	if reconciler, ok := xdpManager.(interface{ Reconcile() error }); ok {
		go runDataplaneReconciler(ctx, cfg.IPTablesReconcileEvery, reconciler)
	}
	go handler.RunSSHProtection(ctx)
	// Heartbeats are already sent every ten seconds. Reuse their response as a
	// low-cost update notification so child agents converge shortly after the
	// manager package changes, while the autoupdate ticker remains a fallback.
	updateTrigger := make(chan struct{}, 1)
	triggerUpdate := func() {
		select {
		case updateTrigger <- struct{}{}:
		default:
		}
	}
	var managerURLMu sync.RWMutex
	currentManagerURL := strings.TrimRight(strings.TrimSpace(cfg.ManagerURL), "/")
	managerURLSource := func() string {
		managerURLMu.RLock()
		defer managerURLMu.RUnlock()
		return currentManagerURL
	}
	setManagerURL := func(managerURL string) {
		managerURL = strings.TrimRight(strings.TrimSpace(managerURL), "/")
		parsed, err := url.Parse(managerURL)
		if err != nil || parsed == nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return
		}
		managerURLMu.Lock()
		currentManagerURL = managerURL
		managerURLMu.Unlock()
		// Keep child updater processes in sync immediately. The updater persists
		// this value to nodewall.env when it replaces the installed runtime.
		_ = os.Setenv("NODEWALL_MANAGER_URL", managerURL)
	}
	// Expose the same authenticated updater used by the periodic loop through
	// node management. The target-aware callback lets the active manager pass
	// its current web URL during a 8080 -> 8086 migration, even when this node
	// still has the legacy manager URL in nodewall.env.
	forceUpdate := func(updateCtx context.Context, managerURL string) error {
		return autoupdate.ForceUpdate(updateCtx, autoupdate.AgentOptions{
			ManagerURL:            managerURL,
			TLSCAFile:             cfg.TLSCAFile,
			TLSInsecureSkipVerify: cfg.TLSInsecureSkipVerify,
			Token:                 token,
			NodeID:                cfg.NodeID,
		})
	}
	handler.SetMaintenanceUpdateTargetFunc(forceUpdate)
	if strings.TrimSpace(cfg.ManagerURL) != "" {
		handler.SetMaintenanceUpdateFunc(func(updateCtx context.Context) error {
			return forceUpdate(updateCtx, managerURLSource())
		})
	}
	packageVersion := version.Current().PackageVersion
	if strings.TrimSpace(cfg.ManagerGRPCAddr) != "" {
		go func() {
			agentHTTPAddr := strings.TrimSpace(cfg.AgentHTTPAddr)
			if agentHTTPAddr == "" {
				agentHTTPAddr = strings.TrimSpace(cfg.ListenAddr)
			}
			if err := grpccontrol.ReportLoop(ctx, cfg.ManagerGRPCAddr, grpccontrol.ReportRequest{
				NodeID:           cfg.NodeID,
				NodeName:         nodeDisplayName(cfg.NodeID),
				AgentHTTPAddr:    agentHTTPAddr,
				AgentURL:         agentURLForReport(cfg),
				AgentCertificate: agentCertificate,
				ServerHTTPAddr:   cfg.ServerHTTPAddr,
				PackageVersion:   packageVersion,
				OnUpdate:         triggerUpdate,
				OnManagerURL:     setManagerURL,
			}, 10*time.Second, grpccontrol.ClientSecurity{Token: token, CAFile: cfg.TLSCAFile, CertFile: cfg.TLSCertFile, InsecureSkipVerify: cfg.TLSInsecureSkipVerify}); err != nil {
				log.Printf("warning: grpc report loop failed: %v", err)
			}
		}()
	}
	if strings.TrimSpace(cfg.ManagerURL) != "" {
		go func() {
			if err := grpccontrol.ReportLoopHTTP(ctx, cfg.ManagerURL, grpccontrol.ReportRequest{
				NodeID:           cfg.NodeID,
				NodeName:         nodeDisplayName(cfg.NodeID),
				AgentHTTPAddr:    agentHTTPAddrForReport(cfg),
				AgentURL:         agentURLForReport(cfg),
				AgentCertificate: agentCertificate,
				ServerHTTPAddr:   cfg.ServerHTTPAddr,
				PackageVersion:   packageVersion,
				OnUpdate:         triggerUpdate,
				OnManagerURL:     setManagerURL,
			}, 10*time.Second, grpccontrol.ClientSecurity{Token: token, CAFile: cfg.TLSCAFile, CertFile: cfg.TLSCertFile, InsecureSkipVerify: cfg.TLSInsecureSkipVerify}); err != nil {
				log.Printf("warning: HTTPS heartbeat loop failed: %v", err)
			}
		}()
	}
	if strings.TrimSpace(cfg.ManagerQUICAddr) != "" {
		go func() {
			if err := grpccontrol.ReportLoopQUIC(ctx, cfg.ManagerURL, cfg.ManagerQUICAddr, grpccontrol.ReportRequest{
				NodeID:           cfg.NodeID,
				NodeName:         nodeDisplayName(cfg.NodeID),
				AgentHTTPAddr:    agentHTTPAddrForReport(cfg),
				AgentURL:         agentURLForReport(cfg),
				AgentCertificate: agentCertificate,
				ServerHTTPAddr:   cfg.ServerHTTPAddr,
				PackageVersion:   packageVersion,
				OnUpdate:         triggerUpdate,
				OnManagerURL:     setManagerURL,
			}, 10*time.Second, cfg.TLSCAFile, cfg.TLSInsecureSkipVerify, token); err != nil {
				log.Printf("warning: QUIC report loop failed: %v", err)
			}
		}()
	}
	if cfg.AutoUpdate {
		go autoupdate.RunLoop(ctx, autoupdate.AgentOptions{
			ManagerURL:            cfg.ManagerURL,
			ManagerURLSource:      managerURLSource,
			Interval:              cfg.AutoUpdateEvery,
			TLSCAFile:             cfg.TLSCAFile,
			TLSInsecureSkipVerify: cfg.TLSInsecureSkipVerify,
			Token:                 token,
			NodeID:                cfg.NodeID,
			Trigger:               updateTrigger,
		})
	}
	clamAVOptions := clamav.Options{
		ManagerURL:            managerURLSource,
		NodeID:                cfg.NodeID,
		Token:                 token,
		TLSCAFile:             cfg.TLSCAFile,
		TLSInsecureSkipVerify: cfg.TLSInsecureSkipVerify,
	}
	if cfg.DevMode == "" || cfg.DevMode == "real" {
		clamAVOptions.Peers = clamAVPeers(config.LoadServerConfig().NodeCredentialsFile)
	}
	go clamav.Run(ctx, clamAVOptions)
	log.Printf("nodewall agent listening on %s", cfg.ListenAddr)
	recoveryCtx, cancelRecovery := context.WithCancel(ctx)
	recoveryDone := make(chan struct{})
	go func() {
		defer close(recoveryDone)
		handler.RunInterfaceRecovery(recoveryCtx)
	}()
	defer func() {
		cancelRecovery()
		<-recoveryDone
		detachDataplane(xdpManager)
	}()
	var routes http.Handler = handler.Routes()
	if token != "" {
		routes = nodeauth.RequireToken(token, routes)
	}
	return serveHTTPContext(ctx, cfg.ListenAddr, cfg.TLSEnabled, cfg.TLSCertFile, cfg.TLSKeyFile, routes)
}

// detachDataplane is part of the agent shutdown path. XDP links normally
// disappear with the owning process, but the iptables compatibility backend
// leaves host rules behind unless it is explicitly detached. Cleaning both
// backends here makes systemd restarts and controlled upgrades fail-open.
func detachDataplane(dataplane xdp.Dataplane) {
	for _, iface := range dataplane.Interfaces() {
		if err := dataplane.Detach(iface); err != nil {
			log.Printf("warning: detach dataplane from %s during shutdown: %v", iface, err)
		}
	}
}

func serveHTTP(addr string, enabled bool, certFile, keyFile string, handler http.Handler) error {
	if !enabled {
		return http.ListenAndServe(addr, handler)
	}
	tlsConfig, err := transporttls.ServerConfig(certFile, keyFile, addr)
	if err != nil {
		return err
	}
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	server := &http.Server{Addr: addr, Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	return server.ListenAndServeTLS("", "")
}

func serveHTTPContext(ctx context.Context, addr string, enabled bool, certFile, keyFile string, handler http.Handler) error {
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	var err error
	if !enabled {
		err = server.ListenAndServe()
	} else {
		tlsConfig, configErr := transporttls.ServerConfig(certFile, keyFile, addr)
		if configErr != nil {
			return configErr
		}
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		server.TLSConfig = tlsConfig
		err = server.ListenAndServeTLS("", "")
	}
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

func agentHTTPAddrForReport(cfg config.AgentConfig) string {
	if value := strings.TrimSpace(cfg.AgentHTTPAddr); value != "" {
		return value
	}
	return strings.TrimSpace(cfg.ListenAddr)
}

func agentURLForReport(cfg config.AgentConfig) string {
	scheme := "http"
	if cfg.TLSEnabled {
		scheme = "https"
	}
	address := agentHTTPAddrForReport(cfg)
	if cfg.ManagerURL == "" {
		if host, port, err := net.SplitHostPort(address); err == nil && (host == "0.0.0.0" || host == "::" || host == "") {
			address = net.JoinHostPort("127.0.0.1", port)
		}
	}
	return scheme + "://" + address
}

func serverHTTPAddrForListener(listener, fallbackHost string) string {
	listener = strings.TrimSpace(listener)
	host, port, err := net.SplitHostPort(listener)
	if err != nil || strings.TrimSpace(port) == "" {
		return listener
	}
	if fallbackHost != "" {
		ip := net.ParseIP(host)
		if host == "" || host == "0.0.0.0" || host == "::" || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified())) || strings.EqualFold(host, "localhost") {
			host = fallbackHost
		}
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}

func maxDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func runDataplaneReconciler(ctx context.Context, interval time.Duration, reconciler interface{ Reconcile() error }) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if err := reconciler.Reconcile(); err != nil {
		log.Printf("warning: dataplane reconciliation failed: %v", err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := reconciler.Reconcile(); err != nil {
				log.Printf("warning: dataplane reconciliation failed: %v", err)
			}
		}
	}
}

func nodeDisplayName(fallback string) string {
	if host, err := os.Hostname(); err == nil {
		if trimmed := strings.TrimSpace(host); trimmed != "" {
			return trimmed
		}
	}
	return fallback
}
