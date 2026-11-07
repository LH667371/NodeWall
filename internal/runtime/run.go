package runtime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"nodewall/internal/api"
	"nodewall/internal/autoupdate"
	"nodewall/internal/config"
	"nodewall/internal/droplog"
	"nodewall/internal/geoip"
	"nodewall/internal/grpccontrol"
	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/service"
	"nodewall/internal/sshactivity"
	"nodewall/internal/store"
	"nodewall/internal/transporttls"
	"nodewall/internal/version"
	"nodewall/internal/xdp"

	"github.com/cilium/ebpf/rlimit"
	"github.com/quic-go/webtransport-go"
	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
)

func RunServer() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg := config.LoadServerConfig()
	if cfg.TLSEnabled {
		if err := transporttls.EnsureCertificate(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.ListenAddr); err != nil {
			return err
		}
	}
	st, err := store.NewPersistent(cfg.StateFile)
	if err != nil {
		return err
	}
	if cfg.InstallMode != "server-only" {
		st.UpsertNode(context.Background(), models.Node{
			ID:       cfg.NodeID,
			Name:     nodeDisplayName(cfg.NodeID),
			AgentURL: cfg.AgentURL,
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
			return err
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
			control, err := grpccontrol.NewServerWithTLS(st, cfg.AgentURL, cfg.DefaultInterface, cfg.TLSCAFile, cfg.TLSInsecureSkipVerify)
			if err != nil {
				log.Printf("warning: grpc control TLS client setup failed: %v", err)
				return
			}
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
			control, err := grpccontrol.NewServerWithTLS(st, cfg.AgentURL, cfg.DefaultInterface, cfg.TLSCAFile, cfg.TLSInsecureSkipVerify)
			if err != nil {
				log.Printf("warning: QUIC control TLS client setup failed: %v", err)
				return
			}
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

func RunAgent() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.LoadAgentConfig()
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
	if token != "" && cfg.TLSCAFile == "" && cfg.ManagerURL == "" {
		cfg.TLSCAFile = cfg.TLSCertFile
	}
	if cfg.DataplaneMode == "real" {
		// systemd normally supplies LimitMEMLOCK, but agents can also run in
		// containers or under a supervisor that ignores the unit file. Raise
		// the process limit before cilium/ebpf creates any maps so attach errors
		// remain actionable instead of surfacing as a generic EPERM.
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("raise BPF memlock limit: %w", err)
		}
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
		return err
	}
	geoDB, err := geoip.LoadCountryDB(cfg.GeoIPDBPath)
	if err != nil {
		log.Printf("warning: failed to load GeoIP database: %v", err)
	}
	handler := api.NewAgentHandler(cfg.NodeID, xdpManager, stateStore, cfg.ConfirmTimeout, recorder, geoDB, api.SSHProtectionOptions{
		StateStore:      store.NewSSHProtectionStore(cfg.SSHProtectionStateFile),
		LogPath:         cfg.SSHAuthLogPath,
		PollInterval:    cfg.SSHProtectionPoll,
		ActivityLogPath: cfg.SSHActivityLogPath,
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
	packageVersion := version.Current().PackageVersion
	if strings.TrimSpace(cfg.ManagerGRPCAddr) != "" {
		go func() {
			agentHTTPAddr := strings.TrimSpace(cfg.AgentHTTPAddr)
			if agentHTTPAddr == "" {
				agentHTTPAddr = strings.TrimSpace(cfg.ListenAddr)
			}
			if err := grpccontrol.ReportLoop(ctx, cfg.ManagerGRPCAddr, grpccontrol.ReportRequest{
				NodeID:         cfg.NodeID,
				NodeName:       nodeDisplayName(cfg.NodeID),
				AgentHTTPAddr:  agentHTTPAddr,
				AgentURL:       agentURLForReport(cfg),
				PackageVersion: packageVersion,
				OnUpdate:       triggerUpdate,
			}, 10*time.Second, grpccontrol.ClientSecurity{Token: token, CAFile: cfg.TLSCAFile, CertFile: cfg.TLSCertFile, InsecureSkipVerify: cfg.TLSInsecureSkipVerify}); err != nil {
				log.Printf("warning: grpc report loop failed: %v", err)
			}
		}()
	}
	if strings.TrimSpace(cfg.ManagerURL) != "" {
		go func() {
			if err := grpccontrol.ReportLoopHTTP(ctx, cfg.ManagerURL, grpccontrol.ReportRequest{
				NodeID:         cfg.NodeID,
				NodeName:       nodeDisplayName(cfg.NodeID),
				AgentHTTPAddr:  agentHTTPAddrForReport(cfg),
				AgentURL:       agentURLForReport(cfg),
				PackageVersion: packageVersion,
				OnUpdate:       triggerUpdate,
			}, 10*time.Second, grpccontrol.ClientSecurity{Token: token, CAFile: cfg.TLSCAFile, CertFile: cfg.TLSCertFile, InsecureSkipVerify: cfg.TLSInsecureSkipVerify}); err != nil {
				log.Printf("warning: HTTPS heartbeat loop failed: %v", err)
			}
		}()
	}
	if strings.TrimSpace(cfg.ManagerQUICAddr) != "" {
		go func() {
			if err := grpccontrol.ReportLoopQUIC(ctx, cfg.ManagerURL, cfg.ManagerQUICAddr, grpccontrol.ReportRequest{
				NodeID:         cfg.NodeID,
				NodeName:       nodeDisplayName(cfg.NodeID),
				AgentHTTPAddr:  agentHTTPAddrForReport(cfg),
				AgentURL:       agentURLForReport(cfg),
				PackageVersion: packageVersion,
				OnUpdate:       triggerUpdate,
			}, 10*time.Second, cfg.TLSCAFile, cfg.TLSInsecureSkipVerify, token); err != nil {
				log.Printf("warning: QUIC report loop failed: %v", err)
			}
		}()
	}
	if cfg.AutoUpdate {
		go autoupdate.RunLoop(ctx, autoupdate.AgentOptions{
			ManagerURL:            cfg.ManagerURL,
			Interval:              cfg.AutoUpdateEvery,
			TLSCAFile:             cfg.TLSCAFile,
			TLSInsecureSkipVerify: cfg.TLSInsecureSkipVerify,
			Token:                 token,
			NodeID:                cfg.NodeID,
			Trigger:               updateTrigger,
		})
	}
	log.Printf("nodewall agent listening on %s", cfg.ListenAddr)
	defer detachDataplane(xdpManager)
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
	return server.ListenAndServeTLS(certFile, keyFile)
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
		err = server.ListenAndServeTLS(certFile, keyFile)
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
