package grpccontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/store"
	"nodewall/internal/transporttls"
	"nodewall/internal/version"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	serviceName = "nodewall.control.Control"
	methodName  = "/nodewall.control.Control/Report"
)

type jsonCodec struct{}

func (jsonCodec) Name() string                       { return "json" }
func (jsonCodec) Marshal(v any) ([]byte, error)      { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

type ReportRequest struct {
	NodeID         string   `json:"node_id"`
	NodeName       string   `json:"node_name"`
	AgentHTTPAddr  string   `json:"agent_http_addr"`
	AgentURL       string   `json:"agent_url,omitempty"`
	PackageVersion string   `json:"package_version,omitempty"`
	Interfaces     []string `json:"interfaces,omitempty"`
	// OnUpdate is local-only and is deliberately omitted from the wire request.
	// Heartbeat responses use it to wake the auto-update loop immediately.
	OnUpdate func() `json:"-"`
}

type ReportResponse struct {
	ServerTime         time.Time `json:"server_time"`
	RecommendedAgentIP string    `json:"recommended_agent_ip,omitempty"`
	PackageVersion     string    `json:"package_version,omitempty"`
	UpdateAvailable    bool      `json:"update_available,omitempty"`
}

type Server struct {
	credentials      *nodeauth.Registry
	store            *store.Store
	agentBaseURL     string
	defaultInterface string
	httpClient       *http.Client
}

func (s *Server) RequireNodeAuth(registry *nodeauth.Registry) { s.credentials = registry }

type ClientSecurity struct {
	Token              string
	CAFile             string
	CertFile           string
	InsecureSkipVerify bool
}

type ControlService interface {
	Report(context.Context, *ReportRequest) (*ReportResponse, error)
}

func NewServer(st *store.Store, agentBaseURL, defaultInterface string) *Server {
	return &Server{
		store:            st,
		agentBaseURL:     normalizeAgentURL(agentBaseURL),
		defaultInterface: strings.TrimSpace(defaultInterface),
		httpClient:       &http.Client{Timeout: 3 * time.Second},
	}
}

// NewServerWithTLS configures the internal HTTP client used for cluster trust
// synchronization. It is separate from the gRPC/HTTP3 listener TLS because
// this client also calls each agent's HTTPS API during node reports.
func NewServerWithTLS(st *store.Store, agentBaseURL, defaultInterface, caFile string, insecureSkipVerify bool) (*Server, error) {
	server := NewServer(st, agentBaseURL, defaultInterface)
	tlsConfig, err := transporttls.ClientConfig(caFile, "", insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	server.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
	return server, nil
}

func (s *Server) Register(grpcServer *grpc.Server) {
	desc := grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*ControlService)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Report",
				Handler:    s.reportHandler,
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "nodewall-control",
	}
	grpcServer.RegisterService(&desc, s)
}

// NewQUICHandler exposes the same small control surface over HTTP/3. Keeping
// the payload and business logic identical to the gRPC fallback makes mixed
// version upgrades safe while new agents switch to QUIC first.
func NewQUICHandler(service *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/report", func(w http.ResponseWriter, r *http.Request) {
		var request ReportRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
			http.Error(w, "invalid report", http.StatusBadRequest)
			return
		}
		ctx := metadata.NewIncomingContext(r.Context(), metadata.Pairs("authorization", r.Header.Get("Authorization")))
		if addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr); err == nil {
			ctx = peer.NewContext(ctx, &peer.Peer{Addr: addr})
		}
		response, err := service.Report(ctx, &request)
		if err != nil {
			code := http.StatusBadRequest
			if status.Code(err) == codes.Unauthenticated {
				code = http.StatusUnauthorized
			}
			http.Error(w, err.Error(), code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	return mux
}

// ServeQUIC starts the encrypted HTTP/3 control endpoint. The generated
// self-signed certificate is intentionally shared with the web TLS setup so a
// deployment has one straightforward certificate lifecycle.
func ServeQUIC(ctx context.Context, addr, certFile, keyFile string, service *Server) error {
	return ServeHTTP3(ctx, addr, certFile, keyFile, NewQUICHandler(service))
}

// ServeHTTP3 serves a handler over QUIC. It is used both by the internal
// control endpoint and by the browser-facing API so the browser can migrate
// to HTTP/3 after learning the Alt-Svc advertised by the HTTPS listener.
func ServeHTTP3(ctx context.Context, addr, certFile, keyFile string, handler http.Handler) error {
	tlsConfig, err := transporttls.QUICServerConfig(certFile, keyFile, addr)
	if err != nil {
		return err
	}
	server := &http3.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   handler,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeHTTP3WithWebTransport starts an HTTP/3 endpoint that also accepts
// WebTransport sessions. The browser-facing endpoint uses a separate UDP
// address, so the page origin and the HTTP/3 origin can have different ports;
// the origin check below deliberately requires the same hostname.
func ServeHTTP3WithWebTransport(ctx context.Context, addr, certFile, keyFile string, handlerFactory func(*webtransport.Server) http.Handler) error {
	tlsConfig, err := transporttls.QUICServerConfig(certFile, keyFile, addr)
	if err != nil {
		return err
	}
	h3Server := &http3.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
	}
	webTransportServer := &webtransport.Server{
		H3: h3Server,
		CheckOrigin: func(r *http.Request) bool {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				return true
			}
			parsed, parseErr := url.Parse(origin)
			if parseErr != nil || parsed.Hostname() == "" || r.Host == "" {
				return false
			}
			return strings.EqualFold(parsed.Hostname(), requestHostname(r.Host))
		},
	}
	webtransport.ConfigureHTTP3Server(h3Server)
	h3Server.Handler = handlerFactory(webTransportServer)

	go func() {
		<-ctx.Done()
		_ = webTransportServer.Close()
	}()
	if err := webTransportServer.ListenAndServe(); ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, context.Canceled) {
		return nil
	} else {
		return err
	}
}

func requestHostname(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(hostport, "[]")
}

func (s *Server) reportHandler(_ any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req ReportRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return s.Report(ctx, &req)
	}
	return interceptor(ctx, &req, &grpc.UnaryServerInfo{Server: s, FullMethod: methodName}, func(ctx context.Context, request any) (any, error) { return s.Report(ctx, request.(*ReportRequest)) })
}

func (s *Server) Report(ctx context.Context, req *ReportRequest) (*ReportResponse, error) {
	if s.credentials != nil {
		md, _ := metadata.FromIncomingContext(ctx)
		values := md.Get("authorization")
		if len(values) != 1 || !s.credentials.Authenticate(req.NodeID, nodeauth.Bearer(values[0])) {
			return nil, status.Error(codes.Unauthenticated, "node enrollment required")
		}
		credential, _ := s.credentials.Get(req.NodeID)
		origin, err := nodeauth.Origin(req.AgentURL)
		if err != nil || origin != credential.AgentURL {
			return nil, status.Error(codes.PermissionDenied, "agent endpoint changed; enroll this node again")
		}
	}
	if strings.TrimSpace(req.NodeID) == "" {
		return nil, fmt.Errorf("node_id is required")
	}
	if strings.TrimSpace(req.AgentHTTPAddr) == "" {
		return nil, fmt.Errorf("agent_http_addr is required")
	}

	peerIP := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err == nil {
			peerIP = host
		} else {
			peerIP = p.Addr.String()
		}
	}
	advertiseIP := normalizeAdvertiseIP(peerIP)

	agentHTTPAddr := strings.TrimSpace(req.AgentHTTPAddr)
	// In an all-in-one installation the agent intentionally listens only on
	// loopback. The report travels over loopback as well, so rewriting
	// 127.0.0.1 to the host's primary address makes the server proxy back to an
	// address where the agent is not listening. Remote agents still advertise
	// their peer address as before.
	preserveLocalAgent := preserveLoopbackAgentAddress(s.agentBaseURL, peerIP)
	if !preserveLocalAgent {
		if strings.HasPrefix(agentHTTPAddr, ":") && advertiseIP != "" {
			agentHTTPAddr = advertiseIP + agentHTTPAddr
		}
		if host, port, err := net.SplitHostPort(agentHTTPAddr); err == nil {
			if advertiseIP != "" && (host == "" || host == "0.0.0.0" || host == "::" || host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost")) {
				agentHTTPAddr = net.JoinHostPort(advertiseIP, port)
			}
		}
	}
	agentScheme := "http"
	if parsed, err := url.Parse(strings.TrimSpace(req.AgentURL)); err == nil && parsed.Scheme != "" {
		agentScheme = parsed.Scheme
	}
	node := models.Node{
		ID:            req.NodeID,
		Name:          firstNonEmpty(req.NodeName, req.NodeID),
		AdvertiseIP:   advertiseIP,
		AgentHTTPAddr: agentHTTPAddr,
		AgentURL:      agentScheme + "://" + agentHTTPAddr,
		LastSeenAt:    time.Now().UTC(),
	}
	if s.credentials != nil {
		credential, _ := s.credentials.Get(req.NodeID)
		endpoint, _ := url.Parse(credential.AgentURL)
		node.AgentURL = credential.AgentURL
		node.AgentHTTPAddr = endpoint.Host
		// The manager's own AgentURL intentionally stays on loopback so its
		// reverse proxy uses the local agent. Keep the externally useful
		// advertise address from the peer report in that all-in-one case.
		node.AdvertiseIP = advertiseIPForEndpoint(endpoint.Hostname(), advertiseIP)
	}
	if err := s.store.UpsertNodeChecked(ctx, node); err != nil {
		return nil, status.Error(codes.Internal, "cannot persist node heartbeat")
	}
	// A heartbeat only records node availability. It must never alter policy
	// maps on another node: protection is enabled explicitly from the console
	// and then takes effect immediately for that selected node.

	remoteVersion := version.Current().PackageVersion
	return &ReportResponse{
		ServerTime:         time.Now().UTC(),
		RecommendedAgentIP: advertiseIP,
		PackageVersion:     remoteVersion,
		UpdateAvailable:    packageUpdateAvailable(req.PackageVersion, remoteVersion),
	}, nil
}

func packageUpdateAvailable(local, remote string) bool {
	local = strings.TrimSpace(local)
	remote = strings.TrimSpace(remote)
	return local != "" && remote != "" && local != remote
}

func normalizeAdvertiseIP(peerIP string) string {
	ip := strings.TrimSpace(peerIP)
	if ip == "" {
		return ip
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if !parsed.IsLoopback() {
		return ip
	}
	primary := detectPrimaryIPv4()
	if primary != "" {
		return primary
	}
	return ip
}

func advertiseIPForEndpoint(endpointHost, reportedIP string) string {
	endpointHost = strings.TrimSpace(endpointHost)
	if endpointHost == "" {
		return reportedIP
	}
	parsed := net.ParseIP(endpointHost)
	if parsed != nil && parsed.IsLoopback() {
		return reportedIP
	}
	return endpointHost
}

func preserveLoopbackAgentAddress(agentBaseURL, peerIP string) bool {
	peer := net.ParseIP(strings.TrimSpace(peerIP))
	if peer == nil || !peer.IsLoopback() {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(agentBaseURL))
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	baseIP := net.ParseIP(parsed.Hostname())
	return baseIP != nil && baseIP.IsLoopback()
}

func detectPrimaryIPv4() string {
	// A UDP connect selects the kernel's default route without sending an
	// application payload. It avoids presenting docker0 or another secondary
	// interface as the host's externally reachable address.
	if conn, err := net.DialTimeout("udp4", "8.8.8.8:80", time.Second); err == nil {
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil && !addr.IP.IsLoopback() {
			ip := addr.IP.To4()
			_ = conn.Close()
			if ip != nil {
				return ip.String()
			}
		} else {
			_ = conn.Close()
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet == nil || ipNet.IP == nil {
				continue
			}
			v4 := ipNet.IP.To4()
			if v4 == nil || v4.IsLoopback() {
				continue
			}
			return v4.String()
		}
	}
	return ""
}

func (s *Server) fetchRecommendedInterface(ctx context.Context) (string, error) {
	return s.fetchRecommendedInterfaceForNode(ctx, s.agentBaseURL)
}

func (s *Server) fetchRecommendedInterfaceForNode(ctx context.Context, agentURL string) (string, error) {
	agentURL = strings.TrimRight(strings.TrimSpace(agentURL), "/")
	if agentURL == "" {
		return "", nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agentURL+"/interfaces", nil)
	if err != nil {
		return "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch interfaces failed: %s", resp.Status)
	}
	var payload struct {
		Recommended string `json:"recommended"`
		Interfaces  []struct {
			Name string `json:"name"`
		} `json:"interfaces"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Recommended) != "" {
		return strings.TrimSpace(payload.Recommended), nil
	}
	if len(payload.Interfaces) > 0 {
		return strings.TrimSpace(payload.Interfaces[0].Name), nil
	}
	return "", nil
}

func (s *Server) fetchPhysicalInterfacesForNode(ctx context.Context, agentURL string) ([]string, error) {
	agentURL = strings.TrimRight(strings.TrimSpace(agentURL), "/")
	if agentURL == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agentURL+"/interfaces", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch interfaces failed: %s", resp.Status)
	}
	var payload struct {
		Interfaces []struct {
			Name       string `json:"name"`
			IsPhysical bool   `json:"is_physical"`
		} `json:"interfaces"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(payload.Interfaces))
	for _, item := range payload.Interfaces {
		name := strings.TrimSpace(item.Name)
		if name == "" || !item.IsPhysical {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

func normalizeAgentURL(raw string) string {
	value := strings.TrimRight(strings.TrimSpace(raw), "/")
	value = strings.Replace(value, "://0.0.0.0:", "://127.0.0.1:", 1)
	return value
}

func ReportLoop(ctx context.Context, managerGRPCAddr string, req ReportRequest, interval time.Duration, options ...ClientSecurity) error {
	if strings.TrimSpace(managerGRPCAddr) == "" {
		return nil
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	transportCredentials := credentials.TransportCredentials(insecure.NewCredentials())
	if len(options) > 0 && options[0].Token != "" {
		security := options[0]
		caFile := security.CAFile
		if caFile == "" {
			caFile = security.CertFile
		}
		tlsConfig, err := transporttls.ClientConfig(caFile, "", security.InsecureSkipVerify)
		if err != nil {
			return err
		}
		transportCredentials = credentials.NewTLS(tlsConfig)
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := grpc.DialContext(connectCtx, managerGRPCAddr,
			grpc.WithTransportCredentials(transportCredentials), grpc.WithBlock())
		cancel()
		if err != nil {
			if !waitReportRetry(ctx, backoff) {
				return nil
			}
			backoff = nextReportBackoff(backoff)
			continue
		}

		reportCtx := ctx
		if len(options) > 0 && options[0].Token != "" {
			reportCtx = metadata.AppendToOutgoingContext(reportCtx, "authorization", "Bearer "+options[0].Token)
		}
		ticker := time.NewTicker(interval)
		send := func() error {
			var resp ReportResponse
			if err := conn.Invoke(reportCtx, methodName, &req, &resp, grpc.CallContentSubtype("json")); err != nil {
				return err
			}
			if resp.UpdateAvailable && req.OnUpdate != nil {
				req.OnUpdate()
			}
			return nil
		}
		reportErr := send()
		for reportErr == nil {
			select {
			case <-ctx.Done():
				ticker.Stop()
				_ = conn.Close()
				return nil
			case <-ticker.C:
				reportErr = send()
			}
		}
		ticker.Stop()
		_ = conn.Close()
		log.Printf("warning: gRPC heartbeat disconnected: %v", reportErr)
		backoff = time.Second
		if !waitReportRetry(ctx, backoff) {
			return nil
		}
	}
}

// ReportLoopHTTP provides a heartbeat path over the manager's HTTPS listener.
// It keeps nodes online when an existing host policy has not yet opened the
// optional gRPC/QUIC ports, and it also serves as a simple reconnecting path
// after a manager restart.
func ReportLoopHTTP(ctx context.Context, managerURL string, req ReportRequest, interval time.Duration, security ClientSecurity) error {
	managerURL = strings.TrimRight(strings.TrimSpace(managerURL), "/")
	if managerURL == "" {
		return nil
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	tlsConfig, err := transporttls.ClientConfig(security.CAFile, "", security.InsecureSkipVerify)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}}
	report := func() error {
		body, err := json.Marshal(req)
		if err != nil {
			return err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, managerURL+"/join/heartbeat", bytes.NewReader(body))
		if err != nil {
			return err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set(nodeauth.NodeHeader, req.NodeID)
		if security.Token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+security.Token)
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			message, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			return fmt.Errorf("HTTPS heartbeat failed: %s: %s", resp.Status, strings.TrimSpace(string(message)))
		}
		var heartbeat ReportResponse
		if err := json.NewDecoder(resp.Body).Decode(&heartbeat); err == nil && heartbeat.UpdateAvailable && req.OnUpdate != nil {
			req.OnUpdate()
		}
		return nil
	}

	backoff := time.Second
	for {
		if err := report(); err != nil {
			log.Printf("warning: HTTPS heartbeat failed: %v", err)
			if !waitReportRetry(ctx, backoff) {
				return nil
			}
			backoff = nextReportBackoff(backoff)
			continue
		}
		backoff = time.Second
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func waitReportRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextReportBackoff(current time.Duration) time.Duration {
	if current >= 30*time.Second {
		return 30 * time.Second
	}
	return current * 2
}

// ReportLoopQUIC reports node presence over HTTP/3. managerURL is only used
// to determine the manager host when managerQUICAddr is written as :port.
func ReportLoopQUIC(ctx context.Context, managerURL, managerQUICAddr string, req ReportRequest, interval time.Duration, caFile string, insecureSkipVerify bool, tokens ...string) error {
	if strings.TrimSpace(managerQUICAddr) == "" {
		return nil
	}
	endpoint, serverName, err := quicEndpoint(managerURL, managerQUICAddr)
	if err != nil {
		return err
	}
	token := ""
	if len(tokens) > 0 {
		token = tokens[0]
	}
	if token != "" {
		insecureSkipVerify = false
	}
	tlsConfig, err := transporttls.ClientConfig(caFile, serverName, insecureSkipVerify)
	if err != nil {
		return err
	}
	transport := &http3.Transport{TLSClientConfig: tlsConfig}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	report := func() error {
		body, err := json.Marshal(req)
		if err != nil {
			return err
		}
		httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		httpRequest.Header.Set("Content-Type", "application/json")
		if token != "" {
			httpRequest.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(httpRequest)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode >= 300 {
			message, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
			return fmt.Errorf("QUIC report failed: %s: %s", response.Status, strings.TrimSpace(string(message)))
		}
		var report ReportResponse
		if err := json.NewDecoder(response.Body).Decode(&report); err == nil && report.UpdateAvailable && req.OnUpdate != nil {
			req.OnUpdate()
		}
		return nil
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		_ = report()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func quicEndpoint(managerURL, managerQUICAddr string) (string, string, error) {
	managerQUICAddr = strings.TrimSpace(managerQUICAddr)
	if managerQUICAddr == "" {
		return "", "", fmt.Errorf("manager QUIC address is required")
	}
	host, port, err := net.SplitHostPort(managerQUICAddr)
	if err != nil {
		if strings.HasPrefix(managerQUICAddr, ":") {
			port = strings.TrimPrefix(managerQUICAddr, ":")
		} else {
			return "", "", fmt.Errorf("invalid manager QUIC address %q: %w", managerQUICAddr, err)
		}
	}
	if strings.TrimSpace(host) == "" {
		parsed, parseErr := url.Parse(strings.TrimSpace(managerURL))
		if parseErr != nil || strings.TrimSpace(parsed.Hostname()) == "" {
			return "", "", fmt.Errorf("manager host is required when QUIC address is %q", managerQUICAddr)
		}
		host = parsed.Hostname()
	}
	if strings.TrimSpace(port) == "" {
		return "", "", fmt.Errorf("manager QUIC port is required")
	}
	serverName := host
	return "https://" + net.JoinHostPort(host, port) + "/v1/report", serverName, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
