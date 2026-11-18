package grpccontrol

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"nodewall/internal/nodeauth"
	"nodewall/internal/store"
	"nodewall/internal/transporttls"
)

func TestReportsRequireEnrollmentAndCannotReplaceAgentEndpoint(t *testing.T) {
	registry, _ := nodeauth.Open("")
	token, _ := nodeauth.NewToken()
	if err := registry.Put(nodeauth.Credential{NodeID: "node-a", AgentURL: "http://127.0.0.1:9080", Token: token}); err != nil {
		t.Fatal(err)
	}
	state := store.New()
	server := NewServer(state, "http://127.0.0.1:9080", "")
	server.RequireNodeAuth(registry)
	report := &ReportRequest{NodeID: "node-a", AgentURL: "http://127.0.0.1:9080", AgentHTTPAddr: "192.0.2.200:9999"}
	for _, value := range []string{"", "wrong"} {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+value))
		if _, err := server.Report(ctx, report); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("unauthenticated report: %v", err)
		}
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	if _, err := server.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	nodes := state.ListNodes(ctx)
	if len(nodes) != 1 || nodes[0].AgentURL != "http://127.0.0.1:9080" {
		t.Fatal("report replaced enrolled endpoint")
	}
	report.NodeID = "another-node"
	if _, err := server.Report(ctx, report); status.Code(err) != codes.Unauthenticated {
		t.Fatal("node impersonated another node")
	}
	report.NodeID = "node-a"
	if err := registry.Revoke("node-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Report(ctx, report); status.Code(err) != codes.Unauthenticated {
		t.Fatal("removed node continued reporting with a revoked credential")
	}
}

func TestAuthenticatedReportRefreshesAgentEndpointAndCertificate(t *testing.T) {
	dir := t.TempDir()
	oldCertFile, oldKeyFile := filepath.Join(dir, "old.crt"), filepath.Join(dir, "old.key")
	newCertFile, newKeyFile := filepath.Join(dir, "new.crt"), filepath.Join(dir, "new.key")
	if err := transporttls.EnsureCertificate(oldCertFile, oldKeyFile, "192.0.2.10:9080"); err != nil {
		t.Fatal(err)
	}
	if err := transporttls.EnsureCertificate(newCertFile, newKeyFile, "198.51.100.20:9080"); err != nil {
		t.Fatal(err)
	}
	oldCertificate, err := os.ReadFile(oldCertFile)
	if err != nil {
		t.Fatal(err)
	}
	newCertificate, err := os.ReadFile(newCertFile)
	if err != nil {
		t.Fatal(err)
	}
	token, err := nodeauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := nodeauth.Open("")
	if err := registry.Put(nodeauth.Credential{
		NodeID:      "node-a",
		AgentURL:    "https://192.0.2.10:9080",
		Token:       token,
		Certificate: string(oldCertificate),
	}); err != nil {
		t.Fatal(err)
	}
	server := NewServer(store.New(), "https://127.0.0.1:9080", "")
	server.RequireNodeAuth(registry)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	if _, err := server.Report(ctx, &ReportRequest{
		NodeID:           "node-a",
		AgentURL:         "https://198.51.100.20:9080",
		AgentHTTPAddr:    "198.51.100.20:9080",
		AgentCertificate: string(newCertificate),
	}); err != nil {
		t.Fatalf("report with refreshed credential: %v", err)
	}
	updated, ok := registry.Get("node-a")
	if !ok || updated.AgentURL != "https://198.51.100.20:9080" || strings.TrimSpace(updated.Certificate) != strings.TrimSpace(string(newCertificate)) {
		t.Fatalf("credential was not refreshed: %#v", updated)
	}
}

func TestAuthenticatedGRPCReportLoopUsesTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	tlsConfig, err := transporttls.ServerConfig(certFile, keyFile, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := nodeauth.Open("")
	token, _ := nodeauth.NewToken()
	if err := registry.Put(nodeauth.Credential{NodeID: "node-a", AgentURL: "http://127.0.0.1:9080", Token: token}); err != nil {
		t.Fatal(err)
	}
	state := store.New()
	control := NewServer(state, "http://127.0.0.1:9080", "")
	control.RequireNodeAuth(registry)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	control.Register(server)
	defer server.Stop()
	go func() { _ = server.Serve(listener) }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ReportLoop(ctx, listener.Addr().String(), ReportRequest{NodeID: "node-a", AgentURL: "http://127.0.0.1:9080", AgentHTTPAddr: "127.0.0.1:9080"}, time.Minute, ClientSecurity{Token: token, CAFile: certFile})
	}()
	for len(state.ListNodes(ctx)) == 0 && ctx.Err() == nil {
		time.Sleep(10 * time.Millisecond)
	}
	if len(state.ListNodes(ctx)) != 1 {
		t.Fatal("authenticated gRPC report did not arrive over TLS")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
