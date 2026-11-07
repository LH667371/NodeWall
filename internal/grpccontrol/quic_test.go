package grpccontrol

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"nodewall/internal/store"
	"nodewall/internal/transporttls"

	"github.com/quic-go/quic-go/http3"
)

func TestReportLoopQUICUsesSelfSignedCertificate(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP listener unavailable: %v", err)
	}
	addr := packet.LocalAddr().String()
	_ = packet.Close()

	certFile := t.TempDir() + "/nodewall.crt"
	keyFile := t.TempDir() + "/nodewall.key"
	state := store.New()
	service := NewServer(state, "", "")
	serverCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- ServeQUIC(serverCtx, addr, certFile, keyFile, service)
	}()

	report := ReportRequest{NodeID: "quic-node", NodeName: "quic-node", AgentHTTPAddr: "127.0.0.1:19080"}
	var reportErr error
	for attempt := 0; attempt < 20; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		reportErr = ReportLoopQUIC(ctx, "https://127.0.0.1:18080", addr, report, time.Second, certFile, false)
		cancel()
		if len(state.ListNodes(context.Background())) > 0 {
			reportErr = nil
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if reportErr != nil {
		t.Fatalf("QUIC report failed: %v", reportErr)
	}
	if nodes := state.ListNodes(context.Background()); len(nodes) != 1 || nodes[0].ID != "quic-node" {
		t.Fatalf("unexpected reported nodes: %#v", nodes)
	}
	stopServer()
	select {
	case <-serverErrors:
	case <-time.After(time.Second):
		t.Fatal("QUIC server did not stop")
	}
}

func TestServeHTTP3ServesBrowserHandler(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP listener unavailable: %v", err)
	}
	addr := packet.LocalAddr().String()
	_ = packet.Close()

	certFile := t.TempDir() + "/nodewall.crt"
	keyFile := t.TempDir() + "/nodewall.key"
	if err := transporttls.EnsureCertificate(certFile, keyFile, addr); err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	go func() {
		_ = ServeHTTP3(serverCtx, addr, certFile, keyFile, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "browser-h3-ok")
		}))
	}()

	tlsConfig, err := transporttls.ClientConfig(certFile, "127.0.0.1", false)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http3.Transport{TLSClientConfig: tlsConfig}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 250 * time.Millisecond}
	var responseBody string
	for attempt := 0; attempt < 20; attempt++ {
		request, requestErr := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/", nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		response, requestErr := client.Do(request)
		if requestErr == nil {
			data, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				responseBody = string(data)
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if responseBody != "browser-h3-ok" {
		t.Fatalf("unexpected HTTP/3 response: %q", responseBody)
	}
}
