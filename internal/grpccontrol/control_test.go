package grpccontrol

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"nodewall/internal/store"

	"google.golang.org/grpc/peer"
)

func TestReportDoesNotSynchronizePolicyToNodes(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer agent.Close()
	st := store.New()
	srv := &Server{
		store:            st,
		agentBaseURL:     agent.URL,
		defaultInterface: "enp1s0",
		httpClient:       agent.Client(),
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.168.2.10"), Port: 50000}})
	if _, err := srv.Report(ctx, &ReportRequest{
		NodeID:        "node-a",
		AgentHTTPAddr: strings.TrimPrefix(agent.URL, "http://"),
		AgentURL:      agent.URL,
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("heartbeat unexpectedly wrote %d requests to an agent", requests.Load())
	}
	if len(st.ListNodes(context.Background())) != 1 {
		t.Fatalf("expected heartbeat to record exactly one node")
	}
}

func TestNormalizeAdvertiseIPPrefersPrimaryOnLoopback(t *testing.T) {
	if got := normalizeAdvertiseIP("127.0.0.1"); got == "" {
		t.Fatal("expected non-empty normalized loopback address")
	}
}

func TestAdvertiseIPForEndpointKeepsLoopbackAgentPrivate(t *testing.T) {
	if got := advertiseIPForEndpoint("127.0.0.1", "192.168.201.20"); got != "192.168.201.20" {
		t.Fatalf("loopback agent endpoint should use the reported address, got %q", got)
	}
	if got := advertiseIPForEndpoint("192.168.201.19", "192.168.201.20"); got != "192.168.201.19" {
		t.Fatalf("remote agent endpoint should remain authoritative, got %q", got)
	}
}

func TestNormalizeAgentURL(t *testing.T) {
	got := normalizeAgentURL("http://0.0.0.0:9080/")
	if got != "http://127.0.0.1:9080" {
		t.Fatalf("unexpected normalized url: %s", got)
	}
}

func TestPackageUpdateAvailable(t *testing.T) {
	for _, test := range []struct {
		name       string
		local      string
		remote     string
		wantUpdate bool
	}{
		{name: "same", local: "0.1.0+build.1", remote: "0.1.0+build.1"},
		{name: "different", local: "0.1.0+build.1", remote: "0.1.0+build.2", wantUpdate: true},
		{name: "missing local", remote: "0.1.0+build.2"},
		{name: "missing remote", local: "0.1.0+build.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := packageUpdateAvailable(test.local, test.remote); got != test.wantUpdate {
				t.Fatalf("packageUpdateAvailable(%q, %q) = %t, want %t", test.local, test.remote, got, test.wantUpdate)
			}
		})
	}
}

func TestPreserveLoopbackAgentAddressForAllInOne(t *testing.T) {
	if !preserveLoopbackAgentAddress("https://127.0.0.1:9080", "127.0.0.1") {
		t.Fatal("expected all-in-one loopback agent address to be preserved")
	}
	if preserveLoopbackAgentAddress("https://127.0.0.1:9080", "192.168.5.10") {
		t.Fatal("did not expect a remote peer to preserve loopback agent address")
	}
	if preserveLoopbackAgentAddress("https://192.168.5.10:9080", "127.0.0.1") {
		t.Fatal("did not expect a remote agent base URL to preserve loopback address")
	}
}

func TestParseHostPortCompatibility(t *testing.T) {
	_, _, err := net.SplitHostPort("192.168.2.200:9080")
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
}
