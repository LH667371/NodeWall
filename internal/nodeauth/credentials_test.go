package nodeauth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"nodewall/internal/transporttls"
)

func TestConcurrentTokenCreationIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	var wg sync.WaitGroup
	values := make(chan string, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := LoadOrCreateToken(path)
			if err != nil {
				t.Error(err)
				return
			}
			values <- value
		}()
	}
	wg.Wait()
	close(values)
	want, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	for value := range values {
		if value != want {
			t.Fatal("concurrent processes used different credentials")
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credential permissions: %v %v", info, err)
	}
}

func TestAnonymousNodeRequestsAreRejected(t *testing.T) {
	token, _ := NewToken()
	called := false
	handler := RequireToken(token, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }))
	for _, value := range []string{"", "Bearer wrong", "Basic " + token} {
		req := httptest.NewRequest(http.MethodPost, "/maintenance/delete", nil)
		req.Header.Set("Authorization", value)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || called {
			t.Fatal("unauthenticated maintenance reached agent")
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatal("valid node credential was rejected")
	}
}

func TestPinnedNodeCertificatesAndIndependentCredentials(t *testing.T) {
	registry, err := Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"node-a", "node-b"} {
		token, _ := NewToken()
		dir := t.TempDir()
		certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		if err := transporttls.EnsureCertificate(certFile, keyFile, "127.0.0.1:9080"); err != nil {
			t.Fatal(err)
		}
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(RequireToken(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Cookie") != "" {
				t.Error("browser cookie leaked to agent")
			}
			w.WriteHeader(http.StatusNoContent)
		})))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
		server.StartTLS()
		defer server.Close()
		certificate, _ := os.ReadFile(certFile)
		if err := registry.Put(Credential{NodeID: id, AgentURL: server.URL, Token: token, Certificate: string(certificate)}); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Transport: &Transport{Registry: registry}}
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/health", nil)
		req.Header.Set("Cookie", "nodewall_session=browser-secret")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("node %s returned %d", id, resp.StatusCode)
		}
		if registry.Authenticate("another-node", token) || registry.Authenticate(id, "wrong") {
			t.Fatal("credential escaped its node scope")
		}
	}
	loaded, err := Open(registry.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Get("node-b"); !ok {
		t.Fatal("enrollment was lost on restart")
	}
	a, _ := loaded.Get("node-a")
	b, _ := loaded.Get("node-b")
	a.Certificate = b.Certificate
	if err := loaded.Put(a); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &Transport{Registry: loaded}}
	if response, err := client.Get(a.AgentURL + "/health"); err == nil {
		response.Body.Close()
		t.Fatal("a different self-signed certificate was accepted")
	}
	transport := &Transport{Registry: loaded}
	request := httptest.NewRequest(http.MethodGet, "https://unregistered.invalid/health", nil)
	if _, err := transport.RoundTrip(request); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatal("unregistered endpoint was trusted")
	}
}
