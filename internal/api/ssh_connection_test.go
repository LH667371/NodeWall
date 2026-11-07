package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
)

func TestNormalizeSSHConnectionProfile(t *testing.T) {
	profile, err := normalizeSSHConnectionProfile(models.SSHConnectionProfile{}, models.Node{AdvertiseIP: "192.0.2.10"})
	if err != nil {
		t.Fatalf("normalize profile: %v", err)
	}
	if profile.Host != "192.0.2.10" || profile.Port != 22 || profile.User != "root" {
		t.Fatalf("unexpected defaults: %#v", profile)
	}

	if _, err := normalizeSSHConnectionProfile(models.SSHConnectionProfile{Host: "http://example.com"}, models.Node{}); err == nil {
		t.Fatal("expected URL host to be rejected")
	}
}

func TestHandleNodeSSHConnectionTestReadsSSHBanner(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-nodewall-test\r\n"))
	}()

	st := store.New()
	svc := service.NewPolicyService(st)
	port := listener.Addr().(*net.TCPAddr).Port
	st.UpsertNode(context.Background(), models.Node{ID: "node-a", Name: "node-a", AdvertiseIP: "127.0.0.1"})
	handler := &ServerHandler{service: svc, store: st}
	req := httptest.NewRequest(http.MethodPost, "/nodes/node-a/ssh-connection/test", nil)
	req.SetPathValue("node", "node-a")
	req.Body = http.NoBody
	req = requestWithJSON(req, fmt.Sprintf(`{"host":"127.0.0.1","port":%d,"user":"root"}`, port))
	rec := httptest.NewRecorder()

	handler.handleNodeSSHConnectionTest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "reachable" {
		t.Fatalf("unexpected response: %#v", payload)
	}
}

func requestWithJSON(req *http.Request, body string) *http.Request {
	req.ContentLength = int64(len(body))
	req.Body = io.NopCloser(bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}
