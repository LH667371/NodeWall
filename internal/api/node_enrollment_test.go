package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/service"
	"nodewall/internal/sshconsole"
	"nodewall/internal/store"
	"nodewall/internal/transporttls"
)

func TestSuggestEnrollmentNodeIDUsesAgentEndpointAndAvoidsManagerID(t *testing.T) {
	state := store.New()
	if err := state.UpsertNodeChecked(t.Context(), models.Node{ID: "192-168-201-18"}); err != nil {
		t.Fatal(err)
	}
	handler := &ServerHandler{nodeID: "manager", store: state}
	suggested := handler.suggestEnrollmentNodeID(nodeauth.Credential{AgentURL: "https://192.168.201.18:9080"})
	if suggested != "192-168-201-18-"+sha256HexPrefix("https://192.168.201.18:9080") {
		t.Fatalf("suggested node ID = %q", suggested)
	}
	if strings.ContainsAny(suggested, "/:") {
		t.Fatalf("suggested node ID contains endpoint punctuation: %q", suggested)
	}
}

func sha256HexPrefix(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:8]
}

func TestEnrollmentIsAuthenticatedSingleUseAndDurable(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "node.crt")
	if err := transporttls.EnsureCertificate(certFile, filepath.Join(dir, "node.key"), "127.0.0.1:9080"); err != nil {
		t.Fatal(err)
	}
	registry, err := nodeauth.Open(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := store.New()
	handler := &ServerHandler{nodeID: "manager", store: state, service: service.NewPolicyService(state), tlsCertFile: certFile, auth: &authManager{enabled: true, sessions: map[string]sessionState{"admin-session": {Username: "admin", Role: "admin", CSRFToken: "admin-csrf", ExpiresAt: time.Now().Add(time.Hour)}, "viewer-session": {Username: "viewer", Role: "viewer", ExpiresAt: time.Now().Add(time.Hour)}}}}
	handler.ConfigureNodeAuth(registry)
	handler.sshConsole = sshconsole.NewWithKeyPath(filepath.Join(dir, "console-key"))
	routes := handler.Routes()
	for _, cookie := range []string{"", "viewer-session"} {
		req := httptest.NewRequest(http.MethodPost, "/nodes/enrollment", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Fatalf("unauthorized enrollment ticket: %d", rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "https://manager.invalid/nodes/enrollment", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "admin-session"})
	req.Header.Set("X-NodeWall-CSRF", "admin-csrf")
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	var ticket struct {
		URL          string `json:"url"`
		Pin          string `json:"pin"`
		ScriptSHA256 string `json:"script_sha256"`
		Command      string `json:"command"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ticket); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ticket.Pin, "sha256//") {
		t.Fatal("registration command has no certificate pin")
	}
	if len(ticket.ScriptSHA256) != 64 {
		t.Fatalf("registration script has invalid SHA-256: %q", ticket.ScriptSHA256)
	}
	for _, expected := range []string{"sha256sum -c", "bash \"$JOIN_TMP/join.sh\""} {
		if !strings.Contains(ticket.Command, expected) {
			t.Fatalf("legacy-compatible registration command is missing %q: %s", expected, ticket.Command)
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		command := exec.Command(bash, "-n", "-c", ticket.Command)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("invalid legacy-compatible registration command: %v %s", err, output)
		}
	}
	u, _ := url.Parse(ticket.URL)
	token := u.Query().Get("token")
	scriptRequest := httptest.NewRequest(http.MethodGet, ticket.URL, nil)
	scriptResponse := httptest.NewRecorder()
	routes.ServeHTTP(scriptResponse, scriptRequest)
	if scriptResponse.Code != http.StatusOK {
		t.Fatal(scriptResponse.Body.String())
	}
	scriptSum := sha256.Sum256(scriptResponse.Body.Bytes())
	if got := hex.EncodeToString(scriptSum[:]); got != ticket.ScriptSHA256 {
		t.Fatalf("enrollment command hash does not match served script: got %s want %s", got, ticket.ScriptSHA256)
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		command := exec.Command(bash, "-n")
		command.Stdin = strings.NewReader(scriptResponse.Body.String())
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("invalid registration shell script: %v %s", err, output)
		}
	}
	for _, expected := range []string{
		"CURL_ARGS",
		"downloading NodeWall agent binary",
		"ClamAV engine and databases will synchronize automatically from enrolled cluster nodes",
		"verifying NodeWall agent binary",
		"progress 'checking curl capabilities'",
		"progress \"selected interface $JOIN_IFACE ($JOIN_IP)\"",
		"PHYSICAL_IFACE",
		"--enable-services=false",
		"start_direct_agent",
		"systemd_online",
		"bridge $SELECTED_BRIDGE -> physical $JOIN_IFACE ($JOIN_IP)",
		"run_root()",
		"CURL_CERT_MODE=curl",
		"CURL_CERT_MODE=legacy",
		"--pinnedpubkey",
		"openssl x509",
		"NODEWALL_AGENT_ADDR=0.0.0.0:9080",
		"NODEWALL_AGENT_HTTP_ADDR=${JOIN_IP}:9080",
		"NODEWALL_AGENT_URL=https://${JOIN_IP}:9080",
		"NODEWALL_SERVER_HTTP_ADDR=${JOIN_IP}:${SERVER_PORT}",
		"LimitMEMLOCK=infinity",
		"systemctl daemon-reload",
		"systemd_enable_unit",
	} {
		if !strings.Contains(scriptResponse.Body.String(), expected) {
			t.Fatalf("join script is missing %q", expected)
		}
	}
	if strings.Contains(scriptResponse.Body.String(), "echo 'NODEWALL_SERVER_ADDR=0.0.0.0:8080'") {
		t.Fatal("join script overwrites the automatically selected web port")
	}
	agentToken, _ := nodeauth.NewToken()
	certificate, _ := os.ReadFile(certFile)
	body, _ := json.Marshal(nodeauth.Credential{NodeID: "node-a", AgentURL: "https://127.0.0.1:9080", Token: agentToken, Certificate: string(certificate)})
	for attempt := 0; attempt < 2; attempt++ {
		req := httptest.NewRequest(http.MethodPost, "https://manager.invalid/join/enroll", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		want := http.StatusCreated
		if attempt == 1 {
			want = http.StatusUnauthorized
		}
		if rec.Code != want {
			t.Fatalf("enrollment attempt %d: status=%d %s", attempt, rec.Code, rec.Body.String())
		}
	}
	loaded, err := nodeauth.Open(filepath.Join(dir, "credentials.json"))
	if err != nil || !loaded.Authenticate("node-a", agentToken) {
		t.Fatalf("credential was not persisted: %v", err)
	}
	newCertFile := filepath.Join(dir, "node-new.crt")
	newKeyFile := filepath.Join(dir, "node-new.key")
	if err := transporttls.EnsureCertificate(newCertFile, newKeyFile, "192.0.2.20:9080"); err != nil {
		t.Fatal(err)
	}
	newCertificate, err := os.ReadFile(newCertFile)
	if err != nil {
		t.Fatal(err)
	}
	ticketRequest := httptest.NewRequest(http.MethodPost, "https://manager.invalid/nodes/enrollment", nil)
	ticketRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "admin-session"})
	ticketRequest.Header.Set("X-NodeWall-CSRF", "admin-csrf")
	ticketResponse := httptest.NewRecorder()
	routes.ServeHTTP(ticketResponse, ticketRequest)
	if ticketResponse.Code != http.StatusCreated {
		t.Fatalf("repair enrollment ticket: %s", ticketResponse.Body.String())
	}
	var repairTicket struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(ticketResponse.Body.Bytes(), &repairTicket); err != nil {
		t.Fatal(err)
	}
	repairURL, err := url.Parse(repairTicket.URL)
	if err != nil {
		t.Fatal(err)
	}
	repairBody, err := json.Marshal(nodeauth.Credential{
		NodeID:      "node-a",
		AgentURL:    "https://192.0.2.20:9080",
		Token:       agentToken,
		Certificate: string(newCertificate),
	})
	if err != nil {
		t.Fatal(err)
	}
	repairRequest := httptest.NewRequest(http.MethodPost, "https://manager.invalid/join/enroll", strings.NewReader(string(repairBody)))
	repairRequest.Header.Set("Content-Type", "application/json")
	repairRequest.Header.Set("Authorization", "Bearer "+repairURL.Query().Get("token"))
	repairResponse := httptest.NewRecorder()
	routes.ServeHTTP(repairResponse, repairRequest)
	if repairResponse.Code != http.StatusCreated {
		t.Fatalf("repair enrollment: status=%d body=%s", repairResponse.Code, repairResponse.Body.String())
	}
	reloaded, err := nodeauth.Open(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	updated, ok := reloaded.Get("node-a")
	if !ok || updated.AgentURL != "https://192.0.2.20:9080" || strings.TrimSpace(updated.Certificate) != strings.TrimSpace(string(newCertificate)) {
		t.Fatalf("repair enrollment did not replace endpoint and certificate: %#v", updated)
	}
	publicNodes, _ := json.Marshal(state.ListNodes(t.Context()))
	if strings.Contains(string(publicNodes), agentToken) {
		t.Fatal("node API exposed its credential")
	}
	req = httptest.NewRequest(http.MethodGet, "/join/script", nil)
	rec = httptest.NewRecorder()
	routes.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("anonymous installation script remained available")
	}
}

func TestJoinBootstrapRequiresEnrolledNodeAndServesStandbyResources(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "node.crt")
	if err := transporttls.EnsureCertificate(certFile, filepath.Join(dir, "node.key"), "127.0.0.1:9080"); err != nil {
		t.Fatal(err)
	}
	authFile := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(authFile, []byte(`{"users":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := nodeauth.Open(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := nodeauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := os.ReadFile(certFile)
	credential := nodeauth.Credential{NodeID: "node-a", AgentURL: "https://127.0.0.1:9080", Token: token, Certificate: string(certificate)}
	if err := registry.Put(credential); err != nil {
		t.Fatal(err)
	}
	state := store.New()
	state.UpsertNode(t.Context(), models.Node{ID: "node-a", Name: "node-a", AgentURL: credential.AgentURL})
	handler := &ServerHandler{
		nodeID:      "manager",
		store:       state,
		service:     service.NewPolicyService(state),
		tlsCertFile: certFile,
		auth:        &authManager{authFile: authFile},
	}
	handler.ConfigureNodeAuth(registry)
	routes := handler.Routes()
	for _, kind := range []string{"state", "credentials", "auth"} {
		req := httptest.NewRequest(http.MethodGet, "/join/bootstrap/"+kind, nil)
		req.Header.Set(nodeauth.NodeHeader, credential.NodeID)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Fatalf("bootstrap %s failed: status=%d body=%s", kind, rec.Code, rec.Body.String())
		}
	}
	unauthorized := httptest.NewRequest(http.MethodGet, "/join/bootstrap/state", nil)
	unauthorizedRec := httptest.NewRecorder()
	routes.ServeHTTP(unauthorizedRec, unauthorized)
	if unauthorizedRec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous bootstrap request returned %d", unauthorizedRec.Code)
	}
}
