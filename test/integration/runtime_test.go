package integration

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"nodewall/internal/nodeauth"
	nodeRuntime "nodewall/internal/runtime"
	"nodewall/internal/securestore"
	"nodewall/internal/security"
	"nodewall/internal/transporttls"
)

func TestRuntimeProcess(t *testing.T) {
	component := os.Getenv("NODEWALL_TEST_COMPONENT")
	if component == "" {
		return
	}
	var err error
	if component == "agent" {
		err = nodeRuntime.RunAgent()
	} else {
		err = nodeRuntime.RunServer()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// Exercise browser access protection and node enrollment with real processes,
// independent self-signed certificates, and a mock dataplane.
// No test process attaches a NIC or modifies sshd/netfilter configuration.
func TestSecureMultiNodeRuntime(t *testing.T) {
	managerDir, remoteDir := t.TempDir(), t.TempDir()
	keyPath := filepath.Join(managerDir, "cluster.key")
	t.Setenv("NODEWALL_CLUSTER_KEY_FILE", keyPath)
	if _, err := securestore.EnsureKey(keyPath); err != nil {
		t.Fatal(err)
	}
	managerAddr, agentAddr, remoteAddr := unusedAddress(t), unusedAddress(t), unusedAddress(t)
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	quicAddr := udpListener.LocalAddr().String()
	udpListener.Close()
	managerCert, managerKey := filepath.Join(managerDir, "node.crt"), filepath.Join(managerDir, "node.key")
	remoteCert, remoteKey := filepath.Join(remoteDir, "node.crt"), filepath.Join(remoteDir, "node.key")
	for _, pair := range [][3]string{{managerCert, managerKey, managerAddr}, {remoteCert, remoteKey, remoteAddr}} {
		if err := transporttls.EnsureCertificate(pair[0], pair[1], pair[2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := security.EnsureAdminUser(filepath.Join(managerDir, "auth.json"), "admin", "integration-test-password"); err != nil {
		t.Fatal(err)
	}
	managerToken, _ := nodeauth.LoadOrCreateToken(filepath.Join(managerDir, "agent-token"))
	remoteToken, _ := nodeauth.LoadOrCreateToken(filepath.Join(remoteDir, "agent-token"))
	baseEnv := func(dir, id, listen, cert, key string) []string {
		values := map[string]string{
			"DEV_MODE": "real", "DATAPLANE": "mock", "NODE_ID": id,
			"TLS_ENABLED": "true", "TLS_CERT": cert, "TLS_KEY": key,
			"TLS_CA": managerCert, "TLS_INSECURE_SKIP_VERIFY": "false",
			"AGENT_TOKEN_FILE":      filepath.Join(dir, "agent-token"),
			"NODE_CREDENTIALS_FILE": filepath.Join(managerDir, "credentials.json"),
			"CLUSTER_KEY_FILE":      keyPath,
			"AGENT_ADDR":            listen, "AGENT_HTTP_ADDR": listen, "AGENT_URL": "https://" + listen,
			"AGENT_STATE":            filepath.Join(dir, "agent-state.json"),
			"SERVER_STATE":           filepath.Join(dir, "server-state.json"),
			"AUTH_FILE":              filepath.Join(managerDir, "auth.json"),
			"AUTH_SETTINGS_FILE":     filepath.Join(dir, "auth-settings.json"),
			"SSH_KEY":                filepath.Join(dir, "ssh-key"),
			"SSH_PROTECTION_STATE":   filepath.Join(dir, "ssh-protection.json"),
			"SSH_ACTIVITY_LOG":       filepath.Join(dir, "ssh-activity.log"),
			"LOG_DIR":                filepath.Join(dir, "logs"),
			"MONITORING_HISTORY_DIR": filepath.Join(dir, "monitoring"),
			"SCAN_REPORT_DIR":        filepath.Join(dir, "scan-reports"),
			"DROP_LOG_STATE":         filepath.Join(dir, "logging-state.json"),
			"AUTO_UPDATE":            "false", "SERVER_ADDR": managerAddr,
			"SERVER_GRPC_ADDR": "", "SERVER_QUIC_ADDR": quicAddr,
			"MANAGER_GRPC_ADDR": "", "MANAGER_QUIC_ADDR": "",
		}
		if id == "remote-node" {
			values["MANAGER_URL"] = "https://" + managerAddr
			values["MANAGER_QUIC_ADDR"] = quicAddr
		}
		var result []string
		for key, value := range values {
			result = append(result, "NODEWALL_"+key+"="+value)
		}
		return result
	}
	startRuntime(t, "agent", baseEnv(managerDir, "manager", agentAddr, managerCert, managerKey), managerDir)
	serverEnv := baseEnv(managerDir, "manager", agentAddr, managerCert, managerKey)
	stopServer := startRuntime(t, "server", serverEnv, managerDir)
	roots := x509.NewCertPool()
	managerPEM, _ := os.ReadFile(managerCert)
	roots.AppendCertsFromPEM(managerPEM)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 5 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	waitEndpoint(t, client, "https://"+managerAddr+"/version", http.StatusOK)
	waitEndpoint(t, client, "https://"+agentAddr+"/health", http.StatusUnauthorized)
	resp, err := client.Get("https://" + managerAddr + "/nodes")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("anonymous browser read node list")
	}
	captchaID := assertLoginCaptchaPNG(t, client, "https://"+managerAddr)
	resp, err = client.PostForm("https://"+managerAddr+"/login", url.Values{
		"username":       {"admin"},
		"password":       {"integration-test-password"},
		"captcha_id":     {captchaID},
		"captcha_answer": {"invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login with an invalid challenge returned %d", resp.StatusCode)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "nodewall_session" && cookie.Value != "" {
			t.Fatal("invalid challenge issued a browser session")
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+agentAddr+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+managerToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("local node token was rejected")
	}
	// Authenticated ticket issuance is covered by the API tests. Seed the
	// enrolled credential before running the node-to-node TLS checks with a
	// loopback server independent of the human challenge.
	stopServer()
	registry, err := nodeauth.Open(filepath.Join(managerDir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	remotePEM, err := os.ReadFile(remoteCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Put(nodeauth.Credential{NodeID: "remote-node", AgentURL: "https://" + remoteAddr, Token: remoteToken, Certificate: string(remotePEM)}); err != nil {
		t.Fatal(err)
	}
	startRuntime(t, "server", append(serverEnv, "NODEWALL_AUTH_ENABLED=false"), managerDir)
	waitEndpoint(t, client, "https://"+managerAddr+"/nodes", http.StatusOK)
	enrollmentRequest, _ := http.NewRequest(http.MethodPost, "https://"+managerAddr+"/nodes/enrollment", bytes.NewBufferString(`{}`))
	enrollmentRequest.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(enrollmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("ticket issuance with console auth disabled returned %d", resp.StatusCode)
	}
	reportAfter := time.Now()
	remoteEnv := baseEnv(remoteDir, "remote-node", remoteAddr, remoteCert, remoteKey)
	stopRemote := startRuntime(t, "agent", remoteEnv, remoteDir)
	waitEndpoint(t, client, "https://"+managerAddr+"/nodes/remote-node/health", http.StatusOK)
	reported := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		resp, err := client.Get("https://" + managerAddr + "/nodes")
		if err != nil {
			t.Fatal(err)
		}
		var nodes []struct {
			ID       string    `json:"id"`
			LastSeen time.Time `json:"last_seen_at"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&nodes)
		resp.Body.Close()
		for _, node := range nodes {
			if node.ID == "remote-node" && node.LastSeen.After(reportAfter) {
				reported = true
			}
		}
		if reported {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !reported {
		t.Fatal("enrolled agent could not report over authenticated QUIC")
	}
	resp, err = client.Get("https://" + managerAddr + "/nodes")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(data, []byte("remote-node")) || bytes.Contains(data, []byte(remoteToken)) {
		t.Fatal("node list lost enrollment or exposed a credential")
	}
	// Reports must survive an actual agent process restart and still be
	// downloadable through the authenticated manager-to-agent TLS proxy.
	scanPath := filepath.Join(remoteDir, "sample.php")
	if err := os.WriteFile(scanPath, []byte("<?php eval(base64_decode($_POST['x'])); ?>"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"path": scanPath})
	scanRequest, _ := http.NewRequest(http.MethodPost, "https://"+managerAddr+"/nodes/remote-node/security/scan", bytes.NewReader(body))
	scanRequest.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(scanRequest)
	if err != nil {
		t.Fatal(err)
	}
	var scan struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&scan)
	resp.Body.Close()
	if resp.StatusCode != 202 || scan.ID == "" {
		t.Fatalf("scan start failed: %d %#v", resp.StatusCode, scan)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		resp, err = client.Get("https://" + managerAddr + "/nodes/remote-node/security/scan")
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewDecoder(resp.Body).Decode(&scan)
		resp.Body.Close()
		if scan.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if scan.Status != "completed" {
		t.Fatalf("scan did not complete: %#v", scan)
	}
	stopRemote()
	startRuntime(t, "agent", remoteEnv, remoteDir)
	waitEndpoint(t, client, "https://"+managerAddr+"/nodes/remote-node/health", http.StatusOK)
	for _, endpoint := range []string{
		"/nodes/remote-node/security/scan/reports",
		"/nodes/remote-node/security/scan/reports/" + scan.ID + "?format=json",
		"/nodes/remote-node/security/scan/reports/" + scan.ID + "?format=html",
	} {
		resp, err = client.Get("https://" + managerAddr + endpoint)
		if err != nil {
			t.Fatal(err)
		}
		data, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !bytes.Contains(data, []byte(scan.ID)) || bytes.Contains(data, []byte(remoteToken)) {
			t.Fatalf("durable report proxy failed: %d %s", resp.StatusCode, data)
		}
	}
}

func assertLoginCaptchaPNG(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	resp, err := client.Get(baseURL + "/login")
	if err != nil {
		t.Fatalf("get login challenge: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read login challenge: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get login challenge returned %d", resp.StatusCode)
	}
	page := string(body)
	idMatch := regexp.MustCompile(`id="login-captcha-id" value="([a-f0-9]+)"`).FindStringSubmatch(page)
	if len(idMatch) != 2 {
		t.Fatal("login page did not contain a captcha id")
	}
	imageMatch := regexp.MustCompile(`src="data:image/png;base64,([^"]+)"`).FindStringSubmatch(page)
	if len(imageMatch) != 2 {
		t.Fatal("login page did not contain an inline PNG captcha")
	}
	data, err := base64.StdEncoding.DecodeString(html.UnescapeString(imageMatch[1]))
	if err != nil {
		t.Fatalf("decode captcha payload: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("decode captcha image: %v", err)
	}
	return idMatch[1]
}

func unusedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func startRuntime(t *testing.T, component string, env []string, dir string) func() {
	t.Helper()
	logFile, err := os.CreateTemp(dir, component+"-*.log")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestRuntimeProcess$")
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "NODEWALL_") {
			command.Env = append(command.Env, item)
		}
	}
	command.Env = append(command.Env, env...)
	command.Env = append(command.Env, "NODEWALL_TEST_COMPONENT="+component)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	var stopped sync.Once
	stop := func() {
		stopped.Do(func() {
			_ = command.Process.Kill()
			_ = command.Wait()
			logFile.Close()
		})
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			output, _ := os.ReadFile(logFile.Name())
			t.Logf("%s logs:\n%s", component, output)
		}
	})
	return stop
}

func waitEndpoint(t *testing.T, client *http.Client, endpoint string, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		response, err := client.Get(endpoint)
		if err == nil {
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode == want {
				return
			}
			last = fmt.Sprintf("%d %s", response.StatusCode, data)
		} else {
			last = err.Error()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("endpoint %s: %s", endpoint, last)
}
