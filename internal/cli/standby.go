package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nodewall/internal/nodeauth"
	"nodewall/internal/securestore"
	"nodewall/internal/transporttls"
)

var errStandbyAccessDenied = errors.New("standby access denied")

// promoteAgentToStandby upgrades an older agent-only enrollment in place. The
// first enrollment script already performs this work for new nodes; keeping
// it in update makes existing cluster members receive the local management
// console without a manual reinstall.
func promoteAgentToStandby(envPath, configDir string) (bool, error) {
	installMode := strings.ToLower(strings.TrimSpace(readEnvValue(envPath, "NODEWALL_INSTALL_MODE", "")))
	managerURL := strings.TrimRight(strings.TrimSpace(readEnvValue(envPath, "NODEWALL_MANAGER_URL", "")), "/")
	if managerURL == "" {
		return false, nil
	}
	// Newer enrolled nodes already have all-in-one mode recorded by the join
	// script. On upgrade, migrate only their legacy standby web port without
	// downloading the bootstrap snapshot a second time.
	if installMode == "all-in-one" {
		return migrateLegacyServerPort(envPath)
	}
	if installMode != "agent-only" {
		return false, nil
	}
	tokenPath := readEnvValue(envPath, "NODEWALL_AGENT_TOKEN_FILE", filepath.Join(configDir, "agent-token"))
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		return false, fmt.Errorf("read agent token for standby promotion: %w", err)
	}
	nodeID := strings.TrimSpace(readEnvValue(envPath, "NODEWALL_NODE_ID", ""))
	if nodeID == "" {
		return false, fmt.Errorf("node ID is required for standby promotion")
	}
	caFile := readEnvValue(envPath, "NODEWALL_TLS_CA", filepath.Join(configDir, "tls", "manager.crt"))
	tlsConfig, err := transporttls.ClientConfig(caFile, "", false)
	if err != nil {
		return false, err
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	get := func(kind string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, managerURL+"/join/bootstrap/"+kind, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set(nodeauth.NodeHeader, nodeID)
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tokenData)))
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			return nil, errStandbyAccessDenied
		}
		if resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			return nil, fmt.Errorf("standby bootstrap %s failed: %s: %s", kind, resp.Status, strings.TrimSpace(string(body)))
		}
		return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	}
	state, err := get("state")
	if errors.Is(err, errStandbyAccessDenied) {
		return false, nil // Ordinary agents stay in agent-only mode.
	}
	if err != nil {
		return false, err
	}
	credentials, err := get("credentials")
	if err != nil {
		return false, err
	}
	auth, err := get("auth")
	if err != nil {
		return false, err
	}
	// The key endpoint was added after the first standby implementation. Keep
	// promotion compatible with an older manager, while preferring the shared
	// cluster key whenever the active manager provides it.
	clusterKeyPath := readEnvValue(envPath, "NODEWALL_CLUSTER_KEY_FILE", filepath.Join(configDir, "cluster.key"))
	clusterKey, keyErr := get("key")
	if keyErr == nil {
		if err := writeFileAtomic(clusterKeyPath, clusterKey, 0o600); err != nil {
			return false, err
		}
	} else if _, err := securestore.EnsureKey(clusterKeyPath); err != nil {
		return false, fmt.Errorf("initialize standby cluster key: %w", err)
	}
	statePath := readEnvValue(envPath, "NODEWALL_SERVER_STATE", filepath.Join(configDir, "server-state.json"))
	credentialsPath := readEnvValue(envPath, "NODEWALL_NODE_CREDENTIALS_FILE", filepath.Join(configDir, "node-credentials.json"))
	authPath := readEnvValue(envPath, "NODEWALL_AUTH_FILE", filepath.Join(configDir, "auth.json"))
	if err := writeFileAtomic(statePath, state, 0o600); err != nil {
		return false, err
	}
	if err := writeFileAtomic(credentialsPath, credentials, 0o600); err != nil {
		return false, err
	}
	if err := writeFileAtomic(authPath, auth, 0o600); err != nil {
		return false, err
	}
	serverAddr, changed, err := chooseManagementServerAddr(readEnvValue(envPath, "NODEWALL_SERVER_ADDR", "0.0.0.0:8086"))
	if err != nil {
		return false, fmt.Errorf("choose standby web address: %w", err)
	}
	if changed {
		fmt.Printf("note: standby web port was busy, selected %s instead\n", serverAddr)
	}
	serverHTTPAddr := installServerHTTPAddr(serverAddr, readEnvValue(envPath, "NODEWALL_AGENT_URL", ""), readEnvValue(envPath, "NODEWALL_AGENT_HTTP_ADDR", ""))
	serviceManager := serviceManagerFromEnv(envPath)
	if (serviceManager == serviceManagerNone || serviceManager == "") && systemdUsable() {
		serviceManager = serviceManagerSystemd
	}
	for key, value := range map[string]string{
		"NODEWALL_INSTALL_MODE":     "all-in-one",
		"NODEWALL_SERVER_ADDR":      serverAddr,
		"NODEWALL_SERVER_HTTP_ADDR": serverHTTPAddr,
		"NODEWALL_SERVER_GRPC_ADDR": "0.0.0.0:50051",
		"NODEWALL_SERVER_QUIC_ADDR": "0.0.0.0:50052",
		"NODEWALL_WEB_ACCESS":       "public",
		"NODEWALL_TRUST_PROXY":      "false",
		"NODEWALL_AUTH_ENABLED":     "true",
		"NODEWALL_CLUSTER_KEY_FILE": clusterKeyPath,
		"NODEWALL_SERVICE_MANAGER":  serviceManager,
	} {
		if err := upsertEnvValue(envPath, key, value); err != nil {
			return false, err
		}
	}
	return true, nil
}

// migrateLegacyServerPort moves values written by older releases to the
// current 8086+ range. The update path calls this for both active and standby
// managers, so an existing main node also leaves the legacy web ports.
func migrateLegacyServerPort(envPath string) (bool, error) {
	current := readEnvValue(envPath, "NODEWALL_SERVER_ADDR", "0.0.0.0:8086")
	_, portText, err := net.SplitHostPort(strings.TrimSpace(current))
	if err != nil {
		return false, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return false, err
	}
	if port < 8080 || port >= 8086 {
		return false, nil
	}
	serverAddr, changed, err := chooseManagementServerAddr(current)
	if err != nil {
		return false, fmt.Errorf("choose migrated web address: %w", err)
	}
	if !changed {
		return false, nil
	}
	serverHTTPAddr := installServerHTTPAddr(
		serverAddr,
		readEnvValue(envPath, "NODEWALL_AGENT_URL", ""),
		readEnvValue(envPath, "NODEWALL_AGENT_HTTP_ADDR", ""),
	)
	if err := upsertEnvValue(envPath, "NODEWALL_SERVER_ADDR", serverAddr); err != nil {
		return false, err
	}
	if err := upsertEnvValue(envPath, "NODEWALL_SERVER_HTTP_ADDR", serverHTTPAddr); err != nil {
		return false, err
	}
	fmt.Printf("note: migrated legacy web port from %s to %s\n", current, serverAddr)
	return true, nil
}
