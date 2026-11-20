package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nodewall/internal/api"
	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/monitoring"
	"nodewall/internal/nodeauth"
	"nodewall/internal/securestore"
	"nodewall/internal/store"
	"nodewall/internal/transporttls"
)

const standbySyncInterval = 15 * time.Second

// runStandbySync keeps an enrolled node's local manager state warm while the
// active manager is reachable. If the active manager goes offline, the local
// server keeps the last complete snapshot and can still serve the console and
// proxy the enrolled agents without a promotion step.
func runStandbySync(ctx context.Context, cfg config.ServerConfig, state *store.Store, credentials *nodeauth.Registry, handler *api.ServerHandler) {
	managerURL := strings.TrimRight(strings.TrimSpace(cfg.ManagerURL), "/")
	if managerURL == "" || credentials == nil {
		return
	}
	tokenData, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		log.Printf("warning: standby manager token unavailable: %v", err)
		return
	}
	token := strings.TrimSpace(string(tokenData))
	if token == "" {
		log.Printf("warning: standby manager token is empty")
		return
	}
	sync := func() {
		syncCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		// Reload the manager CA for every snapshot. Enrollment repair and a
		// standby manager can replace manager.crt while this server remains up;
		// a client created once at startup would make every later sync fail with
		// an obsolete certificate.
		tlsConfig, tlsErr := transporttls.ClientConfig(cfg.TLSCAFile, "", cfg.TLSInsecureSkipVerify)
		if tlsErr != nil {
			log.Printf("warning: standby manager TLS setup failed: %v", tlsErr)
			return
		}
		client := &http.Client{
			Timeout: 12 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:   tlsConfig,
				ForceAttemptHTTP2: true,
			},
		}
		defer client.CloseIdleConnections()
		if err := syncStandbySnapshot(syncCtx, client, managerURL, cfg.NodeID, token, cfg.AuthFile, cfg.ClusterKeyFile, state, credentials); err != nil {
			log.Printf("warning: standby manager sync failed: %v", err)
		}
		if cfg.MonitoringHistoryDir != "" && syncCtx.Err() == nil {
			if err := syncStandbyMonitoring(syncCtx, client, managerURL, cfg.NodeID, token, handler); err != nil {
				log.Printf("warning: standby monitoring sync failed: %v", err)
			}
		}
	}
	sync()
	ticker := time.NewTicker(standbySyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sync()
		}
	}
}

func requestStandbyBootstrap(ctx context.Context, client *http.Client, managerURL, nodeID, token, kind string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, managerURL+"/join/bootstrap/"+kind, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(nodeauth.NodeHeader, nodeID)
	req.Header.Set("Authorization", "Bearer "+token)
	return client.Do(req)
}

func syncStandbySnapshot(ctx context.Context, client *http.Client, managerURL, nodeID, token, authFile, clusterKeyFile string, state *store.Store, credentials *nodeauth.Registry) error {
	get := func(kind string) ([]byte, error) {
		resp, err := requestStandbyBootstrap(ctx, client, managerURL, nodeID, token, kind)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			return nil, fmt.Errorf("bootstrap %s failed: %s: %s", kind, resp.Status, strings.TrimSpace(string(body)))
		}
		return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	}
	// Refresh the shared key before replacing encrypted snapshots. Older
	// managers return 404 here; their plaintext snapshots remain compatible.
	if keyData, keyErr := get("key"); keyErr == nil {
		if err := writeStandbyFile(clusterKeyFile, keyData, 0o600); err != nil {
			return fmt.Errorf("write standby cluster key: %w", err)
		}
	}
	stateData, err := get("state")
	if err != nil {
		return err
	}
	credentialData, err := get("credentials")
	if err != nil {
		return err
	}
	authData, err := get("auth")
	if err != nil {
		return err
	}
	if err := state.ReplaceJSON(stateData); err != nil {
		return fmt.Errorf("replace standby state: %w", err)
	}
	if err := credentials.ReplaceJSON(credentialData); err != nil {
		return fmt.Errorf("replace standby credentials: %w", err)
	}
	if err := securestore.Write(authFile, authData, 0o600); err != nil {
		return fmt.Errorf("write standby auth store: %w", err)
	}
	return nil
}

func syncStandbyMonitoring(ctx context.Context, client *http.Client, managerURL, nodeID, token string, handler *api.ServerHandler) error {
	resp, err := requestStandbyBootstrap(ctx, client, managerURL, nodeID, token, "monitoring")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		return nil // Old managers and managers without an archive still work.
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bootstrap monitoring failed: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, monitoring.StandbyCopyMaxBytes+1))
	if err != nil {
		return err
	}
	if len(data) > monitoring.StandbyCopyMaxBytes {
		return errors.New("standby monitoring response exceeds the size limit")
	}
	var samples []models.SystemMetricPoint
	if err := json.Unmarshal(data, &samples); err != nil {
		return fmt.Errorf("decode standby monitoring samples: %w", err)
	}
	return handler.ImportMonitoringHistory(ctx, samples)
}

func writeStandbyFile(path string, data []byte, mode os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("standby file path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodewall-standby-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
