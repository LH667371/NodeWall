package autoupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"nodewall/internal/transporttls"
)

type AgentOptions struct {
	Token      string
	NodeID     string
	ManagerURL string
	Interval   time.Duration
	// Trigger wakes the normal version check when the manager reports a new
	// package during a heartbeat. The periodic ticker remains the fallback for
	// managers that do not expose the heartbeat version fields yet.
	Trigger               <-chan struct{}
	TLSCAFile             string
	TLSInsecureSkipVerify bool
}

func RunLoop(ctx context.Context, opts AgentOptions) {
	managerURL := strings.TrimRight(strings.TrimSpace(opts.ManagerURL), "/")
	if managerURL == "" {
		return
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	tlsConfig, err := transporttls.ClientConfig(opts.TLSCAFile, "", opts.TLSInsecureSkipVerify)
	if err != nil {
		log.Printf("warning: auto-update TLS setup failed: %v", err)
		return
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}}
	check := func() {
		remote, err := fetchRemoteVersion(ctx, client, managerURL, opts.Token, opts.NodeID)
		if err != nil {
			log.Printf("warning: auto-update check failed: %v", err)
			return
		}
		local := localPackageVersion()
		if remote == "" || remote == local {
			return
		}
		log.Printf("nodewall auto-update: local package=%s remote package=%s", local, remote)
		if err := pullAndUpdate(ctx, client, managerURL, opts); err != nil {
			log.Printf("warning: auto-update apply failed: %v", err)
		}
	}

	check()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-opts.Trigger:
			check()
		case <-ticker.C:
			check()
		}
	}
}

func fetchRemoteVersion(ctx context.Context, client *http.Client, managerURL, token, nodeID string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, managerURL+"/join/version", nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(nodeID) != "" {
		req.Header.Set("X-Nodewall-Node-ID", nodeID)
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("version check failed: %s", resp.Status)
	}
	var payload struct {
		Version        string `json:"version"`
		PackageVersion string `json:"package_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if value := strings.TrimSpace(payload.PackageVersion); value != "" {
		return value, nil
	}
	return strings.TrimSpace(payload.Version), nil
}

func localPackageVersion() string {
	data, err := os.ReadFile("/opt/nodewall/PACKAGE_VERSION")
	if err != nil {
		data, err = os.ReadFile("/opt/nodewall/VERSION")
	}
	if err != nil {
		return "dev"
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "dev"
	}
	return value
}

func pullAndUpdate(ctx context.Context, client *http.Client, managerURL string, options ...AgentOptions) error {
	arch := runtime.GOARCH
	url := managerURL + "/join/nodewall?arch=" + arch
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if len(options) > 0 {
		req.Header.Set("Authorization", "Bearer "+options[0].Token)
		req.Header.Set("X-Nodewall-Node-ID", options[0].NodeID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("package download failed: %s", resp.Status)
	}

	file, err := os.CreateTemp("", "nodewall-update-*")
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	defer os.Remove(tmpPath)
	if _, err := file.ReadFrom(resp.Body); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, tmpPath, "update")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
