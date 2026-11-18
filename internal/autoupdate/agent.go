package autoupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"nodewall/internal/transporttls"
	"nodewall/internal/version"
)

type AgentOptions struct {
	Token      string
	NodeID     string
	ManagerURL string
	// ManagerURLSource allows a live control-plane heartbeat to repair a
	// manager web-port migration without restarting the agent first.
	ManagerURLSource func() string
	Interval         time.Duration
	// Trigger wakes the normal version check when the manager reports a new
	// package during a heartbeat. The periodic ticker remains the fallback for
	// managers that do not expose the heartbeat version fields yet.
	Trigger               <-chan struct{}
	TLSCAFile             string
	TLSInsecureSkipVerify bool
}

func RunLoop(ctx context.Context, opts AgentOptions) {
	interval := opts.Interval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	check := func() {
		// The manager certificate is refreshed during standby synchronization and
		// enrollment repair. Build the transport for every check so a long-lived
		// agent does not keep an obsolete CA pool after that file is replaced.
		client, err := updateHTTPClient(opts)
		if err != nil {
			log.Printf("warning: auto-update TLS setup failed: %v", err)
			return
		}
		managerURL := strings.TrimSpace(opts.ManagerURL)
		if opts.ManagerURLSource != nil {
			if current := strings.TrimSpace(opts.ManagerURLSource()); current != "" {
				managerURL = current
			}
		}
		candidateManagerURL := managerURL
		managerURL, err = normalizeManagerURL(candidateManagerURL)
		if err != nil {
			if strings.TrimSpace(candidateManagerURL) != "" {
				log.Printf("warning: auto-update manager URL is invalid: %v", err)
			}
			return
		}
		remote, err := fetchRemoteVersion(ctx, client, managerURL, opts.Token, opts.NodeID)
		if err != nil {
			log.Printf("warning: auto-update check failed: %v", err)
			return
		}
		local := localPackageVersion()
		serverOutdated := managementServerOutdated("/proc", "/opt/nodewall")
		if remote == "" || (remote == local && runningPackageVersion() == local && !serverOutdated) {
			return
		}
		log.Printf("nodewall auto-update: installed package=%s running package=%s remote package=%s management server outdated=%t", local, runningPackageVersion(), remote, serverOutdated)
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

// runningPackageVersion comes from the binary's build metadata. Reading only
// /opt/nodewall/PACKAGE_VERSION is insufficient after an interrupted update:
// the updater may have replaced that marker while systemd try-restart silently
// skipped an inactive unit, leaving the old process running forever.
func runningPackageVersion() string {
	value := version.Current().PackageVersion
	if value == "dev" {
		return ""
	}
	return value
}

func updateHTTPClient(opts AgentOptions) (*http.Client, error) {
	tlsConfig, err := transporttls.ClientConfig(opts.TLSCAFile, "", opts.TLSInsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			ForceAttemptHTTP2: true,
		},
	}, nil
}

// ForceUpdate downloads the manager's current package and runs the local
// updater immediately. It is used by an explicit node-management action when
// an operator needs convergence before the normal heartbeat/ticker interval.
// The updater itself is responsible for replacing the installed runtime and
// restarting the services, so this function only performs the remote fetch and
// hands off to the existing update path.
func ForceUpdate(ctx context.Context, opts AgentOptions) error {
	managerURL, err := normalizeManagerURL(opts.ManagerURL)
	if err != nil {
		return err
	}
	client, err := updateHTTPClient(opts)
	if err != nil {
		return fmt.Errorf("configure update TLS: %w", err)
	}
	return pullAndUpdate(ctx, client, managerURL, opts)
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
	managerURL, err := normalizeManagerURL(managerURL)
	if err != nil {
		return err
	}
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
	// The updater replaces the running Agent/Server process. It must outlive
	// the agent context: stopping the parent during a direct-service restart
	// cancels CommandContext and previously killed the updater halfway through
	// the install, leaving a new package marker with the old process still
	// serving traffic.
	cmd := exec.Command(tmpPath, "update")
	// The manager may have migrated from the legacy 8080 web port while an
	// enrolled node is still running with the old URL in its environment. Carry
	// the URL used for this download into the updater and persist it there so
	// the next heartbeat and update use the same manager endpoint.
	cmd.Env = replaceEnvValue(os.Environ(), "NODEWALL_MANAGER_URL", managerURL)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func normalizeManagerURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", fmt.Errorf("manager URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid manager URL %q", raw)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid manager URL scheme %q", parsed.Scheme)
	}
	return raw, nil
}

func replaceEnvValue(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	replaced := false
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			if !replaced {
				result = append(result, prefix+value)
				replaced = true
			}
			continue
		}
		result = append(result, entry)
	}
	if !replaced {
		result = append(result, prefix+value)
	}
	return result
}
