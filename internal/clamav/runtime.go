package clamav

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"nodewall/internal/nodeauth"
)

type Options struct {
	AssetsDir  string
	DataDir    string
	Socket     string
	ManagerURL func() string
	// Peers reads the current enrolled registry on each check, so a node can
	// discover later enrollments and refreshed certificates without restarting.
	Peers                 func() ([]nodeauth.Credential, error)
	NodeID                string
	Token                 string
	TLSCAFile             string
	TLSInsecureSkipVerify bool
}

// UpdateStatus is persisted independently of the scanner report: a working
// engine can continue using its last verified database while updates fail.
type UpdateStatus struct {
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	Error       string    `json:"error,omitempty"`
	Source      string    `json:"source,omitempty"`
}

func ReadUpdateStatus() UpdateStatus {
	return readUpdateStatus(DataDir())
}

func readUpdateStatus(dir string) UpdateStatus {
	data, err := os.ReadFile(filepath.Join(dir, "update-status.json"))
	if err != nil {
		return UpdateStatus{}
	}
	var status UpdateStatus
	_ = json.Unmarshal(data, &status)
	return status
}

func writeStatus(dir string, status UpdateStatus) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".update-status-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(dir, "update-status.json"))
}

func loaderName(arch string) string {
	switch arch {
	case "amd64":
		return "ld-musl-x86_64.so.1"
	case "arm64":
		return "ld-musl-aarch64.so.1"
	default:
		return ""
	}
}

func engineCommand(ctx context.Context, engine, arch, executable string, args ...string) *exec.Cmd {
	loader := filepath.Join(engine, "lib", loaderName(arch))
	libraries := filepath.Join(engine, "lib") + ":" + filepath.Join(engine, "usr", "lib")
	commandArgs := []string{"--library-path", libraries, filepath.Join(engine, "usr", executable)}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, loader, commandArgs...)
	if executable == "bin/freshclam" {
		caFile := strings.TrimSpace(os.Getenv("NODEWALL_CLAMAV_CA_FILE"))
		if caFile == "" {
			caFile = filepath.Join(engine, "etc", "ssl", "cert.pem")
		}
		// Alpine's libcurl is built with an Ubuntu-style CA path, which does
		// not exist on CentOS 7. Use the bundled trust store without changing
		// the host; a private enterprise CA bundle can be selected explicitly.
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "CURL_CA_BUNDLE=") && !strings.HasPrefix(entry, "SSL_CERT_FILE=") {
				command.Env = append(command.Env, entry)
			}
		}
		command.Env = append(command.Env, "CURL_CA_BUNDLE="+caFile, "SSL_CERT_FILE="+caFile)
	}
	return command
}

func prepareEngine(assets, data, arch string) (string, error) {
	if loaderName(arch) == "" {
		return "", fmt.Errorf("unsupported ClamAV architecture %s", arch)
	}
	archive := filepath.Join(assets, "engines", arch+".tar.gz")
	engineFile, err := artifact(archive, arch, false)
	if err != nil {
		return "", fmt.Errorf("ClamAV engine bundle unavailable: %w", err)
	}
	runtimes := filepath.Join(data, "engines")
	if err := os.MkdirAll(runtimes, 0o700); err != nil {
		return "", err
	}
	destination := filepath.Join(runtimes, engineFile.SHA256)
	if _, err := os.Stat(filepath.Join(destination, "lib", loaderName(arch))); err == nil {
		if info, certErr := os.Stat(filepath.Join(destination, "etc", "ssl", "cert.pem")); certErr == nil && info.Mode().IsRegular() && info.Size() > 0 {
			return destination, nil
		}
		return "", errors.New("ClamAV runtime is missing its CA certificate bundle")
	}
	stage, err := os.MkdirTemp(runtimes, ".engine-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	if err := extractEngine(archive, stage); err != nil {
		return "", err
	}
	for _, name := range []string{filepath.Join("lib", loaderName(arch)), "usr/sbin/clamd", "usr/bin/freshclam", "usr/bin/clamscan", "usr/bin/sigtool"} {
		if info, err := os.Stat(filepath.Join(stage, name)); err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			return "", fmt.Errorf("invalid ClamAV runtime: missing executable %s", name)
		}
	}
	if info, err := os.Stat(filepath.Join(stage, "etc", "ssl", "cert.pem")); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return "", errors.New("ClamAV runtime is missing its CA certificate bundle")
	}
	if err := os.Rename(stage, destination); err != nil {
		if _, statErr := os.Stat(destination); statErr != nil {
			return "", err
		}
	}
	return destination, nil
}

func managedMarker(data string) error {
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(data, "managed"), []byte("nodewall-clamav\n"), 0o600)
}

// Managed reports whether NodeWall owns the private engine on this host.
func Managed() bool {
	_, err := os.Stat(filepath.Join(DataDir(), "managed"))
	return err == nil
}

// Run supervises a private clamd and retries database updates without stopping
// the agent or changing an existing system ClamAV service.
func Run(ctx context.Context, opts Options) {
	if runtime.GOOS != "linux" {
		return
	}
	runManaged(ctx, opts, 2*time.Minute)
}

func runManaged(ctx context.Context, opts Options, interval time.Duration) {
	if opts.AssetsDir == "" {
		opts.AssetsDir = AssetsDir()
	}
	if opts.DataDir == "" {
		opts.DataDir = DataDir()
	}
	if opts.Socket == "" {
		opts.Socket = strings.TrimSpace(os.Getenv("NODEWALL_CLAMD_SOCKET"))
		if opts.Socket == "" {
			opts.Socket = filepath.Join(opts.DataDir, "clamd.sock")
		}
	}
	managerURL := func() string {
		if opts.ManagerURL == nil {
			return ""
		}
		return strings.TrimRight(strings.TrimSpace(opts.ManagerURL()), "/")
	}
	_, bundleErr := os.Stat(filepath.Join(opts.AssetsDir, "engines", runtime.GOARCH+".tar.gz"))
	_, markerErr := os.Stat(filepath.Join(opts.DataDir, "managed"))
	if bundleErr != nil && managerURL() == "" && markerErr != nil && opts.Peers == nil {
		return
	}
	if err := managedMarker(opts.DataDir); err != nil {
		log.Printf("warning: ClamAV initialization failed: %v", err)
		return
	}
	status := readUpdateStatus(opts.DataDir)
	log.Printf("ClamAV automatic synchronization started: cluster checks every %s", interval)
	var daemon *exec.Cmd
	var daemonExit <-chan error
	var daemonEngine string
	engine := ""
	stopDaemon := func() {
		if daemon == nil {
			return
		}
		_ = daemon.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-daemonExit:
		case <-timer.C:
			_ = daemon.Process.Kill()
			<-daemonExit
		}
		daemon, daemonExit, daemonEngine = nil, nil, ""
	}
	defer stopDaemon()
	startDaemon := func() {
		if daemon != nil && engine != "" && daemonEngine != engine {
			stopDaemon()
		}
		if daemon != nil || engine == "" {
			return
		}
		configPath := filepath.Join(opts.DataDir, "clamd.conf")
		config := fmt.Sprintf("Foreground yes\nLocalSocket %s\nLocalSocketMode 600\nFixStaleSocket yes\nDatabaseDirectory %s\nConcurrentDatabaseReload no\nStreamMaxLength 64M\nMaxThreads 4\n", opts.Socket, filepath.Join(opts.DataDir, "current"))
		if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
			log.Printf("warning: write ClamAV configuration: %v", err)
			return
		}
		command := engineCommand(ctx, engine, runtime.GOARCH, "sbin/clamd", "--config-file="+configPath)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Start(); err != nil {
			log.Printf("warning: start ClamAV daemon: %v", err)
			return
		}
		daemon = command
		daemonEngine = engine
		exited := make(chan error, 1)
		daemonExit = exited
		go func() { exited <- command.Wait() }()
	}
	var lastUpstream time.Time
	check := func() {
		before, _ := os.Readlink(filepath.Join(opts.DataDir, "current"))
		previousEngine := engine
		previousStatus := status
		attempted := false
		status.LastAttempt = time.Now().UTC()
		manager := managerURL()
		var err error
		status.Source = "offline"
		// Start from the bundled verified databases even if the manager or the
		// public update service is temporarily unreachable.
		if localEngine, localErr := prepareEngine(opts.AssetsDir, opts.DataDir, runtime.GOARCH); localErr == nil {
			socket := opts.Socket
			if daemonEngine != localEngine {
				socket = ""
			}
			seedErr := seedDatabase(ctx, opts.AssetsDir, opts.DataDir, localEngine, runtime.GOARCH, socket)
			if seedErr == nil && engine != "" && engine != localEngine {
				seedErr = validateSet(ctx, filepath.Join(opts.DataDir, "current"), localEngine, runtime.GOARCH)
			}
			if seedErr != nil {
				log.Printf("warning: ClamAV offline database: %v", seedErr)
			} else {
				engine = localEngine
			}
			if _, statErr := os.Stat(filepath.Join(opts.DataDir, "current")); statErr == nil {
				startDaemon()
			}
		}
		if manager != "" || opts.Peers != nil {
			var synchronized, source string
			synchronized, source, err = syncFromCluster(ctx, opts, manager)
			if source != "" {
				attempted = true
				status.Source = source
			}
			if synchronized != "" {
				engine = synchronized
			}
			if _, statErr := os.Stat(filepath.Join(opts.DataDir, "current")); statErr == nil {
				startDaemon()
			}
		}
		if manager == "" && engine != "" && time.Since(lastUpstream) >= time.Hour {
			attempted = true
			lastUpstream = time.Now()
			status.Source = "upstream"
			if updateErr := updateFromUpstream(ctx, opts.DataDir, engine, runtime.GOARCH, opts.Socket); updateErr != nil {
				err = errors.Join(err, updateErr)
			} else {
				err = nil
			}
		}
		if engine == "" && err == nil {
			err = errors.New("ClamAV resources unavailable; waiting for an enrolled node with an offline bundle")
		}
		after, _ := os.Readlink(filepath.Join(opts.DataDir, "current"))
		if err != nil {
			status.Error = err.Error()
			log.Printf("warning: ClamAV database synchronization: %v", err)
		} else if attempted || after != before || engine != previousEngine {
			status.Error = ""
			status.LastSuccess = time.Now().UTC()
		} else {
			// Discovery with no peers is not a successful upstream update. Keep
			// an hourly FreshClam failure visible until a real update succeeds.
			status.Error, status.Source = previousStatus.Error, previousStatus.Source
		}
		if after != "" && (after != before || engine != previousEngine) {
			log.Printf("ClamAV synchronized: source=%s engine=%s database=%s", status.Source, filepath.Base(engine), after)
		}
		if writeErr := writeStatus(opts.DataDir, status); writeErr != nil {
			log.Printf("warning: save ClamAV update status: %v", writeErr)
		}
		// A failed update must not prevent the previously verified set running.
		if _, statErr := os.Stat(filepath.Join(opts.DataDir, "current")); statErr == nil {
			startDaemon()
		}
	}
	check()
	// Every node checks peers, including an original manager with no assets.
	// Only nodes without an upstream manager contact public mirrors, hourly.
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	restart := time.NewTicker(time.Minute)
	defer restart.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-daemonExit:
			daemon, daemonExit, daemonEngine = nil, nil, ""
			if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
				log.Printf("warning: ClamAV daemon exited: %v", err)
			}
		case <-restart.C:
			if _, err := os.Stat(filepath.Join(opts.DataDir, "current")); err == nil {
				startDaemon()
			}
		case <-ticker.C:
			check()
		}
	}
}
