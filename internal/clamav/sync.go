package clamav

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"nodewall/internal/nodeauth"
	"nodewall/internal/transporttls"
)

type syncSource struct {
	name, origin, prefix, nodeID, token string
	client                              *http.Client
}

func newSyncSource(name, origin, prefix, nodeID, token string, tlsConfig *tls.Config) (*syncSource, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("ClamAV synchronization requires an HTTPS source URL")
	}
	if tlsConfig == nil || (tlsConfig.InsecureSkipVerify && tlsConfig.VerifyConnection == nil) || token == "" || nodeID == "" {
		return nil, errors.New("ClamAV synchronization requires verified TLS and node credentials")
	}
	return &syncSource{
		name: name, origin: origin, prefix: prefix, nodeID: nodeID, token: token,
		client: &http.Client{
			Timeout: 15 * time.Minute,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
				DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func managerSyncSource(opts Options, manager string) (*syncSource, error) {
	if opts.TLSInsecureSkipVerify {
		return nil, errors.New("ClamAV synchronization requires verified TLS and node credentials")
	}
	tlsConfig, err := transporttls.ClientConfig(opts.TLSCAFile, "", false)
	if err != nil {
		return nil, err
	}
	return newSyncSource("manager", manager, "/join/clamav", opts.NodeID, opts.Token, tlsConfig)
}

func peerSyncSource(peer nodeauth.Credential) (*syncSource, error) {
	parsed, err := url.Parse(peer.AgentURL)
	if err != nil || parsed.Host == "" || peer.Certificate == "" {
		return nil, errors.New("ClamAV peer requires an enrolled endpoint and certificate")
	}
	tlsConfig, err := transporttls.ClientConfigFromPEM([]byte(peer.Certificate), parsed.Hostname(), false)
	if err != nil {
		return nil, err
	}
	// The replicated registry pins each Agent separately. A manager CA must
	// never authorize a different peer's endpoint or receive its credentials.
	return newSyncSource("peer:"+peer.NodeID, peer.AgentURL, "/clamav", peer.NodeID, peer.Token, tlsConfig)
}

func (source *syncSource) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.origin+source.prefix+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(nodeauth.NodeHeader, source.nodeID)
	req.Header.Set("Authorization", "Bearer "+source.token)
	response, err := source.client.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("%s ClamAV request failed: %s", source.name, response.Status)
	}
	return response, nil
}

func (source *syncSource) manifest(ctx context.Context, arch string) (Manifest, error) {
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := source.get(requestCtx, "/manifest?arch="+arch)
	if err != nil {
		return Manifest{}, err
	}
	defer response.Body.Close()
	var manifest Manifest
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	if manifest.Engine.Name != arch || !validArtifact(manifest.Engine, 128<<20) || len(manifest.Database) != len(databaseNames) {
		return Manifest{}, errors.New("source returned an invalid ClamAV manifest")
	}
	if manifest.Engine.Release != "" {
		if _, valid := parseEngineRelease(manifest.Engine.Release); !valid {
			return Manifest{}, errors.New("source returned an invalid ClamAV engine release")
		}
	}
	seen := make(map[string]bool, len(databaseNames))
	for _, item := range manifest.Database {
		name := databaseName(item.Name)
		if !validDatabaseName(name) || (item.Name != name+".cvd" && item.Name != name+".cld") || !validArtifact(item, 256<<20) || item.Version == 0 || seen[name] {
			return Manifest{}, errors.New("source returned an invalid ClamAV database manifest")
		}
		seen[name] = true
	}
	return manifest, nil
}

func (source *syncSource) download(ctx context.Context, kind string, item Artifact, path string) error {
	resp, err := source.get(ctx, "/"+kind+"/"+url.PathEscape(item.Name)+"?sha256="+url.QueryEscape(item.SHA256))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, item.Size+1))
	if copyErr == nil {
		copyErr = file.Sync()
	}
	if closeErr := file.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return copyErr
	}
	if size != item.Size || hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
		return fmt.Errorf("ClamAV %s digest or size mismatch", item.Name)
	}
	return os.Rename(name, path)
}

func syncFromManager(ctx context.Context, opts Options, manager string) (string, error) {
	source, err := managerSyncSource(opts, manager)
	if err != nil {
		return "", err
	}
	defer source.client.CloseIdleConnections()
	engine, _, err := synchronizeSources(ctx, opts, []*syncSource{source})
	return engine, err
}

func syncFromCluster(ctx context.Context, opts Options, manager string) (string, string, error) {
	var sources []*syncSource
	var failures []error
	if manager != "" {
		source, err := managerSyncSource(opts, manager)
		if err != nil {
			failures = append(failures, err)
		} else {
			sources = append(sources, source)
		}
	}
	if opts.Peers != nil {
		peers, err := opts.Peers()
		if err != nil {
			failures = append(failures, err)
		}
		for _, peer := range peers {
			if peer.NodeID == opts.NodeID {
				continue
			}
			source, err := peerSyncSource(peer)
			if err != nil {
				failures = append(failures, fmt.Errorf("ClamAV peer %s: %w", peer.NodeID, err))
				continue
			}
			sources = append(sources, source)
		}
	}
	defer func() {
		for _, source := range sources {
			source.client.CloseIdleConnections()
		}
	}()
	if len(sources) == 0 {
		if len(failures) != 0 {
			return "", "cluster", errors.Join(failures...)
		}
		return "", "", nil
	}
	return synchronizeSources(ctx, opts, sources)
}

type artifactChoice struct {
	item   Artifact
	source *syncSource
	path   string
}

type sourceManifest struct {
	source   *syncSource
	arch     string
	manifest Manifest
	err      error
}

func collectManifests(ctx context.Context, sources []*syncSource) []sourceManifest {
	results := make([]sourceManifest, 0, 2*len(sources))
	for _, source := range sources {
		for _, arch := range []string{runtime.GOARCH, otherArchitecture()} {
			results = append(results, sourceManifest{source: source, arch: arch})
		}
	}
	// Probe every enrolled peer with bounded concurrency and per-request
	// deadlines, without opening an unbounded number of cluster connections.
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(4, len(results)) {
		workers.Go(func() {
			for i := range jobs {
				result := &results[i]
				result.manifest, result.err = result.source.manifest(ctx, result.arch)
			}
		})
	}
	for i := range results {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	return results
}

func synchronizeSources(ctx context.Context, opts Options, sources []*syncSource) (string, string, error) {
	previousSet, _ := os.Readlink(filepath.Join(opts.DataDir, "current"))
	engines := make(map[string]artifactChoice, 2)
	for _, arch := range []string{runtime.GOARCH, otherArchitecture()} {
		path := filepath.Join(opts.AssetsDir, "engines", arch+".tar.gz")
		item, _ := artifact(path, arch, false)
		engines[arch] = artifactChoice{item: item, path: path}
	}
	current, err := currentVersions(opts.DataDir)
	if err != nil {
		return "", "cluster", err
	}
	databases := make(map[string]artifactChoice, len(databaseNames))
	for _, name := range databaseNames {
		if path, err := publishedDatabasePath(opts.AssetsDir, opts.DataDir, name); err == nil {
			item, err := artifact(path, filepath.Base(path), true)
			if err == nil {
				databases[name] = artifactChoice{item: item, path: path}
			}
		}
	}
	var failures []error
	available := false
	for _, result := range collectManifests(ctx, sources) {
		if result.err != nil {
			failures = append(failures, fmt.Errorf("%s/%s: %w", result.source.name, result.arch, result.err))
			continue
		}
		available = true
		if newerEngine(engines[result.arch].item, result.manifest.Engine) {
			engines[result.arch] = artifactChoice{item: result.manifest.Engine, source: result.source}
		}
		for _, item := range result.manifest.Database {
			name := databaseName(item.Name)
			if item.Version > databases[name].item.Version {
				databases[name] = artifactChoice{item: item, source: result.source}
			}
		}
	}
	if !available {
		return "", "cluster", errors.Join(failures...)
	}
	if err := ctx.Err(); err != nil {
		return "", "cluster", err
	}
	engineChoice := engines[runtime.GOARCH]
	if engineChoice.item.SHA256 == "" {
		return "", "cluster", errors.New("no enrolled node has a compatible ClamAV engine")
	}
	engine, publish, cleanup, err := stageEngine(ctx, opts, engineChoice)
	if err != nil {
		return "", "cluster", err
	}
	defer cleanup()
	candidate := make(map[string]uint64, len(databaseNames))
	for name, choice := range databases {
		candidate[name] = choice.item.Version
	}
	changed, err := compareVersions(current, candidate)
	if err != nil {
		return "", "cluster", err
	}
	if changed {
		stage, err := newDatabaseStage(opts.DataDir)
		if err != nil {
			return "", "cluster", err
		}
		defer os.RemoveAll(stage)
		for _, name := range databaseNames {
			choice := databases[name]
			destination := filepath.Join(stage, choice.item.Name)
			if choice.source == nil {
				err = copyAtomic(choice.path, destination, 0o600)
			} else {
				err = choice.source.download(ctx, "database", choice.item, destination)
			}
			if err != nil {
				return "", "cluster", err
			}
			if version, err := databaseVersion(destination); err != nil || version != choice.item.Version {
				return "", "cluster", fmt.Errorf("ClamAV %s database version mismatch", name)
			}
		}
		socket := opts.Socket
		if engineChoice.source != nil {
			// The supervisor restarts clamd with the validated new engine. The
			// old process may be unable to reload a database for a newer engine.
			socket = ""
		}
		if err := validateAndCommit(ctx, opts.DataDir, stage, engine, runtime.GOARCH, socket); err != nil {
			return "", "cluster", err
		}
	} else if engineChoice.source != nil {
		if err := validateSet(ctx, filepath.Join(opts.DataDir, "current"), engine, runtime.GOARCH); err != nil {
			return "", "cluster", err
		}
	}
	if err := publish(); err != nil {
		// The old archive remains intact when atomic publication fails. Restore
		// its database pointer too, in case the new set needs the newer engine.
		if changed {
			if previousSet != "" {
				if restoreErr := swapCurrent(opts.DataDir, previousSet); restoreErr != nil {
					return "", "cluster", errors.Join(err, fmt.Errorf("restore previous ClamAV database: %w", restoreErr))
				}
			} else if removeErr := os.Remove(filepath.Join(opts.DataDir, "current")); removeErr != nil {
				return "", "cluster", errors.Join(err, removeErr)
			}
		}
		return "", "cluster", err
	}
	// Cache both architectures even when this host only runs one of them. The
	// peer remains a distribution source for a mixed-architecture cluster.
	other := engines[otherArchitecture()]
	if other.source != nil {
		_, publishOther, cleanupOther, err := stageEngine(ctx, opts, other)
		if err != nil {
			return engine, "cluster", fmt.Errorf("synchronize standby engine: %w", err)
		}
		defer cleanupOther()
		if err := publishOther(); err != nil {
			return engine, "cluster", err
		}
	}
	return engine, "cluster", nil
}

func stageEngine(ctx context.Context, opts Options, choice artifactChoice) (string, func() error, func(), error) {
	assets := opts.AssetsDir
	cleanup := func() {}
	publish := func() error { return nil }
	if choice.source != nil {
		if err := os.MkdirAll(assets, 0o755); err != nil {
			return "", nil, cleanup, err
		}
		stage, err := os.MkdirTemp(assets, ".incoming-engine-*")
		if err != nil {
			return "", nil, cleanup, err
		}
		cleanup = func() { _ = os.RemoveAll(stage) }
		assets = stage
		archive := filepath.Join(stage, "engines", choice.item.Name+".tar.gz")
		if err := choice.source.download(ctx, "engine", choice.item, archive); err != nil {
			cleanup()
			return "", nil, func() {}, err
		}
		item, err := artifact(archive, choice.item.Name, false)
		if err != nil || (choice.item.Release != "" && item.Release != choice.item.Release) {
			cleanup()
			return "", nil, func() {}, errors.New("ClamAV engine release mismatch or invalid archive")
		}
		publish = func() error {
			return copyAtomic(archive, filepath.Join(opts.AssetsDir, "engines", choice.item.Name+".tar.gz"), 0o600)
		}
	}
	engine, err := prepareEngine(assets, opts.DataDir, choice.item.Name)
	if err != nil {
		cleanup()
		return "", nil, func() {}, err
	}
	return engine, publish, cleanup, nil
}

func databaseName(name string) string {
	return strings.TrimSuffix(strings.TrimSuffix(name, ".cvd"), ".cld")
}

func otherArchitecture() string {
	if runtime.GOARCH == "amd64" {
		return "arm64"
	}
	return "amd64"
}

func validArtifact(item Artifact, maxSize int64) bool {
	if item.Size <= 0 || item.Size > maxSize || len(item.SHA256) != 64 {
		return false
	}
	_, err := hex.DecodeString(item.SHA256)
	return err == nil && item.SHA256 == strings.ToLower(item.SHA256)
}
