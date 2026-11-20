package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/service"
	"nodewall/internal/store"
)

func TestMonitoringCollectsWithoutBrowserAndSurvivesServerRestart(t *testing.T) {
	var samples atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		samples.Add(1)
		writeJSON(w, 200, models.SystemMetrics{
			CapturedAt: time.Now().UTC(),
			CPU: models.CPUMetrics{UsagePercent: 42, Cores: 2, LogicalCPUs: []models.LogicalCPUMetric{
				{Name: "cpu0", UsagePercent: 24, SampleReady: true}, {Name: "cpu1", UsagePercent: 60, SampleReady: true},
			}},
			Memory: models.MemoryMetrics{TotalBytes: 1024, UsedPercent: 60},
			Disk: models.DiskMetrics{Devices: []models.DiskDeviceMetric{{
				Name: "sda", ReadBytesPerSecond: 128, WriteBytesPerSecond: 64,
			}}},
			Network: models.NetworkMetrics{Interfaces: []models.NetworkInterfaceMetric{{
				Name: "eth0", OperationalState: "up", RxBytesPerSecond: 256,
			}}},
			Filesystems: []models.FilesystemMetric{{
				Device: "/dev/sda1", Mountpoint: "/", UsedPercent: 12,
			}},
			Accelerators: []models.AcceleratorMetrics{{
				Vendor: "NVIDIA", Index: 0, Name: "Test GPU", UtilizationPercent: 37,
				Metrics: map[string]models.AcceleratorMetric{"memory_used_bytes": {Value: 0, Unit: "bytes"}},
			}},
		})
	}))
	defer agent.Close()
	st := store.New()
	st.UpsertNode(context.Background(), models.Node{ID: "a", AgentURL: agent.URL})
	cfg := config.ServerConfig{MonitoringHistoryDir: t.TempDir(), MonitoringHistoryBytes: 1 << 20}
	h, err := NewServerHandler(cfg, service.NewPolicyService(st), st)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); h.RunMonitoring(ctx) }()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		h.systemMetricsMu.Lock()
		count := len(h.systemMetricsHistory["a"])
		h.systemMetricsMu.Unlock()
		if count > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if samples.Load() == 0 {
		t.Fatal("monitoring depended on a browser request")
	}
	agent.Close()
	restarted, err := NewServerHandler(cfg, service.NewPolicyService(st), st)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	restarted.handleMonitoringHistory(response, httptest.NewRequest(http.MethodGet, "/monitoring/history?node=a&range=86400", nil))
	var history models.SystemMetricsHistory
	if err := json.Unmarshal(response.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || len(history.Points) != 1 || history.Points[0].CPUPercent != 42 || history.RangeSeconds != 86400 || history.StorageError != "" {
		t.Fatalf("lost monitoring history while agent offline: %d %s", response.Code, response.Body.String())
	}
	if len(history.Nodes) != 1 || history.Nodes[0].CPUPercent != 42 || history.Nodes[0].MemoryTotalBytes != 1024 || history.Nodes[0].Timestamp.IsZero() {
		t.Fatal("offline node summary was replaced by zero values after restart")
	}
	if len(history.Nodes[0].LogicalCPUs) != 2 || len(history.Points[0].LogicalCPUs) != 2 || history.Points[0].LogicalCPUs[1].UsagePercent != 60 {
		t.Fatal("per-core history was lost after restart")
	}
	stream := restarted.monitoringStreamSnapshot(context.Background(), "a", 86400, "", "")
	if len(stream.Nodes) != 1 || len(stream.Nodes[0].LogicalCPUs) != 2 || len(stream.Nodes[0].Disk.Devices) != 1 || len(stream.Nodes[0].NetworkInterfaces) != 1 {
		t.Fatal("SSE lost archived device/core summaries after restart")
	}
	if len(history.Nodes[0].Disk.Devices) != 1 || history.Nodes[0].Disk.Devices[0].Name != "sda" {
		t.Fatal("per-device disk metrics were lost from the retained node summary")
	}
	if len(history.Nodes[0].NetworkInterfaces) != 1 || history.Nodes[0].NetworkInterfaces[0].Name != "eth0" {
		t.Fatal("per-interface network metrics were lost from the retained node summary")
	}
	if len(history.Nodes[0].Filesystems) != 1 || history.Nodes[0].Filesystems[0].Mountpoint != "/" {
		t.Fatal("filesystem metrics were lost from the retained node summary")
	}
	if len(history.Nodes[0].Accelerators) != 1 || history.Nodes[0].Accelerators[0].Name != "Test GPU" {
		t.Fatal("GPU metrics were lost from the retained node summary")
	}
	for _, devices := range [][]models.AcceleratorMetrics{history.Points[0].Accelerators, history.Nodes[0].Accelerators, stream.Nodes[0].Accelerators} {
		if len(devices) != 1 {
			t.Fatal("GPU inventory was lost in API/archive/SSE")
		}
		if metric, ok := devices[0].Metrics["memory_used_bytes"]; !ok || metric.Value != 0 {
			t.Fatal("zero GPU memory disappeared from API/archive/SSE")
		}
	}
	clusterResponse := httptest.NewRecorder()
	restarted.handleMonitoringHistory(clusterResponse, httptest.NewRequest(http.MethodGet, "/monitoring/history?range=86400", nil))
	var clusterHistory models.SystemMetricsHistory
	if err := json.Unmarshal(clusterResponse.Body.Bytes(), &clusterHistory); err != nil {
		t.Fatal(err)
	}
	if clusterResponse.Code != 200 || len(clusterHistory.NodePoints["a"]) != 1 {
		t.Fatalf("cluster monitoring response lost per-node history: %d %s", clusterResponse.Code, clusterResponse.Body.String())
	}
}

func TestMonitoringStorageFailureDoesNotDisableConsole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, models.SystemMetrics{
			CapturedAt: time.Now().UTC(),
			CPU:        models.CPUMetrics{UsagePercent: 12},
			Memory:     models.MemoryMetrics{TotalBytes: 1024},
		})
	}))
	defer agent.Close()
	st := store.New()
	st.UpsertNode(t.Context(), models.Node{ID: "a", AgentURL: agent.URL})
	h, err := NewServerHandler(config.ServerConfig{MonitoringHistoryDir: path, MonitoringHistoryBytes: 1 << 20}, service.NewPolicyService(st), st)
	if err != nil {
		t.Fatal("auxiliary storage disabled management console:", err)
	}
	read := func(handler *ServerHandler) models.SystemMetricsHistory {
		t.Helper()
		response := httptest.NewRecorder()
		handler.handleMonitoringHistory(response, httptest.NewRequest(http.MethodGet, "/monitoring/history?node=a", nil))
		var history models.SystemMetricsHistory
		if err := json.Unmarshal(response.Body.Bytes(), &history); err != nil || response.Code != http.StatusOK {
			t.Fatalf("history returned %d: %v", response.Code, err)
		}
		return history
	}
	now := time.Now().UTC().Truncate(systemMetricsSampleInterval)
	nodes := st.ListNodes(t.Context())
	h.collectSystemMetrics(t.Context(), nodes, now.Add(-systemMetricsSampleInterval))
	if history := read(h); history.StorageError == "" || history.ArchiveReadError != "" || len(history.Points) != 1 {
		t.Fatalf("write failure hid live samples: %+v", history)
	}
	if err := os.Rename(path, path+".fixture"); err != nil {
		t.Fatal(err)
	}
	h.collectSystemMetrics(t.Context(), nodes, now)
	if history := read(h); history.StorageError != "" || len(history.Points) != 2 {
		t.Fatalf("sampler did not recover storage without a restart: %+v", history)
	}
	restarted, err := NewServerHandler(config.ServerConfig{MonitoringHistoryDir: path, MonitoringHistoryBytes: 1 << 20}, service.NewPolicyService(st), st)
	if err != nil {
		t.Fatal(err)
	}
	if history := read(restarted); len(history.Points) != 1 || !history.Points[0].Timestamp.Equal(now) || history.StorageError != "" {
		t.Fatalf("the post-recovery sample was not saved: %+v", history)
	}
}

func TestMonitoringShowsReadableHistoryWhenOneRecordIsDamaged(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	at := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Hour).Add(time.Minute)
	var segment bytes.Buffer
	encoder := json.NewEncoder(&segment)
	for index := range 2 {
		if index > 0 {
			segment.WriteString("{damaged}\n")
		}
		point := models.SystemMetricPoint{NodeID: "retired", Timestamp: at.Add(time.Duration(index) * systemMetricsSampleInterval), CPUPercent: float64(10 + index)}
		if err := encoder.Encode(point); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, at.Format("20060102T15.jsonl")), segment.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	state := store.New()
	h, err := NewServerHandler(config.ServerConfig{MonitoringHistoryDir: dir, MonitoringHistoryBytes: 1 << 20}, service.NewPolicyService(state), state)
	if err != nil {
		t.Fatal(err)
	}
	from, to := at.Format(time.RFC3339), at.Add(time.Minute).Format(time.RFC3339)
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/monitoring/history?node=retired&from="+from+"&to="+to, nil))
	var result models.SystemMetricsHistory
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != http.StatusOK {
		t.Fatalf("read retained node: %d (%v)", response.Code, err)
	}
	for _, view := range []models.SystemMetricsHistory{result, h.monitoringStreamSnapshot(ctx, "retired", 60, from, to)} {
		if view.StorageError != "" || view.ArchiveReadError == "" || len(view.Points) != 2 || len(view.ArchiveNodes) != 1 || view.Points[1].CPUPercent != 11 {
			t.Fatalf("a damaged row hid valid history or looked like a save failure: %+v", view)
		}
	}
	if recent := h.monitoringStreamSnapshot(ctx, "retired", 900, "", ""); recent.StorageError != "" || recent.ArchiveReadError != "" {
		t.Fatalf("an older damaged row affected the current range: %+v", recent)
	}
}

func TestMonitoringReadsArchivedNodeAfterRemovalAndRestart(t *testing.T) {
	ctx := t.Context()
	state := store.New()
	state.UpsertNode(ctx, models.Node{ID: "worker-a", Name: "Worker A"})
	state.UpsertNode(ctx, models.Node{ID: "worker-b", Name: "Worker B"})
	cfg := config.ServerConfig{NodeID: "manager", MonitoringHistoryDir: t.TempDir(), MonitoringHistoryBytes: 1 << 20}
	first, err := NewServerHandler(cfg, service.NewPolicyService(state), state)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-25 * time.Hour).Truncate(systemMetricsSampleInterval)
	for _, point := range []models.SystemMetricPoint{
		{NodeID: "worker-a", NodeName: "Worker A", Timestamp: at, MemoryAvailableBytes: 128 << 20},
		{NodeID: "worker-a", NodeName: "Worker A", Timestamp: at.Add(10 * time.Minute), MemoryAvailableBytes: 12 << 20},
	} {
		if err := first.metricsArchive.Append(point); err != nil {
			t.Fatal(err)
		}
	}
	if !state.DeleteNode(ctx, "worker-a") {
		t.Fatal("fixture node was not removed")
	}
	restarted, err := NewServerHandler(cfg, service.NewPolicyService(state), state)
	if err != nil {
		t.Fatal(err)
	}
	routes := restarted.Routes()
	read := func(path string) models.SystemMetricsHistory {
		t.Helper()
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var history models.SystemMetricsHistory
		if err := json.Unmarshal(rec.Body.Bytes(), &history); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("history %s: %d %s (%v)", path, rec.Code, rec.Body.String(), err)
		}
		return history
	}
	latest := at.Add(10 * time.Minute)
	recent := read("/monitoring/history?node=worker-a&range=900")
	if recent.Points == nil || len(recent.Points) != 0 || len(recent.ArchiveNodes) != 1 {
		t.Fatalf("recent window must keep the archive catalog with an empty sample array: %+v", recent)
	}
	source := recent.ArchiveNodes[0]
	if source.Registered || source.NodeID != "worker-a" || source.Name != "Worker A" || !source.LastSampleAt.Equal(latest) || recent.ArchiveNodeID != "manager" {
		t.Fatalf("retained node metadata is incorrect: %+v", source)
	}
	from := latest.Add(-time.Hour).Format(time.RFC3339)
	to := latest.Format(time.RFC3339)
	history := read("/monitoring/history?node=worker-a&from=" + from + "&to=" + to)
	stream := restarted.monitoringStreamSnapshot(ctx, "worker-a", 3600, from, to)
	for _, result := range []models.SystemMetricsHistory{history, stream} {
		if len(result.Points) != 2 || result.Points[1].MemoryAvailableBytes != 12<<20 || len(result.Nodes) != 1 || result.Nodes[0].NodeID != "worker-a" {
			t.Fatalf("the last hour of real samples is missing: %+v", result)
		}
	}
	if nodes := restarted.service.ListNodes(ctx); len(nodes) != 1 || nodes[0].ID != "worker-b" {
		t.Fatalf("the archive changed live cluster membership: %+v", nodes)
	}
	unknown := httptest.NewRecorder()
	routes.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/monitoring/history?node=unknown", nil))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown node: %d %s", unknown.Code, unknown.Body.String())
	}
}

func TestMonitoringStreamRestoresArchivedMultiNodeSeries(t *testing.T) {
	ctx := context.Background()
	st := store.New()
	st.UpsertNode(ctx, models.Node{ID: "a", Name: "from"})
	st.UpsertNode(ctx, models.Node{ID: "b", Name: "nfs"})
	cfg := config.ServerConfig{MonitoringHistoryDir: t.TempDir(), MonitoringHistoryBytes: 1 << 20}
	h, err := NewServerHandler(cfg, service.NewPolicyService(st), st)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, point := range []models.SystemMetricPoint{
		{NodeID: "a", Timestamp: now, CPUPercent: 12, MemoryPercent: 34},
		{NodeID: "b", Timestamp: now, CPUPercent: 56, MemoryPercent: 78},
	} {
		if err := h.metricsArchive.Append(point); err != nil {
			t.Fatal(err)
		}
	}

	// The in-memory history intentionally stays empty: this is the state after
	// a management server restart before the background sampler has completed.
	snapshot := h.monitoringStreamSnapshot(ctx, "", 15*60, "", "")
	if len(snapshot.Points) != 1 {
		t.Fatalf("expected one aggregate sample, got %d", len(snapshot.Points))
	}
	if len(snapshot.NodePoints["a"]) != 1 || len(snapshot.NodePoints["b"]) != 1 {
		t.Fatalf("archived node series missing: %#v", snapshot.NodePoints)
	}
	if snapshot.Points[0].CPUPercent != 34 {
		t.Fatalf("aggregate CPU was not averaged across nodes: %#v", snapshot.Points[0])
	}

	selected := h.monitoringStreamSnapshot(ctx, "b", 15*60, "", "")
	if selected.Scope != "node" || len(selected.Points) != 1 || selected.Points[0].CPUPercent != 56 {
		t.Fatalf("selected node stream did not restore its archive: %#v", selected)
	}
}

func TestMonitoringResamplingKeepsRealDeviceSamplesAndGaps(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	latest := models.SystemMetricPoint{Timestamp: at.Add(4 * time.Second), LogicalCPUs: []models.LogicalCPUMetric{
		{Name: "cpu0", UsagePercent: 0, SampleReady: true},
	}, DiskDevices: []models.DiskDeviceMetric{{Name: "sda", IOUtilizationPercent: .267}}}
	points := resampleMonitoringPoints([]models.SystemMetricPoint{
		latest,
		{Timestamp: at, CPUPercent: 99},
		{Timestamp: at.Add(20 * time.Second), CPUPercent: 42},
	}, 5*time.Second)
	if len(points) != 2 || !points[0].Timestamp.Equal(at) || !points[1].Timestamp.Equal(at.Add(20*time.Second)) {
		t.Fatalf("resampling fabricated missing buckets: %#v", points)
	}
	if len(points[0].LogicalCPUs) != 1 || !points[0].LogicalCPUs[0].SampleReady || points[0].LogicalCPUs[0].UsagePercent != 0 ||
		len(points[0].DiskDevices) != 1 || points[0].DiskDevices[0].IOUtilizationPercent != .267 {
		t.Fatalf("resampling replaced a real device sample: %#v", points[0])
	}
	if !latest.Timestamp.Equal(at.Add(4 * time.Second)) {
		t.Fatal("resampling mutated a shared source sample")
	}
}

func TestMonitoringStreamBoundsDeviceHistoryAndReportsResolution(t *testing.T) {
	ctx := context.Background()
	st := store.New()
	for _, id := range []string{"a", "b"} {
		st.UpsertNode(ctx, models.Node{ID: id})
	}
	h, err := NewServerHandler(config.ServerConfig{}, service.NewPolicyService(st), st)
	if err != nil {
		t.Fatal(err)
	}
	const wantStep = 30
	const wantPoints = 6 * 3600 / wantStep
	from := time.Now().UTC().Add(-6 * time.Hour).Truncate(wantStep * time.Second)
	to := from.Add(6 * time.Hour)
	for nodeIndex, id := range []string{"a", "b"} {
		for index := range 4320 {
			h.systemMetricsHistory[id] = append(h.systemMetricsHistory[id], models.SystemMetricPoint{
				NodeID: id, Timestamp: from.Add(time.Duration(index)*5*time.Second + time.Duration(nodeIndex)*500*time.Millisecond),
				CPUPercent:        24 + float64(nodeIndex)*24,
				LogicalCPUs:       []models.LogicalCPUMetric{{Name: "cpu0", UsagePercent: float64(index), SampleReady: true}},
				DiskDevices:       []models.DiskDeviceMetric{{Name: "sda", ReadBytesPerSecond: float64(index)}},
				NetworkInterfaces: []models.NetworkInterfaceMetric{{Name: "eth0", RxBytesPerSecond: float64(index)}},
			})
		}
	}
	snapshot := h.monitoringStreamSnapshot(ctx, "", 6*3600, from.Format(time.RFC3339), to.Format(time.RFC3339))
	if snapshot.SampleIntervalSeconds != wantStep || len(snapshot.Points) != wantPoints {
		t.Fatalf("live history bypassed the point budget: step=%d points=%d", snapshot.SampleIntervalSeconds, len(snapshot.Points))
	}
	for _, id := range []string{"a", "b"} {
		history := snapshot.NodePoints[id]
		if len(history) != wantPoints || history[len(history)-1].DiskDevices[0].ReadBytesPerSecond != 4319 ||
			history[len(history)-1].NetworkInterfaces[0].RxBytesPerSecond != 4319 || len(history[len(history)-1].LogicalCPUs) != 1 {
			t.Fatalf("node %s lost its device history during resampling", id)
		}
	}
	if snapshot.Points[0].CPUPercent != 36 {
		t.Fatal("asymmetric node clocks split the aggregate buckets")
	}
	selected := h.monitoringStreamSnapshot(ctx, "a", 6*3600, from.Format(time.RFC3339), to.Format(time.RFC3339))
	if selected.SampleIntervalSeconds != wantStep || len(selected.Points) != wantPoints || len(selected.NodePoints) != 0 {
		t.Fatal("selected node did not use the same bounded resolution")
	}
	for _, node := range []string{"", "a"} {
		response := httptest.NewRecorder()
		h.handleMonitoringHistory(response, httptest.NewRequest(http.MethodGet,
			"/monitoring/history?node="+node+"&from="+from.Format(time.RFC3339)+"&to="+to.Format(time.RFC3339), nil))
		var result models.SystemMetricsHistory
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != http.StatusOK ||
			result.SampleIntervalSeconds != wantStep || len(result.Points) != wantPoints {
			t.Fatalf("HTTP history resolution diverged from SSE: node=%q status=%d step=%d points=%d err=%v",
				node, response.Code, result.SampleIntervalSeconds, len(result.Points), err)
		}
	}
}
