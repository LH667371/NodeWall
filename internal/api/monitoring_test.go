package api

import (
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
		writeJSON(w, 200, models.SystemMetrics{CapturedAt: time.Now().UTC(), CPU: models.CPUMetrics{UsagePercent: 42}, Memory: models.MemoryMetrics{TotalBytes: 1024, UsedPercent: 60}})
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
}

func TestMonitoringStorageFailureDoesNotDisableConsole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := store.New()
	h, err := NewServerHandler(config.ServerConfig{MonitoringHistoryDir: path, MonitoringHistoryBytes: 1 << 20}, service.NewPolicyService(st), st)
	if err != nil {
		t.Fatal("auxiliary storage disabled management console:", err)
	}
	response := httptest.NewRecorder()
	h.handleMonitoringHistory(response, httptest.NewRequest(http.MethodGet, "/monitoring/history", nil))
	var history models.SystemMetricsHistory
	_ = json.Unmarshal(response.Body.Bytes(), &history)
	if response.Code != 200 || history.StorageError == "" {
		t.Fatal("degraded persistence was hidden")
	}
}
