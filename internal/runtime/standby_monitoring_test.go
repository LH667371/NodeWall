package runtime

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nodewall/internal/api"
	"nodewall/internal/config"
	"nodewall/internal/models"
	"nodewall/internal/nodeauth"
	"nodewall/internal/service"
	"nodewall/internal/store"
)

func TestStandbyStoresMonitoringAcrossPrimaryLoss(t *testing.T) {
	ctx := t.Context()
	newManager := func(id, dir string) *api.ServerHandler {
		t.Helper()
		state := store.New()
		h, err := api.NewServerHandler(config.ServerConfig{
			NodeID: id, MonitoringHistoryDir: dir, MonitoringHistoryBytes: 2 << 20,
		}, service.NewPolicyService(state), state)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	primary := newManager("primary", t.TempDir())
	standbyDir := t.TempDir()
	standby := newManager("backup", standbyDir)
	now := time.Now().UTC().Truncate(15 * time.Second)
	first, last := now.Add(-45*time.Second), now.Add(-15*time.Second)
	if err := primary.ImportMonitoringHistory(ctx, []models.SystemMetricPoint{
		{NodeID: "worker", NodeName: "Build worker", Timestamp: first, CPUPercent: 71, MemoryAvailableBytes: 64 << 20},
		{NodeID: "worker", NodeName: "Build worker", Timestamp: last, CPUPercent: 94, MemoryAvailableBytes: 4 << 20},
	}); err != nil {
		t.Fatal(err)
	}
	registry, err := nodeauth.Open("")
	if err != nil {
		t.Fatal(err)
	}
	primary.ConfigureNodeAuth(registry)
	server := httptest.NewTLSServer(primary.Routes())
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	addCredential := func(id, url string, canSync bool) string {
		t.Helper()
		token, err := nodeauth.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if err := registry.Put(nodeauth.Credential{
			NodeID: id, AgentURL: url, Token: token, Certificate: string(cert), Standby: &canSync,
		}); err != nil {
			t.Fatal(err)
		}
		return token
	}
	backupToken := addCredential("backup", "https://127.0.0.1:9080", true)
	ordinaryToken := addCredential("ordinary", "https://127.0.0.1:9081", false)
	for _, tc := range []struct {
		id, token string
		status    int
	}{
		{"", "", http.StatusUnauthorized},
		{"ordinary", ordinaryToken, http.StatusForbidden},
	} {
		resp, err := requestStandbyBootstrap(ctx, server.Client(), server.URL, tc.id, tc.token, "monitoring")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("unauthorized archive request from %q: %d", tc.id, resp.StatusCode)
		}
	}
	if err := syncStandbyMonitoring(ctx, server.Client(), server.URL, "backup", backupToken, standby); err != nil {
		t.Fatal(err)
	}
	archiveSize := func() int64 {
		t.Helper()
		files, err := filepath.Glob(filepath.Join(standbyDir, "*.jsonl"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no locally committed standby samples: %v", err)
		}
		var size int64
		for _, name := range files {
			info, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			size += info.Size()
		}
		return size
	}
	originalSize := archiveSize()
	standby = newManager("backup", standbyDir)
	if err := syncStandbyMonitoring(ctx, server.Client(), server.URL, "backup", backupToken, standby); err != nil {
		t.Fatal(err)
	}
	if size := archiveSize(); size != originalSize {
		t.Fatalf("retry after restart duplicated the archive: %d -> %d", originalSize, size)
	}
	server.Close()
	standby = newManager("backup", standbyDir)
	recorder := httptest.NewRecorder()
	standby.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/monitoring/history?node=worker&range=300", nil))
	var result models.SystemMetricsHistory
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("standby history with primary down: %d %s (%v)", recorder.Code, recorder.Body.String(), err)
	}
	if len(result.Points) != 2 || result.Points[1].MemoryAvailableBytes != 4<<20 || !result.Points[1].Timestamp.Equal(last) {
		t.Fatalf("standby did not preserve the original samples and gap: %+v", result.Points)
	}
	if result.ArchiveNodeID != "backup" || len(result.ArchiveNodes) != 1 || result.ArchiveNodes[0].Registered || !result.ArchiveNodes[0].LastSampleAt.Equal(last) {
		t.Fatalf("standby archive catalog lost the unavailable worker: %+v", result.ArchiveNodes)
	}
}
