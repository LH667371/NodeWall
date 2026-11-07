package monitoring

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"nodewall/internal/models"
)

func TestHistorySurvivesRestartAndSeparatesNodes(t *testing.T) {
	dir := t.TempDir()
	history, err := OpenHistory(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Minute)
	for _, point := range []models.SystemMetricPoint{
		{Timestamp: at, NodeID: "a", CPUPercent: 10},
		{Timestamp: at.Add(time.Second), NodeID: "b", CPUPercent: 80},
		{Timestamp: at.Add(2 * time.Second), NodeID: "a", CPUPercent: 20},
		{Timestamp: at.Add(10 * time.Second), NodeID: "a", CPUPercent: 40},
	} {
		if err := history.Append(point); err != nil {
			t.Fatal(err)
		}
	}
	history, err = OpenHistory(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	points, err := history.Query(context.Background(), []string{"a", "b", "offline"}, at, at.Add(time.Minute), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(points["a"]) != 2 || points["a"][0].CPUPercent != 20 || points["a"][1].CPUPercent != 40 || len(points["b"]) != 1 || points["b"][0].CPUPercent != 80 || len(points["offline"]) != 0 {
		t.Fatalf("unexpected persisted points: %#v", points)
	}
	info, _ := os.Stat(filepath.Join(dir, at.Format("20060102T15.jsonl")))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe history mode: %v", info.Mode())
	}
}

func TestHistoryRepairsInterruptedAppend(t *testing.T) {
	dir := t.TempDir()
	history, _ := OpenHistory(dir, 1<<20)
	at := time.Now().UTC().Add(-time.Minute)
	point := models.SystemMetricPoint{Timestamp: at, NodeID: "a", CPUPercent: 1}
	if err := history.Append(point); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, at.Format("20060102T15.jsonl"))
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString(`{"timestamp":"interrupted`)
	file.Close()
	history, err = OpenHistory(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	point.Timestamp = at.Add(10 * time.Second)
	point.CPUPercent = 2
	if err := history.Append(point); err != nil {
		t.Fatal(err)
	}
	points, err := history.Query(context.Background(), []string{"a"}, at.Add(-time.Second), at.Add(time.Minute), time.Second)
	if err != nil || len(points["a"]) != 2 || points["a"][1].CPUPercent != 2 {
		t.Fatalf("interrupted tail poisoned later samples: %#v %v", points, err)
	}
}

func TestHistoryRetentionAndQuotaDoNotDeleteUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().UTC().Add(-HistoryRetention - time.Hour).Format("20060102T15.jsonl")
	for _, name := range []string{old, "operator-notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("preserve unless a managed expired segment"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	point := models.SystemMetricPoint{Timestamp: time.Now().UTC().Add(-2 * time.Hour), NodeID: "a"}
	data, _ := json.Marshal(point)
	history, err := OpenHistory(dir, int64(len(data)+10))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, old)); !os.IsNotExist(err) {
		t.Fatal("expired segment retained")
	}
	if err := history.Append(point); err != nil {
		t.Fatal(err)
	}
	if err := history.Append(point); err == nil {
		t.Fatal("current-hour quota was ignored")
	}
	point.Timestamp = time.Now().UTC()
	if err := history.Append(point); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "operator-notes.txt")); err != nil {
		t.Fatal("unrelated file was removed")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("quota did not rotate oldest managed file: %v", entries)
	}
}

func TestHistoryConcurrentQueriesAndCancellation(t *testing.T) {
	history, err := OpenHistory(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Minute)
	var workers sync.WaitGroup
	for i := range 20 {
		workers.Go(func() {
			if err := history.Append(models.SystemMetricPoint{NodeID: "a", Timestamp: at.Add(time.Duration(i) * time.Second)}); err != nil {
				t.Error(err)
			}
			if _, err := history.Query(context.Background(), []string{"a"}, at, at.Add(time.Minute), time.Second); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := history.Query(ctx, []string{"a"}, at, at.Add(time.Minute), time.Second); err == nil {
		t.Fatal("canceled history query continued")
	}
}
