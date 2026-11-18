package monitoring

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nodewall/internal/models"
)

func TestParseNvidiaSMI(t *testing.T) {
	metrics, err := parseNvidiaSMI([]byte("0, NVIDIA A10, 23028, 1024, 37, 44\n1, \"NVIDIA RTX, Test\", 8192, N/A, 0, N/A\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected two GPUs, got %#v", metrics)
	}
	if metrics[0].Vendor != "NVIDIA" || metrics[0].Name != "NVIDIA A10" || metrics[0].MemoryTotalBytes != 23028*1024*1024 || metrics[0].MemoryUsedBytes != 1024*1024*1024 || metrics[0].UtilizationPercent != 37 || metrics[0].TemperatureC != 44 {
		t.Fatalf("unexpected first GPU: %#v", metrics[0])
	}
	if metrics[1].Name != "NVIDIA RTX, Test" || metrics[1].MemoryUsedBytes != 0 {
		t.Fatalf("quoted or unavailable fields were not handled: %#v", metrics[1])
	}
}

func TestIdleSMIMetricsSurviveJSONWithoutInventingUnsupportedSensors(t *testing.T) {
	devices, err := parseNvidiaSMI([]byte("0, NVIDIA A30, 24576, 0, 0, 53\n1, NVIDIA A30, 24576, N/A, N/A, [N/A]\n"))
	if err != nil || len(devices) != 2 {
		t.Fatal(err, devices)
	}
	data, err := json.Marshal(devices)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip []models.AcceleratorMetrics
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"utilization_percent", "memory_used_bytes"} {
		metric, ok := roundTrip[0].Metrics[key]
		if !ok || metric.Value != 0 {
			t.Fatalf("idle GPU reading disappeared: %s %#v", key, roundTrip[0])
		}
		if _, ok := roundTrip[1].Metrics[key]; ok {
			t.Fatalf("unsupported sensor became zero: %s", key)
		}
	}
}

func TestSMIQueryFallsBackAndRemembersSupportedFields(t *testing.T) {
	dir := t.TempDir()
	command := filepath.Join(dir, "smi")
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$0.calls\"\ncase \"$1\" in *power.draw*) exit 1;; esac\nprintf '0, NVIDIA A30, 24576, 0, 0, 53\\n'\n"
	if err := os.WriteFile(command, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	c := &smiQueryCollector{command: command, vendor: "NVIDIA", backend: "nvidia-smi"}
	for range 2 {
		devices, err := c.Collect(t.Context())
		if err != nil || len(devices) != 1 || devices[0].TemperatureC != 53 {
			t.Fatalf("basic GPU metrics lost with unsupported extended fields: %#v %v", devices, err)
		}
	}
	log, err := os.ReadFile(command + ".calls")
	if err != nil || strings.Count(string(log), "power.draw") != 1 || len(strings.Split(strings.TrimSpace(string(log)), "\n")) != 3 {
		t.Fatalf("unsupported query was retried on every sample: %s %v", log, err)
	}
}

type gatedAcceleratorCollector struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (c *gatedAcceleratorCollector) Collect(ctx context.Context) ([]models.AcceleratorMetrics, error) {
	if c.calls.Add(1) == 1 {
		close(c.started)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.release:
		return []models.AcceleratorMetrics{{Name: "NVIDIA A30", Vendor: "NVIDIA", MemoryTotalBytes: 24576 * 1024 * 1024}}, nil
	}
}

func TestSlowGPUProbeDoesNotBlockMetricsAndSurvivesCallerCancellation(t *testing.T) {
	provider := &gatedAcceleratorCollector{started: make(chan struct{}), release: make(chan struct{})}
	c := &autoAcceleratorCollector{providers: []AcceleratorCollector{provider}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	returned := make(chan struct{})
	go func() { _, _ = c.Collect(ctx); close(returned) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		close(provider.release)
		t.Fatal("GPU initialization blocked the CPU/network metrics request")
	}
	<-provider.started
	cancel()
	for range 20 {
		_, _ = c.Collect(t.Context())
	}
	if provider.calls.Load() != 1 {
		t.Fatal("multiple Webs spawned duplicate GPU probes")
	}
	close(provider.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		devices, err := c.Collect(t.Context())
		if err == nil && len(devices) == 1 {
			if devices[0].MemoryTotalBytes == 0 || provider.calls.Load() != 1 {
				t.Fatal("GPU cache was not shared")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("cancelled HTTP request cancelled the shared GPU sample")
}

func TestPCIGPUWithoutDRMAndManagementDisplayExclusion(t *testing.T) {
	root := t.TempDir()
	for _, device := range []struct{ bus, vendor, id, class string }{
		{"0000:02:00.0", "0x19e5", "0x1711", "0x030000"},
		{"0000:3b:00.0", "0x10de", "0x20b7", "0x030200"},
		{"0000:86:00.0", "0x10de", "0x20b7", "0x030200"},
	} {
		path := filepath.Join(root, "bus/pci/devices", device.bus)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]string{"vendor": device.vendor, "device": device.id, "class": device.class, "uevent": "DRIVER=vfio-pci\n"} {
			if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	devices := (&drmAcceleratorCollector{root: root}).collectPCI()
	if len(devices) != 2 || devices[0].Driver != "vfio-pci" || len(devices[0].Metrics) != 0 {
		t.Fatalf("PCI GPU identity or unsupported sensor semantics lost: %#v", devices)
	}
	primary := []models.AcceleratorMetrics{{Vendor: "NVIDIA", Index: 9, BusID: "00000000:3B:00.0", Name: "NVIDIA A30", MemoryTotalBytes: 24576 * 1024 * 1024}}
	merged := mergeAcceleratorSources(primary, devices)
	if len(merged) != 2 || merged[0].Name != "NVIDIA A30" || merged[0].Driver != "vfio-pci" {
		t.Fatalf("same PCI device was duplicated by DRM/SMI index differences: %#v", merged)
	}
}

func TestPCIInventoryRefreshesWhileGPUDriverProbeIsStuck(t *testing.T) {
	root := t.TempDir()
	const first = "0000:3b:00.0"
	const replacement = "0000:86:00.0"
	device := filepath.Join(root, "bus/pci/devices", first)
	if err := os.MkdirAll(device, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"vendor": "0x10de", "device": "0x20b7", "class": "0x030200", "uevent": "DRIVER=nvidia\n"} {
		if err := os.WriteFile(filepath.Join(device, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	provider := &gatedAcceleratorCollector{started: make(chan struct{}), release: make(chan struct{})}
	defer close(provider.release)
	c := &autoAcceleratorCollector{providers: []AcceleratorCollector{provider}, sysfs: &drmAcceleratorCollector{root: root}}
	waitForDevice := func(bus string) {
		t.Helper()
		for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
			devices, err := c.Collect(t.Context())
			if err == nil && len(devices) == 1 && devices[0].BusID == bus {
				if devices[0].Name != "NVIDIA A30" || devices[0].Backend != "pci-sysfs" || len(devices[0].Metrics) != 0 {
					t.Fatalf("missing GPU sensors were reported as live: %#v", devices[0])
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("PCI inventory did not expose %s while the vendor query was pending", bus)
	}
	waitForDevice(first)
	select {
	case <-provider.started:
	case <-time.After(time.Second):
		t.Fatal("vendor query did not start")
	}
	if err := os.Rename(device, filepath.Join(filepath.Dir(device), replacement)); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.last = []models.AcceleratorMetrics{{Name: "NVIDIA A30", BusID: first, Backend: "nvidia-smi", UtilizationPercent: 63}}
	c.deadline = time.Now().Add(-time.Second)
	c.inventoryFetchedAt = time.Time{}
	c.mu.Unlock()
	waitForDevice(replacement)
	if calls := provider.calls.Load(); calls != 1 {
		t.Fatalf("blocked vendor query was restarted %d times", calls-1)
	}
}

func TestParseVendorAcceleratorFormats(t *testing.T) {
	metrics, err := parseSMIQuery([]byte("0, MTT S80, 16384, 512, 55, 48, 180, 250, 72, 1500, 1200\n"), "Moore Threads", "mthreads-gmi")
	if err != nil || len(metrics) != 1 {
		t.Fatalf("failed to parse SMI-compatible output: %v %#v", err, metrics)
	}
	if metrics[0].Backend != "mthreads-gmi" || metrics[0].PowerWatts != 180 || metrics[0].FanPercent != 72 || metrics[0].ClockMHz != 1500 {
		t.Fatalf("optional SMI fields were lost: %#v", metrics[0])
	}

	npu := parseNPUInfo([]byte("+--------+--------------+----------+---------------+\n| NPU ID | Chip Name    | AICore(%) | HBM-Usage(MB) |\n+--------+--------------+----------+---------------+\n| 0      | Ascend 910B  | 64       | 1024/8192 MB  |\n"))
	if len(npu) != 1 || npu[0].Vendor != "Huawei Ascend" || npu[0].Name != "Ascend 910B" || npu[0].UtilizationPercent != 64 || npu[0].MemoryUsedBytes != 1024*1000*1000 || npu[0].MemoryTotalBytes != 8192*1000*1000 {
		t.Fatalf("failed to parse NPU table: %#v", npu)
	}

	rocm, err := parseROCMSMI([]byte("{\"card0\":{\"Card series\":\"MI210\",\"GPU use (%)\":42,\"VRAM Total Memory (B)\":17179869184,\"VRAM Total Used Memory (B)\":1073741824,\"Temperature (Sensor edge) (C)\":51}}"))
	if err != nil || len(rocm) != 1 || rocm[0].Name != "MI210" || rocm[0].MemoryTotalBytes != 17179869184 || rocm[0].UtilizationPercent != 42 {
		t.Fatalf("failed to parse ROCm JSON: %v %#v", err, rocm)
	}
}

func TestDRMAcceleratorCollector(t *testing.T) {
	root := t.TempDir()
	device := filepath.Join(root, "class/drm/card0/device")
	if err := os.MkdirAll(filepath.Join(device, "hwmon/hwmon0"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"vendor":                   "0x1002\n",
		"product_name":             "AMD Test GPU\n",
		"gpu_busy_percent":         "62\n",
		"mem_info_vram_used":       "2147483648\n",
		"mem_info_vram_total":      "8589934592\n",
		"hwmon/hwmon0/temp1_input": "55000\n",
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(device, name), []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	metrics, err := (&drmAcceleratorCollector{root: root}).collectDRM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 1 || metrics[0].Vendor != "AMD" || metrics[0].Index != 0 || metrics[0].Name != "AMD Test GPU" || metrics[0].UtilizationPercent != 62 || metrics[0].MemoryUsedBytes != 2147483648 || metrics[0].TemperatureC != 55 {
		t.Fatalf("unexpected DRM GPU metrics: %#v", metrics)
	}
}
