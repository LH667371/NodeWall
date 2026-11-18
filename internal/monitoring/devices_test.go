package monitoring

import (
	"math"
	"testing"

	"nodewall/internal/models"
)

func TestLogicalCPUCounterIdentityAndReset(t *testing.T) {
	before, old, err := parseCPUStat([]byte("cpu 10 0 10 180 0 0 0 0\ncpu0 10 0 0 90 0 0 0 0\ncpu10 0 0 10 90 0 0 0 0\n"))
	if err != nil || before.cores != 2 || len(old) != 2 {
		t.Fatalf("parse logical CPUs: %+v %+v %v", before, old, err)
	}
	_, current, err := parseCPUStat([]byte("cpu 70 0 50 280 0 0 0 0\ncpu10 0 0 50 150 0 0 0 0\ncpu0 70 0 0 130 0 0 0 0\ncpu2 1 0 0 1 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]float64{"cpu0": 60, "cpu10": 40} {
		metric := logicalCPUUsage(name, current[name], old[name])
		if !metric.SampleReady || math.Abs(metric.UsagePercent-want) > 1e-9 {
			t.Fatalf("core identity or percentage lost: %+v want=%v", metric, want)
		}
	}
	if metric := logicalCPUUsage("cpu0", old["cpu0"], current["cpu0"]); metric.SampleReady || metric.UsagePercent != 0 {
		t.Fatal("counter reset invented utilization", metric)
	}
}

func TestNetworkHotplugAndCounterResetDoNotCreateLifetimeRateSpikes(t *testing.T) {
	before := map[string]networkCounters{"em1": {rxBytes: 1000, txBytes: 2000}, "gone0": {rxBytes: 1000000000}}
	current := map[string]networkCounters{"em1": {rxBytes: 1100, txBytes: 2200}, "new0": {rxBytes: 9000000000, txBytes: 8000000000}}
	metrics := models.NetworkMetrics{Interfaces: []models.NetworkInterfaceMetric{{Name: "em1"}, {Name: "new0"}}}
	applyNetworkRates(&metrics, current, before, 2)
	if metrics.RxBytesPerSecond != 50 || metrics.TxBytesPerSecond != 100 || (metrics.Interfaces[0].SampleReady == nil || !*metrics.Interfaces[0].SampleReady) || (metrics.Interfaces[1].SampleReady == nil || *metrics.Interfaces[1].SampleReady) {
		t.Fatalf("hotplug used a lifetime counter as a rate: %+v", metrics)
	}
	reset := models.NetworkMetrics{Interfaces: []models.NetworkInterfaceMetric{{Name: "em1"}}}
	applyNetworkRates(&reset, map[string]networkCounters{"em1": {rxBytes: 10}}, current, 2)
	if (reset.Interfaces[0].SampleReady == nil || *reset.Interfaces[0].SampleReady) || reset.RxBytesPerSecond != 0 {
		t.Fatal("reset NIC needs a new baseline", reset)
	}
}

func TestDiskHotplugAndCounterResetKeepDeviceRatesSeparate(t *testing.T) {
	before := map[string]diskCounters{"sda": {readBytes: 100, writeBytes: 200, readOps: 10, writeOps: 20, ioTimeMs: 20}}
	current := map[string]diskCounters{
		"sda": {readBytes: 300, writeBytes: 600, readOps: 14, writeOps: 28, ioTimeMs: 220},
		"sdb": {readBytes: 9000000000, writeBytes: 8000000000, ioTimeMs: 900000},
	}
	metrics := models.DiskMetrics{Devices: []models.DiskDeviceMetric{{Name: "sdb"}, {Name: "sda"}}}
	applyDiskRates(&metrics, current, before, 2)
	if metrics.ReadBytesPerSecond != 100 || metrics.WriteBytesPerSecond != 200 || metrics.IOUtilizationPercent != 10 ||
		metrics.Devices[0].SampleReady == nil || *metrics.Devices[0].SampleReady ||
		metrics.Devices[1].SampleReady == nil || !*metrics.Devices[1].SampleReady {
		t.Fatalf("disk identity/baseline lost after hotplug: %+v", metrics)
	}
	reset := models.DiskMetrics{Devices: []models.DiskDeviceMetric{{Name: "sda"}}}
	applyDiskRates(&reset, map[string]diskCounters{"sda": {readBytes: 1}}, current, 2)
	if reset.Devices[0].SampleReady == nil || *reset.Devices[0].SampleReady || reset.ReadBytesPerSecond != 0 {
		t.Fatal("reset disk needs a new baseline", reset)
	}
}
