package monitoring

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodewall/internal/models"
)

func TestCollectorCalculatesResourceUsageAndRates(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "proc")
	sysDir := filepath.Join(root, "sys")
	if err := os.MkdirAll(filepath.Join(procDir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysDir, "class/net/ens3"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysDir, "class/net/ens3/operstate"), []byte("up\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProc := func(cpu, rxBytes, txBytes string) {
		stat := "cpu " + cpu + "\nprocessor\t: 0\nprocessor\t: 1\n"
		if err := os.WriteFile(filepath.Join(procDir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(procDir, "meminfo"), []byte("MemTotal:       1024 kB\nMemAvailable:    256 kB\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(procDir, "loadavg"), []byte("1.25 0.50 0.25 1/100 10\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		network := "Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n" +
			"  ens3: " + rxBytes + " 10 0 0 0 0 0 0 " + txBytes + " 20 0 0 0 0 0 0\n"
		if err := os.WriteFile(filepath.Join(procDir, "net/dev"), []byte(network), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeProc("100 0 100 800 0 0 0 0", "1000", "2000")
	currentAt := time.Unix(100, 0)
	collector := NewCollector("node-test")
	collector.procDir = procDir
	collector.sysDir = sysDir
	collector.now = func() time.Time { return currentAt }
	first, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.SampleSeconds != 0 || first.CPU.UsagePercent != 0 {
		t.Fatalf("first sample should not invent rates: %#v", first)
	}
	if first.Memory.TotalBytes != 1024*1024 || first.Memory.UsedBytes != 768*1024 || first.Memory.UsedPercent != 75 {
		t.Fatalf("unexpected memory metrics: %#v", first.Memory)
	}
	if first.Network.Interfaces[0].OperationalState != "up" {
		t.Fatalf("network state was not read: %#v", first.Network.Interfaces)
	}

	writeProc("120 0 120 860 0 0 0 0", "3000", "4000")
	currentAt = currentAt.Add(2 * time.Second)
	second, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.CPU.UsagePercent != 40 {
		t.Fatalf("expected 40%% CPU usage, got %v", second.CPU.UsagePercent)
	}
	if second.Network.RxBytesPerSecond != 1000 || second.Network.TxBytesPerSecond != 1000 {
		t.Fatalf("unexpected network rates: %#v", second.Network)
	}
	if second.Network.Interfaces[0].RxPacketsPerSecond != 0 || second.CPU.Cores != 2 {
		t.Fatalf("unexpected per-interface/CPU metrics: %#v / %#v", second.Network.Interfaces[0], second.CPU)
	}
}

func TestParseNetworkDevSkipsHeaders(t *testing.T) {
	items := parseNetworkDev([]byte("Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\nlo: 1 2 0 0 0 0 0 0 3 4 0 0 0 0 0 0\n"))
	if len(items) != 1 || items[0].name != "lo" || items[0].counters.txPackets != 4 {
		t.Fatalf("unexpected parsed interfaces: %#v", items)
	}
}

func TestParseDiskStatsUsesPrometheusSectorCounters(t *testing.T) {
	items := parseDiskStats([]byte("8 0 sda 10 2 100 3 20 4 200 5 0 6 7\n8 1 sda1 3 0 30 1 4 0 40 1 0 2 3\n"))
	if len(items) != 2 {
		t.Fatalf("unexpected disk devices: %#v", items)
	}
	if items[0].name != "sda" || items[0].counters.readOps != 10 || items[0].counters.readBytes != 100*512 || items[0].counters.writeBytes != 200*512 {
		t.Fatalf("unexpected disk counters: %#v", items[0])
	}
}

func TestIsPhysicalOrNFSFilesystemFiltersVirtualMounts(t *testing.T) {
	tests := []struct {
		name   string
		device string
		fsType string
		want   bool
	}{
		{name: "local ext4", device: "/dev/sda1", fsType: "ext4", want: true},
		{name: "local mapper", device: "/dev/mapper/vg-root", fsType: "xfs", want: true},
		{name: "nfs", device: "nas.example:/exports/data", fsType: "nfs4", want: true},
		{name: "overlay", device: "overlay", fsType: "overlay", want: false},
		{name: "tmpfs", device: "tmpfs", fsType: "tmpfs", want: false},
		{name: "bind mount", device: "/var/lib/container", fsType: "ext4", want: false},
		{name: "fuse", device: "/dev/fuse", fsType: "fuseblk", want: false},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			if got := isPhysicalOrNFSFilesystem(item.device, item.fsType); got != item.want {
				t.Fatalf("isPhysicalOrNFSFilesystem(%q, %q) = %v, want %v", item.device, item.fsType, got, item.want)
			}
		})
	}
}

func TestShorterFilesystemMountPrefersDeviceRoot(t *testing.T) {
	if !shorterFilesystemMount("/", "/var/lib/kubelet/pods/volume") {
		t.Fatal("expected root mount to be preferred")
	}
	if shorterFilesystemMount("/var/lib/kubelet/pods/volume", "/") {
		t.Fatal("did not expect a child mount to replace root")
	}
	if !shorterFilesystemMount("/data", "/data/archive") {
		t.Fatal("expected shorter mountpoint to be preferred")
	}
}

func TestParseProcessStatHandlesSpacesInCommandName(t *testing.T) {
	fields := make([]string, 22)
	fields[0] = "S"
	for index := 1; index < len(fields); index++ {
		fields[index] = "0"
	}
	fields[11] = "120"
	fields[12] = "30"
	fields[21] = "1024"
	data := []byte("123 (worker process) " + strings.Join(fields, " "))

	name, state, utime, stime, rss, ok := parseProcessStat(data)
	if !ok || name != "worker process" || state != "S" || utime != 120 || stime != 30 || rss != 1024 {
		t.Fatalf("unexpected process stat: %q %q %d %d %d %v", name, state, utime, stime, rss, ok)
	}
}

func TestApplyProcessRatesAndKernelRates(t *testing.T) {
	processes := models.ProcessMetrics{}
	applyProcessRates(&processes,
		map[int]processCounters{42: {ticks: 150, item: models.ProcessMetric{PID: 42, Name: "nodewall", MemoryBytes: 1024}}},
		map[int]processCounters{42: {ticks: 100}},
		1,
	)
	if len(processes.Top) != 1 || processes.Top[0].CPUPercent != 50 {
		t.Fatalf("unexpected process rate: %#v", processes.Top)
	}

	kernel := models.KernelMetrics{}
	applyKernelRates(&kernel, kernelCounters{contextSwitches: 300, interrupts: 250, forks: 20}, kernelCounters{contextSwitches: 100, interrupts: 150, forks: 10}, 2)
	if kernel.ContextSwitchesPerSecond != 100 || kernel.InterruptsPerSecond != 50 || kernel.ForksPerSecond != 5 {
		t.Fatalf("unexpected kernel rates: %#v", kernel)
	}
}
