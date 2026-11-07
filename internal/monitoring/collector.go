// Package monitoring collects host resource metrics without external agents
// or command-line dependencies. Linux exposes the required counters through
// /proc and /sys, which keeps the NodeWall agent self-contained.
package monitoring

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"nodewall/internal/models"
)

type Collector struct {
	nodeID  string
	procDir string
	sysDir  string
	now     func() time.Time

	mu              sync.Mutex
	previousCPU     cpuCounters
	previousCPUAt   time.Time
	previousNetwork map[string]networkCounters
	previousDisk    map[string]diskCounters
	previousKernel  kernelCounters
	previousProcess map[int]processCounters
	accelerator     AcceleratorCollector
}

// AcceleratorCollector keeps vendor-specific GPU support behind a small
// interface. The default implementation is empty and does not invoke
// nvidia-smi or require any driver package.
type AcceleratorCollector interface {
	Collect(context.Context) ([]models.AcceleratorMetrics, error)
}

type emptyAcceleratorCollector struct{}

func (emptyAcceleratorCollector) Collect(context.Context) ([]models.AcceleratorMetrics, error) {
	return []models.AcceleratorMetrics{}, nil
}

type cpuCounters struct {
	total  uint64
	idle   uint64
	iowait uint64
	user   uint64
	system uint64
	steal  uint64
	cores  int
}

type networkCounters struct {
	rxBytes   uint64
	txBytes   uint64
	rxPackets uint64
	txPackets uint64
	rxErrors  uint64
	txErrors  uint64
	rxDropped uint64
	txDropped uint64
}

type diskCounters struct {
	readBytes   uint64
	writeBytes  uint64
	readOps     uint64
	writeOps    uint64
	readTimeMs  uint64
	writeTimeMs uint64
	ioTimeMs    uint64
}

type kernelCounters struct {
	contextSwitches uint64
	interrupts      uint64
	forks           uint64
}

type processCounters struct {
	ticks uint64
	item  models.ProcessMetric
}

const processClockTicks = 100

func NewCollector(nodeID string) *Collector {
	return &Collector{
		nodeID:          strings.TrimSpace(nodeID),
		procDir:         "/proc",
		sysDir:          "/sys",
		now:             time.Now,
		previousNetwork: make(map[string]networkCounters),
		previousDisk:    make(map[string]diskCounters),
		previousProcess: make(map[int]processCounters),
		accelerator:     emptyAcceleratorCollector{},
	}
}

// SetAcceleratorCollector allows a future Linux/NVIDIA implementation to be
// added without changing the system metrics API or the default installation.
func (c *Collector) SetAcceleratorCollector(collector AcceleratorCollector) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if collector == nil {
		c.accelerator = emptyAcceleratorCollector{}
		return
	}
	c.accelerator = collector
}

// Collect reads one consistent-enough point-in-time view. The proc counters
// are monotonic in normal operation; counter resets are handled as a fresh
// interval so a reboot or interface reset cannot create a huge rate spike.
func (c *Collector) Collect(ctx context.Context) (models.SystemMetrics, error) {
	if err := ctx.Err(); err != nil {
		return models.SystemMetrics{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	capturedAt := c.now()
	counters, err := c.readCPU()
	if err != nil {
		return models.SystemMetrics{}, fmt.Errorf("read CPU metrics: %w", err)
	}
	memory, err := c.readMemory()
	if err != nil {
		return models.SystemMetrics{}, fmt.Errorf("read memory metrics: %w", err)
	}
	network, currentNetwork, err := c.readNetwork()
	if err != nil {
		return models.SystemMetrics{}, fmt.Errorf("read network metrics: %w", err)
	}
	load1, load5, load15 := c.readLoadAverage()
	kernel, currentKernel := c.readKernel()
	disk, currentDisk := c.readDisk()
	processes, currentProcesses := c.readProcesses(memory.TotalBytes)
	sockets := c.readSockets()
	fileDescriptors := c.readFileDescriptors()
	filesystems := c.readFilesystems()
	uptime := c.readUptime()

	sampleSeconds := 0.0
	if !c.previousCPUAt.IsZero() {
		sampleSeconds = capturedAt.Sub(c.previousCPUAt).Seconds()
		if sampleSeconds < 0 {
			sampleSeconds = 0
		}
	}
	cpu := models.CPUMetrics{Cores: counters.cores, Load1: load1, Load5: load5, Load15: load15}
	if sampleSeconds > 0 {
		totalDelta := counterDelta(c.previousCPU.total, counters.total)
		idleDelta := counterDelta(c.previousCPU.idle, counters.idle)
		iowaitDelta := counterDelta(c.previousCPU.iowait, counters.iowait)
		if totalDelta > 0 {
			busyDelta := totalDelta
			if idleDelta < busyDelta {
				busyDelta -= idleDelta
			} else {
				busyDelta = 0
			}
			cpu.UsagePercent = float64(busyDelta) / float64(totalDelta) * 100
			cpu.IowaitPercent = float64(iowaitDelta) / float64(totalDelta) * 100
			cpu.UserPercent = float64(counterDelta(c.previousCPU.user, counters.user)) / float64(totalDelta) * 100
			cpu.SystemPercent = float64(counterDelta(c.previousCPU.system, counters.system)) / float64(totalDelta) * 100
			cpu.StealPercent = float64(counterDelta(c.previousCPU.steal, counters.steal)) / float64(totalDelta) * 100
		}
	}
	applyNetworkRates(&network, currentNetwork, c.previousNetwork, sampleSeconds)
	applyDiskRates(&disk, currentDisk, c.previousDisk, sampleSeconds)
	applyKernelRates(&kernel, currentKernel, c.previousKernel, sampleSeconds)
	applyProcessRates(&processes, currentProcesses, c.previousProcess, sampleSeconds)
	accelerators := []models.AcceleratorMetrics{}
	if c.accelerator != nil {
		if detected, acceleratorErr := c.accelerator.Collect(ctx); acceleratorErr == nil {
			accelerators = detected
		}
	}

	result := models.SystemMetrics{
		NodeID:          c.nodeID,
		CapturedAt:      capturedAt,
		SampleSeconds:   sampleSeconds,
		CPU:             cpu,
		Memory:          memory,
		Network:         network,
		Disk:            disk,
		Kernel:          kernel,
		Processes:       processes,
		Sockets:         sockets,
		FileDescriptors: fileDescriptors,
		UptimeSeconds:   uptime,
		Filesystems:     filesystems,
		Accelerators:    accelerators,
	}

	c.previousCPU = counters
	c.previousCPUAt = capturedAt
	c.previousNetwork = currentNetwork
	c.previousDisk = currentDisk
	c.previousKernel = currentKernel
	c.previousProcess = currentProcesses
	return result, nil
}

func (c *Collector) readCPU() (cpuCounters, error) {
	data, err := os.ReadFile(filepath.Join(c.procDir, "stat"))
	if err != nil {
		return cpuCounters{}, err
	}
	counters, err := parseCPUStat(data)
	if err != nil {
		return cpuCounters{}, err
	}
	return counters, nil
}

func (c *Collector) readMemory() (models.MemoryMetrics, error) {
	data, err := os.ReadFile(filepath.Join(c.procDir, "meminfo"))
	if err != nil {
		return models.MemoryMetrics{}, err
	}
	values := parseMeminfo(data)
	total := values["MemTotal"]
	available, ok := values["MemAvailable"]
	if !ok {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	if total == 0 {
		return models.MemoryMetrics{}, fmt.Errorf("MemTotal is missing or zero")
	}
	if available > total {
		available = total
	}
	used := total - available
	return models.MemoryMetrics{
		TotalBytes:      total,
		UsedBytes:       used,
		AvailableBytes:  available,
		UsedPercent:     float64(used) / float64(total) * 100,
		CachedBytes:     values["Cached"],
		SwapTotalBytes:  values["SwapTotal"],
		SwapUsedBytes:   swapUsed(values["SwapTotal"], values["SwapFree"]),
		SwapUsedPercent: percentOf(swapUsed(values["SwapTotal"], values["SwapFree"]), values["SwapTotal"]),
	}, nil
}

func (c *Collector) readNetwork() (models.NetworkMetrics, map[string]networkCounters, error) {
	data, err := os.ReadFile(filepath.Join(c.procDir, "net/dev"))
	if err != nil {
		return models.NetworkMetrics{}, nil, err
	}
	interfaces := parseNetworkDev(data)
	result := models.NetworkMetrics{Interfaces: make([]models.NetworkInterfaceMetric, 0, len(interfaces))}
	current := make(map[string]networkCounters, len(interfaces))
	for _, item := range interfaces {
		state := ""
		if stateData, stateErr := os.ReadFile(filepath.Join(c.sysDir, "class/net", item.name, "operstate")); stateErr == nil {
			state = strings.TrimSpace(string(stateData))
		}
		current[item.name] = item.counters
		result.RxBytes += item.counters.rxBytes
		result.TxBytes += item.counters.txBytes
		result.RxPackets += item.counters.rxPackets
		result.TxPackets += item.counters.txPackets
		result.RxErrors += item.counters.rxErrors
		result.TxErrors += item.counters.txErrors
		result.RxDropped += item.counters.rxDropped
		result.TxDropped += item.counters.txDropped
		result.Interfaces = append(result.Interfaces, models.NetworkInterfaceMetric{
			Name:             item.name,
			OperationalState: state,
			RxBytes:          item.counters.rxBytes,
			TxBytes:          item.counters.txBytes,
			RxPackets:        item.counters.rxPackets,
			TxPackets:        item.counters.txPackets,
			RxErrors:         item.counters.rxErrors,
			TxErrors:         item.counters.txErrors,
			RxDropped:        item.counters.rxDropped,
			TxDropped:        item.counters.txDropped,
		})
	}
	return result, current, nil
}

func (c *Collector) readLoadAverage() (float64, float64, float64) {
	data, err := os.ReadFile(filepath.Join(c.procDir, "loadavg"))
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	return parseFloat(fields[0]), parseFloat(fields[1]), parseFloat(fields[2])
}

func (c *Collector) readUptime() float64 {
	data, err := os.ReadFile(filepath.Join(c.procDir, "uptime"))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	return parseFloat(fields[0])
}

func (c *Collector) readSockets() models.SocketMetrics {
	data, err := os.ReadFile(filepath.Join(c.procDir, "net/sockstat"))
	if err != nil {
		return models.SocketMetrics{}
	}
	result := models.SocketMetrics{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		values := make(map[string]uint64)
		for index := 1; index+1 < len(fields); index += 2 {
			value, parseErr := strconv.ParseUint(fields[index+1], 10, 64)
			if parseErr == nil {
				values[fields[index]] = value
			}
		}
		switch fields[0] {
		case "sockets:":
			result.Used = values["used"]
		case "TCP:":
			result.TCPInUse = values["inuse"]
			result.TCPOrphan = values["orphan"]
			result.TCPTimeWait = values["tw"]
			result.TCPAllocated = values["alloc"]
		case "UDP:":
			result.UDPInUse = values["inuse"]
		}
	}
	return result
}

func (c *Collector) readFileDescriptors() models.FileDescriptorMetrics {
	data, err := os.ReadFile(filepath.Join(c.procDir, "sys/fs/file-nr"))
	if err != nil {
		return models.FileDescriptorMetrics{}
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return models.FileDescriptorMetrics{}
	}
	allocated, allocatedErr := strconv.ParseUint(fields[0], 10, 64)
	unused, unusedErr := strconv.ParseUint(fields[1], 10, 64)
	if allocatedErr != nil || unusedErr != nil {
		return models.FileDescriptorMetrics{}
	}
	maximum := uint64(0)
	if maxData, maxErr := os.ReadFile(filepath.Join(c.procDir, "sys/fs/file-max")); maxErr == nil {
		maximum, _ = strconv.ParseUint(strings.TrimSpace(string(maxData)), 10, 64)
	}
	used := allocated
	if unused < used {
		used -= unused
	}
	return models.FileDescriptorMetrics{
		Allocated:   allocated,
		Unused:      unused,
		Maximum:     maximum,
		UsedPercent: percentOf(used, maximum),
	}
}

func (c *Collector) readKernel() (models.KernelMetrics, kernelCounters) {
	data, err := os.ReadFile(filepath.Join(c.procDir, "stat"))
	if err != nil {
		return models.KernelMetrics{}, kernelCounters{}
	}
	var current kernelCounters
	metrics := models.KernelMetrics{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}
		switch fields[0] {
		case "ctxt":
			current.contextSwitches = value
			metrics.ContextSwitches = value
		case "intr":
			current.interrupts = value
			metrics.Interrupts = value
		case "processes":
			current.forks = value
			metrics.Forks = value
		case "procs_running":
			metrics.ProcessesRunning = value
		case "procs_blocked":
			metrics.ProcessesBlocked = value
		}
	}
	return metrics, current
}

func (c *Collector) readDisk() (models.DiskMetrics, map[string]diskCounters) {
	data, err := os.ReadFile(filepath.Join(c.procDir, "diskstats"))
	if err != nil {
		return models.DiskMetrics{}, make(map[string]diskCounters)
	}
	parsed := parseDiskStats(data)
	metrics := models.DiskMetrics{Devices: make([]models.DiskDeviceMetric, 0, len(parsed))}
	current := make(map[string]diskCounters, len(parsed))
	for _, item := range parsed {
		// Keep whole devices in the aggregate. Prometheus exposes partitions
		// separately, but summing both a disk and its partitions would double
		// count throughput in the console's node-level total.
		if c.isDiskPartition(item.name) || isVirtualDisk(item.name) {
			continue
		}
		counters := item.counters
		current[item.name] = counters
		metrics.ReadBytes += counters.readBytes
		metrics.WriteBytes += counters.writeBytes
		metrics.ReadOps += counters.readOps
		metrics.WriteOps += counters.writeOps
		metrics.Devices = append(metrics.Devices, models.DiskDeviceMetric{
			Name:       item.name,
			ReadBytes:  counters.readBytes,
			WriteBytes: counters.writeBytes,
			ReadOps:    counters.readOps,
			WriteOps:   counters.writeOps,
		})
	}
	return metrics, current
}

func (c *Collector) isDiskPartition(name string) bool {
	data, err := os.ReadFile(filepath.Join(c.sysDir, "class/block", name, "partition"))
	return err == nil && strings.TrimSpace(string(data)) != ""
}

func isVirtualDisk(name string) bool {
	return strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "loop") ||
		strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "sr") || strings.HasPrefix(name, "fd")
}

func (c *Collector) readProcesses(totalMemory uint64) (models.ProcessMetrics, map[int]processCounters) {
	entries, err := os.ReadDir(c.procDir)
	if err != nil {
		return models.ProcessMetrics{}, make(map[int]processCounters)
	}
	metrics := models.ProcessMetrics{}
	current := make(map[int]processCounters)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		item, ticks, ok := c.readProcess(pid, totalMemory)
		if !ok {
			continue
		}
		metrics.Total++
		switch item.State {
		case "R":
			metrics.Running++
		case "D":
			metrics.Blocked++
		}
		current[pid] = processCounters{ticks: ticks, item: item}
	}
	return metrics, current
}

func (c *Collector) readProcess(pid int, totalMemory uint64) (models.ProcessMetric, uint64, bool) {
	data, err := os.ReadFile(filepath.Join(c.procDir, strconv.Itoa(pid), "stat"))
	if err != nil {
		return models.ProcessMetric{}, 0, false
	}
	name, state, utime, stime, rssPages, ok := parseProcessStat(data)
	if !ok {
		return models.ProcessMetric{}, 0, false
	}
	memoryBytes := rssPages * uint64(os.Getpagesize())
	memoryPercent := 0.0
	if totalMemory > 0 {
		memoryPercent = float64(memoryBytes) / float64(totalMemory) * 100
	}
	return models.ProcessMetric{
		PID:           pid,
		Name:          name,
		State:         state,
		MemoryBytes:   memoryBytes,
		MemoryPercent: memoryPercent,
	}, utime + stime, true
}

func (c *Collector) readFilesystems() []models.FilesystemMetric {
	data, err := os.ReadFile(filepath.Join(c.procDir, "mounts"))
	if err != nil {
		return nil
	}
	seenDevices := make(map[string]int)
	result := make([]models.FilesystemMetric, 0)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		device := unescapeMountField(fields[0])
		mountpoint := unescapeMountField(fields[1])
		fsType := fields[2]
		if mountpoint == "" || mountpoint == "-" || !isPhysicalOrNFSFilesystem(device, fsType) {
			continue
		}
		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err != nil {
			continue
		}
		blockSize := uint64(stat.Bsize)
		total := uint64(stat.Blocks) * blockSize
		free := uint64(stat.Bfree) * blockSize
		available := uint64(stat.Bavail) * blockSize
		used := uint64(0)
		if total > free {
			used = total - free
		}
		usedPercent := 0.0
		if total > 0 {
			usedPercent = float64(used) / float64(total) * 100
		}
		metric := models.FilesystemMetric{
			Device: device, Mountpoint: mountpoint, FSType: fsType,
			TotalBytes: total, FreeBytes: free, AvailableBytes: available,
			UsedBytes: used, UsedPercent: usedPercent,
		}
		if index, exists := seenDevices[device]; exists {
			// A bind mount can expose the same physical filesystem below a
			// Kubernetes pod path. Keep the shortest mountpoint so one device
			// contributes only one row and one capacity value.
			if shorterFilesystemMount(metric.Mountpoint, result[index].Mountpoint) {
				result[index] = metric
			}
			continue
		}
		seenDevices[device] = len(result)
		result = append(result, metric)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Mountpoint < result[j].Mountpoint })
	return result
}

func shorterFilesystemMount(candidate, current string) bool {
	if current == "/" {
		return false
	}
	if candidate == "/" {
		return true
	}
	return len(candidate) < len(current)
}

func applyKernelRates(metrics *models.KernelMetrics, current, previous kernelCounters, seconds float64) {
	if seconds <= 0 {
		return
	}
	metrics.ContextSwitchesPerSecond = float64(counterDelta(previous.contextSwitches, current.contextSwitches)) / seconds
	metrics.InterruptsPerSecond = float64(counterDelta(previous.interrupts, current.interrupts)) / seconds
	metrics.ForksPerSecond = float64(counterDelta(previous.forks, current.forks)) / seconds
}

func applyDiskRates(metrics *models.DiskMetrics, current, previous map[string]diskCounters, seconds float64) {
	if seconds <= 0 {
		return
	}
	var readAwaitTotal, writeAwaitTotal float64
	var readOpsTotal, writeOpsTotal uint64
	for index := range metrics.Devices {
		device := &metrics.Devices[index]
		currentCounters := current[device.Name]
		previousCounters, existed := previous[device.Name]
		if !existed {
			continue
		}
		device.ReadBytesPerSecond = float64(counterDelta(previousCounters.readBytes, currentCounters.readBytes)) / seconds
		device.WriteBytesPerSecond = float64(counterDelta(previousCounters.writeBytes, currentCounters.writeBytes)) / seconds
		device.ReadOpsPerSecond = float64(counterDelta(previousCounters.readOps, currentCounters.readOps)) / seconds
		device.WriteOpsPerSecond = float64(counterDelta(previousCounters.writeOps, currentCounters.writeOps)) / seconds
		readOpsDelta := counterDelta(previousCounters.readOps, currentCounters.readOps)
		writeOpsDelta := counterDelta(previousCounters.writeOps, currentCounters.writeOps)
		device.IOUtilizationPercent = minFloat(100, float64(counterDelta(previousCounters.ioTimeMs, currentCounters.ioTimeMs))/(seconds*10))
		if readOpsDelta > 0 {
			device.ReadAwaitMilliseconds = float64(counterDelta(previousCounters.readTimeMs, currentCounters.readTimeMs)) / float64(readOpsDelta)
		}
		if writeOpsDelta > 0 {
			device.WriteAwaitMilliseconds = float64(counterDelta(previousCounters.writeTimeMs, currentCounters.writeTimeMs)) / float64(writeOpsDelta)
		}
		readAwaitTotal += float64(counterDelta(previousCounters.readTimeMs, currentCounters.readTimeMs))
		writeAwaitTotal += float64(counterDelta(previousCounters.writeTimeMs, currentCounters.writeTimeMs))
		readOpsTotal += readOpsDelta
		writeOpsTotal += writeOpsDelta
		metrics.ReadBytesPerSecond += device.ReadBytesPerSecond
		metrics.WriteBytesPerSecond += device.WriteBytesPerSecond
		metrics.ReadOpsPerSecond += device.ReadOpsPerSecond
		metrics.WriteOpsPerSecond += device.WriteOpsPerSecond
		metrics.IOUtilizationPercent += device.IOUtilizationPercent
	}
	if len(metrics.Devices) > 0 {
		metrics.IOUtilizationPercent /= float64(len(metrics.Devices))
	}
	if readOpsTotal > 0 {
		metrics.ReadAwaitMilliseconds = readAwaitTotal / float64(readOpsTotal)
	}
	if writeOpsTotal > 0 {
		metrics.WriteAwaitMilliseconds = writeAwaitTotal / float64(writeOpsTotal)
	}
}

func applyProcessRates(metrics *models.ProcessMetrics, current, previous map[int]processCounters, seconds float64) {
	items := make([]models.ProcessMetric, 0, len(current))
	for pid, currentProcess := range current {
		item := currentProcess.item
		if seconds > 0 {
			if previousProcess, ok := previous[pid]; ok {
				item.CPUPercent = float64(counterDelta(previousProcess.ticks, currentProcess.ticks)) / seconds / processClockTicks * 100
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CPUPercent == items[j].CPUPercent {
			return items[i].MemoryBytes > items[j].MemoryBytes
		}
		return items[i].CPUPercent > items[j].CPUPercent
	})
	if len(items) > 8 {
		items = items[:8]
	}
	metrics.Top = items
}

func applyNetworkRates(n *models.NetworkMetrics, current map[string]networkCounters, previous map[string]networkCounters, seconds float64) {
	if seconds <= 0 {
		return
	}
	var previousTotal networkCounters
	for name, item := range current {
		previousItem := previous[name]
		previousTotal.rxBytes += previousItem.rxBytes
		previousTotal.txBytes += previousItem.txBytes
		previousTotal.rxPackets += previousItem.rxPackets
		previousTotal.txPackets += previousItem.txPackets
		previousTotal.rxErrors += previousItem.rxErrors
		previousTotal.txErrors += previousItem.txErrors
		previousTotal.rxDropped += previousItem.rxDropped
		previousTotal.txDropped += previousItem.txDropped
		for index := range n.Interfaces {
			if n.Interfaces[index].Name != name {
				continue
			}
			n.Interfaces[index].RxBytesPerSecond = float64(counterDelta(previousItem.rxBytes, item.rxBytes)) / seconds
			n.Interfaces[index].TxBytesPerSecond = float64(counterDelta(previousItem.txBytes, item.txBytes)) / seconds
			n.Interfaces[index].RxPacketsPerSecond = float64(counterDelta(previousItem.rxPackets, item.rxPackets)) / seconds
			n.Interfaces[index].TxPacketsPerSecond = float64(counterDelta(previousItem.txPackets, item.txPackets)) / seconds
			n.Interfaces[index].RxErrorsPerSecond = float64(counterDelta(previousItem.rxErrors, item.rxErrors)) / seconds
			n.Interfaces[index].TxErrorsPerSecond = float64(counterDelta(previousItem.txErrors, item.txErrors)) / seconds
			n.Interfaces[index].RxDroppedPerSecond = float64(counterDelta(previousItem.rxDropped, item.rxDropped)) / seconds
			n.Interfaces[index].TxDroppedPerSecond = float64(counterDelta(previousItem.txDropped, item.txDropped)) / seconds
			break
		}
	}
	n.RxBytesPerSecond = float64(counterDelta(previousTotal.rxBytes, n.RxBytes)) / seconds
	n.TxBytesPerSecond = float64(counterDelta(previousTotal.txBytes, n.TxBytes)) / seconds
	n.RxPacketsPerSecond = float64(counterDelta(previousTotal.rxPackets, n.RxPackets)) / seconds
	n.TxPacketsPerSecond = float64(counterDelta(previousTotal.txPackets, n.TxPackets)) / seconds
	n.RxErrorsPerSecond = float64(counterDelta(previousTotal.rxErrors, n.RxErrors)) / seconds
	n.TxErrorsPerSecond = float64(counterDelta(previousTotal.txErrors, n.TxErrors)) / seconds
	n.RxDroppedPerSecond = float64(counterDelta(previousTotal.rxDropped, n.RxDropped)) / seconds
	n.TxDroppedPerSecond = float64(counterDelta(previousTotal.txDropped, n.TxDropped)) / seconds
}

type parsedNetworkInterface struct {
	name     string
	counters networkCounters
}

type parsedDiskDevice struct {
	name     string
	counters diskCounters
}

func parseDiskStats(data []byte) []parsedDiskDevice {
	result := make([]parsedDiskDevice, 0)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}
		readOps, errReadOps := strconv.ParseUint(fields[3], 10, 64)
		readSectors, errReadSectors := strconv.ParseUint(fields[5], 10, 64)
		writeOps, errWriteOps := strconv.ParseUint(fields[7], 10, 64)
		writeSectors, errWriteSectors := strconv.ParseUint(fields[9], 10, 64)
		if errReadOps != nil || errReadSectors != nil || errWriteOps != nil || errWriteSectors != nil {
			continue
		}
		result = append(result, parsedDiskDevice{
			name: fields[2],
			counters: diskCounters{
				readOps: readOps, readBytes: readSectors * 512,
				writeOps: writeOps, writeBytes: writeSectors * 512,
				readTimeMs:  parseUintOrZero(fields[6]),
				writeTimeMs: parseUintOrZero(fields[10]),
				ioTimeMs:    parseUintOrZero(fields[12]),
			},
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result
}

func parseProcessStat(data []byte) (name, state string, utime, stime, rssPages uint64, ok bool) {
	line := strings.TrimSpace(string(data))
	closeParen := strings.LastIndex(line, ")")
	openParen := strings.Index(line, "(")
	if openParen < 0 || closeParen <= openParen || closeParen+2 > len(line) {
		return "", "", 0, 0, 0, false
	}
	fields := strings.Fields(line[closeParen+1:])
	// The slice starts at field 3 (state), so utime (field 14), stime
	// (field 15), and rss (field 24) are indexes 11, 12, and 21.
	if len(fields) <= 21 {
		return "", "", 0, 0, 0, false
	}
	utime, errUtime := strconv.ParseUint(fields[11], 10, 64)
	stime, errStime := strconv.ParseUint(fields[12], 10, 64)
	rss, errRSS := strconv.ParseInt(fields[21], 10, 64)
	if errUtime != nil || errStime != nil || errRSS != nil || rss < 0 {
		return "", "", 0, 0, 0, false
	}
	return line[openParen+1 : closeParen], fields[0], utime, stime, uint64(rss), true
}

func unescapeMountField(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(value)
}

func isPseudoFilesystem(fsType string) bool {
	switch strings.ToLower(fsType) {
	case "proc", "sysfs", "devpts", "devtmpfs", "tmpfs", "cgroup", "cgroup2",
		"pstore", "securityfs", "debugfs", "tracefs", "configfs", "fusectl",
		"mqueue", "hugetlbfs", "ramfs", "overlay", "overlayfs", "aufs", "squashfs",
		"rootfs", "autofs", "rpc_pipefs", "nsfs":
		return true
	default:
		return false
	}
}

// isPhysicalOrNFSFilesystem limits the console to storage users can reason
// about. Container overlay layers and other virtual mounts can be numerous and
// do not represent independently usable disks, while NFS devices intentionally
// do not use a /dev path and must be retained.
func isPhysicalOrNFSFilesystem(device, fsType string) bool {
	fsType = strings.ToLower(strings.TrimSpace(fsType))
	if fsType == "nfs" || fsType == "nfs4" {
		return true
	}
	if isPseudoFilesystem(fsType) || strings.HasPrefix(fsType, "fuse") {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(device), "/dev/")
}

func parseCPUStat(data []byte) (cpuCounters, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var values []uint64
		for _, value := range fields[1:] {
			number, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return cpuCounters{}, fmt.Errorf("invalid CPU counter %q: %w", value, err)
			}
			values = append(values, number)
		}
		var total, idle, iowait uint64
		for index, value := range values {
			// guest and guest_nice are already included in user and nice.
			if index <= 7 {
				total += value
			}
		}
		idle = values[3]
		if len(values) > 4 {
			iowait = values[4]
			idle += iowait
		}
		user := values[0]
		if len(values) > 1 {
			user += values[1]
		}
		system := uint64(0)
		if len(values) > 2 {
			system = values[2]
		}
		if len(values) > 6 {
			system += values[5] + values[6]
		}
		steal := uint64(0)
		if len(values) > 7 {
			steal = values[7]
		}
		return cpuCounters{total: total, idle: idle, iowait: iowait, user: user, system: system, steal: steal, cores: countCPUCores(data)}, nil
	}
	return cpuCounters{}, fmt.Errorf("aggregate CPU counter is missing")
}

func countCPUCores(data []byte) int {
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "processor") && strings.Contains(line, ":") {
			count++
		}
	}
	if count == 0 {
		return runtime.NumCPU()
	}
	return count
}

func parseMeminfo(data []byte) map[string]uint64 {
	result := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		multiplier := uint64(1)
		if len(fields) > 1 {
			switch strings.ToLower(fields[1]) {
			case "kb":
				multiplier = 1024
			case "mb":
				multiplier = 1024 * 1024
			case "gb":
				multiplier = 1024 * 1024 * 1024
			}
		}
		result[strings.TrimSpace(parts[0])] = value * multiplier
	}
	return result
}

func parseNetworkDev(data []byte) []parsedNetworkInterface {
	result := make([]parsedNetworkInterface, 0)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || !strings.Contains(line, ":") {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "" || name == "Inter-| face" || strings.HasPrefix(name, "face") {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}
		values := make([]uint64, 12)
		valid := true
		for index := 0; index < len(fields) && index < len(values); index++ {
			parsed, err := strconv.ParseUint(fields[index], 10, 64)
			if err != nil {
				valid = false
				break
			}
			values[index] = parsed
		}
		if valid {
			result = append(result, parsedNetworkInterface{name: name, counters: networkCounters{
				rxBytes: values[0], rxPackets: values[1], rxErrors: values[2], rxDropped: values[3],
				txBytes: values[8], txPackets: values[9], txErrors: values[10], txDropped: values[11],
			}})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result
}

func counterDelta(previous, current uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

func parseFloat(value string) float64 {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func parseUintOrZero(value string) uint64 {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func swapUsed(total, free uint64) uint64 {
	if total < free {
		return 0
	}
	return total - free
}

func percentOf(value, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(value) / float64(total) * 100
}

func minFloat(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}
