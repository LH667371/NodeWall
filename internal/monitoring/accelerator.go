package monitoring

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
)

const (
	acceleratorCommandTimeout = 8 * time.Second
	acceleratorProbeBudget    = 12 * time.Second
)

// autoAcceleratorCollector combines optional vendor tooling with the generic
// DRM sysfs counters exposed by Linux. GPU support stays best-effort so a
// missing driver cannot make the agent's main metrics endpoint fail.
type autoAcceleratorCollector struct {
	providers []AcceleratorCollector
	sysfs     *drmAcceleratorCollector
	mu        sync.Mutex
	fetchedAt time.Time
	last      []models.AcceleratorMetrics
	lastError error
	inFlight  bool
	deadline  time.Time

	// PCI identity is cached separately from queries that enter GPU drivers.
	inventory          []models.AcceleratorMetrics
	inventoryFetchedAt time.Time
	inventoryInFlight  bool
}

// Vendor CLIs may initialize a driver on every invocation. Share a short
// cache across metric reads so extra Webs do not multiply that work.
const acceleratorSampleInterval = 10 * time.Second

func newAutoAcceleratorCollector() AcceleratorCollector {
	lspci := lookupAcceleratorCommand("lspci")
	collector := &autoAcceleratorCollector{sysfs: &drmAcceleratorCollector{root: "/sys", lspci: lspci}}
	// Several domestic accelerator tools intentionally expose an SMI-like CSV
	// query. Discover only installed binaries so a normal host pays no command
	// execution cost and unsupported vendors remain harmless.
	providers := []struct {
		name    string
		vendor  string
		backend string
		args    []string
	}{
		{name: "nvidia-smi", vendor: "NVIDIA", backend: "nvidia-smi"},
		{name: "mthreads-gmi", vendor: "Moore Threads", backend: "mthreads-gmi"},
		{name: "ixsmi", vendor: "Iluvatar", backend: "ixsmi"},
		{name: "hy-smi", vendor: "Hygon", backend: "hy-smi"},
		{name: "efsmi", vendor: "Enflame", backend: "efsmi"},
		{name: "brsmi", vendor: "Biren", backend: "brsmi"},
		{name: "cambricon-smi", vendor: "Cambricon", backend: "cambricon-smi"},
		{name: "cnmon", vendor: "Cambricon", backend: "cnmon"},
		{name: "metax-smi", vendor: "MetaX", backend: "metax-smi"},
	}
	for _, candidate := range providers {
		command := lookupAcceleratorCommand(candidate.name)
		if command == "" {
			continue
		}
		collector.providers = append(collector.providers, &smiQueryCollector{
			command: command,
			vendor:  candidate.vendor,
			backend: candidate.backend,
			args:    candidate.args,
		})
	}
	if command := lookupAcceleratorCommand("rocm-smi"); command != "" {
		collector.providers = append(collector.providers, &rocmSMICollector{command: command})
	}
	for _, commandName := range []string{"npu-smi", "ascend-smi"} {
		if command := lookupAcceleratorCommand(commandName); command != "" {
			collector.providers = append(collector.providers, &npuSMICollector{command: command})
		}
	}
	return collector
}

func lookupAcceleratorCommand(name string) string {
	if command, err := exec.LookPath(name); err == nil {
		return command
	}
	// systemd's PATH does not inherit an administrator's CUDA/ROCm profile.
	for _, directory := range []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/nvidia/bin", "/usr/local/cuda/bin", "/opt/rocm/bin", "/usr/local/Ascend/driver/tools"} {
		path := filepath.Join(directory, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return path
		}
	}
	return ""
}

func (c *autoAcceleratorCollector) Collect(ctx context.Context) ([]models.AcceleratorMetrics, error) {
	if c == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	if c.sysfs != nil && !c.inventoryInFlight && now.Sub(c.inventoryFetchedAt) >= acceleratorSampleInterval {
		c.inventoryInFlight = true
		go c.refreshInventory()
	}
	if !c.inFlight && now.Sub(c.fetchedAt) >= acceleratorSampleInterval {
		c.inFlight = true
		c.deadline = now.Add(acceleratorProbeBudget)
		// Real A30 hosts can take 4–6 seconds to initialize nvidia-smi. GPU
		// collection must outlive an HTTP request without holding the main
		// CPU/network collector lock or spawning a second vendor process.
		go c.refresh(c.deadline)
	}
	// A process blocked in an uninterruptible driver syscall can outlive
	// SIGKILL. Keep its slot occupied, but stop serving its stale readings.
	if c.inFlight && !now.Before(c.deadline) {
		return append([]models.AcceleratorMetrics(nil), c.inventory...), nil
	}
	if len(c.last) == 0 && len(c.inventory) > 0 {
		return append([]models.AcceleratorMetrics(nil), c.inventory...), nil
	}
	return append([]models.AcceleratorMetrics(nil), c.last...), c.lastError
}

func (c *autoAcceleratorCollector) refreshInventory() {
	inventory := c.sysfs.collectPCI()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inventory = inventory
	c.inventoryFetchedAt = time.Now()
	c.inventoryInFlight = false
}

func (c *autoAcceleratorCollector) refresh(deadline time.Time) {
	// This is a budget for all adapters, not a fresh timeout per command.
	probeCtx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	metrics := make([]models.AcceleratorMetrics, 0)
	var failures []error
	for _, provider := range c.providers {
		detected, err := provider.Collect(probeCtx)
		metrics = mergeAcceleratorSources(metrics, detected)
		if err != nil {
			failures = append(failures, err)
		}
	}
	if c.sysfs != nil {
		sysfsMetrics, _ := c.sysfs.collectDRM(probeCtx)
		metrics = mergeAcceleratorSources(metrics, sysfsMetrics)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight = false
	c.fetchedAt = time.Now()
	if len(metrics) == 0 && len(failures) > 0 {
		c.last, c.lastError = nil, errors.Join(failures...)
		return
	}
	if len(metrics) > 0 {
		metrics = mergeAcceleratorSources(metrics, c.inventory)
	}
	c.last = deduplicateAccelerators(metrics)
	c.lastError = nil
}

func acceleratorCommandOutput(ctx context.Context, command string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	// Vendor wrappers can leave a helper holding stdout after cancellation.
	cmd.WaitDelay = 250 * time.Millisecond
	return cmd.Output()
}

// nvidiaSMICollector queries only fixed arguments. It never invokes a shell,
// and the timeout keeps a wedged driver from delaying system metrics.
type nvidiaSMICollector struct {
	command string
}

func (c *nvidiaSMICollector) Collect(ctx context.Context) ([]models.AcceleratorMetrics, error) {
	if c == nil || strings.TrimSpace(c.command) == "" {
		return nil, errors.New("nvidia-smi is unavailable")
	}
	commandCtx, cancel := context.WithTimeout(ctx, acceleratorCommandTimeout)
	defer cancel()
	output, err := acceleratorCommandOutput(commandCtx, c.command,
		"--query-gpu=index,name,memory.total,memory.used,utilization.gpu,temperature.gpu",
		"--format=csv,noheader,nounits",
	)
	if err != nil {
		return nil, fmt.Errorf("nvidia-smi: %w", err)
	}
	return parseNvidiaSMI(output)
}

func parseNvidiaSMI(data []byte) ([]models.AcceleratorMetrics, error) {
	return parseSMIQuery(data, "NVIDIA", "nvidia-smi")
}

type smiQueryCollector struct {
	command string
	vendor  string
	backend string
	args    []string
	query   int
}

func (c *smiQueryCollector) Collect(ctx context.Context) ([]models.AcceleratorMetrics, error) {
	if c == nil || strings.TrimSpace(c.command) == "" {
		return nil, errors.New("accelerator SMI command is unavailable")
	}
	commandCtx, cancel := context.WithTimeout(ctx, acceleratorCommandTimeout)
	defer cancel()
	queries := []string{
		"index,name,memory.total,memory.used,utilization.gpu,temperature.gpu,power.draw,power.limit,fan.speed,clocks.current.graphics,clocks.current.memory,driver_version,pci.bus_id",
		"index,name,memory.total,memory.used,utilization.gpu,temperature.gpu",
		"index,name,memory.total,memory.used",
	}
	var lastErr error
	for index := c.query; index < len(queries); index++ {
		args := append([]string{"--query-gpu=" + queries[index], "--format=csv,noheader,nounits"}, c.args...)
		output, err := acceleratorCommandOutput(commandCtx, c.command, args...)
		if err == nil {
			var metrics []models.AcceleratorMetrics
			metrics, err = parseSMIQuery(output, c.vendor, c.backend)
			if err == nil && len(metrics) > 0 {
				// Remember the supported query rather than failing the extended
				// one again on each sample of an older or virtual GPU driver.
				c.query = index
				return metrics, nil
			}
		}
		lastErr = err
		if commandCtx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", c.backend, commandCtx.Err())
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no supported GPU query returned device data")
	}
	return nil, fmt.Errorf("%s: %w", c.backend, lastErr)
}

func parseSMIQuery(data []byte, vendor, backend string) ([]models.AcceleratorMetrics, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	metrics := make([]models.AcceleratorMetrics, 0)
	for line := 1; ; line++ {
		fields, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse accelerator SMI row %d: %w", line, err)
		}
		if len(fields) < 2 {
			continue
		}
		index, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil || index < 0 {
			continue
		}
		metric := models.AcceleratorMetrics{
			Vendor:  vendor,
			Index:   index,
			Name:    strings.TrimSpace(fields[1]),
			Backend: backend,
		}
		if metric.Name == "" {
			metric.Name = fmt.Sprintf("GPU %d", index)
		}
		// N/A is not zero: omit unsupported sensors, but retain a real idle
		// 0% in Metrics even when the scalar's JSON omitempty removes it.
		for index, definition := range []struct{ key, unit, label, capability string }{
			{"memory_total_bytes", "bytes", "Memory total", "memory"},
			{"memory_used_bytes", "bytes", "Memory used", "memory"},
			{"utilization_percent", "%", "Utilization", "utilization"},
			{"temperature_c", "°C", "Temperature", "temperature"},
		} {
			if index+2 >= len(fields) {
				break
			}
			value, err := strconv.ParseFloat(strings.TrimSpace(fields[index+2]), 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
				continue
			}
			if index < 2 {
				value *= 1024 * 1024
			}
			switch index {
			case 0:
				metric.MemoryTotalBytes = uint64(value)
			case 1:
				metric.MemoryUsedBytes = uint64(value)
			case 2:
				value = clampPercent(value)
				metric.UtilizationPercent = value
			case 3:
				metric.TemperatureC = value
			}
			if metric.Metrics == nil {
				metric.Metrics = make(map[string]models.AcceleratorMetric)
			}
			metric.Metrics[definition.key] = models.AcceleratorMetric{Value: value, Unit: definition.unit, Label: definition.label}
			metric.Capabilities = appendUniqueStrings(metric.Capabilities, definition.capability)
		}
		if len(fields) > 6 {
			metric.PowerWatts = parseAcceleratorFloatOrZero(fields[6])
			setAcceleratorMetric(&metric, "power_watts", metric.PowerWatts, "W", "Power")
		}
		if len(fields) > 7 {
			metric.PowerLimitWatts = parseAcceleratorFloatOrZero(fields[7])
			setAcceleratorMetric(&metric, "power_limit_watts", metric.PowerLimitWatts, "W", "Power limit")
		}
		if len(fields) > 8 {
			metric.FanPercent = clampPercent(parseAcceleratorFloatOrZero(fields[8]))
			setAcceleratorMetric(&metric, "fan_percent", metric.FanPercent, "%", "Fan")
		}
		if len(fields) > 9 {
			metric.ClockMHz = parseAcceleratorFloatOrZero(fields[9])
			setAcceleratorMetric(&metric, "clock_mhz", metric.ClockMHz, "MHz", "Clock")
		}
		if len(fields) > 10 {
			metric.MemoryClockMHz = parseAcceleratorFloatOrZero(fields[10])
			setAcceleratorMetric(&metric, "memory_clock_mhz", metric.MemoryClockMHz, "MHz", "Memory clock")
		}
		if len(fields) > 11 {
			metric.Driver = strings.TrimSpace(fields[11])
		}
		if len(fields) > 12 {
			metric.BusID = normalizedPCIBusID(fields[12])
		}
		if metric.PowerWatts > 0 {
			metric.Capabilities = append(metric.Capabilities, "power")
		}
		if metric.ClockMHz > 0 || metric.MemoryClockMHz > 0 {
			metric.Capabilities = append(metric.Capabilities, "clock")
		}
		metrics = append(metrics, metric)
	}
	return metrics, nil
}

type rocmSMICollector struct {
	command string
}

func (c *rocmSMICollector) Collect(ctx context.Context) ([]models.AcceleratorMetrics, error) {
	if c == nil || strings.TrimSpace(c.command) == "" {
		return nil, errors.New("rocm-smi is unavailable")
	}
	commandCtx, cancel := context.WithTimeout(ctx, acceleratorCommandTimeout)
	defer cancel()
	output, err := acceleratorCommandOutput(commandCtx, c.command,
		"--showproductname", "--showmeminfo", "vram", "--showuse", "--showtemp", "--json",
	)
	if err != nil {
		return nil, fmt.Errorf("rocm-smi: %w", err)
	}
	return parseROCMSMI(output)
}

func parseROCMSMI(data []byte) ([]models.AcceleratorMetrics, error) {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse rocm-smi JSON: %w", err)
	}
	objects := make([]map[string]any, 0)
	collectROCMObjects(raw, "", &objects)
	metrics := make([]models.AcceleratorMetrics, 0, len(objects))
	for index, object := range objects {
		metric := models.AcceleratorMetrics{
			Vendor:             "AMD",
			Index:              index,
			Backend:            "rocm-smi",
			Name:               firstJSONText(object, "card series", "device name", "product name", "name"),
			MemoryTotalBytes:   firstJSONUint(object, "vram total memory", "memory total", "total memory"),
			MemoryUsedBytes:    firstJSONUint(object, "vram total used memory", "memory used", "used memory"),
			UtilizationPercent: clampPercent(firstJSONFloat(object, "gpu use", "utilization")),
			TemperatureC:       firstJSONFloat(object, "temperature"),
		}
		if metric.Name == "" {
			metric.Name = fmt.Sprintf("AMD GPU %d", index)
		}
		metric.Capabilities = acceleratorCapabilities(metric)
		setAcceleratorMetric(&metric, "utilization_percent", metric.UtilizationPercent, "%", "Utilization")
		setAcceleratorMetric(&metric, "temperature_c", metric.TemperatureC, "°C", "Temperature")
		setAcceleratorMetric(&metric, "memory_used_bytes", float64(metric.MemoryUsedBytes), "bytes", "Memory used")
		setAcceleratorMetric(&metric, "memory_total_bytes", float64(metric.MemoryTotalBytes), "bytes", "Memory total")
		metrics = append(metrics, metric)
	}
	return metrics, nil
}

func collectROCMObjects(value any, hint string, result *[]map[string]any) {
	switch object := value.(type) {
	case map[string]any:
		if strings.Contains(strings.ToLower(hint), "gpu") || strings.Contains(strings.ToLower(hint), "card") || hasJSONKey(object, "gpu use", "vram", "temperature") {
			*result = append(*result, object)
		}
		for key, child := range object {
			collectROCMObjects(child, key, result)
		}
	case []any:
		for _, child := range object {
			collectROCMObjects(child, hint, result)
		}
	}
}

func hasJSONKey(object map[string]any, fragments ...string) bool {
	for key := range object {
		lower := strings.ToLower(key)
		for _, fragment := range fragments {
			if strings.Contains(lower, fragment) {
				return true
			}
		}
	}
	return false
}

func firstJSONText(object map[string]any, fragments ...string) string {
	for key, value := range object {
		lower := strings.ToLower(key)
		for _, fragment := range fragments {
			if strings.Contains(lower, fragment) {
				if text, ok := value.(string); ok {
					return strings.TrimSpace(text)
				}
			}
		}
	}
	return ""
}

func firstJSONFloat(object map[string]any, fragments ...string) float64 {
	for key, value := range object {
		lower := strings.ToLower(key)
		for _, fragment := range fragments {
			if strings.Contains(lower, fragment) {
				return jsonNumber(value)
			}
		}
	}
	return 0
}

func firstJSONUint(object map[string]any, fragments ...string) uint64 {
	value := firstJSONFloat(object, fragments...)
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func jsonNumber(value any) float64 {
	switch number := value.(type) {
	case float64:
		return number
	case json.Number:
		parsed, _ := number.Float64()
		return parsed
	case string:
		return parseAcceleratorScalar(number)
	default:
		return 0
	}
}

type npuSMICollector struct {
	command string
}

func (c *npuSMICollector) Collect(ctx context.Context) ([]models.AcceleratorMetrics, error) {
	if c == nil || strings.TrimSpace(c.command) == "" {
		return nil, errors.New("npu-smi is unavailable")
	}
	commandCtx, cancel := context.WithTimeout(ctx, acceleratorCommandTimeout)
	defer cancel()
	output, err := acceleratorCommandOutput(commandCtx, c.command, "info")
	if err != nil {
		return nil, fmt.Errorf("npu-smi: %w", err)
	}
	return parseNPUInfo(output), nil
}

func parseNPUInfo(data []byte) []models.AcceleratorMetrics {
	lines := strings.Split(string(data), "\n")
	header := []string(nil)
	metrics := make([]models.AcceleratorMetrics, 0)
	for _, line := range lines {
		fields := splitPipeFields(line)
		if len(fields) == 0 {
			continue
		}
		lower := strings.ToLower(strings.Join(fields, " "))
		if strings.Contains(lower, "npu id") || (strings.Contains(lower, "chip") && strings.Contains(lower, "name")) {
			header = fields
			continue
		}
		if len(header) == 0 || len(fields) != len(header) {
			continue
		}
		index, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			continue
		}
		metric := models.AcceleratorMetrics{Vendor: "Huawei Ascend", Index: index, Backend: "npu-smi"}
		metric.Name = firstTableField(fields, header, "name", "chip", "model")
		if metric.Name == "" {
			metric.Name = fmt.Sprintf("Ascend NPU %d", index)
		}
		metric.UtilizationPercent = clampPercent(firstTableNumber(fields, header, "aicore", "util"))
		metric.MemoryUsedBytes, metric.MemoryTotalBytes = parseAcceleratorMemoryPair(firstTableField(fields, header, "hbm-usage", "memory used"))
		if metric.MemoryTotalBytes == 0 {
			metric.MemoryTotalBytes = firstTableBytes(fields, header, "hbm-total", "memory total")
		}
		metric.TemperatureC = firstTableNumber(fields, header, "temperature", "temp")
		metric.Capabilities = acceleratorCapabilities(metric)
		setAcceleratorMetric(&metric, "utilization_percent", metric.UtilizationPercent, "%", "Utilization")
		setAcceleratorMetric(&metric, "memory_used_bytes", float64(metric.MemoryUsedBytes), "bytes", "Memory used")
		setAcceleratorMetric(&metric, "memory_total_bytes", float64(metric.MemoryTotalBytes), "bytes", "Memory total")
		setAcceleratorMetric(&metric, "temperature_c", metric.TemperatureC, "°C", "Temperature")
		metrics = append(metrics, metric)
	}
	return metrics
}

func splitPipeFields(line string) []string {
	if !strings.Contains(line, "|") {
		return nil
	}
	parts := strings.Split(line, "|")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func firstTableField(fields, header []string, fragments ...string) string {
	for index, name := range header {
		lower := strings.ToLower(name)
		for _, fragment := range fragments {
			if strings.Contains(lower, fragment) && index < len(fields) {
				return strings.TrimSpace(fields[index])
			}
		}
	}
	return ""
}

func firstTableNumber(fields, header []string, fragments ...string) float64 {
	return parseAcceleratorFloatOrZero(strings.TrimSpace(firstTableField(fields, header, fragments...)))
}

func firstTableBytes(fields, header []string, fragments ...string) uint64 {
	return uint64(parseAcceleratorBytes(firstTableField(fields, header, fragments...), 1024*1024))
}

func acceleratorCapabilities(metric models.AcceleratorMetrics) []string {
	capabilities := make([]string, 0, 4)
	if metric.UtilizationPercent > 0 {
		capabilities = append(capabilities, "utilization")
	}
	if metric.MemoryTotalBytes > 0 || metric.MemoryUsedBytes > 0 {
		capabilities = append(capabilities, "memory")
	}
	if metric.TemperatureC > 0 {
		capabilities = append(capabilities, "temperature")
	}
	if metric.PowerWatts > 0 {
		capabilities = append(capabilities, "power")
	}
	return capabilities
}

func setAcceleratorMetric(metric *models.AcceleratorMetrics, key string, value float64, unit, label string) {
	if metric == nil || value == 0 {
		return
	}
	if metric.Metrics == nil {
		metric.Metrics = make(map[string]models.AcceleratorMetric)
	}
	metric.Metrics[key] = models.AcceleratorMetric{Value: value, Unit: unit, Label: label}
}

func deduplicateAccelerators(metrics []models.AcceleratorMetrics) []models.AcceleratorMetrics {
	result := make([]models.AcceleratorMetrics, 0, len(metrics))
	seen := make(map[string]bool)
	for _, metric := range metrics {
		key := strings.ToLower(metric.Vendor) + "/" + normalizedPCIBusID(metric.BusID)
		if metric.BusID == "" {
			key = fmt.Sprintf("%s/%d/%s", strings.ToLower(metric.Vendor), metric.Index, strings.ToLower(metric.Name))
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, metric)
	}
	return result
}

func mergeAcceleratorSources(primary, secondary []models.AcceleratorMetrics) []models.AcceleratorMetrics {
	result := append([]models.AcceleratorMetrics(nil), primary...)
	for _, candidate := range secondary {
		matched := false
		for index := range result {
			if !strings.EqualFold(result[index].Vendor, candidate.Vendor) {
				continue
			}
			if result[index].BusID != "" && candidate.BusID != "" {
				if normalizedPCIBusID(result[index].BusID) != normalizedPCIBusID(candidate.BusID) {
					continue
				}
			} else if result[index].Index != candidate.Index {
				continue
			}
			mergeAcceleratorMetric(&result[index], candidate)
			matched = true
			break
		}
		if !matched {
			result = append(result, candidate)
		}
	}
	return result
}

func normalizedPCIBusID(busID string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(busID)), ":")
	if len(parts) == 3 {
		if domain, err := strconv.ParseUint(parts[0], 16, 32); err == nil {
			parts[0] = fmt.Sprintf("%04x", domain)
		}
	}
	return strings.Join(parts, ":")
}

func mergeAcceleratorMetric(target *models.AcceleratorMetrics, source models.AcceleratorMetrics) {
	if target == nil {
		return
	}
	if target.Name == "" || strings.HasPrefix(target.Name, "GPU ") {
		target.Name = source.Name
	}
	if target.VendorID == "" {
		target.VendorID = source.VendorID
	}
	if target.Driver == "" {
		target.Driver = source.Driver
	}
	if target.Backend == "" {
		target.Backend = source.Backend
	}
	if target.BusID == "" {
		target.BusID = source.BusID
	}
	if target.DeviceID == "" {
		target.DeviceID = source.DeviceID
	}
	if target.Architecture == "" {
		target.Architecture = source.Architecture
	}
	if target.MemoryTotalBytes == 0 {
		target.MemoryTotalBytes = source.MemoryTotalBytes
	}
	if target.MemoryUsedBytes == 0 {
		target.MemoryUsedBytes = source.MemoryUsedBytes
	}
	if target.UtilizationPercent == 0 {
		target.UtilizationPercent = source.UtilizationPercent
	}
	if target.TemperatureC == 0 {
		target.TemperatureC = source.TemperatureC
	}
	if target.PowerWatts == 0 {
		target.PowerWatts = source.PowerWatts
	}
	if target.PowerLimitWatts == 0 {
		target.PowerLimitWatts = source.PowerLimitWatts
	}
	if target.FanPercent == 0 {
		target.FanPercent = source.FanPercent
	}
	if target.ClockMHz == 0 {
		target.ClockMHz = source.ClockMHz
	}
	if target.MemoryClockMHz == 0 {
		target.MemoryClockMHz = source.MemoryClockMHz
	}
	if target.ProcessCount == 0 {
		target.ProcessCount = source.ProcessCount
	}
	target.Capabilities = appendUniqueStrings(target.Capabilities, source.Capabilities...)
	if target.Metrics == nil {
		target.Metrics = make(map[string]models.AcceleratorMetric)
	}
	for key, value := range source.Metrics {
		if _, exists := target.Metrics[key]; !exists {
			target.Metrics[key] = value
		}
	}
}

func appendUniqueStrings(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	result := make([]string, 0, len(values)+len(additions))
	for _, value := range append(values, additions...) {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

// drmAcceleratorCollector reads common Linux DRM files for AMD, Intel, and
// other PCI GPUs. Vendors expose different subsets; fields absent on a given
// driver remain zero while the device is still listed for inventory purposes.
type drmAcceleratorCollector struct {
	root  string
	lspci string
}

func (c *drmAcceleratorCollector) collectDRM(ctx context.Context) ([]models.AcceleratorMetrics, error) {
	if c == nil || strings.TrimSpace(c.root) == "" {
		return nil, nil
	}
	paths, err := filepath.Glob(filepath.Join(c.root, "class/drm/card[0-9]*", "device"))
	if err != nil {
		return nil, err
	}
	metrics := make([]models.AcceleratorMetrics, 0, len(paths))
	for _, devicePath := range paths {
		if err := ctx.Err(); err != nil {
			return metrics, err
		}
		vendorID := readTrimmed(filepath.Join(devicePath, "vendor"))
		if vendorID == "" {
			continue
		}
		if isManagementDisplay(strings.ToLower(vendorID), strings.ToLower(readTrimmed(filepath.Join(devicePath, "device")))) {
			continue
		}
		index, ok := drmCardIndex(devicePath)
		if !ok {
			continue
		}
		model := firstNonEmpty(
			readTrimmed(filepath.Join(devicePath, "product_name")),
			readTrimmed(filepath.Join(devicePath, "label")),
			acceleratorModel(vendorID, readTrimmed(filepath.Join(devicePath, "device"))),
		)
		busID := readUEventField(filepath.Join(devicePath, "uevent"), "PCI_SLOT_NAME")
		if c.lspci != "" {
			if detected := lookupPCIModel(ctx, c.lspci, busID); detected != "" {
				model = detected
			}
		}
		metric := models.AcceleratorMetrics{
			Vendor:   vendorName(vendorID),
			VendorID: vendorID,
			Index:    index,
			Name:     model,
			Driver:   readUEventField(filepath.Join(devicePath, "uevent"), "DRIVER"),
			BusID:    busID,
			DeviceID: strings.ToLower(readTrimmed(filepath.Join(devicePath, "device"))),
			Backend:  "drm-sysfs",
		}
		if metric.Name == "" {
			metric.Name = fmt.Sprintf("%s GPU %d", metric.Vendor, index)
		}
		busy := readTrimmed(filepath.Join(devicePath, "gpu_busy_percent"))
		metric.UtilizationPercent = clampPercent(parseAcceleratorFloatOrZero(busy))
		memoryUsed := readTrimmed(filepath.Join(devicePath, "mem_info_vram_used"))
		memoryTotal := readTrimmed(filepath.Join(devicePath, "mem_info_vram_total"))
		metric.MemoryUsedBytes = parseAcceleratorUintOrZero(memoryUsed)
		metric.MemoryTotalBytes = parseAcceleratorUintOrZero(memoryTotal)
		metric.TemperatureC = readDeviceTemperature(devicePath)
		metric.Capabilities = acceleratorCapabilities(metric)
		setAcceleratorMetric(&metric, "utilization_percent", metric.UtilizationPercent, "%", "Utilization")
		setAcceleratorMetric(&metric, "memory_used_bytes", float64(metric.MemoryUsedBytes), "bytes", "Memory used")
		setAcceleratorMetric(&metric, "memory_total_bytes", float64(metric.MemoryTotalBytes), "bytes", "Memory total")
		setAcceleratorMetric(&metric, "temperature_c", metric.TemperatureC, "°C", "Temperature")
		if value, err := strconv.ParseFloat(busy, 64); err == nil && value == 0 {
			metric.Capabilities = appendUniqueStrings(metric.Capabilities, "utilization")
			if metric.Metrics == nil {
				metric.Metrics = make(map[string]models.AcceleratorMetric)
			}
			metric.Metrics["utilization_percent"] = models.AcceleratorMetric{Unit: "%", Label: "Utilization"}
		}
		for key, reading := range map[string]string{"memory_used_bytes": memoryUsed, "memory_total_bytes": memoryTotal} {
			if value, err := strconv.ParseUint(reading, 10, 64); err == nil && value == 0 {
				metric.Capabilities = appendUniqueStrings(metric.Capabilities, "memory")
				if metric.Metrics == nil {
					metric.Metrics = make(map[string]models.AcceleratorMetric)
				}
				metric.Metrics[key] = models.AcceleratorMetric{Unit: "bytes"}
			}
		}
		metrics = append(metrics, metric)
	}
	return metrics, nil
}

func (c *drmAcceleratorCollector) collectPCI() []models.AcceleratorMetrics {
	// NVIDIA compute-only/VFIO devices may have no DRM card at all. Keep their
	// PCI identity visible, without inventing sensor values for a passed-through
	// or unbound device. Read only PCI identity attributes so this also works
	// when a vendor CLI or a driver-backed sensor cannot respond.
	pciPaths, _ := filepath.Glob(filepath.Join(c.root, "bus/pci/devices/*"))
	var metrics []models.AcceleratorMetrics
	vendorIndexes := make(map[string]int)
	for _, path := range pciPaths {
		vendorID := strings.ToLower(readTrimmed(filepath.Join(path, "vendor")))
		deviceID := strings.ToLower(readTrimmed(filepath.Join(path, "device")))
		class := strings.ToLower(readTrimmed(filepath.Join(path, "class")))
		if !strings.HasPrefix(class, "0x03") || isManagementDisplay(vendorID, deviceID) {
			continue
		}
		busID := normalizedPCIBusID(filepath.Base(path))
		index := vendorIndexes[vendorID]
		vendorIndexes[vendorID]++
		driver := readUEventField(filepath.Join(path, "uevent"), "DRIVER")
		if driver == "" {
			if link, err := os.Readlink(filepath.Join(path, "driver")); err == nil {
				driver = filepath.Base(link)
			}
		}
		metrics = append(metrics, models.AcceleratorMetrics{
			Vendor: vendorName(vendorID), VendorID: vendorID, DeviceID: deviceID,
			Index: index, BusID: busID, Driver: driver, Backend: "pci-sysfs",
			Name: acceleratorModel(vendorID, deviceID),
		})
	}
	return metrics
}

func isManagementDisplay(vendorID, deviceID string) bool {
	if vendorID == "0x1a03" || (vendorID == "0x19e5" && deviceID == "0x1711") {
		return true
	}
	if vendorID == "0x102b" {
		switch deviceID {
		case "0x0522", "0x0532", "0x0534", "0x0536", "0x0538":
			return true
		}
	}
	return false
}

func drmCardIndex(devicePath string) (int, bool) {
	cardPath := filepath.Dir(devicePath)
	base := filepath.Base(cardPath)
	if !strings.HasPrefix(base, "card") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(base, "card"))
	return index, err == nil && index >= 0
}

func readDeviceTemperature(devicePath string) float64 {
	hwmonPaths, _ := filepath.Glob(filepath.Join(devicePath, "hwmon", "hwmon*", "temp*_input"))
	for _, path := range hwmonPaths {
		value := parseAcceleratorFloatOrZero(readTrimmed(path))
		if value > 0 {
			return value / 1000
		}
	}
	return 0
}

func vendorName(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0x10de":
		return "NVIDIA"
	case "0x1002", "0x1022":
		return "AMD"
	case "0x8086":
		return "Intel"
	case "0x19e5":
		return "Huawei Ascend"
	case "0x1e3e":
		return "Cambricon"
	case "0x1ed5":
		return "Moore Threads"
	case "0x1d22":
		return "Biren"
	case "0x1d94":
		return "Hygon"
	case "0x1d9b":
		return "Enflame"
	default:
		return strings.TrimSpace(value)
	}
}

func acceleratorModel(vendorID, deviceID string) string {
	vendorID = strings.ToLower(strings.TrimSpace(vendorID))
	deviceID = strings.ToLower(strings.TrimSpace(deviceID))
	known := map[string]string{
		"0x10de/0x20b0": "NVIDIA A100",
		"0x10de/0x20b7": "NVIDIA A30",
		"0x10de/0x1eb8": "NVIDIA Tesla T4",
		"0x1002/0x73bf": "AMD Radeon RX 6800",
		"0x8086/0x56c0": "Intel Data Center GPU Flex",
	}
	if model, ok := known[vendorID+"/"+deviceID]; ok {
		return model
	}
	if vendor := vendorName(vendorID); vendor != "" {
		if deviceID != "" {
			return fmt.Sprintf("%s GPU (%s)", vendor, deviceID)
		}
		return vendor + " GPU"
	}
	return ""
}

func lookupPCIModel(ctx context.Context, command, busID string) string {
	if strings.TrimSpace(command) == "" || strings.TrimSpace(busID) == "" {
		return ""
	}
	commandCtx, cancel := context.WithTimeout(ctx, acceleratorCommandTimeout)
	defer cancel()
	output, err := acceleratorCommandOutput(commandCtx, command, "-Dnn", "-s", busID)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(output))
	if colon := strings.Index(line, ": "); colon >= 0 {
		line = line[colon+2:]
	}
	if bracket := strings.LastIndex(line, " ["); bracket >= 0 {
		line = line[:bracket]
	}
	return strings.TrimSpace(line)
}

func readUEventField(path, field string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	prefix := field + "="
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parseAcceleratorUintOrZero(value string) uint64 {
	value = strings.TrimSpace(strings.TrimSuffix(value, " MiB"))
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func parseAcceleratorFloatOrZero(value string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0
	}
	return parsed
}

func parseAcceleratorScalar(value string) float64 {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return 0
	}
	number := parseAcceleratorFloatOrZero(fields[0])
	if len(fields) < 2 {
		return number
	}
	switch strings.ToLower(strings.Trim(fields[1], "()")) {
	case "kib":
		return number * 1024
	case "mib":
		return number * 1024 * 1024
	case "gib":
		return number * 1024 * 1024 * 1024
	case "tib":
		return number * 1024 * 1024 * 1024 * 1024
	case "kb":
		return number * 1000
	case "mb":
		return number * 1000 * 1000
	case "gb":
		return number * 1000 * 1000 * 1000
	case "tb":
		return number * 1000 * 1000 * 1000 * 1000
	default:
		return number
	}
}

func parseAcceleratorBytes(value string, defaultMultiplier float64) float64 {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		parts := strings.SplitN(value, "/", 2)
		unitFields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(unitFields) > 1 {
			return parseAcceleratorScalar(strings.TrimSpace(parts[0]) + " " + unitFields[1])
		}
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	if len(fields) == 1 {
		return parseAcceleratorFloatOrZero(fields[0]) * defaultMultiplier
	}
	return parseAcceleratorScalar(value)
}

func parseAcceleratorMemoryPair(value string) (used, total uint64) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "/") {
		return uint64(parseAcceleratorBytes(value, 1024*1024)), 0
	}
	parts := strings.SplitN(value, "/", 2)
	unit := ""
	fields := strings.Fields(strings.TrimSpace(parts[1]))
	if len(fields) > 1 {
		unit = fields[1]
	}
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(fields[0])
	if unit != "" {
		left += " " + unit
		right += " " + unit
	}
	return uint64(parseAcceleratorBytes(left, 1024*1024)), uint64(parseAcceleratorBytes(right, 1024*1024))
}

func mibToBytes(value uint64) uint64 {
	return value * 1024 * 1024
}

func clampPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
