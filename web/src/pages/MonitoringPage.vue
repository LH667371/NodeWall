<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { BarChart3, Cpu, HardDrive, ListTree, Network, ScrollText, Search } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import InfoTip from "@/components/InfoTip.vue";
import InlineSelect from "@/components/InlineSelect.vue";
import MonitoringChart from "@/components/MonitoringChart.vue";
import MonitoringHistory from "@/components/MonitoringHistory.vue";
import { acceleratorReading, buildDeviceChart, cpuCoreGroups, lastMonitoringHour, monitoringNodeCatalog, numericMetric } from "@/lib/monitoringSeries";
import TablePagination from "@/components/TablePagination.vue";
import { formatDateTime, formatDateTimeLocalValue, formatTime as formatClockTime, timeState, timeZoneOptions, zonedDateTimeToDate } from "@/lib/time";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();
const defaultRangeSeconds = 15 * 60;
const defaultRetentionSeconds = 7 * 24 * 60 * 60;
const scope = ref("cluster");
const selectedNodeId = ref("");
const rangeSeconds = ref(defaultRangeSeconds);
const appliedRange = ref({ range: defaultRangeSeconds });
const activeView = ref("overview");
const dateFields = reactive({ start: "", end: "" });
const dateError = ref("");
const emptyHistory = { points: [], nodes: [], range_seconds: defaultRangeSeconds };
const data = computed(() => props.store.state.monitoringHistory || emptyHistory);
const historyError = computed(() => props.store.state.monitoringHistoryError);
const loading = computed(() => !historyError.value && !props.store.state.monitoringHistory);
const nodePage = ref(0);
const nodePageSize = ref(10);
const processPage = ref(0);
const processPageSize = ref(10);
const filesystemPage = ref(0);
const filesystemPageSize = ref(10);
const diskPage = ref(0);
const diskPageSize = ref(10);
const networkInterfacePage = ref(0);
const networkInterfacePageSize = ref(10);
const acceleratorPage = ref(0);
const acceleratorPageSize = ref(10);
const cpuDetail = ref("total");
const cpuCorePage = ref(0);

const activeNodeId = computed(() => scope.value === "node" ? selectedNodeId.value : "");
const showDateFields = computed(() => rangeSeconds.value === -1);
const dateTimeZone = computed(() => {
  const zone = timeZoneOptions.find((item) => item.value === timeState.timeZone);
  return zone ? t(zone.labelKey) : timeState.timeZone;
});
const points = computed(() => (Array.isArray(data.value.points) ? data.value.points : []));
const nodes = computed(() => {
  const snapshotNodes = Array.isArray(data.value.nodes) ? data.value.nodes : [];
  if (snapshotNodes.length || scope.value === "node") return snapshotNodes;
  // The monitoring stream can briefly contain only the aggregate while the
  // node snapshot is being rebuilt. Keep the selector populated from the
  // authoritative node list instead of making other nodes disappear.
  return (props.store.state.nodes || []).map((item) => ({
    node_id: item.id,
    name: item.name,
    status: item.status,
  }));
});
const nodePoints = computed(() => data.value.node_points || {});
const chartInterval = computed(() => Number(data.value.sample_interval_seconds) || 5);
const lastUpdatedAt = computed(() => !activeNodeId.value && Date.parse(data.value.sampled_at) > 0
  ? data.value.sampled_at : points.value.at(-1)?.timestamp);
const latest = computed(() => points.value[points.value.length - 1] || {});
const sampleLabel = computed(() => t("monitoringSamples", { count: points.value.length }));

const rangeOptions = computed(() => [
  { value: 5 * 60, label: t("monitoringRange5m") },
  { value: 15 * 60, label: t("monitoringRange15m") },
  { value: 30 * 60, label: t("monitoringRange30m") },
  { value: 60 * 60, label: t("monitoringRange1h") },
  { value: 3 * 60 * 60, label: t("monitoringRange3h") },
  { value: 6 * 60 * 60, label: t("monitoringRange6h") },
  { value: 12 * 60 * 60, label: t("monitoringRange12h") },
  { value: 24 * 60 * 60, label: t("monitoringRange1d") },
  { value: 3 * 24 * 60 * 60, label: t("monitoringRange3d") },
  { value: 7 * 24 * 60 * 60, label: t("monitoringRange7d") },
  { value: -1, label: t("monitoringRangeCustom") },
]);
const nodeCatalog = computed(() => {
  const registered = props.store.state.nodesLoaded ? props.store.state.nodes : nodes.value;
  return monitoringNodeCatalog(registered || [], props.store.state.monitoringArchiveNodes || []);
});
const nodeOptions = computed(() => nodeCatalog.value.map((item) => ({
  value: item.node_id,
  label: item.registered ? item.name : t("monitoringArchivedNode", { name: item.name }),
})));
const archiveNode = computed(() => nodeCatalog.value.find((item) => item.node_id === activeNodeId.value && item.last_sample_at));
const archiveHost = computed(() => nodeCatalog.value.find((item) => item.node_id === data.value.archive_node_id)?.name || data.value.archive_node_id);
const replayWindow = computed(() => lastMonitoringHour(archiveNode.value?.last_sample_at, Number(data.value.retention_seconds) || defaultRetentionSeconds));
const archiveIsStale = computed(() => Date.now() - Date.parse(archiveNode.value?.last_sample_at) > 45_000);
const nodeChartEntries = computed(() => {
  const ids = new Set([
    ...nodes.value.map((item) => item.node_id).filter(Boolean),
    ...Object.keys(nodePoints.value),
  ]);
  return [...ids].map((nodeID, index) => {
    const node = nodes.value.find((item) => item.node_id === nodeID);
    return {
      nodeID,
      label: nodeName(node || { node_id: nodeID }),
      color: ["#1db7ae", "#4a9fe8", "#ff9e52", "#8b79e8", "#e66e83", "#75b798", "#d86ec3", "#3b92dd"][index % 8],
      key: `node_${index}`,
    };
  });
});
const hasNodeChartData = computed(() => (
  nodeChartEntries.value.length > 1
  && nodeChartEntries.value.some((entry) => Array.isArray(nodePoints.value[entry.nodeID]) && nodePoints.value[entry.nodeID].length > 0)
));
const nodeFilterOptions = computed(() => [
  { value: "cluster", label: t("monitoringCluster") },
  ...nodeOptions.value,
]);
const nodeFilter = computed({
  get: () => (scope.value === "node" && selectedNodeId.value ? selectedNodeId.value : "cluster"),
  set: (value) => changeNodeFilter(value),
});
const viewOptions = computed(() => [
  { value: "overview", label: t("monitoringTabOverview") },
  { value: "resources", label: t("monitoringTabResource") },
  { value: "io", label: t("monitoringTabIO") },
  { value: "system", label: t("monitoringTabSystem") },
  { value: "processes", label: t("monitoringTabProcess") },
  { value: "history", label: t("monitoringHistory") },
]);
const monitoringViewIcons = {
  overview: BarChart3,
  resources: Cpu,
  io: Network,
  system: HardDrive,
  processes: ListTree,
  history: ScrollText,
};

const cpuSeries = computed(() => [{ key: "cpu_percent", label: t("monitoringCPUUsage"), color: "#1db7ae" }]);
const memorySeries = computed(() => [{ key: "memory_percent", label: t("monitoringMemoryUsage"), color: "#ff9e52" }]);
const networkSeries = computed(() => [
  { key: "rx_bytes_per_second", label: t("monitoringNetworkInShort"), color: "#4a9fe8" },
  { key: "tx_bytes_per_second", label: t("monitoringNetworkOutShort"), color: "#8b79e8" },
]);
const diskSeries = computed(() => [
  { key: "disk_read_bytes_per_second", label: t("monitoringDiskRead"), color: "#ef8f55" },
  { key: "disk_write_bytes_per_second", label: t("monitoringDiskWrite"), color: "#d86ec3" },
]);
const cpuIowaitSeries = computed(() => [{ key: "cpu_iowait_percent", label: t("monitoringCPUIowait"), color: "#e66e83" }]);
const loadSeries = computed(() => [
  { key: "load_1", label: t("monitoringLoad1"), color: "#3b92dd" },
  { key: "load_5", label: t("monitoringLoad5"), color: "#1db7ae" },
  { key: "load_15", label: t("monitoringLoad15"), color: "#f0ad4e" },
]);
const diskIOPSSeries = computed(() => [
  { key: "disk_read_ops_per_second", label: t("monitoringDiskReadOps"), color: "#ef8f55" },
  { key: "disk_write_ops_per_second", label: t("monitoringDiskWriteOps"), color: "#d86ec3" },
]);
const processSeries = computed(() => [
  { key: "processes_total", label: t("monitoringProcessTotal"), color: "#3b92dd" },
  { key: "processes_running", label: t("monitoringProcessRunning"), color: "#1db7ae" },
  { key: "processes_blocked", label: t("monitoringProcessBlocked"), color: "#e66e83" },
]);
const kernelSeries = computed(() => [
  { key: "context_switches_per_second", label: t("monitoringContextSwitch"), color: "#8b79e8" },
  { key: "interrupts_per_second", label: t("monitoringInterrupts"), color: "#f0ad4e" },
  { key: "forks_per_second", label: t("monitoringForks"), color: "#3b92dd" },
]);
const cpuModeSeries = computed(() => [
  { key: "cpu_user_percent", label: t("monitoringCPUUser"), color: "#3b92dd" },
  { key: "cpu_system_percent", label: t("monitoringCPUSystem"), color: "#1db7ae" },
  { key: "cpu_iowait_percent", label: t("monitoringCPUIowait"), color: "#f0ad4e" },
  { key: "cpu_steal_percent", label: t("monitoringCPUSteal"), color: "#e66e83" },
]);
const memoryCapacitySeries = computed(() => [
  { key: "memory_used_bytes", label: t("monitoringMemoryUsed"), color: "#ff9e52" },
  { key: "memory_available_bytes", label: t("monitoringMemoryAvailable"), color: "#75b798" },
  { key: "swap_used_bytes", label: t("monitoringSwapUsed"), color: "#8b79e8" },
]);
const networkPacketSeries = computed(() => [
  { key: "rx_packets_per_second", label: t("monitoringPacketIn"), color: "#4a9fe8" },
  { key: "tx_packets_per_second", label: t("monitoringPacketOut"), color: "#8b79e8" },
]);
const networkQualitySeries = computed(() => [
  { key: "rx_errors_per_second", label: t("monitoringNetworkErrorsIn"), color: "#e66e83" },
  { key: "tx_errors_per_second", label: t("monitoringNetworkErrorsOut"), color: "#f0ad4e" },
  { key: "rx_dropped_per_second", label: t("monitoringNetworkDroppedIn"), color: "#8b79e8" },
  { key: "tx_dropped_per_second", label: t("monitoringNetworkDroppedOut"), color: "#3b92dd" },
]);
const diskHealthSeries = computed(() => [{ key: "disk_io_utilization_percent", label: t("monitoringDiskUtilization"), color: "#1db7ae" }]);
const diskLatencySeries = computed(() => [
  { key: "disk_read_await_milliseconds", label: t("monitoringDiskReadAwait"), color: "#ef8f55" },
  { key: "disk_write_await_milliseconds", label: t("monitoringDiskWriteAwait"), color: "#d86ec3" },
]);
const filesystemSeries = computed(() => [{ key: "filesystem_used_percent", label: t("monitoringFilesystemUsage"), color: "#75b798" }]);
const socketSeries = computed(() => [
  { key: "tcp_in_use", label: t("monitoringTCPInUse"), color: "#3b92dd" },
  { key: "tcp_time_wait", label: t("monitoringTCPTimeWait"), color: "#f0ad4e" },
  { key: "udp_in_use", label: t("monitoringUDPInUse"), color: "#1db7ae" },
]);
const fileDescriptorSeries = computed(() => [
  { key: "file_descriptors_allocated", label: t("monitoringFDAllocated"), color: "#8b79e8" },
]);
const fileDescriptorUsageSeries = computed(() => [{ key: "file_descriptors_used_percent", label: t("monitoringFDUsedPercent"), color: "#e66e83" }]);
const activeNode = computed(() => (scope.value === "node" ? nodes.value.find((item) => item.node_id === selectedNodeId.value) : null));
const nodeResourceRows = computed(() => nodes.value.map((node) => ({
  ...node,
  cpu_percent: Number(node.cpu_percent || 0),
  memory_percent: Number(node.memory_percent || 0),
  rx_bytes_per_second: Number(node.rx_bytes_per_second || 0),
  tx_bytes_per_second: Number(node.tx_bytes_per_second || 0),
  uptime_seconds: Number(node.uptime_seconds || 0),
  cpu_cores: Number(node.cpu_cores || 0),
  filesystem_used_percent: filesystemUsagePercent(node),
  disk_read_bytes_per_second: Number(node.disk?.read_bytes_per_second || 0),
  disk_write_bytes_per_second: Number(node.disk?.write_bytes_per_second || 0),
  process_total: Number(node.processes?.total || 0),
  process_running: Number(node.processes?.running || 0),
  process_blocked: Number(node.processes?.blocked || 0),
})));
const topProcesses = computed(() => {
  const source = scope.value === "node"
    ? (activeNode.value ? [activeNode.value] : [])
    : nodes.value;
  return source.flatMap((node) => (
    Array.isArray(node.processes?.top)
      ? node.processes.top.map((item) => ({
        ...item,
        node_id: node.node_id,
        node_name: nodeName(node),
      }))
      : []
  )).sort((left, right) => (
    Number(right.cpu_percent || 0) - Number(left.cpu_percent || 0)
    || Number(right.memory_bytes || 0) - Number(left.memory_bytes || 0)
  ));
});
const filesystems = computed(() => {
  const source = scope.value === "node"
    ? (activeNode.value ? [activeNode.value] : [])
    : nodes.value;
  return source.flatMap((node) => (
    Array.isArray(node.filesystems)
      ? node.filesystems.map((item) => ({
        ...item,
        node_id: node.node_id,
        node_name: nodeName(node),
      }))
      : []
  ));
});
const diskDevices = computed(() => {
  const source = scope.value === "node"
    ? (activeNode.value ? [activeNode.value] : [])
    : nodes.value;
  return source.flatMap((node) => (
    Array.isArray(node.disk?.devices)
      ? node.disk.devices.map((item) => ({
        ...item,
        node_id: node.node_id,
        node_name: nodeName(node),
      }))
      : []
  )).sort((left, right) => `${left.node_name}-${left.name}`.localeCompare(`${right.node_name}-${right.name}`));
});
const networkInterfaces = computed(() => {
  const source = scope.value === "node"
    ? (activeNode.value ? [activeNode.value] : [])
    : nodes.value;
  return source.flatMap((node) => (
    Array.isArray(node.network_interfaces)
      ? node.network_interfaces.map((item) => ({
        ...item,
        node_id: node.node_id,
        node_name: nodeName(node),
      }))
      : []
  )).sort((left, right) => `${left.node_name}-${left.name}`.localeCompare(`${right.node_name}-${right.name}`));
});
const accelerators = computed(() => {
  const source = scope.value === "node"
    ? (activeNode.value ? [activeNode.value] : [])
    : nodes.value;
  return source.flatMap((node) => (
    Array.isArray(node.accelerators)
      ? node.accelerators.map((item) => ({
        ...item,
        node_id: node.node_id,
        node_name: nodeName(node),
      }))
      : []
  )).sort((left, right) => `${left.node_name}-${left.vendor}-${left.index}`.localeCompare(`${right.node_name}-${right.vendor}-${right.index}`));
});
const visibleNodeResourceRows = computed(() => nodeResourceRows.value.slice(nodePage.value * nodePageSize.value, (nodePage.value + 1) * nodePageSize.value));
const visibleTopProcesses = computed(() => topProcesses.value.slice(processPage.value * processPageSize.value, (processPage.value + 1) * processPageSize.value));
const visibleFilesystems = computed(() => filesystems.value.slice(filesystemPage.value * filesystemPageSize.value, (filesystemPage.value + 1) * filesystemPageSize.value));
const visibleDiskDevices = computed(() => diskDevices.value.slice(diskPage.value * diskPageSize.value, (diskPage.value + 1) * diskPageSize.value));
const visibleNetworkInterfaces = computed(() => networkInterfaces.value.slice(networkInterfacePage.value * networkInterfacePageSize.value, (networkInterfacePage.value + 1) * networkInterfacePageSize.value));
const visibleAccelerators = computed(() => accelerators.value.slice(acceleratorPage.value * acceleratorPageSize.value, (acceleratorPage.value + 1) * acceleratorPageSize.value));
const acceleratorOptionalColumns = [
  { key: "power_watts", label: "monitoringAcceleratorPower", unit: "W" },
  { key: "fan_percent", label: "monitoringAcceleratorFan", unit: "%" },
  { key: "clock_mhz", label: "monitoringAcceleratorClock", unit: "MHz" },
  { key: "memory_clock_mhz", label: "monitoringAcceleratorMemoryClock", unit: "MHz" },
  { key: "process_count", label: "monitoringAcceleratorProcesses", unit: "" },
];
const acceleratorMetricColumns = computed(() => acceleratorOptionalColumns.filter((column) => (
  accelerators.value.some((item) => acceleratorHasMetric(item, column.key))
)));
const acceleratorHasBackend = computed(() => accelerators.value.some((item) => item.backend || item.driver));
const acceleratorHasExtraMetrics = computed(() => accelerators.value.some((item) => acceleratorExtraMetrics(item).length));
const acceleratorTableColumnCount = computed(() => (
  5
  + (scope.value === "cluster" ? 1 : 0)
  + (acceleratorHasBackend.value ? 1 : 0)
  + acceleratorMetricColumns.value.length
  + (acceleratorHasExtraMetrics.value ? 1 : 0)
));

function buildNodeChart(metricKey) {
  const entries = nodeChartEntries.value;
  // Agents do not sample at exactly the same millisecond. Align points to
  // the server's sampling bucket before joining node series; otherwise a
  // harmless scheduling offset turns every other value into a null gap and
  // makes the multi-node chart look intermittently disconnected.
  const intervalMs = chartInterval.value * 1000;
  const bucketTimestamp = (value) => Math.round(value / intervalMs) * intervalMs;
  const timestampSet = new Set();
  const pointMaps = new Map();
  entries.forEach((entry) => {
    const map = new Map();
    for (const point of Array.isArray(nodePoints.value[entry.nodeID]) ? nodePoints.value[entry.nodeID] : []) {
      const timestamp = new Date(point?.timestamp || 0).getTime();
      if (!Number.isFinite(timestamp) || timestamp <= 0) continue;
      const bucket = bucketTimestamp(timestamp);
      // Keep the newest sample when a long-range response contains more than
      // one point in the same display bucket.
      const previous = map.get(bucket);
      if (!previous || new Date(previous.timestamp || 0).getTime() <= timestamp) {
        map.set(bucket, point);
      }
      timestampSet.add(bucket);
    }
    pointMaps.set(entry.nodeID, map);
  });
  const timestamps = [...timestampSet].sort((left, right) => left - right);
  const chartPoints = timestamps.map((timestamp) => {
    const point = { timestamp: new Date(timestamp).toISOString() };
    entries.forEach((entry) => {
      const sample = pointMaps.get(entry.nodeID)?.get(timestamp);
      point[entry.key] = numericMetric(sample?.[metricKey]);
    });
    return point;
  });
  return {
    points: chartPoints,
    series: entries.map((entry) => ({ key: entry.key, label: entry.label, color: entry.color })),
  };
}

// Read device curves from the same page snapshot, without per-device polls.
const deviceHistory = computed(() => scope.value === "node"
  ? { [selectedNodeId.value]: points.value }
  : nodePoints.value);
function deviceChart(field, metrics, deviceIDs = null) {
  return buildDeviceChart({ nodePoints: deviceHistory.value, nodes: nodes.value, field, metrics,
    intervalSeconds: chartInterval.value, includeNode: scope.value === "cluster", deviceIDs });
}
const cpuDetailOptions = computed(() => [
  { value: "total", label: t("monitoringCPUTotalView") },
  { value: "cores", label: t("monitoringCPUCoreView") },
]);
const coreGroups = computed(() => cpuDetail.value === "cores" ? cpuCoreGroups(deviceHistory.value, nodes.value) : []);
const selectedCoreIDs = computed(() => coreGroups.value[Number(cpuCorePage.value)]?.ids || new Set());
const logicalCPUChart = computed(() => cpuDetail.value === "cores"
  ? deviceChart("logical_cpus", [{ key: "usage_percent", label: t("monitoringCPUUsage") }], selectedCoreIDs.value)
  : { points: [], series: [] });
const logicalIowaitChart = computed(() => cpuDetail.value === "cores"
  ? deviceChart("logical_cpus", [{ key: "iowait_percent", label: t("monitoringCPUIowait") }], selectedCoreIDs.value)
  : { points: [], series: [] });
const showAccelerators = computed(() => activeView.value === "resources" || activeView.value === "system");
const acceleratorUsageChart = computed(() => deviceChart("accelerators", [{ key: "utilization_percent", label: t("monitoringAcceleratorUtilization") }]));
const acceleratorMemoryChart = computed(() => deviceChart("accelerators", [{ key: "memory_used_bytes", label: t("monitoringAcceleratorMemory") }]));
watch(activeNodeId, () => { cpuCorePage.value = 0; });
watch(() => coreGroups.value.length, (count) => { if (Number(cpuCorePage.value) >= count) cpuCorePage.value = 0; });
const deviceNetworkChart = computed(() => deviceChart("network_interfaces", [
  { key: "rx_bytes_per_second", label: t("monitoringNetworkInShort") },
  { key: "tx_bytes_per_second", label: t("monitoringNetworkOutShort") },
]));
const deviceNetworkPacketChart = computed(() => deviceChart("network_interfaces", [
  { key: "rx_packets_per_second", label: t("monitoringPacketIn") },
  { key: "tx_packets_per_second", label: t("monitoringPacketOut") },
]));
const deviceNetworkQualityChart = computed(() => deviceChart("network_interfaces", [
  { key: "rx_errors_per_second", label: t("monitoringNetworkErrorsIn") },
  { key: "tx_errors_per_second", label: t("monitoringNetworkErrorsOut") },
  { key: "rx_dropped_per_second", label: t("monitoringNetworkDroppedIn") },
  { key: "tx_dropped_per_second", label: t("monitoringNetworkDroppedOut") },
]));
const deviceDiskChart = computed(() => deviceChart("disk_devices", [
  { key: "read_bytes_per_second", label: t("monitoringDiskRead") },
  { key: "write_bytes_per_second", label: t("monitoringDiskWrite") },
]));
const deviceDiskIOPSChart = computed(() => deviceChart("disk_devices", [
  { key: "read_ops_per_second", label: t("monitoringDiskReadOps") },
  { key: "write_ops_per_second", label: t("monitoringDiskWriteOps") },
]));
const deviceDiskUtilizationChart = computed(() => deviceChart("disk_devices", [{ key: "io_utilization_percent", label: t("monitoringDiskUtilization") }]));
const deviceDiskLatencyChart = computed(() => deviceChart("disk_devices", [
  { key: "read_await_milliseconds", label: t("monitoringDiskReadAwait") },
  { key: "write_await_milliseconds", label: t("monitoringDiskWriteAwait") },
]));
const deviceFilesystemChart = computed(() => deviceChart("filesystems", [{ key: "used_percent", label: t("monitoringFilesystemUsage") }]));

const nodeCPUChart = computed(() => buildNodeChart("cpu_percent"));
const nodeMemoryChart = computed(() => buildNodeChart("memory_percent"));
const nodeNetworkChart = computed(() => buildNodeChart("rx_bytes_per_second"));
const nodeDiskChart = computed(() => buildNodeChart("disk_read_bytes_per_second"));
const nodeLoadChart = computed(() => buildNodeChart("load_1"));
const nodeProcessChart = computed(() => buildNodeChart("processes_total"));
watch(() => nodeResourceRows.value.length, () => { nodePage.value = 0; });
watch(() => topProcesses.value.length, () => { processPage.value = 0; });
watch(() => filesystems.value.length, () => { filesystemPage.value = 0; });
watch(() => diskDevices.value.length, () => { diskPage.value = 0; });
watch(() => networkInterfaces.value.length, () => { networkInterfacePage.value = 0; });
watch(() => accelerators.value.length, () => { acceleratorPage.value = 0; });
const resourceSummary = computed(() => {
  const source = scope.value === "node" && activeNode.value ? [activeNode.value] : nodes.value;
  const result = {
    online: source.filter((item) => item.status === "online").length,
    cpuCores: 0,
    uptimeSeconds: 0,
    memoryTotalBytes: 0,
    memoryUsedBytes: 0,
    swapUsedBytes: 0,
    filesystemTotalBytes: 0,
    filesystemUsedBytes: 0,
    sockets: 0,
  };
  source.forEach((node) => {
    result.cpuCores += Number(node.cpu_cores || 0);
    result.uptimeSeconds = Math.max(result.uptimeSeconds, Number(node.uptime_seconds || 0));
    result.memoryTotalBytes += Number(node.memory_total_bytes || 0);
    result.memoryUsedBytes += Number(node.memory_used_bytes || 0);
    result.swapUsedBytes += Number(node.swap_used_bytes || 0);
    result.sockets += Number(node.sockets?.used || 0);
    (node.filesystems || []).forEach((item) => {
      result.filesystemTotalBytes += Number(item.total_bytes || 0);
      result.filesystemUsedBytes += Number(item.used_bytes || 0);
    });
  });
  result.filesystemUsedPercent = result.filesystemTotalBytes > 0
    ? result.filesystemUsedBytes / result.filesystemTotalBytes * 100
    : 0;
  return result;
});

function filesystemUsagePercent(node) {
  const total = (node?.filesystems || []).reduce((sum, item) => sum + Number(item.total_bytes || 0), 0);
  const used = (node?.filesystems || []).reduce((sum, item) => sum + Number(item.used_bytes || 0), 0);
  return total > 0 ? used / total * 100 : 0;
}

const processStateKeys = {
  R: "monitoringProcessStateRunning",
  S: "monitoringProcessStateSleeping",
  D: "monitoringProcessStateUninterruptible",
  Z: "monitoringProcessStateZombie",
  T: "monitoringProcessStateStopped",
  I: "monitoringProcessStateIdle",
};

function processStateCode(value) {
  return String(value || "?").trim().toUpperCase();
}

function processStateLabel(value) {
  const key = processStateKeys[processStateCode(value)] || "monitoringProcessStateUnknown";
  return t(key);
}

function formatPercent(value) {
  const number = Math.max(0, Number(value) || 0);
  return `${number.toFixed(number >= 10 ? 0 : 1).replace(/\.0$/, "")}%`;
}

function formatRate(value) {
  const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
  let number = Math.max(0, Number(value) || 0);
  let unit = 0;
  while (number >= 1024 && unit < units.length - 1) {
    number /= 1024;
    unit += 1;
  }
  const digits = number >= 100 ? 0 : number >= 10 ? 1 : 2;
  return `${number.toFixed(digits).replace(/\.0+$/, "")} ${units[unit]}`;
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let number = Math.max(0, Number(value) || 0);
  let unit = 0;
  while (number >= 1024 && unit < units.length - 1) {
    number /= 1024;
    unit += 1;
  }
  const digits = number >= 100 ? 0 : number >= 10 ? 1 : 2;
  return `${number.toFixed(digits).replace(/\.0+$/, "")} ${units[unit]}`;
}

function formatCount(value) {
  return new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 0 }).format(Number(value) || 0);
}

function showAppliedDates() {
  const { range, from, to } = appliedRange.value;
  const end = to ? new Date(to) : new Date();
  dateFields.start = formatDateTimeLocalValue(from || new Date(end.getTime() - range * 1000));
  dateFields.end = formatDateTimeLocalValue(end);
  dateError.value = "";
}

function changeRange(seconds) {
  if (seconds === -1) {
    showAppliedDates();
    return;
  }
  dateError.value = "";
  appliedRange.value = { range: seconds };
}

function applyDates() {
  const start = zonedDateTimeToDate(dateFields.start);
  const end = zonedDateTimeToDate(dateFields.end);
  const now = Date.now();
  const retention = Number(data.value.retention_seconds) || defaultRetentionSeconds;
  // The end field has minute precision. Include the entire selected minute.
  const from = start?.getTime();
  const to = Math.min((end?.getTime() ?? NaN) + 59_999, now);
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
    dateError.value = t("monitoringCustomRangeInvalid");
    return;
  }
  if (to <= now - retention * 1000) {
    dateError.value = t("monitoringCustomRangeExpired");
    return;
  }
  dateError.value = "";
  appliedRange.value = {
    range: Math.min(retention, Math.ceil((to - from) / 1000)),
    from: start.toISOString(),
    to: new Date(to).toISOString(),
  };
}

function showLastRecordedHour() {
  if (!replayWindow.value) return;
  activeView.value = "history";
  rangeSeconds.value = -1;
  appliedRange.value = replayWindow.value;
  showAppliedDates();
}

function formatScalar(value) {
  const number = Math.max(0, Number(value) || 0);
  return number.toFixed(number >= 10 ? 0 : 2).replace(/\.0+$/, "");
}

function acceleratorHasMetric(item, key) {
  return acceleratorReading(item, key) !== null;
}

function acceleratorMetricValue(item, column) {
  const metric = item?.metrics?.[column.key];
  const value = metric?.value ?? item?.[column.key];
  if (value === undefined || value === null || value === "") return "-";
  const unit = metric?.unit || column.unit;
  if (unit === "bytes") return formatBytes(value);
  if (unit === "%") return formatPercent(value);
  const formatted = formatScalar(value);
  return unit ? `${formatted} ${unit}` : formatted;
}

function acceleratorUtilizationDisplay(item) {
  return acceleratorHasMetric(item, "utilization_percent") ? formatPercent(acceleratorReading(item, "utilization_percent")) : "—";
}

function acceleratorMemoryDisplay(item) {
  if (!acceleratorHasMetric(item, "memory_used_bytes") && !acceleratorHasMetric(item, "memory_total_bytes")) return "-";
  const used = acceleratorReading(item, "memory_used_bytes");
  const total = acceleratorReading(item, "memory_total_bytes");
  return `${used === null ? "—" : formatBytes(used)} / ${total === null ? "—" : formatBytes(total)}`;
}

function acceleratorTemperatureDisplay(item) {
  return acceleratorHasMetric(item, "temperature_c")
    ? `${formatScalar(acceleratorReading(item, "temperature_c"))} °C`
    : "-";
}

function acceleratorExtraMetrics(item) {
  const known = new Set([
    "utilization_percent", "memory_used_bytes", "memory_total_bytes", "temperature_c",
    ...acceleratorOptionalColumns.map((column) => column.key),
  ]);
  return Object.entries(item?.metrics || {})
    .filter(([key, metric]) => !known.has(key) && metric && metric.value !== undefined)
    .map(([key, metric]) => ({
      key,
      label: acceleratorMetricLabel(key, metric),
      value: formatAcceleratorMetric(metric),
    }));
}

function acceleratorMetricLabel(key, metric) {
  const labels = {
    encoder_utilization_percent: "monitoringAcceleratorEncoder",
    decoder_utilization_percent: "monitoringAcceleratorDecoder",
    memory_bandwidth_bytes_per_second: "monitoringAcceleratorMemoryBandwidth",
    power_watts: "monitoringAcceleratorPower",
    power_limit_watts: "monitoringAcceleratorPowerLimit",
  };
  return labels[key] ? t(labels[key]) : (metric.label || key.replace(/_/g, " "));
}

function formatAcceleratorMetric(metric) {
  const unit = metric?.unit || "";
  if (unit === "bytes") return formatBytes(metric.value);
  if (unit === "%") return formatPercent(metric.value);
  const value = formatScalar(metric?.value);
  return unit ? `${value} ${unit}` : value;
}

function formatTime(value) {
  return formatClockTime(value, props.store.state.locale === "en-US" ? "en-US" : "zh-CN");
}

function nodeName(node) {
  return node?.name || node?.node_id || node?.id || "-";
}

function syncMonitoringStream() {
  props.store.setMonitoringStreamQuery({
    scope: activeNodeId.value ? "node" : "cluster",
    node: activeNodeId.value,
    ...appliedRange.value,
  });
}

function selectNode(node) {
  if (!node?.node_id) return;
  scope.value = "node";
  selectedNodeId.value = node.node_id;
}

function changeNodeFilter(value) {
  if (value === "cluster") {
    showCluster();
    return;
  }
  selectNode(nodeCatalog.value.find((item) => item.node_id === value));
}

function showCluster() {
  scope.value = "cluster";
  selectedNodeId.value = "";
}

watch([activeNodeId, appliedRange], syncMonitoringStream);
watch(() => timeState.timeZone, () => { if (showDateFields.value) showAppliedDates(); });

onMounted(() => {
  syncMonitoringStream();
});

onBeforeUnmount(() => {
  props.store.setMonitoringStreamQuery({ scope: "cluster", node: "", range: defaultRangeSeconds });
});
</script>

<template>
  <section class="page-grid monitoring-page">
    <article class="panel panel-span-12 monitoring-header-panel">
      <div class="monitoring-view-tabs" role="tablist" :aria-label="t('monitoringTitle')">
        <button
          v-for="item in viewOptions"
          :key="item.value"
          type="button"
          role="tab"
          :aria-selected="activeView === item.value"
          :class="{ active: activeView === item.value }"
          @click="activeView = item.value"
        ><component :is="monitoringViewIcons[item.value]" :size="15" stroke-width="1.9" aria-hidden="true" />{{ item.label }}</button>
      </div>
      <div class="monitoring-filters">
        <div class="monitoring-controls">
          <label>
            <span>{{ t("headerNode") }}</span>
            <InlineSelect v-model="nodeFilter" :options="nodeFilterOptions" :aria-label="t('headerNode')" />
          </label>
          <label>
            <span>{{ t("monitoringRange") }}</span>
            <InlineSelect v-model="rangeSeconds" :options="rangeOptions" :aria-label="t('monitoringRange')" @change="changeRange" />
          </label>
        </div>
        <form v-if="showDateFields" class="monitoring-custom-range" @submit.prevent="applyDates" @input="dateError = ''">
          <label>
            <span>{{ t("monitoringCustomStart") }}</span>
            <input v-model="dateFields.start" type="datetime-local" required aria-describedby="monitoring-range-details" />
          </label>
          <label>
            <span>{{ t("monitoringCustomEnd") }}</span>
            <input v-model="dateFields.end" type="datetime-local" required aria-describedby="monitoring-range-details" />
          </label>
          <button type="submit" class="primary-button">
            <Search :size="16" aria-hidden="true" />{{ t("monitoringQueryDates") }}
          </button>
        </form>
        <div v-if="activeView !== 'history'" class="monitoring-meta-row">
          <span class="tag accent">{{ sampleLabel }}</span>
          <span v-if="lastUpdatedAt" class="muted-text">{{ t("monitoringUpdated", { time: formatTime(lastUpdatedAt) }) }}</span>
        </div>
        <p v-if="showDateFields" id="monitoring-range-details" class="monitoring-range-details">{{ dateTimeZone }} · {{ t("monitoringCustomRangeHint") }}</p>
      </div>
      <div v-if="archiveNode || (activeView === 'history' && archiveHost)" class="monitoring-archive-status">
        <span v-if="archiveHost">{{ t("monitoringArchiveHost", { name: archiveHost }) }}</span>
        <span v-if="archiveNode">{{ t("monitoringArchiveLastSample", { time: formatDateTime(archiveNode.last_sample_at, store.state.locale) }) }}</span>
        <span v-if="archiveIsStale && archiveNode?.registered" class="tag">{{ t("monitoringArchiveStale") }}</span>
        <button v-if="replayWindow" type="button" class="ghost-button" @click="showLastRecordedHour">{{ t("monitoringReplayLastHour") }}</button>
      </div>
      <p v-if="dateError || historyError" class="monitoring-request-note" role="alert">{{ dateError || historyError }}</p>
      <p v-if="data.storage_error || data.archive_read_error" class="monitoring-request-note" role="status">
        {{ t(data.storage_error ? "monitoringStorageError" : "monitoringArchiveReadError") }}
      </p>
    </article>

    <article v-if="scope === 'cluster' && activeView === 'overview'" class="panel panel-span-12 monitoring-node-panel monitoring-node-resource-panel">
      <div class="panel-head">
        <div><h3>{{ t("monitoringNodeSnapshot") }}</h3></div>
      </div>
      <div class="table-shell">
        <table class="console-table">
          <thead>
            <tr>
              <th>{{ t("monitoringNodeName") }}</th>
              <th>{{ t("monitoringCPU") }}</th>
              <th>{{ t("monitoringMemory") }}</th>
              <th>{{ t("monitoringFilesystemUsage") }}</th>
              <th>{{ t("monitoringNetworkInShort") }}</th>
              <th>{{ t("monitoringNetworkOutShort") }}</th>
              <th>{{ t("monitoringDiskRead") }}</th>
              <th>{{ t("monitoringDiskWrite") }}</th>
              <th>{{ t("monitoringProcessTotal") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="node in visibleNodeResourceRows"
              :key="node.node_id"
              class="monitoring-node-row"
              :class="{ selected: scope === 'node' && node.node_id === selectedNodeId }"
              @click="selectNode(node)"
            >
              <td :title="nodeName(node)"><strong class="table-cell-clip">{{ nodeName(node) }}</strong></td>
              <td>{{ formatPercent(node.cpu_percent) }}</td>
              <td>{{ formatPercent(node.memory_percent) }}</td>
              <td>{{ formatPercent(node.filesystem_used_percent) }}</td>
              <td>{{ formatRate(node.rx_bytes_per_second) }}</td>
              <td>{{ formatRate(node.tx_bytes_per_second) }}</td>
              <td>{{ formatRate(node.disk_read_bytes_per_second) }}</td>
              <td>{{ formatRate(node.disk_write_bytes_per_second) }}</td>
              <td>{{ formatCount(node.process_total) }}</td>
            </tr>
            <tr v-if="!nodeResourceRows.length"><td colspan="9" class="table-empty">{{ loading ? t("monitoringLoading") : t("monitoringNoHistory") }}</td></tr>
          </tbody>
        </table>
      </div>
      <TablePagination v-model:page="nodePage" v-model:page-size="nodePageSize" :total="nodeResourceRows.length" />
    </article>

    <!-- Keep every visible chart in one grid so changing tabs cannot create a
         half-empty second grid. This also lets each view balance its cards
         across complete rows instead of placing the compact charts after an
         unrelated grid break. -->
    <div v-if="activeView !== 'history'" class="monitoring-chart-grid" :class="`monitoring-chart-grid-${activeView}`">
      <article v-if="activeView === 'overview' || activeView === 'resources'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact monitoring-cpu-head">
          <h3>{{ t("monitoringCPUTrend") }}</h3>
          <div class="monitoring-cpu-controls">
            <InlineSelect v-model="cpuDetail" :options="cpuDetailOptions" :aria-label="t('monitoringCPUView')" />
            <InlineSelect v-if="cpuDetail === 'cores' && coreGroups.length" v-model="cpuCorePage" :options="coreGroups" :aria-label="t('monitoringCPUCoreGroup')" />
            <InfoTip v-if="cpuDetail === 'cores'" :text="t('monitoringCPUCoreHint')" />
          </div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.cpu_percent) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="logicalCPUChart.series.length ? logicalCPUChart.points : points" :series="logicalCPUChart.series.length ? logicalCPUChart.series : cpuSeries" :max-value="100" />
      </article>

      <article v-if="activeView === 'overview' || activeView === 'resources'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringMemory") }}</p><h3>{{ t("monitoringMemoryTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.memory_percent) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="points" :series="memorySeries" :max-value="100" />
      </article>

      <article v-if="activeView === 'overview' || activeView === 'io'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNetwork") }}</p><h3>{{ t("monitoringNetworkTrend") }}</h3></div>
          <div class="monitoring-network-values">
            <strong class="network-in">↓ {{ formatRate(latest.rx_bytes_per_second) }}</strong>
            <strong class="network-out">↑ {{ formatRate(latest.tx_bytes_per_second) }}</strong>
          </div>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="deviceNetworkChart.series.length ? deviceNetworkChart.points : points" :series="deviceNetworkChart.series.length ? deviceNetworkChart.series : networkSeries" unit="rate" />
      </article>

      <article v-if="activeView === 'overview' || activeView === 'io'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringDisk") }}</p><h3>{{ t("monitoringDiskTrend") }}</h3></div>
          <div class="monitoring-network-values">
            <strong class="network-in">↓ {{ formatRate(latest.disk_read_bytes_per_second) }}</strong>
            <strong class="network-out">↑ {{ formatRate(latest.disk_write_bytes_per_second) }}</strong>
          </div>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="deviceDiskChart.series.length ? deviceDiskChart.points : points" :series="deviceDiskChart.series.length ? deviceDiskChart.series : diskSeries" unit="rate" />
      </article>

      <article v-if="activeView === 'resources'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringLoad") }}</p><h3>{{ t("monitoringLoadTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatScalar(latest.load_1) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="points" :series="loadSeries" unit="number" />
      </article>

      <article v-if="activeView === 'system'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringFilesystem") }}</p><h3>{{ t("monitoringFilesystemTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.filesystem_used_percent) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="deviceFilesystemChart.series.length ? deviceFilesystemChart.points : points" :series="deviceFilesystemChart.series.length ? deviceFilesystemChart.series : filesystemSeries" :max-value="100" />
      </article>

      <article v-if="activeView === 'resources'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringCPU") }}</p><h3>{{ t("monitoringCPUIowaitTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.cpu_iowait_percent) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="logicalIowaitChart.series.length ? logicalIowaitChart.points : points" :series="logicalIowaitChart.series.length ? logicalIowaitChart.series : cpuIowaitSeries" />
      </article>

      <article v-if="activeView === 'io'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringDisk") }}</p><h3>{{ t("monitoringDiskIOPSTrend") }}</h3></div>
          <div class="monitoring-network-values">
            <strong class="network-in">↓ {{ formatScalar(latest.disk_read_ops_per_second) }} io/s</strong>
            <strong class="network-out">↑ {{ formatScalar(latest.disk_write_ops_per_second) }} io/s</strong>
          </div>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="deviceDiskIOPSChart.series.length ? deviceDiskIOPSChart.points : points" :series="deviceDiskIOPSChart.series.length ? deviceDiskIOPSChart.series : diskIOPSSeries" unit="iops" />
      </article>

      <article v-if="activeView === 'processes'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringProcess") }}</p><h3>{{ t("monitoringProcessTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.processes_total) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="points" :series="processSeries" unit="count" />
      </article>

      <article v-if="activeView === 'system'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringKernel") }}</p><h3>{{ t("monitoringKernelTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.context_switches_per_second) }}/s</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="points" :series="kernelSeries" unit="count" />
      </article>

      <article v-if="activeView === 'resources'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringCPU") }}</p><h3>{{ t("monitoringCPUBreakdown") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.cpu_percent) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="points" :series="cpuModeSeries" :max-value="100" />
      </article>

      <article v-if="activeView === 'resources'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringMemory") }}</p><h3>{{ t("monitoringMemoryCapacityTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatBytes(resourceSummary.memoryUsedBytes) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="points" :series="memoryCapacitySeries" unit="bytes" />
      </article>

      <article v-if="activeView === 'io'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNetwork") }}</p><h3>{{ t("monitoringPacketTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.rx_packets_per_second + latest.tx_packets_per_second) }}/s</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="deviceNetworkPacketChart.series.length ? deviceNetworkPacketChart.points : points" :series="deviceNetworkPacketChart.series.length ? deviceNetworkPacketChart.series : networkPacketSeries" unit="count" />
      </article>

      <article v-if="activeView === 'io'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNetwork") }}</p><h3>{{ t("monitoringNetworkQualityTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.rx_dropped_per_second + latest.tx_dropped_per_second) }}/s</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="deviceNetworkQualityChart.series.length ? deviceNetworkQualityChart.points : points" :series="deviceNetworkQualityChart.series.length ? deviceNetworkQualityChart.series : networkQualitySeries" unit="count" />
      </article>

      <article v-if="activeView === 'io'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringDisk") }}</p><h3>{{ t("monitoringDiskUtilizationTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.disk_io_utilization_percent) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="deviceDiskUtilizationChart.series.length ? deviceDiskUtilizationChart.points : points" :series="deviceDiskUtilizationChart.series.length ? deviceDiskUtilizationChart.series : diskHealthSeries" />
      </article>

      <article v-if="activeView === 'io'" class="panel monitoring-chart-panel monitoring-compact-chart monitoring-chart-wide">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringDisk") }}</p><h3>{{ t("monitoringDiskLatencyTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatScalar(latest.disk_read_await_milliseconds) }} ms</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="deviceDiskLatencyChart.series.length ? deviceDiskLatencyChart.points : points" :series="deviceDiskLatencyChart.series.length ? deviceDiskLatencyChart.series : diskLatencySeries" unit="milliseconds" />
      </article>

      <article v-if="activeView === 'system'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringSockets") }}</p><h3>{{ t("monitoringSocketTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.tcp_in_use) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="points" :series="socketSeries" unit="count" />
      </article>

      <article v-if="activeView === 'system'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringFileDescriptors") }}</p><h3>{{ t("monitoringFileDescriptorTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.file_descriptors_used_percent) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="points" :series="fileDescriptorSeries" unit="count" />
      </article>

      <article v-if="activeView === 'system'" class="panel monitoring-chart-panel monitoring-compact-chart monitoring-chart-wide">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringFileDescriptors") }}</p><h3>{{ t("monitoringFileDescriptorUsageTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.file_descriptors_used_percent) }}</strong>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="points" :series="fileDescriptorUsageSeries" :max-value="100" />
      </article>
    </div>
    <div
      v-if="activeView !== 'history' && scope === 'cluster' && hasNodeChartData"
      class="monitoring-node-chart-grid"
    >
      <article v-if="['overview', 'resources'].includes(activeView)" class="panel monitoring-chart-panel monitoring-node-trend-panel">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNodeTrend") }}</p><h3>{{ t("monitoringNodeCPUTrend") }}</h3></div>
          <span class="tag accent">{{ t("monitoringNodeLineCount", { count: nodeChartEntries.length }) }}</span>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="nodeCPUChart.points" :series="nodeCPUChart.series" :max-value="100" />
      </article>

      <article v-if="['overview', 'resources'].includes(activeView)" class="panel monitoring-chart-panel monitoring-node-trend-panel">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNodeTrend") }}</p><h3>{{ t("monitoringNodeMemoryTrend") }}</h3></div>
          <span class="tag accent">{{ t("monitoringNodeLineCount", { count: nodeChartEntries.length }) }}</span>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="nodeMemoryChart.points" :series="nodeMemoryChart.series" :max-value="100" />
      </article>

      <article v-if="activeView === 'io'" class="panel monitoring-chart-panel monitoring-node-trend-panel">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNodeTrend") }}</p><h3>{{ t("monitoringNodeNetworkTrend") }}</h3></div>
          <span class="tag accent">{{ t("monitoringNodeLineCount", { count: nodeChartEntries.length }) }}</span>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="nodeNetworkChart.points" :series="nodeNetworkChart.series" unit="rate" />
      </article>

      <article v-if="activeView === 'io'" class="panel monitoring-chart-panel monitoring-node-trend-panel">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNodeTrend") }}</p><h3>{{ t("monitoringNodeDiskTrend") }}</h3></div>
          <span class="tag accent">{{ t("monitoringNodeLineCount", { count: nodeChartEntries.length }) }}</span>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="nodeDiskChart.points" :series="nodeDiskChart.series" unit="rate" />
      </article>

      <article v-if="activeView === 'system'" class="panel monitoring-chart-panel monitoring-node-trend-panel">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNodeTrend") }}</p><h3>{{ t("monitoringNodeLoadTrend") }}</h3></div>
          <span class="tag accent">{{ t("monitoringNodeLineCount", { count: nodeChartEntries.length }) }}</span>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="nodeLoadChart.points" :series="nodeLoadChart.series" unit="number" />
      </article>

      <article v-if="activeView === 'system' || activeView === 'processes'" class="panel monitoring-chart-panel monitoring-node-trend-panel">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNodeTrend") }}</p><h3>{{ t("monitoringNodeProcessTrend") }}</h3></div>
          <span class="tag accent">{{ t("monitoringNodeLineCount", { count: nodeChartEntries.length }) }}</span>
        </div>
        <MonitoringChart :sample-interval="chartInterval" :points="nodeProcessChart.points" :series="nodeProcessChart.series" unit="count" />
      </article>
    </div>
    <MonitoringHistory
      v-if="activeView === 'history'"
      :points="points"
      :query="store.state.monitoringStreamQuery"
      :sample-interval="chartInterval"
      :scope-label="nodeOptions.find((node) => node.value === activeNodeId)?.label || t('monitoringCluster')"
      :loading="loading"
      :failed="Boolean(historyError)"
    />

    <div v-if="activeView === 'processes' || activeView === 'system' || activeView === 'io' || activeView === 'resources'" class="monitoring-lower-grid workspace-fill">
      <article v-if="activeView === 'processes'" class="panel monitoring-node-panel workspace-panel">
        <div class="panel-head">
          <div><p>{{ t("monitoringProcess") }}</p><h3>{{ t("monitoringProcessTableHint") }}</h3></div>
        </div>
        <div v-if="topProcesses.length" class="table-shell monitoring-process-table">
          <table class="console-table">
            <thead>
              <tr>
                <th v-if="scope === 'cluster'">{{ t("monitoringNodeName") }}</th>
                <th><span class="table-heading-with-tip">{{ t("monitoringProcessPID") }}<InfoTip :text="t('monitoringProcessPIDHint')" /></span></th>
                <th>{{ t("monitoringProcessName") }}</th>
                <th><span class="table-heading-with-tip">{{ t("monitoringProcessState") }}<InfoTip :text="t('monitoringProcessStateHint')" /></span></th>
                <th><span class="table-heading-with-tip">{{ t("monitoringProcessCPU") }}<InfoTip :text="t('monitoringProcessCPUHint')" /></span></th>
                <th><span class="table-heading-with-tip">{{ t("monitoringProcessMemory") }}<InfoTip :text="t('monitoringProcessMemoryHint')" /></span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in visibleTopProcesses" :key="`${item.node_id}-${item.pid}`">
                <td v-if="scope === 'cluster'" :title="item.node_name"><strong class="table-cell-clip">{{ item.node_name }}</strong></td>
                <td>{{ item.pid }}</td>
                <td :title="item.name"><span class="table-cell-clip">{{ item.name }}</span></td>
                <td>
                  <span class="process-state-value">
                    <strong>{{ processStateCode(item.state) }}</strong>
                    <span>{{ processStateLabel(item.state) }}</span>
                  </span>
                </td>
                <td>{{ formatPercent(item.cpu_percent) }}</td>
                <td>{{ formatBytes(item.memory_bytes) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">{{ t("monitoringNoProcess") }}</div>
        <TablePagination v-model:page="processPage" v-model:page-size="processPageSize" :total="topProcesses.length" />
      </article>

      <article v-if="activeView === 'system'" class="panel monitoring-node-panel">
        <div class="panel-head"><div><p>{{ t("monitoringFilesystem") }}</p><h3>{{ t("monitoringFilesystemCapacity") }}</h3></div></div>
        <div class="table-shell">
          <table class="console-table">
            <thead>
              <tr>
                <th v-if="scope === 'cluster'">{{ t("monitoringNodeName") }}</th>
                <th>{{ t("monitoringFilesystemMount") }}</th>
                <th><span class="table-heading-with-tip">{{ t("monitoringFilesystemType") }}<InfoTip :text="t('monitoringFilesystemTypeHint')" /></span></th>
                <th><span class="table-heading-with-tip">{{ t("monitoringFilesystemUsage") }}<InfoTip :text="t('monitoringFilesystemUsageHint')" /></span></th>
                <th>{{ t("monitoringFilesystemCapacity") }}</th>
                <th>{{ t("monitoringFilesystemAvailable") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in visibleFilesystems" :key="`${item.node_id}-${item.device}-${item.mountpoint}`">
                <td v-if="scope === 'cluster'" :title="item.node_name"><strong class="table-cell-clip">{{ item.node_name }}</strong></td>
                <td :title="item.mountpoint"><span class="table-cell-clip">{{ item.mountpoint }}</span></td>
                <td :title="[item.device, item.fstype].filter(Boolean).join(' · ')"><span class="table-cell-clip">{{ item.device || "-" }}<span v-if="item.fstype"> · {{ item.fstype }}</span></span></td>
                <td>{{ formatPercent(item.used_percent) }}</td>
                <td>{{ formatBytes(item.used_bytes) }} / {{ formatBytes(item.total_bytes) }}</td>
                <td>{{ formatBytes(item.available_bytes) }}</td>
              </tr>
              <tr v-if="!filesystems.length"><td :colspan="scope === 'cluster' ? 6 : 5" class="table-empty">{{ t("monitoringNoFilesystem") }}</td></tr>
            </tbody>
          </table>
        </div>
        <TablePagination v-model:page="filesystemPage" v-model:page-size="filesystemPageSize" :total="filesystems.length" />
      </article>

      <article v-if="activeView === 'io' || activeView === 'system'" class="panel monitoring-node-panel">
        <div class="panel-head">
          <div>
            <p>{{ t("monitoringDisk") }}</p>
            <h3>{{ t("monitoringDiskDevices") }}</h3>
          </div>
          <span class="tag accent">{{ t("monitoringDiskDeviceCount", { count: diskDevices.length }) }}</span>
        </div>
        <div class="table-shell">
          <table class="console-table">
            <thead>
              <tr>
                <th v-if="scope === 'cluster'">{{ t("monitoringNodeName") }}</th>
                <th>{{ t("monitoringDiskDevice") }}</th>
                <th>{{ t("monitoringDiskRead") }}</th>
                <th>{{ t("monitoringDiskWrite") }}</th>
                <th>{{ t("monitoringDiskReadOps") }}</th>
                <th>{{ t("monitoringDiskWriteOps") }}</th>
                <th>{{ t("monitoringDiskUtilization") }}</th>
                <th>{{ t("monitoringDiskReadAwait") }}</th>
                <th>{{ t("monitoringDiskWriteAwait") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in visibleDiskDevices" :key="`${item.node_id}-${item.name}`">
                <td v-if="scope === 'cluster'" :title="item.node_name"><strong class="table-cell-clip">{{ item.node_name }}</strong></td>
                <td><strong>{{ item.name }}</strong></td>
                <td>{{ formatRate(item.read_bytes_per_second) }}</td>
                <td>{{ formatRate(item.write_bytes_per_second) }}</td>
                <td>{{ formatScalar(item.read_ops_per_second) }} io/s</td>
                <td>{{ formatScalar(item.write_ops_per_second) }} io/s</td>
                <td>{{ formatPercent(item.io_utilization_percent) }}</td>
                <td>{{ formatScalar(item.read_await_milliseconds) }} ms</td>
                <td>{{ formatScalar(item.write_await_milliseconds) }} ms</td>
              </tr>
              <tr v-if="!diskDevices.length"><td :colspan="scope === 'cluster' ? 9 : 8" class="table-empty">{{ t("monitoringNoDiskDevices") }}</td></tr>
            </tbody>
          </table>
        </div>
        <TablePagination v-model:page="diskPage" v-model:page-size="diskPageSize" :total="diskDevices.length" />
      </article>

      <article v-if="activeView === 'io' || activeView === 'system'" class="panel monitoring-node-panel">
        <div class="panel-head">
          <div>
            <p>{{ t("monitoringNetwork") }}</p>
            <h3>{{ t("monitoringNetworkInterfaces") }}</h3>
          </div>
          <span class="tag accent">{{ networkInterfaces.length }}</span>
        </div>
        <div class="table-shell">
          <table class="console-table">
            <thead>
              <tr>
                <th v-if="scope === 'cluster'">{{ t("monitoringNodeName") }}</th>
                <th>{{ t("monitoringNetworkInterface") }}</th>
                <th>{{ t("status") }}</th>
                <th>{{ t("monitoringNetworkIn") }}</th>
                <th>{{ t("monitoringNetworkOut") }}</th>
                <th>{{ t("monitoringNetworkErrors") }}</th>
                <th>{{ t("monitoringNetworkDropped") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in visibleNetworkInterfaces" :key="`${item.node_id}-${item.name}`">
                <td v-if="scope === 'cluster'" :title="item.node_name"><strong class="table-cell-clip">{{ item.node_name }}</strong></td>
                <td><strong>{{ item.name }}</strong></td>
                <td>{{ item.operational_state || "-" }}</td>
                <td>{{ formatRate(item.rx_bytes_per_second) }}</td>
                <td>{{ formatRate(item.tx_bytes_per_second) }}</td>
                <td>{{ formatRate(Number(item.rx_errors_per_second || 0) + Number(item.tx_errors_per_second || 0)) }}</td>
                <td>{{ formatRate(Number(item.rx_dropped_per_second || 0) + Number(item.tx_dropped_per_second || 0)) }}</td>
              </tr>
              <tr v-if="!networkInterfaces.length"><td :colspan="scope === 'cluster' ? 7 : 6" class="table-empty">{{ t("monitoringNoNetworkInterfaces") }}</td></tr>
            </tbody>
          </table>
        </div>
        <TablePagination v-model:page="networkInterfacePage" v-model:page-size="networkInterfacePageSize" :total="networkInterfaces.length" />
      </article>

      <div v-if="showAccelerators && (acceleratorUsageChart.series.length || acceleratorMemoryChart.series.length)" class="monitoring-accelerator-charts">
        <article v-if="acceleratorUsageChart.series.length" class="panel monitoring-chart-panel">
          <div class="panel-head compact"><h3>{{ t("monitoringAcceleratorUtilization") }}</h3></div>
          <MonitoringChart :sample-interval="chartInterval" :points="acceleratorUsageChart.points" :series="acceleratorUsageChart.series" :max-value="100" />
        </article>
        <article v-if="acceleratorMemoryChart.series.length" class="panel monitoring-chart-panel">
          <div class="panel-head compact"><h3>{{ t("monitoringAcceleratorMemory") }}</h3></div>
          <MonitoringChart :sample-interval="chartInterval" :points="acceleratorMemoryChart.points" :series="acceleratorMemoryChart.series" unit="bytes" />
        </article>
      </div>
      <article v-if="showAccelerators" class="panel monitoring-node-panel">
        <div class="panel-head">
          <div>
            <p>{{ t("monitoringAccelerator") }}</p>
            <h3>{{ t("monitoringAcceleratorDetails") }}</h3>
          </div>
          <span class="tag accent">{{ t("monitoringAcceleratorCount", { count: accelerators.length }) }}</span>
        </div>
        <div class="table-shell">
          <table class="console-table">
            <thead>
              <tr>
                <th v-if="scope === 'cluster'">{{ t("monitoringNodeName") }}</th>
                <th>{{ t("monitoringAcceleratorDevice") }}</th>
                <th>{{ t("monitoringAcceleratorVendor") }}</th>
                <th v-if="acceleratorHasBackend">{{ t("monitoringAcceleratorBackend") }}</th>
                <th>{{ t("monitoringAcceleratorUtilization") }}</th>
                <th>{{ t("monitoringAcceleratorMemory") }}</th>
                <th>{{ t("monitoringAcceleratorTemperature") }}</th>
                <th v-for="column in acceleratorMetricColumns" :key="column.key">{{ t(column.label) }}</th>
                <th v-if="acceleratorHasExtraMetrics">{{ t("monitoringAcceleratorExtraMetrics") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in visibleAccelerators" :key="`${item.node_id}-${item.vendor}-${item.index}`">
                <td v-if="scope === 'cluster'" :title="item.node_name"><strong class="table-cell-clip">{{ item.node_name }}</strong></td>
                <td :title="[item.name, item.architecture, item.device_id].filter(Boolean).join(' · ')">
                  <strong class="table-cell-clip">{{ item.name || `${t("monitoringAcceleratorDevice")} ${item.index}` }}</strong>
                  <small v-if="item.architecture" class="muted-text">{{ item.architecture }}</small>
                  <small v-if="item.backend === 'pci-sysfs'" class="muted-text">{{ t("monitoringAcceleratorInventoryOnly") }}</small>
                </td>
                <td>{{ item.vendor || "-" }}</td>
                <td v-if="acceleratorHasBackend" :title="[item.backend, item.driver, item.bus_id].filter(Boolean).join(' · ')">
                  <span class="table-cell-clip">{{ [item.backend, item.driver, item.bus_id].filter(Boolean).join(" · ") || "-" }}</span>
                </td>
                <td>{{ acceleratorUtilizationDisplay(item) }}</td>
                <td>{{ acceleratorMemoryDisplay(item) }}</td>
                <td>{{ acceleratorTemperatureDisplay(item) }}</td>
                <td v-for="column in acceleratorMetricColumns" :key="column.key">{{ acceleratorMetricValue(item, column) }}</td>
                <td v-if="acceleratorHasExtraMetrics">
                  <span v-if="acceleratorExtraMetrics(item).length" class="accelerator-metric-list">
                    <span v-for="metric in acceleratorExtraMetrics(item)" :key="metric.key" class="tag">{{ metric.label }}: {{ metric.value }}</span>
                  </span>
                  <span v-else>-</span>
                </td>
              </tr>
              <tr v-if="!accelerators.length"><td :colspan="acceleratorTableColumnCount" class="table-empty">{{ t("monitoringNoAccelerators") }}</td></tr>
            </tbody>
          </table>
        </div>
        <TablePagination v-model:page="acceleratorPage" v-model:page-size="acceleratorPageSize" :total="accelerators.length" />
      </article>
    </div>
  </section>
</template>
