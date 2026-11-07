<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { BarChart3, Cpu, HardDrive, ListTree, Network, ScrollText } from "@lucide/vue";
import { request } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import InfoTip from "@/components/InfoTip.vue";
import InlineSelect from "@/components/InlineSelect.vue";
import MonitoringChart from "@/components/MonitoringChart.vue";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();
const scope = ref("cluster");
const selectedNodeId = ref("");
const rangeSeconds = ref(15 * 60);
const refreshSeconds = ref(5);
const activeView = ref("overview");
const customRange = reactive({ start: "", end: "" });
const loading = ref(false);
const data = ref({ points: [], nodes: [], range_seconds: 900 });
const lastUpdatedAt = ref(null);
let refreshTimer = null;
let requestSerial = 0;

const activeNodeId = computed(() => scope.value === "node" ? selectedNodeId.value : "");
const customRangeActive = computed(() => rangeSeconds.value === -1);
const customRangeValid = computed(() => {
  if (!customRangeActive.value || !customRange.start || !customRange.end) return false;
  const start = new Date(customRange.start).getTime();
  const end = new Date(customRange.end).getTime();
  return Number.isFinite(start) && Number.isFinite(end) && end > start;
});
const points = computed(() => (Array.isArray(data.value.points) ? data.value.points : []));
const nodes = computed(() => (Array.isArray(data.value.nodes) ? data.value.nodes : []));
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
const nodeOptions = computed(() => nodes.value.map((item) => ({ value: item.node_id, label: nodeName(item) })));
const nodeFilterOptions = computed(() => [
  { value: "cluster", label: t("monitoringCluster") },
  ...nodeOptions.value,
]);
const nodeFilter = computed({
  get: () => (scope.value === "node" && selectedNodeId.value ? selectedNodeId.value : "cluster"),
  set: (value) => changeNodeFilter(value),
});
const refreshOptions = computed(() => [
  { value: 5, label: t("monitoringRefresh5s") },
  { value: 15, label: t("monitoringRefresh15s") },
  { value: 30, label: t("monitoringRefresh30s") },
  { value: 0, label: t("monitoringRefreshOff") },
]);
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
const historyRows = computed(() => points.value.slice().reverse());
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

function toDateTimeLocalValue(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function initializeCustomRange() {
  const end = new Date();
  const start = new Date(end.getTime() - 15 * 60 * 1000);
  customRange.start = toDateTimeLocalValue(start);
  customRange.end = toDateTimeLocalValue(end);
}

function changeRange() {
  if (customRangeActive.value && !customRange.start) initializeCustomRange();
}

function formatScalar(value) {
  const number = Math.max(0, Number(value) || 0);
  return number.toFixed(number >= 10 ? 0 : 2).replace(/\.0+$/, "");
}

function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatHistoryTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "-"
    : date.toLocaleString([], { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function nodeName(node) {
  return node?.name || node?.node_id || "-";
}

async function loadHistory() {
  const serial = ++requestSerial;
  if (customRangeActive.value && !customRangeValid.value) {
    loading.value = false;
    return;
  }
  loading.value = true;
  const query = new URLSearchParams();
  if (customRangeActive.value) {
    const start = new Date(customRange.start);
    const end = new Date(customRange.end);
    // datetime-local has minute precision. Treat the selected end minute as
    // inclusive so samples collected during that minute are not hidden.
    end.setSeconds(59, 999);
    query.set("from", start.toISOString());
    query.set("to", end.toISOString());
  } else {
    query.set("range", String(rangeSeconds.value));
  }
  if (activeNodeId.value) query.set("node", activeNodeId.value);
  try {
    const payload = await request(`/monitoring/history?${query.toString()}`, { key: "monitoring-history", timeoutMs: 10000 });
    if (serial !== requestSerial) return;
    data.value = payload || { points: [], nodes: [] };
    lastUpdatedAt.value = new Date();
  } catch (error) {
    if (error?.code !== "SUPERSEDED" && error?.code !== "AUTH_REQUIRED") props.store.handleError(error);
  } finally {
    if (serial === requestSerial) loading.value = false;
  }
}

function restartTimer() {
  if (refreshTimer) {
    window.clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (refreshSeconds.value > 0) {
    refreshTimer = window.setInterval(loadHistory, refreshSeconds.value * 1000);
  }
}

function selectNode(node) {
  if (!node?.node_id) return;
  scope.value = "node";
  selectedNodeId.value = node.node_id;
  props.store.setNode(node.node_id).catch(props.store.handleError);
}

function changeNodeFilter(value) {
  if (value === "cluster") {
    showCluster();
    return;
  }
  const node = nodes.value.find((item) => item.node_id === value);
  if (node) selectNode(node);
}

function showCluster() {
  scope.value = "cluster";
  selectedNodeId.value = "";
}

watch([scope, selectedNodeId, rangeSeconds, () => customRange.start, () => customRange.end], loadHistory);
watch(refreshSeconds, restartTimer);

onMounted(() => {
  loadHistory();
  restartTimer();
});

onBeforeUnmount(() => {
  if (refreshTimer) window.clearInterval(refreshTimer);
});
</script>

<template>
  <section class="page-grid monitoring-page">
    <p v-if="data.storage_error" class="panel panel-span-12 security-note" role="alert">{{ t("monitoringStorageError") }}: {{ data.storage_error }}</p>
    <article class="panel panel-span-12 monitoring-header-panel">
      <div class="panel-head monitoring-page-head">
        <div class="monitoring-controls">
          <label>
            <span>{{ t("headerNode") }}</span>
            <InlineSelect v-model="nodeFilter" :options="nodeFilterOptions" :aria-label="t('headerNode')" />
          </label>
          <label>
            <span>{{ t("monitoringRange") }}</span>
            <InlineSelect v-model="rangeSeconds" :options="rangeOptions" :aria-label="t('monitoringRange')" @change="changeRange" />
          </label>
          <label>
            <span>{{ t("monitoringRefresh") }}</span>
            <InlineSelect v-model="refreshSeconds" :options="refreshOptions" :aria-label="t('monitoringRefresh')" />
          </label>
        </div>
      </div>
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
      <div v-if="customRangeActive" class="monitoring-custom-range">
        <label>
          <span>{{ t("monitoringCustomStart") }}</span>
          <input v-model="customRange.start" type="datetime-local" :max="customRange.end || undefined" />
        </label>
        <label>
          <span>{{ t("monitoringCustomEnd") }}</span>
          <input v-model="customRange.end" type="datetime-local" :min="customRange.start || undefined" />
        </label>
        <span class="monitoring-custom-range-hint">{{ customRangeValid ? t("monitoringCustomRangeHint") : t("monitoringCustomRangeInvalid") }}</span>
      </div>
      <div class="monitoring-meta-row">
        <span class="tag accent">{{ sampleLabel }}</span>
        <span v-if="lastUpdatedAt" class="muted-text">{{ t("monitoringUpdated", { time: formatTime(lastUpdatedAt) }) }}</span>
      </div>
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
              v-for="node in nodeResourceRows"
              :key="node.node_id"
              class="monitoring-node-row"
              :class="{ selected: scope === 'node' && node.node_id === selectedNodeId }"
              @click="selectNode(node)"
            >
              <td><strong>{{ nodeName(node) }}</strong></td>
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
    </article>

    <!-- Keep every visible chart in one grid so changing tabs cannot create a
         half-empty second grid. This also lets each view balance its cards
         across complete rows instead of placing the compact charts after an
         unrelated grid break. -->
    <div class="monitoring-chart-grid" :class="`monitoring-chart-grid-${activeView}`">
      <article v-show="activeView === 'overview' || activeView === 'resources'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringCPU") }}</p><h3>{{ t("monitoringCPUTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.cpu_percent) }}</strong>
        </div>
        <div class="monitoring-legend"><span class="legend-dot" style="--legend-color: #1db7ae"></span>{{ t("monitoringCPUUsage") }}</div>
        <MonitoringChart :points="points" :series="cpuSeries" :max-value="100" />
      </article>

      <article v-show="activeView === 'overview' || activeView === 'resources'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringMemory") }}</p><h3>{{ t("monitoringMemoryTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.memory_percent) }}</strong>
        </div>
        <div class="monitoring-legend"><span class="legend-dot" style="--legend-color: #ff9e52"></span>{{ t("monitoringMemoryUsage") }}</div>
        <MonitoringChart :points="points" :series="memorySeries" :max-value="100" />
      </article>

      <article v-show="activeView === 'overview' || activeView === 'io'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNetwork") }}</p><h3>{{ t("monitoringNetworkTrend") }}</h3></div>
          <div class="monitoring-network-values">
            <strong class="network-in">↓ {{ formatRate(latest.rx_bytes_per_second) }}</strong>
            <strong class="network-out">↑ {{ formatRate(latest.tx_bytes_per_second) }}</strong>
          </div>
        </div>
        <div class="monitoring-legend-group">
          <span><i class="legend-dot" style="--legend-color: #4a9fe8"></i>{{ t("monitoringNetworkInShort") }}</span>
          <span><i class="legend-dot" style="--legend-color: #8b79e8"></i>{{ t("monitoringNetworkOutShort") }}</span>
        </div>
        <MonitoringChart :points="points" :series="networkSeries" unit="rate" />
      </article>

      <article v-show="activeView === 'overview' || activeView === 'io'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringDisk") }}</p><h3>{{ t("monitoringDiskTrend") }}</h3></div>
          <div class="monitoring-network-values">
            <strong class="network-in">↓ {{ formatRate(latest.disk_read_bytes_per_second) }}</strong>
            <strong class="network-out">↑ {{ formatRate(latest.disk_write_bytes_per_second) }}</strong>
          </div>
        </div>
        <div class="monitoring-legend-group">
          <span><i class="legend-dot" style="--legend-color: #ef8f55"></i>{{ t("monitoringDiskRead") }}</span>
          <span><i class="legend-dot" style="--legend-color: #d86ec3"></i>{{ t("monitoringDiskWrite") }}</span>
        </div>
        <MonitoringChart :points="points" :series="diskSeries" unit="rate" />
      </article>

      <article v-show="activeView === 'resources'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringLoad") }}</p><h3>{{ t("monitoringLoadTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatScalar(latest.load_1) }}</strong>
        </div>
        <div class="monitoring-legend-group">
          <span><i class="legend-dot" style="--legend-color: #3b92dd"></i>{{ t("monitoringLoad1") }}</span>
          <span><i class="legend-dot" style="--legend-color: #1db7ae"></i>{{ t("monitoringLoad5") }}</span>
          <span><i class="legend-dot" style="--legend-color: #f0ad4e"></i>{{ t("monitoringLoad15") }}</span>
        </div>
        <MonitoringChart :points="points" :series="loadSeries" unit="number" />
      </article>

      <article v-show="activeView === 'system'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringFilesystem") }}</p><h3>{{ t("monitoringFilesystemTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.filesystem_used_percent) }}</strong>
        </div>
        <div class="monitoring-legend"><span class="legend-dot" style="--legend-color: #75b798"></span>{{ t("monitoringFilesystemUsage") }}</div>
        <MonitoringChart :points="points" :series="filesystemSeries" :max-value="100" />
      </article>

      <article v-show="activeView === 'resources'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringCPU") }}</p><h3>{{ t("monitoringCPUIowaitTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.cpu_iowait_percent) }}</strong>
        </div>
        <div class="monitoring-legend"><span class="legend-dot" style="--legend-color: #e66e83"></span>{{ t("monitoringCPUIowait") }}</div>
        <MonitoringChart :points="points" :series="cpuIowaitSeries" :max-value="100" />
      </article>

      <article v-show="activeView === 'io'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringDisk") }}</p><h3>{{ t("monitoringDiskIOPSTrend") }}</h3></div>
          <div class="monitoring-network-values">
            <strong class="network-in">↓ {{ formatScalar(latest.disk_read_ops_per_second) }} io/s</strong>
            <strong class="network-out">↑ {{ formatScalar(latest.disk_write_ops_per_second) }} io/s</strong>
          </div>
        </div>
        <div class="monitoring-legend-group">
          <span><i class="legend-dot" style="--legend-color: #ef8f55"></i>{{ t("monitoringDiskReadOps") }}</span>
          <span><i class="legend-dot" style="--legend-color: #d86ec3"></i>{{ t("monitoringDiskWriteOps") }}</span>
        </div>
        <MonitoringChart :points="points" :series="diskIOPSSeries" unit="iops" />
      </article>

      <article v-show="activeView === 'processes'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringProcess") }}</p><h3>{{ t("monitoringProcessTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.processes_total) }}</strong>
        </div>
        <div class="monitoring-legend-group">
          <span><i class="legend-dot" style="--legend-color: #3b92dd"></i>{{ t("monitoringProcessTotal") }}</span>
          <span><i class="legend-dot" style="--legend-color: #1db7ae"></i>{{ t("monitoringProcessRunning") }}</span>
          <span><i class="legend-dot" style="--legend-color: #e66e83"></i>{{ t("monitoringProcessBlocked") }}</span>
        </div>
        <MonitoringChart :points="points" :series="processSeries" unit="count" />
      </article>

      <article v-show="activeView === 'system'" class="panel panel-span-6 monitoring-chart-panel monitoring-resource-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringKernel") }}</p><h3>{{ t("monitoringKernelTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.context_switches_per_second) }}/s</strong>
        </div>
        <div class="monitoring-legend-group">
          <span><i class="legend-dot" style="--legend-color: #8b79e8"></i>{{ t("monitoringContextSwitch") }}</span>
          <span><i class="legend-dot" style="--legend-color: #f0ad4e"></i>{{ t("monitoringInterrupts") }}</span>
        </div>
        <MonitoringChart :points="points" :series="kernelSeries" unit="count" />
      </article>

      <article v-show="activeView === 'resources'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringCPU") }}</p><h3>{{ t("monitoringCPUBreakdown") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.cpu_percent) }}</strong>
        </div>
        <div class="monitoring-legend-group"><span v-for="item in cpuModeSeries" :key="item.key"><i class="legend-dot" :style="{ '--legend-color': item.color }"></i>{{ item.label }}</span></div>
        <MonitoringChart :points="points" :series="cpuModeSeries" :max-value="100" />
      </article>

      <article v-show="activeView === 'resources'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringMemory") }}</p><h3>{{ t("monitoringMemoryCapacityTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatBytes(resourceSummary.memoryUsedBytes) }}</strong>
        </div>
        <div class="monitoring-legend-group"><span v-for="item in memoryCapacitySeries" :key="item.key"><i class="legend-dot" :style="{ '--legend-color': item.color }"></i>{{ item.label }}</span></div>
        <MonitoringChart :points="points" :series="memoryCapacitySeries" unit="bytes" />
      </article>

      <article v-show="activeView === 'io'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNetwork") }}</p><h3>{{ t("monitoringPacketTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.rx_packets_per_second + latest.tx_packets_per_second) }}/s</strong>
        </div>
        <div class="monitoring-legend-group"><span v-for="item in networkPacketSeries" :key="item.key"><i class="legend-dot" :style="{ '--legend-color': item.color }"></i>{{ item.label }}</span></div>
        <MonitoringChart :points="points" :series="networkPacketSeries" unit="count" />
      </article>

      <article v-show="activeView === 'io'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringNetwork") }}</p><h3>{{ t("monitoringNetworkQualityTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.rx_dropped_per_second + latest.tx_dropped_per_second) }}/s</strong>
        </div>
        <div class="monitoring-legend-group"><span v-for="item in networkQualitySeries" :key="item.key"><i class="legend-dot" :style="{ '--legend-color': item.color }"></i>{{ item.label }}</span></div>
        <MonitoringChart :points="points" :series="networkQualitySeries" unit="count" />
      </article>

      <article v-show="activeView === 'io'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringDisk") }}</p><h3>{{ t("monitoringDiskUtilizationTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.disk_io_utilization_percent) }}</strong>
        </div>
        <div class="monitoring-legend"><span class="legend-dot" style="--legend-color: #1db7ae"></span>{{ t("monitoringDiskUtilization") }}</div>
        <MonitoringChart :points="points" :series="diskHealthSeries" :max-value="100" />
      </article>

      <article v-show="activeView === 'io'" class="panel monitoring-chart-panel monitoring-compact-chart monitoring-chart-wide">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringDisk") }}</p><h3>{{ t("monitoringDiskLatencyTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatScalar(latest.disk_read_await_milliseconds) }} ms</strong>
        </div>
        <div class="monitoring-legend-group"><span v-for="item in diskLatencySeries" :key="item.key"><i class="legend-dot" :style="{ '--legend-color': item.color }"></i>{{ item.label }}</span></div>
        <MonitoringChart :points="points" :series="diskLatencySeries" unit="milliseconds" />
      </article>

      <article v-show="activeView === 'system'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringSockets") }}</p><h3>{{ t("monitoringSocketTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatCount(latest.tcp_in_use) }}</strong>
        </div>
        <div class="monitoring-legend-group"><span v-for="item in socketSeries" :key="item.key"><i class="legend-dot" :style="{ '--legend-color': item.color }"></i>{{ item.label }}</span></div>
        <MonitoringChart :points="points" :series="socketSeries" unit="count" />
      </article>

      <article v-show="activeView === 'system'" class="panel monitoring-chart-panel monitoring-compact-chart">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringFileDescriptors") }}</p><h3>{{ t("monitoringFileDescriptorTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.file_descriptors_used_percent) }}</strong>
        </div>
        <div class="monitoring-legend"><span class="legend-dot" style="--legend-color: #8b79e8"></span>{{ t("monitoringFDAllocated") }}</div>
        <MonitoringChart :points="points" :series="fileDescriptorSeries" unit="count" />
      </article>

      <article v-show="activeView === 'system'" class="panel monitoring-chart-panel monitoring-compact-chart monitoring-chart-wide">
        <div class="panel-head compact">
          <div><p>{{ t("monitoringFileDescriptors") }}</p><h3>{{ t("monitoringFileDescriptorUsageTrend") }}</h3></div>
          <strong class="monitoring-chart-value">{{ formatPercent(latest.file_descriptors_used_percent) }}</strong>
        </div>
        <div class="monitoring-legend"><span class="legend-dot" style="--legend-color: #e66e83"></span>{{ t("monitoringFDUsedPercent") }}</div>
        <MonitoringChart :points="points" :series="fileDescriptorUsageSeries" :max-value="100" />
      </article>
    </div>
    <article v-if="activeView === 'history'" class="panel panel-span-12 monitoring-history-panel">
      <div class="panel-head">
        <div>
          <h3>{{ t("monitoringHistory") }}</h3>
          <p>{{ t("monitoringHistoryHint") }}</p>
        </div>
        <span class="tag accent">{{ sampleLabel }}</span>
      </div>
      <div v-if="historyRows.length" class="table-shell monitoring-history-table">
        <table class="console-table">
          <thead>
            <tr>
              <th>{{ t("monitoringHistoryTime") }}</th>
              <th>{{ t("monitoringHistoryScope") }}</th>
              <th>{{ t("monitoringCPU") }}</th>
              <th>{{ t("monitoringCPUIowait") }}</th>
              <th>{{ t("monitoringLoad1") }}</th>
              <th>{{ t("monitoringMemory") }}</th>
              <th>{{ t("monitoringNetworkInShort") }}</th>
              <th>{{ t("monitoringNetworkOutShort") }}</th>
              <th>{{ t("monitoringDiskRead") }}</th>
              <th>{{ t("monitoringDiskWrite") }}</th>
              <th>{{ t("monitoringDiskReadOps") }}</th>
              <th>{{ t("monitoringDiskWriteOps") }}</th>
              <th>{{ t("monitoringContextSwitch") }}</th>
              <th>{{ t("monitoringProcessTotal") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="point in historyRows" :key="`${point.timestamp}-${point.node_id || 'cluster'}`">
              <td>{{ formatHistoryTime(point.timestamp) }}</td>
              <td>{{ scope === "cluster" ? t("monitoringCluster") : nodeName(activeNode) }}</td>
              <td>{{ formatPercent(point.cpu_percent) }}</td>
              <td>{{ formatPercent(point.cpu_iowait_percent) }}</td>
              <td>{{ formatScalar(point.load_1) }}</td>
              <td>{{ formatPercent(point.memory_percent) }}</td>
              <td>{{ formatRate(point.rx_bytes_per_second) }}</td>
              <td>{{ formatRate(point.tx_bytes_per_second) }}</td>
              <td>{{ formatRate(point.disk_read_bytes_per_second) }}</td>
              <td>{{ formatRate(point.disk_write_bytes_per_second) }}</td>
              <td>{{ formatScalar(point.disk_read_ops_per_second) }} io/s</td>
              <td>{{ formatScalar(point.disk_write_ops_per_second) }} io/s</td>
              <td>{{ formatCount(point.context_switches_per_second) }}/s</td>
              <td>{{ formatCount(point.processes_total) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-state">{{ loading ? t("monitoringLoading") : t("monitoringNoHistory") }}</div>
    </article>

    <div v-show="activeView === 'processes' || activeView === 'system'" class="monitoring-lower-grid">
      <article v-show="activeView === 'processes'" class="panel monitoring-node-panel">
        <div class="panel-head">
          <div><p>{{ t("monitoringProcess") }}</p><h3>{{ t("monitoringProcessTableHint") }}</h3></div>
        </div>
        <div class="monitoring-process-list monitoring-process-list-standalone">
        <div v-if="topProcesses.length" class="table-shell">
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
              <tr v-for="item in topProcesses" :key="`${item.node_id}-${item.pid}`">
                <td v-if="scope === 'cluster'"><strong>{{ item.node_name }}</strong></td>
                <td>{{ item.pid }}</td>
                <td>{{ item.name }}</td>
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
      </div>
      </article>

      <article v-show="activeView === 'system'" class="panel monitoring-node-panel">
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
              <tr v-for="item in filesystems" :key="`${item.node_id}-${item.device}-${item.mountpoint}`">
                <td v-if="scope === 'cluster'"><strong>{{ item.node_name }}</strong></td>
                <td>{{ item.mountpoint }}</td>
                <td>{{ item.device || "-" }}<span v-if="item.fstype"> · {{ item.fstype }}</span></td>
                <td>{{ formatPercent(item.used_percent) }}</td>
                <td>{{ formatBytes(item.used_bytes) }} / {{ formatBytes(item.total_bytes) }}</td>
                <td>{{ formatBytes(item.available_bytes) }}</td>
              </tr>
              <tr v-if="!filesystems.length"><td :colspan="scope === 'cluster' ? 6 : 5" class="table-empty">{{ t("monitoringNoFilesystem") }}</td></tr>
            </tbody>
          </table>
        </div>
      </article>
    </div>
  </section>
</template>
