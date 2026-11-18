<script setup>
import { computed, ref, watch } from "vue";
import { ArrowDown, ArrowUp, Download } from "@lucide/vue";
import MonitoringChart from "@/components/MonitoringChart.vue";
import TablePagination from "@/components/TablePagination.vue";
import { useI18n } from "@/lib/i18n";
import { formatMetric, numericMetric } from "@/lib/monitoringSeries";
import { formatDateTime } from "@/lib/time";

const props = defineProps({
  points: { type: Array, required: true },
  query: { type: Object, required: true },
  scopeLabel: { type: String, required: true },
  sampleInterval: { type: Number, required: true },
  loading: Boolean,
  failed: Boolean,
});

const { t, state } = useI18n();
const groups = {
  resources: {
    label: "monitoringHistoryResources",
    columns: [
      { key: "cpu_percent", label: "monitoringCPU", unit: "percent", csvUnit: "%", trend: true },
      { key: "cpu_iowait_percent", label: "monitoringCPUIowait", unit: "percent", csvUnit: "%" },
      { key: "memory_percent", label: "monitoringMemory", unit: "percent", csvUnit: "%", trend: true },
      { key: "load_1", label: "monitoringLoad1", unit: "number" },
    ],
  },
  network: {
    label: "monitoringNetworkTrend",
    columns: [
      { key: "rx_bytes_per_second", label: "monitoringNetworkInShort", unit: "rate", csvUnit: "B/s", trend: true },
      { key: "tx_bytes_per_second", label: "monitoringNetworkOutShort", unit: "rate", csvUnit: "B/s", trend: true },
    ],
  },
  disk: {
    label: "monitoringDiskTrend",
    columns: [
      { key: "disk_read_bytes_per_second", label: "monitoringDiskRead", unit: "rate", csvUnit: "B/s", trend: true },
      { key: "disk_write_bytes_per_second", label: "monitoringDiskWrite", unit: "rate", csvUnit: "B/s", trend: true },
      { key: "disk_read_ops_per_second", label: "monitoringDiskReadOps", unit: "iops", csvUnit: "io/s" },
      { key: "disk_write_ops_per_second", label: "monitoringDiskWriteOps", unit: "iops", csvUnit: "io/s" },
    ],
  },
  system: {
    label: "monitoringTabSystem",
    columns: [
      { key: "processes_total", label: "monitoringProcessTotal", unit: "count", trend: true },
      { key: "context_switches_per_second", label: "monitoringContextSwitch", unit: "count", csvUnit: "/s" },
    ],
  },
};
const group = ref("resources");
const descending = ref(true);
const page = ref(0);
const pageSize = ref(20);
const viewport = ref(null);
const columns = computed(() => groups[group.value].columns);
const trendColumns = computed(() => columns.value.filter((column) => column.trend));
const series = computed(() => trendColumns.value.map(({ key, label }) => ({ key, label: t(label) })));
const rows = computed(() => descending.value ? props.points.slice().reverse() : props.points);
const visibleRows = computed(() => rows.value.slice(page.value * pageSize.value, (page.value + 1) * pageSize.value));
const emptyLabel = computed(() => t(props.loading ? "monitoringLoading" : props.failed ? "monitoringHistoryUnavailable" : "monitoringHistoryEmptyRange"));

function resetPage() {
  page.value = 0;
  if (viewport.value) viewport.value.scrollTop = 0;
}

watch(() => [props.query.node, props.query.range, props.query.from, props.query.to], resetPage);
watch([descending, group, pageSize], resetPage);
watch(() => rows.value.length, (count) => {
  page.value = Math.min(page.value, Math.max(0, Math.ceil(count / pageSize.value) - 1));
});
watch(page, () => { if (viewport.value) viewport.value.scrollTop = 0; });

function displayTime(value) {
  return formatDateTime(value, state.locale);
}

function displayMetric(point, column) {
  const value = point[column.key];
  const display = formatMetric(value, column.unit, false);
  return column.csvUnit === "/s" && numericMetric(value) !== null ? `${display}/s` : display;
}

function exportRows() {
  // CSV uses machine-readable timestamps and numbers so spreadsheet filters
  // and thresholds work independently of the console's language or zone.
  const quote = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const scopeLabel = /^[\s]*[=+\-@]/.test(props.scopeLabel) ? `'${props.scopeLabel}` : props.scopeLabel;
  const header = [`${t("monitoringHistoryTime")} (ISO 8601)`, t("monitoringHistoryScope"), ...columns.value.map(
    (column) => column.csvUnit ? `${t(column.label)} (${column.csvUnit})` : t(column.label),
  )];
  const data = rows.value.map((point) => [point.timestamp, scopeLabel, ...columns.value.map((column) => numericMetric(point[column.key]))]);
  const csv = `\uFEFF${[header, ...data].map((row) => row.map(quote).join(",")).join("\r\n")}`;
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `nodewall-monitoring-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
</script>

<template>
  <div class="monitoring-history-workspace workspace-fill">
    <article class="panel workspace-panel history-trend-panel">
      <div class="panel-head">
        <h3>{{ t("monitoringHistoryTrend") }}</h3>
        <label class="history-metric-filter">
          <span>{{ t("monitoringHistoryMetric") }}</span>
          <select v-model="group">
            <option v-for="(item, key) in groups" :key="key" :value="key">{{ t(item.label) }}</option>
          </select>
        </label>
      </div>
      <template v-if="points.length">
        <MonitoringChart
          :key="group"
          :points="points"
          :series="series"
          :sample-interval="sampleInterval"
          :unit="trendColumns[0].unit"
          :height="184"
          fit-height
        />
        <dl class="history-coverage">
          <div><dt>{{ t("monitoringHistoryFirst") }}</dt><dd>{{ displayTime(points[0].timestamp) }}</dd></div>
          <div><dt>{{ t("monitoringHistoryLast") }}</dt><dd>{{ displayTime(points.at(-1).timestamp) }}</dd></div>
        </dl>
      </template>
      <div v-else class="empty-state" role="status">{{ emptyLabel }}</div>
    </article>

    <article class="panel workspace-panel history-sample-panel" :aria-busy="loading">
      <div class="panel-head">
        <div>
          <h3>{{ t("monitoringHistorySamples") }}</h3>
          <p class="history-sample-meta">{{ scopeLabel }} · {{ t("monitoringSamples", { count: points.length }) }}<template v-if="points.length"> · {{ t("monitoringHistoryInterval", { seconds: sampleInterval }) }}</template></p>
        </div>
        <button type="button" class="ghost-button" :disabled="!points.length" @click="exportRows">
          <Download :size="16" aria-hidden="true" />{{ t("monitoringHistoryExport") }}
        </button>
      </div>
      <div v-if="rows.length" ref="viewport" class="table-shell history-sample-table" tabindex="0" role="region" :aria-label="t('monitoringHistorySamples')">
        <table class="console-table">
          <thead>
            <tr>
              <th scope="col" :aria-sort="descending ? 'descending' : 'ascending'">
                <button type="button" class="history-sort-button" @click="descending = !descending">
                  {{ t("monitoringHistoryTime") }}<component :is="descending ? ArrowDown : ArrowUp" :size="14" aria-hidden="true" />
                </button>
              </th>
              <th v-for="column in columns" :key="column.key" scope="col">{{ t(column.label) }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="point in visibleRows" :key="point.timestamp">
              <td><time :datetime="point.timestamp">{{ displayTime(point.timestamp) }}</time></td>
              <td v-for="column in columns" :key="column.key">{{ displayMetric(point, column) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-state" role="status">{{ emptyLabel }}</div>
      <TablePagination v-model:page="page" v-model:page-size="pageSize" :total="rows.length" :page-sizes="[20, 50, 100]" />
    </article>
  </div>
</template>
