<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import ChartTooltip from "@/components/ChartTooltip.vue";
import { useI18n } from "@/lib/i18n";
import { formatDateTime, formatTime } from "@/lib/time";
import { formatMetric, metricStatistics, nearestTimeIndex, niceMetricMax, numericMetric, seriesColor } from "@/lib/monitoringSeries";

const props = defineProps({
  points: { type: Array, default: () => [] },
  series: { type: Array, default: () => [] },
  sampleInterval: { type: Number, default: 0 },
  unit: { type: String, default: "percent" },
  maxValue: { type: Number, default: 0 },
  height: { type: Number, default: 210 },
  fitHeight: Boolean,
  compact: Boolean,
  showLegend: { type: Boolean, default: true },
  fill: { type: Boolean, default: true },
});
const { t } = useI18n();
const chartHost = ref(null);
const plotHost = ref(null);
const chartWidth = ref(720);
const measuredHeight = ref(0);
const yAxis = ref(null);
const yAxisWidth = ref(0);
const hoverTime = ref(null);
const pointer = ref({ x: 0, y: 0, plotY: 0 });
const hidden = ref(new Set());
const search = ref("");
let observer, closeTimer, moveFrame;
const axisLabelGap = 10;
const padding = computed(() => props.compact
  ? { left: 2, right: 2, top: 3, bottom: 3 }
  : { left: Math.max(74, yAxisWidth.value + axisLabelGap + 6), right: 16, top: 14, bottom: 30 });
const innerWidth = computed(() => Math.max(1, chartWidth.value - padding.value.left - padding.value.right));
const plotHeight = computed(() => (props.fitHeight && measuredHeight.value) || props.height);
const innerHeight = computed(() => Math.max(1, plotHeight.value - padding.value.top - padding.value.bottom));
const source = computed(() => Array.isArray(props.points) ? props.points : []);
const times = computed(() => source.value.map((point, index) => {
  const value = point?.timestamp;
  const parsed = typeof value === "number" ? value : Date.parse(value);
  return Number.isFinite(parsed) ? parsed : index;
}));
const timeRange = computed(() => [times.value[0] ?? 0, times.value[times.value.length - 1] ?? 0]);
const matching = computed(() => props.series.filter((item) => String(item.label).toLowerCase().includes(search.value.trim().toLowerCase())));
const visible = computed(() => matching.value.filter((item) => !hidden.value.has(item.key)));
const maxValue = computed(() => {
  let peak = 0;
  for (const point of source.value) for (const item of visible.value) peak = Math.max(peak, numericMetric(point?.[item.key]) ?? 0);
  return niceMetricMax(peak, props.maxValue);
});
function xAt(index) {
  const [start, end] = timeRange.value;
  return padding.value.left + (end > start ? (times.value[index] - start) / (end - start) : 0.5) * innerWidth.value;
}
function yAt(value) { return padding.value.top + innerHeight.value * (1 - Math.max(0, Number(value) || 0) / maxValue.value); }
const lines = computed(() => visible.value.map((series) => {
  let path = "", area = "", segment = [];
  const singletons = [];
  const flush = () => {
    if (!segment.length) return;
    const first = segment[0], last = segment[segment.length - 1];
    if (segment.length === 1) singletons.push(first);
    const part = segment.map((point, index) => `${index ? "L" : "M"}${point.x.toFixed(2)},${point.y.toFixed(2)}`).join(" ");
    path += `${part} `;
    area += `${part} L${last.x.toFixed(2)},${yAt(0)} L${first.x.toFixed(2)},${yAt(0)} Z `;
    segment = [];
  };
  source.value.forEach((point, index) => {
    const value = numericMetric(point?.[series.key]);
    if (value === null) { flush(); return; }
    if (props.sampleInterval > 0 && times.value[index] - times.value[index - 1] > props.sampleInterval * 1500) flush();
    segment.push({ x: xAt(index), y: yAt(value) });
  });
  flush();
  return { ...series, color: series.color || seriesColor(series.key), path: path.trim(), area: area.trim(), singletons };
}));
const activeIndex = computed(() => hoverTime.value === null ? -1 : nearestTimeIndex(times.value, hoverTime.value));
const active = computed(() => source.value[activeIndex.value] || null);
const tooltipRows = computed(() => lines.value.map((item) => ({ ...item, value: formatMetric(active.value?.[item.key], props.unit) })));
const tooltipTime = computed(() => {
  if (!active.value) return "";
  const raw = active.value.timestamp;
  return typeof raw === "string" && Number.isFinite(Date.parse(raw)) ? formatDateTime(raw).replaceAll("/", "-") : String(raw ?? "—");
});
const legend = computed(() => matching.value.map((item) => ({ ...item, color: item.color || seriesColor(item.key), ...metricStatistics(source.value, item.key) })));
const yTicks = computed(() => Array.from({ length: 5 }, (_, index) => maxValue.value * (4 - index) / 4));
function measureYAxis() {
  // SVG bounds include the text outside the viewport, so long labels can be
  // measured before the plot makes room for them.
  if (yAxis.value) yAxisWidth.value = Math.ceil(yAxis.value.getBBox().width);
}
const xTicks = computed(() => {
  if (!source.value.length) return [];
  const count = chartWidth.value < 480 ? 2 : 4;
  return Array.from({ length: count }, (_, index) => Math.round((source.value.length - 1) * index / (count - 1))).filter((value, index, list) => list.indexOf(value) === index);
});
function timeLabel(index) {
  const raw = source.value[index]?.timestamp;
  if (typeof raw !== "string" || !Number.isFinite(Date.parse(raw))) return String(raw ?? "—");
  return timeRange.value[1] - timeRange.value[0] >= 86400000 ? formatDateTime(raw, "zh-CN", { month: "2-digit", day: "2-digit", year: undefined, second: undefined }) : formatTime(raw);
}
function toggleSeries(key, event) {
  if (event?.ctrlKey || event?.metaKey || event?.shiftKey) {
    hidden.value = new Set(props.series.filter((item) => item.key !== key).map((item) => item.key));
  } else {
    const next = new Set(hidden.value);
    if (next.has(key)) next.delete(key); else next.add(key);
    hidden.value = next;
  }
}
function keepHover() { window.clearTimeout(closeTimer); }
function clearHover() { keepHover(); hoverTime.value = null; }
function scheduleClear() { keepHover(); closeTimer = window.setTimeout(clearHover, 140); }
function move(event) {
  keepHover();
  const clientX = event.clientX, clientY = event.clientY;
  if (moveFrame) cancelAnimationFrame(moveFrame);
  moveFrame = requestAnimationFrame(() => {
    moveFrame = 0;
    const rect = chartHost.value?.querySelector("svg")?.getBoundingClientRect();
    if (!rect || !source.value.length) return;
    const plotX = (clientX - rect.left) / Math.max(1, rect.width) * chartWidth.value;
    const ratio = Math.max(0, Math.min(1, (plotX - padding.value.left) / innerWidth.value));
    const [start, end] = timeRange.value;
    const index = nearestTimeIndex(times.value, start + ratio * (end - start));
    hoverTime.value = times.value[index];
    pointer.value = { x: clientX, y: clientY, plotY: Math.max(padding.value.top, Math.min(plotHeight.value - padding.value.bottom, clientY - rect.top)) };
  });
}
function escape(event) { if (event.key === "Escape") clearHover(); }
function onScroll(event) {
  if (event.target instanceof Element && event.target.closest(".metric-tooltip")) return;
  clearHover();
}
watch(source, (next) => { if (!next.length) clearHover(); });
watch([yAxis, yTicks, chartWidth, () => props.unit], measureYAxis, { flush: "post" });
onMounted(() => {
  const resize = () => {
    const width = chartHost.value?.getBoundingClientRect().width;
    if (width > 0) chartWidth.value = Math.max(120, Math.round(width));
    if (props.fitHeight) measuredHeight.value = plotHost.value?.clientHeight || 0;
  };
  resize();
  if (typeof ResizeObserver !== "undefined") {
    observer = new ResizeObserver(resize);
    observer.observe(chartHost.value);
    if (props.fitHeight) observer.observe(plotHost.value);
  }
  document.fonts?.ready.then(measureYAxis);
  window.addEventListener("scroll", onScroll, true);
  window.addEventListener("keydown", escape);
});
onBeforeUnmount(() => {
  observer?.disconnect();
  window.clearTimeout(closeTimer);
  if (moveFrame) cancelAnimationFrame(moveFrame);
  window.removeEventListener("scroll", onScroll, true);
  window.removeEventListener("keydown", escape);
});
</script>

<template>
  <div ref="chartHost" class="monitoring-chart" :class="{ 'metric-compact': compact, 'metric-fit-height': fitHeight }">
    <div ref="plotHost" class="metric-plot" :style="fitHeight ? { minHeight: `${height}px` } : { height: `${height}px` }">
      <svg class="metric-chart-svg" :viewBox="`0 0 ${chartWidth} ${plotHeight}`" :style="{ height: fitHeight ? '100%' : `${height}px` }" @pointermove="move" @pointerleave="scheduleClear" role="img" :aria-label="series.map(item => item.label).join(', ')">
        <template v-if="!compact">
          <g class="metric-grid">
            <line v-for="tick in yTicks" :key="tick" :x1="padding.left" :x2="chartWidth - padding.right" :y1="yAt(tick)" :y2="yAt(tick)" />
            <line v-for="index in xTicks" :key="`x-${index}`" :x1="xAt(index)" :x2="xAt(index)" :y1="padding.top" :y2="plotHeight - padding.bottom" />
          </g>
          <g ref="yAxis" class="metric-axis">
            <text v-for="tick in yTicks" :key="tick" :x="padding.left - axisLabelGap" :y="yAt(tick) + 4" text-anchor="end">{{ formatMetric(tick, unit, false) }}</text>
          </g>
          <g class="metric-axis">
            <text v-for="(index, tick) in xTicks" :key="`x-${index}`" :x="xAt(index)" :y="plotHeight - 9" :text-anchor="tick === 0 ? 'start' : tick === xTicks.length - 1 ? 'end' : 'middle'">{{ timeLabel(index) }}</text>
          </g>
        </template>
        <template v-for="line in lines" :key="line.key">
          <path v-if="fill && (compact || lines.length <= 8)" :d="line.area" :fill="line.color" class="metric-area" />
          <path :d="line.path" :stroke="line.color" class="metric-line" />
          <circle v-for="(point, index) in line.singletons" :key="index" :cx="point.x" :cy="point.y" r="2.5" :fill="line.color" />
        </template>
        <g v-if="active" class="metric-crosshair">
          <line :x1="xAt(activeIndex)" :x2="xAt(activeIndex)" :y1="padding.top" :y2="plotHeight - padding.bottom" />
          <line v-if="!compact" :x1="padding.left" :x2="chartWidth - padding.right" :y1="pointer.plotY" :y2="pointer.plotY" />
          <template v-for="line in lines" :key="line.key">
            <circle v-if="numericMetric(active[line.key]) !== null" :cx="xAt(activeIndex)" :cy="yAt(active[line.key])" r="4" :fill="line.color" />
          </template>
        </g>
      </svg>
      <div v-if="!source.length" class="metric-empty">{{ t('monitoringNoHistory') }}</div>
    </div>
    <template v-if="showLegend && !compact">
      <div v-if="series.length > 8 || hidden.size" class="metric-legend-tools">
        <input v-if="series.length > 8" v-model="search" type="search" :placeholder="t('chartFilterSeries')" :aria-label="t('chartFilterSeries')" />
        <button v-if="hidden.size" type="button" @click="hidden = new Set()">{{ t('chartShowAll') }}</button>
      </div>
      <div class="metric-legend-scroll">
        <table class="metric-legend-table">
          <colgroup><col /><col v-for="column in 3" :key="column" class="metric-legend-stat-column" /></colgroup>
          <thead><tr><th>{{ t('chartSeriesName') }}</th><th>{{ t('chartMean') }}</th><th>{{ t('chartLast') }}</th><th>{{ t('chartMax') }}</th></tr></thead>
          <tbody>
            <tr v-for="item in legend" :key="item.key" :class="{ 'metric-series-hidden': hidden.has(item.key) }">
              <td><button type="button" :aria-pressed="!hidden.has(item.key)" :title="t('chartToggleSeries')" @click="toggleSeries(item.key, $event)"><i :style="{ background: item.color }" /><span>{{ item.label }}</span></button></td>
              <td>{{ formatMetric(item.mean, unit) }}</td><td>{{ formatMetric(item.last, unit) }}</td><td>{{ formatMetric(item.max, unit) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
    <ChartTooltip :open="Boolean(active)" :x="pointer.x" :y="pointer.y" :timestamp="tooltipTime" :rows="tooltipRows" @enter="keepHover" @leave="scheduleClear" />
  </div>
</template>

<style scoped>
.monitoring-chart { width: 100%; min-width: 0; min-height: 0; height: auto; margin: 0; flex: 1 1 auto; }
.metric-plot { width: 100%; min-width: 0; position: relative; }
.metric-fit-height { display: flex; flex-direction: column; }
.metric-fit-height .metric-plot { flex: 1 1 auto; }
.metric-fit-height .metric-chart-svg { position: absolute; inset: 0; }
svg.metric-chart-svg { display: block; width: 100%; min-height: 0; max-height: none; overflow: hidden; touch-action: pan-y; }
.metric-grid line { stroke: var(--line, #dce2e8); stroke-width: .7; stroke-dasharray: none; }
.metric-axis text { fill: var(--muted-strong, #536578); font-size: 12px; font-weight: 450; letter-spacing: 0; font-variant-numeric: tabular-nums; }
.metric-area { opacity: .045; pointer-events: none; }
.metric-line { fill: none; stroke-width: 1.65; stroke-linecap: round; stroke-linejoin: round; vector-effect: non-scaling-stroke; pointer-events: none; }
.metric-crosshair { pointer-events: none; }
.metric-crosshair line { stroke: #8795a5; stroke-dasharray: 4 3; stroke-width: 1; vector-effect: non-scaling-stroke; }
.metric-crosshair circle { stroke: var(--bg-panel-strong, #fff); stroke-width: 2; vector-effect: non-scaling-stroke; }
.metric-empty { position: absolute; inset: 0; display: grid; place-items: center; color: var(--muted); font-size: 13px; pointer-events: none; }
.metric-legend-tools { display: flex; gap: 8px; align-items: center; margin: 4px 0 7px; }
.metric-legend-tools input { min-width: 0; width: min(260px, 100%); height: 30px; padding: 4px 9px; border: 1px solid var(--line); border-radius: 4px; background: var(--bg-panel-strong, #fff); color: var(--text); font-size: 12px; }
.metric-legend-tools > button { border: 0; padding: 4px; color: var(--primary, #087f87); background: none; cursor: pointer; font-size: 12px; }
.metric-legend-scroll { overflow: auto; max-height: 176px; min-height: 0; }
.metric-legend-table { width: 100%; min-width: 400px; border-collapse: collapse; table-layout: fixed; font-size: 13px; line-height: 1.5; font-variant-numeric: tabular-nums; }
.metric-legend-stat-column { width: 7.5em; }
.metric-legend-table th { color: var(--muted-strong, #536578); font-weight: 600; position: sticky; top: 0; background: var(--bg-panel-strong, #fff); z-index: 1; }
.metric-legend-table th, .metric-legend-table td { padding: 5px 7px; text-align: right; white-space: nowrap; border-bottom: 1px solid var(--line); color: var(--text); }
.metric-legend-table th:first-child, .metric-legend-table td:first-child { text-align: left; white-space: normal; }
.metric-legend-table td:first-child button { display: flex; align-items: baseline; justify-content: flex-start; gap: 8px; width: 100%; min-width: 0; padding: 0; text-align: left; white-space: normal; border: 0; color: inherit; background: none; font: inherit; cursor: pointer; min-height: 0; height: auto; margin: 0; border-radius: 0; box-shadow: none; line-height: inherit; }
.metric-legend-table td:first-child i { width: 20px; height: 4px; flex: 0 0 20px; align-self: center; border-radius: 2px; }
.metric-legend-table td:first-child span { overflow-wrap: anywhere; min-width: 0; }
.metric-series-hidden td { opacity: .45; }
.metric-compact .metric-area { opacity: .12; }
.metric-compact .metric-line { stroke-width: 1.5; }
@media (max-width: 600px) { .metric-legend-table { font-size: 11px; } .metric-legend-table th, .metric-legend-table td { padding: 5px 4px; } }
</style>
