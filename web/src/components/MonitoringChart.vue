<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

const props = defineProps({
  points: { type: Array, default: () => [] },
  series: { type: Array, default: () => [] },
  unit: { type: String, default: "percent" },
  maxValue: { type: Number, default: 0 },
  height: { type: Number, default: 190 },
});

const defaultWidth = 720;
const paddingTop = 16;
const paddingRight = 18;
const paddingBottom = 30;
const paddingLeft = 58;
const hoverIndex = ref(-1);
const chartHost = ref(null);
const chartWidth = ref(defaultWidth);
let resizeObserver = null;

const source = computed(() => (Array.isArray(props.points) ? props.points : []));
const valueMax = computed(() => {
  const values = props.series.flatMap((item) => source.value.map((point) => Number(point?.[item.key] || 0)));
  return Math.max(1, Number(props.maxValue) || 0, ...values);
});
const innerWidth = computed(() => chartWidth.value - paddingLeft - paddingRight);
const innerHeight = computed(() => props.height - paddingTop - paddingBottom);
const yTicks = computed(() => [valueMax.value, valueMax.value / 2, 0]);

function xAt(index) {
  return paddingLeft + (source.value.length <= 1 ? innerWidth.value / 2 : (innerWidth.value * index) / (source.value.length - 1));
}

function yAt(value) {
  return paddingTop + innerHeight.value - (Math.max(0, Number(value) || 0) / valueMax.value) * innerHeight.value;
}

const normalizedSeries = computed(() => props.series.map((item) => {
  const points = source.value.map((point, index) => ({
    x: xAt(index),
    y: yAt(point?.[item.key]),
    value: Number(point?.[item.key] || 0),
  }));
  return {
    ...item,
    points,
    path: points.map((point, index) => `${index ? "L" : "M"}${point.x},${point.y}`).join(" "),
  };
}));

const activePoint = computed(() => source.value[hoverIndex.value] || null);
const tooltipX = computed(() => {
  if (!activePoint.value) return 0;
  const rightEdge = Math.max(paddingLeft, chartWidth.value - 170);
  return Math.max(paddingLeft, Math.min(xAt(hoverIndex.value) - 72, rightEdge));
});
const tooltipY = computed(() => {
  if (!activePoint.value) return 0;
  const top = Math.min(...normalizedSeries.value.map((item) => item.points[hoverIndex.value]?.y ?? props.height / 2));
  return Math.max(6, top - tooltipHeight.value);
});
// Keep a visible bottom inset so the last metric does not sit against the
// tooltip edge, especially on charts with three or more series.
const tooltipHeight = computed(() => props.series.length * 17 + 25);

function formatValue(value) {
  const number = Math.max(0, Number(value) || 0);
  if (props.unit === "percent") return `${number.toFixed(number >= 10 ? 0 : 1).replace(/\.0$/, "")}%`;
  if (props.unit === "number") return number.toFixed(number >= 10 ? 0 : 2).replace(/\.0+$/, "");
  if (props.unit === "count") return formatCompact(number);
  if (props.unit === "iops") return `${formatCompact(number)} io/s`;
  if (props.unit === "milliseconds") return `${formatCompact(number)} ms`;
  if (props.unit === "bytes") return formatBytes(number);
  const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
  let scaled = number;
  let index = 0;
  while (scaled >= 1024 && index < units.length - 1) {
    scaled /= 1024;
    index += 1;
  }
  const digits = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(digits).replace(/\.0+$/, "")} ${units[index]}`;
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let number = Math.max(0, Number(value) || 0);
  let index = 0;
  while (number >= 1024 && index < units.length - 1) {
    number /= 1024;
    index += 1;
  }
  const digits = number >= 100 ? 0 : number >= 10 ? 1 : 2;
  return `${number.toFixed(digits).replace(/\.0+$/, "")} ${units[index]}`;
}

function formatCompact(value) {
  const number = Math.max(0, Number(value) || 0);
  if (number >= 1000000000) return `${(number / 1000000000).toFixed(1).replace(/\.0$/, "")} G`;
  if (number >= 1000000) return `${(number / 1000000).toFixed(1).replace(/\.0$/, "")} M`;
  if (number >= 1000) return `${(number / 1000).toFixed(1).replace(/\.0$/, "")} K`;
  return number.toFixed(number >= 100 ? 0 : number >= 10 ? 1 : 2).replace(/\.0+$/, "");
}

function formatTime(value, fallback = "-") {
  const date = new Date(value || 0);
  if (Number.isNaN(date.getTime())) return fallback;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function onPointerMove(event) {
  if (!source.value.length) return;
  const rect = event.currentTarget?.getBoundingClientRect?.();
  if (!rect) return;
  const x = ((event.clientX - rect.left) / Math.max(rect.width, 1)) * chartWidth.value;
  let nearest = 0;
  let distance = Number.POSITIVE_INFINITY;
  source.value.forEach((_, index) => {
    const next = Math.abs(xAt(index) - x);
    if (next < distance) {
      nearest = index;
      distance = next;
    }
  });
  hoverIndex.value = nearest;
}

function updateChartWidth(width) {
  if (!Number.isFinite(width) || width <= 0) return;
  // Keep the SVG viewBox in the same aspect ratio as its rendered box. With a
  // fixed viewBox stretched to a wide dashboard panel, axis text becomes
  // horizontally distorted even though the line still looks correct.
  chartWidth.value = Math.max(240, Math.round(width));
}

onMounted(() => {
  if (!chartHost.value) return;
  updateChartWidth(chartHost.value.getBoundingClientRect().width);
  if (typeof ResizeObserver === "undefined") return;
  resizeObserver = new ResizeObserver(([entry]) => updateChartWidth(entry.contentRect.width));
  resizeObserver.observe(chartHost.value);
});

onBeforeUnmount(() => {
  resizeObserver?.disconnect();
  resizeObserver = null;
});
</script>

<template>
  <div ref="chartHost" class="monitoring-chart" :class="{ 'monitoring-chart-empty': !source.length }">
    <svg :viewBox="`0 0 ${chartWidth} ${height}`" preserveAspectRatio="none" @mousemove="onPointerMove" @mouseleave="hoverIndex = -1">
      <g class="monitoring-chart-grid">
        <line
          v-for="(tick, index) in yTicks"
          :key="`grid-${index}`"
          :x1="paddingLeft"
          :x2="chartWidth - paddingRight"
          :y1="yAt(tick)"
          :y2="yAt(tick)"
        />
      </g>
      <g class="monitoring-chart-axis">
        <text v-for="(tick, index) in yTicks" :key="`tick-${index}`" :x="paddingLeft - 10" :y="yAt(tick) + 4" text-anchor="end">{{ formatValue(tick) }}</text>
        <text :x="paddingLeft" :y="height - 8" text-anchor="start">{{ formatTime(source[0]?.timestamp) }}</text>
        <text :x="chartWidth - paddingRight" :y="height - 8" text-anchor="end">{{ formatTime(source[source.length - 1]?.timestamp) }}</text>
      </g>
      <path v-for="item in normalizedSeries" :key="item.key" :d="item.path" class="monitoring-chart-line" :stroke="item.color" />
      <line v-if="activePoint" :x1="xAt(hoverIndex)" :x2="xAt(hoverIndex)" :y1="paddingTop" :y2="height - paddingBottom" class="monitoring-chart-hover-line" />
      <circle v-for="item in normalizedSeries" :key="`${item.key}-point`" v-if="activePoint" :cx="item.points[hoverIndex]?.x" :cy="item.points[hoverIndex]?.y" r="4" :fill="item.color" class="monitoring-chart-point" />
      <g v-if="activePoint" class="monitoring-chart-tooltip" :transform="`translate(${tooltipX}, ${tooltipY})`">
        <rect width="154" :height="tooltipHeight" rx="8" />
        <text x="12" y="16">{{ formatTime(activePoint.timestamp) }}</text>
        <text v-for="(item, index) in series" :key="`${item.key}-tip`" x="12" :y="33 + index * 17">
          <tspan :fill="item.color">{{ item.label }}</tspan><tspan> {{ formatValue(activePoint[item.key]) }}</tspan>
        </text>
      </g>
    </svg>
    <div v-if="!source.length" class="monitoring-chart-empty-label">暂无数据</div>
  </div>
</template>
