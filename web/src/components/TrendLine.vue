<script setup>
import { computed } from "vue";
import { ref } from "vue";

const props = defineProps({
  points: { type: Array, default: () => [] },
  tone: { type: String, default: "visit" },
  height: { type: Number, default: 164 },
});

const width = 420;
const paddingTop = 12;
const paddingRight = 12;
const paddingBottom = 24;
const paddingLeft = 42;

const yMax = computed(() => {
  const source = Array.isArray(props.points) ? props.points : [];
  if (!source.length) return 1;
  return Math.max(1, ...source.map((item) => Number(item?.value || 0)));
});

const yTicks = computed(() => {
  const max = yMax.value;
  return [max, Math.round(max / 2), 0];
});

const hoverIndex = ref(-1);

const normalizedPoints = computed(() => {
  const source = Array.isArray(props.points) ? props.points : [];
  if (!source.length) return [];
  const values = source.map((item) => Number(item?.value || 0));
  const max = yMax.value;
  const min = Math.min(0, ...values);
  const span = Math.max(1, max - min);
  const innerWidth = width - paddingLeft - paddingRight;
  const innerHeight = props.height - paddingTop - paddingBottom;
  return values.map((value, index) => {
    const x = paddingLeft + (source.length === 1 ? innerWidth / 2 : (innerWidth * index) / (source.length - 1));
    const y = paddingTop + innerHeight - ((value - min) / span) * innerHeight;
    return { x, y, value };
  });
});

const linePath = computed(() => {
  if (!normalizedPoints.value.length) return "";
  return normalizedPoints.value.map((point, index) => `${index ? "L" : "M"}${point.x},${point.y}`).join(" ");
});

const areaPath = computed(() => {
  if (!normalizedPoints.value.length) return "";
  const first = normalizedPoints.value[0];
  const last = normalizedPoints.value[normalizedPoints.value.length - 1];
  const baseline = props.height - paddingBottom;
  return `${linePath.value} L${last.x},${baseline} L${first.x},${baseline} Z`;
});

const startLabel = computed(() => formatXLabel(props.points?.[0]?.key, 0));
const endLabel = computed(() => formatXLabel(props.points?.[props.points.length - 1]?.key, props.points.length - 1));
const activePoint = computed(() => normalizedPoints.value[hoverIndex.value] || null);
const activeRaw = computed(() => (hoverIndex.value >= 0 ? props.points?.[hoverIndex.value] : null));
const hoverLabel = computed(() => {
  if (!activeRaw.value) return "";
  const time = formatXLabel(activeRaw.value.key, hoverIndex.value);
  return `${time} · ${Number(activeRaw.value.value || 0)}`;
});
const tooltipX = computed(() => {
  if (!activePoint.value) return 0;
  const maxX = width - 110;
  return Math.max(52, Math.min(activePoint.value.x - 46, maxX));
});
const tooltipY = computed(() => {
  if (!activePoint.value) return 0;
  return Math.max(8, activePoint.value.y - 34);
});

function onPointerMove(event) {
  if (!normalizedPoints.value.length) {
    hoverIndex.value = -1;
    return;
  }
  const target = event.currentTarget;
  if (!target?.getBoundingClientRect) return;
  const rect = target.getBoundingClientRect();
  const x = ((event.clientX - rect.left) / Math.max(rect.width, 1)) * width;
  let nearest = 0;
  let distance = Number.POSITIVE_INFINITY;
  normalizedPoints.value.forEach((point, index) => {
    const next = Math.abs(point.x - x);
    if (next < distance) {
      nearest = index;
      distance = next;
    }
  });
  hoverIndex.value = nearest;
}

function onPointerLeave() {
  hoverIndex.value = -1;
}

function formatXLabel(raw, index) {
  if (typeof raw === "string") {
    const value = raw.trim();
    if (!value) return `T${index + 1}`;
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) {
      return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
    }
    return value.length > 8 ? value.slice(-8) : value;
  }
  if (typeof raw === "number" && Number.isFinite(raw)) return `T${raw + 1}`;
  return `T${index + 1}`;
}
</script>

<template>
  <div class="trend-line" :class="`trend-line-${tone}`">
    <svg :viewBox="`0 0 ${width} ${height}`" preserveAspectRatio="none" @mousemove="onPointerMove" @mouseleave="onPointerLeave">
      <defs>
        <linearGradient :id="`line-${tone}`" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop v-if="tone === 'block'" offset="0%" stop-color="#ff7f8c" />
          <stop v-if="tone === 'block'" offset="100%" stop-color="#f3a05b" />
          <stop v-if="tone !== 'block'" offset="0%" stop-color="#2dc0b6" />
          <stop v-if="tone !== 'block'" offset="100%" stop-color="#5dbce7" />
        </linearGradient>
      </defs>
      <g class="trend-grid">
        <line
          v-for="(tick, idx) in yTicks"
          :key="`${tone}-grid-${idx}`"
          :x1="paddingLeft"
          :x2="width - paddingRight"
          :y1="paddingTop + ((yMax - tick) / Math.max(yMax, 1)) * (height - paddingTop - paddingBottom)"
          :y2="paddingTop + ((yMax - tick) / Math.max(yMax, 1)) * (height - paddingTop - paddingBottom)"
        />
      </g>
      <g class="trend-axis-labels">
        <text
          v-for="(tick, idx) in yTicks"
          :key="`${tone}-tick-${idx}`"
          :x="paddingLeft - 6"
          :y="paddingTop + ((yMax - tick) / Math.max(yMax, 1)) * (height - paddingTop - paddingBottom) + 4"
          text-anchor="end"
        >
          {{ tick }}
        </text>
        <text :x="paddingLeft" :y="height - 6" text-anchor="start">{{ startLabel }}</text>
        <text :x="width - paddingRight" :y="height - 6" text-anchor="end">{{ endLabel }}</text>
      </g>
      <path v-if="areaPath" :d="areaPath" class="trend-line-area" :fill="`url(#line-${tone})`" />
      <path v-if="linePath" :d="linePath" class="trend-line-stroke" :stroke="`url(#line-${tone})`" />
      <line
        v-if="activePoint"
        :x1="activePoint.x"
        :x2="activePoint.x"
        :y1="paddingTop"
        :y2="height - paddingBottom"
        class="trend-hover-line"
      />
      <circle
        v-for="(point, index) in normalizedPoints"
        :key="`${tone}-${index}`"
        :cx="point.x"
        :cy="point.y"
        r="2.4"
        :fill="`url(#line-${tone})`"
      />
      <circle
        v-if="activePoint"
        :cx="activePoint.x"
        :cy="activePoint.y"
        r="4.2"
        class="trend-hover-point"
        :fill="`url(#line-${tone})`"
      />
      <g v-if="activePoint" class="trend-tooltip" :transform="`translate(${tooltipX}, ${tooltipY})`">
        <rect width="104" height="22" rx="8" ry="8" />
        <text x="52" y="15" text-anchor="middle">{{ hoverLabel }}</text>
      </g>
    </svg>
  </div>
</template>
