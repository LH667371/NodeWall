<script setup>
import { computed } from "vue";
import MonitoringChart from "@/components/MonitoringChart.vue";

const props = defineProps({
  points: { type: Array, default: () => [] },
  tone: { type: String, default: "visit" },
  height: { type: Number, default: 164 },
  label: { type: String, default: "" },
  unit: { type: String, default: "count" },
});
const source = computed(() => props.points.map((point, index) => ({ timestamp: point.key ?? index, value: point.value })));
const series = computed(() => [{ key: "value", label: props.label || (props.tone === "block" ? "拦截" : "数值"), color: props.tone === "block" ? "#c94f69" : "#009b8d" }]);
</script>

<template>
  <div class="trend-line" :class="`trend-line-${tone}`">
    <MonitoringChart :points="source" :series="series" :unit="unit" :height="height" :compact="height <= 72" :show-legend="false" />
  </div>
</template>
