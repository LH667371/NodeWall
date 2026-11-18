<script setup>
import { computed, nextTick, onBeforeUnmount, ref, watch } from "vue";

const props = defineProps({ open: Boolean, x: Number, y: Number, timestamp: String, rows: { type: Array, default: () => [] } });
defineEmits(["enter", "leave"]);
const host = ref(null);
const size = ref({ width: 340, height: 100 });
const viewport = ref({ width: typeof window === "undefined" ? 1440 : window.innerWidth, height: typeof window === "undefined" ? 900 : window.innerHeight });
const position = computed(() => {
  let left = props.x + 16, top = props.y + 16;
  if (left + size.value.width > viewport.value.width - 12) left = props.x - size.value.width - 16;
  if (top + size.value.height > viewport.value.height - 12) top = props.y - size.value.height - 16;
  return { left: `${Math.max(8, Math.min(left, viewport.value.width - size.value.width - 8))}px`, top: `${Math.max(8, Math.min(top, viewport.value.height - size.value.height - 8))}px` };
});
let generation = 0;
watch(() => [props.open, props.rows.length, props.timestamp], async () => {
  const current = ++generation;
  if (!props.open) return;
  await nextTick();
  if (current !== generation || !host.value) return;
  const rect = host.value.getBoundingClientRect();
  size.value = { width: rect.width, height: rect.height };
  viewport.value = { width: window.innerWidth, height: window.innerHeight };
}, { flush: "post" });
onBeforeUnmount(() => { generation++; });
</script>

<template>
  <Teleport to="body">
    <div v-if="open" ref="host" class="metric-tooltip" :style="position" role="tooltip" @pointerenter="$emit('enter')" @pointerleave="$emit('leave')" @wheel.stop>
      <div class="metric-tooltip-time">{{ timestamp }}</div>
      <div class="metric-tooltip-values">
        <div v-for="row in rows" :key="row.key" class="metric-tooltip-row">
          <i :style="{ background: row.color }" />
          <span class="metric-tooltip-name">{{ row.label }}</span>
          <strong>{{ row.value }}</strong>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.metric-tooltip { position: fixed; z-index: 12000; width: max-content; min-width: min(260px, calc(100vw - 24px)); max-width: min(520px, calc(100vw - 24px)); max-height: min(540px, calc(100dvh - 16px)); display: flex; flex-direction: column; color: var(--text, #1f2937); background: var(--bg-panel-strong, #fff); border: 1px solid var(--line, #ccd5df); border-radius: 5px; box-shadow: 0 5px 18px #12263a26; font-size: 14px; line-height: 1.5; font-variant-numeric: tabular-nums; pointer-events: auto; overflow: hidden; }
.metric-tooltip-time { flex: 0 0 auto; padding: 10px 13px; border-bottom: 1px solid var(--line, #dce2e8); font-weight: 650; white-space: nowrap; }
.metric-tooltip-values { min-height: 0; padding: 6px 0; overflow-y: auto; overscroll-behavior: contain; }
.metric-tooltip-row { display: grid; grid-template-columns: 18px minmax(0, 1fr) max-content; align-items: baseline; column-gap: 9px; padding: 5px 13px; }
.metric-tooltip-row i { height: 4px; border-radius: 2px; align-self: center; }
.metric-tooltip-name { overflow-wrap: anywhere; color: var(--text, #1f2937); }
.metric-tooltip-row strong { padding-left: 12px; font-weight: 650; color: var(--text, #1f2937); white-space: nowrap; text-align: right; }
</style>
