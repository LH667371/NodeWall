<script setup>
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  items: { type: Array, default: () => [] },
  mode: { type: String, default: "mixed" },
});
const { t } = useI18n();

function maxValue() {
  return Math.max(
    1,
    ...props.items.map((item) => {
      if (props.mode === "attackers") return Number(item.dropped || 0);
      if (props.mode === "ports") return Number(item.total || 0);
      return Math.max(Number(item.passed || 0), Number(item.dropped || 0));
    }),
  );
}
</script>

<template>
  <div v-if="items.length" class="trend-list">
    <div v-for="item in items" :key="item.timestamp || item.source_ip || item.port" class="trend-row">
      <div class="trend-row-head">
        <span>{{ item.label || item.country_name || item.source_ip || `:${item.port}` }}</span>
        <strong>{{ item.total || item.dropped || item.passed || 0 }}</strong>
      </div>
      <div class="trend-track">
        <div
          class="trend-fill"
          :style="{ width: `${Math.max(((item.total || item.dropped || item.passed || 0) / maxValue()) * 100, 8)}%` }"
        ></div>
      </div>
    </div>
  </div>
  <div v-else class="empty-state">{{ t("noData") }}</div>
</template>
