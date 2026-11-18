<script setup>
import { computed } from "vue";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  page: { type: Number, default: 0 },
  pageSize: { type: Number, default: 10 },
  total: { type: Number, default: 0 },
  pageSizes: { type: Array, default: () => [10, 20, 50] },
});

const emit = defineEmits(["update:page", "update:pageSize"]);
const { t } = useI18n();

const pageCount = computed(() => Math.max(1, Math.ceil(Math.max(0, props.total) / Math.max(1, props.pageSize))));
const currentPage = computed(() => Math.min(Math.max(0, props.page), pageCount.value - 1));
const rangeStart = computed(() => props.total === 0 ? 0 : currentPage.value * props.pageSize + 1);
const rangeEnd = computed(() => Math.min(props.total, (currentPage.value + 1) * props.pageSize));

function setPage(value) {
  emit("update:page", Math.min(Math.max(0, Number(value) || 0), pageCount.value - 1));
}

function setPageSize(event) {
  emit("update:pageSize", Math.max(1, Number(event.target.value) || props.pageSize));
  setPage(0);
}
</script>

<template>
  <div v-if="total > 0" class="table-pagination" role="navigation" :aria-label="t('tablePagination')">
    <span class="table-pagination-summary">{{ t("tablePaginationSummary", { start: rangeStart, end: rangeEnd, total }) }}</span>
    <label class="table-pagination-size">
      <span>{{ t("tablePageSize") }}</span>
      <select :value="pageSize" @change="setPageSize">
        <option v-for="size in pageSizes" :key="size" :value="size">{{ size }}</option>
      </select>
    </label>
    <div class="table-pagination-controls">
      <button class="ghost-button" :disabled="currentPage === 0" @click="setPage(currentPage - 1)">{{ t("tablePreviousPage") }}</button>
      <span>{{ t("tablePageNumber", { page: currentPage + 1, pages: pageCount }) }}</span>
      <button class="ghost-button" :disabled="currentPage + 1 >= pageCount" @click="setPage(currentPage + 1)">{{ t("tableNextPage") }}</button>
    </div>
  </div>
</template>
