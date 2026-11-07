<script setup>
import MonitoringPage from "@/pages/MonitoringPage.vue";

const props = defineProps({
  store: { type: Object, required: true },
});
</script>

<template>
  <MonitoringPage :store="props.store" />
</template>
