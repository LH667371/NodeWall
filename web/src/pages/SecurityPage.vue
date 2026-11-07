<script setup>
import { computed } from "vue";
import PolicyPage from "@/pages/PolicyPage.vue";
import MalwareScanPage from "@/pages/MalwareScanPage.vue";
import SSHProtectionPage from "@/pages/SSHProtectionPage.vue";

const props = defineProps({
  store: { type: Object, required: true },
});
const activeFeature = computed(() => ["firewall", "malware", "ssh"].includes(props.store.state.securityFeature)
  ? props.store.state.securityFeature
  : "firewall");
const featureComponent = computed(() => ({ firewall: PolicyPage, malware: MalwareScanPage, ssh: SSHProtectionPage }[activeFeature.value] || PolicyPage));
</script>

<template>
  <component :is="featureComponent" :store="props.store" />
</template>
