<script setup>
import { computed } from "vue";
import PolicyPage from "@/pages/PolicyPage.vue";
import MalwareScanPage from "@/pages/MalwareScanPage.vue";
import SSHProtectionPage from "@/pages/SSHProtectionPage.vue";
import SecurityOverviewPage from "@/pages/SecurityOverviewPage.vue";

const props = defineProps({
  store: { type: Object, required: true },
});

const activeFeature = computed(() => props.store.state.securityFeature);

const featureComponent = computed(() => activeFeature.value === "overview"
  ? SecurityOverviewPage
  : ({ firewall: PolicyPage, malware: MalwareScanPage, ssh: SSHProtectionPage }[activeFeature.value] || PolicyPage));

</script>

<template>
  <section class="security-workspace">
    <!-- A scan can keep updating the shared security store for a long time.
         Keying the feature view makes a tab switch replace the active page
         immediately instead of reusing the previous scan view. -->
    <component :is="featureComponent" :key="`${props.store.state.nodeId}:${props.store.state.securityFeature}`" :store="props.store" />
  </section>
</template>
