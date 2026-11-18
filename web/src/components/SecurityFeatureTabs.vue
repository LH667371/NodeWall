<script setup>
import { computed } from "vue";
import { LayoutGrid, Network, ScanSearch, Terminal } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();

const activeFeature = computed(() => props.store.state.securityFeature);
function selectFeature(feature) {
  props.store.setSecurityFeature(feature);
}

const items = computed(() => [
  { key: "overview", title: t("securityOverviewShort"), icon: LayoutGrid },
  { key: "firewall", title: t("navFirewall"), icon: Network },
  { key: "ssh", title: t("navSSHProtection"), icon: Terminal },
  { key: "malware", title: t("navMalwareScan"), icon: ScanSearch },
]);
</script>

<template>
  <nav class="security-feature-tabs" :aria-label="t('securityFeatureTitle')">
    <button
      v-for="item in items"
      :key="item.key"
      type="button"
      :aria-current="activeFeature === item.key ? 'page' : undefined"
      :class="{ active: activeFeature === item.key }"
      @click="selectFeature(item.key)"
    >
      <component :is="item.icon" :size="16" aria-hidden="true" />
      <span>{{ item.title }}</span>
    </button>
  </nav>
</template>
