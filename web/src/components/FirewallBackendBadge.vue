<script setup>
import { useI18n } from "@/lib/i18n";

defineProps({ mode: { type: String, required: true } });
const { t } = useI18n();
const labels = {
  native: "firewallBackendNative",
  generic: "firewallBackendGeneric",
  loading: "firewallBackendLoading",
  detached: "firewallBackendDetached",
  unknown: "firewallBackendUnknown",
  unavailable: "firewallBackendUnavailable",
};
</script>

<template>
  <span class="firewall-backend-badge" :data-mode="mode">
    {{ mode === "iptables" ? "iptables" : t(labels[mode] || labels.unknown) }}
  </span>
</template>

<style scoped>
.firewall-backend-badge {
  display: inline-flex;
  align-items: center;
  width: fit-content;
  min-height: 22px;
  padding: 2px 7px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--bg-soft);
  color: var(--muted-strong);
  font-size: 11px;
  font-weight: 600;
  line-height: 1.2;
  white-space: nowrap;
}

.firewall-backend-badge:is([data-mode="native"], [data-mode="generic"], [data-mode="iptables"]) {
  color: var(--text);
}
</style>
