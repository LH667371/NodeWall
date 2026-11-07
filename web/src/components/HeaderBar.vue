<script setup>
import { computed } from "vue";
import {
  Activity,
  LayoutDashboard,
  LockKeyhole,
  Network,
  ScanSearch,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  Terminal,
} from "@lucide/vue";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  section: { type: String, required: true },
  currentInterface: { type: String, default: "" },
  nodeId: { type: String, default: "" },
  nodes: { type: Array, default: () => [] },
  overviewScope: { type: String, default: "all" },
  clusterAggregate: { type: Object, default: () => ({}) },
  securityFeature: { type: String, default: "firewall" },
});

const emit = defineEmits(["change-node", "change-security-feature", "change-overview-scope"]);

const { t } = useI18n();

const sectionIcons = {
  overview: LayoutDashboard,
  policy: Network,
  cluster: Server,
  logs: ScrollText,
  events: ScrollText,
  monitoring: Activity,
  management: Settings,
  security: ShieldCheck,
  "ssh-console": Terminal,
};

function nodeLabel(item) {
  return item?.name || item?.id || "-";
}

const copy = computed(() => {
  if (props.section === "overview") {
    return props.overviewScope === "node"
      ? { title: t("headerOverviewNodeTitle"), subtitle: "" }
      : { title: t("headerOverviewClusterTitle"), subtitle: "" };
  }
  if (props.section === "policy") {
    return {
      title: t("headerPolicyTitle"),
    };
  }
  if (props.section === "cluster") {
    return {
      title: t("headerClusterTitle"),
    };
  }
  if (props.section === "logs") {
    return {
      title: t("headerLogsTitle"),
    };
  }
  if (props.section === "events") {
    return {
      title: t("headerEventsTitle"),
    };
  }
  if (props.section === "monitoring") {
    return {
      title: t("headerMonitoringTitle"),
    };
  }
  if (props.section === "management") {
    return {
      title: t("headerManagementTitle"),
    };
  }
  if (props.section === "security") {
    return { title: t("headerSecurityTitle") };
  }
  if (props.section === "ssh-console") {
    return { title: t("headerSSHConsoleTitle") };
  }
  return {
    title: t("headerOverviewTitle"),
  };
});

const showTargetNodeSelector = computed(() => ["policy", "logs", "events", "management", "security", "ssh-console"].includes(props.section));
const showSecurityFeatureSwitch = computed(() => props.section === "security");
const sectionIcon = computed(() => sectionIcons[props.section] || LayoutDashboard);
const securityFeatureItems = computed(() => [
  { key: "firewall", title: t("navFirewall"), icon: Network },
  { key: "ssh", title: t("navSSHProtection"), icon: LockKeyhole },
  { key: "malware", title: t("navMalwareScan"), icon: ScanSearch },
]);

function selectOverviewScope(event) {
  const value = String(event?.target?.value || "all");
  if (value === "all") {
    emit("change-overview-scope", "all");
    return;
  }
  emit("change-overview-scope", "node");
  emit("change-node", value);
}
</script>

<template>
  <header class="header-bar">
    <div class="header-title">
      <component :is="sectionIcon" class="header-title-icon" :size="20" stroke-width="1.8" aria-hidden="true" />
      <h2>{{ copy.title }}</h2>
    </div>

    <div class="header-meta">
      <div v-if="showSecurityFeatureSwitch" class="header-security-switch" role="tablist" :aria-label="t('securityFeatureTitle')">
        <button
          v-for="item in securityFeatureItems"
          :key="item.key"
          type="button"
          role="tab"
          :aria-selected="props.securityFeature === item.key"
          :class="{ active: props.securityFeature === item.key }"
          @click="emit('change-security-feature', item.key)"
        >
          <component :is="item.icon" :size="15" stroke-width="1.9" aria-hidden="true" />
          {{ item.title }}
        </button>
      </div>

      <label v-if="props.section === 'overview'" class="header-scope-selector">
        <span>{{ t("overviewScopeLabel") }}</span>
        <select
          :value="props.overviewScope === 'node' ? props.nodeId : 'all'"
          :disabled="!props.nodes.length"
          :aria-label="t('overviewScopeLabel')"
          @change="selectOverviewScope"
        >
          <option value="all">{{ t("overviewScopeCluster") }}</option>
          <option v-for="item in props.nodes" :key="item.id" :value="item.id">{{ nodeLabel(item) }}</option>
        </select>
      </label>

      <label v-else-if="showTargetNodeSelector" class="header-scope-selector">
        <span>{{ t("headerNodeSelect") }}</span>
        <select
          :value="nodeId"
          :disabled="!props.nodes.length"
          :aria-label="t('headerNodeSelect')"
          @change="emit('change-node', $event.target.value)"
        >
          <option v-if="!props.nodes.length" value="">{{ t("headerNodeEmpty") }}</option>
          <option v-for="item in props.nodes" :key="item.id" :value="item.id">{{ nodeLabel(item) }}</option>
        </select>
      </label>
      <button
        v-if="props.section === 'overview' && props.overviewScope === 'node'"
        type="button"
        class="ghost-button compact-button header-overview-back"
        @click="emit('change-overview-scope', 'all')"
      >
        {{ t("overviewBackToCluster") }}
      </button>
    </div>
  </header>
</template>
