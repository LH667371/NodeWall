<script setup>
import { computed, ref } from "vue";
import {
  Activity,
  Bell,
  CircleHelp,
  ChevronDown,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Network,
  ScanSearch,
  Search,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  Terminal,
  UserRound,
} from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import NodeSelector from "@/components/NodeSelector.vue";

const props = defineProps({
  section: { type: String, required: true },
  currentInterface: { type: String, default: "" },
  nodeId: { type: String, default: "" },
  nodes: { type: Array, default: () => [] },
  isNodeOnline: { type: Function, default: null },
  overviewScope: { type: String, default: "all" },
  clusterAggregate: { type: Object, default: () => ({}) },
  securityFeature: { type: String, default: "firewall" },
  managementScope: { type: String, default: "global" },
  authUsername: { type: String, default: "" },
  authRole: { type: String, default: "" },
  alertCount: { type: Number, default: 0 },
});

const emit = defineEmits(["change-node", "change-security-feature", "change-overview-scope", "change-section", "logout", "account"]);

const { t } = useI18n();
const searchOpen = ref(false);
const notificationsOpen = ref(false);
const helpOpen = ref(false);
const accountOpen = ref(false);
const searchQuery = ref("");
let accountCloseTimer = null;

const sectionIcons = {
  overview: LayoutDashboard,
  policy: Network,
  cluster: Server,
  logs: ScrollText,
  events: Bell,
  monitoring: Activity,
  management: Settings,
  account: UserRound,
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
    return { title: t("headerEventsTitle") };
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
  if (props.section === "account") {
    return {
      title: t("headerAccountTitle"),
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

const showTargetNodeSelector = computed(() => ["policy", "security", "ssh-console"].includes(props.section));
const showAllNodeScope = computed(() => ["cluster", "monitoring", "events", "logs"].includes(props.section));
const showGlobalScope = computed(() => props.section === "management");
// Security feature navigation lives inside the protection workspace so the
// header has one stable responsibility: showing the current scope.
const showSecurityFeatureSwitch = computed(() => false);
const sectionIcon = computed(() => props.section === "security" && props.securityFeature === "overview"
  ? LayoutDashboard
  : (sectionIcons[props.section] || LayoutDashboard));
const securityFeatureItems = computed(() => [
  { key: "overview", title: t("securityOverviewShort"), icon: ShieldCheck },
  { key: "firewall", title: t("navFirewall"), icon: Network },
  { key: "ssh", title: t("navSSHProtection"), icon: LockKeyhole },
  { key: "malware", title: t("navMalwareScan"), icon: ScanSearch },
]);

const searchItems = computed(() => [
  { key: "overview", title: t("navOverview"), section: "overview" },
  { key: "cluster", title: t("navNodes"), section: "cluster" },
  { key: "security", title: t("navSecurity"), section: "security" },
  { key: "monitoring", title: t("navMonitoring"), section: "monitoring" },
  { key: "events", title: t("navAlerts"), section: "events" },
  { key: "management", title: t("navSettings"), section: "management" },
  { key: "account", title: t("navAccount"), section: "account" },
].filter((item) => !searchQuery.value.trim() || item.title.toLowerCase().includes(searchQuery.value.trim().toLowerCase())));

function selectOverviewScope(event) {
  const value = String(event?.target?.value || "all");
  if (value === "all") {
    emit("change-overview-scope", "all");
    return;
  }
  emit("change-overview-scope", "node");
  emit("change-node", value);
}

function togglePanel(panel) {
  searchOpen.value = panel === "search" ? !searchOpen.value : false;
  notificationsOpen.value = panel === "notifications" ? !notificationsOpen.value : false;
  helpOpen.value = panel === "help" ? !helpOpen.value : false;
  accountOpen.value = panel === "account" ? !accountOpen.value : false;
}

function clearAccountCloseTimer() {
  if (accountCloseTimer !== null && typeof window !== "undefined") {
    window.clearTimeout(accountCloseTimer);
    accountCloseTimer = null;
  }
}

function openAccountMenu() {
  clearAccountCloseTimer();
  accountOpen.value = true;
}

function scheduleAccountClose() {
  clearAccountCloseTimer();
  if (typeof window === "undefined") return;
  // Keep the menu alive while the pointer crosses the small visual bridge
  // between the avatar and the floating panel.
  accountCloseTimer = window.setTimeout(() => {
    accountOpen.value = false;
    accountCloseTimer = null;
  }, 260);
}

function openAccountFromClick() {
  clearAccountCloseTimer();
  accountOpen.value = true;
}

function openSection(section) {
  emit("change-section", section);
  searchOpen.value = false;
  notificationsOpen.value = false;
  accountOpen.value = false;
}

function openSearch() {
  togglePanel("search");
  if (!searchOpen.value) searchQuery.value = "";
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

      <div v-else-if="showTargetNodeSelector" class="header-scope-selector header-node-selector">
        <span>{{ t("headerNodeSelect") }}</span>
        <NodeSelector
          :model-value="nodeId"
          :nodes="props.nodes"
          :is-online="props.isNodeOnline"
          :aria-label="t('headerNodeSelect')"
          @change="emit('change-node', $event)"
        />
      </div>
      <span v-else-if="showAllNodeScope" class="header-scope-badge">{{ t("headerScopeAllNodes") }}</span>
      <span v-else-if="showGlobalScope" class="header-scope-badge global">{{ props.managementScope === 'node' ? t("settingsNodeScope") : t("headerScopeGlobal") }}</span>
      <button
        v-if="props.section === 'overview' && props.overviewScope === 'node'"
        type="button"
        class="ghost-button compact-button header-overview-back"
        @click="emit('change-overview-scope', 'all')"
      >
        {{ t("overviewBackToCluster") }}
      </button>
    </div>

    <div class="header-actions" :aria-label="t('shellBrand')">
      <div class="header-action-wrap">
        <button type="button" class="header-action-button" :title="t('securityOverviewSearch')" :aria-label="t('securityOverviewSearch')" :aria-expanded="searchOpen" @click="openSearch"><Search :size="18" /></button>
        <div v-if="searchOpen" class="header-popover header-search-popover">
          <div class="header-popover-title">{{ t("headerSearchTitle") }}</div>
          <input v-model="searchQuery" type="search" :placeholder="t('headerSearchPlaceholder')" autofocus />
          <button v-for="item in searchItems" :key="item.key" type="button" class="header-popover-row" @click="openSection(item.section)">{{ item.title }}</button>
          <p v-if="!searchItems.length" class="header-popover-empty">{{ t("headerSearchEmpty") }}</p>
        </div>
      </div>
      <div class="header-action-wrap">
        <button type="button" class="header-action-button header-notification-button" :title="t('securityOverviewNotifications')" :aria-label="t('securityOverviewNotifications')" :aria-expanded="notificationsOpen" @click="togglePanel('notifications')"><Bell :size="18" /><i v-if="props.alertCount" /></button>
        <div v-if="notificationsOpen" class="header-popover header-notification-popover">
          <div class="header-popover-title">{{ t("headerNotificationsTitle") }}</div>
          <p v-if="!props.alertCount" class="header-popover-empty">{{ t("headerNotificationsEmpty") }}</p>
          <p v-else class="header-popover-copy">{{ t("headerNotificationsCount", { count: props.alertCount }) }}</p>
          <button type="button" class="header-popover-link" @click="openSection('events')">{{ t("headerOpenAlerts") }} <ChevronDown :size="14" /></button>
        </div>
      </div>
      <div class="header-action-wrap">
        <button type="button" class="header-action-button" :title="t('securityOverviewHelp')" :aria-label="t('securityOverviewHelp')" :aria-expanded="helpOpen" @click="togglePanel('help')"><CircleHelp :size="18" /></button>
        <div v-if="helpOpen" class="header-popover header-help-popover">
          <div class="header-popover-title">{{ t("headerHelpTitle") }}</div>
          <p class="header-popover-copy">{{ t("headerHelpCopy") }}</p>
          <span class="header-popover-hint">{{ t("headerHelpHint") }}</span>
        </div>
      </div>
      <div class="header-action-wrap header-account-wrap" @mouseenter="openAccountMenu" @mouseleave="scheduleAccountClose">
        <button type="button" class="header-user-button" :title="t('accountGuest')" :aria-expanded="accountOpen" @click="openAccountFromClick">
          <span>{{ (props.authUsername || "NW").slice(0, 2).toUpperCase() }}</span>
          <ChevronDown :size="14" />
        </button>
        <div v-if="accountOpen" class="header-popover header-account-popover" @mouseenter="openAccountMenu" @mouseleave="scheduleAccountClose">
          <div class="header-account-heading"><strong>{{ props.authUsername || t("accountGuest") }}</strong><small>{{ props.authRole === "admin" ? t("roleAdmin") : t("roleViewer") }}</small></div>
          <button type="button" class="header-popover-row" @click="openSection('account')"><UserRound :size="15" />{{ t("headerOpenAccount") }}</button>
          <button v-if="props.authRole === 'admin'" type="button" class="header-popover-row" @click="openSection('users')"><Settings :size="15" />{{ t("headerOpenUsers") }}</button>
          <button type="button" class="header-popover-row danger" @click="emit('logout')"><LogOut :size="15" />{{ t("logout") }}</button>
        </div>
      </div>
    </div>
  </header>
</template>
