<script setup>
import { computed, nextTick, ref, watch } from "vue";
import { ArrowRight, BellRing, Check, ClipboardList, FileText, Search, ShieldAlert, X } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import InfoTip from "@/components/InfoTip.vue";
import TablePagination from "@/components/TablePagination.vue";
import { formatDateTime } from "@/lib/time";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();
const activeTab = ref("pending");
const query = ref("");
const nodeFilter = ref("");
const severityFilter = ref("");
const moduleFilter = ref("");
// Include retained events of any age when opening the pending queue from the badge.
const rangeFilter = ref("all");
const page = ref(0);
const pageSize = ref(20);
const selectedIDs = ref(new Set());
const selectedID = ref("");
const detailOpen = ref(false);
const detailDrawer = ref(null);
function nodeLabel(id) {
  return props.store.state.nodes.find(node => node.id === id)?.name || id;
}
function announce(key, type = "success", params = {}) {
  if (typeof props.store.setNotice === "function") props.store.setNotice(t(key, params), type);
}

function formatTime(value) {
  if (!value) return "-";
  return formatDateTime(value, props.store.state.locale === "en-US" ? "en-US" : "zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function severityLabel(value) {
  return value === "high" ? t("securityHigh") : value === "medium" ? t("securityMedium") : t("securityLow");
}

const rows = computed(() => props.store.eventRows);
const pendingCount = computed(() => props.store.pendingEventCount);
const nodeOptions = computed(() => (props.store.state.nodes || []).map(node => ({ value: node.id, label: node.name || node.id })));
const moduleOptions = computed(() => [
  { value: "firewall", label: t("securityOverviewFirewall") },
  { value: "ssh", label: t("securityOverviewSSH") },
  { value: "malware", label: t("securityOverviewMalware") },
]);
const feedWarning = computed(() => {
  if (props.store.state.eventCenter?.error) return props.store.state.eventCenter.error;
  const unavailable = (props.store.state.eventCenter?.nodes || []).filter(node => Object.keys(node.errors || {}).length).map(node => node.name || node.node_id);
  return unavailable.length ? t("eventsPartialNodes", { nodes: unavailable.join("、") }) : "";
});
// All controls filter the same cluster event feed. None of them write the
// security workspace's node, feature, interface, or direction selection.
const matchingRows = computed(() => {
  const search = query.value.trim().toLowerCase();
  const days = { "24h": 1, "7d": 7 }[rangeFilter.value];
  const rangeStart = days ? Date.now() - days * 86400000 : -Infinity;
  return rows.value.filter((item) => {
    if (nodeFilter.value && item.node !== nodeFilter.value) return false;
    if (severityFilter.value && item.severity !== severityFilter.value) return false;
    if (moduleFilter.value && item.sourceKey !== moduleFilter.value) return false;
    const timestamp = item.time ? new Date(item.time).getTime() : NaN;
    if (Number.isFinite(timestamp) && timestamp < rangeStart) return false;
    return !search || [item.node, nodeLabel(item.node), item.module, item.type, item.description, item.source].join(" ").toLowerCase().includes(search);
  });
});
const filteredRows = computed(() => matchingRows.value.filter(item => activeTab.value === "pending" ? item.status === "pending" : activeTab.value === "audit" ? item.status !== "pending" : true));
const visibleRows = computed(() => filteredRows.value.slice(page.value * pageSize.value, (page.value + 1) * pageSize.value));
const emptyLabel = computed(() => {
  const feed = props.store.state.eventCenter;
  if (!feed.ready) return t(feed.error ? "eventsFeedUnavailable" : "loading");
  if (activeTab.value === "pending" && pendingCount.value > 0) return t("eventsNoMatchingPending", { count: pendingCount.value });
  return t("eventsNoData");
});
const selectedEvent = computed(() => {
  if (!detailOpen.value) return null;
  return filteredRows.value.find((item) => item.id === selectedID.value) || null;
});
const allVisibleSelected = computed(() => visibleRows.value.length > 0 && visibleRows.value.every((item) => selectedIDs.value.has(item.id)));

watch(() => [activeTab.value, query.value, nodeFilter.value, severityFilter.value, moduleFilter.value, rangeFilter.value], () => {
  page.value = 0;
});
watch(visibleRows, (items) => {
  const visibleIDs = new Set(items.map((item) => item.id));
  selectedIDs.value = new Set([...selectedIDs.value].filter((id) => visibleIDs.has(id)));
}, { immediate: true });

watch(filteredRows, (items) => {
  page.value = Math.min(page.value, Math.max(0, Math.ceil(items.length / pageSize.value) - 1));
  if (detailOpen.value && !items.some(item => item.id === selectedID.value)) {
    detailOpen.value = false;
    selectedID.value = "";
  }
});
watch(nodeOptions, (items) => {
  if (nodeFilter.value && !items.some(item => item.value === nodeFilter.value)) nodeFilter.value = "";
});

function selectTab(value) {
  activeTab.value = value;
  selectedIDs.value = new Set();
}

function persistStatus(row, status) {
  return props.store.updateEventDisposition(row.id, row.node, row.sourceKey, status);
}

async function updateSelectedStatus(status) {
  if (!selectedIDs.value.size) return;
  const selected = rows.value.filter((row) => selectedIDs.value.has(row.id));
  await updateRowsStatus(selected, status);
  selectedIDs.value = new Set();
  announce(status === "deferred" ? "eventsDeferredNotice" : "eventsMarkedReadNotice");
}

async function updateRowsStatus(items, status) {
  const queue = [...items];
  const workerCount = Math.min(8, queue.length);
  let cursor = 0;
  const worker = async () => {
    while (cursor < queue.length) {
      const index = cursor;
      cursor += 1;
      await persistStatus(queue[index], status);
    }
  };
  await Promise.all(Array.from({ length: workerCount }, worker));
}

async function ignoreAllVisible() {
  const pending = filteredRows.value.filter((row) => row.status === "pending");
  if (!pending.length) return;
  await updateRowsStatus(pending, "handled");
  selectedIDs.value = new Set();
  announce("eventsIgnoredNotice");
}

async function deferEvent(row) {
  if (!row) return;
  await persistStatus(row, "deferred");
  announce("eventsDeferredNotice");
}

async function handleEvent(row) {
  if (!row) return;
  await persistStatus(row, "handled");
  announce("eventsMarkedReadNotice");
}

function exportAudit() {
  const escapeCell = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
  const headers = [t("recentTime"), t("eventsNode"), t("eventsType"), t("eventsSeverity"), t("securityOverviewDetails"), t("sourceEndpoint"), t("alertsStatus")];
  const lines = filteredRows.value.map((row) => [
    formatTime(row.time),
    nodeLabel(row.node),
    row.type,
    severityLabel(row.severity),
    row.description,
    row.source,
    row.status === "pending" ? t("eventsPending") : row.status === "deferred" ? t("eventsDeferred") : t("alertsHandled"),
  ].map(escapeCell).join(","));
  const csv = `\uFEFF${[headers.map(escapeCell).join(","), ...lines].join("\n")}`;
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `nodewall-events-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  announce("eventsExported");
}

function toggleRow(row) {
  const next = new Set(selectedIDs.value);
  if (next.has(row.id)) next.delete(row.id);
  else next.add(row.id);
  selectedIDs.value = next;
}

function toggleAll() {
  selectedIDs.value = allVisibleSelected.value ? new Set() : new Set(visibleRows.value.map((item) => item.id));
}

async function showEventDetail(row) {
  selectedID.value = row.id;
  detailOpen.value = true;
  await nextTick();
  // Narrow layouts place details below the table, outside the clicked row's viewport.
  const drawer = detailDrawer.value;
  if (drawer && getComputedStyle(drawer).position === "static") drawer.scrollIntoView({ block: "start" });
}

async function openSecurity(row = selectedEvent.value) {
  if (!row) return;
  const targetNode = String(row.node || "");
  if (targetNode && targetNode !== props.store.state.nodeId) await props.store.setNode(targetNode).catch(props.store.handleError);
  props.store.setSection("security");
  props.store.setSecurityFeature(row.sourceKey === "ssh" ? "ssh" : row.sourceKey === "malware" ? "malware" : "firewall");
}

</script>

<template>
  <section class="events-center-page" :class="{ 'has-detail': selectedEvent }">
    <div class="events-center-content">
      <div class="events-page-intro">
        <div>
          <p class="eyebrow">{{ t("navAlerts") }}</p>
          <h1>{{ t("headerEventsTitle") }}</h1>
          <p>{{ t("eventsScopeHint") }}</p>
        </div>
      </div>

      <div class="events-center-tabs" role="tablist" :aria-label="t('headerEventsTitle')">
        <button type="button" role="tab" :aria-selected="activeTab === 'pending'" :class="{ active: activeTab === 'pending' }" @click="selectTab('pending')">
          <BellRing :size="15" />{{ t("eventsPending") }} <b class="events-tab-count">{{ pendingCount }}</b>
        </button>
        <button type="button" role="tab" :aria-selected="activeTab === 'all'" :class="{ active: activeTab === 'all' }" @click="selectTab('all')">
          <ClipboardList :size="15" />{{ t("eventsAll") }}
        </button>
        <button type="button" role="tab" :aria-selected="activeTab === 'audit'" :class="{ active: activeTab === 'audit' }" @click="selectTab('audit')">
          <FileText :size="15" />{{ t("eventsAudit") }}
        </button>
      </div>

      <div class="events-center-filters panel">
        <label><span>{{ t("eventsNode") }}</span><select v-model="nodeFilter"><option value="">{{ t("overviewScopeCluster") }}</option><option v-for="item in nodeOptions" :key="item.value" :value="item.value">{{ item.label }}</option></select></label>
        <label><span>{{ t("eventsType") }}</span><select v-model="moduleFilter"><option value="">{{ t("eventsAll") }}</option><option v-for="item in moduleOptions" :key="item.value" :value="item.value">{{ item.label }}</option></select></label>
        <label><span>{{ t("eventsSeverity") }}</span><select v-model="severityFilter"><option value="">{{ t("alertsAllSeverity") }}</option><option value="high">{{ t("securityHigh") }}</option><option value="medium">{{ t("securityMedium") }}</option><option value="low">{{ t("securityLow") }}</option></select></label>
        <label><span>{{ t("eventsTimeRange") }}</span><select v-model="rangeFilter"><option value="all">{{ t("eventsAllTime") }}</option><option value="24h">{{ t("securityOverviewLast24Hours") }}</option><option value="7d">{{ t("securityOverviewLast7Days") }}</option></select></label>
        <label class="events-center-search"><span>{{ t("eventsSearch") }}</span><div class="input-with-icon"><Search :size="16" /><input v-model="query" type="search" :placeholder="t('eventsSearch')" /></div></label>
      </div>

      <p v-if="feedWarning" class="events-feed-warning" role="status">{{ feedWarning }}</p>

      <article class="panel panel-span-12 events-center-table-panel workspace-fill workspace-panel">
        <div class="events-center-toolbar">
          <span>{{ t("eventsSelected", { count: selectedIDs.size }) }}</span>
          <button class="ghost-button compact-button" type="button" :disabled="!selectedIDs.size" @click="updateSelectedStatus('handled').catch(store.handleError)"><Check :size="14" />{{ t("eventsBatchProcess") }}</button>
          <button class="ghost-button compact-button" type="button" :disabled="!filteredRows.some((item) => item.status === 'pending')" @click="ignoreAllVisible().catch(store.handleError)"><Check :size="14" />{{ t("eventsIgnoreAll") }}</button>
          <button class="ghost-button compact-button" type="button" :disabled="!filteredRows.length" @click="exportAudit"><FileText :size="14" />{{ t("eventsExportAudit") }}</button>
        </div>
        <div class="table-shell events-center-table-shell">
          <table class="console-table events-center-table">
            <thead>
              <tr><th class="select-column"><input type="checkbox" :checked="allVisibleSelected" @change="toggleAll" /></th><th>{{ t("recentTime") }}</th><th>{{ t("eventsNode") }}</th><th>{{ t("eventsType") }}</th><th>{{ t("eventsSeverity") }}</th><th>{{ t("securityOverviewDetails") }}</th><th>{{ t("sourceEndpoint") }}</th><th>{{ t("alertsStatus") }}</th><th>{{ t("policyTableActions") }}</th></tr>
            </thead>
            <tbody>
              <tr v-for="row in visibleRows" :key="row.id" :class="{ selected: row.id === selectedID }" @click="showEventDetail(row)">
                <td class="select-column"><input type="checkbox" :checked="selectedIDs.has(row.id)" @click.stop="toggleRow(row)" /></td>
                <td>{{ formatTime(row.time) }}</td><td><strong>{{ nodeLabel(row.node) }}</strong></td><td>{{ row.type }}</td>
                <td><span class="status-pill events-severity-pill" :class="row.severity">{{ severityLabel(row.severity) }}</span></td>
                <td class="events-description"><InfoTip :text="row.description" ellipsis /></td><td class="events-source"><InfoTip :text="row.source" ellipsis /></td>
                <td><span class="status-pill" :class="{ danger: row.status === 'pending', warning: row.status === 'deferred' }">{{ row.status === "pending" ? t("eventsPending") : row.status === "deferred" ? t("eventsDeferred") : t("alertsHandled") }}</span></td>
                <td><button class="ghost-button compact-button" type="button" :title="t('eventsProcessNow')" :aria-label="t('eventsProcessNow')" @click.stop="openSecurity(row)">{{ t("eventsProcessNow") }} <ArrowRight :size="14" /></button></td>
              </tr>
              <tr v-if="!visibleRows.length"><td colspan="9" class="table-empty">{{ emptyLabel }}</td></tr>
            </tbody>
          </table>
        </div>
        <TablePagination v-model:page="page" v-model:page-size="pageSize" :total="filteredRows.length" />
      </article>
    </div>

    <aside v-if="selectedEvent" ref="detailDrawer" class="events-detail-drawer panel">
      <div class="events-detail-head"><div><p>{{ t("eventsDetail") }}</p><h3>{{ selectedEvent.type }}</h3></div><button class="icon-button" type="button" :aria-label="t('close')" @click="detailOpen = false; selectedID = ''"><X :size="18" /></button></div>
      <span class="status-pill" :class="selectedEvent.severity">{{ severityLabel(selectedEvent.severity) }}</span>
      <dl class="events-detail-list"><div><dt>{{ t("eventsNode") }}</dt><dd>{{ nodeLabel(selectedEvent.node) }}</dd></div><div><dt>{{ t("recentTime") }}</dt><dd>{{ formatTime(selectedEvent.time) }}</dd></div><div><dt>{{ t("sourceEndpoint") }}</dt><dd>{{ selectedEvent.source }}</dd></div><div><dt>{{ t("securityOverviewDetails") }}</dt><dd>{{ selectedEvent.description }}</dd></div></dl>
      <div class="events-detail-note"><ShieldAlert :size="18" /><p>{{ selectedEvent.status === "pending" ? t("securityOverviewProtectionStatus") : selectedEvent.status === "deferred" ? t("eventsDeferred") : t("alertsHandled") }}</p></div>
      <div class="events-detail-actions"><button class="primary-button" type="button" @click="handleEvent(selectedEvent).catch(store.handleError)"><Check :size="15" />{{ t("eventsMarkRead") }}</button><button class="ghost-button" type="button" @click="openSecurity(selectedEvent)">{{ t("eventsProcessNow") }}</button><button class="ghost-button" type="button" @click="deferEvent(selectedEvent).catch(store.handleError)">{{ t("eventsProcessLater") }}</button><button class="ghost-button" type="button" @click="activeTab = 'audit'">{{ t("eventsViewAudit") }}</button></div>
    </aside>
  </section>
</template>
