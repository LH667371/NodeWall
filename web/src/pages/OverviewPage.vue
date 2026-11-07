<script setup>
import { computed, nextTick, ref } from "vue";
import TrendBars from "@/components/TrendBars.vue";
import TrendLine from "@/components/TrendLine.vue";
import { useI18n } from "@/lib/i18n";

const { store } = defineProps({
  store: { type: Object, required: true },
});
const { t } = useI18n();

function summarizeCountries(items = [], field = "total") {
  const map = new Map();
  items.forEach((item) => {
    const rawCode = String(item.country_code || item.geo?.country_code || "").toUpperCase();
    const code = /^[A-Z]{2}$/.test(rawCode) && rawCode !== "ZZ" ? rawCode : "UNKNOWN";
    if (!code) return;
    const name = code === "UNKNOWN" ? t("unknownCountry") : (item.country_name || item.geo?.country_name || code);
    const value = Number(item[field] ?? item.total ?? item.passed ?? item.dropped ?? 0);
    if (!map.has(code)) {
      map.set(code, { country_code: code, country_name: name, total: 0 });
    }
    map.get(code).total += value;
  });
  return [...map.values()].sort((a, b) => b.total - a.total).slice(0, 7);
}

function displaySourceIP(item) {
  return String(item?.source_ip || "-");
}

function formatLogTime(value) {
  if (!value) return "-";
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? "-" : timestamp.toLocaleString("zh-CN");
}

function formatTraffic(value) {
  const number = Number(value || 0);
  const absolute = Math.abs(number);
  const compact = (divisor, suffix) => `${(number / divisor).toFixed(1).replace(/\.0$/, "")}${suffix}`;
  if (absolute >= 1e9) return compact(1e9, "G");
  if (absolute >= 1e6) return compact(1e6, "M");
  if (absolute >= 1e3) return compact(1e3, "K");
  return new Intl.NumberFormat("zh-CN").format(number);
}

function formatPercent(value) {
  const percent = Number(value || 0) * 100;
  return `${percent.toFixed(percent >= 10 ? 0 : 1).replace(/\.0$/, "")}%`;
}

// The agent stores cumulative snapshots. Charts show the rate between
// snapshots so a long-running node does not produce a misleading rising line.
function toRateWave(points = [], field) {
  const source = Array.isArray(points) ? points : [];
  let previous = null;
  return source.slice(-12).map((item, index) => {
    const current = Number(item?.[field] || 0);
    const previousValue = previous?.value ?? current;
    const delta = current >= previousValue ? current - previousValue : current;
    const currentAt = new Date(item?.timestamp || 0).getTime();
    const elapsed = previous?.at && currentAt > previous.at ? (currentAt - previous.at) / 1000 : 0;
    previous = { value: current, at: currentAt };
    return {
      key: item?.timestamp || index,
      value: elapsed > 0 ? delta / elapsed : 0,
    };
  });
}

const aggregate = computed(() => store.state.clusterAggregate || {});
const trafficDetailMode = ref("blocked");
const trafficDetailPanel = ref(null);
const trafficDetailOpen = ref(false);

const recentBlockedLogs = computed(() => {
  const nodeLogs = store.state.overviewScope === "node" ? store.state.interfaceLogs : [];
  const logs = nodeLogs.length ? nodeLogs : (store.state.persistedLogs || []);
  return [...logs]
    .filter((item) => Number(item?.drops ?? item?.count ?? 0) > 0)
    .sort((left, right) => new Date(right?.timestamp || 0).getTime() - new Date(left?.timestamp || 0).getTime())
    .slice(0, 8);
});

const passedSources = computed(() => {
  const items = aggregate.value.top_passed?.length
    ? aggregate.value.top_passed
    : (store.state.insights.top_passed || []);
  return [...items]
    .sort((left, right) => Number(right?.passed || 0) - Number(left?.passed || 0))
    .slice(0, 8);
});

const trafficDetailTitle = computed(() => trafficDetailMode.value === "passed"
  ? t("overviewPassedDetailsTitle")
  : t("overviewRecentBlockedTitle"));

const trafficDetailCount = computed(() => trafficDetailMode.value === "passed"
  ? passedSources.value.length
  : recentBlockedLogs.value.length);

function openTrafficDetails(mode) {
  trafficDetailMode.value = mode === "passed" ? "passed" : "blocked";
  trafficDetailOpen.value = true;
  nextTick(() => trafficDetailPanel.value?.scrollIntoView({ behavior: "smooth", block: "start" }));
}

function closeTrafficDetails() {
  trafficDetailOpen.value = false;
}

function openAllLogs() {
  store.setEventsView("logs");
  store.setSection("events");
}

const nodeNames = computed(() => new Map((store.state.nodes || []).map((item) => [item.id, item.name || item.id])));

const passedWave = computed(() => {
  const base = aggregate.value.trend?.length ? aggregate.value.trend : (store.state.insights.trend || []);
  if (base.length) return toRateWave(base, "passed");
  return Array.from({ length: 12 }, (_, index) => ({
    key: `passed-${index}`,
    value: 0,
  }));
});

const droppedWave = computed(() => {
  const base = aggregate.value.trend?.length ? aggregate.value.trend : (store.state.insights.trend || []);
  if (base.length) return toRateWave(base, "dropped");
  return Array.from({ length: 12 }, (_, index) => ({
    key: `dropped-${index}`,
    value: 0,
  }));
});

const blockedCountries = computed(() => {
  const base = aggregate.value.top_countries?.length ? aggregate.value.top_countries : (store.state.insights.top_countries || []);
  if (base.length) {
    return base.map((item) => ({
      country_code: item.country_code,
      country_name: item.country_name,
      label: item.country_name || item.country_code,
      total: Number(item.dropped || item.total || 0),
    }));
  }
  return [];
});

const visitCountries = computed(() => {
  const base = aggregate.value.top_passed?.length ? aggregate.value.top_passed : (store.state.insights.top_passed || []);
  return summarizeCountries(base, "passed");
});

const peakPassed = computed(() => Math.max(0, ...passedWave.value.map((item) => item.value)));
const peakDropped = computed(() => Math.max(0, ...droppedWave.value.map((item) => item.value)));

const sourceMatrix = computed(() => [
  {
    title: t("overviewCountryPressure"),
    subtitle: "",
    items: blockedCountries.value,
    mode: "ports",
  },
  {
    title: t("overviewHotSources"),
    subtitle: "",
    items: aggregate.value.top_attackers?.length ? aggregate.value.top_attackers : (store.state.insights.top_attackers || []),
    mode: "attackers",
  },
  {
    title: t("overviewHotPorts"),
    subtitle: "",
    items: aggregate.value.top_ports?.length ? aggregate.value.top_ports : (store.state.insights.top_ports || []),
    mode: "ports",
  },
]);

const overviewMetrics = computed(() => {
  const recent = store.state.recentStats || {};
  if (store.state.overviewScope === "node") {
    return {
      passed: Number(recent.recent_passed || 0),
      dropped: Number(recent.recent_dropped || 0),
      dropRate: Number(recent.drop_rate || 0),
    };
  }
  return {
    passed: Number(aggregate.value.recent_passed || 0),
    dropped: Number(aggregate.value.recent_dropped || 0),
    dropRate: Number(aggregate.value.drop_rate || 0),
  };
});

const clusterRows = computed(() => {
  const now = Date.now();
  const rows = (store.state.nodes || []).map((item) => {
    const ts = item?.last_seen_at ? new Date(item.last_seen_at).getTime() : 0;
    const online = ts > 0 && Number.isFinite(ts) && now-ts <= 60 * 1000;
    return {
      id: item.id,
      name: item.name || item.id,
      status: online ? "online" : "offline",
    };
  });
  rows.sort((a, b) => {
    const leftName = String(a.name || a.id || "").toLowerCase();
    const rightName = String(b.name || b.id || "").toLowerCase();
    if (leftName === rightName) {
      return String(a.id || "").toLowerCase().localeCompare(String(b.id || "").toLowerCase());
    }
    return leftName.localeCompare(rightName);
  });
  return rows;
});

const clusterNodeRows = computed(() => {
  const aggregated = Array.isArray(aggregate.value.nodes) ? aggregate.value.nodes : [];
  if (!aggregated.length) return clusterRows.value;
  return aggregated.map((row) => ({
    id: row.id,
    name: row.name || row.id,
    status: row.status || "offline",
  }));
});

const visibleNodeRows = computed(() => {
  if (store.state.overviewScope !== "node") return clusterNodeRows.value;
  return clusterNodeRows.value.filter((item) => item.id === store.state.nodeId);
});

const clusterSummary = computed(() => {
  const rows = clusterNodeRows.value;
  const online = rows.filter((item) => item.status === "online").length;
  return {
    total: rows.length,
    online,
    offline: Math.max(rows.length - online, 0),
  };
});

function fallbackSecuritySnapshot() {
  return {
    id: store.state.nodeId,
    name: store.currentNode?.name || store.state.nodeId || "-",
    summary: store.state.securitySummary || {},
    scan: store.state.securitySummary?.scan || { status: "idle", findings: [] },
    ssh: store.state.sshProtection || {},
  };
}

const securityOverviewRows = computed(() => {
  const records = Array.isArray(store.state.securityOverviewNodes) ? store.state.securityOverviewNodes : [];
  const fallback = fallbackSecuritySnapshot();
  if (store.state.overviewScope === "node") {
    return [records.find((item) => item.id === store.state.nodeId) || fallback];
  }
  if (records.length) return records;
  return (store.state.nodes || []).map((item) => item.id === store.state.nodeId
    ? fallback
    : { id: item.id, name: item.name || item.id, summary: {}, scan: { status: "idle", findings: [] }, ssh: {} });
});

function checkStatus(snapshot, checkID) {
  return (snapshot?.summary?.checks || []).find((item) => item.id === checkID)?.status || "unknown";
}

const securitySnapshotByNode = computed(() => new Map(
  securityOverviewRows.value.map((item) => [item.id, item]),
));

const securityNodeRows = computed(() => visibleNodeRows.value.map((row) => {
  const snapshot = securitySnapshotByNode.value.get(row.id);
  const findings = Array.isArray(snapshot?.scan?.findings) ? snapshot.scan.findings.length : 0;
  const scanState = String(snapshot?.scan?.status || "idle");
  const scanStatus = findings
    ? t("securityReview")
    : scanState === "running"
      ? t("securityScanning")
      : scanState === "failed"
        ? t("securityFailed")
        : scanState === "completed"
          ? t("securityNormal")
          : t("securityIdle");
  return {
    ...row,
    firewallHealthy: checkStatus(snapshot, "xdp") === "ok",
    sshKnown: Boolean(snapshot?.ssh?.settings),
    sshEnabled: Boolean(snapshot?.ssh?.settings?.enabled),
    scanCompleted: scanState === "completed",
    scanFailed: scanState === "failed",
    scanStatus,
    findings,
  };
}));

const protectionSummary = computed(() => {
  const rows = securityOverviewRows.value;
  const total = rows.length;
  const firewallHealthy = rows.filter((item) => checkStatus(item, "xdp") === "ok").length;
  const sshEnabled = rows.filter((item) => item.ssh?.settings?.enabled).length;
  const scanCompleted = rows.filter((item) => item.scan?.status === "completed").length;
  const findings = rows.reduce((sum, item) => sum + Number((item.scan?.findings || []).length), 0);
  const sshBlocks = rows.reduce((sum, item) => sum + Number((item.ssh?.active_blocks || []).length), 0);
  return {
    total,
    firewallHealthy,
    sshEnabled,
    scanCompleted,
    findings,
    sshBlocks,
  };
});

const protectionCards = computed(() => {
  const summary = protectionSummary.value;
  const total = summary.total || 0;
  const ratio = (value) => total ? `${value}/${total}` : "-";
  return [
    {
      key: "firewall",
      title: t("navFirewall"),
      value: ratio(summary.firewallHealthy),
      note: t("overviewProtectionFirewallNote"),
      status: total && summary.firewallHealthy === total ? t("securityNormal") : t("securityReview"),
      tone: total && summary.firewallHealthy === total ? "ok" : "review",
    },
    {
      key: "ssh",
      title: t("navSSHProtection"),
      value: ratio(summary.sshEnabled),
      note: t("overviewProtectionSSHNote", { count: summary.sshBlocks }),
      status: total && summary.sshEnabled === total ? t("enabled") : t("disabled"),
      tone: total && summary.sshEnabled === total ? "ok" : "review",
    },
    {
      key: "malware",
      title: t("navMalwareScan"),
      value: String(summary.findings),
      note: t("overviewProtectionScanNote", { completed: summary.scanCompleted, total }),
      status: summary.findings ? t("securityReview") : (summary.scanCompleted ? t("securityNormal") : t("securityIdle")),
      tone: summary.findings ? "review" : "ok",
    },
  ];
});

function openProtection(key) {
  store.setSection("security");
  store.setSecurityFeature(key);
}

function openNodeDetail(row) {
  if (!row?.id) return;
  store.setOverviewScope("node");
  store.setNode(row.id).catch(store.handleError);
}
</script>

<template>
  <section class="page-grid overview-page">
    <article class="panel panel-span-12 overview-node-panel">
      <div class="panel-head">
        <div>
          <h3>{{ store.state.overviewScope === "all" ? t("overviewClusterSubtitle") : `${t("overviewScopeNode")} · ${store.currentNode?.name || store.state.nodeId}` }}</h3>
        </div>
        <div class="panel-tags">
          <span class="tag">{{ t("overviewNodes", { count: clusterSummary.total }) }}</span>
          <span class="tag accent">{{ t("overviewOnline", { count: clusterSummary.online }) }}</span>
          <span v-if="clusterSummary.offline" class="tag danger">{{ t("overviewOffline", { count: clusterSummary.offline }) }}</span>
        </div>
      </div>
      <div class="table-shell">
        <table class="console-table cluster-overview-table">
          <thead>
            <tr>
              <th>{{ t("headerNode") }}</th>
              <th>{{ t("status") }}</th>
              <th>{{ t("navFirewall") }}</th>
              <th>{{ t("navSSHProtection") }}</th>
              <th>{{ t("securityScanStatus") }}</th>
              <th>{{ t("securityFindings") }}</th>
              <th>{{ t("policyTableActions") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in securityNodeRows" :key="row.id" class="cluster-node-row" @click="openNodeDetail(row)">
              <td>
                <strong>{{ row.name }}</strong>
              </td>
              <td><span class="status-pill" :class="{ danger: row.status === 'offline' }">{{ row.status === "online" ? t("clusterOnline") : t("clusterOffline") }}</span></td>
              <td><span class="status-pill" :class="{ accent: row.firewallHealthy, danger: !row.firewallHealthy }">{{ row.firewallHealthy ? t("securityNormal") : t("securityReview") }}</span></td>
              <td><span class="status-pill" :class="{ accent: row.sshEnabled, danger: row.sshKnown && !row.sshEnabled }">{{ row.sshKnown ? (row.sshEnabled ? t("enabled") : t("disabled")) : t("protectionUnavailable") }}</span></td>
              <td><span class="status-pill" :class="{ danger: row.findings > 0 || row.scanFailed, accent: row.scanCompleted && !row.findings }">{{ row.scanStatus }}</span></td>
              <td>
                <span v-if="row.findings" class="danger-text">{{ row.findings }} {{ t("securityFindings") }}</span>
                <span v-else>0</span>
              </td>
              <td><button class="ghost-button compact-button" @click.stop="openNodeDetail(row)">{{ t("overviewNodeDetail") }}</button></td>
            </tr>
            <tr v-if="!securityNodeRows.length">
              <td colspan="7" class="table-empty">{{ t("noData") }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </article>

    <div class="overview-main-grid">
      <article class="panel panel-span-8 overview-traffic-panel">
        <div class="panel-head compact">
          <div><h3>{{ t("overviewRecentWindow") }}</h3></div>
        </div>
        <div class="overview-stat-row">
          <button type="button" class="overview-stat-button" :title="store.formatNumber(overviewMetrics.passed)" @click="openTrafficDetails('passed')">
            <span>{{ t("overviewRecentPassed") }}</span>
            <strong>{{ formatTraffic(overviewMetrics.passed) }}</strong>
          </button>
          <button type="button" class="overview-stat-button danger" :title="store.formatNumber(overviewMetrics.dropped)" @click="openTrafficDetails('blocked')">
            <span>{{ t("overviewRecentDropped") }}</span>
            <strong>{{ formatTraffic(overviewMetrics.dropped) }}</strong>
          </button>
          <div class="overview-stat-button static">
            <span>{{ t("overviewDropRate") }}</span>
            <strong>{{ formatPercent(overviewMetrics.dropRate) }}</strong>
          </div>
        </div>
        <div class="overview-trend-grid">
          <section class="overview-trend-block">
            <div class="trend-row-head">
              <strong>{{ t("overviewVisitTrend") }}</strong>
              <span>{{ t("overviewPeak", { value: formatTraffic(peakPassed) }) }}</span>
            </div>
            <TrendLine :points="passedWave" tone="visit" :height="140" />
          </section>
          <section class="overview-trend-block">
            <div class="trend-row-head">
              <strong>{{ t("overviewBlockedTrend") }}</strong>
              <span class="danger-text">{{ t("overviewPeak", { value: formatTraffic(peakDropped) }) }}</span>
            </div>
            <TrendLine :points="droppedWave" tone="block" :height="140" />
          </section>
        </div>
      </article>

      <article class="panel panel-span-4 overview-protection-panel">
        <div class="panel-head compact">
          <div><h3>{{ t("overviewProtectionTitle") }}</h3></div>
          <span class="tag">{{ t("overviewProtectionScope", { count: protectionSummary.total }) }}</span>
        </div>
        <div class="overview-protection-list">
          <button v-for="item in protectionCards" :key="item.key" type="button" class="overview-protection-row" :class="item.tone" @click="openProtection(item.key)">
            <span><strong>{{ item.title }}</strong><small>{{ item.note }}</small></span>
            <b>{{ item.value }}</b>
            <em>{{ item.status }}</em>
          </button>
        </div>
      </article>

      <article v-if="trafficDetailOpen" ref="trafficDetailPanel" class="panel panel-span-12 blocked-overview-panel">
      <div class="panel-head">
        <div>
          <h3>{{ trafficDetailTitle }}</h3>
        </div>
        <div class="panel-actions">
          <span class="tag" :class="{ 'danger-tag': trafficDetailMode === 'blocked', accent: trafficDetailMode === 'passed' }">{{ trafficDetailMode === "passed" ? t("overviewPassedDetailsCount", { count: trafficDetailCount }) : t("overviewRecentBlockedCount", { count: trafficDetailCount }) }}</span>
          <button class="ghost-button compact-button" @click="openAllLogs">{{ t("overviewViewAllLogs") }}</button>
          <button class="ghost-button compact-button" @click="closeTrafficDetails">{{ t("close") }}</button>
        </div>
      </div>
      <div v-if="trafficDetailMode === 'blocked' && recentBlockedLogs.length" class="table-shell">
        <table class="console-table blocked-overview-table">
          <thead>
            <tr>
              <th>{{ t("sourceIp") }}</th>
              <th v-if="store.state.overviewScope === 'all'">{{ t("headerNode") }}</th>
              <th>{{ t("port") }}</th>
              <th>{{ t("reason") }}</th>
              <th>{{ t("hitCount") }}</th>
              <th>{{ t("toolbarInterface") }}</th>
              <th>{{ t("recentTime") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in recentBlockedLogs" :key="`${item.interface || '-'}-${displaySourceIP(item)}-${item.port || 0}-${item.timestamp || item.reason}`">
              <td><strong>{{ displaySourceIP(item) }}</strong></td>
              <td v-if="store.state.overviewScope === 'all'">{{ nodeNames.get(item.node_id) || item.node_id || "-" }}</td>
              <td>{{ item.port || "-" }}</td>
              <td>{{ store.formatLogReason(item.reason) }}</td>
              <td class="danger-text">{{ store.formatNumber(Number(item.drops ?? item.count ?? 0)) }}</td>
              <td>{{ item.interface || "-" }}</td>
              <td>{{ formatLogTime(item.timestamp) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else-if="trafficDetailMode === 'passed' && passedSources.length" class="table-shell">
        <table class="console-table blocked-overview-table">
          <thead>
            <tr>
              <th>{{ t("sourceIp") }}</th>
              <th>{{ t("overviewCumulativePassed") }}</th>
              <th>{{ t("overviewCumulativeDropped") }}</th>
              <th>{{ t("overviewTotalTraffic") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in passedSources" :key="`passed-${item.source_ip}`">
              <td><strong>{{ displaySourceIP(item) }}</strong></td>
              <td>{{ store.formatNumber(Number(item.passed || 0)) }}</td>
              <td class="danger-text">{{ store.formatNumber(Number(item.dropped || 0)) }}</td>
              <td>{{ store.formatNumber(Number(item.total || Number(item.passed || 0) + Number(item.dropped || 0))) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-state">{{ trafficDetailMode === "passed" ? t("overviewNoPassed") : t("overviewNoBlocked") }}</div>
      </article>

      <article class="panel panel-span-12 overview-source-panel">
        <div class="panel-head">
          <div><h3>{{ t("overviewSourceMatrixTitle") }}</h3></div>
          <span class="tag">{{ store.state.direction === "egress" ? t("toolbarEgress") : t("toolbarIngress") }}</span>
        </div>
        <div class="overview-ranking-grid">
          <section v-for="section in sourceMatrix" :key="section.title" class="overview-ranking-section">
            <strong>{{ section.title }}</strong>
            <TrendBars :items="section.items" :mode="section.mode" />
          </section>
        </div>
      </article>

    </div>
  </section>
</template>
