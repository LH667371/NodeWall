<script setup>
import { computed, ref, watch } from "vue";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Cpu,
  HardDrive,
  MemoryStick,
  Network,
  ScanSearch,
  ShieldCheck,
  Terminal,
} from "@lucide/vue";
import TrendLine from "@/components/TrendLine.vue";
import MonitoringChart from "@/components/MonitoringChart.vue";
import { formatMetric, numericMetric } from "@/lib/monitoringSeries";
import { useI18n } from "@/lib/i18n";
import { formatTime as formatClockTime } from "@/lib/time";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();
const eventFilter = ref("all");

const aggregate = computed(() => props.store.state.clusterAggregate || {});
const currentNode = computed(() => props.store.currentNode?.value || props.store.currentNode || props.store.state.nodes?.find((item) => item.id === props.store.state.nodeId) || {});
const currentNodeAggregate = computed(() => (Array.isArray(aggregate.value.nodes) ? aggregate.value.nodes : []).find((item) => item.id === props.store.state.nodeId) || {});
const securitySummary = computed(() => props.store.state.securitySummary || {});
const scan = computed(() => securitySummary.value.scan || {});
const ssh = computed(() => props.store.state.sshProtection || {});
const health = computed(() => {
  const iface = props.store.currentInterface?.value ?? props.store.currentInterface ?? props.store.state.defaultInterface ?? "";
  const interfaces = props.store.state.health?.interfaces || [];
  return interfaces.find((item) => item.interface === iface)
    || interfaces.find((item) => item.xdp_attached || item.dataplane_mode === "iptables")
    || interfaces[0]
    || {};
});
const policy = computed(() => props.store.state.policy?.ingress || props.store.state.policy || {});
const pendingCount = computed(() => Number(props.store.pendingEventCount?.value ?? props.store.pendingEventCount ?? 0));

function countRules(input = {}) {
  return [input.rules, input.public_port_rules, input.denied_port_rules, input.allowed_port_rules, input.bypass_cidrs, input.blocked_cidrs, input.icmp_allow_cidrs, input.icmp_blocked_cidrs]
    .reduce((total, list) => total + (Array.isArray(list) ? list.length : 0), 0);
}

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function formatPercent(value) {
  return formatMetric(toNumber(value), "percent", false);
}

function formatCount(value) {
  return new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 0 }).format(Math.max(0, toNumber(value)));
}

function formatRate(value) { return formatMetric(toNumber(value), "rate", false); }

function formatShortTime(value) {
  return formatClockTime(value, props.store.state.locale === "en-US" ? "en-US" : "zh-CN", { hour: "2-digit", minute: "2-digit" });
}

function formatUptime(value) {
  const seconds = Math.max(0, Math.floor(toNumber(value)));
  if (!seconds) return "-";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return String(days) + "天 " + String(hours).padStart(2, "0") + ":" + String(minutes).padStart(2, "0");
  return String(hours).padStart(2, "0") + ":" + String(minutes).padStart(2, "0");
}


const system = computed(() => {
  if (props.store.state.overviewScope === "node") return currentNodeAggregate.value.system_metrics || currentNode.value.system_metrics || {};
  return aggregate.value.system || {};
});
const cpuPercent = computed(() => toNumber(system.value.cpu?.usage_percent ?? system.value.cpu_percent ?? currentNodeAggregate.value.cpu_percent));
const memoryPercent = computed(() => toNumber(system.value.memory?.used_percent ?? system.value.memory_percent ?? currentNodeAggregate.value.memory_percent));
const filesystemPercent = computed(() => {
  if (system.value.filesystems?.length) {
    const total = system.value.filesystems.reduce((sum, item) => sum + toNumber(item.total_bytes), 0);
    const used = system.value.filesystems.reduce((sum, item) => sum + toNumber(item.used_bytes), 0);
    return total > 0 ? used / total * 100 : 0;
  }
  return toNumber(system.value.filesystem_used_percent ?? system.value.average_filesystem_used_percent ?? currentNodeAggregate.value.system_metrics?.filesystem_used_percent);
});
const networkBytes = computed(() => toNumber(system.value.network
  ? toNumber(system.value.network.rx_bytes_per_second) + toNumber(system.value.network.tx_bytes_per_second)
  : toNumber(system.value.rx_bytes_per_second ?? currentNodeAggregate.value.rx_bytes_per_second) + toNumber(system.value.tx_bytes_per_second ?? currentNodeAggregate.value.tx_bytes_per_second)));
const uptime = computed(() => toNumber(system.value.uptime_seconds ?? currentNodeAggregate.value.system_metrics?.uptime_seconds));

const firewallStatus = computed(() => {
  const state = props.store.state;
  if (state.overviewProtectionStatus) return state.overviewProtectionStatus;
  if (state.health?.status === "unavailable") return "unavailable";
  if (health.value.interface) {
    if (!health.value.xdp_attached || health.value.observe_only) return "not_enabled";
    return health.value.policy_enforced || health.value.egress_policy_enforced ? "enforced" : "degraded";
  }
  if (state.health?.status === "ok" && state.health.agent_ok) return "not_enabled";
  return currentNodeAggregate.value.protection_status || (state.interfaceDataStatus === "loading" ? "loading" : "unavailable");
});
const firewallEnabled = computed(() => firewallStatus.value === "enforced");
const firewallKnown = computed(() => ["enforced", "degraded", "not_enabled"].includes(firewallStatus.value));
const firewallStatusLabel = computed(() => t({
  enforced: "protectionEnforced", degraded: "protectionDegraded", not_enabled: "protectionNotEnabled", loading: "protectionLoading",
}[firewallStatus.value] || "protectionUnavailable"));
const firewallDataReady = computed(() => props.store.state.interfaceDataStatus === "ready");
const firewallRules = computed(() => countRules(props.store.state.policy?.ingress || policy.value) + countRules(props.store.state.policy?.egress || {}));
const firewallBlocked = computed(() => toNumber(props.store.state.recentStats?.recent_dropped ?? props.store.state.stats?.dropped));
const sshEnabled = computed(() => ssh.value.settings?.enabled === true);
const malwareThreats = computed(() => Array.isArray(scan.value.findings) ? scan.value.findings.length : 0);
const protectionStatus = computed(() => {
  if (firewallEnabled.value || sshEnabled.value) return t("securityOverviewActive");
  if (props.store.state.interfaceDataStatus === "loading" || ssh.value.loading) return t("protectionLoading");
  return t("securityOverviewReview");
});
const riskLevel = computed(() => {
  const insightRisk = props.store.metrics?.value?.risk || props.store.metrics?.risk || "low";
  if (insightRisk === "high" || malwareThreats.value > 0) return "high";
  if (insightRisk === "medium" || firewallBlocked.value > 0 || (ssh.value.active_blocks || []).length > 0) return "medium";
  return "low";
});
const riskLabel = computed(() => ({ high: t("securityOverviewHighRisk"), medium: t("securityOverviewMediumRisk"), low: t("securityOverviewLowRisk") }[riskLevel.value] || t("securityOverviewLowRisk")));
const rawTrend = computed(() => aggregate.value.trend?.length ? aggregate.value.trend : (props.store.state.insights?.trend || []));
const trafficPoints = computed(() => rawTrend.value.map((item) => ({
  timestamp: item.timestamp, passed: numericMetric(item.passed), dropped: numericMetric(item.dropped),
})));
const trafficSeries = computed(() => [
  { key: "passed", label: t("overviewRecentPassed"), color: "#009b8d" },
  { key: "dropped", label: t("overviewRecentDropped"), color: "#c94f69" },
]);
const resourceHistory = ref([]);
function appendResourceSample() {
  if (!Object.keys(system.value).length) return;
  const timestamp = system.value.captured_at || system.value.timestamp || new Date().toISOString();
  const sample = { timestamp, cpu: cpuPercent.value, memory: memoryPercent.value, disk: filesystemPercent.value, network: networkBytes.value };
  const previous = resourceHistory.value[resourceHistory.value.length - 1];
  if (previous?.timestamp === timestamp) resourceHistory.value = [...resourceHistory.value.slice(0, -1), sample];
  else resourceHistory.value = [...resourceHistory.value.slice(-59), sample];
}
watch(() => [props.store.state.overviewScope, props.store.state.nodeId], () => { resourceHistory.value = []; }, { flush: "sync" });
watch(system, appendResourceSample, { immediate: true });
const resourceCards = computed(() => [
  { key: "cpu", label: t("monitoringCPU"), unit: "percent", value: formatPercent(cpuPercent.value), icon: Cpu },
  { key: "memory", label: t("monitoringMemory"), unit: "percent", value: formatPercent(memoryPercent.value), icon: MemoryStick },
  { key: "disk", label: t("monitoringDisk"), unit: "percent", value: formatPercent(filesystemPercent.value), icon: HardDrive },
  { key: "network", label: t("monitoringNetwork"), unit: "rate", value: formatRate(networkBytes.value), icon: Network },
].map((item) => ({ ...item, points: resourceHistory.value.map((sample) => ({ key: sample.timestamp, value: sample[item.key] })) })));

const events = computed(() => props.store.eventRows
  .filter(item => (props.store.state.overviewScope !== "node" || item.node === props.store.state.nodeId)
    && (eventFilter.value === "all" || item.sourceKey === eventFilter.value))
  .slice(0, 5));
const recentNewEvents = computed(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  return events.value.filter((item) => {
    const timestamp = new Date(item.time || 0).getTime();
    return !Number.isFinite(timestamp) || timestamp >= cutoff;
  }).length;
});

function openSecurity(feature) {
  props.store.setSection("security");
  props.store.setSecurityFeature(feature);
}
function openMonitoring() { props.store.setSection("monitoring"); }
function openEvents() { props.store.setSection("events"); }
function processEvent() { props.store.setSection("events"); }
</script>

<template>
  <section class="overview-design-page">
    <section class="overview-summary-strip" :aria-label="t('overviewSummaryLabel')">
      <div class="overview-summary-item overview-summary-status"><ShieldCheck :size="34" /><span>{{ t("overviewSummarySecurity") }}</span><strong>{{ riskLevel === "low" ? t("securityNormal") : t("securityReview") }}</strong></div>
      <div class="overview-summary-item"><AlertTriangle :size="20" class="danger-icon" /><span>{{ t("overviewSummaryPending") }}</span><strong class="danger-value">{{ pendingCount }}</strong></div>
      <div class="overview-summary-item"><Clock3 :size="20" class="warning-icon" /><span>{{ t("overviewSummaryNew") }}</span><strong class="warning-value">{{ recentNewEvents }}</strong></div>
      <div class="overview-summary-item"><CheckCircle2 :size="20" /><span>{{ t("overviewSummaryProtection") }}</span><strong class="success-value">{{ protectionStatus }}</strong></div>
      <div class="overview-summary-item"><Activity :size="20" /><span>{{ t("overviewSummaryUptime") }}</span><strong>{{ formatUptime(uptime) }}</strong></div>
    </section>

    <section class="overview-module-grid">
      <article class="overview-design-card overview-risk-card"><div class="overview-card-title"><ShieldCheck :size="28" /><h2>{{ t("securityOverviewRiskSummary") }}</h2><span class="overview-risk-badge" :class="riskLevel"><AlertTriangle :size="14" />{{ riskLabel }}</span></div><div class="overview-risk-list"><div><span>{{ t("securityOverviewOpenIssues") }}</span><strong class="danger-value">{{ pendingCount }}</strong><ArrowRight :size="15" /></div><div><span>{{ t("overviewSummaryNew") }}</span><strong class="warning-value">{{ recentNewEvents }}</strong><ArrowRight :size="15" /></div><div><span>{{ t("securityOverviewProtectionStatus") }}</span><strong class="success-value"><CheckCircle2 :size="15" />{{ protectionStatus }}</strong></div></div></article>
      <article class="overview-design-card overview-module-card"><div class="overview-card-title"><Network :size="27" /><h2>{{ t("securityOverviewFirewall") }}</h2><span class="tag" :class="{ accent: firewallEnabled, danger: !firewallKnown }" role="status">{{ firewallStatusLabel }}</span></div><p>{{ t("securityOverviewFirewallCopy") }}</p><div class="overview-module-stats"><div><span>{{ t("securityOverviewRules") }}</span><strong>{{ firewallDataReady ? firewallRules : "—" }}</strong></div><div><span>{{ t("securityOverviewBlocked24h") }}</span><strong class="danger-value">{{ firewallDataReady ? formatCount(firewallBlocked) : "—" }}</strong></div><div><span>{{ t("securityOverviewLastChange") }}</span><strong>{{ formatShortTime(props.store.state.policy?.updated_at) }}</strong></div></div><button class="overview-card-link" type="button" @click="openSecurity('firewall')">{{ t("securityOverviewManageRules") }} <ArrowRight :size="15" /></button></article>
      <article class="overview-design-card overview-module-card"><div class="overview-card-title"><Terminal :size="27" /><h2>{{ t("securityOverviewSSH") }}</h2><span class="overview-card-switch" :class="{ on: sshEnabled }" role="status" :aria-label="sshEnabled ? t('securityOverviewEnabled') : t('securityOverviewDisabled')"><i /></span></div><p>{{ t("securityOverviewSSHCopy") }}</p><div class="overview-module-stats"><div><span>{{ t("securityOverviewAuthAttempts") }}</span><strong>{{ formatCount(ssh.total_bans || ssh.tracked_sources || (ssh.activity || []).length) }}</strong></div><div><span>{{ t("securityOverviewBlockedAttempts") }}</span><strong class="danger-value">{{ formatCount((ssh.active_blocks || []).length) }}</strong></div><div><span>{{ t("securityOverviewActiveRules") }}</span><strong>{{ sshEnabled ? t("securityOverviewRateLimit") : t("securityOverviewDisabled") }}</strong></div></div><button class="overview-card-link" type="button" @click="openSecurity('ssh')">{{ t("securityOverviewConfigureSSH") }} <ArrowRight :size="15" /></button></article>
      <article class="overview-design-card overview-module-card"><div class="overview-card-title"><ScanSearch :size="27" /><h2>{{ t("securityOverviewMalware") }}</h2><span class="overview-card-switch" :class="{ on: scan.status !== 'failed' }" role="status" :aria-label="scan.status !== 'failed' ? t('securityOverviewAvailable') : t('securityOverviewDisabled')"><i /></span></div><p>{{ t("securityOverviewMalwareCopy") }}</p><div class="overview-module-stats"><div><span>{{ t("securityOverviewLastScan") }}</span><strong>{{ formatShortTime(scan.finished_at || scan.started_at) }}</strong></div><div><span>{{ t("securityOverviewThreatsFound") }}</span><strong class="danger-value">{{ malwareThreats }}</strong></div><div><span>{{ t("securityOverviewSignature") }}</span><strong>{{ securitySummary.engine || "NodeWall" }}</strong></div></div><button class="overview-card-link" type="button" @click="openSecurity('malware')">{{ t("securityOverviewRunScan") }} <ArrowRight :size="15" /></button></article>
    </section>

    <section class="overview-resource-strip"><div class="overview-section-head"><div><h2>{{ t("securityResourceHealth") }}</h2><span>{{ currentNode.name || currentNode.id || t("overviewScopeCluster") }}</span></div><button class="overview-text-link" type="button" @click="openMonitoring">{{ t("headerMonitoringTitle") }} <ArrowRight :size="15" /></button></div><div class="overview-resource-grid"><article v-for="item in resourceCards" :key="item.key" class="overview-resource-card"><component :is="item.icon" :size="21" /><div><span>{{ item.label }}</span><strong>{{ item.value }}</strong></div><TrendLine :points="item.points" :label="item.label" :unit="item.unit" tone="visit" :height="46" /></article></div></section>

    <section class="overview-bottom-grid workspace-fill">
      <article class="overview-design-card overview-traffic-card"><div class="overview-section-head"><div><h2>{{ t("overviewTrafficTrendTitle") }}</h2><span>{{ t("overviewTrafficTrendRange") }}</span></div><div class="overview-chart-legend"><i class="passed" />{{ t("overviewRecentPassed") }} <i class="blocked" />{{ t("overviewRecentDropped") }}</div></div><div class="overview-traffic-chart"><MonitoringChart :points="trafficPoints" :series="trafficSeries" unit="count" :height="180" :show-legend="false" /></div><div class="overview-traffic-summary"><div><span>{{ t("overviewTotalTraffic") }}</span><strong>{{ formatCount(toNumber(aggregate.passed) + toNumber(aggregate.dropped)) }}</strong></div><div><span>{{ t("overviewRecentPassed") }}</span><strong class="success-value">{{ formatCount(aggregate.recent_passed) }}</strong></div><div><span>{{ t("overviewRecentDropped") }}</span><strong class="danger-value">{{ formatCount(aggregate.recent_dropped) }}</strong></div></div></article>
      <article class="overview-design-card overview-events-card"><div class="overview-section-head"><div><h2>{{ t("securityOverviewRecentEvents") }}</h2><span>{{ t("eventsScopeHint") }}</span></div><div class="overview-events-tools"><select v-model="eventFilter" :aria-label="t('eventsType')"><option value="all">{{ t("eventsAll") }}</option><option value="firewall">{{ t("securityOverviewFirewall") }}</option><option value="ssh">{{ t("securityOverviewSSH") }}</option><option value="malware">{{ t("securityOverviewMalware") }}</option></select><button class="overview-text-link" type="button" @click="openEvents">{{ t("eventsAll") }} <ArrowRight :size="15" /></button></div></div><div class="overview-events-table-wrap"><table class="overview-events-table"><thead><tr><th>{{ t("recentTime") }}</th><th>{{ t("eventsType") }}</th><th>{{ t("eventsSeverity") }}</th><th>{{ t("securityOverviewDetails") }}</th><th>{{ t("sourceEndpoint") }}</th><th>{{ t("policyTableActions") }}</th></tr></thead><tbody><tr v-for="item in events" :key="item.id"><td>{{ formatShortTime(item.time) }}</td><td>{{ item.type }}</td><td><span class="overview-severity" :class="item.severity">{{ item.severity === "high" ? t("securityHigh") : item.severity === "medium" ? t("securityMedium") : t("securityLow") }}</span></td><td class="overview-event-description">{{ item.description }}</td><td>{{ item.source }}</td><td><button class="overview-process-button" type="button" @click="processEvent(item)">{{ t("eventsProcessNow") }}</button></td></tr><tr v-if="!events.length"><td colspan="6" class="table-empty">{{ t("eventsNoData") }}</td></tr></tbody></table></div></article>
    </section>
  </section>
</template>
