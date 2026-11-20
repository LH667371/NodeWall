<script setup>
import { computed, ref } from "vue";
import { ArrowRight, Cpu, HardDrive, MemoryStick, Network, ScanSearch, Server, ShieldCheck, Terminal } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import { formatMetric } from "@/lib/monitoringSeries";
import { formatDateTime, formatTime } from "@/lib/time";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();
const state = props.store.state;
const eventFilter = ref("all");
const eventWindow = ref("24h");
const node = computed(() => props.store.currentNode?.value || props.store.currentNode || state.nodes.find((item) => item.id === state.nodeId) || {});
const nodeOnline = computed(() => props.store.isNodeOnline(node.value));
const summary = computed(() => state.securitySummary);
const scan = computed(() => summary.value.scan || {});
const ssh = computed(() => state.sshProtection);
const findings = computed(() => scan.value.findings || []);
const checks = computed(() => summary.value.checks || []);
const health = computed(() => {
  const name = props.store.currentInterface?.value ?? props.store.currentInterface ?? state.defaultInterface;
  const interfaces = state.health?.interfaces || [];
  return interfaces.find((item) => item.interface === name)
    || interfaces.find((item) => item.xdp_attached || item.dataplane_mode === "iptables")
    || interfaces[0];
});

function ruleCount(policy = {}) {
  return ["rules", "public_port_rules", "denied_port_rules", "allowed_port_rules", "bypass_cidrs", "blocked_cidrs", "icmp_allow_cidrs", "icmp_blocked_cidrs"]
    .reduce((total, field) => total + (Array.isArray(policy?.[field]) ? policy[field].length : 0), 0);
}

function shortDate(value) {
  return value ? formatDateTime(value, state.locale, { year: undefined, month: "short", day: "numeric", second: undefined }) : "—";
}

const firewallState = computed(() => {
  if ((!health.value && state.health?.agent_ok !== true) || state.health?.status === "unavailable") {
    return { label: state.interfaceDataStatus === "loading" ? "protectionLoading" : "protectionUnavailable" };
  }
  if (health.value?.xdp_attached) {
    if (health.value.egress_policy_enforced || (!health.value.observe_only && health.value.policy_enforced && health.value.enforcement_ok !== false)) {
      return { label: "protectionEnforced", tone: "accent" };
    }
    if (!health.value.observe_only) return { label: "protectionDegraded", tone: "warning" };
  }
  return { label: "protectionNotEnabled" };
});

const sshState = computed(() => {
  if (ssh.value.loading) return { label: "protectionLoading" };
  if (ssh.value.settings.enabled == null) return { label: "protectionUnavailable" };
  return ssh.value.settings.enabled ? { label: "securityOverviewEnabled", tone: "accent" } : { label: "securityOverviewDisabled" };
});

const lastScan = computed(() => scan.value.id ? shortDate(scan.value.finished_at || scan.value.started_at) : "—");
const scanState = computed(() => {
  if (!nodeOnline.value) return { label: "protectionUnavailable" };
  if (scan.value.status === "running") return { label: "securityScanning", tone: "accent" };
  if (scan.value.status === "failed") return { label: "securityScanFailed", tone: "warning" };
  if (scan.value.status === "completed") return { label: "securityCompleted", tone: "accent" };
  return { label: "securityScanIdle" };
});

const risk = computed(() => {
  const insight = props.store.metrics?.value?.risk ?? props.store.metrics?.risk;
  if (insight === "high" || findings.value.length > 5) return { label: "securityOverviewHighRisk", tone: "danger" };
  if (insight === "medium" || findings.value.length || ssh.value.active_blocks?.length || checks.value.some((item) => ["fail", "warning"].includes(item.status))) {
    return { label: "securityOverviewMediumRisk", tone: "warning" };
  }
  if (!nodeOnline.value || (!health.value && !scan.value.id && !checks.value.length)) return { label: "protectionUnavailable" };
  return { label: "securityOverviewLowRisk", tone: "accent" };
});

const summaryItems = computed(() => [
  { label: "securityOverviewOpenIssues", value: nodeOnline.value ? findings.value.filter((finding) => !finding.ignored && !finding.quarantined).length + (ssh.value.active_blocks?.length || 0) : "—" },
  { label: "securityOverviewWarnings", value: checks.value.length ? checks.value.filter((item) => ["warning", "fail"].includes(item.status)).length : "—" },
  { label: "securityOverviewLastScan", value: lastScan.value },
  { label: "securityOverviewProtectionStatus", value: t(firewallState.value.tone === "accent" || sshState.value.tone === "accent" ? "securityOverviewActive" : firewallState.value.label) },
]);

const modules = computed(() => [
  {
    id: "firewall", label: "navFirewall", icon: Network, status: firewallState.value, action: "securityOverviewManageRules",
    stats: [
      { label: "securityOverviewRules", value: state.policy?.interface ? ruleCount(state.policy.ingress || state.policy) + " / " + ruleCount(state.policy.egress) : "—" },
      { label: "securityOverviewRecentBlocks", value: state.recentStats?.recent_dropped ?? "—" },
    ],
  },
  {
    id: "ssh", label: "navSSHProtection", icon: Terminal, status: sshState.value, action: "securityOverviewConfigureSSH",
    stats: [
      { label: "sshTrackedSources", value: ssh.value.settings.enabled == null ? "—" : ssh.value.tracked_sources },
      { label: "sshBlocksTitle", value: ssh.value.settings.enabled == null ? "—" : ssh.value.active_blocks.length },
    ],
  },
  {
    id: "malware", label: "navMalwareScan", icon: ScanSearch, status: scanState.value, action: "securityOverviewViewScan",
    stats: [
      { label: "securityOverviewThreatsFound", value: scan.value.id ? findings.value.length : "—" },
      { label: "securityOverviewSignature", value: scan.value.id || checks.value.length ? summary.value.engine : "—" },
    ],
  },
]);

function showMetric(value, unit) {
  return Number.isFinite(value) ? formatMetric(value, unit, false) : "—";
}

const resourceSummary = computed(() => {
  const metrics = state.clusterAggregate?.nodes?.find((item) => item.id === state.nodeId)?.system_metrics || node.value.system_metrics || {};
  const filesystems = metrics.filesystems || [];
  const total = filesystems.reduce((sum, item) => sum + (item.total_bytes || 0), 0);
  const used = filesystems.reduce((sum, item) => sum + (item.used_bytes || 0), 0);
  const cpuUsage = metrics.cpu?.usage_percent;
  const memoryUsage = metrics.memory?.used_percent;
  const diskUsage = total > 0 ? used / total * 100 : undefined;
  const traffic = [
    { label: "monitoringNetworkInShort", value: metrics.network?.rx_bytes_per_second },
    { label: "monitoringNetworkOutShort", value: metrics.network?.tx_bytes_per_second },
  ].filter((item) => Number.isFinite(item.value));
  const network = traffic.length ? traffic.reduce((sum, item) => sum + item.value, 0) : undefined;
  return [
    { label: "monitoringCPU", value: showMetric(cpuUsage, "percent"), percent: cpuUsage, icon: Cpu },
    { label: "monitoringMemory", value: showMetric(memoryUsage, "percent"), percent: memoryUsage, icon: MemoryStick },
    { label: "monitoringDisk", value: showMetric(diskUsage, "percent"), percent: diskUsage, icon: HardDrive },
    { label: "monitoringNetwork", value: showMetric(network, "rate"), traffic, icon: Network },
  ];
});

const events = computed(() => {
  const cutoff = Date.now() - (eventWindow.value === "7d" ? 7 : 1) * 86400000;
  return props.store.eventRows
    .filter((item) => item.status !== "info" && item.node === state.nodeId && (eventFilter.value === "all" || item.sourceKey === eventFilter.value) && Date.parse(item.time) >= cutoff)
    .slice(0, 6);
});
</script>

<template>
  <section class="page-grid protection-overview">
    <article class="panel protection-summary">
      <div class="protection-summary-node">
        <span class="security-panel-icon"><ShieldCheck :size="16" aria-hidden="true" /></span>
        <div>
          <div class="protection-summary-title">
            <h3>{{ t("securityOverviewRiskSummary") }}</h3>
            <span class="status-pill" :class="risk.tone">{{ t(risk.label) }}</span>
          </div>
          <div class="protection-node-meta">
            <Server :size="13" aria-hidden="true" />
            <span>{{ node.advertise_ip || node.agent_http_addr || node.name || state.nodeId || "—" }}</span>
            <span v-if="state.nodeId" class="protection-node-state" :class="{ online: nodeOnline }">{{ t(nodeOnline ? "clusterOnline" : "clusterOffline") }}</span>
          </div>
        </div>
      </div>
      <dl class="protection-summary-items">
        <div v-for="item in summaryItems" :key="item.label">
          <dt>{{ t(item.label) }}</dt>
          <dd>{{ item.value }}</dd>
        </div>
      </dl>
    </article>

    <div class="protection-module-grid">
      <article v-for="item in modules" :key="item.id" class="panel protection-module">
        <div class="panel-head protection-module-head">
          <div class="protection-panel-title">
            <span class="security-panel-icon"><component :is="item.icon" :size="16" aria-hidden="true" /></span>
            <h3>{{ t(item.label) }}</h3>
          </div>
          <span class="status-pill" :class="item.status.tone">{{ t(item.status.label) }}</span>
        </div>
        <dl class="protection-module-stats">
          <div v-for="stat in item.stats" :key="stat.label">
            <dt>{{ t(stat.label) }}</dt>
            <dd>{{ stat.value ?? "—" }}</dd>
          </div>
        </dl>
        <button type="button" class="protection-link" @click="store.setSecurityFeature(item.id)">{{ t(item.action) }} <ArrowRight :size="16" aria-hidden="true" /></button>
      </article>
    </div>

    <div class="protection-detail-grid workspace-fill">
      <article class="panel protection-events">
        <div class="panel-head">
          <h3>{{ t("securityOverviewRecentEvents") }}</h3>
          <button type="button" class="protection-link" @click="store.setSection('events')">{{ t("headerEventsTitle") }} <ArrowRight :size="16" aria-hidden="true" /></button>
        </div>
        <div class="protection-event-filters">
          <select v-model="eventFilter" :aria-label="t('securityOverviewEvent')">
            <option value="all">{{ t("securityOverviewAllEvents") }}</option>
            <option v-for="item in modules" :key="item.id" :value="item.id">{{ t(item.label) }}</option>
          </select>
          <select v-model="eventWindow" :aria-label="t('securityOverviewTime')">
            <option value="24h">{{ t("securityOverviewLast24Hours") }}</option>
            <option value="7d">{{ t("securityOverviewLast7Days") }}</option>
          </select>
        </div>
        <ul v-if="events.length" class="protection-event-list">
          <li v-for="item in events" :key="item.id">
            <time :datetime="item.time">{{ eventWindow === "7d" ? shortDate(item.time) : formatTime(item.time, state.locale, { second: undefined }) }}</time>
            <div><strong>{{ item.type }}</strong><p>{{ item.description }}<template v-if="item.source && item.source !== '-'"> · {{ item.source }}</template></p></div>
            <span class="status-pill" :class="item.severity === 'high' ? 'danger' : item.severity === 'medium' ? 'warning' : 'muted'">
              {{ t(item.severity === "high" ? "securityHigh" : item.severity === "medium" ? "securityMedium" : "securityLow") }}
            </span>
          </li>
        </ul>
        <div v-else class="empty-state">{{ state.eventCenter.error || t(state.eventCenter.ready ? "securityOverviewNoEvents" : "loading") }}</div>
      </article>

      <article class="panel protection-resources">
        <div class="panel-head">
          <h3>{{ t("securityResourceHealth") }}</h3>
          <button type="button" class="protection-link" @click="store.setSection('monitoring')">{{ t("headerMonitoringTitle") }} <ArrowRight :size="16" aria-hidden="true" /></button>
        </div>
        <dl class="protection-resource-grid">
          <div v-for="item in resourceSummary" :key="item.label">
            <dt><component :is="item.icon" :size="16" aria-hidden="true" />{{ t(item.label) }}</dt>
            <dd class="protection-resource-value">{{ item.value }}</dd>
            <dd v-if="Number.isFinite(item.percent)" class="protection-resource-meter" :style="{ '--resource-usage': `${item.percent}%` }" aria-hidden="true"></dd>
            <dd v-if="item.traffic?.length" class="protection-resource-traffic">
              <span v-for="rate in item.traffic" :key="rate.label">{{ t(rate.label) }} <strong>{{ showMetric(rate.value, "rate") }}</strong></span>
            </dd>
          </div>
        </dl>
      </article>
    </div>
  </section>
</template>

<style scoped>
.protection-overview .panel { min-width: 0; grid-column: auto; }
.protection-summary { display: grid; grid-template-columns: minmax(220px, 1fr) minmax(0, 2.2fr); align-items: center; gap: 22px; }
.protection-summary-node, .protection-summary-title, .protection-node-meta, .protection-panel-title { display: flex; align-items: center; gap: 9px; }
.protection-summary-node { min-width: 0; gap: 12px; }
.protection-summary-title, .protection-node-meta { flex-wrap: wrap; }
.protection-summary-title h3, .protection-panel-title h3 { margin: 0; color: var(--text); font-size: 15px; }
.protection-node-meta { margin-top: 5px; color: var(--muted-strong); font-size: 12px; overflow-wrap: anywhere; }
.protection-node-state { display: inline-flex; align-items: center; gap: 5px; }
.protection-node-state::before { width: 6px; height: 6px; border-radius: 50%; background: currentColor; content: ""; }
.protection-node-state.online { color: var(--accent-strong); }
.protection-summary-items, .protection-module-stats, .protection-resource-grid { display: grid; min-width: 0; gap: 10px; margin: 0; }
.protection-summary-items { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.protection-summary-items > div { min-width: 0; padding-inline-start: 14px; border-inline-start: 1px solid var(--line); }
.protection-summary-items dt, .protection-module-stats dt, .protection-resource-grid dt { color: var(--muted-strong); font-size: 12px; }
.protection-summary-items dd, .protection-module-stats dd, .protection-resource-value { margin: 5px 0 0; color: var(--text); font-size: 16px; font-weight: 680; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
.protection-module-grid, .protection-detail-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--panel-gap); }
.protection-module { display: flex; flex-direction: column; }
.protection-module-head { flex-wrap: wrap; }
.protection-module-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.protection-module-stats > div, .protection-resource-grid > div { min-width: 0; padding: 10px 11px; border-radius: 8px; background: var(--bg-soft); }
.protection-module > .protection-link { align-self: flex-start; margin-top: 10px; }
.protection-link { display: inline-flex; min-height: 30px; align-items: center; gap: 5px; padding: 2px 0; border: 0; background: transparent; color: var(--accent-strong); font-size: 12px; font-weight: 700; text-align: start; }
.protection-link:hover { text-decoration: underline; text-underline-offset: 3px; }
.protection-detail-grid > .protection-events { grid-column: span 2; }
.protection-events, .protection-resources { display: flex; flex-direction: column; }
.protection-events > .empty-state { margin-block: auto; }
.protection-event-filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
.protection-event-filters select { width: auto; min-height: 32px; }
.protection-event-list { margin: 0; padding: 0; list-style: none; }
.protection-event-list li { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: start; gap: 10px; padding: 9px 0; border-top: 1px solid var(--line); font-size: 12px; }
.protection-event-list time { color: var(--muted-strong); font-variant-numeric: tabular-nums; }
.protection-event-list p { margin: 3px 0 0; color: var(--muted-strong); overflow-wrap: anywhere; }
.protection-resource-grid { flex: 1; grid-auto-rows: 1fr; }
.protection-resource-grid > div { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-content: center; align-items: center; gap: 8px 12px; }
.protection-resource-grid dt { display: flex; align-items: center; gap: 6px; }
.protection-resource-grid svg { flex: none; color: var(--accent-strong); }
.protection-resource-value { margin: 0; text-align: end; }
.protection-resource-meter, .protection-resource-traffic { grid-column: 1 / -1; margin: 0; }
.protection-resource-meter { height: 4px; overflow: hidden; border-radius: 999px; background: var(--line); }
.protection-resource-meter::before { display: block; width: clamp(0%, var(--resource-usage), 100%); height: 100%; border-radius: inherit; background: var(--accent); content: ""; }
.protection-resource-traffic { display: flex; flex-wrap: wrap; gap: 3px 12px; color: var(--muted-strong); font-size: 12px; }
.protection-resource-traffic strong { color: var(--text); font-variant-numeric: tabular-nums; }
@media (max-width: 1150px) {
  .protection-summary { grid-template-columns: minmax(0, 1fr); gap: 14px; }
  .protection-summary-items > div:first-child { padding-inline-start: 0; border-inline-start: 0; }
}
@media (max-width: 960px) {
  .protection-detail-grid { grid-template-columns: minmax(0, 1fr); }
  .protection-detail-grid > .protection-events { grid-column: auto; }
  .protection-resource-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); grid-auto-rows: auto; }
  .protection-resource-grid > div { grid-template-columns: minmax(0, 1fr); }
  .protection-resource-value { text-align: start; }
}
@media (max-width: 670px) {
  .protection-module-grid { grid-template-columns: minmax(0, 1fr); }
  .protection-summary-items { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .protection-summary-items > div:nth-child(odd) { padding-inline-start: 0; border-inline-start: 0; }
}
</style>
