<script setup>
import { computed, ref, watch } from "vue";
import { Check, Copy, FileText, Pencil, RefreshCw, Server, ShieldCheck, SquareTerminal, Trash2, X } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import { request } from "@/lib/api";
import TablePagination from "@/components/TablePagination.vue";
import { formatDateTime } from "@/lib/time";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();

const rows = computed(() => props.store.state.nodes || []);
const protectionByNode = computed(() => props.store.state.nodeProtection || {});
const reachabilityByNode = computed(() => props.store.state.nodeReachability || {});
const copied = ref(false);
const tablePage = ref(0);
const tablePageSize = ref(10);
const tableQuery = ref("");
const tableStatus = ref("");
const tableProtection = ref("");
const tableSort = ref("name");
const onlineCount = computed(() => rows.value.filter((item) => statusLabel(item) === t("clusterOnline")).length);
const protectedCount = computed(() => rows.value.filter((item) => !protectionIsProblem(item)).length);
const filteredRows = computed(() => {
  const query = tableQuery.value.trim().toLowerCase();
  const filtered = rows.value.filter((item) => {
    if (tableStatus.value && (statusLabel(item) === t("clusterOnline") ? "online" : "offline") !== tableStatus.value) return false;
    if (tableProtection.value && (protectionByNode.value[item?.id]?.protection_status || "loading") !== tableProtection.value) return false;
    if (!query) return true;
    return [item.id, item.name, item.advertise_ip, item.agent_url, item.server_http_addr, item.package_version].filter(Boolean).join(" ").toLowerCase().includes(query);
  });
  return filtered.slice().sort((left, right) => {
    if (tableSort.value === "status") return (statusLabel(left) === t("clusterOnline") ? 0 : 1) - (statusLabel(right) === t("clusterOnline") ? 0 : 1);
    return String(left.name || left.id || "").localeCompare(String(right.name || right.id || ""));
  });
});
const visibleRows = computed(() => filteredRows.value.slice(tablePage.value * tablePageSize.value, (tablePage.value + 1) * tablePageSize.value));
watch(() => [tableQuery.value, tableStatus.value, tableProtection.value, tableSort.value, rows.value.length], () => { tablePage.value = 0; });

const enrollment = ref(null);
const enrollmentOpen = ref(false);
const enrollmentLoading = ref(false);
const enrollmentError = ref("");
const joinBase = computed(() => enrollment.value?.url || "");
const quickCommand = computed(() => {
  if (!enrollment.value) return "";
  if (enrollment.value.command) return enrollment.value.command;
  return `curl -kfsSL --pinnedpubkey '${enrollment.value.pin}' '${joinBase.value}' | bash`;
});

async function loadEnrollment() {
  enrollmentLoading.value = true;
  enrollmentError.value = "";
  try {
    enrollment.value = await request("/nodes/enrollment", { method: "POST" });
    return enrollment.value;
  } catch (error) {
    enrollmentError.value = t("clusterEnrollmentError");
    throw error;
  } finally {
    enrollmentLoading.value = false;
  }
}

async function ensureEnrollment() {
  try {
    await loadEnrollment();
    return true;
  } catch (_) {
    return false;
  }
}
async function openEnrollment() {
  enrollmentOpen.value = true;
  if (!enrollment.value) await ensureEnrollment();
}

function formatSeen(value) {
  if (!value) return "-";
  return formatDateTime(value, props.store.state.locale === "en-US" ? "en-US" : "zh-CN");
}

function displayAgentURL(item) {
  const raw = String(item?.agent_url || "").trim();
  if (raw && !/(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])/.test(raw)) return raw;
  const advertised = String(item?.agent_http_addr || "").trim();
  if (advertised && !/(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])/.test(advertised)) return `https://${advertised}`;
  const ip = String(item?.advertise_ip || "").trim();
  return ip ? `https://${ip}:9080` : "-";
}

function displayServerURL(item) {
  const raw = String(item?.server_http_addr || "").trim();
  if (!raw) return "";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return raw;
  return `https://${raw}`;
}

function statusLabel(item) {
  return props.store.isNodeOnline(item) ? t("clusterOnline") : t("clusterOffline");
}

function protectionLabel(item) {
  const status = protectionByNode.value[item?.id]?.protection_status || "loading";
  return {
    enforced: t("protectionEnforced"),
    not_enabled: t("protectionNotEnabled"),
    degraded: t("protectionDegraded"),
    unavailable: t("protectionUnavailable"),
    loading: t("protectionLoading"),
  }[status] || t("protectionUnavailable");
}

function protectionIsProblem(item) {
  return protectionLabel(item) !== t("protectionEnforced");
}

async function copyText(value) {
  if (!await ensureEnrollment()) return;
  value = quickCommand.value;
  if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value);
  copied.value = true;
  window.setTimeout(() => { copied.value = false; }, 1800);
}

async function removeNode(item) {
  if (!item?.id) return;
  const ok = window.confirm(t("clusterDeleteConfirm").replace("{id}", item.id));
  if (!ok) return;
  await props.store.deleteNode(item.id);
}

async function updateNode(item) {
  if (!item?.id) return;
  const ok = window.confirm(t("clusterUpdateConfirm").replace("{id}", item.id));
  if (!ok) return;
  await props.store.updateNode(item.id);
}

function openNodeDetails(item) {
  if (!item?.id) return;
  props.store.setNode(item.id)
    .then(() => {
      props.store.setOverviewScope("node");
      props.store.setSection("overview");
    })
    .catch(props.store.handleError);
}

function renameNode(item) {
  props.store.openModal({
    title: t("clusterRenameTitle"),
    copy: t("clusterRenameCopy", { id: item.id }),
    fields: [{ key: "name", label: t("clusterRenameField"), type: "text", value: item.name || item.id, placeholder: t("clusterNamePlaceholder") }],
    onConfirm: async (payload) => {
      await props.store.renameNode(item.id, payload.name);
    },
  });
}
</script>

<template>
  <section class="page-grid cluster-page">
    <article v-if="props.store.state.authRole !== 'viewer' && enrollmentOpen" class="panel panel-span-12 cluster-enrollment-panel cluster-enrollment-drawer">
      <div class="cluster-enrollment-head">
        <div>
          <p>{{ t("clusterEnrollmentEyebrow") }}</p>
          <h3>{{ t("clusterEnrollmentTitle") }}</h3>
          <span>{{ t("clusterEnrollmentCopy") }}</span>
        </div>
        <div class="cluster-enrollment-badge">
          <Server :size="18" stroke-width="1.8" aria-hidden="true" />
          <span>{{ t("clusterJoinSubtitle") }}</span>
        </div>
        <button class="icon-button" type="button" :aria-label="t('clusterEnrollmentClose')" @click="enrollmentOpen = false"><X :size="18" /></button>
      </div>
      <div class="cluster-enrollment-body">
        <div class="cluster-enrollment-copy">
          <div class="cluster-enrollment-step"><b>1</b><span>{{ t("clusterEnrollmentStepOne") }}</span></div>
          <div class="cluster-enrollment-step"><b>2</b><span>{{ t("clusterEnrollmentStepTwo") }}</span></div>
          <div class="cluster-enrollment-links">
            <span>{{ t("clusterJoinCommand") }}</span>
            <a v-if="joinBase" class="text-link" :href="joinBase" target="_blank" rel="noreferrer">
              <FileText :size="14" stroke-width="1.9" aria-hidden="true" />
              {{ t("clusterViewScript") }}
            </a>
          </div>
        </div>
        <div v-if="enrollmentError" class="cluster-enrollment-error" role="alert">
          <span>{{ enrollmentError }}</span>
          <button type="button" class="ghost-button compact-button" :disabled="enrollmentLoading" @click="ensureEnrollment">{{ enrollmentLoading ? t("loading") : t("clusterEnrollmentRetry") }}</button>
        </div>
        <div class="cluster-command-card">
          <div class="cluster-command-head">
            <span class="cluster-command-dot"></span>
            <span>root@node</span>
            <small>{{ t("clusterCommandHint") }}</small>
          </div>
          <code>{{ quickCommand || t("clusterEnrollmentWaiting") }}</code>
          <button class="cluster-command-copy" type="button" :disabled="!quickCommand" :title="t('clusterCopyCommand')" @click="copyText(quickCommand).catch(props.store.handleError)">
            <Check v-if="copied" :size="17" stroke-width="2.2" aria-hidden="true" />
            <Copy v-else :size="17" stroke-width="2" aria-hidden="true" />
            {{ copied ? t("clusterCommandCopied") : t("clusterCopyCommand") }}
          </button>
        </div>
      </div>
    </article>

    <article class="panel panel-span-12 cluster-management-panel workspace-fill workspace-panel">
      <div class="panel-head cluster-management-head">
        <div>
          <p>{{ t("clusterTitle") }}</p>
          <h3>{{ t("clusterSubtitle") }}</h3>
        </div>
        <div class="panel-actions">
          <span class="cluster-management-count">{{ t("clusterNodeSummary", { count: rows.length }) }}</span>
          <button v-if="props.store.state.authRole !== 'viewer'" class="primary-button compact-button" type="button" @click="openEnrollment().catch(props.store.handleError)">{{ t("clusterAddNode") }}</button>
        </div>
      </div>
      <div class="cluster-summary-strip">
        <div class="cluster-summary-item">
          <span>{{ t("clusterTotal") }}</span>
          <strong>{{ rows.length }}</strong>
          <small>{{ t("clusterCurrentCluster") }}</small>
        </div>
        <div class="cluster-summary-item accent">
          <span>{{ t("clusterOnlineCount") }}</span>
          <strong>{{ onlineCount }}</strong>
          <small>{{ t("clusterOnline") }}</small>
        </div>
        <div class="cluster-summary-item" :class="{ warning: protectedCount < rows.length }">
          <span>{{ t("clusterProtectedCount") }}</span>
          <strong>{{ protectedCount }}</strong>
          <small>{{ t("clusterProtectionStatus") }}</small>
        </div>
      </div>
      <div class="cluster-table-heading">
        <small>{{ t("clusterTableHint") }}</small>
      </div>
      <div class="table-toolbar">
        <input v-model="tableQuery" type="search" :placeholder="t('clusterTableSearch')" />
        <select v-model="tableStatus" :aria-label="t('clusterAgentStatus')">
          <option value="">{{ t("clusterAllStatuses") }}</option>
          <option value="online">{{ t("clusterOnline") }}</option>
          <option value="offline">{{ t("clusterOffline") }}</option>
        </select>
        <select v-model="tableProtection" :aria-label="t('clusterProtectionStatus')">
          <option value="">{{ t("clusterAllProtection") }}</option>
          <option value="enforced">{{ t("protectionEnforced") }}</option>
          <option value="not_enabled">{{ t("protectionNotEnabled") }}</option>
          <option value="degraded">{{ t("protectionDegraded") }}</option>
          <option value="unavailable">{{ t("protectionUnavailable") }}</option>
        </select>
        <select v-model="tableSort" :aria-label="t('clusterSort')">
          <option value="name">{{ t("clusterSortName") }}</option>
          <option value="status">{{ t("clusterSortStatus") }}</option>
        </select>
      </div>
      <div class="table-shell">
        <table class="console-table cluster-node-table">
          <colgroup>
            <col class="cluster-col-name" />
            <col class="cluster-col-address" />
            <col class="cluster-col-agent-status" />
            <col class="cluster-col-protection" />
            <col class="cluster-col-actions" />
          </colgroup>
          <thead>
            <tr>
              <th>{{ t("clusterNodeName") }}</th>
              <th>{{ t("clusterAdvertiseIP") }}</th>
              <th>{{ t("clusterAgentStatus") }}</th>
              <th>{{ t("clusterProtectionStatus") }}</th>
              <th>{{ t("policyTableActions") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in visibleRows" :key="item.id" class="cluster-node-row" @click="openNodeDetails(item)">
              <td :title="item.id">
                <div class="cluster-node-identity">
                  <button type="button" class="table-link" @click.stop="openNodeDetails(item)">{{ item.name || item.id || "-" }}</button>
                  <small v-if="item.name && item.name !== item.id">{{ item.id || "-" }}</small>
                </div>
              </td>
              <td :title="displayAgentURL(item)">
                <div class="cluster-node-address">
                  <strong>{{ item.advertise_ip || "-" }}</strong>
                  <small>{{ displayAgentURL(item) }}</small>
                  <small v-if="displayServerURL(item)"><a class="text-link" :href="displayServerURL(item)" target="_blank" rel="noreferrer">{{ t("clusterNodeWeb") }}: {{ displayServerURL(item) }}</a></small>
                  <small v-if="item.package_version">{{ t("clusterNodeVersion") }} {{ item.package_version }}</small>
                </div>
              </td>
              <td>
                <div class="cluster-status-cell">
                  <span class="status-pill" :class="{ danger: statusLabel(item) === t('clusterOffline') }">{{ statusLabel(item) }}</span>
                  <small>{{ formatSeen(item.last_seen_at) }}</small>
                  <small v-if="reachabilityByNode[item.id] === false && props.store.isNodeOnline(item)" :title="protectionByNode[item.id]?.reason || ''">{{ t("clusterConnectionUnavailable") }}</small>
                </div>
              </td>
              <td>
                <div class="cluster-status-cell">
                  <span class="status-pill" :title="protectionByNode[item.id]?.reason || ''" :class="{ danger: (protectionByNode[item.id]?.protection_status || 'loading') !== 'loading' && protectionIsProblem(item) }">
                    <ShieldCheck :size="13" stroke-width="2" aria-hidden="true" />
                    {{ protectionLabel(item) }}
                  </span>
                </div>
              </td>
              <td>
                <div class="inline-actions">
                  <button class="icon-button table-action-button" :title="t('clusterRename')" :aria-label="t('clusterRename')" @click.stop="renameNode(item)"><Pencil :size="18" stroke-width="1.8" aria-hidden="true" /></button>
                  <button class="icon-button table-action-button accent" :title="t('clusterUpdate')" :aria-label="t('clusterUpdate')" @click.stop="updateNode(item).catch(props.store.handleError)"><RefreshCw :size="18" stroke-width="1.8" aria-hidden="true" /></button>
                  <button class="icon-button table-action-button accent" :title="t('sshConsoleAction')" :aria-label="t('sshConsoleAction')" @click.stop="props.store.openSSHConsole(item)"><SquareTerminal :size="18" stroke-width="1.8" aria-hidden="true" /></button>
                  <button class="icon-button table-action-button danger" :title="t('clusterDelete')" :aria-label="t('clusterDelete')" @click.stop="removeNode(item)"><Trash2 :size="18" stroke-width="1.8" aria-hidden="true" /></button>
                </div>
              </td>
            </tr>
            <tr v-if="!visibleRows.length">
              <td colspan="5" class="table-empty">{{ rows.length ? t("clusterNoMatches") : t("noData") }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <TablePagination v-model:page="tablePage" v-model:page-size="tablePageSize" :total="filteredRows.length" />
    </article>
  </section>
</template>
