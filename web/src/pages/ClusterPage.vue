<script setup>
import { computed, onMounted, ref } from "vue";
import { Check, Copy, FileText, Pencil, Server, ShieldCheck, SquareTerminal, Trash2 } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import { request } from "@/lib/api";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();

const rows = computed(() => props.store.state.nodes || []);
const aggregateRows = computed(() => props.store.state.clusterAggregate?.nodes || []);
const copied = ref(false);
const onlineCount = computed(() => rows.value.filter((item) => statusLabel(item) === t("clusterOnline")).length);
const protectedCount = computed(() => rows.value.filter((item) => !protectionIsProblem(item)).length);

const enrollment = ref(null);
const joinBase = computed(() => enrollment.value?.url || "");
const quickCommand = computed(() => {
  if (!enrollment.value) return "";
  if (enrollment.value.command) return enrollment.value.command;
  return `curl -kfsSL --pinnedpubkey '${enrollment.value.pin}' '${joinBase.value}' | bash`;
});

async function loadEnrollment() {
  enrollment.value = await request("/nodes/enrollment", { method: "POST" });
}
onMounted(() => { if (props.store.state.authRole !== "viewer") loadEnrollment().catch(props.store.handleError); });

function formatSeen(value) {
  if (!value) return "-";
  const ts = new Date(value);
  if (Number.isNaN(ts.getTime())) return "-";
  return ts.toLocaleString();
}

function statusLabel(item) {
  if (!item?.last_seen_at) return t("clusterOffline");
  const delta = Date.now() - new Date(item.last_seen_at).getTime();
  return delta <= 60 * 1000 ? t("clusterOnline") : t("clusterOffline");
}

function protectionLabel(item) {
  const status = aggregateRows.value.find((row) => row.id === item?.id)?.protection_status || "unavailable";
  return {
    enforced: t("protectionEnforced"),
    not_enabled: t("protectionNotEnabled"),
    degraded: t("protectionDegraded"),
    unavailable: t("protectionUnavailable"),
  }[status] || t("protectionUnavailable");
}

function protectionIsProblem(item) {
  return protectionLabel(item) !== t("protectionEnforced");
}

async function copyText(value) {
  await loadEnrollment();
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
    <article v-if="props.store.state.authRole !== 'viewer'" class="panel panel-span-12 cluster-enrollment-panel">
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
      </div>
      <div class="cluster-enrollment-body">
        <div class="cluster-enrollment-copy">
          <div class="cluster-enrollment-step"><b>1</b><span>{{ t("clusterEnrollmentStepOne") }}</span></div>
          <div class="cluster-enrollment-step"><b>2</b><span>{{ t("clusterEnrollmentStepTwo") }}</span></div>
          <div class="cluster-enrollment-links">
            <span>{{ t("clusterJoinCommand") }}</span>
            <a class="text-link" :href="joinBase" target="_blank" rel="noreferrer">
              <FileText :size="14" stroke-width="1.9" aria-hidden="true" />
              {{ t("clusterViewScript") }}
            </a>
          </div>
        </div>
        <div class="cluster-command-card">
          <div class="cluster-command-head">
            <span class="cluster-command-dot"></span>
            <span>root@node</span>
            <small>{{ t("clusterCommandHint") }}</small>
          </div>
          <code>{{ quickCommand }}</code>
          <button class="cluster-command-copy" type="button" :disabled="!quickCommand" :title="t('clusterCopyCommand')" @click="copyText(quickCommand).catch(props.store.handleError)">
            <Check v-if="copied" :size="17" stroke-width="2.2" aria-hidden="true" />
            <Copy v-else :size="17" stroke-width="2" aria-hidden="true" />
            {{ copied ? t("clusterCommandCopied") : t("clusterCopyCommand") }}
          </button>
        </div>
      </div>
    </article>

    <article class="panel panel-span-12 cluster-management-panel">
      <div class="panel-head cluster-management-head">
        <div>
          <p>{{ t("clusterTitle") }}</p>
          <h3>{{ t("clusterSubtitle") }}</h3>
        </div>
        <span class="cluster-management-count">{{ t("clusterNodeSummary", { count: rows.length }) }}</span>
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
            <tr v-for="item in rows" :key="item.id" class="cluster-node-row" @click="openNodeDetails(item)">
              <td :title="item.id">
                <div class="cluster-node-identity">
                  <button type="button" class="table-link" @click.stop="openNodeDetails(item)">{{ item.name || item.id || "-" }}</button>
                  <small v-if="item.name && item.name !== item.id">{{ item.id || "-" }}</small>
                </div>
              </td>
              <td :title="item.agent_url || ''">
                <div class="cluster-node-address">
                  <strong>{{ item.advertise_ip || "-" }}</strong>
                  <small>{{ item.agent_url || "-" }}</small>
                </div>
              </td>
              <td>
                <div class="cluster-status-cell">
                  <span class="status-pill" :class="{ danger: statusLabel(item) === t('clusterOffline') }">{{ statusLabel(item) }}</span>
                  <small>{{ formatSeen(item.last_seen_at) }}</small>
                </div>
              </td>
              <td>
                <div class="cluster-status-cell">
                  <span class="status-pill" :class="{ danger: protectionIsProblem(item) }">
                    <ShieldCheck :size="13" stroke-width="2" aria-hidden="true" />
                    {{ protectionLabel(item) }}
                  </span>
                </div>
              </td>
              <td>
                <div class="inline-actions">
                  <button class="icon-button table-action-button" :title="t('clusterRename')" :aria-label="t('clusterRename')" @click.stop="renameNode(item)"><Pencil :size="18" stroke-width="1.8" aria-hidden="true" /></button>
                  <button class="icon-button table-action-button accent" :title="t('sshConsoleAction')" :aria-label="t('sshConsoleAction')" @click.stop="props.store.openSSHConsole(item)"><SquareTerminal :size="18" stroke-width="1.8" aria-hidden="true" /></button>
                  <button class="icon-button table-action-button danger" :title="t('clusterDelete')" :aria-label="t('clusterDelete')" @click.stop="removeNode(item)"><Trash2 :size="18" stroke-width="1.8" aria-hidden="true" /></button>
                </div>
              </td>
            </tr>
            <tr v-if="!rows.length">
              <td colspan="5" class="table-empty">{{ t("noData") }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </article>
  </section>
</template>
