<script setup>
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { RefreshCw, Save, UnlockKeyhole } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import { request } from "@/lib/api";
import InlineSelect from "@/components/InlineSelect.vue";
import InfoTip from "@/components/InfoTip.vue";

const props = defineProps({
  store: { type: Object, required: true },
});
const { t } = useI18n();
const activity = ref([]);
const activityType = ref("");
const activitySource = ref("");
const activitySession = ref("");
const activityLoading = ref(false);
let activitySerial = 0;
const activityTypes = computed(() => [
  { value: "", label: t("sshActivityAll") },
  { value: "command", label: t("sshActivityCommand") },
  { value: "transfer", label: t("sshActivityTransfer") },
  { value: "upload_scan", label: t("sshActivityUploadScan") },
  { value: "audit_status", label: t("sshActivityAuditStatus") },
]);

function trustedCIDRsText() {
  return (props.store.state.sshProtection?.settings?.trusted_cidrs || []).join(", ");
}

function updateTrustedCIDRs(event) {
  props.store.state.sshProtection.settings.trusted_cidrs = String(event.target.value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function saveTransferPolicy() {
  props.store.openModal({
    title: t("sshTransferConfirmTitle"),
    copy: t("sshTransferConfirmCopy"),
    fields: [{ key: "password", label: t("currentPassword"), type: "password", required: true }],
    onConfirm: (values) => props.store.saveSSHTransferPolicy(values.password),
  });
}

async function refreshActivity() {
  const serial = ++activitySerial;
  const node = props.store.state.nodeId;
  if (!node) { activity.value = []; activityLoading.value = false; return; }
  const query = new URLSearchParams({ limit: "100" });
  if (activityType.value) query.set("event", activityType.value);
  if (activitySource.value.trim()) query.set("source", activitySource.value.trim());
  if (activitySession.value) query.set("session", activitySession.value);
  activityLoading.value = true;
  try {
    const payload = await request(`/nodes/${encodeURIComponent(node)}/ssh-protection/activity?${query}`);
    if (serial === activitySerial && node === props.store.state.nodeId) activity.value = payload.records || [];
  } catch (error) {
    if (serial === activitySerial && node === props.store.state.nodeId) props.store.handleError(error);
  } finally { if (serial === activitySerial) activityLoading.value = false; }
}

watch(() => props.store.state.nodeId, () => {
  activity.value = []; activitySession.value = ""; activitySource.value = ""; activityType.value = "";
  refreshActivity();
}, { immediate: true });
onBeforeUnmount(() => { ++activitySerial; });
function selectSession(id) { activitySession.value = id; refreshActivity(); }

function formatActivityTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString(props.store.state.locale === "en-US" ? "en-US" : "zh-CN");
}

function activityEvent(record) {
  return t(`sshActivity${String(record?.event || "").replace(/(^|_)([a-z])/g, (_, _separator, letter) => letter.toUpperCase())}`) || record?.event || "-";
}

function activityTarget(record) {
  if (record?.event === "command") return record.command || "-";
  if (record?.path) return record.path;
  if (record?.event === "audit_status") return record.detail || "-";
  if (record?.transfer) return record.transfer.toUpperCase();
  return "-";
}

function activityResult(record) {
  if (record?.event === "upload_scan") {
    const labels = {
      clean: t("sshScanClean"),
      suspicious: t("sshScanSuspicious"),
      partial: t("sshScanPartial"),
      unavailable: t("sshScanUnavailable"),
    };
    return labels[record.scan_status] || record.scan_status || "-";
  }
  if (record?.exit_code != null && ["command", "session_close"].includes(record.event)) return t("sshActivityExitCode", { code: record.exit_code });
  const actions = { executing: "sshActionExecuting", executed: "sshActionExecuted", uploaded: "sshActionUploaded", downloaded: "sshActionDownloaded", blocked: "sshBlocked", incomplete: "sshActionIncomplete", connected: "sshActionConnected", closed: "sshActionClosed", started: "sshActionStarted", unavailable: "sshScanUnavailable" };
  return actions[record?.action] ? t(actions[record.action]) : (record?.action || "-");
}

function uploadStatusLabel(value) {
  return activityResult({ event: "upload_scan", scan_status: value });
}
</script>

<template>
  <section class="page-grid">
    <div class="management-layout">
      <article class="panel panel-span-6">
        <div class="panel-head">
          <div>
            <p>{{ t("sshProtection") }}</p>
            <h3>{{ t("sshProtectionTitle") }}</h3>
          </div>
          <span v-if="props.store.state.sshProtection.loading" class="status-pill">
            {{ t("loading") }}
          </span>
          <span v-else class="status-pill">
            {{ props.store.state.sshProtection.settings.enabled == null ? t("protectionUnavailable") : (props.store.state.sshProtection.settings.enabled ? t("enabled") : t("disabled")) }}
          </span>
        </div>
        <div class="stack-list">
          <label class="field">
            <span>{{ t("sshProtectionSwitch") }}</span>
            <select v-model="props.store.state.sshProtection.settings.enabled" :disabled="props.store.state.sshProtection.loading || props.store.state.sshProtection.settings.enabled == null">
              <option :value="true">{{ t("enabled") }}</option>
              <option :value="false">{{ t("disabled") }}</option>
            </select>
          </label>
          <div class="filter-grid">
            <label class="field">
              <span>{{ t("sshFailThreshold") }}</span>
              <input v-model.number="props.store.state.sshProtection.settings.max_failures" type="number" min="1" max="100" :disabled="props.store.state.sshProtection.loading || props.store.state.sshProtection.settings.enabled == null" />
            </label>
            <label class="field">
              <span>{{ t("sshWindowSeconds") }}</span>
              <input v-model.number="props.store.state.sshProtection.settings.window_seconds" type="number" min="30" :disabled="props.store.state.sshProtection.loading || props.store.state.sshProtection.settings.enabled == null" />
            </label>
            <label class="field">
              <span>{{ t("sshBanSeconds") }}</span>
              <input v-model.number="props.store.state.sshProtection.settings.ban_duration_seconds" type="number" min="60" :disabled="props.store.state.sshProtection.loading || props.store.state.sshProtection.settings.enabled == null" />
            </label>
          </div>
          <label class="field">
            <span>{{ t("sshTrustedCIDRs") }}</span>
            <input :value="trustedCIDRsText()" :placeholder="t('sshTrustedCIDRsPlaceholder')" :disabled="props.store.state.sshProtection.loading || props.store.state.sshProtection.settings.enabled == null" @input="updateTrustedCIDRs" />
          </label>
          <div class="key-row"><span>{{ t("sshDetectedPorts") }}</span><strong>{{ (props.store.state.sshProtection.ports || []).join(", ") || "22" }}</strong></div>
          <div class="key-row"><span>{{ t("sshTrackedSources") }}</span><strong>{{ props.store.state.sshProtection.tracked_sources || 0 }}</strong></div>
          <div v-if="props.store.state.sshProtection.last_error" class="danger-tag">{{ props.store.state.sshProtection.last_error }}</div>
          <button class="primary-button" :disabled="props.store.state.sshProtection.loading || props.store.state.sshProtection.settings.enabled == null" @click="props.store.saveSSHProtectionSettings().catch(props.store.handleError)">
            <Save :size="16" stroke-width="2" aria-hidden="true" />
            {{ t("sshSave") }}
          </button>
        </div>
      </article>

      <article class="panel panel-span-6">
        <div class="panel-head">
          <div>
            <p>{{ t("sshBlocks") }}</p>
            <h3>{{ t("sshBlocksTitle") }}</h3>
          </div>
          <strong>{{ (props.store.state.sshProtection.active_blocks || []).length }}</strong>
        </div>
        <div v-if="!(props.store.state.sshProtection.active_blocks || []).length" class="empty-state">{{ t("sshNoBlocks") }}</div>
        <div v-else class="table-shell">
          <table class="console-table">
            <thead>
              <tr>
                <th>{{ t("sourceIp") }}</th>
                <th>{{ t("port") }}</th>
                <th>{{ t("expiresAt") }}</th>
                <th>{{ t("policyTableActions") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in props.store.state.sshProtection.active_blocks" :key="item.id">
                <td>{{ item.source_ip }}</td>
                <td>{{ item.port || 22 }}</td>
                <td>{{ item.expires_at || "-" }}</td>
                <td><button class="icon-button table-action-button" :title="t('sshRelease')" :aria-label="t('sshRelease')" @click="props.store.releaseSSHProtectionBlock(item.id).catch(props.store.handleError)"><UnlockKeyhole :size="16" stroke-width="1.8" aria-hidden="true" /></button></td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>

      <article class="panel panel-span-12 ssh-transfer-panel">
        <div class="panel-head">
          <div>
            <p>{{ t("sshTransfer") }}</p>
            <h3>{{ t("sshTransferTitle") }}</h3>
          </div>
          <span v-if="props.store.state.sshProtection.transfer_effective" class="tag accent">{{ t("sshTransferEffective") }}</span>
          <span v-else-if="props.store.state.sshProtection.last_error" class="tag danger-tag">{{ t("sshTransferNotVerified") }}</span>
          <span v-else class="tag">{{ t("sshTransferLayer") }}</span>
        </div>
        <div class="filter-grid">
          <label class="field">
            <span>{{ t("sshBlockSFTP") }}</span>
            <select v-model="props.store.state.sshProtection.settings.transfer.block_sftp">
              <option :value="false">{{ t("sshAllowed") }}</option>
              <option :value="true">{{ t("sshBlocked") }}</option>
            </select>
          </label>
          <label class="field">
            <span>{{ t("sshBlockSCP") }}</span>
            <select v-model="props.store.state.sshProtection.settings.transfer.block_scp">
              <option :value="false">{{ t("sshAllowed") }}</option>
              <option :value="true">{{ t("sshBlocked") }}</option>
            </select>
          </label>
          <label class="field">
            <span>{{ t("sshAuditTransfers") }}</span>
            <select v-model="props.store.state.sshProtection.settings.transfer.audit_transfers">
              <option :value="false">{{ t("disabled") }}</option>
              <option :value="true">{{ t("enabled") }}</option>
            </select>
          </label>
          <label class="field">
            <span>{{ t("sshAuditSessions") }}</span>
            <select v-model="props.store.state.sshProtection.settings.transfer.audit_sessions">
              <option :value="false">{{ t("disabled") }}</option>
              <option :value="true">{{ t("enabled") }}</option>
            </select>
          </label>
          <label class="field">
            <span>{{ t("sshAuditCommands") }} <InfoTip :text="t('sshAuditCommandsHint')" /></span>
            <select v-model="props.store.state.sshProtection.settings.transfer.audit_commands">
              <option :value="false">{{ t("disabled") }}</option>
              <option :value="true">{{ t("enabled") }}</option>
            </select>
          </label>
          <label class="field">
            <span>{{ t("sshScanUploads") }} <InfoTip :text="t('sshScanUploadsHint')" /></span>
            <select v-model="props.store.state.sshProtection.settings.transfer.scan_uploads">
              <option :value="false">{{ t("disabled") }}</option>
              <option :value="true">{{ t("enabled") }}</option>
            </select>
          </label>
        </div>
        <div class="split-actions ssh-transfer-actions">
          <div class="inline-actions">
            <button class="primary-button" @click="saveTransferPolicy">
              <Save :size="16" stroke-width="2" aria-hidden="true" />
              {{ t("sshTransferSave") }}
            </button>
          </div>
        </div>
        <div class="integrity-summary">
          <span>{{ t("sshUploadLastStatus") }}: {{ props.store.state.sshProtection.upload_security?.last_status ? uploadStatusLabel(props.store.state.sshProtection.upload_security.last_status) : t("sshNotChecked") }}</span>
          <span>{{ t("sshUploadFilesChecked") }}: {{ props.store.state.sshProtection.upload_security?.files_checked || 0 }}</span>
          <span>{{ t("sshUploadFindings") }}: {{ props.store.state.sshProtection.upload_security?.findings || 0 }}</span>
        </div>
      </article>

      <article class="panel panel-span-12">
        <div class="panel-head">
          <div>
            <p>{{ t("sshActivity") }}</p>
            <h3>{{ t("sshActivityTitle") }}</h3>
          </div>
          <button class="ghost-button" :disabled="activityLoading" @click="refreshActivity">
            <RefreshCw :size="15" stroke-width="1.9" aria-hidden="true" />
            {{ t("sshActivityRefresh") }}
          </button>
        </div>
        <div class="ssh-activity-filters">
          <InlineSelect v-model="activityType" :options="activityTypes" :aria-label="t('sshActivityEvent')" @change="refreshActivity" />
          <input v-model="activitySource" :placeholder="t('sshActivitySourceFilter')" :aria-label="t('sshActivitySourceFilter')" @keydown.enter="refreshActivity" @change="refreshActivity" />
          <button v-if="activitySession" class="ghost-button" :title="activitySession" @click="selectSession('')">{{ t("sshActivityClearSession") }}</button>
        </div>
        <div v-if="!activity.length" class="empty-state">{{ activityLoading ? t("monitoringLoading") : t("sshActivityEmpty") }}</div>
        <div v-else class="table-shell">
          <table class="console-table">
            <thead>
              <tr>
                <th>{{ t("sshActivityTime") }}</th>
                <th>{{ t("sshActivityEvent") }}</th>
                <th>{{ t("sshActivitySource") }}</th>
                <th>{{ t("sshActivityTarget") }}</th>
                <th>{{ t("sshActivityResult") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="record in activity" :key="record.id || `${record.session_id}-${record.at}-${record.event}-${record.action}-${record.command || record.path || ''}`">
                <td>{{ formatActivityTime(record.at) }}</td>
                <td>{{ activityEvent(record) }}</td>
                <td>
                  <div>{{ record.user || "-" }} · {{ record.source_ip || "-" }}{{ record.source_port ? `:${record.source_port}` : "" }}</div>
                  <button v-if="record.session_id" class="ghost-button ssh-session-link" :title="t('sshActivitySessionHint', { id: record.session_id })" @click="selectSession(record.session_id)">{{ record.session_id }}</button>
                </td>
                <td class="ssh-activity-target" :title="record.truncated ? t('sshActivityTruncated') : undefined">{{ activityTarget(record) }}{{ record.truncated ? "…" : "" }}</td>
                <td :title="record.detail || undefined">{{ activityResult(record) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>
    </div>
  </section>
</template>

<style scoped>
.ssh-activity-filters { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 12px; }
.ssh-activity-filters input { width: min(240px, 100%); }
.ssh-session-link { max-width: 100%; min-height: 28px; padding: 3px 0; font-size: 12px; overflow: hidden; text-overflow: ellipsis; }
</style>
