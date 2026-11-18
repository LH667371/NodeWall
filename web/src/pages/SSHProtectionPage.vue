<script setup>
import { computed, reactive, ref, watch } from "vue";
import { Ban, KeyRound, Terminal, Trash2, UnlockKeyhole, Users } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import InlineSelect from "@/components/InlineSelect.vue";
import InfoTip from "@/components/InfoTip.vue";
import TablePagination from "@/components/TablePagination.vue";
import SettingsSaveBar from "@/components/SettingsSaveBar.vue";
import { useSettingsDraft } from "@/composables/useSettingsDraft";
import { formatDateTime } from "@/lib/time";

const props = defineProps({
  store: { type: Object, required: true },
});
const { t } = useI18n();
const readETag = () => props.store.state.sshSettingsETag;
const protectionSession = useSettingsDraft(() => props.store.state.sshProtection.settings, readETag, ["enabled", "max_failures", "window_seconds", "ban_duration_seconds", "trusted_cidrs", "log_path"]);
const authenticationSession = useSettingsDraft(() => props.store.state.sshProtection.settings, readETag, ["allow_password_login"]);
const transferSession = useSettingsDraft(() => props.store.state.sshProtection.settings.transfer, readETag, ["block_sftp", "block_scp", "audit_transfers", "audit_sessions", "audit_commands", "scan_uploads"]);
const protectionDraft = protectionSession.draft;
const authenticationDraft = authenticationSession.draft;
const transferDraft = transferSession.draft;
const saveBusy = reactive({});
const saveErrors = reactive({});
const ssh = computed(() => props.store.state.sshProtection);
const settingsAvailable = computed(() => !ssh.value.loading && ssh.value.settings.enabled != null);
const canConfigure = computed(() => settingsAvailable.value && props.store.state.authRole !== "viewer");
const settingsSaving = computed(() => saveBusy.protection || saveBusy.transfer || props.store.state.modal.open);

async function saveSettings(key, session, save, settingsFrom) {
  if (!canConfigure.value || settingsSaving.value) return;
  saveBusy[key] = true;
  saveErrors[key] = "";
  try {
    const response = await save({ ...session.draft }, { etag: session.etag.value });
    if (response?.settings) session.reset(settingsFrom(response.settings));
  } catch (error) {
    saveErrors[key] = error.code === "CONFIG_CHANGED" ? t("settingsConflict") : error.message;
  } finally {
    saveBusy[key] = false;
  }
}
function saveProtection() {
  return saveSettings("protection", protectionSession, props.store.saveSSHProtectionSettings, (settings) => settings);
}
function saveTransferPolicy() {
  return saveSettings("transfer", transferSession, props.store.saveSSHTransferPolicy, (settings) => settings.transfer);
}
function openNodeConfirmation(config) {
  const nodeID = props.store.state.nodeId;
  props.store.openModal({ ...config, keepOpenOnError: true, onConfirm: (values) => {
    if (nodeID !== props.store.state.nodeId) throw new Error(t("settingsTargetChanged"));
    return config.onConfirm(values);
  } });
}
const activityType = ref("");
const activitySource = ref("");
const activitySession = ref("");
const blockPage = ref(0);
const blockPageSize = ref(10);
const blockQuery = ref("");
const activityPage = ref(0);
const activityPageSize = ref(20);
const keyPublic = ref("");
const keyComment = ref("");
const keyFormOpen = ref(false);
const activePanel = ref("settings");
const panels = computed(() => [
  { key: "settings", label: t("sshPolicySettings") },
  { key: "keys", label: t("sshKeys") },
  { key: "blocks", label: t("sshBlocksTitle") },
  { key: "activity", label: t("sshActivity") },
]);
const auditOptions = [
  { key: "audit_transfers", label: "sshAuditTransfers" },
  { key: "audit_sessions", label: "sshAuditSessions" },
  { key: "audit_commands", label: "sshAuditCommands", hint: "sshAuditCommandsHint" },
  { key: "scan_uploads", label: "sshScanUploads", hint: "sshScanUploadsHint" },
];
const activeBlocks = computed(() => props.store.state.sshProtection?.active_blocks || []);
const filteredBlocks = computed(() => {
  const query = blockQuery.value.trim().toLowerCase();
  return activeBlocks.value.filter((item) => !query || [item.source_ip, item.port, item.expires_at].filter(Boolean).join(" ").toLowerCase().includes(query));
});
const visibleBlocks = computed(() => filteredBlocks.value.slice(blockPage.value * blockPageSize.value, (blockPage.value + 1) * blockPageSize.value));
const activity = computed(() => props.store.state.sshProtection?.activity || []);
const filteredActivity = computed(() => activity.value.filter((item) => {
  if (activityType.value && item?.event !== activityType.value) return false;
  if (activitySource.value.trim() && !String(item?.source_ip || "").includes(activitySource.value.trim())) return false;
  if (activitySession.value && String(item?.session_id || item?.session || "") !== activitySession.value) return false;
  return true;
}));
const visibleActivity = computed(() => filteredActivity.value.slice(activityPage.value * activityPageSize.value, (activityPage.value + 1) * activityPageSize.value));
watch(() => [activeBlocks.value.length, blockQuery.value], () => { blockPage.value = 0; });
watch(() => [activity.value.length, activityType.value, activitySource.value, activitySession.value], () => { activityPage.value = 0; });
const activityTypes = computed(() => [
  { value: "", label: t("sshActivityAll") },
  { value: "command", label: t("sshActivityCommand") },
  { value: "transfer", label: t("sshActivityTransfer") },
  { value: "upload_scan", label: t("sshActivityUploadScan") },
  { value: "audit_status", label: t("sshActivityAuditStatus") },
]);

function parseTrustedCIDRs(value) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}
const trustedCIDRsText = ref((protectionDraft.trusted_cidrs || []).join(", "));
watch(() => protectionDraft.trusted_cidrs, (cidrs) => {
  const next = (cidrs || []).join(", ");
  if (next !== parseTrustedCIDRs(trustedCIDRsText.value).join(", ")) trustedCIDRsText.value = next;
}, { flush: "sync" });
function updateTrustedCIDRs(event) {
  trustedCIDRsText.value = event.target.value;
  // Keep the separator while typing a second CIDR; only the draft is normalized.
  protectionDraft.trusted_cidrs = parseTrustedCIDRs(trustedCIDRsText.value);
}

function savePasswordLoginPolicy() {
  const allow = Boolean(authenticationDraft.allow_password_login);
  const etag = authenticationSession.etag.value;
  openNodeConfirmation({
    title: t("sshAuthenticationConfirmTitle"),
    copy: t("sshAuthenticationConfirmCopy"),
    fields: [{ key: "password", label: t("currentPassword"), type: "password", required: true }],
    onConfirm: async (values) => {
      const response = await props.store.saveSSHAuthenticationPolicy(allow, values.password, { etag });
      if (response?.settings) authenticationSession.reset(response.settings);
    },
  });
}

function addPublicKey() {
  const publicKey = keyPublic.value.trim();
  if (!publicKey) return;
  openNodeConfirmation({
    title: t("sshKeyAddConfirmTitle"),
    copy: t("sshKeyAddConfirmCopy"),
    fields: [{ key: "password", label: t("currentPassword"), type: "password", required: true }],
    onConfirm: async (values) => {
      await props.store.addSSHKey(publicKey, keyComment.value.trim(), values.password);
      keyPublic.value = "";
      keyComment.value = "";
      keyFormOpen.value = false;
    },
  });
}

function removePublicKey(item) {
  const keys = props.store.state.sshProtection.keys || [];
  const lastKeyWithPasswordDisabled = keys.length <= 1 && props.store.state.sshProtection.settings.allow_password_login === false;
  const legacyConsoleKey = !item?.nodewall_managed && String(item?.comment || "").trim().toLowerCase() === "nodewall-console";
  const unknownNodeWallKey = Boolean(item?.nodewall_managed) && !item?.nodewall_active_known;
  const requiresConfirmation = Boolean(item?.nodewall_active) || unknownNodeWallKey || legacyConsoleKey || lastKeyWithPasswordDisabled;
  if (!requiresConfirmation) {
    props.store.removeSSHKey(item.fingerprint).catch(props.store.handleError);
    return;
  }
  openNodeConfirmation({
    title: t("sshKeyRemoveConfirmTitle"),
    copy: t("sshKeyRemoveConfirmCopy", { fingerprint: item.fingerprint }),
    fields: [{ key: "password", label: t("currentPassword"), type: "password", required: true }],
    onConfirm: (values) => props.store.removeSSHKey(item.fingerprint, values.password),
  });
}

function keyStatus(item) {
  if (item?.nodewall_active) return t("sshKeyCurrent");
  if (item?.nodewall_managed && !item?.nodewall_active_known) return t("sshKeyUnknownConsole");
  if (item?.nodewall_managed) return t("sshKeyHistorical");
  return "-";
}

watch(() => [props.store.state.nodeId, props.store.state.sshProtection?.node_id], () => {
  activitySession.value = "";
  activitySource.value = "";
  activityType.value = "";
}, { immediate: true });
function selectSession(id) { activitySession.value = id; }

function formatActivityTime(value) {
  if (!value) return "-";
  return formatDateTime(value, props.store.state.locale === "en-US" ? "en-US" : "zh-CN");
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
  <section class="page-grid ssh-protection-page">
    <div class="ssh-status-strip">
      <div class="ssh-status-item">
        <Terminal :size="16" aria-hidden="true" />
        <span>{{ t("sshDetectedPorts") }}</span>
        <strong>{{ (ssh.ports || []).join(", ") || "—" }}</strong>
      </div>
      <div class="ssh-status-item">
        <Users :size="16" aria-hidden="true" />
        <span>{{ t("sshTrackedSources") }}</span>
        <strong>{{ settingsAvailable ? ssh.tracked_sources ?? 0 : "—" }}</strong>
      </div>
      <button type="button" class="ssh-status-item ssh-block-link" @click="activePanel = 'blocks'">
        <Ban :size="16" aria-hidden="true" />
        <span>{{ t("sshBlocksTitle") }}</span>
        <strong>{{ settingsAvailable ? activeBlocks.length : "—" }}</strong>
      </button>
    </div>

    <nav class="security-subnav" :aria-label="t('navSSHProtection')">
      <button v-for="item in panels" :key="item.key" type="button" :aria-pressed="activePanel === item.key" @click="activePanel = item.key">
        {{ item.label }}
      </button>
    </nav>

    <div v-if="ssh.last_error" class="ssh-settings-error" role="alert">{{ ssh.last_error }}</div>

    <div v-if="activePanel === 'settings'" class="ssh-settings-columns workspace-fill">
      <div class="ssh-settings-stack">
        <article class="panel ssh-settings-panel">
          <div class="panel-head">
            <h3>{{ t("sshProtectionTitle") }}</h3>
            <label class="ssh-enable-control">
              <input v-model="protectionDraft.enabled" type="checkbox" role="switch" class="ssh-switch" :aria-label="t('sshProtectionSwitch')" :disabled="!canConfigure || settingsSaving" />
              <span>{{ ssh.loading ? t("loading") : !settingsAvailable ? t("protectionUnavailable") : t(protectionDraft.enabled ? "enabled" : "disabled") }}</span>
            </label>
          </div>
          <div class="ssh-thresholds">
            <label class="field">
              <span>{{ t("sshFailThreshold") }}</span>
              <input v-model.number="protectionDraft.max_failures" type="number" min="1" max="100" :disabled="!canConfigure || settingsSaving" />
            </label>
            <label class="field">
              <span>{{ t("sshWindowSeconds") }}</span>
              <input v-model.number="protectionDraft.window_seconds" type="number" min="30" :disabled="!canConfigure || settingsSaving" />
            </label>
            <label class="field">
              <span>{{ t("sshBanSeconds") }}</span>
              <input v-model.number="protectionDraft.ban_duration_seconds" type="number" min="60" :disabled="!canConfigure || settingsSaving" />
            </label>
          </div>
          <label class="field ssh-trusted">
            <span>{{ t("sshTrustedCIDRs") }}</span>
            <input :value="trustedCIDRsText" :placeholder="t('sshTrustedCIDRsPlaceholder')" :disabled="!canConfigure || settingsSaving" @input="updateTrustedCIDRs" />
          </label>
          <SettingsSaveBar
            compact
            :session="protectionSession"
            :loaded="canConfigure"
            :busy="Boolean(saveBusy.protection)"
            :disabled="settingsSaving"
            :error="protectionSession.dirty.value ? saveErrors.protection : ''"
            @save="saveProtection"
          />
        </article>

        <article class="panel ssh-authentication-panel">
          <div class="panel-head"><h3>{{ t("sshLoginMethod") }}</h3></div>
          <div class="ssh-setting-row">
            <label for="ssh-password-login">{{ t("sshPasswordLogin") }}</label>
            <select id="ssh-password-login" v-model="authenticationDraft.allow_password_login" :disabled="!canConfigure || settingsSaving || ssh.settings.allow_password_login == null">
              <option :value="true">{{ t("sshPasswordLoginAllowed") }}</option>
              <option :value="false">{{ t("sshPasswordLoginDisabled") }}</option>
            </select>
          </div>
          <SettingsSaveBar
            compact
            :session="authenticationSession"
            :label="t('sshSavePasswordLogin')"
            :loaded="canConfigure"
            :disabled="settingsSaving"
            @save="savePasswordLoginPolicy"
          />
        </article>
      </div>

      <article class="panel ssh-transfer-panel">
        <div class="panel-head">
          <h3>{{ t("sshTransferTitle") }}</h3>
          <span v-if="settingsAvailable && ssh.transfer_effective" class="status-pill accent">{{ t("sshTransferEffective") }}</span>
          <span v-else-if="settingsAvailable && ssh.last_error" class="status-pill warning">{{ t("sshTransferNotVerified") }}</span>
        </div>
        <div class="ssh-protocols">
          <label class="field">
            <span>{{ t("sshBlockSFTP") }}</span>
            <select v-model="transferDraft.block_sftp" :disabled="!canConfigure || settingsSaving">
              <option :value="false">{{ t("sshAllowed") }}</option>
              <option :value="true">{{ t("sshBlocked") }}</option>
            </select>
          </label>
          <label class="field">
            <span>{{ t("sshBlockSCP") }}</span>
            <select v-model="transferDraft.block_scp" :disabled="!canConfigure || settingsSaving">
              <option :value="false">{{ t("sshAllowed") }}</option>
              <option :value="true">{{ t("sshBlocked") }}</option>
            </select>
          </label>
        </div>
        <div class="ssh-audit-list">
          <div v-for="item in auditOptions" :key="item.key" class="ssh-setting-row">
            <div class="ssh-audit-label">
              <label :for="'ssh-transfer-' + item.key">{{ t(item.label) }}</label>
              <InfoTip v-if="item.hint" :text="t(item.hint)" />
            </div>
            <input :id="'ssh-transfer-' + item.key" v-model="transferDraft[item.key]" type="checkbox" role="switch" class="ssh-switch" :disabled="!canConfigure || settingsSaving" />
          </div>
        </div>
        <dl class="ssh-upload-summary">
          <div><dt>{{ t("sshUploadLastStatus") }}</dt><dd>{{ ssh.upload_security?.last_status ? uploadStatusLabel(ssh.upload_security.last_status) : t("sshNotChecked") }}</dd></div>
          <div><dt>{{ t("sshUploadFilesChecked") }}</dt><dd>{{ settingsAvailable ? ssh.upload_security?.files_checked ?? 0 : "—" }}</dd></div>
          <div><dt>{{ t("sshUploadFindings") }}</dt><dd>{{ settingsAvailable ? ssh.upload_security?.findings ?? 0 : "—" }}</dd></div>
        </dl>
        <SettingsSaveBar
          compact
          :session="transferSession"
          :label="t('sshTransferSave')"
          :loaded="canConfigure"
          :busy="Boolean(saveBusy.transfer)"
          :disabled="settingsSaving"
          :error="transferSession.dirty.value ? saveErrors.transfer : ''"
          @save="saveTransferPolicy"
        />
      </article>
    </div>

    <article v-else-if="activePanel === 'keys'" class="panel ssh-detail-panel ssh-keys-panel workspace-fill workspace-panel">
      <div class="panel-head">
        <h3>{{ t("sshKeysTitle") }}</h3>
        <button type="button" class="ghost-button" :aria-expanded="keyFormOpen" :disabled="!canConfigure" @click="keyFormOpen = !keyFormOpen">
          <KeyRound :size="16" aria-hidden="true" />{{ keyFormOpen ? t("cancel") : t("sshKeyAdd") }}
        </button>
      </div>
      <form v-if="keyFormOpen" class="ssh-key-form" @submit.prevent="addPublicKey">
        <label class="field ssh-key-input">
          <span>{{ t("sshPublicKey") }}</span>
          <textarea v-model="keyPublic" rows="3" :placeholder="t('sshPublicKeyPlaceholder')"></textarea>
        </label>
        <label class="field">
          <span>{{ t("sshKeyComment") }}</span>
          <input v-model="keyComment" type="text" :placeholder="t('sshKeyCommentPlaceholder')" />
        </label>
        <div class="inline-actions ssh-key-add-action">
          <button type="submit" class="primary-button" :disabled="!canConfigure || !keyPublic.trim()">
            <KeyRound :size="16" stroke-width="2" aria-hidden="true" />
            {{ t("sshKeyAdd") }}
          </button>
        </div>
      </form>
      <div v-if="!(props.store.state.sshProtection.keys || []).length" class="empty-state">{{ t("sshKeysEmpty") }}</div>
      <div v-else class="table-shell">
        <table class="console-table ssh-keys-table">
          <thead>
            <tr>
              <th>{{ t("sshKeyType") }}</th>
              <th>{{ t("sshKeyFingerprint") }}</th>
              <th>{{ t("sshKeyComment") }}</th>
              <th>{{ t("sshKeyOptions") }}</th>
              <th>{{ t("policyTableActions") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in props.store.state.sshProtection.keys" :key="item.fingerprint">
              <td>{{ item.type }}</td>
              <td class="ssh-key-fingerprint" :title="item.public_key">{{ item.fingerprint }}</td>
              <td><span>{{ item.comment || "-" }}</span><span v-if="item.nodewall_active || item.nodewall_managed" class="ssh-key-status" :class="{ active: item.nodewall_active }">{{ keyStatus(item) }}</span></td>
              <td :title="(item.options || []).join(', ')">{{ (item.options || []).join(", ") || "-" }}</td>
              <td><button type="button" class="icon-button table-action-button danger" :disabled="!canConfigure" :title="t('sshKeyRemove')" :aria-label="t('sshKeyRemove')" @click="removePublicKey(item)"><Trash2 :size="16" stroke-width="1.8" aria-hidden="true" /></button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </article>

    <article v-else-if="activePanel === 'blocks'" class="panel ssh-detail-panel workspace-fill workspace-panel">
      <div class="panel-head">
        <h3>{{ t("sshBlocksTitle") }}</h3>
        <strong>{{ (props.store.state.sshProtection.active_blocks || []).length }}</strong>
      </div>
      <div class="table-toolbar">
        <input v-model="blockQuery" type="search" :placeholder="t('sshBlocksSearch')" :aria-label="t('sshBlocksSearch')" />
      </div>
      <div v-if="!filteredBlocks.length" class="empty-state">{{ activeBlocks.length ? t("sshBlocksNoMatches") : t("sshNoBlocks") }}</div>
      <div v-else class="table-shell">
        <table class="console-table ssh-blocks-table">
          <thead>
            <tr>
              <th>{{ t("sourceIp") }}</th>
              <th>{{ t("port") }}</th>
              <th>{{ t("expiresAt") }}</th>
              <th>{{ t("policyTableActions") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in visibleBlocks" :key="item.id">
              <td :title="item.source_ip">{{ item.source_ip }}</td>
              <td>{{ item.port || 22 }}</td>
              <td>{{ item.expires_at || "-" }}</td>
              <td><button type="button" class="icon-button table-action-button" :disabled="!canConfigure" :title="t('sshRelease')" :aria-label="t('sshRelease')" @click="props.store.releaseSSHProtectionBlock(item.id).catch(props.store.handleError)"><UnlockKeyhole :size="16" stroke-width="1.8" aria-hidden="true" /></button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <TablePagination v-model:page="blockPage" v-model:page-size="blockPageSize" :total="filteredBlocks.length" />
    </article>

    <article v-else class="panel ssh-detail-panel workspace-fill workspace-panel">
      <div class="panel-head">
        <h3>{{ t("sshActivityTitle") }}</h3>
      </div>
      <div class="ssh-activity-filters">
        <InlineSelect v-model="activityType" :options="activityTypes" :aria-label="t('sshActivityEvent')" />
        <input v-model="activitySource" :placeholder="t('sshActivitySourceFilter')" :aria-label="t('sshActivitySourceFilter')" />
        <button v-if="activitySession" class="ghost-button" :title="activitySession" @click="selectSession('')">{{ t("sshActivityClearSession") }}</button>
      </div>
      <div v-if="!filteredActivity.length" class="empty-state">{{ t(activity.length ? "sshActivityNoMatches" : "sshActivityEmpty") }}</div>
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
            <tr v-for="record in visibleActivity" :key="record.id || `${record.session_id}-${record.at}-${record.event}-${record.action}-${record.command || record.path || ''}`">
              <td>{{ formatActivityTime(record.at) }}</td>
              <td>{{ activityEvent(record) }}</td>
              <td :title="activityTarget(record)">
                <div>{{ record.user || "-" }} · {{ record.source_ip || "-" }}{{ record.source_port ? `:${record.source_port}` : "" }}</div>
                <button v-if="record.session_id" class="ghost-button ssh-session-link" :title="t('sshActivitySessionHint', { id: record.session_id })" @click="selectSession(record.session_id)">{{ record.session_id }}</button>
              </td>
              <td class="ssh-activity-target" :title="activityTarget(record)"><span class="table-cell-clip">{{ activityTarget(record) }}{{ record.truncated ? "…" : "" }}</span></td>
              <td :title="record.detail || undefined">{{ activityResult(record) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <TablePagination v-model:page="activityPage" v-model:page-size="activityPageSize" :total="filteredActivity.length" />
    </article>
  </section>
</template>

<style scoped>
.ssh-status-strip {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--bg-panel);
}
.ssh-status-item {
  position: relative;
  display: flex;
  min-width: 0;
  min-height: 36px;
  align-items: center;
  gap: 9px;
  padding: 4px 12px;
  color: var(--muted-strong);
  font-size: 13px;
  text-align: start;
}
.ssh-status-item + .ssh-status-item::before {
  position: absolute;
  inset-block: 0;
  inset-inline-start: 0;
  inline-size: 1px;
  background: var(--line);
  pointer-events: none;
  content: "";
}
.ssh-status-item svg { flex: none; color: var(--accent-strong); }
.ssh-status-item strong { margin-inline-start: auto; color: var(--text); overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }
.ssh-status-strip > .ssh-block-link { border: 0; background: transparent; box-shadow: none; }
.ssh-status-strip > .ssh-block-link:hover { color: var(--accent-strong); background: var(--accent-soft); }
.ssh-settings-columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--panel-gap); }
.ssh-settings-stack { display: grid; min-width: 0; grid-template-rows: 1fr auto; gap: var(--panel-gap); }
.ssh-settings-columns .panel, .ssh-detail-panel { grid-column: auto; min-width: 0; }
.ssh-settings-columns .panel { display: flex; flex-direction: column; }
.ssh-settings-columns :deep(.settings-save-bar.compact) { margin-top: auto; }
.ssh-settings-columns :is(.ssh-trusted, .ssh-upload-summary, .ssh-authentication-panel .ssh-setting-row) { margin-bottom: 12px; }
.ssh-settings-columns select { appearance: auto; }
.ssh-enable-control, .ssh-audit-label { display: inline-flex; align-items: center; gap: 8px; }
.ssh-enable-control { color: var(--muted-strong); font-size: 12px; }
.ssh-thresholds { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
.ssh-thresholds input, .ssh-trusted input, .ssh-protocols select { width: 100%; }
.ssh-trusted { margin-top: 14px; }
.ssh-protocols { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.ssh-audit-list { margin-top: 14px; }
.ssh-setting-row { display: flex; min-height: 38px; align-items: center; justify-content: space-between; gap: 10px; font-size: 13px; }
.ssh-audit-list .ssh-setting-row + .ssh-setting-row { border-top: 1px solid var(--line); }
.ssh-setting-row select { width: min(100%, 240px); }
input.ssh-switch {
  appearance: none;
  position: relative;
  width: 34px;
  height: 20px;
  min-height: 0;
  flex: none;
  margin: 0;
  padding: 0;
  border: 1px solid var(--line);
  border-radius: 20px;
  background: var(--bg-soft);
  cursor: pointer;
}
.ssh-switch::before {
  position: absolute;
  inset: 2px auto 2px 2px;
  width: 14px;
  border-radius: 50%;
  background: var(--muted);
  content: "";
}
input.ssh-switch:checked { border-color: var(--accent-strong); background: var(--accent-strong); }
.ssh-switch:checked::before { inset-inline: auto 2px; background: white; }
input.ssh-switch:disabled { cursor: default; opacity: .55; }
.ssh-upload-summary { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 12px 0 0; padding: 10px; border-radius: 8px; background: var(--bg-soft); }
.ssh-upload-summary dt { color: var(--muted-strong); font-size: 12px; }
.ssh-upload-summary dd { margin: 4px 0 0; color: var(--text); font-size: 13px; font-weight: 650; overflow-wrap: anywhere; }
.ssh-settings-error { padding: 9px 12px; border-radius: 8px; background: var(--danger-soft); color: var(--danger); font-size: 13px; overflow-wrap: anywhere; }
.ssh-detail-panel :deep(.table-shell) { overflow-x: auto; }
.ssh-detail-panel :deep(.table-shell table) { min-width: 520px; }
.ssh-activity-filters { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 12px; }
.ssh-activity-filters input { width: min(240px, 100%); }
.ssh-session-link { max-width: 100%; min-height: 28px; padding: 3px 0; font-size: 12px; overflow: hidden; text-overflow: ellipsis; }
.ssh-key-form { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr) auto; align-items: end; gap: 12px; margin-bottom: 14px; }
.ssh-key-input textarea { min-height: 76px; resize: vertical; font-family: var(--mono-font, monospace); font-size: 12px; }
.ssh-key-fingerprint { max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono-font, monospace); }
@media (max-width: 1100px) {
  .ssh-settings-columns { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 650px) {
  .ssh-status-strip { grid-template-columns: minmax(0, 1fr); }
  .ssh-status-item + .ssh-status-item::before { inset: 0 12px auto; inline-size: auto; block-size: 1px; }
  .ssh-key-form { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 410px) {
  .ssh-thresholds { grid-template-columns: minmax(0, 1fr); }
  .ssh-authentication-panel .ssh-setting-row { align-items: stretch; flex-direction: column; }
}
</style>
