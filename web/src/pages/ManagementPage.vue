<script setup>
import { computed, onBeforeUnmount, reactive, ref, watch } from "vue";
import { ArrowUpRight, Bell, Fingerprint, Globe2, Logs, Server, ShieldCheck, Trash2 } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import { request } from "@/lib/api";
import { useSettingsDraft } from "@/composables/useSettingsDraft";
import SettingsSaveBar from "@/components/SettingsSaveBar.vue";
import { useTimeZone } from "@/lib/time";

const props = defineProps({ store: { type: Object, required: true } });
const { t } = useI18n();
const { state: timeZoneState, options: timeZoneOptions, setTimeZone } = useTimeZone();
const groups = computed(() => [
  { id: "display", title: t("settingsDisplayGroup"), copy: t("settingsDisplayHint"), icon: Globe2 },
  { id: "security", title: t("settingsLoginSecurity"), copy: t("settingsLoginHint"), icon: ShieldCheck },
  { id: "passkey", title: t("settingsPasskeyGroup"), copy: t("passkeyRequirements"), icon: Fingerprint },
  { id: "notifications", title: t("settingsMailGroup"), copy: t("settingsMailHint"), icon: Bell },
  { id: "audit", title: t("settingsAuditGroup"), copy: t("settingsLoggingHint"), icon: Logs },
  { id: "nodes", title: t("settingsPolicyGroup"), copy: t("settingsPolicyHint"), icon: Server },
]);
const initialQuery = new URLSearchParams(window.location.search);
const initialGroup = initialQuery.get("settings");
const settingsGroup = ref(groups.value.some((item) => item.id === initialGroup) ? initialGroup : "security");
const activeGroup = computed(() => groups.value.find((item) => item.id === settingsGroup.value));
const sessions = Object.fromEntries(Object.entries({
  auth: ["max_failures", "window_seconds", "lock_duration_seconds", "mfa_required", "require_mfa_for_admin", "allowed_mfa_methods"],
  passkey: ["enabled", "rp_id", "origins", "tls_mode", "certificate_pem", "private_key_pem"],
  smtp: ["enabled", "host", "port", "security", "username", "password", "from_email", "from_name", "subject_prefix", "reset_subject", "reset_template", "verify_subject", "verify_template"],
  logging: ["enabled", "retention_days", "flush_interval_seconds", "reply_flow_timeout_seconds", "log_dir"],
}).map(([key, fields]) => [key, useSettingsDraft(() => props.store.state[`${key}Settings`], () => props.store.state.settingsETags[key], fields)]));
const auth = sessions.auth.draft;
const passkey = sessions.passkey.draft;
const smtp = sessions.smtp.draft;
const logging = sessions.logging.draft;
const busy = reactive({});
const errors = reactive({});
const settingsPanel = ref(null);
const nodeQuery = ref("");
const selectedNodeIDs = ref(new Set());
const sourceNodeID = ref(initialQuery.get("source_node") || props.store.state.nodeId || "");
const sourceInterface = ref("");
const sourceInterfaces = ref([]);
const sourceDirection = ref(initialQuery.get("source_direction") === "egress" ? "egress" : "ingress");
const inventoryLoading = ref(false);
const inventoryError = ref("");
const policyResults = ref([]);
const targetInterfaces = reactive({});
const targetInventories = reactive({});
const targetLoading = reactive({});
const targetControllers = new Map();
let inventoryController;

watch(settingsGroup, (group) => {
  const url = new URL(window.location.href);
  url.searchParams.set("settings", group);
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
  props.store.setManagementScope(group === "nodes" ? "node" : "global");
}, { immediate: true });

watch(() => props.store.state.nodes, (nodes) => {
  const ids = new Set((nodes || []).map((item) => item.id));
  selectedNodeIDs.value = new Set([...selectedNodeIDs.value].filter((id) => ids.has(id) && id !== sourceNodeID.value));
  if (!ids.has(sourceNodeID.value)) sourceNodeID.value = nodes?.[0]?.id || "";
}, { deep: true });

async function loadSourceInventory() {
  inventoryController?.abort();
  inventoryLoading.value = false;
  selectedNodeIDs.value = new Set([...selectedNodeIDs.value].filter((id) => id !== sourceNodeID.value));
  if (settingsGroup.value !== "nodes") return;
  sourceInterface.value = "";
  sourceInterfaces.value = [];
  inventoryError.value = "";
  if (!sourceNodeID.value) return;
  const controller = new AbortController();
  inventoryController = controller;
  inventoryLoading.value = true;
  try {
    const value = await request(`/nodes/${encodeURIComponent(sourceNodeID.value)}/interfaces`, { signal: controller.signal });
    if (controller.signal.aborted) return;
    const interfaces = value.interfaces || [];
    const physical = interfaces.filter((item) => item.is_physical);
    sourceInterfaces.value = physical.length ? physical : interfaces;
    const query = new URLSearchParams(window.location.search);
    const desired = query.get("source_node") === sourceNodeID.value ? query.get("source_iface") : "";
    sourceInterface.value = sourceInterfaces.value.find((item) => item.name === desired)?.name || sourceInterfaces.value.find((item) => item.name === value.recommended)?.name || sourceInterfaces.value[0]?.name || "";
  } catch (error) {
    if (!controller.signal.aborted) inventoryError.value = t("settingsInventoryFailed");
  } finally {
    if (inventoryController === controller) inventoryLoading.value = false;
  }
}
watch(() => [settingsGroup.value, sourceNodeID.value], loadSourceInventory, { immediate: true });
watch(() => [sourceNodeID.value, sourceInterface.value, sourceDirection.value], () => {
  if (settingsGroup.value !== "nodes" || !sourceInterface.value) return;
  const url = new URL(window.location.href);
  url.searchParams.set("source_node", sourceNodeID.value);
  url.searchParams.set("source_iface", sourceInterface.value);
  url.searchParams.set("source_direction", sourceDirection.value);
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
});
onBeforeUnmount(() => { inventoryController?.abort(); for (const controller of targetControllers.values()) controller.abort(); });

const visibleNodes = computed(() => {
  const query = nodeQuery.value.trim().toLowerCase();
  return props.store.state.nodes.filter((node) => !query || [node.id, node.name, node.advertise_ip].filter(Boolean).join(" ").toLowerCase().includes(query));
});
const passkeyOriginsText = computed({
  get: () => (passkey.origins || []).join("\n"),
  set: (value) => { passkey.origins = value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean); },
});
const loggingNodeName = computed(() => props.store.state.nodes.find((node) => node.id === props.store.state.loggingNodeID)?.name || props.store.state.loggingNodeID || "—");
function online(node) {
  return props.store.isNodeOnline(node);
}
function protectionStatus(node) {
  return online(node) ? props.store.state.nodeProtection[node.id]?.protection_status || "loading" : "unavailable";
}
function protectionLabel(node) { return t(({ enforced: "protectionEnforced", not_enabled: "protectionNotEnabled", degraded: "protectionDegraded", loading: "protectionLoading" })[protectionStatus(node)] || "protectionUnavailable"); }
function toggleNode(id) {
  const next = new Set(selectedNodeIDs.value);
  if (next.has(id)) next.delete(id); else { next.add(id); loadTargetInterfaces(id); }
  selectedNodeIDs.value = next;
}
async function loadTargetInterfaces(id) {
  if (targetInventories[id]?.length || targetLoading[id]) return;
  const controller = new AbortController();
  targetControllers.set(id, controller);
  targetLoading[id] = true;
  try {
    const value = await request(`/nodes/${encodeURIComponent(id)}/interfaces`, { signal: controller.signal });
    if (controller.signal.aborted) return;
    const items = value.interfaces || [];
    const physical = items.filter((item) => item.is_physical);
    targetInventories[id] = physical.length ? physical : items;
    targetInterfaces[id] = targetInventories[id].find((item) => item.name === value.recommended)?.name || targetInventories[id][0]?.name || "";
  } catch (error) {
    if (!controller.signal.aborted) props.store.handleError(error);
  } finally { targetLoading[id] = false; targetControllers.delete(id); }
}
const canApplyTemplate = computed(() => !busy.nodes && !inventoryLoading.value && !!sourceInterface.value && selectedNodeIDs.value.size > 0
  && props.store.state.nodes.some((node) => node.id === sourceNodeID.value && online(node))
  && [...selectedNodeIDs.value].every((id) => !targetLoading[id] && targetInterfaces[id] && props.store.state.nodes.some((node) => node.id === id && online(node))));
async function openNodeSecurity(id) {
  await props.store.setNode(id);
  props.store.setSection("security");
  props.store.setSecurityFeature("overview");
}
async function save(key) {
  if (busy[key] || sessions[key].conflicts.value.length) return;
  const invalid = settingsPanel.value?.querySelector("input:invalid, select:invalid, textarea:invalid");
  if (invalid) { invalid.reportValidity(); return; }
  busy[key] = true;
  errors[key] = "";
  const methods = { auth: "saveAuthSettings", passkey: "savePasskeySettings", smtp: "saveSMTPSettings", logging: "saveLoggingSettings" };
  try {
    const result = await props.store[methods[key]]({ ...sessions[key].draft }, { etag: sessions[key].etag.value });
    sessions[key].reset(result);
  } catch (error) {
    errors[key] = error.code === "CONFIG_CHANGED" ? t("settingsConflict") : error.message;
    if (error.code === "CONFIG_CHANGED") await props.store.refreshManagementSettings();
  } finally { busy[key] = false; }
}
async function readPasskeyFile(event, field) {
  const file = event.target.files?.[0];
  if (file) passkey[field] = await file.text();
  event.target.value = "";
}
function changeTLSMode(value) {
  passkey.tls_mode = value;
  if (value === "proxy") { passkey.certificate_pem = ""; passkey.private_key_pem = ""; }
}
async function applyProtectionTemplate() {
  if (!canApplyTemplate.value) return;
  const source = { sourceNodeID: sourceNodeID.value, interface: sourceInterface.value, direction: sourceDirection.value, targetInterfaces: Object.fromEntries([...selectedNodeIDs.value].map((id) => [id, targetInterfaces[id]])) };
  const targets = [...selectedNodeIDs.value].filter((id) => id !== source.sourceNodeID && props.store.state.nodes.some((node) => node.id === id && online(node)));
  if (!targets.length) return;
  busy.nodes = true;
  policyResults.value = [];
  try {
    const response = await props.store.copyPolicyToNodes(targets, source);
    if (!response) return;
    policyResults.value = response.results || [];
    selectedNodeIDs.value = new Set(policyResults.value.filter((item) => item.status === "failed").map((item) => item.node_id));
  } catch (error) { props.store.handleError(error); }
  finally { busy.nodes = false; }
}
</script>

<template>
  <section class="settings-workspace">
    <aside class="settings-navigation" :aria-label="t('navManagement')">
      <div class="settings-nav-caption">{{ t("settingsCategories") }}</div>
      <button v-for="group in groups" :key="group.id" type="button" class="settings-category" :class="{ active: settingsGroup === group.id }" :aria-current="settingsGroup === group.id ? 'page' : undefined" @click="settingsGroup = group.id">
        <component :is="group.icon" :size="17" /><span>{{ group.title }}</span>
        <i v-if="({ security: 'auth', passkey: 'passkey', notifications: 'smtp', audit: 'logging' })[group.id] && sessions[({ security: 'auth', passkey: 'passkey', notifications: 'smtp', audit: 'logging' })[group.id]].dirty.value" class="settings-dirty-dot" :title="t('settingsUnsaved')" />
      </button>
      <div class="settings-account-link"><span>{{ t("settingsPersonalHint") }}</span><button class="text-button" @click="props.store.setSection('account')">{{ t("navAccount") }}<ArrowUpRight :size="14" /></button></div>
    </aside>

    <div class="settings-content">
      <article ref="settingsPanel" class="panel settings-detail-panel workspace-fill workspace-panel">
        <header class="settings-detail-heading">
          <div><h2>{{ activeGroup.title }}</h2><p>{{ activeGroup.copy }}</p></div>
        </header>

        <template v-if="settingsGroup === 'display'">
          <div class="settings-form">
            <div class="settings-section-title"><h3>{{ t("settingsDisplayGroup") }}</h3><span class="status-pill success">{{ timeZoneState.timeZone }}</span></div>
            <div class="settings-field-grid">
              <label class="field"><span>{{ t("timeZone") }}</span><select :value="timeZoneState.timeZone" @change="setTimeZone($event.target.value)"><option v-for="item in timeZoneOptions" :key="item.value" :value="item.value">{{ t(item.labelKey) }}</option></select></label>
            </div>
            <p class="field-hint">{{ t("timeZoneHint") }}</p>
          </div>
        </template>

        <template v-else-if="settingsGroup === 'security'">
          <fieldset class="settings-form" :disabled="!props.store.state.settingsLoaded.auth || busy.auth">
            <div class="settings-section-title"><h3>{{ t("managementAuthTitle") }}</h3><span class="field-hint">{{ t("activeLocks") }} · {{ props.store.state.authSettings.active_locks || 0 }}</span></div>
            <div class="settings-field-grid three">
              <label class="field"><span>{{ t("failThreshold") }}</span><input v-model.number="auth.max_failures" type="number" min="1" max="100" /></label>
              <label class="field"><span>{{ t("statsWindow") }}</span><input v-model.number="auth.window_seconds" type="number" min="60" /></label>
              <label class="field"><span>{{ t("lockDuration") }}</span><input v-model.number="auth.lock_duration_seconds" type="number" min="60" /></label>
            </div>
            <div class="settings-form-section">
              <h3>{{ t("mfaAllowedMethods") }}</h3>
              <div class="settings-choice-row"><label class="check-row"><input v-model="auth.allowed_mfa_methods" value="otp" type="checkbox" /> OTP / TOTP</label><label class="check-row"><input v-model="auth.allowed_mfa_methods" value="passkey" type="checkbox" /> Passkey</label></div>
              <div class="settings-choice-row"><label class="check-row"><input v-model="auth.mfa_required" type="checkbox" />{{ t("mfaRequiredAll") }}</label><label class="check-row"><input v-model="auth.require_mfa_for_admin" type="checkbox" />{{ t("mfaRequiredAdmin") }}</label></div>
              <p class="field-hint">{{ t("mfaPolicyHint") }}</p>
            </div>
          </fieldset>
          <SettingsSaveBar :session="sessions.auth" :loaded="props.store.state.settingsLoaded.auth" :busy="busy.auth" :error="errors.auth" @save="save('auth')" />
        </template>

        <template v-else-if="settingsGroup === 'passkey'">
          <fieldset class="settings-form" :disabled="!props.store.state.settingsLoaded.passkey || busy.passkey">
            <div class="settings-section-title"><label class="check-row"><input v-model="passkey.enabled" type="checkbox" />{{ t("passkeyEnabled") }}</label><span class="status-pill" :class="props.store.state.passkeySettings.requirements_met ? 'success' : 'muted'">{{ props.store.state.passkeySettings.requirements_met ? t("passkeyReady") : t("passkeyNotReady") }}</span></div>
            <div class="settings-field-grid">
              <label class="field"><span>{{ t("passkeyRPID") }}</span><input v-model="passkey.rp_id" placeholder="nodewall.example.com" /></label>
              <label class="field"><span>{{ t("passkeyTLSMode") }}</span><select :value="passkey.tls_mode" @change="changeTLSMode($event.target.value)"><option value="local">{{ t("passkeyTLSLocal") }}</option><option value="proxy">{{ t("passkeyTLSProxy") }}</option></select></label>
            </div>
            <label class="field"><span>{{ t("passkeyOrigins") }}</span><textarea v-model="passkeyOriginsText" rows="2" placeholder="https://nodewall.example.com:8086" /></label>
            <p v-if="passkey.tls_mode === 'proxy'" class="field-hint">{{ t("passkeyProxyHint") }}</p>
            <template v-else>
              <p class="field-hint">{{ t("passkeyLocalHint") }}</p>
              <details class="settings-advanced"><summary>{{ t("settingsCertificate") }}<span class="status-pill" :class="props.store.state.passkeySettings.certificate_valid ? 'success' : 'muted'">{{ props.store.state.passkeySettings.certificate_valid ? t("passkeyCertificateReady") : t("passkeyCertificateMissing") }}</span></summary>
                <div class="settings-field-grid">
                  <label class="field"><span>{{ t("passkeyCertificate") }}</span><input type="file" accept=".pem,.crt,.cer" @change="readPasskeyFile($event, 'certificate_pem')" /><textarea v-model="passkey.certificate_pem" rows="3" placeholder="-----BEGIN CERTIFICATE-----" /></label>
                  <label class="field"><span>{{ t("passkeyPrivateKey") }}</span><input type="file" accept=".pem,.key" @change="readPasskeyFile($event, 'private_key_pem')" /><textarea v-model="passkey.private_key_pem" rows="3" placeholder="-----BEGIN PRIVATE KEY-----" /></label>
                </div>
                <p v-if="props.store.state.passkeySettings.certificate_dns_names?.length" class="field-hint">{{ t("passkeyCertificateNames", { value: props.store.state.passkeySettings.certificate_dns_names.join(', ') }) }}</p>
                <p v-if="props.store.state.passkeySettings.certificate_valid && !props.store.state.passkeySettings.certificate_ip_compatible" class="field-hint">{{ t("passkeyCertificateIPWarning") }}</p>
              </details>
            </template>
          </fieldset>
          <SettingsSaveBar :session="sessions.passkey" :loaded="props.store.state.settingsLoaded.passkey" :busy="busy.passkey" :error="errors.passkey" @save="save('passkey')" />
        </template>

        <template v-else-if="settingsGroup === 'notifications'">
          <fieldset class="settings-form" :disabled="!props.store.state.settingsLoaded.smtp || busy.smtp">
            <label class="check-row"><input v-model="smtp.enabled" type="checkbox" />{{ t("smtpEnabled") }}</label>
            <h3>{{ t("settingsMailConnection") }}</h3>
            <div class="settings-field-grid three">
              <label class="field settings-field-wide"><span>{{ t("smtpHost") }}</span><input v-model="smtp.host" required placeholder="smtp.example.com" /></label>
              <label class="field"><span>{{ t("smtpPort") }}</span><input v-model.number="smtp.port" type="number" min="1" max="65535" /></label>
              <label class="field"><span>{{ t("smtpSecurity") }}</span><select v-model="smtp.security"><option value="starttls">STARTTLS</option><option value="smtps">SMTPS</option><option value="plain">{{ t("smtpPlain") }}</option></select></label>
              <label class="field"><span>{{ t("smtpUsername") }}</span><input v-model="smtp.username" autocomplete="off" /></label>
              <label class="field"><span>{{ t("smtpPassword") }}</span><input v-model="smtp.password" type="password" autocomplete="new-password" :placeholder="props.store.state.smtpSettings.has_password ? t('smtpPasswordStored') : ''" /></label>
            </div>
            <div class="settings-form-section"><h3>{{ t("settingsMailSender") }}</h3>
              <div class="settings-field-grid"><label class="field"><span>{{ t("smtpFrom") }}</span><input v-model="smtp.from_email" required type="email" /></label><label class="field"><span>{{ t("smtpFromName") }}</span><input v-model="smtp.from_name" /></label></div>
            </div>
            <details class="settings-advanced"><summary>{{ t("settingsMailTemplates") }}</summary><div class="settings-field-grid">
              <label class="field settings-field-wide"><span>{{ t("smtpSubjectPrefix") }}</span><input v-model="smtp.subject_prefix" /></label>
              <label class="field"><span>{{ t("settingsResetSubject") }}</span><input v-model="smtp.reset_subject" /></label><label class="field"><span>{{ t("settingsVerifySubject") }}</span><input v-model="smtp.verify_subject" /></label>
              <label class="field"><span>{{ t("smtpResetTemplate") }}</span><textarea v-model="smtp.reset_template" rows="4" /></label><label class="field"><span>{{ t("smtpVerifyTemplate") }}</span><textarea v-model="smtp.verify_template" rows="4" /></label>
            </div></details>
          </fieldset>
          <div class="settings-test-row"><span class="field-hint">{{ t("settingsMailTestHint") }}</span><button class="ghost-button" :disabled="!props.store.state.settingsLoaded.smtp || sessions.smtp.dirty.value || busy.smtp || busy.smtpTest || !props.store.state.smtpSettings.enabled" @click="busy.smtpTest = true; props.store.testSMTP().catch(props.store.handleError).finally(() => busy.smtpTest = false)">{{ t("smtpTest") }}</button></div>
          <SettingsSaveBar :session="sessions.smtp" :loaded="props.store.state.settingsLoaded.smtp" :busy="busy.smtp" :error="errors.smtp" @save="save('smtp')" />
        </template>

        <template v-else-if="settingsGroup === 'audit'">
          <fieldset class="settings-form" :disabled="!props.store.state.settingsLoaded.logging || busy.logging">
            <div class="settings-context-note">{{ t("settingsLoggingTarget", { node: loggingNodeName }) }}</div>
            <label class="check-row"><input v-model="logging.enabled" type="checkbox" />{{ t("enableLogging") }}</label>
            <div class="settings-field-grid three">
              <label class="field"><span>{{ t("retentionDays") }}</span><input v-model.number="logging.retention_days" type="number" min="1" /></label>
              <label class="field"><span>{{ t("flushInterval") }}</span><input v-model.number="logging.flush_interval_seconds" type="number" min="1" /></label>
              <label class="field"><span>{{ t("replyTimeout") }}</span><input v-model.number="logging.reply_flow_timeout_seconds" type="number" min="1" /></label>
            </div>
            <label class="field"><span>{{ t("logDir") }}</span><input v-model="logging.log_dir" /></label>
          </fieldset>
          <SettingsSaveBar :session="sessions.logging" :loaded="props.store.state.settingsLoaded.logging" :busy="busy.logging" :error="errors.logging" @save="save('logging')" />
          <div class="settings-danger-row"><div><strong>{{ t("clearLogs") }}</strong><p>{{ t("settingsClearLogsHint") }}</p></div><button class="ghost-button danger-text" @click="props.store.confirmClearPersistedLogs()"><Trash2 :size="14" />{{ t("clearLogs") }}</button></div>
        </template>

        <template v-else>
          <div class="settings-form">
            <div class="settings-field-grid three settings-policy-source">
              <label class="field"><span>{{ t("settingsSourceNode") }}</span><select v-model="sourceNodeID" :disabled="busy.nodes"><option value="" disabled>{{ t("settingsSelectSource") }}</option><option v-for="node in props.store.state.nodes" :key="node.id" :value="node.id" :disabled="!online(node)">{{ node.name || node.id }}</option></select></label>
              <label class="field"><span>{{ t("toolbarInterface") }}</span><select v-model="sourceInterface" :disabled="busy.nodes || inventoryLoading"><option value="" disabled>{{ inventoryLoading ? t("settingsWaiting") : t("settingsSelectInterface") }}</option><option v-for="iface in sourceInterfaces" :key="iface.name" :value="iface.name">{{ iface.name }}</option></select></label>
              <label class="field"><span>{{ t("toolbarDirection") }}</span><select v-model="sourceDirection" :disabled="busy.nodes"><option value="ingress">{{ t("toolbarIngress") }}</option><option value="egress">{{ t("toolbarEgress") }}</option></select></label>
            </div>
            <div v-if="inventoryError" class="settings-feedback" role="alert"><span>{{ inventoryError }}</span><button class="ghost-button compact-button" @click="loadSourceInventory">{{ t("settingsRetry") }}</button></div>
            <div class="settings-section-title"><h3>{{ t("settingsTargetNodes") }}</h3><input v-model="nodeQuery" class="node-settings-search" type="search" :placeholder="t('clusterTableSearch')" /></div>
            <div class="table-shell"><table class="console-table node-settings-table">
              <thead><tr><th class="select-column"></th><th>{{ t("headerNode") }}</th><th>{{ t("clusterAdvertiseIP") }}</th><th>{{ t("clusterAgentStatus") }}</th><th>{{ t("clusterProtectionStatus") }}</th><th>{{ t("settingsTargetInterface") }}</th><th>{{ t("policyTableActions") }}</th></tr></thead>
              <tbody><tr v-for="node in visibleNodes" :key="node.id">
                <td class="select-column"><input type="checkbox" :checked="selectedNodeIDs.has(node.id)" :disabled="busy.nodes || node.id === sourceNodeID || !online(node)" :aria-label="node.name || node.id" @change="toggleNode(node.id)" /></td>
                <td><strong>{{ node.name || node.id }}</strong><span v-if="node.id === sourceNodeID" class="status-pill muted">{{ t("settingsSource") }}</span><small class="table-secondary-text">{{ node.id }}</small></td><td>{{ node.advertise_ip || "—" }}</td>
                <td><span class="status-pill" :class="online(node) ? 'success' : 'muted'">{{ online(node) ? t("clusterOnline") : t("clusterOffline") }}</span></td>
                <td><span class="status-pill" :class="protectionStatus(node) === 'enforced' ? 'success' : 'muted'">{{ protectionLabel(node) }}</span></td>
                <td><span v-if="node.id === sourceNodeID">—</span><select v-else-if="selectedNodeIDs.has(node.id)" v-model="targetInterfaces[node.id]" :disabled="busy.nodes || targetLoading[node.id]" :aria-label="t('settingsTargetInterface') + ' ' + (node.name || node.id)"><option value="" disabled>{{ targetLoading[node.id] ? t('settingsWaiting') : t('settingsSelectInterface') }}</option><option v-for="iface in targetInventories[node.id] || []" :key="iface.name" :value="iface.name">{{ iface.name }}</option></select><span v-else class="field-hint">{{ props.store.state.nodeProtection[node.id]?.interface || '—' }}</span></td>
                <td><button class="text-button" @click="openNodeSecurity(node.id).catch(props.store.handleError)">{{ t("settingsOpenProtection") }}<ArrowUpRight :size="13" /></button></td>
              </tr><tr v-if="!visibleNodes.length"><td colspan="7" class="table-empty">{{ t("noData") }}</td></tr></tbody>
            </table></div>
            <div v-if="policyResults.length" class="settings-policy-results" aria-live="polite"><p v-for="item in policyResults" :key="item.node_id" :class="item.status === 'failed' ? 'danger-text' : 'success-text'">{{ item.node_id }} · {{ item.status === 'failed' ? item.error || t('settingsApplyFailed') : t('settingsApplied') }}</p></div>
          </div>
          <footer class="settings-save-bar"><span class="field-hint">{{ t("settingsSelectedTargets", { count: selectedNodeIDs.size }) }}</span><button class="primary-button" :disabled="!canApplyTemplate" @click="applyProtectionTemplate">{{ busy.nodes ? t("settingsApplying") : t("settingsApplyProtection") }}</button></footer>
        </template>
      </article>
    </div>
  </section>
</template>
