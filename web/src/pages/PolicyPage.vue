<script setup>
import { computed, reactive, ref } from "vue";
import { ArrowLeftRight, Check, Copy, Pencil, Plus, Trash2, X } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import StrategySelect from "@/components/StrategySelect.vue";

const props = defineProps({
  store: { type: Object, required: true },
});
const { t } = useI18n();

const quickForm = reactive({ query: "" });
const busyRows = ref(new Set());
const selectedRowIds = ref(new Set());
const editingDescriptionId = ref("");
const draftDescription = ref("");
const protectionTrialSeconds = ref(30);

const composer = reactive({
  open: false,
  strategy: "allow",
  protocol: "both",
  sourceType: "any",
  sourceValue: "",
  comment: "",
  targetType: "port",
  targetValue: "",
});

const ICMP_SENTINEL_PORT = 0;

function descriptionCategory(kind) {
  if (kind === "allowlist" || kind === "blocked") return "source";
  if (kind === "bypass") return "bypass";
  if (kind === "icmpAllow" || kind === "icmpBlocked") return "icmp";
  if (kind === "public" || kind === "allowed" || kind === "denied") return "port";
  return kind;
}

const presetGroups = [
  {
    titleKey: "presetWeb",
    items: [
      { labelKey: "presetHttp", values: { strategy: "allow", protocol: "tcp", sourceType: "any", sourceValue: "", targetType: "port", targetValue: "80" } },
      { labelKey: "presetHttps", values: { strategy: "allow", protocol: "tcp", sourceType: "any", sourceValue: "", targetType: "port", targetValue: "443" } },
    ],
  },
  {
    titleKey: "presetRemote",
    items: [
      { labelKey: "presetSsh", values: { strategy: "allow", protocol: "tcp", sourceType: "any", sourceValue: "", targetType: "port", targetValue: "22" } },
      { labelKey: "presetWireguard", values: { strategy: "allow", protocol: "udp", sourceType: "any", sourceValue: "", targetType: "port", targetValue: "51820" } },
    ],
  },
  {
    titleKey: "presetAccess",
    items: [
      { labelKey: "presetBlockSource", values: { strategy: "deny", sourceType: "ipv4", sourceValue: "", targetType: "all", targetValue: "" } },
    ],
  },
];

const ruleRows = computed(() => {
  const selectedPolicy = props.store.state.policy?.[props.store.state.direction] || {};
  const allowCommentMap = new Map(
    (selectedPolicy.rules || [])
      .map((item) => [String(item?.cidr || ""), String(item?.comment || "")]),
  );
  const descriptionMap = new Map(
    (selectedPolicy.rule_descriptions || props.store.state.policy?.rule_descriptions || [])
      .map((item) => [`${item.kind}|${item.value}|${item.protocol || ""}`, String(item.description || "")]),
  );
  const descriptionFor = (kind, value, protocol = "") => {
    const category = descriptionCategory(kind);
    return descriptionMap.get(`${category}|${value}|${category === "port" ? protocol : ""}`)
      || (kind === "allowlist" ? allowCommentMap.get(String(value)) : "")
      || "";
  };
  const publicRules = props.store.state.publicPortRules || [];
  const allowedRules = props.store.state.allowedPortRules || [];
  const deniedRules = props.store.state.deniedPortRules || [];
  const rows = [
    ...props.store.state.allowlist.map((value) => {
      const comment = allowCommentMap.get(String(value)) || "";
      return {
        kind: "allowlist",
        strategy: t("actionAllow"),
        protocol: "IPv4",
        source: value,
        target: t("ruleAllTraffic"),
        comment,
        description: descriptionFor("allowlist", value) || comment,
      };
    }),
    ...props.store.state.bypassCIDRs.map((value) => ({ kind: "bypass", strategy: t("ruleBypass"), protocol: "IPv4", source: value, target: t("ruleAllTraffic"), description: descriptionFor("bypass", value) })),
    ...props.store.state.blockedCIDRs.map((value) => ({ kind: "blocked", strategy: t("actionDeny"), protocol: "IPv4", source: value, target: t("ruleAllTraffic"), description: descriptionFor("blocked", value) })),
    ...props.store.state.icmpAllowCIDRs.map((value) => ({ kind: "icmpAllow", strategy: t("actionAllow"), protocol: "ICMP", source: value, target: "ICMP", description: descriptionFor("icmpAllow", value) })),
    ...props.store.state.icmpBlockedCIDRs.map((value) => ({ kind: "icmpBlocked", strategy: t("actionDeny"), protocol: "ICMP", source: value, target: "ICMP", description: descriptionFor("icmpBlocked", value) })),
    ...publicRules.map((item) => ({ kind: "public", strategy: t("actionAllow"), protocol: String(item.protocol || "tcp").toUpperCase(), source: t("ruleAnyIPv4"), target: String(item.protocol || "").toLowerCase() === "icmp" ? "ICMP" : `${t("composerPort")} ${item.port}`, description: descriptionFor("public", item.port, item.protocol || "tcp"), port: item.port, portProtocol: item.protocol || "tcp" })),
    ...allowedRules.map((item) => ({ kind: "allowed", strategy: t("actionAllow"), protocol: String(item.protocol || "tcp").toUpperCase(), source: t("ruleExplicitPortPolicy"), target: String(item.protocol || "").toLowerCase() === "icmp" ? "ICMP" : `${t("composerPort")} ${item.port}`, description: descriptionFor("allowed", item.port, item.protocol || "tcp"), port: item.port, portProtocol: item.protocol || "tcp" })),
    ...deniedRules.map((item) => ({ kind: "denied", strategy: t("actionDeny"), protocol: String(item.protocol || "tcp").toUpperCase(), source: t("ruleAnyIPv4"), target: String(item.protocol || "").toLowerCase() === "icmp" ? "ICMP" : `${t("composerPort")} ${item.port}`, description: descriptionFor("denied", item.port, item.protocol || "tcp"), port: item.port, portProtocol: item.protocol || "tcp" })),
  ].map((item, index) => ({
    ...item,
    id: `${item.kind}-${item.source}-${item.target}-${index}`,
    value: item.kind === "allowlist" || item.kind === "bypass" || item.kind === "blocked" || item.kind === "icmpAllow" || item.kind === "icmpBlocked"
      ? item.source
      : Number(item.port ?? String(item.target).replace(/[^\d]/g, "")),
  }));

  const query = quickForm.query.trim().toLowerCase();
  if (!query) return rows;
  return rows.filter((item) => [item.strategy, item.protocol, item.source, item.target, item.description].join(" ").toLowerCase().includes(query));
});

const derivedRule = computed(() => {
  const { strategy, sourceType, targetType } = composer;
  if (composer.protocol === "icmp" && targetType === "all") {
    if (strategy === "allow" && sourceType === "any") return { supported: true, kind: "public", port: ICMP_SENTINEL_PORT, protocol: "icmp" };
    if (strategy === "deny" && sourceType === "any") return { supported: true, kind: "denied", port: ICMP_SENTINEL_PORT, protocol: "icmp" };
    if (strategy === "allow" && sourceType === "ipv4") return { supported: true, kind: "icmpAllow", protocol: "icmp" };
    if (strategy === "deny" && sourceType === "ipv4") return { supported: true, kind: "icmpBlocked", protocol: "icmp" };
  }
  if (strategy === "allow" && sourceType === "ipv4" && targetType === "all") {
    return { supported: true, kind: "allowlist" };
  }
  if (strategy === "deny" && sourceType === "ipv4" && targetType === "all") {
    return { supported: true, kind: "blocked" };
  }
  if (strategy === "allow" && sourceType === "any" && targetType === "port") {
    return { supported: true, kind: "public" };
  }
  if (strategy === "deny" && sourceType === "any" && targetType === "port") {
    return { supported: true, kind: "denied" };
  }
  return {
    supported: false,
  };
});

const emptyDirectionHint = computed(() => {
  if (ruleRows.value.length) return null;
  const ingress = props.store.state.policy?.ingress || {};
  const egress = props.store.state.policy?.egress || {};
  const ingressCount = Number((ingress.rules || []).length) +
    Number((ingress.public_port_rules || []).length) +
    Number((ingress.denied_port_rules || []).length) +
    Number((ingress.allowed_port_rules || []).length) +
    Number((ingress.bypass_cidrs || []).length) +
    Number((ingress.blocked_cidrs || []).length);
  const egressCount = Number((egress.rules || []).length) +
    Number((egress.public_port_rules || []).length) +
    Number((egress.denied_port_rules || []).length) +
    Number((egress.allowed_port_rules || []).length) +
    Number((egress.bypass_cidrs || []).length) +
    Number((egress.blocked_cidrs || []).length);
  if (props.store.state.direction === "egress" && ingressCount > 0 && egressCount === 0) {
    return {
      text: t("policyDirectionHintIngress"),
      action: t("toolbarIngress"),
      target: "ingress",
    };
  }
  if (props.store.state.direction === "ingress" && egressCount > 0 && ingressCount === 0) {
    return {
      text: t("policyDirectionHintEgress"),
      action: t("toolbarEgress"),
      target: "egress",
    };
  }
  return null;
});

const selectedRows = computed(() => ruleRows.value.filter((row) => selectedRowIds.value.has(row.id)));
const allSelected = computed(() => ruleRows.value.length > 0 && selectedRows.value.length === ruleRows.value.length);
const strategyOptions = computed(() => [
  { value: "allow", label: t("actionAllow") },
  { value: "deny", label: t("actionDeny") },
]);
const protectionStatus = computed(() => {
  const iface = String(props.store.currentInterface || "");
  const health = (props.store.state.health?.interfaces || []).find((item) => item.interface === iface);
  const policy = props.store.state.policy?.[props.store.state.direction] || props.store.state.policy || {};
  if (policy.observe_only || health?.observe_only) return "not_enabled";
  if (!health || !health.xdp_attached) return "not_enabled";
  if (health.map_ok && health.stats_ok && health.policy_enforced && health.enforcement_ok) return "enforced";
  return "degraded";
});

const protectionLabel = computed(() => ({
  enforced: t("protectionEnforced"),
  degraded: t("protectionDegraded"),
  not_enabled: t("protectionNotEnabled"),
}[protectionStatus.value] || t("protectionUnavailable")));

function protectionTrialExpiry(value) {
  const parsed = new Date(value || "");
  return Number.isNaN(parsed.getTime()) ? "-" : parsed.toLocaleTimeString();
}

async function runRowAction(row, task) {
  const key = row?.id || JSON.stringify(row || {});
  if (busyRows.value.has(key)) return;
  const next = new Set(busyRows.value);
  next.add(key);
  busyRows.value = next;
  try {
    await task();
  } finally {
    const done = new Set(busyRows.value);
    done.delete(key);
    busyRows.value = done;
  }
}

function isRowBusy(row) {
  const key = row?.id || JSON.stringify(row || {});
  return busyRows.value.has(key);
}

function toggleSelectAll() {
  if (allSelected.value) {
    selectedRowIds.value = new Set();
    return;
  }
  selectedRowIds.value = new Set(ruleRows.value.map((row) => row.id));
}

function toggleSelectRow(row) {
  const next = new Set(selectedRowIds.value);
  if (next.has(row.id)) next.delete(row.id);
  else next.add(row.id);
  selectedRowIds.value = next;
}

async function removeRule(row) {
  props.store.openModal({
    title: t("actionDelete"),
    copy: `${t("policyTableSource")}：${row.source}\n${t("policyTableTarget")}：${row.target}`,
    fields: [],
    onConfirm: async () => {
      await runRowAction(row, async () => {
        selectedRowIds.value.delete(row.id);
        if (row.kind === "allowlist" || row.kind === "bypass" || row.kind === "blocked" || row.kind === "icmpAllow" || row.kind === "icmpBlocked") {
          await props.store.removeCIDR(row.kind, row.value);
          return;
        }
        await props.store.removePort(row.kind, row.value, row.portProtocol || "");
      });
      props.store.closeModal();
    },
  });
}

function startDescriptionEdit(row) {
  editingDescriptionId.value = row.id;
  draftDescription.value = row.description || "";
}

function cancelDescriptionEdit() {
  editingDescriptionId.value = "";
  draftDescription.value = "";
}

async function saveDescriptionEdit(row) {
  if (editingDescriptionId.value !== row.id) return;
  await runRowAction(row, async () => {
    await props.store.saveRuleDescription({
      kind: row.kind,
      value: row.value,
      protocol: row.portProtocol || "",
      description: draftDescription.value,
    });
  });
  cancelDescriptionEdit();
}

async function removeSelectedRules() {
  const rows = selectedRows.value;
  if (!rows.length) return;
  props.store.openModal({
    title: "批量删除",
    copy: `确认删除已选 ${rows.length} 条规则？`,
    fields: [],
    onConfirm: async () => {
      for (const row of rows) {
        selectedRowIds.value.delete(row.id);
        if (row.kind === "allowlist" || row.kind === "bypass" || row.kind === "blocked" || row.kind === "icmpAllow" || row.kind === "icmpBlocked") {
          await props.store.removeCIDR(row.kind, row.value);
        } else {
          await props.store.removePort(row.kind, row.value, row.portProtocol || "");
        }
      }
      selectedRowIds.value = new Set();
      props.store.closeModal();
    },
  });
}

function openComposer() {
  composer.open = true;
}

function closeComposer() {
  composer.open = false;
  composer.strategy = "allow";
  composer.protocol = "both";
  composer.sourceType = "any";
  composer.sourceValue = "";
  composer.comment = "";
  composer.targetType = "port";
  composer.targetValue = "";
}

function applyPreset(values) {
  Object.assign(composer, values);
}

function isICMPRule(row) {
  return row?.protocol === "ICMP" || String(row?.portProtocol || "").toLowerCase() === "icmp";
}

function onProtocolChanged() {
  if (composer.protocol === "icmp") {
    composer.targetType = "all";
    composer.targetValue = "";
  }
}

async function submitComposer() {
  if (!derivedRule.value.supported) return;
  const kind = derivedRule.value.kind;
  try {
    let value;
    if (["allowlist", "bypass", "blocked", "icmpAllow", "icmpBlocked"].includes(kind)) {
      value = composer.sourceValue;
      await props.store.addCIDR(kind, value);
    } else {
      value = composer.protocol === "icmp" ? ICMP_SENTINEL_PORT : composer.targetValue;
      await props.store.addPort(kind, value, composer.protocol);
    }
    if (composer.comment.trim()) {
      await props.store.saveRuleDescription({
        kind,
        value,
        protocol: kind === "public" || kind === "allowed" || kind === "denied" ? composer.protocol : "",
        description: composer.comment,
      });
    }
    closeComposer();
  } catch (error) {
    props.store.handleError(error);
  }
}

async function toggleRuleStrategy(row) {
  const nextStrategy = row.strategy === t("actionDeny") ? "allow" : "deny";
  await runRowAction(row, () => props.store.changeRuleStrategy(row, nextStrategy));
}

async function setRuleStrategy(row, nextStrategy) {
  const target = nextStrategy === "deny" ? "deny" : "allow";
  const current = row.strategy === t("actionDeny") ? "deny" : "allow";
  if (target === current || row.kind === "bypass") return;
  await runRowAction(row, () => props.store.changeRuleStrategy(row, target));
}

async function toggleSelectedRulesStrategy() {
  const rows = selectedRows.value.filter((row) => row.kind !== "bypass");
  for (const row of rows) {
    await toggleRuleStrategy(row);
  }
}

</script>

<template>
  <section class="page-grid">
    <div class="policy-layout">
      <article class="panel panel-span-12">
        <div class="policy-page-actions">
          <button class="primary-button" @click="openComposer">
            <Plus :size="16" stroke-width="2" aria-hidden="true" />
            {{ t("policyNewRule") }}
          </button>
        </div>
        <div class="policy-status-row" :class="`is-${protectionStatus}`">
          <span class="status-pill" :class="{ danger: protectionStatus !== 'enforced' }">{{ protectionLabel }}</span>
          <span class="policy-status-context">{{ store.currentInterface || "-" }} · {{ store.state.direction === "egress" ? t("toolbarEgress") : t("toolbarIngress") }}</span>
          <template v-if="store.state.protectionTrial">
            <span class="policy-status-context">{{ t("protectionTrialRunning", { time: protectionTrialExpiry(store.state.protectionTrial.expires_at) }) }}</span>
            <button
              class="primary-button"
              :disabled="store.state.actionBusy['protection-baseline']"
              @click="store.confirmProtectionTrial().catch(store.handleError)"
            >{{ t("protectionTrialConfirm") }}</button>
            <button
              class="ghost-button"
              :disabled="store.state.actionBusy['protection-baseline']"
              @click="store.rollbackProtectionTrial().catch(store.handleError)"
            >{{ t("protectionTrialRollback") }}</button>
          </template>
          <template v-else-if="protectionStatus !== 'enforced'">
            <label class="field policy-inline-field protection-trial-field">
              <span>{{ t("protectionTrialSeconds") }}</span>
              <input v-model.number="protectionTrialSeconds" type="number" min="1" max="120" step="1" />
            </label>
            <button
              class="primary-button"
              :disabled="store.state.actionBusy['protection-baseline']"
              @click="store.enableProtectionBaseline().catch(store.handleError)"
            >{{ t("protectionEnable") }}</button>
            <button
              class="ghost-button"
              :disabled="store.state.actionBusy['protection-baseline']"
              @click="store.trialProtectionBaseline(protectionTrialSeconds).catch(store.handleError)"
            >{{ t("protectionTrialStart") }}</button>
          </template>
        </div>
        <div v-if="selectedRows.length" class="rules-batch-toolbar">
          <span>{{ t("policySelected", { count: selectedRows.length }) }}</span>
          <button class="ghost-button" @click="toggleSelectedRulesStrategy().catch(store.handleError)">
            <ArrowLeftRight :size="15" stroke-width="1.9" aria-hidden="true" />
            {{ t("policyBatchStrategy") }}
          </button>
          <button class="ghost-button danger-text" @click="removeSelectedRules().catch(store.handleError)">
            <Trash2 :size="15" stroke-width="1.9" aria-hidden="true" />
            {{ t("policyBatchDelete") }}
          </button>
        </div>

        <div class="rules-toolbar">
          <label class="field policy-search-field">
            <input v-model="quickForm.query" :aria-label="t('policySearch')" :placeholder="t('policySearch')" />
          </label>
          <label class="field policy-inline-field">
            <span>{{ t("policyNonIPv4") }}</span>
            <select
              v-model="store.state.forms.nonIPv4"
              @change="store.saveIPv6Action(store.state.forms.nonIPv4).catch(store.handleError)"
            >
              <option value="pass">{{ t("actionAllow") }}</option>
              <option value="drop">{{ t("actionDeny") }}</option>
            </select>
          </label>
        </div>

        <div class="panel-tags rule-tags">
          <span class="tag accent">{{ t("ruleTrusted") }} {{ store.state.allowlist.length }}</span>
          <span class="tag">{{ t("ruleBypass") }} {{ store.state.bypassCIDRs.length }}</span>
          <span class="tag danger-tag">{{ t("ruleBlocked") }} {{ store.state.blockedCIDRs.length }}</span>
          <span class="tag">{{ t("portRules") }} {{ (store.state.publicPortRules || []).length + (store.state.allowedPortRules || []).length + (store.state.deniedPortRules || []).length }}</span>
        </div>

        <div class="table-shell rules-table-shell">
          <table class="console-table rules-table">
            <thead>
              <tr>
                <th><input type="checkbox" :checked="allSelected" @change="toggleSelectAll" /></th>
                <th>{{ t("policyTableStrategy") }}</th>
                <th>{{ t("policyTableProtocol") }}</th>
                <th>{{ t("policyTableSource") }}</th>
                <th>{{ t("policyTableTarget") }}</th>
                <th>{{ t("policyTableDescription") }}</th>
                <th>{{ t("policyTableActions") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in ruleRows" :key="row.id">
                <td><input type="checkbox" :checked="selectedRowIds.has(row.id)" @change="toggleSelectRow(row)" /></td>
                <td>
                  <div
                    v-if="row.kind !== 'bypass'"
                    class="strategy-cell"
                  >
                    <StrategySelect
                      :model-value="row.strategy === t('actionDeny') ? 'deny' : 'allow'"
                      :options="strategyOptions"
                      :danger="row.strategy === t('actionDeny')"
                      :disabled="isRowBusy(row)"
                      :aria-label="`${t('policyTableStrategy')}：${row.source}`"
                      :title="t('policyStrategyImmediateHint')"
                      @change="setRuleStrategy(row, $event).catch(store.handleError)"
                    />
                  </div>
                  <span v-else class="status-pill">{{ row.strategy }}</span>
                </td>
                <td>{{ row.protocol }}</td>
                <td>{{ row.source }}</td>
                <td>{{ row.target }}</td>
                <td>
                  <div class="description-cell">
                    <template v-if="editingDescriptionId === row.id">
                      <input
                        v-model="draftDescription"
                        class="description-inline-input"
                        type="text"
                        :aria-label="t('policyTableDescription')"
                        :placeholder="t('policyDescriptionPlaceholder')"
                        @keydown.enter.prevent="saveDescriptionEdit(row).catch(store.handleError)"
                        @keydown.esc="cancelDescriptionEdit"
                      />
                      <div class="description-inline-actions">
                        <button
                          type="button"
                          class="description-inline-button save"
                          :disabled="isRowBusy(row)"
                          :aria-label="t('policySaveDescription')"
                          :title="t('policySaveDescription')"
                          @click="saveDescriptionEdit(row).catch(store.handleError)"
                        ><Check :size="15" stroke-width="2.2" aria-hidden="true" /></button>
                        <button
                          type="button"
                          class="description-inline-button cancel"
                          :disabled="isRowBusy(row)"
                          :aria-label="t('policyCancelDescription')"
                          :title="t('policyCancelDescription')"
                          @click="cancelDescriptionEdit"
                        ><X :size="15" stroke-width="2.2" aria-hidden="true" /></button>
                      </div>
                    </template>
                    <template v-else>
                      <span>{{ row.description || "-" }}</span>
                      <button
                        type="button"
                        class="description-edit-button"
                        :disabled="isRowBusy(row)"
                        :aria-label="t('policyEditDescription')"
                        :title="t('policyEditDescription')"
                        @click="startDescriptionEdit(row)"
                      >
                        <Pencil :size="15" stroke-width="1.9" aria-hidden="true" />
                      </button>
                    </template>
                  </div>
                </td>
                <td>
                  <div class="inline-actions">
                    <button
                      v-if="row.kind !== 'bypass' && row.kind !== 'allowed'"
                      class="icon-button table-action-button"
                      :title="t('actionCopy')"
                      :aria-label="t('actionCopy')"
                      @click="openComposer(); applyPreset({ strategy: row.kind === 'blocked' ? 'deny' : 'allow', protocol: row.portProtocol || 'tcp', sourceType: row.kind === 'public' || row.kind === 'denied' || row.kind === 'allowed' ? 'any' : 'ipv4', sourceValue: row.kind === 'public' || row.kind === 'denied' || row.kind === 'allowed' ? '' : String(row.value), targetType: row.kind === 'public' || row.kind === 'denied' || row.kind === 'allowed' ? 'port' : 'all', targetValue: row.kind === 'public' || row.kind === 'denied' || row.kind === 'allowed' ? String(row.value) : '' })"
                    ><Copy :size="18" stroke-width="1.8" aria-hidden="true" /></button>
                    <button class="icon-button table-action-button danger" :title="t('actionDelete')" :aria-label="t('actionDelete')" :disabled="isRowBusy(row)" @click="removeRule(row).catch(store.handleError)">
                      <Trash2 :size="18" stroke-width="1.8" aria-hidden="true" />
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!ruleRows.length">
                <td colspan="7" class="table-empty">
                  <div>{{ t("policyEmpty") }}</div>
                  <button
                    v-if="emptyDirectionHint"
                    class="ghost-button compact-button"
                    @click="props.store.setDirection(emptyDirectionHint.target)"
                  >
                    {{ emptyDirectionHint.text }} · {{ emptyDirectionHint.action }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>

    </div>

    <div v-if="composer.open" class="modal-mask" @click.self="closeComposer">
      <div class="rule-composer">
        <div class="rule-composer-main">
          <div class="modal-head">
            <div>
              <p>{{ t("composerEyebrow") }}</p>
              <h3>{{ t("composerTitle") }}</h3>
            </div>
            <button class="modal-close-dot icon-button" :title="t('close')" :aria-label="t('close')" @click="closeComposer">
              <X :size="18" stroke-width="2" aria-hidden="true" />
            </button>
          </div>

          <div class="rule-form-grid compact">
            <label class="field rule-span-2">
              <span>{{ t("composerStrategy") }} · {{ t("composerRequired") }}</span>
              <div class="segmented strategy-toggle">
                <button :class="{ active: composer.strategy === 'allow' }" @click="composer.strategy = 'allow'">{{ t("actionAllow") }}</button>
                <button :class="{ active: composer.strategy === 'deny' }" @click="composer.strategy = 'deny'">{{ t("actionDeny") }}</button>
              </div>
            </label>

            <label class="field">
              <span>{{ t("composerProtocol") }}</span>
              <select v-model="composer.protocol" @change="onProtocolChanged">
                <option value="both">{{ t("composerProtocolBoth") }}</option>
                <option value="tcp">{{ t("composerProtocolTCP") }}</option>
                <option value="udp">{{ t("composerProtocolUDP") }}</option>
                <option value="icmp">{{ t("composerProtocolICMP") }}</option>
              </select>
            </label>

            <div class="composer-section rule-span-3">
              <div class="composer-section-head">
                <strong>{{ t("composerSourceSection") }}</strong>
                <small>{{ t("composerRequired") }}</small>
              </div>
              <div class="rule-form-grid nested">
                <label class="field">
                  <span>{{ t("composerSource") }}</span>
                  <select v-model="composer.sourceType">
                    <option value="any">{{ t("composerAny") }}</option>
                    <option value="ipv4">{{ t("composerIPv4") }}</option>
                  </select>
                </label>

                <label class="field rule-span-2" v-if="composer.sourceType === 'ipv4'">
                  <span>{{ t("composerSourceValue") }}</span>
                  <input v-model="composer.sourceValue" :placeholder="t('composerSourcePlaceholder')" />
                </label>
                <label class="field rule-span-3">
                  <span>{{ t("policyTableDescription") }}</span>
                  <input v-model="composer.comment" :placeholder="t('policyDescriptionPlaceholder')" />
                </label>
              </div>
            </div>

            <div class="composer-section rule-span-3">
              <div class="composer-section-head">
                <strong>{{ t("composerTargetSection") }}</strong>
                <small>{{ t("composerRequired") }}</small>
              </div>
              <div class="rule-form-grid nested">
                <label class="field">
                  <span>{{ t("composerTarget") }}</span>
                  <select v-model="composer.targetType">
                    <option value="port">{{ t("composerPort") }}</option>
                    <option value="all">{{ t("composerAll") }}</option>
                  </select>
                </label>

                <label class="field rule-span-2" v-if="composer.targetType === 'port' && composer.protocol !== 'icmp'">
                  <span>{{ t("composerTargetValue") }}</span>
                  <input v-model="composer.targetValue" type="number" :placeholder="t('composerTargetPlaceholder')" />
                </label>
                <div class="field rule-span-2" v-else-if="composer.protocol === 'icmp'">
                  <span>{{ t("composerTargetValue") }}</span>
                  <input :value="t('composerICMPTraffic')" disabled />
                </div>
              </div>
            </div>

          </div>

          <div class="modal-actions">
            <button :disabled="!derivedRule.supported" @click="submitComposer">{{ t("submit") }}</button>
            <button class="ghost-button" @click="closeComposer">{{ t("cancel") }}</button>
          </div>
        </div>

        <aside class="rule-composer-side">
          <div class="matrix-head">
            <strong>{{ t("composerQuickLink") }}</strong>
          </div>
          <div class="preset-group" v-for="group in presetGroups" :key="group.titleKey">
            <h4>{{ t(group.titleKey) }}</h4>
            <button v-for="item in group.items" :key="item.labelKey" class="ghost-button preset-button" @click="applyPreset(item.values)">
              {{ t(item.labelKey) }}
            </button>
          </div>
        </aside>
      </div>
    </div>
  </section>
</template>
