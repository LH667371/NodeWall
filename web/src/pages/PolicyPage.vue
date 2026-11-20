<script setup>
import { computed, nextTick, onBeforeUnmount, reactive, ref, watch } from "vue";
import { ArrowDown, ArrowLeftRight, ArrowUp, Check, ListFilter, Pencil, Plus, Search, Trash2, X } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import FirewallBackendBadge from "@/components/FirewallBackendBadge.vue";
import InfoTip from "@/components/InfoTip.vue";
import StrategySelect from "@/components/StrategySelect.vue";
import TablePagination from "@/components/TablePagination.vue";
import NodeSelector from "@/components/NodeSelector.vue";
import { request } from "@/lib/api";
import { interfaceFirewallBackend } from "@/lib/firewallBackend";
import { interfaceAddress, interfaceAddressLabel } from "@/lib/interfaces";
import { formatTime as formatClockTime } from "@/lib/time";

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
const protectionTrialActive = computed(() => Boolean(props.store.currentPolicy && props.store.state.protectionTrial));
const rulePage = ref(0);
const rulePageSize = ref(15);
const recentRuleIDs = ref([]);
const highlightedRuleIDs = ref(new Set());
const rulesTable = ref(null);
const composerRoot = ref(null);
const composerBusy = ref(false);
const composerError = ref("");
const composerResults = ref([]);
const targetInventories = reactive({});
const targetInterfaces = reactive({});
const targetLoading = reactive({});
const targetErrors = reactive({});
const inventoryControllers = new Map();
let submittedRule = null;
let submittedOptions = null;
let active = true;

const composer = reactive({
  open: false,
  editingRow: null,
  strategy: "allow",
  protocol: "both",
  sourceType: "any",
  sourceValue: "",
  comment: "",
  targetType: "port",
  targetValue: "",
  targetNodeIDs: [],
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

const allRuleRows = computed(() => {
  const policy = props.store.currentPolicy;
  if (!policy) return [];
  const selectedPolicy = policy[props.store.state.direction] || {};
  const allowCommentMap = new Map(
    (selectedPolicy.rules || [])
      .map((item) => [String(item?.cidr || ""), String(item?.comment || "")]),
  );
  const descriptionMap = new Map(
    (selectedPolicy.rule_descriptions || policy.rule_descriptions || [])
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
  ].map((item) => ({
    ...item,
    // Identity must survive another rule being inserted or translations
    // changing; array offsets and rendered labels are not rule identifiers.
    id: JSON.stringify([item.kind, item.source && !item.portProtocol ? item.source : item.port, item.portProtocol || ""]),
    value: item.kind === "allowlist" || item.kind === "bypass" || item.kind === "blocked" || item.kind === "icmpAllow" || item.kind === "icmpBlocked"
      ? item.source
      : Number(item.port ?? String(item.target).replace(/[^\d]/g, "")),
  }));

  return rows;
});
watch(() => allRuleRows.value.map((row) => row.id), (ids, previous) => {
  const present = new Set(ids);
  const old = new Set(previous || []);
  const additions = previous ? ids.filter((id) => !old.has(id)) : [];
  recentRuleIDs.value = [...additions, ...recentRuleIDs.value.filter((id) => present.has(id) && !additions.includes(id))];
  selectedRowIds.value = new Set([...selectedRowIds.value].filter((id) => present.has(id)));
}, { immediate: true });
const ruleRows = computed(() => {
  const ranks = new Map(recentRuleIDs.value.map((id, index) => [id, index]));
  const query = quickForm.query.trim().toLowerCase();
  return allRuleRows.value.filter((item) => !query || [item.strategy, item.protocol, item.source, item.target, item.description].join(" ").toLowerCase().includes(query))
    .sort((a, b) => (ranks.get(a.id) ?? ranks.size) - (ranks.get(b.id) ?? ranks.size));
});
const visibleRuleRows = computed(() => ruleRows.value.slice(rulePage.value * rulePageSize.value, (rulePage.value + 1) * rulePageSize.value));
watch(() => [quickForm.query, props.store.state.direction, rulePageSize.value], () => { rulePage.value = 0; });
watch(() => ruleRows.value.length, (count) => {
  // A remote addition must not pull an operator away from their current page.
  rulePage.value = Math.min(rulePage.value, Math.max(0, Math.ceil(count / rulePageSize.value) - 1));
});

const derivedRule = computed(() => {
  const { strategy, sourceType, targetType } = composer;
  const allowPortKind = props.store.state.direction === "egress" ? "allowed" : "public";
  if (composer.protocol === "icmp" && targetType === "all") {
    if (strategy === "allow" && sourceType === "any") return { supported: true, kind: allowPortKind, port: ICMP_SENTINEL_PORT, protocol: "icmp" };
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
    return { supported: true, kind: allowPortKind };
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
  const ingress = props.store.currentPolicy?.ingress || {};
  const egress = props.store.currentPolicy?.egress || {};
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
const selectedInterfaceName = computed(() => String(
  props.store.currentInterface?.value
    || props.store.currentInterface
    || props.store.state.selectedInterface
    || props.store.state.defaultInterface
    || "",
));
const selectedInterface = computed(() => props.store.state.interfaces?.find((item) => item.name === selectedInterfaceName.value));
const backendMode = computed(() => interfaceFirewallBackend(
  props.store.state.health,
  selectedInterfaceName.value,
  props.store.state.interfaceDataStatus,
));
const showTCEgress = computed(() => props.store.state.direction === "egress"
  && ["native", "generic"].includes(backendMode.value));
const ruleScope = computed(() => JSON.stringify([props.store.state.nodeId, selectedInterfaceName.value, props.store.state.direction]));
const interfaceOptions = computed(() => {
  const list = props.store.state.interfaces || [];
  const physical = list.filter((item) => item.is_physical);
  const options = physical.length ? physical : list;
  return options.some((item) => item.name === selectedInterfaceName.value) || !selectedInterfaceName.value
    ? options
    : [...options, selectedInterface.value || { name: selectedInterfaceName.value }];
});
function interfaceLabel(item) {
  if (typeof item.is_physical !== "boolean") return item.name;
  return `${item.name} · ${t(item.is_physical ? "interfaceTypePhysical" : "interfaceTypeVirtual")}`;
}
watch(ruleScope, () => {
  recentRuleIDs.value = [];
  highlightedRuleIDs.value = new Set();
  selectedRowIds.value = new Set();
  editingDescriptionId.value = "";
  rulePage.value = 0;
  closeComposer();
});
const selectedDirectionPolicy = computed(() => props.store.currentPolicy?.[props.store.state.direction] || props.store.currentPolicy || {});
const policyProtectionIntent = computed(() => {
  const policy = selectedDirectionPolicy.value || {};
  const mode = String(policy.mode || "").trim().toLowerCase();
  const defaultAction = String(policy.default_action || "").trim().toLowerCase();
  return policy.enabled !== false
    && !policy.observe_only
    && mode !== "observe"
    && defaultAction !== "pass";
});
const policyDataStatus = computed(() => {
  const status = props.store.state.interfaceDataStatus;
  if (status !== "ready") return status;
  if (!props.store.currentPolicy) return "loading";
  return selectedInterface.value ? "ready" : "unavailable";
});
const interfaceReady = computed(() => policyDataStatus.value === "ready");
const protectionStatus = computed(() => {
  if (!interfaceReady.value) return policyDataStatus.value;
  const iface = selectedInterfaceName.value;
  const interfaces = props.store.state.health?.interfaces || [];
  const health = interfaces.find((item) => item.interface === iface);
  const direction = props.store.state.direction === "egress" ? "egress" : "ingress";
  const policy = selectedDirectionPolicy.value;
  const policyEnforced = direction === "egress" ? !!health?.egress_policy_enforced : !!health?.policy_enforced;
  const observeOnly = direction === "egress" ? !!policy.observe_only : !!(policy.observe_only || health?.observe_only);
  if (observeOnly) return "not_enabled";
  // A successful policy/rule snapshot can arrive while the health probe is
  // briefly unavailable. Keep the state actionable: an enforcing policy is
  // shown as degraded (so it can still be disabled), while an observe policy
  // is clearly shown as not enabled. Rendering "unknown" here used to disable
  // both controls even though the rules were already visible and writable.
  if (!health) return policyProtectionIntent.value ? "degraded" : "not_enabled";
  if (!health.xdp_attached) return "not_enabled";
  if (health.map_ok && health.stats_ok && policyEnforced && (direction === "egress" || health.enforcement_ok)) return "enforced";
  return "degraded";
});

const protectionLabel = computed(() => ({
  enforced: t("protectionEnforced"),
  degraded: t("protectionDegraded"),
  not_enabled: t("protectionNotEnabled"),
  loading: t("protectionLoading"),
}[protectionStatus.value] || t("protectionUnavailable")));
const protectionCanDisable = computed(() => protectionStatus.value === "enforced"
  || (protectionStatus.value === "degraded" && policyProtectionIntent.value));

function protectionTrialExpiry(value) {
  return formatClockTime(value, props.store.state.locale === "en-US" ? "en-US" : "zh-CN");
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
  const scope = ruleScope.value;
  await runRowAction(row, async () => {
    await props.store.saveRuleDescription({
      kind: row.kind,
      value: row.value,
      protocol: row.portProtocol || "",
      description: draftDescription.value,
    });
  });
  if (active && scope === ruleScope.value && editingDescriptionId.value === row.id) cancelDescriptionEdit();
}

function confirmRuleDeletion(rows, title, copy) {
  const scope = ruleScope.value;
  props.store.openModal({
    title,
    copy,
    fields: [],
    onConfirm: async () => {
      let deleted = 0;
      try {
        for (const row of rows) {
          // The next row still belongs to the context that opened this dialog.
          if (!active || ruleScope.value !== scope) return;
          if (isRowBusy(row)) throw new Error(t("policyRuleBusy"));
          await runRowAction(row, () => row.portProtocol
            ? props.store.removePort(row.kind, row.value, row.portProtocol)
            : props.store.removeCIDR(row.kind, row.value));
          deleted++;
        }
      } catch (error) {
        if (!active || ruleScope.value !== scope) return;
        const detail = props.store.handleError(error, { inline: true });
        if (deleted && detail) {
          props.store.handleError(new Error(t("policyRulesDeleteInterrupted", { deleted, remaining: rows.length - deleted, error: detail })));
          return;
        }
        props.store.handleError(error);
      }
      if (deleted && active && ruleScope.value === scope) {
        props.store.setNotice(t("policyRulesDeleted", { count: deleted }), "success");
      }
    },
  });
}

function removeRule(row) {
  confirmRuleDeletion([row], t("actionDelete"),
    `${t("policyTableSource")}：${row.source}\n${t("policyTableTarget")}：${row.target}`);
}

function removeSelectedRules() {
  const rows = selectedRows.value;
  if (!rows.length) return;
  confirmRuleDeletion(rows, t("policyBatchDeleteTitle"), t("policyBatchDeleteCopy", { count: rows.length }));
}

function openComposer() {
  composerError.value = "";
  composerResults.value = [];
  composer.editingRow = null;
  composer.open = true;
  nextTick(() => composerRoot.value?.querySelector("input:not(:disabled), select:not(:disabled)")?.focus());
}

function openRuleEditor(row) {
  openComposer();
  composer.editingRow = row;
  const portRule = Boolean(row.portProtocol);
  const hasTargetPort = portRule && !isICMPRule(row);
  applyPreset({
    strategy: row.kind === "blocked" || row.kind === "denied" || row.kind === "icmpBlocked" ? "deny" : "allow",
    protocol: row.portProtocol || (isICMPRule(row) ? "icmp" : "tcp"),
    sourceType: portRule ? "any" : "ipv4",
    sourceValue: portRule ? "" : String(row.value || ""),
    targetType: hasTargetPort ? "port" : "all",
    targetValue: hasTargetPort ? String(row.value) : "",
    comment: row.description || "",
  });
}

function closeComposer() {
  if (composerBusy.value) return;
  composer.open = false;
  composer.editingRow = null;
  composer.strategy = "allow";
  composer.protocol = "both";
  composer.sourceType = "any";
  composer.sourceValue = "";
  composer.comment = "";
  composer.targetType = "port";
  composer.targetValue = "";
  composer.targetNodeIDs = [];
  composerError.value = "";
  composerResults.value = [];
  submittedRule = null;
  submittedOptions = null;
  for (const controller of inventoryControllers.values()) controller.abort();
  inventoryControllers.clear();
}

function onComposerKeydown(event) {
  if (event.key === "Escape") {
    event.preventDefault();
    closeComposer();
  } else if (event.key === "Tab") {
    const controls = [...composerRoot.value.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex="0"]')]
      .filter((element) => !element.matches(":disabled") && element.getClientRects().length);
    const first = controls[0], last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  }
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

const additionalTargets = computed(() => composer.targetNodeIDs.map((id) => props.store.state.nodes.find((node) => node.id === id)).filter(Boolean));
const canSubmitComposer = computed(() => derivedRule.value.supported && !composerBusy.value && interfaceReady.value
  && composer.targetNodeIDs.every((id) => props.store.state.nodes.some((node) => node.id === id && props.store.isNodeOnline(node)) && !targetLoading[id] && !!targetInterfaces[id] && !targetErrors[id]));

async function loadTargetInventory(id) {
  inventoryControllers.get(id)?.abort();
  const controller = new AbortController();
  inventoryControllers.set(id, controller);
  targetLoading[id] = true;
  targetErrors[id] = "";
  try {
    const value = await request(`/nodes/${encodeURIComponent(id)}/interfaces`, { signal: controller.signal });
    if (controller.signal.aborted) return;
    const items = (value.interfaces || []).filter((item) => item.name !== "lo");
    const physical = items.filter((item) => item.is_physical);
    targetInventories[id] = physical.length ? physical : items;
    targetInterfaces[id] = targetInventories[id].find((item) => item.name === selectedInterfaceName.value)?.name
      || targetInventories[id].find((item) => item.name === value.recommended)?.name || targetInventories[id][0]?.name || "";
    if (!targetInterfaces[id]) targetErrors[id] = t("policyTargetNoInterface");
  } catch (error) {
    if (!controller.signal.aborted) targetErrors[id] = error.message;
  } finally {
    if (inventoryControllers.get(id) === controller) {
      targetLoading[id] = false;
      inventoryControllers.delete(id);
    }
  }
}
watch(() => [...composer.targetNodeIDs], (ids, oldIDs = []) => {
  for (const id of oldIDs) if (!ids.includes(id)) { inventoryControllers.get(id)?.abort(); inventoryControllers.delete(id); targetLoading[id] = false; }
  for (const id of ids) if (!oldIDs.includes(id)) loadTargetInventory(id);
});
watch(() => props.store.state.nodes.map((node) => node.id), (ids) => {
  const next = composer.targetNodeIDs.filter((id) => ids.includes(id) && id !== props.store.state.nodeId);
  if (next.length !== composer.targetNodeIDs.length) composer.targetNodeIDs = next;
});
onBeforeUnmount(() => { active = false; for (const controller of inventoryControllers.values()) controller.abort(); });

async function submitComposer(retry = false) {
  if (composerBusy.value || (!retry && !canSubmitComposer.value)) return;
  const scope = ruleScope.value;
  const beforeIDs = new Set(allRuleRows.value.map((row) => row.id));
  const sourceNodeID = props.store.state.nodeId;
  let targets;
  if (retry) {
    targets = composerResults.value.filter((item) => item.status === "failed");
  } else {
    submittedRule = {
      kind: derivedRule.value.kind,
      sourceValue: composer.sourceType === "ipv4" ? composer.sourceValue.trim() : "",
      targetValue: composer.protocol === "icmp" ? ICMP_SENTINEL_PORT : composer.targetValue,
      protocol: composer.protocol,
      strategy: composer.strategy,
      description: composer.comment.trim(),
    };
    submittedOptions = { sourceNodeID, editingRow: composer.editingRow };
    targets = [{ nodeID: sourceNodeID, interface: selectedInterfaceName.value }, ...additionalTargets.value.map((node) => ({ nodeID: node.id, interface: targetInterfaces[node.id] }))]
      .map((item) => ({ ...item, direction: props.store.state.direction }));
  }
  composerBusy.value = true;
  composerError.value = "";
  try {
    const results = await props.store.addRuleToNodes(submittedRule, targets, submittedOptions);
    if (!active || scope !== ruleScope.value) return;
    composerResults.value = [...composerResults.value.filter((item) => !targets.some((target) => target.nodeID === item.nodeID)), ...results];
    if (results.some((item) => item.nodeID === sourceNodeID && (item.status === "success" || item.ruleSaved))) {
      const additions = allRuleRows.value.filter((row) => !beforeIDs.has(row.id));
      const matches = allRuleRows.value.filter((row) => row.kind === submittedRule.kind
        && String(row.value) === String(submittedRule.sourceValue || submittedRule.targetValue)
        && (!row.portProtocol || submittedRule.protocol === "both" || row.portProtocol === submittedRule.protocol));
      const ids = [...new Set([...additions, ...matches].map((row) => row.id))];
      recentRuleIDs.value = [...ids, ...recentRuleIDs.value.filter((id) => !ids.includes(id))];
      highlightedRuleIDs.value = new Set(ids);
      quickForm.query = "";
      rulePage.value = 0;
    }
    if (composerResults.value.every((item) => item.status === "success")) {
      props.store.setNotice(t("policyRulesSaved", { count: composerResults.value.length }), "success");
      composerBusy.value = false;
      closeComposer();
      await nextTick();
      const savedRow = rulesTable.value?.querySelector(".rule-row-recent");
      savedRow?.focus({ preventScroll: true });
      savedRow?.scrollIntoView({ block: "nearest" });
    }
  } catch (error) {
    if (active && scope === ruleScope.value) composerError.value = error.message;
  } finally {
    composerBusy.value = false;
    if (active && scope !== ruleScope.value) closeComposer();
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
  const scope = ruleScope.value;
  for (const row of rows) {
    if (!active || scope !== ruleScope.value) return;
    await toggleRuleStrategy(row);
  }
}

</script>

<template>
  <section class="page-grid firewall-page">
    <article class="panel policy-context-panel">
      <div class="policy-context-scope">
        <div class="segmented" role="group" :aria-label="t('toolbarDirection')">
          <button type="button" :class="{ active: store.state.direction === 'ingress' }" :aria-pressed="store.state.direction === 'ingress'" @click="store.setDirection('ingress')">
            <ArrowDown :size="16" aria-hidden="true" />{{ t("toolbarIngress") }}
          </button>
          <button type="button" :class="{ active: store.state.direction === 'egress' }" :aria-pressed="store.state.direction === 'egress'" @click="store.setDirection('egress')">
            <ArrowUp :size="16" aria-hidden="true" />{{ t("toolbarEgress") }}
          </button>
        </div>
        <div class="policy-context-interface">
          <label class="policy-interface-picker">
            <span>{{ t("toolbarInterface") }}</span>
            <select :value="selectedInterfaceName" :disabled="!interfaceOptions.length"
              :aria-describedby="selectedInterface ? 'policy-interface-address' : undefined" @change="store.setInterface($event.target.value)">
              <option v-if="!interfaceOptions.length" value="">{{ t(store.state.interfaceDataStatus === "loading" ? "loading" : "protectionUnavailable") }}</option>
              <option v-for="item in interfaceOptions" :key="item.name" :value="item.name">{{ interfaceLabel(item) }}</option>
            </select>
          </label>
          <!-- A native select is single-line. Keep the address outside it so IPv6 and bridge names can wrap. -->
          <span v-if="selectedInterface" id="policy-interface-address" class="policy-interface-address">{{ interfaceAddressLabel(selectedInterface) }}</span>
        </div>
        <span class="status-pill" :class="{ accent: protectionStatus === 'enforced', warning: protectionStatus === 'degraded' }">{{ protectionLabel }}</span>
        <div class="policy-context-backend">
          <span>{{ t("firewallBackend") }}</span>
          <FirewallBackendBadge :mode="backendMode" />
          <InfoTip :text="t('firewallBackendHelp')" />
          <span v-if="showTCEgress">{{ t("firewallBackendEgressHook") }}</span>
        </div>
      </div>
      <div class="policy-context-actions" :class="`is-${protectionStatus}`">
        <template v-if="protectionTrialActive">
          <span class="policy-trial-text">{{ t("protectionTrialRunning", { time: protectionTrialExpiry(store.state.protectionTrial.expires_at) }) }}</span>
          <span class="policy-trial-text policy-trial-lock-hint">{{ t("policyTrialLockHint") }}</span>
          <button
            class="primary-button"
            :disabled="store.state.actionBusy['protection-baseline'] || !interfaceReady"
            @click="store.confirmProtectionTrial().catch(store.handleError)"
          >{{ t("protectionTrialConfirm") }}</button>
          <button
            class="ghost-button"
            :disabled="store.state.actionBusy['protection-baseline'] || !interfaceReady"
            @click="store.rollbackProtectionTrial().catch(store.handleError)"
          >{{ t("protectionTrialRollback") }}</button>
        </template>
        <template v-else-if="protectionCanDisable">
          <button
            class="ghost-button danger-text"
            :disabled="store.state.actionBusy['protection-baseline'] || !interfaceReady"
            @click="store.disableProtectionBaseline().catch(store.handleError)"
          >{{ t("protectionDisable") }}</button>
        </template>
        <template v-else>
          <label class="field policy-inline-field protection-trial-field">
            <span>{{ t("protectionTrialSeconds") }}</span>
            <input v-model.number="protectionTrialSeconds" type="number" min="1" max="120" step="1" />
          </label>
          <button
            class="primary-button"
            :disabled="store.state.actionBusy['protection-baseline'] || !interfaceReady"
            @click="store.enableProtectionBaseline().catch(store.handleError)"
          >{{ t("protectionEnable") }}</button>
          <button
            class="ghost-button"
            :disabled="store.state.actionBusy['protection-baseline'] || !interfaceReady"
            @click="store.trialProtectionBaseline(protectionTrialSeconds).catch(store.handleError)"
          >{{ t("protectionTrialStart") }}</button>
        </template>
      </div>
    </article>

    <div class="policy-layout workspace-fill">
      <article class="panel panel-span-12 workspace-panel">
        <div class="panel-head policy-rules-head">
          <div class="policy-rules-title">
            <span class="security-panel-icon"><ListFilter :size="16" aria-hidden="true" /></span>
            <h3>{{ t("policyTitle") }}</h3>
          </div>
          <button type="button" class="primary-button" :disabled="protectionTrialActive || !interfaceReady" @click="openComposer">
            <Plus :size="16" stroke-width="2" aria-hidden="true" />{{ t("policyNewRule") }}
          </button>
        </div>
        <div v-if="selectedRows.length" class="rules-batch-toolbar">
          <span>{{ t("policySelected", { count: selectedRows.length }) }}</span>
          <button class="ghost-button" :disabled="protectionTrialActive || !interfaceReady" @click="toggleSelectedRulesStrategy().catch(store.handleError)">
            <ArrowLeftRight :size="16" aria-hidden="true" />
            {{ t("policyBatchStrategy") }}
          </button>
          <button class="ghost-button danger-text" :disabled="protectionTrialActive || !interfaceReady || selectedRows.some(isRowBusy)" @click="removeSelectedRules">
            <Trash2 :size="16" aria-hidden="true" />
            {{ t("policyBatchDelete") }}
          </button>
        </div>

        <div class="rules-toolbar">
          <label class="field policy-search-field input-with-icon">
            <Search :size="16" aria-hidden="true" />
            <input v-model="quickForm.query" type="search" :aria-label="t('policySearch')" :placeholder="t('policySearch')" />
          </label>
          <label class="field policy-inline-field">
            <span>{{ t("policyNonIPv4") }}</span>
            <select
              v-model="store.state.forms.nonIPv4"
              :disabled="protectionTrialActive || !interfaceReady"
              @change="store.saveIPv6Action(store.state.forms.nonIPv4).catch(store.handleError)"
            >
              <option value="pass">{{ t("actionAllow") }}</option>
              <option value="drop">{{ t("actionDeny") }}</option>
            </select>
          </label>
        </div>

        <div v-if="store.currentPolicy" class="panel-tags rule-tags">
          <span class="tag accent">{{ t("ruleTrusted") }} {{ store.state.allowlist.length }}</span>
          <span class="tag">{{ t("ruleBypass") }} {{ store.state.bypassCIDRs.length }}</span>
          <span class="tag danger-tag">{{ t("ruleBlocked") }} {{ store.state.blockedCIDRs.length }}</span>
          <span class="tag">{{ t("portRules") }} {{ (store.state.publicPortRules || []).length + (store.state.allowedPortRules || []).length + (store.state.deniedPortRules || []).length }}</span>
        </div>

        <div class="table-shell rules-table-shell">
          <table ref="rulesTable" class="console-table rules-table">
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
              <tr v-for="row in visibleRuleRows" :key="row.id" :class="{ 'rule-row-recent': highlightedRuleIDs.has(row.id) }" :tabindex="highlightedRuleIDs.has(row.id) ? -1 : undefined">
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
                      :disabled="protectionTrialActive || !interfaceReady || isRowBusy(row)"
                      :aria-label="`${t('policyTableStrategy')}：${row.source}`"
                      :title="t('policyStrategyImmediateHint')"
                      @change="setRuleStrategy(row, $event).catch(store.handleError)"
                    />
                  </div>
                  <span v-else class="status-pill">{{ row.strategy }}</span>
                </td>
                <td :title="row.protocol"><span class="table-cell-clip">{{ row.protocol }}</span></td>
                <td :title="row.source"><span class="table-cell-clip">{{ row.source }}</span></td>
                <td :title="row.target"><span class="table-cell-clip">{{ row.target }}</span></td>
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
                          :disabled="protectionTrialActive || !interfaceReady || isRowBusy(row)"
                          :aria-label="t('policySaveDescription')"
                          :title="t('policySaveDescription')"
                          @click="saveDescriptionEdit(row).catch(store.handleError)"
                        ><Check :size="16" aria-hidden="true" /></button>
                        <button
                          type="button"
                          class="description-inline-button cancel"
                          :disabled="isRowBusy(row)"
                          :aria-label="t('policyCancelDescription')"
                          :title="t('policyCancelDescription')"
                          @click="cancelDescriptionEdit"
                        ><X :size="16" aria-hidden="true" /></button>
                      </div>
                    </template>
                    <template v-else>
                      <span class="table-cell-clip" :title="row.description || '-'">{{ row.description || "-" }}</span>
                      <button
                        type="button"
                        class="description-edit-button"
                        :disabled="protectionTrialActive || !interfaceReady || isRowBusy(row)"
                        :aria-label="t('policyEditDescription')"
                        :title="t('policyEditDescription')"
                        @click="startDescriptionEdit(row)"
                      >
                        <Pencil :size="16" aria-hidden="true" />
                      </button>
                    </template>
                  </div>
                </td>
                <td>
                  <div class="inline-actions">
                    <button
                      v-if="row.kind !== 'bypass'"
                      class="icon-button table-action-button"
                      :title="t('policyEditRule')"
                      :aria-label="t('policyEditRule')"
                      :disabled="protectionTrialActive || !interfaceReady"
                      @click="openRuleEditor(row)"
                    ><Pencil :size="16" aria-hidden="true" /></button>
                    <button class="icon-button table-action-button danger" :title="t('actionDelete')" :aria-label="t('actionDelete')" :disabled="protectionTrialActive || !interfaceReady || isRowBusy(row)" @click="removeRule(row)">
                      <Trash2 :size="16" aria-hidden="true" />
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!ruleRows.length">
                <td colspan="7" class="table-empty">
                  <div>{{ t(policyDataStatus === "loading" ? "loading" : policyDataStatus === "unavailable" ? "protectionUnavailable" : "policyEmpty") }}</div>
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
        <TablePagination v-model:page="rulePage" v-model:page-size="rulePageSize" :total="ruleRows.length" :page-sizes="[15, 30, 50]" />
      </article>

    </div>

    <div v-if="composer.open" class="modal-mask" @click.self="closeComposer">
      <div ref="composerRoot" class="rule-composer" role="dialog" aria-modal="true" aria-labelledby="rule-composer-title" :aria-busy="composerBusy" @keydown="onComposerKeydown">
        <form class="rule-composer-main" @submit.prevent="submitComposer(false)">
          <div class="modal-head">
            <div>
              <p>{{ t("composerEyebrow") }}</p>
              <h3 id="rule-composer-title">{{ composer.editingRow ? t("policyEditRule") : t("composerTitle") }}</h3>
              <div class="rule-composer-context">{{ store.currentNode?.name || store.state.nodeId }} · {{ selectedInterfaceName }} · {{ t(store.state.direction === 'egress' ? 'toolbarEgress' : 'toolbarIngress') }}</div>
            </div>
            <button type="button" class="modal-close-dot icon-button" :disabled="composerBusy" :title="t('close')" :aria-label="t('close')" @click="closeComposer">
              <X :size="18" stroke-width="2" aria-hidden="true" />
            </button>
          </div>

          <div class="rule-composer-fields">
            <fieldset class="rule-form-grid compact" :disabled="composerBusy || composerResults.length > 0">
              <label class="field rule-span-2">
                <span>{{ t("composerStrategy") }} · {{ t("composerRequired") }}</span>
                <div class="segmented strategy-toggle">
                  <button type="button" :class="{ active: composer.strategy === 'allow' }" @click="composer.strategy = 'allow'">{{ t("actionAllow") }}</button>
                  <button type="button" :class="{ active: composer.strategy === 'deny' }" @click="composer.strategy = 'deny'">{{ t("actionDeny") }}</button>
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
                    <input v-model="composer.sourceValue" required :placeholder="t('composerSourcePlaceholder')" />
                  </label>
                  <label class="field" :class="composer.sourceType === 'ipv4' ? 'rule-span-3' : 'rule-span-2'">
                    <span>{{ t("policyTableDescription") }}</span>
                    <input v-model="composer.comment" maxlength="256" :placeholder="t('policyDescriptionPlaceholder')" />
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
                    <input v-model="composer.targetValue" type="number" required min="1" max="65535" :placeholder="t('composerTargetPlaceholder')" />
                  </label>
                  <div class="field rule-span-2" v-else-if="composer.protocol === 'icmp'">
                    <span>{{ t("composerTargetValue") }}</span>
                    <input :value="t('composerICMPTraffic')" disabled />
                  </div>
                </div>
              </div>

              <div v-if="store.state.nodes.length > 1" class="field rule-span-3 composer-node-targets">
                <span>{{ t("composerTargetNodes") }}</span>
                <NodeSelector v-model="composer.targetNodeIDs" :nodes="store.state.nodes" multiple :required-value="store.state.nodeId"
                  :is-online="store.isNodeOnline" :disabled="composerBusy || composerResults.length > 0" :aria-label="t('composerTargetNodes')" />
                <small class="field-hint">{{ t("composerTargetNodesHint") }}</small>
                <div v-for="node in additionalTargets" :key="node.id" class="composer-target-interface">
                  <label :for="`rule-target-${node.id}`">{{ node.name || node.id }}</label>
                  <span v-if="targetLoading[node.id]" class="field-hint">{{ t('settingsWaiting') }}</span>
                  <template v-else-if="targetErrors[node.id]">
                    <span class="composer-target-error">{{ targetErrors[node.id] }}</span>
                    <button type="button" class="ghost-button" @click="loadTargetInventory(node.id)">{{ t('settingsRetry') }}</button>
                  </template>
                  <select v-else :id="`rule-target-${node.id}`" v-model="targetInterfaces[node.id]" :aria-label="`${node.name || node.id} · ${t('settingsTargetInterface')}`" required>
                    <option v-for="item in targetInventories[node.id]" :key="item.name" :value="item.name">{{ item.name }} · {{ interfaceAddress(item).address }}</option>
                  </select>
                </div>
              </div>
            </fieldset>

            <div v-if="composerResults.length" class="composer-results" aria-live="polite">
              <strong>{{ t('policySubmitResults') }}</strong>
              <div v-for="item in composerResults" :key="item.nodeID" class="composer-result" :class="{ failed: item.status === 'failed' }">
                <strong>{{ store.state.nodes.find(node => node.id === item.nodeID)?.name || item.nodeID }} · {{ item.interface }}</strong>
                <span>{{ item.status === 'success' ? t('policyRuleSaved') : item.error }}</span>
              </div>
            </div>
            <p v-if="composerError" class="composer-target-error" role="alert">{{ composerError }}</p>
          </div>

          <div class="modal-actions">
            <button v-if="composerResults.length" type="button" class="primary-button" :disabled="composerBusy" @click="submitComposer(true)">{{ composerBusy ? t('settingsSaving') : t('policyRetryFailed') }}</button>
            <button v-else type="submit" class="primary-button" :disabled="!canSubmitComposer">{{ composerBusy ? t('settingsSaving') : composer.editingRow ? t("policySaveRule") : t("submit") }}</button>
            <button v-if="composerResults.length && composerResults.every(item => item.status === 'failed' && !item.ruleSaved)" type="button" class="ghost-button" :disabled="composerBusy" @click="composerResults = []; composerError = ''">{{ t('policyReviseRule') }}</button>
            <button type="button" class="ghost-button" :disabled="composerBusy" @click="closeComposer">{{ composerResults.length ? t("close") : t("cancel") }}</button>
          </div>
        </form>

        <aside class="rule-composer-side">
          <div class="matrix-head">
            <strong>{{ t("composerQuickLink") }}</strong>
          </div>
          <div class="preset-group" v-for="group in presetGroups" :key="group.titleKey">
            <h4>{{ t(group.titleKey) }}</h4>
            <button v-for="item in group.items" :key="item.labelKey" type="button" class="ghost-button preset-button" :disabled="composerBusy || composerResults.length > 0" @click="applyPreset(item.values)">
              {{ t(item.labelKey) }}
            </button>
          </div>
        </aside>
      </div>
    </div>
  </section>
</template>
<style scoped>

.shell .policy-context-panel { display: flex; grid-column: auto; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px 14px; min-width: 0; padding: 10px 12px; }
.policy-context-scope, .policy-context-actions, .policy-context-interface, .policy-interface-picker, .policy-rules-title { display: flex; align-items: center; gap: 8px; }
.policy-context-scope, .policy-context-actions, .policy-context-interface { min-width: 0; flex-wrap: wrap; }
.policy-context-scope { flex: 1 1 auto; }
.policy-context-actions { flex: 0 1 auto; }
.policy-interface-picker, .policy-interface-address { min-width: 0; max-width: 100%; color: var(--muted-strong); font-size: 12px; }
.policy-interface-picker span { white-space: nowrap; }
.policy-interface-picker select {
  width: auto;
  min-width: 0;
  font-size: 13px;
}
.policy-interface-picker select, .rules-toolbar select {
  appearance: auto;
  padding-right: 8px;
}
.policy-interface-address { overflow-wrap: anywhere; }
.policy-context-backend {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px 6px;
  max-width: 100%;
  color: var(--muted-strong);
  font-size: 12px;
}
.policy-context-panel .protection-trial-field { display: inline-flex; flex: 0 1 auto; flex-direction: row; align-items: center; gap: 7px; margin: 0; }
.policy-context-panel .protection-trial-field span { white-space: nowrap; }
.policy-context-panel .protection-trial-field input { width: 66px; min-width: 0; }
.policy-trial-text { color: var(--muted-strong); font-size: 12px; }
.policy-trial-lock-hint { color: var(--warning); }
.policy-rules-head { flex-wrap: wrap; }
.policy-rules-title h3 { margin: 0; }
.shell .firewall-page .rules-toolbar { align-items: center; flex-wrap: wrap; background: transparent; }
.rules-toolbar .policy-search-field { flex: 1 1 220px; min-width: 0; }
.rules-toolbar .policy-search-field > svg { top: 50%; transform: translateY(-50%); }
.rules-toolbar .policy-inline-field { display: flex; flex: 0 1 auto; flex-direction: row; align-items: center; gap: 8px; }
.rules-toolbar .policy-inline-field span { white-space: nowrap; }
.rules-toolbar .policy-inline-field select { width: 120px; }
.rules-table .table-action-button { padding: 0; }
.rules-table button > svg { flex: none; }
@media (max-width: 640px) {
  .policy-context-interface { flex-basis: 100%; }
  .policy-context-panel .protection-trial-field { flex-basis: 100%; }
  .rules-toolbar .policy-search-field { flex-basis: 100%; }
}
</style>
