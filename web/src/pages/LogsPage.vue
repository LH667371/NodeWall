<script setup>
import { computed } from "vue";
import { Ban, Clock3, Gauge, ShieldCheck, Trash2 } from "@lucide/vue";
import InfoTip from "@/components/InfoTip.vue";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  store: { type: Object, required: true },
});
const { t } = useI18n();

const locale = computed(() => props.store?.state?.locale || "zh-CN");
const visibleLogs = computed(() => props.store.filteredLogs);
const selectedVisibleCount = computed(() => visibleLogs.value.filter((item) => isSelected(item)).length);
const allVisibleSelected = computed(() => visibleLogs.value.length > 0 && selectedVisibleCount.value === visibleLogs.value.length);
const someVisibleSelected = computed(() => selectedVisibleCount.value > 0 && !allVisibleSelected.value);

function normalizeIPv4(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const direct = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})$/);
  const candidate = direct?.[1] || raw.match(/(\d{1,3}(?:\.\d{1,3}){3})/)?.[1] || "";
  if (!candidate) return "";
  const parts = candidate.split(".").map((item) => Number(item));
  if (parts.length !== 4 || parts.some((item) => !Number.isInteger(item) || item < 0 || item > 255)) return "";
  return parts.join(".");
}

function displaySourceIP(item) {
  return normalizeIPv4(item?.source_ip) || String(item?.source_ip || "-");
}

function itemKey(item) {
  return [item.interface || "-", item.direction || "ingress", displaySourceIP(item), item.port || 0, item.timestamp || "-"].join("|");
}

function isSelected(item) {
  return props.store.state.selection.has(itemKey(item));
}

function toggleAllLogs() {
  if (allVisibleSelected.value) {
    visibleLogs.value.forEach((item) => props.store.state.selection.delete(itemKey(item)));
    return;
  }
  visibleLogs.value.forEach((item) => {
    if (!isSelected(item)) props.store.toggleLogSelection(item);
  });
}

function isIntercepted(item) {
  return Number(item?.drops ?? item?.count ?? 0) > 0;
}

function isHandled(item) {
  return Boolean(item?.disposition?.status && item.disposition.status !== "open");
}

function dispositionAction(item) {
  const status = item?.disposition?.status;
  if (status === "allowlisted" || status === "bypassed") return "allow";
  if (status === "blocked") return "block";
  if (status === "rate_limited") return "rate-limit";
  if (status === "temp_blocked") return "temp-block";
  return "";
}

function isCurrentAction(item, action) {
  return dispositionAction(item) === action;
}

function actionCopy(item, baseCopy, action) {
  const current = dispositionAction(item);
  if (!current || current === action) return baseCopy;
  const labels = {
    allow: t("actionAllow"),
    block: t("actionBlock"),
    "rate-limit": t("actionRateLimit"),
    "temp-block": t("actionTempBlock"),
  };
  return `${baseCopy} ${t("logActionReplaceCopy", { current: labels[current] || t("handled"), next: labels[action] || action })}`;
}

function actionTooltip(item, action) {
  const copy = {
    allow: t("logActionAllowTooltip"),
    "rate-limit": t("logActionRateTooltip"),
    "temp-block": t("logActionTempTooltip"),
    block: t("logActionBlockTooltip"),
  };
  return actionCopy(item, copy[action] || "", action);
}

function hitCount(item) {
  const value = item?.count ?? item?.drops ?? 0;
  return props.store.formatNumber(Number(value || 0));
}

function formatTime(value) {
  if (!value) return "-";
  const ts = new Date(value);
  if (Number.isNaN(ts.getTime())) return "-";
  return ts.toLocaleString(locale.value === "en-US" ? "en-US" : "zh-CN");
}

function openAllow(item) {
  const source = displaySourceIP(item);
  props.store.openModal({
    title: t("logActionAllowTitle"),
    copy: actionCopy(item, t("logActionAllowCopy", { source }), "allow"),
    fields: [
      {
        key: "target",
        label: t("logActionAllowMode"),
        type: "select",
        value: "allowlist",
        options: [
          { label: t("ruleTrusted"), value: "allowlist" },
          { label: t("ruleBypass"), value: "bypass" },
        ],
      },
    ],
    onConfirm: async (payload) => {
      await props.store.runLogAction("allow", item, { scope: payload.target || "allowlist" });
    },
  });
}

function openBlock(item) {
  const source = displaySourceIP(item);
  props.store.openModal({
    title: t("logActionBlockTitle"),
    copy: actionCopy(item, t("logActionBlockCopy", { source }), "block"),
    onConfirm: async () => {
      await props.store.runLogAction("block", item, {});
    },
  });
}

function openRateLimit(item) {
  const source = displaySourceIP(item);
  const endpoint = item.port ? `${source}:${item.port}` : source;
  props.store.openModal({
    title: t("logActionRateTitle"),
    copy: actionCopy(item, t("logActionRateCopy", { endpoint }), "rate-limit"),
    fields: [
      {
        key: "requests_per_minute",
        label: t("logActionRateRPM"),
        type: "number",
        value: 120,
      },
      {
        key: "burst",
        label: t("logActionRateBurst"),
        type: "number",
        value: 20,
      },
    ],
    onConfirm: async (payload) => {
      await props.store.runLogAction("rate-limit", item, {
        requests_per_minute: Number(payload.requests_per_minute || 120),
        burst: Number(payload.burst || 20),
      });
    },
  });
}

function openTempBlock(item) {
  const source = displaySourceIP(item);
  props.store.openModal({
    title: t("logActionTempTitle"),
    copy: actionCopy(item, t("logActionTempCopy", { source }), "temp-block"),
    fields: [
      {
        key: "duration_minutes",
        label: t("logActionTempDuration"),
        type: "select",
        value: 60,
        options: [
          { label: t("duration15m"), value: 15 },
          { label: t("duration1h"), value: 60 },
          { label: t("duration24h"), value: 1440 },
        ],
      },
    ],
    onConfirm: async (payload) => {
      await props.store.runLogAction("temp-block", item, {
        duration_minutes: Number(payload.duration_minutes || 60),
      });
    },
  });
}

async function bulkTempBlock() {
  const rows = props.store.filteredLogs.filter((item) => isSelected(item));
  for (const item of rows) {
    await props.store.runLogAction("temp-block", item, { duration_minutes: 60 });
  }
  props.store.state.selection.clear();
}

async function bulkRateLimit() {
  const rows = props.store.filteredLogs.filter((item) => isSelected(item));
  for (const item of rows) {
    await props.store.runLogAction("rate-limit", item, { requests_per_minute: 120, burst: 20 });
  }
  props.store.state.selection.clear();
}
</script>

<template>
  <section class="page-grid">
    <div class="logs-layout">
      <article class="panel logs-table-panel">
        <div class="panel-head">
          <div>
            <p>{{ t("logsDesk") }}</p>
            <h3>{{ t("logsDeskTitle") }}</h3>
          </div>
          <div class="panel-actions">
            <button class="ghost-button danger-text" @click="props.store.confirmClearPersistedLogs()">
              <Trash2 :size="15" stroke-width="1.9" aria-hidden="true" />
              {{ t("clearLogs") }}
            </button>
            <template v-if="selectedVisibleCount">
              <button class="ghost-button" @click="bulkRateLimit().catch(props.store.handleError)">
                <Gauge :size="15" stroke-width="1.9" aria-hidden="true" />
                {{ t("bulkRateLimit") }}
              </button>
              <button class="primary-button" @click="bulkTempBlock().catch(props.store.handleError)">
                <Clock3 :size="15" stroke-width="1.9" aria-hidden="true" />
                {{ t("bulkTempBlock") }}
              </button>
            </template>
          </div>
        </div>

        <div class="filter-grid">
          <input v-model="props.store.state.filters.logsQuery" :placeholder="t('logsSearch')" />
          <select v-model="props.store.state.filters.logsInterface">
            <option value="">{{ t("allInterfaces") }}</option>
            <option v-for="item in props.store.state.interfaces" :key="item.name" :value="item.name">{{ item.name }}</option>
          </select>
          <select v-model="props.store.state.filters.logsDirection">
            <option value="">{{ t("allDirections") }}</option>
            <option value="ingress">{{ t("toolbarIngress") }}</option>
            <option value="egress">{{ t("toolbarEgress") }}</option>
          </select>
          <select v-model="props.store.state.filters.logsStatus">
            <option value="">{{ t("allStatus") }}</option>
            <option value="intercepted">{{ t("intercepted") }}</option>
            <option value="handled">{{ t("handled") }}</option>
          </select>
        </div>

        <div class="table-shell">
          <table class="console-table log-table">
            <colgroup>
              <col class="log-col-select" />
              <col class="log-col-source" />
              <col class="log-col-port" />
              <col class="log-col-direction" />
              <col class="log-col-reason" />
              <col class="log-col-hits" />
              <col class="log-col-time" />
              <col class="log-col-status" />
              <col class="log-col-actions" />
            </colgroup>
            <thead>
              <tr>
                <th class="select-column">
                  <label class="table-select-all">
                    <input
                      type="checkbox"
                      :checked="allVisibleSelected"
                      :indeterminate="someVisibleSelected"
                      :disabled="!visibleLogs.length"
                      :aria-label="allVisibleSelected ? t('deselectAll') : t('selectAll')"
                      @change="toggleAllLogs"
                    />
                    <span>{{ allVisibleSelected ? t("deselectAll") : t("selectAll") }}</span>
                  </label>
                </th>
                <th>{{ t("sourceIp") }}</th>
                <th>{{ t("port") }}</th>
                <th>{{ t("toolbarDirection") }}</th>
                <th>{{ t("reason") }}</th>
                <th>{{ t("hitCount") }}</th>
                <th>{{ t("recentTime") }}</th>
                <th>{{ t("interceptStatus") }}</th>
                <th>
                  <span class="table-heading-with-tip">
                    {{ t("policyTableActions") }}
                    <InfoTip :text="t('logsActionHelp')" />
                  </span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in props.store.filteredLogs" :key="itemKey(item)">
                <td><input type="checkbox" :checked="isSelected(item)" @change="props.store.toggleLogSelection(item)" /></td>
                <td class="log-source">
                  <strong>{{ displaySourceIP(item) }}</strong>
                  <small>{{ item.interface }}</small>
                </td>
                <td>{{ item.port || "-" }}</td>
                <td>{{ item.direction === "egress" ? t("toolbarEgress") : t("toolbarIngress") }}</td>
                <td>{{ props.store.formatLogReason(item.reason) }}</td>
                <td>{{ hitCount(item) }}</td>
                <td>{{ formatTime(item.timestamp) }}</td>
                <td>
                  <span v-if="isHandled(item)" class="status-pill">{{ t("handled") }}</span>
                  <span v-else-if="isIntercepted(item)" class="status-pill danger">{{ t("intercepted") }}</span>
                </td>
                <td>
                  <div class="inline-actions">
                    <button class="icon-button table-action-button log-action-button allow" :title="actionTooltip(item, 'allow')" :aria-label="actionTooltip(item, 'allow')" :disabled="isCurrentAction(item, 'allow')" @click="openAllow(item)">
                      <ShieldCheck :size="18" stroke-width="1.9" aria-hidden="true" />
                      <span class="log-action-tooltip" role="tooltip"><strong>{{ t("actionAllow") }}</strong><small>{{ t("logActionAllowTooltip") }}</small></span>
                    </button>
                    <button class="icon-button table-action-button log-action-button rate" :title="actionTooltip(item, 'rate-limit')" :aria-label="actionTooltip(item, 'rate-limit')" :disabled="isCurrentAction(item, 'rate-limit')" @click="openRateLimit(item)">
                      <Gauge :size="18" stroke-width="1.9" aria-hidden="true" />
                      <span class="log-action-tooltip" role="tooltip"><strong>{{ t("actionRateLimit") }}</strong><small>{{ t("logActionRateTooltip") }}</small></span>
                    </button>
                    <button class="icon-button table-action-button log-action-button warning" :title="actionTooltip(item, 'temp-block')" :aria-label="actionTooltip(item, 'temp-block')" :disabled="isCurrentAction(item, 'temp-block')" @click="openTempBlock(item)">
                      <Clock3 :size="18" stroke-width="1.9" aria-hidden="true" />
                      <span class="log-action-tooltip" role="tooltip"><strong>{{ t("actionTempBlock") }}</strong><small>{{ t("logActionTempTooltip") }}</small></span>
                    </button>
                    <button class="icon-button table-action-button log-action-button danger" :title="actionTooltip(item, 'block')" :aria-label="actionTooltip(item, 'block')" :disabled="isCurrentAction(item, 'block')" @click="openBlock(item)">
                      <Ban :size="18" stroke-width="1.9" aria-hidden="true" />
                      <span class="log-action-tooltip" role="tooltip"><strong>{{ t("actionBlock") }}</strong><small>{{ t("logActionBlockTooltip") }}</small></span>
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!props.store.filteredLogs.length">
                <td colspan="9" class="table-empty">{{ t("noLogs") }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>

      <article class="panel logs-queue-panel">
        <div class="panel-head">
          <div>
            <p>{{ t("releaseQueue") }}</p>
            <h3>{{ t("releaseQueueTitle") }}</h3>
          </div>
        </div>
        <div v-if="props.store.state.temporaryBlocks.length" class="stack-list">
          <div v-for="item in props.store.state.temporaryBlocks" :key="item.id" class="queue-card">
            <strong>{{ displaySourceIP(item) }}</strong>
            <span>{{ item.port ? `:${item.port}` : t("allPorts") }}</span>
            <small>{{ formatTime(item.expires_at) }}</small>
          </div>
        </div>
        <div v-else class="empty-state">{{ t("noTempBlocks") }}</div>
      </article>

      <article class="panel logs-queue-panel">
        <div class="panel-head">
          <div>
            <p>{{ t("rateLimitRules") }}</p>
            <h3>{{ t("rateLimitRulesTitle") }}</h3>
          </div>
        </div>
        <div v-if="props.store.state.rateLimits.length" class="stack-list">
          <div v-for="item in props.store.state.rateLimits" :key="item.id" class="queue-card">
            <strong>{{ displaySourceIP(item) }}</strong>
            <span>{{ item.port ? `:${item.port}` : t("allPorts") }}</span>
            <small>{{ item.requests_per_minute }}/min · burst {{ item.burst }}</small>
          </div>
        </div>
        <div v-else class="empty-state">{{ t("noRateLimits") }}</div>
      </article>

      <article class="panel logs-feed-panel">
        <div class="panel-head">
          <div>
            <p>{{ t("interfaceFeed") }}</p>
            <h3>{{ t("interfaceFeedTitle") }}</h3>
          </div>
        </div>
        <div v-if="props.store.state.interfaceLogs.length" class="feed-list">
          <div v-for="item in props.store.state.interfaceLogs.slice(0, 8)" :key="itemKey(item)" class="feed-item">
            <div>
              <strong>{{ displaySourceIP(item) }}</strong>
              <p>{{ props.store.formatLogReason(item.reason) }} · {{ item.port || "-" }} · {{ item.direction || "ingress" }}</p>
            </div>
            <small>{{ formatTime(item.timestamp) }}</small>
          </div>
        </div>
        <div v-else class="empty-state">{{ t("noInterfaceFeed") }}</div>
      </article>
    </div>
  </section>
</template>
