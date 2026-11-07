<script setup>
import { computed, ref } from "vue";
import { RefreshCw, ShieldAlert, Terminal } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import LogsPage from "@/pages/LogsPage.vue";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();
const activeView = ref(props.store.state.eventsView === "ssh" ? "ssh" : "logs");
const activity = computed(() => props.store.state.sshProtection?.activity || []);

function selectView(view) {
  activeView.value = view;
  props.store.setEventsView(view);
}

function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString(props.store.state.locale === "en-US" ? "en-US" : "zh-CN");
}

function activityEvent(record) {
  const key = `sshActivity${String(record?.event || "").replace(/(^|_)([a-z])/g, (_, _separator, letter) => letter.toUpperCase())}`;
  return t(key) || record?.event || "-";
}

function activityTarget(record) {
  if (record?.event === "command") return record.command || "-";
  if (record?.event === "upload_scan") return record.path || "-";
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
  return record?.action || "-";
}
</script>

<template>
  <section class="events-page">
    <div class="page-tabs" role="tablist" :aria-label="t('eventsTitle')">
      <button type="button" role="tab" :aria-selected="activeView === 'logs'" :class="{ active: activeView === 'logs' }" @click="selectView('logs')">
        <ShieldAlert :size="15" stroke-width="1.9" aria-hidden="true" />{{ t("eventsLogs") }}
      </button>
      <button type="button" role="tab" :aria-selected="activeView === 'ssh'" :class="{ active: activeView === 'ssh' }" @click="selectView('ssh')">
        <Terminal :size="15" stroke-width="1.9" aria-hidden="true" />{{ t("eventsSSH") }}
      </button>
    </div>

    <LogsPage v-if="activeView === 'logs'" :store="props.store" />

    <article v-else-if="activeView === 'ssh'" class="panel panel-span-12">
      <div class="panel-head">
        <div>
          <h3>{{ t("sshActivityTitle") }}</h3>
        </div>
        <button class="ghost-button" @click="props.store.refreshSSHActivity().catch(props.store.handleError)">
          <RefreshCw :size="15" stroke-width="1.9" aria-hidden="true" />
          {{ t("sshActivityRefresh") }}
        </button>
      </div>
      <div v-if="activity.length" class="table-shell">
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
            <tr v-for="record in activity" :key="`${record.at}-${record.event}-${record.source_ip}-${record.command || record.path || ''}`">
              <td>{{ formatTime(record.at) }}</td>
              <td>{{ activityEvent(record) }}</td>
              <td>{{ record.user || "-" }} · {{ record.source_ip || "-" }}{{ record.source_port ? `:${record.source_port}` : "" }}</td>
              <td class="ssh-activity-target">{{ activityTarget(record) }}</td>
              <td>{{ activityResult(record) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-state">{{ t("sshActivityEmpty") }}</div>
    </article>

  </section>
</template>
