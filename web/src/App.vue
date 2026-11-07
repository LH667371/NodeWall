<script setup>
import { computed, onMounted, provide } from "vue";
import { ArrowDown, ArrowUp, RotateCw, X } from "@lucide/vue";
import SidebarNav from "@/components/SidebarNav.vue";
import HeaderBar from "@/components/HeaderBar.vue";
import ActionModal from "@/components/ActionModal.vue";
import OverviewPage from "@/pages/OverviewPage.vue";
import ClusterPage from "@/pages/ClusterPage.vue";
import PolicyPage from "@/pages/PolicyPage.vue";
import LogsPage from "@/pages/LogsPage.vue";
import OperationsPage from "@/pages/OperationsPage.vue";
import EventsPage from "@/pages/EventsPage.vue";
import ManagementPage from "@/pages/ManagementPage.vue";
import SecurityPage from "@/pages/SecurityPage.vue";
import SSHConsolePage from "@/pages/SSHConsolePage.vue";
import { useNodewallConsole } from "@/composables/useNodewallConsole";
import { createI18n, I18N_KEY } from "@/lib/i18n";

const i18n = createI18n("zh-CN");
provide(I18N_KEY, i18n);
const store = useNodewallConsole(i18n);

const activePage = computed(() => {
  if (store.state.section === "policy") return PolicyPage;
  if (store.state.section === "cluster") return ClusterPage;
  if (store.state.section === "logs") return LogsPage;
  if (store.state.section === "monitoring") return OperationsPage;
  if (store.state.section === "events") return EventsPage;
  if (store.state.section === "management") return ManagementPage;
  if (store.state.section === "security") return SecurityPage;
  if (store.state.section === "ssh-console") return SSHConsolePage;
  return OverviewPage;
});

const interfaceOptions = computed(() => {
  const list = store.state.interfaces || [];
  const physical = list.filter((item) => item.is_physical);
  return physical.length ? physical : list;
});

// Direction and NIC only affect firewall data. Node scope lives in the header
// so operators always see the selected target before changing a policy.
const firewallPage = computed(() => store.state.section === "policy" || (store.state.section === "security" && store.state.securityFeature === "firewall"));
const showDirectionToolbar = computed(() => store.state.section === "overview" || firewallPage.value);
const showInterfaceToolbar = computed(() => firewallPage.value || (store.state.section === "overview" && store.state.overviewScope === "node"));
const showToolbar = computed(() => showDirectionToolbar.value || showInterfaceToolbar.value);

function interfaceLabel(item) {
  const addresses = Array.isArray(item?.addresses) ? item.addresses : [];
  const ipv4 = addresses.find((value) => String(value).includes(".")) || "";
  const ipv6 = addresses.find((value) => String(value).includes(":")) || "";
  const suffix = ipv4 || ipv6 || "-";
  const kind = item?.is_physical ? i18n.t("interfaceTypePhysical") : i18n.t("interfaceTypeVirtual");
  return `${item.name} · ${kind} · ${suffix}`;
}

onMounted(() => {
  store.bootstrap().catch(store.handleError);
});
</script>

<template>
  <div class="shell">
    <SidebarNav :section="store.state.section" @change="store.setSection" />

    <div class="workspace">
      <HeaderBar
        :section="store.state.section"
        :current-interface="store.currentInterface"
        :node-id="store.state.nodeId"
        :nodes="store.state.nodes"
        :overview-scope="store.state.overviewScope"
        :cluster-aggregate="store.state.clusterAggregate"
        :security-feature="store.state.securityFeature"
        @change-node="store.setNode"
        @change-security-feature="store.setSecurityFeature"
        @change-overview-scope="store.setOverviewScope"
      />

      <div v-if="showToolbar" class="toolbar console-context-bar">
        <div v-if="showDirectionToolbar" class="toolbar-group">
          <label>{{ i18n.t("toolbarDirection") }}</label>
          <div class="segmented">
            <button :class="{ active: store.state.direction === 'ingress' }" @click="store.setDirection('ingress')">
              <ArrowDown :size="14" stroke-width="2" aria-hidden="true" />
              {{ i18n.t("toolbarIngress") }}
            </button>
            <button :class="{ active: store.state.direction === 'egress' }" @click="store.setDirection('egress')">
              <ArrowUp :size="14" stroke-width="2" aria-hidden="true" />
              {{ i18n.t("toolbarEgress") }}
            </button>
          </div>
        </div>

        <div v-if="showInterfaceToolbar" class="toolbar-group toolbar-grow">
          <label>{{ i18n.t("toolbarInterface") }}</label>
          <select :value="store.currentInterface" @change="store.setInterface($event.target.value)">
            <option v-for="item in interfaceOptions" :key="item.name" :value="item.name">{{ interfaceLabel(item) }}</option>
          </select>
        </div>

      <button class="ghost-button context-refresh-button" :disabled="store.state.actionBusy.refresh" @click="store.refreshData().catch(store.handleError)">
          <RotateCw :size="15" stroke-width="1.9" :class="{ 'is-spinning': store.state.actionBusy.refresh }" aria-hidden="true" />
          {{ store.state.actionBusy.refresh ? i18n.t("toolbarRefreshing") : i18n.t("toolbarRefresh") }}
      </button>
      </div>

      <div class="toast-stack" aria-live="polite" aria-atomic="true">
        <div
          v-for="toast in store.state.toasts"
          :key="toast.id"
          class="toast-item"
          :class="toast.type === 'success' ? 'success' : toast.type === 'error' ? 'error' : 'info'"
        >
          <span>{{ toast.text }}</span>
          <button class="toast-close icon-button" :title="i18n.t('close')" :aria-label="i18n.t('close')" @click="store.dismissToast(toast.id)">
            <X :size="15" stroke-width="2" aria-hidden="true" />
          </button>
        </div>
      </div>

      <div v-if="store.state.loading" class="loading-panel">{{ i18n.t("loading") }}</div>
      <component :is="activePage" v-else :store="store" />
    </div>

    <ActionModal
      :open="store.state.modal.open"
      :title="store.state.modal.title"
      :copy="store.state.modal.copy"
      :fields="store.state.modal.fields"
      @close="store.closeModal"
      @confirm="store.confirmModal"
    />

    <div v-if="store.state.errorDialog.open" class="modal-mask" @click.self="store.closeErrorDialog()">
      <div class="modal-card">
        <div class="modal-head">
          <div>
            <p>{{ i18n.t("requestError") }}</p>
            <h3>{{ i18n.t("requestError") }}</h3>
          </div>
          <button class="modal-close-dot icon-button" :title="i18n.t('close')" :aria-label="i18n.t('close')" @click="store.closeErrorDialog()">
            <X :size="18" stroke-width="2" aria-hidden="true" />
          </button>
        </div>
        <p class="modal-copy">{{ store.state.errorDialog.message }}</p>
        <div class="modal-actions">
          <button @click="store.closeErrorDialog()">{{ i18n.t("close") }}</button>
        </div>
      </div>
    </div>
  </div>
</template>
