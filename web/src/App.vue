<script setup>
import { computed, onBeforeUnmount, onMounted, provide } from "vue";
import { X } from "@lucide/vue";
import SidebarNav from "@/components/SidebarNav.vue";
import HeaderBar from "@/components/HeaderBar.vue";
import ActionModal from "@/components/ActionModal.vue";
import OverviewPage from "@/pages/OverviewPage.vue";
import ClusterPage from "@/pages/ClusterPage.vue";
import PolicyPage from "@/pages/PolicyPage.vue";
import OperationsPage from "@/pages/OperationsPage.vue";
import EventsPage from "@/pages/EventsPage.vue";
import ManagementPage from "@/pages/ManagementPage.vue";
import UserManagementPage from "@/pages/UserManagementPage.vue";
import AccountPage from "@/pages/AccountPage.vue";
import SecurityPage from "@/pages/SecurityPage.vue";
import SSHConsolePage from "@/pages/SSHConsolePage.vue";
import SecurityFeatureTabs from "@/components/SecurityFeatureTabs.vue";
import { useNodewallConsole } from "@/composables/useNodewallConsole";
import { createI18n, I18N_KEY } from "@/lib/i18n";
import { initializeTheme } from "@/lib/theme";

const i18n = createI18n("zh-CN");
provide(I18N_KEY, i18n);
const store = useNodewallConsole(i18n);
initializeTheme();

const showSecurityFeatureTabs = computed(() => store.state.section === "security");

onMounted(() => {
  store.bootstrap().catch(store.handleError);
});

onBeforeUnmount(() => store.dispose());
</script>

<template>
  <div class="shell">
    <SidebarNav
      :section="store.state.section"
      :security-feature="store.state.securityFeature"
      :version="store.state.version"
      :alert-count="store.pendingEventCount"
      @change="store.setSection"
    />

    <div class="workspace">
      <HeaderBar
        :section="store.state.section"
        :current-interface="store.currentInterface"
        :node-id="store.state.nodeId"
        :nodes="store.state.nodes"
        :is-node-online="store.isNodeOnline"
        :overview-scope="store.state.overviewScope"
        :cluster-aggregate="store.state.clusterAggregate"
        :security-feature="store.state.securityFeature"
        :management-scope="store.state.managementScope"
        :auth-username="store.state.authUsername"
        :auth-role="store.state.authRole"
        :alert-count="store.pendingEventCount"
        @change-node="store.setNode"
        @change-security-feature="store.setSecurityFeature"
        @change-overview-scope="store.setOverviewScope"
        @change-section="store.setSection"
        @logout="store.logout"
        @account="store.setSection('account')"
      />

      <SecurityFeatureTabs v-if="showSecurityFeatureTabs" :store="store" />

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

      <main class="workspace-content">
        <div v-if="store.state.loading" class="loading-panel">{{ i18n.t("loading") }}</div>
        <!-- Explicit route components keep a running scan from reusing the
             previous security view after a navigation. -->
        <OverviewPage v-else-if="store.state.section === 'overview'" :key="`overview:${store.state.overviewScope}`" :store="store" />
        <ClusterPage v-else-if="store.state.section === 'cluster'" :store="store" />
        <PolicyPage v-else-if="store.state.section === 'policy'" :key="`policy:${store.state.nodeId}:${store.state.securityFeature}`" :store="store" />
        <EventsPage v-else-if="store.state.section === 'events' || store.state.section === 'logs'" :store="store" />
        <OperationsPage v-else-if="store.state.section === 'monitoring'" :store="store" />
        <ManagementPage v-else-if="store.state.section === 'management'" :store="store" />
        <UserManagementPage v-else-if="store.state.section === 'users' && store.state.authRole === 'admin'" :store="store" />
        <AccountPage v-else-if="store.state.section === 'account'" :key="`account:${store.state.authUsername}`" :store="store" />
        <SecurityPage v-else-if="store.state.section === 'security'" :key="`security:${store.state.securityFeature}:${store.state.nodeId}`" :store="store" />
        <SSHConsolePage v-else-if="store.state.section === 'ssh-console'" :key="`ssh-console:${store.state.sshConsole.nodeId}`" :store="store" />
        <OverviewPage v-else :key="`fallback-overview:${store.state.overviewScope}`" :store="store" />
      </main>
    </div>

    <ActionModal
      :open="store.state.modal.open"
      :title="store.state.modal.title"
      :copy="store.state.modal.copy"
      :fields="store.state.modal.fields"
      :busy="store.state.modal.busy"
      :error="store.state.modal.error"
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
