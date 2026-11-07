<script setup>
import { KeyRound, RotateCcw, Save, Trash2, UserPlus } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  store: { type: Object, required: true },
});
const { t } = useI18n();
</script>

<template>
  <section class="page-grid">
    <div class="management-layout">
      <article class="panel panel-span-4">
        <div class="panel-head">
          <div>
            <p>{{ t("managementAuth") }}</p>
            <h3>{{ t("managementAuthTitle") }}</h3>
          </div>
        </div>
        <div class="stack-list">
          <label class="field">
            <span>{{ t("failThreshold") }}</span>
            <input v-model.number="props.store.state.authSettings.max_failures" type="number" min="1" />
          </label>
          <label class="field">
            <span>{{ t("statsWindow") }}</span>
            <input v-model.number="props.store.state.authSettings.window_seconds" type="number" min="60" />
          </label>
          <label class="field">
            <span>{{ t("lockDuration") }}</span>
            <input v-model.number="props.store.state.authSettings.lock_duration_seconds" type="number" min="60" />
          </label>
          <div class="key-row"><span>{{ t("activeLocks") }}</span><strong>{{ props.store.state.authSettings.active_locks || 0 }}</strong></div>
          <button class="primary-button" @click="props.store.saveAuthSettings().catch(props.store.handleError)">
            <Save :size="16" stroke-width="2" aria-hidden="true" />
            {{ t("saveAuth") }}
          </button>
        </div>
      </article>

      <article class="panel panel-span-4">
        <div class="panel-head">
          <div>
            <p>{{ t("managementPassword") }}</p>
            <h3>{{ t("managementPasswordTitle") }}</h3>
          </div>
        </div>
        <div class="stack-list">
          <label class="field">
            <span>{{ t("currentPassword") }}</span>
            <input v-model="props.store.state.forms.currentPassword" type="password" />
          </label>
          <label class="field">
            <span>{{ t("newPassword") }}</span>
            <input v-model="props.store.state.forms.newPassword" type="password" />
          </label>
          <button class="primary-button" @click="props.store.changePassword().catch(props.store.handleError)">
            <KeyRound :size="16" stroke-width="2" aria-hidden="true" />
            {{ t("changePassword") }}
          </button>
        </div>
      </article>

      <article class="panel panel-span-4">
        <div class="panel-head">
          <div>
            <p>{{ t("managementLogging") }}</p>
            <h3>{{ t("managementLoggingTitle") }}</h3>
          </div>
        </div>
        <div class="stack-list">
          <label class="field">
            <span>{{ t("enableLogging") }}</span>
            <select v-model="props.store.state.loggingSettings.enabled">
              <option :value="true">{{ t("enabled") }}</option>
              <option :value="false">{{ t("disabled") }}</option>
            </select>
          </label>
          <label class="field">
            <span>{{ t("retentionDays") }}</span>
            <input v-model.number="props.store.state.loggingSettings.retention_days" type="number" min="1" />
          </label>
          <label class="field">
            <span>{{ t("flushInterval") }}</span>
            <input v-model.number="props.store.state.loggingSettings.flush_interval_seconds" type="number" min="1" />
          </label>
          <label class="field">
            <span>{{ t("replyTimeout") }}</span>
            <input v-model.number="props.store.state.loggingSettings.reply_flow_timeout_seconds" type="number" min="1" />
          </label>
          <label class="field">
            <span>{{ t("logDir") }}</span>
            <input v-model="props.store.state.loggingSettings.log_dir" />
          </label>
          <div class="split-actions">
            <button class="primary-button" @click="props.store.saveLoggingSettings().catch(props.store.handleError)">
              <Save :size="16" stroke-width="2" aria-hidden="true" />
              {{ t("saveLogging") }}
            </button>
            <button class="ghost-button danger-text" @click="props.store.confirmClearPersistedLogs()">
              <Trash2 :size="15" stroke-width="1.9" aria-hidden="true" />
              {{ t("clearLogs") }}
            </button>
          </div>
        </div>
      </article>

      <article class="panel panel-span-12">
        <div class="panel-head">
          <div>
            <p>{{ t("managementUsers") }}</p>
            <h3>{{ t("managementUsersTitle") }}</h3>
          </div>
        </div>
        <div class="stack-list">
          <div class="filter-grid">
            <input v-model="props.store.state.forms.createUsername" :placeholder="t('username')" />
            <input v-model="props.store.state.forms.createPassword" type="password" :placeholder="t('newPassword')" />
            <select v-model="props.store.state.forms.createRole">
              <option value="viewer">{{ t("roleViewer") }}</option>
              <option value="operator">{{ t("roleOperator") }}</option>
              <option value="admin">{{ t("roleAdmin") }}</option>
            </select>
            <button class="primary-button" @click="props.store.createUser().catch(props.store.handleError)">
              <UserPlus :size="16" stroke-width="2" aria-hidden="true" />
              {{ t("createUser") }}
            </button>
          </div>
          <div class="table-shell">
            <table class="console-table">
              <thead>
                <tr>
                  <th>{{ t("username") }}</th>
                  <th>{{ t("role") }}</th>
                  <th>{{ t("status") }}</th>
                  <th>{{ t("policyTableActions") }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="user in props.store.state.users" :key="user.username">
                  <td>{{ user.username }}</td>
                  <td>
                    <select :value="user.role" @change="props.store.updateUserRole(user.username, $event.target.value).catch(props.store.handleError)">
                      <option value="viewer">{{ t("roleViewer") }}</option>
                      <option value="operator">{{ t("roleOperator") }}</option>
                      <option value="admin">{{ t("roleAdmin") }}</option>
                    </select>
                  </td>
                  <td>
                    <select :value="user.enabled ? 'enabled' : 'disabled'" @change="props.store.updateUserEnabled(user.username, $event.target.value === 'enabled').catch(props.store.handleError)">
                      <option value="enabled">{{ t("enabled") }}</option>
                      <option value="disabled">{{ t("disabled") }}</option>
                    </select>
                  </td>
                  <td>
                    <div class="inline-actions">
                      <button class="icon-button table-action-button" :title="t('resetPassword')" :aria-label="t('resetPassword')" @click="props.store.resetUserPassword(user.username).catch(props.store.handleError)">
                        <RotateCcw :size="16" stroke-width="1.8" aria-hidden="true" />
                      </button>
                      <button class="icon-button table-action-button danger" :title="t('actionDelete')" :aria-label="t('actionDelete')" @click="props.store.deleteUser(user.username).catch(props.store.handleError)">
                        <Trash2 :size="16" stroke-width="1.8" aria-hidden="true" />
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <label class="field">
            <span>{{ t("resetPassword") }}</span>
            <input v-model="props.store.state.forms.resetPassword" type="password" :placeholder="t('newPassword')" />
          </label>
        </div>
      </article>

      <article class="panel panel-span-12">
        <div class="panel-head">
          <div>
            <p>{{ t("managementRuntime") }}</p>
            <h3>{{ t("managementRuntimeTitle") }}</h3>
          </div>
        </div>
        <div class="runtime-grid">
          <div class="runtime-card">
            <span>{{ t("headerNode") }}</span>
            <strong>{{ props.store.state.nodeId }}</strong>
          </div>
          <div class="runtime-card">
            <span>{{ t("defaultInterface") }}</span>
            <strong>{{ props.store.state.defaultInterface || "-" }}</strong>
          </div>
          <div class="runtime-card">
            <span>{{ t("recommendedInterface") }}</span>
            <strong>{{ props.store.state.recommendedInterface || "-" }}</strong>
          </div>
          <div class="runtime-card">
            <span>{{ t("authStatus") }}</span>
            <strong>{{ props.store.state.authEnabled ? t("enabled") : t("disabled") }}</strong>
          </div>
          <div class="runtime-card">
            <span>{{ t("username") }}</span>
            <strong>{{ props.store.state.authUsername || "-" }}</strong>
          </div>
          <div class="runtime-card">
            <span>{{ t("role") }}</span>
            <strong>{{ props.store.state.authRole || "-" }}</strong>
          </div>
          <div class="runtime-card">
            <span>{{ t("clientSource") }}</span>
            <strong>{{ props.store.state.currentSourceIP || "-" }}</strong>
          </div>
          <div class="runtime-card">
            <span>{{ t("persistedLogs") }}</span>
            <strong>{{ props.store.state.persistedLogs.length }}</strong>
          </div>
        </div>
      </article>
    </div>
  </section>
</template>
