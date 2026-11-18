<script setup>
import { computed, ref, watch } from "vue";
import { KeyRound, Trash2, UserPlus } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import TablePagination from "@/components/TablePagination.vue";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();
const page = ref(0);
const pageSize = ref(10);
const query = ref("");
const role = ref("");
const status = ref("");
const users = computed(() => props.store.state.users || []);
const filteredUsers = computed(() => {
  const search = query.value.trim().toLowerCase();
  return users.value.filter((user) => {
    if (role.value && user.role !== role.value) return false;
    if (status.value && (user.enabled ? "enabled" : "disabled") !== status.value) return false;
    return !search || [user.username, user.role, user.email].filter(Boolean).join(" ").toLowerCase().includes(search);
  });
});
const visibleUsers = computed(() => filteredUsers.value.slice(page.value * pageSize.value, (page.value + 1) * pageSize.value));

watch(() => [query.value, role.value, status.value, users.value.length], () => {
  page.value = 0;
});
</script>

<template>
  <section class="page-grid">
    <div class="page-heading">
      <div>
        <p>{{ t("managementUsers") }}</p>
        <h2>{{ t("managementUsersTitle") }}</h2>
      </div>
      <span class="status-pill success">{{ t("roleAdmin") }}</span>
    </div>

    <article class="panel panel-span-12 user-management-panel workspace-fill workspace-panel">
      <div class="panel-head">
        <div>
          <p>{{ t("managementUsers") }}</p>
          <h3>{{ t("managementUsersTitle") }}</h3>
        </div>
      </div>

      <div class="stack-list workspace-fill workspace-panel">
        <div class="filter-grid user-create-grid">
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

        <div class="table-toolbar">
          <input v-model="query" type="search" :placeholder="t('managementUserSearch')" />
          <select v-model="role" :aria-label="t('role')">
            <option value="">{{ t("managementAllRoles") }}</option>
            <option value="viewer">{{ t("roleViewer") }}</option>
            <option value="operator">{{ t("roleOperator") }}</option>
            <option value="admin">{{ t("roleAdmin") }}</option>
          </select>
          <select v-model="status" :aria-label="t('status')">
            <option value="">{{ t("managementAllStatuses") }}</option>
            <option value="enabled">{{ t("enabled") }}</option>
            <option value="disabled">{{ t("disabled") }}</option>
          </select>
        </div>

        <div class="table-shell">
          <table class="console-table management-users-table">
            <thead>
              <tr>
                <th>{{ t("username") }}</th>
                <th>{{ t("role") }}</th>
                <th>{{ t("status") }}</th>
                <th>{{ t("policyTableActions") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="user in visibleUsers" :key="user.username">
                <td>
                  <strong>{{ user.username }}</strong>
                  <small v-if="user.email" class="table-secondary-text">{{ user.email }}</small>
                </td>
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
                      <KeyRound :size="16" stroke-width="1.8" aria-hidden="true" />
                    </button>
                    <button class="icon-button table-action-button danger" :title="t('actionDelete')" :aria-label="t('actionDelete')" @click="props.store.deleteUser(user.username).catch(props.store.handleError)">
                      <Trash2 :size="16" stroke-width="1.8" aria-hidden="true" />
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!visibleUsers.length">
                <td colspan="4" class="table-empty">{{ users.length ? t("managementNoUserMatches") : t("noData") }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <TablePagination v-model:page="page" v-model:page-size="pageSize" :total="filteredUsers.length" />

        <label class="field user-reset-password-field">
          <span>{{ t("resetPassword") }}</span>
          <input v-model="props.store.state.forms.resetPassword" type="password" :placeholder="t('newPassword')" />
        </label>
        <p class="field-hint">{{ t("userManagementPasswordHint") }}</p>
      </div>
    </article>
  </section>
</template>
