<script setup>
import { computed, ref } from "vue";
import { Activity, Bell, LayoutDashboard, Server, Settings, ShieldCheck } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import { useTheme } from "@/lib/theme";

const props = defineProps({
  section: { type: String, required: true },
  securityFeature: { type: String, default: "overview" },
  version: { type: Object, default: () => ({}) },
  alertCount: { type: Number, default: 0 },
});

const emit = defineEmits(["change"]);
const { t, state, locales, setLocale } = useI18n();
const { state: themeState, setThemeMode } = useTheme();
const versionTipVisible = ref(false);
const versionTipID = `sidebar-version-${Math.random().toString(36).slice(2, 10)}`;

// Keep the primary navigation to the six product surfaces. Node actions and
// audit history are reached from the relevant page so the sidebar remains a
// stable scope map instead of a list of implementation destinations.
const navItems = computed(() => [
  { key: "overview", title: t("navOverview"), icon: LayoutDashboard },
  { key: "cluster", title: t("navNodes"), icon: Server },
  { key: "security", title: t("navSecurity"), icon: ShieldCheck },
  { key: "monitoring", title: t("navMonitoring"), icon: Activity },
  { key: "events", title: t("navAlerts"), icon: Bell, badge: props.alertCount },
  { key: "management", title: t("navSettings"), icon: Settings },
]);

function isNavItemActive(key) {
  if (key === "overview") return props.section === "overview";
  if (key === "security") return props.section === "security" || props.section === "policy";
  if (key === "cluster") return props.section === "cluster";
  if (key === "events") return props.section === "events" || props.section === "logs";
  return props.section === key;
}
</script>

<template>
  <aside class="sidebar">
    <div class="sidebar-brand-block">
      <div class="brand">
        <img class="brand-logo" src="/nodewall-mark.svg" alt="NodeWall" />
        <div class="brand-copy">
          <div class="brand-name">NodeWall</div>
          <h1>{{ t("shellBrand") }}</h1>
        </div>
      </div>
      <span class="sidebar-live-state"><i aria-hidden="true"></i>{{ t("shellOnline") }}</span>
    </div>

    <nav class="nav-stack" :aria-label="t('shellBrand')">
      <button
        v-for="item in navItems"
        :key="item.key"
        class="nav-item nav-item-compact"
        :class="{ active: isNavItemActive(item.key) }"
        :aria-current="isNavItemActive(item.key) ? 'page' : undefined"
        type="button"
        @click="emit('change', item.key)"
      >
        <span class="nav-item-icon-wrap"><component :is="item.icon" class="nav-item-icon" :size="18" stroke-width="1.9" aria-hidden="true" /></span>
        <span class="nav-item-label">{{ item.title }}</span>
        <span v-if="item.badge" class="nav-item-badge" :title="t('headerNotificationsCount', { count: item.badge })">{{ item.badge > 99 ? "99+" : item.badge }}</span>
      </button>
    </nav>

    <div class="sidebar-footer">
      <div class="sidebar-preferences">
        <label class="sidebar-locale-label" for="sidebar-locale">{{ t("localeLabel") }}</label>
        <select id="sidebar-locale" class="sidebar-locale-select" :value="state.locale" @change="setLocale($event.target.value)">
          <option v-for="item in locales" :key="item.value" :value="item.value">{{ item.label }}</option>
        </select>
      </div>
      <div class="sidebar-preferences">
        <label class="sidebar-locale-label" for="sidebar-theme">{{ t("themeMode") }}</label>
        <select id="sidebar-theme" class="sidebar-locale-select" :value="themeState.mode" @change="setThemeMode($event.target.value)">
          <option value="light">{{ t("themeLight") }}</option>
          <option value="dark">{{ t("themeDark") }}</option>
          <option value="system">{{ t("themeSystem") }}</option>
        </select>
      </div>
      <div
        v-if="version?.package_version"
        class="sidebar-version-wrap"
        @mouseenter="versionTipVisible = true"
        @mouseleave="versionTipVisible = false"
      >
        <small
          class="sidebar-version"
          tabindex="0"
          :aria-label="`${t('versionLabel')} ${version.package_version}`"
          :aria-describedby="versionTipVisible ? versionTipID : undefined"
          @focus="versionTipVisible = true"
          @blur="versionTipVisible = false"
        >
          {{ t("versionLabel") }} {{ version.package_version }}
        </small>
        <span v-if="versionTipVisible" :id="versionTipID" class="sidebar-version-popover" role="tooltip">
          {{ t("versionLabel") }} {{ version.package_version }}
        </span>
      </div>
    </div>
  </aside>
</template>
