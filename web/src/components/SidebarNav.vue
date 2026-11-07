<script setup>
import { computed } from "vue";
import { Activity, LayoutDashboard, ScrollText, Server, Settings, ShieldCheck } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";

defineProps({
  section: { type: String, required: true },
});

const emit = defineEmits(["change"]);
const { t, state, locales, setLocale } = useI18n();

const primaryItems = computed(() => ([
  { key: "overview", title: t("navOverview"), icon: LayoutDashboard },
  { key: "security", title: t("navSecurity"), icon: ShieldCheck },
  { key: "monitoring", title: t("navMonitoring"), icon: Activity },
  { key: "cluster", title: t("navCluster"), icon: Server },
  { key: "events", title: t("navEvents"), icon: ScrollText },
]));
</script>

<template>
  <aside class="sidebar">
    <div class="brand">
      <img class="brand-logo" src="/nodewall-mark.svg" alt="NodeWall" />
      <div class="brand-copy">
        <div class="brand-name">NodeWall</div>
        <h1>{{ t("shellBrand") }}</h1>
      </div>
    </div>

    <nav class="nav-stack">
      <button
        v-for="item in primaryItems"
        :key="item.key"
        class="nav-item"
        :class="{ active: section === item.key || (item.key === 'cluster' && section === 'ssh-console') }"
        @click="emit('change', item.key)"
      >
        <component :is="item.icon" class="nav-item-icon" :size="17" stroke-width="1.8" aria-hidden="true" />
        <span>{{ item.title }}</span>
      </button>
    </nav>

    <div class="sidebar-footer">
      <button
        class="nav-item settings-nav-item"
        :class="{ active: section === 'management' }"
        @click="emit('change', 'management')"
      >
        <Settings class="nav-item-icon" :size="17" stroke-width="1.8" aria-hidden="true" />
        <span>{{ t("navManagement") }}</span>
      </button>

      <div class="sidebar-divider" aria-hidden="true"></div>
      <label class="sidebar-locale-label">{{ t("localeLabel") }}</label>
      <select class="sidebar-locale-select" :value="state.locale" @change="setLocale($event.target.value)">
        <option v-for="item in locales" :key="item.value" :value="item.value">{{ item.label }}</option>
      </select>
    </div>
  </aside>
</template>
