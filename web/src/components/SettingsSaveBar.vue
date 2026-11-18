<script setup>
import { computed } from "vue";
import { Save } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  session: { type: Object, required: true },
  loaded: Boolean,
  busy: Boolean,
  disabled: Boolean,
  error: { type: String, default: "" },
  label: { type: String, default: "" },
  compact: Boolean,
});
defineEmits(["save"]);
const { t } = useI18n();
const conflicts = computed(() => props.session.conflicts.value.length > 0);
</script>

<template>
  <div v-if="conflicts || error" class="settings-feedback" :class="{ compact }" role="alert">
    <span>{{ conflicts ? t("settingsConflict") : error }}</span>
    <button v-if="conflicts" type="button" class="ghost-button compact-button" :disabled="busy || disabled" @click="session.reset()">{{ t("settingsLoadLatest") }}</button>
  </div>
  <footer class="settings-save-bar" :class="{ compact }">
    <span v-if="!compact || session.dirty.value" class="field-hint" aria-live="polite">{{ !loaded ? t("settingsWaiting") : session.dirty.value ? t("settingsUnsaved") : t("settingsSynchronized") }}</span>
    <div class="split-actions">
      <button v-if="!compact || session.dirty.value" type="button" class="ghost-button" :disabled="!loaded || busy || disabled || !session.dirty.value" @click="session.reset()">{{ t("settingsDiscard") }}</button>
      <button type="button" class="primary-button" :disabled="!loaded || busy || disabled || conflicts || !session.dirty.value" @click="$emit('save')"><Save :size="15" />{{ busy ? t("settingsSaving") : label || t("settingsSave") }}</button>
    </div>
  </footer>
</template>
