<script setup>
import { reactive, watch } from "vue";
import { X } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: "" },
  copy: { type: String, default: "" },
  fields: { type: Array, default: () => [] },
  busy: { type: Boolean, default: false },
  error: { type: String, default: "" },
});

const emit = defineEmits(["close", "confirm"]);
const { t } = useI18n();

const values = reactive({});

watch(
  () => props.fields,
  (next) => {
    Object.keys(values).forEach((key) => delete values[key]);
    next.forEach((field) => {
      values[field.key] = field.value ?? "";
    });
  },
  { immediate: true },
);
</script>

<template>
  <div v-if="open" class="modal-mask" @click.self="!busy && emit('close')">
    <form class="modal-card" role="dialog" aria-modal="true" aria-labelledby="action-modal-title" @submit.prevent="!busy && emit('confirm', { ...values })">
      <div class="modal-head">
        <div>
          <p>{{ t("modalAction") }}</p>
          <h3 id="action-modal-title">{{ title }}</h3>
        </div>
        <button type="button" class="modal-close-dot icon-button" :disabled="busy" :title="t('close')" :aria-label="t('close')" @click="emit('close')">
          <X :size="18" stroke-width="2" aria-hidden="true" />
        </button>
      </div>
      <p class="modal-copy">{{ copy }}</p>
      <p v-if="error" class="danger-tag" role="alert">{{ error }}</p>

      <div v-for="field in fields" :key="field.key" class="field">
        <label :for="`action-modal-${field.key}`">{{ field.label }}</label>
        <select v-if="field.type === 'select'" :id="`action-modal-${field.key}`" v-model="values[field.key]" :disabled="busy" :required="field.required">
          <option v-for="option in field.options" :key="option.value" :value="option.value">{{ option.label }}</option>
        </select>
        <textarea v-else-if="field.type === 'textarea'" :id="`action-modal-${field.key}`" v-model="values[field.key]" :disabled="busy" :required="field.required" :placeholder="field.placeholder || ''"></textarea>
        <input v-else :id="`action-modal-${field.key}`" v-model="values[field.key]" :disabled="busy" :required="field.required" :type="field.type || 'text'" :autocomplete="field.type === 'password' ? 'current-password' : 'off'" :placeholder="field.placeholder || ''" />
      </div>

      <div class="modal-actions">
        <button type="submit" :disabled="busy">{{ busy ? t("settingsSaving") : t("submit") }}</button>
        <button type="button" class="ghost-button" :disabled="busy" @click="emit('close')">{{ t("cancel") }}</button>
      </div>
    </form>
  </div>
</template>
