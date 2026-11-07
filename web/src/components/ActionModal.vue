<script setup>
import { reactive, watch } from "vue";
import { X } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: "" },
  copy: { type: String, default: "" },
  fields: { type: Array, default: () => [] },
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
  <div v-if="open" class="modal-mask" @click.self="emit('close')">
    <div class="modal-card">
      <div class="modal-head">
        <div>
          <p>{{ t("modalAction") }}</p>
          <h3>{{ title }}</h3>
        </div>
        <button class="modal-close-dot icon-button" :title="t('close')" :aria-label="t('close')" @click="emit('close')">
          <X :size="18" stroke-width="2" aria-hidden="true" />
        </button>
      </div>
      <p class="modal-copy">{{ copy }}</p>

      <div v-for="field in fields" :key="field.key" class="field">
        <label>{{ field.label }}</label>
        <select v-if="field.type === 'select'" v-model="values[field.key]">
          <option v-for="option in field.options" :key="option.value" :value="option.value">{{ option.label }}</option>
        </select>
        <textarea v-else-if="field.type === 'textarea'" v-model="values[field.key]" :placeholder="field.placeholder || ''"></textarea>
        <input v-else v-model="values[field.key]" :type="field.type || 'text'" :placeholder="field.placeholder || ''" />
      </div>

      <div class="modal-actions">
        <button @click="emit('confirm', { ...values })">{{ t("submit") }}</button>
        <button class="ghost-button" @click="emit('close')">{{ t("cancel") }}</button>
      </div>
    </div>
  </div>
</template>
