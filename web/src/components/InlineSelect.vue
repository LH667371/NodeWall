<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { Check, ChevronDown } from "@lucide/vue";

const props = defineProps({
  modelValue: { type: [String, Number], default: "" },
  options: { type: Array, default: () => [] },
  ariaLabel: { type: String, default: "" },
});

const emit = defineEmits(["update:modelValue", "change"]);
const root = ref(null);
const open = ref(false);
const selected = computed(() => props.options.find((item) => item.value === props.modelValue) || props.options.find((item) => String(item.value) === String(props.modelValue)) || null);

function closeOnOutsidePointer(event) {
  if (!root.value?.contains(event.target)) open.value = false;
}

function selectOption(option) {
  if (!option || option.disabled) return;
  emit("update:modelValue", option.value);
  emit("change", option.value);
  open.value = false;
}

function onTriggerKeydown(event) {
  if (event.key === "Escape") {
    open.value = false;
    return;
  }
  if (event.key === "ArrowDown" || event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    open.value = true;
  }
}

onMounted(() => document.addEventListener("pointerdown", closeOnOutsidePointer));
onBeforeUnmount(() => document.removeEventListener("pointerdown", closeOnOutsidePointer));
</script>

<template>
  <div ref="root" class="inline-select" :class="{ open }">
    <button
      class="inline-select-trigger"
      type="button"
      role="combobox"
      :aria-label="ariaLabel || undefined"
      :aria-expanded="open"
      aria-haspopup="listbox"
      @click="open = !open"
      @keydown="onTriggerKeydown"
    >
      <span>{{ selected?.label || "-" }}</span>
      <ChevronDown class="inline-select-chevron" :size="16" stroke-width="1.9" aria-hidden="true" />
    </button>
    <div v-if="open" class="inline-select-menu" role="listbox" :aria-label="ariaLabel || undefined">
      <button
        v-for="option in options"
        :key="String(option.value)"
        class="inline-select-option"
        :class="{ active: option.value === modelValue, disabled: option.disabled }"
        type="button"
        role="option"
        :aria-selected="option.value === modelValue"
        :disabled="option.disabled"
        @click="selectOption(option)"
      >
        <span>{{ option.label }}</span>
        <Check v-if="option.value === modelValue" class="inline-select-check" :size="15" stroke-width="2.2" aria-hidden="true" />
      </button>
    </div>
  </div>
</template>
