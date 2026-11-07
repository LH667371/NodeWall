<script setup>
import { nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import { Check, ChevronDown } from "@lucide/vue";

const props = defineProps({
  modelValue: { type: String, default: "" },
  options: { type: Array, default: () => [] },
  disabled: { type: Boolean, default: false },
  danger: { type: Boolean, default: false },
  ariaLabel: { type: String, default: "" },
  title: { type: String, default: "" },
});

const emit = defineEmits(["update:modelValue", "change"]);
const open = ref(false);
const root = ref(null);
const menuStyle = ref({});

function selectedLabel() {
  return props.options.find((item) => item.value === props.modelValue)?.label || props.modelValue;
}

function toggle() {
  if (props.disabled) return;
  open.value = !open.value;
  if (open.value) nextTick(updateMenuPosition);
}

function choose(option) {
  open.value = false;
  if (option.value === props.modelValue) return;
  emit("update:modelValue", option.value);
  emit("change", option.value);
}

function closeOnOutsideClick(event) {
  if (root.value && !root.value.contains(event.target)) open.value = false;
}

function updateMenuPosition() {
  if (!open.value || !root.value) return;
  const trigger = root.value.querySelector(".strategy-menu-trigger");
  if (!trigger) return;
  const rect = trigger.getBoundingClientRect();
  const gap = 6;
  const edge = 12;
  const desiredHeight = Math.min(112, window.innerHeight - edge * 2);
  const spaceBelow = Math.max(0, window.innerHeight - rect.bottom - edge);
  const spaceAbove = Math.max(0, rect.top - edge);
  const placeAbove = spaceBelow < desiredHeight && spaceAbove > spaceBelow;
  const availableHeight = placeAbove ? spaceAbove : spaceBelow;
  menuStyle.value = placeAbove
    ? {
      top: "auto",
      bottom: `${window.innerHeight - rect.top + gap}px`,
      left: `${rect.left}px`,
      maxHeight: `${Math.max(48, availableHeight)}px`,
    }
    : {
      top: `${rect.bottom + gap}px`,
      bottom: "auto",
      left: `${rect.left}px`,
      maxHeight: `${Math.max(48, availableHeight)}px`,
    };
}

onMounted(() => document.addEventListener("click", closeOnOutsideClick));
onMounted(() => {
  window.addEventListener("resize", updateMenuPosition);
  window.addEventListener("scroll", updateMenuPosition, true);
});
onBeforeUnmount(() => {
  document.removeEventListener("click", closeOnOutsideClick);
  window.removeEventListener("resize", updateMenuPosition);
  window.removeEventListener("scroll", updateMenuPosition, true);
});
</script>

<template>
  <div ref="root" class="strategy-menu-wrap" :class="{ danger, open }">
    <button
      type="button"
      class="strategy-menu-trigger"
      :disabled="disabled"
      :aria-label="ariaLabel"
      :title="title"
      :aria-expanded="open"
      aria-haspopup="listbox"
      @click.stop="toggle"
    >
      <span>{{ selectedLabel() }}</span>
      <ChevronDown class="strategy-menu-arrow" :size="15" stroke-width="2" aria-hidden="true" />
    </button>
    <Teleport to="body">
      <div v-if="open" class="strategy-menu-list" :style="menuStyle" role="listbox" :aria-label="ariaLabel">
        <button
          v-for="option in options"
          :key="option.value"
          type="button"
          class="strategy-menu-option"
          :class="{ selected: option.value === modelValue }"
          role="option"
          :aria-selected="option.value === modelValue"
          @click.stop="choose(option)"
        >
          <Check v-if="option.value === modelValue" class="strategy-menu-check" :size="15" stroke-width="2.2" aria-hidden="true" />
          <span v-else class="strategy-menu-check" aria-hidden="true"></span>
          <span>{{ option.label }}</span>
        </button>
      </div>
    </Teleport>
  </div>
</template>
