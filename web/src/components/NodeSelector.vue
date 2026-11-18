<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import { Check, ChevronDown, Search } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  modelValue: { type: [String, Array], default: "" },
  nodes: { type: Array, default: () => [] },
  multiple: { type: Boolean, default: false },
  requiredValue: { type: String, default: "" },
  disabled: { type: Boolean, default: false },
  ariaLabel: { type: String, default: "" },
  isOnline: { type: Function, default: null },
});
const emit = defineEmits(["update:modelValue", "change"]);
const { t } = useI18n();
const root = ref(null);
const search = ref(null);
const open = ref(false);
const query = ref("");
const name = (node) => node?.name || node?.id || t("headerNodeEmpty");
const address = (node) => node?.advertise_ip || node?.ssh?.host || node?.id || "";
const selected = computed(() => props.nodes.find((node) => node.id === props.modelValue));
const selectedIDs = computed(() => new Set([...(Array.isArray(props.modelValue) ? props.modelValue : []), props.requiredValue].filter(Boolean)));
const filtered = computed(() => {
  const value = query.value.trim().toLowerCase();
  return props.nodes.filter((node) => !value || [node.name, node.id, address(node)].join(" ").toLowerCase().includes(value));
});
// A selected node that goes offline must remain removable from the batch.
const unavailable = (node) => props.multiple && node.id !== props.requiredValue && !selectedIDs.value.has(node.id) && props.isOnline && !props.isOnline(node);
const isSelected = (node) => props.multiple ? selectedIDs.value.has(node.id) : props.modelValue === node.id;
const selectable = computed(() => filtered.value.filter((node) => node.id !== props.requiredValue && (!props.isOnline || props.isOnline(node))));
const allSelected = computed(() => selectable.value.length > 0 && selectable.value.every((node) => selectedIDs.value.has(node.id)));

function update(value) {
  emit("update:modelValue", value);
  emit("change", value);
}
function choose(node) {
  if (props.disabled || unavailable(node) || (props.multiple && node.id === props.requiredValue)) return;
  if (props.multiple) {
    const values = new Set(Array.isArray(props.modelValue) ? props.modelValue : []);
    if (values.has(node.id)) values.delete(node.id); else values.add(node.id);
    update([...values]);
  } else {
    update(node.id);
    open.value = false;
    root.value?.querySelector(".node-selector-trigger")?.focus();
  }
}
function toggleAll() {
  const values = new Set(Array.isArray(props.modelValue) ? props.modelValue : []);
  for (const node of selectable.value) {
    if (allSelected.value) values.delete(node.id); else values.add(node.id);
  }
  update([...values]);
}
async function toggle() {
  open.value = !open.value;
  if (open.value) {
    query.value = "";
    await nextTick();
    search.value?.focus();
  }
}
function onKeydown(event) {
  if (event.key === "Enter" && event.target === search.value) {
    event.preventDefault();
  } else if (event.key === "Escape" && !props.multiple) {
    event.preventDefault();
    event.stopPropagation();
    open.value = false;
    root.value?.querySelector(".node-selector-trigger")?.focus();
  } else if (["ArrowDown", "ArrowUp"].includes(event.key)) {
    event.preventDefault();
    if (!props.multiple && !open.value) { toggle(); return; }
    const buttons = [...root.value.querySelectorAll(".node-selector-option:not(:disabled)")];
    const index = buttons.indexOf(document.activeElement);
    buttons[(index + (event.key === "ArrowDown" ? 1 : buttons.length - 1)) % buttons.length]?.focus();
  }
}
function onOutside(event) {
  if (!root.value?.contains(event.target)) open.value = false;
}
function onFocusout(event) {
  if (!root.value?.contains(event.relatedTarget)) open.value = false;
}
onMounted(() => document.addEventListener("pointerdown", onOutside));
onBeforeUnmount(() => document.removeEventListener("pointerdown", onOutside));
</script>

<template>
  <div ref="root" class="node-selector" :class="{ 'is-multiple': multiple, 'is-open': open }" @keydown="onKeydown" @focusout="onFocusout">
    <button v-if="!multiple" type="button" class="node-selector-trigger" :disabled="disabled || !nodes.length"
      :aria-label="ariaLabel || t('headerNodeSelect')" :title="selected ? `${name(selected)} · ${address(selected)}` : undefined" aria-haspopup="listbox" :aria-expanded="open" @click="toggle">
      <span class="node-selector-current"><strong>{{ name(selected) }}</strong><small v-if="selected">{{ address(selected) }}</small></span>
      <ChevronDown :size="16" aria-hidden="true" />
    </button>
    <div v-if="multiple || open" class="node-selector-menu">
      <div class="node-selector-search"><Search :size="15" aria-hidden="true" /><input ref="search" v-model="query" type="search"
        :disabled="disabled" :aria-label="t('nodeSelectorSearch')" :placeholder="t('nodeSelectorSearch')" /></div>
      <div v-if="multiple" class="node-selector-tools">
        <span>{{ t('nodeSelectorCount', { count: selectedIDs.size, total: nodes.length }) }}</span>
        <button type="button" :disabled="disabled || !selectable.length" @click="toggleAll">{{ allSelected ? t('nodeSelectorDeselect') : t('nodeSelectorSelect') }}</button>
      </div>
      <div class="node-selector-options" role="listbox" :aria-label="ariaLabel || t('headerNodeSelect')" :aria-multiselectable="multiple || undefined">
        <button v-for="node in filtered" :key="node.id" type="button" role="option" class="node-selector-option"
          :class="{ selected: isSelected(node) }" :aria-selected="isSelected(node)"
          :disabled="disabled || unavailable(node) || (multiple && node.id === requiredValue)" @click="choose(node)">
          <span v-if="multiple" class="node-selector-checkbox"><Check v-if="isSelected(node)" :size="13" aria-hidden="true" /></span>
          <span class="node-selector-node" :title="`${name(node)} · ${address(node)}`"><strong>{{ name(node) }}</strong><small>{{ address(node) }}</small></span>
          <span v-if="node.id === requiredValue" class="node-selector-required">{{ t('composerCurrentNode') }}</span>
          <span v-else-if="isOnline" class="node-selector-status" :class="{ online: isOnline(node) }">{{ t(isOnline(node) ? 'clusterOnline' : 'clusterOffline') }}</span>
          <Check v-if="!multiple && isSelected(node)" class="node-selector-check" :size="15" aria-hidden="true" />
        </button>
        <p v-if="!filtered.length" class="node-selector-empty">{{ t('nodeSelectorEmpty') }}</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.node-selector { position: relative; min-width: 0; color: var(--text); }
.node-selector-trigger { display: flex; align-items: center; justify-content: space-between; gap: 14px; width: 100%; min-height: 40px; padding: 5px 11px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg-panel-strong); color: var(--text); text-align: left; }
.node-selector-current, .node-selector-node { display: grid; gap: 1px; min-width: 0; }
.node-selector-current strong, .node-selector-node strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; font-weight: 600; }
.node-selector-current small, .node-selector-node small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); font-size: 11px; font-weight: 400; }
.node-selector-trigger > svg { flex: 0 0 auto; color: var(--muted); transition: transform .15s; }
.is-open .node-selector-trigger > svg { transform: rotate(180deg); }
.node-selector-menu { position: absolute; z-index: 85; top: calc(100% + 6px); right: 0; width: min(360px, calc(100vw - 32px)); padding: 8px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg-panel-strong); box-shadow: 0 10px 32px rgba(10, 25, 40, .18); }
.node-selector-search { display: flex; align-items: center; gap: 7px; padding: 0 9px; border: 1px solid var(--line); border-radius: 5px; background: var(--bg-soft); color: var(--muted); }
.node-selector .node-selector-search input { width: 100%; min-width: 0; min-height: 34px; padding: 5px 0; border: 0; border-radius: 0; background: transparent; box-shadow: none; color: var(--text); font-size: 12px; }
.node-selector-options { display: grid; gap: 3px; max-height: min(340px, 50vh); overflow-y: auto; margin-top: 7px; overscroll-behavior: contain; }
.node-selector-option { display: flex; align-items: center; gap: 10px; width: 100%; min-width: 0; padding: 9px 10px; border: 1px solid transparent; border-radius: 5px; background: transparent; color: var(--text); text-align: left; }
.node-selector-option:hover, .node-selector-option:focus-visible { background: var(--bg-soft); border-color: var(--accent); outline: none; }
.node-selector-option.selected { background: var(--accent-soft); border-color: color-mix(in srgb, var(--accent) 28%, transparent); }
.node-selector-option:disabled { opacity: .65; cursor: default; }
.node-selector-node { flex: 1; }
.node-selector-status { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 5px; color: var(--muted); font-size: 11px; font-weight: 400; }
.node-selector-status::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--muted); }
.node-selector-status.online::before { background: var(--accent); }
.node-selector-check { color: var(--accent-strong); }
.node-selector-required { flex: 0 0 auto; font-size: 11px; color: var(--accent-strong); font-weight: 500; }
.node-selector-checkbox { display: grid; place-items: center; flex: 0 0 16px; width: 16px; height: 16px; border: 1px solid var(--line-strong); border-radius: 3px; background: var(--bg-panel-strong); }
.selected .node-selector-checkbox { background: var(--accent-strong); color: #fff; border-color: var(--accent-strong); }
.node-selector-empty { margin: 12px; font-size: 12px; color: var(--muted); }
.is-multiple .node-selector-menu { position: static; width: 100%; box-shadow: none; }
.is-multiple .node-selector-options { grid-template-columns: repeat(2, minmax(0, 1fr)); max-height: 210px; }
.is-multiple .node-selector-tools { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 8px 2px 0; font-size: 12px; color: var(--muted); }
.node-selector-tools button { min-height: 24px; padding: 0; border: 0; background: transparent; color: var(--accent-strong); font-size: 12px; }
@media (max-width: 600px) { .is-multiple .node-selector-options { grid-template-columns: minmax(0, 1fr); } }
</style>
