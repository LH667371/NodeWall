<script setup>
import { nextTick, onBeforeUnmount, ref, watch } from "vue";

const props = defineProps({
  text: { type: String, required: true },
  ellipsis: Boolean,
});

const anchor = ref(null);
const popover = ref(null);
const visible = ref(false);
const popoverStyle = ref({ top: "0px", left: "0px", visibility: "hidden" });
const tooltipId = `info-tip-${Math.random().toString(36).slice(2, 10)}`;
let hideTimer = null;

function clearHideTimer() {
  if (hideTimer) {
    window.clearTimeout(hideTimer);
    hideTimer = null;
  }
}

function updatePosition() {
  if (!visible.value || !anchor.value || !popover.value) return;

  const anchorRect = anchor.value.getBoundingClientRect();
  const popoverRect = popover.value.getBoundingClientRect();
  const margin = 12;
  const gap = 8;
  const viewportWidth = document.documentElement.clientWidth || window.innerWidth;
  const viewportHeight = document.documentElement.clientHeight || window.innerHeight;
  const belowTop = anchorRect.bottom + gap;
  const aboveTop = anchorRect.top - popoverRect.height - gap;
  const top = belowTop + popoverRect.height <= viewportHeight - margin || aboveTop < margin
    ? belowTop
    : aboveTop;
  const preferredLeft = anchorRect.left + (anchorRect.width - popoverRect.width) / 2;
  const left = Math.min(
    Math.max(preferredLeft, margin),
    Math.max(margin, viewportWidth - popoverRect.width - margin),
  );

  popoverStyle.value = {
    top: `${Math.min(Math.max(margin, top), Math.max(margin, viewportHeight - popoverRect.height - margin))}px`,
    left: `${left}px`,
    visibility: "visible",
  };
}

async function show() {
  clearHideTimer();
  if (props.ellipsis && anchor.value?.scrollWidth <= anchor.value?.clientWidth) return;
  visible.value = true;
  popoverStyle.value = { top: "0px", left: "0px", visibility: "hidden" };
  await nextTick();
  updatePosition();
}

function hide() {
  clearHideTimer();
  visible.value = false;
}

function scheduleHide() {
  clearHideTimer();
  hideTimer = window.setTimeout(() => {
    hide();
  }, 160);
}

function keepVisible() {
  clearHideTimer();
}

function handleViewportChange() {
  if (visible.value) updatePosition();
}

watch(() => props.text, () => {
  if (visible.value) nextTick(updatePosition);
});

// Tables may contain dozens of tooltip triggers. Only an open tooltip needs
// to track scrolling and window size.
watch(visible, (open, _previous, onCleanup) => {
  if (!open) return;
  window.addEventListener("resize", handleViewportChange);
  window.addEventListener("scroll", handleViewportChange, true);
  onCleanup(() => {
    window.removeEventListener("resize", handleViewportChange);
    window.removeEventListener("scroll", handleViewportChange, true);
  });
});

onBeforeUnmount(clearHideTimer);
</script>

<template>
  <span
    ref="anchor"
    :class="ellipsis ? 'info-tip-text' : 'info-tip'"
    tabindex="0"
    :aria-label="ellipsis ? undefined : text"
    :aria-describedby="visible ? tooltipId : undefined"
    @mouseenter="show"
    @mouseleave="scheduleHide"
    @focus="show"
    @blur="hide"
    @keydown.esc="hide"
  >
    <template v-if="ellipsis">{{ text }}</template>
    <span v-else class="info-tip-mark" aria-hidden="true">?</span>
  </span>
  <Teleport to="body">
    <span
      v-if="visible"
      :id="tooltipId"
      ref="popover"
      class="info-tip-popover"
      :style="popoverStyle"
      role="tooltip"
      @mouseenter="keepVisible"
      @mouseleave="hide"
    >{{ text }}</span>
  </Teleport>
</template>

<style scoped>
.info-tip:focus-visible {
  border-radius: 4px;
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

.info-tip-text {
  display: block;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
