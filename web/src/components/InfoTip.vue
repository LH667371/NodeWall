<script setup>
import { CircleHelp } from "@lucide/vue";
import { nextTick, onBeforeUnmount, ref, watch } from "vue";

const props = defineProps({
  text: { type: String, required: true },
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
    top: `${Math.max(margin, top)}px`,
    left: `${left}px`,
    visibility: "visible",
  };
}

async function show() {
  clearHideTimer();
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

window.addEventListener("resize", handleViewportChange);
window.addEventListener("scroll", handleViewportChange, true);

onBeforeUnmount(() => {
  clearHideTimer();
  window.removeEventListener("resize", handleViewportChange);
  window.removeEventListener("scroll", handleViewportChange, true);
});
</script>

<template>
  <span
    ref="anchor"
    class="info-tip"
    tabindex="0"
    :aria-label="text"
    :aria-describedby="visible ? tooltipId : undefined"
    @mouseenter="show"
    @mouseleave="scheduleHide"
    @focus="show"
    @blur="hide"
  >
    <CircleHelp class="info-tip-mark" :size="14" stroke-width="1.9" aria-hidden="true" />
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
