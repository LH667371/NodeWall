<script setup>
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], required: true },
  note: { type: String, default: "" },
  tone: { type: String, default: "default" },
  title: { type: String, default: "" },
  clickable: { type: Boolean, default: false },
});

const emit = defineEmits(["click"]);
</script>

<template>
  <article
    class="metric-tile"
    :class="[tone, { clickable }]"
    :title="title || undefined"
    :role="clickable ? 'button' : undefined"
    :tabindex="clickable ? 0 : undefined"
    @click="clickable && emit('click')"
    @keydown.enter="clickable && emit('click')"
  >
    <div class="metric-tile-head">
      <span class="metric-label">{{ label }}</span>
      <span class="metric-dot"></span>
    </div>
    <div class="metric-tile-body">
      <strong>{{ value }}</strong>
      <p v-if="note">{{ note }}</p>
    </div>
  </article>
</template>
