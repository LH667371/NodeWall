<script setup>
import { computed, ref } from "vue";
import { getCountryCenter, projectCountryCenter } from "@/lib/countryCenters";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  visitItems: { type: Array, default: () => [] },
  blockItems: { type: Array, default: () => [] },
});
const { t } = useI18n();

const dimension = ref("3d");
const traffic = ref("visit");

function normalizeCountryCode(value) {
  const code = String(value || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code) || code === "ZZ") return "UNKNOWN";
  return code;
}

function countryLabel(item) {
  const code = normalizeCountryCode(item?.country_code);
  if (code === "UNKNOWN") return t("unknownCountry");
  return item?.country_name || code;
}

function aggregateCountryItems(items) {
  const map = new Map();
  (items || []).forEach((item) => {
    const code = normalizeCountryCode(item?.country_code);
    const key = code;
    const value = Number(item?.total || item?.dropped || 0);
    if (!map.has(key)) {
      map.set(key, {
        country_code: code,
        country_name: countryLabel(item),
        total: 0,
      });
    }
    map.get(key).total += value;
  });
  return [...map.values()].sort((a, b) => b.total - a.total);
}

const activeItems = computed(() => aggregateCountryItems(traffic.value === "block" ? props.blockItems : props.visitItems));

const maxValue = computed(() => Math.max(1, ...activeItems.value.map((item) => Number(item.total || item.dropped || 0))));

const worldPoints = computed(() => {
  return activeItems.value.slice(0, 8).map((item, index) => {
    const countryCode = normalizeCountryCode(item.country_code);
    if (countryCode === "UNKNOWN") return null;
    const projected = projectCountryCenter(countryCode);
    if (!projected) return null;
    return {
      id: `${traffic.value}-${countryCode}-${index}`,
      code: countryCode,
      label: countryLabel(item),
      x: projected.x,
      y: projected.y,
      value: Number(item.total || item.dropped || 0),
    };
  }).filter(Boolean);
});

const globePoints = computed(() => {
  return activeItems.value.slice(0, 8).map((item, index) => {
    const countryCode = normalizeCountryCode(item.country_code);
    if (countryCode === "UNKNOWN") return null;
    const center = getCountryCenter(countryCode);
    if (!center) return null;
    const lambda = (center.lon + 12) * (Math.PI / 180);
    const phi = center.lat * (Math.PI / 180);
    const cosPhi = Math.cos(phi);
    const sinPhi = Math.sin(phi);
    const cosLambda = Math.cos(lambda);
    const x3d = cosPhi * cosLambda;
    const y3d = sinPhi;
    const z3d = cosPhi * Math.sin(lambda);
    if (z3d < -0.16) return null;
    return {
      id: `${traffic.value}-${countryCode}-${index}`,
      code: countryCode,
      label: countryLabel(item),
      x: 220 + x3d * 118,
      y: 188 - y3d * 118,
      value: Number(item.total || item.dropped || 0),
    };
  }).filter(Boolean);
});

const ranking = computed(() => activeItems.value.slice(0, 7));
</script>

<template>
  <div class="geo-console">
    <div class="geo-stage">
      <div class="geo-toolbar">
        <div class="segmented map-toggle">
          <button :class="{ active: dimension === '3d' }" @click="dimension = '3d'">3D</button>
          <button :class="{ active: dimension === '2d' }" @click="dimension = '2d'">2D</button>
        </div>

        <div class="segmented map-toggle traffic-toggle">
          <button :class="{ active: traffic === 'visit' }" @click="traffic = 'visit'">{{ t("trafficVisit") }}</button>
          <button :class="{ active: traffic === 'block' }" @click="traffic = 'block'">{{ t("trafficBlock") }}</button>
        </div>
      </div>

      <svg v-if="dimension === '2d'" viewBox="0 0 640 320" class="worldmap-svg" aria-hidden="true">
        <defs>
          <radialGradient id="mapGlow" cx="50%" cy="50%" r="60%">
            <stop offset="0%" stop-color="rgba(29,183,174,0.18)" />
            <stop offset="100%" stop-color="rgba(29,183,174,0)" />
          </radialGradient>
          <linearGradient id="mapStroke" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#72ddd6" />
            <stop offset="100%" stop-color="#3fa7df" />
          </linearGradient>
        </defs>

        <rect x="12" y="12" width="616" height="296" rx="28" fill="url(#mapGlow)" />
        <g class="map-grid">
          <line x1="80" y1="24" x2="80" y2="296" />
          <line x1="160" y1="24" x2="160" y2="296" />
          <line x1="240" y1="24" x2="240" y2="296" />
          <line x1="320" y1="24" x2="320" y2="296" />
          <line x1="400" y1="24" x2="400" y2="296" />
          <line x1="480" y1="24" x2="480" y2="296" />
          <line x1="560" y1="24" x2="560" y2="296" />
          <line x1="24" y1="80" x2="616" y2="80" />
          <line x1="24" y1="160" x2="616" y2="160" />
          <line x1="24" y1="240" x2="616" y2="240" />
        </g>
        <g class="map-continents">
          <path d="M84 100c24-18 56-36 90-38 32-2 46 18 59 28 13 9 18 28 5 38-12 10-35 6-49 16-18 12-12 36-26 48-16 15-44 18-67 4-24-14-44-52-47-79-3-26 11-44 35-57z" />
          <path d="M178 194c17 4 33 19 38 38 5 19 0 44-15 63-9 11-16 22-23 33-7 12-18 11-26-2-11-17-15-41-9-59 8-22 13-40 35-73z" />
          <path d="M304 92c17-17 46-25 82-22 30 2 58 14 71 31 10 13 9 25-6 32-12 5-28 6-39 13-11 7-21 17-35 18-14 1-27-8-43-5-20 4-37 21-57 22-20 1-28-20-20-42 7-20 23-32 47-47z" />
          <path d="M377 173c13-6 35-1 48 12 13 13 17 31 10 44-8 16-30 17-44 28-13 10-18 31-32 38-12 5-28-4-35-17-8-15 0-31 13-42 11-10 17-25 16-38-1-11 10-20 24-25z" />
          <path d="M508 194c18-10 47-9 67 0 14 6 26 18 27 31 2 14-10 24-24 29-14 5-31 5-43 15-13 11-25 32-43 28-18-5-24-30-18-50 6-20 12-42 34-53z" />
        </g>
        <g v-for="point in worldPoints" :key="point.id">
          <circle :cx="point.x" :cy="point.y" :r="10 + (point.value / maxValue) * 12" class="map-node-glow" />
          <circle :cx="point.x" :cy="point.y" :r="3 + (point.value / maxValue) * 5" class="map-node" :class="{ danger: traffic === 'block' }" />
          <text :x="point.x + 10" :y="point.y - 8" class="map-label">{{ point.code }}</text>
        </g>
      </svg>

      <svg v-else viewBox="0 0 440 360" class="globe3d-svg" aria-hidden="true">
        <defs>
          <radialGradient id="sphereGlow" cx="50%" cy="42%" r="62%">
            <stop offset="0%" stop-color="rgba(93, 188, 231, 0.18)" />
            <stop offset="100%" stop-color="rgba(93, 188, 231, 0.02)" />
          </radialGradient>
          <linearGradient id="sphereStroke" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#72ddd6" />
            <stop offset="100%" stop-color="#3fa7df" />
          </linearGradient>
        </defs>

        <circle cx="220" cy="188" r="132" fill="url(#sphereGlow)" />
        <circle cx="220" cy="188" r="126" class="globe-shell-line" />
        <ellipse cx="220" cy="188" rx="126" ry="46" class="globe-lat-line" />
        <ellipse cx="220" cy="188" rx="126" ry="82" class="globe-lat-line" />
        <ellipse cx="220" cy="188" rx="126" ry="108" class="globe-lat-line" />
        <ellipse cx="220" cy="188" rx="92" ry="126" class="globe-lon-line" />
        <ellipse cx="220" cy="188" rx="52" ry="126" class="globe-lon-line" />

        <g class="globe-continents">
          <path d="M151 127c18-18 45-36 71-32 28 4 50 24 54 46 5 22-14 32-27 45-12 13-10 31-22 45-13 15-36 21-57 16-24-6-43-27-49-50-8-29 6-52 30-70z" />
          <path d="M223 111c19-10 50-13 72-2 24 12 43 35 40 59-2 17-20 23-33 30-14 7-22 19-35 32-12 12-31 18-46 11-14-7-19-28-10-43 8-14 13-30 8-46-4-16 -2-30 4-41z" />
          <path d="M289 206c14 2 28 13 34 27 7 15 4 30-8 41-10 9-25 10-35 21-11 11-19 26-34 27-13 2-26-11-28-26-2-17 9-30 21-40 11-9 18-18 20-31 2-11 15-21 30-19z" />
        </g>

        <g v-for="point in globePoints" :key="point.id">
          <circle :cx="point.x" :cy="point.y" :r="10 + (point.value / maxValue) * 10" class="map-node-glow" />
          <circle :cx="point.x" :cy="point.y" :r="3 + (point.value / maxValue) * 4" class="map-node" :class="{ danger: traffic === 'block' }" />
          <line x1="220" y1="188" :x2="point.x" :y2="point.y" class="globe-ray" />
        </g>
      </svg>
    </div>

    <aside class="geo-ranking">
      <div class="geo-ranking-head">
        <span>{{ traffic === "visit" ? t("visitRanking") : t("blockRanking") }}</span>
        <strong>{{ dimension.toUpperCase() }}</strong>
      </div>
      <div v-if="ranking.length" class="geo-ranking-list">
        <div v-for="item in ranking" :key="`${traffic}-${item.country_code}`" class="geo-ranking-row">
          <div class="geo-country">
            <strong>{{ countryLabel(item) }}</strong>
            <small>{{ normalizeCountryCode(item.country_code) === "UNKNOWN" ? "-" : normalizeCountryCode(item.country_code) }}</small>
          </div>
          <div class="geo-metric">
            <div class="geo-metric-bar">
              <span :style="{ width: `${Math.max((Number(item.total || item.dropped || 0) / maxValue) * 100, 8)}%` }" :class="{ danger: traffic === 'block' }"></span>
            </div>
            <strong>{{ item.total || item.dropped || 0 }}</strong>
          </div>
        </div>
      </div>
      <div v-else class="empty-state">{{ t("noCountryData") }}</div>
    </aside>
  </div>
</template>
