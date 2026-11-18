export const chartColors = ["#3274d9", "#c89300", "#009b76", "#c94f91", "#8250c4", "#df692f", "#008dad", "#c34343", "#658b25", "#5767c4"];

export function numericMetric(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

export function seriesColor(identity, offset = 0) {
  let hash = 2166136261;
  for (const char of String(identity)) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  return chartColors[((hash >>> 0) + offset) % chartColors.length];
}

const numberFormatters = new Map();
function decimal(value, digits) {
  // Reuse formatters: a tooltip on a 64-core host can format hundreds of
  // values per pointer frame, while only three precisions are needed.
  if (!numberFormatters.has(digits)) numberFormatters.set(digits, new Intl.NumberFormat("en-US", { maximumFractionDigits: digits }));
  return numberFormatters.get(digits).format(value);
}

export function formatMetric(value, unit = "percent", detail = true) {
  const number = numericMetric(value);
  if (number === null) return "—";
  const digits = detail ? 3 : (Math.abs(number) < 1 ? 3 : 1);
  if (unit === "percent") return `${decimal(number, digits)}%`;
  if (unit === "milliseconds") return `${decimal(number, digits)} ms`;
  if (unit === "iops") return `${decimal(number, digits)} io/s`;
  if (unit === "count" || unit === "number") return decimal(number, unit === "count" ? 0 : digits);
  const units = unit === "bytes" ? ["B", "KiB", "MiB", "GiB", "TiB"] : ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
  let scaled = number;
  let index = 0;
  while (Math.abs(scaled) >= 1024 && index < units.length - 1) { scaled /= 1024; index++; }
  return `${decimal(scaled, detail ? 3 : 1)} ${units[index]}`;
}

export function metricStatistics(points, key) {
  let sum = 0, count = 0, last = null, max = null;
  for (const point of points) {
    const value = numericMetric(point?.[key]);
    if (value === null) continue;
    sum += value; count++; last = value;
    max = max === null ? value : Math.max(max, value);
  }
  return { mean: count ? sum / count : null, last, max };
}

export function niceMetricMax(peak, fixed = 0) {
  if (fixed > 0) return Math.max(fixed, peak);
  if (!(peak > 0)) return 1;
  const scale = 10 ** Math.floor(Math.log10(peak));
  return Math.ceil(peak / scale * 2) / 2 * scale;
}

export function nearestTimeIndex(times, target) {
  if (!times.length) return -1;
  let low = 0, high = times.length - 1;
  while (low < high) {
    const mid = Math.floor((low + high) / 2);
    if (times[mid] < target) low = mid + 1; else high = mid;
  }
  return low > 0 && Math.abs(times[low - 1] - target) <= Math.abs(times[low] - target) ? low - 1 : low;
}

// Core detail is opt-in and bounded before chart construction. A 256-thread
// host must not allocate a curve and tooltip row for every thread by default.
export function cpuCoreGroups(nodePoints, nodes = [], pageSize = 8) {
  const names = new Map(nodes.map(node => [String(node.node_id || node.id), node.name || node.node_id || node.id]));
  const cores = [];
  for (const [nodeID, history] of Object.entries(nodePoints || {})) {
    const latest = [...(Array.isArray(history) ? history : [])].reverse().find(sample => sample?.logical_cpus?.length);
    const seen = new Set();
    for (const cpu of latest?.logical_cpus || []) {
      if (!cpu?.name || seen.has(cpu.name)) continue;
      seen.add(cpu.name);
      cores.push({ nodeID, name: cpu.name, label: `${names.get(nodeID) || nodeID} · ${cpu.name}`,
        id: JSON.stringify([nodeID, "logical_cpus", cpu.name]) });
    }
  }
  cores.sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  const groups = [];
  const size = Math.max(1, Math.trunc(pageSize) || 8);
  for (let index = 0; index < cores.length; index += size) {
    const items = cores.slice(index, index + size);
    const last = items[items.length - 1];
    groups.push({ value: groups.length, label: `${items[0].label} — ${last.nodeID === items[0].nodeID ? last.name : last.label}`,
      ids: new Set(items.map(item => item.id)) });
  }
  return groups;
}

export function acceleratorReading(device, key) {
  return numericMetric(device?.metrics?.[key]?.value ?? device?.[key]);
}

function acceleratorIdentity(device) {
  if (!device.bus_id) return `${device.vendor}/${device.index}`;
  const parts = String(device.bus_id).toLowerCase().split(":");
  if (parts.length === 3 && /^[0-9a-f]+$/.test(parts[0])) parts[0] = Number.parseInt(parts[0], 16).toString(16).padStart(4, "0");
  return parts.join(":");
}

// Device identity includes the node: two nodes' sda/cpu0/eth0 must never share
// a curve. Align independent agent clocks to the API's display sample bucket.
export function buildDeviceChart({ nodePoints, nodes = [], field, metrics, intervalSeconds = 5, includeNode = true, deviceIDs = null }) {
  const interval = Math.max(1, Number(intervalSeconds) || 5) * 1000;
  const buckets = new Map();
  const definitions = new Map();
  const names = new Map(nodes.map((node) => [String(node.node_id || node.id), node.name || node.node_id || node.id]));
  for (const [nodeID, history] of Object.entries(nodePoints || {}).sort(([a], [b]) => a.localeCompare(b))) {
    for (const sample of Array.isArray(history) ? history : []) {
      const captured = new Date(sample?.timestamp).getTime();
      if (!Number.isFinite(captured)) continue;
      const timestamp = Math.round(captured / interval) * interval;
      if (!buckets.has(timestamp)) buckets.set(timestamp, { timestamp: new Date(timestamp).toISOString(), values: new Map() });
      const bucket = buckets.get(timestamp);
      for (const device of Array.isArray(sample?.[field]) ? sample[field] : []) {
        const accelerator = field === "accelerators";
        const deviceName = accelerator ? `${device.name || device.vendor || "GPU"} #${device.index}` : device?.name || device?.mountpoint || device?.device;
        if (!deviceName) continue;
        const identity = accelerator ? acceleratorIdentity(device) : deviceName;
        if (deviceIDs && !deviceIDs.has(JSON.stringify([nodeID, field, identity]))) continue;
        for (const [metricIndex, metric] of metrics.entries()) {
          const key = JSON.stringify([nodeID, field, identity, metric.key]);
          const value = device.sample_ready === false ? null : acceleratorReading(device, metric.key);
          if (accelerator && value === null && !definitions.has(key)) continue;
          if (!definitions.has(key)) definitions.set(key, {
            key, label: [includeNode ? names.get(nodeID) || nodeID : "", deviceName, metric.label].filter(Boolean).join(" · "),
            color: seriesColor(JSON.stringify([nodeID, field, identity]), metricIndex), device: deviceName, nodeID,
          });
          const existing = bucket.values.get(key);
          if (!existing || captured >= existing.captured) {
            bucket.values.set(key, { captured, value });
          }
        }
      }
    }
  }
  const series = [...definitions.values()].sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  return {
    series,
    points: [...buckets].sort(([a], [b]) => a - b).map(([, bucket]) => {
      const row = { timestamp: bucket.timestamp };
      series.forEach(({ key }) => { row[key] = bucket.values.get(key)?.value ?? null; });
      return row;
    }),
  };
}
