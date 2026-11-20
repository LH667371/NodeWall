const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

async function load(file) {
  const module = new vm.SourceTextModule(fs.readFileSync(path.join(__dirname, '../src/lib', file), 'utf8'));
  await module.link(() => { throw new Error('pure data helpers must not import a UI runtime'); });
  await module.evaluate();
  return module.namespace;
}
const metric = load('monitoringSeries.js');
const time = (seconds) => new Date(1700000000000 + seconds * 1000).toISOString();

test('retired nodes remain in monitoring and replay ends at the last archived sample', async () => {
  const { monitoringNodeCatalog, lastMonitoringHour } = await metric;
  const catalog = monitoringNodeCatalog([{ id: 'active', name: 'Current name' }], [
    { node_id: 'active', name: 'Older name', last_sample_at: time(7150), registered: true },
    { node_id: 'retired', name: 'Build worker', last_sample_at: time(3000), registered: false },
  ]);
  assert.deepEqual(Array.from(catalog, node => [node.node_id, node.name, node.registered]), [
    ['active', 'Current name', true], ['retired', 'Build worker', false],
  ]);
  const now = Date.parse(time(7200));
  const available = lastMonitoringHour(catalog[1].last_sample_at, 7 * 86400, now);
  assert.equal(available.from, time(-600));
  assert.equal(available.to, time(3000));
  const clipped = lastMonitoringHour(catalog[1].last_sample_at, 6000, now);
  assert.equal(clipped.from, time(1200));
  assert.equal(clipped.to, time(3000));
  assert.equal(lastMonitoringHour(catalog[1].last_sample_at, 3600, now), null);
});

test('many-core detail is paginated before curves are allocated', async () => {
  const { cpuCoreGroups, buildDeviceChart } = await metric;
  const history = { a: [{ timestamp: time(0), logical_cpus: Array.from({ length: 256 }, (_, index) => ({ name: `cpu${index}`, usage_percent: index / 10 })) }] };
  const groups = cpuCoreGroups(history, [{ node_id: 'a', name: 'tools01' }]);
  assert.equal(groups.length, 32);
  assert.equal(groups[0].ids.size, 8);
  assert.match(groups[0].label, /cpu0 — cpu7$/);
  const chart = buildDeviceChart({ nodePoints: history, field: 'logical_cpus', deviceIDs: groups[31].ids,
    metrics: [{ key: 'usage_percent', label: 'CPU' }] });
  assert.equal(chart.series.length, 8);
  assert.equal(chart.series[0].device, 'cpu248');
  assert.equal(chart.series[7].device, 'cpu255');
});

test('identical GPU models have separate identities and idle zeros survive omission of scalar fields', async () => {
  const { buildDeviceChart, acceleratorReading } = await metric;
  const history = { a: [{ timestamp: time(0), accelerators: [
    { vendor: 'NVIDIA', name: 'NVIDIA A30', index: 0, metrics: { utilization_percent: { value: 0 }, memory_used_bytes: { value: 0 } } },
    { vendor: 'NVIDIA', name: 'NVIDIA A30', index: 1, utilization_percent: 45 },
    { vendor: 'NVIDIA', name: 'NVIDIA A30', index: 2, backend: 'pci-sysfs' },
  ] }] };
  const chart = buildDeviceChart({ nodePoints: history, field: 'accelerators', metrics: [{ key: 'utilization_percent', label: 'GPU' }] });
  assert.equal(chart.series.length, 2, 'inventory-only devices must not create empty curves');
  assert.notEqual(chart.series[0].key, chart.series[1].key);
  assert.equal(chart.points[0][chart.series[0].key], 0);
  assert.equal(chart.points[0][chart.series[1].key], 45);
  assert.equal(acceleratorReading(history.a[0].accelerators[0], 'memory_used_bytes'), 0);
  assert.equal(acceleratorReading(history.a[0].accelerators[2], 'utilization_percent'), null);
});

test('DRM and NVIDIA PCI bus notations retain one GPU curve across upgrades', async () => {
  const { buildDeviceChart } = await metric;
  const chart = buildDeviceChart({ nodePoints: { a: [
    { timestamp: time(0), accelerators: [{ name: 'A30', index: 0, bus_id: '00000000:3B:00.0', utilization_percent: 0 }] },
    { timestamp: time(5), accelerators: [{ name: 'A30', index: 1, bus_id: '0000:3b:00.0', utilization_percent: 10 }] },
  ] }, field: 'accelerators', metrics: [{ key: 'utilization_percent', label: 'GPU' }] });
  assert.equal(chart.series.length, 1);
  assert.deepEqual(Array.from(chart.points, point => point[chart.series[0].key]), [0, 10]);
});

test('separate nodes and devices, align sampling buckets, and preserve genuine zero', async () => {
  const { buildDeviceChart } = await metric;
  const result = buildDeviceChart({
    nodePoints: {
      a: [{ timestamp: time(0), disk_devices: [{ name: 'vda', io_utilization_percent: 0 }, { name: 'vdb', io_utilization_percent: 0.267 }] },
        { timestamp: time(5), disk_devices: [{ name: 'vda', io_utilization_percent: 0.14 }] }],
      b: [{ timestamp: time(0.2), disk_devices: [{ name: 'vda', io_utilization_percent: 0.45 }] }],
    }, nodes: [{ node_id: 'a', name: 'fron' }, { node_id: 'b', name: 'zstack' }],
    field: 'disk_devices', metrics: [{ key: 'io_utilization_percent', label: 'I/O%' }],
  });
  assert.equal(result.series.length, 3);
  assert.equal(new Set(result.series.map(item => item.key)).size, 3);
  const first = result.series.find(item => item.nodeID === 'a' && item.device === 'vda');
  const removed = result.series.find(item => item.nodeID === 'a' && item.device === 'vdb');
  assert.equal(result.points[0][first.key], 0);
  assert.equal(result.points[1][removed.key], null);
  assert.equal(result.points.length, 2);
});

test('hotplug baseline is unknown while older agents without readiness remain compatible', async () => {
  const { buildDeviceChart } = await metric;
  const result = buildDeviceChart({ nodePoints: { a: [
    { timestamp: time(0), logical_cpus: [{ name: 'cpu0', usage_percent: 0, sample_ready: false }] },
    { timestamp: time(5), logical_cpus: [{ name: 'cpu0', usage_percent: 0, sample_ready: true }] },
    { timestamp: time(10), logical_cpus: [{ name: 'cpu0', usage_percent: 4 }] },
  ] }, field: 'logical_cpus', metrics: [{ key: 'usage_percent', label: 'CPU' }] });
  const key = result.series[0].key;
  assert.equal(result.points[0][key], null);
  assert.equal(result.points[1][key], 0);
  assert.equal(result.points[2][key], 4);
});

test('curve identity and colors survive changed node order and scope', async () => {
  const { buildDeviceChart } = await metric;
  const nodePoints = { b: [{ timestamp: time(0), network_interfaces: [{ name: 'eth0', rx_bytes_per_second: 200 }] }],
    a: [{ timestamp: time(0), network_interfaces: [{ name: 'eth0', rx_bytes_per_second: 100 }] }] };
  const options = { nodePoints, field: 'network_interfaces', metrics: [{ key: 'rx_bytes_per_second', label: 'RX' }] };
  const all = buildDeviceChart(options);
  const single = buildDeviceChart({ ...options, nodePoints: { a: nodePoints.a }, includeNode: false });
  const a = all.series.find(item => item.nodeID === 'a');
  assert.equal(single.series[0].key, a.key);
  assert.equal(single.series[0].color, a.color);
  assert.equal(single.series[0].label, 'eth0 · RX');
});

test('latest sample wins within a bucket and filesystems have stable mount identities', async () => {
  const { buildDeviceChart } = await metric;
  const result = buildDeviceChart({ nodePoints: { a: [
    { timestamp: time(1), filesystems: [{ mountpoint: '/', used_percent: 25 }] },
    { timestamp: time(0), filesystems: [{ mountpoint: '/', used_percent: 20 }] },
  ] }, field: 'filesystems', metrics: [{ key: 'used_percent', label: 'Usage' }] });
  assert.equal(result.points.length, 1);
  assert.equal(result.points[0][result.series[0].key], 25);
});

test('opposite directions of one device use distinct stable colors', async () => {
  const { buildDeviceChart } = await metric;
  const options = { nodePoints: { a: [{ timestamp: time(0), network_interfaces: [{ name: 'em1', rx_bytes_per_second: 10, tx_bytes_per_second: 20 }] }] },
    field: 'network_interfaces', metrics: [{ key: 'rx_bytes_per_second', label: 'RX' }, { key: 'tx_bytes_per_second', label: 'TX' }] };
  const all = buildDeviceChart(options);
  const selected = buildDeviceChart({ ...options, includeNode: false });
  assert.notEqual(all.series[0].color, all.series[1].color);
  for (const series of all.series) assert.equal(selected.series.find(item => item.key === series.key).color, series.color);
});

test('tooltip formatting retains useful precision without raw float tails', async () => {
  const { formatMetric, metricStatistics, niceMetricMax, nearestTimeIndex } = await metric;
  assert.equal(formatMetric(0.26749), '0.267%');
  assert.equal(formatMetric(0), '0%');
  assert.equal(formatMetric(null), '—');
  assert.equal(formatMetric(343374, 'count'), '343,374');
  assert.equal(formatMetric(1024, 'rate'), '1 KiB/s');
  const stats = metricStatistics([{ v: 0 }, { v: null }, { v: 0.267 }], 'v');
  assert.equal(stats.last, 0.267); assert.equal(stats.max, 0.267); assert.equal(stats.mean, 0.1335);
  assert.ok(niceMetricMax(0.267) < 1);
  assert.equal(nearestTimeIndex([0, 5, 10], 6), 1);
});

test('bridge IPv4 keeps its full bridge name and unrelated NICs keep their own address', async () => {
  const { interfaceAddressLabel } = await load('interfaces.js');
  const port = { name: 'em1', addresses: ['fe80::1/64'], address_interface: 'br_em1', related_addresses: ['fe80::2/64', '192.168.2.168/24'] };
  assert.equal(interfaceAddressLabel(port), '192.168.2.168/24 (br_em1)');
  assert.equal(interfaceAddressLabel({ ...port, addresses: ['10.0.0.1/24'] }), '10.0.0.1/24');
  assert.equal(interfaceAddressLabel({ addresses: ['2001:db8:1234:5678:90ab:cdef:1234:5678/128'] }), '2001:db8:1234:5678:90ab:cdef:1234:5678/128');
  assert.equal(interfaceAddressLabel({ name: 'em2' }), '—');
});
