// Run with: node --experimental-vm-modules web/tests/console-loading.test.cjs
// The composable is exercised without bundling or generating frontend assets.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function loadConsole(hash, request, options = {}) {
  const window = {
    location: { hash, search: "" },
    addEventListener() {},
    setTimeout,
    clearTimeout,
    ...(options.window || {}),
  };
  const context = vm.createContext({ window, URLSearchParams, setTimeout, clearTimeout, Date, console });
  const eventIDsModule = new vm.SourceTextModule(fs.readFileSync(path.join(__dirname, "../src/lib/eventIds.js"), "utf8"), { context });
  await eventIDsModule.link(() => { throw new Error("event IDs must remain a pure module"); });
  const firewallLogsModule = new vm.SourceTextModule(fs.readFileSync(path.join(__dirname, "../src/lib/firewallLogs.js"), "utf8"), { context });
  await firewallLogsModule.link(() => { throw new Error("firewall logs must remain a pure module"); });
  const eventRecordsModule = new vm.SourceTextModule(fs.readFileSync(path.join(__dirname, "../src/lib/eventRecords.js"), "utf8"), { context });
  await eventRecordsModule.link((specifier) => specifier === "./firewallLogs" ? firewallLogsModule : eventIDsModule);
  const source = fs.readFileSync(path.join(__dirname, "../src/composables/useNodewallConsole.js"), "utf8");
  const module = new vm.SourceTextModule(source, { context });
  await module.link((specifier) => {
    if (specifier === "vue") {
      return new vm.SyntheticModule(["computed", "reactive", "ref"], function () {
        this.setExport("computed", (get) => ({ get value() { return get(); } }));
        this.setExport("reactive", (value) => value);
        this.setExport("ref", (value) => ({ value }));
      }, { context });
    }
    if (specifier === "@/lib/api") {
      return new vm.SyntheticModule(["request", "downloadFile", "withDirection"], function () {
        this.setExport("request", request);
        this.setExport("downloadFile", async () => ({}));
        this.setExport("withDirection", (url, direction) => `${url}?direction=${direction}`);
      }, { context });
    }
    if (specifier === "@/lib/eventIds") return eventIDsModule;
    if (specifier === "@/lib/eventRecords") return eventRecordsModule;
    if (specifier === "@/lib/firewallLogs") return firewallLogsModule;
    throw new Error(`unexpected import: ${specifier}`);
  });
  await module.evaluate();
  return module.namespace.useNodewallConsole({ t: (key) => key });
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 25));

test("aggregate and unspecified sources cannot create a misleading per-IP action", async () => {
  const calls=[];
  const store=await loadConsole("#events",async (...args)=>{calls.push(args);return {};});
  for(const row of [{source_ip:'',source_cidr:'0.0.0.0/0'},{source_ip:'0.0.0.0',reason:'dhcp_broadcast'}]) {
    store.toggleLogSelection(row);
    assert.equal(store.state.selection.size,0);
    await assert.rejects(store.runLogAction('allow',row),/firewallSourceActionUnavailable/);
  }
  assert.equal(calls.length,0);
  const row={source_ip:'10.42.120.76',interface:'eth0'};
  store.toggleLogSelection(row);
  assert.equal(store.state.selection.size,1);
  store.toggleLogSelection(row);
  assert.equal(store.state.selection.size,0);
  store.dispose();
});

function eventStreamHarness() {
  const sources = [];
  class EventSource {
    constructor(url) { this.url = url; this.listeners = {}; sources.push(this); }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
    emit(name, payload) { this.listeners[name]?.({ data: JSON.stringify(payload) }); }
  }
  const snapshot = {
    scope: "cluster", revision: 1, logs: [],
    nodes: ["a", "b"].map(node_id => ({ node_id, ssh_activity: [{ at: "2026-11-17T10:00:00Z", action: "failed" }],
      scans: [{ id: "same-scan-id", status: "completed", finished_at: "2026-11-17T10:00:00Z", findings_count: 2 }] })),
  };
  const request = async url => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "a" };
    if (url === "/nodes") return { nodes: [{ id: "a" }, { id: "b" }] };
    if (url === "/events/snapshot") return snapshot;
    return {};
  };
  return { EventSource, sources, snapshot, request };
}

test("overview node switches resolve the returned NIC and independent health, rejecting old streams", async () => {
  const h = eventStreamHarness();
  const store = await loadConsole("#overview", async url => {
    if (url.endsWith('/interfaces')) return { recommended: 'ens3', interfaces: [{ name: 'ens3' }] };
    return h.request(url);
  }, { window: { EventSource: h.EventSource } });
  await store.bootstrap();
  const old = h.sources.at(-1);
  await store.setNode('b');
  const next = h.sources.at(-1);
  next.emit('overview_data', { node_id: 'b', interface: 'eth9', revision: 4, direction: 'ingress', interface_status: 'ready', reachable: true,
    health: { node_id: 'b', status: 'ok', interfaces: [{ interface: 'eth9', xdp_attached: true, policy_enforced: true }] },
    current: { policy: { node_id: 'b', interface: 'eth9', ingress: { rules: [{ cidr: '10.0.0.0/8' }] } }, health: { interfaces: [] } } });
  assert.equal(store.currentInterface.value, 'eth9');
  assert.equal(store.state.interfaceDataStatus, 'ready');
  assert.equal(store.state.health.interfaces[0].policy_enforced, true);
  assert.equal(store.state.policy.node_id, 'b');
  old.emit('overview_data', { node_id: 'a', interface: 'ens3', current: { policy: { node_id: 'a' } } });
  assert.equal(store.currentInterface.value, 'eth9');
  const current = h.sources.at(-1);
  current.emit('overview_data', { node_id: 'b', interface: 'eth9', revision: 8, health: store.state.health });
  current.emit('overview_data', { node_id: 'b', interface: 'eth9', revision: 7, health: { interfaces: [] } });
  assert.equal(store.state.health.interfaces[0].policy_enforced, true);
  current.emit('overview_data', { node_id: 'b', interface: 'eth9', revision: 9, interface_status: 'unavailable', reachable: false,
    health: { node_id: 'b', status: 'unavailable', interfaces: [] } });
  assert.equal(store.state.interfaceDataStatus, 'unavailable');
  assert.equal(store.state.health.status, 'unavailable');
  store.dispose();
});

test("security health and resolved NIC survive a partial summary without inventory", async () => {
  const h = eventStreamHarness();
  const store = await loadConsole('#firewall', h.request, { window: { EventSource: h.EventSource } });
  await store.bootstrap();
  h.sources.at(-1).emit('security', { nodes: [{ node_id: 'a', interface: 'eno3',
    health: { node_id: 'a', status: 'ok', interfaces: [{ interface: 'eno3', xdp_attached: true, policy_enforced: true }] },
    current: { policy: { node_id: 'a', interface: 'eno3' }, health: { interfaces: [] } } }] });
  assert.equal(store.currentInterface.value, 'eno3');
  assert.equal(store.state.interfaces[0].name, 'eno3');
  assert.equal(store.state.health.interfaces[0].policy_enforced, true);
  assert.equal(store.state.interfaceDataStatus, 'ready');
  h.sources.at(-1).emit('security', { nodes: [{ node_id: 'a', status: 'offline' }] });
  assert.equal(store.state.health.status, 'unavailable');
  assert.equal(store.state.health.interfaces.length, 0);
  store.dispose();
});

test("event subscriptions and badge use all nodes regardless of the security node/feature/direction", async () => {
  const h = eventStreamHarness();
  const store = await loadConsole("#events", h.request, { window: { EventSource: h.EventSource } });
  await store.bootstrap();
  const source = h.sources.at(-1);
  const query = new URLSearchParams(source.url.split("?")[1]);
  assert.equal(query.get("section"), "events");
  for (const key of ["node", "iface", "direction", "feature"]) assert.equal(query.has(key), false);
  assert.equal(store.state.eventCenter.nodes.length, 2);
  assert.equal(store.pendingEventCount.value, 4);
  await store.setNode("b");
  store.state.securitySummary.scan = { status: "completed", findings: new Array(50).fill({}), node_id: "b" };
  store.state.sshProtection.activity = [];
  store.state.direction = "egress";
  assert.equal(store.pendingEventCount.value, 4);
  assert.equal(h.sources.length, 1);
  assert.notEqual(source.closed, true);
  source.emit("events", { ...h.snapshot, revision: 2, nodes: h.snapshot.nodes.map(node => ({ ...node, scans: [...node.scans,
    { id: "another-scan", status: "completed", findings_count: 3, finished_at: "2026-11-17T11:00:00Z" }] })) });
  assert.equal(store.pendingEventCount.value, 6);
  store.dispose();
});

test("other sidebar pages receive cluster events and reload restores the event center", async () => {
  const h = eventStreamHarness();
  const saved = new Map();
  const sessionStorage = { getItem: key => saved.get(key), setItem: (key, value) => saved.set(key, value) };
  const store = await loadConsole("#cluster", h.request, { window: { EventSource: h.EventSource, sessionStorage } });
  await store.bootstrap();
  assert.equal(store.pendingEventCount.value, 4);
  const source = h.sources.at(-1);
  assert.equal(new URL(source.url, "https://nodewall.test").searchParams.get("event_feed"), "1");
  source.emit("events", { ...h.snapshot, revision: 3, nodes: h.snapshot.nodes.map(node => ({ ...node, scans: [] })) });
  assert.equal(store.pendingEventCount.value, 2);
  store.setSection("events");
  store.dispose();

  const reloaded = await loadConsole("", h.request, { window: { EventSource: h.EventSource, sessionStorage, location: { hash: "", search: "?node=b" } } });
  await reloaded.bootstrap();
  assert.equal(reloaded.state.section, "events");
  assert.equal(reloaded.state.nodeId, "b");
  assert.equal(reloaded.state.eventCenter.nodes.length, 2);
  reloaded.dispose();
});

test("overview refresh applies independent firewall health while event history is still loading", async () => {
  const h = eventStreamHarness();
  const events = deferred();
  let overviewReads = 0;
  const store = await loadConsole("#overview", async url => {
    if (url === "/events/snapshot") return events.promise;
    if (url.startsWith("/overview/snapshot?")) {
      overviewReads++;
      return { node_id: "b", direction: "ingress", interface: "eth9", reachable: true,
        interface_status: "unavailable", protection_status: "enforced",
        health: { node_id: "b", status: "ok", interfaces: [{ interface: "eth9", xdp_attached: true, policy_enforced: true }] } };
    }
    return h.request(url);
  }, { window: { EventSource: h.EventSource, location: { hash: "#overview", search: "?node=b" } } });
  const starting = store.bootstrap();
  await tick();
  assert.equal(overviewReads, 1);
  assert.equal(store.state.overviewProtectionStatus, "enforced");
  assert.equal(store.currentInterface.value, "eth9");
  assert.equal(store.state.eventCenter.ready, false);
  assert.equal(h.sources.length, 1);
  events.resolve(h.snapshot);
  await starting;
  assert.equal(store.state.eventCenter.nodes.length, 2);
  store.dispose();
});

test("monitoring range switches clear old custom parameters and reject the previous scope's response", async () => {
  const h = eventStreamHarness();
  const delayed = deferred();
  const requests = [];
  const history = (scope, node, cpu) => ({ scope, node_id: node, points: [{ cpu_percent: cpu }], nodes: [], sample_interval_seconds: 15 });
  const store = await loadConsole("#monitoring", async url => {
    if (!url.startsWith("/monitoring/history?")) return h.request(url);
    const query = new URL(url, "https://nodewall.test").searchParams;
    requests.push(query);
    if (query.has("from")) return delayed.promise;
    return query.has("node") ? history("node", query.get("node"), 40) : history("cluster", "", 20);
  }, { window: { EventSource: h.EventSource } });
  await store.bootstrap();
  assert.equal(store.state.monitoringHistory.scope, "cluster");
  store.setMonitoringStreamQuery({ node: "b", range: 604800, from: "2026-11-17T00:00:00Z", to: "2026-11-17T00:15:00Z" });
  await tick();
  const previousStream = h.sources.at(-1);
  assert.ok(requests.at(-1).has("from"));
  store.setMonitoringStreamQuery({ node: "b", range: 900 });
  await tick();
  assert.equal(requests.at(-1).has("from"), false);
  assert.equal(requests.at(-1).has("to"), false);
  assert.equal(store.state.monitoringHistory.points[0].cpu_percent, 40);
  delayed.resolve(history("node", "b", 10));
  previousStream.emit("monitoring", history("node", "b", 1));
  await tick();
  assert.equal(store.state.monitoringHistory.points[0].cpu_percent, 40);
  await store.setNode("b");
  assert.equal(store.state.monitoringStreamQuery.node, "b");
  store.dispose();
});

test("event SSE does not overwrite security forms and old HTTP cannot undo the live history", async () => {
  const h = eventStreamHarness();
  const pending = deferred();
  const store = await loadConsole("#events", url => url === "/events/snapshot" ? pending.promise : h.request(url), { window: { EventSource: h.EventSource } });
  const bootstrap = store.bootstrap();
  await tick();
  const security = store.state.securitySummary;
  const ssh = store.state.sshProtection;
  h.sources.at(-1).emit("events", { ...h.snapshot, revision: 5 });
  pending.resolve({ ...h.snapshot, revision: 1, nodes: [] });
  await bootstrap;
  assert.equal(store.state.eventCenter.nodes.length, 2);
  assert.equal(store.state.securitySummary, security);
  assert.equal(store.state.sshProtection, ssh);
  const source = h.sources.at(-1);
  store.setSection("security");
  source.emit("events", { ...h.snapshot, revision: 6, nodes: [] });
  assert.equal(store.state.eventCenter.nodes.length, 2);
  assert.equal(source.closed, true);
  store.dispose();
});

test("protection overview accepts the cluster event snapshot independently of the selected host", async () => {
  const h = eventStreamHarness();
  const store = await loadConsole("#security", h.request, { window: { EventSource: h.EventSource } });
  await store.bootstrap();
  const overview = h.sources.at(-1);
  overview.emit("security", {
    feature: "overview", revision: 5, node_id: "a", nodes: [{ node_id: "a" }],
    events: { ...h.snapshot, revision: 5 },
  });
  assert.equal(store.state.eventCenter.nodes.length, 2);
  assert.equal(store.pendingEventCount.value, 4);
  store.setSecurityFeature("ssh");
  overview.emit("security", { feature: "overview", revision: 6, events: { ...h.snapshot, revision: 6, nodes: [] } });
  assert.equal(overview.closed, true);
  assert.equal(store.state.eventCenter.nodes.length, 2);
  store.dispose();
});

test("protection overview renders an empty SSH block list from the Agent", async () => {
  const h = eventStreamHarness();
  const store = await loadConsole("#security", h.request, { window: { EventSource: h.EventSource } });
  await store.bootstrap();
  const source = h.sources.at(-1);
  const publish = (revision, ssh) => source.emit("security", {
    feature: "overview", revision, nodes: [{ node_id: "a", ssh }],
  });
  publish(1, { settings: { enabled: true }, active_blocks: [{ id: "block-1" }] });
  assert.equal(store.state.sshProtection.active_blocks.length, 1);
  publish(2, { tracked_sources: 0 });
  assert.equal(store.state.sshProtection.active_blocks.length, 1);
  publish(3, { active_blocks: null });
  assert.equal(store.state.sshProtection.active_blocks.length, 0);
  assert.equal(store.state.sshProtection.settings.enabled, true);
  store.dispose();
});

test("failed event dispositions leave both the pending rows and badge intact", async () => {
  const h = eventStreamHarness();
  const eventID = "scan-a-same-scan-id";
  let failure;
  const store = await loadConsole("#events", async (url) => {
    if (url === "/events/dispositions") return { dispositions: [] };
    if (url.startsWith("/events/dispositions/")) throw failure;
    return h.request(url);
  });
  await store.bootstrap();
  for (const [status, message] of [[503, "network unavailable"], [403, "forbidden"], [404, "node not found"]]) {
    failure = Object.assign(new Error(message), { status });
    await assert.rejects(store.updateEventDisposition(eventID, "a", "malware", "handled"), { message });
    assert.equal(store.eventRows.value.find((row) => row.id === eventID).status, "pending");
    assert.equal(store.pendingEventCount.value, 4);
  }
  store.dispose();
});

test("legacy dispositions are shared with the badge until the server supplies authoritative state", async () => {
  const h = eventStreamHarness();
  const key = "nodewall-event-status";
  const saved = new Map([[key, JSON.stringify([["scan-a-same-scan-id", "handled"]])]]);
  const localStorage = { getItem: (key) => saved.get(key), setItem: (key, value) => saved.set(key, value) };
  const eventID = "scan-b-same-scan-id";
  let upgraded = false;
  const store = await loadConsole("#events", async (url) => {
    if (url === "/events/dispositions" && upgraded) {
      return { dispositions: [{ event_id: eventID, node_id: "b", status: "deferred" }] };
    }
    if (url.startsWith("/events/dispositions")) throw Object.assign(new Error("endpoint missing"), { status: 404 });
    return h.request(url);
  }, { window: { localStorage } });
  await store.bootstrap();
  assert.equal(store.eventRows.value.find((row) => row.id === "scan-a-same-scan-id").status, "handled");
  assert.equal(store.pendingEventCount.value, 3);
  await store.updateEventDisposition(eventID, "b", "malware", "handled");
  assert.equal(store.eventRows.value.find((row) => row.id === eventID).status, "handled");
  assert.equal(store.pendingEventCount.value, 2);
  assert.equal(new Map(JSON.parse(saved.get(key))).get(eventID), "handled");

  upgraded = true;
  await store.refreshEventDispositions();
  assert.equal(store.eventRows.value.find((row) => row.id === eventID).status, "deferred");
  assert.equal(store.pendingEventCount.value, 3);
  store.dispose();
});

function firewallPolicy(node = "a", iface = "ens3", ports = [8080], updatedAt = "2026-11-17T10:00:00Z") {
  return {
    node_id: node, interface: iface, updated_at: updatedAt,
    ingress: { rules: [{ cidr: "192.0.2.1/32" }], public_port_rules: ports.flatMap(port => [{ port, protocol: "tcp" }, { port, protocol: "udp" }]) },
    egress: { rules: [] },
  };
}

test("firewall scope changes use HTTP when no live stream is available", async () => {
  const requests = [];
  const store = await loadConsole("#firewall", async url => {
    requests.push(url);
    if (url === "/bootstrap") return { node_id: "a", default_interface: "ens3" };
    if (url === "/nodes") return [{ id: "a" }];
    if (url.endsWith("/interfaces")) return { recommended: "ens3", interfaces: [{ name: "ens3" }, { name: "eth9" }] };
    if (url.includes("/summary")) {
      const iface = url.split("/")[4];
      return { policy: firewallPolicy("a", iface), health: { interfaces: [{ interface: iface }] } };
    }
    return {};
  });
  await store.bootstrap();
  store.setInterface("eth9");
  await tick();
  store.setDirection("egress");
  await tick();
  assert.ok(requests.includes("/nodes/a/interfaces/eth9/summary?direction=ingress"));
  assert.ok(requests.includes("/nodes/a/interfaces/eth9/summary?direction=egress"));
  assert.equal(store.state.direction, "egress");
  assert.equal(store.state.policy.interface, "eth9");
  store.dispose();
});

test("an explicit firewall NIC keeps its rules across stale and mismatched updates", async () => {
  const h = eventStreamHarness();
  const inventory = { recommended: "em1", interfaces: [{ name: "em1" }, { name: "em2" }] };
  const health = { node_id: "a", status: "ok", interfaces: [{ interface: "em1", policy_enforced: true }] };
  const em2HTTP = deferred();
  const em1Policy = firewallPolicy("a", "em1");
  em1Policy.egress.rules = [{ cidr: "192.0.2.22/32" }];
  const em2Policy = firewallPolicy("a", "em2", []);
  const store = await loadConsole("#firewall", async (url) => {
    if (url.endsWith("/interfaces")) return inventory;
    if (url.includes("/interfaces/em1/summary")) return { policy: em1Policy, health };
    if (url.includes("/interfaces/em2/summary")) return em2HTTP.promise;
    return h.request(url);
  }, { window: { EventSource: h.EventSource } });
  await store.bootstrap();
  store.setDirection("egress");
  const em1Stream = h.sources.at(-1);
  const em1Frame = { node_id: "a", interface: "em1", inventory, current: { policy: em1Policy, health } };
  em1Stream.emit("security", { nodes: [em1Frame] });
  assert.equal(store.state.allowlist[0], "192.0.2.22/32");

  store.setInterface("em2");
  const em2Stream = h.sources.at(-1);
  const params = new URL(em2Stream.url, "https://nodewall.test").searchParams;
  assert.equal(params.get("iface"), "em2");
  assert.equal(params.get("direction"), "egress");
  assert.equal(em1Stream.closed, true);
  assert.equal(store.currentInterface.value, "em2");
  assert.equal(store.currentPolicy.value, null);
  assert.equal(store.state.allowlist.length, 0);

  em1Stream.emit("security", { nodes: [em1Frame] });
  em2Stream.emit("security", { nodes: [em1Frame] });
  em2Stream.emit("security", { nodes: [{ ...em1Frame, interface: "em2" }] });
  assert.equal(store.currentInterface.value, "em2");
  assert.equal(store.currentPolicy.value, null);
  assert.equal(store.state.interfaceDataStatus, "loading");

  em2Stream.emit("security", { nodes: [{ node_id: "a", interface: "em2", inventory, current: { policy: em2Policy, health } }] });
  assert.equal(store.currentPolicy.value.interface, "em2");
  assert.equal(store.state.interfaceDataStatus, "ready");
  assert.equal(store.state.direction, "egress");
  assert.equal(store.state.allowlist.length, 0);

  // An HTTP request from this selection can still finish after the user has
  // switched back. No em2 data should replace the now visible em1 policy.
  store.setInterface("em1");
  h.sources.at(-1).emit("security", { nodes: [em1Frame] });
  em2HTTP.resolve({ policy: em2Policy, health });
  await tick();
  assert.equal(store.currentInterface.value, "em1");
  assert.equal(store.currentPolicy.value.interface, "em1");
  assert.equal(store.state.allowlist[0], "192.0.2.22/32");
  store.dispose();
});

test("firewall adds render the confirmed policy without waiting for SSE or reloading inventory", async () => {
  const calls = [];
  const policy = firewallPolicy();
  const store = await loadConsole("#firewall", async (url, options = {}) => {
    calls.push({ url, options });
    options.onResponse?.({ headers: { get: () => "12" } });
    return policy;
  });
  Object.assign(store.state, { section: "security", nodeId: "a", selectedInterface: "ens3", interfaceDataStatus: "ready" });
  await store.addPort("public", 8080, "both");
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /\/nodes\/a\/interfaces\/ens3\/public-ports/);
  assert.equal(store.state.publicPortRules.length, 2);
  assert.equal(store.state.publicPortRules[1].protocol, "udp");
  assert.equal(store.state.allowlist[0], "192.0.2.1/32");
  assert.equal(store.state.consoleRevision, 12);
  assert.equal(store.state.policy, policy);
  store.dispose();
});

test("a delayed firewall save cannot replace a different node, NIC, direction, or page", async () => {
  for (const changed of [{ nodeId: "b" }, { selectedInterface: "eth9" }, { direction: "egress" }, { section: "monitoring" }]) {
    const pending = deferred();
    const store = await loadConsole("#firewall", async () => pending.promise);
    Object.assign(store.state, { section: "security", nodeId: "a", selectedInterface: "ens3", policy: firewallPolicy("a", "ens3", []) });
    const save = store.addPort("public", 8080, "tcp");
    const otherPolicy = firewallPolicy("b", "eth9", [9090]);
    Object.assign(store.state, changed, { policy: otherPolicy, publicPortRules: [{ port: 9090, protocol: "tcp" }] });
    pending.resolve(firewallPolicy());
    await save;
    assert.equal(store.state.policy, otherPolicy);
    assert.equal(store.state.publicPortRules[0].port, 9090);
    store.dispose();
  }
});

test("older firewall stream frames cannot undo a confirmed write while newer Web changes still arrive", async () => {
  const sources = [];
  class EventSource {
    constructor() { this.listeners = {}; sources.push(this); }
    addEventListener(name, callback) { this.listeners[name] = callback; }
    close() {}
    emit(payload) { this.listeners.security?.({ data: JSON.stringify(payload) }); }
  }
  const store = await loadConsole("#firewall", async (url, options = {}) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "a", default_interface: "ens3" };
    if (url === "/nodes") return { nodes: [{ id: "a" }] };
    if (url.endsWith("/interfaces")) return { recommended: "ens3", interfaces: [{ name: "ens3" }] };
    if (options.method === "POST") {
      options.onResponse?.({ headers: { get: () => "12" } });
      return firewallPolicy();
    }
    return {};
  }, { window: { EventSource } });
  await store.bootstrap();
  store.state.selectedInterface = "ens3";
  const frame = (revision, ports, time) => ({ revision, nodes: [{ node_id: "a", current: { policy: firewallPolicy("a", "ens3", ports, time) } }] });
  await store.addPort("public", 8080, "both");
  sources.at(-1).emit(frame(11, [], "2026-11-17T09:00:00Z"));
  assert.equal(store.state.publicPortRules.length, 2);
  sources.at(-1).emit(frame(13, [9090], "2026-11-17T11:00:00Z"));
  assert.equal(store.state.publicPortRules[0].port, 9090);
  // Legacy summaries can lack a revision, but their policy timestamp still
  // must not overwrite a newer confirmed policy.
  sources.at(-1).emit(frame(undefined, [], "2026-11-17T08:00:00Z"));
  assert.equal(store.state.publicPortRules[0].port, 9090);
  store.dispose();
});

test("multi-node rule adds use each target NIC and retry only failures without copying other rules", async () => {
  const calls = [];
  let failWorker = true;
  const store = await loadConsole("#firewall", async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body), method: options.method });
    if (url.includes("/b/") && failWorker) throw new Error("agent unavailable");
    const worker = url.includes("/b/");
    return firewallPolicy(worker ? "b" : "a", worker ? "eth1" : "ens3");
  });
  Object.assign(store.state, { section: "security", nodeId: "a", selectedInterface: "ens3" });
  const rule = { kind: "public", targetValue: 8080, protocol: "tcp" };
  const targets = [{ nodeID: "a", interface: "ens3", direction: "ingress" }, { nodeID: "b", interface: "eth1", direction: "egress" }];
  const results = await store.addRuleToNodes(rule, targets);
  assert.deepEqual(Array.from(results, item => item.status), ["success", "failed"]);
  assert.equal(store.state.policy.node_id, "a");
  assert.ok(calls[0].url.includes("/a/interfaces/ens3/public-ports"));
  assert.ok(calls[1].url.includes("/b/interfaces/eth1/public-ports"));
  assert.ok(calls[1].url.includes("direction=egress"));
  assert.deepEqual(calls[0].body, { port: 8080, protocol: "tcp" });
  assert.equal(calls.some(call => call.url === "/policy/copy"), false);
  failWorker = false;
  const retry = await store.addRuleToNodes(rule, results.filter(item => item.status === "failed"));
  assert.equal(retry[0].status, "success");
  assert.equal(calls.length, 3);
  assert.ok(calls[2].url.includes("/b/interfaces/eth1/"));
  assert.equal(store.state.policy.node_id, "a");
  store.dispose();
});

test("cancelled multi-node confirmation leaves unsubmitted nodes visible as failures", async () => {
  let calls = 0;
  const store = await loadConsole("#firewall", async () => {
    calls++;
    throw Object.assign(new Error("cancelled"), { code: "ABORTED" });
  });
  const results = await store.addRuleToNodes({ kind: "public", targetValue: 8080, protocol: "tcp" },
    [{ nodeID: "a", interface: "ens3" }, { nodeID: "b", interface: "eth1" }]);
  assert.equal(calls, 1);
  assert.equal(results.length, 2);
  assert.equal(results[1].status, "failed");
  store.dispose();
});

test("rule edits preserve the policy version and update all displayed rule families atomically", async () => {
  let payload;
  const updated = firewallPolicy("a", "ens3", [9090]);
  const store = await loadConsole("#firewall", async (_url, options) => {
    payload = JSON.parse(options.body);
    return updated;
  });
  const previous = firewallPolicy();
  Object.assign(store.state, { section: "security", nodeId: "a", selectedInterface: "ens3", policy: previous });
  await store.updateRule({ kind: "public", value: 8080, portProtocol: "tcp" }, { kind: "public", targetValue: 9090, protocol: "tcp" });
  assert.equal(payload.policy.updated_at, previous.updated_at);
  assert.equal(store.state.publicPortRules[0].port, 9090);
  assert.equal(store.state.allowlist[0], "192.0.2.1/32");
  store.dispose();
});

test("a failed description preserves the saved rule and reports retryable partial success", async () => {
  const calls = [];
  const store = await loadConsole("#firewall", async (url, options) => {
    calls.push({ url, options });
    if (url.includes("rule-description")) throw new Error("description service unavailable");
    return firewallPolicy();
  });
  Object.assign(store.state, { section: "security", nodeId: "a", selectedInterface: "ens3" });
  const results = await store.addRuleToNodes({ kind: "public", targetValue: 8080, protocol: "tcp", description: "test" }, [{ nodeID: "a", interface: "ens3" }]);
  assert.equal(results[0].status, "failed");
  assert.equal(results[0].ruleSaved, true);
  assert.equal(store.state.publicPortRules[0].port, 8080);
  assert.equal(calls.length, 2);
  store.dispose();
});

test("Webs agree on heartbeat presence when only one Web loses its Agent path", async () => {
  const node = { id: "target", last_seen_at: new Date().toISOString() };
  const makeWeb = (connected) => loadConsole("#cluster", async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id };
    if (url === "/nodes") return { nodes: [node] };
    if (url === "/nodes/target/protection-status") return {
      node_id: node.id, node_status: "online", checked_at: new Date().toISOString(),
      connection_status: connected ? "reachable" : "unreachable",
      protection_status: connected ? "enforced" : "unavailable",
      reason: connected ? "" : "host firewall blocks this Web",
    };
    return {};
  });
  const [first, second] = await Promise.all([makeWeb(true), makeWeb(false)]);
  await Promise.all([first.bootstrap(), second.bootstrap()]);
  await tick();
  assert.equal(first.isNodeOnline(node), true);
  assert.equal(second.isNodeOnline(node), true);
  assert.equal(first.state.nodeReachability.target, true);
  assert.equal(second.state.nodeReachability.target, false);
  assert.equal(second.state.nodeProtection.target.protection_status, "unavailable");
  assert.match(second.state.nodeProtection.target.reason, /host firewall/);
  first.dispose(); second.dispose();
});

test("a newer heartbeat supersedes an older offline snapshot without inventing protection", async () => {
  const store = await loadConsole("#cluster", async () => ({}));
  const checked = new Date(Date.now() - 10000).toISOString();
  const node = { id: "target", last_seen_at: checked };
  store.state.nodeReachability.target = false;
  store.state.nodeProtection.target = { node_status: "offline", checked_at: checked, protection_status: "unavailable" };
  assert.equal(store.isNodeOnline(node), false);
  assert.equal(store.isNodeOnline({ ...node, last_seen_at: new Date().toISOString() }), true);
  assert.equal(store.state.nodeProtection.target.protection_status, "unavailable");
  delete store.state.nodeProtection.target.checked_at;
  assert.equal(store.isNodeOnline(node), false);
  store.dispose();
});

test("slow version metadata does not delay the application shell", async () => {
  const version = deferred();
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "node-a" };
    if (url === "/version") return version.promise;
    if (url === "/nodes") return { nodes: [] };
    return {};
  };
  const store = await loadConsole("#cluster", request);
  await store.bootstrap();
  assert.equal(store.state.loading, false);
  version.resolve({ package_version: "test-version" });
  await tick();
  assert.equal(store.state.version.package_version, "test-version");
});

test("slow malware scan does not hide the page or block other security data", async () => {
  const scan = deferred();
  const node = { id: "node-a", last_seen_at: new Date().toISOString() };
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id, default_interface: "eth0" };
    if (url === "/nodes") return { nodes: [node] };
    if (url.endsWith("/security/scan")) return scan.promise;
    if (url.endsWith("/security/summary")) return { node_id: node.id, checks: [{ name: "ssh" }] };
    if (url.endsWith("/security/quarantine")) return { node_id: node.id, entries: [{ id: "entry" }] };
    if (url.endsWith("/interfaces")) return { recommended: "eth0", interfaces: [{ name: "eth0", is_physical: true }] };
    if (url.includes("/summary?direction=")) return { health: { interfaces: [{ interface: "eth0", xdp_attached: true }] } };
    if (url.endsWith("/ssh-protection")) return { settings: { enabled: true } };
    return {};
  };
  const store = await loadConsole("#security", request);
  const bootstrap = store.bootstrap();
  await tick();
  assert.equal(store.state.loading, false);
  assert.equal(store.state.securitySummary.checks[0].name, "ssh");
  assert.equal(store.state.securityQuarantine.entries[0].id, "entry");
  assert.equal(store.state.health.interfaces[0].xdp_attached, true);
  assert.equal(store.state.sshProtection.settings.enabled, true);
  scan.resolve({ node_id: node.id, status: "idle" });
  await bootstrap;
});

test("one slow node does not block another node's protection status", async () => {
  const slow = deferred();
  const nodes = ["fast", "slow"].map((id) => ({ id, last_seen_at: new Date().toISOString() }));
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "fast" };
    if (url === "/nodes") return { nodes };
    if (url === "/nodes/fast/protection-status") return { node_id: "fast", protection_status: "enforced" };
    if (url === "/nodes/slow/protection-status") return slow.promise;
    return {};
  };
  const store = await loadConsole("#cluster", request);
  const bootstrap = store.bootstrap();
  await tick();
  assert.equal(store.state.loading, false);
  assert.equal(store.state.nodeProtection.fast.protection_status, "enforced");
  assert.equal(store.state.nodeProtection.slow.protection_status, "loading");
  slow.resolve({ node_id: "slow", protection_status: "not_enabled" });
  await bootstrap;
  assert.equal(store.state.nodeProtection.slow.protection_status, "not_enabled");
});

test("switching nodes does not wait for or display the previous node's response", async () => {
  const previousSummary = deferred();
  const nodes = ["old", "new"].map((id) => ({ id, last_seen_at: new Date().toISOString() }));
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "old", default_interface: "eth0" };
    if (url === "/nodes") return { nodes };
    if (url.endsWith("/interfaces")) return { recommended: "eth0", interfaces: [{ name: "eth0", is_physical: true }] };
    if (url.startsWith("/nodes/old/interfaces/eth0/summary")) return previousSummary.promise;
    if (url.startsWith("/nodes/new/interfaces/eth0/summary")) return { health: { interfaces: [{ interface: "eth0", policy_enforced: true }] } };
    return {};
  };
  const store = await loadConsole("#firewall", request);
  const bootstrap = store.bootstrap();
  await tick();
  await store.setNode("new");
  assert.equal(store.state.nodeId, "new");
  assert.equal(store.state.interfaceDataStatus, "ready");
  assert.equal(store.state.health.interfaces[0].policy_enforced, true);
  previousSummary.resolve({ health: { interfaces: [{ interface: "eth0", policy_enforced: false }] } });
  await bootstrap;
  assert.equal(store.state.health.interfaces[0].policy_enforced, true);
});


test("a stale scan poll cannot overwrite a terminal SSE update", async () => {
  const pending = deferred();
  const sources = [];
  class EventSource {
    constructor() { this.listeners = {}; sources.push(this); }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
    emit(scan) { this.listeners.scan({ data: JSON.stringify(scan) }); }
  }
  const request = async (_url, options = {}) => options.method === "POST"
    ? { node_id: "node-a", status: "running", id: "scan-a" }
    : pending.promise;
  const store = await loadConsole("#security", request, { window: { EventSource, setTimeout() { return 1; }, clearTimeout() {} } });
  store.state.nodeId = "node-a";
  store.state.section = "security";
  store.state.securityFeature = "malware";
  await store.startSecurityScan("/", true, true, "process");
  const poll = store.refreshSecurityScan();
  sources[0].emit({ node_id: "node-a", status: "completed", id: "scan-a" });
  pending.resolve({ node_id: "node-a", status: "running", id: "scan-a" });
  await poll;
  assert.equal(store.state.securitySummary.scan.status, "completed");
  assert.equal(sources[0].closed, true);
});

test("scan polling retries after a temporary request failure", async () => {
  const timers = [];
  let polls = 0;
  const request = async (url, options = {}) => {
    if (options.method === "POST") return { node_id: "node-a", status: "running" };
    if (url.endsWith("/security/quarantine")) return { node_id: "node-a", entries: [] };
    if (++polls === 1) throw new Error("temporary failure");
    return { node_id: "node-a", status: "completed" };
  };
  const store = await loadConsole("#security", request, { window: {
    setTimeout(callback, delay) { if (delay === 1500) timers.push(callback); return timers.length; },
    clearTimeout() {},
  } });
  store.state.nodeId = "node-a";
  store.state.section = "security";
  store.state.securityFeature = "malware";
  await store.startSecurityScan("/", true, true, "process");
  assert.equal(timers.length, 1);
  await timers.shift()();
  assert.equal(timers.length, 1);
  await timers.shift()();
  assert.equal(polls, 2);
  assert.equal(store.state.securitySummary.scan.status, "completed");
});

test("event disposition refresh cannot overwrite a newer local update", async () => {
  const staleRefresh = deferred();
  let dispositionGets = 0;
  const node = { id: "node-a", last_seen_at: new Date().toISOString() };
  const request = async (url, options = {}) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id };
    if (url === "/nodes") return { nodes: [node] };
    if (url === "/events/dispositions") {
      dispositionGets += 1;
      if (dispositionGets === 1) return { dispositions: [] };
      return staleRefresh.promise;
    }
    if (url.startsWith("/events/dispositions/") && options.method === "PUT") {
      return {
        disposition: {
          event_id: "firewall-node-a-event-1",
          node_id: "node-a",
          source: "firewall",
          status: "deferred",
          updated_at: new Date().toISOString(),
        },
      };
    }
    return {};
  };
  const store = await loadConsole("#events", request);
  await store.bootstrap();
  const refreshing = store.refreshEventDispositions();
  await store.updateEventDisposition("firewall-node-a-event-1", "node-a", "firewall", "deferred");
  staleRefresh.resolve({ dispositions: [] });
  await refreshing;
  const key = "node-a\u0000firewall-node-a-event-1";
  assert.equal(store.state.eventDispositions[key].status, "deferred");
});

test("batch disposition writes keep node and event keys isolated", async () => {
  const nodes = ["node-a", "node-b"].map((id) => ({ id, last_seen_at: new Date().toISOString() }));
  const request = async (url, options = {}) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "node-a" };
    if (url === "/nodes") return { nodes };
    if (url === "/events/dispositions") return { dispositions: [] };
    if (url.startsWith("/events/dispositions/") && options.method === "PUT") {
      const eventID = decodeURIComponent(url.slice("/events/dispositions/".length));
      const body = JSON.parse(options.body);
      return { disposition: { event_id: eventID, node_id: body.node_id, source: body.source, status: body.status } };
    }
    return {};
  };
  const store = await loadConsole("#events", request);
  await store.bootstrap();
  await Promise.all([
    store.updateEventDisposition("firewall-node-a-1", "node-a", "firewall", "handled"),
    store.updateEventDisposition("firewall-node-b-1", "node-b", "firewall", "deferred"),
    store.updateEventDisposition("ssh-node-a-2", "node-a", "ssh", "handled"),
  ]);
  assert.equal(store.state.eventDispositions["node-a\u0000firewall-node-a-1"].status, "handled");
  assert.equal(store.state.eventDispositions["node-b\u0000firewall-node-b-1"].status, "deferred");
  assert.equal(store.state.eventDispositions["node-a\u0000ssh-node-a-2"].status, "handled");
});

test("event history remains cluster-wide when the security node changes", async () => {
  const nodes = ["node-a", "node-b"].map(id => ({ id, last_seen_at: new Date().toISOString() }));
  const calls = [];
  const snapshot = { scope: "cluster", logs: [], nodes: nodes.map(node => ({ node_id: node.id, scans: [], ssh_activity: [{ command: node.id }] })) };
  const store = await loadConsole("#events", async url => {
    calls.push(url);
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "node-a" };
    if (url === "/nodes") return { nodes };
    if (url === "/events/snapshot") return snapshot;
    return {};
  });
  await store.bootstrap();
  await store.setNode("node-b");
  assert.equal(store.state.eventCenter.nodes.length, 2);
  assert.equal(store.state.eventCenter.nodes[0].ssh_activity[0].command, "node-a");
  assert.equal(store.state.eventCenter.nodes[1].ssh_activity[0].command, "node-b");
  assert.equal(calls.some(url => url.includes("/ssh-protection")), false);
  assert.equal(store.state.sshProtection.activity.length, 0);
  store.dispose();
});

test("cluster event SSE updates every browser store", async () => {
  const sources = [];
  class EventSource {
    constructor() {
      this.listeners = {};
      sources.push(this);
    }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
    emit(name, payload) { this.listeners[name]?.({ data: JSON.stringify(payload) }); }
  }
  const node = { id: "node-a", last_seen_at: new Date().toISOString() };
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id };
    if (url === "/nodes") return { nodes: [node] };
    if (url === "/events/dispositions") return { dispositions: [] };
    return {};
  };
  const first = await loadConsole("#events", request, { window: { EventSource } });
  const second = await loadConsole("#events", request, { window: { EventSource } });
  await first.bootstrap();
  await second.bootstrap();
  const payload = [{
    event_id: "firewall-node-a-event-2",
    node_id: "node-a",
    source: "firewall",
    status: "handled",
    updated_at: new Date().toISOString(),
  }];
  sources.forEach((source) => source.emit("event_dispositions", payload));
  const key = "node-a\u0000firewall-node-a-event-2";
  assert.equal(first.state.eventDispositions[key].status, "handled");
  assert.equal(second.state.eventDispositions[key].status, "handled");
});

test("management settings SSE keeps multiple browser stores synchronized", async () => {
  const sources = [];
  class EventSource {
    constructor() {
      this.listeners = {};
      sources.push(this);
    }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
    emit(name, payload) { this.listeners[name]?.({ data: JSON.stringify(payload) }); }
  }
  const node = { id: "node-a", last_seen_at: new Date().toISOString() };
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id };
    if (url === "/nodes") return { nodes: [node] };
    if (url === "/settings/auth") return { max_failures: 5, window_seconds: 600, lock_duration_seconds: 900, allowed_mfa_methods: ["otp"] };
    if (url === "/settings/passkey") return { enabled: false, requirements_met: false };
    if (url === "/settings/smtp") return { enabled: false, port: 587 };
    if (url === "/settings/logging") return { enabled: true, retention_days: 7 };
    return {};
  };
  const first = await loadConsole("#management", request, { window: { EventSource } });
  const second = await loadConsole("#management", request, { window: { EventSource } });
  await first.bootstrap();
  await second.bootstrap();
  const snapshot = {
    auth: { max_failures: 3, allowed_mfa_methods: ["otp", "passkey"] },
    passkey: { enabled: true, requirements_met: true, rp_id: "nodewall.example.com" },
    smtp: { enabled: true, host: "smtp.example.com" },
    logging: { enabled: false, retention_days: 14 },
  };
  sources.forEach((source) => source.emit("settings", snapshot));
  assert.equal(first.state.authSettings.max_failures, 3);
  assert.equal(Array.from(first.state.authSettings.allowed_mfa_methods).join(","), "otp,passkey");
  assert.equal(second.state.passkeySettings.requirements_met, true);
  assert.equal(second.state.smtpSettings.enabled, true);
  assert.equal(first.state.loggingSettings.retention_days, 14);
  assert.equal(second.state.loggingSettings.enabled, false);
});

test("a local settings write is not reverted by a cached SSE snapshot", async () => {
  const sources = [];
  class EventSource {
    constructor() { this.listeners = {}; sources.push(this); }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
    emit(name, payload) { this.listeners[name]?.({ data: JSON.stringify(payload) }); }
  }
  const node = { id: "node-a", last_seen_at: new Date().toISOString() };
  const request = async (url, options = {}) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id };
    if (url === "/nodes") return { nodes: [node] };
    if (url === "/settings/auth" && options.method === "PUT") {
      options.onResponse?.({ headers: { get: (name) => name === "X-NodeWall-Revision" ? "1" : '"saved"' } });
      return { max_failures: 3 };
    }
    if (url === "/settings/auth") return { max_failures: 5, window_seconds: 600, lock_duration_seconds: 900, allowed_mfa_methods: ["otp"] };
    return {};
  };
  const store = await loadConsole("#management", request, { window: { EventSource } });
  await store.bootstrap();
  store.state.authSettings.max_failures = 3;
  await store.saveAuthSettings();
  sources[0].emit("settings", { revision: 0, auth: { max_failures: 5 } });
  assert.equal(store.state.authSettings.max_failures, 3);
  sources[0].emit("settings", { revision: 2, auth: { max_failures: 6 } });
  assert.equal(store.state.authSettings.max_failures, 6, "a legitimate remote save must arrive immediately, without a timed hold");
});

test("a node removal prunes event history without restarting the cluster subscription", async () => {
  const sources = [];
  class EventSource {
    constructor() { this.listeners = {}; sources.push(this); }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
    emit(name, payload) { this.listeners[name]?.({ data: JSON.stringify(payload) }); }
  }
  const oldNode = { id: "node-a", last_seen_at: new Date().toISOString() };
  const newNode = { id: "node-b", last_seen_at: new Date().toISOString() };
  let currentNodes = [oldNode, newNode];
  let currentLogs = [{ node_id: "node-a", drops: 1 }];
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: oldNode.id };
    if (url === "/nodes") return { nodes: currentNodes };
    if (url === "/events/snapshot") return { scope: "cluster", logs: currentLogs, nodes: currentNodes.map(node => ({ node_id: node.id, ssh_activity: [{ command: node.id }], scans: [] })) };
    if (url === "/events/dispositions") return { dispositions: [] };
    if (url.includes("/nodes/node-a/ssh-protection/activity")) return { records: [{ command: "old" }] };
    if (url.includes("/nodes/node-b/ssh-protection/activity")) return { records: [{ command: "new" }] };
    if (url.includes("/nodes/node-a/ssh-protection")) return { settings: { enabled: true } };
    if (url.includes("/nodes/node-b/ssh-protection")) return { settings: { enabled: true } };
    return {};
  };
  const store = await loadConsole("#events", request, { window: { EventSource } });
  await store.bootstrap();
  currentNodes = [newNode];
  currentLogs = [{ node_id: "node-b", drops: 2 }];
  sources[0].emit("nodes", currentNodes);
  await tick();
  await tick();
  assert.equal(store.state.nodeId, "node-b");
  sources[0].emit("events", { scope: "cluster", logs: currentLogs, nodes: [{ node_id: "node-a", scans: [] }, { node_id: "node-b", ssh_activity: [{ command: "new" }], scans: [] }] });
  assert.equal(store.state.eventCenter.nodes.length, 1);
  assert.equal(store.state.eventCenter.nodes[0].ssh_activity[0].command, "new");
  assert.equal(store.state.eventCenter.logs[0].node_id, "node-b");
  assert.notEqual(sources[0].closed, true);
  assert.equal(sources.length, 1);
  store.dispose();
});

test("management refresh includes current protection status for every node", async () => {
  const node = { id: "node-a", last_seen_at: new Date().toISOString() };
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id };
    if (url === "/nodes") return { nodes: [node] };
    if (url === "/nodes/node-a/protection-status") return { node_id: "node-a", protection_status: "enforced" };
    return {};
  };
  const store = await loadConsole("#management", request);
  await store.bootstrap();
  assert.equal(store.state.nodeProtection["node-a"].protection_status, "enforced");
});

test("newer settings refresh wins over an older in-flight response", async () => {
  const staleAuth = deferred();
  let authReads = 0;
  const node = { id: "node-a", last_seen_at: new Date().toISOString() };
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id };
    if (url === "/nodes") return { nodes: [node] };
    if (url === "/nodes/node-a/protection-status") return { node_id: node.id, protection_status: "enforced" };
    if (url === "/settings/auth") {
      authReads += 1;
      if (authReads === 2) return staleAuth.promise;
      if (authReads >= 3) return { max_failures: 3 };
    }
    return {};
  };
  const store = await loadConsole("#management", request);
  await store.bootstrap();
  const staleRefresh = store.refreshData();
  const currentRefresh = store.refreshData({ force: true });
  await currentRefresh;
  staleAuth.resolve({ max_failures: 99 });
  await staleRefresh;
  assert.equal(store.state.authSettings.max_failures, 3);
});

test("security refresh includes the resource aggregate used by the overview", async () => {
  const node = { id: "node-a", last_seen_at: new Date().toISOString() };
  let aggregateCalls = 0;
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id, default_interface: "eth0" };
    if (url === "/nodes") return { nodes: [node] };
    if (url.startsWith("/cluster/aggregate")) {
      aggregateCalls += 1;
      return { system: { average_cpu_percent: aggregateCalls * 10, average_memory_percent: 20 } };
    }
    if (url.endsWith("/interfaces")) return { recommended: "eth0", interfaces: [{ name: "eth0", is_physical: true }] };
    if (url.includes("/interfaces/eth0/summary")) return { health: { interfaces: [{ interface: "eth0", xdp_attached: true }] } };
    if (url.endsWith("/security/summary")) return { node_id: node.id, checks: [] };
    if (url.endsWith("/security/scan")) return { node_id: node.id, status: "idle", findings: [] };
    if (url.endsWith("/security/quarantine")) return { node_id: node.id, entries: [] };
    if (url.endsWith("/ssh-protection")) return { node_id: node.id, settings: { enabled: true } };
    if (url.includes("/ssh-protection/activity")) return { records: [] };
    if (url.includes("/ssh-protection/keys")) return { keys: [] };
    if (url.startsWith("/logs/drop")) return { logs: [] };
    return {};
  };
  const store = await loadConsole("#security", request);
  await store.bootstrap();
  await store.refreshData({ force: true });
  assert.ok(aggregateCalls >= 2);
  assert.equal(store.state.clusterAggregate.system.average_cpu_percent, aggregateCalls * 10);
});

test("node scoped SSH writes do not overwrite the newly selected node", async () => {
  const pendingSave = deferred();
  const nodes = [
    { id: "node-a", last_seen_at: new Date().toISOString() },
    { id: "node-b", last_seen_at: new Date().toISOString() },
  ];
  const request = async (url, options = {}) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "node-a", default_interface: "eth0" };
    if (url === "/nodes") return { nodes };
    if (options.method === "PUT" && url === "/nodes/node-a/ssh-protection") return pendingSave.promise;
    if (url === "/nodes/node-a/ssh-protection") return { node_id: "node-a", settings: { enabled: false } };
    if (url === "/nodes/node-b/ssh-protection") return { node_id: "node-b", settings: { enabled: true } };
    if (url.includes("/ssh-protection/activity")) return { records: [] };
    if (url.includes("/ssh-protection/keys")) return { keys: [] };
    if (url.endsWith("/interfaces")) return { recommended: "eth0", interfaces: [{ name: "eth0", is_physical: true }] };
    if (url.includes("/interfaces/eth0/summary")) return { health: { interfaces: [{ interface: "eth0" }] } };
    if (url.startsWith("/logs/drop")) return { logs: [] };
    if (url === "/events/dispositions") return { dispositions: [] };
    return {};
  };
  const store = await loadConsole("#security", request);
  await store.bootstrap();
  const save = store.saveSSHProtectionSettings();
  await store.setNode("node-b");
  pendingSave.resolve({ node_id: "node-a", settings: { enabled: false } });
  await save;
  assert.equal(store.state.nodeId, "node-b");
  assert.equal(store.state.sshProtection.node_id, "node-b");
  assert.equal(store.state.sshProtection.settings.enabled, true);
});


test("node switch opens the security stream with the new node inventory", async () => {
  const sources = [];
  class EventSource {
    constructor(url) { this.url = url; this.listeners = {}; sources.push(this); }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
    emit(name, payload) { this.listeners[name]?.({ data: JSON.stringify(payload) }); }
  }
  const nodes = [{ id: "a" }, { id: "b" }].map((node) => ({ ...node, last_seen_at: new Date().toISOString() }));
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "a", default_interface: "eth0" };
    if (url === "/nodes") return { nodes };
    return {};
  };
  const store = await loadConsole("#firewall", request, { window: { EventSource } });
  await store.bootstrap();
  store.state.selectedInterface = "eth0";
  const previous = sources[sources.length - 1];
  await store.setNode("b");
  assert.equal(previous.closed, true);
  const next = sources[sources.length - 1];
  const query = new URLSearchParams(next.url.split("?")[1]);
  assert.equal(query.get("node"), "b");
  assert.equal(query.has("iface"), false, "old node NIC leaked into the new subscription");
  next.emit("security", { revision: 0, nodes: [{ node_id: "b", interface: "ens9", inventory: { recommended: "ens9", interfaces: [{ name: "ens9" }] }, current: { policy: { node_id: "b", interface: "ens9" }, health: { interfaces: [] } } }] });
  assert.equal(store.currentInterface.value, "ens9");
  assert.equal(sources.at(-1), next, "an automatic recommendation should not restart the subscription");
  previous.emit("security", { nodes: [{ node_id: "a", inventory: { recommended: "eth0", interfaces: [{ name: "eth0" }] } }] });
  assert.equal(store.currentInterface.value, "ens9");
  const securityStream = sources.at(-1);
  store.setSection("account");
  assert.equal(securityStream.closed, true);
  const accountQuery = new URL(sources.at(-1).url, "https://nodewall.test").searchParams;
  assert.equal(accountQuery.get("section"), "account");
  assert.equal(accountQuery.get("event_feed"), "1");
  store.dispose();
});

test("a stale unavailable security frame cannot disable a ready firewall page", async () => {
  const sources = [];
  class EventSource {
    constructor(url) { this.url = url; this.listeners = {}; sources.push(this); }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
    emit(name, payload) { this.listeners[name]?.({ data: JSON.stringify(payload) }); }
  }
  const node = { id: "node-a", last_seen_at: new Date().toISOString() };
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: node.id, default_interface: "eth0" };
    if (url === "/nodes") return { nodes: [node] };
    if (url.endsWith("/interfaces")) return { recommended: "eth0", interfaces: [{ name: "eth0", is_physical: true }] };
    if (url.includes("/interfaces/eth0/summary")) return {
      policy: { ingress: { enabled: true, mode: "whitelist", default_action: "drop", rules: [{ cidr: "192.0.2.1/32" }] } },
      health: { interfaces: [] },
    };
    return {};
  };
  const store = await loadConsole("#firewall", request, { window: { EventSource } });
  await store.bootstrap();
  assert.equal(store.state.interfaceDataStatus, "ready");
  const source = sources[sources.length - 1];
  source.emit("security", {
    revision: 0,
    nodes: [{
      node_id: node.id,
      interface: "eth0",
      interface_status: "unavailable",
      current: { policy: { ingress: { enabled: true, mode: "whitelist", default_action: "drop", rules: [{ cidr: "192.0.2.1/32" }] } }, health: { interfaces: [] } },
    }],
  });
  assert.equal(store.state.interfaceDataStatus, "ready");
});

test("SSH keys from another Web are applied by the active page stream", async () => {
  const sources = [];
  class EventSource {
    constructor() { this.listeners = {}; sources.push(this); }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() {}
    emit(name, payload) { this.listeners[name]?.({ data: JSON.stringify(payload) }); }
  }
  const request = async (url) => {
    if (url === "/auth/session") return { authenticated: true };
    if (url === "/bootstrap") return { node_id: "a" };
    if (url === "/nodes") return { nodes: [{ id: "a" }] };
    return {};
  };
  const store = await loadConsole("#ssh", request, { window: { EventSource } });
  await store.bootstrap();
  sources[sources.length - 1].emit("security", { revision: 2, nodes: [{ node_id: "a", ssh: { settings: { enabled: true } }, ssh_settings_etag: '"remote"', sshKeys: { keys: [{ fingerprint: "from-web-b" }] } }] });
  assert.equal(store.state.sshProtection.keys[0].fingerprint, "from-web-b");
  assert.equal(store.state.sshSettingsETag, '"remote"');
});

test('a delayed scan result cannot restart streaming after leaving the scan page', async () => {
  const scan = deferred();
  const sources = [];
  class EventSource {
    constructor(url) { this.url = url; this.listeners = {}; sources.push(this); }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
  }
  const request = async (url) => {
    if (url === '/auth/session') return { authenticated: true };
    if (url === '/bootstrap') return { node_id: 'a' };
    if (url === '/nodes') return { nodes: [{ id: 'a' }] };
    if (url.endsWith('/security/scan')) return scan.promise;
    return {};
  };
  const store = await loadConsole('#malware', request, { window: { EventSource } });
  await store.bootstrap();
  const pending = store.refreshSecurityScan();
  store.setSection('management');
  scan.resolve({ node_id: 'a', status: 'running', findings: [] });
  await pending;
  assert.equal(sources.filter((source) => source.url.endsWith('/security/scan/events')).length, 0);
});

test('scan SSE renders findings immediately and refreshes quarantine without per-frame requests', async () => {
  const sources = [];
  const quarantineTimers = new Map();
  let nextQuarantineTimer = 0;
  let quarantineReads = 0;
  class EventSource {
    constructor(url) { this.url = url; this.listeners = {}; sources.push(this); }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    close() { this.closed = true; }
    emit(name, payload) { this.listeners[name]?.({ data: JSON.stringify(payload) }); }
  }
  const request = async (url, options = {}) => {
    if (url === '/auth/session') return { authenticated: true };
    if (url === '/bootstrap') return { node_id: 'a' };
    if (url === '/nodes') return { nodes: [{ id: 'a' }] };
    if (url === '/nodes/a/security/scan' && options.method === 'POST') return { node_id: 'a', status: 'running', id: 'scan-a', findings: [] };
    if (url === '/nodes/a/security/scan') return { node_id: 'a', status: 'running', id: 'scan-a', findings: [] };
    if (url === '/nodes/a/security/quarantine') {
      quarantineReads += 1;
      return { node_id: 'a', root: '/var/lib/nodewall/quarantine', entries: quarantineReads > 0 ? [{ id: 'q-live' }] : [] };
    }
    return {};
  };
  const store = await loadConsole('#malware', request, { window: {
    EventSource,
    setTimeout(callback, delay) {
      if (delay === 700) {
        const id = ++nextQuarantineTimer;
        quarantineTimers.set(id, callback);
        return id;
      }
      return setTimeout(callback, delay);
    },
    clearTimeout(id) { quarantineTimers.delete(id); },
  } });
  await store.bootstrap();
  await store.startSecurityScan('/', true, true, 'process');
  const source = sources.find((item) => item.url.endsWith('/security/scan/events'));
  assert.ok(source);
  source.emit('scan', { node_id: 'a', status: 'running', id: 'scan-a', files_scanned: 4, findings: [{ id: 'f-live', rule: 'webshell', severity: 'high' }] });
  source.emit('scan', { node_id: 'a', status: 'running', id: 'scan-a', files_scanned: 5, findings: [{ id: 'f-live', rule: 'webshell', severity: 'high' }] });
  assert.equal(store.state.securitySummary.scan.findings[0].id, 'f-live');
  assert.equal(quarantineReads, 0);
  assert.equal(quarantineTimers.size, 1);
  await [...quarantineTimers.values()][0]();
  assert.equal(store.state.securityQuarantine.entries[0].id, 'q-live');
  assert.equal(quarantineReads, 1);
});

test('confirmation prevents duplicate submits and keeps failed actions ready to retry', async () => {
  const store = await loadConsole('#cluster', async () => ({}));
  const pending = deferred();
  let calls = 0;
  store.openModal({ keepOpenOnError: true, onConfirm: async () => { calls++; if (calls === 1) { await pending.promise; throw new Error('temporary fixture failure'); } } });
  const first = store.confirmModal({ password: 'fixture' });
  await store.confirmModal({ password: 'fixture' });
  assert.equal(calls, 1);
  pending.resolve();
  await first;
  assert.equal(store.state.modal.open, true);
  assert.equal(store.state.modal.busy, false);
  assert.equal(store.state.modal.error, 'temporary fixture failure');
  assert.equal(store.state.errorDialog.open, false);
  await store.confirmModal({ password: 'fixture-retry' });
  assert.equal(calls, 2);
  assert.equal(store.state.modal.open, false);
});

test('refreshing a remote node URL never reuses the manager NIC', async () => {
  const sources = [];
  class EventSource {
    constructor(url) { this.url = url; }
    addEventListener() {}
    close() {}
  }
  const request = async (url) => {
    if (url === '/auth/session') return { authenticated: true };
    if (url === '/bootstrap') return { node_id: 'manager', default_interface: 'ens3' };
    if (url === '/nodes') return { nodes: [{ id: 'manager' }, { id: 'worker' }] };
    return {};
  };
  class CapturedSource extends EventSource { constructor(url) { super(url); sources.push(this); } }
  const store = await loadConsole('#firewall', request, { window: { EventSource: CapturedSource, location: { hash: '#firewall', search: '?node=worker' } } });
  await store.bootstrap();
  assert.equal(store.state.nodeId, 'worker');
  const query = new URLSearchParams(sources[sources.length - 1].url.split('?')[1]);
  assert.equal(query.get('node'), 'worker');
  assert.equal(query.has('iface'), false);
});

test('unmounting the console closes streams and cannot reopen a disposed subscription', async () => {
  const sources = [];
  class EventSource {
    constructor(url) { this.url = url; sources.push(this); }
    addEventListener() {}
    close() { this.closed = true; }
  }
  const request = async (url) => {
    if (url === '/auth/session') return { authenticated: true };
    if (url === '/bootstrap') return { node_id: 'a' };
    if (url === '/nodes') return { nodes: [{ id: 'a' }] };
    return {};
  };
  const store = await loadConsole('#security', request, { window: { EventSource } });
  await store.bootstrap();
  store.dispose();
  assert.ok(sources.length > 0);
  assert.ok(sources.every((source) => source.closed));
  const count = sources.length;
  store.setSection('management');
  assert.equal(sources.length, count);
});

test('account password action writes through the authenticated backend endpoint', async () => {
  const calls = [];
  const request = async (url, options = {}) => {
    calls.push({ url, options });
    return {};
  };
  const store = await loadConsole('#account', request);
  await store.changePassword('old-password', 'new-password');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/auth/password');
  assert.equal(calls[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    current_password: 'old-password',
    new_password: 'new-password',
  });
});
