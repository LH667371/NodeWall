const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

async function load() {
  const module = new vm.SourceTextModule(fs.readFileSync(path.join(__dirname, "../src/lib/firewallBackend.js"), "utf8"));
  await module.link(() => { throw new Error("firewall backend labels should only use their inputs"); });
  await module.evaluate();
  return module.namespace;
}

test("firewall backend follows the selected NIC and requires a live attachment", async () => {
  const { interfaceFirewallBackend } = await load();
  const health = { agent_ok: true, interfaces: [
    { interface: "em1", xdp_attached: true, dataplane_mode: "generic", observe_only: true },
    { interface: "em2", xdp_attached: true, dataplane_mode: "iptables" },
    { interface: "em3", xdp_attached: false, dataplane_mode: "native" },
    { interface: "em4", xdp_attached: true },
  ] };
  assert.equal(interfaceFirewallBackend(health, "em1", "ready"), "generic");
  assert.equal(interfaceFirewallBackend(health, "em2", "ready"), "iptables");
  assert.equal(interfaceFirewallBackend(health, "em3", "ready"), "detached");
  assert.equal(interfaceFirewallBackend(health, "em4", "ready"), "unknown");
  assert.equal(interfaceFirewallBackend(health, "em5", "ready"), "detached");
  assert.equal(interfaceFirewallBackend(null, "em1", "loading"), "loading");
  assert.equal(interfaceFirewallBackend({ agent_ok: false }, "em1", "ready"), "unavailable");
});

test("node inventory groups active modes by NIC and distinguishes missing data", async () => {
  const { nodeFirewallBackends } = await load();
  const status = { reachable: true, dataplane_modes: { em1: "native", em2: "generic", em3: "native" } };
  assert.deepEqual(nodeFirewallBackends(status), [
    { mode: "native", interfaces: ["em1", "em3"] },
    { mode: "generic", interfaces: ["em2"] },
  ]);
  assert.equal(nodeFirewallBackends({ dataplane_modes: { eno1: "iptables" } })[0].mode, "iptables");
  assert.equal(nodeFirewallBackends({ reachable: true, dataplane_modes: {} })[0].mode, "detached");
  assert.equal(nodeFirewallBackends({ reachable: true })[0].mode, "unknown");
  assert.equal(nodeFirewallBackends({ reachable: false })[0].mode, "unavailable");
  assert.equal(nodeFirewallBackends({ connection_status: "unreachable" })[0].mode, "unavailable");
  assert.equal(nodeFirewallBackends(undefined)[0].mode, "loading");
});
