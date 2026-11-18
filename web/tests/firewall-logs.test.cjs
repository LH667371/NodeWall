const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

async function load() {
  const module = new vm.SourceTextModule(fs.readFileSync(path.join(__dirname, '../src/lib/firewallLogs.js'), 'utf8'));
  await module.link(() => { throw new Error('source helpers must remain pure'); });
  await module.evaluate();
  return module.namespace;
}

test('only an observed unicast IPv4 can become a per-IP firewall action', async () => {
  const {canActOnFirewallSource: canAct, firewallSourceLabel: label} = await load();
  for (const item of [
    {source_ip:''}, {source_ip:'0.0.0.0'}, {source_ip:'255.255.255.255'}, {source_ip:'224.0.0.1'},
    {source_ip:'10.42.0.0/16'}, {source_ip:'192.0.2.256'}, {source_ip:'::1'},
    {source_ip:'192.0.2.1',source_cidr:'0.0.0.0/0'},
  ]) assert.equal(canAct(item), false, JSON.stringify(item));
  assert.equal(canAct({source_ip:'10.42.120.76'}), true);
  assert.equal(canAct({source_ip:'185.199.110.133'}), true);
  assert.match(label({source_ip:'',source_cidr:'0.0.0.0/0'}), /firewallRuleAggregateSource/);
  assert.match(label({source_ip:'0.0.0.0',reason:'dhcp_broadcast'}), /firewallDHCPUnassigned/);
  assert.equal(label({source_ip:'0.0.0.0',reason:'denied_port'}), '0.0.0.0', 'do not infer DHCP from the address alone');
  assert.equal(label({source_ip:'192.0.2.1',source_domain:'example.test'}), 'example.test 192.0.2.1');
});
