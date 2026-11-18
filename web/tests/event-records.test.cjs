const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

async function load() {
  const context = vm.createContext({});
  const ids = new vm.SourceTextModule(fs.readFileSync(path.join(__dirname,'../src/lib/eventIds.js'),'utf8'),{context});
  await ids.link(()=>{throw new Error('IDs must remain pure');});
  const firewall = new vm.SourceTextModule(fs.readFileSync(path.join(__dirname,'../src/lib/firewallLogs.js'),'utf8'),{context});
  await firewall.link(()=>{throw new Error('firewall source helpers must remain pure');});
  const records = new vm.SourceTextModule(fs.readFileSync(path.join(__dirname,'../src/lib/eventRecords.js'),'utf8'),{context});
  await records.link(specifier=>specifier==='./firewallLogs'?firewall:ids);
  await records.evaluate();
  return records.namespace.buildEventRecords;
}

test('all node histories have stable, separate provenance and compact summary counts', async () => {
  const build = await load();
  const nodes = ['a','b'].map(node_id=>({node_id,ssh_activity:[{node_id:'forged',at:'2026-11-17T08:00:00Z',action:'failed'}],scans:[
    {id:'same-id',status:'completed',findings_count:7,finished_at:'2026-11-17T09:00:00Z'},
    {id:'same-id',status:'completed',findings_count:7,finished_at:'2026-11-17T09:00:00Z'},
    {id:'older',status:'completed',findings_count:1,finished_at:'2026-11-16T09:00:00Z'},
    {id:'in-progress',status:'running'},
  ]}));
  const rows = build({nodes,logs:[]},{t:(key,params)=>params?.count ? String(params.count) : key});
  assert.equal(rows.length,6);
  assert.equal(new Set(rows.map(row=>row.id)).size,6);
  assert.equal(rows.filter(row=>row.node==='b').length,3);
  assert.equal(rows[0].description,'7');
  assert.ok(rows.every(row=>row.node!=='forged'));
  assert.equal(build({logs:[{drops:1}],nodes:[]}).length,0,'unknown provenance must not become the selected security node');
});

test('failed scans need attention even without malware findings and triage state is shared', async () => {
  const build = await load();
  const snapshot={nodes:[{node_id:'b',scans:[{id:'failed',status:'failed',findings_count:0,error:'disk error',finished_at:'2026-11-17T09:00:00Z'}]}]};
  const rows=build(snapshot);
  assert.equal(rows[0].severity,'medium');
  assert.equal(rows[0].status,'pending');
  const triaged=build(snapshot,{statusFor:(_id,node,fallback)=>node==='b'?'handled':fallback});
  assert.equal(triaged[0].status,'handled');
});

test('DHCP, rule aggregates and observation records keep their actual meaning', async () => {
  const build = await load();
  const logs = [
    {node_id:'a',timestamp:'2026-11-17T10:00:00Z',source_ip:'0.0.0.0',port:67,reason:'dhcp_broadcast',count:2,drops:2},
    {node_id:'a',timestamp:'2026-11-17T10:00:00Z',source_ip:'',source_cidr:'0.0.0.0/0',port:67,reason:'nodewall:default_deny',count:4,drops:4},
    {node_id:'a',timestamp:'2026-11-17T10:00:00Z',source_ip:'',source_cidr:'10.42.0.0/16',port:67,reason:'nodewall:default_deny',count:5,drops:5},
    {node_id:'b',source_ip:'192.0.2.1',count:30,drops:0,reason:'denied_port'},
  ];
  const rows = build({logs});
  assert.equal(rows.length,3,'observe-only matches cannot become actual interceptions');
  assert.equal(new Set(rows.map(row=>row.id)).size,3,'different rule scopes must stay separate');
  const dhcp=rows.find(row=>row.raw.reason==='dhcp_broadcast');
  assert.equal(dhcp.severity,'low');
  assert.match(dhcp.source,/firewallDHCPUnassigned/);
  assert.match(rows.find(row=>row.raw.source_cidr==='0.0.0.0/0').source,/firewallRuleAggregateSource/);
  assert.equal(build({logs:[{...logs[0],drops:100}]})[0].severity,'high','frequent broadcasts must remain visible');
  assert.equal(build({logs:[{...logs[0],reason:'denied_port'}]})[0].severity,'high','explicit denies must not be relabeled');
});
