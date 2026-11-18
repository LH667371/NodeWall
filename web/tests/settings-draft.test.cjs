const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const vue = require('../node_modules/vue');

async function loadDraft() {
  const context = vm.createContext({});
  const source = fs.readFileSync(path.join(__dirname, '../src/composables/useSettingsDraft.js'), 'utf8');
  const module = new vm.SourceTextModule(source, { context });
  await module.link(() => new vm.SyntheticModule(['computed', 'reactive', 'ref', 'watch'], function () {
    for (const name of ['computed', 'reactive', 'ref', 'watch']) this.setExport(name, vue[name]);
  }, { context }));
  await module.evaluate();
  return module.namespace.useSettingsDraft;
}

test('remote changes merge untouched fields without erasing an in-progress edit', async () => {
  const useDraft = await loadDraft();
  const server = vue.reactive({ value: { max: 5, window: 600 }, tag: 'v1' });
  const scope = vue.effectScope();
  const form = scope.run(() => useDraft(() => server.value, () => server.tag, ['max', 'window']));
  form.draft.max = 3;
  server.value = { max: 5, window: 900 };
  server.tag = 'v2';
  assert.equal(form.draft.max, 3);
  assert.equal(form.draft.window, 900);
  assert.equal(form.conflicts.value.length, 0);
  assert.equal(form.etag.value, 'v2');
  scope.stop();
});

test('conflicting edits remain visible until the operator explicitly loads latest values', async () => {
  const useDraft = await loadDraft();
  const server = vue.reactive({ value: { max: 5 }, tag: 'v1' });
  const scope = vue.effectScope();
  const form = scope.run(() => useDraft(() => server.value, () => server.tag, ['max']));
  form.draft.max = 3;
  server.value = { max: 7 };
  server.tag = 'v2';
  assert.equal(form.draft.max, 3);
  assert.equal(form.conflicts.value.join(','), 'max');
  assert.equal(form.etag.value, 'v1');
  form.reset();
  assert.equal(form.draft.max, 7);
  assert.equal(form.conflicts.value.length, 0);
  assert.equal(form.dirty.value, false);
  assert.equal(form.etag.value, 'v2');
  scope.stop();
});

test('nested transfer policy updates keep unrelated local choices and settle after save', async () => {
  const useDraft = await loadDraft();
  const server = vue.reactive({ value: { transfer: { scan: false, audit: false } }, tag: 'v1' });
  const scope = vue.effectScope();
  const form = scope.run(() => useDraft(() => server.value, () => server.tag, ['transfer']));
  form.draft.transfer.scan = true;
  server.value = { transfer: { scan: false, audit: true } };
  assert.equal(form.draft.transfer.scan, true);
  assert.equal(form.draft.transfer.audit, true);
  assert.equal(form.conflicts.value.length, 0);
  server.value = { transfer: { scan: true, audit: true } };
  assert.equal(form.dirty.value, false);
  scope.stop();
});

test('secret replacement requires review when another Web saved the same configuration', async () => {
  const useDraft = await loadDraft();
  const server = vue.reactive({ value: { host: 'mail.example.test', password: '' }, tag: 'v1' });
  const scope = vue.effectScope();
  const form = scope.run(() => useDraft(() => server.value, () => server.tag, ['host', 'password']));
  form.draft.password = 'fixture-secret';
  server.tag = 'v2';
  assert.equal(form.conflicts.value.join(','), 'password');
  assert.equal(form.draft.password, 'fixture-secret');
  assert.equal(form.etag.value, 'v1');
  scope.stop();
});
