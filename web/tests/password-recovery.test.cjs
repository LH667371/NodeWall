const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../internal/api/auth_recovery_page.go'), 'utf8');
const controller = source.slice(source.indexOf('<script>') + '<script>'.length, source.indexOf('</script>'))
  .replace(/\{\{\.Messages\.(\w+)\}\}/g, (_, key) => JSON.stringify(key === 'loginRateLimited' ? 'retry in %d seconds' : key));

function setup() {
  const ids = ['request-form', 'reset-form', 'username', 'code', 'password', 'confirm', 'locale',
    'request', 'resend', 'reset', 'edit', 'feedback', 'complete', 'panel', 'request-step', 'reset-step', 'account-name', 'login-link'];
  const nodes = Object.fromEntries(ids.map((id) => [id, {
    events: {},
    attributes: {},
    dataset: {},
    value: '',
    hidden: false,
    addEventListener(kind, handler) { this.events[kind] = handler; },
    setAttribute(key, value) { this.attributes[key] = value; },
    focus() { focused = id; },
  }]));
  nodes.panel.dataset.resendSeconds = '30';
  nodes['request-form'].action = '/auth/forgot-password/request?lang=zh-CN';
  nodes['reset-form'].action = '/auth/forgot-password/reset?lang=zh-CN';
  nodes['reset-form'].hidden = nodes.complete.hidden = true;
  nodes['reset-form'].reset = () => {
    for (const id of ['code', 'password', 'confirm']) nodes[id].value = '';
  };
  nodes['login-link'].href = '/login?lang=zh-CN';
  const requests = [];
  const timers = [];
  const navigations = [];
  let now = 1000000;
  let focused = '';
  vm.runInNewContext(controller, {
    document: { getElementById: (id) => nodes[id.slice('recovery-'.length)] },
    Date: { now: () => now },
    window: {
      setTimeout: (callback, delay) => timers.push({ callback, at: now + delay }),
      location: { assign: (url) => navigations.push(url) },
    },
    fetch: (url, options) => new Promise((resolve, reject) => {
      requests.push({ url, body: JSON.parse(options.body), resolve, reject });
    }),
  });
  return {
    nodes, requests, navigations,
    get focused() { return focused; },
    submit: (form) => nodes[form + '-form'].events.submit({ preventDefault() {} }),
    click: (button) => nodes[button].events.click(),
    respond(index, data, status = 200, retryAfter = null) {
      requests[index].resolve({ status, ok: status >= 200 && status < 300,
        headers: { get: () => retryAfter }, json: async () => data });
    },
    advance(delay) {
      now += delay;
      for (const timer of timers) {
        if (!timer.fired && timer.at <= now) {
          timer.fired = true;
          timer.callback();
        }
      }
    },
  };
}

async function acceptInitialRequest(ui) {
  ui.nodes.username.value = '  test-account  ';
  const sending = ui.submit('request');
  ui.respond(0, { status: 'accepted', request_id: 'first-request' });
  await sending;
}

test('the reset step opens after an accepted request and duplicate submission is blocked', async () => {
  const ui = setup();
  ui.nodes.username.value = '  test-account  ';
  assert.equal(ui.nodes['reset-form'].hidden, true);
  const sending = ui.submit('request');
  assert.equal(ui.nodes.request.disabled, true);
  await ui.submit('request');
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.requests[0].url, '/auth/forgot-password/request?lang=zh-CN');
  assert.deepEqual(ui.requests[0].body, { username: 'test-account' });
  ui.respond(0, { status: 'accepted', request_id: 'first-request' });
  await sending;
  assert.equal(ui.nodes['request-form'].hidden, true);
  assert.equal(ui.nodes['reset-form'].hidden, false);
  assert.equal(ui.nodes['account-name'].textContent, 'test-account');
  assert.equal(ui.nodes['reset-step'].attributes['aria-current'], 'step');
  assert.equal(ui.focused, 'code');
  assert.equal(ui.nodes.resend.disabled, true);
});

test('resend uses the mail cooldown and keeps the current request if the server rejects it', async () => {
  const ui = setup();
  await acceptInitialRequest(ui);
  ui.nodes.code.value = '123456';
  ui.nodes.password.value = ui.nodes.confirm.value = 'test-new-password';
  await ui.click('resend');
  assert.equal(ui.requests.length, 1);
  ui.advance(30000);
  assert.equal(ui.nodes.resend.disabled, false);
  const limited = ui.click('resend');
  ui.respond(1, null, 429, '10');
  await limited;
  assert.equal(ui.nodes.resend.disabled, true);
  assert.equal(ui.nodes.feedback.textContent, 'retry in 10 seconds');
  assert.equal(ui.nodes.code.value, '123456');
  ui.advance(10000);
  const sending = ui.click('resend');
  ui.respond(2, { status: 'accepted', request_id: 'next-request' });
  await sending;
  assert.equal(ui.nodes.code.value, '');
  assert.equal(ui.nodes.password.value, 'test-new-password');
  ui.nodes.code.value = '654321';
  const resetting = ui.submit('reset');
  assert.equal(ui.requests[3].body.request_id, 'next-request');
  ui.respond(3, { error: 'password reset code is invalid or expired' }, 400);
  await resetting;
  assert.equal(ui.nodes.feedback.textContent, 'forgotCodeInvalid');
  assert.equal(ui.nodes['reset-form'].hidden, false);
});

test('password confirmation stays local and successful reset clears fields before redirecting', async () => {
  const ui = setup();
  await acceptInitialRequest(ui);
  ui.nodes.code.value = '123456';
  ui.nodes.password.value = 'test-new-password';
  ui.nodes.confirm.value = 'mismatch';
  await ui.submit('reset');
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.nodes.feedback.textContent, 'forgotPasswordsMismatch');
  ui.nodes.confirm.value = ui.nodes.password.value;
  const failed = ui.submit('reset');
  ui.requests[1].reject(new Error('reset response lost'));
  await failed;
  assert.equal(ui.nodes.feedback.textContent, 'forgotResetUncertain');
  assert.equal(ui.requests.length, 2);
  const resetting = ui.submit('reset');
  assert.equal(ui.requests[2].url, '/auth/forgot-password/reset?lang=zh-CN');
  assert.deepEqual(ui.requests[2].body, { request_id: 'first-request', code: '123456', new_password: 'test-new-password' });
  ui.respond(2, { status: 'reset' });
  await resetting;
  assert.equal(ui.nodes.password.value, '');
  assert.equal(ui.nodes.confirm.value, '');
  assert.equal(ui.nodes['reset-form'].hidden, true);
  assert.equal(ui.nodes.complete.hidden, false);
  ui.advance(900);
  assert.deepEqual(ui.navigations, ['/login?lang=zh-CN']);
});

test('changing the account clears sensitive input and reuses the same account request during cooldown', async () => {
  const ui = setup();
  await acceptInitialRequest(ui);
  ui.nodes.code.value = '123456';
  ui.nodes.password.value = 'test-new-password';
  ui.click('edit');
  assert.equal(ui.nodes['request-form'].hidden, false);
  assert.equal(ui.nodes.code.value, '');
  assert.equal(ui.nodes.password.value, '');
  await ui.submit('request');
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.nodes['reset-form'].hidden, false);
  ui.click('edit');
  ui.nodes.username.value = 'another-account';
  const missingID = ui.submit('request');
  ui.respond(1, { status: 'accepted' });
  await missingID;
  assert.equal(ui.nodes['reset-form'].hidden, true);
  assert.equal(ui.nodes.feedback.textContent, 'forgotRequestFailed');
});
