// Exercise the actual server-rendered login controller without a frontend build.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const authSource = fs.readFileSync(path.join(__dirname, '../../internal/api/auth.go'), 'utf8');
const controller = authSource.slice(authSource.indexOf('        let requestPending = false;'), authSource.indexOf("        const passkeyButton = form.querySelector('#passkey-login');"));
const loginTemplate = authSource.slice(authSource.indexOf('const loginPageHTML = `'), authSource.indexOf('const loginOTPHTML = `'));
const fullController = loginTemplate.slice(loginTemplate.indexOf('<script>') + '<script>'.length, loginTemplate.indexOf('</script>'))
  .replace(/\{\{\.(\w+)\}\}/g, (_match, key) => JSON.stringify(key));

function page(id, message = '', retryAfter = 0) {
  const nodes = {
    '#login-challenge': { dataset: { expiresIn: '180' } },
    '#captcha-content': { image: id },
    '#login-captcha-id': { value: id },
    '#login-form': { dataset: { retryAfter: String(retryAfter) } },
    '#login-error': { textContent: message },
  };
  return { querySelector: (selector) => nodes[selector] || null };
}

function setup(retryAfter = 0, { fullPage = false } = {}) {
  let now = 1000000;
  let timerID = 0;
  const timers = new Map();
  const requests = [];
  const events = {};
  const windowEvents = {};
  const redirects = [];
  let nativeSubmits = 0;
  let decorationWrites = 0;
  const decorations = Array.from({ length: 4 }, () => ({ style: { setProperty() { decorationWrites++; } } }));
  const nodes = {
    '#login-submit': { disabled: false },
    '#captcha-refresh': { disabled: false },
    '#login-captcha-id': { value: 'initial' },
    '#login-error': { textContent: '' },
    '#captcha-answer': { value: '7' },
    '#login-challenge': { dataset: { expiresIn: '180' } },
    '[name="locale"]': { value: 'zh-CN' },
    '[name="username"]': { value: 'admin' },
    '[name="password"]': { value: 'kept-password' },
  };
  const mount = (content) => {
    nodes['#captcha-content'] = { ...content, replaceWith: mount };
    nodes['#captcha-answer'] = { value: '' };
  };
  mount({ image: 'initial' });
  nodes['#captcha-answer'].value = '7';
  const form = {
    action: 'https://nodewall.test/login',
    dataset: { retryAfter: String(retryAfter) },
    querySelector: (selector) => nodes[selector] || null,
    addEventListener: (kind, handler) => { events[kind] = handler; },
  };
  const document = {
    querySelector: (selector) => selector === '#login-form' ? form : null,
    getElementById: (id) => id === 'login-form' ? form : null,
    querySelectorAll: (selector) => selector === '.ambient-light' ? decorations : [],
  };
  const context = vm.createContext({
    form, document, formError: nodes['#login-error'], setupTrace() {}, URL, URLSearchParams,
    Date: { now: () => now },
    captchaExpiredMessage: 'challenge expired', captchaRefreshFailed: 'refresh failed',
    loginRequestFailed: 'request failed', loginNetworkFailed: 'network uncertain; refresh challenge',
    window: {
      matchMedia: () => ({ matches: false }),
      clearTimeout: (id) => timers.delete(id),
      setTimeout: (handler, delay) => { timers.set(++timerID, { handler, at: now + delay }); return timerID; },
      addEventListener: (kind, handler) => { windowEvents[kind] = handler; },
      location: { assign: (url) => redirects.push(url) },
    },
    HTMLFormElement: { prototype: { submit() { nativeSubmits++; } } },
    FormData: function () {
      return [['username', nodes['[name="username"]'].value], ['password', nodes['[name="password"]'].value],
        ['captcha_id', nodes['#login-captcha-id'].value], ['captcha_answer', nodes['#captcha-answer'].value]];
    },
    DOMParser: class { parseFromString(value) { return value; } },
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
  });
  new vm.Script(fullPage ? fullController : controller, { filename: 'login-controller.js' }).runInContext(context);
  return {
    nodes, form, requests, redirects, windowEvents,
    get nativeSubmits() { return nativeSubmits; },
    get decorationWrites() { return decorationWrites; },
    input(selector, value) {
      const field = nodes[selector];
      field.value = value;
      events.input?.({ target: field });
      events.change?.({ target: field });
    },
    submit: () => events.submit({ preventDefault() {} }),
    refresh: () => events.click({ target: { closest: () => nodes['#captcha-refresh'] } }),
    respond(index, nextPage, status = 200, retry = '') {
      requests[index].resolve({ ok: status >= 200 && status < 300, status, headers: { get: () => retry },
        text: async () => nextPage, redirected: false });
    },
    advance(milliseconds) {
      now += milliseconds;
      for (const [id, timer] of [...timers]) {
        if (timer.at <= now) { timers.delete(id); timer.handler(); }
      }
    },
  };
}

test('typing and idling do not schedule recurring background work or send credentials', () => {
  const ui = setup(0, { fullPage: true });
  const initialWrites = ui.decorationWrites;
  const username = 'remote-admin';
  const password = 'remote-input-test';
  for (let length = 1; length <= username.length; length++) {
    ui.input('[name="username"]', username.slice(0, length));
  }
  for (let length = 1; length <= password.length; length++) {
    ui.input('[name="password"]', password.slice(0, length));
  }
  // Run the whole login controller: the old decoration timer continued to
  // repaint while VNC was transporting keystrokes and screen updates.
  for (let second = 0; second < 30; second++) ui.advance(1000);
  assert.equal(ui.decorationWrites, initialWrites, 'idle decoration must not keep invalidating the screen');
  assert.equal(ui.requests.length, 0, 'typing must not submit credentials or refresh the challenge');
  assert.equal(ui.nodes['[name="username"]'].value, username);
  assert.equal(ui.nodes['[name="password"]'].value, password);
  assert.equal(ui.nodes['#login-submit'].disabled, false);
});

test('refresh and login serialize the image, challenge ID, and one-time submission', async () => {
  const ui = setup();
  const refreshing = ui.refresh();
  assert.equal(ui.nodes['#login-submit'].disabled, true);
  await ui.submit();
  await ui.refresh();
  assert.equal(ui.requests.length, 1);
  ui.respond(0, page('new-image'));
  await refreshing;
  assert.equal(ui.nodes['#login-captcha-id'].value, 'new-image');
  assert.equal(ui.nodes['#captcha-content'].image, 'new-image');
  ui.nodes['#captcha-answer'].value = '4';
  const submitting = ui.submit();
  await ui.submit();
  await ui.refresh();
  assert.equal(ui.requests.length, 2);
  assert.equal(ui.requests[1].options.body.get('captcha_id'), 'new-image');
  ui.respond(1, page('retry-image', 'invalid password'));
  await submitting;
  assert.equal(ui.nodes['[name="password"]'].value, 'kept-password');
  assert.equal(ui.nodes['#login-captcha-id'].value, 'retry-image');
  assert.equal(ui.nodes['#login-error'].textContent, 'invalid password');
});

test('lost login response never replays credentials or reuses a consumed challenge', async () => {
  const ui = setup();
  const submitting = ui.submit();
  ui.requests[0].reject(new Error('response lost after server consumed the challenge'));
  await submitting;
  assert.equal(ui.nativeSubmits, 0);
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.nodes['#login-submit'].disabled, true);
  assert.equal(ui.nodes['#captcha-refresh'].disabled, false);
  await ui.submit();
  assert.equal(ui.requests.length, 1);
  const refreshing = ui.refresh();
  ui.respond(1, page('fresh-after-network-failure'));
  await refreshing;
  assert.equal(ui.nodes['#login-submit'].disabled, false);
  assert.equal(ui.nodes['[name="password"]'].value, 'kept-password');
});

test('uncertain refresh response also requires a fresh challenge', async () => {
  const ui = setup();
  const refreshing = ui.refresh();
  ui.requests[0].reject(new Error('refresh response lost'));
  await refreshing;
  await ui.submit();
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.nodes['#login-submit'].disabled, true);
  assert.equal(ui.nodes['#captcha-refresh'].disabled, false);
});

test('a malformed refresh response cannot leave a consumed challenge enabled', async () => {
  const ui = setup();
  const refreshing = ui.refresh();
  ui.respond(0, { querySelector: () => null });
  await refreshing;
  await ui.submit();
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.nodes['#login-submit'].disabled, true);
});

test('successful sign-in stays disabled while browser navigation begins', async () => {
  const ui = setup();
  const submitting = ui.submit();
  ui.requests[0].resolve({ redirected: true, url: 'https://nodewall.test/' });
  await submitting;
  assert.deepEqual(ui.redirects, ['/']);
  assert.equal(ui.nodes['#login-submit'].disabled, true);
  await ui.submit();
  assert.equal(ui.requests.length, 1);
});

test('expired challenges and history-restored pages cannot submit stale answers', async () => {
  const ui = setup();
  ui.advance(180000);
  assert.equal(ui.nodes['#login-submit'].disabled, false);
  assert.equal(ui.nodes['#login-error'].textContent, '');
  const refreshing = ui.submit();
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.nodes['#login-submit'].disabled, true);
  assert.match(ui.requests[0].url, /\/login\/captcha\/refresh/);
  assert.deepEqual([...ui.requests[0].options.body.keys()], ['captcha_id', 'locale']);
  ui.respond(0, page('fresh-after-expiry'));
  await refreshing;
  assert.match(ui.nodes['#login-error'].textContent, /expired/);
  assert.equal(ui.nodes['#login-captcha-id'].value, 'fresh-after-expiry');
  assert.equal(ui.nodes['#captcha-answer'].value, '');
  assert.equal(ui.nodes['[name="username"]'].value, 'admin');
  assert.equal(ui.nodes['[name="password"]'].value, 'kept-password');
  assert.equal(ui.nodes['#login-submit'].disabled, false);

  ui.windowEvents.pageshow({ persisted: true });
  const restored = ui.submit();
  assert.match(ui.requests[1].url, /\/login\/captcha\/refresh/);
  assert.equal(ui.requests[1].options.body.get('captcha_id'), 'fresh-after-expiry');
  ui.respond(1, page('fresh-after-history'));
  await restored;
  assert.equal(ui.nodes['#login-captcha-id'].value, 'fresh-after-history');
});

test('changing a challenge cannot clear the server submit cooldown', async () => {
  const ui = setup();
  const submitting = ui.submit();
  ui.respond(0, 'retry in 60 seconds', 429, '60');
  await submitting;
  const refreshing = ui.refresh();
  ui.respond(1, page('new-challenge-during-cooldown'));
  await refreshing;
  assert.equal(ui.nodes['#login-submit'].disabled, true);
  await ui.submit();
  assert.equal(ui.requests.length, 2);
  ui.advance(60000);
  assert.equal(ui.nodes['#login-submit'].disabled, false);
});

test('refresh rate limiting leaves the current challenge usable for login', async () => {
  const ui = setup();
  const refreshing = ui.refresh();
  ui.respond(0, 'retry refresh later', 429, '60');
  await refreshing;
  assert.equal(ui.nodes['#captcha-refresh'].disabled, true);
  assert.equal(ui.nodes['#login-submit'].disabled, false);
  assert.equal(ui.nodes['#login-captcha-id'].value, 'initial');
});

test('initial and returned password lockouts honor the actual recovery deadline', async () => {
  const initial = setup(42);
  await initial.submit();
  await initial.refresh();
  assert.equal(initial.requests.length, 0);
  initial.advance(42000);
  assert.equal(initial.nodes['#login-submit'].disabled, false);
  assert.equal(initial.nodes['#captcha-refresh'].disabled, false);

  const ui = setup();
  const submitting = ui.submit();
  ui.respond(0, page('locked', 'wait 42 seconds', 42));
  await submitting;
  assert.equal(ui.nodes['#login-submit'].disabled, true);
  assert.equal(ui.nodes['#captcha-refresh'].disabled, true);
  ui.advance(42000);
  assert.equal(ui.nodes['#login-submit'].disabled, false);
});
