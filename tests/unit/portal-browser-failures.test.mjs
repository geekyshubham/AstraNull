import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { collectPortalBrowserFailures, assertPortalInitialLoad } from '../helpers/portal-browser-failures.mjs';

class Page extends EventEmitter {
  async exposeBinding(name, fn) { this.binding = fn; }
  async addInitScript(fn) { this.init = fn; }
  async goto() { this.emit('pageerror', new Error('first-load failure')); }
  locator() { return { waitFor: async () => {} }; }
  async waitForFunction() {}
}

test('first navigation failure cannot be erased by a mounted later shell', async () => {
  await assert.rejects(assertPortalInitialLoad(new Page(), 'http://127.0.0.1:1234'), /unexpected browser failures/);
});

test('collector keeps errors, invalid hook warnings, rejections and failed own modules', async () => {
  const page = new Page();
  const diagnostics = await collectPortalBrowserFailures(page, 'http://127.0.0.1:1234');
  for (const [type, text] of [['error', 'null useState'], ['warning', 'Invalid hook call']]) {
    page.emit('console', { type: () => type, text: () => text, location: () => ({}) });
  }
  page.binding({}, 'unhandled promise');
  page.emit('requestfailed', { url: () => 'http://127.0.0.1:1234/src/main.tsx', resourceType: () => 'script', failure: () => ({ errorText: 'ERR_FAILED' }) });
  assert.equal(diagnostics.failures.length, 4);
  assert.throws(() => diagnostics.assertClean());
});

const resourceUrl = 'http://127.0.0.1:1234/v1/targets';
const resourceMessage = (overrides = {}) => ({
  type: () => 'error',
  text: () => 'Failed to load resource: the server responded with a status of 503 (Service Unavailable)',
  location: () => ({ url: resourceUrl, lineNumber: 0, columnNumber: 0 }),
  args: () => [],
  ...overrides,
});
const resourceResponse = (overrides = {}) => ({
  url: () => resourceUrl,
  status: () => 503,
  request: () => ({ resourceType: () => 'fetch' }),
  ...overrides,
});

for (const order of ['response-first', 'console-first']) {
  test(`one explicitly allowed HTTP failure correlates its native resource console error: ${order}`, async () => {
    const page = new Page();
    let allowanceCalls = 0;
    const diagnostics = await collectPortalBrowserFailures(page, 'http://127.0.0.1:1234', {
      allowResponse: (response) => { allowanceCalls += 1; return response.url() === resourceUrl && response.status() === 503; },
    });
    const events = [['response', resourceResponse()], ['console', resourceMessage()]];
    if (order === 'console-first') events.reverse();
    for (const [name, value] of events) page.emit(name, value);
    diagnostics.assertClean();
    diagnostics.assertClean();
    assert.equal(allowanceCalls, 1, 'allowance must not be reevaluated during assertions');
    assert.equal(diagnostics.failures.length, 1, 'raw console diagnostic is retained');
    page.emit('console', resourceMessage());
    assert.throws(() => diagnostics.assertClean(), /unexpected browser failures/, 'one allowed response cannot hide two console errors');
  });
}

for (const [name, message, response] of [
  ['unmatched URL', resourceMessage({ location: () => ({ url: `${resourceUrl}/other`, lineNumber: 0, columnNumber: 0 }) }), resourceResponse()],
  ['unmatched status', resourceMessage({ text: () => 'Failed to load resource: the server responded with a status of 500 (Internal Server Error)' }), resourceResponse()],
  ['JavaScript console arguments', resourceMessage({ args: () => [{}] }), resourceResponse()],
  ['JavaScript source location', resourceMessage({ location: () => ({ url: resourceUrl, lineNumber: 1, columnNumber: 0 }) }), resourceResponse()],
  ['arbitrary JavaScript error', resourceMessage({ text: () => 'TypeError: Cannot read properties of null (reading useState)' }), resourceResponse()],
  ['invalid hook warning', resourceMessage({ type: () => 'warning', text: () => 'Invalid hook call' }), resourceResponse()],
  ['script HTTP failure', resourceMessage(), resourceResponse({ request: () => ({ resourceType: () => 'script' }) })],
]) {
  test(`HTTP allowance cannot suppress ${name}`, async () => {
    const page = new Page();
    const diagnostics = await collectPortalBrowserFailures(page, 'http://127.0.0.1:1234', { allowResponse: () => true });
    page.emit('response', response);
    page.emit('console', message);
    assert.throws(() => diagnostics.assertClean(), /unexpected browser failures/);
  });
}

test('unpaired native resource error remains a failure', async () => {
  const page = new Page();
  const diagnostics = await collectPortalBrowserFailures(page, 'http://127.0.0.1:1234', { allowResponse: () => true });
  page.emit('console', resourceMessage());
  assert.throws(() => diagnostics.assertClean(), /unexpected browser failures/);
});

test('narrow HTTP allowance does not suppress page errors or invalid hook warnings', async () => {
  const page = new Page();
  const diagnostics = await collectPortalBrowserFailures(page, 'http://127.0.0.1:1234', { allowResponse: (response) => response.status() === 503 });
  page.emit('response', { url: () => 'http://127.0.0.1:1234/v1/state', status: () => 503, request: () => ({ resourceType: () => 'fetch' }) });
  diagnostics.assertClean();
  page.emit('pageerror', new Error('still fails'));
  assert.throws(() => diagnostics.assertClean());
});
