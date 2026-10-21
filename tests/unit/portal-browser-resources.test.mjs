import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PORTAL_FONT_STYLESHEET, installPortalBrowserResources } from '../helpers/portal-browser-resources.mjs';
import { injectPortalDevHeadersSession, clearPortalSession, gotoPortalRoute, gotoPublicPortalRoute } from '../helpers/portal-playwright-session.mjs';

class Page {
  registrations = [];
  events = [];
  async route(match, handler) { this.registrations.push({ match, handler }); this.events.push('route'); }
  async addInitScript() { this.events.push('init'); }
  async goto() { this.events.push('goto'); }
  async waitForFunction() {}
}

function requestRoute({ url = PORTAL_FONT_STYLESHEET, method = 'GET', type = 'stylesheet' } = {}) {
  return {
    request: () => ({ url: () => url, method: () => method, resourceType: () => type }),
    responses: [],
    fallbacks: 0,
    async fulfill(value) { this.responses.push(value); },
    async fallback() { this.fallbacks += 1; },
  };
}

test('only the exact shell stylesheet GET uses the explicit local system-font fixture', async () => {
  const page = new Page();
  await installPortalBrowserResources(page);
  const { match, handler } = page.registrations.find(({ match }) => typeof match === 'function');
  assert.equal(match(new URL(PORTAL_FONT_STYLESHEET)), true);
  const route = requestRoute();
  await handler(route);
  assert.equal(route.fallbacks, 0);
  assert.equal(route.responses.length, 1);
  assert.equal(route.responses[0].status, 200);
  assert.equal(route.responses[0].contentType, 'text/css');
  assert.match(route.responses[0].body, /^\/\*.*system-font fallbacks.*Real Google Fonts are not verified.*\*\/$/);
  assert.doesNotMatch(route.responses[0].body, /url\(|@import|https?:|@font-face/i);
});

test('only favicon image GETs on the dedicated origin use the icon fixture', async () => {
  const page = new Page();
  await installPortalBrowserResources(page);
  const [{ match, handler }] = page.registrations;
  const url = 'https://icons.duckduckgo.com/ip3/example.com.ico';
  assert.equal(match(new URL(url)), true);
  const route = requestRoute({ url, type: 'image' });
  await handler(route);
  assert.equal(route.responses[0].contentType, 'image/svg+xml');
  for (const options of [{ method: 'POST', type: 'image' }, { type: 'fetch' }, { url: `${url}?unexpected=1`, type: 'image' }, { url: 'https://example.test/ip3/example.com.ico', type: 'image' }]) {
    const other = requestRoute({ url, ...options });
    await handler(other);
    assert.equal(other.fallbacks, 1);
    assert.deepEqual(other.responses, []);
  }
});

for (const url of [
  PORTAL_FONT_STYLESHEET.replace('fonts.googleapis.com', 'example.test'),
  `${PORTAL_FONT_STYLESHEET}&unexpected=1`,
  PORTAL_FONT_STYLESHEET.replace('display=swap', 'display=block'),
  'https://fonts.gstatic.com/font.woff2',
  'http://127.0.0.1:1234/app',
]) {
  test(`unrelated URL is neither matched nor fulfilled: ${url}`, async () => {
    const page = new Page();
    await installPortalBrowserResources(page);
    const { match, handler } = page.registrations.find(({ match }) => typeof match === 'function');
    assert.equal(match(new URL(url)), false);
    const route = requestRoute({ url });
    await handler(route);
    assert.equal(route.fallbacks, 1);
    assert.deepEqual(route.responses, []);
  });
}

for (const options of [{ method: 'POST' }, { method: 'HEAD' }, { type: 'xhr' }, { type: 'fetch' }, { type: 'document' }]) {
  test(`matching URL with another method/type falls through: ${JSON.stringify(options)}`, async () => {
    const page = new Page();
    await installPortalBrowserResources(page);
    const route = requestRoute(options);
    await page.registrations.find(({ match }) => typeof match === 'function').handler(route);
    assert.equal(route.fallbacks, 1);
    assert.deepEqual(route.responses, []);
  });
}

test('concurrent installation is idempotent per page, not global', async () => {
  const first = new Page();
  const second = new Page();
  await Promise.all([installPortalBrowserResources(first), installPortalBrowserResources(first), installPortalBrowserResources(second)]);
  await installPortalBrowserResources(first);
  assert.equal(first.registrations.length, 1);
  assert.equal(second.registrations.length, 1);
  assert.equal(typeof first.registrations[0].match, 'function');
});

test('favicon requests use an owned inert image fixture, not the external service', async () => {
  const page = new Page();
  await installPortalBrowserResources(page);
  const [{ handler }] = page.registrations;
  const route = requestRoute({ url: 'https://icons.duckduckgo.com/ip3/checkout.acme.com.ico', type: 'image' });
  await handler(route);
  assert.equal(route.fallbacks, 0);
  assert.equal(route.responses.length, 1);
  assert.equal(route.responses[0].contentType, 'image/svg+xml');
  assert.doesNotMatch(route.responses[0].body, /href=|url\(|<script|<image/);
});

test('failed route installation rejects without masking the failure', async () => {
  const page = new Page();
  page.route = async () => { throw new Error('registration failed'); };
  await assert.rejects(installPortalBrowserResources(page), /registration failed/);
});

for (const [name, invoke] of [
  ['customer session', (page) => injectPortalDevHeadersSession(page)],
  ['public session', (page) => clearPortalSession(page)],
  ['customer route', (page) => gotoPortalRoute(page, 'dashboard', 'http://127.0.0.1:1234')],
  ['public route', (page) => gotoPublicPortalRoute(page, '/login', 'http://127.0.0.1:1234')],
]) {
  test(`${name} installs resources before init or navigation`, async () => {
    const page = new Page();
    await invoke(page);
    assert.deepEqual(page.events, ['route', name.endsWith('session') ? 'init' : 'goto']);
  });
}

test('both shell stylesheet declarations still match the pinned fixture URL', () => {
  for (const file of ['../../apps/web/index.html', '../../apps/web/react/index.html']) {
    const shell = readFileSync(new URL(file, import.meta.url), 'utf8');
    const urls = [...shell.matchAll(/href="(https:\/\/fonts\.googleapis\.com\/css2\?[^"\s]+)"/g)].map((match) => match[1].replaceAll('&amp;', '&'));
    assert.deepEqual(urls, [PORTAL_FONT_STYLESHEET], file);
  }
});
