import assert from 'node:assert/strict';
import { installPortalBrowserResources } from './portal-browser-resources.mjs';

/** Install before navigation. API-failure tests may allow HTTP responses, never JS failures. */
export async function collectPortalBrowserFailures(page, baseUrl, { allowResponse = () => false } = {}) {
  const origin = new URL(baseUrl).origin;
  const failures = [];
  const modules = new Set();
  const responseAllowances = new Map();
  const resourceConsoleKeys = new WeakMap();
  const responseKey = (url, status) => JSON.stringify([url, status]);
  const own = (url) => { try { return new URL(url).origin === origin; } catch { return false; } };
  page.on('console', (message) => {
    if (message.type() === 'error' || /invalid hook call/i.test(message.text())) {
      const failure = { kind: 'console', message: message.text(), location: message.location() };
      failures.push(failure);
      const status = /^Failed to load resource: the server responded with a status of ([45]\d{2}) \([^\r\n]*\)$/.exec(failure.message);
      // Native resource errors have no JavaScript arguments or source position.
      if (status && message.type() === 'error' && typeof message.args === 'function' && message.args().length === 0
        && failure.location.lineNumber === 0 && failure.location.columnNumber === 0 && own(failure.location.url)) {
        resourceConsoleKeys.set(failure, responseKey(failure.location.url, Number(status[1])));
      }
    }
  });
  page.on('pageerror', (error) => failures.push({ kind: 'pageerror', message: error.stack ?? error.message }));
  page.on('requestfailed', (request) => {
    if (own(request.url()) && ['script', 'stylesheet', 'document'].includes(request.resourceType())) {
      failures.push({ kind: 'module-load', url: request.url(), message: request.failure()?.errorText });
    }
  });
  page.on('response', (response) => {
    const request = response.request();
    if (!own(response.url())) return;
    if (request.resourceType() === 'script') modules.add(response.url());
    if (response.status() < 400) return;
    const allowed = ['fetch', 'xhr'].includes(request.resourceType()) && allowResponse(response);
    if (allowed) {
      const key = responseKey(response.url(), response.status());
      responseAllowances.set(key, (responseAllowances.get(key) ?? 0) + 1);
    } else if (['script', 'stylesheet', 'document'].includes(request.resourceType()) || response.status() >= 500) {
      failures.push({ kind: 'response', status: response.status(), url: response.url() });
    }
  });
  await page.exposeBinding('__astranullStartupRejection', (_source, message) => {
    failures.push({ kind: 'unhandledrejection', message });
  });
  await page.addInitScript(() => {
    window.addEventListener('unhandledrejection', (event) => {
      const reason = event.reason;
      void window.__astranullStartupRejection(String(reason?.stack ?? reason?.message ?? reason));
    });
  });
  return {
    failures,
    modules,
    assertClean() {
      // Pair at assertion time: console/response ordering varies between browsers.
      const remaining = new Map(responseAllowances);
      const unexpected = failures.filter((failure) => {
        const key = resourceConsoleKeys.get(failure);
        const count = key === undefined ? 0 : (remaining.get(key) ?? 0);
        if (!count) return true;
        remaining.set(key, count - 1);
        return false;
      });
      assert.deepEqual(unexpected, [], 'unexpected browser failures (including first navigation)');
    },
  };
}

/** No retries, sleeps or recovery reload: a committed shell and resolved seeded content are required. */
export async function assertPortalInitialLoad(page, baseUrl, { hash = 'dashboard', timeout = 120_000, onDiagnostics = () => {} } = {}) {
  const diagnostics = await collectPortalBrowserFailures(page, baseUrl);
  onDiagnostics(diagnostics);
  try {
    await installPortalBrowserResources(page);
    await page.goto(`${baseUrl}/app#${hash}`, { waitUntil: 'networkidle', timeout });
    diagnostics.assertClean();
    await page.locator('#portal-main').waitFor({ state: 'visible', timeout });
    await page.waitForFunction(() => !document.querySelector('#boot')
      && Boolean(document.querySelector('#root > *'))
      && Boolean(document.querySelector('#portal-main h1')), undefined, { timeout });
  } catch (error) {
    diagnostics.assertClean();
    throw error;
  }
  diagnostics.assertClean();
  return diagnostics;
}
