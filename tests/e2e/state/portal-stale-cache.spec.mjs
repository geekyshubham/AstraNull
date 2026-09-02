import { expect, test } from '@playwright/test';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

const FRESH_SECRET = {
  id: 'sec_settings_current',
  name: 'fresh-settings-secret',
  purpose: 'integration_credential',
  rotation: 2,
  updated_at: '2026-09-01T20:00:00.000Z',
};

const STALE_SECRET = {
  id: 'sec_integrations_stale',
  name: 'stale-integrations-secret',
  purpose: 'integration_credential',
  rotation: 1,
  updated_at: '2026-09-01T19:00:00.000Z',
};

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

test.describe('portal route-generation cache authority', () => {
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('late Integrations secrets cannot reappear on Dashboard → Settings', async ({ page }) => {
    await startPortalPlaywrightServer();
    const baseUrl = getPortalPlaywrightBaseUrl();
    const staleRelease = deferred();
    const staleRequestStarted = deferred();
    let secretRequestCount = 0;

    // Record when each /v1/secrets body has been consumed by the served bundle.
    // Request ordinals are assigned before fetch, so the delayed Integrations
    // response remains #1 even though Settings (#2) resolves first.
    await page.addInitScript(() => {
      const nativeFetch = window.fetch.bind(window);
      let secretRequestOrdinal = 0;
      window.__astranullSecretJsonReads = [];
      window.fetch = (...args) => {
        const input = args[0];
        const rawUrl = typeof input === 'string' ? input : input.url;
        const isSecretsRequest = new URL(rawUrl, window.location.origin).pathname === '/v1/secrets';
        const ordinal = isSecretsRequest ? ++secretRequestOrdinal : 0;
        return nativeFetch(...args).then((response) => {
          if (!ordinal) return response;
          const readJson = response.json.bind(response);
          response.json = async () => {
            const payload = await readJson();
            window.__astranullSecretJsonReads.push(ordinal);
            return payload;
          };
          return response;
        });
      };
    });

    await page.route('**/v1/secrets', async (route) => {
      secretRequestCount += 1;
      if (secretRequestCount === 1) {
        staleRequestStarted.resolve();
        await staleRelease.promise;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ items: [STALE_SECRET] }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ items: [FRESH_SECRET] }),
      });
    });

    try {
      await injectPortalDevHeadersSession(page);
      await gotoPortalRoute(page, 'dashboard', baseUrl);

      await page.getByRole('button', { name: 'Integrations', exact: true }).click();
      await staleRequestStarted.promise;

      await page.getByRole('button', { name: 'Settings', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();
      await page.getByRole('tab', { name: 'Security', exact: true }).click();
      await expect(page.getByText(FRESH_SECRET.name, { exact: true })).toBeVisible();
      await expect(page.getByText(STALE_SECRET.name, { exact: true })).toHaveCount(0);

      staleRelease.resolve();
      await page.waitForFunction(() => window.__astranullSecretJsonReads.includes(1));

      // The old result is rejected by React's generation gate.
      await expect(page.getByText(FRESH_SECRET.name, { exact: true })).toBeVisible();
      await expect(page.getByText(STALE_SECRET.name, { exact: true })).toHaveCount(0);

      // It must also be rejected by the shared cache gate. Settings reuses the
      // cache on this revisit, so a third network request cannot mask poisoning.
      await page.getByRole('button', { name: 'Dashboard', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'Readiness overview', exact: true })).toBeVisible();
      await page.getByRole('button', { name: 'Settings', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();
      await page.getByRole('tab', { name: 'Security', exact: true }).click();

      expect(secretRequestCount).toBe(2);
      await expect(page.getByText(FRESH_SECRET.name, { exact: true })).toBeVisible();
      await expect(page.getByText(STALE_SECRET.name, { exact: true })).toHaveCount(0);
    } finally {
      staleRelease.resolve();
    }
  });
});
