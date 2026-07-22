import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  gotoPublicPortalRoute,
  injectPortalSessionForSurface,
} from '../../helpers/portal-playwright-session.mjs';
import { ROUTES_TO_SCAN } from '../../helpers/portal-routes.mjs';

/**
 * FT-ROUTE-01 — per-route render + backend-wiring smoke.
 *
 * One test per reachable surface (public views + every console RouteId, including
 * all 12 detail routes). Each asserts the page actually mounted its real content and
 * consumed the API, rather than blanking, crashing, or falling back to a "not found"
 * empty state. Assertions use role/text signals (not brittle CSS) so they survive
 * Observatory design tweaks. Complements the concern-oriented journeys/state/
 * provenance/a11y suites with systematic route coverage.
 */

/** Empty-state copy that must NOT appear on a route seeded with a valid entity. */
const NOT_RESOLVED_RE = /\bnot found\b|\bNo [a-z-]+ selected\b/i;

/**
 * Attach listeners that record uncaught page errors and failing backend responses
 * during load. Returns getters so each test can assert a clean load.
 * @param {import('@playwright/test').Page} page
 */
function watchForFailures(page) {
  /** @type {string[]} */
  const pageErrors = [];
  /** @type {string[]} */
  const serverErrors = [];
  /** @type {boolean} */
  let sawApiCall = false;

  page.on('pageerror', (err) => {
    pageErrors.push(err?.message ?? String(err));
  });
  page.on('response', (response) => {
    const url = response.url();
    // Track the app's own control-plane calls; ignore fonts/static/analytics.
    if (/\/(v1|ready|internal)\b/.test(url)) {
      sawApiCall = true;
      if (response.status() >= 500) {
        serverErrors.push(`${response.status()} ${url}`);
      }
    }
  });

  return {
    pageErrors: () => pageErrors,
    serverErrors: () => serverErrors,
    sawApiCall: () => sawApiCall,
  };
}

test.describe('portal route coverage (FT-ROUTE-01)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const routeEntry of ROUTES_TO_SCAN) {
    const label = routeEntry.pathname ?? routeEntry.routeId;

    test(`${label} renders its page and is wired to the API`, async ({ page }) => {
      const baseUrl = getPortalPlaywrightBaseUrl();
      const failures = watchForFailures(page);
      await injectPortalSessionForSurface(page, routeEntry.surface);

      if (routeEntry.surface === 'public') {
        await gotoPublicPortalRoute(page, routeEntry.pathname, baseUrl);
      } else {
        await gotoPortalRoute(page, routeEntry.routeId, baseUrl);
      }

      // 1. React mounted — the boot splash is torn down once the tree commits.
      await expect(page.locator('#boot')).toHaveCount(0);

      // 2. #root is populated (not a blank/crashed shell).
      await expect(page.locator('#root > *')).not.toHaveCount(0);

      if (routeEntry.surface === 'public') {
        // Public shells always render the AstraNull brand mark + word.
        await expect(page.getByText('AstraNull', { exact: false }).first()).toBeVisible();
      } else {
        // 3. Console shell landmark present (app-shell sidebar nav).
        await expect(page.locator('nav[aria-label="Portal"]')).toBeVisible();
        // 4. Seeded detail routes must RESOLVE their entity, not show "… not found".
        //    Detail views fetch their entity in an effect after mount and render a
        //    transient not-found/eyebrow-only state (no <h1>) until both PortalData and
        //    the per-entity fetch settle. Poll for resolution FIRST — this waits out the
        //    async load, after which the real heading is guaranteed present. Checking
        //    the <h1> first would race that transient state under parallel load.
        await expect
          .poll(
            async () => NOT_RESOLVED_RE.test(await page.locator('#root').innerText()),
            {
              message: `Route "${routeEntry.routeId}" rendered a not-found/empty state despite a seeded entity`,
              timeout: 15_000,
            },
          )
          .toBe(false);
        // 5. The resolved route rendered a real heading (page-head or detail view).
        await expect(page.locator('h1').first()).toBeVisible({ timeout: 10_000 });
      }

      // 6. The page consumed the control-plane API (proves data wiring, not static markup).
      expect(failures.sawApiCall(), 'expected at least one /v1 (or /ready|/internal) request').toBe(true);

      // 7. No server crashes and no uncaught client exceptions during load.
      expect(failures.serverErrors(), 'server 5xx during load').toEqual([]);
      expect(failures.pageErrors(), 'uncaught page errors during load').toEqual([]);
    });
  }
});
