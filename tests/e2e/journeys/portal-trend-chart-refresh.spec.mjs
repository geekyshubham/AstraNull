/**
 * Regression for UNCOMMITTED_CHANGES_REVIEW F01 / G03: the readiness trend chart must survive a
 * refresh that shrinks scored history while a point is keyboard-selected. Before the fix the
 * chart kept a numeric index and threw "Cannot read properties of undefined (reading 'runId')".
 *
 * Run history is served through a mutable network mock so the same mounted chart sees
 * 5 -> 2 -> 1 -> 0 scored runs across Dashboard refreshes.
 */
import { expect, test } from '@playwright/test';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';

const VIEWPORTS = [
  { name: 'mobile', width: 390, height: 844 },
  { name: 'desktop', width: 1440, height: 900 },
];
const THEMES = ['dark', 'light'];

/** Five scored runs, oldest first. */
function scoredRun(index) {
  return {
    id: `run_trend_${index}`,
    status: 'completed',
    verdict: 'passed',
    readiness_score: 50 + index * 7,
    created_at: `2026-06-0${index}T10:00:00.000Z`,
    completed_at: `2026-06-0${index}T10:05:00.000Z`,
  };
}
const FIVE_RUNS = [1, 2, 3, 4, 5].map(scoredRun);

/** The "Scored runs" figure value (exact dt match so "Change across scored runs" is excluded). */
function scoredRunsFigure(page) {
  return page.locator('.trend-figure').filter({ has: page.locator('dt', { hasText: /^Scored runs$/ }) }).locator('dd');
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {{ items: object[] }} state
 */
async function mockRunHistory(page, state) {
  await page.route(/\/v1\/test-runs(\?.*)?$/, async (route) => {
    if (route.request().method() !== 'GET') return route.fallback();
    await route.fulfill({ json: { items: state.items } });
  });
}

/**
 * Click the Dashboard header Refresh button from script so focus stays on the chart, which is
 * the state the original crash needed (blur clears the selection).
 * @param {import('@playwright/test').Page} page
 */
async function refreshWithoutMovingFocus(page) {
  const response = page.waitForResponse((res) => /\/v1\/test-runs(\?.*)?$/.test(res.url()) && res.request().method() === 'GET');
  const clicked = await page.evaluate(() => {
    const button = [...document.querySelectorAll('button')].find((node) => node.textContent?.trim() === 'Refresh');
    if (!button) return false;
    button.click();
    return true;
  });
  expect(clicked, 'Dashboard Refresh button is rendered').toBe(true);
  await response;
  // Let React commit the refreshed datasets.
  await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeEnabled();
}

test.describe('readiness trend chart survives shrinking history (F01)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const viewport of VIEWPORTS) {
    for (const theme of THEMES) {
      test(`focused End selection then 5 -> 2 -> 1 -> 0 runs (${viewport.name}, ${theme})`, async ({ page }) => {
        const pageErrors = [];
        page.on('pageerror', (error) => pageErrors.push(error.message));
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await page.addInitScript((value) => {
          try { localStorage.setItem('astranull.theme', value); } catch { /* storage blocked */ }
        }, theme);
        await injectPortalDevHeadersSession(page);
        const history = { items: FIVE_RUNS };
        await mockRunHistory(page, history);

        await page.goto(`${getPortalPlaywrightBaseUrl()}/app#dashboard?tab=risk-trends`, { waitUntil: 'networkidle', timeout: 60_000 });
        await waitForPortalRouteSettled(page);
        if (theme === 'light') {
          await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
        } else {
          await expect(page.locator('html')).not.toHaveAttribute('data-theme', 'light');
        }

        const plot = page.locator('.trend-plot[role="group"]');
        const live = page.locator('.trend-live');
        await expect(plot).toBeVisible();
        await expect(scoredRunsFigure(page)).toContainText('5');

        // Keyboard: focus selects the latest point; Home/End move across the series.
        await plot.focus();
        await expect(plot).toHaveAttribute('data-active-run', 'run_trend_5');
        await page.keyboard.press('Home');
        await expect(plot).toHaveAttribute('data-active-run', 'run_trend_1');
        await page.keyboard.press('End');
        await expect(plot).toHaveAttribute('data-active-run', 'run_trend_5');
        await expect(live).toContainText('Run run_trend_5');

        // Shrink to two runs that no longer include the selected run.
        history.items = FIVE_RUNS.slice(0, 2);
        await refreshWithoutMovingFocus(page);
        await expect(scoredRunsFigure(page)).toContainText('2');
        await expect(plot).toBeVisible();
        await expect(plot).toBeFocused();
        await expect(plot).not.toHaveAttribute('data-active-run', /.+/);
        await expect(live).toHaveText('');

        // The surviving chart is still keyboard-readable.
        await page.keyboard.press('End');
        await expect(plot).toHaveAttribute('data-active-run', 'run_trend_2');
        await expect(live).toContainText('Run run_trend_2');
        await page.keyboard.press('ArrowLeft');
        await expect(plot).toHaveAttribute('data-active-run', 'run_trend_1');

        // One scored run: no line is drawn, the fact is stated instead.
        history.items = FIVE_RUNS.slice(0, 1);
        await refreshWithoutMovingFocus(page);
        await expect(page.locator('.trend-pending')).toContainText('One scored run so far');
        await expect(plot).toHaveCount(0);

        // No runs: empty state.
        history.items = [];
        await refreshWithoutMovingFocus(page);
        await expect(page.locator('.trend-empty[role="status"]')).toContainText('No run history to plot yet');

        // The card and page shell are still mounted; nothing crashed.
        await expect(page.getByRole('heading', { name: 'Readiness trend' })).toBeVisible();
        expect(pageErrors, 'no uncaught page errors during refreshes').toEqual([]);
      });
    }
  }

  test('a selection that survives the refresh stays on the same run id', async ({ page }) => {
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await injectPortalDevHeadersSession(page);
    const history = { items: FIVE_RUNS };
    await mockRunHistory(page, history);
    await page.goto(`${getPortalPlaywrightBaseUrl()}/app#dashboard?tab=risk-trends`, { waitUntil: 'networkidle', timeout: 60_000 });
    await waitForPortalRouteSettled(page);

    const plot = page.locator('.trend-plot[role="group"]');
    await plot.focus();
    await page.keyboard.press('End');
    await expect(plot).toHaveAttribute('data-active-run', 'run_trend_5');

    // Older runs drop off; the selected latest run is still plotted at a new index.
    history.items = FIVE_RUNS.slice(3);
    await refreshWithoutMovingFocus(page);
    await expect(scoredRunsFigure(page)).toContainText('2');
    await expect(plot).toHaveAttribute('data-active-run', 'run_trend_5');
    await expect(page.locator('.trend-live')).toContainText('Run run_trend_5');
    expect(pageErrors).toEqual([]);
  });
});
