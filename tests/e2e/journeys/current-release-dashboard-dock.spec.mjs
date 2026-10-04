/**
 * Current release: the dashboard reflows by the width it is given. A docked evidence inspector
 * narrows the main column; the investigation context beside it (what to fix first, target posture,
 * key metrics) must stay readable instead of keeping a squeezed two-column grid. Baseline seed only:
 * the finding's missing evidence reference stays "not recorded"; nothing is fabricated.
 */
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';

const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
const EVIDENCE_TRIGGER = /^View evidence for Block direct access/;

async function openDashboard(page, { width, height = 900, theme }) {
  await page.setViewportSize({ width, height });
  await page.addInitScript((value) => {
    try { localStorage.setItem('astranull.theme', value); } catch { /* storage blocked */ }
  }, theme);
  await injectPortalDevHeadersSession(page);
  await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
  await expect(page.getByRole('heading', { level: 1, name: 'Readiness overview' })).toBeVisible();
}

/** Layout of the investigation context, measured from the rendered page. */
async function measure(page) {
  return page.evaluate(() => {
    const rect = (selector) => document.querySelector(selector)?.getBoundingClientRect() ?? null;
    const grid = document.querySelector('.an-dash-grid');
    const tableWrap = document.querySelector('.dash-area-targets .table-wrap');
    const verdictHeader = [...document.querySelectorAll('.dash-area-targets th')].find((node) => /Recorded verdict/.test(node.textContent ?? ''));
    return {
      main: rect('.dashboard-page'),
      columns: grid ? getComputedStyle(grid).gridTemplateColumns.split(' ').length : 0,
      fixTitle: rect('.dash-area-fixes .fix-row strong'),
      tableClip: tableWrap ? tableWrap.scrollWidth - tableWrap.clientWidth : null,
      verdictHeader: verdictHeader?.getBoundingClientRect() ?? null,
      tableWrap: tableWrap?.getBoundingClientRect() ?? null,
      kpiColumns: getComputedStyle(document.querySelector('.dashboard-kpis')).gridTemplateColumns.split(' ').length,
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    };
  });
}

async function blockingViolations(page) {
  await page.evaluate(() => Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => undefined))));
  const results = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  return results.violations
    .filter((violation) => violation.impact === 'critical' || violation.impact === 'serious')
    .map((violation) => `${violation.id}: ${violation.nodes.slice(0, 3).map((node) => node.target.join(' ')).join(' | ')}`);
}

test.describe('current release: dashboard beside the docked inspector', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const width of [1440, 1512]) {
    for (const theme of ['dark', 'light']) {
      test(`docked at ${width}px, ${theme}: context stays readable, keyboard close restores focus and scroll`, async ({ page }) => {
        await openDashboard(page, { width, theme });

        const undocked = await measure(page);
        expect(undocked.columns, 'full width keeps the two-column overview').toBe(2);

        const trigger = page.getByRole('button', { name: EVIDENCE_TRIGGER });
        await trigger.scrollIntoViewIfNeeded();
        const scrollBefore = await page.evaluate(() => window.scrollY);
        await trigger.focus();
        await page.keyboard.press('Enter');
        const docked = page.locator('aside.inspector-panel[data-mode="docked"]');
        await expect(docked).toBeVisible();
        // The baseline finding cites no evidence reference; that stays visible as "not recorded".
        await expect(docked).toContainText('Supporting evidence not recorded for this result');

        const beside = await measure(page);
        const dockBox = await docked.boundingBox();
        expect(beside.main.right, 'dashboard content ends before the dock begins').toBeLessThanOrEqual(dockBox.x + 1);
        expect(beside.main.width).toBeLessThan(undocked.main.width);
        // With less room, priority and posture stack instead of squeezing two columns.
        expect(beside.columns).toBe(1);
        expect(beside.fixTitle.width, 'fix titles get a readable line').toBeGreaterThanOrEqual(400);
        expect(beside.kpiColumns).toBeLessThanOrEqual(2);
        // The posture table fits: no clipped columns and the verdict column is on screen.
        expect(beside.tableClip).toBeLessThanOrEqual(1);
        expect(beside.verdictHeader.right).toBeLessThanOrEqual(beside.tableWrap.right + 1);
        expect(beside.overflow).toBeLessThanOrEqual(1);
        expect(await blockingViolations(page)).toEqual([]);

        await page.keyboard.press('Escape');
        await expect(docked).toHaveCount(0);
        await expect(trigger).toBeFocused();
        expect(Math.abs((await page.evaluate(() => window.scrollY)) - scrollBefore)).toBeLessThanOrEqual(2);
        await expect.poll(async () => (await measure(page)).columns).toBe(2);
      });
    }
  }

  for (const viewport of [
    { width: 375, height: 812, theme: 'dark', mode: 'sheet' },
    { width: 768, height: 1024, theme: 'light', mode: 'drawer' },
    { width: 1024, height: 900, theme: 'dark', mode: 'drawer' },
  ]) {
    test(`undocked ${viewport.width}px, ${viewport.theme}: full main layout and the ${viewport.mode} keep focus`, async ({ page }) => {
      await openDashboard(page, viewport);
      const layout = await measure(page);
      expect(layout.overflow).toBeLessThanOrEqual(1);
      // Two columns only when each keeps a readable width (fix list and posture table both fit).
      if (viewport.width < 1000) expect(layout.columns).toBe(1);
      expect(layout.fixTitle.width).toBeGreaterThanOrEqual(200);
      expect(layout.tableClip === 0 || viewport.width < 600, 'tables fit except where a phone scrolls them').toBe(true);

      const trigger = page.getByRole('button', { name: EVIDENCE_TRIGGER });
      await trigger.scrollIntoViewIfNeeded();
      await trigger.focus();
      await page.keyboard.press('Enter');
      const panel = page.locator(`dialog.inspector-panel[data-mode="${viewport.mode}"]`);
      await expect(panel).toBeVisible();
      await expect(page.locator('aside.inspector-panel[data-mode="docked"]')).toHaveCount(0);
      // Opening an overlay does not reflow the page behind it.
      expect((await measure(page)).columns).toBe(layout.columns);
      await page.keyboard.press('Escape');
      await expect(panel).toBeHidden();
      await expect(trigger).toBeFocused();
    });
  }
});
