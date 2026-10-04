/**
 * Current release accessibility: the shared evidence inspector (docked, drawer and sheet modes),
 * the unified target workspace and the findings queue, in dark and light themes, plus keyboard
 * focus restoration and reduced motion. Synthetic isolated store; UI from live source via Vite.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { createServer as createViteServer } from 'vite';
import { PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession } from '../helpers/portal-playwright-session.mjs';

const ids = PORTAL_BASELINE_IDS;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
let vite = null;
let webBase = '';

async function settled(page) {
  await page.evaluate(() => Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => undefined))));
}

async function blockingViolations(page, include) {
  await settled(page);
  let builder = new AxeBuilder({ page }).withTags(AXE_TAGS);
  if (include) builder = builder.include(include);
  const results = await builder.analyze();
  return results.violations
    .filter((violation) => violation.impact === 'critical' || violation.impact === 'serious')
    .map((violation) => `${violation.id} (${violation.impact}): ${violation.help} :: ${violation.nodes.slice(0, 3).map((node) => `${node.target.join(' ')} ${node.any?.[0]?.message ?? ''}`).join(' | ')}`);
}

async function open(page, hash, theme) {
  await page.addInitScript((value) => {
    try { localStorage.setItem('astranull.theme', value); } catch { /* storage blocked */ }
  }, theme);
  await injectPortalDevHeadersSession(page);
  await page.goto(`${webBase}/app#${hash}`, { waitUntil: 'networkidle', timeout: 120_000 });
  await page.locator('#portal-main').waitFor({ timeout: 60_000 });
}

const MODES = [
  { name: 'docked, dark', width: 1440, height: 900, theme: 'dark', selector: 'aside.inspector-panel[data-mode="docked"]' },
  { name: 'drawer, light', width: 1024, height: 900, theme: 'light', selector: 'dialog.inspector-panel[data-mode="drawer"]' },
  { name: 'sheet, dark', width: 375, height: 812, theme: 'dark', selector: 'dialog.inspector-panel[data-mode="sheet"]' },
];

test.describe.configure({ mode: 'serial' });

test.describe('current release inspector accessibility (EI-10)', () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(240_000);
    await startPortalPlaywrightServer();
    const apiBase = getPortalPlaywrightBaseUrl();
    vite = await createViteServer({
      configFile: path.join(ROOT, 'vite.config.ts'),
      root: path.join(ROOT, 'apps/web/react'),
      logLevel: 'error',
      server: { host: '127.0.0.1', port: 0, strictPort: false, hmr: false, proxy: { '/v1': apiBase, '/ready': apiBase, '/internal': apiBase } },
    });
    await vite.listen();
    webBase = `http://127.0.0.1:${vite.httpServer.address().port}`;
    const warm = await browser.newPage();
    await injectPortalDevHeadersSession(warm);
    await warm.goto(`${webBase}/app#dashboard`, { waitUntil: 'networkidle', timeout: 180_000 }).catch(() => undefined);
    await warm.waitForTimeout(6000);
    await warm.reload({ waitUntil: 'networkidle' }).catch(() => undefined);
    await warm.locator('#portal-main').waitFor({ timeout: 120_000 }).catch(() => undefined);
    await warm.close();
  });

  test.afterAll(async () => {
    await vite?.close();
    await stopPortalPlaywrightServer();
  });

  for (const mode of MODES) {
    test(`finding inspector has no serious axe violations (${mode.name})`, async ({ page }) => {
      test.setTimeout(120_000);
      await page.setViewportSize({ width: mode.width, height: mode.height });
      await open(page, `findings?inspect=finding&ev_finding=${ids.findingId}`, mode.theme);
      const panel = page.locator(mode.selector);
      await expect(panel).toBeVisible();
      await expect(panel.getByRole('heading', { name: 'Finding evidence' })).toBeVisible();
      await expect(panel.getByRole('heading', { name: 'Finding evidence' })).toBeFocused();
      expect(await blockingViolations(page, '.inspector-panel')).toEqual([]);
    });
  }

  test('target workspace and provider inspector pass axe in both themes', async ({ page }) => {
    test.setTimeout(150_000);
    for (const theme of ['dark', 'light']) {
      await page.setViewportSize({ width: 1440, height: 1000 });
      await open(page, `target-detail?id=${ids.targetId}`, theme);
      await expect(page.getByRole('heading', { name: 'Protection observations' })).toBeVisible();
      expect(await blockingViolations(page, '#portal-main'), `target workspace ${theme}`).toEqual([]);
      await page.getByRole('button', { name: 'How WAF was identified' }).click();
      await expect(page.locator('.inspector-panel')).toBeVisible();
      expect(await blockingViolations(page, '.inspector-panel'), `provider inspector ${theme}`).toEqual([]);
    }
  });

  test('keyboard opens the inspector, Escape closes it and focus returns to the trigger', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1024, height: 900 });
    await open(page, `target-detail?id=${ids.targetId}`, 'dark');
    const trigger = page.getByRole('button', { name: 'How CDN was identified' });
    await trigger.focus();
    await page.keyboard.press('Enter');
    const drawer = page.locator('dialog.inspector-panel[data-mode="drawer"]');
    await expect(drawer).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(drawer).toHaveCount(0);
    await expect(trigger).toBeFocused();
  });

  test('reduced motion renders the inspector without animation', async ({ page }) => {
    test.setTimeout(120_000);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, `findings?inspect=finding&ev_finding=${ids.findingId}`, 'light');
    const panel = page.locator('aside.inspector-panel');
    await expect(panel).toBeVisible();
    expect(await panel.evaluate((node) => getComputedStyle(node).animationName)).toBe('none');
  });

  test('findings queue with the docked inspector passes axe', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, `findings?inspect=finding&ev_finding=${ids.findingId}`, 'dark');
    await expect(page.locator('aside.inspector-panel')).toBeVisible();
    expect(await blockingViolations(page)).toEqual([]);
  });

  for (const width of [375, 1440]) {
    test(`dashboard coverage and the server cohort list pass axe at ${width}px in both themes`, async ({ page }) => {
      test.setTimeout(150_000);
      await page.emulateMedia({ reducedMotion: 'reduce' });
      await page.setViewportSize({ width, height: 900 });
      for (const theme of ['dark', 'light']) {
        await open(page, 'dashboard', theme);
        const coverage = page.locator('section.declared-coverage');
        await expect(coverage.getByRole('group', { name: 'Count by' })).toBeVisible();
        expect(await blockingViolations(page, 'section.declared-coverage'), `coverage ${width} ${theme}`).toEqual([]);
        await open(page, 'targets?family=waf&family_status=not_checked&unit=hostname', theme);
        await expect(page.locator('section.cohort-panel .cohort-count')).toBeVisible();
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        expect(overflow, `no page overflow ${width} ${theme}`).toBeLessThanOrEqual(0);
        expect(await blockingViolations(page, '#portal-main'), `cohort ${width} ${theme}`).toEqual([]);
      }
    });
  }

  for (const width of [375, 768, 1024, 1440]) {
    for (const theme of ['dark', 'light']) {
      test(`target workspace and provider inspector at ${width}px ${theme}: axe, no page overflow, visible focus`, async ({ page }) => {
        test.setTimeout(120_000);
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await page.setViewportSize({ width, height: 900 });
        await open(page, `target-detail?id=${ids.targetId}`, theme);
        await expect(page.getByRole('heading', { name: 'Protection observations' })).toBeVisible();
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        expect(overflow, 'no page-level horizontal overflow').toBeLessThanOrEqual(0);
        expect(await blockingViolations(page, '#portal-main'), `workspace ${width} ${theme}`).toEqual([]);

        const trigger = page.getByRole('button', { name: 'How CDN was identified' });
        await trigger.focus();
        await page.keyboard.press('Enter');
        const panel = page.locator('.inspector-panel');
        await expect(panel).toBeVisible();
        const heading = panel.getByRole('heading', { level: 2 });
        await expect(heading).toBeFocused();
        await page.keyboard.press('Tab');
        const focusOutline = await page.evaluate(() => {
          const active = document.activeElement;
          if (!active) return '';
          const style = getComputedStyle(active);
          return `${style.outlineStyle} ${style.outlineWidth} ${style.boxShadow}`;
        });
        expect(focusOutline, 'the next focused control shows a visible focus indicator').toMatch(/solid|auto|rgb/);
        expect(await blockingViolations(page, '.inspector-panel'), `inspector ${width} ${theme}`).toEqual([]);
        await page.keyboard.press('Escape');
        await expect(panel).toHaveCount(0);
        await expect(trigger).toBeFocused();
      });
    }
  }
});
