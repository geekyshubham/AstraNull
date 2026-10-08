import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

/**
 * FT-INTERACT-01 — interactive control + feedback correctness.
 *
 * Beyond "does the page render", these tests CLICK mutating controls and assert the
 * app produces correct feedback: a success/error banner (role=status|alert), an
 * in-flight loading affordance, and a real backend request (no silent no-op that
 * still reports success). Includes regression coverage for the audit findings:
 *   - finding-detail Retest fired no request for some kinds yet showed success.
 *   - direct target intake and authorization feedback must remain visible.
 */

const BANNER = '.form-banner, [role="status"], [role="alert"], .success-panel';

test.describe('portal interaction feedback (FT-INTERACT-01)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('finding triage Save shows a feedback banner and PATCHes the finding', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);

    /** @type {string[]} */
    const patches = [];
    page.on('request', (req) => {
      if (req.method() === 'PATCH' && /\/v1\/findings\//.test(req.url())) patches.push(req.url());
    });

    await gotoPortalRoute(page, 'finding-detail', baseUrl);
    const saveBtn = page.getByRole('button', { name: 'Save triage' });
    await expect(saveBtn).toBeVisible({ timeout: 10_000 });
    await saveBtn.click();

    // Feedback banner appears (success), and a real PATCH was issued.
    await expect(page.locator(BANNER).filter({ hasText: /Triage updated|updated|saved/i }).first())
      .toBeVisible({ timeout: 10_000 });
    expect(patches.length, 'triage save must PATCH /v1/findings/:id').toBeGreaterThan(0);
  });

  test('finding retest is reviewed, sends nothing until confirmed, and never reports success without a request (regression)', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);

    /** @type {string[]} */
    const retestCalls = [];
    let failNext = true;
    // Retest POSTs are answered in the browser so no probe is dispatched by the dev server.
    await page.route(/\/v1\/(test-runs|waf\/validations|waf\/cve-pipeline\/[^/]+\/retest)$/, async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      retestCalls.push(route.request().url());
      if (failNext) {
        failNext = false;
        return route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: 'safe_window_closed', message: 'The safe window for this target is closed.' }) });
      }
      return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 'run_retest_example', status: 'queued' }) });
    });

    await gotoPortalRoute(page, 'finding-detail', baseUrl);
    const reviewBtn = page.getByRole('button', { name: 'Review retest', exact: true });
    await expect(reviewBtn).toBeEnabled({ timeout: 10_000 });
    await reviewBtn.click();

    const review = page.locator('dialog.modal-confirm[open]').filter({ hasText: 'Review this retest' });
    await expect(review).toBeVisible();
    await expect(review).toContainText('Target');
    await expect(review).toContainText('Check');
    await expect(review).toContainText('The original evidence stays.');
    expect(retestCalls, 'opening the review must not start a retest').toEqual([]);
    await review.getByRole('button', { name: 'Cancel' }).click();
    await expect(review).toHaveCount(0);
    expect(retestCalls, 'cancelling the review must not start a retest').toEqual([]);

    await reviewBtn.click();
    await page.locator('dialog.modal-confirm[open]').getByRole('button', { name: 'Start retest' }).click();
    await expect.poll(() => retestCalls.length).toBe(1);
    await expect(page.locator(BANNER).filter({ hasText: /safe window|safe_window_closed|could not|failed/i }).first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(BANNER).filter({ hasText: /Retest started/i })).toHaveCount(0);

    if (await page.locator('dialog.modal-confirm[open]').count() === 0) await reviewBtn.click();
    await page.locator('dialog.modal-confirm[open]').getByRole('button', { name: 'Start retest' }).click();
    await expect(page.locator(BANNER).filter({ hasText: /Retest started/i }).first()).toBeVisible({ timeout: 10_000 });
    expect(retestCalls, 'success banner requires a real retest request').toHaveLength(2);
  });

  test('direct intake surfaces validation errors beside the form without dispatching traffic', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'targets', getPortalPlaywrightBaseUrl());
    await page.getByRole('button', { name: 'Add target', exact: true }).click();
    const form = page.locator('#target-declare-form');
    await form.locator('input[name="value"]').fill('   ');
    await form.getByRole('button', { name: 'Add target', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Target value is required.' })).toBeVisible();
    await expect(form).toBeVisible();
  });

  test('a directly added domain keeps its issued TXT challenge visible after refresh', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'targets', getPortalPlaywrightBaseUrl());
    await page.getByRole('button', { name: 'Add target', exact: true }).click();
    const domain = `pw-dns-${Date.now()}.example.com`;
    const issued = page.waitForResponse((r) => /\/dns-ownership\/issue$/.test(r.url()) && r.request().method() === 'POST');
    const form = page.locator('#target-declare-form');
    await form.locator('input[name="value"]').fill(domain);
    await form.getByRole('button', { name: 'Add target', exact: true }).click();
    const challenge = (await (await issued).json()).challenge;
    await expect(page).toHaveURL(/#target-detail\?id=/);
    await expect(page.locator('.td-dns')).toContainText(challenge.record_name);
    await expect(page.locator('.td-dns')).toContainText(challenge.record_value);
    await page.reload({ waitUntil: 'networkidle' });
    await expect(page.locator('.td-dns')).toContainText(challenge.record_value);
    const checked = page.waitForResponse((r) => /\/dns-ownership\/verify$/.test(r.url()) && r.request().method() === 'POST');
    await page.getByRole('button', { name: 'Check now', exact: true }).click();
    expect((await checked).status()).toBe(200);
    await expect(page.locator('.td-dns')).toContainText(challenge.record_value);
  });

  test('finding evidence export downloads a file (regression)', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'finding-detail', baseUrl);
    const findingDownload = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export evidence', exact: true }).click();
    const findingFile = await findingDownload;
    expect(findingFile.suggestedFilename()).toMatch(/^finding-.+-evidence\.json$/);
    const bundle = JSON.parse(readFileSync(await findingFile.path(), 'utf8'));
    expect(bundle.custody?.content_sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  test('report-detail exports each format from the single Export menu (regression)', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'report-detail', baseUrl);
    const exportButton = page.getByRole('button', { name: 'Export', exact: true });
    await expect(exportButton).toHaveCount(1);
    for (const [label, ext] of [[/^JSON/, 'json'], [/^Markdown/, 'md'], [/^HTML/, 'html']]) {
      await exportButton.click();
      const menu = page.getByRole('list', { name: /^Export / });
      const download = page.waitForEvent('download');
      await menu.getByRole('button', { name: label }).click();
      expect((await download).suggestedFilename()).toMatch(new RegExp(`\\.${ext}$`));
      await expect(menu).toHaveCount(0);
    }
  });

  test('direct removal drops the declared domain row without a reload', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'targets', baseUrl);
    await page.getByRole('button', { name: 'Add target', exact: true }).click();
    const domain = `pw-rm-${Date.now()}.example.com`;
    const form = page.locator('#target-declare-form');
    await form.locator('input[name="value"]').fill(domain);
    await form.getByRole('button', { name: 'Add target', exact: true }).click();
    await expect(page).toHaveURL(/#target-detail\?id=/);
    await gotoPortalRoute(page, 'targets', baseUrl);
    const removeButton = page.getByRole('button', { name: `Remove target ${domain}` });
    await expect(removeButton).toBeVisible();
    await removeButton.click();
    await page.locator('dialog[open]').getByRole('button', { name: 'Remove target', exact: true }).click();
    await expect(removeButton).toHaveCount(0);
  });
});
