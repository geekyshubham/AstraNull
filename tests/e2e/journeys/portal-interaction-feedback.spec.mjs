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
 *   - target-group onboard/LOA modal errors rendered behind the native <dialog>.
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

  test('onboard modal surfaces validation errors INSIDE the open dialog (regression)', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-group-detail', baseUrl, {
      entityIds: { 'target-group-detail': PORTAL_BASELINE_IDS.targetGroupId },
    });

    // Open the onboard modal (trigger is the "Edit targets" button; the "+ Add Target"
    // label only appears in the empty state, and the baseline group has a target).
    const onboardBtn = page.getByRole('button', { name: /Edit targets|Add Target/i }).first();
    await expect(onboardBtn).toBeVisible({ timeout: 10_000 });
    await onboardBtn.click();

    const dialog = page.locator('dialog.detail-modal[open]');
    await expect(dialog).toBeVisible();

    // Submit a whitespace-only domain (bypasses browser `required`) to force validation error.
    const domain = dialog.locator('input[name="value"]').first();
    await domain.fill('   ');
    await dialog.getByRole('button', { name: /Add & issue target-bound challenge/i }).click();

    // The error banner must be visible WITHIN the dialog (not behind its backdrop).
    await expect(dialog.locator('.form-banner.error, [role="alert"]').first())
      .toBeVisible({ timeout: 5_000 });
  });

  test('a newly added domain keeps its issued TXT challenge visible (regression)', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-group-detail', baseUrl, {
      entityIds: { 'target-group-detail': PORTAL_BASELINE_IDS.targetGroupId },
    });
    await page.getByRole('button', { name: /Edit targets|Add Target/i }).first().click();
    const dialog = page.locator('dialog.detail-modal[open]');
    await expect(dialog).toBeVisible();

    const domain = `pw-dns-${Date.now()}.example.com`;
    const issued = page.waitForResponse((r) => /\/dns-ownership\/issue$/.test(r.url()) && r.request().method() === 'POST');
    await dialog.locator('input[name="value"]').first().fill(domain);
    await dialog.getByRole('button', { name: /Add & issue target-bound challenge/i }).click();
    const challenge = (await (await issued).json()).challenge;

    // The new target reaches entity.targets only after the parent refresh. The selection must
    // survive that window, so the record the operator has to publish is actually shown.
    await expect(dialog.locator('.dns-fields')).toContainText(challenge.record_name, { timeout: 10_000 });
    await expect(dialog.locator('.dns-fields')).toContainText(challenge.record_value);
    await page.waitForTimeout(1500);
    await expect(dialog.locator('.dns-fields')).toContainText(challenge.record_value);

    await dialog.getByRole('button', { name: 'Check now', exact: true }).click();
    await expect(dialog.locator('.dns-footer')).not.toContainText('Not recorded', { timeout: 10_000 });
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

  test('removing a target drops its row from the group detail without a reload (regression)', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-group-detail', baseUrl, {
      entityIds: { 'target-group-detail': PORTAL_BASELINE_IDS.targetGroupId },
    });
    // Declare a throwaway target so the baseline fixture targets are untouched.
    await page.getByRole('button', { name: /Edit targets|Add Target/i }).first().click();
    const dialog = page.locator('dialog.detail-modal[open]');
    const domain = `pw-rm-${Date.now()}.example.com`;
    await dialog.locator('input[name="value"]').first().fill(domain);
    await dialog.getByRole('button', { name: /Add & issue target-bound challenge/i }).click();
    // Scope to the declared-target row (the DNS challenge history table also lists the domain).
    // Wait for the challenge (i.e. the create + refresh finished), then close the modal: while a
    // modal <dialog> is open the page behind it is inert, so its buttons are not in the a11y tree.
    await expect(dialog.locator('.dns-fields')).toContainText(domain, { timeout: 10_000 });
    await dialog.getByRole('button', { name: 'Close dialog' }).click();
    const removeButton = page.getByRole('button', { name: `Remove target ${domain}` });
    await expect(removeButton).toBeVisible({ timeout: 10_000 });

    await removeButton.click();
    await page.locator('dialog[open]').getByRole('button', { name: 'Remove target', exact: true }).click();
    // The group entity must be re-read after the mutation, not just the list datasets.
    await expect(removeButton).toHaveCount(0, { timeout: 10_000 });
  });
});
