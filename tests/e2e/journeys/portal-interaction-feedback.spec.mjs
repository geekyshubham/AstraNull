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

  test('finding Retest never reports success without firing a request (regression)', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);

    /** @type {string[]} */
    const retestCalls = [];
    page.on('request', (req) => {
      const u = req.url();
      if (req.method() === 'POST' && /\/v1\/(test-runs|waf\/validations|waf\/cve-pipeline)/.test(u)) {
        retestCalls.push(u);
      }
    });

    await gotoPortalRoute(page, 'finding-detail', baseUrl);
    const retestBtn = page.getByRole('button', { name: 'Retest', exact: true });
    await expect(retestBtn).toBeVisible({ timeout: 10_000 });
    await retestBtn.click();

    // Either a real retest request fired (success path) OR an error banner is shown.
    // The old bug showed "Retest started." with NO request for waf/cve kinds — this
    // asserts that a success banner is only reached when a request actually happened.
    await expect(page.locator(BANNER).last()).toBeVisible({ timeout: 10_000 });
    const successShown = await page
      .locator(BANNER)
      .filter({ hasText: /Retest started/i })
      .count();
    if (successShown > 0) {
      expect(retestCalls.length, 'success banner requires a real retest request').toBeGreaterThan(0);
    }
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
    await dialog.getByRole('button', { name: 'Add target' }).click();

    // The error banner must be visible WITHIN the dialog (not behind its backdrop).
    await expect(dialog.locator('.form-banner.error, [role="alert"]').first())
      .toBeVisible({ timeout: 5_000 });
  });
});
