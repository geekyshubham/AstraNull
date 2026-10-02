/**
 * Browser regression for the Refined Test policies and Test runs variants
 * (UNCOMMITTED_CHANGES_REVIEW G03):
 *  - Refined schedule creation binds one exact target per selected group, POSTs each
 *    group with its exact target_id, and on a partial failure keeps only the failed
 *    binding selected for retry while reporting the successful write.
 *  - Refined runs keep the classic Cancel/Finalize gates: in-flight rows confirm before
 *    POSTing, settled rows offer no actions, and a role without test_run:start sees none.
 *
 * Only the in-memory dev store is used; the failing policy write is a mocked 400, and no
 * request reaches any declared target.
 */
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
  PORTAL_AUDITOR_SESSION,
} from '../../helpers/portal-playwright-session.mjs';

const ids = PORTAL_BASELINE_IDS;
const SECOND_GROUP_ID = 'tg_refined_api';
const SECOND_GROUP_NAME = 'refined-api';
const SECOND_TARGET_ID = 'tgt_refined_api_1';
const HOST_CHECK = 'Firewall Exposure Scan (Safe)';
const CANCEL_RUN_ID = 'run_refined_cancel';
const FINALIZE_RUN_ID = 'run_refined_finalize';
const COMPLETED_RUN_ID = ids.readinessRunId;

function applyFixture(store) {
  applyPortalBaselineReadinessBoost(store);
  const group = store.targetGroups.find((item) => item.id === ids.targetGroupId);
  if (group) group.validation_mode = 'external_only';
  store.targetGroups.push({
    id: SECOND_GROUP_ID,
    tenant_id: ids.tenantId,
    environment_id: ids.environmentId,
    name: SECOND_GROUP_NAME,
    validation_mode: 'external_only',
    expected_behavior_default: 'cloud_baseline',
    created_at: ids.frozenAt,
  });
  store.targets.push({
    id: SECOND_TARGET_ID,
    tenant_id: ids.tenantId,
    target_group_id: SECOND_GROUP_ID,
    kind: 'fqdn',
    value: 'api.refined.acme.com',
    expected_behavior: 'cloud_baseline',
    verify_state: 'dns_verified',
    eligibility: 'eligible',
    created_at: ids.frozenAt,
  });
  for (const [id, status] of [[CANCEL_RUN_ID, 'running'], [FINALIZE_RUN_ID, 'collecting']]) {
    store.testRuns.push({
      id,
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      target_id: ids.targetId,
      check_id: ids.checkId,
      status,
      started_at: ids.frozenAt,
      created_at: ids.frozenAt,
    });
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function chooseCustomSelect(scope, label, option) {
  const trigger = scope.getByRole('button', { name: label, exact: true });
  await expect(trigger).toBeEnabled({ timeout: 15_000 });
  await trigger.click();
  const listbox = scope.getByRole('listbox', { name: label, exact: true });
  await expect(listbox).toBeVisible();
  await listbox.getByRole('option', { name: new RegExp(escapeRegExp(option)) }).click();
  return trigger;
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {'test-policies' | 'runs'} variantPage
 * @param {{ theme?: string, session?: Record<string, unknown> }} [options]
 */
async function prepareRefined(page, variantPage, { theme = 'dark', session } = {}) {
  await page.addInitScript(({ pageId, themeValue }) => {
    try {
      localStorage.setItem('astranull.theme', themeValue);
      localStorage.setItem(`astranull.design-variant.${pageId}`, 'refined');
    } catch { /* storage blocked */ }
  }, { pageId: variantPage, themeValue: theme });
  await injectPortalDevHeadersSession(page, session);
}

function forbidNativeDialogs(page) {
  const raised = [];
  page.on('dialog', (dialog) => {
    raised.push(`${dialog.type()}: ${dialog.message()}`);
    void dialog.dismiss();
  });
  return raised;
}

test.describe('Refined test policies and runs (G03)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyFixture });
  });
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  for (const combo of [
    { name: 'mobile, light', width: 390, height: 844, theme: 'light' },
    { name: 'desktop, dark', width: 1440, height: 900, theme: 'dark' },
  ]) {
    test(`Refined schedule creation keeps only the failed exact binding after a partial failure (${combo.name})`, async ({ page }) => {
      // Fresh store per combo: the previous combo's successful write would otherwise be a duplicate.
      await startPortalPlaywrightServer({ mutate: applyFixture });
      await page.setViewportSize({ width: combo.width, height: combo.height });
      await prepareRefined(page, 'test-policies', { theme: combo.theme });
      const errors = [];
      page.on('pageerror', (error) => errors.push(error.message));

      /** @type {Array<Record<string, unknown>>} */
      const posts = [];
      await page.route('**/v1/test-policies', async (route) => {
        const request = route.request();
        if (request.method() !== 'POST') return route.fallback();
        const body = request.postDataJSON();
        posts.push(body);
        if (body.target_group_id === SECOND_GROUP_ID) {
          return route.fulfill({
            status: 400,
            contentType: 'application/json',
            body: JSON.stringify({ error: 'invalid_request', message: 'Target is not eligible for this check.' }),
          });
        }
        return route.fallback();
      });

      await gotoPortalRoute(page, 'test-policies', getPortalPlaywrightBaseUrl());
      await expect(page.locator('.rf-policies')).toBeVisible({ timeout: 15_000 });

      await page.locator('.rf-header-actions').getByRole('button', { name: 'Create schedule' }).click();
      const panel = page.locator('section.rf-create');
      await expect(panel).toBeVisible();

      await chooseCustomSelect(panel, 'Check', HOST_CHECK);
      const pickerTrigger = panel.locator('.tg-picker-trigger');
      await pickerTrigger.click();
      const picker = panel.locator('.tg-picker-menu');
      await picker.getByRole('option', { name: /edge-checkout/ }).click();
      await picker.getByRole('option', { name: new RegExp(SECOND_GROUP_NAME) }).click();
      await pickerTrigger.press('Escape');

      const submit = panel.getByRole('button', { name: 'Create schedule', exact: true });
      // Targets are never assigned automatically: submit stays disabled until every group is bound.
      await expect(submit).toBeDisabled();
      await expect(panel.locator('.rf-readiness')).toContainText('Select one exact active target for every selected group.');

      await chooseCustomSelect(panel, 'edge-checkout exact target', 'checkout.acme.com');
      await expect(submit).toBeDisabled();
      await chooseCustomSelect(panel, `${SECOND_GROUP_NAME} exact target`, 'api.refined.acme.com');
      await expect(panel.locator('.rf-readiness')).toContainText('Ready to create 2 schedules');
      await expect(submit).toBeEnabled();

      // Keyboard submission of the form.
      await submit.focus();
      await page.keyboard.press('Enter');

      await expect.poll(() => posts.length, { timeout: 15_000 }).toBe(2);
      expect(posts.map((body) => [body.target_group_id, body.target_id])).toEqual([
        [ids.targetGroupId, ids.targetId],
        [SECOND_GROUP_ID, SECOND_TARGET_ID],
      ]);

      const banner = panel.locator('.form-banner.error[role="alert"]').filter({ hasText: 'Created 1 of 2 policies' });
      await expect(banner).toBeVisible({ timeout: 15_000 });
      await expect(banner).toContainText(`${SECOND_GROUP_ID}/${SECOND_TARGET_ID}`);
      await expect(banner).toContainText('only failed exact target bindings remain selected for retry');

      // Only the failed group stays selected, with its exact binding intact.
      await expect(panel.getByRole('button', { name: 'edge-checkout exact target', exact: true })).toHaveCount(0);
      const retained = panel.getByRole('button', { name: `${SECOND_GROUP_NAME} exact target`, exact: true });
      await expect(retained).toContainText('api.refined.acme.com');
      await expect(panel.locator('.rf-readiness')).toContainText('Ready to create 1 schedule');

      // The successful write is in the schedule table.
      await expect(page.getByRole('row').filter({ hasText: 'checkout.acme.com' }).filter({ hasText: HOST_CHECK }).first())
        .toBeVisible({ timeout: 15_000 });
      expect(errors).toEqual([]);
    });
  }

  test('Refined runs cancel and finalize in-flight rows only after the in-app confirm', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyFixture });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await prepareRefined(page, 'runs');
    const nativeDialogs = forbidNativeDialogs(page);
    /** @type {string[]} */
    const cancelPosts = [];
    /** @type {string[]} */
    const finalizePosts = [];
    page.on('request', (req) => {
      if (req.method() !== 'POST') return;
      if (/\/v1\/test-runs\/[^/]+\/cancel$/.test(req.url())) cancelPosts.push(req.url());
      if (/\/v1\/test-runs\/[^/]+\/finalize$/.test(req.url())) finalizePosts.push(req.url());
    });

    await gotoPortalRoute(page, 'runs', getPortalPlaywrightBaseUrl());
    await expect(page.locator('.rf-runs')).toBeVisible({ timeout: 15_000 });

    const completedRow = page.locator('tr').filter({ hasText: COMPLETED_RUN_ID }).first();
    await expect(completedRow).toBeVisible({ timeout: 15_000 });
    await expect(completedRow.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0);
    await expect(completedRow.getByRole('button', { name: 'Finalize' })).toHaveCount(0);
    await expect(completedRow).toContainText('No actions');

    const cancelRow = page.locator('tr').filter({ hasText: CANCEL_RUN_ID }).first();
    await cancelRow.getByRole('button', { name: 'Cancel', exact: true }).click();
    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toContainText('Cancel this run in progress?');
    await expect(confirm).toContainText(CANCEL_RUN_ID);
    expect(cancelPosts, 'opening the confirm must not cancel the run').toHaveLength(0);
    await page.keyboard.press('Escape');
    await expect(confirm).toBeHidden();
    expect(cancelPosts, 'dismissing the confirm must not cancel the run').toHaveLength(0);

    await cancelRow.getByRole('button', { name: 'Cancel', exact: true }).click();
    await confirm.getByRole('button', { name: 'Cancel run' }).click();
    await expect.poll(() => cancelPosts.length, { timeout: 15_000 }).toBe(1);
    expect(cancelPosts[0]).toContain(CANCEL_RUN_ID);
    await expect(confirm).toBeHidden({ timeout: 15_000 });

    const finalizeRow = page.locator('tr').filter({ hasText: FINALIZE_RUN_ID }).first();
    await finalizeRow.getByRole('button', { name: 'Finalize' }).click();
    await expect(confirm).toContainText('Force finalize this run now?');
    expect(finalizePosts).toHaveLength(0);
    await confirm.getByRole('button', { name: 'Force finalize' }).click();
    await expect.poll(() => finalizePosts.length, { timeout: 15_000 }).toBe(1);
    expect(finalizePosts[0]).toContain(FINALIZE_RUN_ID);
    expect(nativeDialogs, 'no native window.confirm may be raised').toEqual([]);
  });

  test('Refined runs offer no Cancel/Finalize to a role without test_run:start', async ({ page }) => {
    await prepareRefined(page, 'runs', { theme: 'light', session: PORTAL_AUDITOR_SESSION });
    await gotoPortalRoute(page, 'runs', getPortalPlaywrightBaseUrl());
    await expect(page.locator('.rf-runs')).toBeVisible({ timeout: 15_000 });
    const table = page.locator('.validation-runs-table');
    await expect(table.locator('tr').filter({ hasText: COMPLETED_RUN_ID }).first()).toBeVisible({ timeout: 15_000 });
    await expect(table.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0);
    await expect(table.getByRole('button', { name: 'Finalize' })).toHaveCount(0);
  });
});
