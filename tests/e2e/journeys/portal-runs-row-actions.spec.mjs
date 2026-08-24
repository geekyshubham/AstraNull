import { expect, test } from '@playwright/test';
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
 * FT-RUNS-ROW-01 — the runs list can act on an in-flight run.
 *
 * `cancelRun`/`confirmCancelRun`/`finalizeRun` existed on the runs page but no control
 * reached them, so an operator had to open run-detail to stop a run. These tests drive the
 * row controls and assert the confirm-then-POST contract, so the handlers cannot go dead again.
 * The last test covers the run-detail page, which asked the same questions via window.confirm.
 */

const CANCEL_RUN_ID = 'run_inflight_cancel';
const FINALIZE_RUN_ID = 'run_inflight_finalize';
// Detail-page cancel needs its own run: the list tests above settle the other two.
const DETAIL_CANCEL_RUN_ID = 'run_inflight_detail';
const COMPLETED_RUN_ID = 'run_checkout_1';

function seedInFlightRuns(store) {
  const ids = PORTAL_BASELINE_IDS;
  for (const [id, status] of [[CANCEL_RUN_ID, 'running'], [FINALIZE_RUN_ID, 'collecting'], [DETAIL_CANCEL_RUN_ID, 'running']]) {
    store.testRuns.push({
      id,
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      target_id: ids.targetId,
      check_id: 'origin.leak_scan.safe',
      status,
      started_at: ids.frozenAt,
      created_at: ids.frozenAt,
      agent_id: ids.agentId,
    });
  }
}

function forbidNativeDialogs(page) {
  const raised = [];
  page.on('dialog', (dialog) => {
    raised.push(`${dialog.type()}: ${dialog.message()}`);
    void dialog.dismiss();
  });
  return raised;
}

function runRow(page, runId) {
  return page.locator('tr').filter({ hasText: runId }).first();
}

test.describe('runs list row actions (FT-RUNS-ROW-01)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: seedInFlightRuns });
  });
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('an in-flight run row cancels through the in-app confirm and only POSTs on confirm', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    const nativeDialogs = forbidNativeDialogs(page);

    /** @type {string[]} */
    const cancelPosts = [];
    page.on('request', (req) => {
      if (req.method() === 'POST' && /\/v1\/test-runs\/[^/]+\/cancel$/.test(req.url())) {
        cancelPosts.push(req.url());
      }
    });

    await gotoPortalRoute(page, 'runs', baseUrl);
    const row = runRow(page, CANCEL_RUN_ID);
    await expect(row).toBeVisible({ timeout: 15_000 });

    const cancelBtn = row.getByRole('button', { name: 'Cancel', exact: true });
    await expect(cancelBtn).toBeEnabled({ timeout: 15_000 });
    await cancelBtn.click();

    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toBeVisible({ timeout: 10_000 });
    await expect(confirm).toContainText('Cancel this run in progress?');
    await expect(confirm).toContainText(CANCEL_RUN_ID);
    expect(cancelPosts, 'opening the confirm must not cancel the run').toHaveLength(0);

    await confirm.getByRole('button', { name: 'Cancel run' }).click();
    await expect
      .poll(() => cancelPosts.length, { timeout: 15_000 })
      .toBeGreaterThan(0);
    expect(cancelPosts[0]).toContain(CANCEL_RUN_ID);
    await expect(confirm).toBeHidden({ timeout: 15_000 });
    await expect(page.locator('[role="status"], [role="alert"], .form-banner').filter({ hasText: /cancel/i }).first())
      .toBeVisible({ timeout: 15_000 });
    expect(nativeDialogs, 'no native window.confirm may be raised').toEqual([]);
  });

  test('a collecting run row force-finalizes through the in-app confirm; settled rows expose no actions', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    const nativeDialogs = forbidNativeDialogs(page);

    /** @type {string[]} */
    const finalizePosts = [];
    page.on('request', (req) => {
      if (req.method() === 'POST' && /\/v1\/test-runs\/[^/]+\/finalize$/.test(req.url())) {
        finalizePosts.push(req.url());
      }
    });

    await gotoPortalRoute(page, 'runs', baseUrl);
    const row = runRow(page, FINALIZE_RUN_ID);
    await expect(row).toBeVisible({ timeout: 15_000 });

    // A settled run offers no row actions at all.
    const completedRow = runRow(page, COMPLETED_RUN_ID);
    await expect(completedRow.getByRole('button', { name: 'Finalize' })).toHaveCount(0);
    await expect(completedRow.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0);

    const finalizeBtn = row.getByRole('button', { name: 'Finalize' });
    await expect(finalizeBtn).toBeEnabled({ timeout: 15_000 });
    await finalizeBtn.click();

    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toBeVisible({ timeout: 10_000 });
    await expect(confirm).toContainText('Force finalize this run now?');
    expect(finalizePosts, 'opening the confirm must not finalize the run').toHaveLength(0);

    await confirm.getByRole('button', { name: 'Force finalize' }).click();
    await expect
      .poll(() => finalizePosts.length, { timeout: 15_000 })
      .toBeGreaterThan(0);
    expect(finalizePosts[0]).toContain(FINALIZE_RUN_ID);
    await expect(confirm).toBeHidden({ timeout: 15_000 });
    expect(nativeDialogs, 'no native window.confirm may be raised').toEqual([]);
  });

  test('run-detail cancels through the same in-app confirm, never a native dialog', async ({ page }) => {
    // Run-detail kept two window.confirm calls after the list moved to ConfirmModal, so the
    // same action asked twice in two different ways depending on where you started.
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page);
    const nativeDialogs = forbidNativeDialogs(page);

    /** @type {string[]} */
    const cancelPosts = [];
    page.on('request', (req) => {
      if (req.method() === 'POST' && /\/v1\/test-runs\/[^/]+\/cancel$/.test(req.url())) {
        cancelPosts.push(req.url());
      }
    });

    await gotoPortalRoute(page, 'run-detail', baseUrl, {
      entityIds: { 'run-detail': DETAIL_CANCEL_RUN_ID },
    });

    const cancelBtn = page.getByRole('button', { name: 'Cancel', exact: true }).first();
    await expect(cancelBtn).toBeEnabled({ timeout: 15_000 });
    await cancelBtn.click();

    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toBeVisible({ timeout: 10_000 });
    await expect(confirm).toContainText('Cancel this run in progress?');
    await expect(confirm).toContainText(DETAIL_CANCEL_RUN_ID);
    expect(cancelPosts, 'opening the confirm must not cancel the run').toHaveLength(0);

    await confirm.getByRole('button', { name: 'Cancel run' }).click();
    await expect
      .poll(() => cancelPosts.length, { timeout: 15_000 })
      .toBeGreaterThan(0);
    expect(cancelPosts[0]).toContain(DETAIL_CANCEL_RUN_ID);
    await expect(confirm).toBeHidden({ timeout: 15_000 });
    expect(nativeDialogs, 'no native window.confirm may be raised').toEqual([]);
  });
});
