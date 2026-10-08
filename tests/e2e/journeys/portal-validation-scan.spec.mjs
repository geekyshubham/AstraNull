import path from 'node:path';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { createServer as createViteServer } from 'vite';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { ACTIVE_STEP_STATUSES, MAX_SCAN_CHECKS } from '../../../src/contracts/validationScanManagement.mjs';
import {
  advanceScanForTest,
  dispatchDueScansForTest,
  expireScanCollectionWindowsForTest,
  findStoredScanForTest,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  waitForPortalRouteSettled,
  injectPortalDevHeadersSession,
  PORTAL_AUDITOR_SESSION,
} from '../../helpers/portal-playwright-session.mjs';

/**
 * FT-SCAN-01 — validation scans: launcher, live polling view, scheduling, RBAC.
 *
 * Runs against the real in-process dev-json backend (no route mocking) so the
 * step lifecycle, activity log, and Stop path are exercised end to end. Scan reads
 * from the portal are passive (GET never advances a scan); progress comes only from
 * the explicit system runner tick (`advanceScanForTest`). Simulated child runs
 * finalize once their collection window closes; the spec expires those windows
 * through the shared store instead of waiting out the real timers.
 */

/** Steps that are active right now; a scan runs its steps one at a time. */
function activeSteps(scan) {
  return (scan?.steps ?? []).filter((step) => ACTIVE_STEP_STATUSES.includes(step.status));
}

function stepStatuses(scan) {
  return (scan?.steps ?? []).map((step) => String(step.status ?? ''));
}

const SOC_GATED_CHECK_ID = 'l3.connection_table_exhaustion.request_only';
const CHECK_PICKER_SEARCH = 'Search by name, check id, section, or probe kind';
const DNS_SECTION = 'DNS Service Exhaustion';

let sourceBaseUrl = '';
let vite;

function pad(value) {
  return String(value).padStart(2, '0');
}

function localDatetimeValue(date) {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

async function chooseOption(scope, label, optionText) {
  const trigger = scope.getByRole('button', { name: label, exact: true });
  await expect(trigger).toBeEnabled();
  await trigger.click();
  const listbox = scope.getByRole('listbox', { name: label, exact: true });
  const option = listbox.getByRole('option').filter({ hasText: optionText }).first();
  await expect(option).toBeVisible();
  await option.click();
}

function launcher(page) {
  return page.locator('dialog.form-modal[open]');
}

function confirmDialog(page) {
  return page.locator('dialog.modal-confirm:not(.form-modal)[open]');
}

function stepRows(page) {
  return page.locator('.scan-steps tbody tr');
}

async function expectNoBlockingAxeViolations(page, selector) {
  // In-app hash navigation (not only gotoPortalRoute) replays the route-enter fade; axe must
  // sample settled colors or muted copy reads as #727272 instead of #787878 and fails AA.
  await waitForPortalRouteSettled(page);
  const builder = new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']);
  const results = await (selector ? builder.include(selector) : builder).analyze();
  const blocking = results.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? ''));
  expect(blocking.map((violation) => `${violation.id}: ${violation.help}`)).toEqual([]);
}

function scanIdFromHash(url) {
  const hash = new URL(url).hash;
  const match = hash.match(/^#scan-detail\?id=([^&]+)/);
  return match ? decodeURIComponent(match[1]) : '';
}

test.describe('validation scans (FT-SCAN-01)', () => {
  test.beforeAll(async () => {
    const { baseUrl: apiBaseUrl } = await startPortalPlaywrightServer();
    vite = await createViteServer({
      configFile: path.resolve('vite.config.ts'),
      logLevel: 'silent',
      server: {
        host: '127.0.0.1',
        port: 0,
        strictPort: false,
        proxy: { '/v1': apiBaseUrl, '/ready': apiBaseUrl, '/internal': apiBaseUrl },
      },
    });
    await vite.listen();
    const address = vite.httpServer?.address();
    if (!address || typeof address === 'string') throw new Error('Vite source server did not bind.');
    sourceBaseUrl = `http://127.0.0.1:${address.port}`;
  });

  test.afterAll(async () => {
    await vite?.close();
    await stopPortalPlaywrightServer();
  });

  test('picker hides SOC-gated and monitor-only checks, states why, and passes axe while open', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'runs', sourceBaseUrl);
    await page.getByRole('button', { name: 'Start validation scan' }).click();
    const modal = launcher(page);
    await expect(modal).toBeVisible();
    await modal.locator('.domain-picker-option').filter({ hasText: /^checkout\.acme\.com/ }).getByRole('checkbox').check();
    await expect(modal.getByRole('note').filter({ hasText: 'SOC-gated and monitor-only checks cannot be started here' })).toBeVisible();

    const catalog = await page.evaluate(async () => {
      const response = await fetch('/v1/checks', {
        headers: { 'x-tenant-id': 'ten_portal_baseline', 'x-user-id': 'usr_owner', 'x-role': 'owner' },
      });
      const payload = await response.json();
      return payload.items.map((check) => ({ id: check.check_id, safety: check.safety_class, tier: check.evidence_tier }));
    });
    const hidden = catalog.filter((check) => check.safety !== 'safe' || check.tier === 'E5');
    expect(hidden.length).toBeGreaterThan(0);
    expect(hidden.some((check) => check.id === SOC_GATED_CHECK_ID)).toBe(true);
    for (const check of hidden.slice(0, 5)) {
      await expect(modal.locator('li.check-picker-row').filter({ hasText: check.id })).toHaveCount(0);
    }
    await modal.getByPlaceholder(CHECK_PICKER_SEARCH).fill(SOC_GATED_CHECK_ID);
    await expect(modal.locator('li.check-picker-row')).toHaveCount(0);
    await expect(modal.getByText('No selectable checks match this search.')).toBeVisible();
    await modal.getByPlaceholder(CHECK_PICKER_SEARCH).fill('');
    await expect(modal.getByRole('group', { name: DNS_SECTION })).toBeVisible();

    await expectNoBlockingAxeViolations(page, 'dialog.form-modal[open]');
    await modal.getByRole('button', { name: 'Close dialog' }).click();
    await expect(modal).toBeHidden();
  });

  test('launches an exact-target scan, reads it passively, progresses it one step at a time through the runner, and stops it', async ({ page }) => {
    test.setTimeout(120_000);
    await injectPortalDevHeadersSession(page);
    const scanPosts = [];
    const scanReads = [];
    page.on('request', (request) => {
      if (request.method() === 'POST' && /\/v1\/validation-scans$/.test(request.url())) scanPosts.push(request.url());
      if (request.method() === 'GET' && /\/v1\/validation-scans\/[^/?]+$/.test(request.url())) scanReads.push(Date.now());
    });

    await gotoPortalRoute(page, 'runs', sourceBaseUrl);
    await page.getByRole('button', { name: 'Start validation scan' }).click();
    const modal = launcher(page);
    await expect(modal.locator('.domain-picker')).toBeVisible();

    await modal.locator('.domain-picker-option').filter({ hasText: /^checkout\.acme\.com/ }).getByRole('checkbox').check();

    const sectionSelectAll = modal.getByRole('checkbox', { name: new RegExp(`Select all \\d+ applicable checks in ${DNS_SECTION}`) });
    await sectionSelectAll.check();
    const sectionCount = Number((await sectionSelectAll.getAttribute('aria-label')).match(/Select all (\d+)/)[1]);
    expect(sectionCount).toBeGreaterThan(1);

    await modal.getByPlaceholder(CHECK_PICKER_SEARCH).fill('origin leak');
    const originRow = modal.locator('li.check-picker-row').filter({ hasText: PORTAL_BASELINE_IDS.checkId });
    await expect(originRow).toHaveCount(1);
    await expect(originRow).toContainText('Applies to 1 of 1 targets');
    await expect(originRow).toContainText(/max \d+ requests/);
    await originRow.getByRole('checkbox').check();
    const expectedChecks = sectionCount + 1;
    await expect(modal.locator('.check-picker-selected')).toHaveText(`${expectedChecks} of ${MAX_SCAN_CHECKS} selected`);
    await expect(modal.locator('.scan-launcher-summary')).toContainText(`${expectedChecks} checks selected · ${expectedChecks} planned steps`);

    await modal.getByRole('button', { name: 'Review scan' }).click();
    const confirm = confirmDialog(page);
    await expect(confirm).toContainText('Start this validation scan now?');
    await expect(confirm).toContainText('Domains: checkout.acme.com · Fqdn');
    await expect(confirm).toContainText(`${expectedChecks} selected`);
    await expect(confirm).toContainText(`Planned steps: ${expectedChecks}`);
    await expect(confirm).toContainText('Request upper bound:');
    await expect(confirm).toContainText('Runs immediately');
    expect(scanPosts).toHaveLength(0);
    await confirm.getByRole('button', { name: 'Start scan' }).click();

    await expect.poll(() => scanIdFromHash(page.url()), { timeout: 20_000 }).toMatch(/^scan_/);
    const scanId = scanIdFromHash(page.url());
    expect(scanPosts).toHaveLength(1);

    await expect(page.getByRole('heading', { level: 1, name: scanId })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText('Domain checkout.acme.com')).toBeVisible();
    await expect(stepRows(page)).toHaveCount(expectedChecks, { timeout: 20_000 });
    await expect(page.locator('.scan-live-region')).toContainText(/Scan running\. Refreshing every \d+ seconds?\./);
    await expect(page.getByRole('button', { name: `Stop scan ${scanId}` })).toBeVisible();

    // Passive reads: several polls without a runner tick change no stored step.
    const beforePolls = stepStatuses(findStoredScanForTest(scanId));
    expect(beforePolls).toHaveLength(expectedChecks);
    const readsBefore = scanReads.length;
    await expect.poll(() => scanReads.length, { timeout: 15_000 }).toBeGreaterThan(readsBefore + 1);
    expect(stepStatuses(findStoredScanForTest(scanId))).toEqual(beforePolls);
    expect(activeSteps(findStoredScanForTest(scanId)).length).toBeLessThanOrEqual(1);
    await expect(page.getByRole('list', { name: 'Scan activity' })).toBeVisible();
    const initialActivity = await page.getByRole('list', { name: 'Scan activity' }).locator('li').count();
    expect(initialActivity).toBeGreaterThan(0);

    const activeRow = stepRows(page).filter({ hasText: /Collecting|Running|Starting/ }).first();
    await expect(activeRow).toBeVisible();
    await expect(activeRow).toContainText(/max \d+ request/);
    await expect(activeRow).toContainText('0 (simulated, no live traffic)');

    // The explicit runner advances the scan; the page only shows what was recorded.
    const tick = () => {
      expireScanCollectionWindowsForTest(scanId);
      advanceScanForTest(scanId);
      expect(activeSteps(findStoredScanForTest(scanId)).length, 'one step at a time').toBeLessThanOrEqual(1);
    };
    await expect.poll(async () => {
      tick();
      return stepRows(page).filter({ hasText: 'Verdicted' }).count();
    }, { timeout: 30_000, intervals: [500, 1000] }).toBeGreaterThanOrEqual(1);
    const verdictedRow = stepRows(page).filter({ hasText: 'Verdicted' }).first();
    await expect(verdictedRow).toContainText(/Blocked|Connected|Filtered|Rate limited|Unknown/);
    await expect(verdictedRow).toContainText('Inconclusive');
    await expect(verdictedRow.getByRole('link', { name: /^Open run run_/ })).toBeVisible();
    await expect(page.getByRole('progressbar', { name: /Scan progress/ })).toBeVisible();

    await expect.poll(async () => {
      tick();
      return stepRows(page).filter({ hasText: 'Verdicted' }).count();
    }, { timeout: 30_000, intervals: [500, 1000] }).toBeGreaterThanOrEqual(2);
    await expect.poll(() => page.getByRole('list', { name: 'Scan activity' }).locator('li').count(), { timeout: 20_000 })
      .toBeGreaterThan(initialActivity);
    await expect(page.getByRole('list', { name: 'Scan activity' })).toContainText('Probe result received');
    await expect(page.getByText('Metadata only: no request or response bodies are recorded.')).toBeVisible();
    const rawJsonLeak = await page.locator('#root').innerText();
    expect(rawJsonLeak).not.toMatch(/"metadata"\s*:/);

    await expectNoBlockingAxeViolations(page);

    await page.getByRole('button', { name: `Stop scan ${scanId}` }).click();
    const stopConfirm = confirmDialog(page);
    await expect(stopConfirm).toContainText('Stop this validation scan?');
    await stopConfirm.getByLabel('Reason (optional)').fill('Operator stopped the drill');
    await stopConfirm.getByRole('button', { name: 'Stop scan' }).click();
    await expect(stopConfirm).toBeHidden({ timeout: 15_000 });
    await expect(page.locator('.scan-detail-view .page-context-summary, .scan-detail-view').first()).toContainText('Cancelled', { timeout: 15_000 });
    await expect(page.locator('.scan-live-region')).toContainText('Live updates stopped');
    await expect(page.getByRole('note').filter({ hasText: 'reason: Operator stopped the drill' })).toBeVisible();
    await expect(page.getByRole('button', { name: `Stop scan ${scanId}` })).toHaveCount(0);
    await expect(stepRows(page).filter({ hasText: /Skipped|Cancelled/ }).first()).toBeVisible();

    await page.waitForTimeout(1500);
    const readsAfterStop = scanReads.length;
    await page.waitForTimeout(4000);
    expect(scanReads.length, 'polling must stop once the scan is terminal').toBe(readsAfterStop);
    expect(findStoredScanForTest(scanId)?.status).toBe('cancelled');
  });

  test('schedules a recurring scan from the runs page, edits it, dispatches it, and cancels the series', async ({ page }) => {
    test.setTimeout(120_000);
    await injectPortalDevHeadersSession(page);
    const patches = [];
    let created = null;
    page.on('request', (request) => {
      if (request.method() === 'PATCH' && /\/v1\/validation-scans\//.test(request.url())) patches.push(request.postDataJSON());
    });
    page.on('response', async (response) => {
      if (response.request().method() === 'POST' && /\/v1\/validation-scans$/.test(response.url()) && response.status() === 201) {
        created = await response.json();
      }
    });

    await gotoPortalRoute(page, 'runs', sourceBaseUrl);
    await expect(page.getByRole('heading', { name: 'Validation scans' })).toBeVisible({ timeout: 20_000 });
    await page.getByRole('button', { name: 'Start validation scan' }).click();
    const modal = launcher(page);
    await modal.locator('.domain-picker-option').filter({ hasText: /^checkout\.acme\.com/ }).getByRole('checkbox').check();
    await modal.locator('.domain-picker-option').filter({ hasText: /^pay\.acme\.com/ }).getByRole('checkbox').check();
    await modal.getByPlaceholder(CHECK_PICKER_SEARCH).fill('origin leak');
    const originRow = modal.locator('li.check-picker-row').filter({ hasText: PORTAL_BASELINE_IDS.checkId });
    await expect(originRow).toContainText(/Applies to \d+ of \d+ targets/);
    await originRow.getByRole('checkbox').check();
    await modal.getByLabel('Scan name (optional)').fill('Weekly origin sweep');
    await modal.getByRole('radio', { name: 'Schedule for later' }).check();
    const scheduledFor = new Date(Date.now() + 2 * 60_000);
    scheduledFor.setSeconds(0, 0);
    await modal.getByLabel('Scheduled for').fill(localDatetimeValue(scheduledFor));
    await chooseOption(modal, 'Repeat', 'Weekly');
    await modal.getByRole('button', { name: 'Review scan' }).click();
    const confirm = confirmDialog(page);
    await expect(confirm).toContainText('Schedule this validation scan?');
    await expect(confirm).toContainText('Weekly');
    await expect(confirm).toContainText('Name: Weekly origin sweep');
    await confirm.getByRole('button', { name: 'Schedule scan' }).click();
    await expect(modal).toBeHidden({ timeout: 15_000 });
    await expect.poll(() => created?.id ?? '', { timeout: 15_000 }).toMatch(/^scan_/);
    expect(created.status).toBe('scheduled');
    expect(created.recurrence).toMatchObject({ cadence: 'weekly' });
    await expect(page.locator('[role="status"], .form-banner').filter({ hasText: 'Weekly origin sweep scheduled for' }).first()).toBeVisible({ timeout: 15_000 });

    const row = page.locator('.validation-scans-table tbody tr').filter({ hasText: 'Weekly origin sweep' });
    await expect(row).toHaveCount(1, { timeout: 15_000 });
    await expect(row).toContainText('Scheduled');
    await expect(row).toContainText('Weekly');
    await expect(row).toContainText('2 selected domains');

    await row.getByRole('button', { name: 'Edit scan Weekly origin sweep' }).click();
    const editModal = launcher(page);
    await expect(editModal).toContainText('Edit scheduled scan');
    await expect(editModal.getByRole('radio', { name: 'Run now' })).toBeDisabled();
    await editModal.getByLabel('Scan name (optional)').fill('Weekly origin sweep v2');
    await editModal.getByRole('button', { name: 'Review scan' }).click();
    await confirmDialog(page).getByRole('button', { name: 'Save changes' }).click();
    await expect(editModal).toBeHidden({ timeout: 15_000 });
    await expect.poll(() => patches.length).toBe(1);
    expect(patches[0]).toEqual({ name: 'Weekly origin sweep v2' });
    await expect(page.locator('.validation-scans-table tbody tr').filter({ hasText: 'Weekly origin sweep v2' })).toHaveCount(1, { timeout: 15_000 });


    await expect(page.locator('.validation-scans-table tbody tr').filter({ hasText: 'Weekly origin sweep v2' })).toContainText('Scheduled');

    const stored = findStoredScanForTest(created.id);
    expect(stored?.status).toBe('scheduled');
    const dispatched = dispatchDueScansForTest({ now: new Date(new Date(stored.scheduled_for).getTime() + 1000) });
    expect(dispatched.some((result) => result.scan_id === created.id && result.dispatched)).toBe(true);
    const nextOccurrenceId = findStoredScanForTest(created.id)?.next_scan_id;
    expect(nextOccurrenceId).toMatch(/^scan_/);

    await gotoPortalRoute(page, 'scan-detail', sourceBaseUrl, { entityIds: { 'scan-detail': created.id } });
    await expect(page.getByRole('heading', { level: 1, name: 'Weekly origin sweep v2' })).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('.scan-detail-view')).toContainText(/Running|Completed/);
    await expect(stepRows(page)).not.toHaveCount(0, { timeout: 20_000 });

    await page.getByRole('button', { name: 'Stop scan Weekly origin sweep v2' }).click();
    const stopConfirm = confirmDialog(page);
    await stopConfirm.getByRole('checkbox', { name: 'Also cancel future occurrences of this recurring scan' }).check();
    await stopConfirm.getByRole('button', { name: 'Stop scan' }).click();
    await expect(stopConfirm).toBeHidden({ timeout: 15_000 });
    await expect(page.locator('.scan-detail-view')).toContainText('Cancelled', { timeout: 15_000 });
    expect(findStoredScanForTest(created.id)?.status).toBe('cancelled');
    expect(findStoredScanForTest(nextOccurrenceId)?.status).toBe('cancelled');
  });

  test('auditor can read scans and the runs page but sees no start, stop, edit, or cancel controls', async ({ page }) => {
    await injectPortalDevHeadersSession(page, PORTAL_AUDITOR_SESSION);
    await gotoPortalRoute(page, 'runs', sourceBaseUrl);
    await expect(page.getByRole('heading', { name: 'Validation scans' })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('button', { name: 'Start validation scan' })).toHaveCount(0);
    const table = page.locator('.validation-scans-table');
    await expect(table.locator('tbody tr')).not.toHaveCount(0, { timeout: 15_000 });
    await expect(table.getByRole('button', { name: /^Edit scan/ })).toHaveCount(0);
    await expect(table.getByRole('button', { name: /^Cancel scan/ })).toHaveCount(0);
    await expect(table.getByRole('button', { name: /Schedule scan .* again/ })).toHaveCount(0);
    await expect(page.getByRole('note').filter({ hasText: 'Your role can review validation scans' })).toBeVisible();
    const runRow = page.locator('.validation-runs-table tbody tr').filter({ hasText: PORTAL_BASELINE_IDS.readinessRunId }).first();
    await expect(runRow.getByRole('link', { name: `Open parent scan ${PORTAL_BASELINE_IDS.scanId}` })).toBeVisible();

    await gotoPortalRoute(page, 'scan-detail', sourceBaseUrl, { entityIds: { 'scan-detail': PORTAL_BASELINE_IDS.scanId } });
    await expect(page.getByRole('heading', { level: 1, name: 'Checkout baseline scan' })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('note').filter({ hasText: 'Read-only view' })).toBeVisible();
    await expect(page.getByRole('button', { name: /^Stop scan/ })).toHaveCount(0);
    await expect(stepRows(page)).toHaveCount(1);
    await expect(stepRows(page).first()).toContainText('Verdicted');
    await expect(stepRows(page).first()).toContainText('Origin leak scan');
    await expect(stepRows(page).first().getByRole('link', { name: `Open run ${PORTAL_BASELINE_IDS.readinessRunId}` })).toBeVisible();
    await expect(page.locator('.scan-live-region')).toContainText('Live updates stopped');
    await expectNoBlockingAxeViolations(page);

    await gotoPortalRoute(page, 'run-detail', sourceBaseUrl);
    await expect(page.getByRole('link', { name: 'Open parent scan' })).toHaveAttribute('href', new RegExp(`#scan-detail\\?id=${PORTAL_BASELINE_IDS.scanId}`));
  });
});
