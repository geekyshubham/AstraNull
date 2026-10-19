/**
 * Browser regression for the Refined Test policies and Test runs variants
 * (UNCOMMITTED_CHANGES_REVIEW G03):
 *  - Refined schedule creation binds one exact target per selected group, POSTs each
 *    group with its exact target_id, and on a partial failure keeps only the failed
 *    binding selected for retry while reporting the successful write.
 *  - Refined runs keep the classic Cancel/Finalize gates: in-flight rows confirm before
 *    POSTing, settled rows offer no actions, and a role without test_run:start sees none.
 *  - Customers reach Refined runs only through the `#runs?variant=refined` address; the
 *    layout switch and its stored preference are staff-only.
 *  - A legacy schedule without an exact target offers only "Create replacement" and Archive.
 *  - An observation-only check offers only manual review in the Edit dialog, even when an
 *    older stricter expectation was recorded.
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
  waitForPortalRouteSettled,
} from '../../helpers/portal-playwright-session.mjs';

const ids = PORTAL_BASELINE_IDS;
const SECOND_GROUP_ID = 'tg_refined_api';
const SECOND_GROUP_NAME = 'refined-api';
const SECOND_TARGET_ID = 'tgt_refined_api_1';
const CANCEL_RUN_ID = 'run_refined_cancel';
const FINALIZE_RUN_ID = 'run_refined_finalize';
const COMPLETED_RUN_ID = ids.readinessRunId;
const OBSERVATION_POLICY_NAME = 'Observation-only schedule';

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
  store.testPolicies.push({
    id: 'pol_refined_observation',
    tenant_id: ids.tenantId,
    name: OBSERVATION_POLICY_NAME,
    target_group_id: ids.targetGroupId,
    target_id: ids.targetId,
    check_id: ids.checkId,
    cadence: 'weekly',
    expected_verdict: 'pass',
    state: 'active',
    timezone: 'UTC',
    safe_windows: [],
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
 * Customer sessions never read a stored runs layout, so Refined runs is reached by address.
 * @param {import('@playwright/test').Page} page
 */
async function gotoRefinedRuns(page) {
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#runs?variant=refined`, { waitUntil: 'networkidle', timeout: 60_000 });
  await waitForPortalRouteSettled(page);
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

async function chooseScheduleCheck(scope, checkId) {
  const picker = scope.locator('.rf-check-picker, .rf-check-summary').first();
  await expect(picker).toBeVisible({ timeout: 10_000 });
  if (await scope.locator('.rf-check-summary').count()) await scope.locator('.rf-check-summary').getByRole('button', { name: 'Change' }).click();
  await scope.getByRole('searchbox', { name: 'Find a check' }).fill(checkId);
  await scope.getByRole('radio', { name: new RegExp(checkId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }).click();
  await expect(scope.locator('.rf-check-summary')).toContainText(checkId);
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
        if (body.target_id === SECOND_TARGET_ID) {
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

      await chooseScheduleCheck(panel, 'l3.firewall_exposure_scan.safe');
      const submit = panel.getByRole('button', { name: 'Create schedule', exact: true });
      await expect(submit).toBeDisabled();
      await panel.locator('.domain-picker-option').filter({ hasText: 'checkout.acme.com' }).getByRole('checkbox').check();
      await panel.locator('.domain-picker-option').filter({ hasText: 'api.refined.acme.com' }).getByRole('checkbox').check();
      await expect(panel.locator('.rf-readiness')).toContainText('Ready to create 2 schedules');
      await expect(submit).toBeEnabled();

      // Keyboard submission of the form.
      await submit.focus();
      await page.keyboard.press('Enter');

      await expect.poll(() => posts.length, { timeout: 15_000 }).toBe(2);
      expect(posts.map((body) => body.target_id)).toEqual([
        ids.targetId,
        SECOND_TARGET_ID,
      ]);

      const banner = panel.locator('.form-banner.error[role="alert"]').filter({ hasText: 'Created 1 of 2 schedules' });
      await expect(banner).toBeVisible({ timeout: 15_000 });
      await expect(banner).toContainText('api.refined.acme.com');
      await expect(banner).toContainText('only failed exact target bindings remain selected for retry');

      // Only the failed domain stays selected; successful writes are not replayed.
      await expect(panel.locator('.domain-picker-option').filter({ hasText: 'checkout.acme.com' }).getByRole('checkbox')).not.toBeChecked();
      await expect(panel.locator('.domain-picker-option').filter({ hasText: 'api.refined.acme.com' }).getByRole('checkbox')).toBeChecked();
      expect(posts.every((body) => !Object.hasOwn(body, 'target_group_id'))).toBe(true);
      await expect(panel.locator('.rf-readiness')).toContainText('Ready to create 1 schedule');

      // The successful write is in the schedule table.
      await expect(page.getByRole('row').filter({ hasText: 'checkout.acme.com' }).filter({ hasText: 'l3.firewall_exposure_scan.safe' }).first())
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

    await gotoRefinedRuns(page);
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
    await gotoRefinedRuns(page);
    await expect(page.locator('.rf-runs')).toBeVisible({ timeout: 15_000 });
    const table = page.locator('.validation-runs-table');
    await expect(table.locator('tr').filter({ hasText: COMPLETED_RUN_ID }).first()).toBeVisible({ timeout: 15_000 });
    await expect(table.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0);
    await expect(table.getByRole('button', { name: 'Finalize' })).toHaveCount(0);
  });

  test('Customer runs ignore a stored layout preference, show no layout switch, and keep the verdict on screen at 1440', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await prepareRefined(page, 'runs');
    await gotoPortalRoute(page, 'runs', getPortalPlaywrightBaseUrl());
    await expect(page.getByRole('heading', { level: 1, name: 'Test runs' })).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('.rf-runs')).toHaveCount(0);
    await expect(page.locator('.variant-switch')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Open check library' })).toBeVisible();

    const table = page.locator('.validation-runs-table');
    await expect(table.locator('thead th')).toHaveText(['Check', 'Domain', 'Verdict', 'Status', 'Started', 'Mode', 'Duration', 'Actions']);
    const completedRow = table.locator('tr').filter({ hasText: COMPLETED_RUN_ID }).first();
    await expect(completedRow.locator('code.run-id-label')).toHaveAttribute('title', COMPLETED_RUN_ID);
    const verdictVisible = await table.locator('thead th').filter({ hasText: 'Verdict' }).evaluate((th) => {
      const scroller = th.closest('.table-scroller, .table-wrap') ?? document.documentElement;
      const clip = scroller.getBoundingClientRect();
      const rect = th.getBoundingClientRect();
      return rect.right <= Math.min(clip.right, window.innerWidth) + 0.5;
    });
    expect(verdictVisible, 'Verdict header must be visible without horizontal scrolling at 1440').toBe(true);

    const order = await page.evaluate(() => {
      const gate = document.querySelector('.runs-soc-gate');
      const history = [...document.querySelectorAll('.card')].find((card) => card.textContent?.includes('Run history'));
      return Boolean(gate && history && (gate.compareDocumentPosition(history) & Node.DOCUMENT_POSITION_FOLLOWING));
    });
    expect(order, 'validation requests sit above the run history').toBe(true);
    expect(await page.evaluate(() => localStorage.getItem('astranull.design-variant.runs'))).toBe('refined');
  });

  test('Validation requests keep a Retry banner on a load failure and stay hidden on 403', async ({ page }) => {
    let failNext = true;
    let customerCalls = 0;
    await page.route((url) => url.pathname === '/v1/high-scale-requests' && url.searchParams.get('scope') === 'my-tenant', async (route) => {
      customerCalls += 1;
      if (!failNext) return route.fallback();
      failNext = false;
      return route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'internal_error' }) });
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'runs', getPortalPlaywrightBaseUrl());
    const gate = page.locator('.runs-soc-gate');
    const banner = gate.locator('.table-load-error');
    await expect(banner).toContainText('Could not load', { timeout: 15_000 });
    await expect(gate.getByRole('heading', { name: 'Validation requests' })).toBeVisible();
    await banner.getByRole('button', { name: 'Retry' }).click();
    await expect(banner).toHaveCount(0, { timeout: 15_000 });
    await expect(gate.locator('tbody tr').first()).toBeVisible();
    expect(customerCalls).toBeGreaterThanOrEqual(2);

    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await page.route((url) => url.pathname === '/v1/high-scale-requests' && url.searchParams.get('scope') === 'my-tenant', (route) => route.fulfill({
      status: 403,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'forbidden', message: 'Missing high_scale:read.' }),
    }));
    // Same-hash navigation keeps the mounted panel, so reload to read the queue again under the 403.
    await page.reload({ waitUntil: 'networkidle' });
    await expect(page.getByRole('heading', { level: 1, name: 'Test runs' })).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('.validation-runs-table')).toBeVisible();
    await expect(page.locator('.runs-soc-gate')).toHaveCount(0);
  });

  test('A legacy schedule without an exact target offers Create replacement and Archive only', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'test-policies', getPortalPlaywrightBaseUrl());
    const legacy = page.getByRole('row').filter({ hasText: 'No exact target' }).first();
    await expect(legacy).toBeVisible({ timeout: 15_000 });
    const replace = legacy.getByRole('link', { name: /^Create replacement for schedule / });
    await expect(replace).toHaveAttribute('href', new RegExp(`#test-policies\\?check=${escapeRegExp(encodeURIComponent(ids.checkId))}$`));
    await expect(legacy.getByRole('button', { name: /^(Pause|Resume|Edit) schedule/ })).toHaveCount(0);
    await expect(legacy.getByRole('button', { name: /^Archive schedule/ })).toHaveCount(1);
    await expect(page.getByRole('region', { name: 'Schedule summary' })).toContainText('Disabled, blocked, or manual only; see the reason per row');
    await expect(page.getByRole('button', { name: /^Not dispatching \d/ })).toBeVisible();

    await replace.click();
    const panel = page.locator('section.rf-create');
    await expect(panel).toBeVisible();
    await expect(page).not.toHaveURL(/check=/);
  });

  test('An observation-only check offers only manual review when editing a schedule', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'test-policies', getPortalPlaywrightBaseUrl());
    const row = page.getByRole('row').filter({ hasText: OBSERVATION_POLICY_NAME }).first();
    await expect(row).toBeVisible({ timeout: 15_000 });
    await row.getByRole('button', { name: `Edit schedule ${OBSERVATION_POLICY_NAME}` }).click();

    const dialog = page.getByRole('dialog', { name: 'Edit schedule' });
    await expect(dialog).toBeVisible();
    const trigger = dialog.getByRole('button', { name: 'Expected verdict', exact: true });
    await expect(trigger).toContainText('Needs review (observation only)');
    await expect(dialog).toContainText('This check records external observations only and cannot prove protection.');
    await expect(dialog.getByTestId('schedule-verdict-correction')).toContainText('Expect protection to hold');
    await trigger.click();
    const listbox = dialog.getByRole('listbox', { name: 'Expected verdict', exact: true });
    await expect(listbox.getByRole('option')).toHaveCount(1);
    await expect(listbox.getByRole('option')).toContainText('Needs review (observation only)');
    await expect(listbox).not.toContainText(/Recorded earlier|Expect protection to hold/);
  });
});
