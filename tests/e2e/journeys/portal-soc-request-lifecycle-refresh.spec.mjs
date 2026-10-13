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
  PORTAL_SESSION,
  PORTAL_STAFF_SOC_SESSION,
  waitForPortalRouteSettled,
} from '../../helpers/portal-playwright-session.mjs';

/**
 * SOC request lifecycle refresh (queue-detail).
 *
 * Every lifecycle action re-reads the request instead of trusting the POST body or a page
 * reload: after Stop the page reads STOPPED with no Stop control, a stopped request with no
 * post-test report offers the attach form (a 404 is "no report yet", not an error), and a
 * customer who records an artifact sees it listed. All traffic stays inside the governed
 * dry-run adapter stub of the in-memory dev store; no request reaches a declared target.
 */

const RUNNING_ID = 'hsr_lifecycle_running';
const PACK_ID = 'hsr_lifecycle_pack';
const EXPIRED_ID = 'hsr_checkout_scheduled';
const ARTIFACTS_ID = 'hsr_lifecycle_artifacts';
const APPROVED_ID = 'hsr_lifecycle_approved';
const HOUR_MS = 60 * 60 * 1000;

function applyLifecycleFixture(store) {
  applyPortalBaselineReadinessBoost(store);
  const now = Date.now();
  const iso = (offset) => new Date(now + offset).toISOString();
  const base = {
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
    target_ids: [PORTAL_BASELINE_IDS.targetId],
    scope_hash: 'scope_hash_lifecycle',
    scope_confirmation: true,
    requested_scenario_families: ['http_get_flood'],
    delivery_patterns: ['direct'],
    requested_limits: { max_rps: 500, max_duration_minutes: 30 },
    emergency_contacts: [{ name: 'Synthetic On-call', role: 'SRE', contact: 'oncall@example.invalid' }],
    abort_criteria: { error_rate_above_pct: 5, auto_stop: true },
    created_by: 'usr_owner',
    artifacts: [],
  };
  store.highScaleRequests.push(
    {
      ...base,
      id: RUNNING_ID,
      state: 'running',
      reason: 'Lifecycle refresh drill',
      objective: 'Lifecycle refresh drill',
      created_at: iso(-3 * HOUR_MS),
      requested_window: { window_start: iso(-2 * HOUR_MS), window_end: iso(4 * HOUR_MS), timezone: 'UTC' },
      scheduled_window: { window_start: iso(-1 * HOUR_MS), window_end: iso(2 * HOUR_MS), scope_hash: base.scope_hash },
      soc_approvals: [{ user_id: 'soc1', at: iso(-2 * HOUR_MS) }, { user_id: 'soc2', at: iso(-2 * HOUR_MS) }],
      adapter: { status: 'stub_running', started_at: iso(-30 * 60 * 1000), traffic_generated: false, last_action: 'start' },
      audit_trail: [
        { action: 'approve', at: iso(-2 * HOUR_MS), by: 'soc1' },
        { action: 'schedule', at: iso(-90 * 60 * 1000), by: 'soc1' },
        { action: 'start', at: iso(-30 * 60 * 1000), by: 'soc2' },
      ],
    },
    {
      ...base,
      id: PACK_ID,
      state: 'submitted',
      reason: 'Authorization pack drill',
      objective: 'Authorization pack drill',
      created_at: iso(-HOUR_MS),
      requested_window: { window_start: iso(24 * HOUR_MS), window_end: iso(26 * HOUR_MS), timezone: 'UTC' },
      soc_approvals: [],
      audit_trail: [],
    },
    {
      ...base,
      id: ARTIFACTS_ID,
      state: 'submitted',
      reason: 'Artifact review drill',
      objective: 'Artifact review drill',
      created_at: iso(-HOUR_MS),
      requested_window: { window_start: iso(24 * HOUR_MS), window_end: iso(26 * HOUR_MS), timezone: 'UTC' },
      soc_approvals: [],
      audit_trail: [],
      artifacts: [
        { id: 'art_tp_old', type: 'test_plan', status: 'rejected', uploader: 'usr_owner', filename_redacted: 'plan-v1.pdf', created_at: iso(-50 * 60 * 1000), reviewed_by: 'soc1', reviewed_at: iso(-45 * 60 * 1000), review_notes: 'Missing rate plan.' },
        { id: 'art_tp_new', type: 'test_plan', status: 'pending_review', uploader: 'usr_engineer', filename_redacted: 'plan-v2.pdf', created_at: iso(-30 * 60 * 1000) },
        { id: 'art_extra', type: 'provider_approval', status: 'pending_review', uploader: 'usr_owner', filename_redacted: 'provider-note.pdf', created_at: iso(-20 * 60 * 1000) },
      ],
    },
    {
      ...base,
      id: APPROVED_ID,
      state: 'approved',
      reason: 'Schedule drill',
      objective: 'Schedule drill',
      created_at: iso(-HOUR_MS),
      requested_window: { window_start: iso(24 * HOUR_MS), window_end: iso(26 * HOUR_MS), timezone: 'UTC' },
      soc_approvals: [{ user_id: 'soc1', at: iso(-HOUR_MS) }, { user_id: 'soc2', at: iso(-HOUR_MS) }],
      audit_trail: [],
    },
  );
}

async function markDocument(page) {
  await page.evaluate(() => { window.__lifecycleNoReload = true; });
}

async function expectNoReload(page) {
  expect(await page.evaluate(() => window.__lifecycleNoReload === true), 'the page must not reload to show the new state').toBe(true);
}

test.describe('SOC request lifecycle refresh (queue-detail)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyLifecycleFixture });
  });
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('staff SOC: Stop stays in the first viewport on every tab and adapter polling never disables it', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page, PORTAL_STAFF_SOC_SESSION);
    await page.route('**/adapter-status', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      await route.continue();
    });
    await gotoPortalRoute(page, 'queue-detail', baseUrl, { entityIds: { 'queue-detail': RUNNING_ID } });

    const banner = page.getByTestId('soc-live-banner');
    await expect(banner).toContainText('LIVE · Governed high-scale traffic is running', { timeout: 20_000 });
    const stop = page.getByRole('button', { name: 'Stop now' });
    await expect(stop).toHaveCount(1);
    await expect(stop).toBeEnabled();
    await expect(page.getByText(/^Pre-flight gates: \d+\/\d+ passed at start\.$/)).toBeVisible();

    for (const tab of ['Workspace', 'Artifacts', 'Provider', 'Adapter', 'Notes']) {
      await page.getByRole('tab', { name: tab, exact: true }).click();
      await page.evaluate(() => window.scrollTo(0, 0));
      await expect(stop, `Stop is visible on the ${tab} tab`).toBeInViewport();
      await expect(stop).toBeEnabled();
    }
  });

  test('staff SOC: Stop re-reads the request, then a stopped request attaches its report and closes', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page, PORTAL_STAFF_SOC_SESSION);
    await gotoPortalRoute(page, 'queue-detail', baseUrl, { entityIds: { 'queue-detail': RUNNING_ID } });
    await expect(page.getByTestId('soc-live-banner')).toBeVisible({ timeout: 20_000 });
    await markDocument(page);

    await page.getByRole('button', { name: 'Stop now' }).click();
    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toContainText('Stop governed traffic');
    await confirm.getByRole('button', { name: 'Stop traffic' }).click();
    await expect(confirm).toBeHidden({ timeout: 15_000 });

    const kpis = page.getByRole('group', { name: 'Request summary' });
    await expect(kpis).toContainText('Stopped', { timeout: 15_000 });
    await expect(page.getByTestId('soc-live-banner')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /^Stop/ })).toHaveCount(0);
    await expectNoReload(page);

    await expect(page.getByText('Post-test report status could not be loaded.')).toHaveCount(0);
    const close = page.getByRole('button', { name: 'Close', exact: true });
    await expect(close).toBeDisabled();
    const summary = page.getByLabel('Customer summary');
    await expect(summary).toBeVisible();
    await summary.fill('Synthetic governed drill stopped on schedule; no customer impact observed.');
    await page.getByRole('button', { name: 'Attach post-test report' }).click();
    await expect(close).toBeEnabled({ timeout: 15_000 });

    await close.click();
    await expect(confirm).toContainText('Close governed request');
    await confirm.getByRole('button', { name: 'Close request' }).click();
    await expect(kpis).toContainText('Closed', { timeout: 15_000 });
    await expectNoReload(page);
  });

  test('staff SOC: a scheduled window that ended months ago reads expired and keeps Start disabled', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page, PORTAL_STAFF_SOC_SESSION);
    await gotoPortalRoute(page, 'queue-detail', baseUrl, { entityIds: { 'queue-detail': EXPIRED_ID } });

    const kpis = page.getByRole('group', { name: 'Request summary' });
    await expect(kpis).toContainText('Window expired', { timeout: 20_000 });
    await expect(kpis).toContainText('Reschedule required');
    const gates = page.getByRole('list', { name: 'Request gates' });
    const windowGate = gates.getByRole('listitem').filter({ hasText: 'Inside scheduled safe window' });
    await expect(windowGate).toContainText('reschedule required');
    await expect(windowGate).toContainText('pending');
    await expect(page.getByText(/Confirmed safe window|Safe window confirmed/)).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Start', exact: true })).toBeDisabled();
    await expect(page.locator('#soc-start-disabled-reason')).toContainText('Start stays disabled until every request gate passes');
  });

  test('staff SOC: every uploaded artifact stays reviewable and a rejection needs a reason', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page, PORTAL_STAFF_SOC_SESSION);
    await gotoPortalRoute(page, 'queue-detail', baseUrl, { entityIds: { 'queue-detail': ARTIFACTS_ID } });
    await page.getByRole('tab', { name: 'Artifacts', exact: true }).click({ timeout: 20_000 });

    const rows = page.getByTestId('soc-artifact-review-row');
    await expect(rows).toHaveCount(3);
    const current = rows.filter({ hasText: 'plan-v2.pdf' });
    await expect(current).toContainText('usr_engineer');
    await expect(current.getByRole('button', { name: 'Accept', exact: true })).toBeVisible();
    const earlier = rows.filter({ hasText: 'earlier upload' });
    await expect(earlier).toContainText('plan-v1.pdf');
    await expect(earlier).toContainText('Missing rate plan.');
    await expect(earlier.getByRole('button')).toHaveCount(0);

    const extra = rows.filter({ hasText: 'Not part of the required authorization pack' });
    await expect(extra).toContainText('provider-note.pdf');
    await extra.getByRole('button', { name: 'Reject', exact: true }).click();
    const confirm = page.locator('dialog.modal-confirm[open]');
    const rejectButton = confirm.getByRole('button', { name: 'Reject artifact' });
    await expect(rejectButton).toBeDisabled();
    await confirm.getByLabel('Reason shown to the customer').fill('Provider note does not name the approver.');
    await rejectButton.click();
    await expect(confirm).toBeHidden({ timeout: 15_000 });
    await expect(extra).toContainText('Provider note does not name the approver.', { timeout: 15_000 });
    await expect(extra.getByRole('button')).toHaveCount(0);
  });

  test.describe('schedule confirmation in a non-UTC viewer timezone', () => {
    test.use({ timezoneId: 'Asia/Kolkata' });

    test('staff SOC: the schedule confirm names one viewer timezone and the customer timezone separately', async ({ page }) => {
      const baseUrl = getPortalPlaywrightBaseUrl();
      await injectPortalDevHeadersSession(page, PORTAL_STAFF_SOC_SESSION);
      await gotoPortalRoute(page, 'queue-detail', baseUrl, { entityIds: { 'queue-detail': APPROVED_ID } });
      const form = page.getByRole('form', { name: 'Schedule governed window' });
      await expect(form).toBeVisible({ timeout: 20_000 });
      await expect(form).toContainText('customer timezone UTC');
      await form.getByRole('button', { name: 'Schedule', exact: true }).click();
      const confirm = page.locator('dialog.modal-confirm[open]');
      await expect(confirm).toContainText(/Times are shown in your timezone \(Asia\/(?:Kolkata|Calcutta)\); the customer requested this window in UTC\./);
      await expect(confirm).not.toContainText(/GMT\+5:30\s+UTC/);
      await confirm.getByRole('button', { name: 'Cancel' }).click();
      await expect(confirm).toBeHidden();
    });
  });

  test('customer: a recorded authorization artifact is listed without a reload', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    await injectPortalDevHeadersSession(page, PORTAL_SESSION);
    await page.goto(`${baseUrl}/app#queue-detail?id=${PACK_ID}`, { waitUntil: 'networkidle', timeout: 60_000 });
    await waitForPortalRouteSettled(page);
    await expect(page.getByText('You cannot start it from the portal.', { exact: false })).toBeVisible({ timeout: 20_000 });
    await markDocument(page);

    await page.getByRole('tab', { name: 'Authorization pack' }).click();
    const recorded = page.locator('.artifact-upload-card__meta');
    await expect(recorded).toContainText('No artifact records returned.');
    const card = page.locator('.artifact-upload-card').filter({ hasText: 'Test Plan' }).first();
    await card.getByLabel('File name').fill('synthetic-test-plan.pdf');
    await card.getByLabel('Content digest (SHA-256)').fill('c'.repeat(64));
    await card.getByRole('button', { name: 'Record artifact' }).click();

    await expect(recorded).toContainText('Test Plan', { timeout: 15_000 });
    await expect(recorded).not.toContainText('No artifact records returned.');
    await expect(card).not.toContainText('No Test Plan metadata uploaded yet');
    await expectNoReload(page);
  });
});
