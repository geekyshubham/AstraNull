import path from 'node:path';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { createServer as createViteServer } from 'vite';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  PORTAL_AUDITOR_SESSION,
  PORTAL_SESSION,
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

const T = PORTAL_BASELINE_IDS.tenantId;
const SEEDED_AUDIT_ID = 'aud_cr_seed_policy';
const FAILED_ATTEMPT_ID = 'att_cr_failed';
const SCHEDULED_ATTEMPT_ID = 'att_cr_retry';
const UNKNOWN_ATTEMPT_ID = 'att_cr_unknown';
const ORPHAN_ATTEMPT_ID = 'att_cr_orphan';
const OUTSIDE_WINDOW_AUDIT_ID = 'aud_cr_outside_window';
const RULE_ID = 'nrule_cr_webhook';
const BOUND_POLICY_ID = 'pol_cr_bound';
const FUTURE = '2099-03-02T09:30:00.000Z';
const FROZEN_REPORT_ID = 'rpt_cr_frozen_group';
const SNAPSHOT_ONLY_RUN_ID = 'run_cr_snapshot_only';
const SNAPSHOT_EVIDENCE_IDS = ['ev_cr_snapshot_a', 'ev_cr_snapshot_b'];
const ENGINEER_SESSION = Object.freeze({ ...PORTAL_SESSION, user_id: 'usr_engineer', role: 'engineer' });
const VIEWER_SESSION = Object.freeze({ ...PORTAL_SESSION, user_id: 'usr_viewer', role: 'viewer' });

let sourceBaseUrl = '';
let vite;

function applyCustomerPagesFixture(store) {
  applyPortalBaselineReadinessBoost(store);
  const at = '2026-07-01T12:00:00.000Z';
  store.testPolicies.push({
    id: BOUND_POLICY_ID,
    tenant_id: T,
    target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
    target_id: PORTAL_BASELINE_IDS.targetId,
    check_id: PORTAL_BASELINE_IDS.checkId,
    cadence: 'weekly',
    timezone: 'Europe/London',
    expected_verdict: 'pass',
    state: 'active',
    enabled: true,
    safe_windows: [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'Europe/London' }],
    next_run_at: FUTURE,
    schedule_revision: 1,
    created_at: at,
    updated_at: at,
  });
  store.auditLog.push({
    id: OUTSIDE_WINDOW_AUDIT_ID,
    tenant_id: T,
    timestamp: '2026-06-01T08:00:00.000Z',
    created_at: '2026-06-01T08:00:00.000Z',
    actor_user_id: 'usr_owner',
    actor_role: 'owner',
    action: 'target.declared',
    resource_type: 'target',
    resource_id: PORTAL_BASELINE_IDS.targetId,
    metadata: { source: 'manual' },
    entry_hash: 'b'.repeat(64),
  });
  for (let index = 0; index < 205; index += 1) {
    store.auditLog.push({
      id: `aud_cr_fill_${String(index).padStart(3, '0')}`,
      tenant_id: T,
      timestamp: '2026-06-15T08:00:00.000Z',
      created_at: '2026-06-15T08:00:00.000Z',
      actor_user_id: 'usr_engineer',
      actor_role: 'engineer',
      action: 'finding.updated',
      resource_type: 'finding',
      resource_id: PORTAL_BASELINE_IDS.findingId,
      metadata: {},
      entry_hash: 'c'.repeat(64),
    });
  }
  store.auditLog.push({
    id: SEEDED_AUDIT_ID,
    tenant_id: T,
    sequence: 1,
    timestamp: at,
    created_at: at,
    actor_user_id: 'usr_owner',
    actor_role: 'owner',
    action: 'test_policy.updated',
    resource_type: 'test_policy',
    resource_id: BOUND_POLICY_ID,
    metadata: { changed_fields: 'cadence' },
    prev_hash: null,
    entry_hash: 'a'.repeat(64),
  });
  store.notificationRules.push({
    id: RULE_ID,
    tenant_id: T,
    channel: 'webhook',
    destination: 'https://hooks.example.invalid/astranull-test',
    destination_preview: 'https://hooks.example.invalid/…',
    triggers: ['finding.high_severity'],
    enabled: true,
    created_at: at,
    created_by: 'usr_owner',
  });
  store.notificationEvents.push({
    id: 'nev_cr_1',
    tenant_id: T,
    trigger: 'finding.high_severity',
    subject: 'High-severity finding on checkout.acme.com',
    created_at: at,
    delivery_attempts: [
      { id: FAILED_ATTEMPT_ID, rule_id: RULE_ID, channel: 'webhook', destination_preview: 'https://hooks.example.invalid/…', status: 'provider_failed_dlq', reason: 'webhook_http_410', attempt_number: 3, max_attempts: 3, created_at: at },
    ],
  }, {
    id: 'nev_cr_2',
    tenant_id: T,
    trigger: 'report.ready',
    subject: 'Report ready',
    created_at: '2026-07-02T12:00:00.000Z',
    delivery_attempts: [
      { id: SCHEDULED_ATTEMPT_ID, rule_id: RULE_ID, channel: 'webhook', destination_preview: 'https://hooks.example.invalid/…', status: 'provider_retry_scheduled', reason: 'webhook_timeout', attempt_number: 1, max_attempts: 3, created_at: '2026-07-02T12:00:00.000Z' },
    ],
  }, {
    id: 'nev_cr_3',
    tenant_id: T,
    trigger: 'safe_test.completed',
    subject: 'Safe test completed',
    created_at: '2026-07-03T12:00:00.000Z',
    delivery_attempts: [
      { id: UNKNOWN_ATTEMPT_ID, rule_id: RULE_ID, channel: 'webhook', destination_preview: 'https://hooks.example.invalid/…', status: 'provider_outcome_unknown', reason: 'socket_closed_after_send', created_at: '2026-07-03T12:00:00.000Z' },
      { id: ORPHAN_ATTEMPT_ID, rule_id: 'nrule_cr_removed', channel: 'email', destination_preview: 'o…@example.invalid', status: 'provider_failed_dlq', reason: 'smtp_mailbox_unavailable', attempt_number: 3, max_attempts: 3, created_at: '2026-07-03T12:00:00.000Z' },
    ],
  });
  store.findings.push({
    id: 'fnd_cr_live_after_report',
    tenant_id: T,
    target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
    target_id: PORTAL_BASELINE_IDS.targetId,
    test_run_id: 'run_checkout_1',
    check_id: PORTAL_BASELINE_IDS.checkId,
    severity: 's1',
    title: 'Opened after the report snapshot',
    status: 'open',
    state: 'open',
    opened_at: '2026-09-01T00:00:00.000Z',
    created_at: '2026-09-01T00:00:00.000Z',
  });
  store.reports.push({
    id: FROZEN_REPORT_ID,
    tenant_id: T,
    kind: 'technical',
    title: 'Checkout group snapshot',
    status: 'ready',
    period: 'last-30-days',
    run_ids: ['run_checkout_1', SNAPSHOT_ONLY_RUN_ID],
    created_at: at,
    created_by: 'usr_owner',
    summary: {
      as_of: at,
      as_of_source: 'report_generation_clock',
      snapshot_frozen: true,
      readiness_score: null,
      readiness_score_status: 'unknown',
      readiness_score_scope: 'tenant',
      readiness_score_reason: 'published_readiness_formula_is_tenant_wide',
      scope: {
        mode: 'target_groups',
        target_group_ids: [PORTAL_BASELINE_IDS.targetGroupId],
        target_ids: [],
        group_refs: [{ id: PORTAL_BASELINE_IDS.targetGroupId, name: 'edge-checkout' }],
        declared_members: { total: 1, included: 1, excluded: 0, total_status: 'exact' },
        period: { status: 'bounded', label: 'Last 30 days', start: '2026-06-01T12:00:00.000Z', end: at, source: 'report_generation_clock' },
      },
      run_ids: ['run_checkout_1', SNAPSHOT_ONLY_RUN_ID],
      run_capture: { total: 2, included: 2, limit: 50 },
      runs_snapshot: [
        { id: 'run_checkout_1', target_id: PORTAL_BASELINE_IDS.targetId, check_id: PORTAL_BASELINE_IDS.checkId, status: 'completed' },
        { id: SNAPSHOT_ONLY_RUN_ID, target_id: PORTAL_BASELINE_IDS.targetId, check_id: PORTAL_BASELINE_IDS.checkId, status: 'failed' },
      ],
      findings_snapshot: {
        items: [{ id: PORTAL_BASELINE_IDS.findingId, title: 'Origin reachable at generation', severity: 's2', status: 'open' }],
        total: 1,
        included: 1,
        open_total: 1,
      },
      evidence_ids: SNAPSHOT_EVIDENCE_IDS,
      evidence_summaries: { items: [] },
      declaration_snapshot: { status: 'captured', items: [{ target_id: PORTAL_BASELINE_IDS.targetId }] },
      sections: { protection_profile: { status: 'not_included' } },
    },
  });
  store.productionReleaseEvidence.push({
    id: 'pre_cr_invalid',
    tenant_id: T,
    kind: 'vector_safety_policy',
    status: 'accepted',
    release_id: 'rel_cr_1',
    validation: { ok: false, missing_fields: ['evidence_uri', 'reviewed_at'] },
    evidence: {},
    created_at: at,
  });
}

/** Records every non-GET API request so a journey can prove inspection made no writes. */
function recordWrites(page) {
  const writes = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith('/v1/') && request.method() !== 'GET') writes.push(`${request.method()} ${url.pathname}`);
  });
  return writes;
}

test.describe('current-release customer pages', () => {
  test.beforeAll(async () => {
    const { baseUrl: apiBaseUrl } = await startPortalPlaywrightServer({ mutate: applyCustomerPagesFixture });
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
    if (!address || typeof address === 'string') throw new Error('Vite source server did not bind a TCP port.');
    sourceBaseUrl = `http://127.0.0.1:${address.port}`;
  });

  test.afterAll(async () => {
    await vite?.close();
    await stopPortalPlaywrightServer();
  });

  test('schedules: one presentation, exact check link with caller context, recorded timing only', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'test-policies', sourceBaseUrl);

    await expect(page.getByRole('heading', { level: 1, name: 'Validation schedules' })).toBeVisible();
    await expect(page.locator('.variant-switch, .design-variant-switch')).toHaveCount(0);

    const bound = page.getByRole('row').filter({ hasText: 'checkout.acme.com' }).filter({ hasText: 'Weekly' });
    await expect(bound).toContainText('Europe/London');
    await expect(bound).toContainText('Scheduled');

    const legacy = page.getByRole('row').filter({ hasText: 'No exact target' }).first();
    await expect(legacy).toContainText('Next run unavailable');
    await expect(legacy).toContainText('does not dispatch');
    await expect(legacy.getByRole('button', { name: /^Pause schedule/ })).toHaveCount(0);

    await bound.getByRole('link', { name: /Origin Leak Scan/i }).click();
    await expect(page).toHaveURL(new RegExp(`#check-detail\\?id=${PORTAL_BASELINE_IDS.checkId.replaceAll('.', '\\.')}&policy=${BOUND_POLICY_ID}`));
    await expect(page.getByText('Opened from schedule')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Back to schedule' })).toHaveAttribute('href', new RegExp(`policy-detail\\?id=${BOUND_POLICY_ID}`));
    expect(writes).toEqual([]);
  });

  test('schedule detail: immutable binding, edit with dirty guard, pause needs confirmation', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'policy-detail', sourceBaseUrl, { entityIds: { 'policy-detail': BOUND_POLICY_ID } });

    await expect(page.getByRole('heading', { name: 'Will this schedule run?' })).toBeVisible();
    await expect(page.getByText('Europe/London').first()).toBeVisible();

    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    const dialog = page.locator('dialog.form-modal[open]');
    await expect(dialog.getByLabel('Immutable binding')).toContainText('checkout.acme.com');
    await expect(dialog.getByRole('button', { name: 'Save schedule' })).toBeDisabled();
    await dialog.getByRole('button', { name: 'Cadence', exact: true }).click();
    await dialog.getByRole('listbox', { name: 'Cadence' }).getByRole('option', { name: 'Daily' }).click();
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(dialog.getByText('Discard unsaved schedule changes?')).toBeVisible();
    await dialog.getByRole('button', { name: 'Keep editing' }).click();

    const patch = page.waitForRequest((request) => request.method() === 'PATCH' && request.url().includes(`/v1/test-policies/${BOUND_POLICY_ID}`));
    await dialog.getByRole('button', { name: 'Save schedule' }).click();
    expect((await patch).postDataJSON()).toEqual({ cadence: 'daily' });
    await expect(page.getByRole('status').filter({ hasText: 'Schedule updated.' })).toBeVisible();

    await page.getByRole('button', { name: 'Pause', exact: true }).click();
    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toContainText('No run is dispatched to checkout.acme.com while paused');
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('button', { name: 'Pause', exact: true })).toBeVisible();
  });

  test('reports: caller domain is preselected exactly, reviewed, generated without export, and previewed', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await page.goto(`${sourceBaseUrl}/app#reports?target=${PORTAL_BASELINE_IDS.targetId}`, { waitUntil: 'networkidle' });

    await expect(page.getByRole('radio', { name: 'Selected domains' })).toBeChecked();
    await expect(page.getByRole('list', { name: 'Declared domains' }).getByRole('checkbox', { name: /checkout.acme.com/ })).toBeChecked();
    await expect(page.getByRole('button', { name: 'Generate report' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Review report' })).toBeDisabled();
    await page.getByRole('radio', { name: /Technical/ }).check();
    await page.getByRole('button', { name: 'Review report' }).click();

    const review = page.getByRole('region', { name: 'Review before generating' });
    await expect(review.getByRole('heading', { name: 'Review before generating' })).toBeFocused();
    await expect(review).toContainText('checkout.acme.com');
    await expect(review).toContainText('Not included: the published formula covers the whole workspace');
    await expect(review).not.toContainText('Whole workspace');

    const post = page.waitForRequest((request) => request.method() === 'POST' && new URL(request.url()).pathname === '/v1/reports');
    await review.getByRole('button', { name: 'Generate report' }).click();
    const body = (await post).postDataJSON();
    expect(body.target_ids).toEqual([PORTAL_BASELINE_IDS.targetId]);
    for (const key of ['target_group_ids', 'run_ids', 'target_id', 'target_group_id', 'scope']) expect(body).not.toHaveProperty(key);

    const preview = page.locator('.report-generated-preview');
    await expect(preview).toContainText('Generated:');
    await expect(preview).toContainText('Nothing is exported until you choose a format');
    await expect(preview.locator('.kv-list > div').filter({ hasText: /^Scope/ })).toContainText('1 target(s)');
    await expect(preview.locator('.kv-list > div').filter({ hasText: 'Readiness score' })).toContainText('Not included');
    await expect(preview.getByRole('button', { name: 'Export', exact: true })).toBeVisible();
    expect(writes).toEqual(['POST /v1/reports']);
  });

  test('reports: an unknown caller domain is shown and removable, never replaced, and whole workspace sends no scope', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await page.goto(`${sourceBaseUrl}/app#reports?target=tgt_missing_example`, { waitUntil: 'networkidle' });

    await expect(page.getByRole('alert').filter({ hasText: 'Not visible in this workspace: tgt_missing_example. Nothing else was selected in its place.' })).toBeVisible();
    await expect(page.getByRole('list', { name: 'Declared domains' }).getByRole('checkbox', { checked: true })).toHaveCount(0);
    await page.getByRole('radio', { name: /Technical/ }).check();
    await expect(page.getByRole('button', { name: 'Review report' })).toBeDisabled();
    await page.getByRole('button', { name: 'Remove tgt_missing_example' }).click();
    await expect(page.getByText('Not visible in this workspace')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Review report' })).toBeDisabled();

    await page.getByRole('radio', { name: 'Whole workspace' }).check();
    await page.getByRole('button', { name: 'Review report' }).click();
    const review = page.getByRole('region', { name: 'Review before generating' });
    await expect(review).toContainText('Whole workspace');
    const post = page.waitForRequest((request) => request.method() === 'POST' && new URL(request.url()).pathname === '/v1/reports');
    await review.getByRole('button', { name: 'Generate report' }).click();
    const body = (await post).postDataJSON();
    for (const key of ['target_ids', 'target_group_ids', 'run_ids']) expect(body).not.toHaveProperty(key);
    await expect(page.locator('.report-generated-preview')).toContainText('Whole workspace');
    expect(writes).toEqual(['POST /v1/reports']);
  });

  test('reports: a rejected scope keeps every choice and shows the server reason; an unadvertised scope is never promised', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await page.route('**/v1/reports', async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      return route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ error: 'scope_too_large', status: 400, field: 'declared_members', count: 140, limit: 100 }) });
    });
    await page.goto(`${sourceBaseUrl}/app#reports?target=${PORTAL_BASELINE_IDS.targetId}`, { waitUntil: 'networkidle' });
    await page.getByRole('radio', { name: /Technical/ }).check();
    await page.getByRole('button', { name: 'Review report' }).click();
    await page.getByRole('region', { name: 'Review before generating' }).getByRole('button', { name: 'Generate report' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'The scope is too large: 140 declared targets, limit 100. Choose fewer domains.' })).toBeVisible();
    await expect(page.getByRole('list', { name: 'Declared domains' }).getByRole('checkbox', { name: /checkout.acme.com/ })).toBeChecked();
    await expect(page.getByRole('radio', { name: /Technical/ })).toBeChecked();
    await expect(page.locator('.report-generated-preview')).toHaveCount(0);
    await page.unroute('**/v1/reports');

    await page.route(/\/v1\/reports(\?.*)?$/, async (route) => {
      if (route.request().method() !== 'GET') return route.continue();
      const response = await route.fetch();
      const payload = await response.json();
      delete payload.capabilities.scope;
      return route.fulfill({ response, json: payload });
    });
    await page.goto(`${sourceBaseUrl}/app#dashboard`, { waitUntil: 'networkidle' });
    await page.goto(`${sourceBaseUrl}/app#reports?target=${PORTAL_BASELINE_IDS.targetId}`, { waitUntil: 'networkidle' });
    await page.reload({ waitUntil: 'networkidle' });
    await expect(page.getByRole('alert').filter({ hasText: 'This server does not advertise domain-scoped reports. The saved scope was not applied and no other domain was selected.' })).toBeVisible();
    await expect(page.getByRole('radio', { name: /Selected domains/ })).toBeDisabled();
    await expect(page.getByRole('list', { name: 'Declared domains' })).toHaveCount(0);
    await page.getByRole('radio', { name: /Technical/ }).check();
    await expect(page.getByRole('button', { name: 'Review report' })).toBeDisabled();
    await page.getByRole('radio', { name: 'Whole workspace' }).check();
    await expect(page.getByRole('button', { name: 'Review report' })).toBeEnabled();
  });

  test('report detail: legacy snapshot is labeled, live status is separate, one export menu, nothing verifies on open', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'report-detail', sourceBaseUrl);

    await expect(page.getByRole('note').filter({ hasText: 'This is a legacy report' })).toBeVisible();
    await expect(page.getByRole('heading', { name: /At generation/ })).toBeVisible();
    await expect(page.getByRole('heading', { name: /Current status/ })).toBeVisible();
    const snapshot = page.getByRole('region', { name: /At generation/ });
    await expect(snapshot.locator('.kv-list > div').filter({ hasText: 'Open findings at generation' })).toContainText('1');
    await expect(snapshot.getByText('Opened after the report snapshot')).toHaveCount(0);
    const live = page.getByRole('region', { name: /Current status/ });
    await expect(live.getByText('Opened after the report snapshot')).toBeVisible();
    await expect(snapshot.locator('table tbody tr')).toHaveCount(1);
    await expect(snapshot.locator('table tbody tr')).toContainText('run_checkout_1');
    await expect(page.getByRole('button', { name: /^Export/ })).toHaveCount(1);
    await page.getByRole('button', { name: 'Export', exact: true }).click();
    await expect(page.getByRole('button', { name: /JSON/ })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('button', { name: /JSON/ })).toHaveCount(0);
    expect(writes).toEqual([]);
  });

  test('report detail: a frozen scoped snapshot shows every stored reference and no borrowed score', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'report-detail', sourceBaseUrl, { entityIds: { 'report-detail': FROZEN_REPORT_ID } });

    await expect(page.getByRole('note').filter({ hasText: 'This is a legacy report' })).toHaveCount(0);
    const snapshot = page.getByRole('region', { name: /At generation/ });
    await expect(snapshot.locator('.kv-list > div').filter({ hasText: /^Scope/ })).toContainText('Historical domain scope');
    await expect(snapshot.locator('.kv-list > div').filter({ hasText: 'Runs captured' })).toContainText('2 of 2');
    await expect(snapshot.locator('.kv-list > div').filter({ hasText: 'Open findings at generation' })).toContainText('1');
    await expect(snapshot).toContainText('Not included: the published readiness formula covers the whole workspace');
    await expect(snapshot.locator('.readiness-gauge, [aria-label*="Readiness score"]')).toHaveCount(0);

    const runs = snapshot.locator('.card').filter({ hasText: 'Runs captured by this report (2)' });
    await expect(runs.locator('tbody tr')).toHaveCount(2);
    await expect(runs.locator('tbody tr').filter({ hasText: SNAPSHOT_ONLY_RUN_ID })).toContainText('Failed');

    const findings = snapshot.locator('.card').filter({ hasText: 'Findings captured (1 of 1)' });
    await expect(findings).toContainText('Origin reachable at generation');
    await expect(findings).not.toContainText('Opened after the report snapshot');

    const evidence = snapshot.locator('.card').filter({ hasText: 'Evidence references (2)' });
    for (const id of SNAPSHOT_EVIDENCE_IDS) await expect(evidence).toContainText(id);
    await expect(snapshot).toContainText('not included in this report');
    expect(writes).toEqual([]);
  });

  test('audit: exact incoming event is selected; recorded hash is not verification; missing IDs are never substituted', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await page.goto(`${sourceBaseUrl}/app#audit?event=${SEEDED_AUDIT_ID}`, { waitUntil: 'networkidle' });
    const detail = page.getByRole('region', { name: 'Selected audit event' });
    await expect(detail).toContainText(SEEDED_AUDIT_ID);
    await expect(detail).toContainText('This records that the action happened');
    await expect(detail).not.toContainText('Loaded by exact ID');
    await expect(page.getByText('This page does not verify the hash chain')).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Recorded hash' })).toBeVisible();

    await page.goto(`${sourceBaseUrl}/app#audit?event=aud_missing_example`, { waitUntil: 'networkidle' });
    await expect(page.getByText('Event aud_missing_example does not exist in this workspace. Nothing else was selected in its place.')).toBeVisible();
    await expect(page.getByRole('region', { name: 'Selected audit event' })).toHaveCount(0);

    const writes = recordWrites(page);
    const exactRead = page.waitForRequest((request) => new URL(request.url()).pathname === `/v1/audit-log/${OUTSIDE_WINDOW_AUDIT_ID}`);
    await page.goto(`${sourceBaseUrl}/app#audit?event=${OUTSIDE_WINDOW_AUDIT_ID}`, { waitUntil: 'networkidle' });
    await exactRead;
    const older = page.getByRole('region', { name: 'Selected audit event' });
    await expect(older).toContainText(OUTSIDE_WINDOW_AUDIT_ID);
    await expect(older).toContainText('Loaded by exact ID; it is not on the current page of results.');
    await expect(older).toContainText('b'.repeat(64));
    await expect(page.getByRole('row', { name: new RegExp(`target.*${PORTAL_BASELINE_IDS.targetId}`, 'i') })).toHaveCount(0);
    expect(writes).toEqual([]);
  });

  test('audit: filters and paging run on the server with its total and survive in the address', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'audit', sourceBaseUrl);

    const pager = page.getByRole('navigation', { name: 'Audit pages' });
    await expect(pager).toContainText('Page 1');
    await expect(page.locator('table tbody tr')).toHaveCount(50);
    await expect(pager.getByRole('button', { name: 'Newer' })).toBeDisabled();
    const olderRequest = page.waitForRequest((request) => new URL(request.url()).pathname === '/v1/audit-log' && new URL(request.url()).searchParams.has('cursor'));
    await pager.getByRole('button', { name: 'Older' }).click();
    await olderRequest;
    await expect(pager).toContainText('Page 2');
    await pager.getByRole('button', { name: 'Newer' }).click();
    await expect(pager).toContainText('Page 1');

    const auditList = (predicate) => page.waitForResponse((response) => new URL(response.url()).pathname === '/v1/audit-log' && predicate(new URL(response.url()).searchParams));
    await page.getByRole('combobox', { name: 'Action' }).fill('test_policy.updated');
    const filtered = auditList((params) => params.get('action') === 'test_policy.updated');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    const actionPage = await (await filtered).json();
    expect(actionPage.total).toBeGreaterThanOrEqual(1);
    expect(actionPage.items.every((entry) => entry.action === 'test_policy.updated')).toBe(true);
    await expect(page.getByText(new RegExp(`^${actionPage.total} matching for the applied filters`))).toBeVisible();
    await expect(page.locator('table tbody tr')).toHaveCount(actionPage.items.length);
    await expect(page).toHaveURL(/[?&]category=test_policy\.updated/);

    await page.getByRole('combobox', { name: 'Action' }).fill('');
    await page.getByRole('combobox', { name: 'Resource type or ID' }).fill(BOUND_POLICY_ID);
    const byResource = auditList((params) => params.get('resource') === BOUND_POLICY_ID && !params.has('action'));
    await page.getByRole('button', { name: 'Apply filters' }).click();
    const resourcePage = await (await byResource).json();
    expect(resourcePage.items.every((entry) => entry.resource_type === BOUND_POLICY_ID || entry.resource_id === BOUND_POLICY_ID)).toBe(true);
    const resourceTotal = new RegExp(`^${resourcePage.total} matching for the applied filters`);
    await expect(page.getByText(resourceTotal)).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`[?&]resource=${BOUND_POLICY_ID}`));
    await page.reload({ waitUntil: 'networkidle' });
    await expect(page.getByRole('combobox', { name: 'Resource type or ID' })).toHaveValue(BOUND_POLICY_ID);
    await expect(page.getByText(resourceTotal)).toBeVisible();

    await page.getByRole('combobox', { name: 'Action' }).fill('no.such.action');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(page.getByText('No events match these filters.')).toBeVisible();
    await page.getByRole('button', { name: 'Clear filters' }).first().click();
    await expect(pager).toContainText('Page 1');

    await page.getByLabel(/^From/).fill('2026-07-02');
    await page.getByLabel(/^To/).fill('2026-07-01');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'The start date is after the end date' })).toBeVisible();
    expect(writes).toEqual([]);
  });

  test('support: exact event link only for audit-readable roles; summary is copy-only', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'support', sourceBaseUrl);
    await expect(page.getByRole('link', { name: `View audit event ${SEEDED_AUDIT_ID}` })).toHaveAttribute('href', `#audit?event=${SEEDED_AUDIT_ID}`);
    const seededRef = page.getByRole('checkbox', { name: new RegExp(SEEDED_AUDIT_ID) });
    await expect(page.locator('label').filter({ has: seededRef })).not.toContainText('Time not recorded');
    await seededRef.check();
    await expect(page.getByLabel('Summary preview')).toContainText(SEEDED_AUDIT_ID);
    await page.getByLabel('Your note (optional)').fill('password: hunter2');
    await page.getByRole('button', { name: 'Copy summary' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'looks like it contains a credential' })).toBeVisible();
    expect(writes).toEqual([]);
  });

  test('support: engineer cannot open audit events from support', async ({ page }) => {
    await injectPortalDevHeadersSession(page, ENGINEER_SESSION);
    await gotoPortalRoute(page, 'support', sourceBaseUrl);
    await expect(page.getByRole('link', { name: /View audit event/ })).toHaveCount(0);
  });

  test('notifications: failed attempt opens its own channel and retry needs a preview first', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'notifications', sourceBaseUrl);

    await page.getByRole('row', { name: /Inspect failed delivery for High-severity finding/ }).click();
    const detail = page.getByRole('region', { name: 'Selected delivery attempt' });
    await expect(detail).toContainText('webhook_http_410');
    await expect(detail).toContainText('3 of 3');
    await expect(detail.getByRole('link', { name: 'Fix channel configuration' })).toHaveAttribute('href', `#integrations?focus=${RULE_ID}`);
    await expect(detail.getByRole('button', { name: 'Retry delivery' })).toBeDisabled();
    expect(writes).toEqual([]);

    await page.getByRole('row', { name: /Inspect retry scheduled delivery/ }).click();
    await expect(page.getByRole('region', { name: 'Selected delivery attempt' })).toContainText('No manual retry is offered');
    await expect(page.getByRole('button', { name: 'Retry delivery' })).toHaveCount(0);

    await page.getByRole('row', { name: /Inspect provider outcome unknown delivery/ }).click();
    const unknown = page.getByRole('region', { name: 'Selected delivery attempt' });
    await expect(unknown).toContainText('socket_closed_after_send');
    await expect(unknown).toContainText('The outcome is unknown, so retry is not offered');
    await expect(unknown.getByRole('button', { name: /Retry/ })).toHaveCount(0);
    await expect(unknown.getByRole('link', { name: 'Fix channel configuration' })).toHaveAttribute('href', `#integrations?focus=${RULE_ID}`);
    await expect(page).toHaveURL(new RegExp(`focus=${UNKNOWN_ATTEMPT_ID}`));

    await page.getByRole('row', { name: /Inspect failed delivery for Safe test completed/ }).click();
    const orphan = page.getByRole('region', { name: 'Selected delivery attempt' });
    await expect(orphan).toContainText('smtp_mailbox_unavailable');
    await expect(orphan).toContainText('Rule removed or not recorded');
    await expect(orphan.getByRole('link', { name: 'Fix channel configuration' })).toHaveCount(0);

    await page.reload({ waitUntil: 'networkidle' });
    await expect(page.getByRole('region', { name: 'Selected delivery attempt' })).toContainText('smtp_mailbox_unavailable');
    expect(writes).toEqual([]);
  });

  test('integrations: a failure link focuses the exact channel; configured is not delivered', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await page.goto(`${sourceBaseUrl}/app#integrations?focus=${RULE_ID}`, { waitUntil: 'networkidle' });
    await expect(page.getByText('from a delivery failure. It is highlighted below.')).toBeVisible();
    const channels = page.getByRole('region', { name: 'Notification channels' });
    await expect(channels.getByRole('columnheader', { name: 'Last attempt' })).toBeVisible();
    await expect(channels.locator('tr[aria-selected="true"]')).toHaveCount(1);
    await expect(page.getByRole('heading', { name: 'Read-only credential polling' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Manual metadata only' })).toBeVisible();
  });

  test('integrations: connector last attempt is the newest recorded outcome, and unknown without recorded failures', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    let shape = 'dev';
    await page.route(/\/v1\/connectors(\?.*)?$/, async (route) => {
      if (route.request().method() !== 'GET') return route.continue();
      const response = await route.fetch();
      const payload = await response.json();
      const first = (payload.items ?? []).find((item) => item.id === PORTAL_BASELINE_IDS.connectorId);
      if (first) first.secret_id = 'sec_cr_reference_only';
      if (first && shape === 'older-error') Object.assign(first, { last_success_at: '2026-07-03T10:00:00.000Z', last_error_at: '2026-07-01T10:00:00.000Z' });
      if (first && shape === 'newer-error') Object.assign(first, { last_success_at: '2026-07-01T10:00:00.000Z', last_error_at: '2026-07-03T10:00:00.000Z' });
      return route.fulfill({ response, json: payload });
    });
    const connectorTable = () => page.locator('table').filter({ hasText: 'Last successful sync' }).first();
    const connectorRow = () => connectorTable().locator('tbody tr').filter({ hasText: 'Cloudflare checkout' });
    const attemptCell = () => connectorRow().locator('td[data-label="Last attempt"]');

    await gotoPortalRoute(page, 'integrations', sourceBaseUrl);
    await expect(connectorRow()).toHaveCount(1);
    await expect(attemptCell()).toHaveText('Not recorded');
    const manualRows = connectorTable().locator('tbody tr').filter({ has: page.locator('td[data-label="Last successful sync"]', { hasText: 'Not applicable' }) });
    for (const row of await manualRows.all()) await expect(row.locator('td[data-label="Last attempt"]')).toHaveText('Not applicable');

    shape = 'older-error';
    await page.reload({ waitUntil: 'networkidle' });
    await expect(attemptCell()).toContainText('Succeeded');
    await expect(attemptCell()).toContainText('Jul 3');
    await expect(attemptCell()).not.toContainText('Failed');

    shape = 'newer-error';
    await page.reload({ waitUntil: 'networkidle' });
    await expect(attemptCell()).toContainText('Failed');
    await expect(attemptCell()).toContainText('Jul 3');
    await expect(connectorRow().locator('td[data-label="Last successful sync"]')).toContainText('Jul 1');
    expect(writes).toEqual([]);
  });

  test('settings: tab is addressable and shortening retention requires a review', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await page.goto(`${sourceBaseUrl}/app#settings?tab=privacy`, { waitUntil: 'networkidle' });
    const panel = page.locator('#settings-sections-panel-privacy');
    await expect(panel).toBeVisible();
    await expect(page.locator('#settings-sections-panel-access')).toBeHidden();
    await expect(page.locator('#settings-sections-panel-security')).toBeHidden();
    await panel.getByLabel('Metadata retention (days)').fill('30');
    await panel.getByRole('button', { name: 'Save retention policy' }).click();
    const confirm = page.locator('dialog.modal-confirm[open]');
    await expect(confirm).toContainText('Metadata (events, vault metadata, notification history)');
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await panel.getByLabel('Metadata retention (days)').fill('0');
    await panel.getByRole('button', { name: 'Save retention policy' }).click();
    await expect(panel.getByRole('alert')).toContainText('from 1 to 3650');
    expect(writes).toEqual([]);
  });

  test('plan and usage: named truthfully, no deferred high-scale usage, access is not configuration', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'subscription', sourceBaseUrl);
    await expect(page.getByRole('heading', { level: 1, name: 'Plan & usage' })).toBeVisible();
    await expect(page.getByText('High-scale requests')).toHaveCount(0);
  });

  test('release evidence: accepted-but-invalid is a failure with its reason; full missing list', async ({ page }) => {
    await injectPortalDevHeadersSession(page, PORTAL_AUDITOR_SESSION);
    await gotoPortalRoute(page, 'release-evidence', sourceBaseUrl);
    const row = page.getByRole('row', { name: /Inspect Vector safety policy record/i });
    await expect(row).toContainText('Accepted but invalid');
    await row.click();
    await expect(page.getByRole('region', { name: /record detail/ })).toContainText('evidence_uri, reviewed_at');
    await expect(page.getByText(/^…and \d+ more kinds/)).toHaveCount(0);
  });

  test('check library: target-first deep link, separate counts, no design switch', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    const fit = page.waitForResponse((response) => new URL(response.url()).pathname === `/v1/targets/${PORTAL_BASELINE_IDS.targetId}/compatible-checks`);
    await page.goto(`${sourceBaseUrl}/app#checks?target=${PORTAL_BASELINE_IDS.targetId}`, { waitUntil: 'networkidle' });
    const serverChecks = ((await (await fit).json()).checks ?? []).filter((check) => check.safety_class === 'safe');
    await expect(page.locator('.design-variant-switch')).toHaveCount(0);
    const facts = page.getByLabel('Catalog and check counts');
    await expect(facts).toContainText('Catalog vectors');
    await expect(facts).toContainText('Runnable checks');
    await expect(facts).toContainText('Fit this target');
    await expect(facts.locator('div').filter({ hasText: 'Fit this target' }).locator('dd').first()).toHaveText(String(serverChecks.length));
    await expect(page.locator('.vector-target-note')).toContainText('checkout.acme.com');
  });

  test('check detail: exact read with server compatibility for the caller target; unknown check is not substituted', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    const exact = page.waitForRequest((request) => new URL(request.url()).pathname === `/v1/checks/${PORTAL_BASELINE_IDS.checkId}`);
    const compat = page.waitForRequest((request) => new URL(request.url()).pathname === `/v1/targets/${PORTAL_BASELINE_IDS.targetId}/compatible-checks`);
    await page.goto(`${sourceBaseUrl}/app#check-detail?id=${PORTAL_BASELINE_IDS.checkId}&target=${PORTAL_BASELINE_IDS.targetId}`, { waitUntil: 'networkidle' });
    await exact;
    await compat;
    const context = page.locator('.check-caller-context');
    await expect(context).toContainText('checkout.acme.com');
    await expect(context).toContainText('this check is compatible with it (launch gates are evaluated only when a run starts).');

    await page.goto(`${sourceBaseUrl}/app#check-detail?id=origin.missing_example.safe`, { waitUntil: 'networkidle' });
    await expect(page.getByText('Check not found.')).toBeVisible();
    await expect(page.getByText('no other check is substituted')).toBeVisible();
    expect(writes).toEqual([]);
  });

  test('check library: review returns focus on Escape and read-only roles get no launch controls', async ({ page }) => {
    await injectPortalDevHeadersSession(page, VIEWER_SESSION);
    await page.goto(`${sourceBaseUrl}/app#checks?target=${PORTAL_BASELINE_IDS.targetId}`, { waitUntil: 'networkidle' });
    const review = page.getByRole('button', { name: /^Review / }).first();
    await review.click();
    const dialog = page.locator('dialog.form-modal[open]');
    await expect(dialog.getByRole('heading', { name: 'Mapped checks' })).toBeVisible();
    await expect(dialog.getByRole('button', { name: 'Review run' })).toHaveCount(0);
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(review).toBeFocused();
  });

  test('targets: domain first and direct intake has no grouping selector', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'targets', sourceBaseUrl);
    await expect(page.getByRole('link', { name: 'Open target checkout.acme.com', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Add target', exact: true }).click();
    const intake = page.locator('.targets-intake-form');
    await expect(intake.getByLabel('Value', { exact: true })).toBeVisible();
    await expect(intake.getByRole('button', { name: 'Group', exact: true })).toHaveCount(0);
    await expect(page.locator('.targets-intake')).not.toContainText(/\bgroup\b/i);
    expect(writes).toEqual([]);
  });

  test('artifact detail: returns to findings, recorded hash stays unverified', async ({ page }) => {
    const writes = recordWrites(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'evidence-detail', sourceBaseUrl);
    await expect(page.getByRole('link', { name: /Back to Findings/ })).toHaveAttribute('href', '#findings');
    await expect(page.getByText('Server verification')).toBeVisible();
    await expect(page.getByText(/^Not verified \((recorded hash only|no hash or verification recorded)\)$/)).toBeVisible();
    expect(writes).toEqual([]);
  });

  for (const theme of ['dark', 'light']) {
    test(`accessibility: assigned customer pages have no serious or critical axe violations (${theme})`, async ({ page }) => {
      test.setTimeout(180_000);
      await page.addInitScript((value) => localStorage.setItem('astranull.theme', value), theme);
      const routes = [
        ['targets', PORTAL_SESSION],
        [`checks?target=${PORTAL_BASELINE_IDS.targetId}`, PORTAL_SESSION],
        [`check-detail?id=${PORTAL_BASELINE_IDS.checkId}&policy=${BOUND_POLICY_ID}`, PORTAL_SESSION],
        ['test-policies', PORTAL_SESSION],
        [`policy-detail?id=${BOUND_POLICY_ID}`, PORTAL_SESSION],
        ['reports', PORTAL_SESSION],
        ['report-detail?id=rpt_checkout_baseline', PORTAL_SESSION],
        ['evidence-detail?id=art_probe_checkout_1', PORTAL_SESSION],
        [`integrations?focus=${RULE_ID}`, PORTAL_SESSION],
        [`notifications?focus=${FAILED_ATTEMPT_ID}`, PORTAL_SESSION],
        [`audit?event=${SEEDED_AUDIT_ID}`, PORTAL_SESSION],
        ['settings?tab=privacy', PORTAL_SESSION],
        ['support', PORTAL_SESSION],
        ['subscription', PORTAL_SESSION],
        ['release-evidence', PORTAL_AUDITOR_SESSION],
      ];
      const failures = [];
      for (const [hash, session] of routes) {
        await page.addInitScript((value) => sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify(value)), session);
        await page.goto(`${sourceBaseUrl}/app#${hash}`, { waitUntil: 'networkidle' });
        await page.waitForFunction(() => !document.querySelector('.route-transition.is-entering'));
        const result = await new AxeBuilder({ page }).include('main').analyze();
        for (const violation of result.violations) {
          if (['serious', 'critical'].includes(violation.impact ?? '')) failures.push(`${hash}: ${violation.id} (${violation.nodes.length})`);
        }
      }
      expect(failures).toEqual([]);
    });
  }

  test('200% zoom with reduced motion: no page overflow, keyboard-only schedule edit keeps its footer reachable', async ({ page }) => {
    test.setTimeout(180_000);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 640, height: 800 });
    await injectPortalDevHeadersSession(page);
    const overflowing = [];
    for (const hash of ['targets', 'test-policies', `policy-detail?id=${BOUND_POLICY_ID}`, 'reports', 'report-detail?id=rpt_checkout_baseline', `notifications?focus=${FAILED_ATTEMPT_ID}`, `audit?event=${SEEDED_AUDIT_ID}`, 'settings?tab=access', 'support', 'subscription', `checks?target=${PORTAL_BASELINE_IDS.targetId}`]) {
      await page.goto(`${sourceBaseUrl}/app#${hash}`, { waitUntil: 'networkidle' });
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      if (overflow > 1) overflowing.push(`${hash}: ${overflow}px`);
    }
    expect(overflowing).toEqual([]);

    await page.goto(`${sourceBaseUrl}/app#policy-detail?id=${BOUND_POLICY_ID}`, { waitUntil: 'networkidle' });
    const edit = page.getByRole('button', { name: 'Edit', exact: true });
    await edit.focus();
    await page.keyboard.press('Enter');
    const dialog = page.locator('dialog.form-modal[open]');
    await expect(dialog).toBeVisible();
    const transitions = await dialog.evaluate((node) => getComputedStyle(node).transitionDuration);
    expect(transitions.split(',').every((value) => Number.parseFloat(value) === 0)).toBe(true);
    const save = dialog.getByRole('button', { name: 'Save schedule' });
    await save.scrollIntoViewIfNeeded();
    await expect(save).toBeInViewport();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(edit).toBeFocused();
  });

  test('coarse pointer at 390px: interactive targets on assigned pages meet the touch minimum', async ({ browser }) => {
    test.setTimeout(180_000);
    const context = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
    const page = await context.newPage();
    await injectPortalDevHeadersSession(page);
    const small = [];
    for (const hash of ['targets', 'test-policies', `policy-detail?id=${BOUND_POLICY_ID}`, 'reports', 'report-detail?id=rpt_checkout_baseline', `notifications?focus=${FAILED_ATTEMPT_ID}`, `audit?event=${SEEDED_AUDIT_ID}`, 'support', 'subscription', 'settings', `checks?target=${PORTAL_BASELINE_IDS.targetId}`, `integrations?focus=${RULE_ID}`]) {
      await page.goto(`${sourceBaseUrl}/app#${hash}`, { waitUntil: 'networkidle' });
      const found = await page.evaluate(() => {
        const out = [];
        for (const el of document.querySelectorAll('main button, main a[href], main input:not([type=hidden]), main select, main textarea, main [role="button"]')) {
          const rect = el.getBoundingClientRect();
          if (rect.width === 0 && rect.height === 0) continue;
          const style = getComputedStyle(el);
          if (style.visibility === 'hidden' || style.display === 'none' || style.pointerEvents === 'none' || Number(style.opacity) === 0) continue;
          const tag = el.tagName.toLowerCase();
          const type = (el.getAttribute('type') || '').toLowerCase();
          if (tag === 'a' && el.closest('p, li, dd, .muted, .kv-list, code')) continue;
          const minHeight = tag === 'input' && (type === 'checkbox' || type === 'radio') ? 24 : 44;
          if (rect.height + 0.5 < minHeight || rect.width + 0.5 < 24) out.push(`${tag}[${(el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 32)}] ${Math.round(rect.width)}x${Math.round(rect.height)}`);
        }
        return out;
      });
      for (const item of found) small.push(`${hash}: ${item}`);
    }
    await context.close();
    expect(small).toEqual([]);
  });

  test('viewer: audit log is denied without listing events', async ({ page }) => {
    await injectPortalDevHeadersSession(page, VIEWER_SESSION);
    await page.goto(`${sourceBaseUrl}/app#audit`, { waitUntil: 'networkidle' });
    await expect(page.getByText(SEEDED_AUDIT_ID)).toHaveCount(0);
  });
});
