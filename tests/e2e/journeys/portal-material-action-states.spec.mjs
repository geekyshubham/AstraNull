import { expect, test } from '@playwright/test';
import { getStore } from '../../../src/store.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import { buildPortalActionInventory, assertSourcePortalAction } from '../../helpers/portal-action-coverage.mjs';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, getPortalPlaywrightBaseUrl } from '../../helpers/portal-playwright-server.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';

const inventory = buildPortalActionInventory();
const browserDiagnostics = new WeakMap();
const expectedFailures = new WeakMap();
const confirm = (page) => page.locator('dialog.modal-confirm:not(.form-modal)[open]');
const record = (testInfo, query, route, state, assertions) => assertSourcePortalAction(testInfo, inventory, query, state, assertions, { route });
async function open(page, route) { await injectPortalDevHeadersSession(page); await gotoPortalRoute(page, route, getPortalPlaywrightBaseUrl()); }
async function failFirstPost(page, path, payload = (request) => request.postDataJSON(), method = 'POST') {
  const writes = [];
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  await page.route(`**${path}`, async (route) => {
    if (route.request().method() !== method) return route.continue();
    writes.push(payload(route.request()));
    if (writes.length === 1) { expectedFailures.get(page)?.set(route.request().url(), 1); await held; return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'temporary_unavailable' }) }); }
    return route.continue();
  });
  return { writes, release };
}

test.describe('actual remaining material transactions: declared scope, snapshots, in-app routing, organization and retention', () => {
  test.beforeAll(async () => { await startPortalPlaywrightServer({ liveSource: true }); });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });
  test.beforeEach(async ({ page }) => {
    const allowed = new Map(); expectedFailures.set(page, allowed);
    const failures = await collectPortalBrowserFailures(page, getPortalPlaywrightBaseUrl(), { allowResponse(response) {
      if (response.status() !== 503 || !['POST', 'PATCH'].includes(response.request().method()) || allowed.get(response.url()) !== 1) return false;
      allowed.set(response.url(), 0); return true;
    } });
    browserDiagnostics.set(page, failures);
  });
  test.afterEach(async ({ page }) => { browserDiagnostics.get(page)?.assertClean(); });

  test('target native invalid/close, delayed failed create and exact retry persist declared unverified scope only', async ({ page }, testInfo) => {
    const failure = await failFirstPost(page, '/v1/targets');
    await open(page, 'targets');
    await page.getByRole('button', { name: 'Add target', exact: true }).click();
    const form = page.locator('#target-declare-form');
    const query = { owner: 'TargetsPage', kind: 'form-keyboard', handler: 'addTarget' };
    await form.getByRole('button', { name: 'Add target', exact: true }).click();
    await record(testInfo, query, 'targets', 'invalid', async () => {
      expect(await form.getByLabel('Value', { exact: true }).evaluate((input) => input.validity.valueMissing)).toBe(true);
      expect(failure.writes).toEqual([]);
      return ['Empty required declared target rejects native submission before any POST'];
    });
    await page.locator('.targets-intake').getByRole('button', { name: 'Close', exact: true }).click();
    await record(testInfo, { owner: 'TargetsPage', label: 'Close' }, 'targets', 'cancel', async () => {
      await expect(form).toHaveCount(0); expect(failure.writes).toEqual([]);
      return ['Closing declaration form removes it and sends zero target writes'];
    });
    await page.getByRole('button', { name: 'Add target', exact: true }).click();
    await form.getByLabel('Value', { exact: true }).fill('synthetic-action-retry.example.test');
    await form.getByLabel(/^Tags/).fill('env:synthetic, tier:edge');
    await form.getByRole('button', { name: 'Add target', exact: true }).click();
    try {
      await record(testInfo, query, 'targets', 'busy', async () => {
        await expect.poll(() => failure.writes.length).toBe(1);
        await expect(form.getByRole('button', { name: /Add target|Working/ })).toBeDisabled();
        await form.getByLabel('Value', { exact: true }).evaluate((input) => {
          input.dataset.enterHandled = 'pending';
          input.addEventListener('keyup', (event) => { if (event.key === 'Enter') input.dataset.enterHandled = 'complete'; }, { once: true });
        });
        await form.getByLabel('Value', { exact: true }).press('Enter');
        await expect(form.getByLabel('Value', { exact: true })).toHaveAttribute('data-enter-handled', 'complete');
        await expect(form.getByRole('button', { name: /Add target|Working/ })).toBeDisabled();
        expect(failure.writes).toHaveLength(1);
        return ['Held target create disables submit and keyboard activation causes no duplicate POST'];
      });
    } finally { failure.release(); }
    await expect(page.getByRole('alert')).toContainText('Service is temporarily unavailable');
    await expect(form.getByLabel('Value', { exact: true })).toHaveValue('synthetic-action-retry.example.test');
    const accepted = page.waitForResponse((response) => response.url().endsWith('/v1/targets') && response.request().method() === 'POST' && response.status() === 201);
    await form.getByRole('button', { name: 'Add target', exact: true }).click();
    const target = await (await accepted).json();
    await record(testInfo, query, 'targets', 'error-retry', async () => {
      expect(failure.writes).toHaveLength(2); expect(failure.writes[1]).toEqual(failure.writes[0]);
      expect(target.tags).toEqual(['env:synthetic', 'tier:edge']);
      await expect(page).toHaveURL(new RegExp(`#target-detail\\?id=${target.id}`));
      expect(getStore().targets.filter((item) => item.value === target.value)).toHaveLength(1);
      expect(getStore().probeJobs.filter((job) => job.target_id === target.id && job.state === 'running')).toEqual([]);
      return ['Explicit retry writes exactly the same declaration once, routes to the new ID, and never executes a probe for an unverified target'];
    });
    await page.reload({ waitUntil: 'networkidle' });
    await record(testInfo, query, 'targets', 'reload', async () => {
      await expect(page.getByRole('heading', { name: target.value, exact: true })).toBeVisible();
      expect(getStore().targets.filter((item) => item.value === target.value)).toHaveLength(1); expect(failure.writes).toHaveLength(2);
      return ['Reload preserves exact newly declared target metadata and does not replay its creation'];
    });
  });

  test('CSV invalid file, Escape clears draft, held import failure and explicit byte-equivalent retry create declared targets once', async ({ page }, testInfo) => {
    const csv = 'kind,value\nfqdn,csv-action-first.example.test\nfqdn,csv-action-second.example.test';
    const failure = await failFirstPost(page, '/v1/targets:csv', (request) => {
      const body = request.postDataBuffer().toString('utf8');
      const match = body.match(/filename="([^"]+)"[\s\S]*?\r\n\r\n([\s\S]*?)\r\n--/);
      expect(match).not.toBeNull(); return { filename: match[1], bytes: match[2] };
    });
    await open(page, 'targets');
    await page.getByRole('button', { name: 'Import CSV', exact: true }).click();
    const modal = page.locator('dialog.form-modal[open]');
    const file = modal.getByLabel('CSV file', { exact: true });
    await file.setInputFiles({ name: 'invalid.txt', mimeType: 'text/plain', buffer: Buffer.from(csv) });
    await record(testInfo, { owner: 'TargetCsvImportButton', kind: 'field', handler: 'handleFileChange' }, 'targets', 'invalid', async () => {
      await expect(modal.getByRole('alert')).toContainText('Choose a .csv file.');
      await expect(modal.getByRole('button', { name: 'Import', exact: true })).toBeDisabled(); expect(failure.writes).toEqual([]);
      return ['Wrong file extension rejects local import and disables submit before any multipart write'];
    });
    await file.setInputFiles({ name: 'declared.csv', mimeType: 'text/csv', buffer: Buffer.from(csv) });
    await expect(modal.getByRole('status')).toContainText('2 target rows ready');
    await modal.press('Escape');
    await record(testInfo, { owner: 'TargetCsvImportButton', label: 'Import targets from CSV' }, 'targets', 'cancel', async () => {
      await expect(modal).toHaveCount(0); expect(failure.writes).toEqual([]);
      await page.getByRole('button', { name: 'Import CSV', exact: true }).click();
      expect(await file.evaluate((input) => input.files.length)).toBe(0);
      await expect(modal.getByRole('button', { name: 'Import', exact: true })).toBeDisabled();
      return ['Escape closes import with zero writes and clears selected file on reopening'];
    });
    await file.setInputFiles({ name: 'declared.csv', mimeType: 'text/csv', buffer: Buffer.from(csv) });
    const query = { owner: 'TargetCsvImportButton', kind: 'form-keyboard', handler: 'handleSubmit' };
    await modal.getByRole('button', { name: 'Import 2 targets', exact: true }).click();
    try {
      await record(testInfo, query, 'targets', 'busy', async () => {
        await expect.poll(() => failure.writes.length).toBe(1);
        await expect(file).toBeDisabled(); await expect(modal.getByRole('button', { name: 'Cancel', exact: true })).toBeDisabled();
        await modal.press('Escape'); await expect(modal).toBeVisible(); expect(failure.writes).toHaveLength(1);
        return ['Held import disables file/cancel, ignores modal Escape while submitting, and sends one multipart request'];
      });
    } finally { failure.release(); }
    await expect(modal.getByRole('alert')).toContainText('Something went wrong on the server');
    const accepted = page.waitForResponse((response) => response.url().endsWith('/v1/targets:csv') && response.request().method() === 'POST' && response.status() === 201);
    await modal.getByRole('button', { name: 'Import 2 targets', exact: true }).click();
    const result = await (await accepted).json();
    await record(testInfo, query, 'targets', 'error-retry', async () => {
      expect(failure.writes).toHaveLength(2); expect(failure.writes[1]).toEqual(failure.writes[0]); expect(failure.writes[0]).toEqual({ filename: 'declared.csv', bytes: csv });
      expect(result.created).toHaveLength(2); expect(result.errors).toEqual([]);
      await expect(modal.getByRole('status')).toContainText('Created 2 targets');
      for (const target of result.created) expect(getStore().probeJobs.filter((job) => job.target_id === target.id && job.state === 'running')).toEqual([]);
      return ['Explicit retry preserves exactly selected filename/file bytes, creates two declared targets once, and runs no unverified probe'];
    });
    await page.reload({ waitUntil: 'networkidle' });
    await record(testInfo, query, 'targets', 'reload', async () => {
      for (const target of result.created) { expect(getStore().targets.filter((item) => item.id === target.id)).toHaveLength(1); await expect(page.getByRole('link', { name: `Verify ownership of ${target.value}`, exact: true })).toBeVisible(); }
      expect(failure.writes).toHaveLength(2);
      return ['Reload retains both actual declared IDs without replaying CSV creation'];
    });
  });

  test('report review cancel, delayed failed generation, exact retry, export menu keyboard cancel, JSON download and server custody verification', async ({ page }, testInfo) => {
    const failure = await failFirstPost(page, '/v1/reports');
    await open(page, 'reports');
    await page.locator('input[name="report_kind"][value="technical"]').check();
    await page.getByRole('button', { name: 'Review report', exact: true }).click();
    await page.getByRole('button', { name: 'Change choices', exact: true }).click();
    await record(testInfo, { owner: 'ReportsPage', label: 'Change choices' }, 'reports', 'cancel', async () => {
      expect(failure.writes).toEqual([]); await expect(page.locator('.report-review')).toHaveCount(0);
      await expect(page.locator('input[name="report_kind"][value="technical"]')).toBeChecked();
      return ['Change choices cancels review without generation and preserves selected technical audience'];
    });
    await page.getByRole('button', { name: 'Review report', exact: true }).click();
    const query = { owner: 'ReportsPage', handler: 'void handleGenerate()' };
    await page.getByRole('button', { name: 'Generate report', exact: true }).click();
    try {
      await record(testInfo, query, 'reports', 'busy', async () => {
        await expect.poll(() => failure.writes.length).toBe(1);
        await expect(page.getByRole('button', { name: /Generate report|Working/ })).toBeDisabled();
        await expect(page.getByRole('button', { name: 'Change choices', exact: true })).toBeDisabled();
        return ['Report generate and change-choices controls disabled while exact snapshot admission request is held'];
      });
    } finally { failure.release(); }
    await expect(page.getByRole('alert')).toContainText(/temporarily unavailable|temporary unavailable/);
    await expect(page.locator('input[name="report_kind"][value="technical"]')).toBeChecked();
    const accepted = page.waitForResponse((response) => response.url().endsWith('/v1/reports') && response.request().method() === 'POST' && response.status() === 201);
    await page.getByRole('button', { name: 'Generate report', exact: true }).click();
    const report = await (await accepted).json();
    await record(testInfo, query, 'reports', 'error-retry', async () => {
      expect(failure.writes).toHaveLength(2); expect(failure.writes[1]).toEqual(failure.writes[0]);
      await expect(page.locator('.report-generated-preview')).toContainText(report.title);
      expect(getStore().reports.filter((item) => item.id === report.id)).toHaveLength(1);
      return ['Failed report keeps selected choices; explicit identical retry creates one frozen snapshot with exact accepted ID'];
    });
    const preview = page.locator('.report-generated-preview');
    const exports = [];
    page.on('request', (request) => { if (request.url().includes(`/v1/reports/${report.id}/export`)) exports.push(request.url()); });
    await preview.getByRole('button', { name: 'Export', exact: true }).click();
    await preview.locator('.report-export-menu').press('Escape');
    await record(testInfo, { owner: 'ReportExportMenu', handler: "event.key === 'Escape'" }, 'reports', 'cancel', async () => {
      await expect(preview.locator('.report-export-options')).toHaveCount(0); expect(exports).toEqual([]);
      await expect(preview.getByRole('button', { name: 'Export', exact: true })).toBeFocused();
      return ['Escape closes export options and returns focus to trigger without any export request'];
    });
    await preview.getByRole('button', { name: 'Export', exact: true }).click();
    const download = page.waitForEvent('download');
    await preview.locator('.report-export-options').getByRole('button', { name: /^JSON/ }).click();
    expect((await download).suggestedFilename()).toBe(`${report.id}.json`);
    await expect(preview.locator('.report-export-result')).toContainText('Not verified yet');
    await preview.getByRole('button', { name: /Verify/ }).click();
    await expect(preview.locator('.report-export-result')).toContainText('Verified by the server');
    expect(exports).toHaveLength(1);
    await page.reload({ waitUntil: 'networkidle' });
    await record(testInfo, query, 'reports', 'reload', async () => {
      await expect(page.getByRole('link', { name: report.title, exact: true })).toBeVisible();
      expect(failure.writes).toHaveLength(2); expect(getStore().reports.filter((item) => item.id === report.id)).toHaveLength(1);
      return ['Report reload lists the accepted frozen snapshot and does not regenerate/export it automatically'];
    });
  });

  test('notification events: an in-app channel from Integrations, then validation, local cancel, delayed failure and retry add events with no outbound sends', async ({ page }, testInfo) => {
    await open(page, 'integrations');
    await page.getByRole('button', { name: 'Connect In-app', exact: true }).click();
    const inAppDialog = page.locator('dialog.form-modal[open]');
    for (const field of await inAppDialog.locator('input[name="triggers"]').all()) await field.uncheck();
    await inAppDialog.locator('input[value="finding.high_severity"]').check();
    const created = page.waitForResponse((response) => response.url().endsWith('/v1/notifications') && response.request().method() === 'POST' && response.status() === 201);
    await inAppDialog.getByRole('button', { name: 'Turn on in-app feed', exact: true }).click();
    const channel = await (await created).json();
    expect(channel.channel).toBe('in_app');
    expect(channel.triggers).toEqual(['finding.high_severity']);

    const failure = await failFirstPost(page, `/v1/notifications/${channel.id}`, (request) => request.postDataJSON(), 'PATCH');
    await open(page, 'notifications');
    await page.locator('button[aria-expanded="false"]').filter({ hasText: /^Choose events$/ }).click();
    const form = page.locator('form').filter({ has: page.locator('input[name="triggers"]') });
    await expect(form.getByText('High-scale state change', { exact: true })).toBeVisible();
    const query = { owner: 'NotificationsPage', kind: 'form-keyboard', handler: 'handleAddEvents' };
    await form.getByRole('button', { name: 'Channel', exact: true }).click();
    await page.getByRole('option', { name: /^In-app/ }).click();
    for (const field of await form.locator('input[name="triggers"]').all()) await field.uncheck();
    await form.getByRole('button', { name: 'Add events', exact: true }).click();
    await record(testInfo, query, 'notifications', 'invalid', async () => {
      await expect(page.getByRole('alert')).toContainText('Choose at least one event to route'); expect(failure.writes).toEqual([]);
      return ['No-event routing form rejects before any API write'];
    });
    await form.locator('input[value="report.ready"]').check();
    await form.locator('input[value="high_scale.state_change"]').check();
    await form.getByRole('button', { name: 'Cancel', exact: true }).click();
    await record(testInfo, { owner: 'NotificationsPage', label: 'Cancel' }, 'notifications', 'cancel', async () => {
      expect(failure.writes).toEqual([]); await expect(form).toHaveCount(0);
      return ['Cancel closes the local events draft with zero API writes'];
    });
    await page.locator('button[aria-expanded="false"]').filter({ hasText: /^Choose events$/ }).click();
    await expect(form.locator('input[value="report.ready"]')).toBeChecked();
    await expect(form.locator('input[value="high_scale.state_change"]')).toBeChecked();
    await expect(form.getByRole('button', { name: 'Channel', exact: true })).toContainText('In-app');
    const beforeAttempts = getStore().notificationDeliveryAttempts?.length ?? 0;
    await form.getByRole('button', { name: 'Add events', exact: true }).click();
    try {
      await record(testInfo, query, 'notifications', 'busy', async () => {
        await expect.poll(() => failure.writes.length).toBe(1); await expect(form.getByRole('button', { name: /Add events|Working/ })).toBeDisabled();
        await expect(form.locator('input[value="report.ready"]')).toBeDisabled();
        return ['Held events update disables submit/event controls and keeps the chosen events'];
      });
    } finally { failure.release(); }
    await expect(page.getByRole('alert')).toContainText('Service is temporarily unavailable');
    const accepted = page.waitForResponse((response) => response.url().endsWith(`/v1/notifications/${channel.id}`) && response.request().method() === 'PATCH' && response.status() === 200);
    await form.getByRole('button', { name: 'Add events', exact: true }).click();
    const rule = await (await accepted).json();
    await record(testInfo, query, 'notifications', 'error-retry', async () => {
      expect(failure.writes).toHaveLength(2); expect(failure.writes[1]).toEqual(failure.writes[0]);
      expect(rule.channel).toBe('in_app');
      expect([...rule.triggers].sort()).toEqual(['finding.high_severity', 'high_scale.state_change', 'report.ready']);
      expect(getStore().notificationDeliveryAttempts?.length ?? 0).toBe(beforeAttempts);
      await expect(form).toHaveCount(0);
      return ['Explicit identical retry adds events to the existing in-app channel; saving causes no notification delivery/outbound send'];
    });
    await page.reload({ waitUntil: 'networkidle' });
    await record(testInfo, query, 'notifications', 'reload', async () => {
      expect(getStore().notificationRules.filter((item) => item.id === rule.id && !item.deleted_at)).toHaveLength(1); expect(failure.writes).toHaveLength(2);
      await expect(page.getByRole('heading', { name: 'Notifications', exact: true })).toBeVisible();
      return ['Reload keeps one channel with the added events and does not resend the update'];
    });
  });

  test('organization required submission and persisted save; retention bounds and cancelled review never patch, accepted increase reloads', async ({ page }, testInfo) => {
    const patches = [];
    page.on('request', (request) => { if (request.method() === 'PATCH' && request.url().endsWith('/v1/tenants/current')) patches.push(request.postDataJSON()); });
    await open(page, 'settings');
    const organization = page.locator('form').filter({ has: page.getByRole('button', { name: 'Save organization', exact: true }) });
    await organization.getByLabel('Organization name', { exact: true }).fill('');
    await organization.getByRole('button', { name: 'Save organization', exact: true }).click();
    expect(patches).toEqual([]);
    await organization.getByLabel('Organization name', { exact: true }).fill('Synthetic UI action organization');
    await organization.getByRole('button', { name: 'Save organization', exact: true }).click();
    await expect.poll(() => patches.length).toBe(1);
    await record(testInfo, { owner: 'SettingsPage', kind: 'form-keyboard', handler: 'handleSaveOrganization' }, 'settings', 'success', async () => {
      await expect.poll(() => getStore().tenants.find((tenant) => tenant.id === PORTAL_BASELINE_IDS.tenantId)?.name).toBe('Synthetic UI action organization');
      return ['Native required organization input sends zero invalid PATCH; accepted organization name persisted in caller tenant'];
    });
    await page.getByRole('tab', { name: 'Privacy', exact: true }).click();
    const form = page.locator('form').filter({ has: page.getByRole('button', { name: 'Save retention policy', exact: true }) });
    const metadata = form.locator('input[name="metadata_retention_days"]');
    await metadata.fill('0'); await form.getByRole('button', { name: 'Save retention policy', exact: true }).click();
    await expect(form.getByRole('alert')).toBeVisible(); expect(patches).toHaveLength(1);
    await metadata.fill('3650'); await form.getByRole('button', { name: 'Save retention policy', exact: true }).click();
    await confirm(page).getByRole('button', { name: 'Cancel', exact: true }).click();
    await record(testInfo, { owner: 'SettingsPage', handler: 'setPendingRetention(null)' }, 'settings', 'cancel', async () => {
      expect(patches).toHaveLength(1); await expect(metadata).toHaveValue('3650');
      return ['Explicit retention bounds reject zero; cancelling valid increase review sends no PATCH and preserves proposed value'];
    });
    await form.getByRole('button', { name: 'Save retention policy', exact: true }).click();
    await confirm(page).getByRole('button', { name: 'Save retention policy', exact: true }).click();
    await expect.poll(() => patches.length).toBe(2);
    await page.reload({ waitUntil: 'networkidle' });
    await page.getByRole('tab', { name: 'Privacy', exact: true }).click();
    await record(testInfo, { owner: 'SettingsPage', handler: 'confirmSaveRetention' }, 'settings', 'reload', async () => {
      await expect(metadata).toHaveValue('3650'); expect(patches).toHaveLength(2);
      return ['Accepted retention increase survives reload and is not replayed; no shorter deletion window or legal workflow initiated'];
    });
  });
});
