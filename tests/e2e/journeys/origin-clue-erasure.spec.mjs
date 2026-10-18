import path from 'node:path';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { buildPortalActionInventory, assertSourcePortalAction } from '../../helpers/portal-action-coverage.mjs';
import {
  createPortalSourceServer,
  seedPortalPlaywrightStore,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { PORTAL_SESSION, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import { getStore } from '../../../src/store.mjs';
import { createOriginClueService } from '../../../src/services/originClues.mjs';
import { createDevOriginClueRepository } from '../../../src/services/originClueRepository.mjs';

let vite;
let baseUrl;
const endpoint = '/v1/tenants/current/origin-clues/erase';
const counts = { originClues: 3, originClueBatches: 2 };
const inventory = buildPortalActionInventory();
const browserChecks = new WeakMap();
const receipt = (testInfo, handler, kind, state, assertions, dimensions = {}) => assertSourcePortalAction(testInfo, inventory, { owner: 'ErasureForm', handler, kind }, state, assertions, { route: 'settings', ...dimensions });

async function openPrivacy(page, session = PORTAL_SESSION) {
  await injectPortalDevHeadersSession(page, session);
  await page.goto(`${baseUrl}/app#settings?tab=privacy`, { waitUntil: 'networkidle' });
  return page.getByRole('region', { name: 'Erase stored origin clues' });
}

async function review(panel) {
  await panel.getByLabel('Erasure reason').fill('Approved cleanup of retained origin associations');
  await panel.getByRole('button', { name: 'Preview origin-clue erasure' }).click();
  await expect(panel).toContainText('3 clues');
  await expect(panel).toContainText('2 collection batches');
}

test.describe('origin-clue erasure privacy controls', () => {
  test.beforeAll(async () => {
    const { baseUrl: apiBaseUrl } = await startPortalPlaywrightServer({ env: { ASTRANULL_ORIGIN_CLUES_ENABLED_TENANTS: '' } });
    vite = await createPortalSourceServer({
      configFile: path.resolve('vite.config.ts'), logLevel: 'silent',
      server: { host: '127.0.0.1', port: 0, strictPort: false, proxy: { '/v1': apiBaseUrl, '/ready': apiBaseUrl, '/internal': apiBaseUrl } },
    });
    await vite.listen();
    baseUrl = `http://127.0.0.1:${vite.httpServer.address().port}`;
  });
  test.afterAll(async () => { await vite?.close(); await stopPortalPlaywrightServer(); });
  test.beforeEach(async ({ page }) => {
    const expectedStatuses = new Set();
    const diagnostics = await collectPortalBrowserFailures(page, baseUrl, {
      allowResponse: response => new URL(response.url()).pathname === endpoint
        && response.request().method() === 'POST' && expectedStatuses.has(response.status()),
    });
    browserChecks.set(page, { expectedStatuses, diagnostics });
  });
  test.afterEach(async ({ page }, testInfo) => {
    const diagnostics = browserChecks.get(page)?.diagnostics;
    await testInfo.attach('origin-erasure-browser-diagnostics', { body: JSON.stringify(diagnostics?.failures ?? []), contentType: 'application/json' });
    diagnostics?.assertClean();
  });

  test('preview is explicit; cancel never erases; typed tenant confirmation submits only the reviewed scope', async ({ page }, testInfo) => {
    const requests = [];
    await page.route(`**${endpoint}`, async route => {
      const body = route.request().postDataJSON();
      requests.push(body);
      await route.fulfill({ json: { tenant_id: PORTAL_SESSION.tenant_id, dry_run: body.dry_run, legal_hold: false, would_delete: counts, deleted: body.dry_run ? {} : counts, audit_entry_id: body.dry_run ? null : 'aud_owned_erasure' } });
    });
    const panel = await openPrivacy(page);
    expect(requests).toEqual([]);
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
    await review(panel);
    expect(requests).toHaveLength(1);
    expect(requests[0].dry_run).toBe(true);
    await receipt(testInfo, 'submit(true)', 'activate', 'success', async () => {
      await expect(panel).toContainText('3 clues and 2 collection batches');
      expect(requests).toHaveLength(1);
      expect(requests[0]).toEqual({ confirmation_tenant_id: PORTAL_SESSION.tenant_id, reason: 'Approved cleanup of retained origin associations', dry_run: true });
      return ['Explicit preview sends one exact current-tenant dry-run request and renders owned metadata counts, with no erasure'];
    });
    await panel.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
    let dialog = page.locator('dialog.modal-confirm[open]');
    await expect(dialog).toContainText('Targets, origin bindings, runs, findings, and audit records are not erased.');
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await receipt(testInfo, 'submit(false)', 'action-slot', 'cancel', async () => {
      await expect(dialog).toHaveCount(0);
      expect(requests).toHaveLength(1);
      await expect(panel.getByLabel('Erasure reason')).toHaveValue('Approved cleanup of retained origin associations');
      return ['Cancel closes typed confirmation, retains reviewed reason and sends zero destructive requests'];
    });
    await panel.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
    dialog = page.locator('dialog.modal-confirm[open]');
    await expect(dialog.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
    await dialog.getByRole('textbox').fill(PORTAL_SESSION.tenant_id);
    await dialog.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
    await receipt(testInfo, 'submit(false)', 'action-slot', 'success', async () => {
      await expect(panel.getByRole('status')).toContainText('Audit entry: aud_owned_erasure');
      expect(requests.filter(body => body.dry_run === false)).toEqual([{ confirmation_tenant_id: PORTAL_SESSION.tenant_id, reason: 'Approved cleanup of retained origin associations', dry_run: false }]);
      await expect(panel.getByLabel('Erasure reason')).toHaveValue('');
      return ['Exact typed tenant confirmation sends one reviewed destructive payload, renders returned audit ID and clears the local reason; endpoint response is an owned UI fixture, not persisted-erasure proof'];
    });
    expect(requests).toEqual([
      { confirmation_tenant_id: PORTAL_SESSION.tenant_id, reason: 'Approved cleanup of retained origin associations', dry_run: true },
      { confirmation_tenant_id: PORTAL_SESSION.tenant_id, reason: 'Approved cleanup of retained origin associations', dry_run: false },
    ]);
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
  });

  test('a hold from preview blocks erasure even if the loaded policy was older', async ({ page }) => {
    const requests = [];
    await page.route(`**${endpoint}`, async route => {
      const body = route.request().postDataJSON(); requests.push(body);
      await route.fulfill({ json: { tenant_id: PORTAL_SESSION.tenant_id, dry_run: true, legal_hold: true, would_delete: counts, blocked_deletions: counts, deleted: {} } });
    });
    const panel = await openPrivacy(page);
    await review(panel);
    await expect(panel).toContainText('Legal hold blocks erasure');
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
    expect(requests).toHaveLength(1);
    expect(requests[0].dry_run).toBe(true);
  });

  test('preview error can be retried and editing the reason invalidates the previous review', async ({ page }, testInfo) => {
    browserChecks.get(page).expectedStatuses.add(503);
    let attempts = 0;
    await page.route(`**${endpoint}`, async route => {
      attempts += 1;
      if (attempts === 1) return route.fulfill({ status: 503, json: { error: { code: 'temporarily_unavailable', message: 'Owned fixture temporarily unavailable' } } });
      return route.fulfill({ json: { tenant_id: PORTAL_SESSION.tenant_id, dry_run: true, legal_hold: false, would_delete: counts, deleted: {} } });
    });
    const panel = await openPrivacy(page);
    await panel.getByLabel('Erasure reason').fill('Approved cleanup');
    await panel.getByRole('button', { name: 'Preview origin-clue erasure' }).click();
    await expect(panel.getByRole('alert')).toBeVisible();
    await review(panel);
    await receipt(testInfo, 'submit(true)', 'activate', 'error-retry', async () => {
      await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeEnabled();
      await expect(panel.getByRole('alert')).toHaveCount(0);
      expect(attempts).toBe(2);
      return ['Failed owned preview exposes an alert; one explicit retry clears the error and enables confirmation without automatic requests'];
    });
    await panel.getByLabel('Erasure reason').fill('A different approved cleanup');
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
    expect(attempts).toBe(2);
  });

  test('mismatched or malformed previews cannot unlock destructive confirmation', async ({ page }) => {
    let malformed = false;
    const requests = [];
    await page.route(`**${endpoint}`, async route => {
      requests.push(route.request().postDataJSON());
      await route.fulfill({ json: { tenant_id: malformed ? PORTAL_SESSION.tenant_id : 'another-owned-fixture-tenant', dry_run: true, legal_hold: false, would_delete: malformed ? { originClues: -1, originClueBatches: 2 } : counts } });
    });
    const panel = await openPrivacy(page);
    await panel.getByLabel('Erasure reason').fill('Approved cleanup');
    await panel.getByRole('button', { name: 'Preview origin-clue erasure' }).click();
    await expect(panel.getByRole('alert')).toContainText('did not match');
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
    malformed = true;
    await panel.getByRole('button', { name: 'Preview origin-clue erasure' }).click();
    await expect.poll(() => requests.length).toBe(2);
    await expect(panel.getByRole('button', { name: 'Preview origin-clue erasure' })).toBeEnabled();
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
    expect(requests.every(body => body.dry_run === true)).toBe(true);
  });

  test('server hold conflict at confirmation is visible and never automatically retries erasure', async ({ page }) => {
    browserChecks.get(page).expectedStatuses.add(409);
    const requests = [];
    await page.route(`**${endpoint}`, async route => {
      const body = route.request().postDataJSON(); requests.push(body);
      if (!body.dry_run) return route.fulfill({ status: 409, json: { error: 'origin_clue_erasure_legal_hold', message: 'Legal hold blocks erasure.' } });
      return route.fulfill({ json: { tenant_id: PORTAL_SESSION.tenant_id, dry_run: true, legal_hold: false, would_delete: counts } });
    });
    const panel = await openPrivacy(page);
    await review(panel);
    await panel.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
    const dialog = page.locator('dialog.modal-confirm[open]');
    await dialog.getByRole('textbox').fill(PORTAL_SESSION.tenant_id);
    await dialog.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
    await expect(panel.getByRole('alert')).toBeVisible();
    await expect(dialog).toHaveCount(0);
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
    expect(requests).toHaveLength(2);
    expect(requests.filter(body => !body.dry_run)).toHaveLength(1);
  });

  test('leaving during a delayed preview does not republish its result into a reopened form', async ({ page }) => {
    let complete;
    const arrived = new Promise(resolve => { complete = resolve; });
    let release;
    const deferred = new Promise(resolve => { release = resolve; });
    await page.route(`**${endpoint}`, async route => {
      complete();
      await deferred;
      await route.fulfill({ json: { tenant_id: PORTAL_SESSION.tenant_id, dry_run: true, legal_hold: false, would_delete: counts } });
    });
    let panel = await openPrivacy(page);
    await panel.getByLabel('Erasure reason').fill('Approved cleanup');
    await panel.getByRole('button', { name: 'Preview origin-clue erasure' }).click();
    await arrived;
    await page.evaluate(() => { location.hash = '#dashboard'; });
    await expect(panel).toHaveCount(0);
    release();
    await page.evaluate(() => { location.hash = '#settings?tab=privacy'; });
    panel = page.getByRole('region', { name: 'Erase stored origin clues' });
    await expect(panel.getByLabel('Erasure reason')).toHaveValue('');
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
    await expect(panel).not.toContainText('Current preview:');
  });

  test('a role change cannot inherit an outstanding owner preview', async ({ page }) => {
    let release;
    const pending = new Promise(resolve => { release = resolve; });
    let received;
    const arrived = new Promise(resolve => { received = resolve; });
    const requests = [];
    await page.route(`**${endpoint}`, async route => {
      requests.push(route.request().postDataJSON()); received();
      await pending;
      await route.fulfill({ json: { tenant_id: PORTAL_SESSION.tenant_id, dry_run: true, legal_hold: false, would_delete: counts } });
    });
    const panel = await openPrivacy(page);
    await panel.getByLabel('Erasure reason').fill('Approved cleanup');
    await panel.getByRole('button', { name: 'Preview origin-clue erasure' }).click();
    await arrived;
    try {
      await page.getByRole('button', { name: /Role \(dev\)/ }).click();
      await page.getByRole('option', { name: /viewer/i }).click();
      await expect(panel).toContainText('Only an owner or admin');
    } finally { release(); }
    await expect(panel.getByRole('button')).toHaveCount(0);
    await expect(panel).not.toContainText('Current preview:');
    expect(requests).toHaveLength(1);
    expect(requests[0].dry_run).toBe(true);
  });

  for (const theme of ['dark', 'light']) {
    for (const width of [375, 1440]) {
      test(`privacy erasure is accessible and contained at ${width}px in ${theme}`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await page.addInitScript(value => localStorage.setItem('astranull.theme', value), theme);
        const panel = await openPrivacy(page);
        await expect(panel).toBeVisible();
        const scan = await new AxeBuilder({ page }).include('section[aria-labelledby]').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
        expect(scan.violations).toEqual([]);
        expect(await panel.evaluate(element => {
          const box = element.getBoundingClientRect();
          return box.left >= 0 && box.right <= innerWidth + 1 && element.scrollWidth <= element.clientWidth + 1;
        })).toBe(true);
        if (width === 375) {
          for (const button of await panel.getByRole('button').all()) {
            const box = await button.boundingBox();
            expect(box.height).toBeGreaterThanOrEqual(44);
          }
        }
      });
    }
  }

  test('real disabled-feature API erases archived-target metadata and saved copies, with audit retained after reload', async ({ page }, testInfo) => {
    seedPortalPlaywrightStore();
    const store = getStore();
    const tenantId = PORTAL_SESSION.tenant_id;
    const target = store.targets.find(row => row.tenant_id === tenantId && row.kind === 'fqdn');
    expect(target).toBeTruthy();
    const ctx = { tenantId, userId: PORTAL_SESSION.user_id, role: 'owner' };
    const service = createOriginClueService({ repository: createDevOriginClueRepository(), collectDns: async () => { throw new Error('Erasure fixture must never query DNS'); } });
    const input = { source_kind: 'historical_dns', source_ref: 'owned-browser-fixture', records: [{ candidate_ip: '8.8.8.8', associated_hostname: target.normalized_value ?? target.value }] };
    const runtimeConfig = { featureFlags: { originCluesEnabledTenants: { [tenantId]: true } } };
    for (const key of ['browser-origin-first', 'browser-origin-copy']) {
      const result = await service.import(ctx, target.id, input, { runtimeConfig, idempotencyKey: key });
      expect(result.error).toBeUndefined();
    }
    expect(store.originClues.filter(row => row.tenant_id === tenantId)).toHaveLength(1);
    expect(store.originClueBatches.filter(row => row.tenant_id === tenantId)).toHaveLength(2);
    target.deleted_at = new Date().toISOString();
    const preserved = structuredClone({ targets: store.targets, bindings: store.originBindings, runs: store.testRuns, findings: store.findings });
    const requests = [];
    page.on('request', request => { if (new URL(request.url()).pathname === endpoint) requests.push(request.postDataJSON()); });
    try {
      const panel = await openPrivacy(page);
      await panel.getByLabel('Erasure reason').fill('Approved real owned-store cleanup');
      await panel.getByRole('button', { name: 'Preview origin-clue erasure' }).click();
      await expect(panel).toContainText('1 clues and 2 collection batches');
      expect(store.originClues.filter(row => row.tenant_id === tenantId)).toHaveLength(1);
      await panel.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
      const dialog = page.locator('dialog.modal-confirm[open]');
      await dialog.getByRole('textbox').fill(tenantId);
      await dialog.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
      await expect(panel.getByRole('status')).toContainText('Audit entry:');
      const audit = store.auditLog.findLast(row => row.tenant_id === tenantId && row.action === 'privacy.origin_clues_erased');
      expect(audit?.metadata.deleted).toMatchObject({ originClues: 1, originClueBatches: 2 });
      await page.reload({ waitUntil: 'networkidle' });
      await receipt(testInfo, 'submit(false)', 'action-slot', 'reload', async () => {
        expect(store.originClues.filter(row => row.tenant_id === tenantId)).toEqual([]);
        expect(store.originClueBatches.filter(row => row.tenant_id === tenantId)).toEqual([]);
        expect(store.auditLog.some(row => row.id === audit.id)).toBe(true);
        expect({ targets: store.targets, bindings: store.originBindings, runs: store.testRuns, findings: store.findings }).toEqual(preserved);
        await expect(page.getByRole('region', { name: 'Erase stored origin clues' }).getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
        expect(requests.map(body => body.dry_run)).toEqual([true, false]);
        return ['Real owned dev-store API removes archived-target clue and both saved response batches while collection is disabled; page reload retains erased state/audit and unchanged targets/bindings/runs/findings without resubmission. This is not PostgreSQL or process-restart durability proof'];
      });
    } finally { seedPortalPlaywrightStore(); }
  });

  test('pending previews and erasure are single-flight and confirmation cannot dismiss during execution', async ({ page }, testInfo) => {
    const requests = [];
    const releases = [];
    await page.route(`**${endpoint}`, async route => {
      const body = route.request().postDataJSON();
      requests.push(body);
      await new Promise(resolve => { releases.push(resolve); });
      await route.fulfill({ json: { tenant_id: PORTAL_SESSION.tenant_id, dry_run: body.dry_run, legal_hold: false, would_delete: counts, audit_entry_id: body.dry_run ? null : 'aud_pending_erasure' } });
    });
    try {
      const panel = await openPrivacy(page);
      await panel.getByLabel('Erasure reason').fill('Approved pending cleanup');
      const preview = panel.getByRole('button', { name: 'Preview origin-clue erasure' });
      await preview.click();
      await expect.poll(() => requests.length).toBe(1);
      await receipt(testInfo, 'submit(true)', 'activate', 'busy', async () => {
        await expect(preview).toBeDisabled();
        await expect(panel.getByLabel('Erasure reason')).toBeDisabled();
        await preview.evaluate(button => { button.click(); button.click(); });
        expect(requests).toHaveLength(1);
        return ['While the owned preview response is held, preview/reason controls disable and repeated native activation sends no duplicate request'];
      });
      releases.shift()();
      await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeEnabled();
      await panel.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
      const dialog = page.locator('dialog.modal-confirm[open]');
      await dialog.getByRole('textbox').fill(PORTAL_SESSION.tenant_id);
      await dialog.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
      await expect.poll(() => requests.length).toBe(2);
      await receipt(testInfo, 'submit(false)', 'action-slot', 'busy', async () => {
        await expect(dialog.getByRole('button', { name: 'Cancel', exact: true })).toBeDisabled();
        await expect(dialog.getByRole('textbox')).toBeDisabled();
        await dialog.locator('form').evaluate(form => { form.requestSubmit(); form.requestSubmit(); });
        await page.keyboard.press('Escape');
        await expect(dialog).toBeVisible();
        expect(requests.filter(body => !body.dry_run)).toHaveLength(1);
        return ['Held erasure disables confirmation inputs/cancel, rejects repeated form submission and Escape dismissal, and sends exactly one destructive request'];
      });
      releases.shift()();
      await expect(panel.getByRole('status')).toContainText('aud_pending_erasure');
    } finally { for (const release of releases) release(); }
  });

  test('rate-limited preview and execution require an explicit new user review, never an automatic mutation retry', async ({ page }) => {
    browserChecks.get(page).expectedStatuses.add(429);
    const requests = [];
    let limitPreview = true;
    await page.route(`**${endpoint}`, async route => {
      const body = route.request().postDataJSON();
      requests.push(body);
      if (limitPreview || !body.dry_run) {
        limitPreview = false;
        return route.fulfill({ status: 429, headers: { 'retry-after': '0' }, json: { error: 'rate_limited' } });
      }
      return route.fulfill({ json: { tenant_id: PORTAL_SESSION.tenant_id, dry_run: true, legal_hold: false, would_delete: counts } });
    });
    const panel = await openPrivacy(page);
    await panel.getByLabel('Erasure reason').fill('Approved rate-limit regression');
    const preview = panel.getByRole('button', { name: 'Preview origin-clue erasure' });
    await preview.click();
    await expect(preview).toBeEnabled();
    expect(requests).toHaveLength(1);
    await expect(panel.getByRole('alert')).toContainText('Too many requests');
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
    await preview.click();
    await expect(panel).toContainText('3 clues and 2 collection batches');
    expect(requests).toHaveLength(2);
    await panel.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
    const dialog = page.locator('dialog.modal-confirm[open]');
    await dialog.getByRole('textbox').fill(PORTAL_SESSION.tenant_id);
    await dialog.getByRole('button', { name: 'Erase origin clues', exact: true }).click();
    await expect(preview).toBeEnabled();
    expect(requests.map(body => body.dry_run)).toEqual([true, true, false]);
    await expect(dialog).toHaveCount(0);
    await expect(panel.getByRole('alert')).toContainText('Too many requests');
    await expect(panel.getByRole('button', { name: 'Erase origin clues', exact: true })).toBeDisabled();
  });

  test('reason validation explains rejected control characters before any lifecycle request', async ({ page }) => {
    const requests = [];
    await page.route(`**${endpoint}`, route => { requests.push(route.request().method()); return route.abort(); });
    const panel = await openPrivacy(page);
    const reason = panel.getByLabel('Erasure reason');
    const preview = panel.getByRole('button', { name: 'Preview origin-clue erasure' });
    await reason.fill('   ');
    await expect(preview).toBeDisabled();
    await reason.fill('Approved cleanup\nwith a second line');
    await expect(preview).toBeDisabled();
    await expect(panel).toContainText('Use a single line without control characters.');
    await reason.fill('Approved cleanup with a tab\tseparator');
    await expect(preview).toBeDisabled();
    await reason.fill('Approved single-line cleanup');
    await expect(preview).toBeEnabled();
    await expect(panel).not.toContainText('Use a single line without control characters.');
    expect(requests).toEqual([]);
  });

  test('viewer has no preview or destructive control and opening privacy makes no lifecycle request', async ({ page }, testInfo) => {
    const requests = [];
    await page.route(`**${endpoint}`, route => { requests.push(route.request().method()); return route.abort(); });
    const panel = await openPrivacy(page, { ...PORTAL_SESSION, role: 'viewer', user_id: 'usr_viewer' });
    for (const [handler, kind] of [['submit(true)', 'activate'], ['submit(false)', 'action-slot']]) {
      await receipt(testInfo, handler, kind, 'denial', async () => {
        await expect(panel).toContainText('Only an owner or admin');
        await expect(panel.getByRole('button')).toHaveCount(0);
        await expect(panel.getByLabel('Erasure reason')).toHaveCount(0);
        expect(requests).toEqual([]);
        return ['Viewer sees the tenant-write restriction, no preview/erase/reason controls and zero origin-clue lifecycle requests'];
      }, { role: 'viewer' });
    }
  });
});
