import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_EMPTY_IDS } from '../../fixtures/portal-empty/seed.mjs';
import { buildPortalEdgeStore, PORTAL_EDGE_IDS } from '../../fixtures/portal-edge/seed.mjs';
import {
  fetchPortalReadinessScore,
  getPortalPlaywrightBaseUrl,
  portalOwnerHeaders,
  restartPortalPlaywrightWithEmptyStore,
  restartPortalPlaywrightServer,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

const EMPTY_SESSION = Object.freeze({
  mode: 'dev-headers',
  principal: 'customer',
  tenant_id: PORTAL_EMPTY_IDS.tenantId,
  user_id: 'usr_owner',
  role: 'owner',
});

test.describe('portal state coverage (FT-STATE-*)', () => {
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('FT-STATE-populated dashboard renders readiness from GET /v1/state', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const apiScore = await fetchPortalReadinessScore(baseUrl);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
    await expect(page.getByText(String(apiScore), { exact: true }).first()).toBeVisible();
  });

  test('FT-STATE-empty direct targets show the empty declared inventory without group navigation', async ({ page }) => {
    await restartPortalPlaywrightWithEmptyStore();
    const baseUrl = getPortalPlaywrightBaseUrl();

    const emptyHeaders = {
      ...portalOwnerHeaders(),
      'x-tenant-id': PORTAL_EMPTY_IDS.tenantId,
    };
    const groupsRes = await fetch(`${baseUrl}/v1/targets`, { headers: emptyHeaders });
    expect(groupsRes.ok).toBeTruthy();
    const groupsJson = await groupsRes.json();
    expect(groupsJson.count).toBe(0);
    const emptyReason = String(groupsJson.meta?.empty_reason ?? '').trim();
    expect(emptyReason.length).toBeGreaterThan(0);

    await injectPortalDevHeadersSession(page, EMPTY_SESSION);
    await gotoPortalRoute(page, 'targets', baseUrl);

    const emptyTitle = 'No targets declared yet';
    const emptyState = page.getByRole('region', { name: emptyTitle });
    await expect(emptyState.getByRole('heading', { name: emptyTitle })).toBeVisible();
    await expect(emptyState).toContainText('Declare a domain or endpoint here.');
    await expect(page.getByRole('link', { name: 'Target groups', exact: true })).toHaveCount(0);
  });

  test('FT-STATE-loading target-detail shows busy skeleton before hydrator resolves', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
    const baseUrl = getPortalPlaywrightBaseUrl();

    await page.route('**/v1/targets/**', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 1200));
      await route.continue();
    });

    await injectPortalDevHeadersSession(page);
    await page.goto(`${baseUrl}/app#target-detail?id=tgt_checkout_1`, { waitUntil: 'commit' });

    await expect(page.locator('[aria-busy="true"]').first()).toBeVisible();
    await expect(page.locator('.skeleton-row').first()).toBeVisible();
  });

  test('FT-STATE-error target-detail keeps missing, denied and failed reads distinct and never shows raw server text', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
    const baseUrl = getPortalPlaywrightBaseUrl();

    // The real API answers an unknown target with 404 and an explicit empty reason.
    const missingRes = await fetch(`${baseUrl}/v1/targets/tgt_missing_state`, { headers: portalOwnerHeaders() });
    expect(missingRes.status).toBe(404);
    const missingJson = await missingRes.json();
    expect(missingJson.error).toBe('not_found');
    expect(missingJson.target).toBeNull();
    expect(String(missingJson.meta?.empty_reason ?? '').trim().length).toBeGreaterThan(0);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', baseUrl, { entityIds: { 'target-detail': 'tgt_missing_state' } });
    // 404: the shared missing-record state, on the same address, with nothing substituted.
    const missing = page.locator('[data-unavailable-kind="record-missing"]');
    await expect(missing.getByRole('heading', { name: 'This record is not available.' })).toBeVisible();
    await expect(missing).toContainText('No placeholder values are shown in its place.');
    await expect(missing.getByRole('link', { name: 'Back to targets' })).toHaveAttribute('href', /#targets$/);
    await expect(page).toHaveURL(/#target-detail\?id=tgt_missing_state/);
    await expect(page.getByRole('heading', { level: 1, name: 'checkout.acme.com' })).toHaveCount(0);

    // 403 (negative case only): the access-denied state, not "missing" and not an error.
    await page.route('**/v1/targets/tgt_checkout_1', (route) => route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'forbidden', permission: 'target_group:read' }) }));
    await page.goto(`${baseUrl}/app#target-detail?id=tgt_checkout_1`, { waitUntil: 'networkidle' });
    await expect(page.locator('[data-unavailable-kind="access-denied"]')).toBeVisible();
    await expect(page.locator('[data-unavailable-kind="record-missing"]')).toHaveCount(0);
    await page.unroute('**/v1/targets/tgt_checkout_1');

    // 500 with leaky server text (negative case only): a failed read with Retry; raw text never shown.
    const leaky = 'relation "targets" does not exist; password=synthetic-leak at /srv/app/db.mjs:12';
    await page.route('**/v1/targets/tgt_checkout_1', (route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: leaky, message: leaky, meta: { empty_reason: leaky } }) }));
    // Same address as the 403 step, so reload to read it again.
    await page.reload({ waitUntil: 'networkidle' });
    const failed = page.locator('[data-target-load-error="true"]');
    await expect(failed).toHaveAttribute('role', 'alert');
    await expect(failed.getByRole('heading', { name: 'Target details could not load.' })).toBeVisible();
    await expect(failed).toContainText('Something went wrong on the server. Try again.');
    await expect(failed).toContainText('No other target is shown in its place.');
    const visible = await page.locator('#portal-main').innerText();
    expect(visible).not.toMatch(/synthetic-leak|relation "targets"|\/srv\/app/);
    await expect(page.locator('[data-unavailable-kind]')).toHaveCount(0);

    // Retry reads the same target again; once the server answers, the real record appears.
    await page.unroute('**/v1/targets/tgt_checkout_1');
    await failed.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'checkout.acme.com' })).toBeVisible();
    await expect(page.locator('[data-target-load-error="true"]')).toHaveCount(0);
  });

  test('FT-STATE-edge long direct target, null-field finding, and RTL declared owner render', async ({ page }) => {
    const longValue = `https://no-runs.edge.example/${'a'.repeat(256)}`;
    await restartPortalPlaywrightServer({ mutate: (store) => {
      Object.assign(store, buildPortalEdgeStore());
      const target = store.targets.find((item) => item.id === PORTAL_EDGE_IDS.noRunsTargetId);
      target.kind = 'url';
      target.value = longValue;
      target.declaration_json = { owner_label: PORTAL_EDGE_IDS.rtlOwner };
    } });
    const baseUrl = getPortalPlaywrightBaseUrl();

    const edgeHeaders = {
      ...portalOwnerHeaders(),
      'x-tenant-id': PORTAL_EDGE_IDS.tenantId,
    };
    const targetRes = await fetch(`${baseUrl}/v1/targets/${PORTAL_EDGE_IDS.noRunsTargetId}`, { headers: edgeHeaders });
    expect(targetRes.ok).toBeTruthy();
    const targetJson = await targetRes.json();
    expect(targetJson.target.value).toBe(longValue);
    expect(targetJson.target.declaration.owner.label).toBe(PORTAL_EDGE_IDS.rtlOwner);

    await injectPortalDevHeadersSession(page, {
      mode: 'dev-headers',
      principal: 'customer',
      tenant_id: PORTAL_EDGE_IDS.tenantId,
      user_id: 'usr_owner',
      role: 'owner',
    });
    await gotoPortalRoute(page, 'target-detail', baseUrl, {
      entityIds: { 'target-detail': PORTAL_EDGE_IDS.noRunsTargetId },
    });

    const title = page.locator('h1.page-title');
    await expect(title).toBeVisible();
    const titleText = await title.textContent();
    expect(titleText).toBe(longValue);
    await expect(page.locator('#portal-main')).toContainText(PORTAL_EDGE_IDS.rtlOwner);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 2)).toBe(true);

    const findingRes = await fetch(
      `${baseUrl}/v1/findings/${PORTAL_EDGE_IDS.nullFieldFindingId}`,
      { headers: edgeHeaders },
    );
    expect(findingRes.ok).toBeTruthy();
    const findingJson = await findingRes.json();
    expect(findingJson.title).toBe('Optional fields null');

    await gotoPortalRoute(page, 'finding-detail', baseUrl, {
      entityIds: { 'finding-detail': PORTAL_EDGE_IDS.nullFieldFindingId },
    });
    await expect(page.getByText(findingJson.title, { exact: true }).first()).toBeVisible();

    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    const clientWidth = await page.evaluate(() => document.documentElement.clientWidth);
    expect(scrollWidth).toBeLessThanOrEqual(clientWidth + 2);
  });
});