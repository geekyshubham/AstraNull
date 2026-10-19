import { expect, test } from '@playwright/test';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import AxeBuilder from '@axe-core/playwright';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, seedPortalPlaywrightStore } from '../../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession, PORTAL_AUDITOR_SESSION } from '../../helpers/portal-playwright-session.mjs';
import { PORTAL_BASELINE_IDS as ids } from '../../fixtures/portal-baseline/seed.mjs';

let webBase;
const cluePath = `/v1/targets/${ids.targetId}/origin-clues`;
const region = (page) => page.getByRole('region', { name: 'Origin exposure', exact: true });
const fixture = [{ candidate_ip: '93.184.216.34', associated_hostname: 'checkout.acme.com', source_observed_at: null }];

function track(page) {
  const calls = [];
  page.on('request', (request) => { const url = new URL(request.url()); if (url.pathname.startsWith('/v1/')) calls.push({ method: request.method(), path: url.pathname }); });
  return calls;
}
const writes = (calls) => calls.filter((call) => !['GET', 'HEAD'].includes(call.method));

async function open(page, { theme = 'dark', session } = {}) {
  await page.addInitScript((value) => { try { localStorage.setItem('astranull.theme', value); } catch {} }, theme);
  await injectPortalDevHeadersSession(page, session);
  await page.goto(`${webBase}/app#target-detail?id=${ids.targetId}&tab=overview`, { waitUntil: 'networkidle' });
  await expect(region(page).getByRole('heading', { name: 'Origin exposure', exact: true })).toBeVisible();
}

async function reviewImport(page, records = fixture, reference = 'Authorized fixture export') {
  const panel = region(page);
  await panel.getByRole('button', { name: 'Import records', exact: true }).click();
  await panel.getByLabel('Record source', { exact: true }).selectOption('historical_dns');
  await panel.getByLabel('Source reference', { exact: true }).fill(reference);
  await panel.getByLabel('Records file', { exact: true }).setInputFiles({ name: 'origin-associations.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(records)) });
  await panel.getByRole('button', { name: 'Review import', exact: true }).click();
  return page.getByRole('dialog', { name: 'Import these origin associations?' });
}

test.describe('default-off origin associations stay passive without rejected hydration', () => {
  let disabledBase;
  test.beforeAll(async () => {
    const runtime = await startPortalPlaywrightServer({ liveSource: true, env: { ASTRANULL_ORIGIN_CLUES_ENABLED_TENANTS: '' } });
    disabledBase = runtime.webBaseUrl;
  });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });
  test('the actual tenant feature gate prevents origin-clue reads and mutations', async ({ page }) => {
    const diagnostics = await collectPortalBrowserFailures(page, disabledBase);
    const calls = track(page);
    await injectPortalDevHeadersSession(page);
    await page.goto(`${disabledBase}/app#target-detail?id=${ids.targetId}&tab=overview`, { waitUntil: 'networkidle' });
    await expect(page.getByRole('heading', { level: 1, name: 'checkout.acme.com' })).toBeVisible();
    // A disabled tenant feature hides the section entirely instead of explaining it on every target.
    await expect(region(page)).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Review DNS collection' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Import records', exact: true })).toHaveCount(0);
    expect(calls.filter((call) => call.path.includes('/origin-clues'))).toEqual([]);
    expect(writes(calls)).toEqual([]);
    diagnostics.assertClean();
  });
});

test.describe('target Overview origin associations (isolated fixtures; no external probes)', () => {
  test.describe.configure({ mode: 'serial' });
  test.beforeAll(async () => {
    test.setTimeout(180_000);
    const runtime = await startPortalPlaywrightServer({ liveSource: true, env: { ASTRANULL_ORIGIN_CLUES_ENABLED_TENANTS: JSON.stringify({ [ids.tenantId]: true }) } });
    webBase = runtime.webBaseUrl;
  });
  const diagnostics = new WeakMap();
  test.beforeEach(async ({ page }, testInfo) => {
    seedPortalPlaywrightStore();
    diagnostics.set(page, await collectPortalBrowserFailures(page, webBase, { allowResponse: (response) => new URL(response.url()).pathname === cluePath && ((testInfo.title.startsWith('disabled enrichment') && response.status() === 404) || (testInfo.title.startsWith('forbidden associations') && response.status() === 403) || (testInfo.title.startsWith('a failed persisted read') && response.status() === 503)) }));
  });
  test.afterEach(async ({ page }) => { diagnostics.get(page)?.assertClean(); });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });

  test('disabled enrichment explains opt-in without presenting an exposure verdict', async ({ page }) => {
    await page.route(`**${cluePath}?*`, (route) => route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: 'origin_clues_feature_disabled' }) }));
    const calls = track(page);
    await open(page);
    await expect(region(page)).toContainText('not enabled for this tenant');
    await expect(region(page).getByRole('button', { name: 'Review DNS collection' })).toHaveCount(0);
    await expect(region(page)).not.toContainText('No associations recorded');
    expect(writes(calls)).toEqual([]);
  });

  test('a session change cannot reuse prior opt-in while replacement features are delayed', async ({ page }) => {
    const calls = track(page);
    await open(page);
    await expect(region(page).getByRole('heading', { name: 'No associations recorded' })).toBeVisible();
    let release;
    const pending = new Promise((resolve) => { release = resolve; });
    let replacementFeatureReads = 0;
    await page.route('**/v1/tenant/deployment-features', async (route) => {
      if (route.request().headers()['x-role'] !== 'viewer') return route.continue();
      replacementFeatureReads += 1;
      await pending;
      return route.fulfill({ json: { origin_clues: false, waf_posture: true, protection_validation: true } });
    });
    const replacementReads = [];
    page.on('request', (request) => {
      if (request.headers()['x-role'] === 'viewer' && new URL(request.url()).pathname.includes('/origin-clues')) replacementReads.push(request.url());
    });
    try {
      await page.getByRole('button', { name: /Role \(dev\)/ }).click();
      await page.getByRole('option', { name: /viewer/i }).click();
      await expect.poll(() => replacementFeatureReads).toBeGreaterThan(0);
      expect(replacementReads).toEqual([]);
      expect(writes(calls)).toEqual([]);
    } finally { release(); }
    // The replacement session is not opted in, so the section disappears and nothing was read for it.
    await expect(region(page)).toHaveCount(0);
    expect(replacementReads).toEqual([]);
  });

  test('forbidden associations show a permission state rather than an empty safe result', async ({ page }) => {
    await page.route(`**${cluePath}?*`, (route) => route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'forbidden' }) }));
    const calls = track(page);
    await open(page);
    await expect(region(page)).toContainText('Your role cannot read this target’s origin associations');
    await expect(region(page).getByRole('heading', { name: 'No associations recorded' })).toHaveCount(0);
    await expect(region(page).getByRole('button', { name: 'Review DNS collection' })).toHaveCount(0);
    expect(writes(calls)).toEqual([]);
  });

  test('empty records are inconclusive and DNS collection requires review; cancelling stays passive', async ({ page }) => {
    const calls = track(page);
    await open(page);
    await expect(region(page).getByRole('heading', { name: 'No associations recorded' })).toBeVisible();
    await expect(region(page)).toContainText('This does not mean the origin is hidden or protected');
    await region(page).getByRole('button', { name: 'Review DNS collection' }).click();
    const dialog = page.getByRole('dialog', { name: 'Collect DNS associations for this target?' });
    await expect(dialog).toContainText('no HTTP/TLS requests to candidate addresses');
    await dialog.getByRole('checkbox').check();
    expect(writes(calls)).toEqual([]);
    await dialog.getByRole('button', { name: /Cancel/ }).click();
    expect(writes(calls)).toEqual([]);
  });

  test('file review is passive; explicit import persists unverified records, provenance and unknown source times', async ({ page }) => {
    const calls = track(page);
    await open(page);
    const dialog = await reviewImport(page);
    await expect(dialog).toContainText('No target is added');
    expect(writes(calls)).toEqual([]);
    await dialog.getByRole('button', { name: 'Import associations', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(region(page)).toContainText('93.184.216.34');
    await expect(region(page)).toContainText('Unverified association');
    await expect(region(page)).toContainText('Observation time unknown');
    await region(page).getByText('Source and limitations', { exact: true }).click();
    await expect(region(page)).toContainText('Authorized fixture export');
    expect(writes(calls)).toEqual([{ method: 'POST', path: `${cluePath}/import` }]);
    const before = calls.length;
    await region(page).getByRole('button', { name: 'Refresh records' }).click();
    await expect(region(page)).toContainText('93.184.216.34');
    expect(writes(calls.slice(before))).toEqual([]);
  });

  test('a failed persisted read is not an empty result and can retry', async ({ page }) => {
    let failing = true;
    await page.route(`**${cluePath}?*`, (route) => failing ? route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'source_unavailable' }) }) : route.continue());
    const calls = track(page);
    await open(page);
    await expect(region(page).getByRole('alert')).toBeVisible();
    await expect(region(page).getByRole('heading', { name: 'No associations recorded' })).toHaveCount(0);
    failing = false;
    await region(page).getByRole('button', { name: 'Retry associations' }).click();
    await expect(region(page).getByRole('heading', { name: 'No associations recorded' })).toBeVisible();
    expect(writes(calls)).toEqual([]);
  });

  test('read-only role sees records without collection or import actions', async ({ page }) => {
    const calls = track(page);
    await open(page, { session: PORTAL_AUDITOR_SESSION });
    await expect(region(page)).toContainText('Read-only role');
    await expect(region(page).getByRole('button', { name: 'Import records', exact: true })).toHaveCount(0);
    await expect(region(page).getByRole('button', { name: 'Review DNS collection' })).toHaveCount(0);
    expect(writes(calls)).toEqual([]);
  });

  test('unavailable DNS coverage stays explicit even when persisted records are empty', async ({ page }) => {
    await page.route(`**${cluePath}?*`, (route) => route.fulfill({ json: { target_id: ids.targetId, enabled: true, items: [], coverage: { partial: true, sources: [{ hostname: 'checkout.acme.com', type: 'AAAA', status: 'unavailable' }] } } }));
    const calls = track(page);
    await open(page);
    await expect(region(page)).toContainText('1 DNS source question was unavailable');
    await expect(region(page)).toContainText('this is not evidence that the origin is hidden');
    expect(writes(calls)).toEqual([]);
  });

  for (const { method, incomplete } of [{ method: 'HEAD', incomplete: false }, { method: 'GET', incomplete: false }, { method: 'HEAD', incomplete: true }]) test(`paired ${method} ${incomplete ? 'refuses an incomplete reviewed plan' : 'reviews exactly one declared relation and both destinations without starting traffic'}`, async ({ page }) => {
    const digest = 'a'.repeat(64);
    const entry = { id: 'ep_fixture_origin', anchor_target_id: ids.targetId, entry_target_id: 'tgt_fixture_origin', entry_target_value: '93.184.216.34', relation_kind: 'origin', owner: 'Fixture', purpose: 'Authorized fixture only', expected_behavior: 'must_not_be_reachable', required_layers: [], origin_binding_id: 'binding_fixture', status: 'active', declaration_digest: digest, currently_authorized: true };
    const proof = (id) => ({ target_id: id, state: 'dns_verified', kind: 'dns_txt', transitioned_at: '2026-10-16T00:00:00Z', source_ref_digest: digest });
    const pair = { version: `origin-identity-${method.toLowerCase()}-v1`, method, binding_id: entry.origin_binding_id, protected_target: { id: ids.targetId, value: 'checkout.acme.com', kind: 'fqdn' }, origin_target: { id: entry.entry_target_id, value: entry.entry_target_value, kind: 'ip' }, address: entry.entry_target_value, host: 'checkout.acme.com', sni: 'checkout.acme.com', port: 443, path: '/', scheme: 'https', protected_ownership_binding: proof(ids.targetId), origin_ownership_binding: proof(entry.entry_target_id), limits: { http_requests: 2, dns_queries: 2, response_body_bytes_per_leg: 8192, response_body_bytes_total: 16384, duration_ms: 5000, redirects: 0, extra_assets: 0 } };
    const requests = [];
    await page.route(`**/v1/targets/${ids.targetId}/entry-paths*`, (route) => route.fulfill({ json: { items: [entry] } }));
    await page.route(`**/v1/targets/${ids.targetId}/protection-validation`, (route) => route.fulfill({ json: { target_id: ids.targetId, paths: [], limitations: ['external_only'] } }));
    await page.route('**/v1/entry-path-comparisons*', (route) => {
      if (route.request().method() === 'GET') return route.fulfill({ json: { items: [] } });
      const body = route.request().postDataJSON(); requests.push(body);
      return route.fulfill({ json: { anchor_target_id: ids.targetId, primary_entry_path_id: entry.id, plan_digest: digest, expectation: body.expectation, items: [{ entry_path_id: entry.id, target_id: entry.entry_target_id, check_id: body.expectation.scenario, check_version: '1.0.0', eligible: true, paired_plan: incomplete ? null : pair, origin_binding_id: entry.origin_binding_id }], expectation_conflicts: [], limitations: ['external_only'] } });
    });
    await open(page);
    await page.locator('#portal-main details.td-fold > summary', { hasText: 'Setup' }).click();
    const panel = page.getByRole('region', { name: 'Entry-path comparisons', exact: true });
    await panel.getByRole('button', { name: 'Plan a comparison', exact: true }).click();
    await panel.getByLabel('Comparison mode', { exact: true }).selectOption(`origin.identity_pair.${method.toLowerCase()}.v1`);
    await panel.getByRole('button', { name: 'Review plan', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Start these reviewed checks?' });
    if (incomplete) {
      await expect(panel.getByRole('alert')).toContainText('No paired check can start from this incomplete plan');
      await expect(dialog).toHaveCount(0);
      expect(requests).toHaveLength(1);
      expect(requests[0].mode).toBe('plan');
      return;
    }
    await expect(dialog).toContainText('checkout.acme.com');
    await expect(dialog).toContainText('93.184.216.34');
    await expect(dialog).toContainText('2 HTTP requests');
    await expect(dialog).toContainText('16384 body bytes total');
    await expect(dialog).toContainText('Protected ownership');
    await expect(dialog).toContainText('Origin ownership');
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ mode: 'plan', entry_path_ids: [entry.id], primary_entry_path_id: entry.id, expectation: { scenario: `origin.identity_pair.${method.toLowerCase()}.v1` } });
    await dialog.getByRole('button', { name: /Cancel/ }).click();
    expect(requests.every((request) => request.mode === 'plan')).toBe(true);
  });

  test.describe('coarse-pointer controls', () => {
    test.use({ hasTouch: true, viewport: { width: 390, height: 1000 } });
    test('source disclosures and workflow links retain 44px touch targets', async ({ page }) => {
      await open(page);
      expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches)).toBe(true);
      for (const control of [region(page).locator('.oe-details > summary'), region(page).locator('.oe-boundary a')]) {
        const bounds = await control.boundingBox();
        expect(bounds?.height).toBeGreaterThanOrEqual(44);
      }
      await region(page).getByRole('button', { name: 'Review DNS collection' }).click();
      const dialog = page.getByRole('dialog', { name: 'Collect DNS associations for this target?' });
      const checkbox = dialog.locator('.oe-checkbox');
      expect((await checkbox.boundingBox())?.height).toBeGreaterThanOrEqual(44);
      await dialog.getByRole('button', { name: /Cancel/ }).click();
    });
  });

  for (const theme of ['dark', 'light']) for (const width of [390, 1440]) {
    test(`${theme} ${width}px: responsive, keyboard-operable and accessible source evidence`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.emulateMedia({ reducedMotion: 'reduce' });
      await open(page, { theme });
      const dialog = await reviewImport(page, [{ candidate_ip: '2001:4860:4860::8888', associated_hostname: 'checkout.acme.com' }], `Fixture <script>not executable</script> ${'long-reference-'.repeat(15)}`);
      await dialog.getByRole('button', { name: 'Import associations', exact: true }).click();
      await expect(region(page)).toContainText('2001:4860:4860::8888');
      const details = region(page).getByText('Source and limitations', { exact: true });
      await details.focus();
      await page.keyboard.press('Enter');
      await expect(region(page)).toContainText('Fixture <script>not executable</script>');
      const overflow = await region(page).evaluate((node) => node.scrollWidth > node.clientWidth + 1);
      expect(overflow).toBe(false);
      expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)).toBe(false);
      const axe = await new AxeBuilder({ page }).include('.td-origin-exposure').withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
      expect(axe.violations).toEqual([]);
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: testInfo.outputPath(`origin-overview-${theme}-${width}.png`), fullPage: true });
    });
  }
});
