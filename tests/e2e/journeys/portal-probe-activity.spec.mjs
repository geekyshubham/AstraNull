import { mkdir } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { getStore } from '../../../src/store.mjs';
import { probeWorkerAuthHeaders, verifyProbeJobSignature } from '../../../src/services/probeCoordinator.mjs';
import { processJob } from '../../../workers/probe-worker.mjs';
import { createProbeActivityReporter } from '../../../workers/probe-activity-reporter.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { getPortalPlaywrightBaseUrl, seedPortalPlaywrightStore, startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession, PORTAL_SESSION } from '../../helpers/portal-playwright-session.mjs';
import { assertPortalInitialLoad } from '../../helpers/portal-browser-failures.mjs';

const TARGET = 'tgt_checkout_2';
const RUN = 'run_activity_ui';
const CHECK = 'waf.fingerprint.safe';
const AT = '2026-10-04T13:42:01.123Z';
const LOGS = [
  { id: 'log_start', at: AT, source: 'signed_worker', stage: 'request_started', operation: 'http_request', method: 'POST', url: 'https://owned.example/path?key=%5Bredacted%5D', body_bytes: 28, header_names: ['accept'], vector_family: 'waf', marker_class: 'sqli', phase: 'sqli_plain_marker', request_content_type: 'application/json', request_payload_preview: '{"marker":"astranull-inert"}', request_payload_encoding: 'utf8', request_payload_truncated: false },
  { id: 'log_response', at: AT, source: 'signed_worker', stage: 'response_received', operation: 'http_request', method: 'POST', url: 'https://owned.example/path?key=%5Bredacted%5D', status_code: 418, duration_ms: 17, response_content_type: 'text/html', vector_family: 'waf' },
  { id: 'log_payload', at: AT, source: 'signed_worker', stage: 'response_body_completed', operation: 'http_request', method: 'POST', status_code: 418, response_content_type: 'text/html', response_payload_preview: '<html>Request blocked</html>', response_payload_encoding: 'utf8', response_payload_truncated: false, response_bytes_observed: 28, vector_family: 'waf' },
  { id: 'log_omitted', at: AT, source: 'signed_worker', stage: 'request_not_sent', operation: 'optional_marker', reason: 'outside_request_budget' },
];

async function fixture(page, role = 'owner', logs = LOGS) {
  let stopped = false;
  let reads = 0;
  const cancels = [];
  await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [], count: 0, meta: {} } }));
  await page.route('**/v1/test-runs?*', async (route) => {
    if (new URL(route.request().url()).searchParams.get('target_id') !== TARGET) return route.continue();
    await route.fulfill({ json: { items: [{ id: RUN, target_id: TARGET, check_id: CHECK, status: stopped ? 'cancelled' : 'collecting', created_at: AT }], count: 1, meta: {} } });
  });
  await page.route(`**/v1/test-runs/${RUN}/events`, (route) => route.fulfill({ json: { items: LOGS.map((item) => ({ id: item.id, timestamp: item.at, test_run_id: RUN, check_id: CHECK, producer_kind: 'signed_probe', signal_type: 'probe_activity', metadata: { activity: item } })) } }));
  await page.route(`**/v1/test-runs/${RUN}/activity?*`, (route) => {
    reads += 1;
    return route.fulfill({ json: { run_id: RUN, check_id: CHECK, target_id: TARGET, status: stopped ? 'cancelled' : 'collecting', telemetry_recorded: true, requests_sent: null,
      items: stopped ? [...logs, { id: 'log_stop', at: AT, stage: 'run_stopped', source: 'run_state' }] : logs, count: stopped ? logs.length + 1 : logs.length, truncated: false } });
  });
  await page.route(`**/v1/test-runs/${RUN}/cancel`, (route) => {
    stopped = true; cancels.push(route.request().postDataJSON());
    return route.fulfill({ json: { id: RUN, status: 'cancelled' } });
  });
  await injectPortalDevHeadersSession(page, { ...PORTAL_SESSION, role });
  await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': TARGET } });
  await page.getByRole('tab', { name: /Validate/ }).click();
  await expect(page.locator('.probe-activity')).toContainText('HTTP 418');
  return { cancels, reads: () => reads };
}

const LOCAL_TARGET = 'tgt_local_activity';
const LOCAL_CHECK = 'waf.entry_path_api_marker.safe';
const SECRET = '938d3c93a4befa41b096eae03ad0902bc90b4e006b8c8ba0454cc517711b9948';
let wireServer;
let apiBase;
let wireBase;
let wireCalls = [];
let delayWire = false;
function seed(store) {
  applyPortalBaselineReadinessBoost(store);
  store.targets.push({ ...store.targets[0], id: LOCAL_TARGET, kind: 'url', value: `${wireBase}/api?private=local-customer-secret-123`, normalized_value: `${wireBase}/api?private=local-customer-secret-123`, expected_behavior: 'must_block_before_origin', declaration: { allowed_scope: { ports: [Number(new URL(wireBase).port)] } } });
  store.targetVerifications.push({ id: 'tv_local_activity', tenant_id: PORTAL_BASELINE_IDS.tenantId, target_id: LOCAL_TARGET, state: 'dns_verified', source_kind: 'manual_override', transitioned_at: new Date().toISOString(), transitioned_by: 'test_fixture' });
}
test.beforeAll(async ({ browser }) => {
  test.setTimeout(180000);
  // Only loopback is ever contacted by the connected worker tests. No production policy changes.
  wireServer = createHttpServer(async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    const marker = [req.url, req.headers['x-astranull-marker'], body].join(' ').includes('astranull');
    wireCalls.push({ method: req.method, path: req.url, body, marker });
    if (delayWire) await new Promise((resolve) => setTimeout(resolve, 1800));
    res.writeHead(marker ? 403 : 200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ fixture: 'local-wire-observed', blocked: marker, password: 'private-response-password' }));
  });
  await new Promise((resolve) => wireServer.listen(0, '127.0.0.1', resolve));
  wireBase = `http://127.0.0.1:${wireServer.address().port}`;
  const started = await startPortalPlaywrightServer({ liveSource: true, mutate: seed, env: { ASTRANULL_PROBE_MODE: 'signed-worker', ASTRANULL_PROBE_WORKER_SECRET: SECRET } });
  apiBase = started.baseUrl;
  const warm = await browser.newPage();
  try {
    await injectPortalDevHeadersSession(warm);
    await assertPortalInitialLoad(warm, getPortalPlaywrightBaseUrl());
  } finally {
    await warm.close();
  }
});
test.beforeEach(() => { seedPortalPlaywrightStore(seed); wireCalls = []; delayWire = false; });
test.afterAll(async () => {
  await stopPortalPlaywrightServer();
  wireServer?.closeAllConnections?.();
  if (wireServer) await new Promise((resolve) => wireServer.close(resolve));
});

test('recorded requests, omitted attempts, details, search, pause, and standalone Stop work', async ({ page }) => {
  const state = await fixture(page);
  const panel = page.locator('.probe-activity');
  await expect(panel).toContainText('17 ms');
  await expect(panel).not.toContainText('HTTP 200');
  await panel.getByRole('button', { name: 'Details for event log_response' }).click();
  await expect(panel.getByRole('button', { name: 'Details for event log_response' })).toHaveAttribute('aria-expanded', 'true');
  await expect(panel.locator('.probe-activity-detail')).toContainText('signed_worker');
  await expect(panel.locator('.probe-activity-detail')).toContainText('Recorded format: text/html');
  await panel.getByRole('button', { name: 'Details for event log_start' }).click();
  await expect(panel.locator('.probe-activity-detail')).toContainText('astranull-inert');
  await expect(panel.locator('.probe-activity-detail')).toContainText('sqli_plain_marker');
  await panel.getByRole('button', { name: 'Details for event log_payload' }).click();
  await expect(panel.locator('.probe-activity-detail')).toContainText('<html>Request blocked</html>');
  await panel.getByRole('searchbox', { name: 'Search execution activity' }).fill('no-match');
  await expect(panel).toContainText('No recorded events match these filters');
  await panel.getByRole('searchbox', { name: 'Search execution activity' }).fill('');
  await panel.getByRole('combobox', { name: 'Activity severity' }).selectOption('warning');
  await expect(panel).toContainText(/outside request budget/i);
  await expect(panel).not.toContainText('HTTP 418');
  await panel.getByRole('combobox', { name: 'Activity severity' }).selectOption('all');
  await panel.getByRole('button', { name: 'Pause updates' }).click();
  const before = state.reads();
  await page.waitForTimeout(2800);
  expect(state.reads()).toBe(before);
  await expect(panel).toContainText('Updates paused; execution continues');
  await panel.getByRole('button', { name: 'Resume updates' }).click();
  await expect.poll(state.reads).toBeGreaterThan(before);
  await page.getByRole('button', { name: 'Stop current check', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: /^Stop / });
  await dialog.getByRole('button', { name: 'Stop check', exact: true }).click();
  await expect.poll(() => state.cancels.length).toBe(1);
  expect(state.cancels[0].reason).toBe('Stopped from target execution activity');
  await expect(page.getByRole('button', { name: 'Stop current check', exact: true })).toHaveCount(0);
});

test('only one Stop is offered for the run the Inspector is already showing', async ({ page }) => {
  await fixture(page);
  const activity = page.locator('.td-validate .probe-activity');
  await expect(activity.getByRole('button', { name: /^Stop/ })).toHaveCount(1);
  await mockContext(page);
  await page.evaluate(({ target, check, run }) => { const params = new URLSearchParams(location.hash.split('?')[1]); params.set('inspect', 'check_result'); params.set('ev_target', target); params.set('ev_check', check); params.set('ev_run', run); location.hash = `target-detail?${params}`; }, { target: TARGET, check: CHECK, run: RUN });
  await expect(page.locator('.inspector-panel .ei-execution')).toBeVisible();
  await expect(activity.getByRole('button', { name: /^Stop/ })).toHaveCount(0);
  await expect(page.locator('.inspector-panel').getByRole('button', { name: 'Stop check', exact: true })).toHaveCount(1);
});

test('the Validate tab shows no activity console until a check is selected or running', async ({ page }) => {
  await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [], count: 0, meta: {} } }));
  await page.route('**/v1/test-runs?*', async (route) => {
    if (new URL(route.request().url()).searchParams.get('target_id') !== TARGET) return route.continue();
    await route.fulfill({ json: { items: [{ id: 'run_idle_past', target_id: TARGET, check_id: CHECK, status: 'completed', created_at: AT }], count: 1, meta: {} } });
  });
  await injectPortalDevHeadersSession(page);
  await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': TARGET } });
  await page.getByRole('tab', { name: /Validate/ }).click();
  await expect(page.locator('.td-checks')).toBeVisible();
  await expect(page.locator('.td-start-bar')).toContainText('No check selected');
  await expect(page.locator('.td-validate .probe-activity')).toHaveCount(0);
  await expect(page.locator('.td-scan-terminal')).toHaveCount(0);
});

test('a read-only viewer can inspect logs but has no Stop controls', async ({ page }) => {
  await fixture(page, 'viewer');
  await expect(page.locator('.probe-activity')).toContainText('HTTP 418');
  await expect(page.getByRole('button', { name: /^Stop/ })).toHaveCount(0);
});

test('an unrun selection does not hide an active provider observation from the live window', async ({ page }) => {
  await fixture(page);
  await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': TARGET } });
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&check=l7.cors_posture.safe`);
  await expect(page.locator('.probe-activity')).toContainText('HTTP 418');
  await expect(page.locator('.probe-activity')).toContainText('WAF and CDN Fingerprint');
  await expect(page.getByRole('button', { name: 'Stop current check', exact: true })).toBeVisible();
});

test('the selected provider observation shows real request logs and no invented sent count', async ({ page }) => {
  await fixture(page);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&check=${CHECK}`);
  const selected = page.locator('.td-check[data-selected=true]');
  await expect(selected).toContainText('Logical operation count not recorded yet');
  await expect(selected).not.toContainText('13/16');
  await expect(selected).toContainText('HTTP 418');
  await expect(selected).toContainText('outside_request_budget');
  await expect(selected).not.toContainText('reached origin');
});

test('a pause on an older run cannot leave the next active run with an empty live window', async ({ page }) => {
  await fixture(page);
  const panel = page.locator('.probe-activity');
  await expect(panel).toContainText('HTTP 418');
  await panel.getByRole('button', { name: 'Pause updates' }).click();
  await expect(panel).toContainText('Updates paused');
  const next = 'run_next_activity';
  await page.route('**/v1/test-runs?*', async (route) => {
    if (new URL(route.request().url()).searchParams.get('target_id') !== TARGET) return route.fallback();
    await route.fulfill({ json: { items: [{ id: next, target_id: TARGET, check_id: CHECK, status: 'collecting', created_at: new Date().toISOString() }], count: 1 } });
  });
  await page.route(`**/v1/test-runs/${next}/activity?*`, (route) => route.fulfill({ json: {
    run_id: next, check_id: CHECK, target_id: TARGET, status: 'collecting', telemetry_recorded: true,
    items: [{ id: 'next_log', stage: 'request_started', method: 'GET', phase: 'replacement', at: AT, source: 'signed_worker' }], count: 1,
  } }));
  await expect(panel).toContainText(/replacement/i, { timeout: 12000 });
  await expect(panel.getByRole('button', { name: 'Pause updates' })).toBeVisible();
});

for (const width of [375, 768, 1024, 1440]) {
  for (const theme of ['dark', 'light']) {
    test(`activity table stays accessible and contained at ${width}px in ${theme}`, async ({ page }) => {
      test.setTimeout(90000); // Axe's cross-frame pass is slower under concurrent backend checks.
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript((mode) => localStorage.setItem('astranull.theme', mode), theme);
      await fixture(page);
      const panel = page.locator('.probe-activity');
      await expect(panel).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 2)).toBe(true);
      const results = await new AxeBuilder({ page }).include('.probe-activity').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
      expect(results.violations.filter((item) => ['serious', 'critical'].includes(item.impact ?? '')).map((item) => item.id)).toEqual([]);
      await mkdir('output/probe-activity', { recursive: true });
      await panel.screenshot({ path: `output/probe-activity/activity-${width}-${theme}.png` });
    });
  }
}

const EXCHANGE_LOGS = LOGS.slice(0, 3).map((item, index) => ({
  ...item, capture_version: 'http-exchange.v1', exchange_id: 'exchange_reviewed', attempt_id: 'attempt_reviewed', operation_id: 'operation_reviewed', sequence: index + 1,
  source_context: { job_id: 'job_original', worker_id: 'worker_fixture', leased_at: AT }, http_version: 'HTTP/1.1',
  ...(index === 0 ? { request_headers: [{ name: 'accept', value: 'application/json' }, { name: 'authorization', value: 'Bearer must-not-leak' }], request_query_preview: '?token=must-not-leak&marker=inert', request_payload_preview: '{"marker":"astranull-inert","password":"must-not-leak"}' } : {}),
  ...(index === 1 ? { response_headers: [{ name: 'content-type', value: 'text/html' }], response_payload_available: false } : {}),
  ...(index === 2 ? { response_payload_available: true, response_payload_preview: '<html><script>window.captureExecuted=true</script>Request blocked</html>' } : {}),
}));

for (const width of [375, 768, 1024, 1440]) for (const theme of ['dark', 'light']) {
  test(`correlated HTTP exchange is inert accessible and contained at ${width}px in ${theme}`, async ({ page }) => {
    test.setTimeout(90000);
    await page.setViewportSize({ width, height: 1100 });
    await page.addInitScript((mode) => localStorage.setItem('astranull.theme', mode), theme);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await fixture(page, 'owner', EXCHANGE_LOGS);
    const panel = page.locator('.td-validate .probe-activity');
    const exchange = panel.locator('.probe-exchange');
    await expect(exchange).toHaveCount(1);
    await expect(exchange).toContainText('job_original');
    await expect(exchange).toContainText('attempt_reviewed');
    await expect(exchange).toContainText('operation_reviewed');
    await expect(exchange).toContainText('HTTP/1.1');
    await expect(exchange).toContainText('<script>window.captureExecuted=true</script>');
    await expect(exchange).not.toContainText('must-not-leak');
    await expect(exchange).not.toContainText('Not consumed by this check');
    expect(await page.evaluate(() => window.captureExecuted)).toBeUndefined();
    await expect(exchange.locator('script, iframe, html')).toHaveCount(0);
    await page.evaluate(() => { window.capturedClipboard = ''; Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (value) => { window.capturedClipboard = value; } } }); });
    await exchange.getByRole('button', { name: 'Copy sanitized exchange' }).click();
    await expect(exchange.getByRole('status')).toHaveText('Sanitized exchange copied');
    const copied = await page.evaluate(() => window.capturedClipboard);
    expect(copied).toContain('Request'); expect(copied).toContain('Response'); expect(copied).not.toContain('must-not-leak');
    const summary = exchange.locator('.probe-exchange-summary');
    await summary.focus(); await expect(summary).toBeFocused();
    await page.keyboard.press('Enter'); await expect(summary).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('Enter'); await expect(summary).toHaveAttribute('aria-expanded', 'true');
    const sides = await exchange.locator('.probe-exchange-side').evaluateAll((nodes) => nodes.map((node) => { const rect = node.getBoundingClientRect(); return { x: rect.x, y: rect.y }; }));
    const pairWidth = await exchange.locator('.probe-exchange-pair').evaluate((node) => node.clientWidth);
    if (pairWidth < 624) expect(sides[1].y).toBeGreaterThan(sides[0].y); else expect(sides[1].x).toBeGreaterThan(sides[0].x);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    const axe = await new AxeBuilder({ page }).include('.probe-activity').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(axe.violations.filter((item) => ['serious', 'critical'].includes(item.impact ?? '')).map((item) => item.id)).toEqual([]);
    await mkdir('output/probe-activity', { recursive: true });
    await panel.screenshot({ path: `output/probe-activity/exchange-${width}-${theme}.png` });
  });
}

async function withCoarseTouchPage(browser, width, theme, run) {
  const context = await browser.newContext({ viewport: { width, height: 1100 }, hasTouch: true, isMobile: true, reducedMotion: 'reduce' });
  try {
    const page = await context.newPage();
    await page.addInitScript((mode) => localStorage.setItem('astranull.theme', mode), theme);
    await run(page);
  } finally {
    await context.close();
  }
}

async function expectTouchTargets(locator) {
  await expect(locator.first()).toBeVisible();
  expect(await locator.count()).toBeGreaterThan(0);
  const undersized = await locator.evaluateAll((nodes) => nodes.flatMap((node) => {
    const rect = node.getBoundingClientRect();
    return rect.width < 44 || rect.height < 44 ? [{ label: node.getAttribute('aria-label') || node.textContent, width: rect.width, height: rect.height }] : [];
  }));
  expect(undersized).toEqual([]);
}

for (const width of [375, 768]) for (const theme of ['dark', 'light']) {
  test(`coarse touch exchange and event controls are at least 44px at ${width}px in ${theme}`, async ({ browser }) => {
    await withCoarseTouchPage(browser, width, theme, async (page) => {
      await fixture(page, 'owner', [...EXCHANGE_LOGS, LOGS[3]]);
      expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches)).toBe(true);
      const panel = page.locator('.td-validate .probe-activity');
      await expectTouchTargets(panel.locator('.probe-exchange-summary'));
      await panel.locator('.probe-activity-technical > summary').click();
      await expectTouchTargets(panel.locator('.probe-activity-expand'));
      await panel.getByRole('button', { name: 'Details for event log_omitted' }).tap();
      await expect(panel.getByRole('button', { name: 'Details for event log_omitted' })).toHaveAttribute('aria-expanded', 'true');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    });
  });

  test(`coarse touch rule-coverage disclosures are at least 44px at ${width}px in ${theme}`, async ({ browser }) => {
    await withCoarseTouchPage(browser, width, theme, async (page) => {
      await injectPortalDevHeadersSession(page);
      await gotoPortalRoute(page, 'checks', getPortalPlaywrightBaseUrl());
      const legend = page.locator('.rc-legend');
      await expect(legend.locator('summary')).toBeVisible();
      await expectTouchTargets(page.locator('.rc-legend summary, .rc-more summary'));
      // Catalog mode starts open; the first native summary tap closes it, not opens it.
      await expect(legend).toHaveAttribute('open', '');
      await expect(legend.locator('dl')).toBeVisible();
      await legend.locator('summary').tap();
      await expect(legend).not.toHaveAttribute('open', '');
      await expect(legend.locator('dl')).toBeHidden();
      await legend.locator('summary').tap();
      await expect(legend).toHaveAttribute('open', '');
      await expect(legend.locator('dl')).toBeVisible();
    });
  });
}

test('target and check detail share truthful token observation names and purpose', async ({ page }) => {
  await injectPortalDevHeadersSession(page);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&check=waf.jwt_tamper_marker.safe`);
  const selected = page.locator('.td-check[data-selected=true]');
  await expect(selected).toContainText('JWT Tamper token observation');
  await expect(selected).toContainText('GET inert-token');
  await expect(selected).not.toContainText('JWT Tamper Custom Canary Rule');
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#check-detail?id=waf.jwt_tamper_marker.safe`);
  await expect(page.getByRole('heading', { name: 'JWT Tamper token observation', exact: true })).toBeVisible();
  await expect(page.getByText('No exact installed-token rule binding exists in current declarations.', { exact: false })).toBeVisible();
});

test('exchange inspector distinguishes missing, unconsumed, empty, withheld, failed and conflicting capture', async ({ page }) => {
  const make = (exchange, stage, extra = {}) => ({ id: `${exchange}_${stage}_${extra.sequence ?? 0}`, at: AT, source: 'signed_worker', source_context: EXCHANGE_LOGS[0].source_context, capture_version: 'http-exchange.v1', exchange_id: exchange, http_version: 'HTTP/1.1', stage, method: 'GET', url: `https://owned.example/${exchange}`, ...extra });
  await fixture(page, 'owner', [...EXCHANGE_LOGS,
    make('missing', 'request_started'),
    make('failed', 'request_started'), make('failed', 'attempt_failed', { sequence: 2, error_class: 'timeout' }),
    make('headers-only', 'request_started'), make('headers-only', 'response_received', { sequence: 2, status_code: 204, response_payload_available: false }),
    make('withheld', 'request_started'), make('withheld', 'response_body_completed', { sequence: 2, status_code: 200, response_payload_available: true, response_payload_preview: '[Partial payload withheld]', response_payload_encoding: 'redacted', response_payload_truncated: true }),
    make('empty', 'request_started', { request_payload_preview: '', request_headers: [], request_query_preview: '' }), make('empty', 'response_body_completed', { sequence: 2, status_code: 200, response_payload_available: true, response_payload_preview: '' }),
    make('conflict', 'request_started'), make('conflict', 'request_started', { sequence: 2, method: 'POST' }),
  ]);
  const panel = page.locator('.td-validate .probe-activity');
  for (const [name, expected] of [
    ['missing', 'Not recorded by worker. No counterpart is inferred.'],
    ['failed', 'Failure is not proof of blocking.'],
    ['headers-only', 'Not consumed by this check'],
    ['withheld', '[Partial payload withheld]'],
    ['empty', 'Empty recorded body'],
    ['conflict', 'Conflicting worker records. This capture is withheld'],
  ]) {
    const exchange = panel.locator('.probe-exchange').filter({ has: page.locator('.probe-exchange-summary', { hasText: `https://owned.example/${name}` }) });
    const summary = exchange.locator('.probe-exchange-summary');
    if (await summary.getAttribute('aria-expanded') !== 'true') await summary.click();
    await expect(exchange).toContainText(expected);
    if (name === 'conflict') await expect(exchange).toHaveAttribute('data-state', 'partial');
    if (name === 'empty') { await expect(exchange).toContainText('Empty recorded query'); await expect(exchange).toContainText('Empty recorded header set'); }
  }
});

function contextFor(runId, complete = true, checkId = CHECK, targetId = TARGET) {
  return { subject: { target_id: targetId, check_id: checkId },
    answer: { outcome: complete ? 'edge_protected' : '', observed_behavior: complete ? `Recorded blocked response for ${runId}` : 'Waiting for the signed final observation', expected_behavior: 'Block the reviewed bounded marker', explanation: complete ? 'This exact scenario was evaluated; it is not broad protection or capacity proof.' : '' },
    primary: { test_run_id: runId, verdict_id: complete ? `vrd_${runId}` : null, evidence_ids: complete ? [`evt_${runId}_result`] : [], observed_at: AT }, unavailable_reason: complete ? null : 'partial' };
}
function activityFor(runId, items = LOGS, extra = {}) {
  return { run_id: runId, target_id: TARGET, check_id: CHECK, status: 'collecting', telemetry_recorded: true, items, count: items.length,
    pagination: { next_cursor: items.at(-1)?.id ?? null, has_more: false, total_recorded: items.length }, capture: { status: 'recording', recorded_count: items.length }, ...extra };
}
async function openExact(page, runId = RUN, role = 'owner') {
  await injectPortalDevHeadersSession(page, { ...PORTAL_SESSION, role });
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&check=${CHECK}&inspect=check_result&ev_target=${TARGET}&ev_check=${CHECK}&ev_run=${runId}`, { waitUntil: 'domcontentloaded' });
  await expect(page.locator('.inspector-panel .ei-execution')).toBeVisible();
}
async function mockContext(page, callback = (runId) => contextFor(runId)) {
  await page.route('**/v1/evidence-context?*', (route) => route.fulfill({ json: callback(new URL(route.request().url()).searchParams.get('test_run_id')) }));
}

test('reviewed Play opens and focuses the exact returned run, including fast completion and final evidence refresh', async ({ page }) => {
  test.setTimeout(45000);
  const accepted = 'run_exact_accepted'; let reads = 0; const bodies = [];
  await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [] } }));
  await page.route('**/v1/test-runs?*', (route) => route.fulfill({ json: { items: [{ id: 'run_old_capped_list', target_id: TARGET, check_id: CHECK, status: 'completed', created_at: AT }] } }));
  await page.route('**/v1/test-runs', (route) => { if (route.request().method() !== 'POST') return route.continue(); bodies.push(route.request().postDataJSON()); return route.fulfill({ status: 201, json: { run: { id: accepted, target_id: TARGET, check_id: CHECK, status: 'collecting' }, jobs_dispatched: 0 } }); });
  await page.route(`**/v1/test-runs/${accepted}/activity?*`, (route) => {
    reads += 1;
    return route.fulfill({ json: activityFor(accepted, reads > 1 ? [...LOGS, { id: 'fast_final', at: AT, stage: 'result_received', source: 'signed_worker', outcome: 'blocked', requests_sent: 1 }] : LOGS, { status: 'verdicted', requests_sent: reads > 1 ? 1 : null, capture: { status: reads > 1 ? 'complete' : 'recording' } }) });
  });
  await mockContext(page, (id) => contextFor(id, id === accepted && reads > 1));
  await injectPortalDevHeadersSession(page);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&check=${CHECK}`);
  const play = page.getByRole('button', { name: 'Review and start', exact: true });
  await play.click();
  const review = page.locator('dialog.modal-confirm[open]');
  await expect(review).toContainText('Upper bound');
  expect(bodies).toEqual([]);
  await review.getByRole('button', { name: 'Start check', exact: true }).click();
  const inspector = page.locator('.inspector-panel');
  await expect(inspector.getByRole('heading', { name: 'Check result', exact: true })).toBeFocused();
  await expect(page).toHaveURL(new RegExp(`ev_run=${accepted}`));
  await expect(inspector.locator('.probe-activity-run')).toHaveText(accepted);
  await expect(inspector).toContainText('HTTP 418');
  await expect(inspector).not.toContainText('run_old_capped_list');
  await expect(inspector).toContainText(`evt_${accepted}_result`, { timeout: 12000 });
  await expect(inspector).toContainText('Recorded blocked response for run exact accepted');
  await expect(inspector.locator('.probe-activity-status')).toContainText('1 logical operations (attested)');
  await expect(inspector.locator('.probe-activity-status')).not.toContainText('attested operations');
  expect(bodies).toEqual([{ target_id: TARGET, check_id: CHECK }]);
  const executionUrl = page.url();
  await inspector.getByRole('button', { name: 'Close Check result' }).click();
  await expect(play).toBeFocused();
  await expect(page.locator('.td-check[data-selected=true]')).toContainText('HTTP 418');
  await expect(page.locator('.td-check[data-selected=true]')).not.toContainText('run_old_capped_list');
  await page.route('**/v1/test-runs?*', (route) => route.fulfill({ json: { items: [{ id: 'run_newer_after_acceptance', target_id: TARGET, check_id: CHECK, status: 'completed', created_at: '2035-01-01T00:00:00.000Z' }] } }));
  await page.goto(executionUrl);
  await page.reload();
  await expect(page).toHaveURL(new RegExp(`ev_run=${accepted}`));
  await expect(inspector.locator('.probe-activity-run')).toHaveText(accepted);
  await expect(inspector).not.toContainText('run_newer_after_acceptance');
  await expect(inspector).toContainText(`evt_${accepted}_result`);
  expect(bodies).toEqual([{ target_id: TARGET, check_id: CHECK }]);
});

for (const status of [409, 403, 503]) {
  test(`ordinary Play reports ${status} rejection truthfully and retries only after renewed confirmation`, async ({ page }) => {
    test.setTimeout(45000);
    const accepted = `run_retry_after_${status}`;
    const bodies = [];
    let rejectAttempt;
    const rejectionGate = new Promise((resolve) => { rejectAttempt = resolve; });
    await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [] } }));
    await page.route('**/v1/test-runs?*', (route) => route.fulfill({ json: { items: [] } }));
    await page.route('**/v1/test-runs', async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      bodies.push(route.request().postDataJSON());
      if (bodies.length === 1) {
        await rejectionGate;
        return route.fulfill({ status, json: { error: 'fixture_start_rejected' } });
      }
      return route.fulfill({ status: 201, json: { run: { id: accepted, target_id: TARGET, check_id: CHECK, status: 'collecting' }, jobs_dispatched: 0 } });
    });
    await page.route(`**/v1/test-runs/${accepted}/activity?*`, (route) => route.fulfill({ json: activityFor(accepted) }));
    await mockContext(page, (id) => contextFor(id, false));
    await injectPortalDevHeadersSession(page);
    await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&check=${CHECK}`);
    const play = page.getByRole('button', { name: 'Review and start', exact: true });
    const review = page.locator('dialog.modal-confirm[open]');
    await play.click();
    expect(bodies).toEqual([]);
    await review.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(bodies).toEqual([]);
    await expect(page.locator('.inspector-panel')).toHaveCount(0);
    await play.click();
    const start = review.getByRole('button', { name: 'Start check', exact: true });
    await start.click();
    await expect.poll(() => bodies.length).toBe(1);
    await expect(review.locator('button[type=submit]')).toBeDisabled();
    await expect(page.locator('.inspector-panel')).toHaveCount(0);
    rejectAttempt();
    await expect(page.getByText(status >= 500 ? 'Service is temporarily unavailable. Try again shortly.' : 'Fixture start rejected.', { exact: true })).toBeVisible();
    if (status >= 500) await expect(page.getByText('Fixture start rejected.', { exact: true })).toHaveCount(0);
    await expect(page.locator('.inspector-panel')).toHaveCount(0);
    expect(page.url()).not.toContain('ev_run=');
    await expect(page.getByText('Worker acknowledged', { exact: true })).toHaveCount(0);
    expect(bodies).toEqual([{ target_id: TARGET, check_id: CHECK }]);
    await play.click();
    expect(bodies).toHaveLength(1);
    await review.getByRole('button', { name: 'Start check', exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`ev_run=${accepted}`));
    await expect(page.locator('.inspector-panel .probe-activity-run')).toHaveText(accepted);
    expect(bodies).toEqual([{ target_id: TARGET, check_id: CHECK }, { target_id: TARGET, check_id: CHECK }]);
  });
}

test('Inspector retains paged immutable records across reconnect, freezes paused display, and explains omissions', async ({ page }) => {
  test.setTimeout(45000);
  let fail = false; let more = false; const cursors = []; const mutations = [];
  page.on('request', (request) => { if (request.url().includes('/v1/') && request.method() !== 'GET') mutations.push(request.url()); });
  await mockContext(page);
  await page.route(`**/v1/test-runs/${RUN}/activity?*`, (route) => {
    const cursor = new URL(route.request().url()).searchParams.get('cursor'); cursors.push(cursor);
    if (fail) { fail = false; return route.fulfill({ status: 503, json: { error: 'offline' } }); }
    const items = !cursor ? [LOGS[0]] : [LOGS[0], ...LOGS.slice(1), ...(more ? [{ id: 'after_pause', at: AT, source: 'signed_worker', stage: 'response_received', method: 'GET', status_code: 429 }] : [])];
    return route.fulfill({ json: activityFor(RUN, items, { pagination: { next_cursor: !cursor ? LOGS[0].id : more ? 'after_pause' : LOGS.at(-1).id, has_more: !cursor, total_recorded: 5 }, capture: { status: 'incomplete', dropped_count: 2, delivery_failures: 1, sequence_gaps: [{ from: 5, to: 6 }] } }) });
  });
  await openExact(page);
  const panel = page.locator('.inspector-panel .probe-activity');
  await expect(panel).toContainText('4 recorded events retained');
  await expect(panel).toContainText('2 activity events omitted');
  await expect(panel).toContainText('5–6');
  await panel.getByRole('button', { name: 'Pause updates', exact: true }).click();
  more = true;
  await page.waitForTimeout(2800);
  await expect(panel).not.toContainText('HTTP 429');
  await expect(panel).toContainText('execution continues');
  await panel.getByRole('button', { name: 'Resume updates', exact: true }).click();
  await expect(panel).toContainText('HTTP 429');
  await expect(panel).toContainText('5 recorded events retained');
  fail = true;
  await expect(panel).toContainText('Disconnected', { timeout: 9000 });
  await expect(panel).toContainText('HTTP 418');
  await panel.getByRole('button', { name: 'Reconnect', exact: true }).click();
  await expect(panel).not.toContainText('Disconnected');
  expect(cursors.at(-1)).toBe('after_pause');
  expect(mutations).toEqual([]);
});

test('historical references stay pinned and delayed replies cannot cross role or exact-run changes', async ({ page }) => {
  test.setTimeout(45000);
  await page.setViewportSize({ width: 1440, height: 1000 });
  let release; const gate = new Promise((resolve) => { release = resolve; });
  const older = 'run_history_pinned'; const newer = 'run_new_scope';
  await mockContext(page);
  await page.route(`**/v1/test-runs/${older}/activity?*`, async (route) => { await gate; await route.fulfill({ json: activityFor(older, [{ ...LOGS[0], id: 'old_private_row', method: 'OLDOWNER' }]) }); });
  await page.route(`**/v1/test-runs/${newer}/activity?*`, (route) => route.fulfill({ json: activityFor(newer, [{ ...LOGS[0], id: 'new_public_row', method: 'NEWVIEWER' }]) }));
  await openExact(page, older);
  await page.getByRole('button', { name: /Role \(dev\)/ }).click();
  await page.getByRole('option', { name: /viewer/i }).click();
  await page.evaluate((id) => { const params = new URLSearchParams(location.hash.split('?')[1]); params.set('ev_run', id); location.hash = `target-detail?${params}`; }, newer);
  release();
  const inspector = page.locator('.inspector-panel');
  await expect(inspector).toContainText('NEWVIEWER');
  await expect(inspector).not.toContainText('OLDOWNER');
  await expect(inspector.getByRole('button', { name: /^Stop/ })).toHaveCount(0);
  await expect(page).toHaveURL(/ev_run=run_new_scope/);
  await page.waitForTimeout(2800);
  await expect(inspector).not.toContainText('OLDOWNER');
});

test('assessment follows only its own active child, pinning holds, and child Stop freezes the confirmed ID', async ({ page }) => {
  test.setTimeout(45000);
  await page.setViewportSize({ width: 1440, height: 1000 });
  const scanId = 'scan_exact_workspace'; const first = 'run_scan_child_a'; const second = 'run_scan_child_b'; let active = first; const cancelled = [];
  const scan = () => ({ id: scanId, target_id: TARGET, status: 'running', steps: [{ id: 'step_a', check_id: CHECK, target_id: TARGET, test_run_id: first, status: active === first ? 'running' : 'verdicted' }, { id: 'step_b', check_id: CHECK, target_id: TARGET, test_run_id: second, status: active === second ? 'running' : 'planned' }] });
  await mockContext(page);
  await page.route(`**/v1/validation-scans/${scanId}?*`, (route) => { expect(new URL(route.request().url()).searchParams.get('advance')).toBe('false'); return route.fulfill({ json: scan() }); });
  await page.route(`**/v1/validation-scans/${scanId}/activity?*`, (route) => route.fulfill({ json: { scan_id: scanId, status: 'running', items: [], pagination: { next_cursor: null, has_more: false, total_recorded: 0 }, capture: { status: 'unknown' } } }));
  for (const id of [first, second]) {
    await page.route(`**/v1/test-runs/${id}/activity?*`, (route) => route.fulfill({ json: activityFor(id, [{ ...LOGS[0], id: `evt_${id}`, phase: id }]) }));
    await page.route(`**/v1/test-runs/${id}/cancel`, (route) => { cancelled.push(id); return route.fulfill({ json: { id, status: 'cancelled' } }); });
  }
  await page.route(`**/v1/validation-scans/${scanId}/cancel`, (route) => { cancelled.push(scanId); return route.fulfill({ json: { id: scanId, status: 'cancelled' } }); });
  await injectPortalDevHeadersSession(page);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&inspect=validation_scan&ev_target=${TARGET}&ev_scan=${scanId}`);
  const inspector = page.locator('.inspector-panel');
  await expect(inspector.locator('.probe-activity-run')).toHaveText(first);
  await inspector.getByRole('button', { name: 'Keep showing this check', exact: true }).click(); active = second;
  await page.waitForTimeout(2800);
  await expect(inspector.locator('.probe-activity-run')).toHaveText(first);
  await expect(inspector).toContainText('This check only · stays here when the next check starts');
  await inspector.getByRole('button', { name: 'Follow active check', exact: true }).first().click();
  await expect(inspector.locator('.probe-activity-run')).toHaveText(second);
  await inspector.getByRole('button', { name: 'Stop check', exact: true }).click();
  const confirm = page.getByRole('dialog', { name: 'Stop this exact check?' });
  await expect(confirm).toContainText('Other checks in the scan may continue');
  active = first; await page.waitForTimeout(2800);
  await page.evaluate((id) => { const params = new URLSearchParams(location.hash.split('?')[1]); params.set('ev_display', 'pinned'); params.set('ev_pin', id); location.hash = `target-detail?${params}`; }, first);
  await expect(inspector.locator('.probe-activity-run')).toHaveText(first);
  await expect(confirm).toBeVisible();
  await confirm.getByRole('button', { name: 'Stop check', exact: true }).click();
  await expect.poll(() => cancelled).toEqual([second]);
  await inspector.getByRole('button', { name: 'Stop scan', exact: true }).click();
  await page.getByRole('dialog', { name: 'Stop this scan?' }).getByRole('button', { name: 'Stop scan', exact: true }).click();
  await expect.poll(() => cancelled).toEqual([second, scanId]);
});

test('assessment A restores pinned A1 on reload despite active A2 and newer B, then explicit Follow selects A2 without mutations', async ({ page }) => {
  test.setTimeout(45000);
  const scanId = 'scan_pin_restore_a'; const first = 'run_pin_restore_a1'; const second = 'run_pin_restore_a2'; const newer = 'scan_pin_restore_b';
  let active = first; const mutations = []; const passiveReads = []; const contextQueries = [];
  page.on('request', (request) => { if (request.url().includes('/v1/') && request.method() !== 'GET') mutations.push(request.url()); });
  const scan = () => ({ id: scanId, target_id: TARGET, status: 'running', steps: [
    { id: 'restore_step_a1', target_id: TARGET, check_id: CHECK, test_run_id: first, status: active === first ? 'running' : 'verdicted' },
    { id: 'restore_step_a2', target_id: TARGET, check_id: CHECK, test_run_id: second, status: active === second ? 'running' : 'planned' },
  ] });
  await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [{ id: newer, target_id: TARGET, status: 'running', created_at: '2035-01-01T00:00:00.000Z', steps: [] }] } }));
  await page.route('**/v1/test-runs?*', (route) => route.fulfill({ json: { items: [] } }));
  await page.route(`**/v1/validation-scans/${scanId}?*`, (route) => { passiveReads.push(route.request().url()); expect(new URL(route.request().url()).searchParams.get('advance')).toBe('false'); return route.fulfill({ json: scan() }); });
  await page.route(`**/v1/validation-scans/${scanId}/activity?*`, (route) => route.fulfill({ json: { scan_id: scanId, status: 'running', items: [], pagination: { has_more: false, next_cursor: null } } }));
  await page.route('**/v1/evidence-context?*', (route) => { const params = new URL(route.request().url()).searchParams; contextQueries.push(Object.fromEntries(params)); return route.fulfill({ json: contextFor(params.get('test_run_id')) }); });
  for (const id of [first, second]) await page.route(`**/v1/test-runs/${id}/activity?*`, (route) => route.fulfill({ json: activityFor(id, [{ ...LOGS[0], id: `evt_${id}`, phase: id }]) }));
  await injectPortalDevHeadersSession(page);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&inspect=validation_scan&ev_target=${TARGET}&ev_scan=${scanId}`);
  const inspector = page.locator('.inspector-panel');
  await expect(inspector.locator('.probe-activity-run')).toHaveText(first);
  await inspector.getByRole('button', { name: 'Keep showing this check', exact: true }).click();
  active = second;
  await expect(page).toHaveURL(/ev_display=pinned.*ev_pin=run_pin_restore_a1/);
  await expect(inspector.getByRole('combobox', { name: 'Show another check from this scan' }).locator('option[value="run_pin_restore_a2"]')).toHaveCount(1);
  await page.reload();
  await expect(page).toHaveURL(new RegExp(`ev_scan=${scanId}.*ev_display=pinned.*ev_pin=${first}`));
  await expect(inspector.locator('.probe-activity-run')).toHaveText(first);
  await expect(inspector).toContainText('This check only · stays here when the next check starts');
  await expect(inspector).not.toContainText(newer);
  await expect(inspector).toContainText(`evt_${first}_result`);
  await inspector.getByRole('button', { name: 'Follow active check', exact: true }).first().click();
  await expect(inspector.locator('.probe-activity-run')).toHaveText(second);
  await expect(page).toHaveURL(new RegExp(`ev_scan=${scanId}.*ev_display=follow`));
  expect(new URL(page.url()).hash).not.toContain('ev_pin=');
  expect(mutations).toEqual([]);
  expect(passiveReads.length).toBeGreaterThan(1);
  for (const params of contextQueries) {
    expect(Object.keys(params).sort()).toEqual(['check_id', 'entry', 'target_id', 'test_run_id']);
    expect([first, second]).toContain(params.test_run_id);
  }
});

for (const invalid of ['missing', 'unrelated', 'other-target', 'malformed', 'forbidden-scan', 'forbidden-child']) {
  test(`restored assessment pin is explicitly unavailable for ${invalid}, without latest substitution`, async ({ page }) => {
    const scanId = `scan_pin_${invalid}`; const pinned = `run_pin_${invalid}`; const active = `run_active_${invalid}`;
    const mutations = []; const childReads = []; const contextReads = [];
    page.on('request', (request) => { if (request.url().includes('/v1/') && request.method() !== 'GET') mutations.push(request.url()); });
    await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [] } }));
    await page.route('**/v1/test-runs?*', (route) => route.fulfill({ json: { items: [] } }));
    await page.route(`**/v1/validation-scans/${scanId}?*`, (route) => {
      expect(new URL(route.request().url()).searchParams.get('advance')).toBe('false');
      if (invalid === 'forbidden-scan') return route.fulfill({ status: 403, json: { error: 'forbidden' } });
      return route.fulfill({ json: { id: scanId, target_id: TARGET, status: 'running', steps: [
        ...(invalid === 'other-target' || invalid === 'forbidden-child' ? [{ id: 'pin_step', test_run_id: pinned, check_id: CHECK, target_id: invalid === 'other-target' ? 'tgt_foreign_pin' : TARGET, status: 'verdicted' }] : []),
        { id: 'active_step', test_run_id: active, check_id: CHECK, target_id: TARGET, status: 'running' },
      ] } });
    });
    await page.route(`**/v1/validation-scans/${scanId}/activity?*`, (route) => route.fulfill({ json: { scan_id: scanId, status: 'running', items: [], has_more: false } }));
    await page.route('**/v1/test-runs/*/activity?*', (route) => { childReads.push(route.request().url()); return route.fulfill({ status: 403, json: { error: 'forbidden' } }); });
    await page.route('**/v1/evidence-context?*', (route) => { contextReads.push(route.request().url()); return route.fulfill({ json: contextFor(active) }); });
    await injectPortalDevHeadersSession(page);
    const pinParam = invalid === 'missing' ? '' : `&ev_pin=${invalid === 'malformed' ? 'bad%20pin' : pinned}`;
    await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&inspect=validation_scan&ev_target=${TARGET}&ev_scan=${scanId}&ev_display=pinned${pinParam}`);
    const inspector = page.locator('.inspector-panel');
    await expect(inspector).toContainText('Selected check unavailable');
    await expect(inspector.locator('.probe-activity-run')).toHaveCount(0);
    await expect(inspector).not.toContainText(`evt_${active}_result`);
    await expect(inspector.getByRole('button', { name: 'Stop check', exact: true })).toHaveCount(0);
    expect(childReads.every((url) => invalid === 'forbidden-child' && new URL(url).pathname === `/v1/test-runs/${pinned}/activity`)).toBe(true);
    expect(contextReads).toEqual([]); expect(mutations).toEqual([]);
  });
}

test('restored pin revalidates membership after role, tenant and session changes before any child read', async ({ page }) => {
  test.setTimeout(45000);
  await page.setViewportSize({ width: 1440, height: 1000 });
  const scanId = 'scan_pin_scope'; const pinned = 'run_pin_scope'; const childReads = []; const scanScopes = [];
  let release; const gate = new Promise((resolve) => { release = resolve; });
  await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [] } }));
  await page.route('**/v1/test-runs?*', (route) => route.fulfill({ json: { items: [] } }));
  await page.route(`**/v1/validation-scans/${scanId}?*`, async (route) => {
    const headers = route.request().headers(); scanScopes.push([headers['x-tenant-id'], headers['x-user-id'], headers['x-role']]);
    expect(new URL(route.request().url()).searchParams.get('advance')).toBe('false');
    if (headers['x-role'] !== 'owner' || headers['x-tenant-id'] !== PORTAL_BASELINE_IDS.tenantId || headers['x-user-id'] !== 'usr_owner') return route.fulfill({ status: 403, json: { error: 'forbidden' } });
    await gate; return route.fulfill({ json: { id: scanId, target_id: TARGET, status: 'running', steps: [{ target_id: TARGET, check_id: CHECK, test_run_id: pinned, status: 'running' }] } });
  });
  await page.route(`**/v1/validation-scans/${scanId}/activity?*`, (route) => route.fulfill({ json: { scan_id: scanId, status: 'running', items: [], has_more: false } }));
  await page.route(`**/v1/test-runs/${pinned}/activity?*`, (route) => { childReads.push(route.request().headers()); return route.fulfill({ json: activityFor(pinned) }); });
  const href = `${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&inspect=validation_scan&ev_target=${TARGET}&ev_scan=${scanId}&ev_display=pinned&ev_pin=${pinned}`;
  await injectPortalDevHeadersSession(page); await page.goto(href);
  await expect.poll(() => scanScopes.length).toBeGreaterThan(0);
  await page.getByRole('button', { name: /Role \(dev\)/ }).click();
  await page.getByRole('option', { name: /viewer/i }).click();
  await expect.poll(() => scanScopes.some(([, , role]) => role === 'viewer')).toBe(true);
  release();
  await expect(page.locator('.inspector-panel')).toContainText('Selected check unavailable');
  expect(childReads).toEqual([]);
  await page.evaluate(() => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({ mode: 'dev-headers', principal: 'customer', role: 'viewer', tenant_id: 'ten_foreign_pin', user_id: 'usr_foreign_pin' }));
    location.hash = 'targets';
  });
  await expect(page).toHaveURL(/#targets/);
  // Same-document navigation keeps the replacement session; a reload would rerun the owner init script.
  await page.evaluate((hash) => { location.hash = hash; }, new URL(href).hash);
  await expect.poll(() => scanScopes.some(([tenant, user]) => tenant === 'ten_foreign_pin' && user === 'usr_foreign_pin')).toBe(true);
  await expect(page.locator('.inspector-panel')).toContainText('Selected check unavailable');
  expect(childReads).toEqual([]);
});

test('recorded Stop remains requested until real acknowledgment; deadline and unreachable never imply success', async ({ page }) => {
  test.setTimeout(45000);
  let state = 'not_requested'; const cancels = [];
  await mockContext(page);
  await page.route(`**/v1/test-runs/${RUN}/activity?*`, (route) => route.fulfill({ json: activityFor(RUN, LOGS, { status: state === 'not_requested' ? 'collecting' : 'cancelled', stop: { state } }) }));
  await page.route(`**/v1/test-runs/${RUN}/cancel`, (route) => { state = 'requested'; cancels.push(route.request().postDataJSON()); return route.fulfill({ json: { id: RUN, status: 'cancelled' } }); });
  await openExact(page);
  const inspector = page.locator('.inspector-panel');
  await inspector.getByRole('button', { name: 'Stop check', exact: true }).click();
  await page.getByRole('dialog', { name: 'Stop this exact check?' }).getByRole('button', { name: 'Stop check', exact: true }).click();
  await expect(inspector).toContainText('worker acknowledgment pending');
  await expect(inspector).not.toContainText('Worker acknowledged Stop');
  state = 'unreachable';
  await expect(inspector).toContainText('Worker unreachable · Stop is not confirmed', { timeout: 9000 });
  // Explicit Reopen re-reads this exact terminal execution; no different run is chosen.
  await inspector.getByRole('button', { name: 'Close Check result' }).click();
  state = 'deadline_elapsed'; await openExact(page);
  await expect(page.locator('.inspector-panel')).toContainText('Authorization deadline elapsed · worker Stop is not confirmed');
  await page.locator('.inspector-panel').getByRole('button', { name: 'Close Check result' }).click();
  state = 'acknowledged'; await openExact(page);
  await expect(page.locator('.inspector-panel')).toContainText('Worker acknowledged Stop');
  expect(cancels).toHaveLength(1);
});

test('live Inspector is keyboard reachable and contained across themes, reduced motion and four widths', async ({ page }) => {
  test.setTimeout(120000);
  await mockContext(page);
  await page.route(`**/v1/test-runs/${RUN}/activity?*`, (route) => route.fulfill({ json: activityFor(RUN, LOGS, { source_context: { worker_id: 'local-test-worker', job_id: 'job_signed', leased_at: AT }, authorized_bounds: { max_probe_requests: 4, max_total_operations: 6, timeout_ms: 5000 } }) }));
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await openExact(page);
  const inspector = page.locator('.inspector-panel');
  const heading = inspector.getByRole('heading', { name: 'Check result', exact: true });
  await expect(heading).toBeFocused();
  let previousMode = await inspector.getAttribute('data-mode');
  for (const width of [375, 768, 1024, 1440]) for (const theme of ['dark', 'light']) {
    await test.step(`${width}px ${theme}`, async () => {
      await page.setViewportSize({ width, height: 950 });
      await page.evaluate((value) => document.documentElement.setAttribute('data-theme', value), theme);
      const mode = width >= 1360 ? 'docked' : width <= 699 ? 'sheet' : 'drawer';
      await expect(inspector).toBeVisible();
      await expect(inspector).toHaveAttribute('data-mode', mode);
      // A breakpoint transition hands focus to the heading on the next animation frame.
      // Finish that handoff before focusing a row; visibility alone does not settle focus.
      if (mode !== previousMode) await expect(heading).toBeFocused();
      previousMode = mode;
      const details = inspector.getByRole('button', { name: 'Details for event log_payload' });
      await expect(details).toHaveAttribute('aria-expanded', 'false');
      await details.focus();
      await expect(details).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(details).toHaveAttribute('aria-expanded', 'true');
      await expect(inspector.locator('.probe-activity-detail')).toContainText('<html>Request blocked</html>');
      await expect(inspector.locator('.probe-activity-detail html')).toHaveCount(0);
      await details.click();
      await expect(details).toHaveAttribute('aria-expanded', 'false');
      await expect(inspector.locator('.probe-activity-detail')).toHaveCount(0);
      expect(await inspector.evaluate((node) => node.scrollWidth - node.clientWidth), `${width} ${theme}`).toBeLessThanOrEqual(1);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
      const axe = await new AxeBuilder({ page }).include('.inspector-panel').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
      expect(axe.violations.filter((item) => ['serious', 'critical'].includes(item.impact ?? '')).map((item) => `${item.id}: ${item.nodes.map((node) => node.target).join(' ')}`)).toEqual([]);
    });
  }
});

test('reviewed run-all opens and passively reconnects/reloads the exact accepted assessment', async ({ page }) => {
  test.setTimeout(45000);
  const scanId = 'scan_review_accepted'; const child = 'run_review_child'; const bodies = []; const mutations = [];
  let fail = false;
  page.on('request', (request) => { if (request.url().includes('/v1/') && request.method() !== 'GET') mutations.push(request.url()); });
  const scan = { id: scanId, target_id: TARGET, status: 'running', steps: [{ id: 'review_step', check_id: CHECK, target_id: TARGET, test_run_id: child, status: 'running' }] };
  await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [{ id: 'scan_stale_latest', target_id: TARGET, status: 'completed', steps: [] }] } }));
  await page.route('**/v1/validation-scans', (route) => { if (route.request().method() !== 'POST') return route.continue(); bodies.push(route.request().postDataJSON()); return route.fulfill({ status: 201, json: scan }); });
  await page.route(`**/v1/validation-scans/${scanId}?*`, (route) => { expect(new URL(route.request().url()).searchParams.get('advance')).toBe('false'); return route.fulfill({ json: scan }); });
  await page.route(`**/v1/validation-scans/${scanId}/activity?*`, (route) => route.fulfill({ json: { scan_id: scanId, status: 'running', items: [], pagination: { next_cursor: null, has_more: false }, capture: { status: 'unknown' } } }));
  await mockContext(page);
  await page.route(`**/v1/test-runs/${child}/activity?*`, (route) => {
    if (fail) { fail = false; return route.fulfill({ status: 503, json: { error: 'offline' } }); }
    return route.fulfill({ json: activityFor(child) });
  });
  await injectPortalDevHeadersSession(page);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate`);
  await page.locator('.td-checks').getByRole('button', { name: /^Review all/ }).click();
  const review = page.locator('dialog.modal-confirm[open]');
  await expect(review).toContainText('The server re-checks ownership'); expect(bodies).toEqual([]);
  await review.getByRole('button', { name: 'Start all checks', exact: true }).click();
  const inspector = page.locator('.inspector-panel');
  await expect(inspector.getByRole('heading', { name: 'Validation scan', exact: true })).toBeFocused();
  await expect(page).toHaveURL(new RegExp(`ev_scan=${scanId}`));
  await expect(inspector.locator('.probe-activity-run')).toHaveText(child);
  await expect(inspector).not.toContainText('scan_stale_latest');
  expect(bodies).toHaveLength(1); expect(bodies[0].target_id).toBe(TARGET); expect(bodies[0].target_group_id).toBeUndefined();
  const executionUrl = page.url();
  fail = true;
  await expect(inspector).toContainText('Disconnected', { timeout: 9000 });
  await expect(inspector.locator('.probe-activity-run')).toHaveText(child);
  await inspector.getByRole('button', { name: 'Reconnect', exact: true }).click();
  await expect(inspector).not.toContainText('Disconnected');
  await expect(page).toHaveURL(new RegExp(`ev_scan=${scanId}`));
  await page.route('**/v1/validation-scans?*', (route) => route.fulfill({ json: { items: [{ id: 'scan_newer_after_acceptance', target_id: TARGET, status: 'running', created_at: '2035-01-01T00:00:00.000Z', steps: [] }] } }));
  await page.goto(executionUrl);
  await page.reload();
  await expect(page).toHaveURL(new RegExp(`ev_scan=${scanId}`));
  await expect(inspector.locator('.probe-activity-run')).toHaveText(child);
  await expect(inspector).not.toContainText('scan_newer_after_acceptance');
  expect(bodies).toHaveLength(1);
  expect(mutations).toHaveLength(1);
  expect(new URL(mutations[0]).pathname).toBe('/v1/validation-scans');
});

test('reviewed detection uses its returned exact run and does not probe before confirmation', async ({ page }) => {
  const exact = 'run_detection_accepted'; const posts = [];
  await page.route('**/v1/waf/edge-detection', (route) => { if (route.request().method() !== 'POST') return route.continue(); posts.push(route.request().postDataJSON()); return route.fulfill({ status: 202, json: { detection_request: { test_run_id: exact, run_status: 'running' } } }); });
  await mockContext(page);
  await page.route(`**/v1/test-runs/${exact}/activity?*`, (route) => route.fulfill({ json: activityFor(exact) }));
  await injectPortalDevHeadersSession(page);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}`);
  await page.locator('.td-observations').getByRole('button', { name: 'Detect WAF and CDN', exact: true }).click();
  expect(posts).toEqual([]);
  await page.locator('dialog.modal-confirm[open]').getByRole('button', { name: 'Start detection', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`ev_run=${exact}`));
  await expect(page.locator('.inspector-panel .probe-activity-run')).toHaveText(exact);
  expect(posts).toEqual([{ target_id: TARGET }]);
});

test('Stop Cancel and Escape keep the Inspector open and restore nested-modal focus on phone and tablet', async ({ page }) => {
  await mockContext(page);
  await page.route(`**/v1/test-runs/${RUN}/activity?*`, (route) => route.fulfill({ json: activityFor(RUN) }));
  const mutations = [];
  page.on('request', (request) => { if (request.method() !== 'GET' && request.url().includes('/v1/')) mutations.push(request.url()); });
  await openExact(page);
  for (const width of [375, 768]) {
    await page.setViewportSize({ width, height: 950 });
    const inspector = page.locator('.inspector-panel'); const stop = inspector.getByRole('button', { name: 'Stop check', exact: true });
    await stop.click();
    await page.getByRole('dialog', { name: 'Stop this exact check?' }).getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(inspector).toBeVisible(); await expect(stop).toBeFocused();
    await stop.click(); await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog', { name: 'Stop this exact check?' })).toHaveCount(0);
    await expect(inspector).toBeVisible(); await expect(stop).toBeFocused();
  }
  expect(mutations).toEqual([]);
});

test('activity revocation discards retained verdicts and events even in a paused Inspector', async ({ page }) => {
  let revoked = false;
  await mockContext(page);
  await page.route('**/v1/test-runs?*', (route) => route.fulfill({ json: { items: [{ id: RUN, target_id: TARGET, check_id: CHECK, status: 'collecting', created_at: AT }] } }));
  await page.route(`**/v1/test-runs/${RUN}/activity?*`, (route) => revoked ? route.fulfill({ status: 403, json: { error: 'forbidden' } }) : route.fulfill({ json: activityFor(RUN, [{ ...LOGS[0], method: 'PRIVATEOWNER' }]) }));
  await openExact(page);
  const inspector = page.locator('.inspector-panel');
  await expect(inspector).toContainText('PRIVATEOWNER'); await expect(inspector).toContainText(`evt_${RUN}_result`);
  await inspector.getByRole('button', { name: 'Pause updates', exact: true }).click(); revoked = true;
  await expect(inspector).toContainText('Access required', { timeout: 9000 });
  await expect(inspector).not.toContainText('PRIVATEOWNER'); await expect(inspector).not.toContainText(`evt_${RUN}_result`);
  await expect(inspector.getByRole('button', { name: /^Stop/ })).toHaveCount(0);
});

test('late context and activity cannot cross a tenant and user switch in the same page', async ({ page }) => {
  test.setTimeout(45000);
  let release; const gate = new Promise((resolve) => { release = resolve; }); const scopes = [];
  await page.route('**/v1/evidence-context?*', async (route) => {
    const headers = route.request().headers(); scopes.push([headers['x-tenant-id'], headers['x-user-id']]);
    if (headers['x-tenant-id'] !== PORTAL_BASELINE_IDS.tenantId) return route.fulfill({ json: { state: 'not_found' } });
    await gate; return route.fulfill({ json: { ...contextFor(RUN), answer: { observed_behavior: 'PRIORWORKSPACEEVIDENCE' } } });
  });
  await page.route(`**/v1/test-runs/${RUN}/activity?*`, async (route) => {
    if (route.request().headers()['x-tenant-id'] !== PORTAL_BASELINE_IDS.tenantId) return route.fulfill({ status: 404, json: { error: 'not_found', state: 'not_found' } });
    await gate; return route.fulfill({ json: activityFor(RUN, [{ ...LOGS[0], method: 'PRIORWORKSPACEACTIVITY' }]) });
  });
  await openExact(page);
  await page.evaluate(() => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({ mode: 'dev-headers', principal: 'customer', role: 'viewer', tenant_id: 'ten_other_activity', user_id: 'usr_other_activity' }));
    location.hash = 'targets';
  });
  await expect(page).toHaveURL(/#targets/);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${TARGET}&tab=validate&inspect=check_result&ev_target=${TARGET}&ev_check=${CHECK}&ev_run=${RUN}`);
  await expect.poll(() => scopes.some(([tenant, user]) => tenant === 'ten_other_activity' && user === 'usr_other_activity')).toBe(true);
  release();
  const inspector = page.locator('.inspector-panel');
  await expect(inspector).toContainText('No longer available');
  await expect(inspector).not.toContainText('PRIORWORKSPACE');
  await expect(inspector.getByRole('button', { name: /^Stop/ })).toHaveCount(0);
});

async function signed(method, path, body, { tamper = false } = {}) {
  const bodyText = body == null ? '' : JSON.stringify(body);
  const headers = { ...probeWorkerAuthHeaders('worker_browser_local', { method, path, bodyText, tenantId: PORTAL_BASELINE_IDS.tenantId }, SECRET), ...(body ? { 'content-type': 'application/json' } : {}) };
  const response = await fetch(`${apiBase}${path}`, { method, headers, body: body ? (tamper ? JSON.stringify({ ...body, leased_at: 'tampered' }) : bodyText) : undefined });
  return { status: response.status, json: await response.json() };
}
async function startLocalReviewed(page) {
  await injectPortalDevHeadersSession(page);
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#target-detail?id=${LOCAL_TARGET}&tab=validate&check=${LOCAL_CHECK}`);
  await page.getByRole('button', { name: 'Review and start', exact: true }).click();
  const accepted = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname === '/v1/test-runs');
  await page.locator('dialog.modal-confirm[open]').getByRole('button', { name: 'Start check', exact: true }).click();
  const response = await accepted; expect(response.status()).toBe(201);
  const { run } = await response.json();
  expect(run.id).toBeTruthy();
  await expect(page).toHaveURL(new RegExp(`ev_run=${run.id}`));
  await expect(page.locator('.inspector-panel .probe-activity-run')).toHaveText(run.id);
  return run;
}
async function leasedLocal(run) {
  const lease = await signed('GET', '/internal/probe/jobs'); expect(lease.status).toBe(200);
  const job = lease.json.jobs.find((item) => item.test_run_id === run.id); expect(job).toBeTruthy();
  expect(verifyProbeJobSignature(job, SECRET)).toBe(true);
  const path = `/internal/probe/jobs/${job.id}/execute`;
  const tampered = await signed('POST', path, { leased_at: job.leased_at }, { tamper: true }); expect(tampered.status).toBe(401);
  const grant = await signed('POST', path, { leased_at: job.leased_at });
  expect(grant).toMatchObject({ status: 201, json: { authorized: true, not_after: job.constraints.not_after } });
  expect(grant.json.reservation_id).toBeTruthy();
  expect((await signed('POST', path, { leased_at: job.leased_at })).status).toBe(409);
  return job;
}

test('connected reviewed Play observes real loopback HTTP through signed worker capture and final evidence, with secret redaction', async ({ page }) => {
  test.setTimeout(60000);
  const run = await startLocalReviewed(page); const job = await leasedLocal(run);
  const reporter = createProbeActivityReporter(job, (body) => signed('POST', `/internal/probe/jobs/${job.id}/activity`, body));
  let result;
  try { result = await processJob({ secret: SECRET }, job, { destinationPolicy: { allowLoopback: true, allowPrivate: false }, onProbeActivity: reporter.record }); }
  finally { await reporter.close(); }
  expect(result.safety_attestation.probe_requests_sent).toBe(wireCalls.length);
  expect(wireCalls.length).toBeGreaterThan(1);
  expect(wireCalls.some((call) => call.method === 'GET' && call.marker)).toBe(true);
  expect(wireCalls.every((call) => ['GET', 'HEAD'].includes(call.method) && call.body === '')).toBe(true);
  expect((await signed('POST', `/internal/probe/jobs/${job.id}/result`, result)).status).toBe(201);
  // Advance only the deterministic test collection clock, not the passive GET or network work.
  const stored = getStore().testRuns.find((item) => item.id === run.id); stored.collection_deadline_at = new Date(Date.now() - 1000).toISOString();
  const { maybeFinalizeRunAfterProbeIngest } = await import('../../../src/services/testRuns.mjs');
  maybeFinalizeRunAfterProbeIngest({ tenantId: PORTAL_BASELINE_IDS.tenantId }, run.id);
  const inspector = page.locator('.inspector-panel');
  await expect(inspector.locator('.probe-exchanges')).toContainText('GET', { timeout: 15000 });
  await expect(inspector.locator('.probe-exchanges')).toContainText('HTTP 403');
  await expect(inspector.locator('.probe-activity-status')).toContainText(`${result.safety_attestation.requests_sent} logical operations (attested)`);
  const activity = await fetch(`${apiBase}/v1/test-runs/${run.id}/activity?limit=256`, { headers: { 'x-tenant-id': PORTAL_BASELINE_IDS.tenantId, 'x-user-id': 'usr_owner', 'x-role': 'owner' } }).then((response) => response.json());
  expect(JSON.stringify(activity)).not.toMatch(/local-customer-secret-123|private-response-password/);
  const payload = activity.items.find((item) => item.response_payload_preview?.includes('local-wire-observed')); expect(payload).toBeTruthy();
  const capture = inspector.locator('.probe-exchange').filter({ has: page.locator('.probe-exchange-summary', { hasText: 'HTTP 403' }) }).first();
  const captureSummary = capture.locator('.probe-exchange-summary');
  if (await captureSummary.getAttribute('aria-expanded') !== 'true') await captureSummary.click();
  await expect(capture).toContainText('local-wire-observed');
  await expect(inspector).not.toContainText('private-response-password');
  await expect(inspector).not.toContainText('local-customer-secret-123');
  await expect(inspector).toContainText('worker_browser_local');
  await expect(inspector.locator('.ei-evidence-list, .ei-ids, a[href*="evidence-detail"]')).not.toHaveCount(0, { timeout: 15000 });
  expect(activity.source_context.worker_id).toBe('worker_browser_local');
  expect(activity.authorized_bounds.max_total_operations).toBe(job.constraints.max_total_operations);
});

test('connected Stop is exact, keeps recorded requests, and shows only the actual signed worker acknowledgment', async ({ page }) => {
  test.setTimeout(60000); delayWire = true;
  const run = await startLocalReviewed(page); const job = await leasedLocal(run);
  const cancellation = new AbortController(); let reason;
  const reporter = createProbeActivityReporter(job, (body) => signed('POST', `/internal/probe/jobs/${job.id}/activity`, body), { heartbeatMs: 100, partitionGraceMs: 2500, onStop: (stop) => { reason = stop.reason; cancellation.abort(); } });
  const working = processJob({ secret: SECRET }, job, { destinationPolicy: { allowLoopback: true, allowPrivate: false }, cancellationSignal: cancellation.signal, onProbeActivity: reporter.record });
  await expect.poll(() => wireCalls.length).toBeGreaterThan(0);
  const inspector = page.locator('.inspector-panel');
  await inspector.getByRole('button', { name: 'Stop check', exact: true }).click();
  await page.getByRole('dialog', { name: 'Stop this exact check?' }).getByRole('button', { name: 'Stop check', exact: true }).click();
  await expect(inspector).toContainText('worker acknowledgment pending');
  await working; await reporter.close();
  expect(cancellation.signal.aborted).toBe(true);
  await expect(inspector).not.toContainText('Worker acknowledged Stop');
  const ack = await signed('POST', `/internal/probe/jobs/${job.id}/stop`, { leased_at: job.leased_at, reason, capture: reporter.snapshot() });
  expect(ack).toMatchObject({ status: 201, json: { acknowledged: true } });
  await expect(inspector).toContainText('Worker acknowledged Stop', { timeout: 12000 });
  await expect(inspector.locator('.probe-activity-status')).not.toContainText('0 recorded events retained');
  expect(wireCalls.length).toBeLessThanOrEqual(job.constraints.max_probe_requests);
});
