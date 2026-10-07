import { mkdir } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { getPortalPlaywrightBaseUrl, startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession, PORTAL_SESSION } from '../../helpers/portal-playwright-session.mjs';

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

async function fixture(page, role = 'owner') {
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
      items: stopped ? [...LOGS, { id: 'log_stop', at: AT, stage: 'run_stopped', source: 'run_state' }] : LOGS, count: stopped ? LOGS.length + 1 : LOGS.length, truncated: false } });
  });
  await page.route(`**/v1/test-runs/${RUN}/cancel`, (route) => {
    stopped = true; cancels.push(route.request().postDataJSON());
    return route.fulfill({ json: { id: RUN, status: 'cancelled' } });
  });
  await injectPortalDevHeadersSession(page, { ...PORTAL_SESSION, role });
  await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl(), { entityIds: { 'target-detail': TARGET } });
  await page.getByRole('tab', { name: /Validate/ }).click();
  await expect(page.locator('.probe-activity-table')).toContainText('HTTP 418');
  return { cancels, reads: () => reads };
}

test.beforeEach(async () => { await startPortalPlaywrightServer(); });
test.afterEach(async () => { await stopPortalPlaywrightServer(); });

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
  await expect(panel).toContainText('outside request budget');
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
  await expect(selected).toContainText('Request count not recorded yet');
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
  await expect(panel).toContainText('replacement', { timeout: 12000 });
  await expect(panel.getByRole('button', { name: 'Pause updates' })).toBeVisible();
});

for (const width of [375, 768, 1024, 1440]) {
  for (const theme of ['dark', 'light']) {
    test(`activity table stays accessible and contained at ${width}px in ${theme}`, async ({ page }) => {
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
