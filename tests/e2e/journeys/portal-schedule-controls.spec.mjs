import path from 'node:path';
import { expect, test } from '@playwright/test';
import { createServer as createViteServer } from 'vite';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

const URL_TARGET_ID = 'tgt_checkout_url_inferred';
const IP_GROUP_ID = 'tg_api_ip_only';
const IP_TARGET_ID = 'tgt_api_ip_only';
const URL_ONLY_CHECK = 'URL-Only Schedule Probe (Safe)';
const HOST_CHECK = 'Firewall Exposure Scan (Safe)';
const URL_ONLY_CHECK_FIXTURE = {
  check_id: 'ui.url_only_schedule.safe',
  version: '1.0.0',
  name: URL_ONLY_CHECK,
  vector_family: 'l7',
  description: 'Browser fixture for exact URL target compatibility.',
  safety_class: 'safe',
  risk_class: 'safe',
  supported_targets: ['url'],
  required_customer_setup: [],
  evidence_required: ['probe_result'],
  safety_constraints: { customer_runnable: true, max_events: 1, max_duration_seconds: 30 },
  probe_profile: { kind: 'http_head', max_requests: 1, timeout_ms: 1000 },
  default_expected_behavior: 'must_reach_canary',
};
let sourceBaseUrl = '';
let vite;

function applyScheduleControlFixture(store) {
  applyPortalBaselineReadinessBoost(store);
  const group = store.targetGroups.find((item) => item.id === PORTAL_BASELINE_IDS.targetGroupId);
  if (group) group.validation_mode = 'external_only';
  store.targets.push({
    id: URL_TARGET_ID,
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
    // Regression: policy APIs infer URL from the value even when legacy data carries another kind.
    kind: 'fqdn',
    value: 'https://checkout.acme.com/health',
    expected_behavior: 'must_reach_canary',
    verify_state: 'dns_verified',
    eligibility: 'eligible',
    created_at: PORTAL_BASELINE_IDS.frozenAt,
  });
  store.targetGroups.push({
    id: IP_GROUP_ID,
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    environment_id: PORTAL_BASELINE_IDS.environmentId,
    name: 'api-ip-only',
    validation_mode: 'external_only',
    expected_behavior_default: 'must_block_before_origin',
    created_at: PORTAL_BASELINE_IDS.frozenAt,
  });
  store.targets.push({
    id: IP_TARGET_ID,
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    target_group_id: IP_GROUP_ID,
    kind: 'ip',
    value: '203.0.113.42',
    expected_behavior: 'must_block_before_origin',
    verify_state: 'dns_verified',
    eligibility: 'eligible',
    created_at: PORTAL_BASELINE_IDS.frozenAt,
  });
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function chooseCustomSelect(scope, label, option) {
  const trigger = scope.getByRole('button', { name: label, exact: true });
  await expect(trigger).toBeEnabled({ timeout: 10_000 });
  await trigger.click();
  const listbox = scope.getByRole('listbox', { name: label, exact: true });
  await expect(listbox).toBeVisible();
  await listbox.getByRole('option', { name: new RegExp(escapeRegExp(option)) }).click();
  return trigger;
}

test.describe('schedule form controls', () => {
  test.beforeAll(async () => {
    const { baseUrl: apiBaseUrl } = await startPortalPlaywrightServer({ mutate: applyScheduleControlFixture });
    vite = await createViteServer({
      configFile: path.resolve('vite.config.ts'),
      logLevel: 'silent',
      server: {
        host: '127.0.0.1',
        port: 0,
        strictPort: false,
        proxy: {
          '/v1': apiBaseUrl,
          '/ready': apiBaseUrl,
          '/internal': apiBaseUrl,
        },
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

  test.beforeEach(async ({ page }) => {
    await page.route('**/v1/checks', async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({
        response,
        body: JSON.stringify({
          ...payload,
          items: [...(Array.isArray(payload.items) ? payload.items : []), URL_ONLY_CHECK_FIXTURE],
        }),
      });
    });
  });

  test('picker Escape stays inside the create panel and Select stays in the viewport at 360x740 with keyboard navigation', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 740 });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'test-policies', sourceBaseUrl);

    const createButton = page.locator('.rf-header-actions').getByRole('button', { name: 'Create schedule' });
    await createButton.click();
    const panel = page.locator('section.rf-create');
    await expect(panel).toBeVisible();
    await expect(panel.getByRole('heading', { name: 'New validation schedule' })).toBeFocused();

    const domainSearch = panel.getByRole('searchbox', { name: 'Search declared domains' });
    await domainSearch.focus(); await domainSearch.press('Escape');
    await expect(panel).toBeVisible(); await expect(domainSearch).toBeFocused();

    const expectedTrigger = panel.getByRole('button', { name: 'Expected verdict', exact: true });
    await expectedTrigger.scrollIntoViewIfNeeded();
    await expectedTrigger.click();
    const expectedMenu = panel.getByRole('listbox', { name: 'Expected verdict', exact: true });
    await expect(expectedMenu).toBeVisible();
    await page.waitForTimeout(250);
    const menuBox = await expectedMenu.boundingBox();
    expect(menuBox).not.toBeNull();
    expect(menuBox.y).toBeGreaterThanOrEqual(8 - 1);
    expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(740 - 8 + 1);
    expect(menuBox.x + menuBox.width).toBeLessThanOrEqual(360 + 1);

    await expectedTrigger.press('Escape');
    await expect(expectedMenu).toBeHidden();
    await expect(panel).toBeVisible();
    const cadenceTrigger = panel.getByRole('button', { name: 'Cadence', exact: true });
    await cadenceTrigger.focus();
    await cadenceTrigger.press('ArrowDown');
    const cadenceMenu = panel.getByRole('listbox', { name: 'Cadence', exact: true });
    await expect(cadenceMenu).toBeVisible();
    await expect(cadenceMenu.getByRole('option', { name: 'Weekly', exact: true })).toBeFocused();
    await page.keyboard.press('End');
    await page.keyboard.press('Enter');
    await expect(cadenceMenu).toBeHidden();
    await expect(cadenceTrigger).toContainText('Monthly');
    await expect(cadenceTrigger).toBeFocused();

    await expect(panel.locator('.rf-readiness')).toContainText('Select a check to continue.');
    await expect(panel.getByRole('button', { name: 'Create schedule', exact: true })).toBeDisabled();
    await panel.getByRole('button', { name: 'Cancel' }).first().click();
    await expect(panel).toHaveCount(0);
    await expect(createButton).toBeFocused();
  });

  test('direct domain selection retains incompatible selections explicitly and starts no traffic', async ({ page }) => {
    const writes = [];
    page.on('request', (request) => { if (new URL(request.url()).pathname.startsWith('/v1/') && request.method() !== 'GET') writes.push(request.method()); });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'test-policies', sourceBaseUrl);
    await page.locator('.rf-header-actions').getByRole('button', { name: 'Create schedule' }).click();
    const panel = page.locator('section.rf-create');
    await chooseCustomSelect(panel, 'Check', URL_ONLY_CHECK);
    await panel.locator('.domain-picker-option').filter({ hasText: 'https://checkout.acme.com/health' }).getByRole('checkbox').check();
    await expect(panel.getByRole('button', { name: 'Create schedule', exact: true })).toBeEnabled();
    await chooseCustomSelect(panel, 'Check', HOST_CHECK);
    await expect(panel.getByRole('button', { name: 'Create schedule', exact: true })).toBeDisabled();
    await expect(panel.locator('.rf-readiness')).toContainText('Select active domains compatible with this check.');
    await expect(panel.locator('.domain-picker-option').filter({ hasText: 'https://checkout.acme.com/health' }).getByRole('checkbox')).toBeChecked();
    expect(writes).toEqual([]);
  });

  test('removed grouping links resolve to direct Targets with no group request', async ({ page }) => {
    const requests = [];
    page.on('request', (request) => { if (request.url().includes('/v1/target-groups')) requests.push(request.url()); });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-group-detail', sourceBaseUrl);
    await expect(page.getByRole('heading', { name: 'Targets', exact: true })).toBeVisible();
    await expect(page).toHaveURL(/#targets$/);
    await expect(page.getByRole('button', { name: 'Target groups', exact: true })).toHaveCount(0);
    expect(requests).toEqual([]);
  });
});
