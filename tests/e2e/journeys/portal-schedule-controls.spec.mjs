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

  test('picker Escape stays inside the dialog and Select stays bounded at 360x740 with keyboard navigation', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 740 });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'test-policies', sourceBaseUrl);

    await page.getByRole('button', { name: 'Create schedule', exact: true }).first().click();
    const dialog = page.locator('dialog.form-modal[open]');
    await expect(dialog).toBeVisible();

    const pickerTrigger = dialog.locator('.tg-picker-trigger');
    await pickerTrigger.click();
    await expect(dialog.locator('.tg-picker-menu')).toBeVisible();
    await pickerTrigger.press('Escape');
    await expect(dialog.locator('.tg-picker-menu')).toBeHidden();
    await expect(dialog).toBeVisible();
    await expect(pickerTrigger).toBeFocused();

    const expectedTrigger = dialog.getByRole('button', { name: 'Expected verdict', exact: true });
    await expectedTrigger.scrollIntoViewIfNeeded();
    await expectedTrigger.click();
    const expectedMenu = dialog.getByRole('listbox', { name: 'Expected verdict', exact: true });
    await expect(expectedMenu).toBeVisible();
    await page.waitForTimeout(250);

    const [menuBox, bodyBox] = await Promise.all([
      expectedMenu.boundingBox(),
      dialog.locator('.form-modal-body').boundingBox(),
    ]);
    expect(menuBox).not.toBeNull();
    expect(bodyBox).not.toBeNull();
    expect(menuBox.y).toBeGreaterThanOrEqual(Math.max(8, bodyBox.y) - 1);
    expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(
      Math.min(740 - 8, bodyBox.y + bodyBox.height) + 1,
    );

    await expectedTrigger.press('Escape');
    await expect(dialog).toBeVisible();
    const cadenceTrigger = dialog.getByRole('button', { name: 'Cadence', exact: true });
    await cadenceTrigger.focus();
    await cadenceTrigger.press('ArrowDown');
    const cadenceMenu = dialog.getByRole('listbox', { name: 'Cadence', exact: true });
    await expect(cadenceMenu).toBeVisible();
    await expect(cadenceMenu.getByRole('option', { name: 'Weekly', exact: true })).toBeFocused();
    await page.keyboard.press('End');
    await page.keyboard.press('Enter');
    await expect(cadenceMenu).toBeHidden();
    await expect(cadenceTrigger).toContainText('Monthly');
    await expect(cadenceTrigger).toBeFocused();
  });

  test('global schedule offers only compatible exact targets, explains empty compatibility, and clears on check change', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'test-policies', sourceBaseUrl);
    await page.getByRole('button', { name: 'Create schedule', exact: true }).first().click();
    const dialog = page.locator('dialog.form-modal[open]');

    await chooseCustomSelect(dialog, 'Check', URL_ONLY_CHECK);
    const pickerTrigger = dialog.locator('.tg-picker-trigger');
    await pickerTrigger.click();
    const picker = dialog.locator('.tg-picker-menu');
    await picker.getByRole('option', { name: /edge-checkout/ }).click();
    await picker.getByRole('option', { name: /api-ip-only/ }).click();
    await pickerTrigger.press('Escape');

    const edgeTarget = dialog.getByRole('button', { name: 'edge-checkout exact target', exact: true });
    await expect(edgeTarget).toBeEnabled({ timeout: 10_000 });
    await edgeTarget.click();
    const edgeOptions = dialog.getByRole('listbox', { name: 'edge-checkout exact target', exact: true });
    await expect(edgeOptions.getByRole('option', { name: /https:\/\/checkout\.acme\.com\/health/ })).toBeVisible();
    await expect(edgeOptions.getByRole('option', { name: /^checkout\.acme\.com/ })).toHaveCount(0);
    await edgeOptions.getByRole('option', { name: /https:\/\/checkout\.acme\.com\/health/ }).click();

    await expect(dialog.getByText(/api-ip-only has no exact target compatible with URL-Only Schedule Probe/)).toBeVisible();
    await chooseCustomSelect(dialog, 'Check', HOST_CHECK);
    await expect(edgeTarget).toContainText('Select exact target');
    await edgeTarget.click();
    await expect(dialog.getByRole('listbox', { name: 'edge-checkout exact target', exact: true }).getByRole('option', { name: /^checkout\.acme\.com/ })).toBeVisible();
    await expect(dialog.getByRole('listbox', { name: 'edge-checkout exact target', exact: true }).getByRole('option', { name: /https:\/\/checkout\.acme\.com\/health/ })).toHaveCount(0);
  });

  test('target-group schedule filters exact targets and clears an incompatible selection', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-group-detail', sourceBaseUrl, {
      entityIds: { 'target-group-detail': PORTAL_BASELINE_IDS.targetGroupId },
    });

    const search = page.getByPlaceholder('Search rule name, family, or check ID');
    await search.fill(URL_ONLY_CHECK);
    await page.getByRole('radio', { name: new RegExp(`Select ${escapeRegExp(URL_ONLY_CHECK)}`) }).click();
    const targetSelect = page.locator('form.schedule-builder select[name="target_id"]');
    await expect(targetSelect).toBeEnabled();
    await expect(targetSelect.locator('option')).toHaveCount(2);
    await expect(targetSelect.locator('option').nth(1)).toContainText('https://checkout.acme.com/health · Url');
    await targetSelect.selectOption(URL_TARGET_ID);

    await search.fill(HOST_CHECK);
    await page.getByRole('radio', { name: new RegExp(`Select ${escapeRegExp(HOST_CHECK)}`) }).click();
    await expect(targetSelect).toHaveValue('');
    await expect(targetSelect.locator(`option[value="${URL_TARGET_ID}"]`)).toHaveCount(0);
    await expect(targetSelect.locator(`option[value="${PORTAL_BASELINE_IDS.targetId}"]`)).toHaveCount(1);

    await gotoPortalRoute(page, 'target-group-detail', sourceBaseUrl, {
      entityIds: { 'target-group-detail': IP_GROUP_ID },
    });
    const ipSearch = page.getByPlaceholder('Search rule name, family, or check ID');
    await ipSearch.fill(URL_ONLY_CHECK);
    await page.getByRole('radio', { name: new RegExp(`Select ${escapeRegExp(URL_ONLY_CHECK)}`) }).click();
    await expect(page.locator('form.schedule-builder select[name="target_id"]')).toBeDisabled();
    await expect(page.getByText(/This group has no exact target compatible with URL-Only Schedule Probe/)).toBeVisible();
  });
});
