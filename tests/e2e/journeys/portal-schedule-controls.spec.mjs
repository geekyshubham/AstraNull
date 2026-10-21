import path from 'node:path';
import { mkdir } from 'node:fs/promises';
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { createPortalSourceServer as createViteServer } from '../../helpers/portal-playwright-server.mjs';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
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
const HOST_CHECK = 'Internet access to common service ports';
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
const OBSERVATION_CHECK_FIXTURE = {
  ...URL_ONLY_CHECK_FIXTURE,
  check_id: 'ui.observation_schedule.safe',
  name: 'Schedule Observation (Safe)',
  supported_targets: ['fqdn', 'url'],
  observation_only: true,
};
let sourceBaseUrl = '';
let vite;
let diagnostics;

function applyScheduleControlFixture(store) {
  applyPortalBaselineReadinessBoost(store);
  const group = store.targetGroups.find((item) => item.id === PORTAL_BASELINE_IDS.targetGroupId);
  if (group) group.validation_mode = 'external_only';
  const tagged = store.targets.find((target) => target.id === PORTAL_BASELINE_IDS.targetId);
  if (tagged) {
    tagged.tags = ['env:production', 'environment:production', 'team:payments'];
    tagged.metadata = { ...tagged.metadata, tags: tagged.tags };
  }
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
  if (label === 'Check') {
    const clear = scope.locator('.rf-check-selection').getByRole('button', { name: 'Clear', exact: true });
    if (await clear.isEnabled()) await clear.click();
    await scope.getByRole('searchbox', { name: 'Find a check' }).fill(option);
    await scope.getByRole('group', { name: 'Checks to schedule' }).getByRole('checkbox', { name: new RegExp(escapeRegExp(option)) }).check();
    return;
  }

  const trigger = scope.getByRole('button', { name: label, exact: true });
  await expect(trigger).toBeEnabled({ timeout: 10_000 });
  await trigger.click();
  const listbox = scope.getByRole('listbox', { name: label, exact: true });
  await expect(listbox).toBeVisible();
  await listbox.getByRole('option', { name: new RegExp(escapeRegExp(option)) }).click();
  return trigger;
}

async function chooseScheduleCheck(scope, checkId) {
  const clear = scope.locator('.rf-check-selection').getByRole('button', { name: 'Clear', exact: true });
  if (await clear.isEnabled()) await clear.click();
  await scope.getByRole('searchbox', { name: 'Find a check' }).fill(checkId);
  await scope.getByRole('group', { name: 'Checks to schedule' }).getByRole('checkbox').check();
}

test.describe('schedule form controls', () => {
  test.use({ timezoneId: 'Asia/Kolkata' });

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
    diagnostics = await collectPortalBrowserFailures(page, sourceBaseUrl, {
      allowResponse: (response) => new URL(response.url()).pathname === '/v1/test-policies'
        && response.request().method() === 'POST' && response.status() === 400,
    });
    await page.route('**/v1/checks', async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({
        response,
        body: JSON.stringify({
          ...payload,
          items: [...(Array.isArray(payload.items) ? payload.items : []), URL_ONLY_CHECK_FIXTURE, OBSERVATION_CHECK_FIXTURE],
        }),
      });
    });
  });

  test.afterEach(() => diagnostics.assertClean());

  test('pending sequential submission locks all timing controls and preserves its review', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    const posts = [];
    let releaseFirst;
    const firstResponse = new Promise((resolve) => { releaseFirst = resolve; });
    await page.route('**/v1/test-policies', async (route) => {
      if (route.request().method() !== 'POST') return route.fallback();
      posts.push(route.request().postDataJSON());
      if (posts.length === 1) await firstResponse;
      await route.fulfill({ status: 201, json: { id: `pending_schedule_${posts.length}` } });
    });
    try {
      await gotoPortalRoute(page, 'test-policies', sourceBaseUrl);
      await page.locator('.rf-header-actions').getByRole('button', { name: 'Create schedule' }).click();
      const panel = page.locator('section.rf-create');
      await chooseCustomSelect(panel, 'Check', URL_ONLY_CHECK_FIXTURE.check_id);
      await panel.getByRole('searchbox', { name: 'Find a check' }).fill(OBSERVATION_CHECK_FIXTURE.check_id);
      await panel.getByRole('group', { name: 'Checks to schedule' }).getByRole('checkbox').check();
      await panel.locator('.domain-picker-option').filter({ hasText: 'https://checkout.acme.com/health' }).getByRole('checkbox').check();
      await panel.getByLabel('Schedule timezone (IANA)').fill('UTC');
      const viewerZone = await page.evaluate(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
      expect(viewerZone).not.toBe('UTC');
      const shortcut = panel.getByRole('button', { name: `Use ${viewerZone}`, exact: true });
      await expect(shortcut).toBeEnabled();
      const review = await panel.locator('.rf-review').innerText();
      const firstRequest = page.waitForRequest((request) => new URL(request.url()).pathname === '/v1/test-policies' && request.method() === 'POST');
      await panel.getByRole('button', { name: 'Create schedule', exact: true }).click();
      await firstRequest;
      await expect(shortcut).toBeDisabled();
      for (const control of await panel.locator('input:not([type="hidden"]), button').all()) await expect(control).toBeDisabled();
      expect(await panel.locator('.rf-review').innerText()).toBe(review);
      expect(posts).toHaveLength(1);
      releaseFirst();
      await expect(panel).toBeHidden();
      expect(posts).toHaveLength(2);
      expect(posts.every((body) => body.timezone === 'UTC' && body.safe_windows.length === 0)).toBe(true);
    } finally {
      releaseFirst();
    }
  });

  test('special-use targets never request external favicons in either inventory', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    const requests = [];
    await page.route('https://icons.duckduckgo.com/**', (route) => {
      requests.push(route.request().url());
      return route.fulfill({ status: 200, contentType: 'image/svg+xml', body: '<svg xmlns="http://www.w3.org/2000/svg"/>' });
    });
    const values = ['router.home.arpa', 'service.onion', 'service.alt', 'printer.local', 'example.com', 'www.example.net', 'docs.example.org', '203.0.113.42'];
    await page.route((url) => url.pathname === '/v1/targets', async (route) => {
      if (route.request().method() !== 'GET') return route.fallback();
      const response = await route.fetch();
      const payload = await response.json();
      const target = payload.items.find((item) => item.id === PORTAL_BASELINE_IDS.targetId);
      expect(target).toBeTruthy();
      await route.fulfill({ response, json: { ...payload, items: values.map((value, index) => ({ ...target, id: `tgt_private_icon_${index}`, value, kind: index === values.length - 1 ? 'ip' : 'fqdn' })) } });
    });
    for (const variant of ['classic', 'refined']) {
      await gotoPortalRoute(page, `targets?variant=${variant}`, sourceBaseUrl);
      const icons = page.locator(variant === 'classic' ? '.target-primary-icon' : '.rf-target-icon');
      await expect(icons).toHaveCount(values.length);
      await expect(icons.locator('svg')).toHaveCount(values.length);
      await expect(icons.locator('img')).toHaveCount(0);
    }
    expect(requests).toEqual([]);
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
    await chooseCustomSelect(panel, 'Check', URL_ONLY_CHECK_FIXTURE.check_id);
    await panel.locator('.domain-picker-option').filter({ hasText: 'https://checkout.acme.com/health' }).getByRole('checkbox').check();
    await expect(panel.getByRole('button', { name: 'Create schedule', exact: true })).toBeEnabled();
    await chooseScheduleCheck(panel, 'l3.firewall_exposure_scan.safe');
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

  test('all checks can be selected; compatible pairs use per-check verdicts and retry only exact failures', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    const posts = [];
    let failFirstBatch = true;
    await page.route('**/v1/test-policies', async (route) => {
      if (route.request().method() !== 'POST') return route.fallback();
      const body = route.request().postDataJSON();
      posts.push(body);
      const fail = failFirstBatch && (body.check_id === URL_ONLY_CHECK_FIXTURE.check_id || body.target_id === PORTAL_BASELINE_IDS.targetId);
      await route.fulfill({ status: fail ? 400 : 201, json: fail ? { error: 'invalid_request', message: 'Fixture retry needed.' } : { id: `schedule_${posts.length}` } });
    });
    await gotoPortalRoute(page, 'test-policies', sourceBaseUrl);
    await page.locator('.rf-header-actions').getByRole('button', { name: 'Create schedule' }).click();
    const panel = page.locator('section.rf-create');
    const choices = panel.getByRole('group', { name: 'Checks to schedule' });
    const count = await choices.getByRole('checkbox').count();
    expect(count).toBeGreaterThan(2);
    await panel.getByRole('button', { name: 'Select all checks' }).click();
    await expect(choices.getByRole('checkbox', { checked: true })).toHaveCount(count);
    await panel.getByRole('searchbox', { name: 'Find a check' }).fill(URL_ONLY_CHECK_FIXTURE.check_id);
    await expect(choices.getByRole('checkbox', { checked: true })).toHaveCount(1);
    await panel.locator('.rf-check-selection').getByRole('button', { name: 'Clear', exact: true }).click();
    await choices.getByRole('checkbox').check();
    await panel.getByRole('searchbox', { name: 'Find a check' }).fill(OBSERVATION_CHECK_FIXTURE.check_id);
    await choices.getByRole('checkbox').check();
    await panel.locator('.domain-picker-option').filter({ hasText: 'https://checkout.acme.com/health' }).getByRole('checkbox').check();
    await panel.locator('.domain-picker-option').filter({ hasText: /^checkout.acme.com/ }).getByRole('checkbox').check();
    await expect(panel.locator('.rf-readiness')).toContainText('Ready to create 3 schedules');
    await expect(panel.locator('.rf-review')).toContainText('1 incompatible check/domain pair is excluded');
    await panel.getByRole('button', { name: 'Create schedule', exact: true }).click();
    await expect(panel.getByRole('alert')).toContainText('Created 1 of 3 schedules');
    expect(posts.filter((body) => body.check_id === OBSERVATION_CHECK_FIXTURE.check_id).every((body) => body.expected_verdict === 'manual_review')).toBe(true);
    expect(posts.find((body) => body.check_id === URL_ONLY_CHECK_FIXTURE.check_id).expected_verdict).toBe('pass');
    await expect(panel.getByRole('list', { name: 'Schedules to create' }).getByRole('listitem')).toHaveCount(2);
    failFirstBatch = false;
    await panel.getByRole('button', { name: 'Create schedule', exact: true }).click();
    await expect(panel).toBeHidden();
    expect(posts).toHaveLength(5);
    const key = (body) => `${body.check_id}:${body.target_id}`;
    expect(posts.slice(3).map(key).sort()).toEqual(posts.slice(0, 3).filter((body) => body.check_id === URL_ONLY_CHECK_FIXTURE.check_id || body.target_id === PORTAL_BASELINE_IDS.targetId).map(key).sort());
  });

  for (const width of [375, 768, 1024, 1440]) for (const theme of ['dark', 'light']) {
    test(`schedule form fits ${width}px in ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript((mode) => localStorage.setItem('astranull.theme', mode), theme);
      await injectPortalDevHeadersSession(page);
      await gotoPortalRoute(page, 'test-policies', sourceBaseUrl);
      await page.locator('.rf-header-actions').getByRole('button', { name: 'Create schedule' }).click();
      const panel = page.locator('section.rf-create');
      await panel.getByRole('button', { name: 'Select all checks' }).click();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      const overflowingRows = await panel.locator('.rf-check-option').evaluateAll((rows) => rows.filter((row) => {
        const copy = row.querySelector('span');
        return copy && copy.getBoundingClientRect().bottom > row.getBoundingClientRect().bottom + 1;
      }).map((row) => row.textContent));
      expect(overflowingRows, 'Every check name and ID must fit inside its own row').toEqual([]);

      const box = await panel.boundingBox();
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(width);
      const audit = await new AxeBuilder({ page }).include('.rf-create').withTags(['wcag2a', 'wcag2aa']).analyze();
      expect(audit.violations).toEqual([]);
      const undersizedControls = await panel.locator('.rf-check-selection-toolbar button, .rf-link-button').evaluateAll((controls) => controls.filter((control) => control.getBoundingClientRect().height < 44).map((control) => control.textContent));
      expect(undersizedControls, 'Selection and timezone shortcuts keep 44px touch targets').toEqual([]);
      await mkdir('output/vibe-annotations', { recursive: true });
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: `output/vibe-annotations/schedule-${width}-${theme}.png`, fullPage: true });
    });
  }

  test('coverage disclosure switches to Hide checks and catalog reason copy is removed', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'checks', sourceBaseUrl);
    const more = page.locator('.rc-more').first();
    await expect(more.locator('summary')).toContainText('more checks');
    await more.locator('summary').click();
    await expect(more.locator('.rc-more-hide')).toBeVisible();
    await expect(more.locator('.rc-more-show')).toBeHidden();
    await more.locator('summary').press('Enter');
    await expect(more.locator('.rc-more-show')).toBeVisible();
    await expect(page.locator('.rc-assurance-reason')).toHaveCount(0);
  });

  test('declaration records are absent from executable catalog groups and schedule choices', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'checks', sourceBaseUrl);
    await page.getByRole('searchbox', { name: 'Search the vector catalog' }).fill('l3.icmp_flood.readiness');
    await expect(page.locator('.vector-check-group:not(.vector-check-group--misc)')).toHaveCount(0);
    await expect(page.locator('.vector-check-head [data-declaration-only]')).toHaveCount(0);
    await page.getByRole('button', { name: 'More filters', exact: true }).click();
    await page.getByRole('button', { name: 'Evidence level', exact: true }).click();
    await expect(page.getByRole('option', { name: 'Declaration only (E1)', exact: true })).toHaveCount(0);
    await page.keyboard.press('Escape');
    await gotoPortalRoute(page, 'test-policies', sourceBaseUrl);
    await page.locator('.rf-header-actions').getByRole('button', { name: 'Create schedule' }).click();
    const panel = page.locator('section.rf-create');
    await panel.getByRole('searchbox', { name: 'Find a check' }).fill('l3.icmp_flood.readiness');
    await expect(panel.getByRole('group', { name: 'Checks to schedule' }).getByRole('checkbox')).toHaveCount(0);
    await expect(panel).toContainText('No checks match');
  });

  test('target favicons load with no referrer and fall back on errors and IPs in both variants', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    const requests = [];
    await page.route('https://icons.duckduckgo.com/**', async (route) => {
      requests.push(route.request());
      if (route.request().url().includes('checkout.acme.com')) return route.fulfill({ contentType: 'image/png', body: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII=', 'base64') });
      return route.fulfill({ status: 200, contentType: 'image/png', body: Buffer.from('Owned invalid image fixture') });
    });
    for (const variant of ['classic', 'refined']) {
      await page.goto(`${sourceBaseUrl}/app#targets?variant=${variant}`);
      const icon = page.locator(variant === 'classic' ? '.target-primary-icon' : '.rf-target-icon');
      const loaded = icon.locator('img').first();
      await expect(loaded).toBeVisible();
      await expect.poll(() => loaded.evaluate((img) => img.naturalWidth)).toBeGreaterThan(0);
      await expect(icon.locator('svg').first()).toBeVisible();
      await expect(page.locator('[title*="env:production"], [title*="environment:production"]')).toHaveCount(0);
      await expect(page.locator('.target-tag-chip, .rf-tag').filter({ hasText: 'team:payments' })).toHaveCount(1);
      await expect(page.locator('.target-tag-chip, .rf-tag').filter({ hasText: /^(env|environment):/ })).toHaveCount(0);
    }
    expect(requests.length).toBeGreaterThan(0);
    expect(requests.every((request) => !request.headers().referer)).toBe(true);
    expect(requests.every((request) => !request.url().includes('203.0.113.42'))).toBe(true);
  });
});
