import path from 'node:path';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  createPortalSourceServer,
  seedPortalPlaywrightStore,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { PORTAL_SESSION, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import { PORTAL_BASELINE_IDS as IDS } from '../../fixtures/portal-baseline/seed.mjs';

let vite;
let baseUrl;
const browserChecks = new WeakMap();
const FINDING_ID = 'fnd_missing_control_nfw';

function seedGapFinding() {
  seedPortalPlaywrightStore((store) => {
    store.findings.push({
      id: FINDING_ID, tenant_id: IDS.tenantId, target_group_id: IDS.targetGroupId, target_id: IDS.targetId,
      check_id: 'nfw.management_port_exposure.safe', title: `Finding: exposed on ${IDS.targetId}`, severity: 'high', status: 'open',
      system_summary: 'Declared deny for tcp/3389 (ipv4) from external probe was violated; denial cannot be proven from outside. Also violated: tcp/22 (ipv4).',
      evidence_ids: [], created_at: IDS.frozenAt, updated_at: IDS.frozenAt,
    });
    store.targetEdgeDetections = [{
      id: 'ted_missing_control', tenant_id: IDS.tenantId, target_id: IDS.targetId, status: 'detected',
      waf_status: 'not_detected', cdn_status: 'not_detected',
      evidence_json: { cloud: { status: 'detected', provider: 'gcp', type: 'asn' }, cloud_providers: ['gcp'] },
      observed_at: IDS.frozenAt, updated_at: IDS.frozenAt,
    }];
  });
}

async function openFinding(page) {
  await injectPortalDevHeadersSession(page, PORTAL_SESSION);
  await page.goto(`${baseUrl}/app#finding-detail?id=${FINDING_ID}`, { waitUntil: 'networkidle' });
  const card = page.getByRole('region', { name: 'What is missing in your environment' });
  await expect(card).toBeVisible();
  return card;
}

test.describe('finding names the missing control', () => {
  test.beforeAll(async () => {
    const { baseUrl: apiBaseUrl } = await startPortalPlaywrightServer();
    vite = await createPortalSourceServer({
      configFile: path.resolve('vite.config.ts'), logLevel: 'silent',
      server: { host: '127.0.0.1', port: 0, strictPort: false, proxy: { '/v1': apiBaseUrl, '/ready': apiBaseUrl, '/internal': apiBaseUrl } },
    });
    await vite.listen();
    baseUrl = `http://127.0.0.1:${vite.httpServer.address().port}`;
  });
  test.afterAll(async () => { await vite?.close(); await stopPortalPlaywrightServer(); });
  test.beforeEach(async ({ page }) => {
    seedGapFinding();
    browserChecks.set(page, await collectPortalBrowserFailures(page, baseUrl));
  });
  test.afterEach(async ({ page }, testInfo) => {
    const diagnostics = browserChecks.get(page);
    await testInfo.attach('missing-control-browser-diagnostics', { body: JSON.stringify(diagnostics?.failures ?? []), contentType: 'application/json' });
    diagnostics?.assertClean();
  });

  test('states what is missing, what was observed, the policy needed and detected-provider steps first', async ({ page }) => {
    const card = await openFinding(page);
    await expect(card).toContainText('Missing control: Network firewall ingress rules');
    await expect(card).toContainText('Control missing');
    await expect(card.locator('dt', { hasText: 'What is missing' }).locator('xpath=following-sibling::dd')).toContainText(/management and database ports/i);
    await expect(card).toContainText('Declared deny for tcp/3389');
    await expect(card).toContainText('Also violated: tcp/22');
    await expect(card.locator('dt', { hasText: 'Policy you need' })).toBeVisible();
    const tabs = card.getByRole('tab');
    await expect(tabs).toHaveCount(2);
    await expect(tabs.nth(0)).toHaveText(/Google Cloud · detected/);
    await expect(tabs.nth(0)).toHaveAttribute('aria-selected', 'true');
    const panel = card.getByRole('tabpanel');
    await expect(panel).toContainText('Detected as your cloud hosting provider');
    await expect(panel.locator('ol li').first()).toBeVisible();
    const docLinks = panel.getByRole('link');
    await expect(docLinks.first()).toBeVisible();
    expect(await docLinks.count()).toBeGreaterThan(0);
    for (const link of await docLinks.all()) {
      await expect(link).toHaveAttribute('target', '_blank');
      await expect(link).toHaveAttribute('rel', 'noopener noreferrer');
      expect(new URL(await link.getAttribute('href')).protocol).toBe('https:');
    }
    await tabs.nth(0).focus();
    await page.keyboard.press('ArrowRight');
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
    await expect(tabs.nth(1)).toBeFocused();
    await expect(card.getByRole('tabpanel')).toContainText('Vendor-neutral steps');
    const other = card.locator('details.missing-control-other');
    await expect(other.locator('summary')).toHaveText('Guidance for other providers');
    await other.locator('summary').focus();
    await page.keyboard.press('Enter');
    await expect(other).toHaveAttribute('open', '');
    for (const label of ['AWS', 'Microsoft Azure', 'Cloudflare', 'Akamai', 'Fastly']) {
      await expect(other.getByRole('heading', { name: label, exact: true })).toBeVisible();
    }
    await expect(other.getByRole('heading', { name: 'Google Cloud', exact: true })).toHaveCount(0);
  });

  test('findings list shows the missing control on the card', async ({ page }) => {
    await injectPortalDevHeadersSession(page, PORTAL_SESSION);
    await page.goto(`${baseUrl}/app#findings`, { waitUntil: 'networkidle' });
    const queue = page.getByRole('region', { name: 'Finding queue' });
    await expect(queue.locator('.rf-alert-missing').filter({ hasText: 'Network firewall ingress rules' }).first()).toBeVisible();
    await expect(queue.getByRole('link', { name: /missing Network firewall ingress rules/ }).first()).toBeVisible();
    await queue.getByRole('button', { name: 'Each finding' }).click();
    await expect(page.locator('.fc-missing, .rf-alert-missing').filter({ hasText: 'Network firewall ingress rules' }).first()).toBeVisible();
  });

  for (const theme of ['dark', 'light']) {
    for (const width of [375, 1440]) {
      test(`missing-control card is accessible and contained at ${width}px in ${theme}`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await page.addInitScript((value) => localStorage.setItem('astranull.theme', value), theme);
        const card = await openFinding(page);
        await card.locator('details.missing-control-other > summary').click();
        const scan = await new AxeBuilder({ page }).include('.missing-control-card').withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
        expect(scan.violations).toEqual([]);
        expect(await card.evaluate((element) => {
          const box = element.getBoundingClientRect();
          return box.left >= 0 && box.right <= innerWidth + 1 && element.scrollWidth <= element.clientWidth + 1;
        })).toBe(true);
        if (width === 375) {
          for (const control of [...await card.getByRole('tab').all(), ...await card.getByRole('link').all(), card.locator('summary')]) {
            const box = await control.boundingBox();
            expect(box.height).toBeGreaterThanOrEqual(44);
          }
        }
      });
    }
  }
});
