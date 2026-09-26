import { expect, test } from '@playwright/test';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

const VIEWPORTS = [
  { width: 375, height: 812 },
  { width: 768, height: 1024 },
  { width: 1024, height: 900 },
  { width: 1440, height: 900 },
];

async function expectNoPageOverflow(page) {
  const overflow = await page.evaluate(() => (
    document.documentElement.scrollWidth - document.documentElement.clientWidth
  ));
  expect(overflow, 'page-level horizontal overflow').toBeLessThanOrEqual(1);
}

test.describe('portal executive clarity', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('Dashboard answers readiness, protection, effectiveness, and top fixes in plain language', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());

    const brief = page.locator('.executive-brief');
    await expect(brief).toBeVisible();
    await expect(brief.getByText('Are we ready for a DDoS attack?', { exact: true })).toBeVisible();
    await expect(brief.getByRole('heading', { name: 'Not ready yet: high-priority gaps remain' })).toBeVisible();
    await expect(brief.getByRole('heading', { name: 'What is protecting us?' })).toBeVisible();
    await expect(brief.getByText('Web firewall', { exact: true })).toBeVisible();
    await expect(brief.getByText('Origin firewall / access rules', { exact: true })).toBeVisible();
    await expect(brief.getByText('WAF effectiveness', { exact: true })).toBeVisible();
    await expect(brief.getByRole('heading', { name: 'Top fixes' })).toBeVisible();
    await expect(brief.getByText('Block direct access to the origin server', { exact: true })).toBeVisible();
    await expect(brief.locator('.executive-fix-list > li')).toHaveCount(1);

    const glossary = brief.locator('.evidence-guide');
    const summary = glossary.locator('summary');
    await summary.focus();
    await page.keyboard.press('Enter');
    await expect(glossary).toHaveAttribute('open', '');
    await expect(glossary.getByText('Declared only', { exact: true })).toBeVisible();
    await expect(glossary.getByText('Attack traffic reached your server', { exact: true })).toBeVisible();
  });

  test('Dashboard and Target Detail do not overflow at 375, 768, 1024, or 1440 pixels', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    for (const viewport of VIEWPORTS) {
      await page.setViewportSize(viewport);
      await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
      await expect(page.locator('.executive-brief')).toBeVisible();
      await expectNoPageOverflow(page);

      await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());
      await expect(page.getByTestId('target-protection-summary')).toBeVisible();
      await expectNoPageOverflow(page);
    }
  });

  test('Target Detail leads with protection, prefers an API summary, and keeps E1 declaration-only', async ({ page }) => {
    const targetUrl = `**/v1/targets/${PORTAL_BASELINE_IDS.targetId}`;
    const apiSummary = 'Cloudflare and a web application firewall were detected. Blocking effectiveness still comes from the linked validation.';
    await page.route(targetUrl, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      payload.edge_detection = {
        status: 'detected',
        test_run_id: 'run_edge_summary',
        plain_language_summary: apiSummary,
        waf: { status: 'detected', provider: 'cloudflare' },
        cdn: { status: 'detected', provider: 'cloudflare' },
        cloud: { status: 'not_detected' },
        effectiveness: {
          status: 'partially_effective',
          blocked_count: 9,
          tested_count: 10,
          percentage: 90,
          evidence_tier: 'E3',
        },
        network_firewall: {
          direct_origin_reachability: { status: 'not_tested' },
          port_exposure: { status: 'not_tested', open_ports: [] },
        },
        evidence: {},
      };
      payload.checks_applied = (payload.checks_applied ?? []).map((check) => ({
        ...check,
        evidence_tier: 'E1',
        probe_kind: 'metadata_marker',
      }));
      await route.fulfill({ response, json: payload });
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());

    const protection = page.getByTestId('target-protection-summary');
    const verification = page.getByRole('heading', { name: 'Verification ladder' });
    await expect(protection).toBeVisible();
    await expect(protection.getByText(apiSummary, { exact: true })).toBeVisible();
    await expect(protection.getByText('Summary from API', { exact: true })).toBeVisible();
    for (const layer of ['Web application firewall', 'CDN / edge network', 'Cloud hosting', 'Origin access / firewall']) {
      await expect(protection.getByText(layer, { exact: true })).toBeVisible();
    }
    await expect(protection.getByText('9 of 10 safe probes blocked (90%)', { exact: true })).toBeVisible();
    await expect(protection).toContainText('Behavior observed (E3)');
    const positions = await Promise.all([
      protection.boundingBox(),
      verification.boundingBox(),
    ]);
    expect(positions[0]?.y ?? Number.POSITIVE_INFINITY).toBeLessThan(positions[1]?.y ?? 0);

    const declarationOnly = page.locator('.evidence-mode-cell').filter({ hasText: 'Not tested live' });
    await expect(declarationOnly).toHaveCount(1);
    await expect(declarationOnly).toContainText('Needs your evidence');
    await expect(declarationOnly).toContainText('E1');
    await expect(page.getByText('Observed from inside', { exact: true }).first()).toBeVisible();
  });
});
