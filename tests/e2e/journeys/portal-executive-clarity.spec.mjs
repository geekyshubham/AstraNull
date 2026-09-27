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
    await expect(brief.getByText('Block direct access to checkout.acme.com', { exact: true })).toBeVisible();
    await expect(brief.locator('.executive-fix-list > li')).toHaveCount(1);

    const openFindings = page.locator('[data-ui="card"]').filter({ has: page.getByRole('heading', { name: 'Open findings', exact: true }) });
    await expect(openFindings).toContainText('Origin direct bypass · checkout.acme.com');
    await expect(openFindings).toContainText(PORTAL_BASELINE_IDS.findingId);
    const recentRuns = page.locator('[data-ui="card"]').filter({ has: page.getByRole('heading', { name: 'Recent runs', exact: true }) });
    await expect(recentRuns).toContainText('Origin Leak Scan (Safe) · checkout.acme.com');
    await expect(recentRuns).toContainText(PORTAL_BASELINE_IDS.readinessRunId);
    await expect(recentRuns).toContainText('Protection stopped the test traffic');

    const glossary = brief.locator('.evidence-guide');
    const summary = glossary.locator('summary');
    await summary.focus();
    await page.keyboard.press('Enter');
    await expect(glossary).toHaveAttribute('open', '');
    await expect(glossary.getByText('Declared only', { exact: true })).toBeVisible();
    await expect(glossary.getByText('Attack traffic reached your server', { exact: true })).toBeVisible();
  });

  test('Dashboard translates machine-coded WAF empty reasons', async ({ page }) => {
    await page.route('**/v1/waf/coverage/summary', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          protected: 0,
          edge_protected: 0,
          underprotected: 0,
          unknown: 0,
          by_vendor: {},
          meta: { empty_reason: 'coverage_summary_not_populated' },
        }),
      });
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());

    const wafSummary = page.locator('[data-ui="card"]').filter({ has: page.getByRole('heading', { name: 'WAF summary' }) });
    await expect(wafSummary.getByRole('heading', { name: 'No WAF assets in scope.' })).toBeVisible();
    await expect(wafSummary).toContainText('WAF coverage will appear after a declared WAF asset records evidence.');
    await expect(wafSummary).not.toContainText('coverage_summary_not_populated');
  });

  test('Dashboard and Target Detail do not overflow at 375, 768, 1024, or 1440 pixels', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    for (const viewport of VIEWPORTS) {
      await page.setViewportSize(viewport);
      await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
      await expect(page.locator('.executive-brief')).toBeVisible();
      await expectNoPageOverflow(page);
      if (viewport.width === 1440) {
        const groupCard = page.locator('[data-ui="card"]').filter({ has: page.getByRole('heading', { name: 'Target group status' }) });
        const tableWrap = groupCard.locator('.table-wrap');
        await tableWrap.evaluate((node) => { node.scrollLeft = node.scrollWidth; });
        const tableGeometry = await tableWrap.evaluate((node) => {
          const owner = node.querySelector('th:nth-child(3)');
          const container = node.getBoundingClientRect();
          const cell = owner?.getBoundingClientRect();
          return {
            overflowX: getComputedStyle(node).overflowX,
            ownerVisible: Boolean(cell && cell.left >= container.left - 1 && cell.right <= container.right + 1),
          };
        });
        expect(tableGeometry.overflowX).toBe('auto');
        expect(tableGeometry.ownerVisible, 'Owner column must fit or remain reachable by horizontal scroll').toBe(true);
      }

      await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());
      await expect(page.getByTestId('target-protection-summary')).toBeVisible();
      await expectNoPageOverflow(page);
    }
  });

  test('Target Detail leads with protection, prefers a recorded summary, and keeps E1 declaration-only', async ({ page }) => {
    const targetUrl = `**/v1/targets/${PORTAL_BASELINE_IDS.targetId}`;
    const recordedSummary = 'Cloudflare and a web application firewall were detected. Blocking effectiveness still comes from the linked validation.';
    await page.route(targetUrl, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      payload.edge_detection = {
        status: 'detected',
        test_run_id: 'run_edge_summary',
        plain_language_summary: recordedSummary,
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
    await expect(protection.getByText(recordedSummary, { exact: true })).toBeVisible();
    await expect(protection.getByText('Recorded summary', { exact: true })).toBeVisible();
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

    const declarationOnly = page.locator('.evidence-mode-cell').filter({ hasText: 'Declaration only' });
    await expect(declarationOnly).toHaveCount(2);
    await expect(declarationOnly.first()).toContainText('No live traffic was sent');
    await expect(declarationOnly.first()).toContainText('E1');
    await expect(page.getByText('Observed from inside', { exact: true }).first()).toBeVisible();
    await expect(page.locator('.metric-card').filter({ hasText: 'Kind' })).toContainText('Domain name');
    await expect(page.getByText('Detected detected', { exact: true })).toHaveCount(0);

    const visible = await page.locator('#portal-main').innerText();
    expect(visible).not.toMatch(/\b(?:not_detected|not_tested|must_block_before_origin|coverage_summary_not_populated)\b/);
    expect(visible).not.toMatch(/\b(?:API|hydrator|canonical)\b|producer attribution/i);

    const pillLines = await protection.locator('[data-ui="badge"]').evaluateAll((badges) => badges.map((badge) => {
      const range = document.createRange();
      range.selectNodeContents(badge);
      return { text: badge.textContent?.trim(), lines: range.getClientRects().length };
    }));
    expect(pillLines.filter((pill) => pill.lines > 1), 'verdict and status pills must remain single-line').toEqual([]);
  });

  test('Target Detail does not repeat identical empty-state title and body copy', async ({ page }) => {
    await page.route(`**/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      payload.checks_applied = [];
      payload.meta = {
        ...(payload.meta ?? {}),
        checks_empty_reason: 'No customer-runnable checks are bound to this target by a test policy yet.',
      };
      await route.fulfill({ response, json: payload });
    });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());

    const boundChecks = page.locator('[data-ui="card"]').filter({ has: page.getByRole('heading', { name: 'Bound checks' }) });
    await expect(boundChecks.getByRole('heading', { name: 'No customer-runnable checks are bound to this target by a test policy yet' })).toHaveCount(1);
    await expect(boundChecks.locator('.empty-state > p')).toHaveCount(0);
  });
});
