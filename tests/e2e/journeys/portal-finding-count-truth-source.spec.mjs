import path from 'node:path';
import { expect, test } from '@playwright/test';
import { createServer as createViteServer } from 'vite';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import {
  portalOwnerHeaders,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

let sourceBaseUrl = '';
let vite;
let expectedOpenFindings = 0;
let expectedOpenFindingId = '';
let expectedOpenFindingTitle = '';

test.describe('finding-count truth from current React source', () => {
  test.beforeAll(async () => {
    const { baseUrl: apiBaseUrl } = await startPortalPlaywrightServer({
      mutate: (store) => {
        applyPortalBaselineReadinessBoost(store);
        const openFinding = store.findings.find((finding) => String(finding.state ?? '').toLowerCase() === 'open');
        if (!openFinding) throw new Error('Portal baseline is missing its state-only open finding.');
        openFinding.severity = 'S2';
      }
    });
    const findingsResponse = await fetch(`${apiBaseUrl}/v1/findings`, { headers: portalOwnerHeaders() });
    expect(findingsResponse.ok).toBe(true);
    const findingsPayload = await findingsResponse.json();
    const findings = Array.isArray(findingsPayload?.items) ? findingsPayload.items : [];

    // Keep this regression bound to the API shape that exposed the original contradiction.
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((finding) => finding.status === undefined)).toBe(true);
    const openFindings = findings.filter(
      (finding) => String(finding.state ?? finding.status ?? '').trim().toLowerCase() === 'open',
    );
    expectedOpenFindings = openFindings.length;
    expect(expectedOpenFindings).toBe(1);
    expectedOpenFindingId = String(openFindings[0].id);
    expectedOpenFindingTitle = String(openFindings[0].title);
    expect(openFindings[0].severity).toBe('S2');

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

  test('Dashboard, Target Groups, and Findings agree on one open finding', async ({ page }) => {
    const consoleErrors = [];
    const pageErrors = [];
    const ownOriginServerErrors = [];
    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text());
    });
    page.on('pageerror', (error) => pageErrors.push(error.message));
    page.on('response', (response) => {
      if (response.url().startsWith(sourceBaseUrl) && response.status() >= 500) {
        ownOriginServerErrors.push(`${response.status()} ${response.url()}`);
      }
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', sourceBaseUrl);
    const dashboardOpen = page.locator('.kpi-cell').filter({ hasText: 'Open findings' });
    await expect(dashboardOpen.locator('.kpi-value')).toHaveText(String(expectedOpenFindings));

    await gotoPortalRoute(page, 'target-groups', sourceBaseUrl);
    const targetGroupsOpen = page.locator('.kpi-cell').filter({ hasText: 'Open findings' });
    await expect(targetGroupsOpen.locator('.kpi-value')).toHaveText(String(expectedOpenFindings));
    const checkoutRow = page.getByRole('row').filter({ hasText: 'edge-checkout' });
    await expect(checkoutRow.locator('td[data-label="Open"]')).toHaveText(String(expectedOpenFindings));

    await gotoPortalRoute(page, 'findings', sourceBaseUrl);
    await expect(page.locator('.page-context-summary')).toContainText(`${expectedOpenFindings} open`);
    const openFilter = page.getByRole('group', { name: 'Finding status filters' }).getByRole('button', { name: /^Open/ });
    await expect(openFilter.locator('.ft-count')).toHaveText(String(expectedOpenFindings));

    await gotoPortalRoute(page, 'finding-detail', sourceBaseUrl, {
      entityIds: { 'finding-detail': expectedOpenFindingId }
    });
    await expect(page.getByRole('heading', { name: expectedOpenFindingTitle })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Verdict explanation' })).toBeVisible();
    const severityBadges = page.locator('[title="Severity S2 from finding API"]');
    await expect(severityBadges).toHaveCount(2);
    await expect(severityBadges).toHaveText(['Severity 2 · High', 'Severity 2 · High']);
    await page.waitForLoadState('networkidle');

    expect(consoleErrors, 'console errors').toEqual([]);
    expect(pageErrors, 'uncaught page errors').toEqual([]);
    expect(ownOriginServerErrors, 'own-origin 5xx responses').toEqual([]);
  });
});
