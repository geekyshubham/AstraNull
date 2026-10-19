import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';

const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

const BOARD = {
  kind: 'findings',
  generated_at: '2026-10-19T12:00:00.000Z',
  scope: { truncated: false, unavailable: [] },
  verdict: { tone: 'caution', score: null, headline: '3 open findings (2 high, 1 medium); the oldest has been open 2 days.' },
  kpis: [
    { id: 'open', label: 'Open findings', value: 3, unit: 'count', tone: 'caution', detail: '2 high, 1 medium' },
    { id: 'oldest', label: 'Oldest open', value: 2, unit: 'days', tone: 'positive' },
  ],
  sections: [
    { id: 'Q1', title: 'Open findings by severity', hint: 'Severity mix of what is still open.', columns: [{ key: 'label', label: 'Severity', type: 'string' }, { key: 'count', label: 'Count', type: 'number' }], rows: [['High', 2], ['Medium', 1]], suggested_visual: 'bar' },
  ],
  actions: [
    { severity: 'high', title: 'Declared-denied TCP 22 answered from the internet', detail: 'On shop.example.test.', route: 'finding-detail?id=fnd_demo_1' },
    { severity: 'high', title: 'Injected link', route: 'javascript:alert(1)' },
  ],
  narrative: { summary: '3 open findings (2 high, 1 medium); the oldest has been open 2 days.', takeaways: ['Declared-denied TCP 22 answered from the internet.'], ai: false },
};

async function mockInsights(page, { narrative = 'queued', polls = 2 } = {}) {
  const state = { requests: [], polls: 0 };
  await page.route('**/v1/assistant/status', (route) => route.fulfill({
    json: { enabled: true, tenant_enabled: true, runner_online: true, model: 'gemini-3.8-flash-high', reason: null, capabilities: { data_tools: true, visuals: true, page_context: true, insights: true } },
  }));
  await page.route('**/v1/assistant/insights', async (route) => {
    state.requests.push(route.request().postDataJSON());
    const status = narrative === 'queued' ? { status: 'queued', job_id: 'asj_insight_1' } : { status: 'unavailable', reason: 'assistant_runner_offline' };
    return route.fulfill({ json: { board: BOARD, narrative: status } });
  });
  await page.route(/\/v1\/assistant\/jobs\/asj_insight_1$/, async (route) => {
    state.polls += 1;
    const base = { id: 'asj_insight_1', created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    if (state.polls < polls) return route.fulfill({ json: { ...base, status: 'running' } });
    return route.fulfill({ json: { ...base, status: 'done', response: { insight: { summary: 'Two high findings sit on one target; fix the open TCP 22 first.', takeaways: ['Port 22 answers although it is declared denied.', 'Re-run the check after the firewall change.'], ai: true } } } });
  });
  return state;
}

test.describe('AI insights', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('opens page insights from the topbar, then shows the AI-written summary', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    const state = await mockInsights(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'findings', getPortalPlaywrightBaseUrl());
    await page.locator('.topbar').getByRole('button', { name: 'AI insights' }).click();
    const dialog = page.getByRole('dialog', { name: /Findings/ });
    await expect(dialog).toBeVisible();
    expect(state.requests[0]).toEqual({ kind: 'findings', narrative: true });
    await expect(dialog.getByText('3 open findings (2 high, 1 medium); the oldest has been open 2 days.').first()).toBeVisible();
    await expect(dialog.getByRole('list', { name: 'Key numbers' }).getByRole('listitem')).toHaveCount(2);
    await expect(dialog.getByText('AI-written')).toBeVisible({ timeout: 15_000 });
    await expect(dialog.getByText('Two high findings sit on one target; fix the open TCP 22 first.')).toBeVisible();
    await expect(dialog.locator('.ai-ins-takeaways li')).toHaveCount(2);
    await expect(dialog.getByRole('heading', { name: 'Open findings by severity' })).toBeVisible();
    await expect(dialog.getByRole('button', { name: /^Open: / })).toHaveCount(1);
    const results = await new AxeBuilder({ page }).include('dialog.ai-ins').withTags(AXE_TAGS).analyze();
    expect(results.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? '')).map((violation) => violation.id)).toEqual([]);
    await dialog.getByRole('button', { name: /^Open: Declared-denied/ }).click();
    await expect(dialog).toBeHidden();
    await expect(page).toHaveURL(/#finding-detail\?id=fnd_demo_1$/);
  });

  test('keeps the computed summary when the runner is offline and closes with Escape', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await mockInsights(page, { narrative: 'unavailable' });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
    const trigger = page.locator('.topbar').getByRole('button', { name: 'AI insights' });
    await trigger.click();
    const dialog = page.getByRole('dialog', { name: /Dashboard/ });
    await expect(dialog.getByText('Computed', { exact: true })).toBeVisible();
    await expect(dialog.getByText('The AI runner is offline, so the computed summary is shown.')).toBeVisible();
    await expect(dialog.locator('.ai-ins-takeaways')).toHaveCount(0);
    const box = await dialog.boundingBox();
    expect(box?.width).toBeLessThanOrEqual(390);
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
  });

  test('is hidden when the assistant is not enabled for the tenant', async ({ page }) => {
    await page.route('**/v1/assistant/status', (route) => route.fulfill({ json: { enabled: true, tenant_enabled: false, runner_online: false, model: '', reason: 'tenant_not_enabled', capabilities: {} } }));
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'findings', getPortalPlaywrightBaseUrl());
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
    await expect(page.locator('.ai-ins-trigger')).toHaveCount(0);
  });
});
