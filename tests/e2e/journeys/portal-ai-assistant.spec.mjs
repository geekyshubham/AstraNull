import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';

const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
const SHOTS = process.env.ASSISTANT_SHOTS_DIR || 'test-results/assistant-shots';
const ANSWER = [
  '### What is missing',
  'Your origin answers traffic that skips the CDN.',
  '',
  '1. Allow inbound HTTPS only from **Cloudflare** ranges.',
  '2. Re-run the origin check in AstraNull.',
  '',
  'See [Cloudflare IP ranges](https://www.cloudflare.com/ips/) and [bad](javascript:alert(1)).',
].join('\n');

const DATA_ANSWER = {
  content: [
    '### Open findings',
    'High findings lead your open work.',
    '[[data:Q1|bar]]',
    'Share of open work by status:',
    '[[data:Q2|donut]]',
    '[[data:Q9|bar]]',
    'Fix the origin exposure first.',
  ].join('\n'),
  searches: [],
  sources: [],
  tool_calls: [
    { name: 'query_findings', summary: 'Open findings grouped by severity' },
    { name: 'query_targets', summary: 'Declared targets with ownership state' },
  ],
  data_results: [
    {
      id: 'Q1',
      title: 'Open findings by severity',
      columns: [{ key: 'severity', label: 'Severity', type: 'string' }, { key: 'count', label: 'Findings', type: 'number' }],
      rows: [['medium', 4], ['critical', 2], ['high', 7], ['low', 1]],
      suggested_visual: 'bar',
    },
    {
      id: 'Q2',
      title: 'Findings by status',
      columns: [{ key: 'status', label: 'Status', type: 'string' }, { key: 'count', label: 'Findings', type: 'number' }],
      rows: [['open', 14], ['in_progress', 3], ['accepted', 2], ['closed', 21]],
      suggested_visual: 'donut',
    },
    {
      id: 'Q3',
      title: 'Targets by ownership',
      columns: [{ key: 'state', label: 'Ownership', type: 'string' }, { key: 'count', label: 'Targets', type: 'number' }],
      rows: [['verified', 5], ['unverified', 2]],
      suggested_visual: 'table',
    },
  ],
  model: 'gemini-3.8-flash-high',
};

async function mockAssistant(page, { status = {}, finishAfter = 2, hold = false, response = null } = {}) {
  const state = { created: [], polls: 0, cancelled: [] };
  await page.route('**/v1/assistant/status', (route) => route.fulfill({
    json: { enabled: true, tenant_enabled: true, runner_online: true, model: 'gemini-3.8-flash-high', reason: null, capabilities: { data_tools: true, visuals: true, page_context: true }, ...status },
  }));
  await page.route('**/v1/assistant/jobs', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    state.created.push(route.request().postDataJSON());
    return route.fulfill({ status: 202, json: { job_id: `asj_${state.created.length}`, status: 'queued' } });
  });
  await page.route(/\/v1\/assistant\/jobs\/[^/]+$/, async (route) => {
    const id = route.request().url().split('/').pop();
    if (route.request().method() === 'DELETE') {
      state.cancelled.push(id);
      return route.fulfill({ json: { id, status: 'cancelled' } });
    }
    state.polls += 1;
    const base = { id, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    if (hold || state.cancelled.includes(id)) return route.fulfill({ json: { ...base, status: state.cancelled.includes(id) ? 'cancelled' : 'running' } });
    if (state.polls < finishAfter) return route.fulfill({ json: { ...base, status: state.polls === 1 ? 'queued' : 'running' } });
    return route.fulfill({
      json: {
        ...base,
        status: 'done',
        response: response ?? {
          content: ANSWER,
          searches: ['Cloudflare IP ranges allowlist origin', 'Cloudflare authenticated origin pulls'],
          sources: [{ url: 'https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/', title: 'Allow Cloudflare IP addresses' }],
          model: 'gemini-3.8-flash-high',
        },
      },
    });
  });
  return state;
}

async function openPanel(page) {
  await page.getByRole('button', { name: /^Open AstraNull AI/ }).click();
  const panel = page.getByRole('dialog', { name: 'AstraNull AI assistant' });
  await expect(panel).toBeVisible();
  return panel;
}

async function seriousViolations(page) {
  const results = await new AxeBuilder({ page }).include('#as-panel').withTags(AXE_TAGS).analyze();
  return results.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? '')).map((violation) => violation.id);
}

test.describe('AI assistant widget', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer();
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('asks a suggested question, shows progress, then the cited answer', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    const state = await mockAssistant(page, { finishAfter: 3 });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
    const panel = await openPanel(page);
    await expect(panel.getByRole('heading', { name: 'How can I help?' })).toBeVisible();
    await panel.getByRole('list', { name: 'Suggested questions' }).getByRole('button').first().click();
    await expect(panel.getByRole('status').filter({ hasText: 'Researching' })).toBeVisible();
    await expect(panel.getByRole('heading', { name: 'What is missing' })).toBeVisible({ timeout: 15_000 });
    expect(state.created[0].messages).toEqual([{ role: 'user', content: 'Summarise my readiness and the top risks' }]);
    expect(state.created[0].context.page).toMatchObject({ route: 'dashboard', kind: 'dashboard' });
    expect(Object.keys(state.created[0].context.page.facts)).toEqual(expect.arrayContaining(['Declared targets', 'Last validation']));
    await expect(panel.locator('.as-md ol li')).toHaveCount(2);
    await expect(panel.getByRole('link', { name: 'Cloudflare IP ranges' })).toHaveAttribute('href', 'https://www.cloudflare.com/ips/');
    await expect(panel.getByRole('link', { name: 'Cloudflare IP ranges' })).toHaveAttribute('rel', 'noopener noreferrer nofollow');
    await expect(panel.locator('a[href^="javascript"]')).toHaveCount(0);
    await panel.getByText('Searched the web (2)').click();
    await expect(panel.locator('.as-searches')).toContainText('Cloudflare authenticated origin pulls');
    await expect(panel.locator('.as-sources')).toContainText('developers.cloudflare.com');
    await expect(panel).toContainText('AI advice — verify with your provider, then re-run the check.');

    await page.getByRole('button', { name: 'Close assistant' }).click();
    await expect(page.getByRole('dialog', { name: 'AstraNull AI assistant' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /^Open AstraNull AI/ })).toBeFocused();
  });

  test('sends the open page as context and the chip can drop it', async ({ page }) => {
    const state = await mockAssistant(page);
    await injectPortalDevHeadersSession(page);
    const ask = async (panel, text) => {
      await panel.getByRole('textbox', { name: 'Ask the AstraNull assistant' }).fill(text);
      await page.keyboard.press('Enter');
      await expect(panel.getByRole('heading', { name: 'What is missing' }).last()).toBeVisible({ timeout: 15_000 });
    };

    await gotoPortalRoute(page, 'target-detail', getPortalPlaywrightBaseUrl());
    let panel = await openPanel(page);
    await expect(panel.locator('.as-context')).toContainText('Using this page:');
    await ask(panel, "What's missing here?");
    const target = state.created[0].context;
    await expect(panel.locator('.as-context')).toContainText(target.page.facts.Target);
    expect(target.page).toMatchObject({ route: 'target-detail', kind: 'target', entity: { type: 'target' } });
    expect(target.target_id).toBe(target.page.entity.id);
    expect(target.page.facts.Target).toBeTruthy();
    expect(JSON.stringify(target)).not.toMatch(/token|password|secret|bearer/i);
    await page.getByRole('button', { name: 'Close assistant' }).click();

    await gotoPortalRoute(page, 'findings', getPortalPlaywrightBaseUrl());
    panel = await openPanel(page);
    await panel.getByRole('button', { name: 'New chat' }).click();
    await expect(panel.locator('.as-context-label')).toHaveText('Using this page:');
    await expect(panel.locator('.as-context-value')).toHaveText('Findings');
    await expect(panel.getByRole('list', { name: 'Suggested questions' })).toContainText('Group my open findings by check');
    await ask(panel, 'What should I fix first?');
    const findings = state.created[1].context;
    expect(findings.page).toMatchObject({ route: 'findings', kind: 'findings' });
    expect(findings.page.filters).toMatchObject({ view: expect.any(String) });
    expect(findings).not.toHaveProperty('target_id');

    await panel.getByRole('button', { name: "Don't send this page's context" }).click();
    await expect(panel.locator('.as-context')).toHaveCount(0);
    await ask(panel, 'And without the page?');
    expect(state.created[2].context ?? {}).not.toHaveProperty('page');
  });

  test('renders data results as charts with a table view, CSV copy and tool activity', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await mockAssistant(page, { response: DATA_ANSWER });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
    const panel = await openPanel(page);
    await panel.getByRole('textbox', { name: 'Ask the AstraNull assistant' }).fill('Chart open findings by severity');
    await page.keyboard.press('Enter');
    await expect(panel.getByRole('heading', { name: 'Open findings', exact: true })).toBeVisible({ timeout: 15_000 });

    const bar = panel.locator('.as-vis').filter({ has: page.getByRole('heading', { name: 'Open findings by severity' }) });
    await expect(bar.getByRole('img', { name: /bar chart of 4 categories, largest first: high 7/ })).toBeVisible();
    await expect(bar.locator('.as-bar-label')).toHaveText(['high', 'medium', 'critical', 'low']);
    await bar.getByRole('button', { name: 'Table' }).click();
    await expect(bar.getByRole('button', { name: 'Table' })).toHaveAttribute('aria-pressed', 'true');
    const findingsHeader = bar.getByRole('columnheader', { name: /Findings/ });
    await expect(findingsHeader).toHaveAttribute('aria-sort', 'none');
    await findingsHeader.getByRole('button').click();
    await expect(findingsHeader).toHaveAttribute('aria-sort', 'descending');
    await expect(bar.getByRole('row').nth(1)).toContainText('high');
    await bar.getByRole('button', { name: 'Copy Open findings by severity as CSV' }).click();
    await expect(bar.getByRole('button', { name: 'Open findings by severity copied as CSV' })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('Severity,Findings\nmedium,4\ncritical,2\nhigh,7\nlow,1');

    const donut = panel.locator('.as-vis').filter({ has: page.getByRole('heading', { name: 'Findings by status' }) });
    await expect(donut.getByRole('img', { name: /open 35%/ })).toBeVisible();
    await expect(donut.locator('.as-donut-legend li')).toHaveCount(4);
    await expect(donut.locator('.as-donut-legend')).toContainText('21');
    await expect(donut.locator('.as-donut-legend')).toContainText('53%');

    await expect(panel).not.toContainText('[[data:');
    await expect(panel.locator('.as-vis:visible')).toHaveCount(2);
    await panel.getByText('Checked your data: Findings · Targets').click();
    await expect(panel.locator('.as-tools')).toContainText('Open findings grouped by severity');
    await panel.getByText('Data used (1)').click();
    await expect(panel.getByRole('heading', { name: 'Targets by ownership' })).toBeVisible();
    await expect(panel.locator('.as-searches').filter({ hasText: 'Searched the web' })).toHaveCount(0);
  });

  test('stop cancels the running answer and retry asks again', async ({ page }) => {
    const state = await mockAssistant(page, { hold: true });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
    const panel = await openPanel(page);
    await panel.getByRole('textbox', { name: 'Ask the AstraNull assistant' }).fill('How do I block port 6379?');
    await page.keyboard.press('Enter');
    await panel.getByRole('button', { name: 'Stop this answer' }).click();
    await expect(panel).toContainText('Stopped.');
    await expect.poll(() => state.cancelled.length).toBe(1);
    await panel.getByRole('button', { name: 'Retry' }).click();
    await expect.poll(() => state.created.length).toBe(2);
  });

  test('finding page "Ask AI how to fix" opens with the finding as context and sends', async ({ page }) => {
    const state = await mockAssistant(page);
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'finding-detail', getPortalPlaywrightBaseUrl());
    await page.getByRole('button', { name: 'Ask AI how to fix' }).first().click();
    const panel = page.getByRole('dialog', { name: 'AstraNull AI assistant' });
    await expect(panel.locator('.as-context')).toContainText('Asking about:');
    await expect.poll(() => state.created.length).toBe(1);
    expect(state.created[0].context.finding_id).toMatch(/^fnd_/);
    expect(state.created[0].context).not.toHaveProperty('label');
    expect(state.created[0].messages.at(-1).content).toBe('What is missing in my environment and how do I fix it for my provider?');
    await expect(panel.getByRole('heading', { name: 'What is missing' })).toBeVisible({ timeout: 15_000 });
  });

  test('runner offline shows the setup state and disables the composer', async ({ page }) => {
    await mockAssistant(page, { status: { runner_online: false, reason: 'runner_offline' } });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
    const panel = await openPanel(page);
    await expect(panel).toContainText("The AI runner isn't connected.");
    await expect(panel.getByRole('textbox', { name: 'Ask the AstraNull assistant' })).toBeDisabled();
  });

  test('stays hidden when the assistant is disabled or not enabled for the tenant', async ({ page }) => {
    await mockAssistant(page, { status: { enabled: true, tenant_enabled: false, reason: 'tenant_not_enabled' } });
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'finding-detail', getPortalPlaywrightBaseUrl());
    await expect(page.locator('#portal-main h1')).toBeVisible();
    await expect(page.getByRole('button', { name: /^Open AstraNull AI/ })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Ask AI how to fix' })).toHaveCount(0);
  });

  test('open panel passes axe in both themes and fits a 375px phone', async ({ page }) => {
    test.setTimeout(120_000);
    await mockAssistant(page, { response: DATA_ANSWER });
    await injectPortalDevHeadersSession(page);
    for (const theme of ['dark', 'light']) {
      await page.setViewportSize({ width: 1440, height: 1000 });
      await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
      await page.evaluate((value) => document.documentElement.setAttribute('data-theme', value), theme);
      const panel = await openPanel(page);
      await panel.getByRole('button', { name: 'New chat' }).click();
      await panel.getByRole('list', { name: 'Suggested questions' }).getByRole('button').first().click();
      await expect(panel.getByRole('heading', { name: 'Open findings', exact: true })).toBeVisible({ timeout: 15_000 });
      await panel.getByText('Data used (1)').click();
      expect(await seriousViolations(page), `axe ${theme}`).toEqual([]);
      await panel.locator('.as-vis').nth(0).screenshot({ path: `${SHOTS}/assistant-bar-${theme}.png` });
      await panel.locator('.as-vis').nth(1).screenshot({ path: `${SHOTS}/assistant-donut-${theme}.png` });
      await panel.locator('.as-vis').first().getByRole('button', { name: 'Table' }).click();
      expect(await seriousViolations(page), `axe ${theme} table`).toEqual([]);
      await page.screenshot({ path: `${SHOTS}/assistant-visuals-${theme}.png`, animations: 'disabled' });
      await page.getByRole('button', { name: 'Close assistant' }).click();
    }
    await page.setViewportSize({ width: 375, height: 812 });
    await gotoPortalRoute(page, 'dashboard', getPortalPlaywrightBaseUrl());
    const phone = await openPanel(page);
    await expect(phone.getByRole('heading', { name: 'Open findings', exact: true })).toBeVisible({ timeout: 15_000 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
    const box = await page.locator('#as-panel').boundingBox();
    expect(box.width).toBeLessThanOrEqual(375);
    expect(await page.locator('#as-panel').evaluate((node) => [...node.querySelectorAll('.as-vis')].every((vis) => vis.scrollWidth <= vis.clientWidth + 1))).toBe(true);
    await page.screenshot({ path: `${SHOTS}/assistant-visuals-375.png`, animations: 'disabled' });
  });
});
