import { expect as baseExpect, test } from '@playwright/test';
import { currentInsightScope } from '../../../apps/web/react/src/lib/assistant-insights.mjs';
import { findingGroupHref, groupFindings } from '../../../apps/web/react/src/lib/finding-groups.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { createActionMatrix, matrixIdentities, runIdentityMatrix, startMatrixPage } from '../../helpers/portal-action-matrix.mjs';
import { fetchPortalFindings, getPortalPlaywrightBaseUrl, portalOwnerHeaders, startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../../helpers/portal-playwright-server.mjs';
import { resolvePortalRouteUrl, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';

const expect = baseExpect.configure({ timeout: 20_000 });

const ids = PORTAL_BASELINE_IDS;
const matrix = createActionMatrix({ files: ['components/assistant/insights-dialog.tsx', 'components/assistant/insights-button.tsx', 'components/assistant/assistant-visual.tsx'] });
const ACTION_TITLE = 'Review open findings';
const ACTION_ROUTE = 'findings';
const BAR_TITLE = 'Findings by severity';
const TABLE_TITLE = 'Targets by open findings';
const TABLE_ROWS = 30;
const OUTAGE = 'Insights could not be loaded. Try again in a moment.';
const ANSWER = { content: 'Fix the open TCP 22 exposure first, then re-run the check.', searches: [], sources: [], model: 'synthetic-model' };
let groupHref = '';

const headline = (kind) => `Synthetic ${kind} insights for the matrix.`;
function board(kind) {
  return {
    kind,
    generated_at: '2026-10-24T12:00:00.000Z',
    scope: { truncated: false, unavailable: [] },
    verdict: { tone: 'caution', score: 62, headline: headline(kind) },
    kpis: [{ id: 'open', label: 'Open findings', value: 3, unit: 'count', tone: 'caution' }],
    sections: [
      { id: 'Q1', title: BAR_TITLE, columns: [{ key: 'label', label: 'Severity', type: 'string' }, { key: 'count', label: 'Count', type: 'number' }], rows: [['High', 2], ['Medium', 1], ['Low', 4]], suggested_visual: 'bar' },
      { id: 'Q2', title: TABLE_TITLE, columns: [{ key: 'target', label: 'Target', type: 'string' }, { key: 'open', label: 'Open', type: 'number' }], rows: Array.from({ length: TABLE_ROWS }, (_, index) => [`target-${String(index + 1).padStart(2, '0')}.example.test`, (index * 7) % 11]), suggested_visual: 'table' },
    ],
    actions: [{ severity: 'high', title: ACTION_TITLE, detail: 'Three findings are still open.', route: ACTION_ROUTE }],
    narrative: { summary: headline(kind), takeaways: [], ai: false },
  };
}

function seed(store) {
  applyPortalBaselineReadinessBoost(store);
  const base = store.findings.find((item) => item.id === ids.findingId);
  store.findings.push({ ...base, id: 'fnd_member_pay', target_id: 'tgt_checkout_2' });
}

async function assistantMocks(page, injected) {
  const state = { insights: [], jobs: [], failing: false };
  await page.route('**/v1/assistant/status', (route) => route.fulfill({ json: { enabled: true, tenant_enabled: true, runner_online: true, model: 'synthetic-model', reason: null, capabilities: { data_tools: true, visuals: true, page_context: true, insights: true } } }));
  await page.route('**/v1/assistant/insights', (route) => {
    const body = route.request().postDataJSON();
    state.insights.push(body);
    if (state.failing) {
      injected.add(route.request().url());
      return route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'synthetic_insights_outage' }) });
    }
    return route.fulfill({ json: { board: board(body.kind), narrative: { status: 'unavailable', reason: 'assistant_runner_offline' } } });
  });
  await page.route('**/v1/assistant/jobs', (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    state.jobs.push(route.request().postDataJSON());
    return route.fulfill({ status: 202, json: { job_id: `asj_${state.jobs.length}`, status: 'queued' } });
  });
  await page.route(/\/v1\/assistant\/jobs\/asj_\d+$/, (route) => route.fulfill({ json: { id: route.request().url().split('/').pop(), status: 'done', created_at: new Date().toISOString(), updated_at: new Date().toISOString(), response: ANSWER } }));
  return state;
}

const trigger = (page) => page.locator('.topbar').getByRole('button', { name: 'AI insights', exact: true });
const dialogOf = (page) => page.locator('.topbar dialog.ai-ins');
const isOpen = async (dialog) => (await dialog.count()) > 0 && dialog.evaluate((node) => node.open);

async function expectedKind(page) {
  const hash = await page.evaluate(() => window.location.hash);
  return currentInsightScope(hash)?.kind ?? 'finding_group';
}

async function openInsights({ page }) {
  const dialog = dialogOf(page);
  if (await isOpen(dialog)) return dialog;
  await trigger(page).click();
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('.ai-ins-headline')).toHaveText(headline(await expectedKind(page)));
  return dialog;
}

async function closeInsights(page) {
  const dialog = dialogOf(page);
  if (await isOpen(dialog)) await dialog.getByRole('button', { name: 'Close AI insights', exact: true }).click();
  await expect(dialog).toBeHidden();
}

async function expectClosed(page) {
  await expect(dialogOf(page)).toBeHidden();
  await expect(trigger(page)).toHaveAttribute('aria-expanded', 'false');
}

async function denied({ page, requests, route, identity }) {
  const mark = requests.mark();
  await expect(page.locator('#portal-main')).toBeVisible();
  await expect(page.locator('.ai-ins-trigger')).toHaveCount(0);
  await expect(page.locator('dialog.ai-ins')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /AstraNull AI/ })).toHaveCount(0);
  expect(requests.since(mark).filter((entry) => entry.path.startsWith('/v1/assistant/')), 'No assistant request for a denied identity').toEqual([]);
  return [`${identity.label} on ${route} renders no AI insights trigger, no insights dialog and no assistant launcher`, 'No assistant request is issued'];
}

async function stubClipboard(page, failing) {
  await page.evaluate((fail) => {
    window.__clipboardWrites = window.__clipboardWrites ?? [];
    window.__clipboardFail = fail;
    navigator.clipboard.writeText = async (value) => {
      window.__clipboardWrites.push(value);
      if (window.__clipboardFail) throw new DOMException('Synthetic clipboard denial', 'NotAllowedError');
    };
  }, failing);
}

const section = (dialog, title) => dialog.locator('section.as-vis').filter({ has: dialog.page().getByRole('heading', { name: title, exact: true }) });

async function openFromRow(ctx, label) {
  const dialog = await openInsights(ctx);
  await dialog.getByRole('button', { name: `Open: ${ACTION_TITLE}`, exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect.poll(() => ctx.page.evaluate(() => window.location.hash)).toBe(`#${ACTION_ROUTE}`);
  await waitForPortalRouteSettled(ctx.page);
  await expect(ctx.page.locator('#portal-main')).toHaveAttribute('aria-label', 'Findings workspace');
  return [`${label} closes the dialog and routes to #${ACTION_ROUTE}`, 'The Findings workspace renders'];
}

async function reloadFromRow(ctx) {
  await openFromRow(ctx, 'Open');
  await ctx.page.reload({ waitUntil: 'networkidle' });
  await waitForPortalRouteSettled(ctx.page);
  await expect.poll(() => ctx.page.evaluate(() => window.location.hash)).toBe(`#${ACTION_ROUTE}`);
  await expect(ctx.page.locator('#portal-main')).toHaveAttribute('aria-label', 'Findings workspace', { timeout: 60_000 });
  await expect(dialogOf(ctx.page)).toHaveCount(0);
  return [`After a reload the #${ACTION_ROUTE} destination still renders the Findings workspace`, 'The dialog is not reopened by the reload'];
}

const returnToRoute = async ({ arrive, route }) => arrive(route);

const drivers = [
  {
    query: { owner: 'AiInsightsButton', label: /^`AI insights for this/, kind: 'activate' },
    states: {
      success: async (ctx) => {
        const { page, requests, route } = ctx;
        await expect(trigger(page)).toHaveAttribute('aria-expanded', 'false');
        const mark = requests.mark();
        await trigger(page).click();
        const dialog = dialogOf(page);
        await expect(dialog).toBeVisible();
        const kind = await expectedKind(page);
        await expect(dialog.locator('.ai-ins-headline')).toHaveText(headline(kind));
        await expect(trigger(page)).toHaveAttribute('aria-expanded', 'true');
        const writes = requests.writesSince(mark);
        expect(writes.every((entry) => entry.path === '/v1/assistant/insights'), 'Opening insights only posts the insights read').toBe(true);
        return [`The topbar AI insights button on ${route} opens the dialog for the ${kind} scope`, 'The trigger reports aria-expanded=true and the board headline for that scope renders', 'The only POST is the read-only /v1/assistant/insights board request'];
      },
      denial: denied,
    },
    settle: async ({ page }) => closeInsights(page),
  },
  {
    query: { owner: 'AiInsightsButton', label: 'InsightsDialog', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openInsights(ctx);
        await expect(trigger(ctx.page)).toHaveAttribute('aria-expanded', 'true');
        await dialog.getByRole('button', { name: 'Close AI insights', exact: true }).click();
        await expectClosed(ctx.page);
        return ['The dialog onClose resets the trigger to aria-expanded=false and closes the modal'];
      },
      denial: denied,
    },
  },
  {
    query: { owner: 'InsightsDialog', label: 'Close AI insights', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openInsights(ctx);
        await dialog.getByRole('button', { name: 'Close AI insights', exact: true }).click();
        await expectClosed(ctx.page);
        await expect(trigger(ctx.page)).toBeFocused();
        return ['Close AI insights closes the modal dialog', 'Focus returns to the topbar trigger'];
      },
      cancel: async (ctx) => {
        const dialog = await openInsights(ctx);
        const mark = ctx.requests.mark();
        await dialog.getByRole('button', { name: 'Close AI insights', exact: true }).click();
        await expectClosed(ctx.page);
        expect(ctx.requests.writesSince(mark)).toEqual([]);
        return ['Dismissing with Close AI insights issues zero writes', 'The dialog is closed and the trigger is collapsed'];
      },
      denial: denied,
    },
  },
  {
    query: { owner: 'InsightsDialog', label: 'dialog', kind: 'activate' },
    states: {
      success: async (ctx) => {
        await openInsights(ctx);
        await ctx.page.mouse.click(4, 4);
        await expectClosed(ctx.page);
        return ['A click on the dialog backdrop closes AI insights'];
      },
      cancel: async (ctx) => {
        await openInsights(ctx);
        const mark = ctx.requests.mark();
        await ctx.page.keyboard.press('Escape');
        await expectClosed(ctx.page);
        expect(ctx.requests.writesSince(mark)).toEqual([]);
        return ['Escape cancels the modal through onCancel and closes it', 'No write is issued by the dismissal'];
      },
      denial: denied,
    },
  },
  {
    query: { owner: 'InsightsDialog', label: 'Refresh', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openInsights(ctx);
        const before = ctx.assistant.insights.length;
        const kind = await expectedKind(ctx.page);
        await dialog.getByRole('button', { name: 'Refresh', exact: true }).click();
        await expect.poll(() => ctx.assistant.insights.length).toBe(before + 1);
        expect(ctx.assistant.insights.at(-1)).toMatchObject({ kind, refresh: true });
        await expect(dialog.getByRole('button', { name: 'Refresh', exact: true })).toBeEnabled();
        await expect(dialog.locator('.ai-ins-headline')).toHaveText(headline(kind));
        return [`Refresh re-posts the ${kind} board with refresh=true`, 'The refreshed board renders and Refresh is enabled again'];
      },
      denial: denied,
    },
    settle: async ({ page }) => closeInsights(page),
  },
  {
    query: { owner: 'InsightsDialog', label: 'Try again', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const { page, assistant } = ctx;
        await page.reload({ waitUntil: 'networkidle' });
        await waitForPortalRouteSettled(page);
        assistant.failing = true;
        await trigger(page).click();
        const dialog = dialogOf(page);
        await expect(dialog.getByRole('alert')).toContainText(OUTAGE);
        const failed = assistant.insights.length;
        await dialog.getByRole('button', { name: 'Try again', exact: true }).click();
        await expect.poll(() => assistant.insights.length).toBe(failed + 1);
        await expect(dialog.getByRole('alert')).toContainText(OUTAGE);
        assistant.failing = false;
        await dialog.getByRole('button', { name: 'Try again', exact: true }).click();
        await expect(dialog.locator('.ai-ins-headline')).toHaveText(headline(await expectedKind(page)));
        await expect(dialog.getByRole('alert')).toHaveCount(0);
        expect(assistant.insights.length).toBe(failed + 2);
        return ['A failing board read shows the outage message with Try again', 'Try again while still failing re-reads once and keeps the message', 'After the read heals, Try again renders the board and clears the alert'];
      },
      denial: denied,
    },
    settle: async ({ page, assistant }) => { assistant.failing = false; await closeInsights(page); },
  },
  {
    query: { owner: 'InsightsDialog', label: 'Ask AI about this', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openInsights(ctx);
        const before = ctx.assistant.jobs.length;
        await dialog.getByRole('button', { name: 'Ask AI about this', exact: true }).click();
        await expect(dialog).toBeHidden();
        const panel = ctx.page.getByRole('dialog', { name: 'AstraNull AI assistant' });
        await expect(panel).toBeVisible();
        await expect.poll(() => ctx.assistant.jobs.length).toBe(before + 1);
        const sent = JSON.stringify(ctx.assistant.jobs.at(-1));
        expect(sent).toContain('Explain the insights for');
        await expect(panel.getByText(ANSWER.content)).toBeVisible();
        await panel.getByRole('button', { name: 'Close assistant', exact: true }).click();
        await expect(panel).toBeHidden();
        return ['Ask AI about this closes insights and opens the assistant panel', 'The assistant sends one job whose prompt asks to explain these insights', 'The answer renders, and the panel closes again'];
      },
      denial: denied,
    },
  },
  {
    query: { owner: 'InsightsDialog', label: 'ActionRow', kind: 'activate' },
    states: {
      success: (ctx) => openFromRow(ctx, 'The action row onOpen'),
      reload: reloadFromRow,
      denial: denied,
    },
    settle: returnToRoute,
  },
  {
    query: { owner: 'ActionRow', label: /^`Open: /, kind: 'activate' },
    states: {
      success: (ctx) => openFromRow(ctx, `Open: ${ACTION_TITLE}`),
      reload: reloadFromRow,
      denial: denied,
    },
    settle: returnToRoute,
  },
  {
    query: { owner: 'AssistantVisual', kind: 'activate', handler: "setView('table')" },
    states: {
      success: async (ctx) => {
        const visual = section(await openInsights(ctx), BAR_TITLE);
        await visual.getByRole('button', { name: 'Table', exact: true }).click();
        await expect(visual.getByRole('button', { name: 'Table', exact: true })).toHaveAttribute('aria-pressed', 'true');
        await expect(visual.getByRole('table')).toBeVisible();
        await expect(visual.locator('figure.as-bars')).toHaveCount(0);
        return [`Table switches ${BAR_TITLE} from the bar chart to its data table`, 'The Table toggle reports aria-pressed=true'];
      },
      denial: denied,
    },
  },
  {
    query: { owner: 'AssistantVisual', kind: 'activate', handler: "setView('chart')" },
    states: {
      success: async (ctx) => {
        const visual = section(await openInsights(ctx), BAR_TITLE);
        if ((await visual.getByRole('button', { name: 'Chart', exact: true }).getAttribute('aria-pressed')) === 'true') await visual.getByRole('button', { name: 'Table', exact: true }).click();
        await visual.getByRole('button', { name: 'Chart', exact: true }).click();
        await expect(visual.getByRole('button', { name: 'Chart', exact: true })).toHaveAttribute('aria-pressed', 'true');
        await expect(visual.locator('figure.as-bars')).toBeVisible();
        await expect(visual.getByRole('table')).toHaveCount(0);
        return [`Chart switches ${BAR_TITLE} back to the bar chart`, 'The Chart toggle reports aria-pressed=true'];
      },
      denial: denied,
    },
  },
  {
    query: { owner: 'CopyCsv', kind: 'activate' },
    order: ['error-retry', 'success', 'denial'],
    states: {
      success: async (ctx) => {
        const visual = section(await openInsights(ctx), TABLE_TITLE);
        await stubClipboard(ctx.page, false);
        await ctx.page.evaluate(() => { window.__clipboardWrites = []; });
        await visual.getByRole('button', { name: `Copy ${TABLE_TITLE} as CSV`, exact: true }).click();
        await expect(visual.getByRole('button', { name: `${TABLE_TITLE} copied as CSV`, exact: true })).toBeVisible();
        const writes = await ctx.page.evaluate(() => window.__clipboardWrites);
        expect(writes).toHaveLength(1);
        expect(writes[0].split('\n')[0]).toBe('Target,Open');
        expect(writes[0].trim().split('\n')).toHaveLength(TABLE_ROWS + 1);
        return [`Copy CSV writes the ${TABLE_TITLE} header and all ${TABLE_ROWS} rows to the clipboard once`, 'The button is renamed to the copied confirmation'];
      },
      'error-retry': async (ctx) => {
        const visual = section(await openInsights(ctx), TABLE_TITLE);
        const copy = visual.getByRole('button', { name: `Copy ${TABLE_TITLE} as CSV`, exact: true });
        await stubClipboard(ctx.page, true);
        await ctx.page.evaluate(() => { window.__clipboardWrites = []; });
        await copy.click();
        await expect.poll(() => ctx.page.evaluate(() => window.__clipboardWrites.length)).toBe(1);
        await expect(copy).toBeVisible();
        await copy.click();
        await expect.poll(() => ctx.page.evaluate(() => window.__clipboardWrites.length)).toBe(2);
        await expect(visual.getByText('Copied', { exact: true })).toHaveCount(0);
        await stubClipboard(ctx.page, false);
        await copy.click();
        await expect(visual.getByRole('button', { name: `${TABLE_TITLE} copied as CSV`, exact: true })).toBeVisible();
        expect(await ctx.page.evaluate(() => window.__clipboardWrites.length)).toBe(3);
        return ['A rejected clipboard write keeps the Copy CSV label and shows no copied state', 'Retrying while denied tries once more and still shows no copied state', 'After the clipboard heals one more click copies and confirms'];
      },
      denial: denied,
    },
    settle: async ({ page }) => closeInsights(page),
  },
  {
    query: { owner: 'DataTable', kind: 'activate', handler: 'toggle(index)' },
    states: {
      success: async (ctx) => {
        const visual = section(await openInsights(ctx), TABLE_TITLE);
        const header = visual.getByRole('columnheader', { name: /Open/ });
        await expect(header).toHaveAttribute('aria-sort', 'none');
        await header.getByRole('button').click();
        await expect(header).toHaveAttribute('aria-sort', 'descending');
        await expect(visual.locator('tbody tr').first().locator('td').nth(1)).toHaveText('10');
        await header.getByRole('button').click();
        await expect(header).toHaveAttribute('aria-sort', 'ascending');
        await expect(visual.locator('tbody tr').first().locator('td').nth(1)).toHaveText('0');
        return ['Sorting the numeric Open column starts descending with the largest value first', 'A second activation sorts ascending with the smallest value first'];
      },
      denial: denied,
    },
    settle: async ({ page }) => closeInsights(page),
  },
  {
    query: { owner: 'DataTable', kind: 'activate', handler: 'setShown((value) => value + PAGE * 5)' },
    states: {
      success: async (ctx) => {
        const visual = section(await openInsights(ctx), TABLE_TITLE);
        await expect(visual.locator('tbody tr')).toHaveCount(20);
        await visual.getByRole('button', { name: `Show more (${TABLE_ROWS - 20} more rows)`, exact: true }).click();
        await expect(visual.locator('tbody tr')).toHaveCount(TABLE_ROWS);
        await expect(visual.getByRole('button', { name: /^Show more/ })).toHaveCount(0);
        return [`Show more reveals the remaining ${TABLE_ROWS - 20} rows`, 'The Show more control disappears once every row is shown'];
      },
      denial: denied,
    },
    settle: async ({ page }) => closeInsights(page),
  },
];

test.describe('AI insights: every source action across all roles and permitted routes', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ liveSource: true, mutate: seed });
    const findings = await fetchPortalFindings();
    const headers = portalOwnerHeaders();
    const list = async (path) => ((await (await fetch(`${getPortalPlaywrightBaseUrl()}${path}`, { headers })).json()).items ?? []);
    const group = groupFindings(findings, { targets: await list('/v1/targets'), checks: await list('/v1/checks') }).find((item) => item.assets.length >= 2);
    if (!group) throw new Error('Seed did not produce a finding group with two affected targets');
    groupHref = findingGroupHref(group.key);
  });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });

  for (const identity of matrixIdentities()) {
    test(`${identity.label}: insights actions`, async ({ page }, testInfo) => {
      test.setTimeout(Number(process.env.PORTAL_MATRIX_TIMEOUT_MS ?? 2_400_000));
      await page.setViewportSize({ width: 1440, height: 900 });
      const injected = new Set();
      const { failures, requests } = await startMatrixPage(page, identity, { allowResponse: (response) => injected.has(response.url()) });
      const assistant = await assistantMocks(page, injected);
      const arrive = async (route) => {
        await page.goto(route === 'finding-group-detail' ? `${getPortalPlaywrightBaseUrl()}/app${groupHref}` : resolvePortalRouteUrl(route, getPortalPlaywrightBaseUrl()), { waitUntil: 'networkidle' });
        await waitForPortalRouteSettled(page);
      };
      const executed = await runIdentityMatrix(matrix, { page, testInfo, identity, drivers, arrive, failures, requests, context: { assistant } });
      if (!process.env.PORTAL_MATRIX_ROUTES) expect(executed.length).toBe(matrix.cellCount(identity));
      failures.assertClean();
    });
  }
});
