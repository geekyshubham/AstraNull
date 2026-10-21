import { expect as baseExpect, test } from '@playwright/test';
import { canAccessRoute } from '../../../apps/web/react/src/lib/route-access.mjs';
import { groupFindings } from '../../../apps/web/react/src/lib/finding-groups.mjs';
import { findingGroupHref } from '../../../apps/web/react/src/lib/finding-groups.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { createActionMatrix, matrixIdentities, runIdentityMatrix, startMatrixPage, PORTAL_SESSION_KEY } from '../../helpers/portal-action-matrix.mjs';
import { fetchPortalFindings, getPortalPlaywrightBaseUrl, portalOwnerHeaders, startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, resolvePortalRouteUrl, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';
import { getStore } from '../../../src/store.mjs';

const expect = baseExpect.configure({ timeout: 20_000 });

const ids = PORTAL_BASELINE_IDS;
const SECOND_RUN = 'run_checkout_2';
const ARTIFACT = 'art_probe_checkout_1';
const DENIED = 'You do not have access to this page.';
const ASK_PROMPT = 'What is missing in my environment and how do I fix it for my provider?';
const matrix = createActionMatrix({ files: ['components/evidence/evidence-inspector.tsx'] });
const REFS = {
  finding: { entry: 'finding', finding_id: ids.findingId, target_id: ids.targetId, check_id: ids.checkId },
  check: { entry: 'check_result', target_id: ids.targetId, check_id: ids.checkId, test_run_id: SECOND_RUN },
  artifact: { entry: 'artifact', evidence_id: ARTIFACT, test_run_id: SECOND_RUN, finding_id: ids.findingId },
  member: { entry: 'group_member', finding_id: ids.findingId, target_id: ids.targetId },
};
const PARAMS = { finding_id: 'ev_finding', target_id: 'ev_target', check_id: 'ev_check', test_run_id: 'ev_run', evidence_id: 'ev_evidence' };
const ANSWER = { content: ['### What is missing', 'Allow inbound HTTPS only from the CDN ranges.'].join('\n'), searches: [], sources: [], model: 'synthetic-model' };
const BOARD = {
  kind: 'finding',
  generated_at: '2026-10-19T12:00:00.000Z',
  scope: { truncated: false, unavailable: [] },
  verdict: { tone: 'caution', score: null, headline: 'One open finding needs a re-test.' },
  kpis: [{ id: 'open', label: 'Open findings', value: 1, unit: 'count', tone: 'caution' }],
  sections: [],
  actions: [],
  narrative: { summary: 'One open finding needs a re-test.', takeaways: [], ai: false },
};
let groupHref = '';

function seed(store) {
  applyPortalBaselineReadinessBoost(store);
  const run = store.testRuns.find((item) => item.id === ids.readinessRunId);
  store.testRuns.push({ ...run, id: SECOND_RUN });
  const base = store.findings.find((item) => item.id === ids.findingId);
  store.findings.push({ ...base, id: 'fnd_member_pay', target_id: 'tgt_checkout_2' });
}

function assistantMocks(page) {
  const state = { jobs: [], insights: [] };
  return Promise.all([
    page.route('**/v1/assistant/status', (route) => route.fulfill({ json: { enabled: true, tenant_enabled: true, runner_online: true, model: 'synthetic-model', reason: null, capabilities: { data_tools: true, visuals: true, page_context: true, insights: true } } })),
    page.route('**/v1/assistant/jobs', (route) => {
      if (route.request().method() !== 'POST') return route.fallback();
      state.jobs.push(route.request().postDataJSON());
      return route.fulfill({ status: 202, json: { job_id: `asj_${state.jobs.length}`, status: 'queued' } });
    }),
    page.route(/\/v1\/assistant\/jobs\/asj_\d+$/, (route) => route.fulfill({ json: { id: route.request().url().split('/').pop(), status: 'done', created_at: new Date().toISOString(), updated_at: new Date().toISOString(), response: ANSWER } })),
    page.route('**/v1/assistant/insights', (route) => {
      state.insights.push(route.request().postDataJSON());
      return route.fulfill({ json: { board: BOARD, narrative: { status: 'unavailable', reason: 'assistant_runner_offline' } } });
    }),
  ]).then(() => state);
}

function evidenceMocks(page, mode, injected) {
  return page.route((url) => url.pathname === '/v1/evidence-context', (route) => {
    const entry = new URL(route.request().url()).searchParams.get('entry');
    if (entry === 'artifact' || mode.value === 'unavailable') {
      injected.add(route.request().url());
      return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'synthetic_evidence_outage' }) });
    }
    if (mode.value === 'missing') {
      injected.add(route.request().url());
      return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
    }
    return route.fallback();
  });
}

async function openTechnical(dialog) {
  const technical = dialog.locator('details.ei-technical');
  if (!(await technical.evaluate((node) => node.open))) await technical.locator(':scope > summary').click();
  await expect(technical.locator('.ei-technical-body')).toBeVisible();
}

const panel = (page) => page.locator('.inspector-panel');
const contextReads = (requests, mark) => requests.since(mark).filter((entry) => entry.path === '/v1/evidence-context');
const sessionStored = (page) => page.evaluate((key) => JSON.parse(sessionStorage.getItem(key) ?? 'null'), PORTAL_SESSION_KEY);

function routeUrlFor(ctx) {
  return ctx.route === 'finding-group-detail' ? `${ctx.baseUrl}/app${groupHref}` : resolvePortalRouteUrl(ctx.route, ctx.baseUrl);
}

function hashWithInspector(ctx, ref) {
  const hash = new URL(routeUrlFor(ctx)).hash.slice(1);
  const params = new URLSearchParams({ inspect: ref.entry });
  for (const [field, param] of Object.entries(PARAMS)) if (ref[field]) params.set(param, ref[field]);
  return `${hash}${hash.includes('?') ? '&' : '?'}${params}`;
}

async function toRoute(ctx) {
  await ctx.page.goto(routeUrlFor(ctx), { waitUntil: 'networkidle' });
  await waitForPortalRouteSettled(ctx.page);
}

async function openScenario(ctx, name, { mode = 'real', title } = {}) {
  ctx.evidenceMode.value = mode;
  await toRoute(ctx);
  await ctx.page.evaluate((hash) => { window.location.hash = hash; }, hashWithInspector(ctx, REFS[name]));
  const dialog = panel(ctx.page);
  await expect(dialog).toBeVisible();
  if (title) await expect(dialog).toHaveAccessibleName(new RegExp(title));
  await expect(dialog.locator('.ei-loading')).toHaveCount(0);
  await ctx.page.waitForLoadState('networkidle');
  return dialog;
}

async function expectDestination(ctx, hash, { routeId, denied }) {
  await expect.poll(() => ctx.page.evaluate(() => window.location.hash)).toBe(`#${hash}`);
  await waitForPortalRouteSettled(ctx.page);
  const heading = ctx.page.getByRole('heading', { name: DENIED, exact: true });
  if (denied) await expect(heading).toBeVisible();
  else await expect(heading).toHaveCount(0);
}

const canOpen = (ctx, routeId) => canAccessRoute(ctx.identity.role, routeId, { principal: 'customer' });

function anchorDriver(query, { scenario, linkName, hash, routeId }) {
  const link = (ctx) => ctx.dialog.getByRole('link', { name: linkName, exact: true });
  const follow = async (ctx, { reload }) => {
    ctx.dialog = await openScenario(ctx, scenario);
    const anchor = link(ctx);
    await expect(anchor).toHaveAttribute('href', hash);
    const mark = ctx.requests.mark();
    await anchor.click();
    if (reload) await ctx.page.reload({ waitUntil: 'networkidle' });
    await expectDestination(ctx, hash.slice(1), { routeId, denied: !canOpen(ctx, routeId) });
    expect(ctx.requests.writesSince(mark), 'Following an inspector link never writes').toEqual([]);
    await toRoute(ctx);
  };
  return {
    query,
    states: {
      success: async (ctx) => { await follow(ctx, { reload: false }); return [`The ${linkName} link targets ${hash} and activating it lands on #${hash.slice(1)} with the ${canOpen(ctx, routeId) ? `${routeId} workspace rendered` : 'route access denial shown'}`, 'Following it issues no write']; },
      reload: async (ctx) => { await follow(ctx, { reload: true }); return [`A direct reload of ${hash} keeps ${canOpen(ctx, routeId) ? `the ${routeId} workspace` : 'the access denial'} at the same address`]; },
      denial: (ctx) => staffDenial(ctx, gone(linkName)),
    },
  };
}

function staffOpen(ctx) {
  return ctx.page.evaluate((hash) => { window.location.hash = hash; }, hashWithInspector(ctx, REFS.finding));
}

async function staffDenial(ctx, absent) {
  const mark = ctx.requests.mark();
  await toRoute(ctx);
  await staffOpen(ctx);
  await expect(ctx.page.locator('#portal-main')).toBeVisible();
  await expect(panel(ctx.page)).toHaveCount(0);
  await absent(ctx.page);
  expect(contextReads(ctx.requests, mark), 'A staff session never issues the customer evidence read').toEqual([]);
  expect(ctx.requests.writesSince(mark)).toEqual([]);
  expect(await sessionStored(ctx.page)).toEqual(ctx.identity.session);
  return ['A staff session carrying inspector parameters renders no inspector and none of its controls', 'No evidence-context read or write is issued and the staff session is not signed out'];
}

const gone = (name, role = 'link') => (page) => expect(page.getByRole(role, { name, exact: true })).toHaveCount(0);

const drivers = [
  {
    query: { owner: 'EvidenceInspectorHost', label: 'title', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const before = routeUrlFor(ctx);
        const dialog = await openScenario(ctx, 'finding');
        const mark = ctx.requests.mark();
        await dialog.getByRole('button', { name: /^Close Finding evidence/ }).click();
        await expect(panel(ctx.page)).toHaveCount(0);
        await expect.poll(() => ctx.page.url().replace(/#$/, '')).toBe(before);
        expect(ctx.requests.writesSince(mark)).toEqual([]);
        return ['Close removes the inspector and every inspector parameter while the routed page and its address stay unchanged', 'Closing issues no request that writes'];
      },
      reload: async (ctx) => {
        await ctx.page.reload({ waitUntil: 'networkidle' });
        await expect(panel(ctx.page)).toHaveCount(0);
        expect(ctx.page.url().replace(/#$/, '')).toBe(routeUrlFor(ctx));
        return ['A reload after closing keeps the inspector closed at the clean route address'];
      },
      denial: (ctx) => staffDenial(ctx, (page) => expect(page.getByRole('button', { name: /^Close (?:Finding|Check|Evidence)/ })).toHaveCount(0)),
    },
  },
  {
    query: { owner: 'EvidenceInspectorHost', kind: 'disclosure', label: /Technical details/ },
    states: {
      success: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        const details = dialog.locator('details.ei-technical');
        const initial = await details.evaluate((node) => node.open);
        await details.locator(':scope > summary').click();
        expect(await details.evaluate((node) => node.open)).toBe(!initial);
        if (!initial) await expect(details.locator('.ei-technical-body')).toBeVisible();
        await details.locator(':scope > summary').click();
        expect(await details.evaluate((node) => node.open)).toBe(initial);
        return [`The technical-details disclosure starts ${initial ? 'open' : 'closed'}, toggles on activation and returns to its prior state`];
      },
      denial: async (ctx) => {
        const observations = await staffDenial(ctx, async (page) => {
          await expect(page.locator('details.ei-technical')).toHaveCount(0);
        });
        return observations;
      },
    },
  },
  {
    query: { owner: 'EvidenceInspectorHost', kind: 'disclosure', label: /related record/ },
    states: {
      success: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        await openTechnical(dialog);
        const details = dialog.locator('details.ei-alternatives');
        const initial = await details.evaluate((node) => node.open);
        await details.locator('summary').click();
        expect(await details.evaluate((node) => node.open)).toBe(!initial);
        await details.locator('summary').click();
        expect(await details.evaluate((node) => node.open)).toBe(initial);
        return [`The related-records disclosure starts ${initial ? 'open' : 'closed'}, toggles on activation and returns to its prior state`];
      },
      denial: async (ctx) => {
        const observations = await staffDenial(ctx, async (page) => {
          await expect(page.locator('details.ei-alternatives')).toHaveCount(0);
        });
        return observations;
      },
    },
  },
  {
    query: { owner: 'ObservationBlock', kind: 'anchor', label: '{id}' },
    states: {
      success: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        await openTechnical(dialog);
        const details = dialog.locator('details.ei-alternatives');
        if (!(await details.evaluate((node) => node.open))) await details.locator('summary').click();
        const anchor = details.getByRole('link', { name: ARTIFACT, exact: true });
        await expect(anchor).toHaveAttribute('href', `#evidence-detail?id=${ARTIFACT}`);
        await anchor.click();
        await expectDestination(ctx, `evidence-detail?id=${ARTIFACT}`, { routeId: 'evidence-detail', denied: !canOpen(ctx, 'evidence-detail') });
        await toRoute(ctx);
        return [`The recorded evidence id links to #evidence-detail?id=${ARTIFACT} and lands there with ${canOpen(ctx, 'evidence-detail') ? 'the evidence workspace' : 'the route denial'}`];
      },
      reload: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        await openTechnical(dialog);
        const details = dialog.locator('details.ei-alternatives');
        if (!(await details.evaluate((node) => node.open))) await details.locator('summary').click();
        await details.getByRole('link', { name: ARTIFACT, exact: true }).click();
        await ctx.page.reload({ waitUntil: 'networkidle' });
        await expectDestination(ctx, `evidence-detail?id=${ARTIFACT}`, { routeId: 'evidence-detail', denied: !canOpen(ctx, 'evidence-detail') });
        await toRoute(ctx);
        return ['A direct reload of the evidence link keeps the same destination'];
      },
      denial: async (ctx) => {
        const observations = await staffDenial(ctx, async (page) => {
          await expect(page.getByRole('link', { name: ARTIFACT, exact: true })).toHaveCount(0);
        });
        return observations;
      },
    },
  },
  {
    query: { owner: 'ObservationBlock', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        await openTechnical(dialog);
        const details = dialog.locator('details.ei-alternatives');
        if (!(await details.evaluate((node) => node.open))) await details.locator('summary').click();
        const mark = ctx.requests.mark();
        await details.getByRole('button', { name: `View artifact ${ARTIFACT}`, exact: true }).click();
        await expect(panel(ctx.page)).toHaveAccessibleName(/Evidence artifact/);
        await expect.poll(() => ctx.page.evaluate(() => window.location.hash)).toContain(`inspect=artifact`);
        const query = new URLSearchParams((await ctx.page.evaluate(() => window.location.hash)).split('?')[1]);
        expect(query.get('ev_evidence')).toBe(ARTIFACT);
        expect(query.get('ev_finding')).toBe(ids.findingId);
        await expect.poll(() => contextReads(ctx.requests, mark).some((entry) => entry.search.includes('entry=artifact'))).toBe(true);
        expect(ctx.requests.writesSince(mark)).toEqual([]);
        return ['View artifact swaps the open inspector to the artifact entry for the exact evidence id with its finding context', 'The artifact context read is issued as a GET and nothing is written'];
      },
      reload: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        await openTechnical(dialog);
        const details = dialog.locator('details.ei-alternatives');
        if (!(await details.evaluate((node) => node.open))) await details.locator('summary').click();
        await details.getByRole('button', { name: `View artifact ${ARTIFACT}`, exact: true }).click();
        await expect(panel(ctx.page)).toHaveAccessibleName(/Evidence artifact/);
        const mark = ctx.requests.mark();
        await ctx.page.reload({ waitUntil: 'networkidle' });
        await expect(panel(ctx.page)).toHaveAccessibleName(/Evidence artifact/);
        expect(contextReads(ctx.requests, mark).some((entry) => entry.search.includes(`evidence_id=${ARTIFACT}`))).toBe(true);
        return ['A cold reload of the artifact address reopens the same artifact inspector and re-reads its context'];
      },
      denial: async (ctx) => {
        const observations = await staffDenial(ctx, async (page) => {
          await expect(page.getByRole('button', { name: /^View artifact/ })).toHaveCount(0);
        });
        return observations;
      },
    },
  },
  {
    query: { owner: 'EvidenceInspectorHost', label: 'Re-test', kind: 'anchor' },
    states: {
      success: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        const mark = ctx.requests.mark();
        const retest = dialog.getByRole('link', { name: 'Re-test', exact: true });
        await expect(retest).toHaveAttribute('href', `#finding-detail?id=${ids.findingId}&retest=review`);
        await retest.click();
        const review = ctx.page.getByRole('dialog', { name: 'Review this retest' });
        await expect(review).toBeVisible();
        await expect(review).toContainText('never closes other domains');
        expect(ctx.requests.writesSince(mark), 'Opening a retest review does not start the check').toEqual([]);
        await review.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(review).toHaveCount(0);
        return ['Re-test opens the scoped retest review for the exact finding and never starts the check', 'Cancelling the review closes it with no write'];
      },
      reload: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        await dialog.getByRole('link', { name: 'Re-test', exact: true }).click();
        await ctx.page.reload({ waitUntil: 'networkidle' });
        const review = ctx.page.getByRole('dialog', { name: 'Review this retest' });
        await expect(review).toBeVisible();
        await review.getByRole('button', { name: 'Cancel', exact: true }).click();
        return ['A direct reload of the retest address reopens the same scoped review'];
      },
      denial: async (ctx) => {
        if (ctx.identity.principal === 'staff') return staffDenial(ctx, gone('Re-test'));
        const dialog = await openScenario(ctx, 'finding');
        const mark = ctx.requests.mark();
        await expect(dialog.getByRole('link', { name: 'Re-test', exact: true })).toHaveCount(0);
        await expect(dialog.getByRole('link', { name: 'Open finding', exact: true })).toBeVisible();
        expect(ctx.requests.writesSince(mark)).toEqual([]);
        return [`${ctx.identity.label} without test_run:start sees Open finding but no Re-test action`, 'No write is issued'];
      },
    },
  },
  anchorDriver({ owner: 'EvidenceInspectorHost', label: 'Open finding', kind: 'anchor' }, { scenario: 'finding', linkName: 'Open finding', hash: `#finding-detail?id=${ids.findingId}`, routeId: 'finding-detail' }),
  anchorDriver({ owner: 'EvidenceInspectorHost', label: /Open target/, kind: 'anchor' }, { scenario: 'finding', linkName: 'Open target check', hash: `#target-detail?id=${ids.targetId}&tab=validate&check=${ids.checkId}`, routeId: 'target-detail' }),
  anchorDriver({ owner: 'EvidenceInspectorHost', label: 'Open run', kind: 'anchor' }, { scenario: 'check', linkName: 'Open run', hash: `#run-detail?id=${SECOND_RUN}`, routeId: 'run-detail' }),
  anchorDriver({ owner: 'EvidenceInspectorHost', label: 'Open artifact record', kind: 'anchor' }, { scenario: 'artifact', linkName: 'Open artifact record', hash: `#evidence-detail?id=${ARTIFACT}`, routeId: 'evidence-detail' }),
  {
    query: { owner: 'EvidenceInspectorHost', label: 'AskAiButton', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        const before = ctx.assistant.jobs.length;
        await dialog.getByRole('button', { name: 'Ask AI how to fix', exact: true }).click();
        const assistant = ctx.page.getByRole('dialog', { name: 'AstraNull AI assistant' });
        await expect(assistant.locator('.as-context')).toContainText('Asking about:');
        await expect.poll(() => ctx.assistant.jobs.length).toBeGreaterThan(before);
        const job = ctx.assistant.jobs.at(-1);
        expect(job.context.finding_id).toBe(ids.findingId);
        expect(job.messages.at(-1).content).toBe(ASK_PROMPT);
        await expect(assistant.getByRole('heading', { name: 'What is missing' })).toBeVisible({ timeout: 15_000 });
        await ctx.page.keyboard.press('Escape');
        return ['Ask AI how to fix opens the assistant with the finding as context and sends the fixed fix question once', 'The assistant answer renders in the panel'];
      },
      denial: async (ctx) => {
        const observations = await staffDenial(ctx, async (page) => {
          await expect(page.getByRole('button', { name: 'Ask AI how to fix', exact: true })).toHaveCount(0);
        });
        expect(ctx.assistant.jobs.length).toBe(0);
        return observations;
      },
    },
  },
  {
    query: { owner: 'EvidenceInspectorHost', label: 'AiInsightsButton', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding');
        const before = ctx.assistant.insights.length;
        await dialog.getByRole('button', { name: 'AI insights', exact: true }).click();
        const insights = ctx.page.getByRole('dialog', { name: /Finding/ });
        await expect(insights).toBeVisible();
        await expect.poll(() => ctx.assistant.insights.length).toBeGreaterThan(before);
        for (const request of ctx.assistant.insights.slice(before)) expect(JSON.stringify(request)).toContain(ids.findingId);
        await expect(insights.getByText('One open finding needs a re-test.').first()).toBeVisible();
        await ctx.page.keyboard.press('Escape');
        await expect(insights).toBeHidden();
        return ['AI insights opens the finding-scoped dialog and requests insights for the exact finding id', 'The computed headline renders and Escape dismisses the dialog'];
      },
      denial: async (ctx) => {
        const observations = await staffDenial(ctx, async (page) => {
          await expect(page.locator('.inspector-panel').getByRole('button', { name: 'AI insights', exact: true })).toHaveCount(0);
        });
        expect(ctx.assistant.insights.length).toBe(0);
        return observations;
      },
    },
  },
  {
    query: { owner: 'EvidenceInspectorHost', label: 'Retry', kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding', { mode: 'missing' });
        const note = dialog.locator('.ei-partial');
        await expect(async () => {
          await openTechnical(dialog);
          await expect(note).toBeVisible({ timeout: 1000 });
        }).toPass();
        const mark = ctx.requests.mark();
        ctx.evidenceMode.value = 'real';
        await note.getByRole('button', { name: 'Retry', exact: true }).click();
        await expect.poll(() => contextReads(ctx.requests, mark).length).toBeGreaterThan(0);
        await expect(dialog.locator('.ei-partial')).toHaveCount(0);
        expect(ctx.requests.writesSince(mark)).toEqual([]);
        return ['Without the context route the inspector shows the partial exact-record view with a Retry action', 'Retry re-reads the evidence context, replaces the partial note with the full view and writes nothing'];
      },
      denial: async (ctx) => {
        const observations = await staffDenial(ctx, async (page) => {
          await expect(page.locator('.ei-partial')).toHaveCount(0);
        });
        return observations;
      },
    },
  },
  ...[{ owner: 'EvidenceInspectorHost', label: 'StateNotice', kind: 'activate' }, { owner: 'StateNotice', label: 'Retry', kind: 'activate' }].map((query) => ({
    query,
    states: {
      success: async (ctx) => {
        const dialog = await openScenario(ctx, 'finding', { mode: 'unavailable' });
        const notice = dialog.locator('.ei-state[data-state="unavailable"]');
        await expect(notice).toBeVisible();
        await expect(notice).toContainText('This is not the same as having no evidence');
        const mark = ctx.requests.mark();
        ctx.evidenceMode.value = 'real';
        await notice.getByRole('button', { name: 'Retry', exact: true }).click();
        await expect.poll(() => contextReads(ctx.requests, mark).length).toBeGreaterThan(0);
        await expect(dialog.locator('.ei-state[data-state="unavailable"]')).toHaveCount(0);
        await expect(dialog.locator('details.ei-technical')).toBeVisible();
        expect(ctx.requests.writesSince(mark)).toEqual([]);
        return ['A failed evidence read shows the distinct unavailable notice with Retry, not an empty-evidence state', 'Retry re-reads once the service answers, clears the notice, shows the evidence and writes nothing'];
      },
      denial: async (ctx) => {
        const observations = await staffDenial(ctx, async (page) => {
          await expect(page.locator('.ei-state')).toHaveCount(0);
        });
        return observations;
      },
    },
  })),
  {
    query: { owner: 'EvidenceInspectorHost', label: /^position\.next/, kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openMemberInspector(ctx);
        const next = dialog.getByRole('button', { name: /^Next: / });
        const first = await dialog.locator('.ei-sequence-label .tabular-nums').textContent();
        const hashBefore = await ctx.page.evaluate(() => window.location.hash);
        const mark = ctx.requests.mark();
        await next.click();
        await expect(dialog.locator('.ei-sequence-label .tabular-nums')).not.toHaveText(first);
        await expect.poll(() => ctx.page.evaluate(() => window.location.hash)).not.toBe(hashBefore);
        await expect(dialog.getByRole('button', { name: /^Previous: / })).toBeEnabled();
        expect(ctx.requests.writesSince(mark)).toEqual([]);
        return [`Next replaces the open record (${first} advances) without adding a history entry or writing`, 'Previous becomes enabled once a record precedes the current one'];
      },
      reload: async (ctx) => {
        const dialog = await openMemberInspector(ctx);
        await dialog.getByRole('button', { name: /^Next: / }).click();
        const label = await dialog.locator('.ei-sequence-label .tabular-nums').textContent();
        await ctx.page.reload({ waitUntil: 'networkidle' });
        await expect(panel(ctx.page).locator('.ei-sequence-label .tabular-nums')).toHaveText(label);
        await expect(panel(ctx.page).getByRole('button', { name: /^Previous: / })).toBeEnabled();
        return [`After reload the second record (${label}) is still open and its position in the group is restored`];
      },
    },
  },
  {
    query: { owner: 'EvidenceInspectorHost', label: /^position\.previous/, kind: 'activate' },
    states: {
      success: async (ctx) => {
        const dialog = await openMemberInspector(ctx);
        const first = await dialog.locator('.ei-sequence-label .tabular-nums').textContent();
        await expect(dialog.getByRole('button', { name: 'No previous record', exact: true })).toBeDisabled();
        await dialog.getByRole('button', { name: /^Next: / }).click();
        await expect(dialog.locator('.ei-sequence-label .tabular-nums')).not.toHaveText(first);
        const mark = ctx.requests.mark();
        await dialog.getByRole('button', { name: /^Previous: / }).click();
        await expect(dialog.locator('.ei-sequence-label .tabular-nums')).toHaveText(first);
        await expect(dialog.getByRole('button', { name: 'No previous record', exact: true })).toBeDisabled();
        expect(ctx.requests.writesSince(mark)).toEqual([]);
        return ['Previous is disabled on the first record, steps back from the second and is disabled again at the start', 'Stepping writes nothing'];
      },
      reload: async (ctx) => {
        const dialog = await openMemberInspector(ctx);
        await dialog.getByRole('button', { name: /^Next: / }).click();
        await dialog.getByRole('button', { name: /^Previous: / }).click();
        const first = await dialog.locator('.ei-sequence-label .tabular-nums').textContent();
        await ctx.page.reload({ waitUntil: 'networkidle' });
        await expect(panel(ctx.page).locator('.ei-sequence-label .tabular-nums')).toHaveText(first);
        await expect(panel(ctx.page).getByRole('button', { name: 'No previous record', exact: true })).toBeDisabled();
        return ['After stepping back and reloading, the first record remains open with Previous disabled'];
      },
    },
  },
];

async function openMemberInspector(ctx) {
  ctx.evidenceMode.value = 'real';
  await toRoute(ctx);
  const row = ctx.page.getByRole('button', { name: /^View evidence for the .* finding on / }).first();
  await row.click();
  const dialog = panel(ctx.page);
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('.ei-sequence-label')).toBeVisible();
  return dialog;
}

test.describe('evidence inspector: every source action across all roles and permitted routes', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ liveSource: true, mutate: seed });
    const findings = await fetchPortalFindings();
    const headers = portalOwnerHeaders();
    const list = async (path) => ((await (await fetch(`${getPortalPlaywrightBaseUrl()}${path}`, { headers })).json()).items ?? []);
    const groups = groupFindings(findings, { targets: await list('/v1/targets'), checks: await list('/v1/checks') });
    const group = groups.find((item) => item.assets.length >= 2);
    if (!group) throw new Error('Seed did not produce a finding group with two affected targets');
    groupHref = findingGroupHref(group.key);
    expect(getStore().findings.length).toBeGreaterThan(1);
  });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });

  for (const identity of matrixIdentities()) {
    test(`${identity.label}: inspector actions`, async ({ page }, testInfo) => {
      test.setTimeout(Number(process.env.PORTAL_MATRIX_TIMEOUT_MS ?? 1_800_000));
      await page.setViewportSize({ width: 1440, height: 900 });
      const injected = new Set();
      const mode = { value: 'real' };
      const { failures, requests } = await startMatrixPage(page, identity, { allowResponse: (response) => injected.has(response.url()) });
      await evidenceMocks(page, mode, injected);
      const assistant = await assistantMocks(page);
      const arrive = async (route) => {
        await page.goto(route === 'finding-group-detail' ? `${getPortalPlaywrightBaseUrl()}/app${groupHref}` : resolvePortalRouteUrl(route, getPortalPlaywrightBaseUrl()), { waitUntil: 'networkidle' });
        await waitForPortalRouteSettled(page);
      };
      const executed = await runIdentityMatrix(matrix, { page, testInfo, identity, drivers, arrive, failures, requests, context: { evidenceMode: mode, assistant } });
      if (!process.env.PORTAL_MATRIX_ROUTES) expect(executed.length).toBe(matrix.cellCount(identity));
      failures.assertClean();
    });
  }
});
