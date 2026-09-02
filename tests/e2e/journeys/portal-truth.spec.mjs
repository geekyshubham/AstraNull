import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  clearPortalSession,
  gotoPortalRoute,
  gotoPublicPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

async function openCheck(page, checkId) {
  await gotoPortalRoute(page, 'check-detail', getPortalPlaywrightBaseUrl(), {
    entityIds: { 'check-detail': checkId },
  });
  await expect(page.locator('h1').first()).toBeVisible();
}

test.describe('portal truth surfaces', () => {
  test.beforeEach(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('check detail shows real execution semantics and complete taxonomy identifiers', async ({ page }) => {
    await injectPortalDevHeadersSession(page);

    await openCheck(page, 'l3.icmp_flood.readiness');
    await expect(page.getByText('Metadata evaluation', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('No network I/O', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('ATT-002', { exact: true })).toBeVisible();
    await expect(page.getByText('volumetric', { exact: true })).toBeVisible();

    await openCheck(page, 'ops.runbook_contact_validation.safe');
    await expect(page.getByText('Operations self-check', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('1 self-check', { exact: true }).first()).toBeVisible();

    await openCheck(page, 'l3.forbidden_tcp_port.safe');
    await expect(page.getByText('Bounded live probe', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('1 probe operation + up to two DNS destination-vetting resolver operations per hostname destination', { exact: true }).first()).toBeVisible();

    await openCheck(page, 'waf.offensive_sqli.soc');
    await expect(page.getByText('Request only', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('No customer execution', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('WV-001', { exact: true })).toBeVisible();
  });

  test('agent detail attributes only exact run-event provenance after group rebinding', async ({ page }) => {
    const historicalRunId = 'run_checkout_1';
    const reboundGroupId = 'tg_agent_rebound';
    const sameGroupOnlyRunId = 'run_group_only';

    await startPortalPlaywrightServer({
      mutate: (store) => {
        applyPortalBaselineReadinessBoost(store);

        for (const run of store.testRuns) {
          delete run.agent_id;
          delete run.agentId;
          delete run.agent_ids;
          delete run.agentIds;
        }

        store.targetGroups.push({
          id: reboundGroupId,
          tenant_id: PORTAL_BASELINE_IDS.tenantId,
          environment_id: PORTAL_BASELINE_IDS.environmentId,
          name: 'agent-rebound-current',
          expected_behavior_default: 'cloud_baseline',
        });
        const selectedAgent = store.agents.find((agent) => agent.id === PORTAL_BASELINE_IDS.agentId);
        selectedAgent.target_group_id = reboundGroupId;
        selectedAgent.bound_at = '2026-09-01T10:05:00.000Z';

        const historicalRun = store.testRuns.find((run) => run.id === historicalRunId);
        historicalRun.check_id = 'path.protected_canary.safe';
        historicalRun.verdict = 'pass';
        historicalRun.started_at = '2026-09-01T10:01:00.000Z';
        historicalRun.updated_at = '2026-09-01T10:01:00.000Z';

        store.testRuns.push({
          id: sameGroupOnlyRunId,
          tenant_id: PORTAL_BASELINE_IDS.tenantId,
          target_group_id: reboundGroupId,
          target_id: PORTAL_BASELINE_IDS.targetId,
          check_id: 'path.protected_canary.safe',
          status: 'completed',
          verdict: 'pass',
          started_at: '2026-09-01T10:06:00.000Z',
          created_at: '2026-09-01T10:06:00.000Z',
          updated_at: '2026-09-01T10:06:00.000Z',
        });

        const historicalEvent = {
          tenant_id: PORTAL_BASELINE_IDS.tenantId,
          test_run_id: historicalRunId,
          target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
          target_id: PORTAL_BASELINE_IDS.targetId,
          timestamp: '2026-07-01T12:00:05.000Z',
          metadata: {},
        };
        store.events.push(
          {
            ...historicalEvent,
            id: 'evt_historical_exact_agent',
            signal_type: 'agent_observation',
            producer_kind: 'authenticated_agent',
            agent_id: PORTAL_BASELINE_IDS.agentId,
          },
          {
            ...historicalEvent,
            id: 'evt_historical_wrong_agent',
            signal_type: 'agent_observation',
            producer_kind: 'authenticated_agent',
            agent_id: 'agt_decoy',
            metadata: { agent_id: PORTAL_BASELINE_IDS.agentId },
          },
          {
            ...historicalEvent,
            id: 'evt_historical_nested_agent_only',
            signal_type: 'agent_observation',
            producer_kind: 'authenticated_agent',
            metadata: { agent_id: PORTAL_BASELINE_IDS.agentId },
          },
          {
            ...historicalEvent,
            id: 'evt_historical_wrong_producer',
            signal_type: 'agent_observation',
            producer_kind: 'public_api',
            agent_id: PORTAL_BASELINE_IDS.agentId,
          },
          {
            ...historicalEvent,
            id: 'evt_historical_wrong_signal',
            signal_type: 'probe_result',
            producer_kind: 'authenticated_agent',
            agent_id: PORTAL_BASELINE_IDS.agentId,
          },
        );
      },
    });

    const fetchedRunEventIds = new Set();
    page.on('request', (request) => {
      if (request.method() !== 'GET') return;
      const match = new URL(request.url()).pathname.match(/^\/v1\/test-runs\/([^/]+)\/events$/);
      if (match) fetchedRunEventIds.add(decodeURIComponent(match[1]));
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'agent-detail', getPortalPlaywrightBaseUrl());

    expect([...fetchedRunEventIds]).toEqual(expect.arrayContaining([
      historicalRunId,
      sameGroupOnlyRunId,
    ]));

    const historical = page.locator('tr').filter({ hasText: historicalRunId });
    const groupOnly = page.locator('tr').filter({ hasText: sameGroupOnlyRunId });
    await expect(historical).toContainText('Selected agent');
    await expect(groupOnly).toContainText('Not attributed');

    const placementCard = page.locator('.card').filter({
      has: page.getByRole('heading', { name: 'Placement validation', exact: true }),
    });
    await expect(placementCard).toContainText(historicalRunId);
    await expect(placementCard).toContainText('last run · pass');
    await expect(placementCard).not.toContainText(sameGroupOnlyRunId);
  });

  test('agent detail reports unavailable attribution when every rebound history endpoint fails', async ({ page }) => {
    const reboundGroupId = 'tg_agent_rebound_errors';
    await startPortalPlaywrightServer({
      mutate: (store) => {
        applyPortalBaselineReadinessBoost(store);
        store.targetGroups.push({
          id: reboundGroupId,
          tenant_id: PORTAL_BASELINE_IDS.tenantId,
          environment_id: PORTAL_BASELINE_IDS.environmentId,
          name: 'agent-rebound-errors',
          expected_behavior_default: 'cloud_baseline',
        });
        const selectedAgent = store.agents.find((agent) => agent.id === PORTAL_BASELINE_IDS.agentId);
        selectedAgent.target_group_id = reboundGroupId;
        selectedAgent.bound_at = '2026-09-01T11:00:00.000Z';
      },
    });

    let failedEventEndpoints = 0;
    await page.route('**/v1/test-runs/*/events', async (route) => {
      failedEventEndpoints += 1;
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'internal_error', correlation_id: 'cid-agent-history' }),
      });
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'agent-detail', getPortalPlaywrightBaseUrl());

    await expect(page.getByText('Historical run attribution unavailable', { exact: true }).first()).toBeVisible();
    await expect(page.getByText('No recent runs yet.', { exact: true })).toHaveCount(0);
    await expect(page.getByText('No attributed runs yet.', { exact: true })).toHaveCount(0);

    const placementCard = page.locator('.card').filter({
      has: page.getByRole('heading', { name: 'Placement validation', exact: true }),
    });
    await expect(placementCard).toContainText('Historical run attribution unavailable');
    await expect(placementCard.locator('.pt-value')).toHaveText([
      'Unavailable',
      'Unavailable',
      'Unavailable',
      'Unavailable',
    ]);
    await expect(placementCard.getByText('pending', { exact: true })).toHaveCount(0);
    await expect(placementCard.getByText('last run · pass', { exact: true })).toHaveCount(0);
    expect(failedEventEndpoints).toBeGreaterThan(0);
  });

  test('run detail excludes public_api evidence lookalikes and refuses positive placement', async ({ page }) => {
    const runId = 'run_checkout_1';
    const publicProbeMarker = 'untrusted-probe-decoy';
    const publicAgentMarker = 'untrusted-agent-decoy';
    const publicNoObservationMarker = 'untrusted-no-observation-decoy';

    await startPortalPlaywrightServer({
      mutate: (store) => {
        applyPortalBaselineReadinessBoost(store);
        const run = store.testRuns.find((entry) => entry.id === runId);
        run.check_id = 'origin.leak_scan.safe';
        run.correlation = { nonce_hash: 'nonce-public-decoy', window_ms: 120_000 };

        const verdict = store.verdicts.find((entry) => entry.test_run_id === runId);
        verdict.confidence = 'high';
        verdict.explanation = 'Signed probe evidence supports the edge-only conclusion.';
        verdict.placement_confidence = {
          level: 'high',
          observation_mode: 'packet_metadata',
          agent_id: PORTAL_BASELINE_IDS.agentId,
        };

        const eventBase = {
          tenant_id: PORTAL_BASELINE_IDS.tenantId,
          test_run_id: runId,
          target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
          target_id: PORTAL_BASELINE_IDS.targetId,
          timestamp: '2026-09-01T10:10:00.000Z',
        };
        store.events.push(
          {
            ...eventBase,
            id: 'evt_public_probe_decoy',
            signal_type: 'probe_result',
            producer_kind: 'public_api',
            source: publicProbeMarker,
            metadata: { external_result: publicProbeMarker },
          },
          {
            ...eventBase,
            id: 'evt_public_agent_decoy',
            signal_type: 'agent_observation',
            producer_kind: 'public_api',
            source: publicAgentMarker,
            agent_id: PORTAL_BASELINE_IDS.agentId,
            nonce_hash: 'nonce-public-decoy',
            metadata: { observation_mode: publicAgentMarker },
          },
          {
            ...eventBase,
            id: 'evt_public_no_observation_decoy',
            signal_type: 'agent_no_observation',
            producer_kind: 'public_api',
            source: publicNoObservationMarker,
            metadata: { reason: publicNoObservationMarker },
          },
        );
      },
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'run-detail', getPortalPlaywrightBaseUrl(), {
      entityIds: { 'run-detail': runId },
    });

    // Probe and agent evidence lives on its own tab in the run detail view.
    await page.getByRole('tab', { name: 'Probe & agent' }).click();

    const probeCard = page.locator('.card').filter({
      has: page.getByRole('heading', { name: 'Probe result', exact: true }),
    });
    await expect(probeCard).toContainText('blocked');
    await expect(probeCard).not.toContainText(publicProbeMarker);

    const agentCard = page.locator('.card').filter({
      has: page.getByRole('heading', { name: 'Agent observation', exact: true }),
    });
    await expect(agentCard).toContainText('No trusted internal observation recorded.');
    await expect(agentCard).not.toContainText(publicAgentMarker);
    await expect(agentCard).not.toContainText(publicNoObservationMarker);

    // The verdict explanation and truth table sit in the correlation matrix on the summary tab.
    await page.getByRole('tab', { name: 'Summary' }).click();
    const explanation = page.locator('.verdict-explanation');
    const internalEvidence = explanation.locator('.verdict-explanation-item').filter({ hasText: 'Internal agent evidence' });
    const placement = explanation.locator('.verdict-explanation-item').filter({ hasText: 'Placement confidence' });
    await expect(internalEvidence).toContainText('No authenticated agent_observation events');
    await expect(internalEvidence).not.toContainText(publicAgentMarker);
    await expect(internalEvidence).not.toContainText(publicNoObservationMarker);
    await expect(placement).toContainText('cannot be proven from trusted run events');
    await expect(placement).not.toContainText('packet_metadata');
    await expect(placement).not.toContainText(PORTAL_BASELINE_IDS.agentId);

    const verdictMetric = page.locator('.metric-card').filter({
      has: page.getByText('Verdict', { exact: true }),
    });
    await expect(verdictMetric).toContainText('placement unproven');
    await expect(verdictMetric).not.toContainText('placement high');
  });

  test('run detail rebind hides prior-run events and ignores a late prior-run response', async ({ page }) => {
    const runA = 'run_checkout_1';
    const runB = 'run_checkout_2';
    const markerA = 'run-a-loaded-marker';
    const markerALate = 'run-a-late-marker';
    const markerBFirst = 'run-b-first-marker';
    const markerBSecond = 'run-b-second-marker';

    await startPortalPlaywrightServer({
      mutate: (store) => {
        applyPortalBaselineReadinessBoost(store);
        const baselineRun = store.testRuns.find((entry) => entry.id === runA);
        store.testRuns.push({
          ...baselineRun,
          id: runB,
          created_at: '2026-09-01T10:20:00.000Z',
          started_at: '2026-09-01T10:20:00.000Z',
          completed_at: '2026-09-01T10:21:00.000Z',
        });
      },
    });

    const deferred = () => {
      let resolve;
      const promise = new Promise((done) => { resolve = done; });
      return { promise, resolve };
    };
    const firstB = deferred();
    const lateA = deferred();
    const secondB = deferred();
    const lateAFulfilled = deferred();
    let aRequests = 0;
    let bRequests = 0;
    const eventEnvelope = (runId, marker) => ({
      items: [{
        id: `evt_${marker}`,
        tenant_id: PORTAL_BASELINE_IDS.tenantId,
        test_run_id: runId,
        target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
        target_id: PORTAL_BASELINE_IDS.targetId,
        check_id: PORTAL_BASELINE_IDS.checkId,
        signal_type: 'probe_result',
        source: 'probe_worker',
        producer_kind: 'signed_probe',
        timestamp: '2026-09-01T10:20:30.000Z',
        metadata: { probe_kind: 'origin_leak_scan', external_result: marker },
      }],
    });

    await page.route('**/v1/test-runs/*/events', async (route) => {
      const match = new URL(route.request().url()).pathname.match(/^\/v1\/test-runs\/([^/]+)\/events$/);
      const runId = match ? decodeURIComponent(match[1]) : '';
      let marker = markerA;
      if (runId === runA) {
        aRequests += 1;
        if (aRequests > 1) {
          await lateA.promise;
          marker = markerALate;
        }
      } else if (runId === runB) {
        bRequests += 1;
        if (bRequests === 1) {
          await firstB.promise;
          marker = markerBFirst;
        } else {
          await secondB.promise;
          marker = markerBSecond;
        }
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(eventEnvelope(runId, marker)),
      });
      if (runId === runA && aRequests > 1) lateAFulfilled.resolve();
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'run-detail', getPortalPlaywrightBaseUrl(), {
      entityIds: { 'run-detail': runA },
    });
    // Probe evidence markers render on the probe/agent tab; the tab selection persists across
    // run rebinding, so stale-response protection is still observed from a single place.
    await page.getByRole('tab', { name: 'Probe & agent' }).click();
    await expect(page.getByText(markerA, { exact: true })).toBeVisible();

    const firstBRequest = page.waitForRequest((request) => (
      new URL(request.url()).pathname === `/v1/test-runs/${runB}/events`
    ));
    await page.evaluate((id) => { window.location.hash = `run-detail?id=${encodeURIComponent(id)}`; }, runB);
    await firstBRequest;
    await expect(page.getByText(markerA, { exact: true })).toHaveCount(0);
    await expect(page.getByLabel('Loading run event evidence…').first()).toBeVisible();
    firstB.resolve();
    await expect(page.getByText(markerBFirst, { exact: true })).toBeVisible();

    const secondARequest = page.waitForRequest((request) => (
      new URL(request.url()).pathname === `/v1/test-runs/${runA}/events`
    ));
    await page.evaluate((id) => { window.location.hash = `run-detail?id=${encodeURIComponent(id)}`; }, runA);
    await secondARequest;
    await expect(page.getByText(markerBFirst, { exact: true })).toHaveCount(0);

    const secondBRequest = page.waitForRequest((request) => (
      new URL(request.url()).pathname === `/v1/test-runs/${runB}/events`
    ));
    await page.evaluate((id) => { window.location.hash = `run-detail?id=${encodeURIComponent(id)}`; }, runB);
    await secondBRequest;
    lateA.resolve();
    await lateAFulfilled.promise;
    await expect(page.getByText(markerALate, { exact: true })).toHaveCount(0);
    await expect(page.getByText(markerBFirst, { exact: true })).toHaveCount(0);
    secondB.resolve();
    await expect(page.getByText(markerBSecond, { exact: true })).toBeVisible();
  });

  test('run detail reports event endpoint failure without authoritative empty-evidence claims', async ({ page }) => {
    const runId = 'run_checkout_1';
    await page.route(`**/v1/test-runs/${runId}/events`, async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'run_events_failed' }),
      });
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'run-detail', getPortalPlaywrightBaseUrl(), {
      entityIds: { 'run-detail': runId },
    });

    await expect(page.getByText('Run event evidence unavailable.', { exact: true })).toBeVisible();
    await expect(page.getByText('No probe results yet.', { exact: true })).toHaveCount(0);
    await expect(page.getByText('No trusted internal observation recorded.', { exact: true })).toHaveCount(0);
    await expect(page.locator('.verdict-explanation')).toHaveCount(0);
    await expect(page.getByText('Correlation evidence unavailable because run event evidence could not be loaded.', { exact: true })).toBeVisible();
    await expect(page.locator('.metric-card').filter({ has: page.getByText('Verdict', { exact: true }) })).toContainText('placement unavailable');
  });

  test('global and current-group run tables ignore unsupported run agent aliases', async ({ page }) => {
    const runId = 'run_checkout_1';
    const unsupportedAgentAlias = 'unsupported-run-agent-alias';
    const unsupportedObservedAlias = 'unsupported-observed-agent-alias';

    await startPortalPlaywrightServer({
      mutate: (store) => {
        applyPortalBaselineReadinessBoost(store);
        const run = store.testRuns.find((entry) => entry.id === runId);
        run.agent_id = unsupportedAgentAlias;
        run.observed_agent_id = unsupportedObservedAlias;
      },
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'runs', getPortalPlaywrightBaseUrl());
    const globalRunsCard = page.locator('.card').filter({
      has: page.getByRole('heading', { name: 'Run history', exact: true }),
    });
    const globalRunsTable = globalRunsCard.getByRole('table');
    await expect(globalRunsTable.getByRole('columnheader', { name: 'Agent', exact: true })).toHaveCount(0);
    await expect(globalRunsTable).not.toContainText(unsupportedAgentAlias);
    await expect(globalRunsTable).not.toContainText(unsupportedObservedAlias);

    await gotoPortalRoute(page, 'target-group-detail', getPortalPlaywrightBaseUrl(), {
      entityIds: { 'target-group-detail': PORTAL_BASELINE_IDS.targetGroupId },
    });
    const currentGroupRunsCard = page.locator('.card').filter({
      has: page.getByRole('heading', { name: 'Recent runs', exact: true }),
    });
    const currentGroupRunsTable = currentGroupRunsCard.getByRole('table');
    await expect(currentGroupRunsTable.getByRole('columnheader', { name: 'Agent', exact: true })).toHaveCount(0);
    await expect(currentGroupRunsTable).not.toContainText(unsupportedAgentAlias);
    await expect(currentGroupRunsTable).not.toContainText(unsupportedObservedAlias);
  });

  test('forgot-password initiation is controlled and enumeration-safe', async ({ page }) => {
    let submittedBody = null;
    await page.route('**/v1/auth/request-password-reset', async (route) => {
      submittedBody = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'reset_requested' }),
      });
    });
    await clearPortalSession(page);
    await gotoPublicPortalRoute(page, '/login?flow=request-password-reset', getPortalPlaywrightBaseUrl());

    const email = page.getByLabel('Work email');
    await email.fill('  owner@baseline.local  ');
    await page.getByRole('button', { name: 'Request recovery instructions' }).click();

    await expect(page.getByRole('status')).toContainText('If an account is eligible and recovery delivery is configured and succeeds, instructions may arrive. This response confirms neither condition.');
    expect(submittedBody).toEqual({ email: 'owner@baseline.local' });
    await expect(page.getByText('owner@baseline.local', { exact: true })).toHaveCount(0);
  });

  test('unknown portal hashes render not-found instead of dashboard content', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await page.goto(`${getPortalPlaywrightBaseUrl()}/app#not-a-real-route`, { waitUntil: 'networkidle' });

    await expect(page.getByText('Portal route not found.', { exact: true })).toBeVisible();
    await expect(page.locator('main h1').filter({ hasText: /^Dashboard$/ })).toHaveCount(0);
  });

  test('agent install preparation is disabled without accepted release metadata', async ({ page }) => {
    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'agents', getPortalPlaywrightBaseUrl());
    await page.getByRole('tab', { name: 'Install' }).click();

    await expect(page.getByText(/Agent download preparation is unavailable\./)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy signed tarball prep commands' })).toBeDisabled();
    await expect(page.getByText(/does not install the agent/i)).toBeVisible();
  });
});
