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

async function openTechnicalProbeEvidence(page) {
  const summary = page.getByText('Show technical probe evidence', { exact: true }).first();
  await expect(summary).toBeVisible();
  const expanded = await summary.evaluate((node) => node.parentElement?.hasAttribute('open') ?? false);
  if (!expanded) await summary.click();
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

        const eventBase = {
          tenant_id: PORTAL_BASELINE_IDS.tenantId,
          test_run_id: runId,
          target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
          target_id: PORTAL_BASELINE_IDS.targetId,
          timestamp: '2026-09-01T10:10:00.000Z',
        };
        // Untrusted public_api events must never surface as signed probe evidence (ADR-0008
        // removed internal agents; agent_observation lookalikes must also be ignored).
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

    // Signed probe evidence lives on the "Probe evidence" tab; untrusted lookalikes must not appear.
    await page.getByRole('tab', { name: 'Probe evidence' }).click();
    const probeCard = page.locator('.card').filter({
      has: page.getByRole('heading', { name: 'Probe result', exact: true }),
    });
    await expect(probeCard).toBeVisible();
    await expect(probeCard).not.toContainText(publicProbeMarker);
    await expect(probeCard).not.toContainText(publicAgentMarker);
    await expect(probeCard).not.toContainText(publicNoObservationMarker);

    // The verdict explanation on the summary tab summarizes only trusted signed probe evidence.
    await page.getByRole('tab', { name: 'Summary' }).click();
    await page.getByText('Show technical evidence details', { exact: true }).first().click();
    const explanation = page.locator('.verdict-explanation');
    const externalEvidence = explanation.locator('.verdict-explanation-item').filter({ hasText: 'External probe evidence' });
    await expect(externalEvidence).not.toContainText(publicProbeMarker);
    await expect(externalEvidence).not.toContainText(publicAgentMarker);
    await expect(externalEvidence).not.toContainText(publicNoObservationMarker);

    // ADR-0008: the verdict reports external-only confidence and never a positive internal placement.
    const verdictMetric = page.locator('.metric-card').filter({
      has: page.getByText('Verdict', { exact: true }),
    });
    await expect(verdictMetric).toContainText('External-only confidence');
    await expect(verdictMetric).not.toContainText(/placement/i);
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
    // Probe evidence markers render on the "Probe evidence" tab; the tab selection persists across
    // run rebinding, so stale-response protection is still observed from a single place.
    await page.getByRole('tab', { name: 'Probe evidence' }).click();
    await openTechnicalProbeEvidence(page);
    await expect(page.getByText(new RegExp(`^${markerA}$`, 'i'))).toBeVisible();

    const firstBRequest = page.waitForRequest((request) => (
      new URL(request.url()).pathname === `/v1/test-runs/${runB}/events`
    ));
    await page.evaluate((id) => { window.location.hash = `run-detail?id=${encodeURIComponent(id)}`; }, runB);
    await firstBRequest;
    await expect(page.getByText(new RegExp(`^${markerA}$`, 'i'))).toHaveCount(0);
    await expect(page.getByLabel('Loading run event evidence…').first()).toBeVisible();
    firstB.resolve();
    await openTechnicalProbeEvidence(page);
    await expect(page.getByText(new RegExp(`^${markerBFirst}$`, 'i'))).toBeVisible();

    const secondARequest = page.waitForRequest((request) => (
      new URL(request.url()).pathname === `/v1/test-runs/${runA}/events`
    ));
    await page.evaluate((id) => { window.location.hash = `run-detail?id=${encodeURIComponent(id)}`; }, runA);
    await secondARequest;
    await expect(page.getByText(new RegExp(`^${markerBFirst}$`, 'i'))).toHaveCount(0);

    const secondBRequest = page.waitForRequest((request) => (
      new URL(request.url()).pathname === `/v1/test-runs/${runB}/events`
    ));
    await page.evaluate((id) => { window.location.hash = `run-detail?id=${encodeURIComponent(id)}`; }, runB);
    await secondBRequest;
    lateA.resolve();
    await lateAFulfilled.promise;
    await expect(page.getByText(new RegExp(`^${markerALate}$`, 'i'))).toHaveCount(0);
    await expect(page.getByText(new RegExp(`^${markerBFirst}$`, 'i'))).toHaveCount(0);
    secondB.resolve();
    await openTechnicalProbeEvidence(page);
    await expect(page.getByText(new RegExp(`^${markerBSecond}$`, 'i'))).toBeVisible();
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
    await expect(page.locator('.verdict-explanation')).toHaveCount(0);
    await expect(page.getByText('Correlation evidence unavailable because run event evidence could not be loaded.', { exact: true })).toBeVisible();
    // ADR-0008: the verdict reports external-only confidence; there is no internal placement claim.
    const verdictMetric = page.locator('.metric-card').filter({ has: page.getByText('Verdict', { exact: true }) });
    await expect(verdictMetric).toContainText('External-only confidence');
    await expect(verdictMetric).not.toContainText(/placement/i);
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

});
