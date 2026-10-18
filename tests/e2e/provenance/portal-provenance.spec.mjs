import { expect, test } from '@playwright/test';
import {
  applyPortalProvenanceConnectorActive,
  applyPortalProvenanceConnectorDegraded,
  applyPortalProvenanceDnsLadderBaseline,
  applyPortalProvenanceDnsLadderExpanded,
  applyPortalProvenanceFindingsBaseline,
  applyPortalProvenanceFindingsExpanded,
  applyPortalProvenanceRemediationDelivered,
  applyPortalProvenanceRemediationOpen,
  applyPortalProvenanceSocQueueBaseline,
  applyPortalProvenanceSocQueueExpanded,
  applyPortalProvenanceWafPostureDrift,
  applyPortalProvenanceWafPostureProtected,
  PROVENANCE_DNS_LADDER,
  PROVENANCE_FINDINGS,
  PROVENANCE_REMEDIATION,
  PROVENANCE_SOC_QUEUE,
  PROVENANCE_WAF_CONNECTORS,
  PROVENANCE_WAF_POSTURE,
} from '../../fixtures/portal-baseline/provenance.mjs';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { acceptTargetObservation } from '../../../src/services/targetHistory.mjs';
import {
  countOpenFindings,
  expectedReadinessScores,
  fetchPortalFinding,
  fetchPortalFindings,
  fetchPortalHighScaleQueue,
  fetchPortalReadinessScore,
  fetchPortalTargetDetail,
  fetchPortalVerificationLadder,
  fetchPortalWafCoverageSummary,
  getPortalPlaywrightBaseUrl,
  restartPortalPlaywrightServer,
  restartPortalPlaywrightWithReadinessPenalty,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

test.describe('portal dynamic provenance', () => {
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('FT-PROV-dyn-01 dashboard readiness score updates after store mutation + server restart', async ({ page }) => {
    const { boostedScore, penalizedScore } = expectedReadinessScores();
    expect(boostedScore).toBeGreaterThan(0);
    expect(boostedScore).toBeGreaterThan(penalizedScore);

    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialApiScore = await fetchPortalReadinessScore(baseUrl);
    expect(initialApiScore).toBe(boostedScore);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);
    await expect(page.getByTestId('readiness-published-score').locator('strong')).toHaveText(`${initialApiScore}/100`);

    await restartPortalPlaywrightWithReadinessPenalty();
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedApiScore = await fetchPortalReadinessScore(mutatedBaseUrl);
    expect(mutatedApiScore).toBe(penalizedScore);
    expect(mutatedApiScore).not.toBe(initialApiScore);

    await page.goto(`${mutatedBaseUrl}/app#dashboard`, { waitUntil: 'networkidle', timeout: 60_000 });
    const publishedScore = page.getByTestId('readiness-published-score').locator('strong');
    await expect(publishedScore).toHaveText(`${mutatedApiScore}/100`);
    await expect(publishedScore).not.toHaveText(`${initialApiScore}/100`);
  });

  test('FT-PROV-dyn-02 findings tab count and pager update after open-findings mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceFindingsBaseline });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialFindings = await fetchPortalFindings(baseUrl);
    expect(countOpenFindings(initialFindings)).toBe(PROVENANCE_FINDINGS.baselineOpenCount);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'findings', baseUrl);

    // Current Findings: exact single-status chips with server totals, and a server pager in "Each finding".
    const openTab = page.getByRole('group', { name: 'Finding status filters' }).getByRole('button', { name: /^Open/ });
    const pager = page.locator('.rf-pager > .rf-pager-info');
    await expect(openTab.locator('.rf-tab-count')).toHaveText(String(PROVENANCE_FINDINGS.baselineOpenCount));
    await page.getByRole('button', { name: 'Each finding' }).click();
    await expect(pager).toContainText(`of ${PROVENANCE_FINDINGS.baselineOpenCount}`);
    for (const title of PROVENANCE_FINDINGS.baselineOnlyTitles) {
      await expect(page.getByText(title, { exact: false })).toBeVisible();
    }
    for (const title of PROVENANCE_FINDINGS.mutatedOnlyTitles) {
      await expect(page.getByText(title, { exact: false })).toHaveCount(0);
    }

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceFindingsExpanded });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedFindings = await fetchPortalFindings(mutatedBaseUrl);
    expect(countOpenFindings(mutatedFindings)).toBe(PROVENANCE_FINDINGS.mutatedOpenCount);

    await page.goto(`${mutatedBaseUrl}/app#findings`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(openTab.locator('.rf-tab-count')).toHaveText(String(PROVENANCE_FINDINGS.mutatedOpenCount));
    // The restarted server is a new origin, so the remembered view does not carry over.
    await page.getByRole('button', { name: 'Each finding' }).click();
    await expect(pager).toContainText(`of ${PROVENANCE_FINDINGS.mutatedOpenCount}`);
    for (const title of PROVENANCE_FINDINGS.mutatedOnlyTitles) {
      await expect(page.getByText(title, { exact: false })).toBeVisible();
    }
  });

  test('FT-PROV-dyn-03 direct-target ownership counts and verification chips update after DNS mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceDnsLadderBaseline });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialLadder = await fetchPortalVerificationLadder(undefined, baseUrl);
    const initialDns = initialLadder.steps.find((step) => step.id === 'dns_verified');
    expect(initialDns?.count).toBe(PROVENANCE_DNS_LADDER.baselineDnsVerified);
    expect(initialDns?.total).toBe(PROVENANCE_DNS_LADDER.total);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'targets', baseUrl);

    const verifiedSummary = page.getByLabel('Target inventory summary').locator('.targets-summary-cell').filter({ hasText: 'Ownership verified' });
    const promotedTargetRow = page.locator('tr').filter({ hasText: PROVENANCE_DNS_LADDER.promotedTargetValue });
    await expect(verifiedSummary.locator('strong')).toHaveText(String(PROVENANCE_DNS_LADDER.baselineDnsVerified));
    await expect(page.locator('.targets-table-wrap tbody tr')).toHaveCount(PROVENANCE_DNS_LADDER.total);
    // ADR-0008: pending targets read "Verification in progress" (no agent "observed from inside").
    await expect(promotedTargetRow).toContainText('Verification in progress');

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceDnsLadderExpanded });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedLadder = await fetchPortalVerificationLadder(undefined, mutatedBaseUrl);
    const mutatedDns = mutatedLadder.steps.find((step) => step.id === 'dns_verified');
    expect(mutatedDns?.count).toBe(PROVENANCE_DNS_LADDER.mutatedDnsVerified);

    await page.goto(`${mutatedBaseUrl}/app#targets`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(verifiedSummary.locator('strong')).toHaveText(String(PROVENANCE_DNS_LADDER.mutatedDnsVerified));
    await expect(promotedTargetRow).toContainText('Domain ownership verified');
  });

  test('FT-PROV-dyn-04 configured WAF posture never reads as observed WAF detection; per-family history follows recorded observations', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceWafPostureProtected });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialDetail = await fetchPortalTargetDetail(PROVENANCE_WAF_POSTURE.targetId, baseUrl);
    expect(initialDetail.waf_posture?.posture).toBe(PROVENANCE_WAF_POSTURE.baselinePosture);
    expect(initialDetail.protection_profile?.families?.waf?.status).toBe('not_checked');

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', baseUrl);
    // Configuration metadata for a WAF asset is not an external observation: the WAF family stays
    // "Not checked" and blocking stays unmeasured, whatever posture the configuration records.
    const observations = page.getByRole('region', { name: 'Protection observations' });
    const wafFamily = observations.getByRole('listitem').filter({ hasText: /^WAF/ });
    await expect(wafFamily).toContainText('Not checked');
    await expect(wafFamily.locator('.td-provider-meta')).toHaveCount(0);
    await expect(observations).toContainText('Not measured. Detection alone does not show whether anything is blocked.');
    // The declared expectation ("Expected: Protected path baseline") is customer context, not an observation.
    await expect(observations).not.toContainText(/Protection worked|\bprotected\b/i);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceWafPostureDrift });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedDetail = await fetchPortalTargetDetail(PROVENANCE_WAF_POSTURE.targetId, mutatedBaseUrl);
    expect(mutatedDetail.waf_posture?.posture).toBe(PROVENANCE_WAF_POSTURE.mutatedPosture);
    expect(mutatedDetail.waf_posture?.drift_reason).toBe(PROVENANCE_WAF_POSTURE.mutatedDriftReason);
    expect(mutatedDetail.protection_profile?.families?.waf?.status).toBe('not_checked');

    await page.goto(`${mutatedBaseUrl}/app#target-detail?id=${encodeURIComponent(PROVENANCE_WAF_POSTURE.targetId)}`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(wafFamily).toContainText('Not checked');
    await expect(observations).not.toContainText(/\bdrift\b|policy_exception/i);
    await expect(page.locator('#portal-main')).not.toContainText('policy_exception');

    // A recorded WAF observation from an explicit synthetic producer updates that family's history,
    // labelled as not live evidence, and is not promoted into the current detection above.
    const recorded = acceptTargetObservation(
      { tenantId: PORTAL_BASELINE_IDS.tenantId, userId: 'usr_owner', role: 'owner' },
      {
        target_id: PROVENANCE_WAF_POSTURE.targetId,
        family: 'waf',
        check_id: 'waf.fingerprint.safe',
        outcome: 'detected',
        source_kind: 'edge_detection',
        producer_kind: 'internal_simulation',
        nonce: 'prov-dyn-04-waf',
        observed_at: '2026-09-01T10:00:00.000Z',
        source_completed_at: '2026-09-01T10:00:05.000Z',
        corpus_version: 'corpus-synthetic',
        scenario_version: 'scenario-synthetic',
        check_version: 'sha256:synthetic',
      },
      { internal: true },
    );
    expect(recorded.error).toBeUndefined();
    expect(recorded.producer_kind).toBe('internal_simulation');

    await page.reload({ waitUntil: 'networkidle' });
    await expect(wafFamily).toContainText('Not checked');
    await page.getByRole('tab', { name: /^Changes/ }).click();
    const layers = page.getByRole('region', { name: 'Current state by layer' });
    const wafLayer = layers.getByRole('listitem').filter({ hasText: /^WAF/ });
    await expect(wafLayer).toContainText('Detected');
    await expect(wafLayer).toContainText('Not live evidence');
    await expect(layers.getByRole('listitem').filter({ hasText: /^CDN/ })).toHaveCount(0);
  });

  test('FT-PROV-dyn-05 dashboard WAF connectors tile updates after connector status mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceConnectorActive });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialSummary = await fetchPortalWafCoverageSummary(baseUrl);
    expect(initialSummary.connectors_active).toBe(PROVENANCE_WAF_CONNECTORS.baselineActive);
    expect(initialSummary.connectors_degraded).toBe(PROVENANCE_WAF_CONNECTORS.baselineDegraded);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'integrations', baseUrl);

    // The dashboard WAF-summary connector tile was removed in the portal revamp; connector
    // status now surfaces per-connector in the "Configured connectors" table on Integrations.
    // The State column shows each recorded status by meaning: active reads "Configuration accepted",
    // degraded reads "Last poll incomplete".
    const stateCells = page.locator('td[data-label="State"]');
    await expect(stateCells.getByText('Configuration accepted', { exact: true })).toBeVisible();
    await expect(stateCells.getByText('Last poll incomplete', { exact: true })).toHaveCount(0);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceConnectorDegraded });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedSummary = await fetchPortalWafCoverageSummary(mutatedBaseUrl);
    expect(mutatedSummary.connectors_active).toBe(PROVENANCE_WAF_CONNECTORS.mutatedActive);
    expect(mutatedSummary.connectors_degraded).toBe(PROVENANCE_WAF_CONNECTORS.mutatedDegraded);

    await page.goto(`${mutatedBaseUrl}/app#integrations`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(stateCells.getByText('Last poll incomplete', { exact: true })).toBeVisible();
    await expect(stateCells.getByText('Configuration accepted', { exact: true })).toHaveCount(0);
  });

  test('FT-PROV-dyn-06 finding remediation badge and delivered_via line update after mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceRemediationOpen });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialFinding = await fetchPortalFinding(PROVENANCE_REMEDIATION.findingId, baseUrl);
    expect(initialFinding.remediation?.state).toBe(PROVENANCE_REMEDIATION.baselineState);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'finding-detail', baseUrl);

    const remediationCard = page.locator('[data-od-id="finding-remediation"]');
    await expect(remediationCard.getByText(new RegExp(`^${PROVENANCE_REMEDIATION.baselineState}$`, 'i'))).toBeVisible();
    await expect(remediationCard).toContainText(PROVENANCE_REMEDIATION.baselineDescription);
    await expect(remediationCard).not.toContainText(PROVENANCE_REMEDIATION.mutatedDescription);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceRemediationDelivered });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedFinding = await fetchPortalFinding(PROVENANCE_REMEDIATION.findingId, mutatedBaseUrl);
    expect(mutatedFinding.remediation?.state).toBe(PROVENANCE_REMEDIATION.mutatedState);
    expect(mutatedFinding.remediation?.delivered_via).toBe(PROVENANCE_REMEDIATION.deliveredVia);

    await page.goto(`${mutatedBaseUrl}/app#finding-detail?id=${encodeURIComponent(PROVENANCE_REMEDIATION.findingId)}`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(remediationCard.getByText(new RegExp(`^${PROVENANCE_REMEDIATION.mutatedState}$`, 'i'))).toBeVisible();
    await expect(remediationCard).toContainText(PROVENANCE_REMEDIATION.mutatedDescription);
    await expect(remediationCard).not.toContainText(PROVENANCE_REMEDIATION.baselineDescription);
  });

  test('FT-PROV-dyn-07 SOC-gated inline queue row appears after high-scale request mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceSocQueueBaseline });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialQueue = await fetchPortalHighScaleQueue(baseUrl);
    expect(initialQueue).toHaveLength(1);
    expect(initialQueue[0]?.id).toBe(PROVENANCE_SOC_QUEUE.baselineRequestId);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'runs', baseUrl);

    const queueTable = page.locator('.runs-soc-gate table');
    await expect(queueTable.locator(`[title="${PROVENANCE_SOC_QUEUE.baselineRequestId}"]`)).toBeVisible();
    await expect(queueTable.locator(`[title="${PROVENANCE_SOC_QUEUE.addedRequestId}"]`)).toHaveCount(0);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceSocQueueExpanded });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedQueue = await fetchPortalHighScaleQueue(mutatedBaseUrl);
    expect(mutatedQueue).toHaveLength(2);
    expect(mutatedQueue.some((row) => row.id === PROVENANCE_SOC_QUEUE.addedRequestId)).toBe(true);

    await page.goto(`${mutatedBaseUrl}/app#runs`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(queueTable.locator(`[title="${PROVENANCE_SOC_QUEUE.baselineRequestId}"]`)).toBeVisible();
    await expect(queueTable.locator(`[title="${PROVENANCE_SOC_QUEUE.addedRequestId}"]`)).toBeVisible();
  });

  test('FT-PROV-dyn-08 customer owner opens their own high-scale request from runs and reaches the authorization pack', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceSocQueueExpanded });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const socCalls = [];
    page.on('request', (request) => {
      if (new URL(request.url()).pathname.startsWith('/internal/soc')) socCalls.push(request.url());
    });

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'runs', baseUrl);

    const queueTable = page.locator('.runs-soc-gate table');
    const row = queueTable.locator('tbody tr').filter({ hasText: PROVENANCE_SOC_QUEUE.addedObjective });
    await expect(row).toHaveCount(1, { timeout: 20_000 });
    await expect(row).toContainText(/Complete pack \(0\/\d+\)/);
    await expect(row).toContainText(/SOC cannot approve until all \d+ authorization artifacts are accepted \(0 accepted\)\./);
    await expect(queueTable.locator('thead th')).toContainText(['Request', 'Scenario', 'Domains']);
    await expect(queueTable).not.toContainText('soc_gated');

    await row.getByRole('link', { name: `Open authorization pack for request ${PROVENANCE_SOC_QUEUE.addedObjective}`, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`#queue-detail\\?id=${PROVENANCE_SOC_QUEUE.addedRequestId}`));
    await expect(page.getByRole('button', { name: 'Complete authorization pack', exact: true })).toBeVisible({ timeout: 20_000 });

    await gotoPortalRoute(page, 'runs', baseUrl);
    const scheduledRow = queueTable.locator('tbody tr').filter({ has: page.locator(`[title="${PROVENANCE_SOC_QUEUE.baselineRequestId}"]`) });
    await expect(scheduledRow.getByRole('link', { name: /^Open authorization pack for request / })).toHaveAttribute(
      'href',
      new RegExp(`#queue-detail\\?id=${PROVENANCE_SOC_QUEUE.baselineRequestId}$`),
    );
    expect(socCalls).toEqual([]);
  });
});
