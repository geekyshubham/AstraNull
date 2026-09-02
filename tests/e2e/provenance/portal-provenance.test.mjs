/** FT-PROV-dyn-01..07 dynamic provenance checks at the portal API boundary. */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
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

after(async () => {
  await stopPortalPlaywrightServer();
});

describe('portal dynamic provenance (node API)', () => {
  it('FT-PROV-dyn-01 readiness boost changes to penalty after restart', async () => {
    const expected = expectedReadinessScores();
    assert.ok(expected.boostedScore > 0);
    assert.ok(expected.boostedScore > expected.penalizedScore);

    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
    const boosted = await fetchPortalReadinessScore();
    assert.equal(boosted, expected.boostedScore);

    await restartPortalPlaywrightWithReadinessPenalty();
    const penalized = await fetchPortalReadinessScore();
    assert.equal(penalized, expected.penalizedScore);
    assert.ok(penalized < boosted);
  });

  it('FT-PROV-dyn-02 open findings change from 5 to 8', async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceFindingsBaseline });
    const baseline = await fetchPortalFindings();
    assert.equal(countOpenFindings(baseline), PROVENANCE_FINDINGS.baselineOpenCount);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceFindingsExpanded });
    const expanded = await fetchPortalFindings();
    assert.equal(countOpenFindings(expanded), PROVENANCE_FINDINGS.mutatedOpenCount);
    assert.equal(PROVENANCE_FINDINGS.baselineOpenCount, 5);
    assert.equal(PROVENANCE_FINDINGS.mutatedOpenCount, 8);
  });

  it('FT-PROV-dyn-03 DNS verification ladder changes from 3 to 4', async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceDnsLadderBaseline });
    const baseline = await fetchPortalVerificationLadder();
    const baselineDns = baseline.steps.find((step) => step.id === 'dns_verified');
    assert.equal(baselineDns?.count, PROVENANCE_DNS_LADDER.baselineDnsVerified);
    assert.equal(baselineDns?.total, PROVENANCE_DNS_LADDER.total);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceDnsLadderExpanded });
    const expanded = await fetchPortalVerificationLadder();
    const expandedDns = expanded.steps.find((step) => step.id === 'dns_verified');
    assert.equal(expandedDns?.count, PROVENANCE_DNS_LADDER.mutatedDnsVerified);
    assert.equal(PROVENANCE_DNS_LADDER.baselineDnsVerified, 3);
    assert.equal(PROVENANCE_DNS_LADDER.mutatedDnsVerified, 4);
  });

  it('FT-PROV-dyn-04 WAF posture changes from protected to drift', async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceWafPostureProtected });
    const baseline = await fetchPortalTargetDetail(PROVENANCE_WAF_POSTURE.targetId);
    assert.equal(baseline.waf_posture?.posture, PROVENANCE_WAF_POSTURE.baselinePosture);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceWafPostureDrift });
    const drifted = await fetchPortalTargetDetail(PROVENANCE_WAF_POSTURE.targetId);
    assert.equal(drifted.waf_posture?.posture, PROVENANCE_WAF_POSTURE.mutatedPosture);
    assert.equal(drifted.waf_posture?.drift_reason, PROVENANCE_WAF_POSTURE.mutatedDriftReason);
  });

  it('FT-PROV-dyn-05 connector changes from active to degraded', async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceConnectorActive });
    const baseline = await fetchPortalWafCoverageSummary();
    assert.equal(baseline.connectors_active, PROVENANCE_WAF_CONNECTORS.baselineActive);
    assert.equal(baseline.connectors_degraded, PROVENANCE_WAF_CONNECTORS.baselineDegraded);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceConnectorDegraded });
    const degraded = await fetchPortalWafCoverageSummary();
    assert.equal(degraded.connectors_active, PROVENANCE_WAF_CONNECTORS.mutatedActive);
    assert.equal(degraded.connectors_degraded, PROVENANCE_WAF_CONNECTORS.mutatedDegraded);
  });

  it('FT-PROV-dyn-06 remediation changes from open to delivered', async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceRemediationOpen });
    const baseline = await fetchPortalFinding(PROVENANCE_REMEDIATION.findingId);
    assert.equal(baseline.remediation?.state, PROVENANCE_REMEDIATION.baselineState);
    assert.equal(baseline.remediation?.description, PROVENANCE_REMEDIATION.baselineDescription);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceRemediationDelivered });
    const delivered = await fetchPortalFinding(PROVENANCE_REMEDIATION.findingId);
    assert.equal(delivered.remediation?.state, PROVENANCE_REMEDIATION.mutatedState);
    assert.equal(delivered.remediation?.description, PROVENANCE_REMEDIATION.mutatedDescription);
    assert.equal(delivered.remediation?.delivered_via, PROVENANCE_REMEDIATION.deliveredVia);
  });

  it('FT-PROV-dyn-07 SOC queue changes from one row to two rows', async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceSocQueueBaseline });
    const baseline = await fetchPortalHighScaleQueue();
    assert.equal(baseline.length, 1);
    assert.equal(baseline[0]?.id, PROVENANCE_SOC_QUEUE.baselineRequestId);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceSocQueueExpanded });
    const expanded = await fetchPortalHighScaleQueue(getPortalPlaywrightBaseUrl());
    assert.equal(expanded.length, 2);
    assert.ok(expanded.some((row) => row.id === PROVENANCE_SOC_QUEUE.addedRequestId));
  });
});
