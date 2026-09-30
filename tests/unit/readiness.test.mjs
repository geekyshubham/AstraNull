import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  computeReadiness,
  RECENT_EVIDENCE_WINDOW_DAYS,
  WEIGHT_EVIDENCE_FRESHNESS,
  WEIGHT_SOC_GOVERNANCE,
  WEIGHT_VERDICTS,
} from '../../src/services/readiness.mjs';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/services/highScale.mjs';
import {
  catalogCheckSupportsReadiness,
  evidenceTierForProbeKind,
} from '../../src/lib/readinessVerdicts.mjs';
import { artifactProofBody } from '../helpers/highScalePayload.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { buildPortalBaselineStore, PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';
import { buildPortalDemoStore, PORTAL_DEMO_IDS } from '../fixtures/portal-demo/seed.mjs';
import {
  applyPortalBaselineReadinessBoost,
  applyPortalBaselineReadinessPenalty,
} from '../fixtures/portal-baseline/readiness.mjs';
import { freshStore } from '../helpers/reset.mjs';

function daysAgo(n) {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

function daysAhead(n) {
  return new Date(Date.now() + n * 24 * 60 * 60 * 1000).toISOString();
}

function addTrustedVerdictEvidence(store, runId, id, timestamp) {
  store.events.push({
    id,
    tenant_id: 'ten_demo',
    test_run_id: runId,
    signal_type: 'probe_result',
    producer_kind: 'signed_probe',
    timestamp,
  });
  return id;
}

function factor(result, key) {
  return result.factors.find((f) => f.key === key);
}

describe('readiness scoring', () => {
  it('is explainable with factors', () => {
    freshStore();
    const r = computeReadiness('ten_demo');
    assert.ok(r.score >= 0 && r.score <= 100);
    assert.ok(r.factors.length >= 4);
    for (const f of r.factors) {
      assert.ok(f.label);
      assert.ok(f.detail);
    }
  });

  it('selects the baseline readiness run by stable ID/check after unrelated runs are prepended', () => {
    function storeWithUnrelatedFirst() {
      const store = buildPortalBaselineStore();
      store.testRuns.unshift({
        id: 'run_unrelated_prepend',
        tenant_id: PORTAL_BASELINE_IDS.tenantId,
        target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
        target_id: PORTAL_BASELINE_IDS.targetId,
        check_id: 'dns.authoritative_response.safe',
        status: 'completed',
        created_at: new Date().toISOString(),
      });
      return store;
    }

    const boostedStore = storeWithUnrelatedFirst();
    applyPortalBaselineReadinessBoost(boostedStore);
    const boostedEvent = boostedStore.events.find((event) => event.id === 'evt_portal_baseline_boost');
    assert.equal(boostedEvent.test_run_id, PORTAL_BASELINE_IDS.readinessRunId);
    assert.equal(boostedEvent.check_id, PORTAL_BASELINE_IDS.checkId);
    assert.equal(
      boostedStore.testRuns.find((run) => run.id === boostedEvent.test_run_id)?.check_id,
      boostedEvent.check_id,
    );
    assert.equal(
      boostedStore.verdicts.find((verdict) => verdict.id === 'vrd_portal_baseline_boost')?.test_run_id,
      PORTAL_BASELINE_IDS.readinessRunId,
    );
    resetStoreForTests(boostedStore);
    const boosted = computeReadiness(PORTAL_BASELINE_IDS.tenantId);

    const penalizedStore = storeWithUnrelatedFirst();
    applyPortalBaselineReadinessPenalty(penalizedStore);
    resetStoreForTests(penalizedStore);
    const penalized = computeReadiness(PORTAL_BASELINE_IDS.tenantId);

    for (const result of [boosted, penalized]) {
      assert.ok(Number.isInteger(result.score));
      assert.ok(result.score >= 0 && result.score <= 100);
      assert.ok(result.factors.length >= 4);
      assert.ok(result.factors.every((entry) => entry.key && entry.label && entry.detail));
    }
    assert.ok(boosted.score > penalized.score, `${boosted.score} must exceed ${penalized.score}`);
  });

  it('keeps portal-demo freshness and penalty scoring on the remapped tenant', () => {
    const boostedStore = buildPortalDemoStore();
    resetStoreForTests(boostedStore);

    const boosted = computeReadiness(PORTAL_DEMO_IDS.tenantId);
    assert.equal(boosted.score, 100);
    assert.equal(factor(boosted, 'soc_readiness').score, WEIGHT_SOC_GOVERNANCE);
    assert.match(factor(boosted, 'soc_readiness').detail, /hsr_demo_approved: authorization pack accepted/);
    assert.equal(factor(boosted, 'coverage').score, 44);
    assert.equal(factor(boosted, 'verdicts').score, WEIGHT_VERDICTS);
    assert.equal(factor(boosted, 'evidence_freshness').score, WEIGHT_EVIDENCE_FRESHNESS);
    assert.match(factor(boosted, 'evidence_freshness').detail, /1 run\(s\), 1 target group\(s\)/);

    const unmappedTenant = computeReadiness(PORTAL_BASELINE_IDS.tenantId);
    assert.equal(unmappedTenant.score, 0);
    assert.equal(factor(unmappedTenant, 'evidence_freshness').score, 0);

    const penalizedStore = buildPortalDemoStore();
    applyPortalBaselineReadinessPenalty(penalizedStore);
    const run = penalizedStore.testRuns.find((entry) => (
      entry.id === PORTAL_DEMO_IDS.runId && entry.check_id === PORTAL_BASELINE_IDS.checkId
    ));
    const penalty = penalizedStore.findings.find(
      (entry) => entry.id === 'fnd_portal_baseline_penalty',
    );
    assert.ok(run);
    assert.ok(penalty);
    assert.equal(penalty.tenant_id, PORTAL_DEMO_IDS.tenantId);
    assert.equal(penalty.test_run_id, run.id);
    assert.equal(penalty.target_group_id, run.target_group_id);
    assert.equal(penalty.target_id, run.target_id);
    assert.equal(penalty.check_id, run.check_id);
    assert.equal(
      penalizedStore.findings.some((entry) => (
        entry.id === penalty.id && entry.tenant_id === PORTAL_BASELINE_IDS.tenantId
      )),
      false,
    );

    resetStoreForTests(penalizedStore);
    const penalized = computeReadiness(PORTAL_DEMO_IDS.tenantId);
    assert.equal(penalized.score, 72);
    assert.equal(factor(penalized, 'verdicts').score, 0);
    assert.equal(factor(penalized, 'evidence_freshness').score, WEIGHT_EVIDENCE_FRESHNESS);
  });

  it('recomputes authoritative zero instead of returning stale unversioned score 97', () => {
    freshStore();
    const store = getStore();
    store.stateRollups.ten_demo = {
      readiness: { score: 97, factors: [], updated_at: '2025-01-01T00:00:00.000Z' },
    };

    const readiness = computeReadiness('ten_demo');

    assert.equal(store.stateRollups.ten_demo.readiness.score, 97);
    assert.equal(readiness.score, 0);
    assert.notStrictEqual(readiness, store.stateRollups.ten_demo.readiness);
  });

  it('empty tenant state stays explainable and does not award SOC points by absence', () => {
    freshStore();
    const r = computeReadiness('ten_demo');
    const soc = factor(r, 'soc_readiness');
    assert.equal(soc.score, 0);
    assert.match(soc.detail, /No high-scale governance evidence recorded yet/);
    const freshness = factor(r, 'evidence_freshness');
    assert.equal(freshness.score, 0);
    assert.match(freshness.detail, /No evidence-backed validations yet/);
    const verdictsFactor = factor(r, 'verdicts');
    assert.equal(verdictsFactor.score, 0);
    assert.match(verdictsFactor.detail, /absence of findings is not proof/i);
  });

  it('classifies readiness semantics from the authoritative catalog check', () => {
    for (const checkId of [
      'dns.authoritative_response.safe',
      'l3.forbidden_tcp_port.safe',
      'l3.forbidden_udp_port.safe',
      'pattern.carpet_bombing.readiness',
      'l7.http_method_restriction.safe',
      'protocol.http3_control_stream.readiness',
    ]) {
      assert.equal(catalogCheckSupportsReadiness(checkId), false, checkId);
    }
    assert.equal(catalogCheckSupportsReadiness('origin.direct_reachability.safe'), true);
    assert.equal(catalogCheckSupportsReadiness('ops.runbook_contact_validation.safe'), true);
    assert.equal(catalogCheckSupportsReadiness('unknown.check'), false);
    assert.equal(evidenceTierForProbeKind('http_method_matrix'), 'E2');
    assert.equal(evidenceTierForProbeKind('http3_control_probe'), 'E2');
  });

  it('stale completed run does not earn evidence freshness', () => {
    freshStore();
    const store = getStore();
    store.testRuns.push({
      id: 'run_stale',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: daysAgo(RECENT_EVIDENCE_WINDOW_DAYS + 5),
      created_at: daysAgo(RECENT_EVIDENCE_WINDOW_DAYS + 10),
    });
    const staleEvidenceAt = daysAgo(RECENT_EVIDENCE_WINDOW_DAYS + 5);
    const staleEvidenceId = addTrustedVerdictEvidence(
      store,
      'run_stale',
      'evt_stale',
      staleEvidenceAt,
    );
    store.verdicts.push({
      id: 'v_stale',
      tenant_id: 'ten_demo',
      test_run_id: 'run_stale',
      verdict: 'protected',
      created_at: staleEvidenceAt,
      evidence_ids: [staleEvidenceId],
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'evidence_freshness').score, 0);
    assert.match(factor(r, 'evidence_freshness').detail, /stale/i);
    assert.equal(factor(r, 'coverage').score, 0);
  });

  it('recent run without verdict/event/evidence does not earn freshness', () => {
    freshStore();
    getStore().testRuns.push({
      id: 'run_bare',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'completed',
      completed_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'evidence_freshness').score, 0);
    assert.match(factor(r, 'evidence_freshness').detail, /No evidence-backed validations yet/);
    assert.equal(factor(r, 'coverage').score, 0);
  });

  it('ignores an evidence-bound protected verdict for an authoritative observation-only check', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.testRuns.push({
      id: 'run_transport_only',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'dns.authoritative_response.safe',
      status: 'verdicted',
      completed_at: now,
      created_at: now,
    });
    store.events.push({
      id: 'evt_transport_only',
      tenant_id: 'ten_demo',
      test_run_id: 'run_transport_only',
      signal_type: 'probe_result',
      producer_kind: 'signed_probe',
      timestamp: now,
      metadata: { profile_kind: 'host_sni_bypass', external_result: 'blocked' },
    });
    store.verdicts.push({
      id: 'verdict_transport_only',
      tenant_id: 'ten_demo',
      test_run_id: 'run_transport_only',
      verdict: 'protected',
      evidence_ids: ['evt_transport_only'],
      created_at: now,
    });

    const readiness = computeReadiness('ten_demo');
    assert.equal(factor(readiness, 'coverage').score, 0);
    assert.equal(factor(readiness, 'verdicts').score, 0);
    assert.equal(factor(readiness, 'evidence_freshness').score, 0);
  });

  it('does not award readiness for vault evidence linked to a legacy reserved event', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.testRuns.push({
      id: 'run_legacy_link',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'completed',
      completed_at: now,
      created_at: now,
    });
    store.events.push({
      id: 'evt_legacy_link',
      tenant_id: 'ten_demo',
      test_run_id: 'run_legacy_link',
      signal_type: 'probe_result',
      producer_kind: 'legacy_untrusted',
      timestamp: now,
    });
    store.evidenceVault.push({
      id: 'evidence_legacy_link',
      tenant_id: 'ten_demo',
      test_run_id: 'run_legacy_link',
      related_event_id: 'evt_legacy_link',
      created_at: now,
    });

    const readiness = computeReadiness('ten_demo');
    assert.equal(factor(readiness, 'coverage').score, 0);
    assert.equal(factor(readiness, 'evidence_freshness').score, 0);
    assert.match(factor(readiness, 'evidence_freshness').detail, /No evidence-backed validations yet/);
  });

  it('quarantines a historical verdict that references only a legacy producer event', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.testRuns.push({
      id: 'run_legacy_verdict',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: now,
      created_at: now,
    });
    store.events.push({
      id: 'evt_legacy_verdict',
      tenant_id: 'ten_demo',
      test_run_id: 'run_legacy_verdict',
      signal_type: 'probe_result',
      producer_kind: 'legacy_untrusted',
      timestamp: now,
    });
    store.verdicts.push({
      id: 'verdict_legacy_only',
      tenant_id: 'ten_demo',
      test_run_id: 'run_legacy_verdict',
      verdict: 'protected',
      evidence_ids: ['evt_legacy_verdict'],
      created_at: now,
    });

    const readiness = computeReadiness('ten_demo');
    assert.equal(factor(readiness, 'coverage').score, 0);
    assert.equal(factor(readiness, 'verdicts').score, 0);
    assert.equal(factor(readiness, 'evidence_freshness').score, 0);
  });

  it('recent run with verdict/evidence earns freshness and coverage', () => {
    freshStore();
    const store = getStore();
    store.testRuns.push({
      id: 'run_recent',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    });
    store.verdicts.push({
      id: 'v_recent',
      tenant_id: 'ten_demo',
      test_run_id: 'run_recent',
      verdict: 'protected',
      created_at: new Date().toISOString(),
      evidence_ids: ['evt_1'],
    });
    store.events.push({
      id: 'evt_1',
      tenant_id: 'ten_demo',
      test_run_id: 'run_recent',
      signal_type: 'probe_result',
      timestamp: new Date().toISOString(),
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'evidence_freshness').score, WEIGHT_EVIDENCE_FRESHNESS);
    assert.equal(factor(r, 'coverage').score, 44);
    assert.match(factor(r, 'coverage').detail, /1 of 1 target group/);
  });

  it('preserves readiness credit for an evidence-bound ops readiness verdict', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.testRuns.push({
      id: 'run_ops_ready',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'ops.runbook_contact_validation.safe',
      status: 'verdicted',
      completed_at: now,
      created_at: now,
    });
    store.events.push({
      id: 'evt_ops_ready',
      tenant_id: 'ten_demo',
      test_run_id: 'run_ops_ready',
      signal_type: 'probe_result',
      producer_kind: 'signed_probe',
      timestamp: now,
      metadata: { external_result: 'connected', ops_validation_ok: true },
    });
    store.verdicts.push({
      id: 'verdict_ops_ready',
      tenant_id: 'ten_demo',
      test_run_id: 'run_ops_ready',
      verdict: 'protected',
      evidence_ids: ['evt_ops_ready'],
      created_at: now,
    });

    const readiness = computeReadiness('ten_demo');
    assert.equal(factor(readiness, 'coverage').score, 44);
    assert.equal(factor(readiness, 'verdicts').score, WEIGHT_VERDICTS);
    assert.equal(factor(readiness, 'evidence_freshness').score, WEIGHT_EVIDENCE_FRESHNESS);
  });

  it('high-scale request with accepted required artifacts and two distinct approvals earns SOC points', () => {
    freshStore();
    const store = getStore();
    const artifacts = REQUIRED_ARTIFACT_TYPES.map((type, i) => {
      const proof = artifactProofBody(type);
      return {
        id: `art_${i}`,
        type,
        status: 'accepted',
        approval_reference: proof.approval_reference,
        approver: proof.approver,
        valid_window: proof.valid_window,
        approved_scenario_families: proof.approved_scenario_families,
        max_rate: proof.max_rate,
        max_duration_minutes: proof.max_duration_minutes,
        emergency_contacts: proof.emergency_contacts,
        abort_criteria: proof.abort_criteria,
      };
    });
    store.highScaleRequests.push({
      id: 'hs_ok',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      state: 'approved',
      artifacts,
      soc_approvals: [
        { user_id: 'usr_a', at: new Date().toISOString() },
        { user_id: 'usr_b', at: new Date().toISOString() },
      ],
      audit_trail: [{ action: 'approve', at: new Date().toISOString() }],
    });

    const r = computeReadiness('ten_demo');
    const soc = factor(r, 'soc_readiness');
    assert.equal(soc.score, WEIGHT_SOC_GOVERNANCE);
    assert.match(soc.detail, /authorization pack accepted/i);
  });

  it('pending high-scale request without complete artifacts/approvals does not earn SOC points and explains missing gates', () => {
    freshStore();
    getStore().highScaleRequests.push({
      id: 'hs_pending',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      state: 'submitted',
      artifacts: [{ id: 'art_0', type: REQUIRED_ARTIFACT_TYPES[0], status: 'accepted' }],
      soc_approvals: [{ user_id: 'usr_a', at: new Date().toISOString() }],
      audit_trail: [],
    });

    const r = computeReadiness('ten_demo');
    const soc = factor(r, 'soc_readiness');
    assert.equal(soc.score, 0);
    assert.match(soc.detail, /gates remain/i);
    assert.match(soc.detail, /SOC approvals 1\/2/);
    assert.match(soc.detail, /missing accepted artifacts/i);
    assert.ok(REQUIRED_ARTIFACT_TYPES.includes('business_approval'));
    assert.ok(REQUIRED_ARTIFACT_TYPES.includes('legal_approval'));
  });

  it('future-dated run, verdict, and event do not earn freshness or coverage', () => {
    freshStore();
    const store = getStore();
    const future = daysAhead(3);
    store.testRuns.push({
      id: 'run_future',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: future,
      created_at: future,
    });
    store.verdicts.push({
      id: 'v_future',
      tenant_id: 'ten_demo',
      test_run_id: 'run_future',
      verdict: 'protected',
      created_at: future,
      evidence_ids: ['evt_future'],
    });
    store.events.push({
      id: 'evt_future',
      tenant_id: 'ten_demo',
      test_run_id: 'run_future',
      signal_type: 'probe_result',
      timestamp: future,
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'evidence_freshness').score, 0);
    assert.equal(factor(r, 'coverage').score, 0);
  });

  it('recent evidence-backed run for undeclared target group does not earn coverage', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.testRuns.push({
      id: 'run_undeclared_tg',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_not_declared',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: now,
      created_at: now,
    });
    store.verdicts.push({
      id: 'v_undeclared',
      tenant_id: 'ten_demo',
      test_run_id: 'run_undeclared_tg',
      verdict: 'protected',
      created_at: now,
      evidence_ids: ['evt_ud'],
    });
    store.events.push({
      id: 'evt_ud',
      tenant_id: 'ten_demo',
      test_run_id: 'run_undeclared_tg',
      signal_type: 'probe_result',
      timestamp: now,
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'coverage').score, 0);
    assert.match(factor(r, 'coverage').detail, /0 of 1 target group/);
  });

  it('recent verdict with no open findings earns full verdict factor', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.testRuns.push({
      id: 'run_v_ok',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: now,
      created_at: now,
    });
    const evidenceId = addTrustedVerdictEvidence(store, 'run_v_ok', 'evt_v_ok', now);
    store.verdicts.push({
      id: 'v_ok',
      tenant_id: 'ten_demo',
      test_run_id: 'run_v_ok',
      verdict: 'protected',
      created_at: now,
      evidence_ids: [evidenceId],
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'verdicts').score, WEIGHT_VERDICTS);
    assert.match(factor(r, 'verdicts').detail, /0 open finding/);
    assert.match(factor(r, 'verdicts').detail, /1 recent/);
  });

  it('open findings reduce verdict factor when recent verdicts exist', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.testRuns.push({
      id: 'run_x',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: now,
      created_at: now,
    });
    const evidenceId = addTrustedVerdictEvidence(store, 'run_x', 'evt_penalty', now);
    store.verdicts.push({
      id: 'v_penalty',
      tenant_id: 'ten_demo',
      test_run_id: 'run_x',
      verdict: 'exposed',
      created_at: now,
      evidence_ids: [evidenceId],
    });
    store.findings.push({
      id: 'f_1',
      tenant_id: 'ten_demo',
      status: 'open',
      severity: 'high',
    });
    store.findings.push({
      id: 'f_2',
      tenant_id: 'ten_demo',
      status: 'open',
      severity: 'medium',
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'verdicts').score, WEIGHT_VERDICTS - 20);
    assert.match(factor(r, 'verdicts').detail, /2 open finding/);
    assert.match(factor(r, 'verdicts').detail, /1 recent/);
  });
  it('stale-only verdicts do not earn full verdict factor credit', () => {
    freshStore();
    const store = getStore();
    const oldEvidenceAt = daysAgo(RECENT_EVIDENCE_WINDOW_DAYS + 2);
    store.testRuns.push({
      id: 'run_old',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: oldEvidenceAt,
      created_at: oldEvidenceAt,
    });
    const evidenceId = addTrustedVerdictEvidence(store, 'run_old', 'evt_old', oldEvidenceAt);
    store.verdicts.push({
      id: 'v_old',
      tenant_id: 'ten_demo',
      test_run_id: 'run_old',
      verdict: 'protected',
      created_at: oldEvidenceAt,
      evidence_ids: [evidenceId],
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'verdicts').score, 0);
    assert.match(factor(r, 'verdicts').detail, /0 recent/);
    assert.match(factor(r, 'verdicts').detail, /stale/i);
    assert.match(factor(r, 'verdicts').detail, /does not support full posture credit/i);
  });
});