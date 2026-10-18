import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { computeReadiness, evidenceBackedVerdictForRun, RECENT_EVIDENCE_WINDOW_DAYS } from '../../src/services/readiness.mjs';
import { coverageFrom, summarizePairs } from '../../src/lib/protectionCoverage.mjs';
import { projectReadiness, verifiedVerdicts } from '../../src/lib/readinessProjection.mjs';
import { getTargetDetail } from '../../src/services/targetDetail.mjs';
import { maybeFinalizeRunAfterProbeIngest } from '../../src/services/testRuns.mjs';
import { CHECK_CATALOG, getCheckById } from '../../src/contracts/checks.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { assuranceWorld, addAssuredObservation, ASSURANCE_NOW } from '../helpers/assurance-fixtures.mjs';
import { buildPortalBaselineStore, PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';
import { buildPortalDemoStore, PORTAL_DEMO_IDS } from '../fixtures/portal-demo/seed.mjs';
import { applyPortalBaselineReadinessBoost, applyPortalBaselineReadinessPenalty } from '../fixtures/portal-baseline/readiness.mjs';
const factor = (result, key) => result.factors.find((entry) => entry.key === key);
function dev(world) {
  resetStoreForTests({ targets: world.targets, targetGroups: world.groups, testPolicies: world.policies, testRuns: world.runs, verdicts: world.verdicts, events: world.events, evidenceVault: world.evidenceItems, findings: world.findings, highScaleRequests: world.highScaleRequests, auditLog: [], socKillSwitch: world.killSwitch, stateRollups: world.legacy_snapshot ? { [world.tenantId]: { readiness: world.legacy_snapshot } } : {} });
  return computeReadiness(world.tenantId, { now: world.asOf, catalog: world.catalog });
}

describe('versioned conservative readiness', () => {
  it('publishes an explainable seven-day assessment, not capacity or all-path protection', () => {
    const world = assuranceWorld(); addAssuredObservation(world);
    const result = projectReadiness(world);
    assert.equal(result.score, 100); assert.equal(result.assessment_version, 'readiness-assessment.v3');
    assert.equal(RECENT_EVIDENCE_WINDOW_DAYS, 7); assert.equal(result.confidence, 'external_only');
    assert.equal(result.coverage.passed_count, 1); assert.equal(result.current_assurance.status, 'tested_scenarios_only');
    assert.ok(result.factors.every((entry) => entry.label && entry.detail));
  });
  it('rejects contradictory/missing performed positives and wrong/missing nonce or ingestion identically in dev without custody edits', () => {
    for (const outcome of ['protected', 'edge_protected', 'pass', 'passed', 'success', 'ok']) {
      for (const mutate of [
        (w) => { w.events[0].metadata.enforcement = 'not_enforced'; },
        (w) => { delete w.events[0].metadata.enforcement; },
        (w) => { w.events[0].nonce_hash = 'another_run_nonce'; },
        (w) => { delete w.runs[0].correlation; },
        (w) => { delete w.events[0].ingested_at; },
      ]) {
        const world = assuranceWorld(); addAssuredObservation(world, { outcome });
        mutate(world);
        const custody = JSON.stringify([world.runs, world.events, world.verdicts]);
        const result = projectReadiness(world);
        assert.equal(result.score, 0, outcome); assert.equal(result.coverage.passed_count, 0, outcome);
        assert.deepEqual(dev(world), result, outcome);
        assert.equal(JSON.stringify([world.runs, world.events, world.verdicts]), custody);
      }
    }
  });
  it('only credits allowed_as_expected when actual nonce canary identity matches the explicit allow expectation', () => {
    const world = assuranceWorld(); world.targets[0].expected_behavior = 'must_reach_canary';
    const { event } = addAssuredObservation(world, { outcome: 'allowed_as_expected' });
    event.metadata.application_identity = { confirmed: true, method: 'nonce_canary' };
    assert.equal(projectReadiness(world).score, 100);
    event.metadata.application_identity.method = 'header_similarity';
    assert.equal(projectReadiness(world).score, 0);
  });
  it('does not collapse the same check across multiple targets', () => {
    const world = assuranceWorld({ targetCount: 2 }); addAssuredObservation(world);
    const result = projectReadiness(world);
    assert.equal(result.score, 50); assert.equal(result.coverage.applicable_count, 2); assert.equal(result.coverage.not_run_count, 1);
    assert.deepEqual(result.posture, { pass: 1, gap: 0, not_run: 1, review: 0, total: 2 });
  });
  it('counts never-run scenarios as not run, never as review, and the posture buckets sum to the applicable total', () => {
    const world = assuranceWorld({ targetCount: 3, checkCount: 2 });
    const result = projectReadiness(world);
    assert.equal(result.coverage.applicable_count, 6);
    assert.deepEqual(result.posture, { pass: 0, gap: 0, not_run: result.coverage.applicable_count, review: 0, total: result.coverage.applicable_count });
    for (const outcome of ['protected', 'exposed', 'inconclusive']) {
      const observed = assuranceWorld({ targetCount: 2 }); addAssuredObservation(observed, { outcome });
      const { pass, gap, not_run: notRun, review, total } = projectReadiness(observed).posture;
      assert.equal(pass + gap + notRun + review, total, outcome);
      assert.equal(notRun, 1, outcome);
    }
  });
  it('bounds a narrow sample by the complete target/check denominator', () => {
    const world = assuranceWorld({ targetCount: 3, checkCount: 4 }); addAssuredObservation(world);
    assert.equal(projectReadiness(world).score, 8);
    const broad = projectReadiness({ ...world, catalog: CHECK_CATALOG });
    assert.ok(broad.coverage.applicable_count > 12); assert.ok(broad.score < 8);
  });
  it('distinguishes severity and reports accepted-risk findings without subtracting', () => {
    const world = assuranceWorld(); addAssuredObservation(world);
    for (const [severity, expected] of [['low', 99], ['medium', 95], ['high', 90], ['critical', 80]]) {
      world.findings = [{ id: 'f', tenant_id: world.tenantId, target_id: world.targets[0].id, severity, status: 'open' }];
      assert.equal(projectReadiness(world).score, expected);
    }
    world.findings[0].status = 'accepted_risk';
    world.findings[0].risk_acceptance = { review_at: '2026-12-01T00:00:00.000Z' };
    assert.equal(projectReadiness(world).score, 100);
    assert.equal(projectReadiness(world).findings.accepted_risk_count, 1);
    assert.equal(projectReadiness(world).findings.unresolved_count, 0);
    world.findings[0].status = 'closed'; assert.equal(projectReadiness(world).score, 100);
  });
  it('gives gaps and inconclusive results no positive credit without treating unknown as exposed', () => {
    for (const outcome of ['exposed', 'inconclusive', 'skipped', 'unknown']) {
      const world = assuranceWorld(); addAssuredObservation(world, { outcome }); const result = projectReadiness(world);
      assert.equal(result.score, 0); assert.equal(result.posture.gap, outcome === 'exposed' ? 1 : 0);
      assert.equal(result.posture.pass, 0);
    }
  });
  it('never grants protection credit for kill-switch governance alone (audited)', () => {
    const world = assuranceWorld(); world.killSwitch = { tenant_id: world.tenantId, updated_at: world.asOf, active: false };
    const result = dev(world); assert.equal(result.score, 0); assert.equal(result.governance.status, 'recorded'); assert.equal(result.governance.protection_credit, 0);
  });
  it('does not renew stale evidence through mutable metadata or new vault timestamps (audited)', () => {
    const world = assuranceWorld(); const { run, event, verdict } = addAssuredObservation(world, { observedAt: '2026-09-01T12:00:00.000Z' });
    run.updated_at = world.asOf; verdict.created_at = world.asOf;
    world.evidenceItems.push({ id: 'ev_fresh', tenant_id: world.tenantId, test_run_id: run.id, related_event_id: event.id, created_at: world.asOf }); verdict.evidence_ids = ['ev_fresh'];
    const result = dev(world); assert.equal(result.score, 0); assert.equal(result.coverage.stale_count, 1); assert.equal(result.current_assurance.retest_required_count, 1);
  });
  it('uses the oldest required result rather than a newly completed leg', () => {
    const world = assuranceWorld(); const { run, event, verdict } = addAssuredObservation(world);
    const old = { ...structuredClone(event), id: 'old_leg', timestamp: '2026-09-01T12:00:00.000Z' }; world.events.push(old); verdict.evidence_ids.push(old.id);
    run.completed_at = world.asOf; assert.equal(projectReadiness(world).coverage.stale_count, 1);
  });
  for (const field of ['timestamp', 'created_at', 'ingested_at']) it(`rejects future ${field} even when other event times are current`, () => {
    const world = assuranceWorld(); const { event } = addAssuredObservation(world); event[field] = '2026-10-09T00:00:00.000Z';
    assert.equal(projectReadiness(world).score, 0);
  });
  it('requires every referenced evidence ID to resolve to signed same-run same-tenant result', () => {
    for (const mutation of ['missing', 'foreign', 'other_run', 'activity', 'legacy', 'unlinked_vault']) {
      const world = assuranceWorld(); const { run, event, verdict } = addAssuredObservation(world);
      if (mutation === 'missing') verdict.evidence_ids.push('missing');
      if (mutation === 'foreign') event.tenant_id = 'other';
      if (mutation === 'other_run') event.test_run_id = 'another';
      if (mutation === 'activity') event.signal_type = 'probe_activity';
      if (mutation === 'legacy') event.producer_kind = 'legacy_untrusted';
      if (mutation === 'unlinked_vault') { world.evidenceItems.push({ id: 'vault', test_run_id: run.id, tenant_id: world.tenantId, created_at: world.asOf }); verdict.evidence_ids = ['vault']; }
      assert.equal(projectReadiness(world).score, 0, mutation);
    }
  });
  it('retains missing versus invalid citation reasons identically in readiness and target detail without custody edits', () => {
    for (const mutation of ['absent', 'empty', 'malformed', 'blank_id', 'unresolved', 'mixed_activity', 'wrong_nonce', 'foreign', 'other_run', 'untrusted', 'missing_ingestion', 'future_ingestion', 'unlinked_vault']) {
      const world = assuranceWorld();
      world.asOf = new Date().toISOString();
      const { run, event, verdict } = addAssuredObservation(world, { observedAt: world.asOf });
      if (mutation === 'absent') delete verdict.evidence_ids;
      if (mutation === 'empty') verdict.evidence_ids = [];
      if (mutation === 'malformed') verdict.evidence_ids = event.id;
      if (mutation === 'blank_id') verdict.evidence_ids = [''];
      if (mutation === 'unresolved') verdict.evidence_ids = ['missing'];
      if (mutation === 'mixed_activity') {
        world.events.push({ ...structuredClone(event), id: 'activity', signal_type: 'probe_activity' });
        verdict.evidence_ids.push('activity');
      }
      if (mutation === 'wrong_nonce') event.nonce_hash = 'wrong';
      if (mutation === 'foreign') event.tenant_id = 'foreign';
      if (mutation === 'other_run') event.test_run_id = 'other_run';
      if (mutation === 'untrusted') event.producer_kind = 'public_api';
      if (mutation === 'missing_ingestion') delete event.ingested_at;
      if (mutation === 'future_ingestion') event.ingested_at = new Date(Date.now() + 86400000).toISOString();
      if (mutation === 'unlinked_vault') {
        world.evidenceItems.push({ id: 'vault', tenant_id: world.tenantId, test_run_id: run.id, created_at: world.asOf });
        verdict.evidence_ids = ['vault'];
      }
      const before = JSON.stringify([world.runs, world.events, world.verdicts]);
      assert.equal(verifiedVerdicts({ ...world, nowMs: Date.parse(world.asOf) }).size, 0, mutation);
      const readiness = dev(world);
      const pair = getTargetDetail({ tenantId: world.tenantId, role: 'engineer' }, run.target_id).coverage.pairs.find((row) => row.check_id === run.check_id);
      assert.equal(readiness.score, 0, mutation);
      assert.equal(readiness.coverage.unknown_count, 1, mutation);
      assert.equal(pair.pair_reason, ['absent', 'empty'].includes(mutation) ? 'no_evidence' : 'invalid_or_unresolved_evidence', mutation);
      assert.equal(pair.retained.verdict, verdict.verdict, mutation);
      assert.equal(pair.live_external, false, mutation);
      assert.equal(JSON.stringify([world.runs, world.events, world.verdicts]), before, mutation);
    }
  });
  it('does not fall back to an older valid publication when a newer publication has invalid citations', () => {
    const world = assuranceWorld(); const { verdict } = addAssuredObservation(world);
    world.verdicts.push({ ...verdict, id: 'newer', created_at: world.asOf, evidence_ids: ['missing'] });
    const before = structuredClone(world);
    assert.equal(verifiedVerdicts({ ...world, nowMs: Date.parse(world.asOf) }).size, 0);
    assert.equal(projectReadiness(world).coverage.unknown_count, 1);
    assert.equal(projectReadiness(world).score, 0);
    assert.deepEqual(world, before);
  });
  it('publishes only the signed result actually evaluated, excluding activity and contradictory run cache', () => {
    const world = assuranceWorld(); world.asOf = new Date().toISOString();
    const { run, event } = addAssuredObservation(world, { observedAt: world.asOf, outcome: 'inconclusive' });
    world.verdicts = [];
    run.status = 'collecting'; run.completed_at = null;
    run.collection_deadline_at = '2000-01-01T00:00:00.000Z';
    run.probe_external_result = 'blocked';
    event.metadata.external_result = 'timeout';
    world.events.unshift({ ...structuredClone(event), id: 'activity_before', signal_type: 'probe_activity' });
    world.events.push({ ...structuredClone(event), id: 'activity_after', signal_type: 'probe_activity' });
    dev(world);
    const beforeEvents = structuredClone(getStore().events);
    const published = maybeFinalizeRunAfterProbeIngest({ tenantId: world.tenantId, role: 'system' }, run.id);
    assert.equal(published.verdict, 'inconclusive');
    assert.deepEqual(published.evidence_ids, [event.id]);
    assert.equal(verifiedVerdicts({ tenantId: world.tenantId, runs: getStore().testRuns,
      verdicts: getStore().verdicts, events: getStore().events }).size, 1);
    assert.equal(computeReadiness(world.tenantId).score, 0);
    assert.deepEqual(getStore().events, beforeEvents);
    const custody = structuredClone(getStore().verdicts);
    maybeFinalizeRunAfterProbeIngest({ tenantId: world.tenantId, role: 'system' }, run.id);
    assert.deepEqual(getStore().verdicts, custody);
  });
  it('keeps a complete signed positive publish eligible alongside uncited activity, but never upgrades a result-free cache', () => {
    for (const hasResult of [true, false]) {
      const world = assuranceWorld(); world.asOf = new Date().toISOString();
      const { run, event } = addAssuredObservation(world, { observedAt: world.asOf });
      world.verdicts = []; run.status = 'collecting'; run.completed_at = null;
      run.collection_deadline_at = '2000-01-01T00:00:00.000Z'; run.probe_external_result = 'blocked';
      event.metadata.external_result = 'blocked';
      event.metadata.safety_attestation = { probe_requests_sent: 4, destination_resolver_attempts: 2, total_operations: 6, requests_sent: 6, duration_ms: 10 };
      world.events = [{ ...structuredClone(event), id: 'activity', signal_type: 'probe_activity' }, ...(hasResult ? [event] : [])];
      dev(world);
      const verdict = maybeFinalizeRunAfterProbeIngest({ tenantId: world.tenantId, role: 'system' }, run.id);
      assert.deepEqual(verdict.evidence_ids, hasResult ? [event.id] : []);
      assert.equal(hasResult ? ['protected', 'edge_protected'].includes(verdict.verdict) : verdict.verdict === 'inconclusive', true);
      const pair = getTargetDetail({ tenantId: world.tenantId, role: 'engineer' }, run.target_id).coverage.pairs.find((row) => row.check_id === run.check_id);
      assert.equal(pair.live_external, hasResult);
      assert.equal(pair.retained.verdict, verdict.verdict);
      if (!hasResult) assert.equal(pair.pair_reason, 'no_evidence');
    }
  });
  it('never publishes a protected result from missing, empty, mismatched nonce or foreign-tenant evidence', () => {
    for (const mismatch of ['missing_nonce', 'empty_nonce', 'wrong_nonce', 'foreign_tenant']) {
      const world = assuranceWorld(); world.asOf = new Date().toISOString();
      const { run, event } = addAssuredObservation(world, { observedAt: world.asOf });
      world.verdicts = []; run.status = 'collecting'; run.completed_at = null;
      run.collection_deadline_at = '2000-01-01T00:00:00.000Z'; run.probe_external_result = 'blocked';
      event.metadata.external_result = 'blocked';
      event.metadata.safety_attestation = { probe_requests_sent: 4 };
      if (mismatch === 'missing_nonce') { delete run.correlation; delete event.nonce_hash; }
      if (mismatch === 'empty_nonce') { run.correlation.nonce_hash = ''; event.nonce_hash = ''; }
      if (mismatch === 'wrong_nonce') event.nonce_hash = 'different_run';
      if (mismatch === 'foreign_tenant') event.tenant_id = 'ten_foreign';
      dev(world);
      const beforeEvents = structuredClone(getStore().events);
      const verdict = maybeFinalizeRunAfterProbeIngest({ tenantId: world.tenantId, role: 'system' }, run.id);
      assert.equal(verdict.verdict, 'inconclusive', mismatch);
      assert.deepEqual(verdict.evidence_ids, [], mismatch);
      assert.equal(computeReadiness(world.tenantId).score, 0, mismatch);
      assert.deepEqual(getStore().events, beforeEvents, mismatch);
    }
  });
  it('simulation and manual provenance remain retained without live readiness credit', () => {
    for (const producer of ['internal_simulation', 'manual_declaration', 'customer_declaration']) {
      const world = assuranceWorld(); world.asOf = new Date().toISOString();
      const { run, event } = addAssuredObservation(world, { observedAt: world.asOf });
      run.producer_kind = producer;
      event.producer_kind = producer;
      dev(world);
      const pair = getTargetDetail({ tenantId: world.tenantId, role: 'engineer' }, run.target_id).coverage.pairs.find((row) => row.check_id === run.check_id);
      assert.equal(pair.retained.verdict, 'protected');
      assert.equal(pair.pair_reason, producer === 'internal_simulation' ? producer : 'manual_declaration');
      assert.equal(pair.live_external, false);
      assert.equal(computeReadiness(world.tenantId).score, 0);
    }
  });
  it('accepts an actual linked same-run vault record without changing observation age', () => {
    const world = assuranceWorld(); const { run, event, verdict } = addAssuredObservation(world);
    world.evidenceItems.push({ id: 'vault', related_event_id: event.id, test_run_id: run.id, tenant_id: world.tenantId, created_at: world.asOf }); verdict.evidence_ids = ['vault'];
    assert.equal(dev(world).score, 100); assert.equal(evidenceBackedVerdictForRun(getStore(), run.id).id, verdict.id);
  });
  for (const field of ['check_version', 'scenario_version']) it(`invalidates incompatible ${field} while retaining immutable run/verdict`, () => {
    const world = assuranceWorld(); const { run } = addAssuredObservation(world); run[field] = 'old'; const before = structuredClone(world.runs);
    const result = projectReadiness(world); assert.equal(result.score, 0); assert.equal(result.coverage.partial_count, 1); assert.deepEqual(world.runs, before);
  });
  it('invalidates changed definition digest even if explicit catalog version was not bumped', () => {
    const world = assuranceWorld(); addAssuredObservation(world); world.catalog[0].probe_profile.timeout_ms -= 1;
    assert.ok(projectReadiness(world).current_assurance.reasons.includes('check_definition_changed'));
  });
  it('invalidates exact URL path and expected behavior changes but not target names or tags', () => {
    const world = assuranceWorld(); addAssuredObservation(world);
    world.targets[0].name = 'Presentation change'; world.targets[0].tags = ['critical']; assert.equal(projectReadiness(world).score, 100);
    world.targets[0].value += '/new'; const result = projectReadiness(world);
    assert.equal(result.score, 0); assert.ok(result.current_assurance.reasons.includes('target_definition_changed'));
  });
  it('invalidates material policy revisions and current group safety changes', () => {
    const world = assuranceWorld(); const policy = { id: 'pol', tenant_id: world.tenantId, target_id: world.targets[0].id, target_group_id: 'tg_1', check_id: world.catalog[0].check_id, expected_verdict: 'pass', schedule_revision: 1, enabled: true, state: 'active', safety_policy_snapshot: {} }; world.policies.push(policy); addAssuredObservation(world, { policy });
    assert.equal(projectReadiness(world).score, 100); policy.schedule_revision = 2;
    assert.ok(projectReadiness(world).current_assurance.reasons.includes('policy_definition_changed'));
    policy.schedule_revision = 1; world.groups[0].safety_policy = { max_events: 1 }; assert.ok(projectReadiness(world).current_assurance.reasons.includes('target_group_definition_changed'));
  });
  it('selects latest attempt immutably; pending attempt never borrows older passing evidence', () => {
    const world = assuranceWorld(); addAssuredObservation(world); world.runs.push({ ...world.runs[0], id: 'pending', started_at: world.asOf, created_at: world.asOf, completed_at: null, status: 'collecting' }); world.runs.reverse();
    assert.equal(projectReadiness(world).score, 0); assert.equal(projectReadiness(world).coverage.unknown_count, 1);
  });
  it('quarantines incomplete, observation-only, unhealthy and missing planned marker evidence', () => {
    const mutations = [{ observation_only: true }, { readiness_conclusion: false }, { comparison_complete: false },
      { completed_marker_legs: 1 }, { attempted_marker_legs: 1 }, { planned_marker_legs: 0 }, { graded_marker_legs: 0 },
      { ungraded_marker_legs: 1 }, { missing_marker_legs: 1 }, { permitted_baseline_health: 'unhealthy' },
      { trailing_control: { outcome: 'blocked' } }, { source_penalized: true }, { classifier_version: 'marker-comparison-v4' }];
    for (const mutation of mutations) { const world = assuranceWorld(); const { event } = addAssuredObservation(world); Object.assign(event.metadata, mutation); assert.equal(projectReadiness(world).score, 0, JSON.stringify(mutation)); }
    const world = assuranceWorld(); const { event } = addAssuredObservation(world); event.metadata = {}; assert.equal(projectReadiness(world).score, 0);
  });
  it('requires complete performed v5 proof on every cited result, never mutable summaries or aborted required legs', () => {
    const world = assuranceWorld(); const { run, event, verdict } = addAssuredObservation(world);
    run.probe_metadata = structuredClone(event.metadata);
    run.summary_json = { ...structuredClone(event.metadata) };
    const original = structuredClone(event.metadata);
    event.metadata = { enforcement: 'enforced' };
    assert.equal(projectReadiness(world).score, 0);
    event.metadata = original;
    const incomplete = { ...structuredClone(event), id: 'uncompleted_leg', metadata: { enforcement: 'enforced' } };
    world.events.push(incomplete); verdict.evidence_ids.push(incomplete.id);
    assert.equal(projectReadiness(world).score, 0);
    world.events.pop(); verdict.evidence_ids.pop();
    // A delivered but ungraded leg remains part of the complete selected plan,
    // not an invented blocked leg or transport failure.
    event.metadata.graded_marker_legs = 1; event.metadata.ungraded_marker_legs = 1;
    assert.equal(projectReadiness(world).score, 100);
    event.metadata.completed_marker_legs = 1;
    assert.equal(projectReadiness(world).score, 0);
  });
  it('excludes catalog E1/E2 and reports setup-required independently', () => {
    const world = assuranceWorld(); world.targets[0].kind = 'fqdn'; world.targets[0].value = 'app.example.test'; world.catalog.push(getCheckById('dns.authoritative_response.safe'), getCheckById('ops.runbook_contact_validation.safe'), getCheckById('origin.host_sni_bypass.safe'), { ...structuredClone(world.catalog[0]), check_id: 'waf.fixture_setup.safe', required_customer_setup: ['declared_fixture_probe_path'] });
    const result = projectReadiness(world); assert.equal(result.coverage.applicable_count, 1); assert.ok(result.coverage.observation_only_count >= 1); assert.ok(result.coverage.setup_required_count >= 1); assert.equal(result.score, 0);
  });
  it('requires complete inputs rather than inventing estate completeness from a bounded feed', () => {
    const world = assuranceWorld(); addAssuredObservation(world); world.input_complete = false; const result = projectReadiness(world);
    assert.equal(result.score, null); assert.equal(result.score_status, 'incomplete_inputs');
  });
  it('preserves labelled nonauthoritative legacy score and normalizes no-credit factors to positive zero', () => {
    const world = assuranceWorld(); world.legacy_snapshot = { score: 97, updated_at: '2025-01-01T00:00:00.000Z' };
    const result = dev(world); assert.equal(result.score, 0); assert.equal(result.legacy_snapshot.snapshot.score, 97); assert.equal(result.legacy_snapshot.authoritative, false);
    assert.equal(Object.is(factor(result, 'verdicts').score, -0), false); assert.equal(getStore().stateRollups[world.tenantId].readiness.score, 97);
  });
  it('keeps trust/tenant scoping and excludes deleted or undeclared target cohorts', () => {
    const world = assuranceWorld({ targetCount: 2 }); addAssuredObservation(world);
    world.targets[0].deleted_at = world.asOf; world.targets[1].target_group_id = 'missing';
    assert.equal(projectReadiness(world).score, 0); assert.equal(projectReadiness(world).coverage.target_count, 0);
    assert.equal(projectReadiness({ ...world, tenantId: 'other' }).score, 0);
  });
  it('shared pure/dev projection is exactly identical with complete inputs', () => {
    const world = assuranceWorld({ targetCount: 2 }); addAssuredObservation(world); world.findings.push({ id: 'f', tenant_id: world.tenantId, severity: 'high', status: 'open' });
    assert.deepEqual(dev(world), projectReadiness(world));
  });
  it('withdraws current credit after explicit port/protocol changes and scope-version mismatch without rewriting custody', () => {
    for (const change of [{ port: 8443 }, { protocol: 'http' }]) {
      const world = assuranceWorld(); Object.assign(world.targets[0], { port: 443, protocol: 'https' });
      addAssuredObservation(world); const custody = structuredClone({ runs: world.runs, verdicts: world.verdicts, events: world.events });
      assert.equal(projectReadiness(world).score, 100);
      Object.assign(world.targets[0], change);
      assert.equal(projectReadiness(world).score, 0);
      assert.equal(projectReadiness(world).current_assurance.status, 'retest_required');
      assert.deepEqual({ runs: world.runs, verdicts: world.verdicts, events: world.events }, custody);
    }
    const legacy = assuranceWorld(); addAssuredObservation(legacy);
    legacy.runs[0].safety_constraints.assurance_scope.version = 'assurance-scope.v1';
    assert.equal(projectReadiness(legacy).score, 0);
    const unstamped = assuranceWorld(); addAssuredObservation(unstamped);
    delete unstamped.runs[0].safety_constraints.assurance_scope;
    const custody = JSON.stringify([unstamped.runs, unstamped.verdicts, unstamped.events]);
    assert.equal(projectReadiness(unstamped).score, 0);
    assert.equal(projectReadiness(unstamped).current_assurance.status, 'retest_required');
    assert.equal(JSON.stringify([unstamped.runs, unstamped.verdicts, unstamped.events]), custody);
  });
  it('credits only exact signed complete reviewed marker edge denial, not raw edge verdicts', () => {
    const world = assuranceWorld(); const proof = addAssuredObservation(world, { outcome: 'edge_protected' });
    assert.equal(projectReadiness(world).score, 100);
    for (const mutate of [
      w => { w.events[0].producer_kind = 'legacy_untrusted'; },
      w => { w.events[0].metadata.comparison_complete = false; },
      w => { w.events[0].metadata.permitted_baseline_health = 'unhealthy'; },
      w => { w.catalog[0].observation_only = true; },
      w => { w.catalog[0].requires_complete_comparison = false; w.catalog[0].probe_profile.kind = 'http_head'; },
    ]) { const copy = structuredClone(world); mutate(copy); assert.equal(projectReadiness(copy).score, 0); }
    assert.equal(proof.verdict.verdict, 'edge_protected');
  });
  it('complete grouped finding accounting equals raw records without losing tenant, scope, time or severity', () => {
    const world = assuranceWorld(); addAssuredObservation(world);
    world.findings = [
      ...Array.from({ length: 4 }, (_, index) => ({ id: `finding_${index}`, tenant_id: world.tenantId, target_id: world.targets[0].id, status: 'open', severity: 'medium', created_at: world.asOf })),
      { id: 'accepted', tenant_id: world.tenantId, target_id: world.targets[0].id, status: 'accepted_risk', severity: 'high', created_at: world.asOf },
      { id: 'foreign', tenant_id: 'other', status: 'open', severity: 'critical', created_at: world.asOf },
      { id: 'removed', tenant_id: world.tenantId, target_id: 'removed_target', status: 'open', severity: 'critical', created_at: world.asOf },
      { id: 'future', tenant_id: world.tenantId, status: 'open', severity: 'critical', created_at: '2026-10-10T00:00:00.000Z' },
    ];
    const findingCounts = [{ ...world.findings[0], count: 4 }, ...world.findings.slice(4, 7).map((row) => ({ ...row, count: 1 }))];
    const grouped = { ...world, findings: [], findingCounts, finding_counts_complete: true };
    assert.deepEqual(projectReadiness(grouped), projectReadiness(world));
    assert.equal(projectReadiness(grouped).findings.unresolved_count, 4);
    assert.equal(projectReadiness(grouped).findings.accepted_risk_count, 1);
    assert.deepEqual(projectReadiness({ ...grouped, findings: world.findings }), projectReadiness(grouped), 'grouped counts replace raw records, never double-count them');
    assert.equal(projectReadiness({ ...grouped, findingCounts: [...findingCounts, { ...findingCounts[0], created_at: '2026-10-10T00:00:00.000Z' }] }).score, null);
    assert.equal(projectReadiness({ ...grouped, finding_counts_complete: false }).score, null);
    grouped.findingCounts[0].count = -1;
    assert.equal(projectReadiness(grouped).score_status, 'incomplete_inputs');
  });
  it('weighted blank target projection exactly matches fully expanded per-target applicability', () => {
    const world = assuranceWorld({ targetCount: 100 });
    for (let index = 0; index < world.targets.length; index++) {
      if (index % 3 === 1) Object.assign(world.targets[index], { kind: 'fqdn', value: `host${index}.example.test` });
      if (index % 3 === 2) Object.assign(world.targets[index], { kind: 'ip', value: '203.0.113.10' });
    }
    addAssuredObservation(world);
    const allPairs = world.targets.flatMap((target) => coverageFrom({ target, targetGroup: world.groups[0],
      observations: target.id === world.targets[0].id ? [{ run: { ...world.runs[0], readiness_result_metadata: [world.events[0].metadata] }, verdict: world.verdicts[0], observed_at: world.events[0].timestamp, evidence_verified: true }] : [],
      catalog: CHECK_CATALOG, nowMs: Date.parse(world.asOf) }).coverage.pairs);
    const expanded = summarizePairs(allPairs);
    const grouped = projectReadiness({ ...world, catalog: CHECK_CATALOG });
    for (const [key, value] of Object.entries(expanded)) assert.deepEqual(grouped.coverage[key], value, key);
    assert.equal(grouped.coverage.target_count, world.targets.length);
    assert.equal(grouped.coverage.observation_only_count, allPairs.filter((pair) => pair.exclusion_reason === 'observation_only').length);
  });
  it('keeps legacy baseline custody untouched while a broad new fixture cohort supplies current proof', () => {
    const store = buildPortalBaselineStore();
    const original = structuredClone(store.testRuns.find((row) => row.id === PORTAL_BASELINE_IDS.readinessRunId));
    store.testRuns.unshift({ id: 'unrelated', check_id: 'dns.authoritative_response.safe', created_at: ASSURANCE_NOW });
    const { run } = applyPortalBaselineReadinessBoost(store);
    assert.deepEqual(store.testRuns.find((row) => row.id === original.id), original);
    assert.notEqual(run.id, original.id);
    assert.ok(store.events.filter((row) => String(row.test_run_id).startsWith('run_portal_assurance_')).length > 20);
    resetStoreForTests(store);
    const boosted = computeReadiness(PORTAL_BASELINE_IDS.tenantId);
    assert.ok(boosted.score > 0);
    assert.ok(boosted.coverage.observed_target_count >= 2);
    assert.ok(boosted.score < 100, 'untested targets and scenarios remain in the complete denominator');
    applyPortalBaselineReadinessPenalty(store);
    assert.equal(store.findings.find((row) => row.id === 'fnd_portal_baseline_penalty').tenant_id, PORTAL_BASELINE_IDS.tenantId);
    assert.ok(computeReadiness(PORTAL_BASELINE_IDS.tenantId).score < boosted.score);
    const demo = buildPortalDemoStore(); resetStoreForTests(demo);
    assert.equal(computeReadiness(PORTAL_DEMO_IDS.tenantId, { now: ASSURANCE_NOW }).score, 0);
    assert.equal(computeReadiness(PORTAL_BASELINE_IDS.tenantId, { now: ASSURANCE_NOW }).score, 0);
  });
});
