import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  approvedScenarioVersion,
  deriveCheckDefinitionVersion,
  deriveRunEvidenceStamp,
  canonicalDefinitionDigest,
} from '../../src/lib/checkDefinitionVersion.mjs';
import {
  acceptTargetObservation,
  appendTargetObservation,
  assessComparability,
  classifyAttempt,
  compareObservationOrder,
  decodeObservationCursor,
  encodeObservationCursor,
  getCurrentFamilyState,
  listObservationsForTests,
  listTargetObservations,
  normalizeObservationTimestamp,
} from '../../src/services/targetHistory.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { planFindingPatch } from '../../src/services/findings.mjs';
import { historyReadModel } from '../../src/services/protectionProfile.mjs';
import {
  assessOriginReachability,
  createOriginBinding,
  deriveBindingScope,
  getOriginBinding,
  listOriginBindings,
  planOriginBinding,
  validateOriginBindingForRun,
} from '../../src/services/originBindings.mjs';
import {
  labelRunRelation,
  listFindingLineage,
  registerRetestLineage,
} from '../../src/services/retestLineage.mjs';
import { recordTargetEdgeDetectionFromEvent } from '../../src/services/targetEdgeDetectionStore.mjs';
import {
  advanceScan,
  dispatchDueValidationScans,
  getValidationScan,
  getValidationScanActivity,
} from '../../src/services/validationScans.mjs';
import {
  VALIDATION_SCAN_REPOSITORY_REQUIRED_METHODS,
  VALIDATION_SCAN_TEST_RUN_SERVICE_METHODS,
  createPostgresValidationScanServices,
} from '../../src/persistence/postgres/validationScanServiceAdapters.mjs';
import { getStore } from '../../src/store.mjs';

const TENANT = 'ten_hist_unit';
const GROUP = 'tg_hist_unit';
const NOW = new Date('2026-10-04T12:00:00.000Z');
const DECLARED = '2026-09-01T00:00:00.000Z';
const ADMIN = { tenantId: TENANT, userId: 'usr_hist', role: 'admin' };
const ENGINEER = { tenantId: TENANT, userId: 'usr_eng', role: 'engineer' };
const VIEWER = { tenantId: TENANT, userId: 'usr_view', role: 'viewer' };

function scrub() {
  const store = getStore();
  for (const key of [
    'targets', 'targetGroups', 'targetVerifications', 'targetObservations', 'targetObservationCurrents',
    'originBindings', 'findingRetestLineage', 'findings', 'testRuns', 'targetEdgeDetections',
    'validationScans', 'events', 'auditLog',
  ]) {
    if (!Array.isArray(store[key])) continue;
    store[key] = store[key].filter((row) => row.tenant_id !== TENANT);
  }
}

function target(partial) {
  getStore().targets.push({
    tenant_id: TENANT,
    target_group_id: GROUP,
    created_at: DECLARED,
    kind: 'fqdn',
    value: 'app.example.test',
    ...partial,
  });
}

function observation(overrides = {}) {
  return {
    target_id: 'tgt_app',
    family: 'waf',
    check_id: 'waf.fingerprint.safe',
    source_kind: 'explicit_record',
    corpus_version: 'corpus-1',
    scenario_version: 'scenario-1',
    check_version: 'check-1',
    observed_at: '2026-09-02T00:00:00.100Z',
    source_completed_at: '2026-09-02T00:00:01.000Z',
    outcome: 'detected',
    producer_kind: 'manual',
    nonce: `nonce-${Math.random().toString(16).slice(2)}`,
    provenance: { provider: 'cloudflare', status: 'detected' },
    ...overrides,
  };
}

function edgeMetadata(overrides = {}) {
  return {
    external_result: 'connected',
    edge_signature_corpus_version: 'v2',
    scenario_version: 'scenario-edge',
    edge_signature: {
      waf_present: true,
      cdn_detected: true,
      best_vendor: { vendor: 'cloudflare', confidence: 0.9, matched_signals: [{ signal: 'server=cloudflare' }] },
      address_matches: [{ family: 'cdn', provider: 'cloudfront' }],
      vendor_matches: [{ vendor: 'cloudflare', matched_signals: [{ signal: 'cookie=secret' }] }],
    },
    ...overrides,
  };
}

beforeEach(() => {
  scrub();
  getStore().targetGroups.push({ id: GROUP, tenant_id: TENANT, name: 'History', ownership_status: 'dns_verified' });
  target({ id: 'tgt_app', kind: 'fqdn', value: 'app.example.test' });
});

describe('observation order, retention, and comparison', () => {
  it('orders by observed_at, then source_completed_at, then id, with null completion older', () => {
    const older = { observed_at: '2026-09-02T00:00:00.100000Z', source_completed_at: null, id: 'obs_b' };
    const newer = { observed_at: '2026-09-02T00:00:00.100000Z', source_completed_at: '2026-09-02T00:00:01.000000Z', id: 'obs_a' };
    assert.equal(compareObservationOrder(older, newer), -1);
    assert.equal(normalizeObservationTimestamp('2026-09-02T00:00:00.100Z'), '2026-09-02T00:00:00.100000Z');
    const tieLeft = { ...newer, id: 'obs_a' };
    const tieRight = { ...newer, id: 'obs_b' };
    assert.equal(compareObservationOrder(tieLeft, tieRight), -1);
  });

  it('keeps a late older result and a replay from replacing the current successful family', () => {
    const first = acceptTargetObservation(ADMIN, observation({
      nonce: 'late-new',
      observed_at: '2026-09-03T00:00:00.000Z',
      source_completed_at: '2026-09-03T00:00:01.000Z',
    }), { internal: true, now: NOW });
    const late = acceptTargetObservation(ADMIN, observation({
      nonce: 'late-old',
      observed_at: '2026-09-02T00:00:00.000Z',
      source_completed_at: '2026-09-02T00:00:01.000Z',
    }), { internal: true, now: NOW });
    const replay = acceptTargetObservation(ADMIN, observation({
      nonce: 'late-new',
      observed_at: '2026-09-03T00:00:00.000Z',
      source_completed_at: '2026-09-03T00:00:01.000Z',
    }), { internal: true, now: NOW });
    assert.equal(late.replayed, false);
    assert.equal(replay.replayed, true);
    assert.equal(replay.id, first.id);
    const current = getCurrentFamilyState(VIEWER, { target_id: 'tgt_app', family: 'waf' });
    assert.equal(current.items[0].last_successful.id, first.id);
    assert.equal(listObservationsForTests(TENANT).length, 2);
    const conflict = acceptTargetObservation(ADMIN, observation({
      nonce: 'late-new',
      outcome: 'not_detected',
    }), { internal: true, now: NOW });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.error, 'idempotency_conflict');
  });

  it('retains timeout, TLS, and DNS failures apart from the last success', () => {
    assert.equal(classifyAttempt('timeout'), 'failed_attempt');
    assert.equal(classifyAttempt('tls_failure'), 'failed_attempt');
    assert.equal(classifyAttempt('dns_failure'), 'failed_attempt');
    assert.equal(classifyAttempt('inconclusive'), 'retained_noncurrent');
    const success = acceptTargetObservation(ADMIN, observation({ nonce: 'ok', outcome: 'detected' }), { internal: true, now: NOW });
    for (const [nonce, outcome, observedAt] of [
      ['to', 'timeout', '2026-09-04T00:00:00.000Z'],
      ['tls', 'tls_failure', '2026-09-04T00:00:02.000Z'],
      ['dns', 'dns_failure', '2026-09-04T00:00:03.000Z'],
    ]) {
      acceptTargetObservation(ADMIN, observation({
        nonce,
        outcome,
        observed_at: observedAt,
        source_completed_at: observedAt.replace('00.000Z', '01.000Z'),
        provenance: { status: outcome },
      }), { internal: true, now: NOW });
    }
    acceptTargetObservation(ADMIN, observation({
      nonce: 'held',
      outcome: 'inconclusive',
      observed_at: '2026-09-05T00:00:00.000Z',
      source_completed_at: '2026-09-05T00:00:01.000Z',
    }), { internal: true, now: NOW });
    const current = getCurrentFamilyState(VIEWER, { target_id: 'tgt_app' });
    const waf = current.items.find((row) => row.family === 'waf');
    assert.equal(waf.last_successful.id, success.id);
    assert.equal(waf.last_successful.outcome, 'detected');
    assert.equal(waf.latest_failed_attempt.outcome, 'dns_failure');
    assert.equal(waf.fresh_negative, false);
    assert.equal(waf.provider_loss, false);
    const negative = acceptTargetObservation(ADMIN, observation({
      nonce: 'none',
      outcome: 'not_detected',
      observed_at: '2026-09-06T00:00:00.000Z',
      source_completed_at: '2026-09-06T00:00:01.000Z',
    }), { internal: true, now: NOW });
    const after = getCurrentFamilyState(VIEWER, { target_id: 'tgt_app' }).items[0];
    assert.equal(after.last_successful.id, negative.id);
    assert.equal(after.fresh_negative, true);
    assert.equal(after.provider_loss, false);
    assert.equal(listObservationsForTests(TENANT).some((row) => row.outcome === 'inconclusive'), true);
  });

  it('compares only a known same check, corpus, scenario, target, and context', () => {
    const base = observation({ nonce: 'cmp' });
    const left = { ...base, attempt_class: 'successful', id: 'a' };
    const cases = [
      [{ ...left, outcome: 'timeout', attempt_class: 'failed_attempt' }, left, 'transport_failure'],
      [left, { ...left, target_id: 'other' }, 'target_mismatch'],
      [left, { ...left, check_id: 'other.check' }, 'check_mismatch'],
      [{ ...left, check_version: null }, left, 'missing_version'],
      [left, { ...left, corpus_version: 'corpus-2' }, 'corpus_changed'],
      [left, { ...left, scenario_version: 'scenario-2' }, 'scenario_changed'],
      [left, { ...left, check_version: 'check-2' }, 'check_version_changed'],
      [left, { ...left, family: 'cdn' }, 'context_mismatch'],
      [left, { ...left, outcome: 'not_detected' }, null],
    ];
    for (const [previous, next, reason] of cases) {
      const result = assessComparability(previous, next);
      if (reason) {
        assert.equal(result.comparable, false);
        assert.equal(result.reason, reason);
        assert.equal(result.direction, null);
      } else {
        assert.equal(result.comparable, true);
        assert.equal(result.change, 'changed');
        assert.equal(result.direction, 'disappeared');
      }
    }
    assert.equal(assessComparability(
      { ...left, outcome: 'pass' },
      { ...left, outcome: 'fail' },
    ).direction, 'regression');
    assert.equal(assessComparability(null, left).reason, 'missing_observation');
  });

  it('pages with a full-precision cursor and rejects a bad cursor', () => {
    const stamped = [];
    for (let index = 0; index < 3; index += 1) {
      stamped.push(acceptTargetObservation(ADMIN, observation({
        nonce: `page-${index}`,
        source_id: `src-${index}`,
        observed_at: '2026-09-02T00:00:00.100Z',
        source_completed_at: index === 0 ? null : '2026-09-02T00:00:01.000Z',
        provenance: { status: 'detected', slot: index },
      }), { internal: true, now: NOW }));
    }
    const page = listTargetObservations(VIEWER, { target_id: 'tgt_app', family: 'waf', limit: 1 });
    assert.equal(page.items.length, 1);
    assert.match(page.items[0].observed_at, /\.\d{6}Z$/);
    assert.equal(page.next_cursor != null, true);
    const decoded = decodeObservationCursor(page.next_cursor);
    assert.match(decoded.cursor.observed_at, /\.\d{6}Z$/);
    const rest = listTargetObservations(VIEWER, { target_id: 'tgt_app', cursor: page.next_cursor, limit: 10 });
    assert.equal(rest.items.some((row) => row.id === page.items[0].id), false);
    const ordered = [...listObservationsForTests(TENANT)].sort((left, right) => compareObservationOrder(right, left));
    const listed = listTargetObservations(ENGINEER, { target_id: 'tgt_app', limit: 10 });
    assert.deepEqual(listed.items.map((row) => row.id), ordered.map((row) => row.id));
    const invalid = listTargetObservations(VIEWER, { cursor: '@@@' });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.error, 'invalid_cursor');
    assert.equal(encodeObservationCursor(page.items[0]).length > 10, true);
    const hidden = acceptTargetObservation(ADMIN, observation({
      nonce: 'secret',
      provenance: {
        provider: 'cloudflare',
        cookie: 'sid=1',
        authorization: 'Bearer secret',
        note: 'Bearer token',
        raw_body: 'secret',
        ok: true,
        count: 2,
        huge: 'x'.repeat(201),
      },
    }), { internal: true, now: NOW });
    assert.deepEqual(hidden.provenance, { provider: 'cloudflare', ok: true, count: 2 });
  });

  it('rejects timestamps outside the declaration window and body-supplied versions', () => {
    const early = appendTargetObservation(ADMIN, observation({ nonce: 'early', observed_at: '2026-08-01T00:00:00.000Z', check_version: undefined, producer_kind: undefined }), { now: NOW });
    assert.equal(early.error, 'before_declaration');
    const future = appendTargetObservation(ADMIN, observation({
      nonce: 'future',
      observed_at: '2026-10-04T12:03:00.000Z',
      source_completed_at: '2026-10-04T12:03:00.000Z',
      check_version: undefined,
      producer_kind: undefined,
    }), { now: NOW });
    assert.equal(future.error, 'future_timestamp');
    const same = appendTargetObservation(ENGINEER, observation({
      nonce: 'same-instant',
      observed_at: DECLARED,
      source_completed_at: DECLARED,
      check_version: undefined,
      producer_kind: undefined,
    }), { now: NOW });
    assert.equal(same.replayed, false);
    const supplied = appendTargetObservation(ADMIN, observation({ nonce: 'body', check_version: 'live' }), { now: NOW, internal: true });
    assert.equal(supplied.error, 'body_supplied_version');
    assert.equal(listObservationsForTests(TENANT).length, 1);
    const denied = appendTargetObservation(VIEWER, observation({ nonce: 'nope', check_version: undefined, producer_kind: undefined }), { now: NOW });
    assert.equal(denied.status, 403);
  });
});

describe('origin bindings', () => {
  function records(extra = {}) {
    return {
      targets: getStore().targets.filter((row) => row.tenant_id === TENANT),
      targetVerifications: extra.verifications ?? [],
      wafConnectors: [],
      wafConnectorSnapshots: [],
    };
  }

  it('binds a declared hostname to a verified IP and refuses undeclared scope', () => {
    target({ id: 'tgt_ip', kind: 'ip', value: '203.0.113.10' });
    target({ id: 'tgt_scoped', kind: 'url', value: 'https://app.example.test:8443/origin' });
    target({ id: 'tgt_url', kind: 'url', value: 'https://203.0.113.20/origin' });
    target({
      id: 'tgt_choice',
      kind: 'fqdn',
      value: 'choice.example.test',
      declaration_json: { allowed_scope: { ports: [443, 8443], paths: ['/a', '/b'] } },
    });
    const verified = { tenant_id: TENANT, target_id: 'tgt_ip', state: 'dns_verified', transitioned_at: DECLARED, source_ref: {} };
    const planned = planOriginBinding(ADMIN, {
      protected_target_id: 'tgt_app',
      origin_target_id: 'tgt_ip',
    }, records({ verifications: [verified] }), { now: NOW });
    assert.equal(planned.record.host, 'app.example.test');
    assert.equal(planned.record.sni, 'app.example.test');
    assert.equal(planned.record.assurance, 'none');
    assert.equal(planned.record.lockdown, 'not_tested');
    assert.equal(planned.record.relation, 'declared_binding');
    const literal = planOriginBinding(ADMIN, {
      protected_target_id: 'tgt_scoped',
      origin_target_id: 'tgt_url',
    }, records({ verifications: [{ ...verified, target_id: 'tgt_url', state: 'user_confirmed' }] }), { now: NOW });
    assert.equal(literal.record.host, 'app.example.test');
    assert.equal(literal.record.port, 8443);
    assert.equal(literal.record.path, '/origin');
    assert.equal(planOriginBinding(ADMIN, {
      protected_target_id: 'tgt_app',
      origin_target_id: 'tgt_ip',
      direct_ip: '203.0.113.10',
    }, records({ verifications: [verified] })).error, 'scope_not_declared');
    assert.equal(planOriginBinding(ADMIN, {
      protected_target_id: 'tgt_app',
      origin_target_id: 'tgt_ip',
    }, records({ verifications: [{ ...verified, state: 'agent_verified' }] })).error, 'ownership_not_verified');
    assert.equal(planOriginBinding(ADMIN, {
      protected_target_id: 'tgt_app',
      origin_target_id: 'tgt_ip',
    }, records({ verifications: [{ ...verified, state: 'provider_verified' }] })).error, 'ownership_not_verified');
    assert.equal(planOriginBinding(ADMIN, {
      protected_target_id: 'tgt_app',
      origin_target_id: 'tgt_ip',
    }, records()).error, 'ownership_not_verified');
    assert.equal(deriveBindingScope(getStore().targets.find((row) => row.id === 'tgt_choice'), {}).error, 'port_unspecified');
    const chosen = deriveBindingScope(getStore().targets.find((row) => row.id === 'tgt_choice'), { port: 8443, path: '/b' });
    assert.equal(chosen.port, 8443);
    assert.equal(chosen.path, '/b');
  });

  it('does not treat an unbound observation as origin reachability', () => {
    target({ id: 'tgt_ip', kind: 'ip', value: '203.0.113.10' });
    getStore().targetVerifications.push({
      id: 'ver_ip', tenant_id: TENANT, target_id: 'tgt_ip', state: 'dns_verified', transitioned_at: DECLARED, source_ref: {},
    });
    const before = listObservationsForTests(TENANT).length;
    const prior = acceptTargetObservation(ADMIN, observation({
      target_id: 'tgt_ip',
      nonce: 'unbound',
      outcome: 'reachable',
      family: 'origin_hosting',
      observed_at: '2026-09-02T00:00:00.000Z',
      source_completed_at: '2026-09-02T00:00:01.000Z',
    }), { internal: true, now: NOW });
    const audits = () => getStore().auditLog.filter((row) => row.tenant_id === TENANT).length;
    const beforeAudit = audits();
    const binding = createOriginBinding(ADMIN, {
      protected_target_id: 'tgt_app',
      origin_target_id: 'tgt_ip',
    }, { now: new Date('2026-09-10T00:00:00.000Z') });
    assert.equal(binding.currently_authorized, true);
    assert.equal(binding.capacity_assurance, false);
    assert.equal(binding.lockdown, 'not_tested');
    assert.equal(audits(), beforeAudit + 1);
    assert.equal(getOriginBinding(VIEWER, binding.id).id, binding.id);
    assert.equal(listOriginBindings(VIEWER).count, 1);
    assert.equal(audits(), beforeAudit + 1);
    assert.equal(listObservationsForTests(TENANT).find((row) => row.id === prior.id).origin_binding_id, null);
    assert.equal(assessOriginReachability(binding, [prior], { verified: true, state: 'dns_verified' }).reason, 'no_bound_finalized_evidence');
    const tooEarly = acceptTargetObservation(ADMIN, observation({
      target_id: 'tgt_ip',
      nonce: 'early-bound',
      outcome: 'reachable',
      family: 'origin_hosting',
      origin_binding_id: binding.id,
      observed_at: '2026-09-02T00:00:00.000Z',
      source_completed_at: '2026-09-02T00:00:01.000Z',
    }), { internal: true, now: NOW });
    assert.equal(tooEarly.error, 'observation_predates_binding');
    const bound = acceptTargetObservation(ADMIN, observation({
      target_id: 'tgt_ip',
      nonce: 'bound',
      outcome: 'reachable',
      family: 'origin_hosting',
      check_id: 'origin.host_sni_bypass.safe',
      producer_kind: 'signed_probe',
      origin_binding_id: binding.id,
      observed_at: '2026-09-11T00:00:00.000Z',
      source_completed_at: '2026-09-11T00:00:01.000Z',
    }), { internal: true, now: NOW });
    const reach = assessOriginReachability(
      binding,
      listObservationsForTests(TENANT),
      { verified: true, state: 'dns_verified' },
    );
    assert.equal(reach.status, 'reachable');
    assert.equal(reach.lockdown, 'not_established');
    assert.equal(reach.capacity_assurance, false);
    assert.equal(reach.observation_id, bound.id);
    assert.equal(listObservationsForTests(TENANT).length, before + 2);
  });

  it('replays only the identical scope and conflicts on a different choice for the same pair', () => {
    target({ id: 'tgt_ip2', kind: 'ip', value: '203.0.114.10' });
    target({
      id: 'tgt_app2',
      kind: 'fqdn',
      value: 'multi.example.test',
      declaration_json: { allowed_scope: { ports: [443, 8443], paths: ['/checkout', '/data'] } },
    });
    getStore().targetVerifications.push({
      id: 'ver_ip2', tenant_id: TENANT, target_id: 'tgt_ip2', state: 'dns_verified', transitioned_at: DECLARED, source_ref: {},
    });
    const create = (scope) => createOriginBinding(ADMIN, {
      protected_target_id: 'tgt_app2',
      origin_target_id: 'tgt_ip2',
      ...(scope ? { scope } : {}),
    }, { now: NOW });
    const initial = create({ port: 443, path: '/checkout' });
    assert.equal(initial.error, undefined);
    const replay = create({ port: 443, path: '/checkout' });
    assert.equal(replay.replayed, true);
    assert.equal(replay.id, initial.id);
    const replayedAudits = getStore().auditLog.filter((row) => row.tenant_id === TENANT
      && row.action === 'origin_binding.created').length;
    assert.equal(replayedAudits, 1);
    const stored = getStore().originBindings.filter((row) => row.tenant_id === TENANT
      && row.status === 'active'
      && row.protected_target_id === 'tgt_app2'
      && row.origin_target_id === 'tgt_ip2').length;
    assert.equal(stored, 1);
    const conflict = create({ port: 8443, path: '/data' });
    assert.equal(conflict.error, 'scope_conflict');
    assert.equal(conflict.status, 409);
    assert.equal(conflict.existing_id, initial.id);
  });
});

describe('retest lineage', () => {
  it('registers only an explicit same-target retest and leaves siblings open', () => {
    target({ id: 'tgt_other', kind: 'fqdn', value: 'other.example.test' });
    const store = getStore();
    store.findings.push(
      { id: 'fnd_a', tenant_id: TENANT, target_id: 'tgt_app', target_group_id: GROUP, check_id: 'waf.fingerprint.safe', test_run_id: 'run_origin', status: 'open', closed_at: null },
      { id: 'fnd_sib', tenant_id: TENANT, target_id: 'tgt_other', target_group_id: GROUP, check_id: 'waf.fingerprint.safe', test_run_id: 'run_sib', status: 'open', closed_at: null },
    );
    store.testRuns.push(
      { id: 'run_origin', tenant_id: TENANT, target_id: 'tgt_app', target_group_id: GROUP, check_id: 'waf.fingerprint.safe', status: 'verdicted' },
      { id: 'run_later', tenant_id: TENANT, target_id: 'tgt_app', target_group_id: GROUP, check_id: 'waf.fingerprint.safe', status: 'completed' },
      { id: 'run_retest', tenant_id: TENANT, target_id: 'tgt_app', target_group_id: GROUP, check_id: 'waf.fingerprint.safe', status: 'verdicted' },
      { id: 'run_other', tenant_id: TENANT, target_id: 'tgt_other', target_group_id: GROUP, check_id: 'waf.fingerprint.safe', status: 'verdicted' },
    );
    assert.equal(labelRunRelation({
      finding: store.findings[0],
      run: store.testRuns[1],
      lineage: [],
    }).relation, 'later_same_pair');
    assert.equal(registerRetestLineage(ENGINEER, { finding_id: 'fnd_a', test_run_id: 'run_other', intent: 'retest' }).error, 'pair_mismatch');
    assert.equal(registerRetestLineage(ENGINEER, { finding_id: 'fnd_a', test_run_id: 'run_later' }).error, 'intent_required');
    const registered = registerRetestLineage(ENGINEER, { finding_id: 'fnd_a', test_run_id: 'run_retest', intent: 'retest' }, { now: NOW });
    assert.equal(registered.relation, 'retest');
    assert.equal(registered.sibling_closure, false);
    assert.equal(registerRetestLineage(ENGINEER, { finding_id: 'fnd_a', test_run_id: 'run_retest', intent: 'retest' }).replayed, true);
    const lineage = listFindingLineage(VIEWER, 'fnd_a');
    assert.equal(lineage.closed_at, null);
    assert.equal(lineage.sibling_closure, false);
    assert.equal(lineage.siblings[0].id, 'fnd_sib');
    assert.equal(lineage.siblings[0].closed_at, null);
    assert.deepEqual(lineage.retests.map((row) => row.test_run_id), ['run_retest']);
    assert.deepEqual(lineage.later_same_pair.map((row) => row.test_run_id), ['run_later']);
    assert.equal(lineage.later_same_pair[0].can_advance_remediation, false);
    assert.equal(store.findings[1].status, 'open');
    assert.equal(registerRetestLineage(VIEWER, { finding_id: 'fnd_a', test_run_id: 'run_later', intent: 'retest' }).status, 403);
  });
});

describe('check definition version', () => {
  it('uses an explicit version or a canonical digest and ignores a live body marker', () => {
    const definition = { check_id: 'waf.fingerprint.safe', version: '2026.09', producer_kind: 'live_external', body: { secret: true } };
    const derived = deriveCheckDefinitionVersion(definition, { version: 'live', producer_kind: 'live_external', check_version: 'user' });
    assert.equal(derived.derivation, 'explicit');
    assert.equal(derived.check_version, '2026.09');
    assert.equal(derived.producer_kind, null);
    assert.deepEqual(derived.ignored_body_fields, ['version', 'check_version', 'producer_kind']);
    const live = deriveCheckDefinitionVersion({
      check_id: definition.check_id,
      version: 'live',
      request_body: { path: '/login', password: 's3cret-value', note: 'bearer abc.def' },
    }, { live: true });
    assert.equal(live.derivation, 'canonical_digest');
    assert.equal(live.check_version, `sha256:${live.digest}`);
    const withoutBody = deriveCheckDefinitionVersion({ check_id: definition.check_id, version: 'live' });
    const otherPath = deriveCheckDefinitionVersion({
      check_id: definition.check_id,
      version: 'live',
      request_body: { path: '/admin', password: 'other-secret' },
    });
    const samePath = deriveCheckDefinitionVersion({
      check_id: definition.check_id,
      version: 'live',
      request_body: { path: '/login', password: 'different-secret', note: 'bearer zzz.yyy' },
    });
    assert.notEqual(live.digest, withoutBody.digest);
    assert.notEqual(live.digest, otherPath.digest);
    assert.equal(live.digest, samePath.digest);
    assert.equal(JSON.stringify(live).includes('s3cret-value'), false);
    assert.equal(JSON.stringify(live).includes('bearer'), false);
    const reordered = canonicalDefinitionDigest({
      version: 'live',
      check_id: definition.check_id,
      request_body: { note: 'bearer abc.def', password: 's3cret-value', path: '/login' },
    });
    assert.equal(reordered, live.digest);
    assert.equal(deriveCheckDefinitionVersion({ name: 'missing' }).error, 'invalid_check_definition');
  });

  it('stamps producer and expected behavior from the catalog, not body flags', () => {
    const check = getCheckById('ops.runbook_contact_validation.safe');
    const body = {
      check_version: 'live',
      producer_kind: 'signed_probe',
      expected_behavior: 'must_allow',
      scenario_version: 'forged',
      internal: true,
    };
    const ops = deriveRunEvidenceStamp(check, body, {
      probeMode: 'signed-worker',
      opsReadiness: true,
      scenarioVersion: approvedScenarioVersion(check, 'runbook_contacts'),
    });
    assert.equal(ops.producer_kind, 'customer_declaration');
    assert.equal(ops.check_version, '1.0.0');
    assert.equal(ops.scenario_version, 'runbook_contacts');
    assert.equal(ops.expected_behavior, check.default_expected_behavior);
    assert.equal(ops.expected_behavior_json.value, check.default_expected_behavior);
    assert.equal(JSON.stringify(ops).includes('must_allow'), false);
    const signed = deriveRunEvidenceStamp(getCheckById('waf.fingerprint.safe'), body, { probeMode: 'signed-worker' });
    assert.equal(signed.producer_kind, 'signed_probe');
    const inline = deriveRunEvidenceStamp(getCheckById('waf.fingerprint.safe'), body, { probeMode: 'simulation' });
    assert.equal(inline.producer_kind, 'internal_simulation');
  });
});

describe('history read model and finding lifecycle', () => {
  it('confirms only the adjacent successful pair and keeps a revoked proof unauthorized', () => {
    const older = {
      id: 'obs_old', tenant_id: TENANT, target_id: 'tgt_app', family: 'waf', check_id: 'waf.fingerprint.safe',
      corpus_version: 'c1', scenario_version: 's1', check_version: '1', observed_at: '2026-09-02T00:00:00.000Z',
      source_completed_at: '2026-09-02T00:00:01.000Z', outcome: 'not_detected', attempt_class: 'successful',
      producer_kind: 'signed_probe',
    };
    const middle = { ...older, id: 'obs_mid', observed_at: '2026-09-03T00:00:00.000Z', outcome: 'detected', check_version: '1' };
    const newest = { ...older, id: 'obs_new', observed_at: '2026-09-04T00:00:00.000Z', outcome: 'detected', check_version: '2' };
    const failed = { ...older, id: 'obs_fail', family: 'cdn', observed_at: '2026-09-05T00:00:00.000Z', outcome: 'timeout', attempt_class: 'failed_attempt' };
    const success = { ...older, id: 'obs_cdn', family: 'cdn', observed_at: '2026-09-01T00:00:00.000Z', outcome: 'detected' };
    const model = historyReadModel({
      targetId: 'tgt_app',
      observations: [older, middle, newest, failed, success],
      bindings: [],
    });
    assert.equal(model.comparable_changes.length, 0);
    assert.equal(model.comparison_gaps.some((gap) => gap.reason === 'check_version_changed' && gap.previous_id === 'obs_mid'), true);
    assert.equal(model.retained_family_states.find((row) => row.family === 'cdn').last_successful.id, 'obs_cdn');
    assert.equal(model.retained_family_states.find((row) => row.family === 'cdn').latest_failed_attempt.id, 'obs_fail');
    assert.equal(model.retained_family_states.find((row) => row.family === 'cdn').fresh_negative, false);
    const comparable = historyReadModel({
      targetId: 'tgt_app',
      observations: [older, middle],
    });
    assert.equal(comparable.comparable_changes[0].direction, 'appeared');
    const denied = validateOriginBindingForRun({
      binding: { id: 'obind_1', status: 'active', origin_target_id: 'tgt_origin', protected_target_id: 'tgt_app', host: 'app.example.test', sni: 'app.example.test', port: 443, path: null },
      runTarget: { id: 'tgt_origin', kind: 'ip', value: '203.0.113.10' },
      protectedTarget: {
        id: 'tgt_app',
        kind: 'fqdn',
        value: 'app.example.test',
        declaration_json: { allowed_scope: { ports: [443] } },
      },
      check: { probe_profile: { kind: 'host_sni_bypass' } },
      originProof: { verified: false, state: 'pending' },
      protectedProof: { verified: true, state: 'dns_verified' },
      body: {},
    });
    assert.equal(denied.error, 'ownership_not_verified');
    assert.equal(denied.proof, 'origin');
  });

  it('sets closed_at only for an authorized closure status', () => {
    assert.equal(planFindingPatch({ status: 'not_a_status' }).error, 'invalid_lifecycle');
    const closed = planFindingPatch({ status: 'closed' });
    assert.equal(closed.patch.status, 'closed');
    assert.equal(typeof closed.patch.closed_at, 'string');
    assert.equal(planFindingPatch({ status: 'open' }).patch.closed_at, null);
    assert.equal(JSON.stringify(closed).includes('fix_proved'), false);
  });
});

describe('edge history hook', () => {
  it('appends family history for a declared target and does not regress the current edge row', () => {
    const first = recordTargetEdgeDetectionFromEvent({
      tenantId: TENANT,
      targetGroupId: GROUP,
      targetId: 'tgt_app',
      testRunId: 'run_edge_new',
      metadata: edgeMetadata({ source_completed_at: '2026-09-04T00:00:01.000Z' }),
      observedAt: '2026-09-04T00:00:00.000Z',
    });
    assert.equal(first.test_run_id, 'run_edge_new');
    assert.equal(first.history_observation_id != null, true);
    const families = listObservationsForTests(TENANT).map((row) => row.family).sort();
    assert.deepEqual(families, ['cdn', 'waf']);
    assert.equal(listObservationsForTests(TENANT).every((row) => row.producer_kind === 'signed_probe'), true);
    assert.equal(JSON.stringify(listObservationsForTests(TENANT)).includes('matched_signals'), false);
    assert.equal(JSON.stringify(listObservationsForTests(TENANT)).includes('cookie'), false);
    const older = recordTargetEdgeDetectionFromEvent({
      tenantId: TENANT,
      targetGroupId: GROUP,
      targetId: 'tgt_app',
      testRunId: 'run_edge_old',
      metadata: edgeMetadata(),
      observedAt: '2026-09-03T00:00:00.000Z',
    });
    assert.equal(older.test_run_id, 'run_edge_new');
    assert.equal(getStore().targetEdgeDetections.filter((row) => row.target_id === 'tgt_app').length, 1);
    const rejected = recordTargetEdgeDetectionFromEvent({
      tenantId: TENANT,
      targetGroupId: GROUP,
      targetId: 'tgt_app',
      testRunId: 'run_before',
      metadata: edgeMetadata(),
      observedAt: '2026-08-01T00:00:00.000Z',
    });
    assert.equal(rejected.test_run_id, 'run_edge_new');
    recordTargetEdgeDetectionFromEvent({
      tenantId: TENANT,
      targetGroupId: GROUP,
      targetId: 'tgt_missing',
      testRunId: 'run_missing_1',
      metadata: edgeMetadata(),
    });
    recordTargetEdgeDetectionFromEvent({
      tenantId: TENANT,
      targetGroupId: GROUP,
      targetId: 'tgt_missing',
      testRunId: 'run_missing_2',
      metadata: edgeMetadata(),
    });
    const missing = getStore().targetEdgeDetections.filter((row) => row.target_id === 'tgt_missing');
    assert.equal(missing.length, 1);
    assert.equal(missing[0].test_run_id, 'run_missing_2');
    assert.equal(listObservationsForTests(TENANT).some((row) => row.target_id === 'tgt_missing'), false);
  });
});

describe('read-only validation scan mode', () => {
  function seedScan(partial) {
    getStore().validationScans.push({
      id: partial.id,
      tenant_id: TENANT,
      target_group_id: GROUP,
      target_id: 'tgt_app',
      status: partial.status,
      name: partial.id,
      check_ids: [],
      steps: [],
      scheduled_for: partial.scheduled_for ?? null,
      lease_expires_at: partial.lease_expires_at ?? null,
      created_by: 'usr_eng',
      created_at: DECLARED,
      updated_at: DECLARED,
      revision: 1,
    });
  }

  function snapshot() {
    const store = getStore();
    return {
      scans: store.validationScans.filter((row) => row.tenant_id === TENANT).map((row) => [row.id, row.status]),
      runs: store.testRuns.filter((row) => row.tenant_id === TENANT).length,
      events: store.events.filter((row) => row.tenant_id === TENANT).length,
    };
  }

  it('does not dispatch or advance a due, canceled, or stale scan from either read source', () => {
    seedScan({ id: 'scan_due', status: 'scheduled', scheduled_for: '2026-10-01T00:00:00.000Z' });
    seedScan({ id: 'scan_canceled', status: 'cancelled', scheduled_for: '2026-10-01T00:00:00.000Z' });
    seedScan({ id: 'scan_stale', status: 'running', lease_expires_at: '2026-10-01T00:00:00.000Z' });
    const before = snapshot();
    for (const id of ['scan_due', 'scan_canceled', 'scan_stale']) {
      const scan = getValidationScan(ENGINEER, id, { advance: false, now: NOW });
      const activity = getValidationScanActivity(ENGINEER, id, { advance: 'false', now: NOW });
      assert.equal(scan.status, before.scans.find((row) => row[0] === id)[1]);
      assert.equal(activity.scan_id, id);
      assert.equal(activity.status, scan.status);
    }
    assert.deepEqual(dispatchDueValidationScans(ENGINEER, { advance: false, now: NOW }), []);
    assert.equal(advanceScan(ENGINEER, 'scan_stale', { advance: false, now: NOW }).reason, 'advance_disabled');
    assert.deepEqual(snapshot(), before);
  });

  it('skips lease and run start in the postgres adapter when advance is false', async () => {
    const calls = { leaseDueScans: 0, withScanLock: 0, startTestRun: 0, getScan: 0, listSteps: 0, getTargetGroup: 0 };
    const scans = {
      scan_due: { id: 'scan_due', tenant_id: TENANT, status: 'scheduled', target_group_id: GROUP, check_ids: [], scheduled_for: '2026-10-01T00:00:00.000Z', created_by: 'usr_eng', created_at: DECLARED, updated_at: DECLARED, revision: 1 },
      scan_canceled: { id: 'scan_canceled', tenant_id: TENANT, status: 'cancelled', target_group_id: GROUP, check_ids: [], created_by: 'usr_eng', created_at: DECLARED, updated_at: DECLARED, revision: 1 },
      scan_stale: { id: 'scan_stale', tenant_id: TENANT, status: 'running', target_group_id: GROUP, check_ids: [], lease_expires_at: '2026-10-01T00:00:00.000Z', created_by: 'usr_eng', created_at: DECLARED, updated_at: DECLARED, revision: 1 },
    };
    const validationScans = {};
    for (const method of VALIDATION_SCAN_REPOSITORY_REQUIRED_METHODS) validationScans[method] = async () => null;
    validationScans.getScan = async (_ctx, id) => {
      calls.getScan += 1;
      return scans[id] ?? null;
    };
    validationScans.listSteps = async () => {
      calls.listSteps += 1;
      return [];
    };
    validationScans.listStepsForScans = async () => [];
    validationScans.listAuditEntriesForScan = async () => [];
    validationScans.leaseDueScans = async () => {
      calls.leaseDueScans += 1;
      return [];
    };
    validationScans.withScanLock = async () => {
      calls.withScanLock += 1;
      return { acquired: false };
    };
    const testRuns = {};
    for (const method of VALIDATION_SCAN_TEST_RUN_SERVICE_METHODS) testRuns[method] = async () => null;
    testRuns.registerRunTerminalHook = () => {};
    testRuns.startTestRun = async () => {
      calls.startTestRun += 1;
      return null;
    };
    const services = createPostgresValidationScanServices({
      validationScans,
      validationEvidence: {
        listTestRuns: async () => [],
        getTestRun: async () => null,
        getVerdictForRun: async () => null,
        listRunEvents: async () => [],
      },
      coreCatalog: {
        getTargetGroup: async () => {
          calls.getTargetGroup += 1;
          return { id: GROUP, name: 'History', targets: [] };
        },
      },
      killSwitch: { isKillSwitchActiveForTenant: async () => false },
    }, { testRuns });
    for (const id of ['scan_due', 'scan_canceled', 'scan_stale']) {
      const scan = await services.getValidationScan(ENGINEER, id, { advance: false, now: NOW });
      const activity = await services.getValidationScanActivity(ENGINEER, id, { advance: 'false', now: NOW });
      assert.equal(scan.status, scans[id].status);
      assert.equal(activity.status, scans[id].status);
    }
    assert.deepEqual(await services.dispatchDueValidationScans(ENGINEER, { advance: false, now: NOW }), []);
    assert.equal((await services.advanceScan(ENGINEER, 'scan_stale', { advance: false, now: NOW })).reason, 'advance_disabled');
    assert.equal(calls.leaseDueScans, 0);
    assert.equal(calls.withScanLock, 0);
    assert.equal(calls.startTestRun, 0);
    assert.equal(calls.getScan > 0, true);
    assert.equal(calls.listSteps > 0, true);
    assert.equal(calls.getTargetGroup > 0, true);
  });
});
