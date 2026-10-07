import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  acceptTargetObservation,
  appendTargetObservation,
  assessComparability,
  compareObservationOrder,
  decodeObservationCursor,
  encodeObservationCursor,
  listObservationsForTests,
  listTargetObservations,
  normalizeObservationTimestamp,
  observationTimeError,
  prepareObservation,
  projectObservation,
} from '../../src/services/targetHistory.mjs';
import { attachHistoryReadModel, deriveProtectionProfile, historyReadModel } from '../../src/services/protectionProfile.mjs';
import {
  assessOriginReachability,
  deriveBindingScope,
  validateOriginBindingForRun,
} from '../../src/services/originBindings.mjs';
import { presentFindingLineage } from '../../src/services/retestLineage.mjs';
import { getStore } from '../../src/store.mjs';

const TENANT = 'ten_hist_hard';
const GROUP = 'tg_hist_hard';
const NOW = new Date('2026-10-04T12:00:00.000Z');
const DECLARED = '2026-09-01T00:00:00.000Z';
const ADMIN = { tenantId: TENANT, userId: 'usr_hard', role: 'admin' };
const VIEWER = { tenantId: TENANT, userId: 'usr_view', role: 'viewer' };
const ORIGIN_CHECK = 'origin.host_sni_bypass.safe';

function scrub() {
  const store = getStore();
  for (const key of [
    'targets', 'targetGroups', 'targetVerifications', 'targetObservations', 'targetObservationCurrents',
    'originBindings', 'findingRetestLineage', 'findings', 'testRuns',
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
    target_id: 'tgt_origin',
    family: 'origin_hosting',
    check_id: ORIGIN_CHECK,
    source_kind: 'validation_run',
    test_run_id: 'run_signed',
    corpus_version: null,
    scenario_version: 'scenario-1',
    check_version: 'check-1',
    observed_at: '2026-09-11T00:00:00.000Z',
    source_completed_at: '2026-09-11T00:00:01.000Z',
    outcome: 'reachable',
    producer_kind: 'signed_probe',
    origin_binding_id: 'obind_hard',
    nonce: `nonce-${Math.random().toString(16).slice(2)}`,
    provenance: { status: 'reachable' },
    ...overrides,
  };
}

function bindingRow(overrides = {}) {
  return {
    id: 'obind_hard',
    tenant_id: TENANT,
    protected_target_id: 'tgt_app',
    origin_target_id: 'tgt_origin',
    host: 'app.example.test',
    sni: 'app.example.test',
    port: 443,
    path: null,
    status: 'active',
    created_at: '2026-09-10T00:00:00.000Z',
    ...overrides,
  };
}

function verifiedProof(state = 'dns_verified') {
  return { verified: true, state };
}

function runGuard({ binding, scopeOverrides = {}, check = { probe_profile: { kind: 'host_sni_bypass' } } } = {}) {
  return validateOriginBindingForRun({
    binding,
    runTarget: { id: 'tgt_origin', kind: 'ip', value: '203.0.113.10' },
    protectedTarget: {
      id: 'tgt_app',
      kind: 'fqdn',
      value: 'app.example.test',
      declaration_json: { allowed_scope: { ports: [443, 8443], paths: ['/health', '/ready'], ...scopeOverrides } },
    },
    check,
    originProof: verifiedProof(),
    protectedProof: verifiedProof(),
    body: {},
  });
}

beforeEach(() => {
  scrub();
  const store = getStore();
  if (!Array.isArray(store.originBindings)) store.originBindings = [];
  store.targetGroups.push({ id: GROUP, tenant_id: TENANT, name: 'Hardening', ownership_status: 'dns_verified' });
  target({ id: 'tgt_app', kind: 'fqdn', value: 'app.example.test' });
  target({ id: 'tgt_origin', kind: 'ip', value: '203.0.113.10' });
  store.originBindings.push(bindingRow());
});

describe('stored binding scope at run start', () => {
  it('starts a valid multi-port multi-path binding from the stored choice', () => {
    const binding = bindingRow({ port: 8443, path: '/ready' });
    const ok = runGuard({ binding });
    assert.equal(ok.ok, true);
    assert.equal(ok.scope.port, 8443);
    assert.equal(ok.scope.path, '/ready');
    assert.equal(ok.scope.host, 'app.example.test');
    assert.equal(ok.scope.sni, 'app.example.test');
  });

  it('still rejects a stored choice that is no longer inside the declared scope', () => {
    const binding = bindingRow({ port: 8443, path: '/ready' });
    const narrowed = runGuard({ binding, scopeOverrides: { ports: [443], paths: ['/health'] } });
    assert.equal(narrowed.error, 'scope_mismatch');
    assert.equal(JSON.stringify(narrowed).includes('203.0.113'), false);
  });

  it('keeps port_unspecified when the stored binding has no port and several are allowed', () => {
    const binding = bindingRow({ port: null, path: '/ready' });
    const unspecified = runGuard({ binding });
    assert.equal(unspecified.error, 'port_unspecified');
  });

  it('keeps single-value scope derivation and the host and SNI comparison', () => {
    const binding = bindingRow({ port: 443, path: null });
    const ok = runGuard({ binding, scopeOverrides: { paths: undefined } });
    assert.equal(ok.ok, true);
    assert.equal(ok.scope.port, 443);
    const renamed = runGuard({ binding: bindingRow({ host: 'other.example.test', path: '/health' }) });
    assert.equal(renamed.error, 'scope_mismatch');
    assert.equal(runGuard({ binding: bindingRow(), check: { probe_profile: { kind: 'http_head' } } }).error, 'origin_check_not_approved');
    assert.equal(deriveBindingScope(
      { kind: 'fqdn', value: 'app.example.test', declaration_json: { allowed_scope: { ports: [443, 8443], paths: ['/a', '/b'] } } },
      { port: 9000, path: '/a' },
    ).error, 'scope_mismatch');
  });
});

describe('bound origin reachability source requirements', () => {
  function reach(observations) {
    return assessOriginReachability(bindingRow(), observations, verifiedProof());
  }

  it('accepts a signed, approved-check, origin-target bound observation', () => {
    const row = acceptTargetObservation(ADMIN, observation(), { internal: true, now: NOW });
    const result = reach(listObservationsForTests(TENANT));
    assert.equal(result.status, 'reachable');
    assert.equal(result.observation_id, row.id);
    assert.equal(result.capacity_assurance, false);
    assert.equal(result.lockdown, 'not_established');
    assert.deepEqual(result.limitations, ['scoped_to_bound_host_sni_port_path', 'not_capacity_assurance', 'not_origin_lockdown']);
  });

  it('stays not_tested for simulation, manual, declaration, and null producers', () => {
    for (const producer of ['internal_simulation', 'manual', 'customer_declaration', null]) {
      const row = acceptTargetObservation(ADMIN, observation({
        nonce: `producer-${producer ?? 'null'}`,
        producer_kind: producer,
      }), { internal: true, now: NOW });
      assert.equal(row.producer_kind, producer ?? null);
      const result = reach([row]);
      assert.equal(result.status, 'not_tested');
      assert.equal(result.reason, 'no_bound_finalized_evidence');
      assert.equal(result.observation_id, null);
    }
  });

  it('stays not_tested for the wrong target, family, check, or missing completion', () => {
    // A retained row can carry a binding id with the wrong target when it bypassed
    // the writer; the reader must not trust it.
    const wrongTarget = {
      ...projectObservation(observation()),
      id: 'obs_wrong_target',
      target_id: 'tgt_app',
      test_run_id: null,
    };
    const wrongFamily = acceptTargetObservation(ADMIN, observation({ family: 'waf', check_id: 'waf.fingerprint.safe', nonce: 'wrong-family' }), { internal: true, now: NOW });
    const unapprovedCheck = acceptTargetObservation(ADMIN, observation({ check_id: 'waf.fingerprint.safe', nonce: 'wrong-check' }), { internal: true, now: NOW });
    const noCompletion = acceptTargetObservation(ADMIN, observation({ source_completed_at: null, nonce: 'no-completion' }), { internal: true, now: NOW });
    for (const [name, row] of [['target', wrongTarget], ['family', wrongFamily], ['check', unapprovedCheck], ['completion', noCompletion]]) {
      const result = reach([row]);
      assert.equal(result.status, 'not_tested', name);
      assert.equal(result.reason, 'no_bound_finalized_evidence', name);
    }
  });

  it('keeps a bound failed attempt from upgrading the profile and from replacing the success pointer', () => {
    const success = acceptTargetObservation(ADMIN, observation(), { internal: true, now: NOW });
    const failure = acceptTargetObservation(ADMIN, observation({
      nonce: 'bound-timeout',
      outcome: 'timeout',
      observed_at: '2026-09-12T00:00:00.000Z',
      source_completed_at: '2026-09-12T00:00:01.000Z',
    }), { internal: true, now: NOW });
    assert.equal(failure.attempt_class, 'failed_attempt');
    const result = reach([success, failure]);
    assert.equal(result.status, 'reachable');
    assert.equal(result.observation_id, success.id);
    const state = getStore().targetObservationCurrents.find((row) => row.family === 'origin_hosting');
    assert.equal(state.successful_observation_id, success.id);
    assert.equal(state.failed_attempt_observation_id, failure.id);
  });

  it('does not let a public append mint live proof', () => {
    const public_ = appendTargetObservation(ADMIN, observation({
      producer_kind: undefined,
      check_version: undefined,
    }), { now: NOW });
    assert.equal(public_.producer_kind, null);
    const result = reach([public_]);
    assert.equal(result.status, 'not_tested');
    assert.equal(result.reason, 'no_bound_finalized_evidence');
  });
});

describe('provenance header and credential string redaction', () => {
  it('drops Cookie, Set-Cookie, and Basic strings before insert and on read', () => {
    const leaked = appendTargetObservation(ADMIN, observation({
      target_id: 'tgt_app',
      family: 'waf',
      check_id: 'waf.fingerprint.safe',
      outcome: 'detected',
      observed_at: '2026-09-11T00:00:00.000Z',
      source_completed_at: '2026-09-11T00:00:01.000Z',
      producer_kind: undefined,
      check_version: undefined,
      origin_binding_id: undefined,
      provenance: {
        provider: 'Cookie: session=abc',
        note: 'Set-Cookie: a=b',
        product: 'Basic dXNlcjpwYXNz',
        reason: 'Authorization: Bearer tok',
        source: 'cookie=sid=1',
        safe: 'cloudflare',
        count: 3,
      },
    }), { now: NOW });
    assert.equal(leaked.error, undefined);
    assert.deepEqual(leaked.provenance, { safe: 'cloudflare', count: 3 });
    const stored = getStore().targetObservations.find((row) => row.id === leaked.id);
    assert.equal(JSON.stringify(stored.provenance_json).includes('Cookie:'), false);
    assert.equal(JSON.stringify(stored.provenance_json).includes('Set-Cookie:'), false);
    assert.equal(JSON.stringify(stored.provenance_json).includes('Basic '), false);
    assert.equal(JSON.stringify(stored.provenance_json).includes('dXNlcjpwYXNz'), false);
    const listed = listTargetObservations(VIEWER, { target_id: 'tgt_app', family: 'waf' });
    assert.equal(listed.items.length, 1);
    assert.equal(JSON.stringify(listed.items).includes('session=abc'), false);
    assert.equal(JSON.stringify(listed.items).includes('a=b'), false);
    assert.equal(JSON.stringify(listed.items).includes('tok'), false);
    assert.deepEqual(listed.items[0].provenance, { safe: 'cloudflare', count: 3 });
    const projected = projectObservation({ ...stored, provenance: { provider: 'Cookie: session=abc', safe: 'fastly' } });
    assert.deepEqual(projected.provenance, { safe: 'fastly' });
  });

  it('keeps short safe provider, note, and product strings and the source counts', () => {
    const row = acceptTargetObservation(ADMIN, observation({
      target_id: 'tgt_app',
      family: 'cdn',
      check_id: 'waf.fingerprint.safe',
      outcome: 'detected',
      observed_at: '2026-09-11T00:00:00.000Z',
      source_completed_at: '2026-09-11T00:00:01.000Z',
      origin_binding_id: undefined,
      provenance: { provider: 'cloudfront', note: 'edge header match', product: 'CloudFront', status: 'detected' },
    }), { internal: true, now: NOW });
    assert.deepEqual(row.provenance, {
      provider: 'cloudfront', note: 'edge header match', product: 'CloudFront', status: 'detected',
    });
  });

  it('rejects the strings through prepareObservation for every field shape', () => {
    for (const value of ['Cookie: session=abc', 'Set-Cookie: a=b', 'Basic dXNlcjpwYXNz', 'authorization: Bearer x', 'bearer abc.def']) {
      const prepared = prepareObservation(observation({
        target_id: 'tgt_app',
        family: 'waf',
        producer_kind: undefined,
        check_version: undefined,
        origin_binding_id: undefined,
        provenance: { provider: value },
      }), { tenantId: TENANT, target: getStore().targets.find((row) => row.id === 'tgt_app' && row.tenant_id === TENANT) });
      assert.equal(prepared.error, undefined, value);
      assert.equal(prepared.record.provenance.provider, undefined, value);
    }
    const safe = prepareObservation(observation({
      target_id: 'tgt_app',
      family: 'waf',
      producer_kind: undefined,
      check_version: undefined,
      origin_binding_id: undefined,
      provenance: { provider: 'fastly' },
    }), { tenantId: TENANT, target: getStore().targets.find((row) => row.id === 'tgt_app' && row.tenant_id === TENANT) });
    assert.equal(safe.record.provenance.provider, 'fastly');
  });
});

describe('latest retest attempt labeling', () => {
  const finding = {
    id: 'fnd_hard',
    tenant_id: TENANT,
    target_id: 'tgt_app',
    check_id: 'waf.fingerprint.safe',
    test_run_id: 'run_origin',
    status: 'open',
    closed_at: null,
  };
  const runs = [
    { id: 'run_origin', tenant_id: TENANT, target_id: 'tgt_app', check_id: 'waf.fingerprint.safe', status: 'verdicted', completed_at: '2026-09-01T10:00:00.000Z' },
    { id: 'run_retest', tenant_id: TENANT, target_id: 'tgt_app', check_id: 'waf.fingerprint.safe', status: 'running', completed_at: null },
    { id: 'run_retest_done', tenant_id: TENANT, target_id: 'tgt_app', check_id: 'waf.fingerprint.safe', status: 'completed', completed_at: '2026-09-20T10:00:00.000Z' },
  ];

  it('labels a running retest as explicitly pending without claiming its result', () => {
    const lineage = presentFindingLineage({
      finding,
      runs,
      lineage: [{ id: 'rtln_1', test_run_id: 'run_retest', created_at: '2026-09-20T00:00:00.000Z' }],
      siblings: [],
    });
    assert.deepEqual(lineage.latest, {
      test_run_id: 'run_retest',
      relation: 'retest',
      status: 'running',
      finalized: false,
      completed_at: null,
      pending: true,
      can_advance_remediation: false,
    });
    assert.equal(lineage.originating.status, 'verdicted');
    assert.equal(lineage.sibling_closure, false);
    assert.equal(JSON.stringify(lineage).includes('verdict":'), false);
    assert.equal(JSON.stringify(lineage.latest).includes('fix_proved'), false);
  });

  it('labels a finalized retest and a no-lineage originating latest', () => {
    const done = presentFindingLineage({
      finding,
      runs,
      lineage: [{ id: 'rtln_2', test_run_id: 'run_retest_done', created_at: '2026-09-21T00:00:00.000Z' }],
      siblings: [],
    });
    assert.equal(done.latest.status, 'completed');
    assert.equal(done.latest.finalized, true);
    assert.equal(done.latest.completed_at, '2026-09-20T10:00:00.000Z');
    assert.equal(done.latest.pending, false);
    assert.equal(done.latest.can_advance_remediation, false);
    const plain = presentFindingLineage({ finding, runs, lineage: [], siblings: [] });
    assert.equal(plain.latest.relation, 'originating');
    assert.equal(plain.latest.status, 'verdicted');
    assert.equal(plain.latest.finalized, true);
    assert.equal(plain.latest.completed_at, '2026-09-01T10:00:00.000Z');
    assert.equal(plain.latest.can_advance_remediation, false);
  });
});

describe('provider identity comparison', () => {
  const base = {
    id: 'obs_a',
    tenant_id: TENANT,
    target_id: 'tgt_app',
    family: 'waf',
    check_id: 'waf.fingerprint.safe',
    corpus_version: 'corpus-1',
    scenario_version: 'scenario-1',
    check_version: 'check-1',
    outcome: 'detected',
    attempt_class: 'successful',
    producer_kind: 'signed_probe',
    provenance: { status: 'detected', provider: 'ProviderA' },
  };

  it('records an explicit provider change with the safe identity fields', () => {
    const before = { ...base, id: 'obs_before', provenance: { status: 'detected', provider: 'ProviderA' } };
    const after = { ...base, id: 'obs_after', provenance: { status: 'detected', provider: 'ProviderB' } };
    const result = assessComparability(before, after);
    assert.equal(result.comparable, true);
    assert.equal(result.reason, null);
    assert.equal(result.change, 'changed');
    assert.equal(result.direction, 'provider_changed');
    assert.deepEqual(result.details, { before_provider: 'ProviderA', after_provider: 'ProviderB' });
    const back = assessComparability(after, before);
    assert.deepEqual(back.details, { before_provider: 'ProviderB', after_provider: 'ProviderA' });
    assert.equal(back.direction, 'provider_changed');
  });

  it('keeps unchanged and gap semantics for missing providers and versions', () => {
    const same = { ...base, id: 'obs_b', provenance: { status: 'detected', provider: 'ProviderA' } };
    const unchanged = assessComparability(base, same);
    assert.deepEqual(unchanged, { comparable: true, reason: null, change: 'unchanged', direction: null });
    const missingProvider = assessComparability(base, { ...base, id: 'obs_c', provenance: { status: 'detected' } });
    assert.equal(missingProvider.comparable, false);
    assert.equal(missingProvider.reason, 'provider_not_recorded');
    assert.equal(missingProvider.direction, null);
    const missingVersion = assessComparability(base, { ...base, id: 'obs_d', scenario_version: null, provenance: { provider: 'ProviderB' } });
    assert.equal(missingVersion.reason, 'missing_version');
    const outcomeChange = assessComparability(base, { ...base, id: 'obs_e', outcome: 'not_detected', provenance: { provider: 'ProviderB' } });
    assert.equal(outcomeChange.direction, 'disappeared');
    assert.equal(outcomeChange.details, undefined);
    assert.equal(assessComparability(base, { ...base, id: 'obs_f', family: 'cdn', provenance: { provider: 'ProviderB' } }).reason, 'context_mismatch');
  });

  it('does not require provider identity for generic outcomes and same not_detected', () => {
    // Same bound-origin reachability result with no recorded provider stays
    // backed-behavior comparable; it is never marked noncomparable for a
    // missing provider alone.
    const origin = (overrides = {}) => ({
      ...base, id: 'obs_origin', family: 'origin_hosting', outcome: 'reachable',
      producer_kind: 'signed_probe', ...overrides,
    });
    const supportedDirect = assessComparability(
      origin({ provenance: { status: 'reachable' } }),
      origin({ id: 'obs_origin2', provenance: { status: 'reachable' } }),
    );
    assert.deepEqual(supportedDirect, { comparable: true, reason: null, change: 'unchanged', direction: null });
    const passPair = assessComparability(
      { ...base, id: 'obs_pass', outcome: 'pass' },
      { ...base, id: 'obs_pass2', outcome: 'pass' },
    );
    assert.deepEqual(passPair, { comparable: true, reason: null, change: 'unchanged', direction: null });
    const sameNotDetected = assessComparability(
      { ...base, id: 'obs_absent', outcome: 'not_detected' },
      { ...base, id: 'obs_absent2', outcome: 'not_detected' },
    );
    assert.deepEqual(sameNotDetected, { comparable: true, reason: null, change: 'unchanged', direction: null });
    // A recorded provider change stays an explicit attribution change even for
    // generic outcomes.
    const providerChangeOnReach = assessComparability(
      origin({ provenance: { status: 'reachable', provider: 'ProviderA' } }),
      origin({ id: 'obs_origin3', provenance: { status: 'reachable', provider: 'ProviderB' } }),
    );
    assert.equal(providerChangeOnReach.comparable, true);
    assert.equal(providerChangeOnReach.direction, 'provider_changed');
    assert.deepEqual(providerChangeOnReach.details, { before_provider: 'ProviderA', after_provider: 'ProviderB' });
    // A same detected result without the recorded vendor is still a gap.
    const detectedGap = assessComparability(base, { ...base, id: 'obs_det_gap', provenance: { status: 'detected' } });
    assert.equal(detectedGap.reason, 'provider_not_recorded');
  });

  it('surfaces provider changes as comparable changes and version or provider gaps as comparison gaps', () => {
    const older = { ...base, id: 'obs_gap_old', observed_at: '2026-09-02T00:00:00.000Z', provenance: { status: 'detected', provider: 'ProviderA' } };
    const newer = { ...base, id: 'obs_gap_new', observed_at: '2026-09-03T00:00:00.000Z', provenance: { status: 'detected', provider: 'ProviderB' } };
    const noProvider = { ...base, id: 'obs_gap_none', observed_at: '2026-09-04T00:00:00.000Z', provenance: { status: 'detected' } };
    const model = historyReadModel({
      targetId: 'tgt_app',
      observations: [older, newer],
      bindings: [],
    });
    assert.equal(model.comparable_changes.length, 1);
    assert.equal(model.comparable_changes[0].direction, 'provider_changed');
    assert.equal(model.comparable_changes[0].details.after_provider, 'ProviderB');
    assert.equal(model.retained_family_states[0].provider_loss, false);
    const gapModel = historyReadModel({
      targetId: 'tgt_app',
      observations: [noProvider, newer],
      bindings: [],
    });
    assert.equal(gapModel.comparable_changes.length, 0);
    assert.equal(gapModel.comparison_gaps.length, 1);
    assert.equal(gapModel.comparison_gaps[0].reason, 'provider_not_recorded');
    const attached = attachHistoryReadModel(deriveProtectionProfile({ target: { id: 'tgt_app' } }), gapModel);
    assert.equal(attached.protection_profile.comparison_gaps.length, 1);
    assert.equal(attached.coverage.comparison_gaps.length, 1);
    assert.equal(attached.coverage.comparable_changes.length, 0);
    assert.equal(JSON.stringify(attached).includes('provider_not_recorded'), true);
  });
});

describe('microsecond timestamp ordering and cursor precision', () => {
  it('rejects pre-declaration and future observations without truncating microseconds', () => {
    const declaredAt = '2026-10-04T00:00:00.100002Z';
    const observedAt = '2026-10-04T00:00:00.100001Z';
    assert.equal(observationTimeError({ observedAt, declaredAt, now: NOW }).error, 'before_declaration');
    assert.equal(observationTimeError({ observedAt: declaredAt, sourceCompletedAt: observedAt, declaredAt, now: NOW }).error, 'before_declaration');
    assert.equal(observationTimeError({ observedAt: declaredAt, declaredAt, now: NOW }).error, undefined);
    assert.equal(observationTimeError({
      observedAt: '2026-10-04T12:02:00.000001Z', declaredAt, now: NOW,
    }).error, 'future_timestamp');
  });

  it('never uses evidence observed or completed before the binding at microsecond precision', () => {
    const created = '2026-09-11T00:00:00.100002Z';
    const before = '2026-09-11T00:00:00.100001Z';
    const binding = bindingRow({ created_at: created });
    const exact = observation({ id: 'obs_exact', attempt_class: 'successful', tenant_id: TENANT,
      observed_at: created, source_completed_at: created });
    for (const row of [
      { ...exact, observed_at: before },
      { ...exact, source_completed_at: before },
    ]) {
      assert.equal(assessOriginReachability(binding, [row], verifiedProof()).status, 'not_tested');
    }
    assert.equal(assessOriginReachability(binding, [exact], verifiedProof()).status, 'reachable');
  });

  it('normalizes and compares six-digit source precision without losing microseconds', () => {
    assert.equal(normalizeObservationTimestamp('2026-01-01T00:00:00.123001Z'), '2026-01-01T00:00:00.123001Z');
    assert.equal(normalizeObservationTimestamp('2026-01-01T00:00:00.123999Z'), '2026-01-01T00:00:00.123999Z');
    assert.equal(normalizeObservationTimestamp('2026-01-01T00:00:00.123Z'), '2026-01-01T00:00:00.123000Z');
    assert.equal(normalizeObservationTimestamp('2026-01-01T00:00:00Z'), '2026-01-01T00:00:00.000000Z');
    assert.equal(normalizeObservationTimestamp(new Date(Date.parse('2026-01-01T00:00:00.123Z'))), '2026-01-01T00:00:00.123000Z');
    assert.equal(normalizeObservationTimestamp('not-a-time'), null);
    const early = { observed_at: '2026-01-01T00:00:00.123001Z', id: 'obs_b' };
    const late = { observed_at: '2026-01-01T00:00:00.123999Z', id: 'obs_a' };
    assert.equal(compareObservationOrder(early, late), -1);
    assert.equal(compareObservationOrder(late, early), 1);
    assert.equal(compareObservationOrder({ ...early, id: 'obs_a' }, { ...late, id: 'obs_b' }), -1);
    const offset = normalizeObservationTimestamp('2026-01-01T02:00:00.123001+02:00');
    assert.equal(offset, '2026-01-01T00:00:00.123001Z');
  });

  it('round-trips a microsecond cursor and pages dev rows by real microseconds', () => {
    const first = acceptTargetObservation(ADMIN, observation({
      target_id: 'tgt_app',
      family: 'waf',
      check_id: 'waf.fingerprint.safe',
      outcome: 'detected',
      observed_at: '2026-09-11T00:00:00.123001Z',
      source_completed_at: '2026-09-11T00:00:01.123001Z',
      nonce: 'micro-early',
      origin_binding_id: undefined,
    }), { internal: true, now: NOW });
    assert.equal(first.observed_at, '2026-09-11T00:00:00.123001Z');
    const later = acceptTargetObservation(ADMIN, observation({
      target_id: 'tgt_app',
      family: 'waf',
      check_id: 'waf.fingerprint.safe',
      outcome: 'detected',
      observed_at: '2026-09-11T00:00:00.123999Z',
      source_completed_at: '2026-09-11T00:00:01.123999Z',
      nonce: 'micro-late',
      origin_binding_id: undefined,
    }), { internal: true, now: NOW });
    const page = listTargetObservations(VIEWER, { target_id: 'tgt_app', family: 'waf', limit: 1 });
    assert.equal(page.items.length, 1);
    assert.equal(page.items[0].id, later.id);
    assert.match(page.items[0].observed_at, /\.123999Z$/);
    const decoded = decodeObservationCursor(page.next_cursor);
    assert.equal(decoded.cursor.observed_at, '2026-09-11T00:00:00.123999Z');
    assert.equal(decoded.cursor.source_completed_at, '2026-09-11T00:00:01.123999Z');
    const rest = listTargetObservations(VIEWER, { target_id: 'tgt_app', family: 'waf', cursor: page.next_cursor, limit: 10 });
    assert.deepEqual(rest.items.map((row) => row.id), [first.id]);
    const encoded = encodeObservationCursor({ observed_at: '2026-01-01T00:00:00.123001Z', source_completed_at: null, id: 'obs_x' });
    assert.equal(decodeObservationCursor(encoded).cursor.observed_at, '2026-01-01T00:00:00.123001Z');
    assert.equal(compareObservationOrder(first, later), -1);
  });
});
