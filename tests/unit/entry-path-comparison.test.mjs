import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, getCheckById } from '../../src/contracts/checks.mjs';
import {
  PATH_VALIDATION_OUTCOMES,
  REQUIRED_LIMITATIONS,
  normalizeEntryPathComparisonRequest,
  normalizeEntryPathDeclaration,
} from '../../src/contracts/protectionValidation.mjs';
import {
  DEFAULT_SOURCE_PERSPECTIVE,
  attemptScopeMatches,
  buildApprovedScope,
  deriveAttemptObservation,
  describeEntryTarget,
  entryTargetScopeHash,
  evaluateEntryPathComparison,
  planEntryPathComparison,
  reviewedPlanMatches,
  revalidateScopeItem,
  runStartBodyForScopeItem,
  selectEntryPathCheck,
  verifyApprovedScope,
} from '../../src/lib/entryPathComparison.mjs';
import { classifyDirectOriginObservation } from '../../src/lib/externalObservationOutcomes.mjs';
import {
  ENTRY_PATH_SAFE_METHODS,
  buildEntryPathRequest,
  entryPathVariations,
  runEntryPathMarkerProbe,
  runWafClassMarkerProbe,
} from '../../src/lib/vectorProbes/wafClassProbes.mjs';
import { buildEvasionMarkerProfile, runWafEvasionMarkerProbe } from '../../src/lib/vectorProbes/evasionProbes.mjs';

const TENANT = 'ten_demo';
const T0 = '2026-10-06T10:00:00.000Z';
const T1 = '2026-10-06T10:05:00.000Z';
const SCENARIO = 'waf.ssrf_marker.safe';

const TARGETS = [
  { id: 'tgt_app', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'fqdn', value: 'app.example' },
  { id: 'tgt_alt', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'fqdn', value: 'alt.example' },
  { id: 'tgt_login', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'url', value: 'https://app.example/login' },
  { id: 'tgt_api', tenant_id: TENANT, target_group_id: 'tg_2', kind: 'url', value: 'https://api.example:8443/v1/orders' },
  { id: 'tgt_v6', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'url', value: 'https://[2001:db8::5]/' },
  { id: 'tgt_v4', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'url', value: 'https://203.0.113.20:8080/' },
  { id: 'tgt_origin', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'ip', value: '203.0.113.10' },
  { id: 'tgt_public', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'url', value: 'https://status.example/' },
  { id: 'tgt_hidden', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'url', value: 'https://admin.example/' },
];

const BINDING = { id: 'ob_1', tenant_id: TENANT, status: 'active', protected_target_id: 'tgt_app', origin_target_id: 'tgt_origin' };

function relation(id, body) {
  return {
    id,
    ...normalizeEntryPathDeclaration({
      owner: 'App Team',
      purpose: 'Declared route',
      expected_behavior: 'must_be_protected_by_layers',
      required_layers: ['waf'],
      ...body,
    }, { tenantId: TENANT, anchorTargetId: 'tgt_app' }),
  };
}

const RELATIONS = [
  relation('ep_primary', { entry_target_id: 'tgt_app', relation_kind: 'primary_route' }),
  relation('ep_alt', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname' }),
  relation('ep_login', { entry_target_id: 'tgt_login', relation_kind: 'declared_login_url' }),
  relation('ep_api', { entry_target_id: 'tgt_api', relation_kind: 'declared_api_url' }),
  relation('ep_v6', { entry_target_id: 'tgt_v6', relation_kind: 'alternate_hostname' }),
  relation('ep_v4', { entry_target_id: 'tgt_v4', relation_kind: 'fallback_backend_route' }),
  relation('ep_origin', { entry_target_id: 'tgt_origin', relation_kind: 'origin', origin_binding_id: 'ob_1' }),
  relation('ep_public', { entry_target_id: 'tgt_public', relation_kind: 'alternate_hostname', expected_behavior: 'intentionally_public', required_layers: [] }),
  relation('ep_hidden', { entry_target_id: 'tgt_hidden', relation_kind: 'alternate_hostname', expected_behavior: 'must_not_be_reachable', required_layers: [] }),
];

function request(entryPathIds, overrides = {}) {
  return normalizeEntryPathComparisonRequest({
    mode: 'plan',
    anchor_target_id: 'tgt_app',
    primary_entry_path_id: 'ep_primary',
    entry_path_ids: entryPathIds,
    expectation: { scenario: SCENARIO, layer_outcomes: { waf: 'enforce' } },
    ...overrides,
  });
}

function plan(entryPathIds = RELATIONS.map((row) => row.id), extra = {}) {
  return planEntryPathComparison({
    tenantId: TENANT,
    request: request(entryPathIds),
    anchorTarget: TARGETS[0],
    relations: extra.relations ?? RELATIONS,
    targets: extra.targets ?? TARGETS,
    originBindings: [BINDING],
    catalog: CHECK_CATALOG,
    authorize: extra.authorize ?? null,
  });
}

function approved(p) {
  return buildApprovedScope(p, { comparisonId: 'epc_1', approvedAt: T0, approvedBy: 'u1' });
}

function expectationOf(p) {
  return { id: 'pvx_1', ...p.expectation };
}

function signedTargetFor(item) {
  const target = TARGETS.find((row) => row.id === item.target_id);
  return { id: target.id, kind: target.kind, value: target.value, expected_behavior: null };
}

function markerAttempt(item, { baseline = 200, blocked = 2, allowed = 0, external = 'blocked', extra = {}, observedAt = T1 } = {}) {
  const results = [
    ...Array.from({ length: blocked }, (_, i) => ({ phase: `m${i}`, blocked: true, allowed: false, inconclusive: false, status_code: 403 })),
    ...Array.from({ length: allowed }, (_, i) => ({ phase: `a${i}`, blocked: false, allowed: true, inconclusive: false, status_code: 200 })),
  ];
  return {
    test_run_id: `run_${item.entry_path_id}`,
    run_status: 'verdicted',
    check_id: item.check_id,
    check_version: item.check_version,
    scenario_version: item.scenario_version,
    target_id: item.target_id,
    origin_binding_id: item.origin_binding_id ?? null,
    verdict_id: `verdict_${item.entry_path_id}`,
    evidence_ids: [`event_${item.entry_path_id}`],
    observed_at: observedAt,
    worker_id: 'worker-eu-1',
    signed_target: signedTargetFor(item),
    external_result: external,
    probe_metadata: {
      profile_kind: 'waf_class_marker_probe',
      permitted_baseline: { status_code: baseline },
      marker_results: results,
      ...extra,
    },
  };
}

function originAttempt(item, observation) {
  return {
    ...markerAttempt(item),
    external_result: observation.response_observed ? 'connected' : 'error',
    probe_metadata: { profile_kind: 'host_sni_bypass', origin_observation: observation },
  };
}

function itemFor(p, id) {
  return p.items.find((row) => row.entry_path_id === id);
}

function outcomes(result) {
  return Object.fromEntries(result.evaluation.items.map((row) => [row.entry_path_id, row.outcome]));
}

function okResponse(status, headers = {}) {
  return { status, headers: new Map(Object.entries(headers)) };
}

describe('check selection from exact declarations', () => {
  it('uses only approved host/SNI checks for origin relations and the scenario check elsewhere', () => {
    const origin = selectEntryPathCheck({ relation: RELATIONS[6], entryTarget: TARGETS[6], scenario: SCENARIO, catalog: CHECK_CATALOG });
    assert.equal(origin.check.probe_profile.kind, 'host_sni_bypass');
    const alt = selectEntryPathCheck({ relation: RELATIONS[1], entryTarget: TARGETS[1], scenario: SCENARIO, catalog: CHECK_CATALOG });
    assert.equal(alt.check.check_id, SCENARIO);
  });

  it('never selects body-sending or rate-sequence probes for a declared login URL', () => {
    const login = selectEntryPathCheck({ relation: RELATIONS[2], entryTarget: TARGETS[2], scenario: 'waf.inspection_limit.safe', catalog: CHECK_CATALOG });
    assert.equal(login.check, null);
    assert.equal(login.reason, 'login_path_state_change_risk');
    const family = selectEntryPathCheck({ relation: RELATIONS[2], entryTarget: TARGETS[2], scenario: 'marker', catalog: CHECK_CATALOG });
    assert.ok(['waf_class_marker_probe', 'waf_evasion_marker_probe', 'waf_enforcement_probe'].includes(family.check.probe_profile.kind));
  });

  it('reports unsupported target kinds and unknown scenarios instead of guessing', () => {
    const ipTarget = { id: 'tgt_ipx', tenant_id: TENANT, kind: 'ip', value: '198.51.100.4' };
    const rel = { ...RELATIONS[1], entry_target_id: 'tgt_ipx' };
    assert.equal(selectEntryPathCheck({ relation: rel, entryTarget: ipTarget, scenario: SCENARIO, catalog: CHECK_CATALOG }).reason, 'target_kind_not_supported');
    assert.equal(selectEntryPathCheck({ relation: RELATIONS[1], entryTarget: TARGETS[1], scenario: 'no.such.scenario', catalog: CHECK_CATALOG }).reason, 'no_eligible_check');
  });
});

describe('plan', () => {
  it('describes IPv4, IPv6, hostname, port, and path variants without deriving destinations', () => {
    const p = plan();
    assert.deepEqual(itemFor(p, 'ep_v6').target, { kind: 'url', address_family: 'ipv6', host: '2001:db8::5', port: null, path: '/', scheme: 'https' });
    assert.equal(itemFor(p, 'ep_v4').target.address_family, 'ipv4');
    assert.equal(itemFor(p, 'ep_v4').target.port, 8080);
    assert.equal(itemFor(p, 'ep_api').target.port, 8443);
    assert.equal(itemFor(p, 'ep_api').target.path, '/v1/orders');
    assert.equal(itemFor(p, 'ep_alt').target.address_family, 'hostname');
    assert.equal(itemFor(p, 'ep_origin').target.address_family, 'ipv4');
    assert.equal(describeEntryTarget({ kind: 'ip', value: '2001:db8::10' }).address_family, 'ipv6');
    const hashes = new Set(p.items.filter((row) => row.target_scope_hash).map((row) => row.target_scope_hash));
    assert.equal(hashes.size, p.items.filter((row) => row.target_scope_hash).length);
  });

  it('produces a stable digest that changes with declarations and eligibility', () => {
    const first = plan();
    const second = plan();
    assert.equal(first.plan_digest, second.plan_digest);
    assert.ok(reviewedPlanMatches(first, second.plan_digest));
    const archived = RELATIONS.map((row) => (row.id === 'ep_alt' ? { ...row, status: 'archived' } : row));
    const changed = plan(undefined, { relations: archived });
    assert.notEqual(changed.plan_digest, first.plan_digest);
    assert.equal(itemFor(changed, 'ep_alt').eligible, false);
    assert.equal(itemFor(changed, 'ep_alt').ineligible_reason, 'entry_path_archived');
    const gated = plan(undefined, { authorize: (rel) => (rel.id === 'ep_api' ? { ok: false, error: 'ownership_not_verified' } : { ok: true }) });
    assert.notEqual(gated.plan_digest, first.plan_digest);
    assert.equal(itemFor(gated, 'ep_api').ineligible_reason, 'ownership_not_verified');
  });

  it('marks unknown, foreign-tenant, deleted-target, and wrong-anchor relations ineligible', () => {
    const foreign = { ...RELATIONS[1], id: 'ep_foreign', tenant_id: 'ten_other' };
    const otherAnchor = { ...relation('ep_other', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname' }), anchor_target_id: 'tgt_alt' };
    const targets = TARGETS.map((row) => (row.id === 'tgt_public' ? { ...row, deleted_at: T0 } : row));
    const p = planEntryPathComparison({
      tenantId: TENANT,
      request: request(['ep_primary', 'ep_missing', 'ep_foreign', 'ep_other', 'ep_public']),
      anchorTarget: TARGETS[0],
      relations: [...RELATIONS, foreign, otherAnchor],
      targets,
      originBindings: [BINDING],
      catalog: CHECK_CATALOG,
    });
    assert.equal(itemFor(p, 'ep_missing').ineligible_reason, 'unknown_entry_path');
    assert.equal(itemFor(p, 'ep_foreign').ineligible_reason, 'unknown_entry_path');
    assert.equal(itemFor(p, 'ep_other').ineligible_reason, 'entry_path_not_in_anchor');
    assert.equal(itemFor(p, 'ep_public').ineligible_reason, 'target_not_active');
    assert.equal(p.eligible_count, 1);
  });

  it('reports expectation conflicts and carries required limitations', () => {
    const p = planEntryPathComparison({
      tenantId: TENANT,
      request: request(['ep_primary', 'ep_hidden'], { expectation: { scenario: SCENARIO, layer_outcomes: { waf: 'allow' } } }),
      anchorTarget: TARGETS[0],
      relations: RELATIONS,
      targets: TARGETS,
      originBindings: [BINDING],
      catalog: CHECK_CATALOG,
    });
    assert.ok(p.expectation_conflicts.some((row) => row.entry_path_id === 'ep_primary'));
    assert.ok(p.expectation_conflicts.some((row) => row.entry_path_id === 'ep_hidden'));
    assert.deepEqual(p.limitations, [...REQUIRED_LIMITATIONS.path_validation]);
  });

  it('builds run start bodies only from the approved scope item', () => {
    const p = plan();
    const body = runStartBodyForScopeItem(itemFor(p, 'ep_origin'));
    assert.deepEqual(Object.keys(body).sort(), ['check_id', 'origin_binding_id', 'target_group_id', 'target_id']);
    assert.equal(body.target_id, 'tgt_origin');
    assert.equal(body.origin_binding_id, 'ob_1');
    assert.deepEqual(Object.keys(runStartBodyForScopeItem(itemFor(p, 'ep_alt'))).sort(), ['check_id', 'target_group_id', 'target_id']);
  });
});

describe('approved scope integrity', () => {
  it('detects any tampering with the frozen scope', () => {
    const scope = approved(plan());
    assert.equal(verifyApprovedScope(scope), true);
    const tampered = structuredClone(scope);
    tampered.items.find((row) => row.entry_path_id === 'ep_alt').target_id = 'tgt_hidden';
    assert.equal(verifyApprovedScope(tampered), false);
    const result = evaluateEntryPathComparison({ scope: tampered, expectation: expectationOf(plan()), evaluatedAt: T1 });
    assert.equal(result.scope_valid, false);
    assert.ok(result.evaluation.items.every((row) => row.outcome === 'inconclusive' && row.reasons.includes('approved_scope_invalid')));
    assert.equal(result.evaluation.summary.accepted, false);
  });

  it('rejects attempts whose signed target, check, or binding drifted from the approved item', () => {
    const p = plan();
    const item = itemFor(p, 'ep_alt');
    assert.deepEqual(attemptScopeMatches(item, markerAttempt(item)), { ok: true, reasons: [] });
    const redirected = { ...markerAttempt(item), signed_target: { ...signedTargetFor(item), value: 'evil.example' } };
    assert.ok(attemptScopeMatches(item, redirected).reasons.includes('attempt_scope_hash_mismatch'));
    assert.ok(attemptScopeMatches(item, { ...markerAttempt(item), target_id: 'tgt_hidden' }).reasons.includes('attempt_target_mismatch'));
    assert.ok(attemptScopeMatches(item, { ...markerAttempt(item), check_id: 'waf.xxe_marker.safe' }).reasons.includes('attempt_check_mismatch'));
    assert.ok(attemptScopeMatches(item, { ...markerAttempt(item), origin_binding_id: 'ob_1' }).reasons.includes('attempt_binding_mismatch'));
    assert.ok(attemptScopeMatches(item, { ...markerAttempt(item), signed_target: null }).reasons.includes('attempt_signed_scope_missing'));
  });

  it('revalidates declarations, binding, and the exact target hash before each start', () => {
    const p = plan();
    const item = itemFor(p, 'ep_origin');
    const ctxArgs = { relation: RELATIONS[6], anchorTarget: TARGETS[0], entryTarget: TARGETS[6], originBinding: BINDING, tenantId: TENANT };
    assert.deepEqual(revalidateScopeItem(item, ctxArgs), { ok: true });
    assert.equal(revalidateScopeItem(item, { ...ctxArgs, entryTarget: { ...TARGETS[6], value: '198.51.100.99' } }).error, 'attempt_scope_hash_mismatch');
    assert.equal(revalidateScopeItem(item, { ...ctxArgs, originBinding: { ...BINDING, status: 'archived' } }).error, 'unknown_origin_binding');
    assert.equal(revalidateScopeItem(item, { ...ctxArgs, relation: { ...RELATIONS[6], status: 'archived' } }).error, 'entry_path_archived');
    assert.equal(revalidateScopeItem(item, { ...ctxArgs, relation: { ...RELATIONS[6], purpose: 'edited' } }).field, 'declaration_digest');
    assert.equal(entryTargetScopeHash(TARGETS[6]), item.target_scope_hash);
  });
});

describe('per-attempt observations', () => {
  const item = itemFor(plan(), 'ep_alt');

  it('never treats silence or transport failure as enforcement', () => {
    assert.equal(deriveAttemptObservation({ external_result: 'timeout', probe_metadata: { profile_kind: 'waf_class_marker_probe' } }).observation, 'no_response');
    const refused = deriveAttemptObservation({ external_result: 'error', probe_metadata: { profile_kind: 'waf_class_marker_probe', error_class: 'ECONNREFUSED' } });
    assert.equal(refused.observation, 'transport_error');
    assert.equal(refused.enforcement, 'unknown');
  });

  it('grades marker enforcement relative to a healthy permitted baseline', () => {
    assert.equal(deriveAttemptObservation(markerAttempt(item)).enforcement, 'enforced');
    assert.equal(deriveAttemptObservation(markerAttempt(item, { blocked: 1, allowed: 1 })).enforcement, 'partial');
    assert.equal(deriveAttemptObservation(markerAttempt(item, { blocked: 0, allowed: 2 })).enforcement, 'not_enforced');
    const unhealthy = deriveAttemptObservation(markerAttempt(item, { baseline: 503 }));
    assert.equal(unhealthy.enforcement, 'unknown');
    assert.ok(unhealthy.reasons.includes('permitted_baseline_not_healthy'));
    const denied = deriveAttemptObservation(markerAttempt(item, { baseline: 403 }));
    assert.equal(denied.observation, 'response_observed');
    assert.equal(denied.baseline_health, 'unhealthy');
    assert.equal(denied.leg_reason, 'unattributed_denial');
    const misdirected = deriveAttemptObservation(markerAttempt(item, { baseline: 421 }));
    assert.equal(misdirected.observation, null);
    assert.ok(misdirected.reasons.includes('misdirected_request'));
  });

  it('never grades block_suspected or inconclusive marker rows as enforcement', () => {
    const attempt = markerAttempt(item, { blocked: 0, allowed: 0 });
    attempt.probe_metadata.marker_results = [
      { phase: 'q', blocked: false, allowed: false, inconclusive: true, block_suspected: true, reason: 'unattributed_denial', status_code: 403 },
      { phase: 'h', blocked: false, allowed: false, inconclusive: true, reason: 'authentication_gate_precedes_inspection', status_code: 401 },
    ];
    const derived = deriveAttemptObservation(attempt);
    assert.equal(derived.enforcement, 'unknown');
    assert.equal(derived.leg_reason, 'authentication_gate_precedes_inspection');
  });

  it('keeps the blocked-baseline prerequisite for evasion comparisons', () => {
    const allowedBaseline = deriveAttemptObservation({
      external_result: 'not_run',
      probe_metadata: { profile_kind: 'waf_evasion_marker_probe', baseline_blocked: false, permitted_baseline_status: 200, variant_results: [{ label: 'baseline', blocked: false }, { label: 'double_url', blocked: false }] },
    });
    assert.equal(allowedBaseline.enforcement, 'unknown');
    assert.ok(allowedBaseline.reasons.includes('evasion_blocked_baseline_missing'));
    const weaker = deriveAttemptObservation({
      external_result: 'connected',
      probe_metadata: { profile_kind: 'waf_evasion_marker_probe', baseline_blocked: true, permitted_baseline_status: 200, variant_results: [{ label: 'baseline', blocked: true }, { label: 'double_url', blocked: false }] },
    });
    assert.equal(weaker.enforcement, 'partial');
    assert.equal(weaker.baseline_health, 'healthy');
  });

  it('confirms identity only from a nonce-bound canary and distrusts legacy origin flags', () => {
    const markerEcho = classifyDirectOriginObservation({
      response: okResponse(200, { 'x-astranull-marker-echo': 'mk' }),
      baseline: { status_code: 200 },
      expectedMarker: 'mk',
    });
    const derived = deriveAttemptObservation({ probe_metadata: { profile_kind: 'host_sni_bypass', origin_observation: markerEcho } });
    assert.equal(derived.observation, 'response_observed');
    assert.ok(derived.reasons.includes('marker_echo_not_nonce_bound'));
    const legacy = deriveAttemptObservation({ external_result: 'connected', probe_metadata: { profile_kind: 'host_sni_bypass', origin_bypass_confirmed: true } });
    assert.equal(legacy.observation, null);
    assert.ok(legacy.reasons.includes('observation_semantics_unsupported'));
    const canary = deriveAttemptObservation(markerAttempt(item, { blocked: 0, allowed: 2, extra: { application_identity: { confirmed: true, method: 'nonce_canary' } } }));
    assert.equal(canary.observation, 'application_identity_confirmed');
  });
});

describe('non-marker entry observations need real response evidence', () => {
  function httpHeadAttempt(item, external, metadata) {
    return { ...markerAttempt(item), external_result: external, probe_metadata: { profile_kind: 'http_head', ...metadata } };
  }

  it('classifies refusals, NXDOMAIN, server closes, and missing status as no response evidence', () => {
    const item = itemFor(plan(), 'ep_public');
    for (const code of ['ECONNREFUSED', 'ENOTFOUND', 'EHOSTUNREACH']) {
      const derived = deriveAttemptObservation(httpHeadAttempt(item, 'blocked', { error_class: code }));
      assert.equal(derived.observation, 'transport_error', code);
      assert.equal(derived.origin_path, false);
    }
    const closed = deriveAttemptObservation({ external_result: 'blocked', probe_metadata: { profile_kind: 'slow_header_probe', connection_closed_by_server: true } });
    assert.equal(closed.observation, 'transport_error');
    const refusedWithBaseline = deriveAttemptObservation(httpHeadAttempt(item, 'blocked', { error_class: 'ECONNREFUSED', permitted_baseline: { status_code: 200 } }));
    assert.equal(refusedWithBaseline.observation, 'transport_error');
    const silent = deriveAttemptObservation(httpHeadAttempt(item, 'connected', {}));
    assert.equal(silent.observation, null);
    assert.ok(silent.reasons.includes('response_evidence_not_recorded'));
  });

  it('maps a status code to a response, never to a denial; only a recorded signature is a denial', () => {
    const item = itemFor(plan(), 'ep_hidden');
    assert.equal(deriveAttemptObservation(httpHeadAttempt(item, 'connected', { status_code: 200 })).observation, 'response_observed');
    for (const [status, legReason] of [[401, 'authentication_gate_precedes_inspection'], [403, 'unattributed_denial'], [404, 'unattributed_denial'], [502, 'error_not_attributable']]) {
      const derived = deriveAttemptObservation(httpHeadAttempt(item, 'connected', { status_code: status }));
      assert.equal(derived.observation, 'response_observed', String(status));
      assert.equal(derived.leg_reason, legReason);
    }
    for (const [status, reason] of [[421, 'misdirected_request'], [407, 'probe_path_error']]) {
      const derived = deriveAttemptObservation(httpHeadAttempt(item, 'connected', { status_code: status }));
      assert.equal(derived.observation, null, String(status));
      assert.ok(derived.reasons.includes(reason));
    }
    const signed = deriveAttemptObservation(httpHeadAttempt(item, 'blocked', { status_code: 403, denial_signature: { kind: 'vendor', id: 'cloudflare_challenge', vendor: 'cloudflare' } }));
    assert.equal(signed.observation, 'explicit_denial_observed');
  });

  it('never grades silence as public access, exposure, or a fallback reachability gap', () => {
    const p = plan(['ep_primary', 'ep_public', 'ep_hidden', 'ep_v4']);
    const scope = approved(p);
    const result = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: {
        ep_primary: markerAttempt(itemFor(p, 'ep_primary')),
        ep_public: httpHeadAttempt(itemFor(p, 'ep_public'), 'blocked', { error_class: 'ECONNREFUSED' }),
        ep_hidden: httpHeadAttempt(itemFor(p, 'ep_hidden'), 'blocked', { error_class: 'ENOTFOUND' }),
        ep_v4: httpHeadAttempt(itemFor(p, 'ep_v4'), 'connected', {}),
      },
      evaluatedAt: T1,
    });
    assert.deepEqual(outcomes(result), {
      ep_primary: 'consistent_enforcement',
      ep_public: 'inconclusive',
      ep_hidden: 'inconclusive',
      ep_v4: 'inconclusive',
    });
    assert.equal(result.evaluation.summary.accepted, false);
    const hidden403 = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: { ep_hidden: httpHeadAttempt(itemFor(p, 'ep_hidden'), 'connected', { status_code: 403 }) },
      evaluatedAt: T1,
    });
    assert.equal(outcomes(hidden403).ep_hidden, 'reachability_exposure');
    const hiddenSigned = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: { ep_hidden: httpHeadAttempt(itemFor(p, 'ep_hidden'), 'blocked', { status_code: 403, denial_signature: { kind: 'vendor', id: 'akamai_reference_18', vendor: 'akamai' } }) },
      evaluatedAt: T1,
    });
    assert.equal(outcomes(hiddenSigned).ep_hidden, 'consistent_enforcement');
    for (const status of [401, 503]) {
      const hidden = evaluateEntryPathComparison({
        scope,
        expectation: expectationOf(p),
        attempts: { ep_hidden: httpHeadAttempt(itemFor(p, 'ep_hidden'), 'connected', { status_code: status }) },
        evaluatedAt: T1,
      });
      assert.equal(outcomes(hidden).ep_hidden, 'reachability_exposure', String(status));
    }
    const publicChallenge = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: { ep_public: httpHeadAttempt(itemFor(p, 'ep_public'), 'connected', { status_code: 401 }) },
      evaluatedAt: T1,
    });
    assert.equal(outcomes(publicChallenge).ep_public, 'intentional_public_access');
    const publicDenied = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: { ep_public: httpHeadAttempt(itemFor(p, 'ep_public'), 'connected', { status_code: 403 }) },
      evaluatedAt: T1,
    });
    const publicItem = publicDenied.evaluation.items.find((row) => row.entry_path_id === 'ep_public');
    assert.equal(publicItem.outcome, 'inconclusive');
    assert.ok(publicItem.reasons.includes('unattributed_denial'));
    const labels = Object.fromEntries(result.attempts.map((row) => [row.entry_path_id, row.observation_label]));
    assert.equal(/origin/i.test(labels.ep_public), false);
    const reached = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: { ep_public: httpHeadAttempt(itemFor(p, 'ep_public'), 'connected', { status_code: 200 }) },
      evaluatedAt: T1,
    });
    assert.equal(outcomes(reached).ep_public, 'intentional_public_access');
    assert.equal(reached.attempts.find((row) => row.entry_path_id === 'ep_public').observation_label, 'Response observed');
  });
});

describe('direct-origin denials need a control-specific signature', () => {
  it('grades a must_not_be_reachable origin from any HTTP response, and enforcement only from a signature', () => {
    const originRelations = RELATIONS.map((row) => (row.id === 'ep_origin'
      ? relation('ep_origin', { entry_target_id: 'tgt_origin', relation_kind: 'origin', origin_binding_id: 'ob_1', expected_behavior: 'must_not_be_reachable', required_layers: [] })
      : row));
    const p = plan(['ep_primary', 'ep_origin'], { relations: originRelations });
    const scope = approved(p);
    const evaluate = (observation) => evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: { ep_primary: markerAttempt(itemFor(p, 'ep_primary')), ep_origin: originAttempt(itemFor(p, 'ep_origin'), observation) },
      evaluatedAt: T1,
    });
    const challenge = evaluate(classifyDirectOriginObservation({ response: okResponse(401, { 'www-authenticate': 'Basic' }) }));
    assert.equal(outcomes(challenge).ep_origin, 'reachability_exposure');
    const detail = challenge.attempts.find((row) => row.entry_path_id === 'ep_origin');
    assert.equal(detail.observation, 'response_observed');
    const undeclared = evaluate(classifyDirectOriginObservation({ response: okResponse(403), baseline: { status_code: 200 } }));
    assert.equal(outcomes(undeclared).ep_origin, 'reachability_exposure');
    const locked = evaluate(classifyDirectOriginObservation({
      response: okResponse(403, { 'x-origin-lockdown': 'cdn-only' }),
      baseline: { status_code: 200 },
      declaredLockdown: { status_code: 403, header: { name: 'x-origin-lockdown', value: 'cdn-only' } },
    }));
    assert.equal(outcomes(locked).ep_origin, 'consistent_enforcement');
    const vendor = evaluate(classifyDirectOriginObservation({
      response: okResponse(403),
      bodyText: 'Access Denied. Reference #18.2f3e4d5c.1700000000.1a2b3c',
    }));
    assert.equal(outcomes(vendor).ep_origin, 'consistent_enforcement');
    for (const status of [421, 407]) {
      const gap = evaluate(classifyDirectOriginObservation({ response: okResponse(status), baseline: { status_code: 200 } }));
      assert.equal(outcomes(gap).ep_origin, 'inconclusive', String(status));
    }
    const edge = evaluate(classifyDirectOriginObservation({ response: okResponse(403, { server: 'cloudflare', 'cf-ray': '1' }), baseline: { status_code: 200 } }));
    const edgeItem = edge.evaluation.items.find((row) => row.entry_path_id === 'ep_origin');
    assert.equal(edgeItem.outcome, 'inconclusive');
    assert.ok(edgeItem.reasons.includes('not_applicable'));
    const edgeDetail = edge.attempts.find((row) => row.entry_path_id === 'ep_origin');
    assert.equal(edgeDetail.observation, 'not_applicable');
    assert.notEqual(edgeDetail.observation_label, 'Not tested');
  });
});

describe('evaluation', () => {
  function fullEvaluation(overrides = {}) {
    const p = plan();
    const scope = approved(p);
    const attempts = {
      ep_primary: markerAttempt(itemFor(p, 'ep_primary')),
      ep_alt: markerAttempt(itemFor(p, 'ep_alt')),
      ep_login: markerAttempt(itemFor(p, 'ep_login'), { blocked: 1, allowed: 1 }),
      ep_api: markerAttempt(itemFor(p, 'ep_api'), { blocked: 0, allowed: 2 }),
      ep_v6: null,
      ep_v4: markerAttempt(itemFor(p, 'ep_v4'), { blocked: 0, allowed: 2, extra: { application_identity: { confirmed: true, method: 'nonce_canary' } } }),
      ep_origin: originAttempt(itemFor(p, 'ep_origin'), classifyDirectOriginObservation({ response: okResponse(200), baseline: { status_code: 200 } })),
      ep_public: markerAttempt(itemFor(p, 'ep_public'), { blocked: 0, allowed: 2 }),
      ep_hidden: {
        ...markerAttempt(itemFor(p, 'ep_hidden')),
        probe_metadata: { profile_kind: 'http_head', status_code: 403, denial_signature: { kind: 'declared', id: 'declared_response', vendor: null } },
      },
      ...overrides,
    };
    return { p, scope, result: evaluateEntryPathComparison({ scope, expectation: expectationOf(p), attempts, evaluatedAt: '2026-10-06T10:10:00.000Z' }) };
  }

  it('distinguishes every path outcome against a healthy enforcing primary', () => {
    const { result } = fullEvaluation();
    assert.deepEqual(outcomes(result), {
      ep_primary: 'consistent_enforcement',
      ep_alt: 'consistent_enforcement',
      ep_login: 'weaker_observed_enforcement',
      ep_api: 'suspected_alternate_application_route',
      ep_v6: 'not_tested',
      ep_v4: 'scoped_application_bypass',
      ep_origin: 'reachability_exposure',
      ep_public: 'intentional_public_access',
      ep_hidden: 'consistent_enforcement',
    });
    for (const row of result.evaluation.items) {
      assert.ok(PATH_VALIDATION_OUTCOMES.includes(row.outcome));
      assert.equal(row.attribution, 'unattributed');
      for (const limitation of REQUIRED_LIMITATIONS.path_validation) assert.ok(row.limitations.includes(limitation));
      if (!['inconclusive', 'not_tested', 'skipped'].includes(row.outcome)) {
        assert.equal(row.evidence_refs.length, 1);
        assert.equal(row.evidence_refs[0].source_perspective, DEFAULT_SOURCE_PERSPECTIVE);
        assert.deepEqual(Object.keys(row.evidence_refs[0]).sort(), [
          'check_id', 'check_version', 'evidence_ids', 'finalized', 'observed_at', 'run_status', 'scenario_version',
          'source_perspective', 'target_id', 'test_run_id', 'verdict_id', 'worker_id',
        ]);
      }
    }
    assert.ok(result.evaluation.items.find((row) => row.entry_path_id === 'ep_origin').reasons.includes('reachability_only_comparison'));
    assert.equal(result.evaluation.summary.accepted, false);
    assert.equal(result.evaluation.summary.by_status.not_tested, 1);
    assert.ok(result.primary_evidence_set);
  });

  it('never lets primary success validate untested or skipped alternates', () => {
    const p = plan(['ep_primary', 'ep_alt', 'ep_login']);
    const scope = approved(p);
    const result = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: { ep_primary: markerAttempt(itemFor(p, 'ep_primary')) },
      execution: { ep_login: { state: 'skipped', skip_reason: 'kill_switch_active' } },
      evaluatedAt: T1,
    });
    assert.deepEqual(outcomes(result), { ep_primary: 'consistent_enforcement', ep_alt: 'not_tested', ep_login: 'skipped' });
    assert.ok(result.evaluation.items.find((row) => row.entry_path_id === 'ep_login').reasons.includes('kill_switch_active'));
    assert.equal(result.evaluation.summary.accepted, false);
    assert.equal(result.evaluation.summary.evaluated, 1);
  });

  it('is inconclusive without a healthy blocked primary baseline', () => {
    const p = plan(['ep_primary', 'ep_alt', 'ep_hidden']);
    const scope = approved(p);
    const allowedPrimary = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: {
        ep_primary: markerAttempt(itemFor(p, 'ep_primary'), { blocked: 0, allowed: 2 }),
        ep_alt: markerAttempt(itemFor(p, 'ep_alt'), { blocked: 0, allowed: 2 }),
        ep_hidden: markerAttempt(itemFor(p, 'ep_hidden'), { baseline: 200, blocked: 0, allowed: 0 }),
      },
      evaluatedAt: T1,
    });
    assert.deepEqual(outcomes(allowedPrimary), { ep_primary: 'inconclusive', ep_alt: 'inconclusive', ep_hidden: 'reachability_exposure' });
    assert.ok(allowedPrimary.evaluation.items.find((row) => row.entry_path_id === 'ep_alt').reasons.includes('blocked_primary_baseline_missing'));
    const missingPrimary = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: { ep_alt: markerAttempt(itemFor(p, 'ep_alt')) },
      evaluatedAt: T1,
    });
    const alt = missingPrimary.evaluation.items.find((row) => row.entry_path_id === 'ep_alt');
    assert.equal(alt.outcome, 'inconclusive');
    assert.ok(alt.compatibility_reasons.includes('evidence_missing'));
  });

  it('keeps timeouts, transport errors, drifted scopes, and unsigned evidence inconclusive', () => {
    const p = plan();
    const { result } = fullEvaluation({
      ep_alt: { ...markerAttempt(itemFor(p, 'ep_alt')), external_result: 'timeout' },
      ep_login: { ...markerAttempt(itemFor(p, 'ep_login')), external_result: 'error', probe_metadata: { profile_kind: 'waf_class_marker_probe', error_class: 'ECONNRESET' } },
      ep_api: { ...markerAttempt(itemFor(p, 'ep_api')), signed_target: { id: 'tgt_api', kind: 'url', value: 'https://redirected.example/' } },
      ep_public: { ...markerAttempt(itemFor(p, 'ep_public'), { blocked: 0, allowed: 2 }), worker_id: null },
    });
    const byId = Object.fromEntries(result.evaluation.items.map((row) => [row.entry_path_id, row]));
    assert.equal(byId.ep_alt.outcome, 'inconclusive');
    assert.ok(byId.ep_alt.reasons.includes('no_response_enforcement_unverified'));
    assert.equal(byId.ep_login.outcome, 'inconclusive');
    assert.ok(byId.ep_login.reasons.includes('transport_error_enforcement_unverified'));
    assert.equal(byId.ep_api.outcome, 'inconclusive');
    assert.ok(byId.ep_api.reasons.includes('attempt_scope_hash_mismatch'));
    assert.equal(byId.ep_public.outcome, 'inconclusive');
    assert.ok(byId.ep_public.compatibility_reasons.includes('source_missing'));
  });

  it('does not convert a cross-scenario origin denial into consistent enforcement', () => {
    const p = plan();
    const denial = classifyDirectOriginObservation({
      response: okResponse(403, { 'x-origin-lockdown': 'cdn-only' }),
      baseline: { status_code: 200 },
      declaredLockdown: { status_code: 403, header: { name: 'x-origin-lockdown', value: 'cdn-only' } },
    });
    const { result } = fullEvaluation({ ep_origin: originAttempt(itemFor(p, 'ep_origin'), denial) });
    const origin = result.evaluation.items.find((row) => row.entry_path_id === 'ep_origin');
    assert.equal(origin.outcome, 'inconclusive');
    assert.ok(origin.reasons.includes('scenario_not_comparable'));
    assert.ok(origin.reasons.includes('explicit_denial_observed'));
    assert.ok(origin.compatibility_reasons.includes('scenario_version_mismatch'));
  });

  it('keeps unsigned alternate-leg 401/403/5xx inconclusive against a signature-blocked primary', () => {
    const p = plan();
    for (const [status, reason] of [[401, 'authentication_gate_precedes_inspection'], [403, 'unattributed_denial'], [500, 'error_not_attributable']]) {
      const { result } = fullEvaluation({
        ep_origin: originAttempt(itemFor(p, 'ep_origin'), classifyDirectOriginObservation({ response: okResponse(status), baseline: { status_code: 200 } })),
      });
      const origin = result.evaluation.items.find((row) => row.entry_path_id === 'ep_origin');
      assert.equal(origin.outcome, 'inconclusive', String(status));
      assert.ok(origin.reasons.includes(reason), `${status}: ${origin.reasons}`);
    }
  });

  it('reports stacked edges without attributing the block to an inner layer', () => {
    const p = plan();
    const { result } = fullEvaluation({
      ep_alt: markerAttempt(itemFor(p, 'ep_alt'), { extra: { edge_signature: { stacked_vendor_signals: true, layers: ['cdn', 'waf'] } } }),
    });
    const alt = result.evaluation.items.find((row) => row.entry_path_id === 'ep_alt');
    assert.equal(alt.outcome, 'consistent_enforcement');
    assert.equal(alt.attribution, 'unattributed');
    assert.ok(alt.reasons.includes('stacked_edges_observed'));
  });

  it('marks evidence stale or declarations changed after approval as inconclusive', () => {
    const p = plan(['ep_primary', 'ep_alt']);
    const scope = approved(p);
    const attempts = { ep_primary: markerAttempt(itemFor(p, 'ep_primary')), ep_alt: markerAttempt(itemFor(p, 'ep_alt')) };
    const changed = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts,
      currentDeclarationDigests: { ep_alt: 'archived' },
      evaluatedAt: T1,
    });
    assert.ok(changed.evaluation.items.find((row) => row.entry_path_id === 'ep_alt').compatibility_reasons.includes('declaration_changed'));
    const stale = evaluateEntryPathComparison({
      scope,
      expectation: expectationOf(p),
      attempts: { ...attempts, ep_alt: markerAttempt(itemFor(p, 'ep_alt'), { observedAt: '2026-12-30T00:00:00.000Z' }) },
      evaluatedAt: T1,
    });
    const staleAlt = stale.evaluation.items.find((row) => row.entry_path_id === 'ep_alt');
    assert.equal(staleAlt.outcome, 'inconclusive');
    assert.ok(staleAlt.compatibility_reasons.includes('baseline_stale'));
  });

  it('treats an unfinished attempt as not tested', () => {
    const p = plan(['ep_primary', 'ep_alt']);
    const result = evaluateEntryPathComparison({
      scope: approved(p),
      expectation: expectationOf(p),
      attempts: { ep_primary: markerAttempt(itemFor(p, 'ep_primary')), ep_alt: { ...markerAttempt(itemFor(p, 'ep_alt')), run_status: 'collecting' } },
      evaluatedAt: T1,
    });
    assert.equal(outcomes(result).ep_alt, 'not_tested');
  });
});

describe('declared login/API path scenarios (wafClassProbes)', () => {
  it('only uses safe methods, never sends a body, and stays within 8 requests', async () => {
    for (const scenario of ['declared_login_path', 'declared_api_path']) {
      const calls = [];
      const fetchFn = async (url, init) => {
        calls.push({ url, init });
        const marker = String(url).includes('astranull_') || Boolean(init?.headers?.['x-astranull-marker']);
        return marker ? okResponse(403, { 'cf-mitigated': 'challenge' }) : okResponse(200);
      };
      const result = await runEntryPathMarkerProbe({ url: 'https://app.example/login', entry_path_scenario: scenario, marker_class: 'sqli', fetchFn });
      assert.ok(calls.length <= 8);
      assert.equal(result.requests_sent, calls.length);
      for (const call of calls) {
        assert.ok(ENTRY_PATH_SAFE_METHODS.includes(call.init.method));
        assert.equal(call.init.body, undefined);
        assert.equal(call.init.redirect, 'manual');
        const sent = new URL(call.url);
        assert.equal(sent.host, 'app.example');
        assert.equal(sent.pathname, '/login');
      }
      assert.equal(result.enforcement, 'enforced');
      assert.equal(result.posture, 'protected');
      assert.equal(result.baseline_health, 'healthy');
      assert.equal(result.redirects_followed, false);
    }
  });

  it('covers encoding, content-type, and bounded inspection-limit variations', () => {
    const variations = entryPathVariations('declared_api_path').map((row) => row.variation);
    assert.ok(variations.includes('query_marker_double_encoded'));
    assert.ok(variations.includes('query_marker_json_content_type'));
    assert.ok(variations.includes('query_marker_after_padding'));
    assert.ok(variations.includes('header_marker_after_padding'));
    const padded = entryPathVariations('declared_api_path').find((row) => row.variation === 'query_marker_after_padding');
    const request = buildEntryPathRequest('https://api.example:8443/v1/orders?keep=1', 'sqli', padded);
    const url = new URL(request.url);
    assert.equal(url.port, '8443');
    assert.equal(url.searchParams.get('keep'), '1');
    assert.equal(url.searchParams.get('astranull_pad').length, 2048);
    assert.throws(() => buildEntryPathRequest('https://api.example/', 'sqli', { variation: 'x', method: 'POST', where: 'query' }));
  });

  it('reports partial enforcement and keeps an unhealthy baseline inconclusive', async () => {
    const partial = await runEntryPathMarkerProbe({
      url: 'https://app.example/api',
      entry_path_scenario: 'declared_api_path',
      fetchFn: async (url, init) => (String(url).includes('astranull_pad') || init?.headers?.['x-astranull-padding']
        ? okResponse(200)
        : (String(url).includes('astranull_') || init?.headers?.['x-astranull-marker'] ? okResponse(403, { 'cf-mitigated': 'challenge' }) : okResponse(200))),
    });
    assert.equal(partial.enforcement, 'partial');
    const unhealthy = await runEntryPathMarkerProbe({ url: 'https://app.example/api', entry_path_scenario: 'declared_api_path', fetchFn: async () => okResponse(503) });
    assert.equal(unhealthy.enforcement, 'unknown');
    assert.equal(unhealthy.posture, 'inconclusive');
  });

  it('confirms identity only when the baseline echoes the expected nonce', async () => {
    const fetchFn = async (url, init) => okResponse(200, init?.headers?.['x-astranull-nonce'] ? { 'x-astranull-canary-echo': init.headers['x-astranull-nonce'] } : {});
    const confirmed = await runWafClassMarkerProbe({ url: 'https://app.example/', entry_path_scenario: 'declared_login_path', expected_nonce: 'n-123', fetchFn });
    assert.deepEqual(confirmed.application_identity, { confirmed: true, method: 'nonce_canary', attempted: true });
    const wrong = await runEntryPathMarkerProbe({
      url: 'https://app.example/',
      entry_path_scenario: 'declared_login_path',
      expected_nonce: 'n-123',
      fetchFn: async () => okResponse(200, { 'x-astranull-canary-echo': 'other' }),
    });
    assert.equal(wrong.application_identity.confirmed, false);
    assert.equal(JSON.stringify(wrong).includes('n-123'), false);
  });

  it('stops on a baseline transport failure without grading enforcement', async () => {
    let calls = 0;
    const result = await runEntryPathMarkerProbe({
      url: 'https://app.example/',
      entry_path_scenario: 'declared_login_path',
      fetchFn: async () => {
        calls += 1;
        throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' });
      },
    });
    assert.equal(calls, 1);
    assert.equal(result.enforcement, 'unknown');
    assert.equal(result.error_class, 'baseline_transport_error');
  });
});

describe('evasion entry-path baseline (evasionProbes)', () => {
  it('adds a permitted baseline and keeps the blocked-baseline prerequisite', async () => {
    const statuses = [200, 200, 200];
    let index = 0;
    const job = { target: { value: 'https://app.example/login' }, probe_profile: buildEvasionMarkerProfile({ transform: 'double_url', entry_path_scenario: 'declared_login_path' }) };
    const allowed = await runWafEvasionMarkerProbe(job, { fetchFn: async () => okResponse(statuses[index++] ?? 200) });
    assert.equal(allowed.external_result, 'inconclusive');
    assert.equal(allowed.metadata.blocked_baseline_prerequisite, 'not_met');
    assert.equal(allowed.metadata.permitted_baseline_health, 'healthy');
    const sequence = [okResponse(200), okResponse(403, { 'cf-mitigated': 'challenge' }), okResponse(200)];
    index = 0;
    const weaker = await runWafEvasionMarkerProbe(job, { fetchFn: async () => sequence[index++] });
    assert.equal(weaker.external_result, 'external_allowed');
    assert.equal(weaker.metadata.blocked_baseline_prerequisite, 'met');
    const unsigned = [200, 403, 200];
    index = 0;
    const bare = await runWafEvasionMarkerProbe(job, { fetchFn: async () => okResponse(unsigned[index++]) });
    assert.equal(bare.external_result, 'inconclusive');
    assert.equal(bare.metadata.blocked_baseline_prerequisite, 'not_observed');
  });

  it('never counts a transformed-variant transport failure as an allowed bypass', async () => {
    let index = 0;
    const job = { target: { value: 'https://app.example/' }, probe_profile: buildEvasionMarkerProfile({ transform: 'double_url' }) };
    const result = await runWafEvasionMarkerProbe(job, {
      fetchFn: async () => {
        index += 1;
        if (index === 1) return okResponse(403);
        throw Object.assign(new Error('reset'), { code: 'ECONNRESET' });
      },
    });
    assert.equal(result.external_result, 'inconclusive');
    assert.equal(result.metadata.evasion_bypass_suspected, false);
  });
});

describe('catalog sanity', () => {
  it('selected checks are customer-runnable existing catalog entries', () => {
    for (const item of plan().items.filter((row) => row.eligible)) {
      const check = getCheckById(item.check_id);
      assert.ok(check, item.check_id);
      assert.notEqual(check.risk_class, 'soc_gated');
    }
  });
});
