import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { PERMISSIONS } from '../../src/contracts/roles.mjs';
import {
  COMPARISON_KINDS,
  COMPATIBILITY_REASONS,
  ENTRY_PATH_EXPECTED_BEHAVIORS,
  ENTRY_PATH_RELATION_KINDS,
  EVIDENCE_REQUIREMENTS,
  FIREWALL_COMPARISON_STATUSES,
  FIREWALL_GAP_KINDS,
  LAYER_EVIDENCE_DIMENSIONS,
  LAYER_EVIDENCE_STATES,
  PATH_VALIDATION_OUTCOMES,
  PROTECTION_LAYERS,
  PROTECTION_VALIDATION_CONTRACT_VERSION,
  PROTECTION_VALIDATION_LIMITATIONS,
  PROTECTION_VALIDATION_ROUTES,
  REQUIRED_LIMITATIONS,
  ProtectionValidationError,
  assessComparisonCompatibility,
  assessFreshness,
  checkExpectationAgainstRelation,
  classifyEntryPathWrite,
  classifyFirewallComparisonItem,
  classifyFirewallExpectationWrite,
  classifyPathValidationItem,
  comparisonBaselineDigest,
  compatibilityFailureStatus,
  emptyLayerEvidence,
  emptyProtectionMatrixRow,
  entryPathAuthorizesExecution,
  entryPathComparisonPlanDigest,
  findBannedScopeKey,
  findProtectionValidationRoute,
  normalizeComparisonBaseline,
  normalizeComparisonEvaluation,
  normalizeEntryPathComparisonRequest,
  normalizeEntryPathDeclaration,
  normalizeEvidenceReference,
  normalizeFirewallBaselineCapture,
  normalizeFirewallBaselineRequest,
  normalizeFirewallComparisonRequest,
  normalizeFirewallExpectation,
  normalizeLayerEvidence,
  normalizePathValidationExpectation,
  sha256Digest,
  stableStringify,
  summarizeComparisonItems,
  validateComparisonBaseline,
  validateEntryPathDeclaration,
  validateEntryPathReferences,
  validateFirewallExpectation,
  verifyBaselineDigest,
} from '../../src/contracts/protectionValidation.mjs';

const TENANT = 'ten_a';

function relationBody(overrides = {}) {
  return {
    entry_target_id: 'tgt_alt',
    relation_kind: 'alternate_hostname',
    owner: '  App Team ',
    purpose: 'Legacy hostname kept for partner integrations',
    expected_behavior: 'must_be_protected_by_layers',
    required_layers: ['waf', 'cdn_edge'],
    ...overrides,
  };
}

function relation(overrides = {}, context = {}) {
  return { id: 'ep_1', ...normalizeEntryPathDeclaration(relationBody(overrides), { tenantId: TENANT, anchorTargetId: 'tgt_app', ...context }) };
}

function firewallBody(overrides = {}) {
  return {
    destination_target_id: 'tgt_fw',
    protocol: 'tcp',
    port: 443,
    expected: 'allow',
    source_perspective: 'public-worker-eu',
    change_id: 'CHG-1001',
    ...overrides,
  };
}

function ref(overrides = {}) {
  return {
    test_run_id: 'run_1',
    check_id: 'net.tcp.reachability',
    check_version: 'v3',
    scenario_version: null,
    verdict_id: 'verdict_1',
    evidence_ids: ['ev_2', 'ev_1'],
    target_id: 'tgt_fw',
    observed_at: '2026-10-01T00:00:00.000Z',
    run_status: 'verdicted',
    source_perspective: 'public-worker-eu',
    worker_id: 'worker_eu_1',
    ...overrides,
  };
}

function firewallSet(expectation, overrides = {}) {
  return {
    kind: 'firewall_change',
    tenant_id: TENANT,
    expectation_id: 'fwx_1',
    expectation_version: expectation.expectation_version,
    expectation_digest: expectation.digest,
    declaration_digest: null,
    target_id: 'tgt_fw',
    references: [ref()],
    captured_at: '2026-10-01T00:00:00.000Z',
    ...overrides,
  };
}

function pathSet(rel, expectation, overrides = {}) {
  return {
    kind: 'path_validation',
    tenant_id: TENANT,
    anchor_target_id: rel.anchor_target_id,
    entry_path_id: rel.id,
    expectation_id: 'pvx_1',
    expectation_version: expectation.expectation_version,
    expectation_digest: expectation.digest,
    declaration_digest: rel.declaration_digest,
    target_id: rel.entry_target_id,
    references: [ref({ target_id: rel.entry_target_id, check_id: 'waf.marker.sqli', scenario_version: 's2' })],
    captured_at: '2026-10-01T00:00:00.000Z',
    ...overrides,
  };
}

function rejects(fn, code, field) {
  assert.throws(fn, (err) => {
    assert.ok(err instanceof ProtectionValidationError, `expected ProtectionValidationError, got ${err}`);
    assert.equal(err.code, code);
    if (field !== undefined) assert.equal(err.field, field);
    return true;
  });
}

describe('protection validation contract enums', () => {
  it('pins the frozen vocabularies', () => {
    assert.deepEqual([...PROTECTION_LAYERS], ['waf', 'cdn_edge', 'network_firewall', 'ddos']);
    assert.deepEqual([...ENTRY_PATH_RELATION_KINDS], ['primary_route', 'alternate_hostname', 'declared_api_url', 'declared_login_url', 'origin', 'fallback_backend_route']);
    assert.deepEqual([...ENTRY_PATH_EXPECTED_BEHAVIORS], ['must_be_protected_by_layers', 'intentionally_public', 'must_not_be_reachable']);
    assert.deepEqual([...PATH_VALIDATION_OUTCOMES], [
      'intentional_public_access', 'reachability_exposure', 'weaker_observed_enforcement', 'suspected_alternate_application_route',
      'scoped_application_bypass', 'consistent_enforcement', 'inconclusive', 'not_tested', 'skipped',
    ]);
    assert.deepEqual([...FIREWALL_COMPARISON_STATUSES], ['matched', 'regression', 'improvement', 'inconclusive', 'not_tested', 'stale', 'not_comparable']);
    assert.deepEqual([...FIREWALL_GAP_KINDS], ['forbidden_service_newly_reachable', 'required_service_newly_unavailable']);
    assert.deepEqual([...LAYER_EVIDENCE_DIMENSIONS], [
      'declared_intent', 'vendor_detection', 'observed_enforcement', 'application_identity', 'suspected_bypass', 'confirmed_scoped_bypass', 'evidence_limitations',
    ]);
    for (const value of [PROTECTION_LAYERS, ENTRY_PATH_RELATION_KINDS, PATH_VALIDATION_OUTCOMES, FIREWALL_COMPARISON_STATUSES, PROTECTION_VALIDATION_ROUTES]) {
      assert.ok(Object.isFrozen(value));
    }
  });

  it('includes the required limitation strings', () => {
    for (const limitation of ['sampled_public_ingress_only', 'rule_table_equivalence_not_established', 'routing_nat_egress_east_west_not_established', 'not_capacity_assurance']) {
      assert.ok(PROTECTION_VALIDATION_LIMITATIONS.includes(limitation));
      assert.ok(REQUIRED_LIMITATIONS.firewall_change.includes(limitation));
    }
    assert.ok(REQUIRED_LIMITATIONS.path_validation.includes('not_capacity_assurance'));
    assert.ok(REQUIRED_LIMITATIONS.path_validation.includes('firewall_traversal_not_established'));
    assert.ok(REQUIRED_LIMITATIONS.path_validation.includes('stacked_layer_attribution_not_established'));
  });

  it('gives every status an evidence requirement and an unknown/inconclusive alternative', () => {
    for (const status of PATH_VALIDATION_OUTCOMES) {
      const entry = EVIDENCE_REQUIREMENTS.path_validation[status];
      assert.ok(entry?.requires, status);
      assert.ok(['inconclusive', 'not_tested', 'skipped', 'suspected_alternate_application_route'].includes(entry.unknown_alternative), status);
    }
    for (const status of FIREWALL_COMPARISON_STATUSES) {
      const entry = EVIDENCE_REQUIREMENTS.firewall_change[status];
      assert.ok(entry?.requires, status);
      assert.ok(['inconclusive', 'not_tested', 'stale', 'not_comparable'].includes(entry.unknown_alternative), status);
    }
    for (const dimension of LAYER_EVIDENCE_DIMENSIONS) {
      const entry = EVIDENCE_REQUIREMENTS.layer[dimension];
      assert.ok(entry?.requires, dimension);
      if (LAYER_EVIDENCE_STATES[dimension]) assert.ok(LAYER_EVIDENCE_STATES[dimension].includes(entry.unknown_alternative), dimension);
    }
  });
});

describe('route and permission map', () => {
  it('uses only existing least-privilege permissions', () => {
    const allowed = new Set(['target_group:read', 'target_group:write', 'evidence:read', 'test_run:start']);
    for (const entry of PROTECTION_VALIDATION_ROUTES) {
      assert.ok(allowed.has(entry.permission), `${entry.method} ${entry.path}`);
      assert.ok(PERMISSIONS[entry.permission], entry.permission);
      assert.ok(entry.path.startsWith('/v1/'));
      if (entry.method === 'GET') {
        assert.equal(entry.passive, true);
        assert.equal(entry.mutates, false);
        assert.ok(['target_group:read', 'evidence:read'].includes(entry.permission));
      }
    }
  });

  it('only the reviewed comparison start can dispatch traffic and there is no observation write route', () => {
    const active = PROTECTION_VALIDATION_ROUTES.filter((entry) => !entry.passive);
    assert.deepEqual(active.map((entry) => `${entry.method} ${entry.path}`), ['POST /v1/entry-path-comparisons']);
    assert.equal(active[0].permission, 'test_run:start');
    assert.ok(!PROTECTION_VALIDATION_ROUTES.some((entry) => /observation/.test(entry.path)));
    assert.equal(PROTECTION_VALIDATION_ROUTES.length, 18);
    assert.equal(new Set(PROTECTION_VALIDATION_ROUTES.map((entry) => `${entry.method} ${entry.path}`)).size, 18);
    const cancel = findProtectionValidationRoute('POST', '/v1/entry-path-comparisons/:comparisonId/cancel');
    assert.equal(cancel.permission, 'test_run:start');
    assert.equal(cancel.passive, true);
    assert.equal(findProtectionValidationRoute('POST', '/v1/firewall-baselines').permission, 'target_group:write');
    assert.equal(findProtectionValidationRoute('DELETE', '/v1/entry-paths/:entryPathId'), null);
  });

  it('viewers can read but cannot write or start', () => {
    assert.ok(PERMISSIONS['target_group:read'].includes('viewer'));
    assert.ok(PERMISSIONS['evidence:read'].includes('viewer'));
    assert.ok(!PERMISSIONS['target_group:write'].includes('viewer'));
    assert.ok(!PERMISSIONS['test_run:start'].includes('viewer'));
  });
});

describe('entry path declarations', () => {
  it('normalizes an explicit declaration with a stable digest', () => {
    const record = normalizeEntryPathDeclaration(relationBody(), { tenantId: TENANT, anchorTargetId: 'tgt_app' });
    assert.equal(record.owner, 'App Team');
    assert.deepEqual(record.required_layers, ['waf', 'cdn_edge']);
    assert.equal(record.status, 'active');
    assert.equal(record.declaration_source, 'explicit');
    assert.equal(record.declaration_version, 1);
    assert.equal(record.origin_binding_id, null);
    assert.match(record.declaration_digest, /^[a-f0-9]{64}$/);
    const reordered = normalizeEntryPathDeclaration(relationBody({ required_layers: ['cdn_edge', 'waf', 'waf'] }), { tenantId: TENANT, anchorTargetId: 'tgt_app' });
    assert.equal(reordered.declaration_digest, record.declaration_digest);
    const bumped = normalizeEntryPathDeclaration(relationBody(), { tenantId: TENANT, anchorTargetId: 'tgt_app', declarationVersion: 2 });
    assert.notEqual(bumped.declaration_digest, record.declaration_digest);
    const otherTenant = normalizeEntryPathDeclaration(relationBody(), { tenantId: 'ten_b', anchorTargetId: 'tgt_app' });
    assert.notEqual(otherTenant.declaration_digest, record.declaration_digest);
  });

  it('requires an origin binding exactly for origin relations', () => {
    rejects(() => relation({ relation_kind: 'origin' }), 'origin_binding_required', 'origin_binding_id');
    rejects(() => relation({ origin_binding_id: 'obind_1' }), 'origin_binding_not_allowed', 'origin_binding_id');
    assert.equal(relation({ relation_kind: 'origin', origin_binding_id: 'obind_1' }).origin_binding_id, 'obind_1');
  });

  it('enforces layer and behavior consistency', () => {
    rejects(() => relation({ required_layers: [] }), 'required_layers_conflict');
    rejects(() => relation({ expected_behavior: 'intentionally_public' }), 'required_layers_conflict');
    assert.deepEqual(relation({ expected_behavior: 'intentionally_public', required_layers: [] }).required_layers, []);
    assert.deepEqual(relation({ expected_behavior: 'must_not_be_reachable', required_layers: ['network_firewall'] }).required_layers, ['network_firewall']);
    rejects(() => relation({ required_layers: ['waf', 'antivirus'] }), 'invalid_entry_path', 'required_layers');
    rejects(() => relation({ relation_kind: 'vendor_inferred' }), 'invalid_entry_path', 'relation_kind');
    rejects(() => relation({ expected_behavior: 'protected' }), 'invalid_entry_path', 'expected_behavior');
  });

  it('rejects destination overrides, inference, secrets, and server-owned fields', () => {
    rejects(() => relation({ scope: { nested: [{ direct_ip: '203.0.113.9' }] } }), 'scope_not_declared', 'direct_ip');
    rejects(() => relation({ host_override: 'evil.example' }), 'scope_not_declared', 'host_override');
    rejects(() => relation({ inferred_from: 'tag:cdn' }), 'scope_not_declared', 'inferred_from');
    rejects(() => relation({ token: 'x' }), 'scope_not_declared', 'token');
    for (const field of ['status', 'declaration_digest', 'declaration_version', 'tenant_id', 'id']) {
      rejects(() => relation({ [field]: 'x' }), 'server_owned_field', field);
    }
    assert.equal(findBannedScopeKey({ service_endpoint: { port: 1 } }), null);
  });

  it('validates owner, purpose, ids, and anchor/entry pairing', () => {
    rejects(() => relation({ owner: '' }), 'invalid_entry_path', 'owner');
    rejects(() => relation({ owner: 'x'.repeat(121) }), 'invalid_entry_path', 'owner');
    rejects(() => relation({ purpose: 'bad\u0007purpose' }), 'invalid_entry_path', 'purpose');
    rejects(() => relation({ entry_target_id: '../etc' }), 'invalid_entry_path', 'entry_target_id');
    rejects(() => relation({ entry_target_id: 'tgt_app' }), 'invalid_entry_path', 'entry_target_id');
    assert.equal(relation({ entry_target_id: 'tgt_app', relation_kind: 'primary_route' }).entry_target_id, 'tgt_app');
    rejects(() => relation({ anchor_target_id: 'tgt_other' }), 'invalid_entry_path', 'anchor_target_id');
    rejects(() => normalizeEntryPathDeclaration(null), 'invalid_entry_path');
  });

  it('returns non-throwing results from validate*', () => {
    const bad = validateEntryPathDeclaration(relationBody({ relation_kind: 'nope' }), { anchorTargetId: 'tgt_app' });
    assert.deepEqual(Object.keys(bad).sort(), ['error', 'field', 'message', 'ok', 'status']);
    assert.equal(bad.ok, false);
    assert.equal(bad.status, 400);
    const good = validateEntryPathDeclaration(relationBody(), { anchorTargetId: 'tgt_app' });
    assert.equal(good.ok, true);
    assert.equal(good.value.relation_kind, 'alternate_hostname');
  });

  it('classifies idempotent writes as create, replay, or conflict', () => {
    const first = relation();
    assert.equal(classifyEntryPathWrite([], first).action, 'create');
    assert.equal(classifyEntryPathWrite([first], relation()).action, 'replay');
    const conflict = classifyEntryPathWrite([first], relation({ purpose: 'Different purpose' }));
    assert.equal(conflict.action, 'conflict');
    assert.equal(conflict.status, 409);
    assert.equal(classifyEntryPathWrite([{ ...first, status: 'archived' }], relation({ purpose: 'Different' })).action, 'create');
  });

  it('rejects cross-tenant and inactive references without disclosure', () => {
    const rel = relation();
    const anchor = { id: 'tgt_app', tenant_id: TENANT };
    const entry = { id: 'tgt_alt', tenant_id: TENANT };
    assert.deepEqual(validateEntryPathReferences({ tenantId: TENANT, relation: rel, anchorTarget: anchor, entryTarget: entry }), { ok: true });
    const foreign = validateEntryPathReferences({ tenantId: TENANT, relation: rel, anchorTarget: anchor, entryTarget: { id: 'tgt_alt', tenant_id: 'ten_b' } });
    assert.deepEqual(foreign, { ok: false, error: 'unknown_target', status: 404, field: 'entry_target_id' });
    assert.equal(validateEntryPathReferences({ tenantId: TENANT, relation: rel, anchorTarget: null, entryTarget: entry }).error, 'unknown_target');
    const deleted = validateEntryPathReferences({ tenantId: TENANT, relation: rel, anchorTarget: anchor, entryTarget: { ...entry, deleted_at: '2026-10-01T00:00:00Z' } });
    assert.equal(deleted.error, 'target_not_active');
    assert.equal(deleted.status, 409);
  });

  it('reuses origin binding authority for origin relations', () => {
    const rel = relation({ relation_kind: 'origin', origin_binding_id: 'obind_1', entry_target_id: 'tgt_ip' });
    const anchor = { id: 'tgt_app', tenant_id: TENANT };
    const entry = { id: 'tgt_ip', tenant_id: TENANT };
    const binding = { id: 'obind_1', tenant_id: TENANT, status: 'active', protected_target_id: 'tgt_app', origin_target_id: 'tgt_ip' };
    assert.equal(validateEntryPathReferences({ tenantId: TENANT, relation: rel, anchorTarget: anchor, entryTarget: entry, originBinding: binding }).ok, true);
    assert.equal(validateEntryPathReferences({ tenantId: TENANT, relation: rel, anchorTarget: anchor, entryTarget: entry, originBinding: { ...binding, status: 'archived' } }).error, 'unknown_origin_binding');
    assert.equal(validateEntryPathReferences({ tenantId: TENANT, relation: rel, anchorTarget: anchor, entryTarget: entry, originBinding: { ...binding, tenant_id: 'ten_b' } }).status, 404);
    assert.equal(validateEntryPathReferences({ tenantId: TENANT, relation: rel, anchorTarget: anchor, entryTarget: entry, originBinding: { ...binding, origin_target_id: 'tgt_other' } }).error, 'origin_binding_mismatch');
  });

  it('archived or tampered relations cannot authorize execution', () => {
    const rel = relation();
    const refs = { anchorTarget: { id: 'tgt_app', tenant_id: TENANT }, entryTarget: { id: 'tgt_alt', tenant_id: TENANT } };
    assert.equal(entryPathAuthorizesExecution(rel, refs).ok, true);
    assert.equal(entryPathAuthorizesExecution({ ...rel, status: 'archived' }, refs).error, 'entry_path_archived');
    assert.equal(entryPathAuthorizesExecution({ ...rel, required_layers: ['waf'] }, refs).field, 'declaration_digest');
  });
});

describe('behavior expectations', () => {
  it('normalizes a path validation expectation with canonical layer order', () => {
    const expectation = normalizePathValidationExpectation({ scenario: 'waf.sqli.marker', layer_outcomes: { cdn_edge: 'allow', waf: 'enforce' } }, { tenantId: TENANT, anchorTargetId: 'tgt_app' });
    assert.deepEqual(Object.keys(expectation.layer_outcomes), ['waf', 'cdn_edge']);
    assert.equal(expectation.kind, 'path_validation');
    assert.equal(expectation.expectation_version, 1);
    const again = normalizePathValidationExpectation({ scenario: 'waf.sqli.marker', layer_outcomes: { waf: 'enforce', cdn_edge: 'allow' } }, { tenantId: TENANT, anchorTargetId: 'tgt_app' });
    assert.equal(again.digest, expectation.digest);
    rejects(() => normalizePathValidationExpectation({ scenario: 'Bad Scenario', layer_outcomes: { waf: 'enforce' } }, { anchorTargetId: 'tgt_app' }), 'invalid_behavior_expectation', 'scenario');
    rejects(() => normalizePathValidationExpectation({ scenario: 's', layer_outcomes: {} }, { anchorTargetId: 'tgt_app' }), 'invalid_behavior_expectation', 'layer_outcomes');
    rejects(() => normalizePathValidationExpectation({ scenario: 's', layer_outcomes: { waf: 'maybe' } }, { anchorTargetId: 'tgt_app' }), 'invalid_behavior_expectation', 'layer_outcomes.waf');
  });

  it('flags expectations that contradict the relation declaration', () => {
    const rel = relation();
    const ok = normalizePathValidationExpectation({ scenario: 's', layer_outcomes: { waf: 'enforce', cdn_edge: 'enforce' } }, { anchorTargetId: 'tgt_app' });
    assert.deepEqual(checkExpectationAgainstRelation(ok, rel), { ok: true, conflicts: [] });
    const weak = normalizePathValidationExpectation({ scenario: 's', layer_outcomes: { waf: 'allow', cdn_edge: 'no_expectation' } }, { anchorTargetId: 'tgt_app' });
    assert.deepEqual(checkExpectationAgainstRelation(weak, rel).conflicts, ['required_layer_not_enforced:waf', 'required_layer_not_enforced:cdn_edge']);
    const unreachable = relation({ expected_behavior: 'must_not_be_reachable', required_layers: [] });
    assert.deepEqual(checkExpectationAgainstRelation(weak, unreachable).conflicts, ['unreachable_path_allows:waf']);
  });

  it('normalizes firewall expectations for tcp, udp, and service endpoints', () => {
    const tcp = normalizeFirewallExpectation(firewallBody(), { tenantId: TENANT });
    assert.equal(tcp.port, 443);
    assert.equal(tcp.service_endpoint, null);
    assert.equal(tcp.pre_post_mapping, null);
    assert.match(tcp.digest, /^[a-f0-9]{64}$/);
    const service = normalizeFirewallExpectation(firewallBody({ protocol: 'service', port: undefined, service_endpoint: { service: 'https', port: 8443, path: '/health' } }), { tenantId: TENANT });
    assert.deepEqual(service.service_endpoint, { service: 'https', port: 8443, path: '/health' });
    rejects(() => normalizeFirewallExpectation(firewallBody({ protocol: 'udp', port: 70000 })), 'invalid_firewall_expectation', 'port');
    rejects(() => normalizeFirewallExpectation(firewallBody({ protocol: 'icmp' })), 'invalid_firewall_expectation', 'protocol');
    rejects(() => normalizeFirewallExpectation(firewallBody({ protocol: 'service', service_endpoint: { service: 'https', port: 443 } })), 'invalid_firewall_expectation', 'port');
    rejects(() => normalizeFirewallExpectation(firewallBody({ service_endpoint: { service: 'https', port: 443 } })), 'invalid_firewall_expectation', 'service_endpoint');
    rejects(() => normalizeFirewallExpectation(firewallBody({ protocol: 'service', port: undefined, service_endpoint: { service: 'https', port: 443, path: '/a?b=1' } })), 'invalid_firewall_expectation', 'service_endpoint.path');
    rejects(() => normalizeFirewallExpectation(firewallBody({ expected: 'maybe' })), 'invalid_firewall_expectation', 'expected');
    rejects(() => normalizeFirewallExpectation(firewallBody({ source_perspective: 'Any Source' })), 'invalid_firewall_expectation', 'source_perspective');
    rejects(() => normalizeFirewallExpectation(firewallBody({ change_id: '' })), 'invalid_firewall_expectation', 'change_id');
    rejects(() => normalizeFirewallExpectation(firewallBody({ source_ip: '198.51.100.1' })), 'scope_not_declared', 'source_ip');
    rejects(() => normalizeFirewallExpectation(firewallBody({ destination: '203.0.113.10' })), 'scope_not_declared', 'destination');
    assert.equal(validateFirewallExpectation(firewallBody({ port: 0 })).ok, false);
  });

  it('requires explicit customer pre/post mappings', () => {
    const mapping = { pre_destination_target_id: 'tgt_old', post_destination_target_id: 'tgt_fw', declared_by_customer: true };
    assert.deepEqual(normalizeFirewallExpectation(firewallBody({ pre_post_mapping: mapping })).pre_post_mapping, mapping);
    rejects(() => normalizeFirewallExpectation(firewallBody({ pre_post_mapping: { ...mapping, declared_by_customer: false } })), 'invalid_firewall_expectation', 'pre_post_mapping.declared_by_customer');
    rejects(() => normalizeFirewallExpectation(firewallBody({ pre_post_mapping: { ...mapping, pre_destination_target_id: 'tgt_fw' } })), 'invalid_firewall_expectation', 'pre_post_mapping');
    rejects(() => normalizeFirewallExpectation(firewallBody({ pre_post_mapping: { ...mapping, pre_destination_target_id: 'tgt_x', post_destination_target_id: 'tgt_y' } })), 'invalid_firewall_expectation', 'pre_post_mapping');
  });

  it('classifies firewall expectation writes idempotently', () => {
    const first = normalizeFirewallExpectation(firewallBody(), { tenantId: TENANT });
    assert.equal(classifyFirewallExpectationWrite([first], normalizeFirewallExpectation(firewallBody(), { tenantId: TENANT })).action, 'replay');
    assert.equal(classifyFirewallExpectationWrite([first], normalizeFirewallExpectation(firewallBody({ expected: 'deny' }), { tenantId: TENANT })).action, 'conflict');
    assert.equal(classifyFirewallExpectationWrite([first], normalizeFirewallExpectation(firewallBody({ port: 22 }), { tenantId: TENANT })).action, 'create');
  });
});

describe('evidence references and baselines', () => {
  it('keeps evidence links reference-only', () => {
    const normalized = normalizeEvidenceReference({ ...ref(), headers: { cookie: 'x' }, body: 'raw', status_code: 200 });
    assert.deepEqual(Object.keys(normalized).sort(), [
      'check_id', 'check_version', 'evidence_ids', 'finalized', 'observed_at', 'run_status', 'scenario_version',
      'source_perspective', 'target_id', 'test_run_id', 'verdict_id', 'worker_id',
    ]);
    assert.deepEqual(normalized.evidence_ids, ['ev_1', 'ev_2']);
    assert.equal(normalized.finalized, true);
    assert.equal(normalizeEvidenceReference(ref({ run_status: 'running' })).finalized, false);
    rejects(() => normalizeEvidenceReference(ref({ observed_at: 'yesterday' })), 'invalid_evidence_reference', 'observed_at');
    rejects(() => normalizeEvidenceReference(ref({ evidence_ids: 'ev_1' })), 'invalid_evidence_reference', 'evidence_ids');
  });

  it('captures an immutable baseline only from finalized, sourced evidence', () => {
    const expectation = normalizeFirewallExpectation(firewallBody(), { tenantId: TENANT });
    const baseline = normalizeComparisonBaseline(firewallSet(expectation));
    assert.equal(baseline.immutable, true);
    assert.equal(baseline.freshness_window_seconds, 30 * 24 * 3600);
    assert.ok(verifyBaselineDigest(baseline));
    assert.ok(verifyBaselineDigest({ ...baseline, id: 'fwb_1', created_at: '2026-10-02T00:00:00Z', created_by: 'usr_1' }));
    assert.equal(verifyBaselineDigest({ ...baseline, references: [ref({ check_version: 'v4' })] }), false);
    assert.equal(baseline.baseline_digest, comparisonBaselineDigest(baseline));
    rejects(() => normalizeComparisonBaseline(firewallSet(expectation, { references: [ref({ run_status: 'running' })] })), 'evidence_not_finalized');
    rejects(() => normalizeComparisonBaseline(firewallSet(expectation, { references: [ref({ worker_id: null })] })), 'invalid_comparison_baseline', 'references');
    rejects(() => normalizeComparisonBaseline(firewallSet(expectation, { references: [] })), 'invalid_comparison_baseline', 'references');
    rejects(() => normalizeComparisonBaseline(firewallSet(expectation, { references: [ref({ target_id: 'tgt_other' })] })), 'invalid_comparison_baseline', 'references');
    rejects(() => normalizeComparisonBaseline(firewallSet(expectation, { freshness_window_seconds: 10 })), 'invalid_comparison_baseline', 'freshness_window_seconds');
    assert.equal(validateComparisonBaseline(firewallSet(expectation, { expectation_digest: 'nope' })).field, 'expectation_digest');
  });

  it('pins the declaration digest for path validation baselines', () => {
    const rel = relation();
    const expectation = normalizePathValidationExpectation({ scenario: 's', layer_outcomes: { waf: 'enforce' } }, { anchorTargetId: 'tgt_app' });
    rejects(() => normalizeComparisonBaseline(pathSet(rel, expectation, { declaration_digest: null })), 'invalid_comparison_baseline', 'declaration_digest');
    assert.equal(normalizeComparisonBaseline(pathSet(rel, expectation)).declaration_digest, rel.declaration_digest);
  });

  it('wraps per-expectation firewall baselines into one change capture', () => {
    const allow = normalizeFirewallExpectation(firewallBody(), { tenantId: TENANT });
    const deny = normalizeFirewallExpectation(firewallBody({ port: 22, expected: 'deny' }), { tenantId: TENANT });
    const capture = normalizeFirewallBaselineCapture({
      change_id: 'CHG-1001',
      captured_at: '2026-10-01T01:00:00Z',
      entries: [firewallSet(deny, { expectation_id: 'fwx_2' }), firewallSet(allow)],
    });
    assert.deepEqual(capture.entries.map((entry) => entry.expectation_id), ['fwx_1', 'fwx_2']);
    assert.match(capture.baseline_digest, /^[a-f0-9]{64}$/);
    assert.ok(capture.entries.every((entry) => verifyBaselineDigest(entry)));
    rejects(() => normalizeFirewallBaselineCapture({ change_id: 'CHG-1', entries: [firewallSet(allow), firewallSet(allow)] }), 'invalid_comparison_baseline', 'entries');
    rejects(() => normalizeFirewallBaselineCapture({ change_id: 'CHG-1', entries: [] }), 'invalid_comparison_baseline', 'entries');
  });

  it('assesses freshness', () => {
    assert.deepEqual(assessFreshness('2026-10-01T00:00:00Z', 3600, '2026-10-01T00:30:00Z'), { fresh: true, age_seconds: 1800, expires_at: '2026-10-01T01:00:00.000Z' });
    assert.equal(assessFreshness('2026-10-01T00:00:00Z', 3600, '2026-10-01T02:00:00Z').fresh, false);
    assert.equal(assessFreshness('bad', 3600).fresh, false);
  });
});

describe('assessComparisonCompatibility', () => {
  const expectation = normalizeFirewallExpectation(firewallBody(), { tenantId: TENANT });
  const baseline = normalizeComparisonBaseline(firewallSet(expectation));
  const candidate = firewallSet(expectation, { captured_at: '2026-10-03T00:00:00.000Z', references: [ref({ test_run_id: 'run_2', observed_at: '2026-10-03T00:00:00.000Z' })] });

  it('accepts compatible finalized pre/post evidence', () => {
    assert.deepEqual(assessComparisonCompatibility(baseline, candidate), { comparable: true, stale: false, reasons: [] });
  });

  it('rejects mismatched expectations, versions, sources, and checks', () => {
    const cases = [
      [{ expectation_version: 2 }, 'expectation_version_mismatch'],
      [{ expectation_digest: 'a'.repeat(64) }, 'expectation_digest_mismatch'],
      [{ expectation_id: 'fwx_9' }, 'expectation_mismatch'],
      [{ tenant_id: 'ten_b' }, 'tenant_mismatch'],
      [{ references: [ref({ test_run_id: 'run_2', check_version: 'v4' })] }, 'check_version_mismatch'],
      [{ references: [ref({ test_run_id: 'run_2', check_id: 'net.tcp.other' })] }, 'check_mismatch'],
      [{ references: [ref({ test_run_id: 'run_2', source_perspective: 'public-worker-us' })] }, 'source_mismatch'],
      [{ references: [ref({ test_run_id: 'run_2', worker_id: null })] }, 'source_missing'],
      [{ references: [ref({ test_run_id: 'run_2', run_status: 'running' })] }, 'evidence_not_finalized'],
      [{ references: [] }, 'evidence_missing'],
      [{ captured_at: '2026-09-30T00:00:00.000Z' }, 'candidate_not_after_baseline'],
      [{ contract_version: 'protection-validation-v0' }, 'contract_version_mismatch'],
      [{ declaration_digest: 'b'.repeat(64) }, 'declaration_digest_mismatch'],
    ];
    for (const [overrides, reason] of cases) {
      const result = assessComparisonCompatibility(baseline, { ...candidate, ...overrides });
      assert.equal(result.comparable, false, reason);
      assert.ok(result.reasons.includes(reason), `${reason}: ${result.reasons}`);
      assert.ok(result.reasons.every((entry) => COMPATIBILITY_REASONS.includes(entry)));
    }
  });

  it('never infers a destination change without an explicit mapping', () => {
    const moved = { ...candidate, target_id: 'tgt_new', references: [ref({ test_run_id: 'run_2', target_id: 'tgt_new' })] };
    assert.deepEqual(assessComparisonCompatibility(baseline, moved).reasons, ['destination_mapping_missing']);
    const mapping = { pre_destination_target_id: 'tgt_fw', post_destination_target_id: 'tgt_new', declared_by_customer: true };
    assert.equal(assessComparisonCompatibility(baseline, { ...moved, destination_mapping: mapping }).comparable, true);
    const wrong = { ...mapping, post_destination_target_id: 'tgt_elsewhere' };
    assert.ok(assessComparisonCompatibility(baseline, { ...moved, destination_mapping: wrong }).reasons.includes('destination_mismatch'));
  });

  it('marks stale evidence separately from incomparable evidence', () => {
    const late = { ...candidate, captured_at: '2026-12-15T00:00:00.000Z' };
    const result = assessComparisonCompatibility(baseline, late);
    assert.deepEqual(result, { comparable: false, stale: true, reasons: ['baseline_stale'] });
    assert.equal(compatibilityFailureStatus(result), 'stale');
    const candStale = assessComparisonCompatibility(baseline, candidate, { now: '2027-03-01T00:00:00Z' });
    assert.ok(candStale.reasons.includes('candidate_stale'));
    assert.equal(compatibilityFailureStatus({ comparable: false, reasons: ['baseline_stale', 'check_mismatch'] }), 'not_comparable');
    assert.equal(compatibilityFailureStatus({ comparable: true, reasons: [] }), null);
  });

  it('detects a tampered baseline and invalid inputs', () => {
    assert.deepEqual(assessComparisonCompatibility({ ...baseline, expectation_version: 2, expectation_digest: baseline.expectation_digest }, { ...candidate, expectation_version: 2 }).reasons, ['invalid_baseline']);
    assert.deepEqual(assessComparisonCompatibility(null, candidate).reasons, ['invalid_baseline']);
    assert.deepEqual(assessComparisonCompatibility(baseline, {}).reasons, ['invalid_candidate']);
  });

  it('path validation: compares routes under one anchor and catches declaration changes', () => {
    const primary = relation({ entry_target_id: 'tgt_app', relation_kind: 'primary_route' });
    const alternate = { ...relation(), id: 'ep_2' };
    const pathExpectation = normalizePathValidationExpectation({ scenario: 's', layer_outcomes: { waf: 'enforce' } }, { tenantId: TENANT, anchorTargetId: 'tgt_app' });
    const base = normalizeComparisonBaseline(pathSet(primary, pathExpectation));
    const cand = pathSet(alternate, pathExpectation, { captured_at: '2026-10-01T00:05:00.000Z' });
    assert.equal(assessComparisonCompatibility(base, cand).comparable, true);
    assert.ok(assessComparisonCompatibility(base, cand, { sameEntryPath: true }).reasons.includes('entry_path_mismatch'));
    assert.ok(assessComparisonCompatibility(base, { ...cand, anchor_target_id: 'tgt_other' }).reasons.includes('anchor_mismatch'));
    const changed = assessComparisonCompatibility(base, cand, { currentDeclarationDigests: { [primary.id]: 'c'.repeat(64) } });
    assert.ok(changed.reasons.includes('declaration_changed'));
    const scenarioDrift = { ...cand, references: [ref({ target_id: 'tgt_alt', check_id: 'waf.marker.sqli', scenario_version: 's3' })] };
    assert.ok(assessComparisonCompatibility(base, scenarioDrift).reasons.includes('scenario_version_mismatch'));
    const originCheck = { ...cand, references: [ref({ target_id: 'tgt_alt', check_id: 'origin.host_sni', scenario_version: 's2' })] };
    assert.ok(assessComparisonCompatibility(base, originCheck).reasons.includes('check_mismatch'));
    assert.equal(assessComparisonCompatibility(base, originCheck, { matchBy: 'scenario_version' }).comparable, true);
    assert.ok(assessComparisonCompatibility(base, { ...cand, kind: 'firewall_change' }).reasons.includes('kind_mismatch'));
  });
});

describe('classifyFirewallComparisonItem', () => {
  const allow = { expected: 'allow' };
  const deny = { expected: 'deny' };
  const ok = { comparable: true, stale: false, reasons: [] };

  it('matched, regression, and improvement require compatible evidence', () => {
    assert.equal(classifyFirewallComparisonItem({ expectation: allow, baseline: ['service_response_observed'], candidate: ['service_response_observed'], compatibility: ok }).status, 'matched');
    const reach = classifyFirewallComparisonItem({ expectation: deny, baseline: ['explicit_denial_observed'], candidate: ['service_response_observed'], compatibility: ok });
    assert.equal(reach.status, 'regression');
    assert.equal(reach.gap_kind, 'forbidden_service_newly_reachable');
    assert.equal(reach.expectation_met, false);
    const gone = classifyFirewallComparisonItem({ expectation: allow, baseline: ['service_response_observed'], candidate: ['no_response', 'no_response'], compatibility: ok });
    assert.equal(gone.status, 'regression');
    assert.equal(gone.gap_kind, 'required_service_newly_unavailable');
    const fixed = classifyFirewallComparisonItem({ expectation: deny, baseline: ['reachable_transport_only'], candidate: ['explicit_denial_observed'], compatibility: ok });
    assert.equal(fixed.status, 'improvement');
    assert.equal(fixed.expectation_met, true);
  });

  it('keeps ambiguous observations inconclusive', () => {
    const single = classifyFirewallComparisonItem({ expectation: allow, baseline: ['service_response_observed'], candidate: ['no_response'], compatibility: ok });
    assert.equal(single.status, 'inconclusive');
    const udp = classifyFirewallComparisonItem({ expectation: deny, baseline: ['explicit_denial_observed'], candidate: ['udp_silence', 'udp_silence'], compatibility: ok });
    assert.equal(udp.status, 'inconclusive');
    assert.ok(udp.limitations.includes('udp_silence_ambiguous'));
    const timeoutDeny = classifyFirewallComparisonItem({ expectation: deny, baseline: ['no_response'], candidate: ['no_response'], compatibility: ok });
    assert.equal(timeoutDeny.status, 'inconclusive');
    assert.equal(timeoutDeny.expectation_met, null);
    const transportAllow = classifyFirewallComparisonItem({ expectation: allow, baseline: ['service_response_observed'], candidate: ['reachable_transport_only'], compatibility: ok });
    assert.equal(transportAllow.status, 'inconclusive');
    const mixed = classifyFirewallComparisonItem({ expectation: allow, baseline: ['service_response_observed'], candidate: ['service_response_observed', 'no_response'], compatibility: ok });
    assert.equal(mixed.status, 'inconclusive');
    const noPre = classifyFirewallComparisonItem({ expectation: allow, baseline: [], candidate: ['service_response_observed'], compatibility: ok });
    assert.equal(noPre.status, 'inconclusive');
    assert.equal(noPre.expectation_met, true);
  });

  it('a mixed deny sample with any reachable response is a violation', () => {
    const result = classifyFirewallComparisonItem({ expectation: deny, baseline: ['explicit_denial_observed'], candidate: ['explicit_denial_observed', 'reachable_transport_only'], compatibility: ok });
    assert.equal(result.status, 'regression');
    assert.equal(result.gap_kind, 'forbidden_service_newly_reachable');
  });

  it('unchanged failure is matched but not met', () => {
    const result = classifyFirewallComparisonItem({ expectation: deny, baseline: ['service_response_observed'], candidate: ['service_response_observed'], compatibility: ok });
    assert.equal(result.status, 'matched');
    assert.equal(result.expectation_met, false);
  });

  it('not_tested, stale, and not_comparable outcomes', () => {
    assert.equal(classifyFirewallComparisonItem({ expectation: allow, baseline: ['service_response_observed'], candidate: [], compatibility: ok }).status, 'not_tested');
    const stale = classifyFirewallComparisonItem({ expectation: allow, baseline: ['service_response_observed'], candidate: ['service_response_observed'], compatibility: { comparable: false, stale: true, reasons: ['baseline_stale'] } });
    assert.equal(stale.status, 'stale');
    assert.deepEqual(stale.compatibility_reasons, ['baseline_stale']);
    assert.equal(classifyFirewallComparisonItem({ expectation: allow, baseline: ['service_response_observed'], candidate: ['service_response_observed'] }).status, 'not_comparable');
    assert.equal(classifyFirewallComparisonItem({ expectation: {}, candidate: ['service_response_observed'], compatibility: ok }).status, 'not_comparable');
    for (const limitation of REQUIRED_LIMITATIONS.firewall_change) {
      assert.ok(stale.limitations.includes(limitation));
    }
  });
});

describe('classifyPathValidationItem', () => {
  const protectedRel = relation();
  const healthy = { primaryBaselineHealth: 'healthy', primaryEnforcement: 'enforced' };

  it('covers every outcome with its evidence prerequisite', () => {
    assert.equal(classifyPathValidationItem({ relation: protectedRel, skipped: true }).outcome, 'skipped');
    assert.equal(classifyPathValidationItem({ relation: protectedRel }).outcome, 'not_tested');
    assert.equal(classifyPathValidationItem({ relation: relation({ expected_behavior: 'intentionally_public', required_layers: [] }), observation: 'response_observed' }).outcome, 'intentional_public_access');
    const unreachable = relation({ expected_behavior: 'must_not_be_reachable', required_layers: [] });
    assert.equal(classifyPathValidationItem({ relation: unreachable, observation: 'response_observed' }).outcome, 'reachability_exposure');
    assert.equal(classifyPathValidationItem({ relation: unreachable, observation: 'explicit_denial_observed' }).outcome, 'consistent_enforcement');
    assert.equal(classifyPathValidationItem({ relation: protectedRel, ...healthy, observation: 'response_observed', enforcement: 'partial' }).outcome, 'weaker_observed_enforcement');
    const suspected = classifyPathValidationItem({ relation: protectedRel, ...healthy, observation: 'response_observed', enforcement: 'not_enforced' });
    assert.equal(suspected.outcome, 'suspected_alternate_application_route');
    assert.deepEqual(suspected.reasons, ['application_identity_not_confirmed']);
    assert.equal(classifyPathValidationItem({ relation: protectedRel, ...healthy, observation: 'application_identity_confirmed', enforcement: 'not_enforced' }).outcome, 'scoped_application_bypass');
    assert.equal(classifyPathValidationItem({ relation: protectedRel, ...healthy, observation: 'response_observed', enforcement: 'enforced' }).outcome, 'consistent_enforcement');
    assert.equal(classifyPathValidationItem({ relation: protectedRel, ...healthy, observation: 'explicit_denial_observed' }).outcome, 'consistent_enforcement');
  });

  it('never turns timeouts or missing baselines into protection or bypass claims', () => {
    for (const observation of ['no_response', 'transport_error']) {
      const result = classifyPathValidationItem({ relation: protectedRel, ...healthy, observation, enforcement: 'not_enforced' });
      assert.equal(result.outcome, 'inconclusive');
    }
    assert.deepEqual(classifyPathValidationItem({ relation: protectedRel, primaryBaselineHealth: 'unhealthy', primaryEnforcement: 'enforced', observation: 'application_identity_confirmed', enforcement: 'not_enforced' }).reasons, ['primary_baseline_not_healthy']);
    assert.deepEqual(classifyPathValidationItem({ relation: protectedRel, primaryBaselineHealth: 'healthy', primaryEnforcement: 'not_enforced', observation: 'response_observed', enforcement: 'not_enforced' }).reasons, ['blocked_primary_baseline_missing']);
    assert.equal(classifyPathValidationItem({ relation: protectedRel, ...healthy, observation: 'response_observed' }).outcome, 'inconclusive');
    const originRel = relation({ relation_kind: 'origin', origin_binding_id: 'obind_1', entry_target_id: 'tgt_ip' });
    assert.equal(classifyPathValidationItem({ relation: originRel, ...healthy, observation: 'response_observed' }).outcome, 'reachability_exposure');
    const incompatible = classifyPathValidationItem({ relation: protectedRel, ...healthy, observation: 'application_identity_confirmed', enforcement: 'not_enforced', compatibility: { comparable: false, reasons: ['scenario_version_mismatch'] } });
    assert.equal(incompatible.outcome, 'inconclusive');
    assert.deepEqual(incompatible.compatibility_reasons, ['scenario_version_mismatch']);
    assert.equal(classifyPathValidationItem({ relation: { ...protectedRel, status: 'archived' }, observation: 'response_observed' }).outcome, 'inconclusive');
  });

  it('does not attribute stacked layers and carries required limitations', () => {
    const result = classifyPathValidationItem({ relation: protectedRel, ...healthy, observation: 'explicit_denial_observed' });
    assert.equal(result.attribution, 'unattributed');
    assert.deepEqual(result.limitations, [...REQUIRED_LIMITATIONS.path_validation]);
  });
});

describe('layer evidence', () => {
  it('starts every layer as unknown/not tested with declared intent only from the relation', () => {
    const rel = relation();
    const row = emptyProtectionMatrixRow(rel);
    assert.deepEqual(row.layers.map((layer) => [layer.layer, layer.declared_intent]), [
      ['waf', 'required'], ['cdn_edge', 'required'], ['network_firewall', 'not_required'], ['ddos', 'not_required'],
    ]);
    assert.ok(row.layers.every((layer) => layer.observed_enforcement === 'not_tested' && layer.vendor_detection === 'unknown'));
    assert.equal(row.outcome, 'not_tested');
    assert.equal(emptyLayerEvidence('waf').declared_intent, 'undeclared');
    assert.ok(emptyLayerEvidence('ddos').evidence_limitations.includes('not_capacity_assurance'));
  });

  it('requires evidence for observed and confirmed states', () => {
    const base = { ...emptyLayerEvidence('waf', relation()) };
    rejects(() => normalizeLayerEvidence({ ...base, observed_enforcement: 'enforced' }), 'invalid_comparison_evaluation', 'observed_enforcement');
    rejects(() => normalizeLayerEvidence({ ...base, application_identity: 'confirmed' }), 'invalid_comparison_evaluation', 'application_identity');
    rejects(() => normalizeLayerEvidence({ ...base, confirmed_scoped_bypass: 'confirmed', evidence_refs: [ref()] }), 'invalid_comparison_evaluation', 'confirmed_scoped_bypass');
    rejects(() => normalizeLayerEvidence({ ...base, attribution: 'attributed' }), 'invalid_comparison_evaluation', 'attribution');
    rejects(() => normalizeLayerEvidence({ ...base, vendor_detection: 'cloudflare' }), 'invalid_comparison_evaluation', 'vendor_detection');
    const enforced = normalizeLayerEvidence({ ...base, observed_enforcement: 'enforced', evidence_refs: [ref()] });
    assert.equal(enforced.observed_enforcement, 'enforced');
    const ddos = normalizeLayerEvidence({ ...emptyLayerEvidence('ddos'), evidence_limitations: ['external_only'] });
    assert.ok(ddos.evidence_limitations.includes('not_capacity_assurance'));
  });
});

describe('comparison evaluations', () => {
  function firewallItem(overrides = {}) {
    return {
      expectation_id: 'fwx_1',
      status: 'matched',
      expectation_met: true,
      pre_state: 'satisfied',
      post_state: 'satisfied',
      evidence_refs: [ref()],
      limitations: [...REQUIRED_LIMITATIONS.firewall_change],
      ...overrides,
    };
  }

  function evaluation(items, overrides = {}) {
    return { kind: 'firewall_change', tenant_id: TENANT, baseline_id: 'fwb_1', items, evaluated_at: '2026-10-03T00:00:00Z', ...overrides };
  }

  it('summarizes and digests a firewall evaluation', () => {
    const result = normalizeComparisonEvaluation(evaluation([firewallItem(), firewallItem({ expectation_id: 'fwx_2', status: 'improvement', pre_state: 'violated' })]));
    assert.equal(result.summary.total, 2);
    assert.equal(result.summary.evaluated, 2);
    assert.equal(result.summary.accepted, true);
    assert.equal(result.compatibility.comparable, true);
    assert.match(result.evaluation_digest, /^[a-f0-9]{64}$/);
    for (const limitation of REQUIRED_LIMITATIONS.firewall_change) assert.ok(result.limitations.includes(limitation));
    const again = normalizeComparisonEvaluation(evaluation([firewallItem(), firewallItem({ expectation_id: 'fwx_2', status: 'improvement', pre_state: 'violated' })]));
    assert.equal(again.evaluation_digest, result.evaluation_digest);
  });

  it('zero items never means success and mixed results stay visible', () => {
    const empty = normalizeComparisonEvaluation(evaluation([]));
    assert.equal(empty.summary.accepted, false);
    assert.equal(empty.compatibility.comparable, false);
    const mixed = normalizeComparisonEvaluation(evaluation([
      firewallItem(),
      firewallItem({ expectation_id: 'fwx_2', status: 'inconclusive', expectation_met: null, evidence_refs: [] }),
      firewallItem({ expectation_id: 'fwx_3', status: 'not_tested', evidence_refs: [] }),
    ]));
    assert.equal(mixed.summary.accepted, false);
    assert.equal(mixed.summary.evaluated, 1);
    assert.equal(mixed.summary.by_status.inconclusive, 1);
    assert.equal(mixed.summary.by_status.not_tested, 1);
    const unmet = normalizeComparisonEvaluation(evaluation([firewallItem({ expectation_met: false })]));
    assert.equal(unmet.summary.accepted, false);
  });

  it('rejects gaps outside regressions, missing evidence, and missing limitations', () => {
    rejects(() => normalizeComparisonEvaluation(evaluation([firewallItem({ gap_kind: 'forbidden_service_newly_reachable' })])), 'invalid_comparison_evaluation');
    rejects(() => normalizeComparisonEvaluation(evaluation([firewallItem({ evidence_refs: [] })])), 'invalid_comparison_evaluation');
    rejects(() => normalizeComparisonEvaluation(evaluation([firewallItem({ limitations: ['external_only'] })])), 'invalid_comparison_evaluation');
    const regression = normalizeComparisonEvaluation(evaluation([firewallItem({ status: 'regression', gap_kind: 'required_service_newly_unavailable', expectation_met: false, post_state: 'not_observed' })]));
    assert.equal(regression.summary.gaps.required_service_newly_unavailable, 1);
  });

  it('incompatible evidence can never produce a match, regression, or improvement', () => {
    rejects(() => normalizeComparisonEvaluation(evaluation([firewallItem({ compatibility_reasons: ['source_mismatch'] })])), 'baseline_not_comparable');
    rejects(() => normalizeComparisonEvaluation(evaluation([firewallItem({ status: 'not_comparable', evidence_refs: [] })])), 'invalid_comparison_evaluation');
    const result = normalizeComparisonEvaluation(evaluation([firewallItem({ status: 'stale', compatibility_reasons: ['baseline_stale'], evidence_refs: [] })]));
    assert.deepEqual(result.compatibility, { comparable: false, stale: true, reasons: ['baseline_stale'] });
    assert.equal(result.summary.accepted, false);
  });

  it('validates path validation evaluations', () => {
    const pathItem = {
      entry_path_id: 'ep_2',
      scenario: 'waf.sqli.marker',
      outcome: 'scoped_application_bypass',
      evidence_refs: [ref({ target_id: 'tgt_alt' })],
      limitations: [...REQUIRED_LIMITATIONS.path_validation],
    };
    const result = normalizeComparisonEvaluation({ kind: 'path_validation', tenant_id: TENANT, items: [pathItem, { ...pathItem, entry_path_id: 'ep_3', outcome: 'not_tested', evidence_refs: [] }], evaluated_at: '2026-10-03T00:00:00Z' });
    assert.equal(result.summary.by_status.scoped_application_bypass, 1);
    assert.equal(result.summary.accepted, false);
    assert.equal(result.items[0].attribution, 'unattributed');
    rejects(() => normalizeComparisonEvaluation({ kind: 'path_validation', tenant_id: TENANT, items: [{ ...pathItem, evidence_refs: [] }], evaluated_at: '2026-10-03T00:00:00Z' }), 'invalid_comparison_evaluation');
    rejects(() => normalizeComparisonEvaluation({ kind: 'path_validation', tenant_id: TENANT, items: [{ ...pathItem, compatibility_reasons: ['anchor_mismatch'] }], evaluated_at: '2026-10-03T00:00:00Z' }), 'baseline_not_comparable');
    assert.deepEqual(summarizeComparisonItems('path_validation', []).accepted, false);
  });
});

describe('request normalizers', () => {
  it('entry path comparison: plan by default, start requires the reviewed plan digest', () => {
    const body = {
      anchor_target_id: 'tgt_app',
      primary_entry_path_id: 'ep_1',
      entry_path_ids: ['ep_2', 'ep_1', 'ep_2'],
      expectation: { scenario: 'waf.sqli.marker', layer_outcomes: { waf: 'enforce' } },
    };
    const plan = normalizeEntryPathComparisonRequest(body);
    assert.equal(plan.mode, 'plan');
    assert.deepEqual(plan.entry_path_ids, ['ep_1', 'ep_2']);
    assert.equal(plan.reviewed_plan_digest, null);
    rejects(() => normalizeEntryPathComparisonRequest({ ...body, mode: 'start' }), 'invalid_comparison_request', 'reviewed_plan_digest');
    assert.equal(normalizeEntryPathComparisonRequest({ ...body, mode: 'start', reviewed_plan_digest: 'd'.repeat(64) }).mode, 'start');
    rejects(() => normalizeEntryPathComparisonRequest({ ...body, primary_entry_path_id: 'ep_9' }), 'invalid_comparison_request', 'primary_entry_path_id');
    rejects(() => normalizeEntryPathComparisonRequest({ ...body, sni_override: 'x.example' }), 'scope_not_declared');
    rejects(() => normalizeEntryPathComparisonRequest({ ...body, entry_path_ids: [] }), 'invalid_comparison_request', 'entry_path_ids');
  });

  it('plan digest is order-independent and changes with scope', () => {
    const items = [
      { entry_path_id: 'ep_1', target_id: 'tgt_app', check_id: 'waf.a', eligible: true },
      { entry_path_id: 'ep_2', target_id: 'tgt_alt', check_id: 'waf.a', eligible: false },
    ];
    const plan = { tenant_id: TENANT, anchor_target_id: 'tgt_app', primary_entry_path_id: 'ep_1', items };
    assert.equal(entryPathComparisonPlanDigest(plan), entryPathComparisonPlanDigest({ ...plan, items: [...items].reverse() }));
    assert.notEqual(entryPathComparisonPlanDigest(plan), entryPathComparisonPlanDigest({ ...plan, items: [items[0], { ...items[1], target_id: 'tgt_other' }] }));
  });

  it('firewall baseline and comparison requests', () => {
    const baseline = normalizeFirewallBaselineRequest({ change_id: 'CHG-1001', expectation_ids: ['fwx_2', 'fwx_1'], test_run_ids: ['run_1'] });
    assert.deepEqual(baseline.expectation_ids, ['fwx_1', 'fwx_2']);
    assert.equal(baseline.freshness_window_seconds, 30 * 24 * 3600);
    rejects(() => normalizeFirewallBaselineRequest({ change_id: 'CHG-1', expectation_ids: [], test_run_ids: ['run_1'] }), 'invalid_comparison_request', 'expectation_ids');
    rejects(() => normalizeFirewallBaselineRequest({ change_id: 'CHG-1', expectation_ids: ['fwx_1'], test_run_ids: ['run_1'], endpoint: '1.2.3.4' }), 'scope_not_declared');
    assert.deepEqual(normalizeFirewallComparisonRequest({ baseline_id: 'fwb_1', post_test_run_ids: ['run_3', 'run_2'] }), { baseline_id: 'fwb_1', post_test_run_ids: ['run_2', 'run_3'] });
    rejects(() => normalizeFirewallComparisonRequest({ baseline_id: 'fwb_1', post_test_run_ids: [] }), 'invalid_comparison_request', 'post_test_run_ids');
  });
});

describe('provider-neutral workflow', () => {
  it('a custom/unidentified provider completes declaration, baseline, comparison, and evaluation with connectors disabled', () => {
    const rel = relation({ relation_kind: 'declared_api_url', required_layers: ['waf', 'network_firewall'] });
    assert.ok(!Object.keys(rel).some((key) => /vendor|provider|connector/.test(key)));
    const expectation = normalizeFirewallExpectation(firewallBody({ expected: 'deny', port: 8080 }), { tenantId: TENANT });
    const capture = normalizeFirewallBaselineCapture({ change_id: 'CHG-1001', entries: [firewallSet(expectation)], captured_at: '2026-10-01T00:00:00Z' });
    const candidate = firewallSet(expectation, { captured_at: '2026-10-02T00:00:00.000Z', references: [ref({ test_run_id: 'run_9' })] });
    const compatibility = assessComparisonCompatibility(capture.entries[0], candidate);
    assert.equal(compatibility.comparable, true);
    const item = classifyFirewallComparisonItem({ expectation, baseline: ['explicit_denial_observed'], candidate: ['explicit_denial_observed'], compatibility });
    const result = normalizeComparisonEvaluation({
      kind: 'firewall_change',
      tenant_id: TENANT,
      baseline_id: 'fwb_1',
      baseline_digest: capture.baseline_digest,
      items: [{ ...item, expectation_id: 'fwx_1', evidence_refs: [ref({ test_run_id: 'run_9' })] }],
      evaluated_at: '2026-10-02T01:00:00Z',
    });
    assert.equal(result.summary.accepted, true);
    assert.ok(result.limitations.includes('rule_table_equivalence_not_established'));
    assert.ok(result.limitations.includes('not_capacity_assurance'));
    assert.equal(result.contract_version, PROTECTION_VALIDATION_CONTRACT_VERSION);
  });

  it('digest helpers are stable over key order', () => {
    assert.equal(stableStringify({ b: 1, a: [2, { d: 1, c: undefined }] }), '{"a":[2,{"d":1}],"b":1}');
    assert.equal(sha256Digest({ a: 1, b: 2 }), sha256Digest({ b: 2, a: 1 }));
    assert.ok(COMPARISON_KINDS.includes('path_validation'));
  });
});
