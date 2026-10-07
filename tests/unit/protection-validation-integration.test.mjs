// Integration seams between the PV slices: gate, source resolution, storage encodings, findings, and retest authorization.
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { isProtectionValidationEnabledForTenant, loadRuntimeConfig } from '../../src/config.mjs';
import {
  classifyFirewallComparisonItem,
  normalizeComparisonEvaluation,
  normalizeEntryPathDeclaration,
  normalizeFirewallExpectation,
  pathValidationExpectationScopeKey,
  PROTECTION_VALIDATION_AUDIT_ACTIONS,
} from '../../src/contracts/protectionValidation.mjs';
import { buildProtectionConfig, normalizeStoredProtectionConfig, PROTECTION_CONFIG_SCHEMA } from '../../src/lib/connectorProviders/common.mjs';
import { decodeFirewallObservations, encodeFirewallObservations } from '../../src/lib/firewallChangeAcceptance.mjs';
import { applyProtectionFindingPatch } from '../../src/lib/protectionValidationFindings.mjs';
import { approvedProbeSourcesFromEnv, createProbeSourceResolver, probeSourceResolverFromEnv, DEFAULT_SOURCE_PERSPECTIVE } from '../../src/lib/probeSourcePerspective.mjs';
import { upsertFindingFromVerdict, upsertProtectionFindingsFromEvaluation } from '../../src/services/findings.mjs';
import { boundedEvaluationProvenance, PROTECTION_VALIDATION_EXTRA_AUDIT_ACTIONS } from '../../src/services/protectionValidation.mjs';
import { createProtectionValidationFacade, edgeDetectionSignals } from '../../src/services/protectionValidationFacade.mjs';
import { resolveDevProtectionRetestAuthorization } from '../../src/services/protectionValidationRetest.mjs';
import { getTenantDeploymentFeatures, isProtectionValidationEnabled } from '../../src/services/tenantDeploymentFeatures.mjs';
import { attachConfigurationContext } from '../../src/services/protectionProfile.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TENANT = 'ten_demo';
const CTX = { tenantId: TENANT, userId: 'usr_eng', role: 'engineer' };
const T1 = '2026-10-01T10:00:00.000Z';
const T2 = '2026-10-03T10:00:00.000Z';

function expectation(overrides = {}) {
  return {
    ...normalizeFirewallExpectation({
      destination_target_id: 'tgt_1', protocol: 'tcp', port: 443, expected: 'allow',
      source_perspective: DEFAULT_SOURCE_PERSPECTIVE, change_id: 'CHG-9', owner: 'Network', ...overrides,
    }, { tenantId: TENANT }),
    id: 'fwx_int',
    status: 'active',
  };
}

function ref(run) {
  return {
    test_run_id: run, check_id: 'tls.full_audit.safe', check_version: '1.0.0', scenario_version: null, verdict_id: `vrd_${run}`,
    evidence_ids: [`ev_${run}`], target_id: 'tgt_1', observed_at: T2, run_status: 'verdicted',
    source_perspective: DEFAULT_SOURCE_PERSPECTIVE, worker_id: 'worker_1',
  };
}

function firewallEvaluation(exp, { id = 'fwc_int', candidate = ['no_response', 'no_response'], at = T2 } = {}) {
  const classified = classifyFirewallComparisonItem({
    expectation: exp, baseline: ['service_response_observed'], candidate, compatibility: { comparable: true, stale: false, reasons: [] },
  });
  return {
    ...normalizeComparisonEvaluation({
      kind: 'firewall_change', tenant_id: TENANT, baseline_id: 'fwb_int', baseline_digest: 'b'.repeat(64), evaluated_at: at,
      items: [{ expectation_id: exp.id, ...classified, evidence_refs: [ref(`run_${id}`)] }],
    }),
    id,
  };
}

describe('tenant gate', () => {
  it('is off by default, honours tenant overrides, and an explicit global off wins', () => {
    const base = loadRuntimeConfig({ ...process.env, ASTRANULL_PROTECTION_VALIDATION_ENABLED: '', ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS: '{"ten_a":true}' });
    assert.equal(isProtectionValidationEnabledForTenant(base, 'ten_a'), true);
    assert.equal(isProtectionValidationEnabledForTenant(base, 'ten_b'), false);
    const on = loadRuntimeConfig({ ...process.env, ASTRANULL_PROTECTION_VALIDATION_ENABLED: '1', ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS: '{"ten_b":false}' });
    assert.equal(isProtectionValidationEnabledForTenant(on, 'ten_a'), true);
    assert.equal(isProtectionValidationEnabledForTenant(on, 'ten_b'), false);
    const off = loadRuntimeConfig({ ...process.env, ASTRANULL_PROTECTION_VALIDATION_ENABLED: '0', ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS: '{"ten_a":true}' });
    assert.equal(isProtectionValidationEnabledForTenant(off, 'ten_a'), false);
    assert.equal(isProtectionValidationEnabled({ tenantId: 'Astra-demo-1' }, off), false);
    assert.equal(isProtectionValidationEnabled({ tenantId: 'Astra-demo-1' }, base), true);
    assert.equal(getTenantDeploymentFeatures({ tenantId: 'ten_a' }, base).protection_validation, true);
    const demoOff = loadRuntimeConfig({ ...process.env, ASTRANULL_PROTECTION_VALIDATION_ENABLED: '', ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS: '{"Astra-demo-1":false}' });
    assert.equal(isProtectionValidationEnabled({ tenantId: 'Astra-demo-1' }, demoOff), false);
    assert.equal(getTenantDeploymentFeatures({ tenantId: 'Astra-demo-1' }, demoOff).protection_validation, false);
  });
});

describe('server-side source perspective', () => {
  it('maps every signed worker to the shared pool without a registry', () => {
    const resolve = createProbeSourceResolver();
    assert.equal(resolve('worker_x'), DEFAULT_SOURCE_PERSPECTIVE);
    assert.equal(resolve(null), null);
    assert.equal(resolve.mode, 'shared_public_pool');
  });

  it('only resolves registered workers with a registry and ignores invalid entries', () => {
    const registry = approvedProbeSourcesFromEnv({ ASTRANULL_APPROVED_PROBE_SOURCES: JSON.stringify({ 'public-worker-eu': ['w_eu'], 'Bad Label': ['w_bad'] }) });
    assert.deepEqual(registry, { 'public-worker-eu': ['w_eu'] });
    const resolve = createProbeSourceResolver({ registry });
    assert.equal(resolve('w_eu'), 'public-worker-eu');
    assert.equal(resolve('w_bad'), null);
    assert.equal(resolve('w_unknown'), null);
    assert.deepEqual(approvedProbeSourcesFromEnv({ ASTRANULL_APPROVED_PROBE_SOURCES: '{not json' }), {});
  });

  it('does not fall back to the shared pool when a configured registry admits no workers', () => {
    for (const raw of ['{not json', 'null', '[]', '{}', '{"Bad Label":["worker_x"]}']) {
      const resolve = probeSourceResolverFromEnv({ ASTRANULL_APPROVED_PROBE_SOURCES: raw });
      assert.equal(resolve('worker_x'), null, raw);
      assert.equal(resolve.mode, 'registry');
      assert.deepEqual(resolve.perspectives, []);
    }
  });

  it('does not attribute a worker registered in conflicting source perspectives', () => {
    for (const registry of [{ eu: ['shared', 'eu-only'], us: ['shared'] }, { us: ['shared'], eu: ['shared', 'eu-only'] }]) {
      const resolve = createProbeSourceResolver({ registry });
      assert.equal(resolve('shared'), null);
      assert.equal(resolve('eu-only'), 'eu');
      assert.deepEqual(resolve.perspectives, ['eu']);
    }
  });
});

describe('contract additions', () => {
  it('keeps the path expectation scope key and extra audit actions in the contract', () => {
    assert.equal(pathValidationExpectationScopeKey({ tenant_id: 't', anchor_target_id: 'a', scenario: 's' }), 't|a|s');
    for (const action of Object.values(PROTECTION_VALIDATION_EXTRA_AUDIT_ACTIONS)) {
      assert.ok(Object.values(PROTECTION_VALIDATION_AUDIT_ACTIONS).includes(action), action);
    }
  });
});

describe('storage encodings', () => {
  it('round-trips firewall observations positionally', () => {
    const observations = [{
      evidence_id: 'evt_1', test_run_id: 'run_1', check_id: 'tls.full_audit.safe', observation_class: 'service_response_observed',
      evidence_tier: 'E3', source_perspective: DEFAULT_SOURCE_PERSPECTIVE, worker_id: 'w1', destination_fingerprint: null, observed_at: T1,
    }];
    assert.deepEqual(decodeFirewallObservations(encodeFirewallObservations(observations)), observations);
    assert.ok(JSON.stringify(encodeFirewallObservations(observations)).length < JSON.stringify(observations).length);
  });

  it('bounds evaluation provenance and drops oversize detail with an explicit marker', () => {
    const small = boundedEvaluationProvenance({ post_test_run_ids: ['run_1'], readiness_effect: 'none' });
    assert.deepEqual(small, { post_test_run_ids: ['run_1'], readiness_effect: 'none' });
    const big = boundedEvaluationProvenance({ post_test_run_ids: ['run_1'], observations: 'x'.repeat(20_000), statement: { headline: 'h' } });
    assert.equal(big.observations, undefined);
    assert.equal(big.observations_truncated, true);
    assert.deepEqual(big.post_test_run_ids, ['run_1']);
  });

  it('re-validates stored protection_config and rejects anything off-schema', () => {
    const config = buildProtectionConfig({ enforcementUnit: 'rule_group', actions: ['block', 'monitor'], attachmentLevel: 'hostname', attachmentPaths: ['/api/*'] });
    assert.deepEqual(normalizeStoredProtectionConfig(config), config);
    assert.equal(normalizeStoredProtectionConfig({ ...config, schema: 'other' }), null);
    assert.equal(normalizeStoredProtectionConfig('raw rule dump'), null);
    const hostile = normalizeStoredProtectionConfig({ schema: PROTECTION_CONFIG_SCHEMA, action_counts: { block: -4, monitor: 'x', exfil: 9 }, attachment_paths: ['not-a-path', '/ok'], raw_config: 'secret' });
    assert.equal(hostile.action_counts.block, 0);
    assert.equal(hostile.action_counts.monitor, 0);
    assert.equal(hostile.action_counts.exfil, undefined);
    assert.deepEqual(hostile.attachment_paths, ['/ok']);
    assert.equal(hostile.raw_config, undefined);
  });

  it('attaches configuration beside the derived profile only', () => {
    const payload = { protection_profile: { families: { waf: { status: 'unknown' } } }, coverage: { unit: 'x' } };
    const out = attachConfigurationContext(payload, { status: 'configuration_evidence_available', absence_means: 'unknown' });
    assert.deepEqual(out.protection_profile.families, payload.protection_profile.families);
    assert.equal(out.protection_profile.configuration.absence_means, 'unknown');
    assert.equal(attachConfigurationContext(payload, null), payload);
  });

  it('maps edge detections to vendor-detection signals per layer and provider', () => {
    const signals = edgeDetectionSignals([{ tenant_id: TENANT, target_id: 'tgt_1', waf_status: 'detected', waf_providers: ['cloudflare', 'akamai'], cdn_status: 'inconclusive', cdn_providers: [] }]);
    assert.deepEqual(signals.filter((row) => row.layer === 'waf').map((row) => [row.provider, row.state]), [['cloudflare', 'detected'], ['akamai', 'detected']]);
    assert.deepEqual(signals.filter((row) => row.layer === 'cdn_edge').map((row) => row.state), ['unknown']);
  });
});

describe('protection findings in the dev pipeline', () => {
  beforeEach(() => {
    freshStore();
    getStore().targetVerifications = [{
      id: 'tv_int', tenant_id: TENANT, target_id: 'tgt_1', state: 'dns_verified', source_kind: 'dns_txt', source_ref: {}, transitioned_at: T1, transitioned_by: 'system',
    }];
  });

  it('creates once, records later observations without closing, and never mixes with verdict findings', () => {
    const exp = expectation();
    const first = upsertProtectionFindingsFromEvaluation(CTX, firewallEvaluation(exp), { expectations: [exp] });
    assert.equal(first.ok, true);
    assert.equal(first.created.length, 1);
    const finding = getStore().findings.find((row) => row.id === first.created[0]);
    assert.equal(finding.source, 'protection_validation');
    assert.equal(finding.status, 'open');
    assert.equal(getStore().auditLog.filter((row) => row.resource_id === finding.id && row.action === 'finding.created').length, 1);

    const passing = firewallEvaluation(exp, { id: 'fwc_pass', candidate: ['service_response_observed'], at: '2026-10-04T10:00:00.000Z' });
    const later = upsertProtectionFindingsFromEvaluation(CTX, passing, { expectations: [exp] });
    assert.equal(later.created.length, 0);
    assert.equal(getStore().findings.find((row) => row.id === finding.id).status, 'open', 'a passing evaluation never closes');

    const again = upsertProtectionFindingsFromEvaluation(CTX, firewallEvaluation(exp, { id: 'fwc_again', at: '2026-10-05T10:00:00.000Z' }), { expectations: [exp] });
    assert.deepEqual(again.created, []);
    assert.deepEqual(again.updated, [finding.id]);
    assert.equal(getStore().findings.find((row) => row.id === finding.id).protection_validation.last_evaluation_id, 'fwc_again');

    const tampered = { ...firewallEvaluation(exp, { id: 'fwc_bad' }), evaluation_digest: 'f'.repeat(64) };
    assert.equal(upsertProtectionFindingsFromEvaluation(CTX, tampered, { expectations: [exp] }).ok, false);

    const run = { id: 'run_verdict', target_group_id: null, check_id: finding.check_id };
    const verdictFinding = upsertFindingFromVerdict(CTX, { id: 'vrd_x', verdict: 'fail', severity: 'high', evidence_ids: [] }, run, { id: 'tgt_1', value: 'app' });
    assert.notEqual(verdictFinding.id, finding.id, 'ordinary verdicts never attach to a protection finding');
  });

  it('patches never change lifecycle status or closure', () => {
    const row = { id: 'f1', status: 'accepted_risk', closed_at: null, severity: 'low', protection_validation: { finding_class: 'unavailable_evidence' } };
    const next = applyProtectionFindingPatch(row, { severity: 'high', finding_class: 'confirmed_exposure', latest_observation: { a: 1 } }, T2);
    assert.equal(next.status, 'accepted_risk');
    assert.equal(next.closed_at, null);
    assert.equal(next.severity, 'high');
    assert.equal(next.protection_validation.finding_class, 'confirmed_exposure');
    assert.deepEqual(next.protection_validation.latest_observation, { a: 1 });
  });

  it('rechecks retest authorization against the current relation, targets, and ownership', () => {
    const store = getStore();
    store.targets.push({ id: 'tgt_alt', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'fqdn', value: 'alt.example', created_at: T1 });
    store.targetVerifications.push({ id: 'tv_alt', tenant_id: TENANT, target_id: 'tgt_alt', state: 'dns_verified', source_kind: 'dns_txt', source_ref: {}, transitioned_at: T1, transitioned_by: 'system' });
    const relation = {
      ...normalizeEntryPathDeclaration({
        entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', owner: 'App', purpose: 'Alt', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'],
      }, { tenantId: TENANT, anchorTargetId: 'tgt_1' }),
      id: 'ep_int',
      created_at: T1,
    };
    store.applicationEntryPaths = [relation];
    const finding = {
      id: 'finding_pv', tenant_id: TENANT, target_id: 'tgt_alt', check_id: 'waf.ssrf_marker.safe', source: 'protection_validation',
      protection_validation: {
        comparison_kind: 'path_validation',
        observed_route: { anchor_target_id: 'tgt_1', entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', origin_binding_id: null, entry_path_id: 'ep_int' },
        comparison_context: { comparison_kind: 'path_validation', entry_path_id: 'ep_int', declaration_digest: relation.declaration_digest },
      },
    };
    assert.equal(resolveDevProtectionRetestAuthorization(CTX, finding).ok, true);
    store.targetVerifications = store.targetVerifications.filter((row) => row.target_id !== 'tgt_alt');
    assert.equal(resolveDevProtectionRetestAuthorization(CTX, finding).error, 'target_not_authorized');
    store.applicationEntryPaths[0].status = 'archived';
    assert.equal(resolveDevProtectionRetestAuthorization(CTX, finding).error, 'entry_path_archived');
    assert.equal(resolveDevProtectionRetestAuthorization(CTX, { id: 'plain', tenant_id: TENANT }), null);
  });
});

describe('connector-derived configuration context follows the waf:connector_read gate', () => {
  const RUNTIME = { featureFlags: { wafPostureEnabled: true, connectorsEnabledDefault: true, protectionValidationEnabledDefault: true } };
  const TARGET = { id: 'tgt_cfg', tenant_id: TENANT, kind: 'fqdn', value: 'app.example.com' };
  const SNAPSHOT = {
    id: 'snap_cfg', tenant_id: TENANT, connector_id: 'conn_cfg', provider: 'provider_a', snapshot_kind: 'waf_policy',
    resource_ref_hash: 'sha256:cfg', observed_at: T1, evidence_source: 'connector', summary: { policy_mode: 'monitor', hostnames: ['app.example.com'] },
  };

  function facadeWithSpy() {
    const calls = [];
    const backend = {
      async loadConfigurationSnapshots(ctx) {
        calls.push(ctx.role);
        return { snapshots: [SNAPSHOT], connectors: [{ id: 'conn_cfg', status: 'degraded', permission_gaps: ['zone:read'] }] };
      },
      async loadTargetContext() { return { targets: [TARGET], records: {} }; },
      async listEntryPaths() {
        return [{ ...normalizeEntryPathDeclaration({ entry_target_id: 'tgt_cfg', relation_kind: 'primary_route', owner: 'App', purpose: 'Main', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] }, { tenantId: TENANT, anchorTargetId: 'tgt_cfg' }), id: 'ep_cfg', status: 'active' }];
      },
      async listEvaluations() { return []; },
      async listExpectations() { return []; },
    };
    return { calls, facade: createProtectionValidationFacade({ base: { recordComparisonEvaluation: async () => null }, backend }) };
  }

  for (const role of ['viewer', 'soc']) {
    it(`redacts configuration for ${role} on target detail and the matrix`, async () => {
      const { calls, facade } = facadeWithSpy();
      const ctx = { tenantId: TENANT, userId: `usr_${role}`, role };
      assert.deepEqual(await facade.getTargetConfigurationContext(ctx, TARGET, { runtimeConfig: RUNTIME }), { configuration_access: 'redacted' });
      const matrix = await facade.getProtectionMatrix(ctx, { targetId: 'tgt_cfg' }, { runtimeConfig: RUNTIME });
      assert.equal(matrix.configuration_access, 'redacted');
      assert.ok(matrix.paths.length > 0);
      assert.ok(matrix.paths.every((row) => row.layers.every((layer) => layer.configuration === undefined)));
      assert.equal(JSON.stringify(matrix).includes('monitor'), false);
      assert.deepEqual(calls, []);
    });
  }

  it('redacts configuration for an API key without the waf:connector_read scope', async () => {
    const { calls, facade } = facadeWithSpy();
    const ctx = { tenantId: TENANT, userId: 'usr_key', role: 'engineer', scopes: ['evidence:read'] };
    assert.deepEqual(await facade.getTargetConfigurationContext(ctx, TARGET, { runtimeConfig: RUNTIME }), { configuration_access: 'redacted' });
    assert.deepEqual(calls, []);
  });

  it('returns nothing when WAF posture is disabled, even with connectors on', async () => {
    const { calls, facade } = facadeWithSpy();
    const runtimeConfig = { featureFlags: { ...RUNTIME.featureFlags, wafPostureEnabled: false } };
    assert.equal(await facade.getTargetConfigurationContext(CTX, TARGET, { runtimeConfig }), null);
    assert.deepEqual(calls, []);
  });

  it('serves configuration context to roles with waf:connector_read', async () => {
    const { calls, facade } = facadeWithSpy();
    const context = await facade.getTargetConfigurationContext(CTX, TARGET, { runtimeConfig: RUNTIME });
    assert.equal(context.configuration_access, 'granted');
    assert.equal(context.connectors_enabled, true);
    const matrix = await facade.getProtectionMatrix(CTX, { targetId: 'tgt_cfg' }, { runtimeConfig: RUNTIME });
    assert.equal(matrix.configuration_access, 'granted');
    assert.ok(matrix.paths[0].layers.every((layer) => layer.configuration?.evidence_role === 'explanation_only'));
    assert.deepEqual(calls, ['engineer', 'engineer']);
  });
});
