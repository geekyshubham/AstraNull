import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { presentTargetEdgeDetection } from '../../src/lib/edgeDetectionPresenter.mjs';
import { deriveRunEvidenceStamp } from '../../src/lib/checkDefinitionVersion.mjs';
import {
  normalizeDeclarationInput,
  presentTargetDeclaration,
} from '../../src/lib/targetDeclarations.mjs';
import { deriveProtectionProfile as projectProtectionProfile } from '../../src/services/protectionProfile.mjs';
import { getTargetDetail } from '../../src/services/targetDetail.mjs';
import {
  addTarget,
  createTargetGroup,
  listTargets,
  patchTargetById,
  patchTargetGroup,
} from '../../src/services/targetGroups.mjs';
import { getStore } from '../../src/store.mjs';
import { sanitizeProbeMetadata } from '../../workers/probe-worker.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { assuranceWorld, addAssuredObservation } from '../helpers/assurance-fixtures.mjs';
import { WAF_GRADING_VERSION, SIGNATURE_CORPUS_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_profile', role: 'engineer' };
const NOW = '2026-10-04T00:00:00.000Z';
const FRESH = '2026-10-03T00:00:00.000Z';
const STALE = '2026-09-01T00:00:00.000Z';

// Synthetic state-machine checks use the same required schema as reviewed definitions.
// These fixture IDs are never admitted to the production catalog or dispatched.
function fixtureDefinition(check) {
  return { required_customer_setup: [], prerequisites: [], evidence_required: [], stop_conditions: [],
    ...check, ...(check.probe_profile ? { probe_profile: { kind: 'waf_class_marker_probe', max_requests: 2,
      timeout_ms: 1000, ...check.probe_profile } } : {}) };
}
function deriveProtectionProfile(input) {
  return projectProtectionProfile({ ...input, catalog: input.catalog?.map(fixtureDefinition) });
}

const CATALOG = [
  { check_id: 'app.ok', version: '1.0.0', vector_family: 'l7', supported_targets: ['fqdn'] },
  { check_id: 'app.stale', version: '1.0.0', vector_family: 'waf', supported_targets: ['fqdn'] },
  { check_id: 'net.inconclusive', version: '1.0.0', vector_family: 'l3_l4', supported_targets: ['fqdn'] },
  { check_id: 'dns.not_run', version: '1.0.0', vector_family: 'dns', supported_targets: ['fqdn'] },
  {
    check_id: 'setup.excluded',
    vector_family: 'origin',
    supported_targets: ['fqdn'],
    required_customer_setup: ['declared_fixture_probe_path'],
    probe_profile: { kind: 'waf_class_marker_probe' },
  },
  { check_id: 'soc.hidden', vector_family: 'l7', risk_class: 'soc_gated', supported_targets: ['fqdn'] },
  { check_id: 'ip.only', vector_family: 'protocol', supported_targets: ['ip'] },
];

function declarationError(input) {
  try {
    normalizeDeclarationInput(input);
    return null;
  } catch (error) {
    return error;
  }
}

describe('typed target declarations', () => {
  beforeEach(() => {
    freshStore();
  });

  it('rejects unknown fields, roles, owner status, and overlong text', () => {
    assert.equal(declarationError({ service_roles: ['mail'] })?.code, 'invalid_declaration');
    assert.equal(declarationError({ purpose: 'x'.repeat(201) })?.field, 'purpose');
    assert.equal(declarationError({ criticality: 'urgent' })?.field, 'criticality');
    assert.equal(declarationError({ vendor: 'cloudflare' })?.field, 'vendor');
    assert.equal(declarationError({ owner: { label: 'Ops', status: 'declared' } })?.field, 'owner');
    assert.equal(declarationError([])?.field, 'declaration');
    assert.deepEqual(normalizeDeclarationInput({
      service_roles: ['dns', 'website', 'website'],
      criticality: 'HIGH',
      owner: { label: '  App team ' },
    }), {
      service_roles: ['website', 'dns'],
      owner_label: 'App team',
      criticality: 'high',
    });
  });

  it('inherits only unset fields from the target group and keeps explicit empties', () => {
    const group = {
      purpose: 'customer edge',
      service_roles: ['website', 'api'],
      owner_label: 'Group owner',
      criticality: 'high',
    };
    const inherited = presentTargetDeclaration({}, group);
    assert.equal(inherited.purpose_status, 'inherited');
    assert.equal(inherited.purpose_source, 'target_group');
    assert.equal(inherited.criticality.status, 'inherited');
    assert.equal(inherited.criticality.value, 'high');
    assert.deepEqual(inherited.service_roles, ['website', 'api']);

    const cleared = presentTargetDeclaration({ purpose: null, service_roles: [], owner_label: null }, group);
    assert.equal(cleared.purpose_status, 'unassigned');
    assert.equal(cleared.purpose_source, 'target');
    assert.equal(cleared.service_roles_status, 'unassigned');
    assert.deepEqual(cleared.service_roles, []);
    assert.equal(cleared.owner.status, 'unassigned');
    assert.equal(cleared.owner.source, 'target');
    assert.equal(cleared.criticality.status, 'inherited');

    const groupCleared = presentTargetDeclaration({ purpose: null }, null, { subject: 'target_group' });
    assert.equal(groupCleared.purpose_status, 'unassigned');
    assert.equal(groupCleared.purpose_source, 'target_group');
  });

  it('round-trips audited writes, inheritance, and immutable identity in the dev store', () => {
    const group = createTargetGroup(ctx, { name: 'Declared scope' });
    const invalid = patchTargetGroup(ctx, group.id, { declaration: { service_roles: ['mail'] } });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.error, 'invalid_declaration');
    assert.equal(getStore().auditLog.some((entry) => entry.action === 'target_group.declaration_updated'), false);

    const patchedGroup = patchTargetGroup(ctx, group.id, {
      declaration: {
        purpose: 'customer edge',
        criticality: 'HIGH',
        service_roles: ['dns', 'website'],
        owner: 'Group owner',
      },
    });
    assert.equal(patchedGroup.declaration.criticality.value, 'high');
    assert.equal(patchedGroup.declaration.criticality.source, 'target_group');
    assert.equal(patchedGroup.declaration.criticality.status, 'declared');
    assert.deepEqual(patchedGroup.declaration.service_roles, ['website', 'dns']);
    assert.equal(patchedGroup.declaration_json, undefined);
    assert.equal(
      getStore().targetGroups.find((item) => item.id === group.id).declaration_json.criticality,
      'high',
    );

    const target = addTarget(ctx, group.id, { kind: 'fqdn', value: 'app.example.com', tags: ['edge'] });
    const listed = listTargets(ctx).find((item) => item.id === target.id);
    assert.equal(listed.declaration.purpose_status, 'inherited');
    assert.equal(listed.declaration.purpose_source, 'target_group');
    assert.equal(listed.declaration.criticality.status, 'inherited');
    assert.deepEqual(listed.tags, ['edge']);

    const blocked = patchTargetById(ctx, target.id, {
      value: 'other.example.com',
      declaration: { purpose: 'should not apply' },
    });
    assert.equal(blocked.status, 409);
    assert.equal(blocked.error, 'target_identity_immutable');
    assert.equal(listTargets(ctx).find((item) => item.id === target.id).declaration.purpose, 'customer edge');

    const updated = patchTargetById(ctx, target.id, {
      declaration: { purpose: 'login portal', owner: { label: 'App team' }, service_roles: ['login', 'api'] },
      metadata: { declaration: { purpose: 'smuggled' }, notes: 'kept' },
    });
    assert.equal(updated.declaration.purpose, 'login portal');
    assert.equal(updated.declaration.purpose_status, 'declared');
    assert.equal(updated.declaration.purpose_source, 'target');
    assert.equal(updated.declaration.owner.label, 'App team');
    assert.equal(updated.declaration.owner.status, 'declared');
    assert.equal(updated.declaration.criticality.status, 'inherited');
    assert.equal(updated.metadata.notes, 'kept');
    assert.equal(updated.metadata.declaration, undefined);
    assert.equal(updated.declaration_json, undefined);

    const declarationAudit = getStore().auditLog.filter((entry) => entry.action === 'target.declaration_updated');
    assert.equal(declarationAudit.length, 1);
    assert.ok(getStore().auditLog.some((entry) => entry.action === 'target_group.declaration_updated'));
    const updateAudit = getStore().auditLog.find((entry) => (
      entry.action === 'target.updated'
      && entry.resource_id === target.id
      && entry.metadata.changed_fields.includes('declaration')
    ));
    assert.ok(updateAudit.metadata.dropped_untrusted_fields.includes('declaration'));

    const detail = getTargetDetail(ctx, target.id);
    assert.equal(detail.target.declaration.purpose, 'login portal');
    assert.equal(detail.target.declaration.service_roles_status, 'declared');
    assert.deepEqual(detail.target.tags, ['edge']);
    assert.equal(detail.protection_profile.families.origin_hosting.status, 'unknown');
    assert.equal(detail.protection_profile.families.origin_hosting.reason, 'no_origin_hosting_observation');
    assert.equal(detail.protection_profile.origin.status, 'not_tested');
    assert.equal(detail.coverage.runtime_launch_gates, 'not_evaluated');
    assert.equal(detail.coverage.percentage === null || Number.isInteger(detail.coverage.percentage), true);
  });

  it('uses the remediation owner and recorded posture, and leaves stuffed finding owners unread', () => {
    const group = createTargetGroup(ctx, { name: 'Owners' });
    const target = addTarget(ctx, group.id, { kind: 'fqdn', value: 'owners.example.com' });
    const store = getStore();
    store.findings.push(
      {
        id: 'fnd_stuffed',
        tenant_id: ctx.tenantId,
        target_id: target.id,
        title: 'Stuffed owner',
        severity: 'low',
        status: 'open',
        created_at: '2026-10-02T00:00:00.000Z',
        owner_group: 'edge-sre',
      },
      {
        id: 'fnd_owned',
        tenant_id: ctx.tenantId,
        target_id: target.id,
        title: 'Recorded owner',
        severity: 'low',
        status: 'open',
        created_at: '2026-10-01T00:00:00.000Z',
        owner_group: 'edge-sre',
      },
    );
    store.findingRemediations = [{
      finding_id: 'fnd_owned',
      tenant_id: ctx.tenantId,
      owner_group: 'app-owners',
    }];
    store.wafAssets = [{
      id: 'waf_recorded',
      tenant_id: ctx.tenantId,
      target_id: target.id,
      vendor: 'generic',
      marker_rules: 0,
      origin_bypass_state: 'not_exposed',
    }];

    const detail = getTargetDetail(ctx, target.id);
    const byId = new Map(detail.findings.map((finding) => [finding.id, finding]));
    assert.equal(byId.get('fnd_stuffed').owner_group, 'unassigned');
    assert.equal(byId.get('fnd_owned').owner_group, 'app-owners');
    assert.equal(detail.waf_posture.marker_rules, 0);
    assert.equal(detail.waf_posture.origin_bypass.state, 'not_exposed');

    store.wafAssets[0] = {
      id: 'waf_blank',
      tenant_id: ctx.tenantId,
      target_id: target.id,
      vendor: 'generic',
    };
    const blank = getTargetDetail(ctx, target.id);
    assert.equal(blank.waf_posture.marker_rules, null);
    assert.equal(blank.waf_posture.origin_bypass.state, 'not_tested');
    assert.equal(blank.waf_posture.fingerprint, null);
  });

  it('ignores foreign and tenantless rows and gates connector configuration', () => {
    const group = createTargetGroup(ctx, { name: 'Scope' });
    const target = addTarget(ctx, group.id, { kind: 'fqdn', value: 'scope.example.com' });
    const store = getStore();
    store.findings.push(
      {
        id: 'fnd_owned_scope',
        tenant_id: ctx.tenantId,
        target_id: target.id,
        title: 'Owned',
        severity: 'low',
        status: 'open',
        created_at: '2026-10-02T00:00:00.000Z',
      },
      {
        id: 'fnd_foreign',
        tenant_id: 'ten_other',
        target_id: target.id,
        title: 'Foreign',
        severity: 'high',
        status: 'open',
        created_at: '2026-10-03T00:00:00.000Z',
      },
      {
        id: 'fnd_legacy',
        target_id: target.id,
        title: 'No tenant',
        severity: 'high',
        status: 'closed',
        created_at: '2026-10-03T00:00:00.000Z',
      },
    );
    store.findingRemediations = [
      { finding_id: 'fnd_owned_scope', owner_group: 'edge-sre' },
      { finding_id: 'fnd_owned_scope', tenant_id: 'ten_other', owner_group: 'foreign-team' },
    ];
    store.targetVerifications = [{
      target_id: target.id,
      tenant_id: 'ten_other',
      state: 'user_confirmed',
      transitioned_at: '2026-10-03T00:00:00.000Z',
      source_kind: 'user_attestation',
    }];
    store.wafAssets = [{
      id: 'waf_scope',
      tenant_id: ctx.tenantId,
      target_id: target.id,
      vendor: 'generic',
      connector_id: 'conn_scope',
      raw_context_yaml: 'vendor: generic\nsecret: stored-secret\n',
    }];
    store.wafConnectors = [
      { id: 'conn_scope', tenant_id: 'ten_other', status: 'healthy' },
      { id: 'conn_scope', tenant_id: ctx.tenantId, status: 'degraded', secret_id: 'sec_1' },
    ];
    store.wafPostureSnapshots = [{
      waf_asset_id: 'waf_scope',
      tenant_id: 'ten_other',
      state: 'protected',
      observed_at: '2026-10-04T00:00:00.000Z',
    }];
    store.wafFingerprints = [
      { waf_asset_id: 'waf_scope', tenant_id: 'ten_other', signature: 'foreign', score: 1 },
      { waf_asset_id: 'waf_scope', tenant_id: ctx.tenantId, signature: 'owned-fp' },
    ];

    const detail = getTargetDetail(ctx, target.id);
    assert.deepEqual(detail.findings.map((finding) => finding.id), ['fnd_owned_scope']);
    assert.equal(detail.findings[0].owner_group, 'unassigned');
    assert.equal(detail.counts.findings_open, 1);
    assert.equal(detail.counts.findings_closed, 0);
    assert.equal(detail.verification.state, 'unverified');
    assert.equal(detail.waf_posture.fingerprint.signature, 'owned-fp');
    assert.equal(detail.waf_posture.fingerprint.score, null);
    assert.equal(detail.waf_posture.fingerprint.score_status, 'not_recorded');
    assert.equal(detail.waf_posture.posture, 'unknown');
    // Feature flags no longer gate connector configuration; only the role permission does.
    assert.equal(detail.waf_posture.connector.id, 'conn_scope');
    assert.equal(detail.waf_posture.connector.state, 'degraded');
    assert.equal(typeof detail.waf_posture.raw_context_yaml, 'string');
    assert.equal(detail.waf_posture.raw_context_yaml.includes('stored-secret'), false);
    assert.equal(detail.waf_posture.raw_context_yaml.includes('[redacted]'), true);
    assert.equal(detail.waf_posture.configuration_access, 'allowed');
    assert.equal(detail.waf_posture.configuration_disabled_reason, null);
    assert.equal(detail.waf_posture.profiles.core_fingerprint, 'independent');
    assert.equal(JSON.stringify(detail.waf_posture).includes('stored-secret'), false);
    assert.equal(JSON.stringify(detail.waf_posture).includes('sec_1'), false);

    const previousPosture = process.env.ASTRANULL_WAF_POSTURE_ENABLED;
    const previousConnectors = process.env.ASTRANULL_CONNECTORS_ENABLED;
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    process.env.ASTRANULL_CONNECTORS_ENABLED = '1';
    try {
      const opened = getTargetDetail(ctx, target.id);
      assert.equal(opened.waf_posture.configuration_access, 'allowed');
      assert.equal(opened.waf_posture.connector.id, 'conn_scope');
      assert.equal(opened.waf_posture.connector.state, 'degraded');
      assert.equal(opened.waf_posture.raw_context_yaml.includes('stored-secret'), false);
      assert.equal(opened.waf_posture.raw_context_yaml.includes('[redacted]'), true);
      assert.equal(Object.hasOwn(opened.waf_posture.connector, 'secret_id'), false);
      const viewer = getTargetDetail({ ...ctx, role: 'viewer' }, target.id);
      assert.equal(viewer.waf_posture.configuration_access, 'redacted');
      assert.equal(viewer.waf_posture.configuration_disabled_reason, 'permission_denied');
      assert.equal(viewer.waf_posture.connector, null);
      assert.equal(viewer.waf_posture.raw_context_yaml, null);
      assert.equal(viewer.waf_posture.fingerprint.signature, 'owned-fp');
      assert.equal(viewer.edge_detection === null || typeof viewer.edge_detection === 'object', true);
    } finally {
      if (previousPosture == null) delete process.env.ASTRANULL_WAF_POSTURE_ENABLED;
      else process.env.ASTRANULL_WAF_POSTURE_ENABLED = previousPosture;
      if (previousConnectors == null) delete process.env.ASTRANULL_CONNECTORS_ENABLED;
      else process.env.ASTRANULL_CONNECTORS_ENABLED = previousConnectors;
    }
  });
});

describe('protection profile derivation', () => {
  const target = {
    id: 'tgt_profile',
    kind: 'fqdn',
    value: 'app.example.com',
    tenant_id: ctx.tenantId,
    target_group_id: 'tg_profile',
  };

  it('uses the same catalog version derivation as run creation and distinguishes missing and changed versions', () => {
    const check = fixtureDefinition({ check_id: 'waf.digest', vector_family: 'waf', supported_targets: ['fqdn'], probe_profile: { scenario_family: 'marker' } });
    const stamp = deriveRunEvidenceStamp(check, {}, { probeMode: 'signed-worker', scenarioVersion: 'marker' });
    const metadata = addAssuredObservation(assuranceWorld()).event.metadata;
    const coverageFor = (overrides) => deriveProtectionProfile({
      now: NOW, target, catalog: [check], observations: [{
        check_id: check.check_id,
        evidence_verified: true,
        run: { producer_kind: 'signed_probe', id: 'run_digest', status: 'verdicted', completed_at: FRESH, ...stamp,
          readiness_result_metadata: [metadata], probe_metadata: metadata, ...overrides },
        verdict: { verdict: 'edge_exposed', evidence_ids: ['ev_digest'] },
      }],
    }).coverage.pairs[0];
    assert.equal(coverageFor({}).state, 'conclusive');
    assert.equal(coverageFor({}).live_external, true);
    assert.equal(coverageFor({ check_version: null }).pair_reason, 'missing_check_version');
    assert.equal(coverageFor({ check_version: 'older-version' }).pair_reason, 'check_version_mismatch');
    assert.equal(coverageFor({ scenario_version: null }).pair_reason, 'missing_scenario_version');
    assert.equal(coverageFor({ scenario_version: 'different-scenario' }).pair_reason, 'scenario_version_mismatch');
    assert.equal(coverageFor({ producer_kind: 'internal_simulation' }).live_external, false);
  });

  it('excludes declarations and control-plane readiness from the live external coverage denominator', () => {
    const checks = [
      { check_id: 'declaration.tier', evidence_tier: 'E1' },
      { check_id: 'declaration.marker', probe_profile: { kind: 'metadata_marker' } },
      { check_id: 'declaration.ops', probe_profile: { kind: 'ops_readiness' } },
      { check_id: 'external.safe', evidence_tier: 'E3' },
    ].map((check) => ({ vector_family: 'l7', supported_targets: ['fqdn'], ...check }));
    const { coverage } = deriveProtectionProfile({ now: NOW, target, catalog: checks });
    assert.equal(coverage.applicable_count, 1);
    assert.equal(coverage.not_run_count, 1);
    assert.equal(coverage.excluded_count, 3);
    for (const pair of coverage.pairs.filter((pair) => pair.state === 'excluded')) {
      assert.equal(pair.exclusion_reason, 'declaration_only');
      assert.equal(pair.live_external, false);
    }
  });

  it('keeps the five families independent and does not copy WAF onto CDN or cloud onto origin', () => {
    const presented = presentTargetEdgeDetection({
      status: 'detected',
      waf_status: 'detected',
      waf_vendor: 'cloudflare',
      cdn_status: 'detected',
      confidence: 0.8,
      observed_at: FRESH,
    });
    assert.equal(presented.waf.provider, 'cloudflare');
    assert.equal(presented.cdn.provider, undefined);

    const { protection_profile: profile, coverage } = deriveProtectionProfile({
      now: NOW,
      target,
      catalog: CATALOG,
      edgeRow: {
        status: 'detected',
        waf_status: 'detected',
        waf_vendor: 'cloudflare',
        cdn_status: 'detected',
        confidence: 0.8,
        observed_at: STALE,
        test_run_id: 'run_edge',
        evidence_json: {
          cloud: { provider: 'aws', status: 'detected', confidence: 0, observed_at: FRESH },
          cname_chain: ['edge.example.net'],
          resolved_ips: ['203.0.113.10'],
        },
      },
      policies: [],
      observations: [],
    });

    assert.equal(profile.families.waf.provider, 'cloudflare');
    assert.equal(profile.families.waf.status, 'detected');
    assert.equal(profile.families.waf.confidence, null);
    assert.equal(profile.families.waf.freshness, 'stale');
    assert.equal(profile.families.cdn.provider, null);
    assert.equal(profile.families.cdn.confidence, null);
    assert.equal(profile.families.cdn.reason, 'provider_not_recorded');
    assert.equal(profile.families.cloud.provider, 'aws');
    assert.equal(profile.families.cloud.confidence, 0);
    assert.equal(profile.families.cloud.reason, 'observed_edge_or_cloud_layer');
    assert.equal(profile.families.dns.status, 'not_recorded');
    assert.equal(profile.families.dns.reason, 'no_dns_provider_observation');
    assert.equal(profile.families.origin_hosting.status, 'unknown');
    assert.equal(profile.families.origin_hosting.reason, 'no_origin_hosting_observation');
    assert.equal(profile.origin.status, 'not_tested');
    assert.equal(profile.origin.binding_id, null);
    assert.equal(profile.effectiveness.percentage, null);
    assert.equal(profile.effectiveness.percentage_reason, 'not_recorded');
    assert.notEqual(profile.effectiveness.percentage, coverage.percentage);
    assert.equal(coverage.runtime_launch_gates, 'not_evaluated');
  });

  it('records the cloud source from the stored cloud type when the layer lost its sources', () => {
    const { protection_profile: profile } = deriveProtectionProfile({
      now: NOW,
      target,
      catalog: CATALOG,
      edgeRow: {
        status: 'detected',
        waf_status: 'not_detected',
        cdn_status: 'detected',
        cdn_provider: 'google',
        cdn_type: 'address_range',
        observed_at: FRESH,
        test_run_id: 'run_edge',
        evidence_json: {
          cloud: { status: 'detected', provider: 'google', type: 'address_range' },
          layers: [{ family: 'cloud', provider: 'google', confidence: 0.7 }],
        },
      },
      policies: [],
      observations: [],
    });
    assert.deepEqual(profile.families.cloud.sources, ['address_range']);
    assert.deepEqual(profile.families.cdn.sources, ['address_range']);
  });

  it('keeps edge layer sources through the probe worker metadata sanitizer', () => {
    const sanitized = sanitizeProbeMetadata({
      edge_signature: { layers: [{ family: 'cloud', provider: 'google', confidence: 0.7, sources: ['address_range'] }] },
    });
    assert.deepEqual(sanitized.edge_signature.layers[0].sources, ['address_range']);
  });

  it('separates applicable, excluded, incompatible, stale, and zero denominators', () => {
    const empty = deriveProtectionProfile({
      now: NOW,
      target,
      catalog: [{ check_id: 'ip.only', vector_family: 'protocol', supported_targets: ['ip'] }],
      policies: [],
      observations: [],
    });
    assert.equal(empty.coverage.applicable_count, 0);
    assert.equal(empty.coverage.excluded_count, 0);
    assert.equal(empty.coverage.percentage, null);
    assert.equal(empty.coverage.percentage_reason, 'not_applicable');
    assert.equal(empty.protection_profile.dimensions.find((item) => item.id === 'network').status, 'not_applicable');

    const measured = deriveProtectionProfile({
      now: NOW,
      target,
      catalog: [
        { check_id: 'dns.a', vector_family: 'dns', supported_targets: ['fqdn'] },
        { check_id: 'dns.b', vector_family: 'dns', supported_targets: ['fqdn'] },
      ],
      policies: [{ id: 'pol_group', check_id: 'dns.a', tenant_id: target.tenant_id, target_group_id: target.target_group_id }],
      observations: [],
    });
    assert.equal(measured.coverage.applicable_count, 2);
    assert.equal(measured.coverage.conclusive_count, 0);
    assert.equal(measured.coverage.not_run_count, 2);
    assert.equal(measured.coverage.percentage, 0);
    assert.equal(measured.coverage.pairs.find((pair) => pair.check_id === 'dns.a').policy_binding, 'test_policy_target_binding_missing');
    assert.equal(measured.coverage.pairs[0].launchable, null);
    assert.equal(measured.coverage.pairs[0].launch_block_reason, 'not_evaluated');

    const mixed = deriveProtectionProfile({
      now: NOW,
      target,
      catalog: CATALOG,
      policies: [{
        id: 'pol_target',
        check_id: 'app.ok',
        tenant_id: target.tenant_id,
        target_group_id: target.target_group_id,
        target_id: target.id,
      }],
      observations: [
        {
          check_id: 'app.ok', evidence_verified: true,
          run: { readiness_result_metadata: [{ enforcement: 'enforced' }], producer_kind: 'signed_probe', id: 'run_ok', status: 'completed', completed_at: FRESH, check_version: '1.0.0' },
          verdict: { verdict: 'protected', evidence_ids: ['ev_ok'] },
        },
        {
          check_id: 'app.stale',
          run: {
            producer_kind: 'signed_probe',
            id: 'run_stale',
            status: 'completed',
            completed_at: STALE,
            check_version: '1.0.0',
            grading_version: WAF_GRADING_VERSION,
            signature_corpus_version: SIGNATURE_CORPUS_VERSION,
          },
          verdict: { verdict: 'exposed', evidence_ids: ['ev_stale'] },
        },
        {
          check_id: 'net.inconclusive',
          run: { producer_kind: 'signed_probe', id: 'run_inc', status: 'completed', completed_at: FRESH, check_version: '1.0.0' },
          verdict: { verdict: 'inconclusive', evidence_ids: ['ev_inc'] },
        },
      ],
    });
    const pairs = mixed.coverage.pairs;
    // SOC request markers are applicable now; they simply have no observation yet.
    assert.equal(pairs.find((pair) => pair.check_id === 'soc.hidden').state, 'not_run');
    assert.equal(pairs.some((pair) => pair.check_id === 'ip.only'), false);
    // Required customer setup is advisory now, so this check is applicable but unobserved.
    assert.equal(pairs.find((pair) => pair.check_id === 'setup.excluded').state, 'not_run');
    assert.equal(pairs.find((pair) => pair.check_id === 'setup.excluded').exclusion_reason, null);
    assert.equal(pairs.find((pair) => pair.check_id === 'app.ok').state, 'conclusive');
    assert.equal(pairs.find((pair) => pair.check_id === 'app.ok').live_external, true);
    assert.equal(pairs.find((pair) => pair.check_id === 'app.ok').policy_binding, 'bound');
    assert.equal(pairs.find((pair) => pair.check_id === 'app.stale').state, 'stale');
    assert.equal(pairs.find((pair) => pair.check_id === 'app.stale').prior_state, 'conclusive');
    assert.equal(pairs.find((pair) => pair.check_id === 'net.inconclusive').state, 'inconclusive');
    assert.equal(pairs.find((pair) => pair.check_id === 'dns.not_run').state, 'not_run');
    assert.equal(mixed.coverage.applicable_count, 6);
    assert.equal(mixed.coverage.evaluated_count, 3);
    assert.equal(mixed.coverage.conclusive_count, 1);
    assert.equal(mixed.coverage.inconclusive_count, 1);
    assert.equal(mixed.coverage.not_run_count, 3);
    assert.equal(mixed.coverage.stale_count, 1);
    assert.equal(mixed.coverage.excluded_count, 0);
    assert.equal(mixed.coverage.percentage, 17);
    const application = mixed.protection_profile.dimensions.find((item) => item.id === 'application');
    assert.equal(application.conclusive_count + application.stale_count, 2);
    assert.equal(application.status, 'partial');

    const markers = deriveProtectionProfile({
      now: NOW,
      target,
      catalog: [],
      edgeRow: {
        evidence_json: { effectiveness: { tested_count: 0, blocked_count: null, passed_count: 0 } },
      },
    });
    assert.equal(markers.protection_profile.effectiveness.unit, 'definitive_marker');
    assert.equal(markers.protection_profile.effectiveness.percentage, null);
    assert.equal(markers.protection_profile.effectiveness.percentage_reason, 'not_applicable');
    assert.equal(markers.protection_profile.effectiveness.not_run_count, null);
    assert.equal(markers.coverage.percentage, null);
  });

  it('does not treat reachability, simulation, or incomplete observations as current live coverage', () => {
    const reached = deriveProtectionProfile({
      now: NOW,
      target,
      catalog: CATALOG,
      edgeRow: {
        target_id: target.id,
        evidence_json: {
          network_firewall: {
            direct_origin_reachability: {
              status: 'exposed',
              target_id: target.id,
              scenario_id: 'origin.direct_reachability.safe',
            },
          },
        },
      },
    });
    assert.equal(reached.protection_profile.origin.status, 'unknown');
    assert.equal(reached.protection_profile.origin.binding_id, null);
    assert.equal(reached.protection_profile.origin.assurance, 'none');
    assert.equal(reached.protection_profile.origin.reason, 'no_origin_binding_recorded');
    assert.equal(reached.protection_profile.origin.reachability.status, 'exposed');
    assert.equal(reached.protection_profile.origin.reachability.tested_target_id, target.id);
    assert.ok(reached.protection_profile.origin.reachability.limitations.includes('does_not_prove_host_origin_lockdown'));

    const adversarial = deriveProtectionProfile({
      now: NOW,
      target,
      catalog: [
        { check_id: 'time.missing', version: '1.0.0', vector_family: 'l7', supported_targets: ['fqdn'] },
        { check_id: 'run.canceled', version: '1.0.0', vector_family: 'l7', supported_targets: ['fqdn'] },
        { check_id: 'run.open', version: '1.0.0', vector_family: 'l7', supported_targets: ['fqdn'] },
        { check_id: 'no.evidence', version: '1.0.0', vector_family: 'l7', supported_targets: ['fqdn'] },
        { check_id: 'version.missing', version: '1.0.0', vector_family: 'l7', supported_targets: ['fqdn'] },
        {
          check_id: 'scenario.missing',
          version: '1.0.0',
          vector_family: 'waf',
          supported_targets: ['fqdn'],
          probe_profile: { scenario_family: 'marker' },
        },
        { check_id: 'sim.run', version: '1.0.0', vector_family: 'l7', supported_targets: ['fqdn'] },
        { check_id: 'manual.run', version: '1.0.0', vector_family: 'l7', supported_targets: ['fqdn'] },
      ],
      observations: [
        {
          check_id: 'time.missing',
          run: { producer_kind: 'signed_probe', id: 'run_time', status: 'completed', started_at: FRESH, check_version: '1.0.0' },
          verdict: { verdict: 'blocked', evidence_ids: ['ev_time'] },
        },
        {
          check_id: 'run.canceled',
          run: { producer_kind: 'signed_probe', id: 'run_cancel', status: 'cancelled', completed_at: FRESH, check_version: '1.0.0' },
          verdict: { verdict: 'blocked', evidence_ids: ['ev_cancel'] },
        },
        {
          check_id: 'run.open',
          run: { producer_kind: 'signed_probe', id: 'run_open', status: 'collecting', check_version: '1.0.0' },
          verdict: { verdict: 'blocked', evidence_ids: ['ev_open'] },
        },
        {
          check_id: 'no.evidence',
          run: { producer_kind: 'signed_probe', id: 'run_none', status: 'completed', completed_at: FRESH, check_version: '1.0.0' },
          verdict: { verdict: 'blocked', evidence_ids: [] },
        },
        {
          check_id: 'version.missing',
          run: { producer_kind: 'signed_probe', id: 'run_version', status: 'completed', completed_at: FRESH },
          verdict: { verdict: 'blocked', evidence_ids: ['ev_version'] },
        },
        {
          check_id: 'scenario.missing',
          run: { producer_kind: 'signed_probe', id: 'run_scenario', status: 'completed', completed_at: FRESH, check_version: '1.0.0' },
          verdict: { verdict: 'blocked', evidence_ids: ['ev_scenario'] },
        },
        {
          check_id: 'sim.run',
          run: {
            producer_kind: 'signed_probe',
            id: 'run_sim',
            status: 'completed',
            completed_at: FRESH,
            check_version: '1.0.0',
            producer_kind: 'internal_simulation',
            simulation: 'SAFE_PROBE_SIMULATION',
            evidence_label: 'probe_simulation_evidence',
          },
          verdict: { verdict: 'blocked', evidence_ids: ['ev_sim'] },
        },
        {
          check_id: 'manual.run',
          run: {
            producer_kind: 'signed_probe',
            id: 'run_manual',
            status: 'completed',
            completed_at: FRESH,
            check_version: '1.0.0',
            source: 'manual_declaration',
            producer_kind: 'customer_declaration',
          },
          verdict: { verdict: 'blocked', evidence_ids: ['ev_manual'] },
        },
      ],
    });
    const byId = new Map(adversarial.coverage.pairs.map((pair) => [pair.check_id, pair]));
    for (const checkId of ['time.missing', 'run.canceled', 'run.open', 'no.evidence', 'sim.run', 'manual.run']) {
      assert.equal(byId.get(checkId).state, 'unknown', checkId);
      assert.equal(byId.get(checkId).live_external, false, checkId);
    }
    assert.equal(byId.get('time.missing').pair_reason, 'observation_time_unknown');
    assert.equal(byId.get('time.missing').retained.verdict, 'blocked');
    assert.equal(byId.get('run.canceled').pair_reason, 'canceled');
    assert.equal(byId.get('run.canceled').retained.verdict, 'blocked');
    assert.equal(byId.get('run.open').pair_reason, 'unfinalized');
    assert.equal(byId.get('no.evidence').pair_reason, 'no_evidence');
    assert.equal(byId.get('version.missing').state, 'partial');
    assert.equal(byId.get('version.missing').pair_reason, 'missing_check_version');
    assert.equal(byId.get('version.missing').retained.verdict, 'blocked');
    assert.equal(byId.get('scenario.missing').state, 'partial');
    assert.equal(byId.get('scenario.missing').pair_reason, 'missing_scenario_version');
    assert.equal(byId.get('sim.run').provenance, 'internal_simulation');
    assert.equal(byId.get('sim.run').retained.verdict, 'blocked');
    assert.equal(byId.get('manual.run').provenance, 'manual_declaration');
    assert.equal(adversarial.coverage.conclusive_count, 0);
    assert.equal(adversarial.coverage.percentage, 0);
    assert.equal(adversarial.coverage.unknown_count, 6);
    assert.equal(adversarial.coverage.partial_count, 2);
  });
});


describe('actual signed proof in the dev target profile reader', () => {
  beforeEach(() => freshStore());
  function recordedWorld() {
    const world = assuranceWorld(); addAssuredObservation(world, { outcome: 'edge_protected', observedAt: new Date(Date.now() - 1000).toISOString() });
    Object.assign(getStore(), { targets: world.targets, targetGroups: world.groups, testRuns: world.runs,
      verdicts: world.verdicts, events: world.events, evidenceVault: world.evidenceItems, testPolicies: [] });
    return world;
  }
  function pair(world) {
    return getTargetDetail(ctx, world.targets[0].id).coverage.pairs.find((row) => row.check_id === world.catalog[0].check_id);
  }
  it('credits complete scoped edge denial only from actual same-run nonce-bound signed events or available linked vault references', () => {
    const world = recordedWorld();
    assert.equal(pair(world).state, 'conclusive'); assert.equal(pair(world).outcome, 'pass');
    world.evidenceItems.push({ id: 'vault_profile', tenant_id: world.tenantId, test_run_id: world.runs[0].id,
      related_event_id: world.events[0].id, created_at: world.events[0].timestamp });
    world.verdicts[0].evidence_ids = ['vault_profile'];
    assert.equal(pair(world).state, 'conclusive');
    const custody = JSON.stringify([world.runs, world.verdicts, world.events, world.evidenceItems]);
    world.targets[0].port = 8443;
    assert.equal(pair(world).pair_reason, 'target_definition_changed');
    assert.equal(JSON.stringify([world.runs, world.verdicts, world.events, world.evidenceItems]), custody);
  });
  it('does not let a newer unresolved positive verdict borrow an older valid gap proof on the same run', () => {
    const world = recordedWorld(); world.verdicts[0].verdict = 'edge_exposed';
    assert.equal(pair(world).outcome, 'gap');
    world.verdicts.push({ ...world.verdicts[0], id: 'newer_unresolved_verdict', verdict: 'edge_protected',
      evidence_ids: ['unresolved_evidence'], created_at: new Date().toISOString() });
    const result = pair(world);
    assert.equal(result.state, 'unknown'); assert.equal(result.pair_reason, 'invalid_or_unresolved_evidence');
    assert.equal(result.live_external, false);
  });
  it('never credits unresolved, cross-run, cross-tenant, wrong/missing nonce, unsigned, missing-ingestion, future or incomplete proof', () => {
    for (const mutate of [
      w => { w.verdicts[0].evidence_ids = ['missing']; },
      w => { w.events[0].test_run_id = 'other_run'; },
      w => { w.events[0].tenant_id = 'other_tenant'; },
      w => { w.events[0].nonce_hash = 'wrong_nonce'; },
      w => { delete w.runs[0].correlation; },
      w => { w.events[0].producer_kind = 'customer_declaration'; },
      w => { delete w.events[0].ingested_at; },
      w => { w.events[0].ingested_at = new Date(Date.now() + 60000).toISOString(); },
      w => { w.events[0].metadata.comparison_complete = false; },
      w => { w.events[0].metadata.enforcement = 'not_enforced'; },
      w => { delete w.events[0].metadata.enforcement; },
      w => { delete w.runs[0].safety_constraints.assurance_scope; },
    ]) { const world = recordedWorld(); mutate(world); assert.notEqual(pair(world).state, 'conclusive'); }
  });
});
