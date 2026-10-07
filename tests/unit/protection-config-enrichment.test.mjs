import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  attachConfigurationExplanations,
  attachConfigurationToMatrixRow,
  buildConfigurationContext,
  classifyEnforcementCoverage,
  CONFIG_ABSENCE_MEANING,
  CONFIG_CANDIDATE_EXPLANATIONS,
  CONFIG_ENRICHMENT_MARKERS,
  explainComparisonItem,
  explainComparisonItems,
  matchConfigurationScope,
  normalizeConfigurationScope,
  normalizeConfigurationSnapshot,
  pathPatternMatches,
} from '../../src/lib/protectionConfigEnrichment.mjs';
import {
  buildNormalizedSnapshot,
  buildProtectionConfig,
  PROTECTION_CONFIG_MAX_PATTERNS,
} from '../../src/lib/connectorProviders/common.mjs';
import { pollAkamaiApplicationSecurity } from '../../src/lib/connectorProviders/akamaiAppSec.mjs';
import { pollAwsWaf, awsRuleActionCategory } from '../../src/lib/connectorProviders/awsWaf.mjs';
import { pollCloudflare, cloudflareRuleActionCategory } from '../../src/lib/connectorProviders/cloudflare.mjs';
import { assertNoRawWafEvidence } from '../../src/contracts/wafPosture.mjs';
import {
  classifyFirewallComparisonItem,
  classifyPathValidationItem,
  comparisonEvaluationDigest,
  emptyProtectionMatrixRow,
  findBannedScopeKey,
  LAYER_EVIDENCE_DIMENSIONS,
  normalizeComparisonEvaluation,
  normalizeEntryPathDeclaration,
  normalizeFirewallExpectation,
} from '../../src/contracts/protectionValidation.mjs';

const NOW = new Date('2026-10-06T12:00:00.000Z');
const FRESH = '2026-10-06T06:00:00.000Z';
const TENANT = 'ten_a';
const NEGATIVE_PROTECTION_WORDING = /no_protection|unprotected|not_protected|no protection/i;

function snapshot(overrides = {}) {
  const { summary, protection_config: config, ...rest } = overrides;
  return {
    id: 'snap_1',
    connector_id: 'conn_1',
    provider: 'akamai_appsec',
    snapshot_kind: 'waf_policy',
    resource_ref_hash: 'ref_1',
    display_ref: 'prod-config::policy-1',
    config_hash: 'hash_1',
    evidence_source: 'provider_api',
    inventory_complete: true,
    inventory_truncated: false,
    observed_at: FRESH,
    summary: { hostnames: ['app.example.com'], policy_mode: 'block', ...summary },
    ...(config === undefined
      ? { protection_config: buildProtectionConfig({ enforcementUnit: 'attack_group', actions: ['block', 'block'], attachmentLevel: 'hostname' }) }
      : config === null ? {} : { protection_config: config }),
    ...rest,
  };
}

function context(snapshots, scope = { hostname: 'app.example.com', path: '/api/login', method: 'POST' }, extra = {}) {
  return buildConfigurationContext({ scope, snapshots, now: NOW, ...extra });
}

function relation(overrides = {}) {
  return {
    id: 'ep_1',
    ...normalizeEntryPathDeclaration({
      entry_target_id: 'tgt_alt',
      relation_kind: 'alternate_hostname',
      owner: 'App Team',
      purpose: 'Legacy hostname kept for partners',
      expected_behavior: 'must_be_protected_by_layers',
      required_layers: ['waf', 'cdn_edge'],
      ...overrides,
    }, { tenantId: TENANT, anchorTargetId: 'tgt_app' }),
  };
}

function ref(overrides = {}) {
  return {
    test_run_id: 'run_1',
    check_id: 'waf.marker.sqli',
    check_version: 'v3',
    scenario_version: 's2',
    verdict_id: 'verdict_1',
    evidence_ids: ['ev_1'],
    target_id: 'tgt_alt',
    observed_at: '2026-10-06T05:00:00.000Z',
    run_status: 'verdicted',
    source_perspective: 'public-worker-eu',
    worker_id: 'worker_eu_1',
    ...overrides,
  };
}

function pathEvaluation(classified) {
  return normalizeComparisonEvaluation({
    kind: 'path_validation',
    tenant_id: TENANT,
    items: classified.map((entry, index) => ({
      ...entry,
      entry_path_id: `ep_${index + 1}`,
      scenario: 'waf.sqli',
      evidence_refs: ['inconclusive', 'not_tested', 'skipped'].includes(entry.outcome) ? [] : [ref()],
    })),
    evaluated_at: '2026-10-06T07:00:00.000Z',
  });
}

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}

function jsonResponse(body) {
  return { ok: true, status: 200, json: async () => body };
}

describe('provider snapshots expose generic configuration fields', () => {
  it('keeps missing match-target ordering unknown instead of manufacturing priority zero', () => {
    const base = { provider: 'akamai_appsec', snapshotKind: 'waf_policy', resourceRef: 'policy' };
    for (const value of [null, undefined, '']) {
      assert.equal(buildNormalizedSnapshot({ ...base, summary: { match_target_order: value } }).summary.match_target_order, undefined);
      const unknown = buildNormalizedSnapshot({ ...base, summary: { rule_count: value, record_ttl: value } }).summary;
      assert.equal(unknown.rule_count, undefined);
      assert.equal(unknown.record_ttl, undefined);
    }
    assert.equal(buildNormalizedSnapshot({ ...base, summary: { match_target_order: 0 } }).summary.match_target_order, 0);
    assert.equal(buildNormalizedSnapshot({ ...base, summary: { match_target_order: 2 } }).summary.match_target_order, 2);
    assert.equal(buildNormalizedSnapshot({ ...base, summary: { rule_count: 0 } }).summary.rule_count, 0);
  });
  it('keeps the generic fields outside the summary so config_hash and persistence allowlists are unchanged', () => {
    const base = { provider: 'aws_waf', snapshotKind: 'waf_policy', resourceRef: 'arn:1', displayRef: 'acl', summary: { policy_mode: 'block', rule_count: 2 }, observedAt: FRESH };
    const legacy = buildNormalizedSnapshot(base);
    const enriched = buildNormalizedSnapshot({ ...base, protectionConfig: { actions: ['block'], attachmentLevel: 'resource' } });
    assert.equal(enriched.config_hash, legacy.config_hash);
    assert.deepEqual(enriched.summary, legacy.summary);
    assert.equal(legacy.protection_config, undefined);
    assert.equal(enriched.protection_config.schema, 'protection-config-v1');
    assert.doesNotThrow(() => assertNoRawWafEvidence(enriched));
  });

  it('bounds and sanitizes patterns, methods, and versions without keeping raw rule content', () => {
    const paths = Array.from({ length: 50 }, (_, i) => `/p${i}/*`);
    const config = buildProtectionConfig({
      actions: ['block', 'weird'],
      attachmentPaths: [...paths, 'javascript:alert(1)', '/ok path'],
      exclusionPaths: ['/health', 'http://evil.example/x'],
      exclusionMethods: ['options', 'G3T', 'TRACE'],
      configVersion: 'v 1; drop',
      unsupportedFields: ['path_exclusions', 'not_a_field'],
    });
    assert.equal(config.attachment_paths.length, PROTECTION_CONFIG_MAX_PATTERNS);
    assert.ok(config.attachment_paths.every((p) => p.startsWith('/') && !p.includes(' ')));
    assert.deepEqual(config.exclusion_paths, ['/health']);
    assert.deepEqual(config.exclusion_methods, ['OPTIONS', 'TRACE']);
    assert.equal(config.config_version, null);
    assert.equal(config.action_counts.unknown, 1);
    assert.deepEqual(config.unsupported_fields, ['path_exclusions']);
  });

  it('Akamai keeps per-attack-group actions so one deny group does not imply every group blocks', async () => {
    const result = await pollAkamaiApplicationSecurity({
      credentials: { host: 'example.luna.akamaiapis.net', access_token: 'a', client_token: 'c', client_secret: 's' },
      observedAt: FRESH,
      now: NOW,
      nonce: 'n',
      fetchFn: async (url) => {
        const path = String(url);
        if (path.endsWith('/appsec/v1/configs')) return jsonResponse({ configurations: [{ id: 111, name: 'prod', productionVersion: 7 }] });
        if (path.endsWith('/security-policies')) return jsonResponse({ policies: [{ policyId: 'pol1' }] });
        if (path.endsWith('/attack-groups')) return jsonResponse({ attackGroupActions: [{ group: 'SQL', action: 'deny' }, { group: 'XSS', action: 'alert' }, { group: 'CMD', action: 'none' }] });
        if (path.endsWith('/match-targets')) {
          return jsonResponse({ matchTargets: { websiteTargets: [{ targetId: 1, hostnames: ['app.example.com'], filePaths: ['/app/*'], securityPolicy: { policyId: 'pol1' }, sequence: 1 }] } });
        }
        throw new Error(`unexpected ${path}`);
      },
    });
    const [snap] = result.snapshots;
    assert.equal(snap.summary.policy_mode, 'block');
    assert.deepEqual(snap.protection_config.action_counts, { block: 1, challenge: 0, monitor: 1, bypass: 0, disabled: 1, delegated: 0, unknown: 0 });
    assert.deepEqual(snap.protection_config.attachment_paths, ['/app/*']);
    assert.equal(snap.protection_config.path_match, 'include');
    assert.equal(snap.protection_config.config_version, 'production_version:7');
    const record = normalizeConfigurationSnapshot({ ...snap, inventory_complete: true }, { now: NOW });
    assert.equal(record.enforcement.coverage, 'some_units_enforcing');
    assert.ok(record.markers.includes('partial_enforcement_units'));
    assert.ok(record.markers.includes('disabled_units'));
  });

  it('AWS WAF maps rule and override actions and counts managed-group exclusions', async () => {
    const result = await pollAwsWaf({
      prefetchedMetadata: {
        web_acls: [{
          ARN: 'arn:aws:wafv2:acl/1',
          Name: 'acl-1',
          hostnames: ['app.example.com'],
          DefaultAction: { Allow: {} },
          Rules: [
            { Name: 'r1', Action: { Block: {} } },
            { Name: 'r2', Action: { Count: {} } },
            { Name: 'r3', Action: { Allow: {} } },
            { Name: 'r4', OverrideAction: { None: {} }, Statement: { ManagedRuleGroupStatement: { ExcludedRules: [{ Name: 'x' }], RuleActionOverrides: [{ Name: 'y' }] } } },
            { Name: 'r5', Action: { Challenge: {} } },
          ],
        }],
      },
      observedAt: FRESH,
    });
    const config = result.snapshots[0].protection_config;
    assert.deepEqual(config.action_counts, { block: 1, challenge: 1, monitor: 1, bypass: 1, disabled: 0, delegated: 1, unknown: 0 });
    assert.equal(config.exclusion_count, 2);
    assert.equal(config.attachment_level, 'resource');
    assert.ok(config.unsupported_fields.includes('path_exclusions'));
    assert.equal(awsRuleActionCategory({ OverrideAction: { Count: {} } }), 'monitor');
    const record = normalizeConfigurationSnapshot(result.snapshots[0], { now: NOW });
    assert.equal(record.enforcement.coverage, 'some_units_enforcing');
    assert.ok(record.markers.includes('delegated_actions_unresolved'));
    assert.ok(record.markers.includes('exclusions_present_scope_unknown'));
  });

  it('Cloudflare reports zone-level attachment and leaves actions unreported when rules are not listed', async () => {
    const withRules = await pollCloudflare({
      prefetchedMetadata: {
        zones: [{
          id: 'z1',
          name: 'example.com',
          rulesets: [
            { phase: 'http_request_firewall_custom', rules: [{ action: 'block' }, { action: 'skip' }, { action: 'log' }, { action: 'block', enabled: false }] },
            { phase: 'http_request_transform', rules: [{ action: 'rewrite' }] },
          ],
        }],
      },
      observedAt: FRESH,
    });
    const config = withRules.snapshots[0].protection_config;
    assert.equal(config.attachment_level, 'zone');
    assert.deepEqual(config.action_counts, { block: 1, challenge: 0, monitor: 1, bypass: 1, disabled: 1, delegated: 0, unknown: 0 });
    assert.equal(config.exclusion_count, 1);
    assert.equal(cloudflareRuleActionCategory({ action: 'managed_challenge' }), 'challenge');
    const noRules = await pollCloudflare({ prefetchedMetadata: { zones: [{ id: 'z2', name: 'example.org', rulesets: [{ phase: 'http_request_firewall_managed' }] }] }, observedAt: FRESH });
    assert.equal(noRules.snapshots[0].protection_config.action_counts, null);
  });
});

describe('normalized configuration records', () => {
  it('maps a legacy snapshot with no generic fields to explicit not_reported states and never treats aggregate block as full coverage', () => {
    const record = normalizeConfigurationSnapshot(snapshot({ protection_config: null }), { now: NOW });
    assert.equal(record.enforcement.coverage, 'unknown');
    assert.equal(record.enforcement.aggregate_mode, 'block');
    assert.equal(record.field_states.enforcement_actions, 'not_reported');
    assert.equal(record.field_states.attachment_paths, 'not_reported');
    assert.equal(record.field_states.attachment_scope, 'reported');
    assert.equal(record.field_states.observation_time, 'reported');
    assert.ok(record.markers.includes('policy_level_aggregate_only'));
    assert.ok(record.markers.includes('enforcement_actions_not_reported'));
  });

  it('classifies coverage from enforcement units only, ignoring bypass exceptions', () => {
    const counts = (o) => ({ block: 0, challenge: 0, monitor: 0, bypass: 0, disabled: 0, delegated: 0, unknown: 0, ...o });
    assert.equal(classifyEnforcementCoverage(counts({ block: 2, bypass: 3 })).coverage, 'all_units_enforcing');
    assert.equal(classifyEnforcementCoverage(counts({ block: 1, monitor: 4 })).coverage, 'some_units_enforcing');
    assert.equal(classifyEnforcementCoverage(counts({ monitor: 2 })).coverage, 'monitor_only');
    assert.equal(classifyEnforcementCoverage(counts({ disabled: 2 })).coverage, 'disabled');
    assert.equal(classifyEnforcementCoverage(counts({ monitor: 1, disabled: 1 })).coverage, 'no_enforcing_units');
    assert.equal(classifyEnforcementCoverage(counts({ monitor: 1, delegated: 1 })).coverage, 'unknown');
    assert.equal(classifyEnforcementCoverage(counts({ bypass: 2 })).coverage, 'unknown');
    assert.equal(classifyEnforcementCoverage(null).coverage, 'unknown');
  });

  it('marks unsupported fields, permission gaps, incomplete inventory, stale snapshots, and unknown observation time', () => {
    const record = normalizeConfigurationSnapshot(snapshot({
      observed_at: 'not-a-time',
      inventory_complete: false,
      summary: { permission_gaps: ['rulesets:z1'] },
      protection_config: buildProtectionConfig({ attachmentLevel: 'hostname', unsupportedFields: ['path_exclusions', 'method_exclusions'] }),
    }), { now: NOW });
    for (const marker of ['unsupported_field', 'incomplete_inventory', 'missing_permission', 'stale_snapshot', 'unknown_observation_time']) {
      assert.ok(record.markers.includes(marker), marker);
    }
    assert.equal(record.field_states.path_exclusions, 'unsupported');
    assert.equal(record.field_states.enforcement_actions, 'permission_missing');
    assert.equal(record.field_states.observation_time, 'not_reported');
    const old = normalizeConfigurationSnapshot(snapshot({ observed_at: '2026-10-01T00:00:00.000Z' }), { now: NOW });
    assert.equal(old.freshness.stale, true);
  });

  it('keeps provider identity and evidence source separate from any conclusion', () => {
    const record = normalizeConfigurationSnapshot(snapshot({ evidence_source: 'manual_metadata', provider: 'custom_vendor' }), { now: NOW });
    assert.equal(record.provider_label, 'custom_vendor');
    assert.equal(record.evidence.source, 'manual_metadata');
    assert.equal(record.evidence.role, 'explanation_only');
    assert.equal(record.evidence.signed_external_result, false);
    const forged = normalizeConfigurationSnapshot(snapshot({ evidence_source: 'signed_external' }), { now: NOW });
    assert.equal(forged.evidence.source, 'manual_metadata');
    assert.equal(normalizeConfigurationSnapshot(snapshot({ snapshot_kind: 'dns_record' }), { now: NOW }), null);
  });
});

describe('scope matching preserves partial attachment', () => {
  it('a hostname attachment does not imply every path is covered', () => {
    const record = normalizeConfigurationSnapshot(snapshot(), { now: NOW });
    const match = matchConfigurationScope(record, normalizeConfigurationScope({ url: 'https://app.example.com/api/login' }));
    assert.equal(match.attachment_match, 'hostname_only');
    assert.ok(match.markers.includes('attachment_hostname_only'));
  });

  it('distinguishes included, excluded, and uncovered paths plus method exclusions', () => {
    const include = normalizeConfigurationSnapshot(snapshot({ protection_config: buildProtectionConfig({ attachmentLevel: 'hostname', attachmentPaths: ['/app/*'], pathMatch: 'include', exclusionMethods: ['POST'], exclusionPaths: ['/app/health'] }) }), { now: NOW });
    assert.equal(matchConfigurationScope(include, { hostname: 'app.example.com', path: '/app/x', method: 'GET' }).attachment_match, 'hostname_and_path');
    const uncovered = matchConfigurationScope(include, { hostname: 'app.example.com', path: '/api/login', method: 'POST' });
    assert.equal(uncovered.attachment_match, 'path_not_in_attachment');
    assert.ok(uncovered.markers.includes('method_excluded'));
    assert.ok(matchConfigurationScope(include, { hostname: 'app.example.com', path: '/app/health', method: 'GET' }).markers.includes('path_excluded'));
    const exclude = normalizeConfigurationSnapshot(snapshot({ protection_config: buildProtectionConfig({ attachmentLevel: 'hostname', attachmentPaths: ['/api/*'], pathMatch: 'exclude' }) }), { now: NOW });
    assert.equal(matchConfigurationScope(exclude, { hostname: 'app.example.com', path: '/api/login', method: null }).attachment_match, 'path_excluded');
    assert.equal(matchConfigurationScope(exclude, { hostname: 'other.example.com', path: '/', method: null }).attachment_match, 'not_attached');
  });

  it('zone-level and wildcard attachments stay weaker than an exact hostname match', () => {
    const zone = normalizeConfigurationSnapshot(snapshot({ provider: 'cloudflare', snapshot_kind: 'dns_zone', summary: { hostnames: ['example.com'] }, protection_config: buildProtectionConfig({ attachmentLevel: 'zone' }) }), { now: NOW });
    assert.equal(matchConfigurationScope(zone, { hostname: 'app.example.com', path: '/', method: null }).attachment_match, 'zone_only');
    assert.equal(matchConfigurationScope(zone, { hostname: 'example.com', path: '/', method: null }).attachment_match, 'zone_only');
    assert.equal(matchConfigurationScope(zone, { hostname: 'example.org', path: '/', method: null }).attachment_match, 'not_attached');
    const wildcard = normalizeConfigurationSnapshot(snapshot({ summary: { hostnames: ['*.example.com'] } }), { now: NOW });
    assert.equal(matchConfigurationScope(wildcard, { hostname: 'app.example.com', path: null, method: null }).attachment_match, 'hostname_only');
    assert.equal(matchConfigurationScope(wildcard, { hostname: 'example.com', path: null, method: null }).attachment_match, 'not_attached');
    assert.equal(pathPatternMatches('/a.b/*', '/aXb/c'), false);
  });
});

describe('configuration context', () => {
  it('with connectors disabled ignores every snapshot and reports unknown, not unprotected', () => {
    const ctx = context([snapshot()], undefined, { connectorsEnabled: false });
    assert.equal(ctx.status, 'connectors_disabled');
    assert.deepEqual(ctx.records, []);
    assert.equal(ctx.absence_means, CONFIG_ABSENCE_MEANING);
    assert.equal(ctx.behavior_conclusion, null);
    for (const layer of Object.values(ctx.layers)) {
      assert.equal(layer.absence_means, 'unknown');
      assert.equal(layer.coverage, 'unknown');
    }
    assert.doesNotMatch(JSON.stringify(ctx), NEGATIVE_PROTECTION_WORDING);
  });

  it('configuration absence never means no protection', () => {
    for (const snaps of [[], undefined, [snapshot({ summary: { hostnames: ['elsewhere.example.net'] } })]]) {
      const ctx = context(snaps);
      assert.equal(ctx.status, 'no_configuration_evidence');
      assert.equal(ctx.absence_means, 'unknown');
      assert.ok(ctx.markers.includes('no_configuration_evidence'));
      assert.equal(ctx.layers.waf.coverage, 'unknown');
      assert.doesNotMatch(JSON.stringify(ctx), NEGATIVE_PROTECTION_WORDING);
    }
  });

  it('flags conflicting configuration and ambiguous ordering across matching records', () => {
    const ctx = context([
      snapshot(),
      snapshot({ id: 'snap_2', resource_ref_hash: 'ref_2', summary: { policy_mode: 'monitor' }, protection_config: buildProtectionConfig({ actions: ['monitor'], attachmentLevel: 'hostname' }) }),
    ]);
    assert.ok(ctx.layers.waf.markers.includes('conflicting_configuration'));
    assert.ok(ctx.layers.waf.markers.includes('ambiguous_ordering'));
    assert.equal(ctx.layers.waf.coverage, 'conflicting');
    assert.ok(ctx.markers.includes('conflicting_configuration'));
  });

  it('uses only the latest snapshot per resource so history is not treated as a conflict', () => {
    const ctx = context([
      snapshot({ id: 'old', observed_at: '2026-10-06T01:00:00.000Z', protection_config: buildProtectionConfig({ actions: ['monitor'], attachmentLevel: 'hostname' }) }),
      snapshot({ id: 'new' }),
    ]);
    assert.equal(ctx.records.length, 1);
    assert.equal(ctx.records[0].evidence.snapshot_id, 'new');
    assert.equal(ctx.layers.waf.markers.includes('conflicting_configuration'), false);
  });

  it('surfaces connector-level permission and inventory gaps and unscoped resource attachments', () => {
    const ctx = context(
      [snapshot(), snapshot({ id: 'acl', resource_ref_hash: 'acl', provider: 'aws_waf', summary: { hostnames: [] }, protection_config: buildProtectionConfig({ attachmentLevel: 'resource' }) })],
      undefined,
      { connectorHealth: [{ status: 'degraded', permission_gaps: ['get_webacl:1'], inventory_complete: false, inventory_truncated: true }] },
    );
    assert.equal(ctx.unscoped_record_count, 1);
    for (const marker of ['missing_permission', 'incomplete_inventory', 'attachment_scope_unknown']) assert.ok(ctx.markers.includes(marker), marker);
  });

  it('does not enumerate configured hostnames, authorize execution, or carry destination keys', () => {
    const ctx = context([snapshot({ summary: { hostnames: ['app.example.com', 'hidden-admin.example.com'] } })]);
    assert.equal(ctx.authorizes_execution, false);
    assert.equal(ctx.upgrades_observed_behavior, false);
    assert.equal(findBannedScopeKey(ctx), null);
    assert.doesNotMatch(JSON.stringify(ctx), /hidden-admin/);
    assert.equal(ctx.records[0].attachment_hostname_count, 2);
    assert.ok(ctx.markers.every((marker) => CONFIG_ENRICHMENT_MARKERS.includes(marker)));
  });
});

describe('explanations never change external results', () => {
  const monitorCtx = () => context([snapshot({ protection_config: buildProtectionConfig({ actions: ['monitor', 'monitor'], attachmentLevel: 'hostname' }) })]);
  const enforcingCtx = () => context([snapshot()]);

  it('attaches candidate explanations beside items while the evaluation digest still verifies', () => {
    const rel = relation();
    const items = [
      classifyPathValidationItem({ relation: rel, primaryBaselineHealth: 'healthy', primaryEnforcement: 'enforced', observation: 'response_observed', enforcement: 'not_enforced' }),
      classifyPathValidationItem({ relation: rel }),
    ];
    const evaluation = deepFreeze(pathEvaluation(items));
    const before = structuredClone(evaluation);
    const projected = attachConfigurationExplanations(evaluation, { ep_1: monitorCtx(), ep_2: monitorCtx() });
    assert.deepEqual(evaluation, before);
    assert.deepEqual(projected.items, evaluation.items);
    assert.equal(comparisonEvaluationDigest(projected), evaluation.evaluation_digest);
    const [gap, untested] = projected.configuration_explanations.items;
    assert.equal(gap.status, 'suspected_alternate_application_route');
    assert.equal(gap.status_changed, false);
    assert.deepEqual(gap.candidate_explanations.map((c) => c.code), ['configuration_reports_monitor_mode']);
    assert.ok(gap.candidate_explanations.every((c) => c.corroborated === false && CONFIG_CANDIDATE_EXPLANATIONS.includes(c.code)));
    assert.equal(gap.candidate_explanations[0].evidence_source, 'provider_api');
    assert.equal(gap.candidate_explanations[0].provider_label, 'akamai_appsec');
    assert.equal(untested.status, 'not_tested');
    assert.deepEqual(untested.candidate_explanations, []);
    assert.ok(untested.notes.includes('untested_behavior_not_inferred'));
  });

  it('config evidence cannot upgrade untested, skipped, or inconclusive behaviour', () => {
    for (const outcome of ['not_tested', 'skipped', 'inconclusive']) {
      const explanation = explainComparisonItem('path_validation', { entry_path_id: 'ep_1', outcome }, enforcingCtx());
      assert.equal(explanation.status, outcome);
      assert.equal(explanation.behavior_inference, 'none');
      assert.deepEqual(explanation.candidate_explanations, []);
    }
    const row = emptyProtectionMatrixRow(relation());
    const enriched = attachConfigurationToMatrixRow(row, enforcingCtx());
    assert.equal(enriched.outcome, row.outcome);
    for (const [index, layer] of enriched.layers.entries()) {
      for (const dimension of LAYER_EVIDENCE_DIMENSIONS) assert.deepEqual(layer[dimension], row.layers[index][dimension], dimension);
      assert.equal(layer.attribution, row.layers[index].attribution);
      assert.equal(layer.configuration.evidence_role, 'explanation_only');
    }
    assert.equal(enriched.layers.find((l) => l.layer === 'waf').observed_enforcement, 'not_tested');
    assert.equal(enriched.layers.find((l) => l.layer === 'waf').vendor_detection, 'unknown');
  });

  it('flags disagreement instead of overriding behaviour in either direction', () => {
    const gap = explainComparisonItem('path_validation', { entry_path_id: 'ep_1', outcome: 'scoped_application_bypass', evidence_refs: [ref()] }, enforcingCtx());
    assert.equal(gap.status, 'scoped_application_bypass');
    assert.deepEqual(gap.candidate_explanations.map((c) => c.code), ['configuration_and_behavior_disagree']);
    const consistent = explainComparisonItem('path_validation', { entry_path_id: 'ep_1', outcome: 'consistent_enforcement', evidence_refs: [ref()] }, monitorCtx());
    assert.equal(consistent.status, 'consistent_enforcement');
    assert.deepEqual(consistent.candidate_explanations.map((c) => c.code), ['configuration_and_behavior_disagree']);
  });

  it('explains uncovered paths and partial units, and marks misaligned configuration time', () => {
    const ctx = context([snapshot({
      observed_at: '2026-10-06T11:00:00.000Z',
      protection_config: buildProtectionConfig({ actions: ['block', 'monitor'], attachmentLevel: 'hostname', attachmentPaths: ['/app/*'] }),
    })]);
    const explanation = explainComparisonItem('path_validation', {
      entry_path_id: 'ep_1',
      outcome: 'weaker_observed_enforcement',
      evidence_refs: [ref({ observed_at: '2026-10-01T00:00:00.000Z' })],
    }, ctx);
    assert.deepEqual(explanation.candidate_explanations.map((c) => c.code), [
      'configuration_attachment_excludes_path',
      'configuration_reports_partial_enforcing_units',
    ]);
    assert.ok(explanation.candidate_explanations.every((c) => c.time_alignment === 'misaligned'));
    assert.ok(explanation.markers.includes('configuration_time_misaligned'));
  });

  it('firewall comparisons keep status and note that WAF configuration does not cover the firewall layer', () => {
    const expectation = normalizeFirewallExpectation({
      destination_target_id: 'tgt_fw', protocol: 'tcp', port: 8080, expected: 'deny', source_perspective: 'public-worker-eu', change_id: 'CHG-1',
    }, { tenantId: TENANT });
    const item = classifyFirewallComparisonItem({ expectation, baseline: ['explicit_denial_observed'], candidate: ['service_response_observed', 'service_response_observed'], compatibility: { comparable: true, stale: false, reasons: [] } });
    const [explanation] = explainComparisonItems('firewall_change', [{ ...item, expectation_id: 'fwx_1' }], new Map([['fwx_1', enforcingCtx()]]));
    assert.equal(explanation.status, item.status);
    assert.equal(explanation.item_index, 0);
    assert.equal(explanation.expectation_id, 'fwx_1');
    assert.deepEqual(explanation.candidate_explanations, []);
    assert.ok(explanation.notes.includes('configuration_layer_not_covered'));
  });

  it('the full workflow runs with connectors disabled and leaves every status intact', () => {
    const rel = relation({ relation_kind: 'declared_api_url', required_layers: ['waf'] });
    const items = [
      classifyPathValidationItem({ relation: rel, primaryBaselineHealth: 'healthy', primaryEnforcement: 'enforced', observation: 'explicit_denial_observed', enforcement: 'enforced' }),
      classifyPathValidationItem({ relation: rel, skipped: true }),
    ];
    const evaluation = pathEvaluation(items);
    const disabled = buildConfigurationContext({ scope: { url: 'https://api.example.com/v1' }, snapshots: [snapshot()], connectorsEnabled: false });
    const projected = attachConfigurationExplanations(evaluation, { ep_1: disabled, ep_2: disabled });
    assert.equal(projected.summary.accepted, evaluation.summary.accepted);
    assert.deepEqual(projected.configuration_explanations.items.map((e) => e.status), evaluation.items.map((i) => i.outcome));
    for (const explanation of projected.configuration_explanations.items) {
      assert.ok(explanation.notes.includes('connectors_disabled'));
      assert.deepEqual(explanation.candidate_explanations, []);
      assert.equal(explanation.absence_means, 'unknown');
    }
    const noContext = attachConfigurationExplanations(evaluation, null);
    assert.ok(noContext.configuration_explanations.items.every((e) => e.notes.includes('no_configuration_evidence')));
    assert.throws(() => explainComparisonItem('unknown_kind', {}, null), { code: 'invalid_comparison_evaluation' });
  });
});
