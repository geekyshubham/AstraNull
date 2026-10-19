import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  CHECK_CATEGORIES,
  MISC_CATEGORY_ID,
  categorizeCheckGroups,
  checkCategoryId,
  countCompatibleSafeChecks,
  evidenceCapabilityCopy,
  groupVectorsByCheck,
  latestRunForCheckOnTarget,
  preferredRunnableCheck,
  searchAndFilterVectors,
  sortVectorsByTargetFit,
  vectorTargetAvailability,
} from '../../apps/web/react/src/lib/vector-library.mjs';

const fqdn = { id: 'tgt_exact', kind: 'fqdn', value: 'example.test' };
const safeCheck = {
  check_id: 'l7.rate.safe',
  name: 'Rate-limit behavior',
  safety_class: 'safe',
  supported_targets: ['fqdn'],
};
const urlCheck = {
  check_id: 'l7.route.safe',
  name: 'Route behavior',
  safety_class: 'safe',
  supported_targets: ['url'],
};

function vector(overrides = {}) {
  return {
    vector_id: 'APP-001',
    canonical_name: 'HTTP GET flood',
    section: 'L7 DDoS',
    family: 'Request flood',
    protocol_service: 'HTTP/S',
    intended_detection_goal: 'Intent only: assess rate-limit evidence. This is not an observed result.',
    failure_means: 'No throttle was observed within declared bounds.',
    expected_controls: 'Per-route rate limiting',
    evidence_capability: 'semantic_safe',
    execution_disposition: 'safe_validation_available',
    safe_check_ids: ['l7.rate.safe'],
    semantic_safe_check_ids: ['l7.rate.safe'],
    ...overrides,
  };
}

describe('portal vector-library truth and target selection', () => {
  it('keeps E1 and E2 labels explicitly below semantic proof', () => {
    assert.match(evidenceCapabilityCopy('declaration_only').detail, /does not prove exposure/i);
    assert.match(evidenceCapabilityCopy('transport_only').detail, /does not prove semantic susceptibility/i);
    assert.match(evidenceCapabilityCopy('soc_governed').detail, /only an authorized governed workflow/i);
    assert.match(evidenceCapabilityCopy('monitor_only').detail, /no active outside-in result/i);
  });

  it('requires an exact target before exposing compatible safe checks', () => {
    assert.equal(vectorTargetAvailability(vector(), [safeCheck], null).id, 'select_target');
    const available = vectorTargetAvailability(vector(), [safeCheck], fqdn);
    assert.equal(available.id, 'safe_runnable');
    assert.deepEqual(available.runnableChecks, [safeCheck]);
    assert.equal(preferredRunnableCheck(vector(), available), safeCheck);
  });

  it('never assigns semantic preference to declaration-only or transport-only rows', () => {
    for (const capability of ['declaration_only', 'transport_only']) {
      const nonSemantic = vector({ evidence_capability: capability, semantic_safe_check_ids: [] });
      const available = vectorTargetAvailability(nonSemantic, [safeCheck], fqdn);
      assert.equal(available.id, 'safe_runnable');
      assert.equal(preferredRunnableCheck(nonSemantic, available), null, capability);
    }
  });

  it('never turns SOC or monitor vectors into customer-runnable checks', () => {
    assert.equal(vectorTargetAvailability(vector({ execution_disposition: 'soc_gated_only' }), [safeCheck], fqdn).id, 'soc_gated');
    assert.equal(vectorTargetAvailability(vector({ execution_disposition: 'monitor_only' }), [safeCheck], fqdn).id, 'monitor_only');
  });

  it('separates unsupported targets from hidden additional-input checks and filters all 721-style fields', () => {
    assert.equal(vectorTargetAvailability(vector({ safe_check_ids: ['l7.route.safe'] }), [urlCheck], fqdn).id, 'target_not_supported');
    assert.equal(vectorTargetAvailability(vector({ safe_check_ids: ['l7.hidden.safe'] }), [safeCheck], fqdn).id, 'additional_input');
    const rows = [vector(), vector({ vector_id: 'APP-002', canonical_name: 'TLS request pressure', expected_controls: 'Connection budgets' })];
    assert.deepEqual(searchAndFilterVectors(rows, { query: 'connection budgets' }).map((row) => row.vector_id), ['APP-002']);
    assert.deepEqual(searchAndFilterVectors(rows, { targetAvailability: 'safe_runnable', checks: [safeCheck], target: fqdn }).map((row) => row.vector_id), ['APP-001', 'APP-002']);
  });

  it('counts distinct customer-safe compatible checks from server-shaped pairs with nested catalog identity', () => {
    const pairs = [
      { check_id: 'l7.rate.safe', mechanism: 'http_rate', state: 'not_run', launch_eligibility: 'blocked', catalog: { check_id: 'l7.rate.safe', safety_class: 'safe' } },
      { check_id: 'l7.rate.safe', mechanism: 'http_rate_alt', state: 'stale', catalog: { check_id: 'l7.rate.safe', safety_class: 'safe' } },
      { check_id: 'l7.route.safe', mechanism: 'route', catalog: null },
      { check_id: 'hs.volumetric.soc', mechanism: 'volumetric', catalog: { check_id: 'hs.volumetric.soc', safety_class: 'soc_gated' } },
      { check_id: '', catalog: { safety_class: 'safe' } },
    ];
    const socCheck = { check_id: 'hs.volumetric.soc', safety_class: 'soc_gated' };
    assert.equal(countCompatibleSafeChecks(pairs, [safeCheck, urlCheck, socCheck]), 2);
    assert.equal(countCompatibleSafeChecks(pairs, []), 1);
    assert.equal(countCompatibleSafeChecks([], [safeCheck]), 0);
    assert.equal(countCompatibleSafeChecks(undefined, undefined), 0);
  });

  it('orders vectors by fit for the chosen target and keeps catalog order within each fit', () => {
    const rows = [
      vector({ vector_id: 'SOC-1', execution_disposition: 'soc_gated_only' }),
      vector({ vector_id: 'MON-1', execution_disposition: 'monitor_only' }),
      vector({ vector_id: 'UNSUP-1', safe_check_ids: ['l7.route.safe'] }),
      vector({ vector_id: 'INPUT-1', safe_check_ids: ['l7.hidden.safe'] }),
      vector({ vector_id: 'RUN-1' }),
      vector({ vector_id: 'INPUT-2', safe_check_ids: ['l7.hidden.safe'] }),
      vector({ vector_id: 'RUN-2' }),
    ];
    const checks = [safeCheck, urlCheck];
    assert.deepEqual(
      sortVectorsByTargetFit(rows, checks, fqdn).map((row) => row.vector_id),
      ['RUN-1', 'RUN-2', 'INPUT-1', 'INPUT-2', 'UNSUP-1', 'MON-1', 'SOC-1'],
    );
    assert.deepEqual(sortVectorsByTargetFit(rows, checks, null).map((row) => row.vector_id), rows.map((row) => row.vector_id));
    assert.notEqual(sortVectorsByTargetFit(rows, checks, null), rows);
  });

  it('finds the latest run of a mapped check on the selected target only', () => {
    const runs = [
      { id: 'run_old', check_id: 'l7.rate.safe', target_id: 'tgt_exact', started_at: '2026-01-01T00:00:00Z', status: 'verdicted' },
      { id: 'run_other_target', check_id: 'l7.rate.safe', target_id: 'tgt_other', started_at: '2026-03-01T00:00:00Z' },
      { id: 'run_new', check_id: 'l7.rate.safe', target_id: 'tgt_exact', created_at: '2026-02-01T00:00:00Z', status: 'running' },
      { id: 'run_other_check', check_id: 'l7.route.safe', target_id: 'tgt_exact', started_at: '2026-04-01T00:00:00Z' },
    ];
    assert.equal(latestRunForCheckOnTarget(runs, 'l7.rate.safe', 'tgt_exact')?.id, 'run_new');
    assert.equal(latestRunForCheckOnTarget(runs, 'l7.rate.safe', 'tgt_missing'), null);
    assert.equal(latestRunForCheckOnTarget(runs, '', 'tgt_exact'), null);
  });
});

describe('check-first catalog grouping', () => {
  const checks = [
    { check_id: 'waf.sqli.safe', safety_class: 'safe', canonical_name: 'SQLi managed marker' },
    { check_id: 'waf.xss.safe', safety_class: 'safe', canonical_name: 'XSS managed marker' },
  ];
  it('never groups or offers declaration-only metadata as an executable check', () => {
    const declarations = [
      { check_id: 'e1', safety_class: 'safe', evidence_tier: 'E1', supported_targets: ['fqdn'] },
      { check_id: 'metadata', safety_class: 'safe', probe_profile: { kind: 'metadata_marker' }, supported_targets: ['fqdn'] },
    ];
    const vectors = declarations.map((check) => vector({ vector_id: check.check_id, safe_check_ids: [check.check_id] }));
    const grouped = groupVectorsByCheck(vectors, [...checks, ...declarations]);
    assert.deepEqual(grouped.groups, []);
    assert.equal(grouped.unmapped.length, 2);
    for (const entry of vectors) assert.deepEqual(vectorTargetAvailability(entry, declarations, fqdn).runnableChecks, []);
    assert.equal(countCompatibleSafeChecks(declarations.map((catalog) => ({ check_id: catalog.check_id, catalog })), declarations), 0);
  });
  it('nests vectors under the checks that cover them and buckets the rest as unmapped', () => {
    const vectors = [
      { vector_id: 'V1', safe_check_ids: ['waf.sqli.safe'] },
      { vector_id: 'V2', safe_check_ids: ['waf.sqli.safe'] },
      { vector_id: 'V3', mapped_check_ids: ['waf.xss.safe'] },
      { vector_id: 'V4', safe_check_ids: [] },
      { vector_id: 'V5', safe_check_ids: ['soc.only.gated'] },
    ];
    const { groups, unmapped } = groupVectorsByCheck(vectors, checks);
    assert.deepEqual(groups.map((group) => group.checkId), ['waf.sqli.safe', 'waf.xss.safe']);
    assert.deepEqual(groups[0].vectors.map((vector) => vector.vector_id), ['V1', 'V2']);
    assert.deepEqual(groups[1].vectors.map((vector) => vector.vector_id), ['V3']);
    assert.deepEqual(unmapped.map((vector) => vector.vector_id), ['V4', 'V5']);
  });
  it('lists a vector under every covering check without inventing checks', () => {
    const { groups } = groupVectorsByCheck([{ vector_id: 'V1', safe_check_ids: ['waf.sqli.safe', 'waf.xss.safe'] }], checks);
    assert.deepEqual(groups.flatMap((group) => group.vectors.map((vector) => vector.vector_id)), ['V1', 'V1']);
  });
});

describe('check library categories', () => {
  const group = (checkId, family) => ({ checkId, check: { check_id: checkId, vector_family: family }, vectors: [] });
  const groups = [
    group('waf.a', 'waf'),
    group('waf.b', 'waf'),
    group('dns.a', 'dns'),
    group('refl.a', 'reflection'),
    group('amp.a', 'amplification'),
    group('path.a', 'path'),
    group('odd.a', 'brand_new_family'),
  ];
  const unmapped = [{ vector_id: 'V9' }, { vector_id: 'V10' }];

  it('maps catalog vector families onto the chip categories and unknown families to miscellaneous', () => {
    assert.equal(checkCategoryId({ vector_family: 'WAF' }), 'waf');
    assert.equal(checkCategoryId({ vector_family: 'amplification' }), 'reflection');
    assert.equal(checkCategoryId({ vector_family: 'high_scale' }), 'operations');
    assert.equal(checkCategoryId({ vector_family: 'tls' }), 'protocol');
    assert.equal(checkCategoryId({ vector_family: 'brand_new_family' }), MISC_CATEGORY_ID);
    assert.equal(checkCategoryId(null), MISC_CATEGORY_ID);
    const families = CHECK_CATEGORIES.flatMap((entry) => entry.families);
    assert.equal(new Set(families).size, families.length);
  });

  it('counts check groups per category and folds unmapped vectors into miscellaneous', () => {
    const { counts, groups: all, unmapped: allUnmapped } = categorizeCheckGroups(groups, unmapped);
    assert.equal(counts.all, 7);
    assert.equal(counts.waf, 2);
    assert.equal(counts.reflection, 2);
    assert.equal(counts.origin, 1);
    assert.equal(counts.l7, 0);
    assert.equal(counts[MISC_CATEGORY_ID], 3);
    assert.equal(all.length, 7);
    assert.equal(allUnmapped.length, 2);
  });

  it('filters to one category and only keeps unmapped vectors for all or miscellaneous', () => {
    const waf = categorizeCheckGroups(groups, unmapped, 'waf');
    assert.deepEqual(waf.groups.map((entry) => entry.checkId), ['waf.a', 'waf.b']);
    assert.deepEqual(waf.unmapped, []);
    assert.equal(waf.counts.waf, 2);
    const misc = categorizeCheckGroups(groups, unmapped, MISC_CATEGORY_ID);
    assert.deepEqual(misc.groups.map((entry) => entry.checkId), ['odd.a']);
    assert.equal(misc.unmapped.length, 2);
  });
});

describe('check library mapped-check run truth', () => {
  it('labels a mapped check with a verdict only when the run has an evidence-backed published verdict', () => {
    const source = readFileSync(new URL('../../apps/web/react/src/pages/vector-library-page.tsx', import.meta.url), 'utf8');
    const component = source.slice(source.indexOf('function MappedCheckLatestRun'), source.indexOf('export function VectorLibraryPage'));
    assert.match(component, /hasEvidenceBackedVerdict\(run, evidence\) \? publishedRunVerdict\(run\) : ''/);
    assert.doesNotMatch(component, /run\.verdict as DataItem/);
    assert.match(source, /<MappedCheckLatestRun run=\{latestRun\} evidence=\{data\.evidence\} \/>/);
  });
});
