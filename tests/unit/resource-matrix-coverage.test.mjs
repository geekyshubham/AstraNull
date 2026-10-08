import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  RESOURCE_EVIDENCE_FRESHNESS_MS,
  RESOURCE_FAMILIES,
  applicableResourceFamilyCheckIds,
  resourceFamilyCheckIds,
  resourceFamilyVerdictState,
  resourceMatrixTargets,
} from '../../apps/web/react/src/lib/resource-matrix.mjs';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { EXHAUSTED_RESOURCE_FAMILIES } from '../../src/contracts/resourceExhaustionTaxonomy.mjs';

const NOW = Date.parse('2026-07-15T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const CHECK_A = 'l3.icmp_flood.readiness';
const CHECK_B = 'l3.forbidden_udp_port.safe';

function iso(millisecondsAgo = 0) {
  return new Date(NOW - millisecondsAgo).toISOString();
}

function storedRun({
  id = 'run_1',
  checkId = CHECK_A,
  targetId = 'tgt_1',
  verdict = 'protected',
  at = iso(DAY),
  status = 'completed',
} = {}) {
  return {
    id,
    check_id: checkId,
    target_id: targetId,
    status,
    completed_at: at,
    verdict: {
      test_run_id: id,
      check_id: checkId,
      target_id: targetId,
      verdict,
      evidence_ids: [`evt_${id}`],
      created_at: at,
    },
  };
}

function state({ checkIds = new Set([CHECK_A]), runs = [], evidence = [], targetId = 'tgt_1' } = {}) {
  return resourceFamilyVerdictState({ checkIds, targetId, runs, evidence, nowMs: NOW });
}

describe('resource-exhaustion matrix (DET-024)', () => {
  it('projects every authoritative exhausted-resource family in contract order', () => {
    assert.equal(RESOURCE_FAMILIES.length, 17);
    assert.deepEqual(
      RESOURCE_FAMILIES.map((family) => ({
        id: family.id,
        label: family.label,
        metric: family.metric,
        layer: family.layer,
        scored_for_ddos_readiness: family.scoredForDdosReadiness,
      })),
      EXHAUSTED_RESOURCE_FAMILIES.map((family) => ({
        id: family.id,
        label: family.label,
        metric: family.metric,
        layer: family.layer,
        scored_for_ddos_readiness: family.scored_for_ddos_readiness,
      })),
    );
    assert.equal(RESOURCE_FAMILIES[0].id, 'volumetric');
    assert.equal(RESOURCE_FAMILIES.at(-1).id, 'ai_agentic');
    for (const family of RESOURCE_FAMILIES) {
      assert.ok(family.description.length > 0, family.id);
      assert.equal(
        family.visualization,
        family.scoredForDdosReadiness ? 'readiness_posture' : 'validation_coverage',
        family.id,
      );
    }
  });

  it('classifies every shipped catalog check in every declared exhausted-resource family', () => {
    const apiRows = CHECK_CATALOG.map((check) => ({
      check_id: check.check_id,
      exhausted_resource: check.exhausted_resource,
      exhausted_resources: check.exhausted_resources,
    }));
    assert.ok(resourceFamilyCheckIds(apiRows, { id: 'volumetric' }).has(CHECK_A));
    assert.ok(resourceFamilyCheckIds(apiRows, { id: 'volumetric' }).has(CHECK_B));
    assert.ok(resourceFamilyCheckIds(apiRows, { id: 'reflection' }).has('reflect.ssdp_exposure.safe'));
    assert.ok(resourceFamilyCheckIds(apiRows, { id: 'backend_exhaustion' }).has('l7.graphql_complexity.safe'));

    const declaredFamilies = new Set(RESOURCE_FAMILIES.map((family) => family.id));
    const shippedFamilies = new Set(apiRows.flatMap((row) => row.exhausted_resources));
    assert.deepEqual(shippedFamilies, declaredFamilies, 'the matrix must not truncate shipped families');

    for (const family of RESOURCE_FAMILIES) {
      assert.ok(resourceFamilyCheckIds(apiRows, family).size > 0, `no shipped checks represented for ${family.id}`);
    }
    for (const row of apiRows) {
      const expected = new Set(row.exhausted_resources.length > 0
        ? row.exhausted_resources
        : row.exhausted_resource ? [row.exhausted_resource] : []);
      const represented = new Set(
        RESOURCE_FAMILIES
          .filter((family) => resourceFamilyCheckIds(apiRows, family).has(row.check_id))
          .map((family) => family.id),
      );
      assert.deepEqual(represented, expected, `${row.check_id} family membership drift`);
    }
  });

  it('matches every plural exhausted-resource family, with plural precedence and singular fallback', () => {
    const checks = [
      {
        check_id: 'multi',
        exhausted_resources: ['volumetric', 'delivery_pattern'],
        exhausted_resource: 'dns_exhaustion',
        supported_targets: ['fqdn'],
      },
      { check_id: 'legacy', exhausted_resource: 'dns_exhaustion', supported_targets: ['fqdn'] },
    ];
    assert.ok(resourceFamilyCheckIds(checks, { id: 'volumetric' }).has('multi'));
    assert.ok(resourceFamilyCheckIds(checks, { id: 'delivery_pattern' }).has('multi'));
    assert.equal(resourceFamilyCheckIds(checks, { id: 'dns_exhaustion' }).has('multi'), false);
    assert.ok(resourceFamilyCheckIds(checks, { id: 'dns_exhaustion' }).has('legacy'));

    const targets = [{ target_id: 'tgt_1', kind: 'fqdn' }];
    assert.ok(applicableResourceFamilyCheckIds({
      checks, family: { id: 'delivery_pattern' }, targetId: 'tgt_1', targets,
    }).has('multi'));
  });

  it('renders every active target group without a five-column cap', () => {
    const groups = Array.from({ length: 8 }, (_, index) => ({ id: `tgt_${index + 1}` }));
    groups.push({ id: 'tg_archived', archived_at: iso() });
    groups.push({ id: 'tg_deleted', deleted_at: iso() });
    assert.deepEqual(resourceMatrixTargets(groups).map((group) => group.id), [
      'tgt_1', 'tgt_2', 'tgt_3', 'tgt_4', 'tgt_5', 'tgt_6', 'tgt_7', 'tgt_8',
    ]);
  });

  it('derives target-kind applicability and never infers it from unavailable inventory', () => {
    const family = { id: 'volumetric' };
    const checks = [
      { check_id: CHECK_A, exhausted_resource: 'volumetric', supported_targets: ['fqdn'] },
      { check_id: CHECK_B, exhausted_resource: 'volumetric', supported_targets: ['url'] },
      { check_id: 'generic', exhausted_resource: 'volumetric' },
      { check_id: 'dns', exhausted_resource: 'dns_exhaustion', supported_targets: ['hostname'] },
    ];
    const targets = [
      { target_id: 'tgt_1', kind: 'url' },
      { target_id: 'tg_other', kind: 'fqdn' },
    ];

    assert.deepEqual(
      [...applicableResourceFamilyCheckIds({ checks, family, targetId: 'tgt_1', targets })].sort(),
      [CHECK_B, 'generic'].sort(),
    );
    assert.equal(
      applicableResourceFamilyCheckIds({ checks, family, targetId: 'tg_empty', targets }).size,
      0,
    );
    assert.deepEqual(
      [...applicableResourceFamilyCheckIds({
        checks,
        family,
        targetId: 'tgt_1',
        targets: [],
        targetInventoryLoaded: false,
      })].sort(),
      [CHECK_A, CHECK_B, 'generic'].sort(),
    );
  });

  it('distinguishes all six user-facing states', () => {
    assert.equal(state({ checkIds: new Set() }).status, 'not_applicable');
    assert.equal(state().status, 'not_run');
    assert.equal(state({ runs: [storedRun()] }).status, 'protected');
    assert.equal(state({ runs: [storedRun({ verdict: 'allowed_as_expected' })] }).status, 'protected');
    assert.equal(state({ runs: [storedRun({ verdict: 'failed' })] }).status, 'exposed');
    assert.equal(state({ runs: [storedRun({ verdict: 'unknown_result' })] }).status, 'inconclusive');
    assert.equal(state({ runs: [storedRun({ at: iso(31 * DAY) })] }).status, 'stale');
  });

  it('does not treat policy, lifecycle activity, or an unbound verdict as coverage', () => {
    // Policies are intentionally not accepted by the verdict helper at all.
    assert.equal(state({ runs: [{ id: 'run_1', check_id: CHECK_A, target_id: 'tgt_1' }] }).status, 'not_run');
    assert.equal(state({ runs: [storedRun({ status: 'running' })] }).status, 'not_run');
    assert.equal(state({ runs: [{
      id: 'run_1', check_id: CHECK_A, target_id: 'tgt_1', status: 'completed',
      verdict: 'protected', completed_at: iso(),
    }] }).status, 'not_run');
    assert.equal(state({ runs: [{
      ...storedRun(),
      verdict: { test_run_id: 'run_other', check_id: CHECK_A, verdict: 'protected', evidence_ids: ['evt_1'] },
    }] }).status, 'not_run');
    assert.equal(state({ runs: [{
      ...storedRun(),
      verdict: { test_run_id: 'run_1', check_id: CHECK_A, verdict: 'protected', evidence_ids: [] },
    }] }).status, 'not_run');
  });

  it('keeps an edge-only persisted detail verdict reviewable and accepts evidence-bound legacy strings', () => {
    assert.equal(state({ runs: [{
      id: 'run_nested',
      check: { check_id: CHECK_A },
      target: { id: 'tgt_1' },
      target_id: 'tgt_1',
      status: 'verdicted',
      verdict: {
        test_run_id: 'run_nested',
        check_id: CHECK_A,
        target_id: 'tgt_1',
        status: 'edge_protected',
        evidence_ids: ['evt_nested'],
        verdict_at: iso(),
      },
    }] }).status, 'inconclusive');

    const legacyRun = {
      id: 'run_legacy', check_id: CHECK_A, target_id: 'tgt_1', status: 'completed',
      verdict: 'edge_exposed', completed_at: iso(),
    };
    assert.equal(state({
      runs: [legacyRun],
      evidence: [{ test_run_id: 'run_legacy', observed_at: iso() }],
    }).status, 'exposed');
    assert.equal(state({
      runs: [legacyRun],
      evidence: [{ test_run_id: 'run_other', check_id: CHECK_A, target_id: 'tgt_1' }],
    }).status, 'not_run');
  });

  it('keeps other checks and target groups from leaking into a cell', () => {
    const runs = [
      storedRun({ id: 'wrong_check', checkId: CHECK_B, verdict: 'failed' }),
      storedRun({ id: 'wrong_group', targetId: 'tg_2', verdict: 'failed' }),
    ];
    assert.equal(state({ runs }).status, 'not_run');
  });

  it('uses the latest outcome per check and the backend-aligned 30-day freshness boundary', () => {
    assert.equal(RESOURCE_EVIDENCE_FRESHNESS_MS, 30 * DAY);
    assert.equal(state({ runs: [storedRun({ at: iso(30 * DAY) })] }).status, 'protected');
    assert.equal(state({ runs: [storedRun({ at: iso(30 * DAY + 1) })] }).status, 'stale');

    const runs = [
      storedRun({ id: 'older', verdict: 'failed', at: iso(2 * DAY) }),
      storedRun({ id: 'newer', verdict: 'passed', at: iso(DAY) }),
    ];
    assert.equal(state({ runs }).status, 'protected');
  });

  it('requires fresh pass evidence for every applicable check before reporting protected', () => {
    const checkIds = new Set([CHECK_A, CHECK_B]);
    const partial = state({
      checkIds,
      runs: [storedRun({ id: 'only_one', checkId: CHECK_A })],
    });
    assert.equal(partial.status, 'inconclusive');
    assert.equal(partial.testedCheckCount, 1);
    assert.equal(partial.applicableCheckCount, 2);

    const complete = state({
      checkIds,
      runs: [
        storedRun({ id: 'first_pass', checkId: CHECK_A }),
        storedRun({ id: 'second_pass', checkId: CHECK_B }),
      ],
    });
    assert.equal(complete.status, 'protected');
    assert.equal(complete.freshCheckCount, 2);
  });

  it('applies exposed, inconclusive, stale, protected, then not-run precedence conservatively', () => {
    const checkIds = new Set([CHECK_A, CHECK_B]);
    const freshProtected = storedRun({ id: 'protected', checkId: CHECK_A });
    const staleProtected = storedRun({ id: 'stale', checkId: CHECK_B, at: iso(31 * DAY) });
    const inconclusive = storedRun({ id: 'inconclusive', checkId: CHECK_B, verdict: 'needs_review' });
    const exposed = storedRun({ id: 'exposed', checkId: CHECK_B, verdict: 'unprotected' });

    assert.equal(state({ checkIds, runs: [freshProtected, staleProtected] }).status, 'stale');
    assert.equal(state({ checkIds, runs: [freshProtected, staleProtected, inconclusive] }).status, 'inconclusive');
    assert.equal(state({ checkIds, runs: [freshProtected, staleProtected, inconclusive, exposed] }).status, 'exposed');
  });

  it('reports tested/applicable and verdict counts without implying complete family coverage', () => {
    const result = state({
      checkIds: new Set([CHECK_A, CHECK_B, 'untested']),
      runs: [
        storedRun({ id: 'pass', checkId: CHECK_A }),
        storedRun({ id: 'gap', checkId: CHECK_B, verdict: 'failed' }),
      ],
    });
    assert.deepEqual(result, {
      status: 'exposed',
      applicableCheckCount: 3,
      testedCheckCount: 2,
      freshCheckCount: 2,
      staleCheckCount: 0,
      protectedCount: 1,
      exposedCount: 1,
      inconclusiveCount: 0,
      latestEvidenceAt: iso(DAY),
    });
  });
});
