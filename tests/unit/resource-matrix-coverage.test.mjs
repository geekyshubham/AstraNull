import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  RESOURCE_EVIDENCE_FRESHNESS_MS,
  RESOURCE_FAMILIES,
  applicableResourceFamilyCheckIds,
  resourceFamilyCheckIds,
  resourceFamilyVerdictState,
  resourceMatrixGroups,
} from '../../apps/web/react/src/lib/resource-matrix.mjs';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';

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
  groupId = 'tg_1',
  verdict = 'protected',
  at = iso(DAY),
  status = 'completed',
} = {}) {
  return {
    id,
    check_id: checkId,
    target_group_id: groupId,
    target_id: 'tgt_1',
    status,
    completed_at: at,
    verdict: {
      test_run_id: id,
      check_id: checkId,
      target_id: 'tgt_1',
      verdict,
      evidence_ids: [`evt_${id}`],
      created_at: at,
    },
  };
}

function state({ checkIds = new Set([CHECK_A]), runs = [], evidence = [], groupId = 'tg_1' } = {}) {
  return resourceFamilyVerdictState({ checkIds, groupId, runs, evidence, nowMs: NOW });
}

describe('resource-exhaustion matrix (DET-024)', () => {
  it('declares the twelve exhausted-resource families in display order', () => {
    assert.equal(RESOURCE_FAMILIES.length, 12);
    assert.equal(RESOURCE_FAMILIES[0].id, 'volumetric');
    assert.equal(RESOURCE_FAMILIES[11].id, 'delivery_pattern');
    for (const family of RESOURCE_FAMILIES) {
      assert.ok(family.label.length > 0, family.id);
      assert.ok(family.metric.length > 0, family.id);
    }
  });

  it('classifies shipped catalog checks only by their declared exhausted_resource', () => {
    const apiRows = CHECK_CATALOG.map((check) => ({
      check_id: check.check_id,
      exhausted_resource: check.exhausted_resource,
    }));
    const volumetric = resourceFamilyCheckIds(apiRows, { id: 'volumetric' });
    assert.ok(volumetric.has(CHECK_A));
    assert.ok(volumetric.has(CHECK_B));
    assert.ok(resourceFamilyCheckIds(apiRows, { id: 'reflection' }).has('reflect.ssdp_exposure.safe'));

    const declaredFamilies = new Set(RESOURCE_FAMILIES.map((family) => family.id));
    for (const row of apiRows) {
      if (row.exhausted_resource == null) {
        for (const family of RESOURCE_FAMILIES) {
          assert.equal(resourceFamilyCheckIds(apiRows, family).has(row.check_id), false, row.check_id);
        }
      } else {
        assert.ok(declaredFamilies.has(row.exhausted_resource), row.check_id);
      }
    }
  });

  it('renders every active target group without a five-column cap', () => {
    const groups = Array.from({ length: 8 }, (_, index) => ({ id: `tg_${index + 1}` }));
    groups.push({ id: 'tg_archived', archived_at: iso() });
    groups.push({ id: 'tg_deleted', deleted_at: iso() });
    assert.deepEqual(resourceMatrixGroups(groups).map((group) => group.id), [
      'tg_1', 'tg_2', 'tg_3', 'tg_4', 'tg_5', 'tg_6', 'tg_7', 'tg_8',
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
      { target_group_id: 'tg_1', kind: 'url' },
      { target_group_id: 'tg_other', kind: 'fqdn' },
    ];

    assert.deepEqual(
      [...applicableResourceFamilyCheckIds({ checks, family, groupId: 'tg_1', targets })].sort(),
      [CHECK_B, 'generic'].sort(),
    );
    assert.equal(
      applicableResourceFamilyCheckIds({ checks, family, groupId: 'tg_empty', targets }).size,
      0,
    );
    assert.deepEqual(
      [...applicableResourceFamilyCheckIds({
        checks,
        family,
        groupId: 'tg_1',
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
    assert.equal(state({ runs: [{ id: 'run_1', check_id: CHECK_A, target_group_id: 'tg_1' }] }).status, 'not_run');
    assert.equal(state({ runs: [storedRun({ status: 'running' })] }).status, 'not_run');
    assert.equal(state({ runs: [{
      id: 'run_1', check_id: CHECK_A, target_group_id: 'tg_1', status: 'completed',
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
      target_group: { id: 'tg_1' },
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
      id: 'run_legacy', check_id: CHECK_A, target_group_id: 'tg_1', status: 'completed',
      verdict: 'edge_exposed', completed_at: iso(),
    };
    assert.equal(state({
      runs: [legacyRun],
      evidence: [{ test_run_id: 'run_legacy', observed_at: iso() }],
    }).status, 'exposed');
    assert.equal(state({
      runs: [legacyRun],
      evidence: [{ test_run_id: 'run_other', check_id: CHECK_A, target_group_id: 'tg_1' }],
    }).status, 'not_run');
  });

  it('keeps other checks and target groups from leaking into a cell', () => {
    const runs = [
      storedRun({ id: 'wrong_check', checkId: CHECK_B, verdict: 'failed' }),
      storedRun({ id: 'wrong_group', groupId: 'tg_2', verdict: 'failed' }),
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
