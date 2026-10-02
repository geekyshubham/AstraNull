/**
 * Refined grouping must stay linear in findings (UNCOMMITTED_CHANGES_REVIEW F05).
 *
 * The previous helper re-mapped and linearly searched the targets array for every finding,
 * which took ~4.8s for 10,000 findings / 10,000 targets. The indexed helper takes well under
 * 200ms locally; the budgets below are generous for CI but far below the quadratic behaviour.
 * An operation-count check guards the same property without depending on wall-clock time.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createFindingGroupIndex,
  groupFindings,
  matchesFindingFilters,
} from '../../apps/web/react/src/lib/finding-groups.mjs';

const N = 10_000;
const NOW = Date.parse('2026-01-10T00:00:00Z');
const STATUSES = ['open', 'open', 'accepted_risk', 'closed'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

function inventory(size) {
  const targets = Array.from({ length: size }, (_, i) => ({ id: `tgt_${i}`, value: `h${i}.example.test`, name: `Edge ${i}`, target_group_id: `tg_${i % 25}` }));
  const targetGroups = Array.from({ length: 25 }, (_, i) => ({ id: `tg_${i}`, name: `Group ${i}` }));
  const checks = Array.from({ length: 12 }, (_, i) => ({ check_id: `check.${i}.safe`, name: `Check ${i}`, vector_family: `family_${i % 4}` }));
  const findings = targets.map((target, i) => ({
    id: `f_${i}`,
    check_id: `check.${i % 12}.safe`,
    target_id: target.id,
    target_group_id: target.target_group_id,
    // Mix generated titles (verdict identity) with custom titles that need target-token stripping.
    title: i % 2 ? `Finding: bypassable on ${target.value}` : `Origin reachable on ${target.name}`,
    status: STATUSES[i % STATUSES.length],
    severity: SEVERITIES[i % SEVERITIES.length],
    assignee: i % 3 ? `owner${i % 7}@example.test` : '',
    created_at: new Date(NOW - (i % 400) * 3_600_000).toISOString(),
  }));
  return { targets, targetGroups, checks, findings };
}

/** Wraps an array so every element read through the iterator or index is counted. */
function countingArray(items, counter) {
  return new Proxy(items, {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && /^\d+$/.test(prop)) counter.reads += 1;
      return Reflect.get(target, prop, receiver);
    },
  });
}

function timed(fn) {
  const start = performance.now();
  const result = fn();
  return { result, ms: performance.now() - start };
}

describe('Refined grouping at production scale', () => {
  const { targets, targetGroups, checks, findings } = inventory(N);

  it('groups 10,000 findings across 10,000 targets well inside the budget', () => {
    // Warm up JIT once so the measurement reflects steady state.
    groupFindings(findings.slice(0, 500), { targets, checks, targetGroups, now: NOW });
    const { result, ms } = timed(() => groupFindings(findings, { targets, checks, targetGroups, now: NOW }));
    assert.ok(result.length > 0);
    assert.equal(result.reduce((sum, group) => sum + group.findingIds.length, 0), N);
    assert.ok(ms < 1500, `summary grouping took ${Math.round(ms)}ms (old quadratic helper: ~4800ms)`);
  });

  it('reuses one index for summary and filtered grouping', () => {
    const index = createFindingGroupIndex({ targets, checks, targetGroups, now: NOW });
    const { ms: summaryMs } = timed(() => groupFindings(findings, index));
    const matched = findings.filter((finding) => matchesFindingFilters(finding, { status: 'open', severity: 'high' }));
    assert.ok(matched.length > 0);
    const { result: filtered, ms: filteredMs } = timed(() => groupFindings(matched, index));
    assert.equal(filtered.reduce((sum, group) => sum + group.openCount, 0), matched.length);
    assert.ok(summaryMs + filteredMs < 2000, `summary ${Math.round(summaryMs)}ms + filtered ${Math.round(filteredMs)}ms`);
  });

  it('reads each target record a bounded number of times, independent of finding count', () => {
    const counter = { reads: 0 };
    const counted = countingArray(targets, counter);
    const index = createFindingGroupIndex({ targets: counted, checks, targetGroups, now: NOW });
    const afterIndex = counter.reads;
    groupFindings(findings, index);
    groupFindings(findings.filter((_, i) => i % 3 === 0), index);
    // Indexing touches each target once; grouping must not scan the targets array again.
    assert.equal(afterIndex, N);
    assert.equal(counter.reads, N, `grouping re-read targets ${counter.reads - N} times`);

    // A plain context builds its own index: still one pass over targets per call, never per finding.
    counter.reads = 0;
    groupFindings(findings, { targets: counted, checks, targetGroups, now: NOW });
    assert.equal(counter.reads, N);
  });
});
