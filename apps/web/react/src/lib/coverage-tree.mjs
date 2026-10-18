/**
 * Domain coverage tree: one cell per target and family, rolled up from subdomains into their
 * parent domain. Cell outcomes come from resourceFamilyVerdictState (latest evidence-backed
 * verdict per applicable check); an open finding on a covered check is an evidence-backed gap.
 */
import { resourceFamilyVerdictState } from './resource-matrix.mjs';

/** @typedef {'gap' | 'review' | 'stale' | 'partial' | 'pass' | 'untested' | 'na'} CoverageOutcome */

export const COVERAGE_OUTCOME_LABEL = Object.freeze({
  gap: 'Gap found',
  review: 'Review',
  stale: 'Stale',
  partial: 'Partly tested',
  pass: 'Passing',
  untested: 'Not tested',
  na: 'Not applicable',
});

export const COVERAGE_OUTCOME_TONE = Object.freeze({
  gap: 'danger',
  review: 'warn',
  stale: 'warn',
  partial: 'warn',
  pass: 'success',
  untested: 'muted',
  na: 'muted',
});

const RANK = Object.freeze({ gap: 6, review: 5, stale: 4, partial: 3, pass: 2, untested: 1, na: 0 });

function text(value) {
  return value === undefined || value === null ? '' : String(value);
}

/** Check ids with an open finding, per target id. */
export function openFindingChecksByTarget(findings) {
  /** @type {Map<string, Set<string>>} */
  const map = new Map();
  for (const finding of Array.isArray(findings) ? findings : []) {
    if (!finding || typeof finding !== 'object') continue;
    const status = text(finding.status ?? finding.state).toLowerCase();
    if (status && !['open', 'in_progress', 'remediation_pending', 'reopened'].includes(status)) continue;
    const targetId = text(finding.target_id);
    const checkId = text(finding.check_id);
    if (!targetId || !checkId) continue;
    const set = map.get(targetId) ?? new Set();
    set.add(checkId);
    map.set(targetId, set);
  }
  return map;
}

/**
 * Outcome for one target and family.
 * @param {{ checkIds: Set<string>, targetId: string, runs: Record<string, unknown>[], evidence: Record<string, unknown>[], openChecks?: Set<string>, nowMs?: number }} input
 */
export function coverageCell({ checkIds, targetId, runs, evidence, openChecks, nowMs }) {
  const state = resourceFamilyVerdictState({ checkIds, targetId, runs, evidence, nowMs });
  const hasOpenFinding = [...(openChecks ?? [])].some((id) => checkIds.has(id));
  /** @type {CoverageOutcome} */
  let outcome;
  if (state.status === 'not_applicable') outcome = 'na';
  else if (state.status === 'exposed' || hasOpenFinding) outcome = 'gap';
  else if (state.status === 'protected') outcome = 'pass';
  else if (state.status === 'stale') outcome = 'stale';
  else if (state.status === 'not_run') outcome = 'untested';
  else outcome = state.inconclusiveCount > 0 ? 'review' : 'partial';
  return {
    outcome,
    testedChecks: state.testedCheckCount,
    applicableChecks: state.applicableCheckCount,
    hosts: outcome === 'na' ? 0 : 1,
    testedHosts: outcome === 'na' || outcome === 'untested' ? 0 : 1,
  };
}

/** Worst outcome across cells; host counts add up. */
export function rollUpCoverage(cells) {
  let outcome = /** @type {CoverageOutcome} */ ('na');
  let hosts = 0;
  let testedHosts = 0;
  let testedChecks = 0;
  let applicableChecks = 0;
  for (const cell of cells) {
    if (RANK[cell.outcome] > RANK[outcome]) outcome = cell.outcome;
    hosts += cell.hosts;
    testedHosts += cell.testedHosts;
    testedChecks += cell.testedChecks;
    applicableChecks += cell.applicableChecks;
  }
  return { outcome, hosts, testedHosts, testedChecks, applicableChecks };
}

/** True when any cell in the row has a result. */
export function rowHasResult(cells) {
  return cells.some((cell) => cell.testedHosts > 0 || cell.outcome === 'gap');
}

/** Attack-type columns: a check joins by vector_family, or by check id prefix when the family is missing. */
export const ATTACK_FAMILIES = Object.freeze([
  { id: 'origin', label: 'Origin', keys: ['origin', 'path'] },
  { id: 'network', label: 'Network', keys: ['l3_l4', 'nfw'] },
  { id: 'dns', label: 'DNS', keys: ['dns'] },
  { id: 'waf', label: 'WAF', keys: ['waf'] },
  { id: 'application', label: 'Application', keys: ['l7', 'exploit', 'pattern'] },
  { id: 'protocol', label: 'TLS & protocol', keys: ['tls', 'protocol'] },
  { id: 'reflection', label: 'Reflection', keys: ['reflection', 'amplification'] },
]);

export function attackFamilyCheckIds(checks, family) {
  const ids = new Set();
  for (const check of Array.isArray(checks) ? checks : []) {
    const id = text(check?.check_id ?? check?.id);
    if (!id) continue;
    const vectorFamily = text(check.vector_family).toLowerCase();
    const prefix = id.split('.')[0].toLowerCase();
    if (family.keys.includes(vectorFamily) || (!vectorFamily && family.keys.includes(prefix))) ids.add(id);
  }
  return ids;
}
