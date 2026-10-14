import { catalogRuleCoverage, RULE_COVERAGE_CATEGORIES } from '../contracts/ruleCoverage.mjs';
import { controlDeclarationsFromTarget } from '../contracts/controlDeclarations.mjs';
import { COVERAGE_FRESHNESS_POLICY } from '../lib/protectionCoverage.mjs';
import { latestRunsByCheck } from '../lib/targetDetailRows.mjs';
import { listProbePerspectives } from '../lib/probePerspectiveRegistry.mjs';
import { getStore } from '../store.mjs';
import { getTarget } from './targetGroups.mjs';

const PASS_VERDICTS = new Set(['protected', 'pass', 'passed', 'success', 'ok', 'allowed_as_expected', 'edge_protected']);
const FAIL_VERDICTS = new Set(['exposed', 'unprotected', 'gap', 'fail', 'failed', 'bypassable', 'penetrated', 'edge_exposed']);

function declarationPresent(declarations, key) {
  if (key === 'network_policy') return Array.isArray(declarations?.network_policy) && declarations.network_policy.length > 0;
  if (key === 'canary_sink') return Boolean(declarations?.canary_sink?.url);
  if (key === 'waf.rate_limit_canary') return Boolean(declarations?.waf?.rate_limit_canary?.path);
  if (key === 'origin.lockdown_expected') return declarations?.origin?.lockdown_expected === true;
  if (key === 'origin_binding' || key === 'origin_bindings') {
    return Boolean(declarations?.origin_binding || (Array.isArray(declarations?.origin_bindings) && declarations.origin_bindings.length > 0));
  }
  if (key === 'connection_limits') return Array.isArray(declarations?.connection_limits) && declarations.connection_limits.length > 0;
  if (key === 'perspectives') {
    const row = declarations?.perspectives;
    return Boolean(row && ((row.allowlisted_perspective_ids?.length ?? 0) + (row.denied_perspective_ids?.length ?? 0) > 0));
  }
  return false;
}

function verdictLabel(value) {
  const label = String(value ?? '').trim().toLowerCase();
  if (PASS_VERDICTS.has(label)) return 'pass';
  if (FAIL_VERDICTS.has(label)) return 'fail';
  if (!label) return null;
  return 'inconclusive';
}

function latestForCheck(latestByCheck, checkId, nowMs) {
  const entry = latestByCheck.get(checkId);
  if (!entry?.run) return { status: 'not_run', verdict: null, observed_at: null, stale: false };
  const observedMs = Date.parse(entry.run.completed_at ?? entry.run.started_at ?? '');
  const observed_at = Number.isFinite(observedMs) ? new Date(observedMs).toISOString() : null;
  const stale = !Number.isFinite(observedMs) || nowMs - observedMs > COVERAGE_FRESHNESS_POLICY.max_age_ms;
  if (stale) return { status: 'not_run', verdict: entry.verdict?.verdict ?? null, observed_at, stale: true };
  const label = verdictLabel(entry.verdict?.verdict);
  if (label === 'pass') return { status: 'covered_pass', verdict: entry.verdict.verdict, observed_at, stale: false };
  if (label === 'fail') return { status: 'covered_fail', verdict: entry.verdict.verdict, observed_at, stale: false };
  if (label === 'inconclusive') return { status: 'inconclusive', verdict: entry.verdict.verdict, observed_at, stale: false };
  return { status: 'not_run', verdict: entry.verdict?.verdict ?? null, observed_at, stale: false };
}

function categoryStatus(catalogRow, checkRows, missingDeclarations, perspectiveCount) {
  if (catalogRow.assurance === 'out_of_scope' || catalogRow.out_of_scope_reason) return 'out_of_scope';
  if (catalogRow.assurance === 'not_assessable' || catalogRow.not_assessable_reason) return 'not_assessable';
  if (catalogRow.id === 'allowlists_geo' && perspectiveCount < 2) return 'not_run';
  if (missingDeclarations.length) return 'needs_declaration';
  const live = checkRows.filter((row) => row.status !== 'not_run');
  if (!live.length) return 'not_run';
  if (live.some((row) => row.status === 'covered_fail')) return 'covered_fail';
  if (live.some((row) => row.status === 'inconclusive')) return 'inconclusive';
  if (live.every((row) => row.status === 'covered_pass')) return 'covered_pass';
  return 'inconclusive';
}

/** Pure projection shared by dev and Postgres: same output for the same declarations, runs and verdicts. */
export function buildTargetRuleCoverage({ targetId, declarations, runs = [], verdictForRun = () => null, nowMs = Date.now(), env = process.env }) {
  const latestByCheck = latestRunsByCheck(runs, verdictForRun);
  const catalog = catalogRuleCoverage();
  const perspectiveCount = listProbePerspectives(env).length;
  const resolvedDeclarations = declarations ?? {};
  const categories = catalog.categories.map((row) => {
    const source = RULE_COVERAGE_CATEGORIES.find((entry) => entry.id === row.id);
    const missing_declarations = (row.required_declarations ?? []).filter((key) => !declarationPresent(resolvedDeclarations, key));
    const checks = (row.checks ?? []).map((check) => {
      const latest = latestForCheck(latestByCheck, check.check_id, nowMs);
      return { ...check, ...latest };
    });
    return {
      id: row.id,
      layer: row.layer,
      name: row.name,
      description: row.description,
      check_ids: row.check_ids ?? [],
      probe_kinds: row.probe_kinds ?? [],
      assurance: row.assurance,
      assurance_reason: row.assurance_reason ?? null,
      out_of_scope_reason: row.out_of_scope_reason,
      not_assessable_reason: row.not_assessable_reason,
      required_declarations: row.required_declarations ?? source?.required_declarations ?? [],
      missing_declarations,
      status: categoryStatus(row, checks, missing_declarations, perspectiveCount),
      not_runnable_reason: row.id === 'allowlists_geo' && perspectiveCount < 2 ? 'two_perspectives_required' : null,
      checks,
    };
  });
  return {
    version: 'rule-coverage.v1',
    target_id: targetId,
    freshness_policy: COVERAGE_FRESHNESS_POLICY,
    verdict_capable_from: catalog.verdict_capable_from,
    categories,
  };
}

export function targetRuleCoverage(ctx, targetId, { nowMs = Date.now(), env = process.env } = {}) {
  if (!ctx?.tenantId || !targetId) return null;
  const owned = getTarget(ctx, targetId);
  if (!owned) return null;
  const store = getStore();
  const raw = (store.targets ?? []).find((row) => row.id === targetId && row.tenant_id === ctx.tenantId) ?? null;
  const runs = (store.testRuns ?? []).filter((run) => run.target_id === targetId && run.tenant_id === ctx.tenantId);
  const targetBindings = (store.originBindings ?? []).filter((row) =>
    row.tenant_id === ctx.tenantId && row.status === 'active'
    && (row.protected_target_id === targetId || row.origin_target_id === targetId)
  );
  const declarations = {
    ...(controlDeclarationsFromTarget(raw) ?? {}),
    ...(targetBindings.length > 0 ? { origin_binding: targetBindings[0], origin_bindings: targetBindings } : {}),
  };
  return buildTargetRuleCoverage({
    targetId,
    declarations,
    runs,
    verdictForRun: (run) => (
      (store.verdicts ?? []).find((verdict) => verdict.test_run_id === run.id && verdict.tenant_id === ctx.tenantId) ?? null
    ),
    nowMs,
    env,
  });
}
