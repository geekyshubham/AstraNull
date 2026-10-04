import { isConnectorsEnabledForTenant, loadRuntimeConfig } from '../config.mjs';
import { getCheckById, isCustomerRunnable } from '../contracts/checks.mjs';
import { targetKindCompatibilityError } from '../contracts/checkTargetCompatibility.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { redactString } from './redact.mjs';
import { WAF_EDGE_DETECTION_CHECK_ID } from './edgeDetection.mjs';

const NON_PUBLISHED_VERDICTS = new Set(['', 'none', 'unknown', 'pending', 'planned', 'queued', 'running', 'collecting']);

function toIso(value) {
  if (value == null || value === '') return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function runStartedAt(run) {
  return toIso(run?.started_at ?? run?.created_at);
}

export function verdictEvidenceIds(verdict) {
  if (!Array.isArray(verdict?.evidence_ids)) return [];
  return verdict.evidence_ids.map((id) => String(id ?? '').trim()).filter(Boolean);
}

/** Verdict text only when a published verdict record cites at least one evidence id. */
export function evidenceBackedVerdict(verdict) {
  const value = String(verdict?.verdict ?? '').trim();
  if (NON_PUBLISHED_VERDICTS.has(value.toLowerCase())) return null;
  return verdictEvidenceIds(verdict).length > 0 ? value : null;
}

/** Remediation owner when a row recorded one. Never a hardcoded team name. */
export function remediationOwnerGroup(ownerGroup) {
  const value = typeof ownerGroup === 'string' ? ownerGroup.trim() : '';
  return value || 'unassigned';
}

export function recentRunRow(run, verdict = null) {
  return {
    run_id: run.id,
    policy_id: run.policy_id ?? run.test_policy_id ?? null,
    check_id: run.check_id ?? null,
    status: String(run.status ?? '').trim() || 'unknown',
    verdict: String(verdict?.verdict ?? '').trim() || 'unknown',
    verdict_id: verdict?.id ?? null,
    evidence_ids: verdictEvidenceIds(verdict),
    started_at: runStartedAt(run),
    completed_at: toIso(run.completed_at),
  };
}

/** Newest run (with its verdict record) per check id, from runs already scoped to one target. */
export function latestRunsByCheck(runs, verdictForRun = () => null) {
  const latest = new Map();
  for (const run of runs) {
    if (!run?.check_id) continue;
    const previous = latest.get(run.check_id);
    if (previous) {
      const order = String(runStartedAt(run) ?? '').localeCompare(String(runStartedAt(previous.run) ?? ''));
      if (order < 0 || (order === 0 && String(run.id) < String(previous.run.id))) continue;
    }
    latest.set(run.check_id, { run, verdict: verdictForRun(run) ?? null });
  }
  return latest;
}

function policyBindsTarget(policy, target) {
  if (!policy || policy.archived_at || policy.state === 'archived') return false;
  if (policy.tenant_id && policy.tenant_id !== target.tenant_id) return false;
  if (policy.target_group_id !== target.target_group_id) return false;
  return !policy.target_id || policy.target_id === target.id;
}

function policyState(policy) {
  if (policy.enabled === false) return 'disabled';
  return String(policy.state ?? '').trim() || 'active';
}

/**
 * Checks bound to a target through test policies: target-scoped policies and group-wide
 * policies on the target's group. Only customer-runnable, kind-compatible checks are returned
 * so every row can be launched through POST /v1/test-runs.
 */
export function boundCheckRows(target, policies, latestByCheck = new Map()) {
  const rows = new Map();
  for (const policy of policies ?? []) {
    if (!policyBindsTarget(policy, target)) continue;
    const check = getCheckById(policy.check_id);
    if (!isCustomerRunnable(check) || targetKindCompatibilityError(check, target)) continue;
    const targetScoped = Boolean(policy.target_id);
    const existing = rows.get(check.check_id);
    if (existing && (existing.binding_scope === 'target' || !targetScoped)) continue;
    const last = latestByCheck.get(check.check_id) ?? null;
    rows.set(check.check_id, {
      check_id: check.check_id,
      policy_id: policy.id,
      policy_state: policyState(policy),
      binding_scope: targetScoped ? 'target' : 'target_group',
      cadence: policy.cadence ?? 'manual',
      last_verdict: evidenceBackedVerdict(last?.verdict) ?? 'unknown',
      last_run_id: last?.run?.id ?? null,
      last_ran_at: last ? runStartedAt(last.run) : null,
    });
  }
  return [...rows.values()];
}

/** Latest governed WAF/CDN detection request for the target, so the UI can explain its outcome. */
export function edgeDetectionRequestRow(latestByCheck) {
  const run = latestByCheck.get(WAF_EDGE_DETECTION_CHECK_ID)?.run;
  if (!run?.id) return null;
  return {
    test_run_id: run.id,
    run_status: String(run.status ?? '').trim() || 'unknown',
    started_at: runStartedAt(run),
    completed_at: toIso(run.completed_at),
  };
}

const YAML_SECRET_LINE = /^(\s*)([A-Za-z0-9_-]*(?:secret|token|password|credential|api_key|private_key)[A-Za-z0-9_-]*)\s*:\s*\S/i;

/** Missing score stays null. A recorded 0 stays 0. */
export function fingerprintMeasure(score) {
  if (score == null || score === '') return { score: null, score_status: 'not_recorded' };
  const number = Number(score);
  if (!Number.isFinite(number)) return { score: null, score_status: 'not_recorded' };
  return { score: number, score_status: 'recorded' };
}

function redactStoredYaml(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  return redactString(value).split('\n').map((line) => (
    YAML_SECRET_LINE.test(line) ? line.replace(/:.*/, ': [redacted]') : line
  )).join('\n');
}

function connectorConfigAllowed(ctx) {
  try {
    const config = loadRuntimeConfig();
    const enabled = config.featureFlags?.wafPostureEnabled === true
      && isConnectorsEnabledForTenant(config, ctx?.tenantId);
    if (!enabled) return { allowed: false, reason: 'feature_disabled' };
    if (!roleHasPermission(ctx?.role, 'waf:connector_read')) {
      return { allowed: false, reason: 'permission_denied' };
    }
    if (Array.isArray(ctx?.scopes)) {
      const scopeOk = ctx.scopes.includes('*') || ctx.scopes.includes('waf:connector_read');
      if (!scopeOk) return { allowed: false, reason: 'permission_denied' };
    }
    return { allowed: true, reason: null };
  } catch {
    return { allowed: false, reason: 'feature_disabled' };
  }
}

/**
 * Core fingerprint and marker fields stay. Connector config and stored YAML are
 * returned only when the connector feature is on and the caller has waf:connector_read.
 * Stored strings are re-read here and secret-bearing lines are redacted.
 */
export function presentWafPosture(posture, ctx) {
  if (!posture) return null;
  const access = connectorConfigAllowed(ctx);
  const measure = posture.fingerprint ? fingerprintMeasure(posture.fingerprint.score) : null;
  const connector = posture.connector && typeof posture.connector === 'object'
    ? {
      id: posture.connector.id ?? null,
      state: posture.connector.state ?? posture.connector.status ?? 'unknown',
      last_polled_at: posture.connector.last_polled_at ?? null,
    }
    : null;
  return {
    asset_id: posture.asset_id,
    vendor: posture.vendor ?? 'generic',
    posture: posture.posture ?? 'unknown',
    drift_reason: posture.drift_reason ?? null,
    validation: posture.validation ?? null,
    fingerprint: posture.fingerprint
      ? {
        signature: posture.fingerprint.signature ?? null,
        score: measure.score,
        score_status: measure.score_status,
      }
      : null,
    marker_rules: posture.marker_rules ?? null,
    origin_bypass: posture.origin_bypass ?? { state: 'not_tested', last_checked_at: null },
    connector: access.allowed ? connector : null,
    raw_context_yaml: access.allowed ? redactStoredYaml(posture.raw_context_yaml) : null,
    configuration_access: access.allowed ? 'allowed' : 'redacted',
    configuration_disabled_reason: access.reason,
    profiles: {
      edge: 'independent',
      core_fingerprint: 'independent',
    },
  };
}

export { WAF_EDGE_DETECTION_CHECK_ID };
