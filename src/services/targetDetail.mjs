import { decodeCursor, encodeCursor, paginateItems } from '../lib/cursorPagination.mjs';
import { effectiveTargetVerifications } from '../lib/effectiveTargetVerification.mjs';
import { getStore } from '../store.mjs';
import { getTargetEdgeDetection } from './targetEdgeDetectionStore.mjs';
import { presentTargetEdgeDetection } from '../lib/edgeDetectionPresenter.mjs';
import {
  boundCheckRows,
  edgeDetectionRequestRow,
  latestRunsByCheck,
  recentRunRow,
} from '../lib/targetDetailRows.mjs';

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

const VERIFICATION_STATE_RANK = Object.freeze({
  unverified: 0,
  pending: 1,
  dns_verified: 2,
  agent_verified: 3,
  user_confirmed: 4,
});

function latestVerificationRows(targetId) {
  const rows = (getStore().targetVerifications ?? [])
    .filter((row) => row.target_id === targetId)
    .sort((a, b) => {
      const at = String(a.transitioned_at).localeCompare(String(b.transitioned_at));
      if (at !== 0) return at;
      return (VERIFICATION_STATE_RANK[a.state] ?? 0) - (VERIFICATION_STATE_RANK[b.state] ?? 0);
    });
  return rows;
}

function latestVerificationState(targetId) {
  const rows = latestVerificationRows(targetId);
  if (!rows.length) {
    return {
      state: 'unverified',
      source_kind: null,
      source_ref: null,
      history: [],
    };
  }
  const store = getStore();
  const target = store.targets.find((candidate) => candidate.id === targetId);
  const latest = target
    ? effectiveTargetVerifications(store, target.tenant_id, [targetId]).get(targetId)
    : null;
  if (!latest) {
    return {
      state: 'unverified',
      source_kind: null,
      source_ref: null,
      history: rows.map((row) => ({
        state: row.state,
        transitioned_at: toIso(row.transitioned_at),
        ...(row.state !== 'pending' && row.source_ref ? { source_ref: row.source_ref } : {}),
      })),
    };
  }
  return {
    state: latest.state,
    source_kind: latest.source_kind,
    source_ref: latest.source_ref,
    history: rows.map((row) => ({
      state: row.state,
      transitioned_at: toIso(row.transitioned_at),
      ...(row.state !== 'pending' && row.source_ref ? { source_ref: row.source_ref } : {}),
    })),
  };
}

function buildAgentBinding(target, tenantId) {
  const agent = getStore().agents.find(
    (a) =>
      a.tenant_id === tenantId
      && a.target_group_id === target.target_group_id
      && (a.bound_target_id === target.id || a.id === target.agent_id),
  );
  if (!agent && !target.agent_binding) return null;
  if (target.agent_binding) return target.agent_binding;
  return {
    agent_id: agent.id,
    bound_at: toIso(agent.bound_at ?? agent.created_at ?? agent.enrolled_at),
  };
}

function buildWafPosture(ctx, target) {
  const asset = getStore().wafAssets?.find(
    (row) => row.tenant_id === ctx.tenantId && row.target_id === target.id,
  );
  if (!asset) return null;

  const postures = (getStore().wafPostureSnapshots ?? [])
    .filter((row) => row.waf_asset_id === asset.id)
    .sort((a, b) => String(b.observed_at).localeCompare(String(a.observed_at)));
  const posture = postures[0] ?? asset.posture ?? null;

  const connector = asset.connector_id
    ? getStore().wafConnectors?.find((c) => c.id === asset.connector_id)
    : null;

  const validationRuns = (getStore().wafValidationRuns ?? [])
    .filter((row) => row.waf_asset_id === asset.id)
    .sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)));

  const fingerprint = (getStore().wafFingerprints ?? []).find((row) => row.waf_asset_id === asset.id);

  return {
    asset_id: asset.id,
    vendor: asset.vendor ?? 'generic',
    posture: posture?.state ?? posture?.posture ?? 'unknown',
    drift_reason: posture?.drift_reason ?? null,
    validation: validationRuns[0]
      ? {
          last_ran_at: toIso(validationRuns[0].started_at ?? validationRuns[0].completed_at),
          verdict: validationRuns[0].verdict ?? 'unknown',
          run_id: validationRuns[0].id,
        }
      : null,
    connector: connector
      ? {
          id: connector.id,
          state: connector.status ?? connector.state ?? 'unknown',
          last_polled_at: toIso(connector.last_success_at ?? connector.last_polled_at),
        }
      : null,
    fingerprint: fingerprint
      ? { signature: fingerprint.signature ?? fingerprint.id, score: fingerprint.score ?? 0 }
      : null,
    marker_rules: asset.marker_rules ?? posture?.marker_rules ?? 0,
    origin_bypass: {
      state: asset.origin_bypass_state ?? 'not_exposed',
      last_checked_at: toIso(asset.origin_bypass_checked_at ?? posture?.observed_at),
    },
    raw_context_yaml: asset.raw_context_yaml
      ?? `asset_id: ${asset.id}\nvendor: ${asset.vendor ?? 'generic'}\ntarget_id: ${target.id}\n`,
  };
}

function targetRunsWithVerdicts(ctx, targetId) {
  const store = getStore();
  const runs = (store.testRuns ?? []).filter(
    (run) => run.target_id === targetId && run.tenant_id === ctx.tenantId,
  );
  const runIds = new Set(runs.map((run) => run.id));
  const verdictsByRunId = new Map();
  for (const verdict of store.verdicts ?? []) {
    if (verdict.tenant_id !== ctx.tenantId || !runIds.has(verdict.test_run_id)) continue;
    const previous = verdictsByRunId.get(verdict.test_run_id);
    if (!previous || String(verdict.created_at ?? '') > String(previous.created_at ?? '')) {
      verdictsByRunId.set(verdict.test_run_id, verdict);
    }
  }
  return { runs, verdictForRun: (run) => verdictsByRunId.get(run.id) ?? null };
}

function buildChecksApplied(ctx, target, latestByCheck) {
  const policies = (getStore().testPolicies ?? []).filter((policy) => policy.tenant_id === ctx.tenantId);
  return boundCheckRows(target, policies, latestByCheck);
}

function buildRunsRecent(runs, verdictForRun, limit = 5) {
  return runs
    .slice()
    .sort((a, b) => String(b.started_at ?? b.created_at).localeCompare(String(a.started_at ?? a.created_at)))
    .slice(0, limit)
    .map((run) => recentRunRow(run, verdictForRun(run)));
}

function buildFindings(targetId, query = {}) {
  const all = (getStore().findings ?? [])
    .filter((f) => f.target_id === targetId)
    .sort((a, b) => String(b.opened_at).localeCompare(String(a.opened_at)))
    .map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
      state: f.state,
      opened_at: toIso(f.opened_at),
      owner_group: f.owner_group,
    }));

  const limit = Number(query.findings_limit);
  if (Number.isFinite(limit) && limit > 0) {
    const paged = paginateItems(all, {
      limit,
      cursor: query.findings_cursor,
      cursorField: 'id',
    });
    return { findings: paged.items, next_cursor: paged.next_cursor };
  }
  return { findings: all.slice(0, 20), next_cursor: null };
}

function buildLoa(ctx, groupId) {
  const loa = (getStore().loaSignatures ?? []).find(
    (row) =>
      row.tenant_id === ctx.tenantId
      && row.target_group_id === groupId
      && row.state === 'signed',
  );
  if (!loa) return null;
  return {
    id: loa.id,
    state: loa.state,
    signed_at: toIso(loa.signed_at),
    signer_name: loa.signer_name,
    custody_digest_sha256: loa.custody_digest_sha256,
  };
}

/**
 * Target-detail hydrator (§4.1).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} targetId
 * @param {{ runs_limit?: number, findings_limit?: number, findings_cursor?: string }} [query]
 */
export function getTargetDetail(ctx, targetId, query = {}) {
  const target = getStore().targets.find(
    (t) => t.id === targetId && t.tenant_id === ctx.tenantId && !t.deleted_at,
  );
  if (!target) {
    return {
      target: null,
      verification: null,
      waf_posture: null,
      checks_applied: [],
      runs_recent: [],
      findings: [],
      loa: null,
      counts: { runs_total: 0, findings_open: 0, findings_closed: 0 },
      meta: { empty_reason: 'Target not found or outside tenant scope.' },
      error: 'not_found',
      status: 404,
    };
  }

  const verification = latestVerificationState(targetId);
  const { findings, next_cursor } = buildFindings(targetId, query);
  const allFindings = (getStore().findings ?? []).filter((f) => f.target_id === targetId);
  const { runs, verdictForRun } = targetRunsWithVerdicts(ctx, targetId);
  const latestByCheck = latestRunsByCheck(runs, verdictForRun);

  const payload = {
    target: {
      id: target.id,
      tenant_id: target.tenant_id,
      target_group_id: target.target_group_id,
      kind: target.kind,
      value: target.value,
      expected_behavior: target.expected_behavior ?? 'cloud_baseline',
      agent_binding: buildAgentBinding(target, ctx.tenantId),
      created_at: toIso(target.created_at),
      eligibility: target.eligibility ?? 'eligible',
      eligibility_reason: target.eligibility_reason ?? null,
    },
    verification,
    waf_posture: target.kind === 'ip' && !getStore().wafAssets?.some((a) => a.target_id === target.id)
      ? null
      : buildWafPosture(ctx, target),
    edge_detection: presentTargetEdgeDetection(getTargetEdgeDetection(ctx.tenantId, target.id)),
    edge_detection_request: edgeDetectionRequestRow(latestByCheck),
    checks_applied: buildChecksApplied(ctx, target, latestByCheck),
    runs_recent: buildRunsRecent(runs, verdictForRun, Number(query.runs_limit) || 5),
    findings,
    loa: buildLoa(ctx, target.target_group_id),
    counts: {
      runs_total: runs.length,
      findings_open: allFindings.filter((f) => f.state === 'open').length,
      findings_closed: allFindings.filter((f) => f.state === 'closed' || f.state === 'accepted').length,
    },
  };
  if (next_cursor) payload.findings_next_cursor = next_cursor;

  const runsRecent = payload.runs_recent ?? [];
  const findingsList = payload.findings ?? [];
  const checksList = payload.checks_applied ?? [];

  payload.meta = {
    runs_empty_reason: runsRecent.length
      ? null
      : 'No bounded test runs have been recorded for this target yet.',
    findings_empty_reason: findingsList.length
      ? null
      : 'No findings are scoped to this target yet.',
    checks_empty_reason: checksList.length
      ? null
      : 'No customer-runnable checks are bound to this target by a test policy yet.',
    waf_empty_reason: payload.waf_posture
      ? null
      : 'No WAF posture asset is linked to this target.',
  };

  return payload;
}

export { encodeCursor, decodeCursor };