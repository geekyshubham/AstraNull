import { clampPageLimit, decodeCursor, encodeCursor, paginateItems } from '../lib/cursorPagination.mjs';
import { targetTagsFromRecord } from '../contracts/targetManagement.mjs';
import { effectiveTargetVerifications } from '../lib/effectiveTargetVerification.mjs';
import { presentTargetDeclaration } from '../lib/targetDeclarations.mjs';
import { getStore } from '../store.mjs';
import { getTargetEdgeDetection } from './targetEdgeDetectionStore.mjs';
import { presentTargetEdgeDetection } from '../lib/edgeDetectionPresenter.mjs';
import { bindingRecordsFromStore, currentOriginProof } from './originBindings.mjs';
import { attachHistoryReadModel, deriveProtectionProfile, historyReadModel } from './protectionProfile.mjs';
import {
  boundCheckRows,
  edgeDetectionRequestRow,
  latestRunsByCheck,
  presentWafPosture,
  recentRunRow,
  remediationOwnerGroup,
} from '../lib/targetDetailRows.mjs';

const RUNS_PAGE_MAX = 100;
const RUNS_PAGE_FALLBACK = 5;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

const VERIFICATION_STATE_RANK = Object.freeze({
  unverified: 0,
  pending: 1,
  dns_verified: 2,
  provider_verified: 2,
  user_confirmed: 4,
});

function ownedByTenant(row, tenantId) {
  return row?.tenant_id === tenantId;
}

function latestVerificationRows(targetId, tenantId) {
  const rows = (getStore().targetVerifications ?? [])
    .filter((row) => row.target_id === targetId && ownedByTenant(row, tenantId))
    .sort((a, b) => {
      const at = String(a.transitioned_at).localeCompare(String(b.transitioned_at));
      if (at !== 0) return at;
      return (VERIFICATION_STATE_RANK[a.state] ?? 0) - (VERIFICATION_STATE_RANK[b.state] ?? 0);
    });
  return rows;
}

function latestVerificationState(targetId, tenantId) {
  const rows = latestVerificationRows(targetId, tenantId);
  if (!rows.length) {
    return {
      state: 'unverified',
      source_kind: null,
      source_ref: null,
      history: [],
    };
  }
  const store = getStore();
  const target = store.targets.find((candidate) => candidate.id === targetId && ownedByTenant(candidate, tenantId));
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

function recordedMarkerRules(...values) {
  for (const value of values) {
    if (value == null || value === '') continue;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }
  return null;
}

function recordedOriginState(value) {
  if (value == null) return 'not_tested';
  const text = String(value).trim();
  return text || 'not_tested';
}

function remediationOwnerForFinding(findingId, tenantId) {
  const rows = getStore().findingRemediations ?? [];
  const row = rows.find((item) => item.finding_id === findingId && ownedByTenant(item, tenantId));
  return remediationOwnerGroup(row?.owner_group);
}

function runProvenance(run, tenantId) {
  const store = getStore();
  const event = (store.events ?? [])
    .filter((row) => ownedByTenant(row, tenantId) && row.test_run_id === run.id)
    .sort((a, b) => String(b.timestamp ?? '').localeCompare(String(a.timestamp ?? '')))[0];
  const evidence = (store.evidenceVault ?? [])
    .filter((row) => ownedByTenant(row, tenantId) && row.test_run_id === run.id)
    .sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? '')))[0];
  return {
    producer_kind: run.producer_kind ?? event?.producer_kind ?? null,
    simulation: run.simulation ?? event?.metadata?.simulation ?? evidence?.metadata?.simulation ?? null,
    evidence_label: run.evidence_label ?? evidence?.label ?? null,
  };
}

function buildWafPosture(ctx, target) {
  const asset = getStore().wafAssets?.find(
    (row) => row.tenant_id === ctx.tenantId && row.target_id === target.id,
  );
  if (!asset) return null;

  const postures = (getStore().wafPostureSnapshots ?? [])
    .filter((row) => row.waf_asset_id === asset.id && ownedByTenant(row, ctx.tenantId))
    .sort((a, b) => String(b.observed_at).localeCompare(String(a.observed_at)));
  const posture = postures[0] ?? asset.posture ?? null;

  const connector = asset.connector_id
    ? getStore().wafConnectors?.find((row) => row.id === asset.connector_id && ownedByTenant(row, ctx.tenantId))
    : null;

  const validationRuns = (getStore().wafValidationRuns ?? [])
    .filter((row) => row.waf_asset_id === asset.id && ownedByTenant(row, ctx.tenantId))
    .sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)));

  const fingerprint = (getStore().wafFingerprints ?? []).find(
    (row) => row.waf_asset_id === asset.id && ownedByTenant(row, ctx.tenantId),
  );

  return presentWafPosture({
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
      ? { signature: fingerprint.signature ?? fingerprint.id ?? null, score: fingerprint.score ?? null }
      : null,
    marker_rules: recordedMarkerRules(asset.marker_rules, posture?.marker_rules),
    origin_bypass: {
      state: recordedOriginState(asset.origin_bypass_state),
      last_checked_at: toIso(asset.origin_bypass_checked_at ?? posture?.observed_at),
    },
    raw_context_yaml: typeof asset.raw_context_yaml === 'string' ? asset.raw_context_yaml : null,
  }, ctx);
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

function buildRunsRecent(runs, verdictForRun, limit = RUNS_PAGE_FALLBACK) {
  const boundedLimit = clampPageLimit(limit, {
    max: RUNS_PAGE_MAX,
    fallback: RUNS_PAGE_FALLBACK,
  });
  return runs
    .slice()
    .sort((a, b) => String(b.started_at ?? b.created_at).localeCompare(String(a.started_at ?? a.created_at)))
    .slice(0, boundedLimit)
    .map((run) => recentRunRow(run, verdictForRun(run)));
}

function buildFindings(targetId, tenantId, query = {}) {
  const all = (getStore().findings ?? [])
    .filter((f) => f.target_id === targetId && ownedByTenant(f, tenantId))
    .sort((a, b) =>
      String(b.created_at ?? b.opened_at ?? '').localeCompare(
        String(a.created_at ?? a.opened_at ?? ''),
      ) || String(b.id ?? '').localeCompare(String(a.id ?? '')),
    )
    .map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
      state: f.status ?? f.state,
      opened_at: toIso(f.created_at ?? f.opened_at),
      owner_group: remediationOwnerForFinding(f.id, tenantId),
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

  const verification = latestVerificationState(targetId, ctx.tenantId);
  const { findings, next_cursor } = buildFindings(targetId, ctx.tenantId, query);
  const allFindings = (getStore().findings ?? []).filter(
    (f) => f.target_id === targetId && ownedByTenant(f, ctx.tenantId),
  );
  const { runs, verdictForRun } = targetRunsWithVerdicts(ctx, targetId);
  const latestByCheck = latestRunsByCheck(runs, verdictForRun);
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === target.target_group_id && candidate.tenant_id === ctx.tenantId,
  );
  const edgeRow = getTargetEdgeDetection(ctx.tenantId, target.id);
  const policies = (getStore().testPolicies ?? []).filter((policy) => policy.tenant_id === ctx.tenantId);
  const derived = deriveProtectionProfile({
    now: new Date(),
    target: {
      id: target.id,
      kind: target.kind,
      value: target.value,
      tenant_id: target.tenant_id,
      target_group_id: target.target_group_id,
    },
    edgeRow,
    policies,
    observations: [...latestByCheck.values()].map((entry) => ({
      check_id: entry.run?.check_id,
      run: entry.run ? { ...entry.run, ...runProvenance(entry.run, ctx.tenantId) } : entry.run,
      verdict: entry.verdict,
    })),
  });
  const historyRecords = bindingRecordsFromStore(getStore(), ctx.tenantId);
  const attached = attachHistoryReadModel(derived, historyReadModel({
    observations: (getStore().targetObservations ?? []).filter((row) => row.tenant_id === ctx.tenantId && row.target_id === target.id),
    bindings: (getStore().originBindings ?? []).filter((row) => row.tenant_id === ctx.tenantId
      && row.status === 'active'
      && (row.origin_target_id === target.id || row.protected_target_id === target.id)),
    proofFor: (id) => currentOriginProof(historyRecords, ctx.tenantId, id),
    targetId: target.id,
  }));

  const payload = {
    target: {
      id: target.id,
      tenant_id: target.tenant_id,
      target_group_id: target.target_group_id,
      kind: target.kind,
      value: target.value,
      expected_behavior: target.expected_behavior ?? 'cloud_baseline', // target declaration default, not the immutable run snapshot
      // WAF-CDN-01: expose canonical top-level `tags: string[]` so the detail page matches the
      // collection serializer (docs/api.md: every target payload, including detail targets,
      // exposes top-level tags). Reserved metadata stays stripped — only the trusted tag list.
      tags: targetTagsFromRecord(target),
      declaration: presentTargetDeclaration(target.declaration_json, group?.declaration_json),
      created_at: toIso(target.created_at),
      eligibility: target.eligibility ?? 'eligible',
      eligibility_reason: target.eligibility_reason ?? null,
    },
    verification,
    waf_posture: target.kind === 'ip' && !getStore().wafAssets?.some(
      (asset) => asset.target_id === target.id && ownedByTenant(asset, ctx.tenantId),
    )
      ? null
      : buildWafPosture(ctx, target),
    edge_detection: presentTargetEdgeDetection(edgeRow),
    protection_profile: attached.protection_profile,
    coverage: attached.coverage,
    edge_detection_request: edgeDetectionRequestRow(latestByCheck),
    checks_applied: buildChecksApplied(ctx, target, latestByCheck),
    runs_recent: buildRunsRecent(runs, verdictForRun, Number(query.runs_limit) || 5),
    findings,
    loa: buildLoa(ctx, target.target_group_id),
    counts: {
      runs_total: runs.length,
      findings_open: allFindings.filter((f) => (f.status ?? f.state) === 'open').length,
      findings_closed: allFindings.filter((f) => ['closed', 'accepted'].includes(f.status ?? f.state)).length,
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