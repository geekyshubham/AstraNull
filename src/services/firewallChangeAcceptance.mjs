import {
  MAX_COMPARISON_ITEMS,
  PROTECTION_VALIDATION_AUDIT_ACTIONS,
  PROTECTION_VALIDATION_PAGE_LIMIT,
  PROTECTION_VALIDATION_PERMISSIONS,
  ProtectionValidationError,
  firewallBaselineCaptureDigest,
  normalizeFirewallBaselineRequest,
  normalizeFirewallComparisonRequest,
  normalizeIsoTimestamp,
  sha256Digest,
  verifyBaselineDigest,
} from '../contracts/protectionValidation.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { requirePermission } from '../rbac.mjs';
import { getStore } from '../store.mjs';
import { approvedProbeSourcesFromEnv, createProbeSourceResolver } from '../lib/probeSourcePerspective.mjs';
import {
  FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION,
  buildFirewallBaselineCapture,
  evaluateFirewallChange,
  firewallSampleFromProbeEvent,
  isFinalizedRun,
} from '../lib/firewallChangeAcceptance.mjs';

const PERMS = PROTECTION_VALIDATION_PERMISSIONS;
const MAX_LIST_SCAN = 1000;

function hasPermission(ctx, permission) {
  if (!roleHasPermission(ctx?.role, permission)) return false;
  if (Array.isArray(ctx?.scopes)) return ctx.scopes.includes('*') || ctx.scopes.includes(permission);
  return true;
}

function gate(ctx, permission, resourceType) {
  if (!ctx?.tenantId) return { ok: false, status: 401 };
  if (hasPermission(ctx, permission)) return { ok: true };
  return requirePermission(ctx, permission, { resource_type: resourceType });
}

function fail(error, status, extra = {}) {
  return { error, status, ...extra };
}

function fromValidation(err) {
  if (err instanceof ProtectionValidationError) return { ...err.toResponse() };
  throw err;
}

/** Approved worker->source registry; unknown workers have no source and so can never satisfy a comparison. */
export function createApprovedSourceResolver(registry = null) {
  return createProbeSourceResolver({ registry: registry ?? {} });
}

export function approvedSourcesFromEnv(env = process.env) {
  return approvedProbeSourcesFromEnv(env);
}

/** Tenant-scoped, read-only access to finalized runs and signed probe events in the dev store. */
export function createDevStoreFirewallEvidenceReader(storeProvider = getStore) {
  return {
    getTestRun(tenantId, runId) {
      return (storeProvider().testRuns ?? []).find((run) => run.tenant_id === tenantId && run.id === runId) ?? null;
    },
    listRunProbeEvents(tenantId, runId) {
      return (storeProvider().events ?? []).filter((event) => event.tenant_id === tenantId
        && event.test_run_id === runId
        && event.signal_type === 'probe_result');
    },
    getRunVerdictId(tenantId, runId) {
      const verdict = (storeProvider().verdicts ?? []).find((row) => row.test_run_id === runId && (row.tenant_id == null || row.tenant_id === tenantId));
      return verdict?.id ?? null;
    },
    getTarget(tenantId, targetId) {
      return (storeProvider().targets ?? []).find((target) => target.tenant_id === tenantId && target.id === targetId) ?? null;
    },
  };
}

function targetIsActive(target) {
  return Boolean(target) && !target.deleted_at && !target.archived_at && target.status !== 'archived' && target.status !== 'deleted';
}

function pageLimit(value) {
  const limit = Number.parseInt(value ?? PROTECTION_VALIDATION_PAGE_LIMIT.default, 10);
  if (!Number.isInteger(limit) || limit < 1) return PROTECTION_VALIDATION_PAGE_LIMIT.default;
  return Math.min(limit, PROTECTION_VALIDATION_PAGE_LIMIT.max);
}

/** Injected repository (expectations, baselines, evaluations) and read-only evidence reader; see PV-05 report for the interface. */
export function createFirewallChangeAcceptanceService({
  repository,
  evidence = createDevStoreFirewallEvidenceReader(),
  resolveSourcePerspective = createApprovedSourceResolver(approvedSourcesFromEnv()),
  now = () => new Date(),
} = {}) {
  if (!repository) throw new Error('firewall change acceptance requires a repository');

  function nowIso() {
    return normalizeIsoTimestamp(now(), 'now');
  }

  async function loadSamples(tenantId, runIds, { requireFinalized }) {
    const samples = [];
    const runs = [];
    const targetCache = new Map();
    for (const runId of runIds) {
      const run = await evidence.getTestRun(tenantId, runId);
      if (!run || run.tenant_id !== tenantId) return { error: fail('unknown_test_run', 404, { field: 'test_run_ids', test_run_id: runId }) };
      if (requireFinalized && !isFinalizedRun(run)) {
        return { error: fail('evidence_not_finalized', 409, { field: 'test_run_ids', test_run_id: runId }) };
      }
      runs.push(run);
      if (!targetCache.has(run.target_id)) targetCache.set(run.target_id, await evidence.getTarget(tenantId, run.target_id));
      const verdictId = evidence.getRunVerdictId ? await evidence.getRunVerdictId(tenantId, run.id) : null;
      const events = await evidence.listRunProbeEvents(tenantId, run.id);
      for (const event of events ?? []) {
        if (event.tenant_id != null && event.tenant_id !== tenantId) continue;
        if (event.test_run_id !== run.id) continue;
        const workerId = event?.metadata?.probe_worker_id ?? null;
        samples.push(firewallSampleFromProbeEvent({
          event,
          run,
          target: targetCache.get(run.target_id) ?? null,
          verdictId,
          sourcePerspective: resolveSourcePerspective(workerId),
        }));
      }
    }
    return { samples, runs, targets: targetCache };
  }

  async function loadExpectations(tenantId, ids) {
    const out = [];
    for (const id of ids) {
      const record = await repository.getFirewallExpectation(tenantId, id);
      if (!record || (record.tenant_id != null && record.tenant_id !== tenantId)) {
        return { error: fail('unknown_firewall_expectation', 404, { field: 'expectation_ids', expectation_id: id }) };
      }
      out.push({ id, record });
    }
    return { expectations: out };
  }

  async function captureFirewallBaseline(ctx, body = {}) {
    const allowed = gate(ctx, PERMS.declaration_write, 'firewall_baseline');
    if (!allowed.ok) return fail('forbidden', allowed.status ?? 403);
    let request;
    try {
      request = normalizeFirewallBaselineRequest(body);
    } catch (err) {
      return fromValidation(err);
    }
    const tenantId = ctx.tenantId;
    const loaded = await loadExpectations(tenantId, request.expectation_ids);
    if (loaded.error) return loaded.error;
    for (const { id, record } of loaded.expectations) {
      for (const targetId of new Set([record.destination_target_id, record.pre_post_mapping?.pre_destination_target_id].filter(Boolean))) {
        const target = await evidence.getTarget(tenantId, targetId);
        if (!target) return fail('unknown_target', 404, { field: 'expectation_ids', expectation_id: id });
        if (!targetIsActive(target)) return fail('target_not_active', 409, { field: 'expectation_ids', expectation_id: id });
      }
    }
    const runs = await loadSamples(tenantId, request.test_run_ids, { requireFinalized: true });
    if (runs.error) return runs.error;
    let built;
    try {
      built = buildFirewallBaselineCapture({
        tenantId,
        changeId: request.change_id,
        expectations: loaded.expectations,
        samples: runs.samples,
        freshnessWindowSeconds: request.freshness_window_seconds,
        capturedAt: nowIso(),
      });
    } catch (err) {
      return fromValidation(err);
    }
    const unused = request.test_run_ids.filter((runId) => !built.used_test_run_ids.includes(runId));
    if (unused.length) {
      return fail('invalid_comparison_baseline', 400, {
        field: 'test_run_ids',
        message: 'Every selected run must provide evidence for a selected expectation endpoint.',
        test_run_ids: unused,
      });
    }
    const idempotencyKey = sha256Digest({
      purpose: 'firewall_baseline',
      tenant_id: tenantId,
      change_id: request.change_id,
      freshness_window_seconds: request.freshness_window_seconds,
      classifier_version: FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION,
      entries: built.capture.entries.map((entry) => [entry.expectation_id, entry.baseline_digest, entry.observations_digest]),
    });
    const existing = await repository.findFirewallBaselineByIdempotencyKey(tenantId, idempotencyKey);
    if (existing) return { ...existing, replayed: true };
    const record = {
      ...built.capture,
      idempotency_key: idempotencyKey,
      status: 'active',
      created_by: ctx.userId ?? null,
    };
    const auditEntry = {
      tenant_id: tenantId,
      actor_user_id: ctx.userId ?? null,
      actor_role: ctx.role ?? null,
      action: PROTECTION_VALIDATION_AUDIT_ACTIONS.firewall_baseline_captured,
      resource_type: 'firewall_baseline',
      metadata: {
        change_id: record.change_id,
        baseline_digest: record.baseline_digest,
        expectation_ids: record.entries.map((entry) => entry.expectation_id),
        test_run_ids: built.used_test_run_ids,
        dispatched_traffic: false,
      },
    };
    const stored = await repository.insertFirewallBaseline(tenantId, record, { auditEntry });
    if (stored?.error) return stored;
    return { ...stored, replayed: false };
  }

  function baselineIntegrity(baseline) {
    if (!baseline || baseline.kind !== 'firewall_change' || !Array.isArray(baseline.entries)) return false;
    if (baseline.baseline_digest !== firewallBaselineCaptureDigest(baseline)) return false;
    return baseline.entries.every((entry) => verifyBaselineDigest(entry));
  }

  async function evaluateFirewallComparison(ctx, body = {}) {
    const allowed = gate(ctx, PERMS.declaration_write, 'firewall_comparison');
    if (!allowed.ok) return fail('forbidden', allowed.status ?? 403);
    let request;
    try {
      request = normalizeFirewallComparisonRequest(body);
    } catch (err) {
      return fromValidation(err);
    }
    const tenantId = ctx.tenantId;
    const baseline = await repository.getFirewallBaseline(tenantId, request.baseline_id);
    if (!baseline || baseline.tenant_id !== tenantId) return fail('unknown_firewall_baseline', 404, { field: 'baseline_id' });
    if (baseline.status != null && baseline.status !== 'active') {
      return fail('baseline_not_comparable', 409, { field: 'baseline_id', message: 'Archived baselines cannot be used for new comparisons.' });
    }
    const loaded = await loadSamples(tenantId, request.post_test_run_ids, { requireFinalized: false });
    if (loaded.error) return loaded.error;
    const intact = baselineIntegrity(baseline);
    const expectations = {};
    for (const entry of baseline.entries ?? []) {
      const record = await repository.getFirewallExpectation(tenantId, entry.expectation_id);
      if (record && (record.tenant_id == null || record.tenant_id === tenantId)) expectations[entry.expectation_id] = record;
    }
    const extraExpectations = repository.listFirewallExpectations
      ? ((await repository.listFirewallExpectations(tenantId, { change_id: baseline.change_id, status: 'active' }))?.items ?? [])
        .filter((row) => row.tenant_id == null || row.tenant_id === tenantId)
      : [];
    const evaluatedAt = nowIso();
    const entries = intact
      ? baseline.entries
      : (baseline.entries ?? []).map((entry) => ({ ...entry, observations_digest: null }));
    const result = evaluateFirewallChange({
      tenantId,
      baseline: { ...baseline, entries },
      expectations,
      candidateSamples: loaded.samples,
      extraExpectations: extraExpectations.slice(0, MAX_COMPARISON_ITEMS - entries.length),
      evaluatedAt,
      now: evaluatedAt,
    });
    const idempotencyKey = sha256Digest({
      purpose: 'firewall_comparison',
      tenant_id: tenantId,
      baseline_id: baseline.id,
      baseline_digest: baseline.baseline_digest,
      classifier_version: FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION,
      post_test_run_ids: request.post_test_run_ids,
      items: result.evaluation.items.map((item) => [item.expectation_id, item.status, item.gap_kind, item.reasons, item.compatibility_reasons, item.evidence_refs]),
    });
    const existing = await repository.findFirewallEvaluationByIdempotencyKey(tenantId, idempotencyKey);
    if (existing) return { ...existing, replayed: true };
    const record = {
      ...result.evaluation,
      change_id: baseline.change_id,
      post_test_run_ids: request.post_test_run_ids,
      observations: result.observations,
      statement: result.statement,
      classifier_version: FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION,
      readiness_effect: 'none',
      idempotency_key: idempotencyKey,
      created_by: ctx.userId ?? null,
    };
    const auditEntry = {
      tenant_id: tenantId,
      actor_user_id: ctx.userId ?? null,
      actor_role: ctx.role ?? null,
      action: PROTECTION_VALIDATION_AUDIT_ACTIONS.firewall_comparison_evaluated,
      resource_type: 'firewall_comparison',
      metadata: {
        change_id: baseline.change_id,
        baseline_id: baseline.id,
        evaluation_digest: record.evaluation_digest,
        accepted: record.summary.accepted,
        total: record.summary.total,
        evaluated: record.summary.evaluated,
        post_test_run_ids: request.post_test_run_ids,
        dispatched_traffic: false,
      },
    };
    const stored = await repository.insertFirewallEvaluation(tenantId, record, { auditEntry });
    if (stored?.error) return stored;
    return { ...stored, replayed: false };
  }

  async function getFirewallBaseline(ctx, id) {
    const allowed = gate(ctx, PERMS.evidence_read, 'firewall_baseline');
    if (!allowed.ok) return fail('forbidden', allowed.status ?? 403);
    const row = await repository.getFirewallBaseline(ctx.tenantId, id);
    if (!row || row.tenant_id !== ctx.tenantId) return fail('unknown_firewall_baseline', 404);
    return row;
  }

  async function getFirewallComparison(ctx, id) {
    const allowed = gate(ctx, PERMS.evidence_read, 'firewall_comparison');
    if (!allowed.ok) return fail('forbidden', allowed.status ?? 403);
    const row = await repository.getFirewallEvaluation(ctx.tenantId, id);
    if (!row || row.tenant_id !== ctx.tenantId) return fail('unknown_firewall_comparison', 404);
    return row;
  }

  async function listFirewallBaselines(ctx, query = {}) {
    const allowed = gate(ctx, PERMS.evidence_read, 'firewall_baseline');
    if (!allowed.ok) return fail('forbidden', allowed.status ?? 403);
    return repository.listFirewallBaselines(ctx.tenantId, { ...query, limit: pageLimit(query.limit), max_scan: MAX_LIST_SCAN });
  }

  async function listFirewallComparisons(ctx, query = {}) {
    const allowed = gate(ctx, PERMS.evidence_read, 'firewall_comparison');
    if (!allowed.ok) return fail('forbidden', allowed.status ?? 403);
    return repository.listFirewallEvaluations(ctx.tenantId, { ...query, limit: pageLimit(query.limit), max_scan: MAX_LIST_SCAN });
  }

  return {
    captureFirewallBaseline,
    evaluateFirewallComparison,
    getFirewallBaseline,
    getFirewallComparison,
    listFirewallBaselines,
    listFirewallComparisons,
  };
}
