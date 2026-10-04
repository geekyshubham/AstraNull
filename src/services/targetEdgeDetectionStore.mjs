/**
 * Durable per-target WAF/CDN edge detection — in-memory runtime.
 *
 * Keeps one current detection per target, refreshed each time a signed `waf.fingerprint.safe`
 * probe result resolves. The Postgres runtime mirrors this in `target_edge_detections`.
 */

import { getStore, persistStore } from '../store.mjs';
import { newId } from '../lib/ids.mjs';
import { getCheckById } from '../contracts/checks.mjs';
import {
  projectEdgeDetection,
  edgeDetectionRowFields,
  isPersistableEdgeDetection,
} from '../lib/edgeDetectionProjection.mjs';
import {
  acceptTargetObservation,
  classifyAttempt,
  compareObservationOrder,
  normalizeObservationTimestamp,
  observationTimeError,
  originOutcomeFromProbe,
  transportOutcomeFromProbe,
} from './targetHistory.mjs';

const WAF_EDGE_CHECK_ID = 'waf.fingerprint.safe';

let defaultObservedAtMs = 0;

function resolveObservedAt(observedAt) {
  if (observedAt != null) return observedAt;
  const now = Date.now();
  defaultObservedAtMs = Math.max(now, defaultObservedAtMs + 1);
  return new Date(defaultObservedAtMs).toISOString();
}

function edgeFamilyRows(metadata, projection) {
  const rows = [
    { family: 'waf', outcome: projection.waf?.status, provider: projection.waf?.vendor ?? null },
    { family: 'cdn', outcome: projection.cdn?.status, provider: projection.cdn?.provider ?? null },
  ];
  if (typeof metadata?.edge_signature?.cloud_hosted === 'boolean') {
    rows.push({
      family: 'cloud',
      outcome: projection.cloud?.status,
      provider: projection.cloud?.provider ?? null,
    });
  }
  return rows.filter((row) => classifyAttempt(row.outcome));
}

function ensureCollection(store) {
  if (!Array.isArray(store.targetEdgeDetections)) store.targetEdgeDetections = [];
  return store.targetEdgeDetections;
}

function declaredTarget(store, tenantId, targetId) {
  return (store.targets ?? []).find((row) => row.tenant_id === tenantId
    && row.id === targetId
    && !row.deleted_at
    && !row.archived_at) ?? null;
}

function stampedRun(store, tenantId, testRunId) {
  if (!testRunId) return null;
  return (store.testRuns ?? []).find((row) => row.tenant_id === tenantId && row.id === testRunId) ?? null;
}

function bindingForOrigin(store, tenantId, bindingId, targetId) {
  if (!bindingId) return null;
  const binding = (store.originBindings ?? []).find((row) => row.tenant_id === tenantId
    && row.id === bindingId
    && row.status === 'active') ?? null;
  if (!binding || binding.origin_target_id !== targetId) return null;
  return binding;
}

function appendFamilyHistory({
  tenantId,
  target,
  testRunId,
  observed,
  completed,
  families,
  sourceKind,
  checkId,
  originBindingId = null,
}) {
  const store = getStore();
  const run = stampedRun(store, tenantId, testRunId);
  for (const family of families) {
    const provenance = { status: family.outcome };
    if (family.provider) provenance.provider = family.provider;
    acceptTargetObservation({ tenantId }, {
      target_id: target.id,
      family: family.family,
      check_id: checkId,
      test_run_id: testRunId,
      source_kind: sourceKind,
      source_id: testRunId,
      corpus_version: family.corpus_version ?? null,
      scenario_version: run?.scenario_version ?? null,
      check_version: run?.check_version ?? null,
      observed_at: observed,
      source_completed_at: completed,
      outcome: family.outcome,
      producer_kind: 'signed_probe',
      origin_binding_id: originBindingId,
      event_id: family.event_id,
      provenance,
    }, { internal: true });
  }
}

/**
 * Project a signed probe result and upsert the current detection for its target.
 * No-ops for simulations, worker errors, or results without an edge signature.
 *
 * @returns {object|null} the stored detection row, or null when nothing was persisted
 */
export function recordTargetEdgeDetectionFromEvent({
  tenantId,
  targetGroupId,
  targetId,
  testRunId = null,
  metadata = {},
  observedAt = null,
}) {
  if (!tenantId || !targetGroupId || !targetId) return null;

  const store = getStore();
  const collection = ensureCollection(store);
  const existing = collection.find(
    (row) => row.tenant_id === tenantId && row.target_id === targetId,
  ) ?? null;
  const target = declaredTarget(store, tenantId, targetId);
  const transport = transportOutcomeFromProbe(metadata);
  const resolvedObserved = resolveObservedAt(observedAt);
  const sourceCompletedRaw = metadata?.source_completed_at ?? metadata?.completed_at ?? null;
  const observed = normalizeObservationTimestamp(resolvedObserved) ?? resolvedObserved;
  const completed = sourceCompletedRaw == null || sourceCompletedRaw === ''
    ? null
    : normalizeObservationTimestamp(sourceCompletedRaw);

  if (!isPersistableEdgeDetection(metadata)) {
    if (transport && target) {
      const times = observationTimeError({
        observedAt: resolvedObserved,
        sourceCompletedAt: sourceCompletedRaw,
        declaredAt: target.created_at,
      });
      if (!times.error) {
        const families = [
          { family: 'waf', outcome: transport },
          { family: 'cdn', outcome: transport },
        ];
        if (typeof metadata?.edge_signature?.cloud_hosted === 'boolean') {
          families.push({ family: 'cloud', outcome: transport });
        }
        appendFamilyHistory({
          tenantId,
          target,
          testRunId,
          observed,
          completed,
          families: families.map((family) => ({
            ...family,
            corpus_version: typeof metadata.edge_signature_corpus_version === 'string'
              ? metadata.edge_signature_corpus_version
              : null,
            event_id: `edge-fail:${testRunId ?? 'none'}:${family.family}:${observed}`,
          })),
          sourceKind: 'edge_detection',
          checkId: WAF_EDGE_CHECK_ID,
        });
        persistStore();
      }
    }
    return existing;
  }

  const projection = projectEdgeDetection(metadata);
  const fields = edgeDetectionRowFields(projection, { testRunId, observedAt: observed });

  if (target) {
    const times = observationTimeError({
      observedAt: resolvedObserved,
      sourceCompletedAt: sourceCompletedRaw,
      declaredAt: target.created_at,
    });
    if (times.error) return existing;
    const run = stampedRun(store, tenantId, testRunId);
    const binding = bindingForOrigin(store, tenantId, run?.origin_binding_id, targetId);
    appendFamilyHistory({
      tenantId,
      target,
      testRunId,
      observed,
      completed,
      families: edgeFamilyRows(metadata, projection).map((family) => ({
        ...family,
        corpus_version: projection.corpus_version || null,
        event_id: `edge:${testRunId ?? 'none'}:${family.family}:${observed}`,
      })),
      sourceKind: 'edge_detection',
      checkId: WAF_EDGE_CHECK_ID,
      originBindingId: binding?.id ?? null,
    });
  }

  const candidate = { observed_at: observed, source_completed_at: completed, id: String(testRunId ?? '') };
  const currentOrder = existing
    ? {
      observed_at: existing.observed_at,
      source_completed_at: existing.source_completed_at ?? null,
      id: String(existing.test_run_id ?? ''),
    }
    : null;
  if (existing && compareObservationOrder(candidate, currentOrder) <= 0) return existing;

  const historyId = target
    ? (store.targetObservations ?? []).find((row) => row.tenant_id === tenantId
      && row.event_id === `edge:${testRunId ?? 'none'}:waf:${observed}`)?.id ?? existing?.history_observation_id ?? null
    : existing?.history_observation_id ?? null;
  const nowIso = new Date().toISOString();
  const stamped = {
    ...fields,
    target_group_id: targetGroupId,
    source_completed_at: completed,
    history_observation_id: historyId,
    updated_at: nowIso,
  };
  if (existing) {
    Object.assign(existing, stamped);
    persistStore();
    return existing;
  }

  const record = {
    id: newId('edgedet'),
    tenant_id: tenantId,
    target_id: targetId,
    ...stamped,
    created_at: nowIso,
  };
  collection.push(record);
  persistStore();
  return record;
}

/**
 * Dev signed-result history. Edge fingerprint updates the current detection.
 * An approved origin check records origin_hosting only when the run names an
 * active binding whose origin target is this target.
 */
export function recordSignedProbeHistory({
  checkId,
  tenantId,
  targetGroupId,
  targetId,
  testRunId = null,
  metadata = {},
  observedAt = null,
}) {
  const edge = checkId == null || checkId === WAF_EDGE_CHECK_ID
    ? recordTargetEdgeDetectionFromEvent({
      tenantId, targetGroupId, targetId, testRunId, metadata, observedAt,
    })
    : null;
  const check = checkId ? getCheckById(checkId) : null;
  if (check?.probe_profile?.kind !== 'host_sni_bypass' || !tenantId || !targetId) return edge;
  const store = getStore();
  const target = declaredTarget(store, tenantId, targetId);
  const run = stampedRun(store, tenantId, testRunId);
  const binding = bindingForOrigin(store, tenantId, run?.origin_binding_id, targetId);
  const outcome = originOutcomeFromProbe(metadata);
  if (!target || !binding || !outcome) return edge;
  const resolvedObserved = resolveObservedAt(observedAt);
  const sourceCompletedRaw = metadata?.source_completed_at ?? metadata?.completed_at ?? resolvedObserved;
  const observed = normalizeObservationTimestamp(resolvedObserved) ?? resolvedObserved;
  const completed = normalizeObservationTimestamp(sourceCompletedRaw);
  const times = observationTimeError({
    observedAt: resolvedObserved,
    sourceCompletedAt: sourceCompletedRaw,
    declaredAt: target.created_at,
  });
  if (times.error) return edge;
  appendFamilyHistory({
    tenantId,
    target,
    testRunId,
    observed,
    completed,
    families: [{
      family: 'origin_hosting',
      outcome,
      corpus_version: null,
      event_id: `origin:${testRunId ?? 'none'}:${observed}`,
    }],
    sourceKind: 'validation_run',
    checkId,
    originBindingId: binding.id,
  });
  persistStore();
  return edge;
}

/** Current detection for a single target, or null. */
export function getTargetEdgeDetection(tenantId, targetId) {
  const collection = ensureCollection(getStore());
  return collection.find(
    (row) => row.tenant_id === tenantId && row.target_id === targetId,
  ) ?? null;
}

/** Current detections keyed by target id for every target in a group. */
export function listTargetEdgeDetectionsForGroup(tenantId, targetGroupId) {
  const collection = ensureCollection(getStore());
  const map = {};
  for (const row of collection) {
    if (row.tenant_id !== tenantId || row.target_group_id !== targetGroupId) continue;
    map[row.target_id] = row;
  }
  return map;
}
