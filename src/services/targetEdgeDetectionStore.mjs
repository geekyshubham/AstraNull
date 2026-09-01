/**
 * Durable per-target WAF/CDN edge detection — in-memory runtime.
 *
 * Keeps one current detection per target, refreshed each time a signed `waf.fingerprint.safe`
 * probe result resolves. The Postgres runtime mirrors this in `target_edge_detections`.
 */

import { getStore, persistStore } from '../store.mjs';
import { newId } from '../lib/ids.mjs';
import {
  projectEdgeDetection,
  edgeDetectionRowFields,
  isPersistableEdgeDetection,
} from '../lib/edgeDetectionProjection.mjs';

function ensureCollection(store) {
  if (!Array.isArray(store.targetEdgeDetections)) store.targetEdgeDetections = [];
  return store.targetEdgeDetections;
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
  if (!isPersistableEdgeDetection(metadata)) return null;

  const projection = projectEdgeDetection(metadata);
  const fields = edgeDetectionRowFields(projection, {
    testRunId,
    observedAt: observedAt ?? new Date().toISOString(),
  });

  const store = getStore();
  const collection = ensureCollection(store);
  const nowIso = new Date().toISOString();
  const existing = collection.find(
    (row) => row.tenant_id === tenantId && row.target_id === targetId,
  );

  if (existing) {
    Object.assign(existing, fields, {
      target_group_id: targetGroupId,
      updated_at: nowIso,
    });
    persistStore();
    return existing;
  }

  const record = {
    id: newId('edgedet'),
    tenant_id: tenantId,
    target_group_id: targetGroupId,
    target_id: targetId,
    ...fields,
    created_at: nowIso,
    updated_at: nowIso,
  };
  collection.push(record);
  persistStore();
  return record;
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
