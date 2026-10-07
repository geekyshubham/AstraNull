// Server-side source perspective for signed probe evidence; never taken from worker-submitted metadata.
import { SOURCE_PERSPECTIVE_PATTERN } from '../contracts/protectionValidation.mjs';
import { DEFAULT_SOURCE_PERSPECTIVE } from './entryPathComparison.mjs';

export { DEFAULT_SOURCE_PERSPECTIVE };

/** An absent registry uses the shared pool; an invalid configured registry admits no workers. */
export function approvedProbeSourcesFromEnv(env = process.env) {
  const raw = env?.ASTRANULL_APPROVED_PROBE_SOURCES;
  if (raw == null || String(raw).trim() === '') return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  const registry = {};
  for (const [perspective, workers] of Object.entries(parsed)) {
    if (!SOURCE_PERSPECTIVE_PATTERN.test(perspective) || !Array.isArray(workers)) continue;
    const ids = workers.filter((id) => typeof id === 'string' && id.trim()).map((id) => id.trim());
    if (ids.length) registry[perspective] = ids;
  }
  return registry;
}

/**
 * With a registry, only registered workers have a source (unknown workers resolve to null).
 * Without one, every signed worker belongs to the single shared public pool.
 */
export function createProbeSourceResolver({ registry = null } = {}) {
  const index = new Map();
  for (const [perspective, workers] of Object.entries(registry ?? {})) {
    for (const workerId of Array.isArray(workers) ? workers : []) {
      if (typeof workerId !== 'string' || !workerId) continue;
      if (!index.has(workerId)) index.set(workerId, perspective);
      else if (index.get(workerId) !== perspective) index.set(workerId, null);
    }
  }
  const strict = registry !== null;
  const resolve = (workerId) => {
    if (typeof workerId !== 'string' || !workerId) return null;
    if (strict) return index.get(workerId) ?? null;
    return DEFAULT_SOURCE_PERSPECTIVE;
  };
  resolve.mode = strict ? 'registry' : 'shared_public_pool';
  resolve.perspectives = strict ? [...new Set(index.values())].filter(Boolean).sort() : [DEFAULT_SOURCE_PERSPECTIVE];
  return resolve;
}

export function probeSourceResolverFromEnv(env = process.env) {
  return createProbeSourceResolver({ registry: approvedProbeSourcesFromEnv(env) });
}
