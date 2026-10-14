import { isIP } from 'node:net';
import { validateHmacSecretEntropy } from './evidenceSigning.mjs';

const PERSPECTIVE_ID = /^[a-z0-9-]{1,32}$/;
const MAX_LABEL = 64;
const MAX_REGION = 64;
const MAX_EGRESS_IPS = 32;

export const DEFAULT_PROBE_PERSPECTIVES = Object.freeze([
  Object.freeze({
    id: 'default',
    label: 'Primary',
    region: null,
    asn: null,
    egress_ips: Object.freeze([]),
  }),
]);

function fail(message) {
  throw new Error(`ASTRANULL_PROBE_PERSPECTIVES ${message}`);
}

function normalizePerspective(entry, index) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    fail(`entry [${index}] must be an object {id,label,region,asn,egress_ips,worker_secret?}.`);
  }
  const id = typeof entry.id === 'string' ? entry.id.trim() : '';
  if (!PERSPECTIVE_ID.test(id)) {
    fail(`entry [${index}] id must match [a-z0-9-]{1,32}.`);
  }
  if (typeof entry.label !== 'string' || !entry.label.trim()) {
    fail(`entry [${index}] label is required.`);
  }
  const label = entry.label.trim().slice(0, MAX_LABEL);
  let region = null;
  if (entry.region != null && entry.region !== '') {
    if (typeof entry.region !== 'string') fail(`entry [${index}] region must be a string.`);
    region = entry.region.trim().slice(0, MAX_REGION) || null;
  }
  let asn = null;
  if (entry.asn != null && entry.asn !== '') {
    if (typeof entry.asn === 'number') {
      if (!Number.isInteger(entry.asn) || entry.asn < 0) fail(`entry [${index}] asn must be a non-negative integer.`);
      asn = entry.asn;
    } else if (typeof entry.asn === 'string' && /^\d+$/.test(entry.asn.trim())) {
      asn = Number(entry.asn.trim());
    } else {
      fail(`entry [${index}] asn must be a non-negative integer.`);
    }
  }
  const rawIps = entry.egress_ips == null ? [] : entry.egress_ips;
  if (!Array.isArray(rawIps)) fail(`entry [${index}] egress_ips must be an array of IP addresses.`);
  if (rawIps.length > MAX_EGRESS_IPS) fail(`entry [${index}] egress_ips is capped at ${MAX_EGRESS_IPS}.`);
  const egress_ips = [];
  for (const raw of rawIps) {
    if (typeof raw !== 'string' || isIP(raw.trim()) === 0) {
      fail(`entry [${index}] egress_ips must contain valid IPv4 or IPv6 addresses.`);
    }
    egress_ips.push(raw.trim());
  }
  let workerSecret = null;
  if (entry.worker_secret != null && entry.worker_secret !== '') {
    const validated = validateHmacSecretEntropy(entry.worker_secret);
    if (!validated.ok) fail(`entry [${index}] worker_secret failed entropy validation (${validated.error}).`);
    workerSecret = validated.secret;
  }
  const perspective = { id, label, region, asn, egress_ips };
  if (workerSecret) Object.defineProperty(perspective, 'worker_secret', { value: workerSecret, enumerable: false });
  return perspective;
}

/**
 * Parse `ASTRANULL_PROBE_PERSPECTIVES`. Empty env yields the built-in `default`
 * perspective. Malformed JSON, a non-array, an empty array, or an invalid entry
 * throws a startup error (fail closed).
 *
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function loadProbePerspectivesFromEnv(env = process.env) {
  const raw = env?.ASTRANULL_PROBE_PERSPECTIVES;
  if (raw == null || String(raw).trim() === '') return [...DEFAULT_PROBE_PERSPECTIVES];
  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch {
    fail('must be a JSON array of {id,label,region,asn,egress_ips,worker_secret?}.');
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    fail('must be a non-empty JSON array of {id,label,region,asn,egress_ips,worker_secret?}.');
  }
  const seen = new Set();
  const perspectives = parsed.map((entry, index) => {
    const normalized = normalizePerspective(entry, index);
    if (seen.has(normalized.id)) fail(`duplicate id "${normalized.id}".`);
    seen.add(normalized.id);
    return normalized;
  });
  return perspectives;
}

/** Per-perspective worker HMAC secret, or null when the perspective uses the shared worker secret. */
export function perspectiveWorkerSecret(perspectiveId, env = process.env) {
  if (typeof perspectiveId !== 'string' || !perspectiveId) return null;
  const match = loadProbePerspectivesFromEnv(env).find((row) => row.id === perspectiveId);
  return match?.worker_secret ?? null;
}

/** Server-stamped perspective evidence: the header-claimed id and whether its own secret signed the request. */
export function probePerspectiveEvidence(workerCtx) {
  return {
    claimed_perspective_id: workerCtx?.perspectiveId ?? null,
    perspective_authenticated: workerCtx?.perspectiveAuthenticated === true,
  };
}

export function probePerspectiveIds(env = process.env) {
  return new Set(loadProbePerspectivesFromEnv(env).map((row) => row.id));
}

/** Customer-facing projection: id, label, region, egress_ips. */
export function listProbePerspectives(env = process.env) {
  return loadProbePerspectivesFromEnv(env).map(({ id, label, region, egress_ips }) => ({
    id,
    label,
    region,
    egress_ips,
  }));
}
