import { createHash, randomBytes } from 'node:crypto';
import {
  BLOCK_SUSPECTED_UNVERIFIED_SIGNATURE,
  WAF_GRADING_VERSION,
  SIGNATURE_CORPUS_VERSION,
  matchSuspectedVendorSignature,
} from '../externalObservationOutcomes.mjs';
import { isBlockedOrChallenged } from '../outsideInWafScanner.mjs';

export const CACHE_BUSTER_PARAM = 'an_cb';
export const RESPONSE_FEATURE_HEADER_ALLOWLIST = Object.freeze([
  'server', 'via', 'age', 'cf-ray', 'cf-mitigated', 'cf-cache-status',
  'x-cache', 'cache-status', 'x-amzn-errortype', 'x-amzn-requestid', 'x-amz-cf-id',
  'x-azure-ref', 'x-served-by', 'x-cache-hits', 'x-sucuri-block', 'x-bot-challenge',
  'x-waf-block', 'x-iinfo', 'retry-after', 'location',
]);
const BLOCKED_FEATURE_HEADERS = new Set([
  'set-cookie', 'cookie', 'authorization', 'proxy-authorization', 'www-authenticate',
]);
const ENFORCEMENT_RANK = Object.freeze({
  not_enforced: 4, partial: 3, challenged: 2, unknown: 1, enforced: 0,
});

export function deriveRunNonce(seed) {
  if (typeof seed === 'string' && seed.trim()) return seed.trim().slice(0, 64);
  return randomBytes(8).toString('hex');
}

export function cacheBusterToken(runNonce, seq) {
  return createHash('sha256').update(`cb:${String(runNonce)}:${seq}`).digest('hex').slice(0, 12);
}

export function applyCacheBuster(href, runNonce, seq) {
  const token = cacheBusterToken(runNonce, seq);
  const sep = String(href).includes('?') ? '&' : '?';
  return `${href}${sep}${CACHE_BUSTER_PARAM}=${token}`;
}

export function shuffleWithRng(items, rng = Math.random) {
  const copy = [...items];
  const draw = typeof rng === 'function' ? rng : Math.random;
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.min(0.999999, Math.max(0, Number(draw()) || 0)) * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

export function readCacheStatus(headerNames, headerGet) {
  const get = typeof headerGet === 'function' ? headerGet : () => null;
  for (const name of ['cf-cache-status', 'x-cache', 'cache-status']) {
    const value = get(name);
    if (value) return value.slice(0, 64);
  }
  if ((headerNames ?? []).includes('age') || get('age')) {
    const age = get('age');
    return age ? `age:${age.slice(0, 16)}` : 'age';
  }
  return null;
}

export function bodyLengthBucket(bytes) {
  const n = Number(bytes) || 0;
  if (n <= 0) return 'empty';
  if (n < 256) return 'lt_256';
  if (n < 1024) return 'lt_1kb';
  if (n < 4096) return 'lt_4kb';
  if (n < 8192) return 'lt_8kb';
  return 'gte_8kb';
}

function headerSubset(headerGet) {
  const get = typeof headerGet === 'function' ? headerGet : () => null;
  const subset = {};
  for (const name of RESPONSE_FEATURE_HEADER_ALLOWLIST) {
    if (BLOCKED_FEATURE_HEADERS.has(name)) continue;
    const value = get(name);
    if (value) subset[name] = String(value).slice(0, 256);
  }
  return subset;
}

export function extractSignatureBasis(snapshot, graded) {
  const sig = graded?.denial_signature ?? snapshot?.denial_signature;
  if (!sig) return null;
  if (sig.kind === 'declared') {
    const basisKind = sig.basis === 'declared_body' ? 'declared_body' : 'declared_header';
    return {
      kind: basisKind,
      id: sig.id != null ? String(sig.id).slice(0, 128) : 'declared_response',
      declaration_digest: sig.declaration_digest ?? null,
    };
  }
  if (sig.kind === 'vendor') {
    if (String(sig.id).startsWith('challenge_header:') || String(sig.id).startsWith('block_header:')) {
      return { kind: 'vendor_header', id: String(sig.id).slice(0, 128) };
    }
    if (String(sig.id).startsWith('block_sig_')) {
      return { kind: 'block_page', id: String(sig.id).slice(0, 128) };
    }
    if (sig.id === 'cloudflare_challenge') {
      return { kind: 'vendor_header', id: String(sig.id).slice(0, 128) };
    }
    return { kind: 'vendor_body', id: String(sig.id).slice(0, 128) };
  }
  return null;
}

export function redactedResponseFeature({
  placement,
  status_code,
  signature_id = null,
  headerGet,
  body_bytes = 0,
  path = null,
  signature_basis = null,
  declaration_digest = null,
  location_changed = false,
  redirected = false,
}) {
  const basisDigest = declaration_digest ?? signature_basis?.declaration_digest ?? null;
  return {
    placement,
    status_code: Number.isInteger(status_code) ? status_code : null,
    header_subset: headerSubset(headerGet),
    body_length_bucket: bodyLengthBucket(body_bytes),
    signature_id: typeof signature_id === 'string' ? signature_id.slice(0, 128) : null,
    signature_basis: signature_basis && typeof signature_basis === 'object'
      ? {
          kind: String(signature_basis.kind),
          id: signature_basis.id != null ? String(signature_basis.id).slice(0, 128) : null,
        }
      : null,
    ...(basisDigest ? { declaration_digest: String(basisDigest).slice(0, 64) } : {}),
    location_changed: Boolean(location_changed),
    redirected: Boolean(redirected),
    ...(path ? { path: String(path) } : {}),
  };
}

export const WAF_EXPECTED_ACTIONS = Object.freeze(['block', 'challenge', 'block_or_challenge']);

export function expectedWafActionOf(options = {}) {
  const action = options?.expected_action
    ?? options?.declarations?.waf?.expected_action
    ?? options?.probe_profile?.declarations?.waf?.expected_action;
  return WAF_EXPECTED_ACTIONS.includes(action) ? action : 'block';
}

/** A challenged leg satisfies only a challenge-accepting expectation; under `block` it is never counted as allowed. */
export function enforcementFromGraded(graded, { expectedAction = 'block' } = {}) {
  const rows = (graded ?? []).filter(Boolean);
  const blocked = rows.filter((row) => row.blocked === true).length;
  const allowed = rows.filter((row) => row.allowed === true && row.blocked !== true).length;
  const challenged = rows.filter((row) => row.challenged === true && row.blocked !== true).length;
  if (rows.length === 0) return 'unknown';
  if (expectedAction === 'block_or_challenge' || expectedAction === 'challenge') {
    const satisfied = blocked + challenged;
    if (satisfied === rows.length) return 'enforced';
    if (satisfied > 0 && allowed > 0) return 'partial';
    if (allowed > 0) return 'not_enforced';
    return 'unknown';
  }
  if (blocked === rows.length) return 'enforced';
  if (allowed > 0 && blocked > 0) return 'partial';
  if (allowed > 0 && challenged > 0) return 'partial';
  if (allowed > 0) return 'not_enforced';
  if (challenged > 0) return 'challenged';
  return 'unknown';
}

/** Generic proxy/CDN headers on a denial are recorded as a suspected vendor, never as a block signature. */
export function withSuspectedSignature(snapshot, res, bodyText = '') {
  if (!snapshot || !res || snapshot.transport_error) return snapshot;
  const suspected = matchSuspectedVendorSignature({ statusCode: snapshot.status_code, headers: res, bodyText });
  return suspected ? { ...snapshot, suspected_signature: suspected } : snapshot;
}

export function gradeMarkerSnapshot(snapshot, baseline) {
  const graded = isBlockedOrChallenged(snapshot, baseline);
  const suspected = snapshot?.suspected_signature;
  if (!suspected || graded.blocked || graded.challenged || graded.allowed || graded.redirected) return graded;
  if (graded.reason !== 'unattributed_denial') return graded;
  return {
    ...graded,
    block_suspected: true,
    reason: BLOCK_SUSPECTED_UNVERIFIED_SIGNATURE,
    inconclusive_reason: BLOCK_SUSPECTED_UNVERIFIED_SIGNATURE,
    matched_vendor: suspected.vendor ?? null,
    suspected_signature_id: suspected.id ?? null,
  };
}

export function suspectedVendorSummary(rows) {
  const suspected = (rows ?? []).filter((row) => row?.reason === BLOCK_SUSPECTED_UNVERIFIED_SIGNATURE);
  if (!suspected.length) return null;
  return { inconclusive_reason: BLOCK_SUSPECTED_UNVERIFIED_SIGNATURE, matched_vendor: suspected[0].matched_vendor ?? null };
}

export function worstEnforcement(values) {
  let worst = 'enforced';
  let rank = -1;
  for (const value of values ?? []) {
    const next = ENFORCEMENT_RANK[value] ?? ENFORCEMENT_RANK.unknown;
    if (next >= rank) {
      rank = next;
      worst = ENFORCEMENT_RANK[value] == null ? 'unknown' : value;
    }
  }
  return rank < 0 ? 'unknown' : worst;
}

export function postureFromEnforcement(enforcement, { sourcePenalized = false } = {}) {
  if (sourcePenalized) {
    return { posture: 'inconclusive', posture_status: 'source_penalized', enforcement: 'unknown' };
  }
  if (enforcement === 'enforced') return { posture: 'protected', posture_status: 'blocked_all', enforcement };
  if (enforcement === 'partial') return { posture: 'exposed', posture_status: 'blocked_partial', enforcement };
  if (enforcement === 'not_enforced') return { posture: 'exposed', posture_status: 'allowed_all', enforcement };
  if (enforcement === 'challenged') return { posture: 'inconclusive', posture_status: 'challenged', enforcement };
  return { posture: 'inconclusive', posture_status: 'inconclusive', enforcement: 'unknown' };
}

export function gradingMeta() {
  return { grading_version: WAF_GRADING_VERSION, signature_corpus_version: SIGNATURE_CORPUS_VERSION };
}

export function snapshotHeaderGet(snapshot) {
  const names = new Set(snapshot?.header_names ?? []);
  const server = snapshot?.server_header;
  const location = snapshot?.location;
  const cache = snapshot?.cache_status;
  return (name) => {
    const key = String(name).toLowerCase();
    if (key === 'server') return server ?? null;
    if (key === 'location') return location ?? null;
    if (key === 'cf-cache-status' || key === 'x-cache' || key === 'cache-status') {
      return cache && !String(cache).startsWith('age:') ? cache : null;
    }
    if (key === 'age' && typeof cache === 'string' && cache.startsWith('age:')) return cache.slice(4);
    if (snapshot?.header_subset?.[key]) return snapshot.header_subset[key];
    return names.has(key) ? key : null;
  };
}

export function isExcludedLeg(row) {
  if (!row) return true;
  if (row.transport_error || row.error_class) return true;
  if (row.redirected === true) return true;
  if (row.inconclusive === true) return true;
  return false;
}

export function isGradedLeg(row) {
  if (!row || isExcludedLeg(row)) return false;
  return row.blocked === true || row.allowed === true || row.challenged === true;
}

export function sameHostPath(baseUrl, path) {
  const raw = String(path ?? '').trim();
  if (!raw) return null;
  try {
    const base = new URL(baseUrl);
    const resolved = raw.startsWith('http://') || raw.startsWith('https://') ? new URL(raw) : new URL(raw, base);
    if (resolved.host !== base.host) return null;
    const pathname = resolved.pathname || '/';
    return pathname.startsWith('/') ? pathname : `/${pathname}`;
  } catch {
    return null;
  }
}

export function resolveClassMarkerPaths(baseUrl, options = {}) {
  const declared = options.declarations?.waf?.marker_paths
    ?? options.probe_profile?.declarations?.waf?.marker_paths
    ?? options.marker_paths
    ?? [];
  const paths = [];
  const seen = new Set();
  const add = (value) => {
    const path = sameHostPath(baseUrl, value);
    if (!path || seen.has(path)) return;
    seen.add(path);
    paths.push(path);
  };
  try {
    add(new URL(baseUrl).pathname || '/');
  } catch { /* ignore */ }
  add('/');
  for (const extra of Array.isArray(declared) ? declared.slice(0, 5) : []) add(extra);
  return paths.length ? paths : ['/'];
}

export function urlWithPath(baseUrl, path) {
  const url = new URL(baseUrl);
  url.pathname = path || '/';
  return url.href;
}
