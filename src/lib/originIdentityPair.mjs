// Exact, reviewed two-endpoint identity comparison. Clues never enter this authority path.
import { isDeepStrictEqual } from 'node:util';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { sha256Digest } from '../contracts/protectionValidation.mjs';
import { effectiveTargetVerifications } from './effectiveTargetVerification.mjs';
import { ownershipProofFromStates } from './ownershipPolicy.mjs';
import { assertProbeDestinationAllowed } from './probeEndpoint.mjs';

export const ORIGIN_IDENTITY_PAIR_SCENARIOS = Object.freeze({
  'origin.identity_pair.head.v1': { method: 'HEAD', version: 'origin-identity-head-v1' },
  'origin.identity_pair.get.v1': { method: 'GET', version: 'origin-identity-get-v1' },
});
export const ORIGIN_IDENTITY_PAIR_LIMITS = Object.freeze({
  http_requests: 2, dns_queries: 2, response_body_bytes_per_leg: 8192,
  response_body_bytes_total: 16384, duration_ms: 5000, comparability_ms: 60000,
  redirects: 0, extra_assets: 0,
});

export function originIdentityScenario(check) {
  if (check?.probe_profile?.kind !== 'origin_identity_pair') return null;
  return ORIGIN_IDENTITY_PAIR_SCENARIOS[check.check_id] ?? null;
}

export function originIdentityTargetDescriptor(target) {
  return { id: target.id, kind: target.kind, value: target.value,
    port: target.port ?? null, protocol: target.protocol ?? null };
}

export function originIdentityProofBinding(records, tenantId, targetId) {
  const row = effectiveTargetVerifications(records ?? {}, tenantId, [targetId]).get(targetId);
  if (!ownershipProofFromStates({ targetState: row?.state }).verified || !Number.isFinite(Date.parse(row?.transitioned_at))) return null;
  return { target_id: targetId, state: row.state, kind: row.source_kind,
    transitioned_at: row.transitioned_at, inherited_from_target_id: row.inherited_from_target_id ?? null,
    source_ref_digest: sha256Digest(row.source_ref ?? {}) };
}

function targetHost(target) {
  try { return new URL(target.value).hostname.replace(/^\[|\]$/g, '').toLowerCase(); }
  catch { return String(target?.value ?? '').replace(/^\[|\]$/g, '').toLowerCase(); }
}

/** Passive plan, built only from the already verified binding and exact declared targets. */
export function planOriginIdentityPair({ check, binding, originTarget, protectedTarget, scope, records, tenantId } = {}) {
  const scenario = originIdentityScenario(check);
  if (!scenario || !binding || binding.status !== 'active' || binding.tenant_id !== tenantId
    || originTarget?.tenant_id !== tenantId || protectedTarget?.tenant_id !== tenantId
    || binding.origin_target_id !== originTarget?.id || binding.protected_target_id !== protectedTarget?.id) return null;
  const address = targetHost(originTarget);
  if (!isIP(address) || !assertProbeDestinationAllowed(address).ok || targetHost(protectedTarget) !== scope?.host
    || scope.host !== scope.sni) return null;
  const originProof = originIdentityProofBinding(records, tenantId, originTarget.id);
  const protectedProof = originIdentityProofBinding(records, tenantId, protectedTarget.id);
  if (!originProof || !protectedProof) return null;
  let scheme = 'https';
  if (protectedTarget.kind === 'url') {
    let url;
    try { url = new URL(protectedTarget.value); } catch { return null; }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) return null;
    scheme = url.protocol.slice(0, -1);
  }
  const port = scope.port ?? (scheme === 'https' ? 443 : 80);
  const path = scope.path ?? '/';
  if (!Number.isInteger(port) || port < 1 || port > 65535 || typeof path !== 'string'
    || !path.startsWith('/') || path.startsWith('//') || /[\\?#@\s\u0000-\u001f\u007f]/.test(path)
    || path.length > 256) return null;
  return { version: scenario.version, method: scenario.method, binding_id: binding.id,
    origin_target: originIdentityTargetDescriptor(originTarget), protected_target: originIdentityTargetDescriptor(protectedTarget),
    origin_ownership_binding: originProof, protected_ownership_binding: protectedProof,
    address, host: scope.host, sni: scope.sni, port, path, scheme,
    limits: { ...ORIGIN_IDENTITY_PAIR_LIMITS } };
}

/** The reviewed item must be revalidated by the existing comparison scope lifecycle first. */
export function buildOriginIdentityPairSnapshot({ reviewedPair, ...input } = {}) {
  const plan = planOriginIdentityPair(input);
  if (!plan || !reviewedPair || !isDeepStrictEqual(plan, reviewedPair.plan)
    || typeof reviewedPair.comparison_id !== 'string' || !/^[a-f0-9]{64}$/.test(reviewedPair.scope_digest ?? '')) {
    return { error: 'origin_identity_review_required', status: 409 };
  }
  return { ok: true, snapshot: { ...plan, comparison_id: reviewedPair.comparison_id, scope_digest: reviewedPair.scope_digest } };
}

/** Worker shape check before DNS or any socket. All fields are HMAC-covered by the job. */
export function signedOriginIdentityPair(job) {
  const scenario = ORIGIN_IDENTITY_PAIR_SCENARIOS[job?.check_id];
  const pair = job?.constraints?.origin_identity_pair;
  const scope = job?.constraints?.origin_scope;
  const authorityMs = Date.parse(job?.constraints?.not_after) - Date.parse(job?.constraints?.issued_at);
  if (!scenario || job?.probe_profile?.kind !== 'origin_identity_pair' || !pair
    || pair.version !== scenario.version || pair.method !== scenario.method
    || job.probe_profile.scenario_version !== scenario.version
    || !isDeepStrictEqual(pair.limits, ORIGIN_IDENTITY_PAIR_LIMITS)
    || job.probe_profile.max_requests !== 2 || job.constraints.max_probe_requests !== 2
    || job.constraints.max_destination_resolver_attempts !== 2 || job.constraints.max_total_operations !== 4
    || !Number.isFinite(authorityMs) || authorityMs <= 0 || authorityMs > ORIGIN_IDENTITY_PAIR_LIMITS.comparability_ms
    || !pair.binding_id || !pair.comparison_id || !/^[a-f0-9]{64}$/.test(pair.scope_digest ?? '')
    || !['http', 'https'].includes(pair.scheme)
    || pair.host !== pair.sni || !scope || scope.host !== pair.host || scope.sni !== pair.sni
    || (scope.port ?? (pair.scheme === 'https' ? 443 : 80)) !== pair.port || (scope.path ?? '/') !== pair.path
    || !Number.isInteger(pair.port) || pair.port < 1 || pair.port > 65535
    || typeof pair.path !== 'string' || pair.path.length > 256 || !pair.path.startsWith('/')
    || pair.path.startsWith('//') || /[\\?#@\s\u0000-\u001f\u007f]/.test(pair.path)
    || targetHost(pair.protected_target) !== pair.host
    || pair.origin_target?.id !== job.target?.id || pair.origin_target?.kind !== job.target?.kind
    || pair.origin_target?.value !== job.target?.value || (pair.origin_target?.port ?? null) !== (job.target?.port ?? null)
    || (pair.origin_target?.protocol ?? null) !== (job.target?.protocol ?? null)
    || targetHost(job.target) !== pair.address || !isIP(pair.address) || !assertProbeDestinationAllowed(pair.address).ok) return null;
  for (const [proof, target] of [[pair.origin_ownership_binding, pair.origin_target], [pair.protected_ownership_binding, pair.protected_target]]) {
    if (proof?.target_id !== target?.id || !ownershipProofFromStates({ targetState: proof?.state }).verified
      || !proof.kind || !Number.isFinite(Date.parse(proof.transitioned_at)) || !/^[a-f0-9]{64}$/.test(proof.source_ref_digest ?? '')) return null;
  }
  return pair;
}

const GENERIC_PAGE = /(?:access denied|forbidden|captcha|just a moment|checking your browser|default (?:web|server)|welcome to nginx|apache2? (?:ubuntu|debian) default|index of \/|service unavailable|error [45]\d\d)/i;
export function originIdentityBodyIsGeneric(body) { return GENERIC_PAGE.test(String(body ?? '')); }
function fingerprint(leg) {
  if (!leg || leg.response?.status < 200 || leg.response?.status >= 300 || !leg.body_complete || leg.error) return null;
  const body = leg.body_text ?? '';
  if (Buffer.byteLength(body) < 128 || originIdentityBodyIsGeneric(body)) return null;
  const tags = body.match(/<\/?[a-z][a-z0-9:-]*/gi) ?? [];
  return { sha256: createHash('sha256').update(body).digest('hex'),
    title: body.match(/<title[^>]*>([^<]{1,256})<\/title\s*>/i)?.[1]?.trim() ?? null,
    // A bounded linear tag sequence is supporting only, never a similarity/identity threshold.
    structure: tags.length ? createHash('sha256').update(tags.join('|').toLowerCase()).digest('hex') : null };
}

export function originIdentityContentSupport(baseline, direct) {
  const left = fingerprint(baseline);
  const right = fingerprint(direct);
  const usable = Boolean(left && right);
  const signals = usable ? [left.sha256 === right.sha256 ? 'complete_body_hash_match' : null,
    left.title && left.title === right.title ? 'title_match' : null,
    left.structure && left.structure === right.structure ? 'structure_match' : null].filter(Boolean) : [];
  return { suspected_application_association: signals.length > 0, supporting_signals: signals,
    content_complete: usable, nonce_confirmed: false,
    limitations: ['content_similarity_is_supporting_only', 'single_baseline_stability_not_established',
      'certificate_names_do_not_establish_current_origin_identity'] };
}
