import { createHmac, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import {
  buildProbeProfile,
  CAPABILITY_PROFILE_PASSTHROUGH_KEYS,
  normalizeProbeHttpPath,
  WAF_SAFE_PROBE_METADATA_KEYS,
} from '../contracts/checks.mjs';
import { signedOriginIdentityPair } from './originIdentityPair.mjs';
import {
  API_DOC_PATHS,
  RISKY_ADMIN_PORTS,
  minimumProbeRequestsForKind,
} from './capabilityProbes.mjs';
import { assertProbeDestinationAllowed } from './probeEndpoint.mjs';
import { generateNonce, hashNonce } from '../lib/crypto.mjs';
import {
  controlDeclarationsFromTarget,
  declaredPortsForBoundedScan,
  mapDeclaredBlockSignatureForProbe,
  probeDeclarationsSubset,
} from '../contracts/controlDeclarations.mjs';

function stableStringify(value) {
  if (value === undefined) {
    return 'null';
  }
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined ? 'null' : stableStringify(v))).join(',')}]`;
  }
  const keys = Object.keys(value).sort().filter((k) => value[k] !== undefined);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

const DEFAULT_MAX_REQUESTS = 1;
const DEFAULT_TIMEOUT_CAP_MS = 5000;
const RESOLVER_ATTEMPTS_PER_HOSTNAME = 2;
const EXTRA_DESTINATION_RESOLVER_ATTEMPTS_BY_KIND = new Map([
  ['dns_axfr_leak', RESOLVER_ATTEMPTS_PER_HOSTNAME],
]);

const CAPABILITY_ARRAY_OVERRIDE_KEYS = new Set(['ports', 'paths', 'secondary_nameservers', 'collect']);

const BENIGN_PROBE_PROFILE_OVERRIDE_KEYS = new Set([
  'marker',
  ...WAF_SAFE_PROBE_METADATA_KEYS,
  ...CAPABILITY_PROFILE_PASSTHROUGH_KEYS,
]);

const SAFE_TARGET_METADATA_KEYS = new Set([
  'alert_webhook_url',
  'webhook_url',
  'direct_origin_ip',
  'declared_apex_domain',
  'protected_host',
  'resolver_host',
  'zone',
  'graphql_path',
]);

const TARGET_TO_PROFILE_ALIASES = Object.freeze({
  direct_origin_ip: 'direct_ip',
});

function safeEqualUtf8(a, b) {
  if (!a || !b) return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/**
 * Keys whose values become outbound probe destinations. Anything unsafe here would be
 * HMAC-signed into the job and therefore trusted by the worker, so they are validated
 * before signing rather than after.
 */
const HOST_SHAPED_OVERRIDE_KEYS = new Set([
  'resolver_host',
  'direct_ip',
  'scan_host',
  'secondary_nameservers',
]);

const PROFILE_SOCKET_DESTINATION_KEYS = Object.freeze([
  'direct_ip',
  'resolver_host',
  'scan_host',
]);

// Domain-shaped fields can trigger DNS work even when they are not the initial worker
// destination. They may survive catalog, request-body, or target-metadata merges, so bind them
// only after every merge has completed.
const PROFILE_EXACT_TARGET_HOST_KEYS = Object.freeze([
  'zone',
  'recursion_test_name',
]);
const TARGET_METADATA_EXACT_TARGET_HOST_KEYS = new Set([
  'declared_apex_domain',
  'zone',
]);

const OVERRIDE_HOSTNAME_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const RISKY_ADMIN_PORT_SET = new Set(RISKY_ADMIN_PORTS);
const API_DOC_PATH_SET = new Set(API_DOC_PATHS);

/**
 * IP literals are classified immediately. Hostnames cannot be classified without DNS,
 * which the control plane must not perform at job-build time, so they are shape-checked
 * here and resolved + classified by the worker destination gate before any egress.
 *
 * @param {unknown} value
 */
function isHostShapedValueSafe(value) {
  if (typeof value !== 'string') return false;
  const candidate = value.trim();
  if (!candidate || candidate.length > 253) return false;

  if (isIP(candidate) !== 0) {
    return assertProbeDestinationAllowed(candidate).ok;
  }

  const lower = candidate.toLowerCase();
  const hostname = lower.endsWith('.') ? lower.slice(0, -1) : lower;
  if (
    !hostname
    || hostname.includes('://')
    || hostname.includes('@')
    || hostname.includes('/')
    || hostname.includes(':')
    || /\s/.test(hostname)
  ) {
    return false;
  }
  const labels = hostname.split('.');
  return labels.every((label) => label.length > 0 && OVERRIDE_HOSTNAME_LABEL.test(label));
}

function safePortOverride(entry) {
  const port = typeof entry === 'number' ? entry : Number(String(entry).trim());
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return RISKY_ADMIN_PORT_SET.has(port) ? port : null;
}

/**
 * Filter an array override down to values that survive per-key validation.
 * Returns null when nothing survives so the caller leaves the curated default in place.
 *
 * @param {string} key
 * @param {unknown[]} raw
 */
function filterArrayOverride(key, raw) {
  let values;
  if (key === 'ports') {
    values = raw.map(safePortOverride).filter((port) => port != null);
  } else if (key === 'paths') {
    values = raw
      .filter((entry) => typeof entry === 'string')
      .map((entry) => entry.trim())
      .filter((entry) => API_DOC_PATH_SET.has(entry));
  } else if (HOST_SHAPED_OVERRIDE_KEYS.has(key)) {
    values = raw
      .filter((entry) => isHostShapedValueSafe(entry))
      .map((entry) => String(entry).trim());
  } else {
    values = raw
      .map((entry) => (typeof entry === 'number' ? entry : String(entry).trim()))
      .filter((entry) => entry !== '' && entry != null);
  }
  const bounded = [...new Set(values)].slice(0, 16);
  return bounded.length > 0 ? bounded : null;
}

function mergeCapabilityOverride(merged, key, override) {
  if (key === 'nonce_hash_only') {
    if (override.nonce_hash_only === true) merged.nonce_hash_only = true;
    return;
  }
  if (CAPABILITY_ARRAY_OVERRIDE_KEYS.has(key)) {
    if (!Array.isArray(override[key])) return;
    const values = filterArrayOverride(key, override[key]);
    if (values) merged[key] = values;
    return;
  }
  if (key === 'use_https') {
    if (typeof override.use_https === 'boolean') merged.use_https = override.use_https;
    return;
  }
  if (key === 'graphql_path' || key === 'grpc_path') {
    const path = normalizeProbeHttpPath(override[key]);
    if (path) merged[key] = path;
    return;
  }
  if (override[key] == null) return;
  if (HOST_SHAPED_OVERRIDE_KEYS.has(key)) {
    // direct_ip is an address override, never a second hostname. Requiring a
    // classified literal also removes DNS rebinding from Host/SNI jobs.
    if (key === 'direct_ip' && (typeof override[key] !== 'string' || isIP(override[key].trim()) === 0)) return;
    // Drop unsafe destinations entirely so the curated default (or nothing) applies.
    if (!isHostShapedValueSafe(override[key])) return;
    merged[key] = String(override[key]).trim().slice(0, 128);
    return;
  }
  merged[key] = String(override[key]).slice(0, 128);
}

export function resolveJobProbeProfile(check, override) {
  const base = check?.probe_profile
    ? { ...check.probe_profile }
    : buildProbeProfile({ kind: 'metadata_marker' });
  if (override == null || typeof override === 'string') return base;
  if (typeof override !== 'object' || Array.isArray(override)) return base;
  const merged = { ...base };
  for (const key of BENIGN_PROBE_PROFILE_OVERRIDE_KEYS) {
    mergeCapabilityOverride(merged, key, override);
  }
  return buildProbeProfile(merged);
}

function enrichProbeProfileFromTarget(profile, target) {
  const raw = target?.metadata_json ?? target?.metadata;
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) return profile;
  const merged = { ...profile };
  for (const [targetKey, profileKey] of Object.entries(TARGET_TO_PROFILE_ALIASES)) {
    if (merged[profileKey] != null) continue;
    const value = raw[targetKey];
    if (typeof value === 'string' && value.trim()) {
      merged[profileKey] = value.trim().slice(0, 128);
    }
  }
  for (const key of CAPABILITY_PROFILE_PASSTHROUGH_KEYS) {
    if (merged[key] != null || raw[key] == null) continue;
    mergeCapabilityOverride(merged, key, raw);
  }
  return buildProbeProfile(merged);
}

function unbracketHost(value) {
  return String(value ?? '').trim().replace(/^\[|\]$/g, '');
}

function comparableHost(value) {
  const candidate = unbracketHost(value);
  if (!candidate) return null;
  return isIP(candidate) !== 0
    ? candidate.toLowerCase()
    : candidate.toLowerCase().replace(/\.$/, '');
}

function targetLogicalHost(target) {
  const value = String(target?.value ?? '').trim();
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) {
    try {
      return unbracketHost(new URL(value).hostname) || null;
    } catch {
      return null;
    }
  }
  const bracketed = value.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) return bracketed[1];
  if (isIP(value) !== 0) return value;
  const hostPort = value.match(/^([^:]+):(\d+)$/);
  return (hostPort ? hostPort[1] : value.split('/')[0]) || null;
}

/**
 * Maximum A/AAAA calls used only to classify socket destinations. Probe DNS queries remain
 * in the independent probe budget. AXFR can discover one nameserver mid-probe, requiring a
 * second bounded A/AAAA classification pair.
 */
export function initialDestinationResolverAttemptsForJob(probeProfile, target) {
  if (probeProfile?.kind === 'metadata_marker') return 0;
  if (probeProfile?.kind === 'origin_identity_pair') return RESOLVER_ATTEMPTS_PER_HOSTNAME;
  const host = targetLogicalHost(target);
  if (!host || isIP(host) !== 0) return 0;
  // DNS wire and DNSSEC posture discover the authoritative nameserver first, then classify
  // that hostname with one A and one AAAA lookup before opening UDP/TCP transport.
  return ['dns_wire_query', 'dnssec_posture'].includes(probeProfile?.kind)
    ? RESOLVER_ATTEMPTS_PER_HOSTNAME + 1
    : RESOLVER_ATTEMPTS_PER_HOSTNAME;
}

export function maxDestinationResolverAttemptsForJob(probeProfile, target) {
  const initialAttempts = initialDestinationResolverAttemptsForJob(probeProfile, target);
  return initialAttempts
    + (EXTRA_DESTINATION_RESOLVER_ATTEMPTS_BY_KIND.get(probeProfile?.kind) ?? 0);
}

export function targetLiteralIpAddress(target) {
  const value = String(target?.value ?? '').trim();
  if (/^https?:\/\//i.test(value)) {
    try {
      const host = unbracketHost(new URL(value).hostname);
      return isIP(host) !== 0 ? host : null;
    } catch {
      return null;
    }
  }
  if (target?.kind !== 'ip') return null;
  const host = unbracketHost(value);
  return isIP(host) !== 0 ? host : null;
}

export const ORIGIN_LOCKDOWN_CHECK_ID = 'nfw.origin_lockdown.safe';

export function isOriginLockdownHostnameCheck(check, target) {
  return check?.check_id === ORIGIN_LOCKDOWN_CHECK_ID
    && check?.probe_profile?.kind === 'host_sni_bypass'
    && !targetLiteralIpAddress(target);
}

function originLockdownRefusal(check, error, status, message, extra = {}) {
  return { error, status, check_id: check?.check_id ?? null, message, ...extra };
}

function publicOriginAddress(value) {
  const address = typeof value === 'string' ? unbracketHost(value) : '';
  if (!address || isIP(address) === 0) return null;
  return assertProbeDestinationAllowed(address).ok ? address : null;
}

export { resolveOriginLockdownBinding } from './originLockdownResolution.mjs';


export function originLockdownProvenance(resolved) {
  if (!resolved?.ok) return null;
  return {
    binding_id: resolved.binding_id,
    address: resolved.address,
    host: resolved.host,
    sni: resolved.sni,
    port: resolved.port,
    path: resolved.path,
    ...(resolved.authority ? { authority: structuredClone(resolved.authority) } : {}),
  };
}

export function runOriginLockdownScope(run, check, target) {
  if (!isOriginLockdownHostnameCheck(check, target)) return null;
  const stored = run?.provenance_json?.origin_lockdown;
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) return null;
  const scope = validatedOriginScopeSnapshot(stored);
  const address = publicOriginAddress(stored.address);
  const bindingId = typeof stored.binding_id === 'string' ? stored.binding_id.trim() : '';
  if (!scope || !address || !bindingId) return null;
  if (!isExactTargetHost(scope.host, targetLogicalHost(target))) return null;
  return { ...scope, address, binding_id: bindingId };
}

export function validateHostSniTargetBinding(check, target, { originLockdown = null, originBindings = null } = {}) {
  // Every account runs every check: destination/binding refusals never block dispatch.
  return null;
}

function isExactTargetHost(value, targetHost) {
  const candidate = comparableHost(value);
  return candidate != null && candidate === comparableHost(targetHost);
}

/**
 * Exact protected Host/SNI/port/path of a bound run. Only the server-validated scope that
 * startTestRun captured in the run's provenance stamp (after both current proofs and the
 * exact-existing-binding check) is trusted here. A request probe profile or target metadata
 * can never introduce a binding scope, and no scope at all means the run is not bound
 * (legacy unbound behavior).
 *
 * @param {{ origin_binding_id?: unknown, provenance_json?: unknown }} run
 * @param {{ probe_profile?: { kind?: unknown } }} check
 * @returns {{ host: string, sni: string, port: number | null, path: string | null } | null}
 */
export function runBoundOriginScope(run, check) {
  if (!['host_sni_bypass', 'origin_identity_pair'].includes(check?.probe_profile?.kind)) return null;
  const bindingId = typeof run?.origin_binding_id === 'string' ? run.origin_binding_id.trim() : '';
  if (!bindingId) return null;
  return validatedOriginScopeSnapshot(run?.provenance_json?.origin_scope);
}

function validatedOriginScopeSnapshot(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
  const host = typeof candidate.host === 'string' ? candidate.host.trim().toLowerCase() : null;
  const sni = typeof candidate.sni === 'string' ? candidate.sni.trim().toLowerCase() : null;
  if (!host || !sni || host !== sni || !isHostShapedValueSafe(host)) return null;
  let port = null;
  if (candidate.port != null) {
    if (typeof candidate.port !== 'number') return null;
    port = candidate.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  }
  let path = null;
  if (candidate.path != null) {
    if (
      typeof candidate.path !== 'string'
      || !candidate.path.startsWith('/')
      || candidate.path.startsWith('//')
      || candidate.path.includes('\\')
      || candidate.path.includes('@')
      || candidate.path.includes('?')
      || candidate.path.includes('#')
      || candidate.path.includes('://')
      || /[\u0000-\u0020\u007f]/.test(candidate.path)
      || candidate.path.length > 256
    ) {
      return null;
    }
    path = candidate.path;
  }
  return { host, sni, port, path };
}

const NO_CALLER_DESTINATIONS = Object.freeze(new Set());

/**
 * Final signed-job destination boundary. This runs after catalog, request, and target metadata
 * merges. A destination the caller put in the request body is an explicit instruction and is
 * kept as-is; everything inherited from the catalog or target metadata is bound to the target
 * so no earlier source can retarget a worker job on its own. Host/SNI labels and HTTP path
 * fields are intentionally unaffected: they do not select a socket or DNS destination.
 *
 * @param {Record<string, unknown>} profile
 * @param {Record<string, unknown>} target
 * @param {Set<string>} callerKeys keys the request body supplied
 */
function bindProbeProfileDestinationsToTarget(profile, target, callerKeys = NO_CALLER_DESTINATIONS) {
  const bound = { ...profile };
  const targetHost = targetLogicalHost(target);
  const canonicalTargetHost = comparableHost(targetHost);
  const targetIp = targetLiteralIpAddress(target);
  const callerSupplied = (key) => callerKeys.has(key) && bound[key] != null;

  for (const key of PROFILE_SOCKET_DESTINATION_KEYS) {
    if (callerSupplied(key)) continue;
    if (!targetIp || !isExactTargetHost(bound[key], targetIp)) delete bound[key];
  }

  for (const key of PROFILE_EXACT_TARGET_HOST_KEYS) {
    const exact = canonicalTargetHost && isExactTargetHost(bound[key], canonicalTargetHost);
    if (callerSupplied(key)) {
      // A caller-named zone/lookup name points the worker somewhere on purpose; only the
      // spelling is canonicalized when it happens to be the target itself.
      if (exact) bound[key] = canonicalTargetHost;
      continue;
    }
    if (exact) {
      bound[key] = canonicalTargetHost;
    } else {
      delete bound[key];
    }
  }

  const resolvers = Array.isArray(bound.secondary_nameservers) ? bound.secondary_nameservers : [];
  const canonicalResolver = (value) => (
    canonicalTargetHost && isExactTargetHost(value, canonicalTargetHost) ? canonicalTargetHost : value
  );
  if (callerSupplied('secondary_nameservers') && resolvers.length > 0) {
    // Keep every resolver the caller named, canonicalizing only the target's own spelling.
    bound.secondary_nameservers = resolvers.map(canonicalResolver);
  } else if (resolvers.some((value) => canonicalResolver(value) === canonicalTargetHost) && canonicalTargetHost) {
    bound.secondary_nameservers = [canonicalTargetHost];
  } else {
    delete bound.secondary_nameservers;
  }

  return buildProbeProfile(bound);
}

/**
 * Destination keys the request body supplied with a usable value. An unsafe value dropped by the
 * merge never shields an inherited catalog default from target binding.
 */
function callerDestinationKeys(check, override) {
  if (override == null || typeof override !== 'object' || Array.isArray(override)) {
    return NO_CALLER_DESTINATIONS;
  }
  const resolved = resolveJobProbeProfile(check, override);
  const keys = new Set();
  for (const key of Object.keys(override)) {
    if (!BENIGN_PROBE_PROFILE_OVERRIDE_KEYS.has(key)) continue;
    const isDestination = PROFILE_SOCKET_DESTINATION_KEYS.includes(key)
      || PROFILE_EXACT_TARGET_HOST_KEYS.includes(key)
      || key === 'secondary_nameservers';
    if (!isDestination || !callerDestinationAccepted(key, override[key])) continue;
    // The merge may still have dropped it for another reason (e.g. catalog filtering).
    if (resolved[key] != null) keys.add(key);
  }
  return keys;
}

function callerDestinationAccepted(key, value) {
  if (key === 'secondary_nameservers') {
    return Array.isArray(value) && filterArrayOverride(key, value) != null;
  }
  if (typeof value !== 'string' || !value.trim()) return false;
  // direct_ip is an address override, exactly as the merge rule requires.
  if (key === 'direct_ip') return isIP(value.trim()) !== 0;
  return isHostShapedValueSafe(value);
}

export function normalizeJobConstraints(safetyConstraints, probeProfile, target = null) {
  const src = safetyConstraints ?? {};
  const out = {};
  if (src.max_events != null) out.max_events = src.max_events;
  if (src.max_duration_seconds != null) out.max_duration_seconds = src.max_duration_seconds;
  if (src.max_concurrent_runs_per_target_group != null) {
    out.max_concurrent_runs_per_target_group = src.max_concurrent_runs_per_target_group;
  }
  let maxRequests =
    probeProfile?.max_requests != null ? probeProfile.max_requests : DEFAULT_MAX_REQUESTS;
  const mandatoryRequests = minimumProbeRequestsForKind(probeProfile?.kind);
  if (maxRequests < mandatoryRequests) {
    throw new RangeError(
      `${probeProfile.kind} requires a signed max_requests budget of ${mandatoryRequests}`,
    );
  }
  if (src.max_requests != null) {
    if (src.max_requests < mandatoryRequests) {
      throw new RangeError(
        `${probeProfile.kind} requires a signed max_requests budget of ${mandatoryRequests}`,
      );
    }
    maxRequests = Math.min(maxRequests, src.max_requests);
  }
  const minDestinationResolverAttempts = initialDestinationResolverAttemptsForJob(
    probeProfile,
    target,
  );
  const maxDestinationResolverAttempts = maxDestinationResolverAttemptsForJob(
    probeProfile,
    target,
  );
  // max_requests is the signed total logical-operation cap. Keep a distinct probe cap so
  // additive destination classification allowance can never authorize extra probe egress.
  out.max_probe_requests = maxRequests;
  out.min_destination_resolver_attempts = minDestinationResolverAttempts;
  out.max_destination_resolver_attempts = maxDestinationResolverAttempts;
  out.max_total_operations = maxRequests + maxDestinationResolverAttempts;
  out.max_requests = out.max_total_operations;
  let timeoutMs;
  if (src.timeout_ms != null) {
    timeoutMs = src.timeout_ms;
  } else {
    const fromDuration =
      src.max_duration_seconds != null
        ? Math.floor(Number(src.max_duration_seconds) * 1000)
        : DEFAULT_TIMEOUT_CAP_MS;
    const derived = Number.isFinite(fromDuration) ? fromDuration : DEFAULT_TIMEOUT_CAP_MS;
    timeoutMs = Math.min(derived, DEFAULT_TIMEOUT_CAP_MS);
  }
  if (probeProfile?.timeout_ms != null) {
    timeoutMs = Math.min(timeoutMs, probeProfile.timeout_ms);
  }
  out.timeout_ms = Math.min(timeoutMs, DEFAULT_TIMEOUT_CAP_MS);
  return out;
}

function safeTargetMetadata(target) {
  const raw = target.metadata_json ?? target.metadata;
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const metadata = {};
  const targetHost = targetLogicalHost(target);
  const canonicalTargetHost = comparableHost(targetHost);
  const targetIp = targetLiteralIpAddress(target);
  for (const key of SAFE_TARGET_METADATA_KEYS) {
    const value = raw[key];
    if (typeof value !== 'string' || !value.trim()) continue;
    const candidate = value.trim();
    if (TARGET_METADATA_EXACT_TARGET_HOST_KEYS.has(key)) {
      if (canonicalTargetHost && isExactTargetHost(candidate, canonicalTargetHost)) {
        metadata[key] = canonicalTargetHost;
      }
      continue;
    }
    if (key === 'direct_origin_ip' || key === 'resolver_host') {
      if (targetIp && isExactTargetHost(candidate, targetIp)) metadata[key] = candidate.slice(0, 512);
      continue;
    }
    if (key === 'alert_webhook_url' || key === 'webhook_url') {
      try {
        const webhookHost = unbracketHost(new URL(candidate).hostname);
        if (targetHost && isExactTargetHost(webhookHost, targetHost)) {
          metadata[key] = candidate.slice(0, 512);
        }
      } catch {
        // Invalid URLs cannot become signed worker destinations.
      }
      continue;
    }
    metadata[key] = candidate.slice(0, 512);
  }
  return Object.keys(metadata).length > 0 ? metadata : null;
}

export function targetDescriptor(target) {
  const out = {
    id: target.id,
    kind: target.kind,
    value: target.value,
    expected_behavior: target.expected_behavior ?? null,
  };
  if (target.port != null) out.port = target.port;
  if (target.protocol != null) out.protocol = target.protocol;
  const metadata = safeTargetMetadata(target);
  if (metadata) out.metadata = metadata;
  return out;
}

export const PROBE_AUTHORITY_VERSION = 'probe-authority-v2';
export const MAX_PROBE_AUTHORITY_MS = 120_000;

export function probeAuthority(job, now = Date.now()) {
  const expires = Date.parse(job?.constraints?.not_after);
  const issued = Date.parse(job?.constraints?.issued_at);
  const at = now instanceof Date ? now.getTime() : Number(now);
  if (job?.constraints?.authority_version !== PROBE_AUTHORITY_VERSION
    || !Number.isFinite(expires) || !Number.isFinite(issued) || expires <= issued
    || expires - issued > MAX_PROBE_AUTHORITY_MS || issued > at + 1000) {
    return { ok: false, reason: 'probe_authority_invalid', remaining_ms: 0 };
  }
  if (!Number.isFinite(at) || at >= expires) return { ok: false, reason: 'probe_authority_expired', remaining_ms: 0 };
  return { ok: true, not_after: new Date(expires).toISOString(), remaining_ms: expires - at };
}

function canonicalJobSigningPayload(job) {
  return stableStringify({
    check_id: job.check_id,
    constraints: job.constraints,
    id: job.id,
    nonce_hash: job.nonce_hash,
    probe_profile: job.probe_profile,
    target: job.target,
    tenant_id: job.tenant_id,
    test_run_id: job.test_run_id,
  });
}

export function signProbeJob(job, secret) {
  return createHmac('sha256', secret)
    .update(canonicalJobSigningPayload(job), 'utf8')
    .digest('hex');
}

export function verifyProbeJobSignature(job, secret) {
  if (!job?.job_signature || !secret) return false;
  const signingJob = {
    check_id: job.check_id,
    constraints: job.constraints,
    id: job.id,
    nonce_hash: job.nonce_hash,
    probe_profile: job.probe_profile,
    target: job.target,
    tenant_id: job.tenant_id,
    test_run_id: job.test_run_id,
  };
  const expected = signProbeJob(signingJob, secret);
  return safeEqualUtf8(job.job_signature, expected);
}

/**
 * A bound run (non-empty `origin_binding_id`) whose provenance stamp carries no shape-valid
 * approved origin scope snapshot must never dispatch. Thrown before any signing, job record,
 * or dispatch exists, so a bound legacy/recovery record can never silently fall back to the
 * legacy unbound host resolution (e.g. re-targeting from target metadata `protected_host`).
 * Recovery and run-start callers must translate this into a structured fail-closed response;
 * the runtime request body can never repair a missing stored scope.
 */
export class BoundRunScopeMissingError extends Error {
  constructor(checkId) {
    super('bound_run_missing_approved_origin_scope');
    this.name = 'BoundRunScopeMissingError';
    this.code = 'bound_run_missing_approved_origin_scope';
    this.check_id = checkId ?? null;
  }
}

export class OriginLockdownBindingMissingError extends Error {
  constructor(checkId) {
    super('origin_lockdown_binding_missing');
    this.name = 'OriginLockdownBindingMissingError';
    this.code = 'origin_lockdown_binding_missing';
    this.check_id = checkId ?? null;
  }
}

const PERSPECTIVE_ID_PATTERN = /^[a-z0-9-]{1,32}$/;
export const PERSPECTIVE_ROUTED_CHECK_IDS = Object.freeze(['nfw.perspective_allowlist.safe']);

export function isValidPerspectiveId(value) {
  return typeof value === 'string' && PERSPECTIVE_ID_PATTERN.test(value);
}

// Declared denied perspectives first: only a denied perspective can observe an allowlist violation.
export function requiredPerspectiveIdForJob(check, declarations) {
  const fromCatalog = check?.probe_profile?.required_perspective_id;
  if (isValidPerspectiveId(fromCatalog)) return fromCatalog;
  if (!PERSPECTIVE_ROUTED_CHECK_IDS.includes(check?.check_id)) return null;
  const perspectives = declarations?.perspectives;
  const candidates = [
    ...(Array.isArray(perspectives?.denied_perspective_ids) ? perspectives.denied_perspective_ids : []),
    ...(Array.isArray(perspectives?.allowlisted_perspective_ids) ? perspectives.allowlisted_perspective_ids : []),
  ];
  return candidates.find(isValidPerspectiveId) ?? null;
}

export function jobClaimableByPerspective(job, perspectiveId) {
  const required = job?.constraints?.required_perspective_id;
  if (required == null || required === '') return true;
  return isValidPerspectiveId(perspectiveId) && perspectiveId === required;
}

export function attachControlDeclarationsToProfile(profile, check, declarations) {
  if (!declarations || typeof declarations !== 'object' || Array.isArray(declarations)) return profile;
  const next = { ...profile, declarations: probeDeclarationsSubset(declarations, check) };
  const mapped = mapDeclaredBlockSignatureForProbe(declarations);
  if (mapped) next.declared_block_signature = mapped;
  if (next.kind === 'port_scan_bounded') {
    const ports = declaredPortsForBoundedScan(declarations);
    if (ports.length) next.declared_ports = ports;
  }
  return next;
}

/**
 * @param {{
 *   run: { id: string, tenant_id: string, safety_constraints?: Record<string, unknown>, origin_binding_id?: unknown, provenance_json?: unknown },
 *   check: Record<string, unknown>,
 *   target: Record<string, unknown>,
 *   probeProfile?: unknown,
 *   ownershipBinding?: Record<string, unknown> | null,
 *   declarations?: Record<string, unknown> | null,
 *   probeWorkerSecret: string,
 *   now: Date,
 *   newId: () => string,
 * }} params
 */
export function buildSignedProbeJobRecord({
  run,
  check,
  target,
  probeProfile,
  ownershipBinding = null,
  declarations = undefined,
  probeWorkerSecret,
  now,
  newId,
}) {
  if (Object.hasOwn(run?.safety_constraints ?? {}, 'reviewed_operation_binding')) {
    throw new Error('reviewed_operation_execution_unavailable');
  }
  // Fail closed FIRST: a bound record without a validated approved scope snapshot cannot
  // dispatch, and no target metadata (e.g. protected_host) may stand in for the scope.
  const boundByOriginBinding = typeof run?.origin_binding_id === 'string' && run.origin_binding_id.trim() !== '';
  if (boundByOriginBinding) {
    const approvedScope = runBoundOriginScope(run, check);
    if (!approvedScope) throw new BoundRunScopeMissingError(check?.check_id);
  }
  const lockdownScope = runOriginLockdownScope(run, check, target);
  if (isOriginLockdownHostnameCheck(check, target) && !lockdownScope) {
    throw new OriginLockdownBindingMissingError(check?.check_id);
  }
  const storedDeclarations = declarations === undefined ? controlDeclarationsFromTarget(target) : declarations;
  const nonce = generateNonce();
  const nonce_hash = hashNonce(nonce);
  let resolvedProbeProfile = bindProbeProfileDestinationsToTarget(
    enrichProbeProfileFromTarget(
      resolveJobProbeProfile(check, probeProfile),
      target,
    ),
    target,
    callerDestinationKeys(check, probeProfile),
  );
  const signedTarget = targetDescriptor(target);
  const bindingScope = runBoundOriginScope(run, check);
  if (bindingScope) {
    // Bound run: the approved signed scope is the exact protected Host (SNI by derivation
    // always equals the bound host). Silently overriding the merged catalog/body/metadata
    // label here is what the worker executes and what the signature covers.
    resolvedProbeProfile = { ...resolvedProbeProfile, protected_host: bindingScope.host };
  }
  if (lockdownScope) {
    resolvedProbeProfile = {
      ...resolvedProbeProfile,
      protected_host: lockdownScope.host,
      direct_ip: lockdownScope.address,
    };
  }
  resolvedProbeProfile = attachControlDeclarationsToProfile(resolvedProbeProfile, check, storedDeclarations);
  const requiredPerspectiveId = requiredPerspectiveIdForJob(check, storedDeclarations);
  const signedOriginScope = bindingScope ?? (lockdownScope
    ? { host: lockdownScope.host, sni: lockdownScope.sni, port: lockdownScope.port, path: lockdownScope.path }
    : null);
  const baseConstraints = normalizeJobConstraints(
    run.safety_constraints,
    resolvedProbeProfile,
    signedTarget,
  );
  const issuedAt = run.created_at == null ? now.getTime() : Date.parse(run.created_at);
  if (!Number.isFinite(issuedAt)) throw new Error('probe_authority_invalid');
  const deadlines = [issuedAt + (check.probe_profile?.kind === 'origin_identity_pair' ? 60_000 : MAX_PROBE_AUTHORITY_MS), Date.parse(run.collection_deadline_at),
    Date.parse(run.safety_constraints?.safe_window_not_after)].filter(Number.isFinite);
  const constraints = {
    ...baseConstraints,
    authority_version: PROBE_AUTHORITY_VERSION,
    issued_at: new Date(issuedAt).toISOString(),
    not_after: new Date(Math.min(...deadlines)).toISOString(),
    execution_attempts: 1,
    ...(ownershipBinding && typeof ownershipBinding === 'object'
      ? { ownership_binding: structuredClone(ownershipBinding) }
      : {}),
    ...(signedOriginScope ? { origin_scope: { ...signedOriginScope } } : {}),
    ...((run.provenance_json?.origin_authority ?? run.provenance_json?.origin_lockdown?.authority)
      ? { origin_authority: structuredClone(run.provenance_json.origin_authority ?? run.provenance_json.origin_lockdown.authority) } : {}),
    ...(check.probe_profile?.kind === 'origin_identity_pair'
      ? { origin_identity_pair: structuredClone(run.provenance_json?.origin_identity_pair ?? null) } : {}),
    ...(requiredPerspectiveId ? { required_perspective_id: requiredPerspectiveId } : {}),
  };
  const job = {
    id: newId(),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: target.id,
    check_id: check.check_id,
    vector_family: check.vector_family,
    status: 'pending',
    created_at: now.toISOString(),
    nonce_hash,
    nonce,
    probe_profile: resolvedProbeProfile,
    constraints,
    target: signedTarget,
    worker_metadata: {
      check_title: check.title ?? check.check_id,
      safety_class: check.safety_class ?? check.risk_class ?? null,
    },
    leased_at: null,
    leased_by: null,
    completed_at: null,
  };
  if (check.probe_profile?.kind === 'origin_identity_pair' && !signedOriginIdentityPair(job)) {
    throw Object.assign(new Error('origin_identity_review_required'), { code: 'origin_identity_review_required' });
  }
  job.job_signature = signProbeJob(job, probeWorkerSecret);
  return job;
}
