import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  buildProbeProfile,
  CAPABILITY_PROFILE_PASSTHROUGH_KEYS,
  WAF_SAFE_PROBE_METADATA_KEYS,
} from '../contracts/checks.mjs';
import { generateNonce, hashNonce } from '../lib/crypto.mjs';
import { stableStringify } from './agentUpdates.mjs';

const DEFAULT_MAX_REQUESTS = 1;
const DEFAULT_TIMEOUT_CAP_MS = 5000;

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

function mergeCapabilityOverride(merged, key, override) {
  if (key === 'nonce_hash_only') {
    if (override.nonce_hash_only === true) merged.nonce_hash_only = true;
    return;
  }
  if (CAPABILITY_ARRAY_OVERRIDE_KEYS.has(key)) {
    if (!Array.isArray(override[key])) return;
    const values = override[key]
      .map((entry) => (typeof entry === 'number' ? entry : String(entry).trim()))
      .filter((entry) => entry !== '' && entry != null)
      .slice(0, 16);
    if (values.length > 0) merged[key] = values;
    return;
  }
  if (key === 'use_https') {
    if (typeof override.use_https === 'boolean') merged.use_https = override.use_https;
    return;
  }
  if (override[key] != null) {
    merged[key] = String(override[key]).slice(0, 128);
  }
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

export function normalizeJobConstraints(safetyConstraints, probeProfile) {
  const src = safetyConstraints ?? {};
  const out = {};
  if (src.max_events != null) out.max_events = src.max_events;
  if (src.max_duration_seconds != null) out.max_duration_seconds = src.max_duration_seconds;
  if (src.max_concurrent_runs_per_target_group != null) {
    out.max_concurrent_runs_per_target_group = src.max_concurrent_runs_per_target_group;
  }
  let maxRequests =
    probeProfile?.max_requests != null ? probeProfile.max_requests : DEFAULT_MAX_REQUESTS;
  if (src.max_requests != null) {
    maxRequests = Math.min(maxRequests, src.max_requests);
  }
  out.max_requests = maxRequests;
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
  for (const key of SAFE_TARGET_METADATA_KEYS) {
    const value = raw[key];
    if (typeof value === 'string' && value.trim()) {
      metadata[key] = value.trim().slice(0, 512);
    }
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
 * @param {{
 *   run: { id: string, tenant_id: string, safety_constraints?: Record<string, unknown> },
 *   check: Record<string, unknown>,
 *   target: Record<string, unknown>,
 *   probeProfile?: unknown,
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
  probeWorkerSecret,
  now,
  newId,
}) {
  const nonce = generateNonce();
  const nonce_hash = hashNonce(nonce);
  const resolvedProbeProfile = enrichProbeProfileFromTarget(
    resolveJobProbeProfile(check, probeProfile),
    target,
  );
  const constraints = normalizeJobConstraints(run.safety_constraints, resolvedProbeProfile);
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
    target: targetDescriptor(target),
    worker_metadata: {
      check_title: check.title ?? check.check_id,
      safety_class: check.safety_class ?? check.risk_class ?? null,
    },
    leased_at: null,
    leased_by: null,
    completed_at: null,
  };
  job.job_signature = signProbeJob(job, probeWorkerSecret);
  return job;
}