import { probeAuthority } from './probeJobs.mjs';
import { canonicalJsonStringify } from './custody.mjs';
import { createHash } from 'node:crypto';

export function executionReservation(job, workerId, leasedAt, id, now = new Date()) {
  if (job?.status !== 'leased' || job.leased_at !== leasedAt) return { error: 'probe_execution_lease_mismatch', status: 409 };
  if (!workerId || job.leased_by !== workerId) return { error: 'job_leased_to_another_worker', status: 403 };
  const authority = probeAuthority(job, now);
  if (!authority.ok) return { error: authority.reason, status: 409 };
  if (job.worker_metadata?.execution_reservation) return { error: 'probe_budget_already_reserved', status: 409 };
  const constraints = job.constraints ?? {};
  const probe = constraints.max_probe_requests;
  const resolver = constraints.max_destination_resolver_attempts;
  const total = constraints.max_total_operations;
  if (![probe, resolver, total].every((value) => Number.isSafeInteger(value) && value >= 0 && value <= 1024)
    || probe + resolver !== total || constraints.max_requests !== total || constraints.execution_attempts !== 1) {
    return { error: 'probe_operation_budget_invalid', status: 409 };
  }
  // Reserve the whole signed allowance before dispatch. Unknown operations are never refunded;
  // a crash/reclaim requires a separately reviewed new run, not another execution of this job.
  return { reservation: { version: 'execution-reservation.v1', id, worker_id: workerId, leased_at: leasedAt,
    reserved_at: now.toISOString(), not_after: authority.not_after, max_probe_requests: probe,
    max_destination_resolver_attempts: resolver, max_total_operations: total, state: 'reserved_unknown' } };
}

export function probeExecutionReceipt(job, workerId, attestation, externalResult) {
  if (attestation?.requests_sent === 0 && ['error', 'not_run'].includes(externalResult)) return { ok: true };
  const reservation = job?.worker_metadata?.execution_reservation;
  const constraints = job?.constraints ?? {};
  const reservedAt = Date.parse(reservation?.reserved_at);
  const authority = probeAuthority(job, reservedAt);
  if (!authority.ok || !reservation || reservation.version !== 'execution-reservation.v1'
    || job.status !== 'leased' || !job.leased_at || job.leased_by !== workerId
    || reservation.worker_id !== workerId || reservation.leased_at !== job.leased_at
    || reservation.not_after !== constraints.not_after
    || reservedAt < Date.parse(constraints.issued_at)
    || ['max_probe_requests', 'max_destination_resolver_attempts', 'max_total_operations']
      .some((key) => reservation[key] !== constraints[key])) {
    return { error: 'probe_execution_not_reserved', status: 409 };
  }
  return { ok: true };
}

/** Server-stamped custody binding for an accepted result, not another execution grant. */
export function probeExecutionEvidenceReceipt(job, workerId, attestation, externalResult) {
  const payload = { tenant_id: job.tenant_id, test_run_id: job.test_run_id, job_id: job.id,
    target_id: job.target_id, check_id: job.check_id, nonce_hash: job.nonce_hash,
    job_signature: job.job_signature, constraints: job.constraints, target: job.target,
    probe_profile: job.probe_profile, worker_id: workerId, leased_at: job.leased_at,
    execution_reservation: job.worker_metadata?.execution_reservation ?? null,
    safety_attestation: attestation, external_result: externalResult };
  return { version: 'accepted-probe-execution.v1',
    digest: createHash('sha256').update(canonicalJsonStringify(payload)).digest('hex') };
}

export function normalizeProbeCapture(value, now = new Date()) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some((key) => !['version', 'recorded_count', 'dropped_count', 'delivery_failures', 'last_sequence', 'finalized_at'].includes(key))
    || value.version !== 'probe-capture.v1') return null;
  const out = { version: value.version };
  for (const key of ['recorded_count', 'dropped_count', 'delivery_failures', 'last_sequence']) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0 || value[key] > 1_048_576) return null;
    out[key] = value[key];
  }
  if (out.recorded_count > 256 || out.last_sequence !== out.recorded_count) return null;
  out.finalized_at = null;
  if (value.finalized_at != null) {
    const at = new Date(value.finalized_at);
    if (!Number.isFinite(at.getTime()) || Math.abs(now.getTime() - at.getTime()) > 300_000) return null;
    out.finalized_at = at.toISOString();
  }
  return out;
}

export function mergeProbeCapture(previous, next) {
  if (!next) return previous ?? null;
  return { ...next,
    ...Object.fromEntries(['recorded_count', 'dropped_count', 'delivery_failures', 'last_sequence']
      .map((key) => [key, Math.max(previous?.[key] ?? 0, next[key])])),
    finalized_at: previous?.finalized_at ?? next.finalized_at ?? null };
}

export function normalizeStopAcknowledgment(body, job, workerId, now = new Date()) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).some((key) => !['leased_at', 'reason', 'capture'].includes(key))
    || body.leased_at !== job.leased_at || !job.leased_at) return { error: 'probe_stop_lease_mismatch', status: 409 };
  if (job.leased_by !== workerId) return { error: 'job_leased_to_another_worker', status: 403 };
  if (!['job_revoked', 'control_plane_unavailable', 'deadline_elapsed', 'worker_cancelled'].includes(body.reason)) {
    return { error: 'invalid_probe_stop', status: 400 };
  }
  const capture = body.capture == null ? null : normalizeProbeCapture(body.capture, now);
  if (body.capture != null && !capture) return { error: 'invalid_probe_capture', status: 400 };
  return { acknowledgment: { acknowledged_at: now.toISOString(), reason: body.reason,
    worker_id: workerId, leased_at: job.leased_at }, capture };
}
