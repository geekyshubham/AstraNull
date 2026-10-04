import { createHash } from 'node:crypto';
import { presentProductDetectionEvidence } from './productDetectionEvidence.mjs';
import { redactPayloadPreview, PROBE_PREVIEW_CHARS, previewContentType } from './probePayloadPreview.mjs';

export const MAX_PROBE_ACTIVITY_ITEMS = 256;
export const MAX_PROBE_ACTIVITY_BATCH = 16;
export const PROBE_ACTIVITY_STAGES = Object.freeze([
  'job_started', 'request_started', 'response_received', 'attempt_started',
  'attempt_failed', 'request_not_sent', 'probe_completed',
  'phase_completed',
  'response_payload', 'response_body_completed',
]);
const FIELDS = new Set(['sequence', 'at', 'stage', 'operation', 'method', 'url', 'protocol',
  'status_code', 'duration_ms', 'error_class', 'reason', 'requests_sent', 'body_bytes', 'header_names', 'outcome', 'phase',
  'request_content_type', 'response_content_type', 'request_payload_preview', 'request_query_preview', 'response_payload_preview',
  'request_payload_encoding', 'response_payload_encoding', 'request_payload_truncated', 'response_payload_truncated',
  'response_bytes_observed', 'response_bytes_captured']);
const TOKEN = /^[a-zA-Z0-9_.:-]{1,80}$/;

/** Keep the observed destination/path and query names; never retain query values or credentials. */
export function activityUrl(value) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    url.username = ''; url.password = ''; url.hash = '';
    for (const name of [...new Set(url.searchParams.keys())]) url.searchParams.set(name, '[redacted]');
    return url.href.slice(0, 1024);
  } catch { return null; }
}

export function normalizeProbeActivityItem(item, now = new Date()) {
  if (!item || typeof item !== 'object' || Array.isArray(item)
    || Object.keys(item).some((key) => !FIELDS.has(key))) return null;
  if (!Number.isInteger(item.sequence) || item.sequence < 1 || item.sequence > MAX_PROBE_ACTIVITY_ITEMS
    || !PROBE_ACTIVITY_STAGES.includes(item.stage)) return null;
  const at = new Date(item.at);
  if (Number.isNaN(at.getTime()) || Math.abs(now.getTime() - at.getTime()) > 300_000) return null;
  const result = { sequence: item.sequence, at: at.toISOString(), stage: item.stage };
  for (const field of ['operation', 'method', 'protocol', 'error_class', 'reason', 'outcome', 'phase', 'request_payload_encoding', 'response_payload_encoding']) {
    if (item[field] == null) continue;
    if (typeof item[field] !== 'string' || !TOKEN.test(item[field])) return null;
    result[field] = item[field];
  }
  if (item.url != null) {
    result.url = activityUrl(item.url);
    if (!result.url) return null;
  }
  for (const field of ['status_code', 'duration_ms', 'requests_sent', 'body_bytes', 'response_bytes_observed', 'response_bytes_captured']) {
    if (item[field] == null) continue;
    if (!Number.isInteger(item[field]) || item[field] < 0 || item[field] > 1_048_576) return null;
    if (field === 'status_code' && (item[field] < 100 || item[field] > 599)) return null;
    result[field] = item[field];
  }
  if (item.header_names != null) {
    if (!Array.isArray(item.header_names) || item.header_names.length > 16
      || item.header_names.some((name) => typeof name !== 'string' || !/^[a-z0-9-]{1,64}$/i.test(name))) return null;
    result.header_names = [...new Set(item.header_names.map((name) => name.toLowerCase()))];
  }
  for (const field of ['request_content_type', 'response_content_type']) {
    if (item[field] == null) continue;
    result[field] = previewContentType(item[field]);
    if (!result[field]) return null;
  }
  for (const field of ['request_payload_preview', 'request_query_preview', 'response_payload_preview']) {
    if (item[field] == null) continue;
    if (typeof item[field] !== 'string' || item[field].length > PROBE_PREVIEW_CHARS) return null;
    result[field] = redactPayloadPreview(item[field]);
  }
  for (const field of ['request_payload_truncated', 'response_payload_truncated']) {
    if (item[field] == null) continue;
    if (typeof item[field] !== 'boolean') return null;
    result[field] = item[field];
  }
  // Every item fits even the signed 32-KiB body boundary after UTF-8/JSON encoding.
  while (Buffer.byteLength(JSON.stringify(result)) > 24 * 1024) {
    let shortened = false;
    for (const field of ['request_payload_preview', 'request_query_preview', 'response_payload_preview']) {
      if (typeof result[field] !== 'string' || result[field].length <= 512) continue;
      result[field] = result[field].slice(0, Math.floor(result[field].length / 2));
      result[field.startsWith('response') ? 'response_payload_truncated' : 'request_payload_truncated'] = true;
      shortened = true;
    }
    if (!shortened) return null;
  }
  return result;
}

export function emitProbeActivity(deps, item) {
  try { deps?.onProbeActivity?.(item); } catch { /* Telemetry cannot change transport safety or outcomes. */ }
}

export function normalizeProbeActivityBatch(body, job, now = new Date()) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).some((key) => !['leased_at', 'items'].includes(key))
    || !Array.isArray(body.items) || body.items.length > MAX_PROBE_ACTIVITY_BATCH) {
    return { error: 'invalid_probe_activity', status: 400 };
  }
  if (body.leased_at !== job.leased_at) return { error: 'probe_activity_lease_mismatch', status: 409 };
  const items = body.items.map((item) => normalizeProbeActivityItem(item, now));
  if (items.some((item) => !item) || new Set(items.map((item) => item.sequence)).size !== items.length) {
    return { error: 'invalid_probe_activity', status: 400 };
  }
  return { items };
}

export function probeActivityEvent(job, item, workerId) {
  const digest = createHash('sha256').update(`${job.id}:${job.leased_at}:${item.sequence}`).digest('hex');
  return {
    id: `evt_activity_${digest}`, event_id: `activity:${digest}`, tenant_id: job.tenant_id,
    test_run_id: job.test_run_id, target_id: job.target_id, check_id: job.check_id,
    source: 'probe_worker', signal_type: 'probe_activity', producer_kind: 'signed_probe',
    nonce_hash: job.nonce_hash, timestamp: item.at,
    metadata: { activity: item, probe_job_id: job.id, probe_worker_id: workerId,
      vector_family: job.vector_family ?? null, probe_kind: job.probe_profile?.kind ?? null,
      marker_class: job.probe_profile?.marker_class ?? null },
  };
}

export function sameProbeActivity(left, right) {
  return [...FIELDS].every((field) => JSON.stringify(left?.[field]) === JSON.stringify(right?.[field]));
}

export function projectRunActivity(run, events, limit = 200) {
  const bounded = Math.max(1, Math.min(MAX_PROBE_ACTIVITY_ITEMS, Number(limit) || 200));
  const items = [];
  const startedAt = run.started_at ?? run.created_at;
  if (startedAt) items.push({ id: `run:${run.id}:started`, at: startedAt, stage: run.started_at ? 'run_started' : 'run_created', source: 'run_state', operation: run.check_id });
  if (['cancelled', 'canceled'].includes(run.status) && run.completed_at) {
    items.push({ id: `run:${run.id}:stopped`, at: run.completed_at, stage: 'run_stopped', source: 'run_state', operation: run.check_id });
  }
  let requestsSent = null;
  for (const event of events ?? []) {
    if (event.tenant_id !== run.tenant_id || event.test_run_id !== run.id) continue;
    if (event.signal_type === 'probe_activity' && event.producer_kind === 'signed_probe') {
      const activity = event.metadata?.activity;
      const normalized = normalizeProbeActivityItem(activity, new Date(activity?.at));
      if (normalized) items.push({ id: event.id, ...normalized, source: 'signed_worker', check_id: event.check_id,
        vector_family: event.metadata?.vector_family ?? run.vector_family ?? null,
        probe_kind: event.metadata?.probe_kind ?? null, marker_class: event.metadata?.marker_class ?? null });
    }
    if (event.signal_type === 'probe_result' && ['signed_probe', 'internal_simulation'].includes(event.producer_kind)) {
      const metadata = event.metadata ?? {};
      const count = metadata.safety_attestation?.requests_sent;
      if (Number.isInteger(count) && count >= 0) requestsSent = count;
      items.push({ id: event.id, at: event.timestamp, stage: 'result_received',
        source: event.producer_kind === 'signed_probe' ? 'signed_worker' : 'simulation',
        operation: metadata.probe_kind ?? 'probe',
        ...(Number.isInteger(metadata.status_code) ? { status_code: metadata.status_code } : {}),
        ...(typeof metadata.external_result === 'string' ? { outcome: metadata.external_result } : {}),
        ...(Number.isInteger(count) ? { requests_sent: count } : {}),
        ...(typeof metadata.error_class === 'string' && TOKEN.test(metadata.error_class) ? { error_class: metadata.error_class } : {}),
        observations: Object.fromEntries(['query_name', 'qtype', 'rcode', 'response_bytes', 'response_received',
          'tls_protocol', 'tls_cipher', 'cipher', 'authorized', 'tls_authorized', 'cert_expiry', 'port', 'protocol', 'http_method', 'http_version',
          'dns_rcode', 'dns_qtype', 'record_count', 'alpn_protocol', 'reply_received', 'websocket_status',
          'redirect_hops', 'axfr_leak', 'websocket_upgrade', 'grpc_status', 'amplification_ratio']
          .filter((field) => ['string', 'boolean', 'number'].includes(typeof metadata[field]))
          .map((field) => [field, typeof metadata[field] === 'string' ? metadata[field].slice(0, 253) : metadata[field]])),
      });
    }
  }
  items.sort((a, b) => String(a.at).localeCompare(String(b.at)) || (a.sequence ?? 0) - (b.sequence ?? 0));
  return presentProductDetectionEvidence({ run_id: run.id, check_id: run.check_id, target_id: run.target_id,
    status: run.status, vector_family: run.vector_family ?? null, created_at: run.created_at ?? null, started_at: run.started_at ?? null, completed_at: run.completed_at ?? null,
    requests_sent: requestsSent, telemetry_recorded: items.some((item) => item.source === 'signed_worker' && item.stage !== 'result_received'),
    items: items.slice(-bounded), count: Math.min(items.length, bounded), truncated: items.length > bounded });
}
