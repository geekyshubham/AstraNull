import { createHash } from 'node:crypto';
import { normalizeProbeCapture } from './probeExecution.mjs';
import { presentProductDetectionEvidence } from './productDetectionEvidence.mjs';
import { capturePayloadText, PROBE_PREVIEW_CHARS, PROBE_PREVIEW_BYTES, MAX_CAPTURE_BODY_BYTES, previewContentType } from './probePayloadPreview.mjs';
import { captureUrl, HTTP_CAPTURE_VERSION, normalizeCapturedHeaders } from './probeHttpCapture.mjs';

export const MAX_PROBE_ACTIVITY_ITEMS = 256;
export const MAX_PROBE_ACTIVITY_BATCH = 16;
export const PROBE_ACTIVITY_STAGES = Object.freeze([
  'job_started', 'request_started', 'response_received', 'attempt_started',
  'attempt_failed', 'request_not_sent', 'probe_completed',
  'phase_completed',
  'request_payload', 'response_payload', 'response_body_completed',
]);
const FIELDS = new Set(['sequence', 'at', 'stage', 'operation', 'method', 'url', 'protocol',
  'status_code', 'duration_ms', 'error_class', 'reason', 'requests_sent', 'body_bytes', 'header_names', 'outcome', 'phase',
  'request_content_type', 'response_content_type', 'request_payload_preview', 'request_query_preview', 'response_payload_preview',
  'request_payload_encoding', 'response_payload_encoding', 'request_payload_truncated', 'response_payload_truncated',
  'response_bytes_observed', 'response_bytes_captured', 'capture_version', 'exchange_id', 'attempt_id', 'operation_id',
  'http_version', 'request_headers', 'response_headers', 'request_payload_offset', 'response_payload_offset']);
FIELDS.add('response_payload_available');
const TOKEN = /^[a-zA-Z0-9_.:-]{1,80}$/;

/** Preserve the recorded HTTP destination and query values. */
export function activityUrl(value) {
  return captureUrl(value);
}

export function normalizeProbeActivityItem(item, now = new Date()) {
  if (!item || typeof item !== 'object' || Array.isArray(item)
    || Object.keys(item).some((key) => !FIELDS.has(key))) return null;
  if (!Number.isInteger(item.sequence) || item.sequence < 1 || item.sequence > MAX_PROBE_ACTIVITY_ITEMS
    || !PROBE_ACTIVITY_STAGES.includes(item.stage)) return null;
  const at = new Date(item.at);
  if (Number.isNaN(at.getTime()) || Math.abs(now.getTime() - at.getTime()) > 300_000) return null;
  const result = { sequence: item.sequence, at: at.toISOString(), stage: item.stage };
  if (item.capture_version != null) {
    if (item.capture_version !== HTTP_CAPTURE_VERSION) return null;
    result.capture_version = item.capture_version;
  }
  for (const field of ['exchange_id', 'attempt_id', 'operation_id']) {
    if (item[field] == null) continue;
    if (item.capture_version !== HTTP_CAPTURE_VERSION || typeof item[field] !== 'string' || !TOKEN.test(item[field])) return null;
    result[field] = item[field];
  }
  if (item.http_version != null) {
    if (!['1.0', '1.1', '2.0', '3.0'].includes(item.http_version)) return null;
    result.http_version = item.http_version;
  }
  for (const field of ['request_headers', 'response_headers']) {
    if (item[field] == null) continue;
    if (item.capture_version !== HTTP_CAPTURE_VERSION) return null;
    result[field] = normalizeCapturedHeaders(item[field]);
    if (!result[field]) return null;
  }
  for (const field of ['operation', 'method', 'protocol', 'error_class', 'reason', 'outcome', 'phase', 'request_payload_encoding', 'response_payload_encoding']) {
    if (item[field] == null) continue;
    if (typeof item[field] !== 'string' || !TOKEN.test(item[field])) return null;
    result[field] = item[field];
  }
  if (item.url != null) {
    result.url = activityUrl(item.url);
    if (!result.url) return null;
  }
  for (const field of ['status_code', 'duration_ms', 'requests_sent', 'body_bytes', 'response_bytes_observed', 'response_bytes_captured', 'request_payload_offset', 'response_payload_offset']) {
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
    result[field] = capturePayloadText(item[field]);
  }
  for (const field of ['request_payload_truncated', 'response_payload_truncated', 'response_payload_available']) {
    if (item[field] == null) continue;
    if (typeof item[field] !== 'boolean') return null;
    result[field] = item[field];
  }
  for (const side of ['request', 'response']) {
    const offset = result[`${side}_payload_offset`];
    if (offset == null) continue;
    const preview = result[`${side}_payload_preview`];
    if (result.capture_version !== HTTP_CAPTURE_VERSION || result.stage !== `${side}_payload`
      || result[`${side}_payload_encoding`] !== 'base64' || typeof preview !== 'string'
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(preview)) return null;
    const bytes = Buffer.from(preview, 'base64');
    if (bytes.toString('base64') !== preview || bytes.length > PROBE_PREVIEW_BYTES
      || offset + bytes.length > MAX_CAPTURE_BODY_BYTES) return null;
  }
  // Every item fits even the signed 32-KiB body boundary after UTF-8/JSON encoding.
  while (Buffer.byteLength(JSON.stringify(result)) > 24 * 1024) {
    // Chunk bytes are immutable; shortening them would corrupt offsets and replay identity.
    if (result.request_payload_offset != null || result.response_payload_offset != null) return null;
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
    || Object.keys(body).some((key) => !['leased_at', 'items', 'capture'].includes(key))
    || !Array.isArray(body.items) || body.items.length > MAX_PROBE_ACTIVITY_BATCH) {
    return { error: 'invalid_probe_activity', status: 400 };
  }
  if (body.leased_at !== job.leased_at) return { error: 'probe_activity_lease_mismatch', status: 409 };
  const items = body.items.map((item) => normalizeProbeActivityItem(item, now));
  if (items.some((item) => !item) || new Set(items.map((item) => item.sequence)).size !== items.length) {
    return { error: 'invalid_probe_activity', status: 400 };
  }
  const capture = body.capture == null ? null : normalizeProbeCapture(body.capture, now);
  if (body.capture != null && !capture) return { error: 'invalid_probe_capture', status: 400 };
  return { items, capture };
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
      marker_class: job.probe_profile?.marker_class ?? null, leased_at: job.leased_at ?? null },
  };
}

export function sameProbeActivity(left, right) {
  return [...FIELDS].every((field) => JSON.stringify(left?.[field]) === JSON.stringify(right?.[field]));
}

export function projectRunActivity(run, events, limit = 200) {
  const paginated = limit != null && typeof limit === 'object';
  const options = paginated ? limit : { limit };
  const job = options.job ?? null;
  const bounded = Math.max(1, Math.min(MAX_PROBE_ACTIVITY_ITEMS, Math.floor(Number(options.limit)) || 200));
  const items = [];
  const startedAt = run.started_at ?? run.created_at;
  if (startedAt) items.push({ id: `run:${run.id}:started`, at: startedAt, stage: run.started_at ? 'run_started' : 'run_created', source: 'run_state', operation: run.check_id });
  if (['cancelled', 'canceled'].includes(run.status) && run.completed_at) {
    items.push({ id: `run:${run.id}:stopped`, at: run.completed_at, stage: 'stop_requested', source: 'run_state', operation: run.check_id });
  }
  let requestsSent = null;
  let accounting = { probe_logical_attempts: null, destination_vetting_resolver_attempts: null,
    total_operations: null, counting_basis: null };
  const operationCount = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 1_048_576 ? value : null;
  for (const event of events ?? []) {
    if (event.tenant_id !== run.tenant_id || event.test_run_id !== run.id) continue;
    if (event.signal_type === 'probe_activity' && event.producer_kind === 'signed_probe') {
      const activity = event.metadata?.activity;
      const normalized = normalizeProbeActivityItem(activity, new Date(activity?.at));
      if (normalized) items.push({ id: event.id, ...normalized, recorded_at: event.ingested_at ?? event.timestamp,
        source: 'signed_worker', source_context: { job_id: event.metadata?.probe_job_id ?? null,
          worker_id: event.metadata?.probe_worker_id ?? null, leased_at: event.metadata?.leased_at ?? null }, check_id: event.check_id,
        vector_family: event.metadata?.vector_family ?? run.vector_family ?? null,
        probe_kind: event.metadata?.probe_kind ?? null, marker_class: event.metadata?.marker_class ?? null });
    }
    if (event.signal_type === 'probe_result' && ['signed_probe', 'internal_simulation'].includes(event.producer_kind)) {
      const metadata = event.metadata ?? {};
      const count = metadata.safety_attestation?.requests_sent;
      if (Number.isInteger(count) && count >= 0) requestsSent = count;
      const recorded = metadata.request_accounting ?? {};
      const attested = metadata.safety_attestation ?? {};
      accounting = { probe_logical_attempts: operationCount(attested.probe_requests_sent ?? recorded.probe_logical_attempts),
        destination_vetting_resolver_attempts: operationCount(attested.destination_resolver_attempts ?? recorded.destination_vetting_resolver_attempts),
        total_operations: operationCount(attested.total_operations ?? recorded.total_operations ?? count),
        counting_basis: metadata.request_counting_basis === 'logical_operations' ? 'logical_operations' : null };
      items.push({ id: event.id, at: event.timestamp, recorded_at: event.ingested_at ?? event.timestamp, stage: 'result_received',
        source: event.producer_kind === 'signed_probe' ? 'signed_worker' : 'simulation',
        operation: metadata.probe_kind ?? 'probe',
        ...(Number.isInteger(metadata.status_code) ? { status_code: metadata.status_code } : {}),
        ...(typeof metadata.external_result === 'string' ? { outcome: metadata.external_result } : {}),
        ...(Number.isInteger(count) ? { requests_sent: count } : {}),
        ...(typeof metadata.error_class === 'string' && TOKEN.test(metadata.error_class) ? { error_class: metadata.error_class } : {}),
        observations: Object.fromEntries(['query_name', 'qtype', 'rcode', 'response_bytes', 'response_received',
          'tls_protocol', 'tls_cipher', 'cipher', 'authorized', 'tls_authorized', 'cert_expiry', 'port', 'protocol', 'http_method', 'http_version',
          'dns_rcode', 'dns_qtype', 'record_count', 'alpn_protocol', 'reply_received', 'websocket_status',
          'redirect_hops', 'axfr_leak', 'websocket_upgrade', 'grpc_status', 'amplification_ratio',
          'dns_cname_lookups', 'baseline_status_code', 'audit_host', 'query_type', 'dnssec_enabled',
          'waf_detected', 'cdn_detected', 'detected_vendor', 'detected_product', 'response_reason',
          'phases_completed', 'request_counting_basis', 'enforcement', 'baseline_blocked']
          .filter((field) => ['string', 'boolean', 'number'].includes(typeof metadata[field]))
          .map((field) => [field, typeof metadata[field] === 'string' ? metadata[field].slice(0, 253) : metadata[field]])),
        port_observations: Object.fromEntries(['open_ports', 'filtered_ports', 'closed_ports']
          .filter((field) => Array.isArray(metadata[field]))
          .map((field) => [field, metadata[field].filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535).slice(0, 15)])),
      });
    }
  }
  items.sort((a, b) => String(paginated ? (a.recorded_at ?? a.at) : a.at).localeCompare(String(paginated ? (b.recorded_at ?? b.at) : b.at))
    || String(a.id).localeCompare(String(b.id)));
  const after = options.cursor ? items.findIndex((item) => item.id === options.cursor) : -1;
  if (options.cursor && after < 0) return { error: 'invalid_activity_cursor', status: 400 };
  const page = paginated ? items.slice(after + 1, after + 1 + bounded) : items.slice(-bounded);
  const hasMore = paginated ? after + 1 + page.length < items.length : items.length > bounded;
  const stats = job?.worker_metadata?.capture ?? null;
  const currentItems = items.filter((item) => item.source === 'signed_worker' && item.sequence != null
    && (!job || (item.source_context?.job_id === job.id && item.source_context?.leased_at === job.leased_at)));
  const seen = new Set(currentItems.map((item) => item.sequence));
  const gaps = [];
  const expected = stats?.last_sequence ?? Math.max(0, ...seen);
  for (let seq = 1; seq <= Math.min(MAX_PROBE_ACTIVITY_ITEMS, expected); seq += 1) {
    if (seen.has(seq)) continue;
    const prior = gaps[gaps.length - 1];
    if (prior?.to === seq - 1) prior.to = seq;
    else gaps.push({ from: seq, to: seq });
  }
  const incomplete = gaps.length > 0 || (stats?.dropped_count ?? 0) > 0 || (stats?.delivery_failures ?? 0) > 0;
  const capture = { status: !stats ? 'unknown' : incomplete ? 'incomplete' : stats.finalized_at ? 'complete' : 'recording',
    limit: MAX_PROBE_ACTIVITY_ITEMS, recorded_count: seen.size, dropped_count: stats?.dropped_count ?? null,
    delivery_failures: stats?.delivery_failures ?? null, sequence_gaps: gaps, finalized_at: stats?.finalized_at ?? null,
    perspective: 'recorded_metadata_only' };
  const requestedAt = ['cancelled', 'canceled'].includes(run.status) ? run.completed_at ?? null : null;
  const acknowledgment = job?.worker_metadata?.stop_acknowledgment;
  const deadline = job?.constraints?.not_after ?? run.collection_deadline_at ?? null;
  const expired = Number.isFinite(Date.parse(deadline)) && Date.parse(deadline) <= Date.now();
  const stop = { state: acknowledgment ? 'acknowledged' : !requestedAt ? 'not_requested' : expired ? 'deadline_elapsed'
    : Date.now() - Date.parse(requestedAt) >= 4000 ? 'unreachable' : 'requested', requested_at: requestedAt,
    acknowledged_at: acknowledgment?.acknowledged_at ?? null, deadline_at: deadline,
    reason: acknowledgment?.reason ?? (requestedAt ? 'worker_acknowledgment_not_received' : null) };
  return { run_id: run.id, check_id: run.check_id, target_id: run.target_id,
    status: run.status, vector_family: run.vector_family ?? null, created_at: run.created_at ?? null, started_at: run.started_at ?? null, completed_at: run.completed_at ?? null,
    requests_sent: requestsSent, accounting, telemetry_recorded: items.some((item) => item.source === 'signed_worker' && item.stage !== 'result_received'),
    source_context: job ? { job_id: job.id, worker_id: job.leased_by ?? null, leased_at: job.leased_at ?? null } : null,
    authorized_bounds: job?.job_signature ? Object.fromEntries(['max_probe_requests', 'max_destination_resolver_attempts',
      'max_total_operations', 'timeout_ms', 'not_after', 'authority_version'].filter((key) => job.constraints?.[key] != null)
      .map((key) => [key, job.constraints[key]])) : null,
    capture, stop, pagination: { next_cursor: page.at(-1)?.id ?? options.cursor ?? null, has_more: hasMore, total_recorded: items.length },
    items: page.map((item) => ({ ...item, ...(typeof item.operation === 'string'
      ? { operation: presentProductDetectionEvidence(item.operation) } : {}) })), count: page.length, truncated: hasMore };
}
