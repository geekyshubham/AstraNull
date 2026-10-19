import { isUtf8 } from 'node:buffer';

export const PROBE_PREVIEW_BYTES = 8192;
export const PROBE_PREVIEW_CHARS = 16384;
export const MAX_CAPTURE_BODY_BYTES = 1024 * 1024;

export function capturePayloadText(value) {
  return String(value ?? '');
}

export function previewContentType(value) {
  if (typeof value !== 'string' || value.length > 1024 || /[\r\n]/.test(value)) return null;
  return /^[a-z0-9.+-]+\/[a-z0-9.+-]+(?:\s*;.*)?$/i.test(value) ? value : null;
}

export function previewBytes(buffer) {
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer ?? '');
  const sample = bytes.subarray(0, PROBE_PREVIEW_BYTES);
  const textual = isUtf8(sample) && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(sample.toString('utf8'));
  return { preview: sample.toString(textual ? 'utf8' : 'base64'), encoding: textual ? 'utf8' : 'base64', truncated: bytes.length > sample.length };
}

export function previewRequest(url, options = {}) {
  const contentType = previewContentType(Object.entries(options.headers ?? {}).find(([name]) => name.toLowerCase() === 'content-type')?.[1]);
  const body = options.body == null ? Buffer.alloc(0) : Buffer.from(options.body);
  const captured = previewBytes(body);
  const query = Object.create(null);
  for (const [name, value] of new URL(url).searchParams) {
    if (!Object.hasOwn(query, name)) query[name] = value;
    else query[name] = [...(Array.isArray(query[name]) ? query[name] : [query[name]]), value];
  }
  return { request_content_type: contentType, request_payload_preview: captured.preview,
    request_payload_encoding: captured.encoding, request_payload_truncated: captured.truncated,
    ...(Object.keys(query).length ? { request_query_preview: JSON.stringify(query, null, 2) } : {}) };
}

/** Chunk bytes into the existing signed activity envelope without changing network reads. */
export function emitPayloadChunks(deps, common, side, bytes) {
  if (typeof deps.onProbeActivity !== 'function') return;
  const { request_headers, response_headers, ...identity } = common;
  for (let offset = 0; offset < bytes.length; offset += PROBE_PREVIEW_BYTES) {
    deps.onProbeActivity?.({ ...identity, stage: `${side}_payload`,
      [`${side}_payload_offset`]: offset,
      [`${side}_payload_preview`]: bytes.subarray(offset, offset + PROBE_PREVIEW_BYTES).toString('base64'),
      [`${side}_payload_encoding`]: 'base64' });
  }
}

/** Observe only bytes already consumed by the probe; no clone, refetch, or extra draining. */
export function captureResponsePayload(deps, common, contentType) {
  let total = 0;
  let capturedBytes = 0;
  const chunks = [];
  let first = false;
  const emit = (complete, available = true, includeChunks = false) => {
    if (typeof deps.onProbeActivity !== 'function') return;
    const captured = Buffer.concat(chunks, capturedBytes);
    const payload = previewBytes(captured);
    if (includeChunks && (captured.length > PROBE_PREVIEW_BYTES || Buffer.byteLength(JSON.stringify({ ...common, response_payload_preview: payload.preview })) > 20 * 1024)) {
      try { emitPayloadChunks(deps, common, 'response', captured); } catch { /* Observation cannot alter transport. */ }
    }
    try { deps.onProbeActivity({ ...common, stage: complete ? 'response_body_completed' : 'response_payload',
      response_content_type: contentType, response_payload_preview: payload.preview,
      response_payload_available: available,
      ...(!available ? { response_payload_preview: '[Response body was not consumed by this check]', reason: 'response_not_consumed' } : {}),
      response_payload_encoding: payload.encoding, response_payload_truncated: !complete || total > capturedBytes || capturedBytes > PROBE_PREVIEW_BYTES,
      response_bytes_observed: total, response_bytes_captured: capturedBytes }); } catch { /* Observation cannot alter transport. */ }
  };
  return {
    chunk(value) {
      const bytes = Buffer.from(value);
      total += bytes.length;
      const remaining = MAX_CAPTURE_BODY_BYTES - capturedBytes;
      if (remaining > 0) {
        const sample = Buffer.from(bytes.subarray(0, remaining));
        chunks.push(sample); capturedBytes += sample.length;
      }
      if (!first) { first = true; emit(false); }
    },
    complete() { emit(true, true, true); },
    cancelled() { emit(false, capturedBytes > 0, true); },
  };
}
