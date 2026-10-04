import { redactString, isVariantSensitiveKey } from './redact.mjs';

export const PROBE_PREVIEW_BYTES = 2048;
export const PROBE_PREVIEW_CHARS = 4096;

function scrub(value, sensitiveValues = []) {
  let text = redactString(String(value));
  for (const secret of sensitiveValues) {
    if (typeof secret === 'string' && secret.length >= 4) text = text.split(secret).join('[redacted]');
  }
  return text
    .replace(/("(?:password|token|secret|api[_-]?key|authorization|cookie|session|csrf|nonce)"\s*:\s*")[^"]*(?:"|$)/gi, '$1[redacted]"')
    .replace(/((?:password|token|secret|api[_-]?key|authorization|cookie|session|csrf|nonce)\s*[=:]\s*)[^\s&<]+/gi, '$1[redacted]')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[private key redacted]')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
}

export function redactPayloadPreview(value, sensitiveValues = []) {
  let text = String(value ?? '');
  const walk = (entry, depth = 0) => {
    if (depth > 8) return '[depth limit]';
    if (typeof entry === 'string') return scrub(entry, sensitiveValues);
    if (!entry || typeof entry !== 'object') return entry;
    if (Array.isArray(entry)) return entry.map((child) => walk(child, depth + 1));
    return Object.fromEntries(Object.entries(entry).map(([key, child]) => [key,
      isVariantSensitiveKey(key) || /nonce|csrf|session/i.test(key) ? '[redacted]' : walk(child, depth + 1)]));
  };
  try { text = JSON.stringify(walk(JSON.parse(text)), null, 2); } catch { /* Partial/text payloads remain text. */ }
  return scrub(text, sensitiveValues).slice(0, PROBE_PREVIEW_CHARS);
}

export function previewContentType(value) {
  const raw = String(value ?? '').slice(0, 253);
  const mime = raw.split(';')[0].trim().toLowerCase();
  if (!/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(mime)) return null;
  const charset = raw.match(/charset\s*=\s*([a-z0-9_-]+)/i)?.[1];
  return charset ? `${mime}; charset=${charset}` : mime;
}

export function previewBytes(buffer, contentType, sensitiveValues = []) {
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer ?? '');
  const sample = bytes.subarray(0, PROBE_PREVIEW_BYTES);
  const textual = !contentType || /json|text\/|xml|javascript|x-www-form-urlencoded|multipart/i.test(contentType);
  if (!textual) {
    const literal = sample.toString('utf8');
    const containsSecret = redactString(literal) !== literal
      || sensitiveValues.some((secret) => typeof secret === 'string' && secret.length >= 4 && literal.includes(secret))
      || /(?:password|token|secret|api[_-]?key|authorization|cookie)\s*[=:]/i.test(literal);
    return { preview: containsSecret ? '[binary payload redacted]' : sample.toString('base64'), encoding: containsSecret ? 'redacted' : 'base64', truncated: bytes.length > sample.length };
  }
  let value = sample.toString('utf8');
  if (/x-www-form-urlencoded/i.test(contentType ?? '')) {
    const form = new URLSearchParams(value);
    for (const [key] of form) if (isVariantSensitiveKey(key) || /nonce|csrf|session/i.test(key)) form.set(key, '[redacted]');
    value = form.toString();
  }
  const preview = redactPayloadPreview(value, sensitiveValues);
  return { preview, encoding: 'utf8', truncated: bytes.length > sample.length || preview.length >= PROBE_PREVIEW_CHARS };
}

export function previewRequest(url, options = {}, deps = {}) {
  const contentType = previewContentType(Object.entries(options.headers ?? {}).find(([name]) => name.toLowerCase() === 'content-type')?.[1]);
  const body = options.body == null ? Buffer.alloc(0) : Buffer.from(options.body);
  const captured = previewBytes(body, contentType, deps.activitySensitiveValues ?? []);
  const query = Object.create(null);
  const inherited = new URLSearchParams();
  try { for (const [name, value] of new URL(deps.activityBaseUrl).searchParams) inherited.append(name, value); } catch { /* FQDN targets have no declared query. */ }
  for (const [name, value] of new URL(url).searchParams) {
    query[name] = inherited.has(name) || isVariantSensitiveKey(name) || /nonce|csrf|session/i.test(name) ? '[redacted]' : scrub(value, deps.activitySensitiveValues ?? []);
  }
  return { request_content_type: contentType, request_payload_preview: captured.preview,
    request_payload_encoding: captured.encoding, request_payload_truncated: captured.truncated,
    ...(Object.keys(query).length ? { request_query_preview: JSON.stringify(query, null, 2).slice(0, PROBE_PREVIEW_CHARS) } : {}) };
}

/** Observe only bytes already consumed by the probe; no clone, refetch, or extra draining. */
export function captureResponsePayload(deps, common, contentType) {
  let total = 0;
  let captured = Buffer.alloc(0);
  let first = false;
  const emit = (complete) => {
    if (typeof deps.onProbeActivity !== 'function') return;
    const payload = previewBytes(captured, contentType, deps.activitySensitiveValues ?? []);
    try { deps.onProbeActivity({ ...common, stage: complete ? 'response_body_completed' : 'response_payload',
      response_content_type: contentType, response_payload_preview: payload.preview,
      response_payload_encoding: payload.encoding, response_payload_truncated: !complete || total > captured.length,
      response_bytes_observed: total, response_bytes_captured: captured.length }); } catch { /* Observation cannot alter transport. */ }
  };
  return {
    chunk(value) {
      const bytes = Buffer.from(value);
      total += bytes.length;
      const remaining = PROBE_PREVIEW_BYTES - captured.length;
      if (remaining > 0) captured = Buffer.concat([captured, bytes.subarray(0, remaining)]);
      if (!first) { first = true; emit(false); }
    },
    complete() { emit(true); },
  };
}
