const text = (value) => typeof value === 'string' ? value : '';
const object = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : {};

/** React renders these values as inert text; display and clipboard preserve the recorded bytes. */
export function safeCaptureText(value) {
  return String(value ?? '');
}

export function safeCaptureUrl(value) {
  return text(value);
}

export function captureHeaders(value) {
  if (!Array.isArray(value)) return null;
  return value.filter((entry) => typeof entry?.name === 'string' && typeof entry?.value === 'string')
    .map((entry) => ({ name: entry.name, value: entry.value }));
}

function assembledPayload(events, side, item) {
  const parts = new Map();
  const conflicts = [];
  for (const event of events) {
    const offset = event[`${side}_payload_offset`];
    if (!Number.isInteger(offset)) continue;
    const encoded = event[`${side}_payload_preview`];
    if (parts.has(offset) && parts.get(offset) !== encoded) conflicts.push(`${side}.payload_chunk`);
    parts.set(offset, encoded);
  }
  if (!parts.size || !item) return { item, conflicts };
  const chunks = [];
  let length = 0;
  let gap = false;
  for (const [offset, encoded] of [...parts].sort((a, b) => a[0] - b[0])) {
    if (offset !== length) { gap = true; break; }
    try {
      const bytes = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
      if (length + bytes.length > 1024 * 1024) { gap = true; break; }
      chunks.push(bytes); length += bytes.length;
    } catch { gap = true; break; }
  }
  if (conflicts.length) return { item: null, conflicts };
  const bytes = new Uint8Array(length);
  let position = 0;
  for (const chunk of chunks) { bytes.set(chunk, position); position += chunk.length; }
  let preview;
  let encoding;
  try {
    preview = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(preview)) throw new Error('binary');
    encoding = 'utf8';
  } catch {
    preview = chunks.map((chunk) => Array.from(chunk, (byte) => String.fromCharCode(byte)).join('')).join('');
    preview = btoa(preview); encoding = 'base64';
  }
  const expected = side === 'response' ? item.response_bytes_observed : item.body_bytes;
  const completed = side === 'request' ? events.some((event) => event.stage === 'request_started') : events.some((event) => event.stage === 'response_body_completed');
  return { item: { ...item, [`${side}_payload_preview`]: preview, [`${side}_payload_encoding`]: encoding,
    [`${side}_payload_truncated`]: gap || !completed || length !== expected }, conflicts };
}

const IDENTITY_FACTS = ['method', 'url', 'http_version', 'protocol', 'attempt_id', 'operation_id'];
function mergeCapture(events, side) {
  if (!events.length) return { item: null, conflicts: [] };
  const immutable = [...IDENTITY_FACTS, `${side}_headers`, `${side}_content_type`, ...(side === 'response' ? ['status_code'] : ['request_query_preview', 'request_payload_preview', 'request_payload_encoding'])];
  const facts = new Map();
  const conflicts = new Set();
  for (const event of events) for (const key of immutable) {
    if (event[key] == null || (event[`${side}_payload_offset`] != null && key.startsWith(`${side}_payload_`))) continue;
    const value = JSON.stringify(event[key]);
    if (facts.has(key) && facts.get(key) !== value) conflicts.add(`${side}.${key}`);
    else facts.set(key, value);
  }
  // Progressive payload events may supersede header-only availability. Contradictory
  // identity/status/header facts never become a synthetic merged request or response.
  const assembled = assembledPayload(events, side, conflicts.size ? null : Object.assign({}, ...events));
  return { item: assembled.item, conflicts: [...conflicts, ...assembled.conflicts] };
}

/** No timestamp, URL, phase or operation heuristic is allowed to pair legacy lifecycle events. */
export function recordedExchanges(items) {
  const groups = new Map();
  const lifecycle = [];
  for (const item of Array.isArray(items) ? items : []) {
    const source = object(item.source_context);
    if (item.capture_version !== 'http-exchange.v1' || !text(item.exchange_id) || !text(source.job_id) || !text(source.leased_at)) { lifecycle.push(item); continue; }
    const key = JSON.stringify([source.job_id, source.leased_at, item.exchange_id]);
    if (!groups.has(key)) groups.set(key, { id: key, exchangeId: text(item.exchange_id), source, events: [] });
    groups.get(key).events.push(item);
  }
  const exchanges = [...groups.values()].map((group) => {
    const events = group.events.slice().sort((a, b) => Number(a.sequence ?? 0) - Number(b.sequence ?? 0));
    const requestEvents = events.filter((item) => ['request_started', 'request_payload'].includes(item.stage));
    const responseEvents = events.filter((item) => ['response_received', 'response_payload', 'response_body_completed'].includes(item.stage));
    const requestCapture = mergeCapture(requestEvents, 'request');
    const responseCapture = mergeCapture(responseEvents, 'response');
    const conflictFields = [...requestCapture.conflicts, ...responseCapture.conflicts];
    let request = requestCapture.item;
    let response = responseCapture.item;
    for (const key of IDENTITY_FACTS.filter((field) => field !== 'http_version')) {
      if (request?.[key] != null && response?.[key] != null && request[key] !== response[key]) conflictFields.push(`exchange.${key}`);
    }
    if (conflictFields.some((field) => field.startsWith('exchange.'))) { request = null; response = null; }
    const failure = events.find((item) => item.stage === 'attempt_failed' || item.stage === 'request_not_sent');
    const bodyComplete = responseEvents.some((item) => item.stage === 'response_body_completed');
    const state = conflictFields.length ? 'partial' : failure ? failure.stage === 'request_not_sent' ? 'not_sent' : 'failed'
      : !request || !response || request.request_payload_truncated || response.response_payload_truncated ? 'partial' : bodyComplete ? 'captured' : 'partial';
    return { ...group, events, request, response, failure: failure ?? null, bodyComplete, state, conflictFields };
  });
  return { exchanges, lifecycle };
}

export function exchangeCopyText(exchange) {
  const lines = [`Recorded exchange: ${exchange.exchangeId}`, `Job: ${text(exchange.source.job_id)}`, `Lease: ${text(exchange.source.leased_at)}`];
  for (const [label, item] of [['Request', exchange.request], ['Response', exchange.response]]) {
    lines.push(`\n${label}`);
    if (!item) { lines.push('Not recorded'); continue; }
    if (item.method) lines.push(text(item.method));
    if (item.url) lines.push(safeCaptureUrl(item.url));
    lines.push(`Protocol: ${safeCaptureText(item.http_version || item.protocol || 'Not recorded')}`);
    if (item.status_code != null) lines.push(`HTTP ${item.status_code}`);
    const prefix = label.toLowerCase();
    const headers = captureHeaders(item[`${prefix}_headers`]);
    lines.push(headers === null ? 'Headers: not recorded' : headers.length ? headers.map((header) => `${header.name}: ${header.value}`).join('\n') : 'Headers: empty recorded set');
    if (label === 'Request') lines.push(`Query: ${item.request_query_preview == null ? 'Not recorded' : safeCaptureText(item.request_query_preview) || '(empty recorded query)'}`);
    const preview = item[`${prefix}_payload_preview`];
    lines.push(`Body: ${item[`${prefix}_payload_available`] === false ? 'Not consumed by this check' : preview == null ? 'Not recorded' : safeCaptureText(preview) || '(empty recorded body)'}`);
    if (item[`${prefix}_payload_encoding`] === 'base64') lines.push('Body encoding: Base64');
    if (item[`${prefix}_payload_truncated`] === true) lines.push('Partial capture');
  }
  if (exchange.conflictFields?.length) lines.push(`Capture conflict: ${exchange.conflictFields.join(', ')}. Conflicting capture withheld; no merged counterpart inferred.`);
  if (exchange.failure) lines.push(`Failure: ${safeCaptureText(exchange.failure.error_class || exchange.failure.reason || 'Not recorded')}`);
  return lines.join('\n');
}
