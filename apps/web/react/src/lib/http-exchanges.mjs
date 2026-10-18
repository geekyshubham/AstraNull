import { isVariantSensitiveKey, redactString } from '../../../../../src/lib/redact.mjs';

const text = (value) => typeof value === 'string' ? value : '';
const object = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const secretKey = (key) => isVariantSensitiveKey(key) || /nonce|csrf|session/i.test(key);

/** Display and clipboard share one bounded, inert, redacted representation. Never a replay command. */
export function safeCaptureText(value) {
  const scrub = (raw) => redactString(String(raw))
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[private key redacted]')
    .replace(/((?:["']?(?:password|token|secret|api[_-]?key|authorization|cookie|set-cookie|session|csrf|nonce)["']?)\s*[:=]\s*)(?:"[^"]*(?:"|$)|'[^']*(?:'|$)|[^\s&<,}]+)/gi, '$1[redacted]')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
  const walk = (entry, depth = 0) => {
    if (depth > 8) return '[depth limit]';
    if (Array.isArray(entry)) return entry.map((child) => walk(child, depth + 1));
    if (entry && typeof entry === 'object') return Object.fromEntries(Object.entries(entry).map(([key, child]) => [key, secretKey(key) ? '[redacted]' : walk(child, depth + 1)]));
    return typeof entry === 'string' ? scrub(entry) : entry;
  };
  const raw = String(value ?? '').slice(0, 8192);
  try { return JSON.stringify(walk(JSON.parse(raw)), null, 2).slice(0, 4096); } catch { return scrub(raw).slice(0, 4096); }
}

export function safeCaptureUrl(value) {
  const raw = text(value);
  if (!raw) return '';
  try {
    const url = new URL(raw);
    url.username = ''; url.password = ''; url.hash = '';
    for (const name of [...url.searchParams.keys()]) if (secretKey(name)) url.searchParams.set(name, '[redacted]');
    return safeCaptureText(url.toString());
  } catch { return safeCaptureText(raw); }
}

export function captureHeaders(value) {
  if (!Array.isArray(value)) return null;
  return value.slice(0, 64).filter((entry) => typeof entry?.name === 'string' && typeof entry?.value === 'string').map((entry) => ({
    name: safeCaptureText(entry.name), value: secretKey(entry.name) ? '[redacted]' : safeCaptureText(entry.value),
  }));
}

const IDENTITY_FACTS = ['method', 'url', 'http_version', 'protocol', 'attempt_id', 'operation_id'];
function mergeCapture(events, side) {
  if (!events.length) return { item: null, conflicts: [] };
  const immutable = [...IDENTITY_FACTS, `${side}_headers`, `${side}_content_type`, ...(side === 'response' ? ['status_code'] : ['request_query_preview', 'request_payload_preview', 'request_payload_encoding'])];
  const facts = new Map();
  const conflicts = new Set();
  for (const event of events) for (const key of immutable) {
    if (event[key] == null) continue;
    const value = JSON.stringify(event[key]);
    if (facts.has(key) && facts.get(key) !== value) conflicts.add(`${side}.${key}`);
    else facts.set(key, value);
  }
  // Progressive payload events may supersede header-only availability. Contradictory
  // identity/status/header facts never become a synthetic merged request or response.
  return { item: conflicts.size ? null : Object.assign({}, ...events), conflicts: [...conflicts] };
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
    const requestEvents = events.filter((item) => item.stage === 'request_started');
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
      : !request || !response ? 'partial' : bodyComplete ? 'captured' : 'partial';
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
    lines.push(`Body: ${item[`${prefix}_payload_available`] === false ? 'Not consumed by this check' : item[`${prefix}_payload_encoding`] === 'base64' ? 'Binary preview withheld' : preview == null ? 'Not recorded' : safeCaptureText(preview) || '(empty recorded body)'}`);
    if (item[`${prefix}_payload_truncated`] === true) lines.push('Partial preview');
  }
  if (exchange.conflictFields?.length) lines.push(`Capture conflict: ${exchange.conflictFields.join(', ')}. Conflicting capture withheld; no merged counterpart inferred.`);
  if (exchange.failure) lines.push(`Failure: ${safeCaptureText(exchange.failure.error_class || exchange.failure.reason || 'Not recorded')}`);
  return lines.join('\n');
}
