import { redactPayloadPreview, previewContentType } from './probePayloadPreview.mjs';

export const HTTP_CAPTURE_VERSION = 'http-exchange.v1';
export const MAX_CAPTURE_HEADERS = 16;
const HEADER_NAME = /^:?[a-z0-9!#$%&'*+.^_`|~-]{1,64}$/i;
const REDACTED = '[redacted]';
const PUBLIC_HEADERS = new Set(['host', ':authority', ':method', ':scheme', ':status', 'accept',
  'accept-encoding', 'content-length', 'content-type', 'content-encoding', 'cache-control',
  'connection', 'date', 'server', 'via', 'retry-after', 'allow', 'vary', 'location',
  'strict-transport-security', 'x-content-type-options', 'x-frame-options', 'user-agent', 'x-astranull-marker']);
const PRIVATE_HEADER = /authorization|cookie|token|secret|key|session|nonce|credential|authenticat/i;

/** A URL representation, not a replayable destination: credentials/query values are withheld. */
export function captureUrl(value, { relative = false, sensitiveValues = [] } = {}) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value, relative ? 'https://capture.invalid' : undefined);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    url.username = ''; url.password = ''; url.hash = '';
    const literals = sensitiveValues.flatMap((secret) => typeof secret === 'string' ? [secret, encodeURIComponent(secret)] : []);
    const path = redactPayloadPreview(url.pathname, literals)
      .replace(/\/(reset|verify|token|secret|password|session|auth|invite)(?:\/[^/?#]+)+/gi, '/$1/[redacted]');
    url.pathname = path;
    const query = new URLSearchParams();
    for (const [key] of url.searchParams) query.append(redactPayloadPreview(key, sensitiveValues).slice(0, 128), REDACTED);
    url.search = query.toString();
    const absolute = /^[a-z][a-z0-9+.-]*:/i.test(value) || value.startsWith('//');
    return (relative && !absolute ? `${url.pathname}${url.search}` : url.href).slice(0, 1024);
  } catch { return null; }
}

function headerValue(name, value, sensitiveValues) {
  if (PRIVATE_HEADER.test(name) || !PUBLIC_HEADERS.has(name)) return REDACTED;
  if (name === 'location') return captureUrl(value, { relative: true, sensitiveValues }) ?? REDACTED;
  if (name === 'x-astranull-marker' && !/^astranull-[a-z0-9._%-]{1,240}(?:-inert|\.txt)$/i.test(value)) return REDACTED;
  if (name === ':path') return REDACTED;
  if (name === 'content-type') return previewContentType(value, sensitiveValues) ?? REDACTED;
  const safe = redactPayloadPreview(value, sensitiveValues).replace(/[\r\n]/g, ' ').slice(0, 384);
  // Structured numeric fields must not become an alternative channel for arbitrary values.
  if (['content-length', ':status'].includes(name) && !/^\d{1,12}$/.test(safe)) return REDACTED;
  return safe;
}

function headerEntries(headers) {
  if (Array.isArray(headers)) {
    return headers.every((entry) => entry && typeof entry === 'object' && !Array.isArray(entry))
      ? headers.map((entry) => [entry.name, entry.value])
      : Array.from({ length: Math.floor(headers.length / 2) }, (_, index) => [headers[index * 2], headers[index * 2 + 1]]);
  }
  return Object.entries(headers ?? {}).flatMap(([name, value]) =>
    (Array.isArray(value) ? value : [value]).map((entry) => [name, entry]));
}

/** Retain bounded names and allowlisted values; duplicate entries remain separate when observable. */
export function captureHttpHeaders(headers, sensitiveValues = []) {
  const entries = headerEntries(headers);
  // A response can reflect its own cookie/nonce into an otherwise public header.
  // Collect secrets from the complete set before bounding or serializing any entry.
  const secrets = [...sensitiveValues, ...captureHeaderSecrets(headers)].sort((left, right) => right.length - left.length);
  const result = [];
  for (const [rawName, rawValue] of entries) {
    if (result.length >= MAX_CAPTURE_HEADERS) break;
    if (typeof rawName !== 'string' || !HEADER_NAME.test(rawName) || rawValue == null) continue;
    const name = rawName.toLowerCase();
    result.push({ name, value: headerValue(name, String(rawValue), secrets) });
  }
  return result;
}

export function captureHeaderSecrets(headers) {
  return headerEntries(headers).filter(([name, value]) => typeof name === 'string' && (PRIVATE_HEADER.test(name) || !PUBLIC_HEADERS.has(name.toLowerCase())
    || (name.toLowerCase() === 'x-astranull-marker' && !/^astranull-[a-z0-9._%-]{1,240}(?:-inert|\.txt)$/i.test(String(value)))))
    .flatMap(([, value]) => (Array.isArray(value) ? value : [value]))
    .filter((value) => typeof value === 'string' && value.length >= 4)
    .flatMap((value) => [value, value.replace(/^(?:Bearer|Basic)\s+/i, ''),
      ...value.split(';').map((part) => part.includes('=') ? part.slice(part.indexOf('=') + 1).trim() : '')])
    .filter((value) => value.length >= 4);
}

export function normalizeCapturedHeaders(value) {
  if (!Array.isArray(value) || value.length > MAX_CAPTURE_HEADERS
    || value.some((entry) => !entry || typeof entry !== 'object' || Array.isArray(entry)
      || Object.keys(entry).some((key) => !['name', 'value'].includes(key))
      || typeof entry.name !== 'string' || !HEADER_NAME.test(entry.name)
      || typeof entry.value !== 'string' || entry.value.length > 1024)) return null;
  return captureHttpHeaders(value);
}
