export const HTTP_CAPTURE_VERSION = 'http-exchange.v1';
export const MAX_CAPTURE_HEADERS = 2048;
const HEADER_NAME = /^:?[a-z0-9!#$%&'*+.^_`|~-]{1,64}$/i;

/** Record the observed HTTP URL. Fragments are not sent over HTTP. */
export function captureUrl(value, { relative = false } = {}) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value, relative ? 'https://capture.invalid' : undefined);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    url.hash = '';
    const absolute = /^[a-z][a-z0-9+.-]*:/i.test(value) || value.startsWith('//');
    return relative && !absolute ? `${url.pathname}${url.search}` : url.href;
  } catch { return null; }
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

/** Preserve all observed header values and duplicate entries without filtering by name. */
export function captureHttpHeaders(headers) {
  return headerEntries(headers).filter(([name, value]) => typeof name === 'string' && HEADER_NAME.test(name) && value != null)
    .map(([name, value]) => ({ name: name.toLowerCase(), value: String(value) }));
}

export function normalizeCapturedHeaders(value) {
  if (!Array.isArray(value) || value.length > MAX_CAPTURE_HEADERS
    || value.some((entry) => !entry || typeof entry !== 'object' || Array.isArray(entry)
      || Object.keys(entry).some((key) => !['name', 'value'].includes(key))
      || typeof entry.name !== 'string' || !HEADER_NAME.test(entry.name)
      || typeof entry.value !== 'string' || entry.value.length > 16384)) return null;
  return captureHttpHeaders(value);
}
