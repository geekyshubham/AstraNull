/**
 * `GET /v1/findings` contract helpers (docs/backend/current-release-findings.md). The server owns
 * the predicate, the paging and the totals; nothing here filters or counts rows in the browser.
 */

export const FINDING_STATUSES = Object.freeze(['open', 'in_progress', 'accepted_risk', 'accepted', 'resolved', 'closed', 'false_positive']);

export const FINDING_STATUS_LABELS = Object.freeze({
  open: 'Open',
  in_progress: 'In progress',
  accepted_risk: 'Accepted risk',
  accepted: 'Accepted',
  resolved: 'Resolved',
  closed: 'Closed',
  false_positive: 'False positive',
});

/** Display groups only. Every count and list underneath is one exact server status. */
export const FINDING_STATUS_GROUPS = Object.freeze([
  Object.freeze({ id: 'active', label: 'Active', statuses: Object.freeze(['open', 'in_progress']) }),
  Object.freeze({ id: 'decided', label: 'Risk decisions', statuses: Object.freeze(['accepted_risk', 'accepted']) }),
  Object.freeze({ id: 'closed', label: 'Closed', statuses: Object.freeze(['resolved', 'closed', 'false_positive']) }),
]);

export const FINDINGS_LIMIT_MAX = 200;

/** Canonical severity classes the server compares on (docs/backend/current-release-findings.md). */
export const FINDING_SEVERITY_CLASSES = Object.freeze(['critical', 'high', 'medium', 'low', 'info', 'unknown']);

export const FINDING_SEVERITY_CLASS_LABELS = Object.freeze({
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  unknown: 'Not recorded or unrecognized',
});

const SEVERITY_ALIASES = Object.freeze({
  critical: 'critical', s1: 'critical',
  high: 'high', s2: 'high',
  medium: 'medium', moderate: 'medium', s3: 'medium',
  low: 'low', s4: 'low',
  info: 'info',
});

/** Server severity class of a recorded or requested token: aliases fold together, anything else is `unknown`. */
export function findingSeverityClass(value) {
  const token = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return SEVERITY_ALIASES[token] ?? 'unknown';
}

const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const SEVERITY = /^[A-Za-z0-9_.:-]{1,32}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

function text(value) {
  return typeof value === 'string' ? value.trim() : typeof value === 'number' ? String(value) : '';
}

/** A status the server accepts as a single exact predicate, or '' for every status. */
export function findingStatusFilter(value) {
  const status = text(value).toLowerCase();
  return FINDING_STATUSES.includes(status) ? status : '';
}

/**
 * Query string for one server predicate and page. Values the server would reject are dropped
 * here so a malformed address never turns into a 400; `all` and blanks mean "no filter".
 */
export function findingsQuery(filters = {}) {
  const params = new URLSearchParams();
  const q = text(filters.q);
  if (q && q.length <= 200 && !CONTROL.test(q)) params.set('q', q);
  const status = findingStatusFilter(filters.status);
  if (status) params.set('status', status);
  const severity = text(filters.severity);
  if (severity && severity.toLowerCase() !== 'all' && SEVERITY.test(severity)) params.set('severity', findingSeverityClass(severity));
  for (const key of ['check_id', 'target_group_id', 'target_id', 'test_run_id']) {
    const value = text(filters[key]);
    if (value && value !== 'all' && ID.test(value)) params.set(key, value);
  }
  const limit = Number(filters.limit);
  if (Number.isInteger(limit) && limit >= 1) params.set('limit', String(Math.min(limit, FINDINGS_LIMIT_MAX)));
  const page = Number(filters.page);
  if (Number.isInteger(page) && page > 1) params.set('page', String(page));
  return params.toString();
}

export function findingsPath(filters = {}) {
  const query = findingsQuery(filters);
  return query ? `/v1/findings?${query}` : '/v1/findings';
}

function count(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

/**
 * The list envelope as the server sent it. `exact` is false when the server returned no total
 * (an older deployment), so callers can say the count is unknown instead of using the page length.
 */
export function parseFindingsEnvelope(body) {
  const record = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  const items = Array.isArray(record.items) ? record.items.filter((item) => item && typeof item === 'object') : Array.isArray(body) ? body : [];
  const total = count(record.total);
  const limit = count(record.limit);
  const page = count(record.page) ?? 1;
  const pages = count(record.pages) ?? (total !== null && limit ? Math.ceil(total / limit) : null);
  const meta = record.meta && typeof record.meta === 'object' ? record.meta : null;
  return {
    items,
    total,
    page,
    pages,
    limit,
    hasMore: record.has_more === true,
    emptyReason: typeof meta?.empty_reason === 'string' ? meta.empty_reason : null,
    exact: total !== null,
  };
}

/** True when a loaded set of rows is every row the server matched. */
export function findingsComplete(envelope, loadedCount) {
  return Boolean(envelope?.exact) && !envelope.hasMore && loadedCount >= envelope.total;
}

/** Group key `encodeURIComponent(check)|encodeURIComponent(issue)` back to its check id. */
export function findingGroupCheckId(groupKey) {
  const raw = text(groupKey);
  const index = raw.indexOf('|');
  if (index <= 0) return '';
  try {
    const checkId = decodeURIComponent(raw.slice(0, index));
    return checkId !== 'unknown-check' && ID.test(checkId) ? checkId : '';
  } catch {
    return '';
  }
}
