/**
 * Pure finding-list query. Dev and Postgres both use this predicate.
 * `q` matches safe identity columns only. Notes, remediation, and evidence are not searched.
 */
import { FINDING_LIFECYCLE } from './findingLifecycle.mjs';

export const FINDING_LIST_DEFAULT_LIMIT = 50;
export const FINDING_LIST_MAX_LIMIT = 200;
export const FINDING_LIST_MAX_Q = 200;
export const FINDING_LIST_MAX_PAGE = 1_000_000;

/**
 * Canonical severity class aliases, matching the portal `normalizeSeverity`
 * contract: S1=critical, S2=high, S3=medium, S4=low, moderate=medium, info=info.
 * A recorded value outside this list is the `unknown` class, never `low`.
 */
export const FINDING_SEVERITY_ALIASES = Object.freeze({
  critical: 'critical',
  s1: 'critical',
  high: 'high',
  s2: 'high',
  medium: 'medium',
  moderate: 'medium',
  s3: 'medium',
  low: 'low',
  s4: 'low',
  info: 'info',
});

export const FINDING_SEVERITY_CLASSES = Object.freeze([
  'critical', 'high', 'medium', 'low', 'info', 'unknown',
]);

/** Canonical severity class of a recorded severity token; unrecognized stays `unknown`. */
export function findingSeverityClass(value) {
  const text = String(value ?? '').trim().toLowerCase();
  return FINDING_SEVERITY_ALIASES[text] ?? 'unknown';
}

/**
 * SQL twin of `findingSeverityClass` for one column expression. Both sides of the
 * comparison use the same canonical CASE, so an alias query matches its equivalent
 * recorded classes and an `unknown` query selects the actually unknown rows.
 */
export function findingSeverityClassSql(column = 'f.severity') {
  return `(CASE lower(btrim(${column}))
    WHEN 'critical' THEN 'critical'
    WHEN 's1' THEN 'critical'
    WHEN 'high' THEN 'high'
    WHEN 's2' THEN 'high'
    WHEN 'medium' THEN 'medium'
    WHEN 'moderate' THEN 'medium'
    WHEN 's3' THEN 'medium'
    WHEN 'low' THEN 'low'
    WHEN 's4' THEN 'low'
    WHEN 'info' THEN 'info'
    ELSE 'unknown'
  END)`;
}

/**
 * Effective lifecycle status of a stored row: the first non-blank trimmed
 * lowercase value of `status` then `state`, else `open` (the portal
 * `findingStatus` compatibility fallback). Legacy rows recorded with `state`
 * only keep filtering and counting as their effective lifecycle.
 */
export function findingRowStatus(row) {
  if (row && typeof row === 'object' && !Array.isArray(row)) {
    for (const key of ['status', 'state']) {
      const value = row[key];
      if (value === undefined || value === null) continue;
      const normalized = String(value).trim().toLowerCase();
      if (normalized) return normalized;
    }
  }
  return 'open';
}

/** Columns `q` may scan. Do not add notes, remediation_template, or evidence. */
export const FINDING_LIST_Q_COLUMNS = Object.freeze([
  'title',
  'id',
  'check_id',
  'target_id',
  'target_group_id',
  'assignee',
]);

const CUSTOMER_KEYS = new Set([
  'q',
  'status',
  'severity',
  'check_id',
  'target_group_id',
  'target_id',
  'test_run_id',
  'limit',
  'page',
  'offset',
]);
const INTERNAL_KEYS = new Set(['client']);
const STATUSES = new Set(FINDING_LIFECYCLE);
const ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const SEVERITY_RE = /^[A-Za-z0-9_.:-]{1,32}$/;
const CONTROL_RE = /[\u0000-\u001F\u007F]/;

export class FindingListQueryError extends Error {
  constructor(code, message, field = null, status = 400) {
    super(message);
    this.name = 'FindingListQueryError';
    this.code = code;
    this.field = field;
    this.status = status;
  }
}

function reject(code, message, field) {
  throw new FindingListQueryError(code, message, field, 400);
}

function absent(value) {
  return value == null || value === '';
}

function readId(value, field) {
  if (absent(value)) return null;
  const text = String(value).trim();
  if (!ID_RE.test(text)) reject('invalid_query_value', `${field} is not valid.`, field);
  return text;
}

function readStatus(value) {
  if (absent(value)) return null;
  const text = String(value).trim();
  if (text === 'all') return null;
  if (!STATUSES.has(text)) reject('invalid_query_value', 'Unsupported status.', 'status');
  return text;
}

function readSeverity(value) {
  if (absent(value)) return null;
  const text = String(value).trim();
  if (text === 'all') return null;
  if (!SEVERITY_RE.test(text)) reject('invalid_query_value', 'severity is not valid.', 'severity');
  return text;
}

function readQ(value) {
  if (absent(value)) return null;
  const text = String(value).trim();
  if (text === '') return null;
  if (text.length > FINDING_LIST_MAX_Q) reject('invalid_query_value', 'q is too long.', 'q');
  if (CONTROL_RE.test(text)) reject('invalid_query_value', 'q is not valid.', 'q');
  return text;
}

function readInt(value, field, { min, max }) {
  if (typeof value === 'number' && Number.isInteger(value)) {
    if (value < min || value > max) reject('invalid_query_value', `${field} is out of range.`, field);
    return value;
  }
  const text = String(value).trim();
  if (!/^\d+$/.test(text)) reject('invalid_query_value', `${field} must be an integer.`, field);
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    reject('invalid_query_value', `${field} is out of range.`, field);
  }
  return parsed;
}

/**
 * @param {object} [input]
 * @param {{ paginate?: boolean }} [options] Envelope reads default page 1 and limit 50.
 * Array reads stay unbounded when limit, page, and offset are omitted.
 */
export function parseFindingListQuery(input = {}, { paginate = false } = {}) {
  if (input == null || typeof input !== 'object' || Array.isArray(input)) {
    reject('invalid_query', 'Query must be an object.', 'query');
  }
  const unknown = Object.keys(input).filter((key) => !CUSTOMER_KEYS.has(key) && !INTERNAL_KEYS.has(key));
  if (unknown.length > 0) reject('unknown_query_param', `Unknown query parameter: ${unknown[0]}.`, unknown[0]);

  const filters = {
    q: readQ(input.q),
    status: readStatus(input.status),
    severity: readSeverity(input.severity),
    // Canonical class for the validated token, so a known alias query matches
    // every equivalent recorded class and an unknown token selects the actual
    // unknown class instead of every row. `all`/absent stays null.
    severity_class: input.severity != null && input.severity !== '' && input.severity !== 'all'
      ? findingSeverityClass(input.severity)
      : null,
    check_id: readId(input.check_id, 'check_id'),
    target_group_id: readId(input.target_group_id, 'target_group_id'),
    target_id: readId(input.target_id, 'target_id'),
    test_run_id: readId(input.test_run_id, 'test_run_id'),
  };
  const limit = absent(input.limit)
    ? null
    : readInt(input.limit, 'limit', { min: 1, max: FINDING_LIST_MAX_LIMIT });
  const page = absent(input.page)
    ? null
    : readInt(input.page, 'page', { min: 1, max: FINDING_LIST_MAX_PAGE });
  const offset = absent(input.offset)
    ? null
    : readInt(input.offset, 'offset', { min: 0, max: FINDING_LIST_MAX_PAGE * FINDING_LIST_MAX_LIMIT });

  const appliedLimit = limit ?? ((paginate || page != null) ? FINDING_LIST_DEFAULT_LIMIT : null);
  const appliedPage = page ?? (paginate ? 1 : null);
  let appliedOffset = offset ?? 0;
  if (appliedPage != null) {
    if (appliedLimit == null) reject('invalid_query_value', 'page requires limit.', 'page');
    const fromPage = (appliedPage - 1) * appliedLimit;
    if (offset != null && offset !== fromPage) {
      reject('invalid_query_value', 'offset conflicts with page.', 'offset');
    }
    appliedOffset = fromPage;
  }

  return {
    ...filters,
    limit: appliedLimit,
    offset: appliedOffset,
    page: appliedPage ?? (appliedLimit ? Math.floor(appliedOffset / appliedLimit) + 1 : 1),
  };
}

export function findingListGroupSql(paramRef) {
  return `(f.target_group_id = ${paramRef} OR EXISTS (
    SELECT 1 FROM targets member
    WHERE member.tenant_id = f.tenant_id
      AND member.id = f.target_id
      AND member.target_group_id = ${paramRef}
      AND member.deleted_at IS NULL
  ))`;
}

export function findingListQSql(paramRef) {
  return `(${FINDING_LIST_Q_COLUMNS.map((column) => (
    `strpos(lower(coalesce(f.${column}, '')), lower(${paramRef})) > 0`
  )).join(' OR ')})`;
}

export function findingMatchesListQuery(row, query, memberTargetIds) {
  if (query.target_group_id) {
    const stored = row?.target_group_id === query.target_group_id;
    const member = Boolean(row?.target_id) && memberTargetIds?.has(row.target_id) === true;
    if (!stored && !member) return false;
  }
  if (query.target_id && row?.target_id !== query.target_id) return false;
  if (query.test_run_id && row?.test_run_id !== query.test_run_id) return false;
  if (query.check_id && row?.check_id !== query.check_id) return false;
  // Lifecycle comparison uses the effective row status (`status`, then legacy
  // `state`, else `open`), trimmed and lowercase, matching the portal contract.
  if (query.status && findingRowStatus(row) !== query.status) return false;
  // Severity comparison uses the canonical class so `S2` and `high` are the
  // same effective class for stored rows and for the query.
  if (query.severity != null && findingSeverityClass(row?.severity) !== query.severity_class) return false;
  if (!query.q) return true;
  const needle = query.q.toLowerCase();
  return FINDING_LIST_Q_COLUMNS.some((column) => String(row?.[column] ?? '').toLowerCase().includes(needle));
}

export function findingListEmptyReason(query) {
  if (query.target_group_id) return 'No findings match this target group filter.';
  if (query.target_id) return 'No findings match this target filter.';
  if (query.test_run_id) return 'No findings match this test run filter.';
  if (query.check_id) return 'No findings match this check filter.';
  if (query.status) return 'No findings match this status filter.';
  if (query.severity) return 'No findings match this severity filter.';
  if (query.q) return 'No findings match this search.';
  return 'No findings have been published for this tenant yet.';
}

export function buildFindingListEnvelope(items, total, query) {
  const count = Number(total);
  const limit = query.limit;
  const page = query.page;
  const pages = count === 0 ? 0 : Math.ceil(count / limit);
  return {
    items,
    count,
    total: count,
    page,
    pages,
    has_more: page * limit < count,
    limit,
    meta: {
      empty_reason: count === 0 ? findingListEmptyReason(query) : null,
    },
  };
}

export function findingListQueryFailure(err) {
  if (!(err instanceof FindingListQueryError)) return null;
  return {
    error: err.code,
    message: err.message,
    field: err.field,
    status: err.status,
  };
}
