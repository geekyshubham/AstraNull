/**
 * Shared declared-target list and rollup predicate.
 * Filters rows it is given. Does not derive verdicts, freshness, or provenance.
 * `asOf` is the caller evaluation clock, not a historical estate snapshot.
 */
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { decodeCursor, encodeCursor } from './cursorPagination.mjs';

export const DECLARED_HOST_ANALYTICS_VERSION = 'declared-host-analytics.v1';
export const DECLARED_HOST_SOURCE = 'active_declared_targets';
/** No default estate cap. An explicit `rowBound` is an optional work budget. */
export const DECLARED_HOST_ROW_BOUND = null;
export const DECLARED_HOST_BATCH_SIZE = 200;
export const DECLARED_HOST_LIMIT_MAX = 200;
export const DECLARED_HOST_LIMIT_DEFAULT = 50;

/** Citation of the profile observation window. This module does not apply it. */
export const CITED_OBSERVATION_FRESHNESS_POLICY = Object.freeze({
  id: 'protection-profile.observation.v1',
  version: 1,
  max_age_ms: 7 * 24 * 60 * 60 * 1000,
  unit: 'family_observation',
  applied: false,
});

export const DECLARED_HOST_QUERY_KEYS = Object.freeze([
  'q',
  'target_group_id',
  'verification_state',
  'kind',
  'tag',
  'service_role',
  'criticality',
  'owner_status',
  'owner',
  'family',
  'family_status',
  'freshness',
  'has_open_finding',
  'unit',
  'cursor',
  'limit',
  'as_of',
  'cohort_version',
]);

export const FAMILY_BUCKETS = Object.freeze([
  'detected',
  'not_detected',
  'inconclusive',
  'not_checked',
  'not_recorded',
  'unknown',
  'stale',
  'conflict',
]);

export const SEGMENT_IDS = Object.freeze(['all', 'api', 'login', 'website', 'unclassified']);

const QUERY_KEY_SET = new Set(DECLARED_HOST_QUERY_KEYS);
const SERVICE_ROLES = Object.freeze(['website', 'api', 'login', 'dns', 'network']);
const WEB_ROLES = new Set(['website', 'api', 'login']);
const ROLE_FILTERS = new Set([...SERVICE_ROLES, 'unclassified']);
const CRITICALITY_VALUES = new Set(['critical', 'high', 'medium', 'low']);
const CRITICALITY_FILTERS = new Set([...CRITICALITY_VALUES, 'unassigned', 'unknown']);
const OWNER_STATUSES = new Set(['declared', 'inherited', 'unassigned', 'unknown']);
const VERIFICATION_STATES = new Set([
  'unverified',
  'pending',
  'dns_verified',
  'provider_verified',
  'agent_verified',
  'user_confirmed',
  'unknown',
]);
const KINDS = new Set(['fqdn', 'domain', 'hostname', 'ip', 'cidr', 'url', 'tcp', 'dns_zone', 'canary']);
const HOST_KINDS = new Set(['fqdn', 'domain', 'hostname', 'dns_zone', 'url']);
const FAMILIES = new Set(['waf', 'cdn']);
const FRESHNESS = new Set(['current', 'stale', 'unknown']);
const STATUS_BUCKETS = new Set([
  'detected',
  'not_detected',
  'inconclusive',
  'not_checked',
  'not_recorded',
  'unknown',
]);
const UNITS = new Set(['target', 'hostname']);
const QUERY_ALIASES = Object.freeze({
  search: 'q',
  group: 'target_group_id',
  verification: 'verification_state',
  role: 'service_role',
});
const UNIT_ALIASES = Object.freeze({
  hostname: 'hostname',
  target: 'target',
  normalized_hostname: 'hostname',
  declared_target: 'target',
});
const ECHO_KEYS = Object.freeze([
  'q',
  'target_group_id',
  'verification_state',
  'kind',
  'tag',
  'service_role',
  'criticality',
  'owner_status',
  'owner',
  'family',
  'family_status',
  'freshness',
  'has_open_finding',
  'unit',
]);

const SEGMENT_LABELS = Object.freeze({
  hostname: {
    all: 'All declared hosts',
    api: 'Hosts with declared API role',
    login: 'Hosts with declared login role',
    website: 'Hosts with declared website role',
    unclassified: 'Unclassified hosts',
  },
  target: {
    all: 'All declared targets',
    api: 'Targets with declared API role',
    login: 'Targets with declared login role',
    website: 'Targets with declared website role',
    unclassified: 'Unclassified targets',
  },
});

export class DeclaredHostQueryError extends Error {
  constructor(code, message, field = null, status = 400, extra = null) {
    super(message);
    this.name = 'DeclaredHostQueryError';
    this.code = code;
    this.status = status;
    this.field = field;
    if (extra && typeof extra === 'object') Object.assign(this, extra);
  }
}

function reject(code, message, field, status = 400, extra = null) {
  throw new DeclaredHostQueryError(code, message, field, status, extra);
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function cleanString(value, field, max) {
  if (typeof value !== 'string' && typeof value !== 'number') {
    reject('invalid_query_value', `${field} must be a string.`, field);
  }
  const text = String(value).trim();
  if (!text) return null;
  if (text.length > max) reject('invalid_query_value', `${field} is too long.`, field);
  return text;
}

function percentage(numerator, denominator) {
  if (!denominator) return null;
  return Math.round((numerator * 10000) / denominator) / 100;
}

/**
 * DNS hostname for the declared-host unit.
 * IP, CIDR, and IP-literal URLs return null and stay out of that denominator.
 *
 * @param {{ kind?: unknown, value?: unknown }} row
 * @returns {string | null}
 */
export function normalizedDeclaredHostname(row) {
  const kind = String(row?.kind ?? '').trim().toLowerCase();
  const value = String(row?.value ?? '').trim();
  if (!value || !HOST_KINDS.has(kind)) return null;
  let host = value;
  if (kind === 'url' || /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    try {
      host = new URL(value.includes('://') ? value : `http://${value}`).hostname;
    } catch {
      return null;
    }
  }
  host = host.replace(/^\[|\]$/g, '').replace(/\.+$/g, '').trim();
  if (!host || isIP(host)) return null;
  let ascii = host;
  try {
    ascii = domainToASCII(host) || host;
  } catch {
    return null;
  }
  ascii = ascii.toLowerCase().replace(/\.+$/g, '');
  if (!ascii || ascii.length > 253 || isIP(ascii) || /\s/.test(ascii)) return null;
  return ascii;
}

/**
 * One family observation. Missing input stays `unknown`.
 * Conflict and stale are not collapsed into detected or not_detected.
 *
 * @param {unknown} family
 */
export function familyObservationBucket(family) {
  const record = asObject(family);
  if (!record) return { bucket: 'unknown', freshness: 'unknown' };
  const freshness = FRESHNESS.has(record.freshness) ? record.freshness : 'unknown';
  const conflict = record.conflict === true
    || record.conflicting === true
    || record.conflicting_vendor_signals === true
    || record.status === 'conflict';
  if (conflict) return { bucket: 'conflict', freshness };
  if (freshness === 'stale') return { bucket: 'stale', freshness };
  const status = typeof record.status === 'string' ? record.status.trim().toLowerCase() : '';
  if (STATUS_BUCKETS.has(status)) return { bucket: status, freshness };
  return { bucket: 'unknown', freshness };
}

function emptyBuckets() {
  return Object.fromEntries(FAMILY_BUCKETS.map((bucket) => [bucket, 0]));
}

function isInactive(row) {
  if (row.deleted_at || row.archived_at || row.group_archived_at) return true;
  if (row.group_archived === true || row.active === false) return true;
  return false;
}

function readFamily(row, name) {
  const profile = asObject(row.protection_profile);
  const families = asObject(profile?.families);
  if (!families || !Object.hasOwn(families, name)) return familyObservationBucket(null);
  return familyObservationBucket(families[name]);
}

function roleInfo(row) {
  const declaration = asObject(row.declaration);
  if (!declaration || !Object.hasOwn(declaration, 'service_roles') || !Array.isArray(declaration.service_roles)) {
    return { known: false, roles: [] };
  }
  const found = new Set();
  for (const entry of declaration.service_roles) {
    if (typeof entry !== 'string') continue;
    const role = entry.trim().toLowerCase();
    if (SERVICE_ROLES.includes(role)) found.add(role);
  }
  return { known: true, roles: SERVICE_ROLES.filter((role) => found.has(role)) };
}

function verificationOf(row) {
  if (row.verification_state == null || row.verification_state === '') return 'unknown';
  return String(row.verification_state).trim().toLowerCase();
}

function criticalityOf(row) {
  const criticality = asObject(row.declaration)?.criticality;
  const record = asObject(criticality);
  if (!record) return { kind: 'unknown', value: null };
  const status = typeof record.status === 'string' ? record.status : 'unknown';
  const value = typeof record.value === 'string' ? record.value.trim().toLowerCase() : null;
  if (status === 'unassigned' || ((status === 'declared' || status === 'inherited') && !value)) {
    return { kind: 'unassigned', value: null };
  }
  if ((status === 'declared' || status === 'inherited') && CRITICALITY_VALUES.has(value)) {
    return { kind: 'value', value };
  }
  return { kind: 'unknown', value: null };
}

function ownerOf(row) {
  const owner = asObject(asObject(row.declaration)?.owner);
  if (!owner) return { status: 'unknown', label: null };
  const status = OWNER_STATUSES.has(owner.status) ? owner.status : 'unknown';
  const label = typeof owner.label === 'string' && owner.label.trim()
    ? owner.label.trim().toLowerCase()
    : null;
  return { status, label };
}

function tagsOf(row) {
  if (!Array.isArray(row.tags)) return [];
  return row.tags
    .filter((tag) => typeof tag === 'string')
    .map((tag) => tag.trim().toLowerCase())
    .filter(Boolean);
}

function findingsOf(row) {
  if (!Object.hasOwn(row, 'findings_count') || row.findings_count == null || row.findings_count === '') {
    return null;
  }
  const number = Number(row.findings_count);
  if (!Number.isInteger(number) || number < 0) return null;
  return number > 0;
}

function projectMember(row) {
  return {
    row,
    id: String(row.id),
    hostKey: normalizedDeclaredHostname(row),
    kind: String(row.kind ?? '').trim().toLowerCase(),
    roles: roleInfo(row),
    verification: verificationOf(row),
    criticality: criticalityOf(row),
    owner: ownerOf(row),
    tags: tagsOf(row),
    findings: findingsOf(row),
    waf: readFamily(row, 'waf'),
    cdn: readFamily(row, 'cdn'),
  };
}

function reduceObservation(observations) {
  const buckets = new Set(observations.map((item) => item.bucket));
  const freshnesses = new Set(observations.map((item) => item.freshness));
  return {
    bucket: buckets.size === 1 ? [...buckets][0] : 'conflict',
    freshness: freshnesses.size === 1 ? [...freshnesses][0] : 'unknown',
    disagreement: buckets.size > 1,
  };
}

function unionRoles(members) {
  let known = false;
  const found = new Set();
  for (const member of members) {
    if (!member.roles.known) continue;
    known = true;
    for (const role of member.roles.roles) found.add(role);
  }
  const roles = SERVICE_ROLES.filter((role) => found.has(role));
  return {
    known,
    roles,
    unclassified: known && !roles.some((role) => WEB_ROLES.has(role)),
  };
}

function compareId(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function unitFromMembers(members, unit) {
  const ordered = [...members].sort((left, right) => compareId(left.id, right.id));
  const representative = ordered[0];
  const roles = unionRoles(ordered);
  const waf = reduceObservation(ordered.map((member) => member.waf));
  const cdn = reduceObservation(ordered.map((member) => member.cdn));
  const value = String(representative.row.value ?? '').toLowerCase();
  const sortKey = unit === 'hostname'
    ? [representative.hostKey]
    : [representative.hostKey ?? '', representative.kind, value];
  return {
    id: representative.id,
    sortKey,
    unit,
    members: ordered,
    representative,
    roles,
    waf,
    cdn,
    hostKey: representative.hostKey ?? null,
  };
}

function buildUnits(rows, unit) {
  if (!Array.isArray(rows)) reject('invalid_rows', 'Rows must be an array.', 'rows');
  const members = [];
  for (const row of rows) {
    if (!asObject(row)) reject('invalid_row', 'Each row must be an object.', 'rows');
    if (typeof row.id !== 'string' || !row.id.trim()) {
      reject('invalid_row', 'Each row needs a string id.', 'id');
    }
    if (isInactive(row)) continue;
    members.push(projectMember(row));
  }
  if (unit === 'target') return members.map((member) => unitFromMembers([member], 'target'));
  const groups = new Map();
  for (const member of members) {
    if (!member.hostKey) continue;
    const group = groups.get(member.hostKey);
    if (group) group.push(member);
    else groups.set(member.hostKey, [member]);
  }
  return [...groups.values()].map((group) => unitFromMembers(group, 'hostname'));
}

function textHit(member, needle) {
  const purpose = asObject(member.row.declaration)?.purpose;
  const fields = [member.id, member.row.value, member.row.normalized_value, member.hostKey, purpose];
  return fields.some((field) => typeof field === 'string' && field.toLowerCase().includes(needle));
}

function matchesCriticality(member, filter) {
  if (filter === 'unknown') return member.criticality.kind === 'unknown';
  if (filter === 'unassigned') return member.criticality.kind === 'unassigned';
  return member.criticality.kind === 'value' && member.criticality.value === filter;
}

function matchesRole(roles, serviceRole) {
  if (serviceRole === 'unclassified') return roles.unclassified === true;
  return roles.known === true && roles.roles.includes(serviceRole);
}

function matchesFindings(unit, expected) {
  const states = unit.members.map((member) => member.findings);
  if (expected === true) return states.includes(true);
  return states.length > 0 && states.every((state) => state === false);
}

function matchesUnit(unit, query) {
  if (query.q && !unit.members.some((member) => textHit(member, query.q.toLowerCase()))) return false;
  if (query.target_group_id && !unit.members.some((member) => member.row.target_group_id === query.target_group_id)) {
    return false;
  }
  if (query.kind && !unit.members.some((member) => member.kind === query.kind)) return false;
  if (query.tag && !unit.members.some((member) => member.tags.includes(query.tag))) return false;
  if (query.verification_state && !unit.members.some((member) => member.verification === query.verification_state)) {
    return false;
  }
  if (query.criticality && !unit.members.some((member) => matchesCriticality(member, query.criticality))) {
    return false;
  }
  if (query.owner_status && !unit.members.some((member) => member.owner.status === query.owner_status)) {
    return false;
  }
  if (query.owner && !unit.members.some((member) => member.owner.label === query.owner)) return false;
  if (query.has_open_finding != null && !matchesFindings(unit, query.has_open_finding)) return false;
  if (query.service_role && !matchesRole(unit.roles, query.service_role)) return false;
  if (query.family) {
    const observation = unit[query.family];
    if (query.family_status && observation.bucket !== query.family_status) return false;
    if (query.freshness && observation.freshness !== query.freshness) return false;
  }
  return true;
}

function isAfterCursor(unit, cursor) {
  if (!cursor) return true;
  const length = Math.max(unit.sortKey.length, cursor.k.length);
  for (let index = 0; index < length; index += 1) {
    const left = unit.sortKey[index] ?? '';
    const right = cursor.k[index] ?? '';
    if (left > right) return true;
    if (left < right) return false;
  }
  return unit.id > cursor.id;
}

function echoFilters(query) {
  const filters = {};
  for (const key of ECHO_KEYS) {
    if (query[key] != null) filters[key] = query[key];
  }
  return filters;
}

function listQuery(filters, extra = {}) {
  return { ...filters, ...extra };
}

function roleQueryExact(filters, segment) {
  return segment === 'all' || filters.service_role == null || filters.service_role === segment;
}

function toItem(unit) {
  return {
    ...unit.representative.row,
    analytics: {
      unit: unit.unit,
      host_key: unit.hostKey,
      host_eligible: unit.hostKey != null,
      target_ids: unit.members.map((member) => member.id),
      member_count: unit.members.length,
      roles_known: unit.roles.known,
      segment_roles: [...unit.roles.roles],
      unclassified: unit.roles.unclassified,
      families: {
        waf: { bucket: unit.waf.bucket, freshness: unit.waf.freshness },
        cdn: { bucket: unit.cdn.bucket, freshness: unit.cdn.freshness },
      },
      family_disagreement: {
        waf: unit.waf.disagreement,
        cdn: unit.cdn.disagreement,
      },
    },
  };
}

function bucketPayload(units, family, segmentQuery, segmentExact, filters) {
  const counts = emptyBuckets();
  for (const unit of units) counts[unit[family].bucket] += 1;
  const familyExact = segmentExact
    && filters.family == null
    && filters.family_status == null
    && filters.freshness == null;
  const percentages = {};
  const listQueries = {};
  for (const bucket of FAMILY_BUCKETS) {
    percentages[bucket] = percentage(counts[bucket], units.length);
    listQueries[bucket] = {
      list_query: listQuery(segmentQuery, { family, family_status: bucket }),
      list_query_exact: familyExact,
    };
  }
  return { ...counts, percentages, list_queries: listQueries };
}

function segmentPayload(segment, units, allCount, filters) {
  const exact = roleQueryExact(filters, segment);
  const query = segment === 'all'
    ? { ...filters }
    : listQuery(filters, { service_role: segment });
  return {
    id: segment,
    label: SEGMENT_LABELS[filters.unit][segment],
    unit: filters.unit,
    count: units.length,
    percentage: percentage(units.length, segment === 'all' ? units.length : allCount),
    list_query: query,
    list_query_exact: exact,
    waf: bucketPayload(units, 'waf', query, exact, filters),
    cdn: bucketPayload(units, 'cdn', query, exact, filters),
  };
}

function clockValue(value, field) {
  if (value == null || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) reject('invalid_as_of', `${field} must be a real timestamp.`, field);
  return date.toISOString();
}

function filterFingerprint(filters) {
  return createHash('sha256').update(JSON.stringify(filters)).digest('hex').slice(0, 16);
}

function cohortVersion(filters, cohort) {
  const ids = [];
  for (const unit of cohort) {
    ids.push(unit.id);
    for (const member of unit.members) ids.push(member.id);
  }
  ids.sort();
  return createHash('sha256').update(JSON.stringify({ filters, ids })).digest('hex').slice(0, 32);
}

function applyQueryAliases(source) {
  const query = { ...source };
  for (const [alias, canonical] of Object.entries(QUERY_ALIASES)) {
    if (!Object.hasOwn(query, alias)) continue;
    const aliasValue = query[alias];
    if (Object.hasOwn(query, canonical) && String(query[canonical] ?? '') !== String(aliasValue ?? '')) {
      reject('invalid_query_value', `${alias} conflicts with ${canonical}.`, alias);
    }
    if (!Object.hasOwn(query, canonical) || query[canonical] == null || query[canonical] === '') {
      query[canonical] = aliasValue;
    }
    delete query[alias];
  }
  if (query.unit != null && query.unit !== '') {
    const token = String(query.unit).trim().toLowerCase();
    if (!UNIT_ALIASES[token]) reject('invalid_query_value', 'Unsupported unit.', 'unit');
    query.unit = UNIT_ALIASES[token];
  }
  return query;
}

function parseCursor(value, unit, fingerprint, filters) {
  if (value == null || value === '') return null;
  if (typeof value !== 'string' || value.length > 2048) {
    reject('invalid_cursor', 'Cursor is not valid.', 'cursor');
  }
  const decoded = decodeCursor(value);
  if (!decoded || decoded.v !== 2 || decoded.unit !== unit || typeof decoded.id !== 'string' || !decoded.id) {
    reject('invalid_cursor', 'Cursor is not valid for this query.', 'cursor');
  }
  if (!Array.isArray(decoded.k) || decoded.k.some((part) => typeof part !== 'string')) {
    reject('invalid_cursor', 'Cursor is not valid for this query.', 'cursor');
  }
  if (typeof decoded.fp !== 'string' || typeof decoded.cv !== 'string' || !decoded.cv) {
    reject('invalid_cursor', 'Cursor is not valid for this query.', 'cursor');
  }
  if (decoded.as_of != null && typeof decoded.as_of !== 'string') {
    reject('invalid_cursor', 'Cursor is not valid for this query.', 'cursor');
  }
  if (decoded.fp !== fingerprint) {
    reject('cursor_filter_mismatch', 'Cursor does not match these filters.', 'cursor', 409, { filters });
  }
  return {
    k: decoded.k,
    id: decoded.id,
    unit,
    fp: decoded.fp,
    as_of: decoded.as_of ?? null,
    cv: decoded.cv,
  };
}

function parseLimit(value) {
  if (value == null || value === '') return DECLARED_HOST_LIMIT_DEFAULT;
  const text = typeof value === 'number' ? String(value) : typeof value === 'string' ? value.trim() : '';
  if (!/^[1-9]\d*$/.test(text)) {
    reject('invalid_limit', `limit must be an integer from 1 to ${DECLARED_HOST_LIMIT_MAX}.`, 'limit');
  }
  const number = Number(text);
  if (number > DECLARED_HOST_LIMIT_MAX) {
    reject('invalid_limit', `limit must be an integer from 1 to ${DECLARED_HOST_LIMIT_MAX}.`, 'limit');
  }
  return number;
}

function optionalEnum(value, field, allowed) {
  if (value == null || value === '') return null;
  const text = cleanString(value, field, 80);
  if (text == null) return null;
  const normalized = text.toLowerCase();
  if (!allowed.has(normalized)) reject('invalid_query_value', `Unsupported ${field}.`, field);
  return normalized;
}

/**
 * Unknown query keys and unknown enum values are rejected.
 * A typo must not silently widen the cohort.
 *
 * @param {unknown} query
 * @param {{ asOf?: unknown }} [options]
 */
export function normalizeDeclaredHostQuery(query, options = {}) {
  const input = query == null ? {} : asObject(query);
  if (!input) reject('invalid_query', 'Query must be an object.', 'query');
  const source = applyQueryAliases(input);
  for (const key of Object.keys(source)) {
    if (!QUERY_KEY_SET.has(key)) reject('unknown_query_param', `Unknown query parameter "${key}".`, key);
  }
  const family = optionalEnum(source.family, 'family', FAMILIES);
  const familyStatus = optionalEnum(source.family_status, 'family_status', new Set(FAMILY_BUCKETS));
  const freshness = optionalEnum(source.freshness, 'freshness', FRESHNESS);
  if ((familyStatus || freshness) && !family) {
    reject('family_required', 'family is required with family_status or freshness.', 'family');
  }
  let hasOpenFinding = null;
  if (source.has_open_finding != null && source.has_open_finding !== '') {
    const text = String(source.has_open_finding).trim().toLowerCase();
    if (text !== 'true' && text !== 'false') {
      reject('invalid_query_value', 'has_open_finding must be true or false.', 'has_open_finding');
    }
    hasOpenFinding = text === 'true';
  }
  const tag = source.tag == null || source.tag === ''
    ? null
    : cleanString(source.tag, 'tag', 48)?.toLowerCase() ?? null;
  if (tag && !/^[a-z0-9][a-z0-9:_.-]{0,47}$/.test(tag)) {
    reject('invalid_query_value', 'tag is not a valid tag.', 'tag');
  }
  const targetGroupId = source.target_group_id == null || source.target_group_id === ''
    ? null
    : cleanString(source.target_group_id, 'target_group_id', 80);
  if (targetGroupId && !/^[A-Za-z0-9_.:-]{1,80}$/.test(targetGroupId)) {
    reject('invalid_query_value', 'target_group_id is not valid.', 'target_group_id');
  }
  const defaultUnit = options.defaultUnit ?? 'target';
  if (!UNITS.has(defaultUnit)) reject('invalid_query_value', 'Unsupported unit.', 'unit');
  const unit = optionalEnum(source.unit, 'unit', UNITS) ?? defaultUnit;
  const cohortVersionRequested = source.cohort_version == null || source.cohort_version === ''
    ? null
    : cleanString(source.cohort_version, 'cohort_version', 64);
  if (cohortVersionRequested && !/^[A-Za-z0-9_-]{8,64}$/.test(cohortVersionRequested)) {
    reject('invalid_query_value', 'cohort_version is not valid.', 'cohort_version');
  }
  const filters = {
    q: source.q == null || source.q === '' ? null : cleanString(source.q, 'q', 200),
    target_group_id: targetGroupId,
    verification_state: optionalEnum(source.verification_state, 'verification_state', VERIFICATION_STATES),
    kind: optionalEnum(source.kind, 'kind', KINDS),
    tag,
    service_role: optionalEnum(source.service_role, 'service_role', ROLE_FILTERS),
    criticality: optionalEnum(source.criticality, 'criticality', CRITICALITY_FILTERS),
    owner_status: optionalEnum(source.owner_status, 'owner_status', OWNER_STATUSES),
    owner: (() => {
      if (source.owner == null || source.owner === '') return null;
      const owner = cleanString(source.owner, 'owner', 80);
      return owner ? owner.toLowerCase() : null;
    })(),
    family,
    family_status: familyStatus,
    freshness,
    has_open_finding: hasOpenFinding,
    unit,
  };
  const echoed = echoFilters(filters);
  const fingerprint = filterFingerprint(echoed);
  const cursor = parseCursor(source.cursor, unit, fingerprint, echoed);
  const queryClock = clockValue(source.as_of, 'as_of');
  const optionClock = clockValue(options.asOf, 'asOf');
  if (queryClock && optionClock && queryClock !== optionClock) {
    reject('invalid_as_of', 'as_of does not match the evaluation clock.', 'as_of');
  }
  let asOf = queryClock ?? optionClock;
  if (cursor) {
    if (asOf && cursor.as_of !== asOf) {
      reject('cursor_clock_mismatch', 'Cursor clock does not match as_of.', 'cursor', 409, {
        filters: echoFilters(filters),
        as_of: asOf,
      });
    }
    if (!asOf) asOf = cursor.as_of;
  }
  return {
    ...filters,
    fingerprint,
    cohort_version: cohortVersionRequested,
    cursor,
    limit: parseLimit(source.limit),
    as_of: asOf,
    as_of_semantics: asOf ? 'caller_evaluation_clock' : 'not_recorded',
  };
}

function selectCohort(rows, normalized) {
  return buildUnits(rows, normalized.unit)
    .filter((unit) => matchesUnit(unit, normalized))
    .sort((left, right) => {
      const length = Math.max(left.sortKey.length, right.sortKey.length);
      for (let index = 0; index < length; index += 1) {
        const a = left.sortKey[index] ?? '';
        const b = right.sortKey[index] ?? '';
        if (a < b) return -1;
        if (a > b) return 1;
      }
      return compareId(left.id, right.id);
    });
}

function pageCohort(cohort, normalized) {
  const visible = cohort.filter((unit) => isAfterCursor(unit, normalized.cursor));
  const page = visible.slice(0, normalized.limit);
  const last = page[page.length - 1];
  const next = visible.length > normalized.limit && last
    ? encodeCursor({
      v: 2,
      unit: normalized.unit,
      k: last.sortKey,
      id: last.id,
      fp: normalized.fingerprint,
      as_of: normalized.as_of,
      cv: normalized.cohort_stamp,
    })
    : null;
  return { items: page.map(toItem), next_cursor: next };
}

function projectRollup(cohort, normalized) {
  const filters = echoFilters(normalized);
  const segments = {};
  for (const segment of SEGMENT_IDS) {
    const subset = segment === 'all'
      ? cohort
      : cohort.filter((unit) => matchesRole(unit.roles, segment));
    segments[segment] = segmentPayload(segment, subset, cohort.length, filters);
  }
  return {
    source: DECLARED_HOST_SOURCE,
    version: DECLARED_HOST_ANALYTICS_VERSION,
    scope: 'current',
    historical: false,
    snapshot_id: null,
    as_of: normalized.as_of,
    as_of_semantics: normalized.as_of_semantics,
    freshness_policy: CITED_OBSERVATION_FRESHNESS_POLICY,
    unit: normalized.unit,
    filters,
    total: cohort.length,
    segments,
  };
}

function listFrom(cohort, normalized) {
  const page = pageCohort(cohort, normalized);
  return {
    items: page.items,
    count: page.items.length,
    total: cohort.length,
    next_cursor: page.next_cursor,
    filters: echoFilters(normalized),
    as_of: normalized.as_of,
    as_of_semantics: normalized.as_of_semantics,
    unit: normalized.unit,
    limit: normalized.limit,
    scope: 'current',
    historical: false,
    snapshot_id: null,
  };
}

/**
 * @param {readonly object[]} rows
 * @param {unknown} query
 * @param {{ asOf?: unknown }} [options]
 */
function scopeChanged(normalized, filters) {
  return {
    filters,
    as_of: normalized.as_of,
    scope: 'current',
    historical: false,
  };
}

function evaluateNormalized(rows, normalized) {
  const cohort = selectCohort(rows, normalized);
  const otherUnit = normalized.unit === 'hostname' ? 'target' : 'hostname';
  const other = selectCohort(rows, { ...normalized, unit: otherUnit });
  const units = {
    target_records: normalized.unit === 'target' ? cohort.length : other.length,
    normalized_hosts: normalized.unit === 'hostname' ? cohort.length : other.length,
  };
  const filters = echoFilters(normalized);
  const version = cohortVersion(filters, cohort);
  if (normalized.cohort_version && normalized.cohort_version !== version) {
    reject(
      'cohort_changed',
      'The cohort changed. Repeat the same filters without cohort_version.',
      'cohort_version',
      409,
      scopeChanged(normalized, filters),
    );
  }
  if (normalized.cursor && normalized.cursor.cv !== version) {
    reject(
      'cohort_changed',
      'The cursor cohort no longer matches this scope. Repeat the same filters without the cursor.',
      'cursor',
      409,
      scopeChanged(normalized, filters),
    );
  }
  const stamped = { ...normalized, cohort_stamp: version };
  const list = listFrom(cohort, stamped);
  const rollup = projectRollup(cohort, stamped);
  rollup.cohort_version = version;
  rollup.units = units;
  return { complete: true, ...list, units, cohort_version: version, rollup };
}

export function evaluateDeclaredHostAnalytics(rows, query, options = {}) {
  return evaluateNormalized(rows, normalizeDeclaredHostQuery(query, options));
}

/**
 * Filtered, stable, paginated list. `total` is the full predicate, not the page.
 *
 * @param {readonly object[]} rows
 * @param {unknown} query
 * @param {{ asOf?: unknown }} [options]
 */
export function applyDeclaredTargetQuery(rows, query, options = {}) {
  const evaluated = evaluateDeclaredHostAnalytics(rows, query, options);
  const { rollup: _rollup, complete: _complete, ...list } = evaluated;
  return list;
}

/**
 * Rollup of the same cohort `applyDeclaredTargetQuery` pages.
 *
 * @param {readonly object[]} rows
 * @param {unknown} query
 * @param {{ asOf?: unknown }} [options]
 */
export function projectDeclaredHostRollup(rows, query, options = {}) {
  return evaluateDeclaredHostAnalytics(rows, query, options).rollup;
}

function boundOption(value, fallback, max, field) {
  if (value == null) return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > max) {
    reject('invalid_read_bound', `${field} must be an integer from 1 to ${max}.`, field);
  }
  return number;
}

function incomplete(normalized, rowBound) {
  const filters = echoFilters(normalized);
  return {
    complete: false,
    unavailable_reason: 'read_bound_exceeded',
    read_bound: rowBound,
    items: [],
    count: 0,
    total: null,
    next_cursor: null,
    filters,
    as_of: normalized.as_of,
    as_of_semantics: normalized.as_of_semantics,
    unit: normalized.unit,
    limit: normalized.limit,
    scope: 'current',
    historical: false,
    snapshot_id: null,
    cohort_version: null,
    units: { target_records: null, normalized_hosts: null },
    rollup: null,
  };
}

function optionalRowBound(value) {
  if (value == null || value === '') return null;
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1) {
    reject('invalid_read_bound', 'rowBound must be a positive integer.', 'rowBound');
  }
  return number;
}

/**
 * Load projected rows through a bounded id keyset, then apply the shared predicate.
 * The default reads the finite snapshot to completion. An explicit rowBound is a work
 * budget: crossing it returns complete:false and total:null. The bound is never `total`.
 *
 * ponytail: the whole snapshot is filtered in memory. Upgrade path: SQL predicate
 * pushdown once the presentation columns are stable, still calling this normalizer.
 *
 * @param {(request: { afterId: string | null, limit: number }) => Promise<object[]>} readBatch
 * @param {unknown} query
 * @param {{ asOf?: unknown, batchSize?: number, rowBound?: number }} [options]
 */
export async function readDeclaredHostCohort(readBatch, query, options = {}) {
  if (typeof readBatch !== 'function') reject('invalid_reader', 'readBatch must be a function.', 'readBatch');
  const normalized = normalizeDeclaredHostQuery(query, options);
  const batchSize = boundOption(options.batchSize, DECLARED_HOST_BATCH_SIZE, DECLARED_HOST_BATCH_SIZE, 'batchSize');
  const rowBound = optionalRowBound(options.rowBound);
  const rows = [];
  let afterId = null;
  for (;;) {
    const room = rowBound == null ? batchSize : Math.min(batchSize, rowBound - rows.length);
    if (room < 1) break;
    const batch = await readBatch({ afterId, limit: room });
    if (!Array.isArray(batch)) reject('invalid_reader', 'readBatch must return an array.', 'readBatch');
    if (batch.length > room) reject('invalid_reader', 'readBatch exceeded the requested limit.', 'readBatch');
    if (batch.length === 0) return evaluateNormalized(rows, normalized);
    for (const row of batch) {
      if (!asObject(row) || typeof row.id !== 'string' || !row.id) {
        reject('invalid_reader', 'Each batch row needs a string id.', 'id');
      }
      rows.push(row);
    }
    afterId = batch[batch.length - 1].id;
    if (batch.length < room) return evaluateNormalized(rows, normalized);
    if (rowBound != null && rows.length >= rowBound) break;
  }
  const extra = await readBatch({ afterId, limit: 1 });
  if (!Array.isArray(extra)) reject('invalid_reader', 'readBatch must return an array.', 'readBatch');
  if (extra.length > 0) return incomplete(normalized, rowBound);
  return evaluateNormalized(rows, normalized);
}
