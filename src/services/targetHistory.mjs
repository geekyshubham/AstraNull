/**
 * Retained target and layer observations.
 *
 * Append-only history plus a current pointer ordered by
 * (observed_at, source_completed_at, id). A late older result does not replace
 * the current successful observation. A timeout, TLS failure, or DNS failure is
 * a failed attempt, not a fresh negative and not provider loss. The current row
 * is never projected backwards into history.
 */
import { createHash, randomBytes } from 'node:crypto';
import { roleHasPermission } from '../contracts/roles.mjs';
import { requirePermission } from '../rbac.mjs';
import { clampPageLimit, decodeCursor, encodeCursor } from '../lib/cursorPagination.mjs';
import { getStore, persistStore } from '../store.mjs';
import { originObservationOf } from '../lib/externalObservationOutcomes.mjs';

export const OBSERVATION_FAMILIES = Object.freeze([
  'waf', 'cdn', 'cloud', 'dns', 'origin_hosting', 'maintenance',
]);
export const SUCCESSFUL_OUTCOMES = Object.freeze(['detected', 'not_detected', 'pass', 'fail', 'reachable', 'unreachable', 'denied']);
export const TRANSPORT_FAILURE_OUTCOMES = Object.freeze([
  'timeout', 'tls_failure', 'dns_failure', 'transport_failure', 'source_disconnected',
]);
export const RETAINED_OUTCOMES = Object.freeze(['inconclusive', 'canceled', 'cancelled', 'stale', 'error', 'pending']);
export const CLOCK_SKEW_MS = 120_000;
const SOURCE_KINDS = new Set(['edge_detection', 'validation_run', 'explicit_record']);
const PRODUCER_KINDS = new Set(['live_external', 'signed_probe', 'internal_simulation', 'customer_declaration', 'manual']);
const FORBIDDEN_PROVENANCE = /header|cookie|authorization|password|secret|token|credential|body|raw/i;
// Same summary-policy shapes as the evidence-context string filter: cookie, set-cookie,
// authorization, and Basic credential strings never survive provenance.
const FORBIDDEN_VALUE = /cookie\s*[=:]|set-cookie\s*:|authorization\s*:|bearer\s+|\bbasic\s+[a-z0-9+/=]{8,}/i;

const successSet = new Set(SUCCESSFUL_OUTCOMES);
const transportSet = new Set(TRANSPORT_FAILURE_OUTCOMES);
const retainedSet = new Set(RETAINED_OUTCOMES);

function error(code, status, extra = {}) {
  return { error: code, status, ...extra };
}

function hasPermission(ctx, permission) {
  if (!roleHasPermission(ctx?.role, permission)) return false;
  if (Array.isArray(ctx?.scopes)) return ctx.scopes.includes('*') || ctx.scopes.includes(permission);
  return true;
}

function gate(ctx, permissions) {
  if (permissions.some((permission) => hasPermission(ctx, permission))) return { ok: true };
  return requirePermission(ctx, permissions[0], { resource_type: 'target_observation' });
}

const TIMESTAMP_SHAPE = /^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|z|[+-]\d{2}:?\d{2})?$/;

/**
 * UTC string with six fractional digits. A string source keeps its recorded
 * sub-millisecond precision (Postgres `to_char(..., US)` writes the same shape),
 * so equal-millisecond rows still order by real microseconds. Date and number
 * inputs carry millisecond precision and are padded to the same six-digit shape.
 */
export function normalizeObservationTimestamp(value) {
  if (value == null || value === '') return null;
  if (value instanceof Date || typeof value === 'number') {
    const instant = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(instant.getTime())) return null;
    return instant.toISOString().replace(/\.(\d{3})Z$/, '.$1000Z');
  }
  const text = String(value).trim();
  if (!text) return null;
  const match = text.match(TIMESTAMP_SHAPE);
  if (match) {
    const [, datePart, timePart, fractionRaw = '', offsetRaw = ''] = match;
    const offset = /^[+-]/.test(offsetRaw)
      ? offsetRaw.replace(/^([+-]\d{2})(\d{2})$/, '$1:$2')
      : (offsetRaw ? 'Z' : '');
    const base = new Date(`${datePart}T${timePart}${offset}`);
    if (Number.isNaN(base.getTime())) return null;
    return `${base.toISOString().slice(0, 19)}.${(fractionRaw + '000000').slice(0, 6)}Z`;
  }
  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().replace(/\.(\d{3})Z$/, '.$1000Z');
}

export function compareObservationOrder(left, right) {
  const leftObserved = normalizeObservationTimestamp(left?.observed_at) ?? '';
  const rightObserved = normalizeObservationTimestamp(right?.observed_at) ?? '';
  if (leftObserved !== rightObserved) return leftObserved < rightObserved ? -1 : 1;
  const leftCompleted = normalizeObservationTimestamp(left?.source_completed_at) ?? '';
  const rightCompleted = normalizeObservationTimestamp(right?.source_completed_at) ?? '';
  if (leftCompleted !== rightCompleted) return leftCompleted < rightCompleted ? -1 : 1;
  const leftId = String(left?.id ?? '');
  const rightId = String(right?.id ?? '');
  if (leftId !== rightId) return leftId < rightId ? -1 : 1;
  return 0;
}

export function classifyAttempt(outcome) {
  if (successSet.has(outcome)) return 'successful';
  if (transportSet.has(outcome)) return 'failed_attempt';
  if (retainedSet.has(outcome)) return 'retained_noncurrent';
  return null;
}

/** Map a probe result onto a failed-attempt outcome. A normal result returns null. */
export function transportOutcomeFromProbe(metadata = {}) {
  const errorClass = String(metadata?.error_class ?? '').toLowerCase();
  const external = String(metadata?.external_result ?? '').toLowerCase();
  const raw = `${errorClass} ${external}`;
  if (raw.includes('timeout')) return 'timeout';
  if (raw.includes('tls')) return 'tls_failure';
  if (raw.includes('dns')) return 'dns_failure';
  if (errorClass || external === 'error' || raw.includes('transport') || raw.includes('disconnect')) {
    return 'transport_failure';
  }
  return null;
}

const ORIGIN_OBSERVATION_HISTORY_OUTCOMES = Object.freeze({
  response_observed: 'reachable',
  application_identity_confirmed: 'reachable',
  explicit_denial_observed: 'denied',
  no_response: 'timeout',
  transport_error: 'transport_failure',
});

/**
 * Origin-check outcome. Unrecognized results are omitted rather than invented. A legacy
 * `blocked` without explicit denial evidence cannot distinguish refusal from denial, so it is omitted.
 */
export function originOutcomeFromProbe(metadata = {}) {
  const observation = originObservationOf(metadata);
  if (observation?.outcome === 'transport_error') return transportOutcomeFromProbe(metadata) ?? 'transport_failure';
  if (observation) return ORIGIN_OBSERVATION_HISTORY_OUTCOMES[observation.outcome] ?? null;
  const transport = transportOutcomeFromProbe(metadata);
  if (transport) return transport;
  const external = String(metadata?.external_result ?? '').toLowerCase();
  if (external === 'connected') return 'reachable';
  if (external === 'blocked' || external === 'unreachable') return null;
  if (successSet.has(external)) return external;
  return null;
}

export function observationTimeError({ observedAt, sourceCompletedAt = null, declaredAt, now = new Date() }) {
  const observed = normalizeObservationTimestamp(observedAt);
  const declared = normalizeObservationTimestamp(declaredAt);
  const completed = sourceCompletedAt == null || sourceCompletedAt === ''
    ? null
    : normalizeObservationTimestamp(sourceCompletedAt);
  if (!observed) return error('invalid_timestamp', 400, { field: 'observed_at' });
  if (sourceCompletedAt != null && sourceCompletedAt !== '' && !completed) {
    return error('invalid_timestamp', 400, { field: 'source_completed_at' });
  }
  if (!declared) return error('declaration_time_unknown', 409);
  const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
  const latest = normalizeObservationTimestamp(nowMs + CLOCK_SKEW_MS);
  if (latest && (observed > latest || (completed && completed > latest))) {
    return error('future_timestamp', 400);
  }
  if (observed < declared || (completed && completed < declared)) {
    return error('before_declaration', 400);
  }
  return { observed_at: observed, source_completed_at: completed, declared_at: declared };
}

export function redactProvenance(input) {
  const source = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const out = {};
  for (const [key, value] of Object.entries(source)) {
    if (FORBIDDEN_PROVENANCE.test(key)) continue;
    if (typeof value === 'string') {
      if (value.length > 200 || FORBIDDEN_VALUE.test(value)) continue;
      out[key] = value;
    } else if (typeof value === 'number') {
      if (Number.isFinite(value)) out[key] = value;
    } else if (typeof value === 'boolean') {
      out[key] = value;
    }
  }
  return out;
}

function stableStringify(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

export function observationDigest(record) {
  return createHash('sha256').update(stableStringify({
    tenant_id: record.tenant_id,
    target_id: record.target_id,
    family: record.family,
    check_id: record.check_id,
    test_run_id: record.test_run_id,
    source_kind: record.source_kind,
    source_id: record.source_id,
    corpus_version: record.corpus_version,
    scenario_version: record.scenario_version,
    check_version: record.check_version,
    observed_at: record.observed_at,
    source_completed_at: record.source_completed_at,
    outcome: record.outcome,
    producer_kind: record.producer_kind,
    origin_binding_id: record.origin_binding_id,
    provenance: record.provenance,
  })).digest('hex');
}

export function encodeObservationCursor(row) {
  return encodeCursor({
    observed_at: row.observed_at,
    source_completed_at: row.source_completed_at ?? null,
    id: row.id,
  });
}

export function decodeObservationCursor(cursor) {
  if (cursor == null || cursor === '') return { cursor: null };
  const decoded = decodeCursor(cursor);
  const observed = normalizeObservationTimestamp(decoded?.observed_at);
  const id = typeof decoded?.id === 'string' ? decoded.id : '';
  if (!decoded || !observed || !id) return error('invalid_cursor', 400);
  const completed = decoded.source_completed_at == null || decoded.source_completed_at === ''
    ? null
    : normalizeObservationTimestamp(decoded.source_completed_at);
  if (decoded.source_completed_at != null && decoded.source_completed_at !== '' && !completed) {
    return error('invalid_cursor', 400);
  }
  return { cursor: { observed_at: observed, source_completed_at: completed, id } };
}

function blankComparison(reason) {
  return { comparable: false, reason, change: null, direction: null };
}

/**
 * Provider identity is the safe recorded provenance string only. It is never
 * inferred from another family, from a derived vendor projection, or from a
 * historical backfill. A row with no recorded provider stays a comparison gap.
 */
export function recordedProvider(row) {
  const source = row?.provenance && typeof row.provenance === 'object' && !Array.isArray(row.provenance)
    ? row.provenance
    : (row?.provenance_json && typeof row.provenance_json === 'object' && !Array.isArray(row.provenance_json)
      ? row.provenance_json
      : null);
  const provider = source?.provider;
  if (typeof provider !== 'string' || !provider.trim()) return null;
  return provider.trim();
}

function directionFor(previous, next) {
  if (previous === 'pass' && next === 'fail') return 'regression';
  if (previous === 'fail' && next === 'pass') return 'improvement';
  if (previous === 'detected' && next === 'not_detected') return 'disappeared';
  if (previous === 'not_detected' && next === 'detected') return 'appeared';
  if (previous === 'reachable' && next === 'unreachable') return 'disappeared';
  if (previous === 'unreachable' && next === 'reachable') return 'appeared';
  if (previous === 'reachable' && next === 'denied') return 'disappeared';
  if (previous === 'denied' && next === 'reachable') return 'appeared';
  return 'unclassified';
}

export function assessComparability(left, right) {
  if (!left || !right) return blankComparison('missing_observation');
  const transport = transportSet.has(left.outcome) || transportSet.has(right.outcome);
  if (left.attempt_class !== 'successful' || right.attempt_class !== 'successful') {
    return blankComparison(transport ? 'transport_failure' : 'not_successful');
  }
  if (left.target_id !== right.target_id) return blankComparison('target_mismatch');
  if (left.check_id !== right.check_id) return blankComparison('check_mismatch');
  if (!left.corpus_version || !right.corpus_version || !left.scenario_version || !right.scenario_version
    || !left.check_version || !right.check_version) {
    return blankComparison('missing_version');
  }
  if (left.corpus_version !== right.corpus_version) return blankComparison('corpus_changed');
  if (left.scenario_version !== right.scenario_version) return blankComparison('scenario_changed');
  if (left.check_version !== right.check_version) return blankComparison('check_version_changed');
  if ((left.family ?? null) !== (right.family ?? null)) return blankComparison('context_mismatch');
  if ((left.origin_binding_id ?? null) !== (right.origin_binding_id ?? null)) return blankComparison('context_mismatch');
  if ((left.producer_kind ?? null) !== (right.producer_kind ?? null)) return blankComparison('context_mismatch');
  const beforeProvider = recordedProvider(left);
  const afterProvider = recordedProvider(right);
  if (left.outcome === right.outcome) {
    if (beforeProvider != null && afterProvider != null) {
      if (beforeProvider !== afterProvider) {
        return {
          comparable: true,
          reason: null,
          change: 'changed',
          direction: 'provider_changed',
          details: { before_provider: beforeProvider, after_provider: afterProvider },
        };
      }
      return { comparable: true, reason: null, change: 'unchanged', direction: null };
    }
    // Provider identity is the recorded vendor evidence only. It is not required to
    // compare the same generic check outcome (pass/fail), the same bound origin
    // reachability result (reachable/unreachable), or a same `not_detected`
    // absence: those stay backed-behavior comparable without a provider gap. A
    // same `detected` result whose vendor was not recorded is a comparison gap.
    if (left.outcome !== 'detected') {
      return { comparable: true, reason: null, change: 'unchanged', direction: null };
    }
    return blankComparison('provider_not_recorded');
  }
  return { comparable: true, reason: null, change: 'changed', direction: directionFor(left.outcome, right.outcome) };
}

export function projectObservation(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_id: row.target_id,
    target_group_id: row.target_group_id,
    family: row.family,
    check_id: row.check_id,
    test_run_id: row.test_run_id ?? null,
    source_kind: row.source_kind,
    source_id: row.source_id ?? null,
    corpus_version: row.corpus_version ?? null,
    scenario_version: row.scenario_version ?? null,
    check_version: row.check_version ?? null,
    observed_at: row.observed_at,
    source_completed_at: row.source_completed_at ?? null,
    outcome: row.outcome,
    attempt_class: row.attempt_class,
    producer_kind: row.producer_kind ?? null,
    origin_binding_id: row.origin_binding_id ?? null,
    provenance: redactProvenance(row.provenance ?? row.provenance_json),
    created_at: row.created_at ?? null,
  };
}

function observationsOf(store) {
  if (!Array.isArray(store.targetObservations)) store.targetObservations = [];
  return store.targetObservations;
}

function currentsOf(store) {
  if (!Array.isArray(store.targetObservationCurrents)) store.targetObservationCurrents = [];
  return store.targetObservationCurrents;
}

function findTarget(store, tenantId, targetId) {
  return (store.targets ?? []).find((target) => target.tenant_id === tenantId && target.id === targetId) ?? null;
}

export function prepareObservation(input, context) {
  const tenantId = context?.tenantId;
  const target = context?.target ?? null;
  const serverDerived = context?.serverDerived === true;
  if (!tenantId) return error('invalid_tenant', 400);
  if (!target || target.tenant_id !== tenantId || target.deleted_at || target.archived_at) {
    return error('unknown_target', 404);
  }
  if (!serverDerived && (input?.producer_kind != null || input?.check_version != null || input?.server_derived === true)) {
    return error('body_supplied_version', 400);
  }
  if (input?.target_group_id && input.target_group_id !== target.target_group_id) {
    return error('target_group_mismatch', 409);
  }
  if (!OBSERVATION_FAMILIES.includes(input?.family)) return error('invalid_family', 400);
  if (!input?.check_id || typeof input.check_id !== 'string') return error('invalid_check', 400);
  if (!SOURCE_KINDS.has(input?.source_kind)) return error('invalid_source', 400);
  const attemptClass = classifyAttempt(input?.outcome);
  if (!attemptClass) return error('invalid_outcome', 400);
  const producer = input?.producer_kind ?? null;
  if (producer != null && !PRODUCER_KINDS.has(producer)) return error('invalid_producer', 400);
  const times = observationTimeError({
    observedAt: input.observed_at,
    sourceCompletedAt: input.source_completed_at,
    declaredAt: target.created_at,
    now: context.now ?? new Date(),
  });
  if (times.error) return times;
  const nonce = typeof input.nonce === 'string' && input.nonce.trim() ? input.nonce.trim() : null;
  const eventId = typeof input.event_id === 'string' && input.event_id.trim() ? input.event_id.trim() : null;
  if (!nonce && !eventId) return error('missing_idempotency', 400);
  const binding = context.binding ?? null;
  if (input.origin_binding_id) {
    if (!binding || binding.tenant_id !== tenantId || binding.id !== input.origin_binding_id) {
      return error('unknown_origin_binding', 404);
    }
    if (binding.origin_target_id !== target.id) return error('binding_target_mismatch', 409);
    if (Date.parse(times.observed_at) < Date.parse(binding.created_at)) {
      return error('observation_predates_binding', 409);
    }
  }
  const provenance = redactProvenance(input.provenance);
  const record = {
    tenant_id: tenantId,
    target_id: target.id,
    target_group_id: target.target_group_id,
    family: input.family,
    check_id: input.check_id,
    test_run_id: input.test_run_id ?? null,
    source_kind: input.source_kind,
    source_id: input.source_id ?? null,
    corpus_version: input.corpus_version || null,
    scenario_version: input.scenario_version || null,
    check_version: serverDerived ? (input.check_version || null) : null,
    observed_at: times.observed_at,
    source_completed_at: times.source_completed_at,
    outcome: input.outcome,
    attempt_class: attemptClass,
    producer_kind: serverDerived ? producer : null,
    origin_binding_id: input.origin_binding_id ?? null,
    provenance,
    nonce,
    event_id: eventId,
  };
  record.digest = observationDigest(record);
  return { record };
}

function relationConflict(existing, record) {
  if (existing.digest !== record.digest) return true;
  if (record.nonce && existing.nonce && record.nonce !== existing.nonce) return true;
  if (record.event_id && existing.event_id && record.event_id !== existing.event_id) return true;
  return false;
}

function matchingRows(rows, record) {
  return rows.filter((row) => row.tenant_id === record.tenant_id && (
    (record.nonce && row.nonce === record.nonce)
    || (record.event_id && row.event_id === record.event_id)
    || row.digest === record.digest
  ));
}

function pointerTimes(row) {
  return {
    id: row.id,
    observed_at: row.observed_at,
    source_completed_at: row.source_completed_at ?? null,
  };
}

function preferPointer(current, candidate) {
  if (!candidate?.id) return current;
  if (!current?.id) return candidate;
  return compareObservationOrder(candidate, current) > 0 ? candidate : current;
}

function applyCurrent(currents, record) {
  if (record.attempt_class === 'retained_noncurrent') return;
  let row = currents.find((entry) => entry.tenant_id === record.tenant_id
    && entry.target_id === record.target_id
    && entry.family === record.family);
  if (!row) {
    row = {
      tenant_id: record.tenant_id,
      target_id: record.target_id,
      family: record.family,
      successful_observation_id: null,
      successful_observed_at: null,
      successful_source_completed_at: null,
      failed_attempt_observation_id: null,
      failed_observed_at: null,
      failed_source_completed_at: null,
      updated_at: record.created_at,
    };
    currents.push(row);
  }
  const candidate = pointerTimes(record);
  if (record.attempt_class === 'successful') {
    const next = preferPointer(row.successful_observation_id ? {
      id: row.successful_observation_id,
      observed_at: row.successful_observed_at,
      source_completed_at: row.successful_source_completed_at,
    } : null, candidate);
    row.successful_observation_id = next?.id ?? null;
    row.successful_observed_at = next?.observed_at ?? null;
    row.successful_source_completed_at = next?.source_completed_at ?? null;
  } else if (record.attempt_class === 'failed_attempt') {
    const next = preferPointer(row.failed_attempt_observation_id ? {
      id: row.failed_attempt_observation_id,
      observed_at: row.failed_observed_at,
      source_completed_at: row.failed_source_completed_at,
    } : null, candidate);
    row.failed_attempt_observation_id = next?.id ?? null;
    row.failed_observed_at = next?.observed_at ?? null;
    row.failed_source_completed_at = next?.source_completed_at ?? null;
  }
  row.updated_at = record.created_at;
}

export function acceptTargetObservation(ctx, input = {}, options = {}) {
  const store = getStore();
  const target = findTarget(store, ctx?.tenantId, input.target_id);
  const binding = input.origin_binding_id
    ? (store.originBindings ?? []).find((row) => row.id === input.origin_binding_id && row.tenant_id === ctx?.tenantId) ?? null
    : null;
  const prepared = prepareObservation(input, {
    tenantId: ctx?.tenantId,
    target,
    binding,
    now: options.now,
    serverDerived: options.internal === true,
  });
  if (prepared.error) return prepared;
  const rows = observationsOf(store);
  const matches = matchingRows(rows, prepared.record);
  const distinct = [...new Map(matches.map((row) => [row.id, row])).values()];
  if (distinct.length > 1 || (distinct[0] && relationConflict(distinct[0], prepared.record))) {
    return error('idempotency_conflict', 409);
  }
  if (distinct[0]) return { ...projectObservation(distinct[0]), replayed: true };
  const record = {
    ...prepared.record,
    id: `obs_${randomBytes(8).toString('hex')}`,
    provenance_json: prepared.record.provenance,
    created_at: normalizeObservationTimestamp(options.now ?? new Date()),
  };
  rows.push(record);
  applyCurrent(currentsOf(store), record);
  persistStore();
  return { ...projectObservation(record), replayed: false };
}

export function appendTargetObservation(ctx, input = {}, options = {}) {
  const allowed = gate(ctx, ['evidence:write', 'test_run:start']);
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403, permission: allowed.body?.permission ?? 'evidence:write' };
  return acceptTargetObservation(ctx, input, { now: options.now, internal: false });
}

function pageObservations(rows, query) {
  const decoded = decodeObservationCursor(query.cursor);
  if (decoded.error) return decoded;
  const from = query.from ? normalizeObservationTimestamp(query.from) : null;
  const to = query.to ? normalizeObservationTimestamp(query.to) : null;
  if (query.from && !from) return error('invalid_timestamp', 400, { field: 'from' });
  if (query.to && !to) return error('invalid_timestamp', 400, { field: 'to' });
  if (query.family && !OBSERVATION_FAMILIES.includes(query.family)) return error('invalid_family', 400);
  let filtered = rows.filter((row) => {
    if (query.target_id && row.target_id !== query.target_id) return false;
    if (query.family && row.family !== query.family) return false;
    if (from && row.observed_at < from) return false;
    if (to && row.observed_at > to) return false;
    return true;
  });
  filtered.sort((left, right) => compareObservationOrder(right, left));
  if (decoded.cursor) {
    filtered = filtered.filter((row) => compareObservationOrder(row, decoded.cursor) < 0);
  }
  const limit = clampPageLimit(query.limit, { max: 100, fallback: 50 });
  const page = filtered.slice(0, limit);
  const more = filtered.length > limit;
  return {
    items: page.map(projectObservation),
    count: page.length,
    next_cursor: more ? encodeObservationCursor(page[page.length - 1]) : null,
    filters: {
      target_id: query.target_id ?? null,
      family: query.family ?? null,
      from,
      to,
    },
  };
}

export function listTargetObservations(ctx, query = {}) {
  const allowed = gate(ctx, ['evidence:read', 'target_group:read']);
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403 };
  const rows = observationsOf(getStore()).filter((row) => row.tenant_id === ctx.tenantId);
  return pageObservations(rows, query);
}

export function getCurrentFamilyState(ctx, query = {}) {
  const allowed = gate(ctx, ['evidence:read', 'target_group:read']);
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403 };
  if (!query.target_id) return error('invalid_target', 400);
  if (query.family && !OBSERVATION_FAMILIES.includes(query.family)) return error('invalid_family', 400);
  const store = getStore();
  const rows = observationsOf(store).filter((row) => row.tenant_id === ctx.tenantId && row.target_id === query.target_id);
  const byId = new Map(rows.map((row) => [row.id, row]));
  const pointers = currentsOf(store).filter((row) => row.tenant_id === ctx.tenantId
    && row.target_id === query.target_id
    && (!query.family || row.family === query.family));
  return {
    target_id: query.target_id,
    items: pointers.map((pointer) => {
      const successful = byId.get(pointer.successful_observation_id) ?? null;
      const failed = byId.get(pointer.failed_attempt_observation_id) ?? null;
      return {
        family: pointer.family,
        last_successful: projectObservation(successful),
        latest_failed_attempt: projectObservation(failed),
        fresh_negative: successful?.outcome === 'not_detected',
        provider_loss: false,
      };
    }),
  };
}

export function listObservationsForTests(tenantId) {
  return observationsOf(getStore()).filter((row) => row.tenant_id === tenantId).map(projectObservation);
}
