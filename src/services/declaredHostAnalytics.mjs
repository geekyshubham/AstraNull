/**
 * Declared-host list and rollup. Both calls use src/lib/declaredHostAnalytics.mjs.
 * Pass already projected rows, or a bounded reader. This module does not load targets.
 */
import {
  FAMILY_BUCKETS,
  applyDeclaredTargetQuery,
  evaluateDeclaredHostAnalytics,
  projectDeclaredHostRollup,
  readDeclaredHostCohort,
} from '../lib/declaredHostAnalytics.mjs';
import { deriveProtectionProfile } from './protectionProfile.mjs';

export {
  CITED_OBSERVATION_FRESHNESS_POLICY,
  DECLARED_HOST_ANALYTICS_VERSION,
  DECLARED_HOST_BATCH_SIZE,
  DECLARED_HOST_QUERY_KEYS,
  DECLARED_HOST_ROW_BOUND,
  DECLARED_HOST_SOURCE,
  DeclaredHostQueryError,
  FAMILY_BUCKETS,
  SEGMENT_IDS,
  applyDeclaredTargetQuery,
  evaluateDeclaredHostAnalytics,
  familyObservationBucket,
  normalizeDeclaredHostQuery,
  normalizedDeclaredHostname,
  projectDeclaredHostRollup,
} from '../lib/declaredHostAnalytics.mjs';

/** Paginated list for one query. */
export function listDeclaredHosts(rows, query, options) {
  return applyDeclaredTargetQuery(rows, query, options);
}

/** Rollup for the same predicate, ignoring page size. */
export function rollupDeclaredHosts(rows, query, options) {
  return projectDeclaredHostRollup(rows, query, options);
}

/** List fields plus rollup. `total` matches `rollup.total` and `rollup.segments.all.count`. */
export function queryDeclaredHostAnalytics(rows, query, options) {
  return evaluateDeclaredHostAnalytics(rows, query, options);
}

/**
 * Dev or Postgres reader. `readBatch({ afterId, limit })` returns projected rows
 * ordered by id. A hit on the row cap returns `total: null` and `rollup: null`.
 */
export function queryDeclaredHostAnalyticsFromReader(readBatch, query, options) {
  return readDeclaredHostCohort(readBatch, query, options);
}

const UNIT_TOKEN = Object.freeze({
  hostname: 'normalized_hostname',
  target: 'declared_target',
});

function publicFamily(family, conflict) {
  return {
    status: family?.status ?? 'unknown',
    freshness: family?.freshness ?? 'unknown',
    provider: family?.provider ?? null,
    observed_at: family?.observed_at ?? null,
    conflict: conflict === true,
  };
}

/**
 * Project one batch row. Declarations stay on the row. Families come from
 * deriveProtectionProfile using the same clock. Raw evidence and metadata are omitted.
 * `catalog: []` skips coverage; analytics only needs the family clocks.
 *
 * @param {object} raw
 * @param {{ now?: unknown, asOf?: unknown }} [options]
 */
export function presentDeclaredTargetObservation(raw, options = {}) {
  const now = options.now ?? options.asOf ?? undefined;
  const edgePresent = raw?.edge_id != null
    || raw?.waf_status != null
    || raw?.cdn_status != null
    || raw?.edge_observed_at != null
    || raw?.observed_at != null;
  const edgeRow = edgePresent ? {
    waf_status: raw.waf_status ?? null,
    cdn_status: raw.cdn_status ?? null,
    waf_vendor: raw.waf_vendor ?? null,
    cdn_provider: raw.cdn_provider ?? null,
    observed_at: raw.edge_observed_at ?? raw.observed_at ?? null,
  } : null;
  const derived = deriveProtectionProfile({
    now,
    target: {
      id: raw.id,
      kind: raw.kind,
      value: raw.value,
      tenant_id: raw.tenant_id,
      target_group_id: raw.target_group_id,
    },
    edgeRow,
    policies: [],
    observations: [],
    catalog: [],
  });
  const profile = derived.protection_profile;
  return {
    derivation_version: profile.derivation_version,
    as_of: profile.as_of,
    freshness_policy: {
      id: profile.freshness_policy.id,
      version: profile.freshness_policy.version,
      max_age_ms: profile.freshness_policy.max_age_ms,
      unit: profile.freshness_policy.unit,
    },
    families: {
      waf: publicFamily(profile.families.waf, raw.conflicting_vendor_signals === true || raw.edge_conflict === true),
      cdn: publicFamily(profile.families.cdn, false),
    },
  };
}

function bucketSegments(familyNode, prefix = '') {
  if (!familyNode) return [];
  return FAMILY_BUCKETS
    .filter((bucket) => bucket !== 'unknown')
    .map((bucket) => ({
      key: `${prefix}${bucket}`,
      count: familyNode[bucket],
      percentage: familyNode.percentages?.[bucket] ?? null,
      list_query: familyNode.list_queries?.[bucket]?.list_query ?? null,
    }));
}

/**
 * API envelope. `segments` is the dashboard family array copied from
 * `rollup.segments.all`. `role_segments` is the role rollup. Counts are not recomputed.
 *
 * @param {object} result
 * @param {{ family?: string | null }} [options]
 */
export function declaredHostApiPayload(result, options = {}) {
  const filters = result.filters ?? {};
  const family = options.family === 'waf' || options.family === 'cdn' ? options.family : null;
  const roleSegments = result.rollup?.segments ?? null;
  const all = roleSegments?.all ?? null;
  let segments = [];
  let unknownCount = null;
  let staleCount = null;
  if (result.complete !== false && all) {
    if (family) {
      segments = bucketSegments(all[family]);
      unknownCount = all[family].unknown;
      staleCount = all[family].stale;
    } else {
      segments = [
        ...bucketSegments(all.waf, 'waf_'),
        ...bucketSegments(all.cdn, 'cdn_'),
      ];
    }
  }
  const page = {
    items: result.items ?? [],
    count: result.count ?? 0,
    total: result.total ?? null,
    next_cursor: result.next_cursor ?? null,
    limit: result.limit ?? null,
  };
  return {
    source: result.rollup?.source ?? null,
    version: result.rollup?.version ?? null,
    scope: 'current',
    historical: false,
    snapshot_id: null,
    as_of: result.as_of ?? null,
    as_of_semantics: result.as_of_semantics ?? 'not_recorded',
    cohort_version: result.cohort_version ?? null,
    complete: result.complete !== false,
    unavailable_reason: result.unavailable_reason ?? null,
    unit: UNIT_TOKEN[result.unit] ?? result.unit ?? null,
    canonical_unit: result.unit ?? null,
    denominator: result.total ?? null,
    units: result.units ?? { target_records: null, normalized_hosts: null },
    filters,
    list_query: { query: filters },
    segments,
    unknown_count: unknownCount,
    stale_count: staleCount,
    role_segments: roleSegments,
    page,
    items: page.items,
    count: page.count,
    total: page.total,
    next_cursor: page.next_cursor,
    limit: page.limit,
    rollup: result.rollup ?? null,
  };
}

/** Target-list envelope. Legacy `items` / `count` / `meta` stay. `.segments` is the role rollup. */
export function declaredTargetListPayload(result) {
  const items = result.complete === false ? [] : (result.items ?? []);
  const filters = result.filters ?? {};
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length || result.complete === false
        ? null
        : 'No targets have been declared for this tenant yet.',
    },
    total: result.total ?? null,
    next_cursor: result.next_cursor ?? null,
    filters,
    unit: result.unit ?? 'target',
    units: result.units ?? { target_records: null, normalized_hosts: null },
    segments: result.rollup?.segments ?? null,
    page: {
      items,
      count: items.length,
      total: result.total ?? null,
      next_cursor: result.next_cursor ?? null,
      limit: result.limit ?? null,
    },
    list_query: { query: filters },
    as_of: result.as_of ?? null,
    as_of_semantics: result.as_of_semantics ?? 'not_recorded',
    cohort_version: result.cohort_version ?? null,
    scope: 'current',
    historical: false,
    snapshot_id: null,
    complete: result.complete !== false,
    unavailable_reason: result.unavailable_reason ?? null,
  };
}
