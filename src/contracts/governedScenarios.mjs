/**
 * SOC-011 / DET-022 — governed high-scale execution scenario taxonomy.
 *
 * This contract names scenarios a certified partner adapter may execute after SOC review.
 * It never generates traffic. Each family declares the one typed intensity ceiling that
 * must be present in addition to a bounded duration, plus the delivery patterns that are
 * valid for that family.
 */

import { DELIVERY_PATTERN_LABELS } from './resourceExhaustionTaxonomy.mjs';

/** Numeric bounds are governance ceilings, not traffic-generator defaults. */
export const GOVERNED_LIMIT_BOUNDS = Object.freeze({
  max_gbps: Object.freeze({ min: 0.001, max: 1000, integer: false, unit: 'Gbps' }),
  max_pps: Object.freeze({ min: 1, max: 2_000_000_000, integer: true, unit: 'pps' }),
  max_rps: Object.freeze({ min: 1, max: 10_000_000, integer: true, unit: 'rps' }),
  max_qps: Object.freeze({ min: 1, max: 10_000_000, integer: true, unit: 'qps' }),
  max_cps: Object.freeze({ min: 1, max: 10_000_000, integer: true, unit: 'cps' }),
  max_connections: Object.freeze({ min: 1, max: 10_000_000, integer: true, unit: 'connections' }),
  max_resets_per_sec: Object.freeze({ min: 1, max: 1_000_000, integer: true, unit: 'resets/s' }),
  max_duration_minutes: Object.freeze({ min: 1, max: 720, integer: true, unit: 'minutes' }),
});

export const GOVERNED_LIMIT_FIELDS = Object.freeze(Object.keys(GOVERNED_LIMIT_BOUNDS));

const RAW_GOVERNED_SCENARIO_FAMILIES = [
  { id: 'udp_flood', label: 'UDP volumetric', exhausted_resource: 'volumetric', metric: 'Gbps', limit_field: 'max_gbps', delivery_patterns: ['direct', 'spoofed'] },
  { id: 'icmp_flood', label: 'ICMP volumetric', exhausted_resource: 'volumetric', metric: 'Gbps', limit_field: 'max_gbps', delivery_patterns: ['direct'] },
  { id: 'gre_flood', label: 'GRE tunnel volumetric', exhausted_resource: 'volumetric', metric: 'Gbps', limit_field: 'max_gbps', delivery_patterns: ['direct'] },
  { id: 'quic_flood', label: 'QUIC/HTTP3 volumetric', exhausted_resource: 'volumetric', metric: 'Gbps', limit_field: 'max_gbps', delivery_patterns: ['direct', 'spoofed'] },
  { id: 'sip_flood', label: 'SIP/VoIP volumetric', exhausted_resource: 'volumetric', metric: 'Gbps', limit_field: 'max_gbps', delivery_patterns: ['direct'] },
  { id: 'packet_processing_flood', label: 'Packet-processing (small-packet PPS)', exhausted_resource: 'packet_processing', metric: 'pps', limit_field: 'max_pps', delivery_patterns: ['direct'] },
  { id: 'syn_flood', label: 'SYN state exhaustion', exhausted_resource: 'state_exhaustion', metric: 'cps', limit_field: 'max_cps', delivery_patterns: ['direct', 'spoofed'] },
  { id: 'tcp_connection_flood', label: 'TCP connection flood', exhausted_resource: 'state_exhaustion', metric: 'cps', limit_field: 'max_cps', delivery_patterns: ['direct'] },
  { id: 'app_connection_exhaustion', label: 'Application connection exhaustion', exhausted_resource: 'state_exhaustion', metric: 'connections', limit_field: 'max_connections', delivery_patterns: ['direct'] },
  { id: 'http_get_flood', label: 'HTTP GET flood', exhausted_resource: 'application_l7', metric: 'rps', limit_field: 'max_rps', delivery_patterns: ['direct', 'coordinated_swarm'] },
  { id: 'http_post_flood', label: 'HTTP POST flood', exhausted_resource: 'application_l7', metric: 'rps', limit_field: 'max_rps', delivery_patterns: ['direct', 'application_aware'] },
  { id: 'cache_busting_at_scale', label: 'Cache-busting at scale', exhausted_resource: 'application_l7', metric: 'rps', limit_field: 'max_rps', delivery_patterns: ['application_aware'] },
  { id: 'dns_query_flood', label: 'DNS query flood', exhausted_resource: 'dns_exhaustion', metric: 'qps', limit_field: 'max_qps', delivery_patterns: ['direct', 'spoofed'] },
  { id: 'water_torture', label: 'Random-subdomain water torture', exhausted_resource: 'dns_exhaustion', metric: 'qps', limit_field: 'max_qps', delivery_patterns: ['direct'] },
  { id: 'nxdomain_at_scale', label: 'NXDOMAIN flood at scale', exhausted_resource: 'dns_exhaustion', metric: 'qps', limit_field: 'max_qps', delivery_patterns: ['direct'] },
  { id: 'slowloris', label: 'Slowloris (slow headers)', exhausted_resource: 'memory_exhaustion', metric: 'connections', limit_field: 'max_connections', delivery_patterns: ['direct'] },
  { id: 'slow_post', label: 'Slow POST / RUDY', exhausted_resource: 'memory_exhaustion', metric: 'connections', limit_field: 'max_connections', delivery_patterns: ['direct'] },
  { id: 'slow_read', label: 'Slow read', exhausted_resource: 'memory_exhaustion', metric: 'connections', limit_field: 'max_connections', delivery_patterns: ['direct'] },
  { id: 'rapid_reset_validation', label: 'HTTP/2 Rapid Reset validation', exhausted_resource: 'computational', metric: 'resets/s', limit_field: 'max_resets_per_sec', delivery_patterns: ['direct'] },
  { id: 'made_you_reset_validation', label: 'HTTP/2 MadeYouReset validation', exhausted_resource: 'computational', metric: 'resets/s', limit_field: 'max_resets_per_sec', delivery_patterns: ['direct'] },
  { id: 'tls_handshake_exhaustion', label: 'TLS handshake exhaustion', exhausted_resource: 'computational', metric: 'rps', limit_field: 'max_rps', delivery_patterns: ['direct'] },
  { id: 'database_exhaustion', label: 'Database exhaustion', exhausted_resource: 'backend_exhaustion', metric: 'rps', limit_field: 'max_rps', delivery_patterns: ['application_aware'] },
  { id: 'graphql_depth_at_scale', label: 'GraphQL depth at scale', exhausted_resource: 'backend_exhaustion', metric: 'rps', limit_field: 'max_rps', delivery_patterns: ['application_aware'] },
  { id: 'carpet_bombing', label: 'Carpet bombing', exhausted_resource: 'delivery_pattern', metric: 'Gbps', limit_field: 'max_gbps', delivery_patterns: ['carpet_bombing', 'multi_vector'] },
  { id: 'pulse_wave', label: 'Pulse wave', exhausted_resource: 'delivery_pattern', metric: 'Gbps', limit_field: 'max_gbps', delivery_patterns: ['pulse_wave'] },
  { id: 'multi_vector_switching', label: 'Multi-vector switching', exhausted_resource: 'delivery_pattern', metric: 'Gbps', limit_field: 'max_gbps', delivery_patterns: ['multi_vector'] },
  { id: 'coordinated_swarm', label: 'Coordinated device swarm', exhausted_resource: 'delivery_pattern', metric: 'rps', limit_field: 'max_rps', delivery_patterns: ['coordinated_swarm'] },
  { id: 'degradation_recovery', label: 'Degradation / recovery drill', exhausted_resource: 'delivery_pattern', metric: 'minutes', limit_field: 'max_duration_minutes', delivery_patterns: ['recovery_drill'] },
];

export const GOVERNED_SCENARIO_FAMILIES = Object.freeze(
  RAW_GOVERNED_SCENARIO_FAMILIES.map((family) => Object.freeze({
    ...family,
    delivery_patterns: Object.freeze([...family.delivery_patterns]),
  })),
);

const GOVERNED_FAMILY_BY_ID = new Map(GOVERNED_SCENARIO_FAMILIES.map((family) => [family.id, family]));
const DELIVERY_PATTERN_SET = new Set(DELIVERY_PATTERN_LABELS);
const LIMIT_FIELD_SET = new Set(GOVERNED_LIMIT_FIELDS);

/** @returns {{ ok: boolean, value?: string[], unknown?: string[] }} */
export function normalizeGovernedScenarioFamilies(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return { ok: false, unknown: [] };
  const seen = new Set();
  const unknown = [];
  for (const entry of raw) {
    if (typeof entry !== 'string' || entry.trim() === '') return { ok: false, unknown };
    const id = entry.trim();
    if (!GOVERNED_FAMILY_BY_ID.has(id)) {
      if (!unknown.includes(id)) unknown.push(id);
    } else {
      seen.add(id);
    }
  }
  if (unknown.length > 0) return { ok: false, unknown };
  return { ok: true, value: [...seen], unknown: [] };
}

/** @returns {{ ok: boolean, value?: string[], unknown?: string[] }} */
export function normalizeGovernedDeliveryPatterns(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return { ok: false, value: [], unknown: [] };
  const seen = new Set();
  const unknown = [];
  for (const entry of raw) {
    if (typeof entry !== 'string' || entry.trim() === '') return { ok: false, unknown };
    const id = entry.trim();
    if (!DELIVERY_PATTERN_SET.has(id)) {
      if (!unknown.includes(id)) unknown.push(id);
    } else {
      seen.add(id);
    }
  }
  if (unknown.length > 0) return { ok: false, unknown };
  return { ok: true, value: [...seen], unknown: [] };
}

export function scenarioFamilyById(id) {
  return GOVERNED_FAMILY_BY_ID.get(String(id ?? '')) ?? null;
}

export function governedLimitFieldsForFamilies(rawFamilies) {
  const parsed = normalizeGovernedScenarioFamilies(rawFamilies);
  if (!parsed.ok) return [];
  const fields = new Set(['max_duration_minutes']);
  for (const id of parsed.value) fields.add(GOVERNED_FAMILY_BY_ID.get(id).limit_field);
  return GOVERNED_LIMIT_FIELDS.filter((field) => fields.has(field));
}

/**
 * Validate exact, numeric governed limits. Numeric-looking strings and legacy labels such
 * as `500_rps_metadata` are intentionally rejected at this trust boundary.
 */
export function normalizeGovernedLimits(raw, rawFamilies) {
  const required = governedLimitFieldsForFamilies(rawFamilies);
  if (required.length === 0 || !raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, missing: required, unknown: [], invalid: [] };
  }

  const unknown = Object.keys(raw).filter((field) => !LIMIT_FIELD_SET.has(field));
  const missing = required.filter((field) => !Object.hasOwn(raw, field));
  const invalid = [];
  const value = {};

  for (const field of required) {
    if (!Object.hasOwn(raw, field)) continue;
    const candidate = raw[field];
    const bound = GOVERNED_LIMIT_BOUNDS[field];
    if (
      typeof candidate !== 'number'
      || !Number.isFinite(candidate)
      || candidate < bound.min
      || candidate > bound.max
      || (bound.integer && !Number.isInteger(candidate))
    ) {
      invalid.push({ field, min: bound.min, max: bound.max, integer: bound.integer });
      continue;
    }
    value[field] = candidate;
  }

  if (unknown.length > 0 || missing.length > 0 || invalid.length > 0) {
    return { ok: false, missing, unknown, invalid };
  }
  return { ok: true, value };
}

/**
 * A request pattern is valid only if it is supported by a requested family, and every
 * requested family has at least one selected compatible pattern.
 */
export function deliveryPatternsCoverScenarioFamilies(rawFamilies, rawPatterns) {
  const families = normalizeGovernedScenarioFamilies(rawFamilies);
  const patterns = normalizeGovernedDeliveryPatterns(rawPatterns);
  if (!families.ok || !patterns.ok) {
    return {
      ok: false,
      unsupported: patterns.unknown ?? [],
      families_without_compatible_pattern: families.value ?? [],
    };
  }
  const supported = new Set(
    families.value.flatMap((id) => GOVERNED_FAMILY_BY_ID.get(id).delivery_patterns),
  );
  const unsupported = patterns.value.filter((pattern) => !supported.has(pattern));
  const selected = new Set(patterns.value);
  const familiesWithoutCompatiblePattern = families.value.filter((id) =>
    !GOVERNED_FAMILY_BY_ID.get(id).delivery_patterns.some((pattern) => selected.has(pattern)),
  );
  return {
    ok: unsupported.length === 0 && familiesWithoutCompatiblePattern.length === 0,
    unsupported,
    families_without_compatible_pattern: familiesWithoutCompatiblePattern,
  };
}

export function scenarioFamiliesCoverRequested(requestedFamilies, approvedFamilies) {
  const approved = new Set((approvedFamilies ?? []).map((family) => String(family).trim()).filter(Boolean));
  const uncovered = (requestedFamilies ?? [])
    .map((family) => String(family).trim())
    .filter((family) => family && !approved.has(family));
  return { ok: uncovered.length === 0, uncovered };
}

export function buildGovernedScenarioReview(requestedFamilies) {
  const normalized = normalizeGovernedScenarioFamilies(requestedFamilies);
  if (!normalized.ok) return { ok: false, unknown: normalized.unknown ?? [], scenarios: [] };
  return {
    ok: true,
    unknown: [],
    scenarios: normalized.value.map((id) => {
      const family = GOVERNED_FAMILY_BY_ID.get(id);
      return {
        scenario_family: family.id,
        exhausted_resource: family.exhausted_resource,
        metric: family.metric,
        required_limit_field: family.limit_field,
        limit_bounds: GOVERNED_LIMIT_BOUNDS[family.limit_field],
        delivery_patterns: [...family.delivery_patterns],
      };
    }),
  };
}
