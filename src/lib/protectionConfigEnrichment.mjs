import {
  DEFAULT_PROTECTION_MAPPING_STALE_AFTER_MS,
  hostnameFromCanonicalUrl,
  normalizeProtectionMappingHostname,
} from '../contracts/protectionMapping.mjs';
import {
  COMPARISON_KINDS,
  PROTECTION_LAYERS,
} from '../contracts/protectionValidation.mjs';
import {
  PROTECTION_CONFIG_ACTIONS,
  PROTECTION_CONFIG_SCHEMA,
} from './connectorProviders/common.mjs';

export const CONFIG_ENRICHMENT_VERSION = 'protection-config-enrichment-v1';
export const CONFIG_EVIDENCE_ROLE = 'explanation_only';
export const CONFIG_EVIDENCE_SOURCES = Object.freeze(['provider_api', 'manual_metadata', 'customer_declaration']);
export const CONFIG_ABSENCE_MEANING = 'unknown';
export const CONFIG_ENRICHMENT_LIMITATIONS = Object.freeze(['configuration_evidence_not_behavior', 'vendor_label_not_proof']);
export const MAX_CONFIG_SNAPSHOTS = 1000;

export const CONFIG_SNAPSHOT_LAYERS = Object.freeze({
  waf_policy: 'waf',
  dns_zone: 'waf',
  cdn_property: 'cdn_edge',
});

export const CONFIG_ENRICHMENT_FIELDS = Object.freeze([
  'attachment_scope',
  'attachment_paths',
  'enforcement_actions',
  'path_exclusions',
  'method_exclusions',
  'version',
  'observation_time',
]);

export const CONFIG_FIELD_STATES = Object.freeze(['reported', 'not_reported', 'unsupported', 'permission_missing']);

export const CONFIG_ENFORCEMENT_COVERAGE = Object.freeze([
  'all_units_enforcing',
  'some_units_enforcing',
  'monitor_only',
  'disabled',
  'no_enforcing_units',
  'unknown',
]);

export const CONFIG_ATTACHMENT_MATCHES = Object.freeze([
  'hostname_and_path',
  'hostname_only',
  'zone_only',
  'path_not_in_attachment',
  'path_excluded',
  'not_attached',
  'unknown',
]);

export const CONFIG_CONTEXT_STATUSES = Object.freeze([
  'connectors_disabled',
  'no_configuration_evidence',
  'configuration_evidence_available',
]);

export const CONFIG_ENRICHMENT_MARKERS = Object.freeze([
  'connectors_disabled',
  'no_configuration_evidence',
  'unsupported_field',
  'unsupported_snapshot_kind',
  'incomplete_inventory',
  'missing_permission',
  'conflicting_configuration',
  'ambiguous_ordering',
  'stale_snapshot',
  'unknown_observation_time',
  'attachment_hostname_only',
  'attachment_zone_level',
  'attachment_scope_unknown',
  'path_not_in_attachment',
  'path_excluded',
  'method_excluded',
  'exclusions_present_scope_unknown',
  'partial_enforcement_units',
  'monitor_only',
  'disabled_units',
  'delegated_actions_unresolved',
  'policy_level_aggregate_only',
  'enforcement_actions_not_reported',
  'configuration_time_misaligned',
]);

export const CONFIG_CANDIDATE_EXPLANATIONS = Object.freeze([
  'configuration_attachment_excludes_path',
  'configuration_path_exclusion_may_apply',
  'configuration_method_exclusion_may_apply',
  'configuration_reports_monitor_mode',
  'configuration_reports_disabled_units',
  'configuration_reports_partial_enforcing_units',
  'configuration_exclusions_may_apply',
  'configuration_and_behavior_disagree',
  'configuration_consistent_with_observation',
]);

export const CONFIG_EXPLANATION_NOTES = Object.freeze([
  'untested_behavior_not_inferred',
  'no_configuration_evidence',
  'connectors_disabled',
  'configuration_layer_not_covered',
]);

const PATH_GAP_OUTCOMES = new Set([
  'reachability_exposure',
  'weaker_observed_enforcement',
  'suspected_alternate_application_route',
  'scoped_application_bypass',
]);
const PATH_CONSISTENT_OUTCOMES = new Set(['consistent_enforcement']);
const PATH_UNRESOLVED_OUTCOMES = new Set(['inconclusive', 'not_tested', 'skipped']);
const FIREWALL_GAP_STATUSES = new Set(['regression']);
const FIREWALL_CONSISTENT_STATUSES = new Set(['matched', 'improvement']);
const FIREWALL_UNRESOLVED_STATUSES = new Set(['inconclusive', 'not_tested', 'stale', 'not_comparable']);
const DEFAULT_EXPLAINED_LAYERS = Object.freeze({
  path_validation: Object.freeze(['waf', 'cdn_edge']),
  firewall_change: Object.freeze(['network_firewall']),
});
const MARKER_SET = new Set(CONFIG_ENRICHMENT_MARKERS);
const ATTACHED_MATCHES = new Set(['hostname_and_path', 'hostname_only', 'zone_only']);
const DISPLAY_REF_MAX = 200;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;
const METHOD_PATTERN = /^[A-Z]{3,10}$/;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function nowMs(value) {
  if (value instanceof Date) return value.getTime();
  const parsed = typeof value === 'string' ? Date.parse(value) : Number(value);
  return Number.isFinite(parsed) ? parsed : Date.now();
}

function boundedText(value, max) {
  if (typeof value !== 'string') return null;
  const text = value.replace(CONTROL_CHARS, '').trim();
  return text ? text.slice(0, max) : null;
}

function orderedMarkers(values) {
  const set = new Set(values);
  return CONFIG_ENRICHMENT_MARKERS.filter((marker) => set.has(marker));
}

function evidenceSource(snapshot) {
  const source = String(snapshot?.evidence_source ?? '').trim();
  return CONFIG_EVIDENCE_SOURCES.includes(source) ? source : 'manual_metadata';
}

function protectionConfigOf(snapshot) {
  const config = snapshot?.protection_config ?? snapshot?.summary?.protection_config ?? snapshot?.summary_json?.protection_config;
  return isPlainObject(config) && config.schema === PROTECTION_CONFIG_SCHEMA ? config : null;
}

function summaryOf(snapshot) {
  const summary = snapshot?.summary ?? snapshot?.summary_json;
  return isPlainObject(summary) ? summary : {};
}

function stringList(value, transform = (entry) => entry) {
  return Array.isArray(value) ? value.map((entry) => transform(String(entry ?? '').trim())).filter(Boolean) : null;
}

function actionCounts(config) {
  if (!isPlainObject(config?.action_counts)) return null;
  const counts = {};
  for (const action of PROTECTION_CONFIG_ACTIONS) {
    const n = Number(config.action_counts[action]);
    counts[action] = Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }
  return counts;
}

export function classifyEnforcementCoverage(counts) {
  if (!counts) return { coverage: 'unknown', enforcement_units: null, enforcing_units: null };
  const total = PROTECTION_CONFIG_ACTIONS.reduce((sum, action) => sum + counts[action], 0);
  const units = total - counts.bypass;
  const enforcing = counts.block + counts.challenge;
  let coverage = 'unknown';
  if (units <= 0) coverage = 'unknown';
  else if (enforcing === units) coverage = 'all_units_enforcing';
  else if (enforcing > 0) coverage = 'some_units_enforcing';
  else if (counts.monitor === units) coverage = 'monitor_only';
  else if (counts.disabled === units) coverage = 'disabled';
  else if (counts.delegated + counts.unknown > 0) coverage = 'unknown';
  else coverage = 'no_enforcing_units';
  return { coverage, enforcement_units: Math.max(0, units), enforcing_units: enforcing };
}

function fieldState({ reported, unsupported, permissionMissing = false }) {
  if (reported) return 'reported';
  if (unsupported) return 'unsupported';
  if (permissionMissing) return 'permission_missing';
  return 'not_reported';
}

function freshness(observedAt, now, staleAfterMs) {
  const observedMs = Date.parse(String(observedAt ?? ''));
  if (!Number.isFinite(observedMs)) return { observed_at: null, age_seconds: null, stale: true };
  const age = Math.max(0, now - observedMs);
  return { observed_at: new Date(observedMs).toISOString(), age_seconds: Math.floor(age / 1000), stale: age > staleAfterMs };
}

export function normalizeConfigurationSnapshot(snapshot, options = {}) {
  if (!isPlainObject(snapshot)) return null;
  const layer = CONFIG_SNAPSHOT_LAYERS[String(snapshot.snapshot_kind ?? '').trim()];
  if (!layer) return null;
  const now = nowMs(options.now);
  const staleAfterMs = Number.isFinite(Number(options.staleAfterMs)) ? Number(options.staleAfterMs) : DEFAULT_PROTECTION_MAPPING_STALE_AFTER_MS;
  const summary = summaryOf(snapshot);
  const config = protectionConfigOf(snapshot);
  const unsupported = new Set(Array.isArray(config?.unsupported_fields) ? config.unsupported_fields : []);
  const permissionGaps = stringList(summary.permission_gaps) ?? [];
  const hostnames = (stringList(summary.hostnames, normalizeProtectionMappingHostname) ?? []);
  const level = config?.attachment_level ?? (snapshot.snapshot_kind === 'dns_zone' ? 'zone' : hostnames.length ? 'hostname' : 'unknown');
  const attachmentPaths = stringList(config?.attachment_paths);
  const exclusionPaths = stringList(config?.exclusion_paths);
  const exclusionMethods = stringList(config?.exclusion_methods, (entry) => entry.toUpperCase())?.filter((entry) => METHOD_PATTERN.test(entry)) ?? null;
  const counts = actionCounts(config);
  const { coverage, enforcement_units: enforcementUnits, enforcing_units: enforcingUnits } = classifyEnforcementCoverage(counts);
  const aggregateMode = typeof summary.policy_mode === 'string' ? summary.policy_mode : null;
  const exclusionCount = Number.isFinite(Number(config?.exclusion_count)) && config?.exclusion_count !== null ? Number(config.exclusion_count) : null;
  const version = boundedText(config?.config_version, 64);
  const managedVersions = stringList(summary.managed_rule_versions) ?? [];
  const fresh = freshness(snapshot.observed_at, now, staleAfterMs);
  const inventoryComplete = snapshot.inventory_complete === true && snapshot.inventory_truncated !== true;

  const fieldStates = {
    attachment_scope: fieldState({ reported: hostnames.length > 0, unsupported: unsupported.has('attachment_scope') }),
    attachment_paths: fieldState({ reported: attachmentPaths !== null, unsupported: unsupported.has('attachment_paths') }),
    enforcement_actions: fieldState({ reported: counts !== null, unsupported: unsupported.has('enforcement_actions'), permissionMissing: permissionGaps.length > 0 }),
    path_exclusions: fieldState({ reported: exclusionPaths !== null, unsupported: unsupported.has('path_exclusions') }),
    method_exclusions: fieldState({ reported: exclusionMethods !== null, unsupported: unsupported.has('method_exclusions') }),
    version: fieldState({ reported: Boolean(version) || managedVersions.length > 0, unsupported: unsupported.has('version') }),
    observation_time: fieldState({ reported: fresh.observed_at !== null, unsupported: false }),
  };

  const markers = [];
  if (Object.values(fieldStates).includes('unsupported')) markers.push('unsupported_field');
  if (!inventoryComplete) markers.push('incomplete_inventory');
  if (permissionGaps.length) markers.push('missing_permission');
  if (fresh.stale) markers.push('stale_snapshot');
  if (fresh.observed_at === null) markers.push('unknown_observation_time');
  if (coverage === 'some_units_enforcing') markers.push('partial_enforcement_units');
  if (coverage === 'monitor_only') markers.push('monitor_only');
  if (counts && counts.disabled > 0) markers.push('disabled_units');
  if (counts && counts.delegated > 0) markers.push('delegated_actions_unresolved');
  if (!counts && aggregateMode) markers.push('policy_level_aggregate_only');
  if (!counts) markers.push('enforcement_actions_not_reported');
  if ((exclusionCount ?? 0) > 0 && exclusionPaths === null) markers.push('exclusions_present_scope_unknown');

  return {
    layer,
    provider_label: boundedText(snapshot.provider, 64),
    evidence: {
      role: CONFIG_EVIDENCE_ROLE,
      source: evidenceSource(snapshot),
      signed_external_result: false,
      snapshot_id: boundedText(snapshot.id, 128),
      connector_id: boundedText(snapshot.connector_id, 128),
      snapshot_kind: snapshot.snapshot_kind,
      resource_ref_hash: boundedText(snapshot.resource_ref_hash, 128),
      display_ref: boundedText(snapshot.display_ref, DISPLAY_REF_MAX),
      config_hash: boundedText(snapshot.config_hash ?? summary.config_hash, 128),
      observed_at: fresh.observed_at,
    },
    attachment: {
      level,
      hostnames,
      path_match: attachmentPaths ? (config?.path_match === 'exclude' ? 'exclude' : 'include') : 'unspecified',
      paths: attachmentPaths,
    },
    enforcement: {
      unit: boundedText(config?.enforcement_unit, 64),
      action_counts: counts,
      enforcement_units: enforcementUnits,
      enforcing_units: enforcingUnits,
      coverage,
      aggregate_mode: aggregateMode,
    },
    exclusions: { count: exclusionCount, paths: exclusionPaths, methods: exclusionMethods },
    version: { value: version, managed_rule_versions: managedVersions },
    freshness: fresh,
    inventory: { complete: inventoryComplete, truncated: snapshot.inventory_truncated === true },
    permission_gaps: permissionGaps,
    match_target_order: Number.isFinite(Number(summary.match_target_order)) && summary.match_target_order !== null ? Number(summary.match_target_order) : null,
    field_states: fieldStates,
    markers: orderedMarkers(markers),
  };
}

function escapeRegex(value) {
  return value.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

export function pathPatternMatches(pattern, path) {
  if (typeof pattern !== 'string' || typeof path !== 'string') return false;
  const regex = new RegExp(`^${pattern.split('*').map(escapeRegex).join('.*')}$`);
  return regex.test(path);
}

export function hostnameAttachmentMatches(attachmentHostname, hostname) {
  if (!attachmentHostname || !hostname) return false;
  if (attachmentHostname === hostname) return true;
  if (attachmentHostname.startsWith('*.')) {
    const suffix = attachmentHostname.slice(1);
    return hostname.endsWith(suffix) && hostname.length > suffix.length;
  }
  return false;
}

export function normalizeConfigurationScope(scope = {}) {
  if (!isPlainObject(scope)) return { hostname: null, path: null, method: null };
  let hostname = null;
  let path = null;
  if (typeof scope.url === 'string' && /^https?:\/\//i.test(scope.url.trim())) {
    try {
      const url = new URL(scope.url.trim());
      hostname = normalizeProtectionMappingHostname(url.hostname);
      path = url.pathname || '/';
    } catch {
      hostname = null;
    }
  }
  if (typeof scope.hostname === 'string') hostname = hostnameFromCanonicalUrl(scope.hostname) || hostname;
  if (typeof scope.path === 'string' && scope.path.startsWith('/')) path = scope.path.slice(0, 2048);
  const method = typeof scope.method === 'string' && METHOD_PATTERN.test(scope.method.trim().toUpperCase())
    ? scope.method.trim().toUpperCase()
    : null;
  return { hostname: hostname || null, path, method };
}

export function matchConfigurationScope(record, scope) {
  const markers = [];
  const { hostname, path, method } = scope;
  const { level, hostnames, paths, path_match: pathMatch } = record.attachment;
  let match = 'unknown';
  if (!hostname || hostnames.length === 0) {
    match = 'unknown';
  } else if (level === 'zone') {
    const zones = hostnames.map((zone) => zone.replace(/^\*\./, ''));
    match = zones.some((zone) => hostname === zone || hostname.endsWith(`.${zone}`)) ? 'zone_only' : 'not_attached';
  } else if (hostnames.some((entry) => hostnameAttachmentMatches(entry, hostname))) {
    if (!paths || !path) match = 'hostname_only';
    else if (pathMatch === 'exclude') match = paths.some((pattern) => pathPatternMatches(pattern, path)) ? 'path_excluded' : 'hostname_and_path';
    else match = paths.some((pattern) => pathPatternMatches(pattern, path)) ? 'hostname_and_path' : 'path_not_in_attachment';
  } else {
    match = 'not_attached';
  }
  if (match === 'hostname_only') markers.push('attachment_hostname_only');
  if (match === 'zone_only') markers.push('attachment_zone_level');
  if (match === 'path_not_in_attachment') markers.push('path_not_in_attachment');
  if (match === 'path_excluded') markers.push('path_excluded');
  if (path && record.exclusions.paths?.some((pattern) => pathPatternMatches(pattern, path))) markers.push('path_excluded');
  if (method && record.exclusions.methods?.includes(method)) markers.push('method_excluded');
  return { attachment_match: match, markers };
}

function latestPerResource(records) {
  const byKey = new Map();
  for (const record of records) {
    const key = `${record.evidence.connector_id ?? ''}|${record.provider_label ?? ''}|${record.evidence.resource_ref_hash ?? record.evidence.display_ref ?? ''}`;
    const existing = byKey.get(key);
    const ms = Date.parse(record.evidence.observed_at ?? '') || 0;
    if (!existing || ms > (Date.parse(existing.evidence.observed_at ?? '') || 0)) byKey.set(key, record);
  }
  return [...byKey.values()];
}

function layerConflicts(records) {
  const markers = [];
  const coverages = new Set(records.map((r) => r.enforcement.coverage).filter((c) => c !== 'unknown'));
  const modes = new Set(records.map((r) => r.enforcement.aggregate_mode).filter((m) => m && m !== 'unknown'));
  if (coverages.size > 1 || modes.size > 1) markers.push('conflicting_configuration');
  const hostnameLevel = records.filter((r) => r.layer === 'waf' && r.attachment.level === 'hostname');
  if (hostnameLevel.length > 1) {
    const orders = hostnameLevel.map((r) => r.match_target_order);
    if (orders.some((order) => order === null) || new Set(orders).size !== orders.length) markers.push('ambiguous_ordering');
  }
  return markers;
}

function combinedCoverage(records) {
  const coverages = [...new Set(records.map((r) => r.enforcement.coverage))];
  if (coverages.length === 0) return 'unknown';
  if (coverages.length === 1) return coverages[0];
  return 'conflicting';
}

function publicRecord(record, match) {
  return {
    layer: record.layer,
    provider_label: record.provider_label,
    evidence: { ...record.evidence },
    attachment_match: match.attachment_match,
    attachment_level: record.attachment.level,
    attachment_hostname_count: record.attachment.hostnames.length,
    path_match: record.attachment.path_match,
    enforcement: { ...record.enforcement, action_counts: record.enforcement.action_counts ? { ...record.enforcement.action_counts } : null },
    exclusions: {
      count: record.exclusions.count,
      path_count: record.exclusions.paths ? record.exclusions.paths.length : null,
      method_count: record.exclusions.methods ? record.exclusions.methods.length : null,
    },
    version: { value: record.version.value, managed_rule_versions: [...record.version.managed_rule_versions] },
    freshness: { ...record.freshness },
    inventory: { ...record.inventory },
    permission_gap_count: record.permission_gaps.length,
    field_states: { ...record.field_states },
    markers: orderedMarkers([...record.markers, ...match.markers]),
  };
}

function emptyLayer(layer, status) {
  return {
    layer,
    status,
    absence_means: CONFIG_ABSENCE_MEANING,
    record_count: 0,
    coverage: 'unknown',
    provider_labels: [],
    markers: status === 'connectors_disabled' ? ['connectors_disabled'] : ['no_configuration_evidence'],
  };
}

function healthMarkers(connectorHealth) {
  const markers = [];
  for (const health of Array.isArray(connectorHealth) ? connectorHealth : []) {
    if (!isPlainObject(health)) continue;
    if (Array.isArray(health.permission_gaps) && health.permission_gaps.length) markers.push('missing_permission');
    if (health.status === 'permission_insufficient' || health.status === 'revoked') markers.push('missing_permission');
    if (health.inventory_complete !== true || health.inventory_truncated === true) markers.push('incomplete_inventory');
  }
  return markers;
}

function baseContext(scope, connectorsEnabled) {
  return {
    enrichment_version: CONFIG_ENRICHMENT_VERSION,
    evidence_role: CONFIG_EVIDENCE_ROLE,
    scope,
    connectors_enabled: connectorsEnabled,
    absence_means: CONFIG_ABSENCE_MEANING,
    behavior_conclusion: null,
    authorizes_execution: false,
    upgrades_observed_behavior: false,
    limitations: [...CONFIG_ENRICHMENT_LIMITATIONS],
  };
}

export function buildConfigurationContext({
  scope = {},
  snapshots = [],
  connectorsEnabled = true,
  connectorHealth = [],
  now,
  staleAfterMs,
} = {}) {
  const normalizedScope = normalizeConfigurationScope(scope);
  const enabled = connectorsEnabled === true;
  if (!enabled) {
    return {
      ...baseContext(normalizedScope, false),
      status: 'connectors_disabled',
      layers: Object.fromEntries(PROTECTION_LAYERS.map((layer) => [layer, emptyLayer(layer, 'connectors_disabled')])),
      records: [],
      unscoped_record_count: 0,
      unsupported_snapshot_count: 0,
      markers: ['connectors_disabled'],
    };
  }
  const list = Array.isArray(snapshots) ? snapshots : [];
  const bounded = list.slice(0, MAX_CONFIG_SNAPSHOTS);
  const contextMarkers = [...healthMarkers(connectorHealth)];
  if (list.length > MAX_CONFIG_SNAPSHOTS) contextMarkers.push('incomplete_inventory');
  let unsupportedCount = 0;
  const normalized = [];
  for (const snapshot of bounded) {
    const record = normalizeConfigurationSnapshot(snapshot, { now, staleAfterMs });
    if (record) normalized.push(record);
    else unsupportedCount += 1;
  }
  if (unsupportedCount) contextMarkers.push('unsupported_snapshot_kind');
  const latest = latestPerResource(normalized);
  const matched = [];
  let unscoped = 0;
  for (const record of latest) {
    const match = matchConfigurationScope(record, normalizedScope);
    if (match.attachment_match === 'not_attached') continue;
    if (match.attachment_match === 'unknown') {
      unscoped += 1;
      continue;
    }
    matched.push({ record, match });
  }
  if (unscoped) contextMarkers.push('attachment_scope_unknown');
  const layers = {};
  for (const layer of PROTECTION_LAYERS) {
    const entries = matched.filter(({ record }) => record.layer === layer);
    if (!entries.length) {
      layers[layer] = emptyLayer(layer, 'no_configuration_evidence');
      continue;
    }
    const records = entries.map(({ record }) => record);
    const attached = entries.filter(({ match }) => ATTACHED_MATCHES.has(match.attachment_match)).map(({ record }) => record);
    const markers = [
      ...layerConflicts(attached),
      ...entries.flatMap(({ record, match }) => [...record.markers, ...match.markers]),
    ];
    layers[layer] = {
      layer,
      status: 'configuration_evidence_available',
      absence_means: CONFIG_ABSENCE_MEANING,
      record_count: records.length,
      coverage: combinedCoverage(attached),
      provider_labels: [...new Set(records.map((r) => r.provider_label).filter(Boolean))].sort(),
      markers: orderedMarkers(markers),
    };
  }
  const records = matched.map(({ record, match }) => publicRecord(record, match));
  const status = records.length ? 'configuration_evidence_available' : 'no_configuration_evidence';
  const markers = orderedMarkers([
    ...contextMarkers,
    ...(records.length ? [] : ['no_configuration_evidence']),
    ...Object.values(layers).filter((l) => l.status === 'configuration_evidence_available').flatMap((l) => l.markers),
  ].filter((marker) => MARKER_SET.has(marker)));
  return {
    ...baseContext(normalizedScope, true),
    status,
    layers,
    records,
    unscoped_record_count: unscoped,
    unsupported_snapshot_count: unsupportedCount,
    markers,
  };
}

function itemKey(kind, item) {
  return kind === 'firewall_change' ? item?.expectation_id ?? null : item?.entry_path_id ?? null;
}

function contextFor(contexts, key) {
  if (!contexts || key == null) return null;
  if (contexts instanceof Map) return contexts.get(key) ?? null;
  return isPlainObject(contexts) && Object.hasOwn(contexts, key) ? contexts[key] : null;
}

function latestObservationMs(item) {
  const times = (Array.isArray(item?.evidence_refs) ? item.evidence_refs : [])
    .map((ref) => Date.parse(String(ref?.observed_at ?? '')))
    .filter(Number.isFinite);
  return times.length ? Math.max(...times) : null;
}

function timeAlignment(record, observationMs, staleAfterMs) {
  const configMs = Date.parse(String(record.evidence?.observed_at ?? ''));
  if (!Number.isFinite(configMs) || observationMs === null) return 'unknown';
  return Math.abs(configMs - observationMs) <= staleAfterMs ? 'aligned' : 'misaligned';
}

function gapCandidates(record) {
  const codes = [];
  if (record.attachment_match === 'path_not_in_attachment') codes.push('configuration_attachment_excludes_path');
  if (record.markers.includes('path_excluded')) codes.push('configuration_path_exclusion_may_apply');
  if (record.markers.includes('method_excluded')) codes.push('configuration_method_exclusion_may_apply');
  if (record.enforcement.coverage === 'monitor_only') codes.push('configuration_reports_monitor_mode');
  if (record.enforcement.coverage === 'disabled' || record.markers.includes('disabled_units')) codes.push('configuration_reports_disabled_units');
  if (record.enforcement.coverage === 'some_units_enforcing') codes.push('configuration_reports_partial_enforcing_units');
  if (record.markers.includes('exclusions_present_scope_unknown')) codes.push('configuration_exclusions_may_apply');
  if (!codes.length && record.enforcement.coverage === 'all_units_enforcing' && ATTACHED_MATCHES.has(record.attachment_match)) {
    codes.push('configuration_and_behavior_disagree');
  }
  return codes;
}

function consistentCandidates(record) {
  if (!ATTACHED_MATCHES.has(record.attachment_match)) return [];
  const coverage = record.enforcement.coverage;
  if (['monitor_only', 'disabled', 'no_enforcing_units'].includes(coverage)) return ['configuration_and_behavior_disagree'];
  if (['all_units_enforcing', 'some_units_enforcing'].includes(coverage)) return ['configuration_consistent_with_observation'];
  return [];
}

export function explainComparisonItem(kind, item, context, options = {}) {
  if (!COMPARISON_KINDS.includes(kind)) {
    const err = new Error('kind must be path_validation or firewall_change.');
    err.code = 'invalid_comparison_evaluation';
    throw err;
  }
  const statusField = kind === 'firewall_change' ? 'status' : 'outcome';
  const status = item?.[statusField] ?? null;
  const staleAfterMs = Number.isFinite(Number(options.staleAfterMs)) ? Number(options.staleAfterMs) : DEFAULT_PROTECTION_MAPPING_STALE_AFTER_MS;
  const layers = Array.isArray(options.layers) ? options.layers.filter((l) => PROTECTION_LAYERS.includes(l)) : DEFAULT_EXPLAINED_LAYERS[kind];
  const unresolved = kind === 'firewall_change' ? FIREWALL_UNRESOLVED_STATUSES : PATH_UNRESOLVED_OUTCOMES;
  const gaps = kind === 'firewall_change' ? FIREWALL_GAP_STATUSES : PATH_GAP_OUTCOMES;
  const consistent = kind === 'firewall_change' ? FIREWALL_CONSISTENT_STATUSES : PATH_CONSISTENT_OUTCOMES;
  const notes = [];
  const candidates = [];
  const markers = [];
  const contextStatus = context?.status ?? 'no_configuration_evidence';
  if (contextStatus === 'connectors_disabled') notes.push('connectors_disabled');
  const relevant = (Array.isArray(context?.records) ? context.records : []).filter((record) => layers.includes(record.layer));
  if (contextStatus !== 'connectors_disabled' && !relevant.length) {
    notes.push(contextStatus === 'configuration_evidence_available' ? 'configuration_layer_not_covered' : 'no_configuration_evidence');
  }
  if (unresolved.has(status) || status === null) notes.push('untested_behavior_not_inferred');
  const observationMs = latestObservationMs(item);
  if (!unresolved.has(status) && status !== null) {
    for (const record of relevant) {
      const codes = gaps.has(status) ? gapCandidates(record) : consistent.has(status) ? consistentCandidates(record) : [];
      const alignment = timeAlignment(record, observationMs, staleAfterMs);
      if (alignment === 'misaligned') markers.push('configuration_time_misaligned');
      markers.push(...record.markers);
      for (const code of codes) {
        candidates.push({
          code,
          layer: record.layer,
          corroborated: false,
          provider_label: record.provider_label,
          evidence_source: record.evidence.source,
          snapshot_id: record.evidence.snapshot_id,
          display_ref: record.evidence.display_ref,
          configuration_observed_at: record.evidence.observed_at,
          time_alignment: alignment,
        });
      }
    }
  }
  return {
    [kind === 'firewall_change' ? 'expectation_id' : 'entry_path_id']: itemKey(kind, item),
    status_field: statusField,
    status,
    status_changed: false,
    evidence_role: CONFIG_EVIDENCE_ROLE,
    behavior_inference: 'none',
    configuration_status: contextStatus,
    absence_means: CONFIG_ABSENCE_MEANING,
    candidate_explanations: candidates,
    notes: CONFIG_EXPLANATION_NOTES.filter((note) => notes.includes(note)),
    markers: orderedMarkers([...(Array.isArray(context?.markers) ? context.markers : []), ...markers]),
    limitations: [...CONFIG_ENRICHMENT_LIMITATIONS],
  };
}

export function explainComparisonItems(kind, items, contexts, options = {}) {
  return (Array.isArray(items) ? items : []).map((item, index) => ({
    item_index: index,
    ...explainComparisonItem(kind, item, contextFor(contexts, itemKey(kind, item)), options),
  }));
}

export function attachConfigurationExplanations(evaluation, contexts, options = {}) {
  if (!isPlainObject(evaluation)) {
    const err = new Error('Evaluation must be an object.');
    err.code = 'invalid_comparison_evaluation';
    throw err;
  }
  return {
    ...evaluation,
    configuration_explanations: {
      enrichment_version: CONFIG_ENRICHMENT_VERSION,
      evidence_role: CONFIG_EVIDENCE_ROLE,
      evaluation_digest: evaluation.evaluation_digest ?? null,
      items: explainComparisonItems(evaluation.kind, evaluation.items, contexts, options),
    },
  };
}

export function attachConfigurationToMatrixRow(row, context) {
  if (!isPlainObject(row)) return row;
  const layers = Array.isArray(row.layers) ? row.layers : [];
  return {
    ...row,
    layers: layers.map((layer) => ({
      ...layer,
      configuration: context?.layers?.[layer.layer]
        ? { ...context.layers[layer.layer], evidence_role: CONFIG_EVIDENCE_ROLE }
        : { ...emptyLayer(layer.layer, context?.status === 'connectors_disabled' ? 'connectors_disabled' : 'no_configuration_evidence'), evidence_role: CONFIG_EVIDENCE_ROLE },
    })),
  };
}
