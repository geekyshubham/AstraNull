/**
 * Lightweight JSON-shape validators for portal revamp contract tests (docs/ux/16 §4).
 */
import './dev-data-dir.mjs';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function matchesPrimitive(value, type) {
  if (type === 'string') return typeof value === 'string';
  if (type === 'number') return typeof value === 'number' && !Number.isNaN(value);
  if (type === 'boolean') return typeof value === 'boolean';
  if (type === 'null') return value === null;
  if (type === 'object') return isObject(value);
  if (type === 'array') return Array.isArray(value);
  return false;
}

function shapeEntries(shape) {
  return Object.entries(shape).map(([key, childShape]) => {
    const optional = key.endsWith('?');
    return [optional ? key.slice(0, -1) : key, childShape, optional];
  });
}

function assertShape(value, shape, path = '$', issues = []) {
  if (typeof shape === 'string') {
    if (!matchesPrimitive(value, shape)) issues.push(`${path}: expected ${shape}`);
    return issues;
  }

  if (Array.isArray(shape)) {
    if (shape.length === 0) {
      if (!Array.isArray(value)) issues.push(`${path}: expected array`);
      return issues;
    }
    if (shape.length === 1) {
      if (!Array.isArray(value)) {
        issues.push(`${path}: expected array`);
        return issues;
      }
      for (let i = 0; i < value.length; i += 1) {
        assertShape(value[i], shape[0], `${path}[${i}]`, issues);
      }
      return issues;
    }
    if (shape.every((entry) => typeof entry === 'string')) {
      if (!shape.some((type) => matchesPrimitive(value, type))) {
        issues.push(`${path}: expected one of ${shape.join('|')}`);
      }
      return issues;
    }
    if (shape.length === 2 && shape.includes('null')) {
      if (value === null) return issues;
      const childShape = shape.find((entry) => entry !== 'null');
      return assertShape(value, childShape, path, issues);
    }
    if (!Array.isArray(value)) {
      issues.push(`${path}: expected array`);
      return issues;
    }
    assertShape(value, shape[0], path, issues);
    return issues;
  }

  if (!isObject(shape)) {
    issues.push(`${path}: invalid schema node`);
    return issues;
  }

  if (!isObject(value)) {
    issues.push(`${path}: expected object`);
    return issues;
  }

  const entries = shapeEntries(shape);
  const allowed = new Set(entries.map(([key]) => key));
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) issues.push(`${path}.${key}: undocumented field`);
  }

  for (const [key, childShape, optional] of entries) {
    if (!(key in value)) {
      if (!optional) issues.push(`${path}.${key}: missing required field`);
      continue;
    }
    assertShape(value[key], childShape, `${path}.${key}`, issues);
  }

  return issues;
}

export function validateShape(value, shape) {
  const issues = assertShape(value, shape);
  return { ok: issues.length === 0, issues };
}

export const EDGE_DETECTION_SHAPE = {
  status: 'string',
  reason: ['string', 'null'],
  waf: {
    status: 'string',
    'provider?': 'string',
    'type?': 'string',
  },
  cdn: {
    status: 'string',
    'provider?': 'string',
    'type?': 'string',
  },
  cloud: {
    status: 'string',
    'provider?': 'string',
    'type?': 'string',
  },
  layers: [{
    family: 'string',
    provider: 'string',
    display_name: ['string', 'null'],
    sources: ['string'],
    confidence: 'number',
    evidence_consistency: 'string',
    matched_signal_count: 'number',
    conflicting: 'boolean',
  }],
  waf_providers: ['string'],
  cdn_providers: ['string'],
  cloud_providers: ['string'],
  confidence: 'number',
  evidence_consistency: 'string',
  conflicting_vendor_signals: 'boolean',
  conflicting_provider_signals: 'boolean',
  effectiveness: {
    status: 'string',
    label: 'string',
    attempted_count: 'number',
    tested_count: 'number',
    blocked_count: 'number',
    passed_count: 'number',
    inconclusive_count: 'number',
    percentage: ['number', 'null'],
    coverage_complete: ['boolean', 'null'],
    required_class_coverage_complete: 'boolean',
    per_class: {
      'sqli?': 'string',
      'xss?': 'string',
      'path_traversal?': 'string',
      'evasion_variants?': 'string',
      'content_type_confusion?': 'string',
      'multipart_confusion?': 'string',
      'inspection_limit?': 'string',
    },
  },
  protection: {
    status: 'string',
    label: 'string',
    evidence_tier: 'string',
    origin_lockdown_confirmed: 'boolean',
  },
  network_firewall: {
    status: 'string',
    direct_origin_reachability: {
      status: 'string',
      reachable: 'boolean',
      application_bypass_confirmed: 'boolean',
      status_code: ['number', 'null'],
    },
    port_exposure: {
      status: 'string',
      open_ports: ['number'],
      tested_count: 'number',
      reason: ['string', 'null'],
    },
  },
  plain_language_summary: 'string',
  summary: {
    edge: 'string',
    effectiveness: 'string',
    network_firewall: 'string',
  },
  corpus_version: ['string', 'null'],
  test_run_id: ['string', 'null'],
  observed_at: ['string', 'null'],
  updated_at: ['string', 'null'],
  evidence: {
    vendor_matches: [{
      vendor: 'string',
      name: 'string',
      confidence: 'number',
      matched_signals: [{ signal: 'string', tier: 'string' }],
    }],
    address_matches: [{ family: 'string', provider: 'string' }],
    cname_matches: [{ provider: 'string', type: 'string', suffix: 'string' }],
    dns_cname_chain: ['string'],
    dns_resolved_ips: ['string'],
    wafw00f: [{
      detected: 'boolean',
      firewall: 'string',
      manufacturer: 'string',
      plugin: ['string', 'null'],
      all_matches: ['string'],
      generic: [{
        found: 'boolean',
        reason_code: ['string', 'null'],
        reason: ['string', 'null'],
      }, 'null'],
    }, 'null'],
    cdncheck: [{
      matched: 'boolean',
      provider: ['string', 'null'],
      item_type: ['string', 'null'],
      source: ['string', 'null'],
      value: ['string', 'null'],
    }, 'null'],
  },
};

const NULLABLE_STRING = ['string', 'null'];
const NULLABLE_NUMBER = ['number', 'null'];

const PROTECTION_FAMILY_SHAPE = {
  status: 'string',
  reason: NULLABLE_STRING,
  provider: NULLABLE_STRING,
  product: NULLABLE_STRING,
  confidence: NULLABLE_NUMBER,
  observed_at: NULLABLE_STRING,
  test_run_id: NULLABLE_STRING,
  evidence_ids: ['string'],
  sources: ['string'],
  freshness: 'string',
  freshness_policy_id: 'string',
};

const FRESHNESS_POLICY_SHAPE = {
  id: 'string',
  version: 'number',
  max_age_ms: 'number',
  unit: 'string',
};

const COVERAGE_COUNTS_SHAPE = {
  applicable_count: 'number',
  evaluated_count: 'number',
  conclusive_count: 'number',
  inconclusive_count: 'number',
  not_run_count: 'number',
  stale_count: 'number',
  unknown_count: 'number',
  partial_count: 'number',
  excluded_count: 'number',
  percentage: NULLABLE_NUMBER,
  percentage_reason: 'string',
};

/** Projected observation from `projectObservation`. Provenance is a redacted scalar map, not a fixed key set. */
const HISTORY_OBSERVATION_SHAPE = {
  id: 'string',
  tenant_id: 'string',
  target_id: 'string',
  target_group_id: 'string',
  family: 'string',
  check_id: 'string',
  test_run_id: NULLABLE_STRING,
  source_kind: 'string',
  source_id: NULLABLE_STRING,
  corpus_version: NULLABLE_STRING,
  scenario_version: NULLABLE_STRING,
  check_version: NULLABLE_STRING,
  observed_at: 'string',
  source_completed_at: NULLABLE_STRING,
  outcome: 'string',
  attempt_class: 'string',
  producer_kind: NULLABLE_STRING,
  origin_binding_id: NULLABLE_STRING,
  provenance: 'object',
  created_at: NULLABLE_STRING,
};

const HISTORY_RETAINED_FAMILY_SHAPE = {
  family: 'string',
  last_successful: [HISTORY_OBSERVATION_SHAPE, 'null'],
  latest_failed_attempt: [HISTORY_OBSERVATION_SHAPE, 'null'],
  fresh_negative: 'boolean',
  provider_loss: 'boolean',
};

/** Shared by comparable_changes entries and comparison_gaps entries. `details` is the
 *  explicit provider-identity payload that only provider_changed pairs carry. */
const HISTORY_COMPARISON_ENTRY_SHAPE = {
  family: 'string',
  previous_id: 'string',
  observation_id: 'string',
  comparable: 'boolean',
  reason: NULLABLE_STRING,
  change: NULLABLE_STRING,
  direction: NULLABLE_STRING,
  'details?': {
    before_provider: 'string',
    after_provider: 'string',
  },
};

/** Only a comparable changed pair is stored. Gaps stay off this array. */
const HISTORY_COMPARABLE_CHANGE_SHAPE = HISTORY_COMPARISON_ENTRY_SHAPE;

const HISTORY_COMPARISON_GAP_SHAPE = HISTORY_COMPARISON_ENTRY_SHAPE;

const HISTORY_BINDING_REACHABILITY_SHAPE = {
  status: 'string',
  lockdown: 'string',
  assurance: 'string',
  reason: NULLABLE_STRING,
  observation_id: NULLABLE_STRING,
  'capacity_assurance?': 'boolean',
  'scope?': {
    host: 'string',
    sni: 'string',
    port: NULLABLE_NUMBER,
    path: NULLABLE_STRING,
  },
  'limitations?': ['string'],
};

/** `historyReadModel` binding, not the origin-binding list presenter. */
const HISTORY_ORIGIN_BINDING_SHAPE = {
  id: 'string',
  protected_target_id: 'string',
  origin_target_id: 'string',
  host: 'string',
  sni: 'string',
  port: NULLABLE_NUMBER,
  path: NULLABLE_STRING,
  status: 'string',
  assurance: 'string',
  lockdown: 'string',
  currently_authorized: 'boolean',
  reachability: HISTORY_BINDING_REACHABILITY_SHAPE,
};

const HISTORY_READ_FIELDS = {
  retained_family_states: [HISTORY_RETAINED_FAMILY_SHAPE],
  comparable_changes: [HISTORY_COMPARABLE_CHANGE_SHAPE],
  comparison_gaps: [HISTORY_COMPARISON_GAP_SHAPE],
  origin_bindings: [HISTORY_ORIGIN_BINDING_SHAPE],
};

const DECLARATION_SHAPE = {
  purpose: NULLABLE_STRING,
  purpose_status: 'string',
  purpose_source: NULLABLE_STRING,
  service_roles: ['string'],
  service_roles_status: 'string',
  service_roles_source: NULLABLE_STRING,
  owner: { status: 'string', label: NULLABLE_STRING, source: NULLABLE_STRING },
  criticality: { status: 'string', value: NULLABLE_STRING, source: NULLABLE_STRING },
};

export const TARGET_DETAIL_SHAPE = {
  target: {
    id: 'string',
    tenant_id: 'string',
    target_group_id: 'string',
    kind: 'string',
    value: 'string',
    expected_behavior: 'string',
    // ADR-0008: tags are the membership mechanism (e.g. `env:prod`); every target payload
    // exposes the trusted top-level list, which may be empty.
    tags: ['string'],
    declaration: DECLARATION_SHAPE,
    created_at: 'string',
    eligibility: 'string',
    eligibility_reason: 'null',
  },
  verification: {
    state: 'string',
    source_kind: 'string',
    source_ref: ['object', 'null'],
    history: [{ state: 'string', transitioned_at: 'string', 'source_ref?': ['object', 'null'] }],
  },
  // Loose: legacy posture keys stay, including null marker_rules and unknown origin state.
  // Connector YAML is permission-scoped and is not part of this core shape.
  waf_posture: ['object', 'null'],
  'edge_detection?': [EDGE_DETECTION_SHAPE, 'null'],
  protection_profile: {
    derivation_version: 'string',
    as_of: 'string',
    freshness_policy: FRESHNESS_POLICY_SHAPE,
    families: {
      waf: PROTECTION_FAMILY_SHAPE,
      cdn: PROTECTION_FAMILY_SHAPE,
      cloud: PROTECTION_FAMILY_SHAPE,
      dns: PROTECTION_FAMILY_SHAPE,
      origin_hosting: PROTECTION_FAMILY_SHAPE,
    },
    effectiveness: {
      unit: 'string',
      status: 'string',
      blocked_count: NULLABLE_NUMBER,
      allowed_count: NULLABLE_NUMBER,
      inconclusive_count: NULLABLE_NUMBER,
      not_run_count: NULLABLE_NUMBER,
      tested_count: NULLABLE_NUMBER,
      percentage: NULLABLE_NUMBER,
      percentage_reason: 'string',
    },
    origin: {
      status: 'string',
      binding_id: 'null',
      reason: 'string',
      assurance: 'string',
      reachability: {
        status: 'string',
        source: NULLABLE_STRING,
        tested_target_id: NULLABLE_STRING,
        scenario_id: NULLABLE_STRING,
        limitations: ['string'],
      },
    },
    dimensions: [{
      id: 'string',
      unit: 'string',
      status: 'string',
      ...COVERAGE_COUNTS_SHAPE,
      freshness_policy_id: 'string',
      scope: { target_id: 'string', plan_version: 'string' },
    }],
    ...HISTORY_READ_FIELDS,
  },
  coverage: {
    unit: 'string',
    plan_version: 'string',
    as_of: 'string',
    freshness_policy: FRESHNESS_POLICY_SHAPE,
    runtime_launch_gates: 'string',
    scope: { target_id: 'string', plan_version: 'string' },
    ...COVERAGE_COUNTS_SHAPE,
    pairs: [{
      check_id: 'string',
      dimension: 'string',
      state: 'string',
      prior_state: NULLABLE_STRING,
      exclusion_reason: NULLABLE_STRING,
      last_run_id: NULLABLE_STRING,
      observed_at: NULLABLE_STRING,
      freshness: 'string',
      provenance: 'string',
      live_external: 'boolean',
      pair_reason: NULLABLE_STRING,
      retained: [{
        verdict: NULLABLE_STRING,
        observed_at: NULLABLE_STRING,
        provenance: 'string',
        check_version: NULLABLE_STRING,
        scenario_version: NULLABLE_STRING,
        run_status: NULLABLE_STRING,
      }, 'null'],
      policy_id: NULLABLE_STRING,
      launch_eligibility: { status: 'string', reason: 'string' },
      launchable: 'null',
      launch_block_reason: 'string',
      policy_binding: 'string',
    }],
    ...HISTORY_READ_FIELDS,
  },
  'edge_detection_request?': [{
    test_run_id: 'string',
    run_status: 'string',
    started_at: ['string', 'null'],
    completed_at: ['string', 'null'],
  }, 'null'],
  checks_applied: [{
    check_id: 'string',
    policy_id: 'string',
    policy_state: 'string',
    binding_scope: 'string',
    cadence: 'string',
    last_verdict: 'string',
    last_run_id: ['string', 'null'],
    last_ran_at: ['string', 'null'],
  }],
  runs_recent: [{
    run_id: 'string',
    policy_id: ['string', 'null'],
    check_id: ['string', 'null'],
    status: 'string',
    verdict: 'string',
    verdict_id: ['string', 'null'],
    evidence_ids: ['string'],
    started_at: 'string',
    completed_at: ['string', 'null'],
  }],
  findings: [{ id: 'string', severity: 'string', title: 'string', state: 'string', opened_at: 'string', owner_group: 'string' }],
  loa: ['object', 'null'],
  counts: { runs_total: 'number', findings_open: 'number', findings_closed: 'number' },
  'meta?': {
    runs_empty_reason: ['string', 'null'],
    findings_empty_reason: ['string', 'null'],
    checks_empty_reason: ['string', 'null'],
    waf_empty_reason: ['string', 'null'],
  },
  'findings_next_cursor?': 'string',
};

/** `presentFindingLineage` on GET /v1/findings/:id. Strict: every field is documented. */
export const FINDING_LINEAGE_SHAPE = {
  finding_id: 'string',
  tenant_id: 'string',
  target_id: 'string',
  check_id: 'string',
  closed_at: NULLABLE_STRING,
  sibling_closure: 'boolean',
  siblings: [{ id: 'string', target_id: 'string', status: 'string', closed_at: NULLABLE_STRING }],
  retests: [{
    id: 'string',
    test_run_id: 'string',
    target_id: 'string',
    check_id: 'string',
    intent: 'string',
    relation: 'string',
    created_at: 'string',
  }],
  later_same_pair: [{
    test_run_id: 'string',
    relation: 'string',
    reason: NULLABLE_STRING,
    can_advance_remediation: 'boolean',
    'finalized?': 'boolean',
  }],
  originating: [{
    test_run_id: 'string',
    relation: 'string',
    status: NULLABLE_STRING,
  }, 'null'],
  latest: [{
    test_run_id: 'string',
    relation: 'string',
    status: NULLABLE_STRING,
    finalized: 'boolean',
    completed_at: NULLABLE_STRING,
    pending: 'boolean',
    can_advance_remediation: 'boolean',
  }, 'null'],
};

export const EVIDENCE_SHAPE = {
  finding: { id: 'string', title: 'string', run_id: 'string' },
  bundle: {
    id: 'string',
    sha256: 'string',
    sealed_at: 'string',
    size_bytes: 'number',
    custody_schema_version: 'string',
  },
  artifacts: [{ id: 'string', kind: 'string', run_id: 'string', sha256: 'string', sealed_at: 'string', size_bytes: 'number' }],
  custody_chain: [{ step: 'number', kind: 'string', sha256: 'string', at: 'string' }],
  verify_url: 'string',
};

export const WAF_SUMMARY_SHAPE = {
  assets_total: 'number',
  protected: 'number',
  edge_protected: 'number',
  underprotected: 'number',
  unknown: 'number',
  coverage_pct: 'number',
  by_vendor: 'object',
  connectors_active: 'number',
  connectors_degraded: 'number',
  connectors_disabled: 'number',
  refreshed_at: 'string',
};

export const VERIFICATION_LADDER_SHAPE = {
  steps: [{ id: 'string', label: 'string', done: 'boolean', count: 'number', total: 'number' }],
};

export const LIST_ENVELOPE_SHAPE = {
  items: 'array',
  count: 'number',
  meta: ['object', 'null'],
};

export function validateListEnvelope(value, { requireEmptyReason = false } = {}) {
  const result = validateShape(value, LIST_ENVELOPE_SHAPE);
  if (!result.ok) return result;
  if (!Array.isArray(value.items)) {
    return { ok: false, issues: ['$.items: expected array'] };
  }
  if (requireEmptyReason) {
    const reason = value?.meta?.empty_reason;
    if (typeof reason !== 'string' || reason.trim().length === 0) {
      return { ok: false, issues: ['$.meta.empty_reason: required non-empty string for empty lists'] };
    }
  }
  return { ok: true, issues: [] };
}