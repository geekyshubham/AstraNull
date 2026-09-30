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

export const TARGET_DETAIL_SHAPE = {
  target: {
    id: 'string',
    tenant_id: 'string',
    target_group_id: 'string',
    kind: 'string',
    value: 'string',
    expected_behavior: 'string',
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
  waf_posture: ['object', 'null'],
  'edge_detection?': [EDGE_DETECTION_SHAPE, 'null'],
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