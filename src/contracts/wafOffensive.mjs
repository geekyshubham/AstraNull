import { assertNoRawWafEvidence } from './wafPosture.mjs';

/** SOC-gated offensive WAF validation — curated suites only; no customer self-service execution. */

export const WAF_OFFENSIVE_STATES = Object.freeze([
  'submitted',
  'under_review',
  'approved',
  'scheduled',
  'running',
  'stopped',
  'closed',
  'rejected',
]);

export const WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES = Object.freeze([
  'customer_authorization_letter',
  'target_ownership_confirmation',
  'emergency_contacts',
  'stop_criteria',
  'waf_offensive_test_plan',
  'staging_isolation_confirmation',
]);

export const WAF_OFFENSIVE_SUITE_CATALOG = Object.freeze([
  {
    suite_id: 'sqli_offensive',
    label: 'SQL injection offensive suite',
    owasp_category: 'A03:2021-Injection',
    attack_class: 'sqli',
    check_id: 'waf.offensive_sqli.soc',
    scenario_family: 'sqli_offensive',
    max_requests: 12,
    risk_class: 'soc_gated',
    description: 'Bounded SQLi probe patterns against declared parameters — SOC execution only.',
  },
  {
    suite_id: 'xss_offensive',
    label: 'Cross-site scripting offensive suite',
    owasp_category: 'A03:2021-Injection',
    attack_class: 'xss',
    check_id: 'waf.offensive_xss.soc',
    scenario_family: 'xss_offensive',
    max_requests: 12,
    risk_class: 'soc_gated',
    description: 'Reflected/stored XSS probe patterns — SOC execution only.',
  },
  {
    suite_id: 'rce_offensive',
    label: 'Remote code execution offensive suite',
    owasp_category: 'A03:2021-Injection',
    attack_class: 'rce',
    check_id: 'waf.offensive_rce.soc',
    scenario_family: 'rce_offensive',
    max_requests: 8,
    risk_class: 'soc_gated',
    description: 'Bounded RCE/command-execution probe patterns — SOC execution only.',
  },
  {
    suite_id: 'path_traversal_offensive',
    label: 'Path traversal offensive suite',
    owasp_category: 'A01:2021-Broken Access Control',
    attack_class: 'path_traversal',
    check_id: 'waf.offensive_path_traversal.soc',
    scenario_family: 'path_traversal_offensive',
    max_requests: 10,
    risk_class: 'soc_gated',
    description: 'Directory traversal and file inclusion probe patterns — SOC execution only.',
  },
  {
    suite_id: 'command_injection_offensive',
    label: 'OS command injection offensive suite',
    owasp_category: 'A03:2021-Injection',
    attack_class: 'command_injection',
    check_id: 'waf.offensive_command_injection.soc',
    scenario_family: 'command_injection_offensive',
    max_requests: 8,
    risk_class: 'soc_gated',
    description: 'OS/shell command injection probe patterns — SOC execution only.',
  },
  {
    suite_id: 'ldap_injection_offensive',
    label: 'LDAP injection offensive suite',
    owasp_category: 'A03:2021-Injection',
    attack_class: 'ldap_injection',
    check_id: 'waf.offensive_ldap_injection.soc',
    scenario_family: 'ldap_injection_offensive',
    max_requests: 6,
    risk_class: 'soc_gated',
    description: 'LDAP filter injection probe patterns — SOC execution only.',
  },
  {
    suite_id: 'ssti_offensive',
    label: 'Server-side template injection offensive suite',
    owasp_category: 'A03:2021-Injection',
    attack_class: 'ssti',
    check_id: 'waf.offensive_ssti.soc',
    scenario_family: 'ssti_offensive',
    max_requests: 6,
    risk_class: 'soc_gated',
    description: 'Template injection probe patterns — SOC execution only.',
  },
  {
    suite_id: 'combined_offensive',
    label: 'Combined OWASP offensive bundle',
    owasp_category: 'multi',
    attack_class: 'combined',
    check_id: 'waf.offensive_combined.soc',
    scenario_family: 'combined_offensive',
    max_requests: 24,
    risk_class: 'soc_gated',
    description: 'Curated multi-vector offensive bundle for staging validation windows.',
  },
]);

const SUITE_BY_ID = new Map(WAF_OFFENSIVE_SUITE_CATALOG.map((s) => [s.suite_id, s]));
const SUITE_ID_SET = new Set(WAF_OFFENSIVE_SUITE_CATALOG.map((s) => s.suite_id));

const FORBIDDEN_INTAKE_FIELDS = new Set([
  'raw_payload',
  'payload',
  'exploit_code',
  'exploit_payload',
  'attack_script',
  'poc_code',
  'request_body',
  'response_body',
  'traffic_' + 'generator',
  'amplification',
]);

export function getOffensiveSuiteById(suiteId) {
  return SUITE_BY_ID.get(String(suiteId ?? '').trim()) ?? null;
}

export function listOffensiveSuites() {
  return WAF_OFFENSIVE_SUITE_CATALOG.map((suite) => ({
    suite_id: suite.suite_id,
    label: suite.label,
    owasp_category: suite.owasp_category,
    attack_class: suite.attack_class,
    check_id: suite.check_id,
    scenario_family: suite.scenario_family,
    max_requests: suite.max_requests,
    risk_class: suite.risk_class,
    description: suite.description,
  }));
}

export function assertApprovedOffensiveSuiteIds(raw) {
  if (!Array.isArray(raw) || raw.length === 0) {
    const err = new Error('requested_suites must be a non-empty array of approved suite IDs.');
    err.code = 'invalid_offensive_request';
    throw err;
  }
  const suites = [...new Set(raw.map((s) => String(s).trim()).filter(Boolean))];
  if (suites.length === 0) {
    const err = new Error('requested_suites must include at least one suite ID.');
    err.code = 'invalid_offensive_request';
    throw err;
  }
  for (const suiteId of suites) {
    if (!SUITE_ID_SET.has(suiteId)) {
      const err = new Error(`Unknown offensive suite: ${suiteId}`);
      err.code = 'invalid_offensive_suite';
      throw err;
    }
  }
  return suites;
}

function rejectForbiddenIntakeFields(body) {
  for (const key of Object.keys(body ?? {})) {
    const normalized = String(key)
      .replace(/([a-z])([A-Z])/g, '$1_$2')
      .replace(/[^A-Za-z0-9]+/g, '_')
      .toLowerCase();
    if (FORBIDDEN_INTAKE_FIELDS.has(normalized)) {
      const err = new Error(`Field ${key} is not permitted on offensive WAF requests.`);
      err.code = 'unsafe_offensive_request';
      throw err;
    }
  }
}

export function validateOffensiveRequestIntake(body = {}) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { error: 'invalid_offensive_request', status: 400, message: 'Body must be a plain object.' };
  }
  try {
    assertNoRawWafEvidence(body);
    rejectForbiddenIntakeFields(body);
  } catch (err) {
    return { error: err.code ?? 'unsafe_offensive_request', status: 400, message: err.message };
  }

  const waf_asset_id = typeof body.waf_asset_id === 'string' ? body.waf_asset_id.trim() : '';
  if (!waf_asset_id) {
    return { error: 'missing_waf_asset_id', status: 400, message: 'waf_asset_id is required.' };
  }

  const objective = String(body.objective ?? body.reason ?? '').trim();
  if (!objective) {
    return { error: 'missing_objective', status: 400, message: 'objective (or reason) is required.' };
  }

  if (body.scope_confirmation !== true) {
    return {
      error: 'scope_confirmation_required',
      status: 400,
      message: 'scope_confirmation must be true for offensive WAF validation.',
    };
  }

  let requested_suites;
  try {
    requested_suites = assertApprovedOffensiveSuiteIds(body.requested_suites);
  } catch (err) {
    return { error: err.code ?? 'invalid_offensive_request', status: 400, message: err.message };
  }

  const emergency_contacts = Array.isArray(body.emergency_contacts)
    ? body.emergency_contacts
        .map((c) => (typeof c === 'string' ? c.trim() : c))
        .filter(Boolean)
    : [];
  if (emergency_contacts.length === 0) {
    return {
      error: 'missing_emergency_contacts',
      status: 400,
      message: 'At least one emergency contact is required.',
    };
  }

  const requested_window =
    typeof body.requested_window === 'string' && body.requested_window.trim()
      ? body.requested_window.trim()
      : null;

  const stop_criteria = String(body.stop_criteria ?? '').trim() || null;
  const abort_criteria = String(body.abort_criteria ?? body.stop_criteria ?? '').trim() || null;

  const staging_only = body.staging_only !== false;

  return {
    waf_asset_id,
    objective,
    requested_suites,
    emergency_contacts,
    requested_window,
    stop_criteria,
    abort_criteria,
    staging_only,
  };
}

export function offensiveAuthorizationPackComplete(request) {
  const artifacts = Array.isArray(request?.artifacts) ? request.artifacts : [];
  const accepted = new Set(
    artifacts.filter((a) => a.status === 'accepted').map((a) => a.type),
  );
  return WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES.every((type) => accepted.has(type));
}

export function offensiveAuthorizationPackStatus(request) {
  const artifacts = Array.isArray(request?.artifacts) ? request.artifacts : [];
  const byType = new Map(artifacts.map((a) => [a.type, a]));
  const requirements = WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES.map((type) => {
    const artifact = byType.get(type) ?? null;
    return {
      type,
      status: artifact?.status ?? 'missing',
      artifact_id: artifact?.id ?? null,
    };
  });
  const complete = offensiveAuthorizationPackComplete(request);
  return {
    complete,
    requirements,
    missing_types: requirements.filter((r) => r.status !== 'accepted').map((r) => r.type),
  };
}

export function normalizeOffensiveSuiteResult(entry, suiteId) {
  if (entry === null || entry === undefined || typeof entry !== 'object' || Array.isArray(entry)) {
    const err = new Error('Suite result must be a plain object.');
    err.code = 'unsafe_offensive_evidence';
    throw err;
  }
  assertNoRawWafEvidence(entry);
  const suite = getOffensiveSuiteById(suiteId);
  if (!suite) {
    const err = new Error(`Unknown offensive suite: ${suiteId}`);
    err.code = 'invalid_offensive_suite';
    throw err;
  }
  const observed_action = String(entry.observed_action ?? 'inconclusive').trim();
  let passed = null;
  if (entry.passed !== undefined && entry.passed !== null) {
    passed = Boolean(entry.passed);
  }
  const confidence = Number(entry.confidence ?? 0);
  const evidence_summary = entry.evidence_summary ?? entry.evidence_summary_json ?? {};
  return {
    suite_id: suite.suite_id,
    scenario_family: suite.scenario_family,
    check_id: suite.check_id,
    test_material_type: 'soc_gated_offensive_suite',
    expected_action: 'block',
    observed_action,
    passed,
    confidence: Number.isFinite(confidence) ? confidence : 0,
    evidence_summary_json:
      typeof evidence_summary === 'object' && evidence_summary !== null ? evidence_summary : {},
    probes_attempted: Number(entry.probes_attempted ?? suite.max_requests),
    blocked_count: Number(entry.blocked_count ?? 0),
    bypass_suspected_count: Number(entry.bypass_suspected_count ?? 0),
  };
}