/**
 * Server-derived check definition version and run evidence stamp.
 *
 * Uses the explicit catalog `version` when it is a real version string, otherwise a
 * stable digest of the canonical definition. Request and body patterns stay in the
 * digest. Credential values are replaced with a stable placeholder before hashing
 * and are not returned. A request body cannot supply the version or producer.
 */
import { createHash } from 'node:crypto';
import { resolveExpectedBehaviorForCheck } from '../contracts/checks.mjs';

const LIVE_MARKERS = new Set(['live', 'latest', 'current', 'producer', 'live_external', 'user']);
const IGNORED_BODY_FIELDS = ['version', 'check_version', 'scenario_version', 'producer_kind', 'live', 'expected_behavior'];
const STRIPPED_DEFINITION_KEYS = new Set(['producer_kind', 'live']);
const CREDENTIAL_KEY = /password|secret|token|credential|authorization|cookie|api[_-]?key|private[_-]?key/i;
const CREDENTIAL_VALUE = /bearer\s+\S|cookie\s*=|authorization\s*:/i;

function stableStringify(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

function redactForDigest(value, key = '') {
  if (CREDENTIAL_KEY.test(key)) return '[redacted]';
  if (typeof value === 'string' && CREDENTIAL_VALUE.test(value)) return '[redacted]';
  if (Array.isArray(value)) return value.map((entry) => redactForDigest(entry));
  if (value && typeof value === 'object') {
    const out = {};
    for (const child of Object.keys(value).sort()) out[child] = redactForDigest(value[child], child);
    return out;
  }
  return value;
}

function definitionForDigest(definition) {
  const copy = {};
  for (const key of Object.keys(definition).sort()) {
    if (STRIPPED_DEFINITION_KEYS.has(key)) continue;
    copy[key] = definition[key];
  }
  return redactForDigest(copy);
}

export function canonicalDefinitionDigest(definition) {
  return createHash('sha256').update(stableStringify(definitionForDigest(definition))).digest('hex');
}

function explicitVersion(definition) {
  const raw = typeof definition?.version === 'string' ? definition.version.trim() : '';
  if (!raw || LIVE_MARKERS.has(raw.toLowerCase())) return null;
  return raw;
}

/**
 * @param {object} definition Catalog check definition. Not a request body.
 * @param {object} [body] Ignored for version and producer. Listed in `ignored_body_fields`.
 */
export function deriveCheckDefinitionVersion(definition, body = undefined) {
  if (!definition || typeof definition !== 'object' || Array.isArray(definition) || !definition.check_id) {
    return { error: 'invalid_check_definition', status: 400 };
  }
  const ignored = [];
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    for (const field of IGNORED_BODY_FIELDS) {
      if (body[field] != null) ignored.push(field);
    }
  }
  const digest = canonicalDefinitionDigest(definition);
  const version = explicitVersion(definition);
  if (!version) {
    return {
      check_version: `sha256:${digest}`,
      derivation: 'canonical_digest',
      digest,
      producer_kind: null,
      ignored_body_fields: ignored,
    };
  }
  return {
    check_version: version,
    derivation: 'explicit',
    digest,
    producer_kind: null,
    ignored_body_fields: ignored,
  };
}

/**
 * Run stamp from the catalog definition and the approved scenario. Body version,
 * producer, and expected-behavior flags are ignored.
 *
 * @param {object} check Catalog check.
 * @param {object} [body]
 * @param {{ probeMode?: string, opsReadiness?: boolean, scenarioVersion?: string|null }} [runtime]
 */
/** Catalog scenario, else the caller-supplied approved ops scenario. Body flags are not read. */
export function approvedScenarioVersion(check, opsScenario = null) {
  const profile = check?.probe_profile ?? {};
  if (typeof profile.scenario === 'string' && profile.scenario.trim()) return profile.scenario.trim();
  if (typeof profile.scenario_family === 'string' && profile.scenario_family.trim()) return profile.scenario_family.trim();
  return typeof opsScenario === 'string' && opsScenario.trim() ? opsScenario.trim() : null;
}

export function deriveRunEvidenceStamp(check, body = undefined, runtime = {}) {
  const version = deriveCheckDefinitionVersion(check, body);
  if (version.error) return version;
  const producerKind = runtime.opsReadiness
    ? 'customer_declaration'
    : runtime.probeMode === 'signed-worker'
      ? 'signed_probe'
      : 'internal_simulation';
  const scenario = typeof runtime.scenarioVersion === 'string' && runtime.scenarioVersion.trim()
    ? runtime.scenarioVersion.trim()
    : null;
  const expected = typeof check.default_expected_behavior === 'string' && check.default_expected_behavior.trim()
    ? check.default_expected_behavior.trim()
    : null;
  return {
    check_version: version.check_version,
    scenario_version: scenario,
    producer_kind: producerKind,
    derivation: version.derivation,
    digest: version.digest,
    ignored_body_fields: version.ignored_body_fields,
    expected_behavior: expected,
    expected_behavior_json: expected == null ? null : {
      value: expected,
      source: 'catalog_default',
      check_id: check.check_id,
      check_version: version.check_version,
    },
    provenance_json: {
      derivation: version.derivation,
      digest: version.digest,
      producer_kind: producerKind,
      scenario_source: scenario ? 'catalog_or_approved_runtime' : 'not_recorded',
      expected_behavior_source: expected ? 'catalog_default' : 'not_recorded',
      ignored_body_fields: version.ignored_body_fields,
    },
  };
}

/**
 * Expected behavior that governs a run's final verdict.
 *
 * A stamped run (one created through deriveRunEvidenceStamp) must finalize against the
 * immutable expected_behavior_json snapshot captured at start so a catalog change while
 * the run is collecting cannot change its outcome semantics. A stamped run with no
 * recorded snapshot reports `null` (truthfully unrecorded); only legacy unstamped runs
 * keep the historical today-catalog fallback. Request bodies can never supply this value.
 *
 * @param {{ producer_kind?: unknown, check_id?: unknown, expected_behavior_json?: unknown }} run
 * @returns {string | null}
 */
export function verdictExpectedBehaviorForRun(run) {
  const stamped = typeof run?.producer_kind === 'string' && run.producer_kind.trim() !== '';
  if (!stamped) {
    return resolveExpectedBehaviorForCheck(run?.check_id);
  }
  const snapshot = run?.expected_behavior_json;
  if (
    snapshot
    && typeof snapshot === 'object'
    && !Array.isArray(snapshot)
    && (snapshot.check_id == null || snapshot.check_id === run.check_id)
    && typeof snapshot.value === 'string'
    && snapshot.value.trim() !== ''
  ) {
    return snapshot.value.trim();
  }
  return null;
}
