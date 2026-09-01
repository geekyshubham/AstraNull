/**
 * Wave-4 WAF-evasion coverage manifest (W4-EVA).
 * Proposes checks/kinds/fields and registry moves for 69 E0 WAF-evasion vectors.
 * Data only — the integration worker wires these into checks.mjs / the registry.
 * The safe evasion probe lives in src/lib/vectorProbes/evasionProbes.mjs.
 */

import {
  WAF_EVASION_PROBE_KIND,
  MAX_WAF_EVASION_MARKER_REQUESTS,
  buildEvasionMarkerProfile,
} from '../../lib/vectorProbes/evasionProbes.mjs';

const SAFE_STOP_CONDITIONS = Object.freeze([
  'max_events_reached',
  'max_duration_elapsed',
  'customer_cancel',
  'tenant_kill_switch',
]);

function humanize(transform) {
  return transform
    .split('_')
    .map((w) => (w.length <= 3 ? w.toUpperCase() : w[0].toUpperCase() + w.slice(1)))
    .join(' ');
}

// Every E3 entry wraps an inert marker in a single evasion transform (see evasionProbes.mjs).
const EVASION_E3_TECHNIQUES = Object.freeze([
  { eva: 'EVA-004', transform: 'unicode_normalization', marker_class: 'sqli', technique: 'Unicode normalization mismatch' },
  { eva: 'EVA-005', transform: 'homoglyph', marker_class: 'sqli', technique: 'Unicode homoglyph / confusable substitution' },
  { eva: 'EVA-006', transform: 'overlong_utf8', marker_class: 'sqli', technique: 'Invalid / overlong UTF-8 handling discrepancy' },
  { eva: 'EVA-007', transform: 'alt_charset', marker_class: 'sqli', technique: 'Alternate declared character set' },
  { eva: 'EVA-008', transform: 'html_entity', marker_class: 'xss', technique: 'HTML entity encoding' },
  { eva: 'EVA-009', transform: 'js_escape', marker_class: 'xss', technique: 'JavaScript string / Unicode escapes' },
  { eva: 'EVA-010', transform: 'json_unicode_escape', marker_class: 'xss', technique: 'JSON Unicode escape encoding' },
  { eva: 'EVA-011', transform: 'css_escape', marker_class: 'xss', technique: 'CSS escape encoding' },
  { eva: 'EVA-012', transform: 'base64_wrap', marker_class: 'sqli', technique: 'Base64 / textual wrapping' },
  { eva: 'EVA-013', transform: 'numeric_repr', marker_class: 'sqli', technique: 'Hex / octal / numeric representation' },
  { eva: 'EVA-015', transform: 'whitespace', marker_class: 'sqli', technique: 'Whitespace substitution' },
  { eva: 'EVA-017', transform: 'lexical_operator', marker_class: 'sqli', technique: 'Operator / function substitution' },
  { eva: 'EVA-018', transform: 'lexical_tautology', marker_class: 'sqli', technique: 'Logical invariant / tautology mutation' },
  { eva: 'EVA-019', transform: 'lexical_literal', marker_class: 'sqli', technique: 'Number / literal shuffling' },
  { eva: 'EVA-020', transform: 'control_char', marker_class: 'sqli', technique: 'Null-byte / control-character insertion' },
  { eva: 'EVA-022', transform: 'path_matrix', marker_class: 'path_traversal', technique: 'Matrix / path-parameter ambiguity' },
  { eva: 'EVA-023', transform: 'path_suffix', marker_class: 'path_traversal', technique: 'Trailing dot / slash / suffix ambiguity' },
  { eva: 'EVA-024', transform: 'ip_representation', marker_class: 'sqli', technique: 'Alternative IP-address representation' },
  { eva: 'EVA-025', transform: 'parser_hpp', marker_class: 'sqli', technique: 'HTTP parameter pollution' },
  { eva: 'EVA-026', transform: 'parser_json_dup', marker_class: 'sqli', technique: 'Duplicate JSON key ambiguity' },
  { eva: 'EVA-027', transform: 'parser_header_dup', marker_class: 'sqli', technique: 'Duplicate / conflicting HTTP header ambiguity' },
  { eva: 'EVA-028', transform: 'framing_cl_te', marker_class: 'sqli', technique: 'Content-Length vs Transfer-Encoding ambiguity' },
  { eva: 'EVA-029', transform: 'framing_transfer_coding', marker_class: 'sqli', technique: 'Transfer-coding obfuscation' },
  { eva: 'EVA-030', transform: 'framing_h2_h1', marker_class: 'sqli', technique: 'HTTP/2-to-HTTP/1 framing differential' },
  { eva: 'EVA-031', transform: 'framing_line_ending', marker_class: 'sqli', technique: 'Line-ending / request-splitting discrepancy' },
  { eva: 'EVA-032', transform: 'framing_chunk_ext', marker_class: 'sqli', technique: 'Chunk-extension / trailer ambiguity' },
  { eva: 'EVA-033', transform: 'body_gzip', marker_class: 'sqli', technique: 'Compressed request-body evasion' },
  { eva: 'EVA-034', transform: 'body_nested_encoding', marker_class: 'sqli', technique: 'Nested content encoding' },
  { eva: 'EVA-041', transform: 'content_type_binary', marker_class: 'sqli', technique: 'Binary / protobuf opacity' },
  { eva: 'EVA-044', transform: 'struct_type_confusion', marker_class: 'sqli', technique: 'Type confusion / scalar-object switching' },
  { eva: 'EVA-045', transform: 'struct_deep_nesting', marker_class: 'sqli', technique: 'Deep nesting / sparse-index abuse' },
  { eva: 'EVA-046', transform: 'parameter_location', marker_class: 'sqli', technique: 'Parameter-location move' },
  { eva: 'EVA-047', transform: 'method_override', marker_class: 'sqli', technique: 'HTTP method override' },
  { eva: 'EVA-048', transform: 'protocol_version', marker_class: 'sqli', technique: 'HTTP version switch' },
  { eva: 'EVA-049', transform: 'protocol_upgrade', marker_class: 'xss', technique: 'WebSocket upgrade / post-upgrade opacity' },
  { eva: 'EVA-065', transform: 'benign_padding', marker_class: 'sqli', technique: 'Benign padding / anomaly-score dilution' },
  { eva: 'EVA-081', transform: 'polyglot_content', marker_class: 'xss', technique: 'Polyglot / multi-parser content' },
  { eva: 'EVA-083', transform: 'protocol_h3_h1', marker_class: 'sqli', technique: 'HTTP/3-to-HTTP/1.1 translation differential' },
  { eva: 'EVA-084', transform: 'protocol_qpack_hpack', marker_class: 'sqli', technique: 'QPACK / HPACK normalization gap' },
  { eva: 'EVA-090', transform: 'multipart_charset', marker_class: 'xss', technique: 'Multipart per-part charset coverage gap' },
  { eva: 'EVA-091', transform: 'xml_attribute', marker_class: 'xss', technique: 'XML attribute-value inspection bypass' },
]);

const INSPECTION_LIMIT_CHECK_ID = 'waf.inspection_limit.safe';
// Already implemented as waf_inspection_limit_probe (wave 3). We only wire it to a check + map IDs.
const INSPECTION_LIMIT_EVAS = Object.freeze([
  'EVA-035', 'EVA-036', 'EVA-037', 'EVA-038', 'EVA-067', 'EVA-068', 'EVA-069',
]);

const E4_GOVERNED = Object.freeze([
  { eva: 'EVA-058', family: 'residential_proxy', reason: 'Real-browser automation defeats bot detection only at distributed client scale.' },
  { eva: 'EVA-059', family: 'residential_proxy', reason: 'Headless-browser fingerprint masking is a distributed client-emulation campaign.' },
  { eva: 'EVA-060', family: 'residential_proxy', reason: 'Session / cookie warming requires sustained multi-session behavior.' },
  { eva: 'EVA-061', family: 'rate_limit_evasion', reason: 'Account rotation to defeat per-identity limits needs distributed identities.' },
  { eva: 'EVA-062', family: 'rate_limit_evasion', reason: 'Credential / token / API-key rotation at scale to evade throttles.' },
  { eva: 'EVA-063', family: 'rate_limit_evasion', reason: 'Endpoint / object rotation to spread load below thresholds.' },
  { eva: 'EVA-066', family: 'adaptive_evasion', reason: 'Threshold and rule probing requires many adaptive requests.' },
  { eva: 'EVA-070', family: 'adaptive_evasion', reason: 'Policy / version drift only surfaces via distributed sampling across nodes.' },
  { eva: 'EVA-073', family: 'adaptive_evasion', reason: 'Attack state assembled across many requests is a multi-request campaign.' },
  { eva: 'EVA-077', family: 'adaptive_evasion', reason: 'Alternate-protocol topology bypass requires probing distinct network paths at scale.' },
  { eva: 'EVA-087', family: 'adaptive_evasion', reason: 'AI semantic / adversarial-suffix evasion requires adversarial-input generation; a safe canary marker could later make this E3.' },
  { eva: 'EVA-088', family: 'adaptive_evasion', reason: 'Multimodal hidden-instruction evasion requires generating multimodal adversarial inputs.' },
  { eva: 'EVA-089', family: 'adaptive_evasion', reason: 'Tool-schema / agent-boundary confusion requires driving an agent runtime; potential future E1 posture.' },
]);

const GOVERNED_PATTERN_CHECK = Object.freeze({
  residential_proxy: 'pattern.residential_proxy.readiness',
  rate_limit_evasion: 'pattern.rate_limit_evasion.readiness',
  adaptive_evasion: 'pattern.adaptive_evasion.readiness',
});

const E1_POSTURE = Object.freeze([
  { eva: 'EVA-050', slug: 'cache_key_mismatch', name: 'Cache-key / routing mismatch', setup: 'declared_cache_key_normalization', reason: 'Confirming a cache-key mismatch requires poisoning a shared cache, affecting third parties; records declared cache-key normalization posture.' },
  { eva: 'EVA-051', slug: 'reassembly_differential', name: 'IP fragmentation / TCP segmentation differential', setup: 'declared_edge_reassembly_policy', reason: 'Requires raw-packet fragmentation outside the bounded HTTP probe surface; records declared L3/L4 reassembly-normalization posture.' },
  { eva: 'EVA-071', slug: 'rule_gap', name: 'Zero-day / rule-gap evasion', setup: 'declared_managed_ruleset', reason: 'No known marker can probe an unknown gap; records declared managed-ruleset / virtual-patching posture.' },
  { eva: 'EVA-072', slug: 'second_order', name: 'Stored / deferred second-order payload', setup: 'declared_stored_content_inspection', reason: 'Confirmation requires a state-changing write then trigger; records declared stored-content inspection posture.' },
  { eva: 'EVA-079', slug: 'encrypted_payload', name: 'Application-layer encrypted / opaque payload', setup: 'declared_app_layer_decryption', reason: 'No plaintext marker is inspectable outside-in; records declared application-layer decryption/inspection posture.' },
  { eva: 'EVA-080', slug: 'signed_structured_data', name: 'Signed but malicious structured data', setup: 'declared_schema_signature_validation', reason: 'A valid signature cannot be forged without the application key; records declared schema/signature-validation posture.' },
  { eva: 'EVA-085', slug: 'connection_coalescing', name: 'Connection coalescing identity confusion', setup: 'declared_per_host_policy', reason: 'Requires a multi-host TLS coalescing setup not reproducible via a single bounded probe; records declared per-host policy posture.' },
  { eva: 'EVA-086', slug: 'ech_routing_metadata', name: 'Encrypted ClientHello / hidden routing-metadata gap', setup: 'declared_ech_sni_inspection', reason: 'Hidden routing metadata is not visible outside-in; records declared ECH/SNI inspection posture.' },
]);

function evasionCheckId(transform) {
  return `waf.evasion_${transform}.safe`;
}

function buildEvasionCheck({ transform, marker_class, technique }) {
  const profile = { ...buildEvasionMarkerProfile({ transform, marker_class }) };
  return {
    check_id: evasionCheckId(transform),
    version: '1.0.0',
    name: `WAF Evasion — ${humanize(transform)} (Safe)`,
    vector_family: 'waf',
    safety_class: 'safe',
    description: `Bounded probe: wraps the inert ${marker_class} marker in a ${technique} transform and checks whether the WAF still blocks it.`,
    required_agent_modes: ['heartbeat'],
    supported_targets: ['url', 'fqdn'],
    required_customer_setup: ['declared_waf_asset', 'customer_approves_waf_marker_probe'],
    evidence_required: ['probe_result', 'agent_observation'],
    stop_conditions: [...SAFE_STOP_CONDITIONS],
    safety_constraints: { max_events: MAX_WAF_EVASION_MARKER_REQUESTS, max_duration_seconds: 120, max_concurrent_runs_per_target_group: 1 },
    verdict_logic: `Baseline inert marker should be blocked; if the ${technique} variant passes while baseline is blocked, evasion is suspected (finding). Both blocked = evasion resisted.`,
    default_expected_behavior: 'must_block_before_origin',
    prerequisites: [],
    remediation_template: `Enable normalization/canonicalization for ${technique} on the edge WAF so inspection occurs after decoding.`,
    explanation_template: `Bounded inert-marker probe correlated with agent observation graded WAF normalization of ${technique}.`,
    probe_profile: profile,
    probe_simulation_profile: 'external_blocked',
  };
}

function buildPostureCheck({ slug, name, setup, reason }) {
  return {
    check_id: `waf.evasion_${slug}.posture`,
    version: '1.0.0',
    name: `WAF Evasion Posture — ${name}`,
    vector_family: 'waf',
    safety_class: 'safe',
    description: `Posture-only record for ${name}. ${reason}`,
    required_agent_modes: ['heartbeat'],
    supported_targets: ['url', 'fqdn'],
    required_customer_setup: ['declared_waf_asset', setup],
    evidence_required: ['agent_observation'],
    stop_conditions: [...SAFE_STOP_CONDITIONS],
    safety_constraints: { max_events: 1, max_duration_seconds: 60, max_concurrent_runs_per_target_group: 1 },
    verdict_logic: 'Posture-only: verdict reflects the declared configuration fact; no outside-in probe signal exists.',
    default_expected_behavior: 'must_block_before_origin',
    prerequisites: [],
    remediation_template: `Declare and verify ${name} controls; no safe outside-in probe can establish this fact.`,
    explanation_template: `Declared-configuration posture for ${name}.`,
    probe_profile: { kind: 'metadata_marker', max_requests: 1, timeout_ms: 5000, marker: 'astranull-safe-marker' },
    probe_simulation_profile: 'external_blocked',
  };
}

export const PROPOSED_PROBE_KINDS = Object.freeze([
  {
    kind: WAF_EVASION_PROBE_KIND,
    max_requests: MAX_WAF_EVASION_MARKER_REQUESTS,
    rationale: 'Bounded (<=8) inert-marker evasion probe: wraps an existing benign SQLi/XSS/path marker in one encoding/canonicalization/parser transform and grades whether the WAF still blocks it. Sends nothing exploitable.',
  },
]);

export const PROPOSED_PROFILE_FIELDS = Object.freeze([
  { field: 'evasion_transform', validation: 'enum of EVASION_TRANSFORMS (evasionProbes.mjs)', applies_to_kinds: [WAF_EVASION_PROBE_KIND] },
  { field: 'marker_class', validation: 'enum: sqli|xss|path_traversal', applies_to_kinds: [WAF_EVASION_PROBE_KIND] },
]);

export const PROPOSED_CHECKS = Object.freeze([
  ...EVASION_E3_TECHNIQUES.map(buildEvasionCheck),
  {
    check_id: INSPECTION_LIMIT_CHECK_ID,
    version: '1.0.0',
    name: 'WAF Inspection-Limit / Fail-Open (Safe)',
    vector_family: 'waf',
    safety_class: 'safe',
    description: 'Wires the existing wave-3 waf_inspection_limit_probe to a check: places the inert marker past body/field/parser inspection limits and checks whether it is still blocked.',
    required_agent_modes: ['heartbeat'],
    supported_targets: ['url', 'fqdn'],
    required_customer_setup: ['declared_waf_asset', 'customer_approves_waf_marker_probe'],
    evidence_required: ['probe_result', 'agent_observation'],
    stop_conditions: [...SAFE_STOP_CONDITIONS],
    safety_constraints: { max_events: 6, max_duration_seconds: 120, max_concurrent_runs_per_target_group: 1 },
    verdict_logic: 'If the marker placed past an inspection limit passes while an in-limit marker is blocked, an inspection-limit / fail-open gap is suspected.',
    default_expected_behavior: 'must_block_before_origin',
    prerequisites: [],
    remediation_template: 'Raise or enforce WAF body/field/parser inspection limits and fail-closed on inspection budget exhaustion.',
    explanation_template: 'Bounded inspection-limit probe correlated with agent observation.',
    probe_profile: {
      kind: 'waf_inspection_limit_probe',
      max_requests: 6,
      timeout_ms: 5000,
      marker: 'astranull-safe-marker',
      scenario_family: 'marker',
      marker_type: 'query',
      expected_action: 'block',
      http_method: 'POST',
      nonce_hash_only: true,
      collect: ['status_code', 'waf_product_hint', 'evasion_bypass_suspected'],
    },
    probe_simulation_profile: 'external_blocked',
  },
  ...E1_POSTURE.map(buildPostureCheck),
]);

export const PROPOSED_REGISTRY_MAPPING = Object.freeze([
  ...EVASION_E3_TECHNIQUES.map(({ eva, transform }) => ({
    registry_id: eva,
    add_check_ids: [evasionCheckId(transform)],
    target_tier: 'E3',
  })),
  ...INSPECTION_LIMIT_EVAS.map((eva) => ({
    registry_id: eva,
    add_check_ids: [INSPECTION_LIMIT_CHECK_ID],
    target_tier: 'E3',
  })),
  ...E4_GOVERNED.map(({ eva, family }) => ({
    registry_id: eva,
    add_check_ids: [GOVERNED_PATTERN_CHECK[family]],
    target_tier: 'E4',
  })),
  ...E1_POSTURE.map(({ eva, slug }) => ({
    registry_id: eva,
    add_check_ids: [`waf.evasion_${slug}.posture`],
    target_tier: 'E1',
  })),
]);

export const PROPOSED_TIER_RECLASSIFICATION = Object.freeze([
  ...E4_GOVERNED.map(({ eva, family, reason }) => ({
    registry_id: eva,
    target_tier: 'E4',
    governed_scenario_family: family,
    reason,
  })),
  ...E1_POSTURE.map(({ eva, reason }) => ({
    registry_id: eva,
    target_tier: 'E1',
    reason,
  })),
]);

export const EVASION_COVERAGE_SUMMARY = Object.freeze({
  total: EVASION_E3_TECHNIQUES.length + INSPECTION_LIMIT_EVAS.length + E4_GOVERNED.length + E1_POSTURE.length,
  e3_new_probe: EVASION_E3_TECHNIQUES.length,
  e3_inspection_limit: INSPECTION_LIMIT_EVAS.length,
  e4_governed: E4_GOVERNED.length,
  e1_posture: E1_POSTURE.length,
});
