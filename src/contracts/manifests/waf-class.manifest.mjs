/**
 * WAF attack-class coverage manifest (Wave 4, ticket W4-WAF).
 *
 * PROPOSES — does not wire — the additions that move all 117 currently-E0 WAF
 * catalog vectors (grouped under registry entries WV-009..WV-042) out of E0.
 * The integration worker consumes this module and applies it to checks.mjs and
 * resourceExhaustionTaxonomy.mjs. This file edits neither.
 *
 * Coverage discipline:
 *  - E3 (gradeable): a WAF rule can be exercised by an INERT benign marker.
 *  - E1 (posture): no honest outside-in signal; a declared config/header fact.
 *  - E4 (SOC-governed): needs auth, disposable state, or an adversarial suite.
 * Every one of the 117 catalog IDs is accounted for exactly once below.
 */

import {
  WAF_CLASS_MARKER_PROBE_KIND,
  WAF_CLASS_PROBE_MAX_REQUESTS,
  WAF_CLASS_MARKERS,
  buildWafClassProbeProfile,
} from '../../lib/vectorProbes/wafClassProbes.mjs';

export const PROPOSED_PROBE_KINDS = Object.freeze([
  {
    kind: WAF_CLASS_MARKER_PROBE_KIND,
    max_requests: WAF_CLASS_PROBE_MAX_REQUESTS,
    rationale:
      'Bounded outside-in benign-marker probe for WAF attack families. Up to 8 GET '
      + 'requests (baseline plus marker in query, path, and a benign header). No rate, '
      + 'concurrency, or repeat parameter. Markers are inert detection strings.',
  },
]);

export const PROPOSED_PROFILE_FIELDS = Object.freeze([
  {
    field: 'marker_class',
    validation: `enum of ${Object.keys(WAF_CLASS_MARKERS).join(', ')}`,
    applies_to_kinds: [WAF_CLASS_MARKER_PROBE_KIND],
  },
]);

function e3Check({ check_id, name, marker_class, description, verdict_logic, remediation_template }) {
  return {
    check_id,
    version: '1.0.0',
    name,
    vector_family: 'waf',
    safety_class: 'safe',
    risk_class: 'safe',
    description,
    supported_targets: ['url', 'fqdn'],
    prerequisites: [],
    required_customer_setup: ['declared_waf_asset', 'customer_approves_waf_marker_probe'],
    evidence_required: ['probe_result'],
    stop_conditions: [
      'max_events_reached',
      'max_duration_elapsed',
      'customer_cancel',
      'tenant_kill_switch',
    ],
    safety_constraints: {
      max_events: WAF_CLASS_PROBE_MAX_REQUESTS,
      max_duration_seconds: 120,
      max_concurrent_runs_per_target_group: 1,
    },
    verdict_logic,
    probe_profile: {
      ...buildWafClassProbeProfile({ marker_class, max_requests: WAF_CLASS_PROBE_MAX_REQUESTS, timeout_ms: 5000 }),
    },
    default_expected_behavior: 'must_block_before_origin',
    probe_simulation_profile: 'external_blocked',
    remediation_template,
    explanation_template:
      'A bounded set of inert benign markers for this WAF attack class was correlated '
      + 'with edge blocking/challenge behaviour. Markers achieve nothing if they reach origin.',
  };
}

const E3_CHECK_DEFS = [
  {
    check_id: 'waf.http_method_policy_marker.safe', name: 'WAF HTTP Method/Protocol Policy Marker (Safe)',
    marker_class: 'http_method_policy',
    description: 'Benign method/header-policy marker to confirm the WAF flags malformed-request and protocol-policy signatures.',
    verdict_logic: 'Baseline plus method/protocol-policy markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable request/protocol-policy and header-policy WAF rules to block malformed-request signatures.',
  },
  {
    check_id: 'waf.request_smuggling_marker.safe', name: 'WAF Request-Smuggling Marker (Safe)',
    marker_class: 'request_smuggling',
    description: 'Inert request-smuggling signature marker (no conflicting CL/TE constructed) to confirm smuggling WAF rules.',
    verdict_logic: 'Baseline plus smuggling-signature markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable request-smuggling normalization and CL/TE conflict rejection at the edge.',
  },
  {
    check_id: 'waf.crlf_injection_marker.safe', name: 'WAF CRLF/Response-Splitting Marker (Safe)',
    marker_class: 'crlf',
    description: 'Encoded CRLF marker injecting a benign header token to confirm CRLF/response-splitting WAF rules.',
    verdict_logic: 'Baseline plus CRLF markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable CRLF/header-injection WAF rules and reject encoded newline sequences in inputs.',
  },
  {
    check_id: 'waf.open_redirect_marker.safe', name: 'WAF Open-Redirect / Parameter-Policy Marker (Safe)',
    marker_class: 'open_redirect',
    description: 'Benign off-host (.invalid) redirect and parameter/path-policy marker to confirm redirect and duplicate-input WAF rules.',
    verdict_logic: 'Baseline plus redirect/parameter markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable open-redirect and parameter/path normalization WAF rules; allowlist redirect targets.',
  },
  {
    check_id: 'waf.nosql_injection_marker.safe', name: 'WAF NoSQL Injection Marker (Safe)',
    marker_class: 'nosql',
    description: 'Inert NoSQL operator marker (matches nothing) to confirm NoSQL-operator WAF rules.',
    verdict_logic: 'Baseline plus NoSQL-operator markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable NoSQL-operator WAF rules and reject query-operator tokens in string inputs.',
  },
  {
    check_id: 'waf.xpath_injection_marker.safe', name: 'WAF XPath/XML Injection Marker (Safe)',
    marker_class: 'xpath',
    description: 'Benign always-false XPath marker to confirm XPath/XML-injection WAF rules.',
    verdict_logic: 'Baseline plus XPath markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable XPath/XQuery-injection WAF rules for declared XML endpoints.',
  },
  {
    check_id: 'waf.jndi_ldap_marker.safe', name: 'WAF JNDI/LDAP (Log4Shell) Marker (Safe)',
    marker_class: 'ldap',
    description: 'Inert JNDI/LDAP marker pointing at a .invalid sink to confirm Log4Shell/JNDI WAF rules.',
    verdict_logic: 'Baseline plus JNDI markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable JNDI/Log4Shell WAF rules; block ${jndi:} lookup signatures in inputs and headers.',
  },
  {
    check_id: 'waf.csv_formula_marker.safe', name: 'WAF CSV/Formula & Data-Channel Injection Marker (Safe)',
    marker_class: 'csv_injection',
    description: 'Inert leading-equals formula marker (no function call) to confirm CSV/formula and data-channel WAF rules.',
    verdict_logic: 'Baseline plus formula markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable formula/CSV-injection and data-channel WAF rules; neutralize leading =,+,-,@ in exports.',
  },
  {
    check_id: 'waf.prototype_pollution_marker.safe', name: 'WAF Prototype-Pollution Marker (Safe)',
    marker_class: 'prototype_pollution',
    description: 'Inert __proto__ token string (no nested object assignment) to confirm prototype-pollution WAF rules.',
    verdict_logic: 'Baseline plus __proto__ markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable prototype-pollution WAF rules; reject __proto__/constructor/prototype property paths.',
  },
  {
    check_id: 'waf.deserialization_marker.safe', name: 'WAF Unsafe-Deserialization Marker (Safe)',
    marker_class: 'deserialization',
    description: 'Inert serialized-stream signature marker (not a functional gadget) to confirm deserialization WAF rules.',
    verdict_logic: 'Baseline plus deserialization-signature markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable unsafe-deserialization WAF rules; reject serialized-object magic signatures in inputs.',
  },
  {
    check_id: 'waf.ssrf_marker.safe', name: 'WAF SSRF Marker (Safe)',
    marker_class: 'ssrf',
    description: 'Benign SSRF marker pointing at a .invalid sink (never a metadata endpoint) to confirm SSRF WAF rules.',
    verdict_logic: 'Baseline plus SSRF-URL markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable SSRF WAF rules and egress allowlists; block internal/metadata URL fetch signatures.',
  },
  {
    check_id: 'waf.xxe_marker.safe', name: 'WAF XXE Marker (Safe)',
    marker_class: 'xxe',
    description: 'Benign DOCTYPE/external-entity marker referencing a .invalid sink to confirm XXE WAF rules.',
    verdict_logic: 'Baseline plus XXE DOCTYPE markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable XXE WAF rules and disable external-entity resolution on declared XML endpoints.',
  },
  {
    check_id: 'waf.file_upload_marker.safe', name: 'WAF File-Upload Signature Marker (Safe)',
    marker_class: 'file_upload_marker',
    description: 'Benign upload filename marker (harmless .txt, no code) to confirm the edge flags web-shell upload signatures.',
    verdict_logic: 'Baseline plus upload-signature markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enable file-upload WAF rules; block double-extension and web-shell filename/content signatures.',
  },
  {
    check_id: 'waf.jwt_tamper_marker.safe', name: 'WAF/API-Gateway JWT Tamper Marker (Safe)',
    marker_class: 'jwt_tamper',
    description: 'Inert alg:none JWT with no real claims/signature to confirm gateway JWT-tamper rejection rules.',
    verdict_logic: 'Baseline plus alg:none JWT markers; blocked/challenged => protected, allowed => exposed.',
    remediation_template: 'Enforce JWT signature/alg validation at the API gateway; reject alg:none and unsigned tokens.',
  },
];

export const PROPOSED_CHECKS = Object.freeze(E3_CHECK_DEFS.map((def) => Object.freeze(e3Check(def))));

export const PROPOSED_REGISTRY_MAPPING = Object.freeze([
  { registry_id: 'WV-009', add_check_ids: ['waf.http_method_policy_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-010', add_check_ids: ['waf.request_smuggling_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-011', add_check_ids: ['waf.crlf_injection_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-013', add_check_ids: ['waf.open_redirect_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-014', add_check_ids: ['waf.nosql_injection_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-015', add_check_ids: ['waf.xpath_injection_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-016', add_check_ids: ['waf.jndi_ldap_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-017', add_check_ids: ['waf.csv_formula_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-018', add_check_ids: ['waf.prototype_pollution_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-019', add_check_ids: ['waf.deserialization_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-020', add_check_ids: ['waf.ssrf_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-021', add_check_ids: ['waf.xxe_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-024', add_check_ids: ['waf.file_upload_marker.safe'], target_tier: 'E3' },
  { registry_id: 'WV-028', add_check_ids: ['waf.jwt_tamper_marker.safe'], target_tier: 'E3' },
]);

export const PROPOSED_TIER_RECLASSIFICATION = Object.freeze([
  {
    registry_id: 'WV-012', target_tier: 'E1', governed_scenario_family: null,
    posture_fact: 'declared_proxy_trust_boundary',
    reason: 'Forwarded-header/HTTPoxy/authority trust is an origin-declared config fact; whether a trusted proxy honours a spoofed forwarded header is not observable by a stateless outside-in marker.',
  },
  {
    registry_id: 'WV-022', target_tier: 'E1', governed_scenario_family: null,
    posture_fact: 'declared_content_security_policy',
    reason: 'JSONP-hijack and CSS-injection exposure is governed by CSP, content-type, and X-Content-Type-Options headers (a posture fact), not by a reliable outside-in WAF signature.',
  },
  {
    registry_id: 'WV-023', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'disposable_filesystem_canary_and_write_symlink_race_fixtures',
    reason: 'Remote/local file write, symlink, and TOCTOU race confirmation requires a disposable filesystem canary and destructive fixtures. (RFI sub-vector alone could be E3 via the SSRF-family marker.)',
  },
  {
    registry_id: 'WV-025', target_tier: 'E4', governed_scenario_family: 'http_post_flood',
    governed_requirement: 'disposable_accounts_and_bounded_enumeration_push_fatigue_workflow',
    reason: 'Account enumeration and MFA push-fatigue need disposable accounts and repeated auth/push traffic (governed automation), not a stateless marker.',
  },
  {
    registry_id: 'WV-026', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'authenticated_disposable_session_fixation_replay_tamper_fixtures',
    reason: 'Session fixation/replay/tampering requires an authenticated disposable session; not confirmable without auth or state change.',
  },
  {
    registry_id: 'WV-027', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'authenticated_state_changing_action_and_cross_origin_canary',
    reason: 'CSRF confirmation needs an authenticated state-changing action performed cross-origin — a state change disallowed for a safe probe.',
  },
  {
    registry_id: 'WV-029', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'disposable_oauth_client_and_redirect_state_pkce_canaries',
    reason: 'OAuth/OIDC redirect, state, PKCE, and token-leak validation requires a disposable OAuth client and full authorization-code flow.',
  },
  {
    registry_id: 'WV-030', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'disposable_saml_service_provider_and_signature_wrapping_fixtures',
    reason: 'SAML signature-wrapping/replay needs a disposable service provider and signed-assertion fixtures.',
  },
  {
    registry_id: 'WV-031', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'disposable_identity_across_declared_auth_endpoints',
    reason: 'Alternate authentication-path coverage requires a disposable identity exercised across every declared auth endpoint, method, and content type.',
  },
  {
    registry_id: 'WV-032', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'two_disposable_users_tenants_and_declared_object_ids',
    reason: 'BOLA/BOPLA/BFLA/mass-assignment need two disposable users/tenants and declared object ids to prove authorization crossing — inherently authenticated.',
  },
  {
    registry_id: 'WV-033', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'disposable_identities_and_declared_rest_graphql_grpc_canaries',
    reason: 'API data-exposure/authorization across REST/GraphQL/gRPC/business-flow needs disposable identities and declared endpoints.',
  },
  {
    registry_id: 'WV-034', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'disposable_transaction_workflow_for_parameter_sequence_race_replay',
    reason: 'Business-logic parameter/sequence/race/replay abuse requires a disposable transaction workflow and state changes.',
  },
  {
    registry_id: 'WV-035', target_tier: 'E4', governed_scenario_family: 'coordinated_swarm',
    governed_requirement: 'tenant_declared_business_flows_and_bounded_oat_automation_scenarios',
    reason: 'OAT automated commercial abuse (scraping/carding/credential-stuffing/scalping) is validated only by governed automation at scale against declared business flows.',
  },
  {
    registry_id: 'WV-036', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'declared_llm_endpoint_and_direct_indirect_prompt_canaries',
    reason: 'Direct/indirect prompt injection needs a tenant-declared LLM endpoint plus prompt and retrieved-content canaries. (A prompt-injection canary marker could be E3 given a declared AI-gateway.)',
  },
  {
    registry_id: 'WV-037', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'declared_llm_endpoint_prompt_canary_and_output_sink_assertions',
    reason: 'System-prompt extraction and output-handling validation needs a declared LLM endpoint, a non-secret prompt canary, and output-sink assertions.',
  },
  {
    registry_id: 'WV-038', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'sandboxed_agent_with_declared_tools_identities_denylisted_actions',
    reason: 'AI tool/goal/identity/privilege validation requires a sandboxed agent with declared tools, identities, and denylisted canary actions.',
  },
  {
    registry_id: 'WV-039', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'disposable_agent_runtime_and_canary_memory_retrieval_docs',
    reason: 'Agent supply-chain/memory/retrieval poisoning needs a disposable agent runtime and canary documents in declared stores.',
  },
  {
    registry_id: 'WV-040', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'declared_multimodal_endpoint_and_hidden_instruction_corpus',
    reason: 'Multimodal/adversarial-suffix validation needs a tenant-declared multimodal endpoint and a benign hidden-instruction corpus.',
  },
  {
    registry_id: 'WV-041', target_tier: 'E4', governed_scenario_family: 'http_post_flood',
    governed_requirement: 'declared_llm_endpoint_and_bounded_token_toolcall_time_cost_budgets',
    reason: 'Unbounded model resource-consumption validation needs a declared LLM endpoint and governed token/tool-call/time/cost budgets at scale.',
  },
  {
    registry_id: 'WV-042', target_tier: 'E4', governed_scenario_family: null,
    governed_requirement: 'sandboxed_multi_agent_workflow_with_signed_message_and_kill_switch_canaries',
    reason: 'Cross-agent message and rogue-agent validation requires a sandboxed multi-agent workflow with signed-message, trust-boundary, and kill-switch canaries.',
  },
]);

/** Full 117-ID accounting: every owned catalog vector and the tier it lands in. */
export const PROPOSED_CATALOG_COVERAGE = Object.freeze([
  { registry_id: 'WV-009', tier: 'E3', catalog_vector_ids: ['WAF-002', 'WAF-003', 'WAF-004', 'WAF-005', 'WAF-006'] },
  { registry_id: 'WV-010', tier: 'E3', catalog_vector_ids: ['WAF-007', 'WAF-008', 'WAF-009', 'WAF-010'] },
  { registry_id: 'WV-011', tier: 'E3', catalog_vector_ids: ['WAF-011'] },
  { registry_id: 'WV-012', tier: 'E1', catalog_vector_ids: ['WAF-013', 'WAF-014', 'WAF-015'] },
  { registry_id: 'WV-013', tier: 'E3', catalog_vector_ids: ['WAF-016', 'WAF-017', 'WAF-020', 'WAF-022', 'WAF-024'] },
  { registry_id: 'WV-014', tier: 'E3', catalog_vector_ids: ['WAF-033', 'WAF-034', 'WAF-035', 'WAF-036'] },
  { registry_id: 'WV-015', tier: 'E3', catalog_vector_ids: ['WAF-038', 'WAF-039'] },
  { registry_id: 'WV-016', tier: 'E3', catalog_vector_ids: ['WAF-047'] },
  { registry_id: 'WV-017', tier: 'E3', catalog_vector_ids: ['WAF-048', 'WAF-049', 'WAF-050', 'WAF-051', 'WAF-052'] },
  { registry_id: 'WV-018', tier: 'E3', catalog_vector_ids: ['WAF-053', 'WAF-054'] },
  { registry_id: 'WV-019', tier: 'E3', catalog_vector_ids: ['WAF-055', 'WAF-056', 'WAF-057', 'WAF-058', 'WAF-059', 'WAF-060'] },
  { registry_id: 'WV-020', tier: 'E3', catalog_vector_ids: ['WAF-061', 'WAF-062', 'WAF-063', 'WAF-064', 'WAF-065', 'WAF-066'] },
  { registry_id: 'WV-021', tier: 'E3', catalog_vector_ids: ['WAF-067', 'WAF-068'] },
  { registry_id: 'WV-022', tier: 'E1', catalog_vector_ids: ['WAF-080', 'WAF-081'] },
  { registry_id: 'WV-023', tier: 'E4', catalog_vector_ids: ['WAF-084', 'WAF-086', 'WAF-095'] },
  { registry_id: 'WV-024', tier: 'E3', catalog_vector_ids: ['WAF-087', 'WAF-088', 'WAF-089', 'WAF-090', 'WAF-091', 'WAF-092', 'WAF-093'] },
  { registry_id: 'WV-025', tier: 'E4', catalog_vector_ids: ['WAF-099', 'WAF-101'] },
  { registry_id: 'WV-026', tier: 'E4', catalog_vector_ids: ['WAF-104', 'WAF-105', 'WAF-106'] },
  { registry_id: 'WV-027', tier: 'E4', catalog_vector_ids: ['WAF-107'] },
  { registry_id: 'WV-028', tier: 'E3', catalog_vector_ids: ['WAF-108', 'WAF-109', 'WAF-110', 'WAF-111'] },
  { registry_id: 'WV-029', tier: 'E4', catalog_vector_ids: ['WAF-113', 'WAF-114', 'WAF-115'] },
  { registry_id: 'WV-030', tier: 'E4', catalog_vector_ids: ['WAF-116', 'WAF-117'] },
  { registry_id: 'WV-031', tier: 'E4', catalog_vector_ids: ['WAF-118'] },
  { registry_id: 'WV-032', tier: 'E4', catalog_vector_ids: ['WAF-119', 'WAF-120', 'WAF-121', 'WAF-122', 'WAF-124', 'WAF-125', 'WAF-126'] },
  { registry_id: 'WV-033', tier: 'E4', catalog_vector_ids: ['WAF-128', 'WAF-130', 'WAF-132', 'WAF-134', 'WAF-136'] },
  { registry_id: 'WV-034', tier: 'E4', catalog_vector_ids: ['WAF-138', 'WAF-139', 'WAF-140', 'WAF-141'] },
  { registry_id: 'WV-035', tier: 'E4', catalog_vector_ids: ['WAF-142', 'WAF-143', 'WAF-144', 'WAF-145', 'WAF-146', 'WAF-147', 'WAF-151', 'WAF-153', 'WAF-154', 'WAF-155', 'WAF-157', 'WAF-158', 'WAF-161'] },
  { registry_id: 'WV-036', tier: 'E4', catalog_vector_ids: ['WAF-163', 'WAF-164'] },
  { registry_id: 'WV-037', tier: 'E4', catalog_vector_ids: ['WAF-165', 'WAF-171'] },
  { registry_id: 'WV-038', tier: 'E4', catalog_vector_ids: ['WAF-166', 'WAF-167', 'WAF-168'] },
  { registry_id: 'WV-039', tier: 'E4', catalog_vector_ids: ['WAF-169', 'WAF-170'] },
  { registry_id: 'WV-040', tier: 'E4', catalog_vector_ids: ['WAF-172', 'WAF-173'] },
  { registry_id: 'WV-041', tier: 'E4', catalog_vector_ids: ['WAF-174'] },
  { registry_id: 'WV-042', tier: 'E4', catalog_vector_ids: ['WAF-175', 'WAF-176'] },
]);
