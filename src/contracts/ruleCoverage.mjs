/**
 * WAF and NFW rule-coverage categories: what AstraNull can conclude per rule family.
 * Assurance is derived from the live catalog. Only kinds on VERDICT_CAPABLE_PROBE_KINDS
 * (or SEMANTIC_SAFE_PROBE_KINDS when that list is absent) are verdict-capable; unknown kinds are observation.
 */
import { CHECK_CATALOG, additionalInputRefusal, getCheckById } from './checks.mjs';
import * as probeEvidenceTiers from '../lib/probeEvidenceTiers.mjs';

export const RULE_COVERAGE_ASSURANCE = Object.freeze([
  'verdict',
  'violation_only',
  'partial',
  'observation',
  'declaration',
  'soc_only',
  'missing',
  'not_assessable',
  'out_of_scope',
]);

function capitalizeReason(value) {
  if (typeof value !== 'string' || !value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}

export const CUSTOM_CANARY_ONLY_REASON = "Custom canary rule only — proves a rule written for AstraNull's inert token, not the managed attack-class rule";
export const NEVER_RUNNABLE_REASON = 'No runnable probe: the only probe check cannot run (no port or declaration source), so nothing is assessed';
const TWO_PERSPECTIVE_ENV = Object.freeze({
  ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([{ id: 'coverage-a', label: 'a' }, { id: 'coverage-b', label: 'b' }]),
});

const ASSURANCE_RANK = Object.freeze(Object.fromEntries(RULE_COVERAGE_ASSURANCE.map((id, index) => [id, RULE_COVERAGE_ASSURANCE.length - index])));

function verdictCapableKindSet() {
  if (Array.isArray(probeEvidenceTiers.VERDICT_CAPABLE_PROBE_KINDS)) {
    return new Set(probeEvidenceTiers.VERDICT_CAPABLE_PROBE_KINDS);
  }
  const observation = new Set(probeEvidenceTiers.OBSERVATION_ONLY_PROBE_KINDS ?? []);
  const semantic = probeEvidenceTiers.SEMANTIC_SAFE_PROBE_KINDS ?? [];
  return new Set([...semantic].filter((kind) => !observation.has(kind)));
}

function isCustomCanaryCheck(check) {
  return check?.probe_profile?.kind === 'waf_class_marker_probe'
    && (check.probe_profile.assurance_scope === 'custom_canary_rule' || check.rule_family === 'custom_canary');
}

/** A probe check that the catalog itself refuses for every target (no port, no declaration source). */
function neverRunnable(check) {
  if (!check?.probe_profile || check.probe_profile.kind === 'metadata_marker') return false;
  if (check.mechanism_supported === false) return true;
  const refusal = additionalInputRefusal(check, TWO_PERSPECTIVE_ENV, { deferTargetRequirements: true });
  return Boolean(refusal);
}

export function checkAssuranceReason(check) {
  if (!check) return 'Check not in catalog';
  if (neverRunnable(check)) return NEVER_RUNNABLE_REASON;
  if ((check.runnable_requires ?? []).includes('two_perspectives')) {
    return 'Needs at least two registered probe perspectives.';
  }
  if (isCustomCanaryCheck(check)) return CUSTOM_CANARY_ONLY_REASON;
  return null;
}

function isNfwViolationOnly(check, kind, observation) {
  if (!observation.has(kind)) return false;
  const family = String(check.vector_family ?? '');
  return String(check.check_id).startsWith('nfw.')
    || family === 'l3_l4'
    || family === 'reflection'
    || family === 'amplification'
    || (family === 'origin' && kind === 'host_sni_bypass');
}

export function checkCatalogAssurance(check) {
  if (!check) return 'missing';
  if (check.safety_class === 'soc_gated' || check.risk_class === 'soc_gated' || !check.probe_profile) return 'soc_only';
  const kind = check.probe_profile.kind;
  if (kind === 'metadata_marker') return 'declaration';
  if (neverRunnable(check)) return 'not_assessable';
  const observation = new Set(probeEvidenceTiers.OBSERVATION_ONLY_PROBE_KINDS ?? []);
  if (isNfwViolationOnly(check, kind, observation)) return 'violation_only';
  if (isCustomCanaryCheck(check)) return 'partial';
  if (verdictCapableKindSet().has(kind)) return 'verdict';
  return 'observation';
}

function bestAssurance(values) {
  let best = 'missing';
  for (const value of values) {
    if ((ASSURANCE_RANK[value] ?? 0) > (ASSURANCE_RANK[best] ?? 0)) best = value;
  }
  return best;
}

export const WAF_RULE_CATEGORIES = Object.freeze([
  {
    id: 'custom_canary',
    layer: 'waf',
    name: 'Custom canary rules',
    description: 'Proves a rule you wrote for an AstraNull inert token fires on the tested path.',
    check_ids: [
      'waf.http_method_policy_marker.safe',
      'waf.request_smuggling_marker.safe',
      'waf.crlf_injection_marker.safe',
      'waf.open_redirect_marker.safe',
      'waf.nosql_injection_marker.safe',
      'waf.xpath_injection_marker.safe',
      'waf.jndi_ldap_marker.safe',
      'waf.csv_formula_marker.safe',
      'waf.prototype_pollution_marker.safe',
      'waf.deserialization_marker.safe',
      'waf.ssrf_marker.safe',
      'waf.xxe_marker.safe',
      'waf.file_upload_marker.safe',
      'waf.jwt_tamper_marker.safe',
      'waf.ssti_marker.safe',
      'waf.scanner_signature_marker.safe',
    ],
  },
  {
    id: 'sqli',
    layer: 'waf',
    name: 'SQL injection',
    description: 'Managed SQL injection marker plus encoding-evasion checks. Real payloads are run only by the AstraNull SOC.',
    check_ids: [
      'waf.sqli_managed_marker.safe',
      'waf.evasion_double_url.safe',
      'waf.evasion_mixed_url.safe',
      'waf.evasion_case_fold.safe',
      'waf.offensive_sqli.soc',
    ],
  },
  {
    id: 'xss',
    layer: 'waf',
    name: 'Cross-site scripting',
    description: 'Managed cross-site scripting marker plus evasion variants. Real payloads are run only by the AstraNull SOC.',
    check_ids: ['waf.xss_managed_marker.safe', 'waf.offensive_xss.soc'],
  },
  {
    id: 'rce',
    layer: 'waf',
    name: 'RCE and command injection',
    description: 'SOC-run checks only, with results entered by the operator.',
    check_ids: ['waf.offensive_rce.soc', 'waf.offensive_command_injection.soc'],
  },
  {
    id: 'path_traversal',
    layer: 'waf',
    name: 'Path traversal and LFI',
    description: 'Managed path traversal marker. Real payloads are run only by the AstraNull SOC.',
    check_ids: ['waf.path_traversal_managed_marker.safe', 'waf.offensive_path_traversal.soc'],
  },
  {
    id: 'ssti',
    layer: 'waf',
    name: 'Template injection (SSTI)',
    description: 'Inert canary token only. Real template injection payloads are run only by the AstraNull SOC.',
    check_ids: ['waf.ssti_marker.safe', 'waf.offensive_ssti.soc'],
  },
  {
    id: 'rfi',
    layer: 'waf',
    name: 'Remote file inclusion',
    description: 'Remote inclusion tests are not self-serve. They are covered by the combined SOC-run suite.',
    check_ids: ['waf.offensive_combined.soc'],
  },
  {
    id: 'ssrf_xxe_jndi',
    layer: 'waf',
    name: 'SSRF, XXE, JNDI, LDAP',
    description: 'Inert canary tokens only. The XXE test sends no XML body and the JNDI token holds no lookup expression.',
    check_ids: ['waf.ssrf_marker.safe', 'waf.xxe_marker.safe', 'waf.jndi_ldap_marker.safe', 'waf.offensive_ldap_injection.soc'],
  },
  {
    id: 'deserialization',
    layer: 'waf',
    name: 'Deserialization',
    description: 'Inert canary token shaped like a serialized Java object header only.',
    check_ids: ['waf.deserialization_marker.safe'],
  },
  {
    id: 'request_smuggling',
    layer: 'waf',
    name: 'Request smuggling and protocol violations',
    description: 'An inert string in the query only. No conflicting length or chunked framing is ever sent.',
    check_ids: ['waf.request_smuggling_marker.safe'],
  },
  {
    id: 'http_method_policy',
    layer: 'waf',
    name: 'HTTP method policy',
    description: 'Sends TRACE and an unusual method with no body and checks the edge refuses them. The method marker check is a custom canary sent with GET.',
    check_ids: ['waf.http_method_policy_enforced.safe', 'waf.http_method_policy_marker.safe', 'l7.http_method_restriction.safe'],
  },
  {
    id: 'file_upload',
    layer: 'waf',
    name: 'File upload',
    description: 'Filename canary sent with GET, plus a SOC-run upload body marker.',
    check_ids: ['waf.file_upload_marker.safe', 'waf.body_multipart_marker.soc'],
  },
  {
    id: 'request_body',
    layer: 'waf',
    name: 'Request body inspection (JSON, XML, form)',
    description: 'Body tests run only by the AstraNull SOC against your declared canary endpoint. Self-serve checks never send a request body.',
    check_ids: ['waf.body_json_marker.soc', 'waf.body_form_marker.soc', 'waf.body_multipart_marker.soc'],
    required_declarations: ['canary_sink'],
  },
  {
    id: 'inspection_limits',
    layer: 'waf',
    name: 'Inspection limits and oversize bodies',
    description: 'SOC-run padded body tests (8, 16, 64 and 128 KB) against your declared canary endpoint.',
    check_ids: ['waf.body_inspection_limit.soc'],
    required_declarations: ['canary_sink'],
  },
  {
    id: 'encoding_evasion',
    layer: 'waf',
    name: 'Encoding evasion',
    description: 'Double URL encoding, mixed URL encoding and case folding, plus other encoding variants.',
    check_ids: [
      'waf.evasion_double_url.safe',
      'waf.evasion_mixed_url.safe',
      'waf.evasion_case_fold.safe',
      'waf.evasion_homoglyph.safe',
      'waf.evasion_overlong_utf8.safe',
    ],
  },
  {
    id: 'rate_limiting',
    layer: 'waf',
    name: 'Rate limiting',
    description: 'Uses a low-threshold canary route you declare. Without one, request sequences are recorded as observations only.',
    check_ids: ['waf.rate_limit_canary.validation', 'waf.low_rate_limit.safe', 'l7.low_rate_rate_limit.safe'],
    required_declarations: ['waf.rate_limit_canary'],
  },
  {
    id: 'bot_management',
    layer: 'waf',
    name: 'Bot management',
    description: 'Records bot challenges as observations only.',
    check_ids: ['l7.bot_challenge_marker.safe'],
  },
  {
    id: 'credential_stuffing',
    layer: 'waf',
    name: 'Credential stuffing and account takeover',
    description: 'Records login abuse handling as an observation only.',
    check_ids: ['l7.login_abuse_flow.safe'],
  },
  {
    id: 'graphql_api',
    layer: 'waf',
    name: 'GraphQL and API schema',
    description: 'GraphQL checks record observations only. There is no schema validation test.',
    check_ids: ['l7.graphql_complexity.safe', 'l7.api_surface_scan.safe'],
  },
  {
    id: 'cve_virtual_patching',
    layer: 'waf',
    name: 'CVE virtual patching',
    description: 'Known-vulnerability tests are not self-serve. They are covered by SOC-run suites.',
    check_ids: ['waf.offensive_combined.soc', 'waf.offensive_rce.soc'],
  },
  {
    id: 'scanner_detection',
    layer: 'waf',
    name: 'Scanner detection and session fixation',
    description: 'Scanner user-agent canary. There is no session fixation check.',
    check_ids: ['waf.scanner_signature_marker.safe'],
  },
  {
    id: 'response_dlp',
    layer: 'waf',
    name: 'Response inspection and data-loss prevention',
    description: 'SOC-run response data-loss canary against an endpoint you deploy and declare.',
    check_ids: ['waf.response_dlp_canary.soc'],
    required_declarations: ['canary_sink'],
  },
]);

export const NFW_RULE_CATEGORIES = Object.freeze([
  {
    id: 'inbound_tcp_deny',
    layer: 'nfw',
    name: 'Inbound TCP allow and deny',
    description: 'Can only find violations: a declared deny that still completes a TCP handshake from a non-CDN address is exposed. Outside-in evidence can never prove the port is protected.',
    check_ids: ['nfw.declared_deny_tcp.safe', 'l3.forbidden_tcp_port.safe', 'l3.basic_deny_rule.safe'],
    required_declarations: ['network_policy'],
    forced_assurance: 'violation_only',
  },
  {
    id: 'inbound_udp_deny',
    layer: 'nfw',
    name: 'Inbound UDP allow and deny',
    description: 'Can only find violations: a declared deny that still returns a genuine service reply is exposed. Silence is recorded as an observation only.',
    check_ids: ['nfw.declared_deny_udp.safe', 'l3.forbidden_udp_port.safe'],
    required_declarations: ['network_policy'],
    forced_assurance: 'violation_only',
  },
  {
    id: 'management_ports',
    layer: 'nfw',
    name: 'Management ports (SSH, RDP, databases)',
    description: 'Small bounded scan of common management and database ports. A finding needs a port you declared as denied.',
    check_ids: ['nfw.management_port_exposure.safe', 'l3.firewall_exposure_scan.safe'],
    forced_assurance: 'violation_only',
  },
  {
    id: 'origin_lockdown',
    layer: 'nfw',
    name: 'Origin lockdown to CDN ranges',
    description: 'One request to your declared origin address using your hostname. Exposed when the origin answers directly, outside the CDN, while you declared it locked down.',
    check_ids: ['nfw.origin_lockdown.safe', 'origin.direct_reachability.safe'],
    required_declarations: ['origin.lockdown_expected', 'origin_binding'],
    forced_assurance: 'violation_only',
  },
  {
    id: 'reflection_amplification',
    layer: 'nfw',
    name: 'Reflection and amplification exposure',
    description: 'Single small UDP requests for common reflector services. A genuine service reply is a finding; silence is recorded as an observation only.',
    check_ids: [
      'reflect.mdns_netbios_wsdiscovery_exposure.safe',
      'reflect.dtls_sip_rdp_tftp_exposure.safe',
      'dns.amplification_exposure.safe',
    ],
  },
  {
    id: 'icmp_policy',
    layer: 'nfw',
    name: 'ICMP policy',
    description: 'AstraNull sends no ICMP probes. Flood readiness here is a customer declaration and does not test ICMP allow or deny rules.',
    check_ids: ['l3.icmp_flood.readiness'],
    not_assessable_reason: 'AstraNull sends no ICMP probes, and outside-in TCP and UDP tests cannot show whether ICMP is allowed or denied.',
  },
  {
    id: 'ip_fragments',
    layer: 'nfw',
    name: 'IP fragments',
    description: 'Fragmentation and teardrop handling are customer declarations.',
    check_ids: ['l3.fragmentation_flood.readiness'],
  },
  {
    id: 'stateful_inspection',
    layer: 'nfw',
    name: 'Stateful inspection (out-of-state ACK, RST)',
    description: 'Customer declarations only. The flag-anomaly check needs a port and still sends only normal TCP handshakes.',
    check_ids: ['l3.out_of_state_tcp.readiness', 'l3.tcp_flag_anomaly.readiness'],
    not_assessable_reason: 'The only probe check can never run an out-of-state test: the safe TCP connect sends normal handshakes only, never out-of-state or flag-anomaly segments. Out-of-state handling stays a customer declaration.',
  },
  {
    id: 'syn_flood',
    layer: 'nfw',
    name: 'SYN flood protection',
    description: 'Declarations plus a SOC dry-run.',
    check_ids: ['l3.syn_flood.readiness'],
  },
  {
    id: 'connection_limits',
    layer: 'nfw',
    name: 'Per-source connection and rate limits',
    description: 'Opens at most 12 connections from one source to test a declared per-source connection limit. Needs a connection limit declaration.',
    check_ids: ['nfw.connection_limit.safe', 'l3.tcp_connection_flood.readiness'],
    required_declarations: ['connection_limits'],
    forced_assurance: 'violation_only',
  },
  {
    id: 'ipv6_parity',
    layer: 'nfw',
    name: 'IPv6 parity with IPv4',
    description: 'IPv4 and IPv6 addresses are tested separately. A finding needs a declared deny that one address family breaks.',
    check_ids: ['nfw.ipv6_parity.safe', 'l3.ipv6_reachability.safe'],
    forced_assurance: 'violation_only',
  },
  {
    id: 'allowlists_geo',
    layer: 'nfw',
    name: 'Allowlists and geo-blocking',
    description: 'Needs at least two registered source perspectives with published egress IPs.',
    check_ids: ['nfw.perspective_allowlist.safe'],
    required_declarations: ['perspectives'],
    forced_assurance: 'violation_only',
  },
  {
    id: 'tunnels',
    layer: 'nfw',
    name: 'GRE, ESP, IPsec, SCTP',
    description: 'Declarations only.',
    check_ids: ['l3.gre_esp_flood.readiness', 'l3.sctp_exposure.readiness', 'l3.ike_ipsec_negotiation.readiness'],
  },
  {
    id: 'anti_spoofing',
    layer: 'nfw',
    name: 'Anti-spoofing (BCP38)',
    description: 'A customer declaration. It cannot be tested live from outside your network.',
    check_ids: [],
    not_assessable_reason: 'Anti-spoofing cannot be proven from an outside-in vantage; BCP38 is a declaration.',
  },
  {
    id: 'volumetric',
    layer: 'nfw',
    name: 'Volumetric, carpet-bombing, pulse-wave',
    description: 'High-scale tests are requested from and run only by the AstraNull SOC. High-scale execution is disabled on AWS.',
    check_ids: ['high_scale.volumetric.request_only', 'high_scale.multi_vector.request_only'],
  },
  {
    id: 'egress_filtering',
    layer: 'nfw',
    name: 'Egress filtering',
    description: 'Needs a vantage point inside the network.',
    check_ids: [],
    out_of_scope_reason: 'Egress filtering needs a vantage point inside the network, which the outside-in model rules out.',
  },
]);

export const RULE_COVERAGE_CATEGORIES = Object.freeze([...WAF_RULE_CATEGORIES, ...NFW_RULE_CATEGORIES]);

export const RFI_CVE_MISSING_REASON = 'Not tested. Remote-file-inclusion and CVE exploit markers could trigger work on a vulnerable server, so AstraNull does not send them. Ask SOC for a manual assessment.';

function projectCategory(category) {
  const checks = (category.check_ids ?? []).map((id) => {
    const check = getCheckById(id);
    return {
      check_id: id,
      present: Boolean(check),
      name: check?.name ?? null,
      probe_kind: check?.probe_profile?.kind ?? null,
      safety_class: check?.safety_class ?? null,
      assurance: check ? checkCatalogAssurance(check) : 'missing',
      assurance_reason: checkAssuranceReason(check),
      required_declarations: check?.required_customer_setup ?? [],
    };
  });
  const runnableForced = category.forced_assurance
    && checks.some((row) => row.assurance === category.forced_assurance || row.assurance === 'verdict');
  let assurance = category.out_of_scope_reason
    ? 'out_of_scope'
    : category.not_assessable_reason
      ? 'not_assessable'
      : runnableForced
        ? category.forced_assurance
        : bestAssurance(checks.map((row) => row.assurance));

  if (category.id === 'rfi' || category.id === 'cve_virtual_patching') assurance = 'missing';
  const perspectiveReason = checks.some((row) => (row.assurance_reason ?? '').includes('two registered probe perspectives'))
    ? 'Needs at least two registered probe perspectives.'
    : null;
  const reason = (category.id === 'rfi' || category.id === 'cve_virtual_patching')
    ? RFI_CVE_MISSING_REASON
    : (category.out_of_scope_reason ?? category.not_assessable_reason
      ?? perspectiveReason
      ?? (assurance === 'partial' ? CUSTOM_CANARY_ONLY_REASON : null));
  return {
    id: category.id,
    layer: category.layer,
    name: category.name,
    description: category.description,
    check_ids: [...(category.check_ids ?? [])],
    probe_kinds: [...new Set(checks.map((row) => row.probe_kind).filter(Boolean))],
    assurance,
    out_of_scope_reason: category.out_of_scope_reason ?? null,
    not_assessable_reason: category.not_assessable_reason ?? null,
    assurance_reason: capitalizeReason(reason),
    required_declarations: category.required_declarations ?? [],
    checks,
  };
}

export function catalogRuleCoverage() {
  const verdict_capable_from = Array.isArray(probeEvidenceTiers.VERDICT_CAPABLE_PROBE_KINDS)
    ? 'VERDICT_CAPABLE_PROBE_KINDS'
    : 'observation_only_complement';
  return {
    version: 'rule-coverage.v1',
    verdict_capable_from,
    catalog_check_count: CHECK_CATALOG.length,
    categories: RULE_COVERAGE_CATEGORIES.map(projectCategory),
  };
}
