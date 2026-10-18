import {
  OBSERVATION_ONLY_PROBE_KINDS,
  isObservationOnlyProbeKind,
  isVerdictCapableProbeKind,
} from '../lib/probeEvidenceTiers.mjs';
import { verdictSupportsReadiness } from '../lib/readinessVerdicts.mjs';
import { declaredNetworkPolicyFor } from '../contracts/controlDeclarations.mjs';
import { inconclusiveReason } from '../lib/inconclusiveReasons.mjs';
import { originObservationOf, WAF_GRADING_VERSION } from '../lib/externalObservationOutcomes.mjs';
import { markerComparisonComplete } from '../lib/vectorProbes/wafProbeSupport.mjs';
import { providerDisplayName } from '../lib/edgeDetectionPresenter.mjs';
import { listProbePerspectives } from '../lib/probePerspectiveRegistry.mjs';

export {
  OBSERVATION_ONLY_PROBE_KINDS,
  isObservationOnlyProbeKind,
  isVerdictCapableProbeKind,
  verdictSupportsReadiness,
};

/**
 * Correlation truth table — evidence-backed verdicts (metadata-only developer validation).
 */

export function probeEventHasProbeIo(probeEvent) {
  const metadata = probeEvent?.metadata ?? probeEvent?.metadata_json;
  const probeRequestsSent = metadata?.safety_attestation?.probe_requests_sent;
  return Number.isSafeInteger(probeRequestsSent) && probeRequestsSent > 0;
}

/** True when a check's verdict depends on nothing but its signed probe result. */
export function probeResultCompletesEvidence(check) {
  const required = check?.evidence_required;
  return Array.isArray(required) && required.length === 1 && required[0] === 'probe_result';
}

const EDGE_SOURCE_LABELS = Object.freeze({
  asn_lookup: 'address range',
  address_range: 'address range',
  cname: 'DNS CNAME',
  cname_suffix: 'DNS CNAME',
  response_header: 'response headers',
  response_fingerprint: 'response fingerprint',
  corroborated_generic_behavior: 'response behavior',
});

function edgeLayerPhrase(layer) {
  const name = String(providerDisplayName(layer) ?? '').slice(0, 64);
  const family = String(layer?.family ?? '').toUpperCase().slice(0, 16);
  if (!name || !family) return null;
  const sources = [...new Set((Array.isArray(layer.sources) ? layer.sources : [])
    .map((source) => EDGE_SOURCE_LABELS[source] ?? null).filter(Boolean))];
  const from = sources.length > 1 ? `${sources.slice(0, -1).join(', ')} and ${sources.at(-1)}` : sources[0];
  return `${name} (${family}${from ? `, from ${from}` : ''})`;
}

function fingerprintObservationExplanation(externalResult, metadata = {}) {
  const edge = metadata?.edge_signature ?? {};
  const layers = (Array.isArray(edge.layers) ? edge.layers : []).slice(0, 6);
  const observed = layers.map(edgeLayerPhrase).filter(Boolean);
  const httpCompleted = Number.isInteger(metadata?.baseline_status_code) && metadata.baseline_status_code > 0;
  if (['timeout', 'error', 'not_run'].includes(externalResult) || !httpCompleted) {
    const failure = externalResult === 'timeout' ? 'timed out' : 'did not complete';
    const errorClass = String(metadata?.error_class ?? '').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 64);
    const reason = errorClass && errorClass !== 'Error' ? ` (${errorClass})` : '';
    return `The ordinary GET ${failure}${reason}, so HTTP fingerprints were not evaluated. `
      + (observed.length
        ? `DNS and address signals show ${observed.join(', ')}. `
        : 'DNS and address signals matched no CDN or WAF provider. ')
      + (edge.waf_present === true ? 'Blocking remains unverified.' : 'WAF presence and blocking remain unverified.');
  }
  const status = ` on an HTTP ${metadata.baseline_status_code} response`;
  const providerText = observed.length
    ? `Observed ${observed.join(', ')}${status}.`
    : `No CDN or WAF provider was identified from HTTP, DNS or address signals${status}.`;
  const wafText = edge.waf_present === true
    ? ' Provider detection does not establish that requests are blocked; run the WAF marker check to test enforcement.'
    : ' No WAF was identified: one ordinary GET cannot establish WAF presence or blocking; run the WAF marker check to test enforcement.';
  return `${providerText}${wafText}`;
}

function correlateObservationOnlyVerdict(probeKind, probeMetadata, externalResult) {
  const noIo = probeKind === 'metadata_marker';
  return {
    verdict: 'inconclusive',
    confidence: 'external_only',
    explanation: noIo
      ? 'Metadata-only check performed no network I/O and cannot establish readiness or exposure.'
      : probeKind === 'waf_fingerprint_observation'
        ? fingerprintObservationExplanation(externalResult, probeMetadata)
        : `${probeKind} recorded transport or liveness metadata only; it did not establish this check's verdict logic.`,
    createsFinding: false,
  };
}

function correlateProbeFailure(externalResult, probeKind, metadata) {
  if (!['error', 'not_run', 'timeout'].includes(externalResult)) return null;
  const reason = inconclusiveReason({ externalResult, probeKind, metadata });
  return {
    verdict: 'inconclusive',
    confidence: 'external_only',
    explanation: metadata?.missing_message || reason.explanation,
    explanation_reason: reason.reason,
    createsFinding: false,
  };
}

const EVIDENCE_GAP_EXPLANATIONS = Object.freeze({
  misdirected_request: 'The direct-origin request received HTTP 421 (misdirected request). That reflects how the probe connection was routed, not a control decision, so the result is a coverage gap and is ignored for verdicts. Retest on a fresh connection whose SNI matches the Host.',
  probe_path_error: 'The direct-origin request received HTTP 407, meaning a proxy sits between the probe and the target. This is a probe-path problem, so the result is a coverage gap and is ignored for verdicts.',
  not_applicable: 'A CDN or WAF edge answered the direct-origin request, so it is not an origin observation. The result is ignored for verdicts; declare a non-edge origin address to test origin lockdown.',
});

const MARKER_GAP_EXPLANATIONS = Object.freeze({
  authentication_gate_precedes_inspection: 'The marker request received HTTP 401. An authentication gate answered before any inspection could be observed, so a WAF block cannot be told apart from the login challenge. The result is ignored for verdicts.',
  unattributed_denial: 'The marker request was denied without a vendor or customer-declared block signature. A block is suspected but not attributed, so it counts neither as enforcement nor as a gap.',
  baseline_not_available: 'The marker request was denied without a vendor or customer-declared block signature and no permitted baseline was captured, so the result is ignored for verdicts.',
  misdirected_request: 'The marker request received HTTP 421 (misdirected request), a connection-routing artifact. The result is ignored for verdicts.',
  probe_path_error: 'The marker request received HTTP 407 from a proxy on the probe path. The result is ignored for verdicts.',
  error_not_attributable: 'The marker request received a server error. A 5xx cannot be attributed to a control and may be an application failure, so the result is ignored for verdicts.',
  block_suspected_unverified_signature: 'The marker request was denied with only generic proxy or CDN headers from a vendor whose block signature is not yet live-verified. A block is suspected but not proven, so the result is ignored for verdicts.',
});

function vendorText(value) {
  return String(value ?? '').replace(/[^A-Za-z0-9 ._-]/g, '').slice(0, 32);
}

function evidenceGapVerdict(explanation) {
  return { verdict: 'inconclusive', confidence: 'external_only', explanation, createsFinding: false };
}

/** G4: results without usable evidence are coverage gaps with a reason code, never pass, fail, or partial. */
function correlateEvidenceGap(probeKind, probeMetadata) {
  if (probeKind === 'host_sni_bypass') {
    const outcome = originObservationOf(probeMetadata)?.outcome;
    return EVIDENCE_GAP_EXPLANATIONS[outcome] ? evidenceGapVerdict(EVIDENCE_GAP_EXPLANATIONS[outcome]) : null;
  }
  const reason = probeMetadata?.inconclusive_reason;
  if (typeof reason !== 'string' || !MARKER_GAP_EXPLANATIONS[reason]) return null;
  const vendor = reason === 'block_suspected_unverified_signature' ? vendorText(probeMetadata?.matched_vendor) : '';
  return evidenceGapVerdict(vendor ? `${MARKER_GAP_EXPLANATIONS[reason]} Suspected vendor: ${vendor}.` : MARKER_GAP_EXPLANATIONS[reason]);
}

const NFW_PROBE_KINDS = new Set([
  'tcp_connect', 'udp_probe', 'port_scan_bounded', 'reflection_service_probe', 'connection_limit_probe',
]);
const HIGH_SEVERITY_PORTS = new Set([
  22, 23, 3389, 445, 139, 3306, 1433, 1521, 5432, 6379, 27017, 9200, 2375, 2379, 6443, 10250, 5900, 5985, 389, 636, 2049,
]);
const MANAGED_TRANSFORM_FAMILIES = new Set(['sqli', 'xss', 'path_traversal']);
const MARKER_CLASS_LABELS = Object.freeze({
  sqli: 'SQL injection', xss: 'cross-site scripting', path_traversal: 'path traversal', rce: 'remote code execution',
  command_injection: 'command injection', ldap_injection: 'LDAP injection', ssti: 'server-side template injection',
  ssrf: 'server-side request forgery', xxe: 'XML external entity', jndi: 'JNDI/Log4Shell lookup', log4shell: 'JNDI/Log4Shell lookup',
  scanner_signature: 'vulnerability-scanner signature', scanner_user_agent: 'vulnerability-scanner user-agent', nosqli: 'NoSQL injection', jwt: 'JWT tampering',
  request_smuggling: 'HTTP request smuggling', smuggling: 'HTTP request smuggling', lfi: 'local file inclusion', rfi: 'remote file inclusion',
});

function markerClassLabel(markerClass) {
  if (typeof markerClass !== 'string' || !markerClass.trim()) return null;
  const key = markerClass.trim().toLowerCase();
  return MARKER_CLASS_LABELS[key] ?? key.replace(/[_-]+/g, ' ');
}
const CHALLENGE_ACTIONS = new Set(['challenge', 'block_or_challenge']);
const FAMILY_KEYS = Object.freeze(['ipv4', 'ipv6']);

function inconclusiveVerdict(explanation) {
  return { verdict: 'inconclusive', confidence: 'external_only', explanation, createsFinding: false };
}

function nfwPortSeverity(port) {
  return HIGH_SEVERITY_PORTS.has(Number(port)) ? 'high' : 'medium';
}

function perspectiveLabel(metadata) {
  const perspective = metadata?.source_perspective;
  if (perspective && typeof perspective === 'object') {
    return perspective.label || perspective.id || 'external probe';
  }
  if (typeof perspective === 'string' && perspective.trim()) return perspective.trim();
  return 'external probe';
}

function addressFamilyName(value, fallback = 'ipv4') {
  if (value === 6 || value === '6' || value === 'ipv6') return 'ipv6';
  if (value === 4 || value === '4' || value === 'ipv4') return 'ipv4';
  return fallback;
}

function familyBucket(metadata, key) {
  const families = metadata?.families;
  return families && typeof families === 'object' ? families[key] ?? null : null;
}

function tcpOpen(row) {
  return row?.tcp_outcome === 'handshake';
}

function udpValidated(row) {
  return row?.udp_outcome === 'validated_reply';
}

function nfwExposed({ port, protocol, family, metadata, extra = '' }) {
  const perspective = perspectiveLabel(metadata);
  return {
    verdict: 'exposed',
    confidence: 'external_only',
    createsFinding: true,
    severity: nfwPortSeverity(port),
    explanation: `Declared deny for ${protocol}/${port} (${family}) from ${perspective} was violated; denial cannot be proven from outside.${extra}`,
  };
}

function samplesDisagree(metadata, row = null) {
  const allowed = ['single', 'agree', 'disagree'];
  if (allowed.includes(row?.sample_agreement)) return row.sample_agreement === 'disagree';
  const fams = metadata?.families && typeof metadata.families === 'object' ? Object.values(metadata.families) : [];
  if (fams.length && fams.every((f) => allowed.includes(f?.sample_agreement))) {
    return fams.some((f) => f?.sample_agreement === 'disagree');
  }
  return metadata?.sample_agreement === 'disagree' || row?.sample_agreement === 'disagree';
}

function peerIsCdn(metadata, row = null) {
  if (row?.peer_is_cdn === true || metadata?.peer_is_cdn === true) return true;
  return false;
}

/** Origin lockdown needs both a live declared origin binding and `origin.lockdown_expected`. */
function originBindingDeclared(declarations, originBinding) {
  const bound = Boolean(originBinding && originBinding.status !== 'archived' && originBinding.status !== 'deleted'
    && (originBinding.id || originBinding.protected_target_id || originBinding.origin_target_id));
  return bound && declarations?.origin?.lockdown_expected === true;
}

function isHttp2xx(code) {
  return Number.isInteger(code) && code >= 200 && code < 300;
}

function applicationFingerprintMatched(metadata) {
  const observation = originObservationOf(metadata);
  const raw = metadata?.origin_observation;
  return metadata?.application_bypass_confirmed === true
    || observation?.application_bypass_confirmed === true
    || observation?.outcome === 'application_identity_confirmed'
    || raw?.application_bypass_confirmed === true
    || raw?.outcome === 'application_identity_confirmed';
}

function httpStatusOf(probeMetadata) {
  const observation = originObservationOf(probeMetadata);
  const raw = observation?.status_code
    ?? probeMetadata?.origin_observation?.status_code
    ?? probeMetadata?.status_code;
  return Number.isInteger(raw) ? raw : Number(raw);
}

function correlateOriginLockdownVerdict(probeMetadata, declarations, originBinding) {
  if (!originBindingDeclared(declarations, originBinding)) return null;
  if (peerIsCdn(probeMetadata)) return null;
  if (!isHttp2xx(httpStatusOf(probeMetadata))) return null;
  if (!applicationFingerprintMatched(probeMetadata)) return null;
  return {
    verdict: 'exposed',
    confidence: 'external_only',
    createsFinding: true,
    severity: 'medium',
    explanation: 'Your origin was reachable directly, outside the CDN: the declared origin binding answered as the application for the target hostname (application identity confirmed, not just a TCP handshake) to a non-CDN probe while origin.lockdown_expected is declared.',
  };
}

function familyViolatesDeny(declarations, { protocol, port, familyKey, row }) {
  const rule = declaredNetworkPolicyFor(declarations, { protocol, port, addressFamily: familyKey });
  if (rule?.action !== 'deny') return false;
  if (protocol === 'tcp') return tcpOpen(row);
  if (protocol === 'udp') return udpValidated(row);
  return false;
}

const REFLECTOR_PROTOCOL_LABELS = Object.freeze({
  ssdp: 'SSDP', snmp: 'SNMP', mdns: 'mDNS', netbios: 'NetBIOS', ws: 'WS-Discovery', chargen: 'CharGen',
  coap: 'CoAP', stun: 'STUN', ipmi: 'IPMI', mssql: 'MS-SQL Browser', tftp: 'TFTP', memcached: 'Memcached',
  dtls: 'DTLS', portmap: 'Portmap', ntp: 'NTP', cldap: 'CLDAP', openvpn: 'OpenVPN', jenkins: 'Jenkins discovery',
  rip: 'RIP', sip: 'SIP', rdp: 'RDP', slp: 'SLP', tp240: 'TP-240', l2tp: 'L2TP', natpmp: 'NAT-PMP', ipp: 'IPP',
});

function reflectorProtocolLabel(metadata) {
  const validated = Array.isArray(metadata?.protocol_results)
    ? metadata.protocol_results.find((row) => row?.service_validated === true || row?.udp_outcome === 'validated_reply')
    : null;
  const profile = String(validated?.payload_profile ?? metadata?.payload_profile ?? metadata?.payload_profiles_sent?.[0] ?? '');
  const head = profile.split('_')[0];
  return REFLECTOR_PROTOCOL_LABELS[head] ?? 'UDP';
}

function correlateReflectorExposure(metadata, port) {
  const protocol = reflectorProtocolLabel(metadata);
  return {
    verdict: 'exposed',
    confidence: 'external_only',
    createsFinding: true,
    severity: 'medium',
    explanation: `Open ${protocol} reflector reachable from the internet: a protocol-validated reply came back on udp/${port || metadata?.port} to ${perspectiveLabel(metadata)}. This is direct evidence of an open reflector from the reply itself, independent of any firewall declaration.`,
    metadata: { exposure_basis: 'validated_reflector_reply' },
  };
}

function bothFamiliesSampled(metadata, port) {
  return FAMILY_KEYS.every((key) => {
    const bucket = familyBucket(metadata, key);
    return Array.isArray(bucket?.ports_sampled) ? bucket.ports_sampled.includes(Number(port)) : false;
  });
}

function correlateNfwViolation(probeKind, metadata, declarations) {
  if (probeKind === 'connection_limit_probe') {
    if (samplesDisagree(metadata)) {
      return inconclusiveVerdict('Connection-limit samples disagreed between attempts, so the admitted count cannot be attributed to a per-source limit.');
    }
    if (peerIsCdn(metadata)) {
      return inconclusiveVerdict('The connection-limit peer is a CDN edge address; admitted connections reflect the CDN, not the origin per-source limit.');
    }
    const accepted = Number(metadata?.accepted_count);
    const port = Number(metadata?.port ?? metadata?.target_port);
    const rule = declarations?.connection_limits?.find((row) => row.protocol === 'tcp' && row.port === port);
    const limit = rule?.max_connections_per_source != null ? Number(rule.max_connections_per_source) : null;
    if (!Number.isInteger(limit)) {
      return inconclusiveVerdict('No declared connection limit configured for this target port; limit cannot be verified.');
    }
    if (Number.isInteger(accepted) && accepted > limit) {
      return {
        verdict: 'exposed',
        confidence: 'external_only',
        createsFinding: true,
        severity: 'medium',
        explanation: `Connection-limit canary accepted ${accepted} connections above the declared limit of ${limit} on tcp/${port}; denial cannot be proven from outside.`,
      };
    }
    return null;
  }

  if (samplesDisagree(metadata) || peerIsCdn(metadata)) return null;

  if (probeKind === 'port_scan_bounded') {
    const leaks = [];
    for (const familyKey of FAMILY_KEYS) {
      const bucket = familyBucket(metadata, familyKey);
      const open = Array.isArray(bucket?.open_ports) ? bucket.open_ports : (familyKey === 'ipv4' || !metadata?.families ? metadata.open_ports : []);
      if (!Array.isArray(open)) continue;
      for (const port of open) {
        const rule = declaredNetworkPolicyFor(declarations, { protocol: 'tcp', port, addressFamily: familyKey });
        if (rule?.action === 'deny') leaks.push({ port, family: familyKey });
      }
    }
    if (!metadata?.families && Array.isArray(metadata?.open_ports)) {
      for (const port of metadata.open_ports) {
        const family = addressFamilyName(metadata.address_family);
        const rule = declaredNetworkPolicyFor(declarations, { protocol: 'tcp', port, addressFamily: family });
        if (rule?.action === 'deny' && !leaks.some((row) => row.port === port && row.family === family)) {
          leaks.push({ port, family });
        }
      }
    }
    if (!leaks.length) return null;
    const leakingFamilies = [...new Set(leaks.map((row) => row.family))];
    const primary = leaks.find((row) => HIGH_SEVERITY_PORTS.has(Number(row.port))) ?? leaks[0];
    const others = leaks.filter((row) => row !== primary);
    const parityMismatch = metadata?.parity === 'mismatch' && leakingFamilies.length === 1
      && bothFamiliesSampled(metadata, primary.port);
    const alsoViolated = others.length ? ` Also violated: ${others.map((row) => `tcp/${row.port} (${row.family})`).join(', ')}.` : '';
    return nfwExposed({
      port: primary.port,
      protocol: 'tcp',
      family: primary.family,
      metadata,
      extra: `${parityMismatch ? ` IPv6 parity mismatch: ${primary.family} is the leaking family.` : ''}${alsoViolated}`,
    });
  }

  const protocol = probeKind === 'udp_probe' || metadata?.protocol === 'udp' ? 'udp' : 'tcp';
  const port = Number(metadata?.port ?? metadata?.target_port);
  const topRow = {
    tcp_outcome: metadata?.tcp_outcome,
    udp_outcome: metadata?.udp_outcome,
    sample_agreement: metadata?.sample_agreement,
    peer_is_cdn: metadata?.peer_is_cdn,
  };
  const violating = [];
  for (const familyKey of FAMILY_KEYS) {
    const row = familyBucket(metadata, familyKey);
    if (!row && metadata?.families) continue;
    const sample = row ?? (familyKey === addressFamilyName(metadata.address_family) ? topRow : null);
    if (!sample) continue;
    if (familyViolatesDeny(declarations, { protocol, port, familyKey, row: sample })) {
      if (samplesDisagree(metadata, sample) || peerIsCdn(metadata, sample)) continue;
      violating.push(familyKey);
    }
  }
  if (!metadata?.families) {
    const family = addressFamilyName(metadata.address_family);
    if (familyViolatesDeny(declarations, { protocol, port, familyKey: family, row: topRow })
      && !samplesDisagree(metadata, topRow)
      && !peerIsCdn(metadata, topRow)
      && !violating.includes(family)) {
      violating.push(family);
    }
  }
  if (violating.length) {
    const leaking = violating[0];
    const otherObservedClosed = metadata?.parity === 'mismatch' && violating.length === 1;
    return nfwExposed({
      port,
      protocol,
      family: leaking,
      metadata,
      extra: otherObservedClosed ? ` IPv6 parity mismatch: ${leaking} is the leaking family.` : '',
    });
  }

  if (probeKind === 'reflection_service_probe' && udpValidated(metadata) && metadata?.service_validated !== false) {
    return correlateReflectorExposure(metadata, port);
  }
  return null;
}

function expectedWafAction(declarations) {
  const action = declarations?.waf?.expected_action;
  return typeof action === 'string' ? action : 'block';
}

function placementsOf(metadata) {
  return Array.isArray(metadata?.placements) ? metadata.placements.filter(Boolean) : [];
}

function redirectedOnlyLegs(metadata) {
  const placements = placementsOf(metadata);
  if (!placements.length) return false;
  const redirected = placements.filter((row) => row.outcome === 'redirected' || row.location_changed === true);
  const blocked = placements.filter((row) => row.outcome === 'blocked' || row.blocked === true);
  return redirected.length > 0 && blocked.length === 0 && redirected.length === placements.length;
}

function unenforcedPlacementNames(metadata) {
  return placementsOf(metadata)
    .filter((row) => row.outcome === 'allowed' || row.allowed === true || row.enforcement === 'not_enforced')
    .map((row) => row.placement)
    .filter(Boolean);
}

function correlateChallengeRedirectPenalty(metadata, declarations, externalResult) {
  if (metadata?.source_penalized === true || metadata?.posture_status === 'source_penalized') {
    return inconclusiveVerdict('Trailing benign request was penalized; source-level ban makes later legs untrustworthy, so posture is inconclusive.');
  }
  if (metadata?.posture_status === 'inconclusive') {
    return inconclusiveVerdict('WAF posture is inconclusive; a block or allow conclusion cannot be drawn from this run.');
  }
  if (redirectedOnlyLegs(metadata)) {
    return inconclusiveVerdict('Redirected-only legs cannot satisfy a block expectation; posture is inconclusive.');
  }
  const challenged = metadata?.enforcement === 'challenged'
    || metadata?.posture_status === 'challenged'
    || metadata?.external_result === 'challenged'
    || externalResult === 'challenged';
  if (!challenged) return null;
  const expected = expectedWafAction(declarations);
  if (CHALLENGE_ACTIONS.has(expected)) {
    return {
      verdict: 'protected',
      confidence: 'external_only',
      createsFinding: false,
      explanation: `Observed challenge matches declared WAF expected_action '${expected}'.`,
    };
  }
  return inconclusiveVerdict('A challenge does not satisfy a block expectation.');
}

function correlateClassMarkerVerdict(metadata) {
  const enforcement = metadata?.enforcement;
  const scope = metadata?.assurance_scope;
  const custom = scope === 'custom_canary_rule';
  if (enforcement === 'enforced') {
    return {
      verdict: 'protected',
      confidence: 'external_only',
      createsFinding: false,
      explanation: custom
        ? "Your custom canary rule for AstraNull's marker was enforced on the tested placements."
        : 'Managed-rule marker was enforced on the tested placements.',
    };
  }
  if (enforcement === 'not_enforced') {
    return {
      verdict: 'exposed',
      confidence: 'external_only',
      createsFinding: true,
      severity: custom ? 'low' : 'medium',
      explanation: custom
        ? "Your custom canary rule for AstraNull's marker was not enforced."
        : markerClassLabel(metadata?.marker_class)
          ? `Managed-rule marker for ${markerClassLabel(metadata.marker_class)} was not enforced: the edge let it through to the origin.`
          : 'Managed-rule marker was not enforced.',
    };
  }
  if (enforcement === 'partial') {
    const names = unenforcedPlacementNames(metadata);
    if (placementsOf(metadata).length && !names.length) {
      return inconclusiveVerdict('Partial enforcement without any allowed placement (for example blocked plus challenged legs) is not exposure; posture is inconclusive.');
    }
    const named = names.length ? ` Unenforced placements: ${names.join(', ')}.` : '';
    return {
      verdict: 'exposed',
      confidence: 'external_only',
      createsFinding: true,
      severity: 'low',
      explanation: custom
        ? `Your custom canary rule for AstraNull's marker was only partially enforced.${named}`
        : markerClassLabel(metadata?.marker_class)
          ? `Managed-rule marker for ${markerClassLabel(metadata.marker_class)} was only partially enforced.${named}`
          : `Managed-rule marker was only partially enforced.${named}`,
    };
  }
  return null;
}

function correlateEvasionVerdict(metadata) {
  if (metadata?.reference_not_enforced === true) {
    return inconclusiveVerdict('The plain managed-rule marker was not enforced, so this evasion transform cannot be graded. Run the matching managed-rule marker check first.');
  }
  if (metadata?.normalization_gap === true) {
    const transform = metadata?.evasion_transform ?? metadata?.transform ?? 'transform';
    const family = metadata?.marker_class;
    const medium = MANAGED_TRANSFORM_FAMILIES.has(family);
    return {
      verdict: 'exposed',
      confidence: 'external_only',
      createsFinding: true,
      severity: medium ? 'medium' : 'low',
      explanation: markerClassLabel(family)
        ? `normalization gap for ${transform}: the plain ${markerClassLabel(family)} marker was blocked, but the same marker sent with ${transform} encoding was allowed through.`
        : `normalization gap for ${transform}`,
    };
  }
  return null;
}

function correlateRateLimitCanary(metadata, declarations) {
  const canaryDecl = declarations?.waf?.rate_limit_canary;
  const threshold = Number(canaryDecl?.threshold);
  const requestsSent = Number(metadata?.requests_sent);
  if (!Number.isInteger(threshold) || threshold < 1) return null;
  const rawIndex = metadata?.first_limited_at;
  const limitedIndex = rawIndex == null || rawIndex === '' ? null : Number(rawIndex);
  const hasIndex = Number.isInteger(limitedIndex) && limitedIndex > 0;
  const allowedBefore = metadata?.allowed_before_limit == null ? null : Number(metadata.allowed_before_limit);
  const expectedAction = canaryDecl?.expected_action ?? 'block';
  if (hasIndex && limitedIndex <= threshold) {
    return inconclusiveVerdict(`Rate-limit canary was limited at request ${limitedIndex}, at or before the declared threshold of ${threshold}; the route may always be blocked, so this is not rate-limit evidence (limited_before_threshold).`);
  }
  if (hasIndex && limitedIndex > threshold + 2) {
    return inconclusiveVerdict(`Rate-limit canary was first limited at request ${limitedIndex}, later than the declared threshold plus two; the result is inconclusive.`);
  }
  if (hasIndex) {
    if (metadata?.limited_outcome === 'challenged' && expectedAction !== 'block_or_challenge') {
      return inconclusiveVerdict('Rate-limit canary encountered a challenge response, but expected_action requires a block (limited_by_challenge).');
    }
    if (Number.isInteger(allowedBefore) && allowedBefore < threshold) {
      return inconclusiveVerdict(`Only ${allowedBefore} of the first ${threshold} canary requests were allowed before the limit, so the threshold behaviour is not proven; the result is inconclusive.`);
    }
    return {
      verdict: 'protected',
      confidence: 'external_only',
      createsFinding: false,
      explanation: `Rate-limit canary allowed the first ${threshold} requests and was limited at request ${limitedIndex}, within the declared threshold plus two.`,
    };
  }
  const limitedOutcome = metadata?.limited_outcome;
  if (['blocked', 'challenged', 'rate_limited'].includes(limitedOutcome)) {
    if (limitedOutcome === 'challenged' && expectedAction !== 'block_or_challenge') {
      return inconclusiveVerdict('Rate-limit canary encountered a challenge response, but expected_action requires a block (limited_by_challenge).');
    }
    return inconclusiveVerdict('Rate-limit canary reported a limited response without the request index; the threshold cannot be checked.');
  }
  if (Number.isInteger(requestsSent) && requestsSent > threshold) {
    if (Number.isInteger(allowedBefore) && allowedBefore > threshold) {
      return {
        verdict: 'exposed',
        confidence: 'external_only',
        createsFinding: true,
        severity: 'low',
        explanation: `Rate-limit canary sent ${requestsSent} requests, more than the declared threshold of ${threshold}, and was never limited.`,
      };
    }
    return inconclusiveVerdict(`Rate-limit canary sent ${requestsSent} requests, but did not observe more than ${threshold} allowed requests (unattributed_errors).`);
  }
  return inconclusiveVerdict(`Rate-limit canary sent ${Number.isInteger(requestsSent) ? requestsSent : 'too few'} requests before the window or budget ran out, never exceeding the declared threshold of ${threshold} (window_expired_before_threshold).`);
}

function axfrLeakingNameservers(metadata) {
  const names = Array.isArray(metadata?.nameserver_results)
    ? [...new Set(metadata.nameserver_results.filter((row) => row?.axfr_leak === true && typeof row.nameserver === 'string').map((row) => row.nameserver))]
    : [];
  if (!names.length && metadata?.axfr_leak === true && typeof metadata?.nameserver === 'string' && metadata.nameserver.trim()) names.push(metadata.nameserver.trim());
  return names.length ? ` Nameservers that allowed the transfer: ${names.slice(0, 8).join(', ')}.` : '';
}

function axfrLeaked(metadata, externalResult) {
  if (metadata?.axfr_leak === true) return true;
  if (Array.isArray(metadata?.nameserver_results) && metadata.nameserver_results.some((row) => row?.axfr_leak === true)) return true;
  return false;
}

/** AXFR: exposed on any leaking nameserver; protected only when every nameserver was queried and refused. */
function correlateAxfrVerdict(externalResult, metadata, probeIoObserved) {
  if (externalResult === 'connected' && probeIoObserved === true && axfrLeaked(metadata, externalResult)) {
    return {
      verdict: 'exposed',
      confidence: 'external_only',
      createsFinding: true,
      severity: 'medium',
      explanation: `At least one authoritative nameserver answered a zone transfer (AXFR) request from the internet.${axfrLeakingNameservers(metadata)}`,
    };
  }
  const hasRefusalCoverage =
    metadata?.axfr_refused === true &&
    Number.isSafeInteger(metadata?.nameservers_total) &&
    metadata.nameservers_total > 0 &&
    metadata?.nameservers_queried === metadata.nameservers_total &&
    Array.isArray(metadata?.nameserver_results) &&
    metadata.nameserver_results.length > 0 &&
    (!metadata?.unqueried_nameservers || (Array.isArray(metadata.unqueried_nameservers) && metadata.unqueried_nameservers.length === 0)) &&
    metadata.nameserver_results.every((row) =>
      row?.queried === true && row?.axfr_refused === true && row?.axfr_leak !== true &&
      typeof row?.nameserver === 'string' && row.nameserver.trim().length > 0
    ) &&
    new Set(metadata.nameserver_results.map((row) => row.nameserver.trim())).size === metadata.nameservers_total;

  if (probeIoObserved === true && !['error', 'not_run', 'timeout'].includes(externalResult) && hasRefusalCoverage) {
    return {
      verdict: 'protected',
      confidence: 'external_only',
      createsFinding: false,
      explanation: 'Every authoritative nameserver for the zone was queried and refused the zone transfer.',
    };
  }
  if (metadata?.enforcement === 'partial') {
    return inconclusiveVerdict('Every queried nameserver refused the zone transfer, but the request budget left some nameservers unqueried, so the zone is not proven protected.');
  }
  if (['error', 'not_run', 'timeout'].includes(externalResult)) return null;
  return inconclusiveVerdict('The zone transfer result did not show a refusal from every nameserver or a leak; the result is inconclusive.');
}

function perspectiveIdOf(metadata) {
  const perspective = metadata?.source_perspective;
  if (perspective && typeof perspective === 'object') return perspective.id ?? null;
  if (typeof perspective === 'string' && perspective.trim()) return perspective.trim();
  return null;
}

function correlateMethodPolicyVerdict(probeMetadata) {
  if (probeMetadata?.source_penalized === true) {
    return inconclusiveVerdict('Method-policy source was penalized; the comparison is not a control verdict.');
  }
  if (probeMetadata?.inconclusive_reason === 'not_enforced_by_waf_but_rejected_by_origin') {
    return inconclusiveVerdict('not_enforced_by_waf_but_rejected_by_origin');
  }
  if (probeMetadata?.enforcement === 'enforced') {
    return {
      verdict: 'protected',
      confidence: 'external_only',
      createsFinding: false,
      explanation: 'TRACE and a nonstandard token method (sent with no body) were refused at the edge with a control-specific denial while the permitted GET baseline stayed healthy.',
    };
  }
  if (probeMetadata?.enforcement === 'not_enforced') {
    return {
      verdict: 'exposed',
      confidence: 'external_only',
      createsFinding: true,
      severity: 'low',
      explanation: 'TRACE or a nonstandard token method (sent with no body) was allowed through the edge.',
    };
  }
  return inconclusiveVerdict('HTTP method policy did not produce a complete enforcement comparison.');
}

function correlatePerspectiveAllowlist(probeMetadata, declarations, externalResult, env) {
  const perspectives = listProbePerspectives(env);
  if (perspectives.length < 2) {
    return inconclusiveVerdict('This check needs at least two registered probe perspectives.');
  }
  const denied = Array.isArray(declarations?.perspectives?.denied_perspective_ids)
    ? declarations.perspectives.denied_perspective_ids.filter(Boolean)
    : [];
  const claimedId = typeof probeMetadata?.claimed_perspective_id === 'string' && probeMetadata.claimed_perspective_id
    ? probeMetadata.claimed_perspective_id
    : null;
  const sourceId = claimedId ?? perspectiveIdOf(probeMetadata);
  const handshake = probeMetadata?.tcp_outcome === 'handshake'
    || externalResult === 'connected';
  if (denied.length && handshake && sourceId && denied.includes(sourceId)) {
    if (probeMetadata?.perspective_authenticated !== true) {
      return inconclusiveVerdict(`A handshake was observed from perspective ${sourceId}, but that perspective was not authenticated with its own worker secret, so the source cannot be attributed. Configure a per-perspective worker secret and re-run.`);
    }
    return {
      verdict: 'exposed',
      confidence: 'external_only',
      createsFinding: true,
      severity: 'medium',
      explanation: `Allowlist not enforced for perspective ${sourceId}`,
    };
  }
  return inconclusiveVerdict('Perspective allowlist did not observe a handshake from a denied perspective.');
}

const PORT_RESULT_FIELDS = Object.freeze([
  'protocol', 'port', 'address', 'address_family', 'tcp_outcome', 'udp_outcome', 'icmp',
  'service_validated', 'peer_is_cdn', 'families', 'parity', 'samples', 'sample_agreement',
]);

/** Per-port deny verdicts for a multi-port deny probe; null when the result is single-port. */
function nfwPortResults(probeKind, metadata, declarations) {
  if (!['tcp_connect', 'udp_probe'].includes(probeKind)) return null;
  const rows = Array.isArray(metadata?.port_results) ? metadata.port_results.filter((row) => row && typeof row === 'object') : [];
  if (!rows.length) return null;
  const { port_results: _ignored, ...base } = metadata;
  return rows.map((row) => {
    const single = { ...base, target_port: row.port };
    for (const key of PORT_RESULT_FIELDS) single[key] = row[key];
    if (!row.families || typeof row.families !== 'object') delete single.families;
    const protocol = probeKind === 'udp_probe' || row.protocol === 'udp' ? 'udp' : 'tcp';
    const verdict = correlateNfwViolation(probeKind, single, declarations);
    const violated = verdict?.verdict === 'exposed';
    return {
      protocol,
      port: Number(row.port),
      outcome: protocol === 'udp' ? row.udp_outcome ?? null : row.tcp_outcome ?? null,
      result: violated ? 'violated' : 'no_violation_observed',
      severity: violated ? verdict.severity ?? nfwPortSeverity(row.port) : null,
      explanation: violated ? verdict.explanation : null,
      ...(row.sample_agreement ? { sample_agreement: row.sample_agreement } : {}),
      ...(Array.isArray(row.samples) ? { samples: row.samples } : {}),
    };
  });
}

function withPortResults(verdict, portResults) {
  return { ...verdict, metadata: { ...(verdict.metadata ?? {}), port_results: portResults } };
}

/**
 * Correlate a verdict from external probe evidence only (ADR-0008: no agents).
 */
const NEVER_PUBLIC_PORTS = Object.freeze({
  23: 'Telnet', 445: 'SMB', 2375: 'Docker Engine API', 2379: 'etcd', 6379: 'Redis', 9200: 'Elasticsearch',
  10250: 'Kubernetes kubelet', 27017: 'MongoDB',
});
const NEVER_PUBLIC_SCAN_CHECKS = new Set(['nfw.management_port_exposure.safe', 'l3.firewall_exposure_scan.safe']);
const UNLIMITED_H2_STREAMS = 2147483647;

function inferredGap(severity, explanation) {
  return { verdict: 'exposed', confidence: 'external_only', createsFinding: true, severity, explanation, inferred_without_declaration: true };
}

function neverPublicPortGap(metadata) {
  if (peerIsCdn(metadata) || samplesDisagree(metadata)) return null;
  const familyRows = metadata?.families && typeof metadata.families === 'object'
    ? Object.entries(metadata.families).filter(([, row]) => row && typeof row === 'object' && !row.not_sampled)
    : [['ipv4', metadata]];
  const exposed = [];
  for (const [family, row] of familyRows) {
    if (row !== metadata && (peerIsCdn(metadata, row) || samplesDisagree(metadata, row))) continue;
    const open = Array.isArray(row.open_ports) ? row.open_ports.map(Number) : [];
    const silentOrClosed = ['closed_ports', 'rejected_ports', 'filtered_ports']
      .some((key) => Array.isArray(row[key]) && row[key].some((port) => !open.includes(Number(port))));
    if (!silentOrClosed) continue;
    for (const port of open) {
      if (NEVER_PUBLIC_PORTS[port] && !exposed.some((item) => item.port === port && item.family === family)) exposed.push({ port, family });
    }
  }
  if (!exposed.length) return null;
  const listed = exposed.map((item) => `tcp/${item.port} ${NEVER_PUBLIC_PORTS[item.port]} (${item.family})`).join(', ');
  return inferredGap('high', `Services that should never be reachable from the internet accepted a TCP handshake from ${perspectiveLabel(metadata)}: ${listed}. Other scanned ports were closed or filtered, so this is not an accept-all host.`);
}

function correlateInferredMissingControl({ checkId, probeKind, externalResult, probeIoObserved, probeMetadata: metadata }) {
  if (!checkId || probeIoObserved !== true || !metadata || typeof metadata !== 'object') return null;
  if (metadata.inconclusive_reason || metadata.error_class) return null;
  if (correlateEvidenceGap(probeKind, metadata) || correlateProbeFailure(externalResult, probeKind, metadata)) return null;
  if (externalResult !== 'connected') return null;
  if (NEVER_PUBLIC_SCAN_CHECKS.has(checkId) && probeKind === 'port_scan_bounded') return neverPublicPortGap(metadata);
  if (checkId === 'reflect.redis_direct_exposure.safe' && probeKind === 'tcp_connect') {
    const samples = Array.isArray(metadata.samples) ? metadata.samples : [];
    if (peerIsCdn(metadata) || metadata.sample_agreement !== 'agree' || samples.length < 2
      || !samples.every((row) => row?.tcp_outcome === 'handshake' && Number(row?.port) === 6379)) return null;
    return inferredGap('high', `Redis (tcp/6379) accepted a TCP handshake from ${perspectiveLabel(metadata)} on ${samples.length} of ${samples.length} samples; Redis should never be reachable from the internet.`);
  }
  if (checkId === 'tls.full_audit.safe' && probeKind === 'tls_audit' && metadata.complete === true) {
    const issues = Array.isArray(metadata.tls_issues) ? metadata.tls_issues : [];
    if (issues.includes('cert_expired')) {
      return inferredGap('medium', `The certificate served on this endpoint expired ${Math.abs(Number(metadata.days_to_expiry))} day(s) ago${metadata.valid_to ? ` (valid to ${metadata.valid_to})` : ''}.`);
    }
    if (issues.includes('certificate_not_yet_valid')) {
      return inferredGap('medium', 'The certificate served on this endpoint is not yet valid.');
    }
    return null;
  }
  if (checkId === 'dns.secondary_failover.safe' && probeKind === 'dns_failover_posture') {
    if (metadata.nameserver_count_below_two !== true || metadata.nameserver_count !== 1) return null;
    return inferredGap('medium', `The zone${metadata.zone ? ` ${metadata.zone}` : ''} is delegated to a single nameserver${Array.isArray(metadata.nameservers) && metadata.nameservers[0] ? ` (${metadata.nameservers[0]})` : ''}, so there is no secondary to answer if it is overwhelmed.`);
  }
  if (checkId === 'l7.cors_posture.safe' && probeKind === 'cors_posture_probe') {
    if (metadata.access_control_allow_origin !== 'https://probe.invalid.astranull' || metadata.credentials_advertised !== true) return null;
    return inferredGap('medium', "This URL reflected AstraNull's unrelated test Origin in Access-Control-Allow-Origin and allowed credentials, so any website can make credentialed requests to it.");
  }
  if (checkId === 'protocol.grpc_reflection_stream.safe' && probeKind === 'grpc_reflection_probe') {
    if (metadata.reflection_service_exposed !== true || metadata.protocol_identity_confirmed !== true) return null;
    return inferredGap('low', 'The gRPC server reflection service answered an unauthenticated list_services request, exposing the service catalog to anyone.');
  }
  if (checkId === 'tls.renegotiation.readiness' && probeKind === 'tls_session') {
    if (metadata.tls_protocol !== 'TLSv1.2' || metadata.client_renegotiation_attempted !== true || metadata.client_renegotiation_accepted !== true) return null;
    return inferredGap('low', 'The TLS 1.2 endpoint accepted a client-initiated renegotiation on an established connection, so one client can force repeated expensive handshakes.');
  }
  if (checkId === 'protocol.http2_stream_concurrency.safe' && probeKind === 'http2_settings') {
    const streams = metadata.max_concurrent_streams;
    if (!(streams === null || (Number.isFinite(Number(streams)) && Number(streams) >= UNLIMITED_H2_STREAMS)) || !('max_concurrent_streams' in metadata)) return null;
    return inferredGap('low', 'The HTTP/2 endpoint advertised no SETTINGS_MAX_CONCURRENT_STREAMS limit, so one client can open an unbounded number of concurrent streams.');
  }
  return null;
}

function withInferredMissingControl(input, result) {
  if (result?.verdict !== 'inconclusive') return result;
  const inferred = correlateInferredMissingControl(input ?? {});
  return inferred ? { ...inferred, ...(result.metadata ? { metadata: result.metadata } : {}) } : result;
}

export function correlateExternalOnlyVerdict(input) {
  const isNfwKind = NFW_PROBE_KINDS.has(input?.probeKind);
  if (isNfwKind && (!input?.probeIoObserved || ['error', 'not_run', 'timeout'].includes(input?.externalResult))) {
    // Without attested I/O (or on a failed/absent probe) a declared deny cannot be proven violated:
    // fall back to the established inconclusive verdict and never let unattested liveness read as exposed.
    const single = correlateSingleExternalVerdict(input);
    const base = single.verdict === 'exposed'
      ? correlateObservationOnlyVerdict(input?.probeKind, input?.probeMetadata, input?.externalResult)
      : single;
    // Keep whatever per-port outcomes the probe did record as evidence; the verdict stays inconclusive.
    const observedPorts = nfwPortResults(input?.probeKind, input?.probeMetadata, input?.declarations ?? null);
    return observedPorts ? withPortResults(base, observedPorts) : base;
  }
  const portResults = nfwPortResults(input?.probeKind, input?.probeMetadata, input?.declarations ?? null);
  if (!portResults) return withInferredMissingControl(input, correlateSingleExternalVerdict(input));
  const violated = portResults.filter((row) => row.result === 'violated');
  if (violated.length) {
    const severity = violated.some((row) => row.severity === 'high') ? 'high' : 'medium';
    const ports = violated.map((row) => `${row.protocol}/${row.port}`).join(', ');
    return withPortResults({
      verdict: 'exposed',
      confidence: 'external_only',
      createsFinding: true,
      severity,
      explanation: `Declared deny violated on ${ports} from ${perspectiveLabel(input.probeMetadata)} (${violated.length} of ${portResults.length} probed declared deny ports); denial cannot be proven from outside.`,
    }, portResults);
  }
  return withInferredMissingControl(input, withPortResults(correlateSingleExternalVerdict(input), portResults));
}

function correlateSingleExternalVerdict({
  externalResult,
  expectedBehavior,
  probeKind,
  probeIoObserved = false,
  probeMetadata = {},
  declarations = null,
  originBinding = null,
  checkId = null,
  env = process.env,
}) {
  if (probeMetadata?.inconclusive_reason === 'required_input_missing' || probeMetadata?.error_class === 'required_input_missing') {
    const reason = inconclusiveReason({ probeKind, externalResult, metadata: probeMetadata });
    return {
      verdict: 'inconclusive',
      confidence: 'external_only',
      explanation: probeMetadata?.missing_message || reason.explanation,
      explanation_reason: reason.reason,
      createsFinding: false,
    };
  }
  const evidenceGap = correlateEvidenceGap(probeKind, probeMetadata);
  if (evidenceGap) return evidenceGap;

  // Specialized fields cannot override a terminal failure or manufacture attested delivery.
  const semanticKind = ['waf_class_marker_probe', 'waf_evasion_marker_probe', 'outside_in_waf_scan', 'waf_method_policy_probe', 'rate_limit_canary_probe', 'dns_axfr_leak'].includes(probeKind);
  if (semanticKind) {
    const failure = correlateProbeFailure(externalResult, probeKind, probeMetadata);
    if (failure) return failure;
    if (probeIoObserved !== true) return inconclusiveVerdict('Control metadata has no attested probe I/O; no enforcement or exposure conclusion is available.');
    if (probeMetadata.assurance_scope === 'custom_canary_rule' || probeMetadata.setup_required === true) {
      return inconclusiveVerdict('Custom canary setup is not bound to an installed exact-token rule and placements. This is an inert-token observation only, with no enforcement conclusion or managed-rule coverage; the current declaration workflow cannot establish that binding.');
    }
    if (['waf_class_marker_probe', 'outside_in_waf_scan'].includes(probeKind)
      && (!markerComparisonComplete(probeMetadata) || probeMetadata.grading_version !== WAF_GRADING_VERSION)) {
      return inconclusiveVerdict('The current marker comparison lacks complete attested planned delivery, healthy controls or compatible grading; excluded placements do not establish enforcement.');
    }
    if (probeMetadata.enforcement === 'enforced' && placementsOf(probeMetadata).some((row) => row.outcome === 'allowed' || row.allowed === true)) {
      return inconclusiveVerdict('Enforcement metadata contradicts an allowed placement; the comparison must be repeated.');
    }
    if (probeMetadata.comparison_complete === false || probeMetadata.baseline_health === 'unhealthy') {
      return inconclusiveVerdict('The specialized control comparison is incomplete or its baseline is unhealthy.');
    }
  }

  if (checkId === 'nfw.perspective_allowlist.safe') {
    return correlatePerspectiveAllowlist(probeMetadata, declarations, externalResult, env);
  }

  const nfw = NFW_PROBE_KINDS.has(probeKind)
    ? correlateNfwViolation(probeKind, probeMetadata, declarations)
    : null;
  if (nfw) return nfw;

  if (probeKind === 'host_sni_bypass') {
    const origin = correlateOriginLockdownVerdict(probeMetadata, declarations, originBinding);
    if (origin) return origin;
  }

  if (probeKind === 'rate_limit_canary_probe') {
    const rate = correlateRateLimitCanary(probeMetadata, declarations);
    if (rate) return rate;
    return inconclusiveVerdict('Rate-limit canary did not produce a conclusive limit or miss.');
  }

  if (probeKind === 'waf_class_marker_probe' || probeKind === 'waf_evasion_marker_probe' || probeKind === 'outside_in_waf_scan') {
    const penalty = correlateChallengeRedirectPenalty(probeMetadata, declarations, externalResult);
    if (penalty) return penalty;
    if (probeKind === 'waf_class_marker_probe') {
      return correlateClassMarkerVerdict(probeMetadata)
        ?? inconclusiveVerdict('WAF class marker did not produce control-specific enforcement evidence.');
    }
    if (probeKind === 'waf_evasion_marker_probe') {
      const evasion = correlateEvasionVerdict(probeMetadata);
      if (evasion) return evasion;
    }
  }

  if (probeKind === 'waf_method_policy_probe') {
    return correlateMethodPolicyVerdict(probeMetadata);
  }

  if (probeKind === 'dns_axfr_leak') {
    const axfr = correlateAxfrVerdict(externalResult, probeMetadata, probeIoObserved);
    if (axfr) return axfr;
  }

  if (isObservationOnlyProbeKind(probeKind)) {
    return correlateObservationOnlyVerdict(probeKind, probeMetadata, externalResult);
  }

  const probeFailure = correlateProbeFailure(externalResult, probeKind, probeMetadata);
  if (probeFailure) return probeFailure;

  if (!isVerdictCapableProbeKind(probeKind)) {
    return inconclusiveVerdict(`${probeKind || 'unrecognized probe'} is not a verdict-capable probe kind.`);
  }

  const blocked = externalResult === 'blocked';
  const connected = externalResult === 'connected' || externalResult === 'allowed';
  const challenged = externalResult === 'challenged' || probeMetadata?.enforcement === 'challenged';

  if (blocked && probeIoObserved !== true) {
    return inconclusiveVerdict('Blocked metadata had no attested probe I/O and cannot establish edge protection.');
  }

  if (challenged) {
    const expected = expectedWafAction(declarations);
    if (CHALLENGE_ACTIONS.has(expected) && expectedBehavior === 'must_block_before_origin') {
      return {
        verdict: 'protected',
        confidence: 'external_only',
        createsFinding: false,
        explanation: `Observed challenge matches declared WAF expected_action '${expected}'.`,
      };
    }
    if (expectedBehavior === 'must_block_before_origin') {
      return inconclusiveVerdict('A challenge does not satisfy a block expectation.');
    }
  }

  if (expectedBehavior === 'must_block_before_origin') {
    if (blocked) {
      const enforcementCredit = probeMetadata?.enforcement === 'enforced'
        || probeKind === 'waf_class_marker_probe';
      if (enforcementCredit) {
        return {
          verdict: 'protected',
          confidence: 'external_only',
          explanation: 'External probe was blocked by the control under test.',
          createsFinding: false,
        };
      }
      return {
        verdict: 'edge_protected',
        confidence: 'external_only',
        explanation: 'External probe was blocked at the edge; the declared path did not respond as reachable.',
        createsFinding: false,
      };
    }
    if (connected) {
      return {
        verdict: 'edge_exposed',
        confidence: 'external_only',
        explanation: 'External probe reached the declared path; the edge did not block traffic before origin.',
        createsFinding: true,
        severity: 'medium',
      };
    }
  }

  if (expectedBehavior === 'must_reach_canary') {
    if (connected) {
      return {
        verdict: 'allowed_as_expected',
        confidence: 'external_only',
        explanation: 'Protected-path canary traffic reached the declared path as expected.',
        createsFinding: false,
      };
    }
    if (blocked) {
      return inconclusiveVerdict('Canary path did not complete — protected path or canary may be unreachable.');
    }
  }

  return inconclusiveVerdict('Insufficient external probe evidence for a definitive verdict.');
}

/**
 * Ops-readiness verdict — control-plane self-check with no agent/external target traffic.
 * Reuses the existing verdict vocabulary ('protected' / 'inconclusive') the UI handles.
 * Never creates a customer target finding.
 *
 * @param {{ externalResult?: string, opsValidationOk?: boolean }} params
 */
export function correlateOpsReadinessVerdict({ externalResult, opsValidationOk } = {}) {
  const validated =
    opsValidationOk === true || (externalResult === 'connected' && opsValidationOk === true);
  if (validated) {
    return {
      verdict: 'protected',
      confidence: 'high',
      createsFinding: false,
      explanation: 'Operational readiness control validated by control-plane self-check.',
    };
  }
  return {
    verdict: 'inconclusive',
    confidence: 'low',
    createsFinding: false,
    explanation:
      'Operational readiness could not be validated (no recorded operational evidence).',
  };
}

export function withinCorrelationWindow(probeTs, obsTs, windowMs = 120_000) {
  const a = new Date(probeTs).getTime();
  const b = new Date(obsTs).getTime();
  return Math.abs(b - a) <= windowMs;
}
