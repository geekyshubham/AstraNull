/**
 * Outside-in WAF scanner — bounded metadata-only edge validation.
 * Detects WAF presence, fingerprints vendor/product, validates benign class markers
 * (including safe evasion variants), content-type confusion, optional origin bypass,
 * and emits a posture summary. Protected requires agent corroboration by default.
 */

import { createHash } from 'node:crypto';
import { resolve4, resolve6, resolveCname } from 'node:dns/promises';
import tls from 'node:tls';
import { classifyWafPosture } from '../contracts/wafPosture.mjs';
import { classifyWafProductFromSignals } from './wafProductCatalog.mjs';
import { pinnedFetch } from './pinnedHttpRequest.mjs';
import {
  EDGE_SIGNATURE_CORPUS_VERSION,
  FINGERPRINT_BODY_MAX_LENGTH,
  classifyEdgeFingerprint,
  extractFingerprintHeaderEntries,
} from './edgeFingerprint.mjs';
import { assessWafEffectiveness } from './edgeDetectionProjection.mjs';

const MAX_BODY_READ_BYTES = 8192;
const FINGERPRINT_BODY_READ_BYTES = FINGERPRINT_BODY_MAX_LENGTH;
const BLOCK_STATUSES = new Set([401, 403, 406, 429, 503]);
const CHALLENGE_HEADERS = ['cf-mitigated', 'x-waf-block', 'x-bot-challenge', 'x-sucuri-block'];
const CLASS_MARKER_FAMILIES = Object.freeze({
  sqli: 'sqli_marker',
  xss: 'xss_marker',
  path_traversal: 'path_traversal_marker',
});

export const BENIGN_CLASS_MARKERS = Object.freeze({
  xss: '<astranull-xss-probe/>',
  sqli: "astranull' OR '1'='0",
  path_traversal: '../../astranull-probe',
});

/** Safe evasion-class variants — single-request probes, not reusable attack tooling. */
export const EVASION_VARIANT_MARKERS = Object.freeze({
  sqli_encoded: encodeURIComponent(encodeURIComponent(BENIGN_CLASS_MARKERS.sqli)),
  sqli_case: "AsTrAnUlL' oR '1'='0",
  sqli_comment: "astranull' O/**/R '1'='0",
  xss_encoded: encodeURIComponent(BENIGN_CLASS_MARKERS.xss),
  path_encoded: encodeURIComponent(BENIGN_CLASS_MARKERS.path_traversal),
});

export const OUTSIDE_IN_SCAN_PHASES = Object.freeze([
  'baseline',
  'combined_marker',
  'path_traversal_marker',
  'sqli_marker',
  'xss_marker',
  'sqli_encoded_marker',
  'sqli_case_marker',
  'sqli_comment_marker',
  'xss_encoded_marker',
  'no_user_agent',
  'content_type_confusion',
  'multipart_confusion',
  'origin_bypass',
]);

export const OUTSIDE_IN_SCAN_DEFAULT_BUDGET = 13;

const OUTSIDE_IN_PHASE_RETENTION_PRIORITY = Object.freeze([
  'baseline',
  'path_traversal_marker',
  'sqli_marker',
  'xss_marker',
  'combined_marker',
  'origin_bypass',
  'content_type_confusion',
  'multipart_confusion',
  'sqli_case_marker',
  'sqli_comment_marker',
  'sqli_encoded_marker',
  'xss_encoded_marker',
  'no_user_agent',
]);

const DEFAULT_BROWSER_HEADERS = Object.freeze({
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'User-Agent': 'Mozilla/5.0 (compatible; AstraNullOutsideIn/1.0; +https://astranull.invalid/probe)',
  'Accept-Language': 'en-US,en;q=0.5',
  DNT: '1',
});

const BLOCK_PAGE_SIGNATURE_RULES = Object.freeze([
  { id: 'block_sig_cloudflare_generic_v1', pattern: /cloudflare|cf-ray/i },
  { id: 'block_sig_akamai_generic_v1', pattern: /akamai|reference\s+#\d+\.\w+\.\d+\.\d+\.\d+/i },
  { id: 'block_sig_incapsula_generic_v1', pattern: /incapsula|imperva|visid_incap/i },
  { id: 'block_sig_aws_waf_v1', pattern: /request blocked|aws.?waf|x-amz-cf-id/i },
  { id: 'block_sig_modsecurity_v1', pattern: /mod.?security|modsecurity/i },
  { id: 'block_sig_sucuri_v1', pattern: /sucuri|cloudproxy@sucuri/i },
  { id: 'block_sig_f5_asm_v1', pattern: /the requested url was rejected|support id|f5/i },
  { id: 'block_sig_barracuda_v1', pattern: /barracuda/i },
  { id: 'block_sig_fortiweb_v1', pattern: /fortiweb|fortigate/i },
  { id: 'block_sig_azure_waf_v1', pattern: /azure|front door|application gateway/i },
  { id: 'block_sig_fastly_v1', pattern: /fastly error|fastly-ssl/i },
  { id: 'block_sig_radware_v1', pattern: /radware|appwall/i },
  { id: 'block_sig_paloalto_v1', pattern: /palo alto|prisma/i },
  { id: 'block_sig_generic_waf_v1', pattern: /access denied|request rejected|security policy|web application firewall/i },
  { id: 'block_sig_alertlogic_v1', pattern: /alert logic|reference id.*cannot be found/i },
  { id: 'block_sig_zscaler_v1', pattern: /zscaler|zscloud\.net|accenture policy/i },
  { id: 'block_sig_vercel_v1', pattern: /vercel security checkpoint|\/vercel\/security\//i },
  { id: 'block_sig_zenedge_v1', pattern: /zenedge|x-zen-fury/i },
  { id: 'block_sig_wordfence_v1', pattern: /wordfence|wf-waf/i },
  { id: 'block_sig_ddosguard_v1', pattern: /ddos-guard|__ddg/i },
  { id: 'block_sig_airlock_v1', pattern: /airlock|al[_-]?sess/i },
  { id: 'block_sig_azion_v1', pattern: /azion|x-azion-/i },
  { id: 'block_sig_qrator_v1', pattern: /qrator/i },
  { id: 'block_sig_cloudbric_v1', pattern: /cloudbric/i },
  { id: 'block_sig_safedog_v1', pattern: /safedog/i },
  { id: 'block_sig_yundun_v1', pattern: /yundun/i },
  { id: 'block_sig_imunify360_v1', pattern: /imunify360/i },
  { id: 'block_sig_link11_v1', pattern: /rhino-core-shield|link11/i },
  { id: 'block_sig_nexusguard_v1', pattern: /nexusguard/i },
  { id: 'block_sig_dotdefender_v1', pattern: /dotdefender/i },
  { id: 'block_sig_webseal_v1', pattern: /webseal|ibm security access manager/i },
  { id: 'block_sig_denyall_v1', pattern: /denyall|da_session/i },
  { id: 'block_sig_sitelock_v1', pattern: /sitelock|trueshield/i },
  { id: 'block_sig_distil_v1', pattern: /distil networks|distil_r_blocked/i },
  { id: 'block_sig_godaddy_v1', pattern: /godaddy.*waf|site security/i },
  { id: 'block_sig_malcare_v1', pattern: /malcare|blogvault/i },
  { id: 'block_sig_webarx_v1', pattern: /webarx|patchstack/i },
  { id: 'block_sig_naxsi_v1', pattern: /naxsi/i },
  { id: 'block_sig_arvancloud_v1', pattern: /arvancloud/i },
  { id: 'block_sig_baidu_v1', pattern: /yunjiasu|baidu.*waf/i },
  { id: 'block_sig_chuangyu_v1', pattern: /chuangyu|365cyd/i },
  { id: 'block_sig_knownsec_v1', pattern: /knownsec|ks-waf/i },
  { id: 'block_sig_jiasule_v1', pattern: /jiasule/i },
  { id: 'block_sig_anquanbao_v1', pattern: /anquanbao/i },
  { id: 'block_sig_safeline_v1', pattern: /safeline|chaitin/i },
  { id: 'block_sig_ptaf_v1', pattern: /ptaf|positive technologies/i },
  { id: 'block_sig_variti_v1', pattern: /variti/i },
  { id: 'block_sig_transip_v1', pattern: /transip.*waf|webshield/i },
]);

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const LOW_SPECIFICITY_BLOCK_PAGE_SIGNATURES = new Set(['block_sig_generic_waf_v1']);
const MAX_BASELINE_REDIRECT_HOPS = 2;

let markerParamSequence = 0;

function randomParamName() {
  markerParamSequence = (markerParamSequence + 1) % Number.MAX_SAFE_INTEGER;
  return `p${markerParamSequence.toString(36)}`;
}

function hashBodySnippet(text) {
  const snippet = String(text ?? '').slice(0, MAX_BODY_READ_BYTES);
  if (!snippet) return null;
  return createHash('sha256').update(snippet).digest('hex').slice(0, 32);
}

function headerNamesFromResponse(res) {
  if (!res?.headers) return [];
  const names = [];
  if (typeof res.headers.forEach === 'function') {
    res.headers.forEach((_value, name) => names.push(String(name).toLowerCase()));
    return [...new Set(names)].sort();
  }
  if (typeof res.headers === 'object') {
    return [...new Set(Object.keys(res.headers).map((k) => String(k).toLowerCase()))].sort();
  }
  return [];
}

function headerValue(res, name) {
  if (!res?.headers?.get) return null;
  return res.headers.get(name);
}

function cookieNamesFromResponse(res) {
  const raw = headerValue(res, 'set-cookie');
  if (!raw) return [];
  return [...new Set(
    String(raw)
      .split(/,(?=[^;]+?=)/)
      .map((part) => part.split('=')[0]?.trim())
      .filter(Boolean)
      .map((name) => name.toLowerCase()),
  )].sort();
}

function matchBlockPageSignature(bodyText) {
  const text = String(bodyText ?? '').slice(0, MAX_BODY_READ_BYTES);
  if (!text) return null;
  for (const rule of BLOCK_PAGE_SIGNATURE_RULES) {
    if (rule.pattern.test(text)) return rule.id;
  }
  return null;
}

/**
 * Header values restricted to the fingerprint-corpus allowlist (bounded length) and the
 * raw body text (bounded) are carried on the snapshot for in-memory edge-signature
 * classification only. They are metadata-only inputs and are never returned by the scan
 * result or persisted — result consumers see names, hashes, and classifications.
 */
function dedupeHeaderEntries(entries) {
  const byName = new Map();
  for (const entry of entries) {
    const name = String(entry?.name ?? '').toLowerCase();
    if (!name || byName.has(name)) continue;
    byName.set(name, { name, value: String(entry?.value ?? '') });
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function fingerprintInputs(res, bodyText) {
  return {
    fingerprint_header_entries: res ? extractFingerprintHeaderEntries(res) : [],
    fingerprint_body_text: String(bodyText ?? '').slice(0, FINGERPRINT_BODY_READ_BYTES),
    fingerprint_status_reason: String(res?.statusText ?? '').slice(0, 256),
  };
}

function wafw00fResponseEvidence(snapshot) {
  if (!snapshot || snapshot.connection_dropped) return null;
  return {
    headerEntries: snapshot.fingerprint_header_entries ?? [],
    cookieNames: snapshot.cookie_names ?? [],
    bodyText: snapshot.fingerprint_body_text ?? '',
    statusCode: snapshot.status_code,
    statusReason: snapshot.fingerprint_status_reason ?? '',
  };
}

const WAFW00F_GENERIC_REASONS = Object.freeze({
  connection_level_blocking: 'Blocking is being done at connection/packet level.',
  server_header_changed: 'The server header is different when an attack is detected.',
  status_code_changed: 'The server returns a different response code when an attack string is used.',
  no_user_agent_response_changed: "The response was different when the request wasn't made from a browser.",
});

/**
 * wafw00f `genericdetect` decision order over snapshots this scanner already captured:
 * no-User-Agent drift, then XSS, path-traversal, and SQLi status drift, then Server header drift
 * on the combined response. Any dropped connection is connection-level blocking.
 */
export function wafw00fGenericDetection({ baseline, noUserAgent, xss, pathTraversal, sqli, combined } = {}) {
  const found = (reasonCode) => ({
    found: true,
    reason_code: reasonCode,
    reason: WAFW00F_GENERIC_REASONS[reasonCode],
  });
  if (!baseline) return { found: false, reason_code: null, reason: null };
  const captured = [baseline, noUserAgent, xss, pathTraversal, sqli, combined].filter(Boolean);
  if (captured.some((snapshot) => snapshot.connection_dropped)) return found('connection_level_blocking');
  if (noUserAgent && noUserAgent.status_code !== baseline.status_code) return found('no_user_agent_response_changed');
  for (const snapshot of [xss, pathTraversal, sqli]) {
    if (snapshot && snapshot.status_code !== baseline.status_code) return found('status_code_changed');
  }
  if (combined && (combined.server_header ?? '') !== (baseline.server_header ?? '')) {
    return found('server_header_changed');
  }
  return { found: false, reason_code: null, reason: null };
}

function responseSnapshot(res, bodyText = '') {
  if (!res) {
    return {
      status_code: 0,
      status_code_class: 'error',
      header_names: [],
      cookie_names: [],
      server_header: null,
      block_page_signature_id: null,
      block_page_fingerprint_hash: null,
      connection_dropped: true,
      ...fingerprintInputs(null, ''),
    };
  }
  const status = res.status ?? 0;
  const blockPageSignatureId = matchBlockPageSignature(bodyText);
  return {
    status_code: status,
    status_code_class: status >= 500 ? '5xx' : status >= 400 ? '4xx' : status >= 300 ? '3xx' : '2xx',
    header_names: headerNamesFromResponse(res),
    cookie_names: cookieNamesFromResponse(res),
    server_header: headerValue(res, 'server'),
    block_page_signature_id: blockPageSignatureId,
    block_page_fingerprint_hash: blockPageSignatureId ? hashBodySnippet(bodyText) : null,
    connection_dropped: false,
    ...fingerprintInputs(res, bodyText),
  };
}

function challengeHeaderDelta(snapshot, baseline) {
  const current = new Set(snapshot?.header_names ?? []);
  const previous = new Set(baseline?.header_names ?? []);
  return CHALLENGE_HEADERS.some((name) => current.has(name) && !previous.has(name));
}

function specificBlockPageDelta(snapshot, baseline) {
  const signature = snapshot?.block_page_signature_id;
  return Boolean(
    signature
    && !LOW_SPECIFICITY_BLOCK_PAGE_SIGNATURES.has(signature)
    && signature !== baseline?.block_page_signature_id,
  );
}

export function isBlockedOrChallenged(snapshot, baseline = null) {
  if (!snapshot || snapshot.connection_dropped || snapshot.error_class) {
    return {
      blocked: false,
      challenged: false,
      allowed: false,
      inconclusive: true,
      ...(snapshot?.error_class ? { error_class: snapshot.error_class } : {}),
    };
  }
  const status = snapshot.status_code;
  const headerChallenge = challengeHeaderDelta(snapshot, baseline);
  const blockPage = specificBlockPageDelta(snapshot, baseline);
  if (headerChallenge || blockPage) {
    return { blocked: true, challenged: headerChallenge, allowed: false, inconclusive: false };
  }

  if (baseline && !baseline.connection_dropped && !baseline.error_class) {
    const repeatedBlockPage = Boolean(
      snapshot.block_page_signature_id
      && snapshot.block_page_signature_id === baseline.block_page_signature_id,
    );
    const repeatedChallenge = CHALLENGE_HEADERS.some((name) => (
      snapshot.header_names?.includes(name) && baseline.header_names?.includes(name)
    ));
    const unchangedBlockedBaseline = baseline.status_code === status
      && (BLOCK_STATUSES.has(status) || REDIRECT_STATUSES.has(status));
    if (unchangedBlockedBaseline || repeatedBlockPage || repeatedChallenge) {
      return { blocked: false, challenged: false, allowed: false, inconclusive: true };
    }
  }

  if (BLOCK_STATUSES.has(status)) {
    if (!baseline || baseline.connection_dropped || baseline.error_class) {
      return { blocked: false, challenged: false, allowed: false, inconclusive: true };
    }
    return {
      blocked: baseline.status_code !== status,
      challenged: baseline.status_code !== status && (status === 403 || status === 401),
      allowed: false,
      inconclusive: baseline.status_code === status,
    };
  }
  if (status >= 300 && status < 400) {
    if (!baseline || baseline.connection_dropped || baseline.status_code === status) {
      return { blocked: false, challenged: false, allowed: false, inconclusive: true };
    }
    return { blocked: true, challenged: true, allowed: false, inconclusive: false };
  }
  if (baseline && baseline.status_code !== status) {
    const baselineOk = baseline.status_code >= 200 && baseline.status_code < 400;
    const probeOk = status >= 200 && status < 400;
    if (baselineOk !== probeOk || (baseline.server_header && snapshot.server_header
      && baseline.server_header !== snapshot.server_header)) {
      return { blocked: true, challenged: false, allowed: false, inconclusive: false };
    }
  }
  if (status >= 200 && status < 300) {
    return { blocked: false, challenged: false, allowed: true, inconclusive: false };
  }
  return { blocked: false, challenged: false, allowed: false, inconclusive: true };
}

export function detectGenericWafPresence({ baseline, attack, noUserAgent } = {}) {
  const reasons = [];
  const evidenceReasons = [];
  if (!baseline || baseline.connection_dropped || baseline.error_class) {
    return {
      detected: false,
      reason: null,
      reasons: ['baseline_inconclusive'],
      inconclusive: true,
    };
  }
  if (attack?.connection_dropped || attack?.error_class) {
    return {
      detected: false,
      reason: null,
      reasons: ['marker_inconclusive'],
      inconclusive: true,
    };
  }
  if (attack && baseline.status_code !== attack.status_code) reasons.push('status_code_drift');
  if (attack && baseline.server_header && attack.server_header
    && baseline.server_header !== attack.server_header) {
    reasons.push('server_header_drift');
  }
  if (noUserAgent && baseline.status_code !== noUserAgent.status_code) reasons.push('no_user_agent_drift');
  if (challengeHeaderDelta(attack, baseline)) evidenceReasons.push('waf_challenge_header');
  if (specificBlockPageDelta(attack, baseline)) evidenceReasons.push('waf_specific_block_page');
  reasons.push(...evidenceReasons);
  return {
    detected: evidenceReasons.length > 0,
    reason: evidenceReasons[0] ?? null,
    reasons,
    inconclusive: false,
  };
}

function evidenceBackedVendorClassification(classification) {
  const candidates = (classification?.candidates ?? []).flatMap((candidate) => {
    const matchedSignals = (candidate.matched_signals ?? [])
      .filter((signal) => signal !== 'customer_vendor_hint');
    if (matchedSignals.length === 0) return [];
    const declarationBoost = candidate.matched_signals?.includes('customer_vendor_hint') ? 0.1 : 0;
    return [{
      ...candidate,
      confidence: Math.max(0, Number((candidate.confidence - declarationBoost).toFixed(3))),
      matched_signals: matchedSignals,
    }];
  }).sort((left, right) => right.confidence - left.confidence);
  const best = candidates[0] ?? null;
  const rival = best ? candidates.find((candidate) => candidate.vendor !== best.vendor) : null;
  return {
    ...classification,
    candidates,
    best,
    conflicting_vendor_signals: Boolean(
      best && rival && best.confidence - rival.confidence <= 0.2,
    ),
  };
}

function recordMarkerResult(markerResults, entry) {
  const existing = markerResults.find((row) => row.family === entry.family && row.variant === entry.variant);
  if (existing) Object.assign(existing, entry);
  else markerResults.push(entry);
}

function detectEvasionBypass(markerResults) {
  const plainFamilies = ['sqli_marker', 'xss_marker', 'path_traversal_marker'];
  const evasionFamilies = [
    'sqli_encoded_marker',
    'sqli_case_marker',
    'sqli_comment_marker',
    'xss_encoded_marker',
    'content_type_confusion',
    'multipart_confusion',
  ];
  const plainRows = markerResults.filter((row) => plainFamilies.includes(row.family));
  const plainBlocked = plainRows.length > 0 && plainRows.every((row) => row.blocked);
  const evasionAllowed = markerResults
    .filter((row) => evasionFamilies.includes(row.family))
    .some((row) => row.allowed);
  return plainBlocked && evasionAllowed;
}

/**
 * @param {object} input
 * @param {boolean} [input.agentCorroborated=false]
 * @param {boolean} [input.requireAgentForProtected=true]
 * @param {string} [input.domXssValidation='agent_required']
 * @param {object|null} [input.edgeSignature=null] — classifyEdgeFingerprint() result.
 */
export function buildOutsideInPostureReport({
  wafDetected = false,
  genericWafDetected = false,
  markerResults = [],
  originBypassConfirmed = false,
  wafRequired = true,
  vendorClassification = null,
  agentCorroborated = false,
  requireAgentForProtected = true,
  evasionBypassSuspected = false,
  domXssValidation = 'agent_required',
  edgeSignature = null,
  coverageComplete,
  probeErrorsPresent = false,
} = {}) {
  const anyMarkerAllowed = markerResults.some((m) => m.allowed === true);
  const markerInconclusive = markerResults.some((marker) => (
    marker.inconclusive === true || Boolean(marker.error_class)
  ));
  const probeInconclusive = probeErrorsPresent || markerInconclusive;
  const classMarkerResults = Object.values(CLASS_MARKER_FAMILIES).map(
    (family) => markerResults.find((row) => row.family === family && row.variant === 'plain'),
  );
  const classCoverageComplete = classMarkerResults.every(Boolean);
  const probeValidationPassed = classCoverageComplete
    && classMarkerResults.every((marker) => marker.blocked === true)
    && !anyMarkerAllowed
    && !probeInconclusive;
  const validationFailed = markerResults.length > 0 && (anyMarkerAllowed || evasionBypassSuspected);

  let validationPassed = probeValidationPassed && !evasionBypassSuspected;
  if (requireAgentForProtected && validationPassed && !agentCorroborated) {
    validationPassed = false;
  }

  const effectiveWafDetected = wafDetected || genericWafDetected
    || Boolean(vendorClassification?.best)
    || edgeSignature?.waf_present === true;
  const posture = classifyWafPosture({
    wafDetected: effectiveWafDetected,
    validationPassed,
    validationFailed,
    originBypassConfirmed,
    wafRequired,
  });

  const reason_codes = [...posture.reason_codes];
  if (evasionBypassSuspected && !reason_codes.includes('scenario_category_failed')) {
    reason_codes.push('scenario_category_failed');
  }
  if (probeValidationPassed && requireAgentForProtected && !agentCorroborated
    && !reason_codes.includes('insufficient_validation_evidence')) {
    reason_codes.push('insufficient_validation_evidence');
  }
  if (probeInconclusive && !validationFailed && !reason_codes.includes('probe_result_inconclusive')) {
    reason_codes.push('probe_result_inconclusive');
  }

  let posture_label = 'Unknown';
  let posture_status = posture.status;

  if (originBypassConfirmed) {
    posture_label = 'Bypass Risk';
    posture_status = 'underprotected';
  } else if (validationFailed) {
    posture_label = 'Underprotected';
    posture_status = 'underprotected';
  } else if (probeInconclusive) {
    posture_label = 'Inconclusive';
    posture_status = 'inconclusive';
  } else if (validationPassed && agentCorroborated) {
    posture_label = 'Protected';
    posture_status = 'protected';
  } else if (probeValidationPassed && effectiveWafDetected && !agentCorroborated) {
    posture_label = 'Edge protected · not internally validated';
    posture_status = 'edge_protected';
  } else if (posture.status === 'unprotected') {
    posture_label = 'Unprotected';
  } else if (posture.status === 'excluded') {
    posture_label = 'Excluded';
  } else if (posture.status === 'underprotected') {
    posture_label = 'Underprotected';
  }

  const best = vendorClassification?.best ?? null;
  const edgeBest = edgeSignature?.best_vendor ?? null;
  const corpusWafPresent = edgeSignature?.waf_present === true;
  const corpusDetected = corpusWafPresent || edgeSignature?.cdn_detected === true;
  const wafConfidence = best?.confidence
    ?? (edgeBest ? Math.max(edgeBest.confidence, genericWafDetected ? 0.45 : 0) : (genericWafDetected ? 0.45 : 0));
  const effectiveness = assessWafEffectiveness({
    wafPresent: effectiveWafDetected,
    markerResults,
    coverageComplete,
    transportError: probeErrorsPresent,
  });
  const class_posture = Object.fromEntries(Object.entries(CLASS_MARKER_FAMILIES).map(([className, family]) => {
    const observation = markerResults.find((row) => row.family === family && row.variant === 'plain');
    const status = observation?.blocked === true
      ? 'protected'
      : observation?.allowed === true
        ? 'underprotected'
        : 'unknown';
    return [className, status];
  }));
  return {
    posture_status,
    posture_label,
    reason_codes: [...new Set(reason_codes)],
    waf_detected: effectiveWafDetected,
    waf_fingerprint_detected: Boolean(best) || wafDetected || genericWafDetected || Boolean(edgeBest),
    generic_waf_detected: genericWafDetected,
    detected_vendor: best?.vendor ?? edgeBest?.vendor ?? null,
    detected_product: best?.product ?? null,
    waf_product_hint: best ? `${best.vendor}/${best.product}` : (edgeBest ? `corpus:${edgeBest.vendor}` : null),
    waf_confidence: wafConfidence,
    cdn_detected: edgeSignature?.cdn_detected === true,
    edge_signature_corpus_version: corpusDetected ? (edgeSignature?.corpus_version ?? null) : null,
    validation_passed: validationPassed,
    validation_failed: validationFailed,
    probe_validation_passed: probeValidationPassed,
    agent_corroborated: agentCorroborated,
    agent_corroboration_required: requireAgentForProtected,
    evasion_bypass_suspected: evasionBypassSuspected,
    dom_xss_validation: domXssValidation,
    origin_bypass_confirmed: originBypassConfirmed,
    ...(typeof coverageComplete === 'boolean' ? { coverage_complete: coverageComplete } : {}),
    class_posture,
    waf_effectiveness: effectiveness,
    marker_summary: {
      probes_sent: markerResults.length,
      blocked_count: markerResults.filter((m) => m.blocked).length,
      allowed_count: markerResults.filter((m) => m.allowed).length,
      challenged_count: markerResults.filter((m) => m.challenged).length,
      inconclusive_count: markerResults.filter((m) => m.inconclusive || m.error_class).length,
      evasion_probes_sent: markerResults.filter((m) => String(m.variant ?? '') !== 'plain').length,
    },
  };
}

function buildMultipartConfusionBody(marker, boundary = 'astranullBoundary7f3a') {
  const fieldName = randomParamName();
  return [
    `--${boundary}`,
    `Content-Disposition: form-data; name="${fieldName}"`,
    '',
    marker,
    `--${boundary}--`,
    '',
  ].join('\r\n');
}

function buildUrl(baseUrl, { pathSuffix = '', params = {}, rawParams = {} } = {}) {
  const url = new URL(baseUrl);
  if (pathSuffix) {
    const joined = `${url.pathname.replace(/\/$/, '')}/${pathSuffix}`.replace(/\/+/g, '/');
    url.pathname = joined.startsWith('/') ? joined : `/${joined}`;
  }
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  let href = url.href;
  for (const [key, value] of Object.entries(rawParams)) {
    const sep = href.includes('?') ? '&' : '?';
    href = `${href}${sep}${key}=${value}`;
  }
  return href;
}

function normalizeDnsHostname(value) {
  return String(value ?? '').trim().toLowerCase().replace(/\.$/, '');
}

/** Bounded CNAME-chain depth. cdncheck suffix matching only needs the edge-facing hops. */
const DNS_CNAME_CHAIN_MAX = 8;
/** Bounded address count per family, keeping the metadata summary small and comparable. */
const DNS_ADDRESSES_PER_FAMILY_MAX = 4;

/**
 * Optional standalone CNAME/A/AAAA lookup chain for metadata-only WAF/CDN catalog matching.
 * This raw collector is direct-helper opt-in only; the signed capability adapter keeps it disabled
 * because these operations are not separately signed, reserved, counted, pinned, and bounded.
 *
 * Returns the display `dns_chain` string plus the structured `cname_chain`/`resolved_ips` the
 * pinned cdncheck corpus consumes. Structured fields avoid re-parsing the display string.
 *
 * @param {string} hostname
 * @param {{
 *   resolveCname?: typeof resolveCname,
 *   resolve4?: typeof resolve4,
 *   resolve6?: typeof resolve6,
 * }} [deps]
 */
export async function resolveOutsideInDnsHints(hostname, deps = {}) {
  const host = normalizeDnsHostname(hostname);
  if (!host) {
    return { dns_chain: null, cname_chain: [], resolved_ips: [], error_class: 'missing_hostname' };
  }

  const resolveCnameFn = deps.resolveCname ?? resolveCname;
  const resolve4Fn = deps.resolve4 ?? resolve4;
  // A caller that injects resolvers is running hermetically. Falling back to the real AAAA
  // resolver for the one function it did not stub would put live DNS behind an injected test.
  const partiallyInjected = Boolean(deps.resolveCname || deps.resolve4);
  const resolve6Fn = deps.resolve6 ?? (partiallyInjected ? async () => [] : resolve6);
  const cnameChain = [host];
  const seen = new Set([host]);
  const resolvedIps = [];

  try {
    // Follow the delegation chain hop by hop. A single hop only reveals the first edge provider;
    // stacked CDN/WAF deployments expose their vendor further down the chain.
    while (cnameChain.length < DNS_CNAME_CHAIN_MAX) {
      let next = null;
      try {
        const cnames = await resolveCnameFn(cnameChain[cnameChain.length - 1]);
        next = normalizeDnsHostname(cnames?.[0]);
      } catch {
        /* ENODATA / ENOTFOUND — chain ends here, proceed to address lookup */
      }
      if (!next || seen.has(next)) break;
      seen.add(next);
      cnameChain.push(next);
    }

    const lookupHost = cnameChain[cnameChain.length - 1];
    const [v4, v6] = await Promise.all([
      resolve4Fn(lookupHost).catch(() => []),
      resolve6Fn(lookupHost).catch(() => []),
    ]);
    for (const list of [v4, v6]) {
      for (const entry of (Array.isArray(list) ? list : []).slice(0, DNS_ADDRESSES_PER_FAMILY_MAX)) {
        const address = String(entry ?? '').trim();
        if (address && !resolvedIps.includes(address)) resolvedIps.push(address);
      }
    }
  } catch (err) {
    return {
      dns_chain: cnameChain.join(' '),
      cname_chain: cnameChain,
      resolved_ips: resolvedIps,
      error_class: err?.code ?? err?.name ?? 'dns_lookup_failed',
    };
  }

  return {
    dns_chain: [...cnameChain, ...resolvedIps].join(' '),
    cname_chain: cnameChain,
    resolved_ips: resolvedIps,
  };
}

/**
 * Optional standalone TLS handshake read (protocol + cipher name only). This raw collector is
 * direct-helper opt-in only; signed outside-in execution keeps it disabled unless a future
 * operation is separately signed, reserved, counted, deadline-bounded, and destination-pinned.
 * @param {string} url
 * @param {{ tlsConnect?: typeof tls.connect, timeoutMs?: number }} [deps]
 */
export async function resolveOutsideInTlsHints(url, deps = {}) {
  let parsed;
  try {
    parsed = new URL(String(url ?? '').trim());
  } catch {
    return { tls_protocol_hint: null, tls_cipher_hint: null, error_class: 'invalid_url' };
  }

  if (parsed.protocol !== 'https:') {
    return { tls_protocol_hint: null, tls_cipher_hint: null };
  }

  const tlsConnectFn = deps.tlsConnect ?? tls.connect;
  const timeoutMs = Number.isInteger(deps.timeoutMs) && deps.timeoutMs > 0 ? deps.timeoutMs : 3000;
  const port = parsed.port ? Number(parsed.port) : 443;
  const host = parsed.hostname;
  const connectHost = deps.connectHost ?? host;

  return new Promise((resolve) => {
    let settled = false;
    const socket = tlsConnectFn({
      host: connectHost,
      port,
      servername: host,
      rejectUnauthorized: false,
    });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        tls_protocol_hint: null,
        tls_cipher_hint: null,
        error_class: 'tls_timeout',
      });
    }, timeoutMs);

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    socket.once('secureConnect', () => {
      finish({
        tls_protocol_hint: socket.getProtocol() ?? null,
        tls_cipher_hint: socket.getCipher()?.name ?? null,
      });
    });
    socket.once('error', (err) => {
      finish({
        tls_protocol_hint: null,
        tls_cipher_hint: null,
        error_class: err?.code ?? err?.name ?? 'tls_handshake_failed',
      });
    });
  });
}

function resolveRedirectTarget(location, baseUrl) {
  const raw = String(location ?? '').trim();
  if (!raw) return null;
  try {
    return new URL(raw, baseUrl).href;
  } catch {
    return null;
  }
}

/**
 * Baseline GET with optional manual redirect follow (bounded, baseline only).
 */
async function runBaselineGet(
  url,
  headers,
  { followRedirects = false, timeoutMs, requestBudget = 1, deps } = {},
) {
  let currentUrl = url;
  let redirectHops = 0;
  let requestsSent = 0;
  let finalUrlHostname = null;

  while (requestsSent < requestBudget) {
    requestsSent += 1;
    const { res, bodyText, error } = await boundedRequest(
      currentUrl,
      { method: 'GET', headers },
      timeoutMs,
      deps,
    );

    try {
      finalUrlHostname = new URL(currentUrl).hostname;
    } catch {
      finalUrlHostname = null;
    }

    if (error || !res) {
      const snapshot = error
        ? { ...responseSnapshot(null), error_class: error.name ?? error.code ?? 'probe_failed' }
        : responseSnapshot(res, bodyText);
      return {
        snapshot,
        redirect_hops: redirectHops,
        final_url_hostname: finalUrlHostname,
        requests_sent: requestsSent,
      };
    }

    if (followRedirects && REDIRECT_STATUSES.has(res.status)
      && redirectHops < MAX_BASELINE_REDIRECT_HOPS && requestsSent < requestBudget) {
      const nextUrl = resolveRedirectTarget(headerValue(res, 'location'), currentUrl);
      if (nextUrl && nextUrl !== currentUrl) {
        redirectHops += 1;
        currentUrl = nextUrl;
        continue;
      }
    }

    return {
      snapshot: responseSnapshot(res, bodyText),
      redirect_hops: redirectHops,
      final_url_hostname: finalUrlHostname,
      requests_sent: requestsSent,
    };
  }

  return {
    snapshot: { ...responseSnapshot(null), error_class: 'request_budget_exhausted' },
    redirect_hops: redirectHops,
    final_url_hostname: finalUrlHostname,
    requests_sent: requestsSent,
  };
}

export async function readBoundedResponseBody(res, maxBytes = MAX_BODY_READ_BYTES) {
  const reader = res?.body?.getReader?.();
  if (!reader) return '';

  const chunks = [];
  let total = 0;
  let complete = false;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) {
        complete = true;
        break;
      }
      if (!(value instanceof Uint8Array) || value.byteLength === 0) continue;
      const remaining = maxBytes - total;
      const chunk = value.byteLength <= remaining ? value : value.subarray(0, remaining);
      chunks.push(chunk);
      total += chunk.byteLength;
      if (value.byteLength > remaining) break;
    }
  } finally {
    if (!complete) {
      try {
        await reader.cancel('response_body_limit_reached');
      } catch {
        // The transport may already be closed; the copied evidence remains bounded.
      }
    }
    reader.releaseLock?.();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(body);
}

async function boundedRequest(url, { method = 'GET', headers = {}, body = null }, timeoutMs, deps) {
  const fetchFn = deps.fetchFn ?? ((input, init) => pinnedFetch(input, init, deps));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, {
      method,
      headers,
      body,
      redirect: 'manual',
      signal: controller.signal,
    });
    if (!res || !Number.isInteger(res.status)) {
      const error = new Error('invalid HTTP response from probe transport');
      error.code = 'invalid_probe_response';
      return { res: null, bodyText: '', error };
    }
    const bodyText = await readBoundedResponseBody(res, FINGERPRINT_BODY_READ_BYTES);
    return { res, bodyText, error: null };
  } catch (err) {
    if (
      err?.code === 'signed_operation_budget_exceeded'
      || err?.code === 'probe_job_deadline_exceeded'
    ) {
      throw err;
    }
    return { res: null, bodyText: '', error: err };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Priority-ordered scan phases for a given request budget.
 * @param {number} budget
 * @param {{ hasDirectIp?: boolean }} options
 */
export function buildOutsideInScanPlan(budget, { hasDirectIp = false } = {}) {
  const methods = new Map([
    ['content_type_confusion', 'POST'],
    ['multipart_confusion', 'POST'],
    ['origin_bypass', 'HEAD'],
  ]);
  const availablePhases = OUTSIDE_IN_SCAN_PHASES.filter((phase) => hasDirectIp || phase !== 'origin_bypass');
  const boundedBudget = Number.isInteger(budget) && budget > 0 ? budget : 0;
  const retained = new Set(
    OUTSIDE_IN_PHASE_RETENTION_PRIORITY
      .filter((phase) => availablePhases.includes(phase))
      .slice(0, boundedBudget),
  );
  return availablePhases
    .filter((phase) => retained.has(phase))
    .map((phase) => ({ phase, method: methods.get(phase) ?? 'GET' }));
}

/**
 * @param {{
 *   url: string,
 *   hostname?: string,
 *   directIp?: string,
 *   budget?: number,
 *   timeoutMs?: number,
 *   wafRequired?: boolean,
 *   customerVendorHint?: string,
 *   agentCorroborated?: boolean,
 *   requireAgentForProtected?: boolean,
 *   domXssValidation?: string,
 *   followRedirects?: boolean,
 *   collectNetworkHints?: boolean,
 *   fetchFn?: typeof fetch,
 *   resolveCname?: typeof resolveCname,
 *   resolve4?: typeof resolve4,
 *   tlsConnect?: typeof tls.connect,
 *   tlsHost?: string,
 *   originBypassFn?: (args: object) => Promise<{ res: object|null, error: Error|null }>,
 * }} options
 */
export async function runOutsideInWafScan(options = {}) {
  const url = String(options.url ?? '').trim();
  if (!url) {
    return { error_class: 'unsupported_target', requests_sent: 0, phases: [] };
  }

  const budget = Number.isInteger(options.budget) && options.budget > 0
    ? options.budget
    : OUTSIDE_IN_SCAN_DEFAULT_BUDGET;
  const timeoutMs = Number.isInteger(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : 5000;
  const followRedirects = options.followRedirects === true;
  const collectNetworkHints = options.collectNetworkHints === true;
  const deps = {
    fetchFn: options.fetchFn,
    resolveCname: options.resolveCname,
    resolve4: options.resolve4,
    resolve6: options.resolve6,
    tlsConnect: options.tlsConnect,
    tlsHost: options.tlsHost,
  };
  const started = Date.now();
  let requestsSent = 0;
  const phaseLog = [];
  const markerResults = [];
  const transportErrorClasses = [];

  function recordTransportError(snapshot) {
    const errorClass = String(snapshot?.error_class ?? '').trim();
    if (errorClass && !transportErrorClasses.includes(errorClass)) transportErrorClasses.push(errorClass);
  }

  const directIp = options.directIp ?? null;
  const hostname = options.hostname ?? (() => {
    try { return new URL(url).hostname; } catch { return null; }
  })();
  const plan = buildOutsideInScanPlan(budget, { hasDirectIp: Boolean(directIp && hostname) });
  const plannedPhases = new Set(plan.map((entry) => entry.phase));
  const phasesPlanned = OUTSIDE_IN_SCAN_PHASES.filter(
    (phase) => Boolean(directIp && hostname) || phase !== 'origin_bypass',
  );
  const phasesDropped = phasesPlanned.filter((phase) => !plannedPhases.has(phase));

  const suppliedIps = Array.isArray(options.resolvedIps)
    ? options.resolvedIps.map((ip) => String(ip ?? '').trim()).filter(Boolean)
    : [];
  const suppliedCnameChain = Array.isArray(options.cnameChain)
    ? options.cnameChain.map((name) => normalizeDnsHostname(name)).filter(Boolean)
    : [];
  const [initialDnsHints, tlsHints] = collectNetworkHints
    ? await Promise.all([
        hostname
          ? resolveOutsideInDnsHints(hostname, deps)
          : Promise.resolve({ dns_chain: null, cname_chain: [], resolved_ips: [] }),
        resolveOutsideInTlsHints(url, {
          tlsConnect: deps.tlsConnect,
          connectHost: deps.tlsHost,
          timeoutMs: Math.min(timeoutMs, 3000),
        }),
      ])
    : [{ dns_chain: null, cname_chain: [], resolved_ips: [] }, {}];

  let redirectHops = 0;
  let finalUrlHostname = null;
  let dnsChainHint = initialDnsHints.dns_chain ?? null;
  const dnsCnameChain = [...new Set([...(initialDnsHints.cname_chain ?? []), ...suppliedCnameChain])];
  const dnsResolvedIps = [...new Set([...(initialDnsHints.resolved_ips ?? []), ...suppliedIps])];
  const dnsObserved = collectNetworkHints || suppliedIps.length > 0 || suppliedCnameChain.length > 0;

  async function runGetPhase(phase, requestUrl, headers) {
    if (requestsSent >= budget) return null;
    requestsSent += 1;
    const { res, bodyText, error } = await boundedRequest(requestUrl, { method: 'GET', headers }, timeoutMs, deps);
    const snapshot = error
      ? { ...responseSnapshot(null), error_class: error.name ?? error.code ?? 'probe_failed' }
      : responseSnapshot(res, bodyText);
    recordTransportError(snapshot);
    phaseLog.push({
      phase,
      status_code: snapshot.status_code,
      ...(snapshot.error_class ? { error_class: snapshot.error_class } : {}),
    });
    return snapshot;
  }

  let baseline = null;
  let combined = null;
  let sqli = null;
  let xss = null;
  let pathTraversal = null;
  let noUserAgent = null;

  if (plannedPhases.has('baseline')) {
    if (requestsSent >= budget) {
      return { error_class: 'request_budget_exhausted', requests_sent: requestsSent, phases: phaseLog };
    }
    const baselineResult = await runBaselineGet(url, { ...DEFAULT_BROWSER_HEADERS }, {
      followRedirects,
      timeoutMs,
      requestBudget: budget - requestsSent,
      deps,
    });
    requestsSent += baselineResult.requests_sent;
    baseline = baselineResult.snapshot;
    recordTransportError(baseline);
    redirectHops = baselineResult.redirect_hops;
    finalUrlHostname = baselineResult.final_url_hostname;
    phaseLog.push({
      phase: 'baseline',
      status_code: baseline.status_code,
      redirect_hops: redirectHops,
      ...(baseline.error_class ? { error_class: baseline.error_class } : {}),
    });

    if (
      followRedirects
      && collectNetworkHints
      && finalUrlHostname
      && finalUrlHostname !== hostname
    ) {
      const finalDnsHints = await resolveOutsideInDnsHints(finalUrlHostname, deps);
      if (finalDnsHints.dns_chain) {
        dnsChainHint = [dnsChainHint, finalDnsHints.dns_chain].filter(Boolean).join(' ');
      }
      for (const cname of finalDnsHints.cname_chain ?? []) {
        if (!dnsCnameChain.includes(cname)) dnsCnameChain.push(cname);
      }
      for (const ip of finalDnsHints.resolved_ips ?? []) {
        if (!dnsResolvedIps.includes(ip)) dnsResolvedIps.push(ip);
      }
    }
  }

  if (plannedPhases.has('combined_marker')) {
    const combinedParams = {
      [randomParamName()]: BENIGN_CLASS_MARKERS.xss,
      [randomParamName()]: BENIGN_CLASS_MARKERS.sqli,
      [randomParamName()]: BENIGN_CLASS_MARKERS.path_traversal,
    };
    combined = await runGetPhase('combined_marker', buildUrl(url, { params: combinedParams }), { ...DEFAULT_BROWSER_HEADERS });
    if (combined) {
      const evalResult = isBlockedOrChallenged(combined, baseline);
      recordMarkerResult(markerResults, {
        family: 'combined_marker',
        variant: 'mixed_classes',
        ...evalResult,
        status_code: combined.status_code,
      });
    }
  }

  if (plannedPhases.has('path_traversal_marker')) {
    pathTraversal = await runGetPhase(
      'path_traversal_marker',
      buildUrl(url, { pathSuffix: BENIGN_CLASS_MARKERS.path_traversal }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (pathTraversal) {
      recordMarkerResult(markerResults, {
        family: 'path_traversal_marker',
        variant: 'plain',
        ...isBlockedOrChallenged(pathTraversal, baseline),
        status_code: pathTraversal.status_code,
      });
    }
  }

  if (plannedPhases.has('sqli_marker')) {
    sqli = await runGetPhase(
      'sqli_marker',
      buildUrl(url, { params: { [randomParamName()]: BENIGN_CLASS_MARKERS.sqli } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (sqli) {
      recordMarkerResult(markerResults, {
        family: 'sqli_marker',
        variant: 'plain',
        ...isBlockedOrChallenged(sqli, baseline),
        status_code: sqli.status_code,
      });
    }
  }

  if (plannedPhases.has('sqli_encoded_marker')) {
    const snap = await runGetPhase(
      'sqli_encoded_marker',
      buildUrl(url, { rawParams: { [randomParamName()]: EVASION_VARIANT_MARKERS.sqli_encoded } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (snap) {
      recordMarkerResult(markerResults, {
        family: 'sqli_encoded_marker',
        variant: 'double_url_encoded',
        ...isBlockedOrChallenged(snap, baseline),
        status_code: snap.status_code,
      });
    }
  }

  if (plannedPhases.has('sqli_case_marker')) {
    const snap = await runGetPhase(
      'sqli_case_marker',
      buildUrl(url, { params: { [randomParamName()]: EVASION_VARIANT_MARKERS.sqli_case } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (snap) {
      recordMarkerResult(markerResults, {
        family: 'sqli_case_marker',
        variant: 'case_mixed',
        ...isBlockedOrChallenged(snap, baseline),
        status_code: snap.status_code,
      });
    }
  }

  if (plannedPhases.has('sqli_comment_marker')) {
    const snap = await runGetPhase(
      'sqli_comment_marker',
      buildUrl(url, { params: { [randomParamName()]: EVASION_VARIANT_MARKERS.sqli_comment } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (snap) {
      recordMarkerResult(markerResults, {
        family: 'sqli_comment_marker',
        variant: 'comment_insertion',
        ...isBlockedOrChallenged(snap, baseline),
        status_code: snap.status_code,
      });
    }
  }

  if (plannedPhases.has('xss_marker')) {
    xss = await runGetPhase(
      'xss_marker',
      buildUrl(url, { params: { [randomParamName()]: BENIGN_CLASS_MARKERS.xss } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (xss) {
      recordMarkerResult(markerResults, {
        family: 'xss_marker',
        variant: 'plain',
        ...isBlockedOrChallenged(xss, baseline),
        status_code: xss.status_code,
      });
    }
  }

  if (plannedPhases.has('xss_encoded_marker')) {
    const snap = await runGetPhase(
      'xss_encoded_marker',
      buildUrl(url, { rawParams: { [randomParamName()]: EVASION_VARIANT_MARKERS.xss_encoded } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (snap) {
      recordMarkerResult(markerResults, {
        family: 'xss_encoded_marker',
        variant: 'url_encoded',
        ...isBlockedOrChallenged(snap, baseline),
        status_code: snap.status_code,
      });
    }
  }

  if (plannedPhases.has('no_user_agent')) {
    const noUaHeaders = { ...DEFAULT_BROWSER_HEADERS };
    delete noUaHeaders['User-Agent'];
    noUserAgent = await runGetPhase('no_user_agent', url, noUaHeaders);
  }

  if (plannedPhases.has('content_type_confusion') && requestsSent < budget) {
    requestsSent += 1;
    const formBody = `${randomParamName()}=${encodeURIComponent(BENIGN_CLASS_MARKERS.sqli)}`;
    const { res, bodyText, error } = await boundedRequest(url, {
      method: 'POST',
      headers: {
        ...DEFAULT_BROWSER_HEADERS,
        'Content-Type': 'application/json',
        'Content-Length': String(formBody.length),
      },
      body: formBody,
    }, timeoutMs, deps);
    const snapshot = error
      ? { ...responseSnapshot(null), error_class: error.name ?? error.code ?? 'probe_failed' }
      : responseSnapshot(res, bodyText);
    recordTransportError(snapshot);
    phaseLog.push({
      phase: 'content_type_confusion',
      status_code: snapshot.status_code,
      ...(snapshot.error_class ? { error_class: snapshot.error_class } : {}),
    });
    const contentTypeEval = snapshot.status_code >= 200 && snapshot.status_code < 300
      ? { blocked: false, challenged: false, allowed: true }
      : isBlockedOrChallenged(snapshot, baseline);
    recordMarkerResult(markerResults, {
      family: 'content_type_confusion',
      variant: 'json_header_form_body',
      ...contentTypeEval,
      status_code: snapshot.status_code,
    });
  }

  if (plannedPhases.has('multipart_confusion') && requestsSent < budget) {
    requestsSent += 1;
    const boundary = 'astranullBoundary7f3a';
    const multipartBody = buildMultipartConfusionBody(BENIGN_CLASS_MARKERS.sqli, boundary);
    const { res, bodyText, error } = await boundedRequest(url, {
      method: 'POST',
      headers: {
        ...DEFAULT_BROWSER_HEADERS,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': String(multipartBody.length),
      },
      body: multipartBody,
    }, timeoutMs, deps);
    const snapshot = error
      ? { ...responseSnapshot(null), error_class: error.name ?? error.code ?? 'probe_failed' }
      : responseSnapshot(res, bodyText);
    recordTransportError(snapshot);
    phaseLog.push({
      phase: 'multipart_confusion',
      status_code: snapshot.status_code,
      ...(snapshot.error_class ? { error_class: snapshot.error_class } : {}),
    });
    const multipartEval = snapshot.status_code >= 200 && snapshot.status_code < 300
      ? { blocked: false, challenged: false, allowed: true }
      : isBlockedOrChallenged(snapshot, baseline);
    recordMarkerResult(markerResults, {
      family: 'multipart_confusion',
      variant: 'multipart_form_field',
      ...multipartEval,
      status_code: snapshot.status_code,
    });
  }

  let originBypassConfirmed = false;
  let directOriginReachable = false;
  let originBypassAttempted = false;
  let originBypassStatus = null;
  if (plannedPhases.has('origin_bypass') && directIp && hostname
    && requestsSent < budget && typeof options.originBypassFn === 'function') {
    requestsSent += 1;
    originBypassAttempted = true;
    const { res, error } = await options.originBypassFn({ directIp, hostname, timeoutMs, deps });
    originBypassStatus = error ? 0 : (res?.status ?? 0);
    directOriginReachable = !error && originBypassStatus >= 100;
    originBypassConfirmed = directOriginReachable
      && originBypassStatus >= 200 && originBypassStatus < 400;
    if (error) {
      const errorClass = error.name ?? error.code ?? 'origin_probe_failed';
      if (!transportErrorClasses.includes(errorClass)) transportErrorClasses.push(errorClass);
    }
    phaseLog.push({
      phase: 'origin_bypass',
      status_code: originBypassStatus,
      reachable: directOriginReachable,
      bypass_signal: originBypassConfirmed,
      ...(error ? { error_class: error.name ?? error.code ?? 'origin_probe_failed' } : {}),
    });
  }

  const attackSnapshot = combined ?? sqli ?? xss ?? pathTraversal ?? baseline;
  const generic = detectGenericWafPresence({ baseline, attack: attackSnapshot, noUserAgent });
  const signalSource = attackSnapshot?.header_names?.length >= baseline?.header_names?.length
    ? attackSnapshot
    : baseline;

  // Structured chain data straight from the resolver. Re-splitting the display string lost IPv6
  // addresses and mislabelled every non-IP token as a CNAME.
  const resolvedIps = dnsResolvedIps;
  const cnameChain = dnsCnameChain;
  const genericDetection = {
    ...wafw00fGenericDetection({
      baseline,
      noUserAgent,
      xss,
      pathTraversal,
      sqli,
      combined,
    }),
    corroborated: generic.detected,
  };
  const edgeSignature = classifyEdgeFingerprint({
    normal: wafw00fResponseEvidence(baseline),
    attack: wafw00fResponseEvidence(combined ?? sqli ?? xss ?? pathTraversal),
    resolvedIps,
    cnameChain,
    dnsObserved,
    genericDetection,
  });

  const vendorClassification = evidenceBackedVendorClassification(classifyWafProductFromSignals({
    header_names: [...new Set([...(baseline?.header_names ?? []), ...(signalSource?.header_names ?? [])])],
    cookie_names: [...new Set([...(baseline?.cookie_names ?? []), ...(signalSource?.cookie_names ?? [])])],
    dns_chain: dnsChainHint ?? '',
    block_page_signature_id: attackSnapshot?.block_page_signature_id ?? baseline?.block_page_signature_id ?? null,
    customer_vendor_hint: options.customerVendorHint ?? null,
    waf_present: generic.detected || specificBlockPageDelta(attackSnapshot, baseline),
  }));

  const vendorChainHints = (vendorClassification.candidates ?? []).slice(0, 3).map((candidate) => ({
    vendor: candidate.vendor,
    product: candidate.product,
    confidence: candidate.confidence,
    matched_signals: candidate.matched_signals ?? [],
  }));

  const wafDetected = Boolean(vendorClassification.best) || generic.detected || edgeSignature.waf_present;
  const evasionBypassSuspected = detectEvasionBypass(markerResults);
  const phasesExecuted = phaseLog.map((entry) => entry.phase);
  const coverageComplete = phasesDropped.length === 0
    && transportErrorClasses.length === 0
    && plan.every((entry) => phasesExecuted.includes(entry.phase));
  const posture = buildOutsideInPostureReport({
    wafDetected,
    genericWafDetected: generic.detected,
    markerResults,
    originBypassConfirmed,
    wafRequired: options.wafRequired !== false,
    vendorClassification,
    agentCorroborated: options.agentCorroborated === true,
    requireAgentForProtected: options.requireAgentForProtected !== false,
    evasionBypassSuspected,
    domXssValidation: options.domXssValidation ?? 'agent_required',
    edgeSignature,
    coverageComplete,
    probeErrorsPresent: transportErrorClasses.length > 0,
  });

  const networkFirewall = {
    status: directOriginReachable
      ? 'exposed'
      : originBypassAttempted ? 'inconclusive' : 'not_tested',
    direct_origin_reachability: {
      status: directOriginReachable
        ? 'exposed'
        : originBypassAttempted ? 'inconclusive' : 'not_tested',
      reachable: directOriginReachable,
      application_bypass_confirmed: originBypassConfirmed,
      status_code: originBypassStatus,
    },
    port_exposure: {
      status: 'not_tested',
      open_ports: [],
      tested_count: 0,
      reason: 'separate_bounded_port_scan_required',
    },
  };
  const durationMs = Date.now() - started;
  const scanErrorClass = transportErrorClasses.find((value) => /abort|timeout|deadline/i.test(value))
    ? 'timeout'
    : transportErrorClasses[0] ?? null;
  const external_result = scanErrorClass
    ? (scanErrorClass === 'timeout' ? 'timeout' : 'error')
    : originBypassConfirmed || posture.validation_failed
      ? 'connected'
      : posture.validation_passed || (wafDetected && posture.probe_validation_passed)
        ? 'blocked'
        : 'not_run';

  return {
    duration_ms: durationMs,
    requests_sent: requestsSent,
    phases: phaseLog,
    scan_plan: plan.map((entry) => entry.phase),
    phases_planned: phasesPlanned,
    phases_executed: phasesExecuted,
    phases_dropped: phasesDropped,
    coverage_complete: coverageComplete,
    baseline_status_code: baseline?.status_code ?? 0,
    header_names: signalSource?.header_names ?? baseline?.header_names ?? [],
    cookie_names: signalSource?.cookie_names ?? baseline?.cookie_names ?? [],
    block_page_signature_id: attackSnapshot?.block_page_signature_id ?? null,
    block_page_fingerprint_hash: attackSnapshot?.block_page_fingerprint_hash ?? null,
    generic_waf_reasons: generic.reasons,
    marker_probes: markerResults,
    origin_bypass_confirmed: originBypassConfirmed,
    direct_origin_reachable: directOriginReachable,
    origin_bypass_status_code: originBypassStatus,
    network_firewall: networkFirewall,
    ...(scanErrorClass ? { error_class: scanErrorClass } : {}),
    vendor_candidates: (vendorClassification.candidates ?? []).slice(0, 3),
    ...(collectNetworkHints ? { vendor_chain_hints: vendorChainHints } : {}),
    edge_signature: {
      waf_present: edgeSignature.waf_present,
      waf_providers: edgeSignature.waf_providers,
      waf_generic_detected: edgeSignature.waf_generic_detected,
      cdn_detected: edgeSignature.cdn_detected,
      cdn_providers: edgeSignature.cdn_providers,
      cloud_hosted: edgeSignature.cloud_hosted,
      cloud_providers: edgeSignature.cloud_providers,
      dns_observed: edgeSignature.dns_observed,
      attack_response_evaluated: edgeSignature.attack_response_evaluated,
      wafw00f: edgeSignature.wafw00f,
      cdncheck: edgeSignature.cdncheck,
      conflicting_vendor_signals: edgeSignature.conflicting_vendor_signals,
      conflicting_provider_signals: edgeSignature.conflicting_provider_signals,
      stacked_vendor_signals: edgeSignature.stacked_vendor_signals,
      layers: edgeSignature.layers,
      confidence: edgeSignature.confidence,
      evidence_consistency: edgeSignature.evidence_consistency,
      best_vendor: edgeSignature.best_vendor
        ? {
          vendor: edgeSignature.best_vendor.vendor,
          name: edgeSignature.best_vendor.name,
          confidence: edgeSignature.best_vendor.confidence,
          matched_signals: edgeSignature.best_vendor.matched_signals,
        }
        : null,
      vendor_matches: edgeSignature.vendor_matches.slice(0, 5).map((match) => ({
        vendor: match.vendor,
        name: match.name,
        confidence: match.confidence,
        matched_signals: match.matched_signals,
      })),
      ...(dnsObserved
        ? {
            address_matches: edgeSignature.address_matches,
            cname_matches: edgeSignature.cname_matches,
          }
        : {}),
    },
    edge_signature_corpus_version: EDGE_SIGNATURE_CORPUS_VERSION,
    network_hints_collected: collectNetworkHints,
    redirect_following_enabled: followRedirects,
    ...(dnsObserved
      ? {
          dns_cname_chain: dnsCnameChain,
          dns_resolved_ips: dnsResolvedIps,
        }
      : {}),
    ...(collectNetworkHints
      ? {
          dns_chain_hint: dnsChainHint,
          tls_protocol_hint: tlsHints.tls_protocol_hint ?? null,
          tls_cipher_hint: tlsHints.tls_cipher_hint ?? null,
        }
      : {}),
    redirect_hops: redirectHops,
    final_url_hostname: finalUrlHostname,
    ...posture,
    external_result,
  };
}
