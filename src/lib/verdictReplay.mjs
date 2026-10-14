import { getCheckById } from '../contracts/checks.mjs';
import { correlateExternalOnlyVerdict, probeEventHasProbeIo } from '../services/correlation.mjs';
import {
  SIGNATURE_CORPUS_VERSION,
  VENDOR_DENIAL_SIGNATURES,
  WAF_GRADING_VERSION,
  computeDeclaredSignatureDigest,
  matchControlDenialSignature,
  matchSuspectedVendorSignature,
} from './externalObservationOutcomes.mjs';
import {
  BLOCK_PAGE_SIGNATURE_RULES,
  NON_DENIAL_BLOCK_PAGE_SIGNATURES,
  SIGNATURE_BLOCK_HEADERS,
  SIGNATURE_CHALLENGE_HEADERS,
} from './outsideInWafScanner.mjs';
import {
  gradeMarkerSnapshot,
  enforcementFromGraded,
  isGradedLeg,
  worstEnforcement,
} from './vectorProbes/wafProbeSupport.mjs';
import { blockedBaselinePrerequisite } from './vectorProbes/evasionProbes.mjs';
import { verdictExpectedBehaviorForRun } from './checkDefinitionVersion.mjs';
import { scrubAgentPlacementText, scrubVerdictForCustomer } from './outsideInEvidence.mjs';

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function isSignatureIdInCurrentCorpus(id, kind) {
  if (!id || typeof id !== 'string') return false;
  if (kind === 'vendor_header' || String(id).startsWith('block_header:') || String(id).startsWith('challenge_header:')) {
    if (String(id).startsWith('block_header:')) {
      const headerName = id.slice('block_header:'.length).toLowerCase();
      return Object.hasOwn(SIGNATURE_BLOCK_HEADERS, headerName);
    }
    if (String(id).startsWith('challenge_header:')) {
      const headerName = id.slice('challenge_header:'.length).toLowerCase();
      return Object.hasOwn(SIGNATURE_CHALLENGE_HEADERS, headerName);
    }
    return false;
  }
  if (kind === 'block_page' || String(id).startsWith('block_sig_')) {
    const isRule = BLOCK_PAGE_SIGNATURE_RULES.some((r) => r.id === id);
    return isRule && !NON_DENIAL_BLOCK_PAGE_SIGNATURES.has(id);
  }
  const vendorMatch = VENDOR_DENIAL_SIGNATURES.some((r) => r.id === id);
  if (vendorMatch) return true;
  if (id === 'cloudflare_challenge' || id === 'cloudflare_js_challenge' || id === 'captcha_interstitial') return true;
  return false;
}

function getVendorForSignature(id) {
  if (!id) return null;
  const rule = VENDOR_DENIAL_SIGNATURES.find((r) => r.id === id);
  if (rule?.vendor) return rule.vendor;
  if (String(id).startsWith('block_sig_')) {
    const match = /^block_sig_([a-z0-9]+)_/.exec(String(id));
    return match ? match[1] : null;
  }
  if (String(id).startsWith('challenge_header:') || String(id).startsWith('block_header:')) {
    const headerName = id.split(':')[1];
    return SIGNATURE_CHALLENGE_HEADERS[headerName] ?? SIGNATURE_BLOCK_HEADERS[headerName] ?? null;
  }
  return null;
}

function isChallengeSignature(id) {
  if (!id) return false;
  if (id === 'cloudflare_challenge' || id === 'cloudflare_js_challenge' || id === 'captcha_interstitial') return true;
  if (String(id).startsWith('challenge_header:')) return true;
  const rule = VENDOR_DENIAL_SIGNATURES.find((r) => r.id === id);
  return rule?.challenge === true;
}

function gradeFeature(feature, baseline, declarations) {
  const headers = feature.header_subset ?? {};
  const headerNames = Object.keys(headers).map((k) => k.toLowerCase());
  const snapshot = {
    status_code: feature.status_code,
    headers,
    header_names: headerNames,
    _headerGet: (name) => headers[name.toLowerCase()] ?? null,
    body_length_bucket: feature.body_length_bucket ?? 'lt_8kb',
    location: headers.location ?? null,
    suspected_signature: matchSuspectedVendorSignature({
      statusCode: feature.status_code,
      headers,
      bodyText: '',
    }),
  };
  const graded = gradeMarkerSnapshot(snapshot, baseline);

  if (feature.redirected === true || feature.location_changed === true) {
    graded.redirected = true;
    graded.location_changed = true;
    graded.outcome = 'redirected';
    graded.allowed = false;
    graded.blocked = false;
    graded.challenged = false;
    graded.inconclusive = false;
    delete graded.inconclusive_reason;
    delete graded.block_suspected;
  }

  const basis = feature.signature_basis;
  if (basis && typeof basis === 'object') {
    if (basis.kind === 'declared_header' || basis.kind === 'declared_body') {
      const decl = declarations?.waf?.block_signature;
      const currentDigest = computeDeclaredSignatureDigest(decl);
      const storedDigest = feature.declaration_digest ?? basis.declaration_digest ?? null;
      const digestMatches = Boolean(storedDigest && currentDigest && storedDigest === currentDigest);
      const statusMatches = decl ? (Array.isArray(decl.status_codes) ? decl.status_codes.includes(feature.status_code) : decl.status_code === feature.status_code) : false;
      if (decl && digestMatches && statusMatches) {
        graded.blocked = true;
        graded.inconclusive = false;
        graded.allowed = false;
        graded.challenged = false;
        delete graded.inconclusive_reason;
        delete graded.block_suspected;
        graded.outcome = 'blocked';
        graded.denial_signature = { kind: 'declared', id: decl.id ?? basis.id ?? 'declared_response', vendor: null, declaration_digest: currentDigest };
      }
    } else if (basis.kind === 'vendor_header' || basis.kind === 'vendor_body' || basis.kind === 'block_page') {
      if (!isSignatureIdInCurrentCorpus(basis.id, basis.kind)) {
        graded.inconclusive = true;
        graded.blocked = false;
        graded.allowed = false;
        graded.challenged = false;
        graded.outcome = 'inconclusive';
        graded.inconclusive_reason = 'signature_retired';
        delete graded.denial_signature;
        delete graded.block_suspected;
      } else {
        const challenge = isChallengeSignature(basis.id);
        const vendor = getVendorForSignature(basis.id);
        graded.inconclusive = false;
        graded.allowed = false;
        delete graded.inconclusive_reason;
        delete graded.block_suspected;
        if (challenge) {
          graded.challenged = true;
          graded.blocked = false;
          graded.outcome = 'challenged';
          graded.denial_signature = { kind: 'vendor', id: basis.id, vendor, challenge: true };
        } else {
          graded.blocked = true;
          graded.challenged = false;
          graded.outcome = 'blocked';
          graded.denial_signature = { kind: 'vendor', id: basis.id, vendor };
        }
        if (vendor) graded.matched_vendor = vendor;
      }
    }
  } else if (declarations?.waf?.block_signature) {
    const matchedControl = matchControlDenialSignature({
      statusCode: feature.status_code,
      headers,
      declared: declarations.waf.block_signature,
    });
    if (matchedControl) {
      graded.blocked = true;
      graded.inconclusive = false;
      delete graded.inconclusive_reason;
      delete graded.block_suspected;
      graded.outcome = 'blocked';
      graded.denial_signature = matchedControl;
    }
  }
  return {
    placement: feature.placement,
    path: feature.path ?? null,
    outcome: graded.outcome,
    status_code: feature.status_code,
    signature_id: graded.denial_signature?.id ?? feature.signature_id ?? null,
    cache_status: graded.cache_status ?? null,
    location_changed: graded.location_changed === true,
    ...(graded.inconclusive_reason ? { inconclusive_reason: graded.inconclusive_reason } : {}),
    ...(graded.matched_vendor ? { matched_vendor: graded.matched_vendor } : {}),
    blocked: graded.blocked,
    allowed: graded.allowed,
    challenged: graded.challenged,
    inconclusive: graded.inconclusive,
    error_class: graded.error_class,
    redirected: graded.redirected,
    transport_error: graded.transport_error,
  };
}

// Re-grade placements from stored response features using current grading functions.
function regradePlacementsFromFeatures(features, metadata, declarations, check) {
  if (!Array.isArray(features) || features.length === 0) {
    return { ok: false, reason: 'missing_response_features' };
  }
  const rawBaseline = metadata.baseline ?? metadata.permitted_baseline;
  if (!rawBaseline || rawBaseline.status_code == null) {
    return { ok: false, reason: 'baseline_not_recorded' };
  }
  const baselineHeaders = rawBaseline.header_subset ?? rawBaseline.headers ?? {};
  const baseline = {
    ...rawBaseline,
    status_code: rawBaseline.status_code,
    headers: baselineHeaders,
    header_names: rawBaseline.header_names ?? Object.keys(baselineHeaders).map((k) => k.toLowerCase()),
    _headerGet: (name) => baselineHeaders[name.toLowerCase()] ?? null,
  };

  const isEvasion = check?.probe_profile?.kind === 'waf_evasion_marker_probe' || metadata?.evasion_transform != null;
  const trailingFeature = features.find((f) => f && f.placement === 'trailing_control');
  let sourcePenalized = false;
  let trailingControl = null;
  if (trailingFeature) {
    const gradedTrailing = gradeFeature(trailingFeature, baseline, declarations);
    trailingControl = { outcome: gradedTrailing.outcome, status_code: trailingFeature.status_code };
    sourcePenalized = gradedTrailing.allowed !== true;
  }

  if (isEvasion) {
    const refFeature = features.find((f) => f && f.placement === 'baseline');
    const transFeature = features.find((f) => f && f.placement !== 'baseline' && f.placement !== 'trailing_control');
    if (!refFeature || !transFeature) {
      return { ok: false, reason: 'insufficient_feature_data' };
    }
    const refRow = gradeFeature(refFeature, baseline, declarations);
    const transRow = gradeFeature(transFeature, baseline, declarations);
    const bothGraded = isGradedLeg(refRow) && isGradedLeg(transRow);
    const baselineBlocked = refRow && !refRow.inconclusive && !refRow.transport_error ? refRow.blocked === true : null;
    const prerequisite = blockedBaselinePrerequisite(baselineBlocked);
    const normalizationGap = !sourcePenalized && bothGraded && refRow.blocked === true && transRow.allowed === true;
    const expectedAction = declarations?.waf?.expected_action ?? check?.probe_profile?.expected_action ?? 'block';
    const enforcement = sourcePenalized ? 'unknown' : (normalizationGap ? 'not_enforced' : (transRow.blocked === true ? 'enforced' : 'unknown'));
    return {
      ok: true,
      placements: [refRow, transRow],
      enforcement,
      normalization_gap: normalizationGap,
      reference_outcome: refRow.outcome,
      transform_outcome: transRow.outcome,
      reference_not_enforced: refRow.allowed === true,
      blocked_baseline_prerequisite: prerequisite,
      source_penalized: sourcePenalized,
      trailing_control: trailingControl,
    };
  }

  const markerFeatures = features.filter((f) => f && f.placement !== 'baseline' && f.placement !== 'trailing_control');
  if (markerFeatures.length === 0) {
    return { ok: false, reason: 'insufficient_feature_data' };
  }
  for (const feature of markerFeatures) {
    if (typeof feature !== 'object' || feature.status_code == null) {
      return { ok: false, reason: 'insufficient_feature_data' };
    }
  }

  const baselineForPath = (path) => {
    const fromFeatures = features.find((f) => f && f.placement === 'baseline' && f.path === path);
    if (fromFeatures) {
      const bHeaders = fromFeatures.header_subset ?? fromFeatures.headers ?? {};
      return {
        ...fromFeatures,
        status_code: fromFeatures.status_code,
        headers: bHeaders,
        header_names: fromFeatures.header_names ?? Object.keys(bHeaders).map((k) => k.toLowerCase()),
        _headerGet: (name) => bHeaders[name.toLowerCase()] ?? null,
      };
    }
    const fromPaths = (metadata.paths ?? []).find((pr) => pr.path === path)?.baseline;
    if (fromPaths) {
      const bHeaders = fromPaths.header_subset ?? fromPaths.headers ?? {};
      return {
        ...fromPaths,
        status_code: fromPaths.status_code,
        headers: bHeaders,
        header_names: fromPaths.header_names ?? Object.keys(bHeaders).map((k) => k.toLowerCase()),
        _headerGet: (name) => bHeaders[name.toLowerCase()] ?? null,
      };
    }
    return baseline;
  };

  const pathMap = new Map();
  const regradedPlacements = [];
  for (const feature of markerFeatures) {
    const p = feature.path ?? '/';
    const pathBaseline = baselineForPath(p);
    const row = gradeFeature(feature, pathBaseline, declarations);

    const isOldFormat = !Object.hasOwn(feature, 'signature_basis') || feature.signature_basis === undefined;
    if (isOldFormat) {
      if (feature.signature_id && row.signature_id !== feature.signature_id) {
        return { ok: false, reason: 'insufficient_features' };
      }
      if (feature.status_code >= 300 && feature.status_code < 400 && feature.redirected == null && feature.location_changed == null && !row.redirected) {
        return { ok: false, reason: 'insufficient_features' };
      }
      if (declarations?.waf?.block_signature && !row.blocked) {
        const decl = declarations.waf.block_signature;
        const statusMatches = Array.isArray(decl.status_codes) ? decl.status_codes.includes(feature.status_code) : decl.status_code === feature.status_code;
        if (statusMatches) return { ok: false, reason: 'insufficient_features' };
      }
      const originalLeg = (metadata.placements ?? []).find((pl) => {
        if (!pl || pl.placement !== feature.placement) return false;
        if (pl.path == null) return true;
        return (pl.path ?? '/') === p;
      });
      if (originalLeg && (originalLeg.outcome === 'blocked' || originalLeg.outcome === 'redirected') && row.outcome !== originalLeg.outcome && !feature.redirected && !feature.location_changed) {
        return { ok: false, reason: 'insufficient_features' };
      }
    }

    if (!pathMap.has(p)) pathMap.set(p, []);
    pathMap.get(p).push(row);
    regradedPlacements.push(row);
  }

  const expectedAction = declarations?.waf?.expected_action
    ?? check?.probe_profile?.expected_action
    ?? 'block';

  let enforcement;
  if (sourcePenalized) {
    enforcement = 'unknown';
  } else if (pathMap.size > 1) {
    const pathEnforcements = [];
    for (const [, rows] of pathMap) {
      const gradedForPath = rows.filter(isGradedLeg);
      pathEnforcements.push(enforcementFromGraded(gradedForPath, { expectedAction }));
    }
    enforcement = worstEnforcement(pathEnforcements);
  } else {
    const graded = regradedPlacements.filter(isGradedLeg);
    enforcement = enforcementFromGraded(graded, { expectedAction });
  }

  return {
    ok: true,
    placements: regradedPlacements,
    enforcement,
    source_penalized: sourcePenalized,
    trailing_control: trailingControl,
  };
}

// Re-run correlation on stored (redacted) response features. Does not modify correlation.
export function rederiveVerdict(evidenceRecord = {}) {
  const metadata = { ...asObject(evidenceRecord.metadata ?? evidenceRecord.metadata_json) };
  delete metadata.declarations;
  delete metadata.expected_behavior;
  delete metadata.declared_limit;
  const features = evidenceRecord.response_features ?? metadata.response_features ?? null;
  let regraded = false;
  let regradeUnavailableReason = null;
  if (features != null) {
    metadata.response_features = features;
    const check = getCheckById(evidenceRecord.check_id ?? metadata.check_id);
    const regradeResult = regradePlacementsFromFeatures(features, metadata, evidenceRecord.declarations, check);
    if (regradeResult.ok) {
      regraded = true;
      metadata.placements = regradeResult.placements;
      metadata.enforcement = regradeResult.enforcement;
      if (regradeResult.normalization_gap !== undefined) {
        metadata.normalization_gap = regradeResult.normalization_gap;
        metadata.reference_outcome = regradeResult.reference_outcome;
        metadata.transform_outcome = regradeResult.transform_outcome;
        metadata.reference_not_enforced = regradeResult.reference_not_enforced;
        metadata.blocked_baseline_prerequisite = regradeResult.blocked_baseline_prerequisite;
      }
      if (regradeResult.source_penalized !== undefined) {
        metadata.source_penalized = regradeResult.source_penalized;
      }
      if (regradeResult.trailing_control !== undefined) {
        metadata.trailing_control = regradeResult.trailing_control;
      }
    } else {
      regraded = false;
      regradeUnavailableReason = regradeResult.reason;
    }
  } else {
    regraded = false;
    regradeUnavailableReason = 'missing_response_features';
  }
  const probeKind = evidenceRecord.probe_kind ?? metadata.probe_kind ?? metadata.profile_kind ?? null;
  const derived = correlateExternalOnlyVerdict({
    externalResult: evidenceRecord.external_result ?? metadata.external_result ?? null,
    expectedBehavior: evidenceRecord.expected_behavior ?? null,
    probeKind,
    probeIoObserved: evidenceRecord.probe_io_observed
      ?? (Number.isSafeInteger(metadata.safety_attestation?.probe_requests_sent)
        && metadata.safety_attestation.probe_requests_sent > 0),
    probeMetadata: metadata,
    declarations: evidenceRecord.declarations ?? null,
    originBinding: evidenceRecord.origin_binding ?? null,
    checkId: evidenceRecord.check_id ?? metadata.check_id ?? null,
  });
  const recorded = evidenceRecord.verdict ?? evidenceRecord.recorded_verdict ?? null;
  const recordedValue = typeof recorded === 'string' ? recorded : recorded?.verdict ?? null;
  if (regraded && recordedValue && recordedValue !== derived.verdict) {
    const hasOldFeatures = (features ?? []).some((f) => f && (!Object.hasOwn(f, 'signature_basis') || f.signature_basis === undefined));
    if (hasOldFeatures) {
      regraded = false;
      regradeUnavailableReason = 'insufficient_features';
    }
  }
  const derivedVerdict = regradeUnavailableReason === 'insufficient_features'
    ? (recordedValue ?? derived.verdict)
    : derived.verdict;
  const versionGap = gradingVersionGap(storedVerdictView(evidenceRecord), metadata);
  const retestRequired = regradeUnavailableReason === 'insufficient_features' && Boolean(versionGap);
  return {
    derived: {
      ...derived,
      verdict: derivedVerdict,
      ...(retestRequired ? { retest_required: true } : {}),
    },
    recorded: recordedValue,
    matches: recordedValue == null ? null : derivedVerdict === recordedValue,
    replayable: features != null || metadata.placements != null,
    grading_version: evidenceRecord.grading_version ?? metadata.grading_version ?? null,
    signature_corpus_version: evidenceRecord.signature_corpus_version ?? metadata.signature_corpus_version ?? null,
    regraded,
    ...(regradeUnavailableReason ? { regrade_unavailable_reason: regradeUnavailableReason } : {}),
    ...(retestRequired ? { retest_required: true } : {}),
  };
}

function storedVerdictView(rawVerdict) {
  if (!rawVerdict) return null;
  const verdict = scrubVerdictForCustomer(rawVerdict);
  const placement = asObject(rawVerdict.placement_confidence);
  return {
    id: verdict.id ?? null,
    verdict: verdict.verdict ?? null,
    confidence: verdict.confidence ?? null,
    explanation: verdict.explanation ?? null,
    grading_version: verdict.grading_version ?? placement.grading_version ?? null,
    signature_corpus_version: verdict.signature_corpus_version ?? placement.signature_corpus_version ?? null,
    created_at: verdict.created_at ?? null,
  };
}

function gradingVersionGap(stored, metadata) {
  const grading = stored?.grading_version ?? metadata.grading_version ?? null;
  const corpus = stored?.signature_corpus_version ?? metadata.signature_corpus_version ?? null;
  if (grading == null && corpus == null) return null;
  if (!grading) return 'missing_grading_version';
  if (grading !== WAF_GRADING_VERSION) return 'grading_version_mismatch';
  if (!corpus) return 'missing_signature_corpus_version';
  if (corpus !== SIGNATURE_CORPUS_VERSION) return 'signature_corpus_version_mismatch';
  return null;
}

// Read-only replay: stored evidence plus current declarations, correlated as finalize does.
export function buildVerdictReplay({ run, storedVerdict = null, probeEvent = null, declarations = null, originBinding = null }) {
  const check = getCheckById(run.check_id);
  const metadata = asObject(probeEvent?.metadata ?? probeEvent?.metadata_json);
  const features = metadata.response_features ?? probeEvent?.response_features ?? run?.probe_metadata?.response_features ?? null;
  let regraded = false;
  let regradeUnavailableReason = null;
  const replayMetadata = { ...metadata };
  delete replayMetadata.declarations;
  delete replayMetadata.expected_behavior;
  delete replayMetadata.declared_limit;
  let regradeResult = null;
  if (features) {
    regradeResult = regradePlacementsFromFeatures(features, metadata, declarations, check);
    if (regradeResult.ok) {
      regraded = true;
      replayMetadata.placements = regradeResult.placements;
      replayMetadata.enforcement = regradeResult.enforcement;
      if (regradeResult.normalization_gap !== undefined) {
        replayMetadata.normalization_gap = regradeResult.normalization_gap;
        replayMetadata.reference_outcome = regradeResult.reference_outcome;
        replayMetadata.transform_outcome = regradeResult.transform_outcome;
        replayMetadata.reference_not_enforced = regradeResult.reference_not_enforced;
        replayMetadata.blocked_baseline_prerequisite = regradeResult.blocked_baseline_prerequisite;
      }
      if (regradeResult.source_penalized !== undefined) {
        replayMetadata.source_penalized = regradeResult.source_penalized;
      }
      if (regradeResult.trailing_control !== undefined) {
        replayMetadata.trailing_control = regradeResult.trailing_control;
      }
    } else {
      regraded = false;
      regradeUnavailableReason = regradeResult.reason;
    }
  } else {
    regraded = false;
    regradeUnavailableReason = 'missing_response_features';
  }

  const derived = correlateExternalOnlyVerdict({
    externalResult: run.probe_external_result ?? metadata.external_result ?? null,
    expectedBehavior: verdictExpectedBehaviorForRun(run),
    probeKind: check?.probe_profile?.kind ?? null,
    probeIoObserved: probeEventHasProbeIo(probeEvent),
    probeMetadata: replayMetadata,
    declarations: declarations ?? null,
    originBinding,
    checkId: run.check_id,
  });
  const stored = storedVerdictView(storedVerdict);
  if (regraded && stored && stored.verdict !== derived.verdict) {
    const hasOldFeatures = (features ?? []).some((f) => f && (!Object.hasOwn(f, 'signature_basis') || f.signature_basis === undefined));
    if (hasOldFeatures) {
      regraded = false;
      regradeUnavailableReason = 'insufficient_features';
    }
  }
  const rederivedVerdict = regradeUnavailableReason === 'insufficient_features'
    ? (stored?.verdict ?? derived.verdict)
    : derived.verdict;
  const changed = regradeUnavailableReason === 'insufficient_features'
    ? false
    : (stored ? stored.verdict !== rederivedVerdict : null);
  const versionGap = gradingVersionGap(stored, metadata);
  const retestRequired = regradeUnavailableReason === 'insufficient_features' && Boolean(versionGap);
  return {
    test_run_id: run.id,
    check_id: run.check_id,
    stored,
    rederived: {
      verdict: rederivedVerdict,
      confidence: derived.confidence ?? null,
      explanation: derived.explanation == null ? null : scrubAgentPlacementText(derived.explanation),
      severity: derived.severity ?? null,
      creates_finding: derived.createsFinding === true,
      grading_version: WAF_GRADING_VERSION,
      signature_corpus_version: SIGNATURE_CORPUS_VERSION,
      declarations_applied: Boolean(declarations),
      evidence_available: Boolean(probeEvent),
      regraded,
      ...(regradeUnavailableReason ? { regrade_unavailable_reason: regradeUnavailableReason } : {}),
      ...(retestRequired ? { retest_required: true } : {}),
    },
    changed,
    grading_version_gap: versionGap,
    regraded,
    placements: regradeResult?.placements ?? replayMetadata.placements ?? null,
    ...(regradeUnavailableReason ? { regrade_unavailable_reason: regradeUnavailableReason } : {}),
    ...(retestRequired ? { retest_required: true } : {}),
  };
}
