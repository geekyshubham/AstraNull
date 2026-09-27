const EVIDENCE_TIERS = Object.freeze([
  Object.freeze({
    code: 'E1',
    label: 'Declared only',
    description: 'Customer-provided information. Not tested live; supporting evidence is still needed.',
  }),
  Object.freeze({
    code: 'E2',
    label: 'Connection observed',
    description: 'A bounded live check observed network behavior, not application-level protection.',
  }),
  Object.freeze({
    code: 'E3',
    label: 'Behavior observed',
    description: 'A bounded live check observed an application or protection behavior.',
  }),
  Object.freeze({
    code: 'E4',
    label: 'SOC-governed',
    description: 'An authorized high-scale validation that only AstraNull SOC can coordinate.',
  }),
  Object.freeze({
    code: 'E5',
    label: 'Monitoring only',
    description: 'No active check. The conclusion depends on monitoring or integration evidence.',
  }),
]);

export { EVIDENCE_TIERS };

function normalize(value) {
  return String(value ?? '').trim().toLowerCase().replaceAll('-', '_');
}

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function firstValue(record, keys) {
  for (const key of keys) {
    const value = record?.[key];
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return '';
}

function nestedRecord(record, key) {
  return asRecord(record?.[key]) ?? {};
}

function sentenceLabel(value) {
  const text = String(value ?? '').trim().replaceAll('_', ' ').replaceAll('-', ' ');
  if (!text) return 'Not reported';
  return `${text.charAt(0).toUpperCase()}${text.slice(1)}`;
}

const MACHINE_CODE_RE = /^[a-z]+(?:_[a-z0-9]+)+$/;
const EMPTY_REASON_COPY = Object.freeze({
  coverage_summary_not_populated: 'WAF coverage will appear after a declared WAF asset records evidence.',
});

export function plainCodeLabel(value, fallback = 'Not reported') {
  const text = String(value ?? '').trim();
  if (!text) return fallback;
  const labels = {
    fqdn: 'Domain name',
    must_block_before_origin: 'Block before the origin server',
    should_be_protected: 'Should be protected',
  };
  const key = normalize(text);
  if (labels[key]) return labels[key];
  const words = text.replaceAll('_', ' ');
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

export function plainEmptyReason(value) {
  const text = String(value ?? '').trim();
  if (!text) return '';
  if (!MACHINE_CODE_RE.test(text)) return text;
  return EMPTY_REASON_COPY[text] ?? `${sentenceLabel(text)}.`;
}

const VISIBLE_RECORD_ID_RE = /^(?:tgt|tg|run|fnd|evt|agt|env|rpt|scan|usr|ten|wof|id|job|evd|btok|dns)_/;

export function plainInlineText(value) {
  const text = String(value ?? '');
  return text.replace(/\b[a-z]+(?:_[a-z0-9]+)+\b/g, (token, offset) => {
    if (VISIBLE_RECORD_ID_RE.test(token)) return token;
    const before = text.slice(0, offset);
    const start = before.match(/[a-z0-9_.-]+$/i)?.[0] ?? '';
    const after = text.slice(offset + token.length).match(/^[a-z0-9_.-]+/i)?.[0] ?? '';
    const envelope = `${start}${token}${after}`.replace(/^\.+|\.+$/g, '');
    if (/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/i.test(envelope)) return token;
    const label = plainCodeLabel(token);
    return offset === 0 || /[.!?:]\s*$/.test(before)
      ? label
      : `${label.charAt(0).toLowerCase()}${label.slice(1)}`;
  });
}

export function plainCheckName(value) {
  return String(value ?? '')
    .trim()
    .replace(/\bWAF\s*\/\s*API[- ]?Gateway\b/gi, 'WAF application gateway')
    .replace(/\bL7\s*\/\s*API\b/gi, 'application layer')
    .replace(/\bAPI[- ]?Gateway\b/gi, 'application gateway')
    .replace(/\bAPI\b/g, 'application interface');
}

const VERDICT_LABELS = Object.freeze({
  protected: 'Protection stopped the test traffic',
  pass: 'Protection worked as expected',
  passed: 'Protection worked as expected',
  success: 'Protection worked as expected',
  ok: 'Protection worked as expected',
  bypassable: 'A bypass path reached your server',
  penetrated: 'Attack traffic reached your server',
  edge_exposed: 'Direct server access was found',
  exposed: 'Direct server access was found',
  allowed_as_expected: 'The tested traffic behaved as expected',
  gap: 'Protection did not work as expected',
  fail: 'Protection did not work as expected',
  failed: 'Protection did not work as expected',
  unprotected: 'No effective protection was observed',
  inconclusive: 'Not enough evidence',
  review: 'Needs review',
  manual_review: 'Needs review',
  partial: 'Only partly verified',
  // Pill-length labels; the full meaning lives in VERDICT_DESCRIPTIONS.
  misplaced: 'Agent did not see the test',
  misplaced_agent: 'Agent did not see the test',
  edge_protected: 'Blocked at the edge',
  unknown: 'No conclusion yet',
});

const VERDICT_DESCRIPTIONS = Object.freeze({
  protected: 'The tested traffic was stopped before it reached the protected server.',
  bypassable: 'The safe test marker reached the protected environment through a bypass path.',
  penetrated: 'Evidence confirms that the safe test traffic reached the protected server.',
  inconclusive: 'The available probe and internal observations cannot prove an outcome.',
  misplaced: 'The agent or canary could not observe the declared protected path reliably.',
  misplaced_agent: 'The agent or canary could not observe the declared protected path reliably.',
  edge_protected: 'The edge blocked the test traffic; no inside agent confirmed it, so this is external evidence only.',
});

export function plainVerdictLabel(value) {
  const key = normalize(value);
  return VERDICT_LABELS[key] ?? sentenceLabel(value);
}

export function plainVerdictDescription(value) {
  const key = normalize(value);
  return VERDICT_DESCRIPTIONS[key] ?? '';
}

function recordString(record, keys) {
  return String(firstValue(record, keys) ?? '').trim();
}

export function plainFindingTitle(value, targets = [], checks = []) {
  const finding = asRecord(value) ?? {};
  const rawTitle = recordString(finding, ['title', 'summary', 'label']);
  const generated = rawTitle.match(/^Finding:\s*([a-z][a-z0-9_-]*)\s+on\s+(.+)$/i);
  const nestedVerdict = nestedRecord(finding, 'verdict');
  const directVerdict = typeof finding.verdict === 'string' ? finding.verdict.trim() : '';
  const verdict = directVerdict
    || recordString(finding, ['outcome', 'result', 'reason_code'])
    || recordString(nestedVerdict, ['verdict', 'result', 'status'])
    || generated?.[1]
    || '';
  const targetId = recordString(finding, ['target_id']) || generated?.[2] || '';
  const embeddedTarget = asRecord(finding.target);
  const target = (Array.isArray(targets) ? targets : []).map(asRecord).find((entry) => recordString(entry, ['id', 'target_id']) === targetId);
  const targetName = recordString(finding, ['target_hostname', 'target_value'])
    || recordString(embeddedTarget, ['hostname', 'value', 'name', 'label'])
    || recordString(target, ['hostname', 'value', 'name', 'label'])
    || generated?.[2]
    || targetId;
  const checkId = recordString(finding, ['check_id']);
  const check = (Array.isArray(checks) ? checks : []).map(asRecord).find((entry) => recordString(entry, ['check_id', 'id']) === checkId);
  const checkName = plainCheckName(recordString(check, ['name', 'title']) || checkId);

  if (generated || (!rawTitle && verdict)) {
    const outcome = plainVerdictLabel(verdict || generated?.[1]);
    return targetName ? `${outcome} on ${targetName}` : outcome;
  }
  if (rawTitle) {
    const namedTitle = targetId && targetName ? rawTitle.replaceAll(targetId, targetName) : rawTitle;
    const plainTitle = plainCheckName(namedTitle);
    return targetName && targetName !== targetId && !plainTitle.toLowerCase().includes(targetName.toLowerCase())
      ? `${plainTitle} · ${targetName}`
      : plainTitle;
  }
  if (checkName && targetName) return `${checkName} on ${targetName}`;
  return checkName || targetName || 'Evidence-backed finding';
}

const VERIFICATION_LABELS = Object.freeze({
  unverified: 'Ownership not verified',
  pending: 'Verification in progress',
  dns_pending: 'Domain verification in progress',
  checking: 'Checking ownership',
  awaiting_heartbeat: 'Waiting for inside observation',
  pending_agent: 'Waiting for inside observation',
  dns_verified: 'Domain ownership verified',
  provider_verified: 'Provider account verified',
  agent_verified: 'Observed from inside',
  user_confirmed: 'Owner confirmed',
  verified: 'Ownership verified',
});

export function plainVerificationLabel(value) {
  return VERIFICATION_LABELS[normalize(value)] ?? sentenceLabel(value);
}

const PROTECTION_LABELS = Object.freeze({
  protected: 'Protection worked',
  edge_protected: 'Blocked at the edge only',
  underprotected: 'Protection needs work',
  unprotected: 'No effective WAF protection observed',
  unknown: 'Not enough evidence',
  detected: 'Detected',
  not_detected: 'Not detected in this check',
  inconclusive: 'Not enough evidence',
  error: 'Check could not complete',
  pending: 'Check in progress',
  not_exposed: 'No direct path found in the last check',
  exposed: 'Direct server access found',
  suspected: 'Possible direct server access',
  active: 'Connected',
  degraded: 'Needs attention',
  disabled: 'Disabled',
  none: 'None reported',
});

export function plainProtectionLabel(value) {
  return PROTECTION_LABELS[normalize(value)] ?? sentenceLabel(value);
}

export function evidenceTierInfo(value) {
  const normalized = String(value ?? '').trim().toUpperCase();
  const code = normalized.match(/E[1-5]/)?.[0] ?? '';
  return EVIDENCE_TIERS.find((tier) => tier.code === code) ?? null;
}

export function evidenceModePresentation(value, catalogCheck = null) {
  const record = asRecord(value) ?? {};
  const check = asRecord(catalogCheck) ?? {};
  const metadata = nestedRecord(record, 'metadata');
  const profile = nestedRecord(record, 'probe_profile');
  const checkMetadata = nestedRecord(check, 'metadata');
  const checkProfile = nestedRecord(check, 'probe_profile');
  const tier = evidenceTierInfo(firstValue(record, ['evidence_tier', 'evidence_level', 'tier'])
    || firstValue(metadata, ['evidence_tier', 'evidence_level', 'tier'])
    || firstValue(check, ['evidence_tier', 'evidence_level', 'tier'])
    || firstValue(checkMetadata, ['evidence_tier', 'evidence_level', 'tier']));
  const probeKind = normalize(
    firstValue(record, ['probe_kind', 'profile_kind'])
      || firstValue(metadata, ['probe_kind', 'profile_kind'])
      || firstValue(profile, ['kind'])
      || firstValue(check, ['probe_kind', 'profile_kind'])
      || firstValue(checkMetadata, ['probe_kind', 'profile_kind'])
      || firstValue(checkProfile, ['kind']),
  );
  const nestedVerdict = nestedRecord(record, 'verdict');
  const evidenceIds = [
    ...(Array.isArray(record.evidence_ids) ? record.evidence_ids : []),
    ...(Array.isArray(nestedVerdict.evidence_ids) ? nestedVerdict.evidence_ids : []),
  ].filter(Boolean);
  const hasEvidenceReference = evidenceIds.length > 0;
  const hasPublishedLastResult = Boolean(firstValue(record, ['last_run_id']))
    && !['', 'unknown', 'pending'].includes(normalize(firstValue(record, ['last_verdict'])));
  const hasResult = hasEvidenceReference || hasPublishedLastResult;

  if (['metadata_marker', 'none', 'ops_readiness'].includes(probeKind) || tier?.code === 'E1') {
    return {
      label: 'Declaration only',
      detail: 'No live traffic was sent for this check.',
      tone: 'warn',
      live: false,
      code: tier?.code ?? 'E1',
    };
  }
  if (tier?.code === 'E4') {
    return {
      label: 'SOC-governed only',
      detail: tier.description,
      tone: 'info',
      live: false,
      code: tier.code,
    };
  }
  if (tier?.code === 'E5') {
    return {
      label: 'Monitoring only',
      detail: tier.description,
      tone: 'muted',
      live: false,
      code: tier.code,
    };
  }
  if (probeKind || tier?.code === 'E2' || tier?.code === 'E3') {
    return {
      label: hasResult ? 'Tested live (bounded)' : 'Bounded live check available',
      detail: hasResult
        ? 'A bounded check recorded evidence for this run.'
        : tier?.description ?? 'A bounded check can collect live evidence.',
      tone: hasResult ? 'success' : 'info',
      live: hasResult,
      code: tier?.code ?? '',
    };
  }
  if (hasResult) {
    return {
      label: 'Evidence recorded',
      detail: 'Evidence was recorded, but the test method was not identified.',
      tone: 'info',
      live: false,
      code: '',
    };
  }
  return {
    label: 'Test method not reported',
    detail: 'Open the check definition before treating this as a live test.',
    tone: 'muted',
    live: false,
    code: '',
  };
}

export function dashboardReadinessMessage({ score, highPriorityFindings = 0, coveragePercent = null, dataUnavailable = false } = {}) {
  if (dataUnavailable || typeof score !== 'number' || !Number.isFinite(score)) {
    return {
      headline: 'Readiness is not known yet',
      detail: 'Required readiness or evidence data is unavailable.',
      tone: 'warn',
    };
  }
  if (highPriorityFindings > 0) {
    return {
      headline: 'Not ready yet: high-priority gaps remain',
      detail: 'Resolve the evidence-backed gaps below, then run the same checks again.',
      tone: 'danger',
    };
  }
  if (typeof coveragePercent !== 'number' || coveragePercent < 100) {
    return {
      headline: 'Partly ready: some services still need evidence',
      detail: 'This answer covers only services with evidence-backed results.',
      tone: 'warn',
    };
  }
  if (score >= 80) {
    return {
      headline: 'Ready for the scenarios tested',
      detail: 'Keep checks current. This does not claim readiness for untested scenarios.',
      tone: 'success',
    };
  }
  if (score >= 55) {
    return {
      headline: 'Partly ready for the scenarios tested',
      detail: 'Some tested protections need attention before the next review.',
      tone: 'warn',
    };
  }
  return {
    headline: 'Not ready for the scenarios tested',
    detail: 'The evidence-backed score shows material gaps in tested protection paths.',
    tone: 'danger',
  };
}
