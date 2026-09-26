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

const VERDICT_LABELS = Object.freeze({
  protected: 'Protection stopped the test traffic',
  pass: 'Protection worked as expected',
  passed: 'Protection worked as expected',
  success: 'Protection worked as expected',
  ok: 'Protection worked as expected',
  bypassable: 'A bypass path reached your server',
  penetrated: 'Attack traffic reached your server',
  gap: 'Protection did not work as expected',
  fail: 'Protection did not work as expected',
  failed: 'Protection did not work as expected',
  unprotected: 'No effective protection was observed',
  inconclusive: 'Not enough evidence',
  review: 'Needs review',
  manual_review: 'Needs review',
  partial: 'Only partly verified',
  misplaced: 'The observation agent is in the wrong place',
  misplaced_agent: 'The observation agent is in the wrong place',
  unknown: 'No conclusion yet',
});

const VERDICT_DESCRIPTIONS = Object.freeze({
  protected: 'The tested traffic was stopped before it reached the protected server.',
  bypassable: 'The safe test marker reached the protected environment through a bypass path.',
  penetrated: 'Evidence confirms that the safe test traffic reached the protected server.',
  inconclusive: 'The available probe and internal observations cannot prove an outcome.',
  misplaced: 'The agent or canary could not observe the declared protected path reliably.',
  misplaced_agent: 'The agent or canary could not observe the declared protected path reliably.',
});

export function plainVerdictLabel(value) {
  const key = normalize(value);
  return VERDICT_LABELS[key] ?? sentenceLabel(value);
}

export function plainVerdictDescription(value) {
  const key = normalize(value);
  return VERDICT_DESCRIPTIONS[key] ?? '';
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

export function evidenceModePresentation(value) {
  const record = asRecord(value) ?? {};
  const metadata = nestedRecord(record, 'metadata');
  const profile = nestedRecord(record, 'probe_profile');
  const tier = evidenceTierInfo(firstValue(record, ['evidence_tier', 'evidence_level', 'tier'])
    || firstValue(metadata, ['evidence_tier', 'evidence_level', 'tier']));
  const probeKind = normalize(
    firstValue(record, ['probe_kind', 'profile_kind'])
      || firstValue(metadata, ['probe_kind', 'profile_kind'])
      || firstValue(profile, ['kind']),
  );
  const evidenceIds = Array.isArray(record.evidence_ids) ? record.evidence_ids.filter(Boolean) : [];
  const hasResult = evidenceIds.length > 0
    || Boolean(firstValue(record, ['last_run_id', 'run_id']))
      && !['', 'unknown', 'pending'].includes(normalize(firstValue(record, ['last_verdict', 'verdict'])));

  if (probeKind === 'metadata_marker' || tier?.code === 'E1') {
    return {
      label: 'Not tested live',
      detail: 'Needs your evidence before AstraNull can verify protection.',
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
  if (tier?.code === 'E2' || tier?.code === 'E3' || probeKind) {
    return {
      label: hasResult ? 'Tested live' : 'Live check available',
      detail: tier?.description ?? 'A bounded probe can collect live evidence for this check.',
      tone: hasResult ? 'success' : 'info',
      live: hasResult,
      code: tier?.code ?? '',
    };
  }
  if (hasResult) {
    return {
      label: 'Evidence recorded',
      detail: 'The API returned evidence, but did not report whether the check ran live.',
      tone: 'info',
      live: false,
      code: '',
    };
  }
  return {
    label: 'Evidence level not reported',
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
