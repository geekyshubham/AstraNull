const RUN_VERIFICATION_STATES = new Set(['dns_verified', 'provider_verified', 'agent_verified', 'user_confirmed', 'verified']);
const LOA_SCOPE_STATES = new Set(['agent_verified', 'user_confirmed']);
const SIGNED_LOA_STATES = new Set(['signed', 'active', 'valid']);

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function firstString(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const normalized = String(value).trim();
    if (normalized) return normalized;
  }
  return '';
}

function normalize(value) {
  return firstString(value).toLowerCase();
}

function humanize(value) {
  const normalized = firstString(value).replace(/[_-]+/g, ' ');
  if (!normalized) return '';
  const label = `${normalized.charAt(0).toUpperCase()}${normalized.slice(1)}`;
  return label.replace(/\b(api|cdn|csv|dns|ip|tcp|udp|waf)\b/gi, (token) => token.toUpperCase());
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  const record = asRecord(value);
  if (!record) return value;
  return Object.fromEntries(Object.keys(record).sort().map((key) => [key, stableValue(record[key])]));
}

/** A target is runnable only when both API eligibility and ownership are explicitly affirmative. */
export function isTargetRunEligible(eligibility, verificationState) {
  return normalize(eligibility) === 'eligible' && RUN_VERIFICATION_STATES.has(normalize(verificationState));
}

/** Mirrors the current LOA service contract: DNS verification alone is not enough for signed scope. */
export function isLoaScopeEligible(verificationState) {
  return LOA_SCOPE_STATES.has(normalize(verificationState));
}

export function isSignedLoaState(state) {
  return SIGNED_LOA_STATES.has(normalize(state));
}

/** Missing/invalid expiry fails closed rather than treating an old pending record as active. */
export function isActiveDnsChallenge(challenge, now = Date.now()) {
  const record = asRecord(challenge);
  if (!record || normalize(record.state) !== 'pending') return false;
  const expiresAt = Date.parse(firstString(record.expires_at));
  return Number.isFinite(expiresAt) && expiresAt > now;
}

export function apiErrorCode(error) {
  const record = asRecord(error);
  const payload = asRecord(record?.payload);
  return normalize(payload?.error ?? record?.code);
}

/** Human-readable declaration provenance without presenting connector IDs as provider names. */
export function targetDeclarationProvenanceLabel(target) {
  const record = asRecord(target) ?? {};
  const metadata = asRecord(record.metadata) ?? asRecord(record.metadata_json) ?? {};
  const source = normalize(record.source ?? record.declaration_source ?? record.source_kind ?? metadata.source ?? metadata.target_source);
  const integration = firstString(
    record.import_integration,
    record.import_source,
    metadata.import_integration,
    metadata.import_source,
  );
  const connectorId = firstString(record.connector_id, metadata.connector_id);
  const imported = source === 'import'
    || source === 'connector_inventory'
    || source === 'cloud_inventory'
    || Boolean(integration)
    || Boolean(connectorId);

  if (imported) {
    const normalizedIntegration = normalize(integration);
    if (integration && !/^conn(?:ector)?[_:-]/i.test(integration) && normalizedIntegration !== 'connector_inventory') {
      return `Imported · ${humanize(integration)}`;
    }
    return integration || connectorId
      ? 'Imported from connector inventory'
      : 'Imported (provider not reported)';
  }
  if (!source || source === 'manual' || source === 'manual_declaration') return 'Manual declaration';
  if (source === 'api') return 'Declared through API';
  if (source === 'csv' || source === 'csv_import') return 'Imported from CSV';
  return `Declared via ${humanize(source)}`;
}

/** Display an optional port while retaining the canonical persisted value as a bare IP. */
export function targetDisplayValue(target) {
  const record = asRecord(target) ?? {};
  const value = firstString(record.value) || '—';
  if (normalize(record.kind) !== 'ip') return value;
  const metadata = asRecord(record.metadata) ?? asRecord(record.metadata_json) ?? {};
  const parsedPort = parseOptionalPort(metadata.port);
  if (!parsedPort.port) return value;
  return value.includes(':') ? `[${value}]:${parsedPort.port}` : `${value}:${parsedPort.port}`;
}

export function parseOptionalPort(value) {
  const raw = firstString(value);
  if (!raw) return { port: '', error: '' };
  if (!/^\d+$/.test(raw)) return { port: '', error: 'Port must be a whole number from 1 to 65535.' };
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65_535) {
    return { port: '', error: 'Port must be a whole number from 1 to 65535.' };
  }
  return { port: String(parsed), error: '' };
}

function uniqueRecords(items, keyFor) {
  if (!Array.isArray(items)) return [];
  const seen = new Set();
  const unique = [];
  for (const item of items) {
    const record = asRecord(item);
    if (!record) continue;
    const key = keyFor(record);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(record);
  }
  return unique;
}

export function uniqueAppliedChecks(items) {
  return uniqueRecords(items, (item) => firstString(item.check_id, item.id) || JSON.stringify(stableValue(item)));
}

export function uniqueRecentRuns(items) {
  return uniqueRecords(items, (item) => firstString(item.run_id, item.id)
    || JSON.stringify(stableValue({
      started_at: item.started_at ?? item.created_at,
      verdict: item.verdict ?? item.status,
      policy_id: item.policy_id ?? item.test_policy_id,
    })));
}

export function uniqueVerificationHistory(items) {
  return uniqueRecords(items, (item) => JSON.stringify(stableValue({
    state: item.state,
    transitioned_at: item.transitioned_at,
    source_kind: item.source_kind,
    source_ref: item.source_ref,
  })));
}

export function ownershipMethodLabel(verification) {
  const record = asRecord(verification) ?? {};
  const sourceKind = normalize(record.source_kind ?? record.method ?? record.ownership_method);
  if (sourceKind === 'dns_txt') return 'DNS TXT record';
  if (sourceKind === 'agent_observation' || sourceKind === 'agent_heartbeat') return 'Agent observation';
  if (sourceKind === 'user_attestation' || sourceKind === 'manual_override') return 'Authorized user attestation';
  if (sourceKind) return humanize(sourceKind);
  return normalize(record.state) === 'unverified' ? 'No ownership proof recorded' : 'Ownership method not reported';
}

/** Provider row for an edge family: the asserted provider is shown separately, so list only the rest. */
export function edgeFamilyProviderSummary(assertedProvider, providers) {
  const asserted = firstString(assertedProvider);
  const reported = Array.isArray(providers) ? providers.map((entry) => firstString(entry)).filter(Boolean) : [];
  if (!asserted) return { label: 'Reported providers', value: reported.join(', ') || 'None reported' };
  return { label: 'Other providers', value: reported.filter((entry) => entry !== asserted).join(', ') || 'None' };
}

const EDGE_REASON_EXPLANATIONS = {
  simulation_not_detection: 'Simulation mode: the run completed with a simulated probe, which is never treated as edge evidence. Real detection requires a signed probe worker — see docs/operator-local-runbook.md "Real probe results locally".',
  worker_result_pending: 'The governed test run is waiting for signed probe-worker evidence.',
  worker_result_not_observed: 'The run finished without a trusted probe-worker result, so nothing can be asserted.',
  worker_result_not_observed_before_poll_timeout: 'No trusted probe-worker result arrived during the bounded wait. The test-run page remains authoritative.',
  worker_result_error: 'The probe worker reported an error, so no detection result was recorded.',
  worker_result_incomplete: 'The probe-worker result was incomplete, so no detection result was recorded.',
  test_run_failed: 'The detection test run failed before producing evidence.',
  test_run_not_successful: 'The detection test run did not complete successfully.',
};

/** Human explanation for an edge-detection status reason; empty when the reason is unknown. */
export function edgeDetectionReasonExplanation(reason) {
  return EDGE_REASON_EXPLANATIONS[normalize(reason)] ?? '';
}

/** Why Detect edge is locked for a target whose ownership is not yet proven. */
export function edgeDetectionLockedReason(verificationState) {
  const state = humanize(verificationState) || 'Unverified';
  return `Detect edge is locked: ownership is ${state.toLowerCase()}. Verify this target with DNS, provider, or agent proof first.`;
}

/** Prevent a clickable table row from intercepting nested controls or links. */
export function isNestedInteractiveTarget(target, currentTarget) {
  if (!target || typeof target.closest !== 'function') return false;
  const interactive = target.closest('a, button, input, select, textarea, label, summary, [role="button"], [role="link"], [contenteditable="true"]');
  return Boolean(interactive && interactive !== currentTarget);
}
