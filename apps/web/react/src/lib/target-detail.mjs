const RUN_VERIFICATION_STATES = new Set(['dns_verified', 'agent_verified', 'user_confirmed', 'verified']);
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

/** Prevent a clickable table row from intercepting nested controls or links. */
export function isNestedInteractiveTarget(target, currentTarget) {
  if (!target || typeof target.closest !== 'function') return false;
  const interactive = target.closest('a, button, input, select, textarea, label, summary, [role="button"], [role="link"], [contenteditable="true"]');
  return Boolean(interactive && interactive !== currentTarget);
}
