import { createHash } from 'node:crypto';

export const CONNECTOR_POLL_MAX_ATTEMPTS = 3;
export const CONNECTOR_POLL_BASE_BACKOFF_MS = 250;
export const CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS = 10_000;
export const CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS = 30_000;
export const CONNECTOR_POLL_MAX_INVENTORY_ITEMS = 200;
export const CONNECTOR_POLL_INVENTORY_PAGE_SIZE = 50;

export function resolveConnectorPollFetchTimeoutMs(env = process.env) {
  const raw = String(env?.ASTRANULL_CONNECTOR_POLL_FETCH_TIMEOUT_MS ?? '').trim();
  if (!raw) return CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS;
  }
  return Math.min(Math.floor(parsed), CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS);
}

const POLICY_MODE_VALUES = new Set(['block', 'monitor', 'disabled', 'unknown']);

export function hashRef(value) {
  return createHash('sha256').update(String(value ?? ''), 'utf8').digest('hex').slice(0, 32);
}

function stableStringify(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

export function computeConfigHash(summary) {
  return createHash('sha256').update(stableStringify(summary ?? {}), 'utf8').digest('hex').slice(0, 32);
}

export function normalizePolicyMode(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  if (!raw) return 'unknown';
  if (raw.includes('block') || raw.includes('prevent') || raw.includes('under_attack') || raw === 'high') {
    return 'block';
  }
  if (raw.includes('monitor') || raw.includes('detect') || raw.includes('count') || raw === 'low') {
    return 'monitor';
  }
  if (raw.includes('off') || raw.includes('disable') || raw === 'essentially_off') {
    return 'disabled';
  }
  return POLICY_MODE_VALUES.has(raw) ? raw : 'unknown';
}

export const PROTECTION_CONFIG_SCHEMA = 'protection-config-v1';
export const PROTECTION_CONFIG_ACTIONS = Object.freeze([
  'block',
  'challenge',
  'monitor',
  'bypass',
  'disabled',
  'delegated',
  'unknown',
]);
export const PROTECTION_CONFIG_ATTACHMENT_LEVELS = Object.freeze(['hostname', 'zone', 'resource', 'unknown']);
export const PROTECTION_CONFIG_PATH_MATCH = Object.freeze(['include', 'exclude', 'unspecified']);
export const PROTECTION_CONFIG_FIELDS = Object.freeze([
  'attachment_scope',
  'attachment_paths',
  'enforcement_actions',
  'path_exclusions',
  'method_exclusions',
  'version',
]);
export const PROTECTION_CONFIG_MAX_PATTERNS = 32;
const PROTECTION_CONFIG_PATTERN = /^\/[A-Za-z0-9._~*%/:@!$&'()+,;=-]{0,255}$/;
const PROTECTION_CONFIG_METHOD = /^[A-Z]{3,10}$/;
const PROTECTION_CONFIG_TOKEN = /^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,63}$/;

function boundedList(values, pattern, transform = (value) => value) {
  if (!Array.isArray(values)) return null;
  const out = [];
  for (const value of values) {
    const normalized = transform(String(value ?? '').trim());
    if (pattern.test(normalized) && !out.includes(normalized)) out.push(normalized);
    if (out.length >= PROTECTION_CONFIG_MAX_PATTERNS) break;
  }
  return out.sort();
}

export function countProtectionConfigActions(actions) {
  if (!Array.isArray(actions)) return null;
  const counts = Object.fromEntries(PROTECTION_CONFIG_ACTIONS.map((action) => [action, 0]));
  for (const action of actions) {
    const key = PROTECTION_CONFIG_ACTIONS.includes(action) ? action : 'unknown';
    counts[key] += 1;
  }
  return counts;
}

export function buildProtectionConfig({
  enforcementUnit = null,
  actions = null,
  attachmentLevel = 'unknown',
  attachmentPaths = null,
  pathMatch = 'unspecified',
  exclusionCount = null,
  exclusionPaths = null,
  exclusionMethods = null,
  configVersion = null,
  unsupportedFields = [],
} = {}) {
  const unit = PROTECTION_CONFIG_TOKEN.test(String(enforcementUnit ?? '')) ? String(enforcementUnit) : null;
  const count = Number(exclusionCount);
  const version = PROTECTION_CONFIG_TOKEN.test(String(configVersion ?? '')) ? String(configVersion) : null;
  return {
    schema: PROTECTION_CONFIG_SCHEMA,
    enforcement_unit: unit,
    action_counts: countProtectionConfigActions(actions),
    attachment_level: PROTECTION_CONFIG_ATTACHMENT_LEVELS.includes(attachmentLevel) ? attachmentLevel : 'unknown',
    attachment_paths: boundedList(attachmentPaths, PROTECTION_CONFIG_PATTERN),
    path_match: PROTECTION_CONFIG_PATH_MATCH.includes(pathMatch) ? pathMatch : 'unspecified',
    exclusion_count: exclusionCount === null || !Number.isFinite(count) ? null : Math.max(0, Math.floor(count)),
    exclusion_paths: boundedList(exclusionPaths, PROTECTION_CONFIG_PATTERN),
    exclusion_methods: boundedList(exclusionMethods, PROTECTION_CONFIG_METHOD, (value) => value.toUpperCase()),
    config_version: version,
    unsupported_fields: PROTECTION_CONFIG_FIELDS.filter((field) => (unsupportedFields ?? []).includes(field)),
  };
}

const MAX_STORED_ACTION_COUNT = 100_000;

/** Re-validates a stored or submitted protection_config; anything outside the schema yields null. */
export function normalizeStoredProtectionConfig(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schema !== PROTECTION_CONFIG_SCHEMA) return null;
  const rawCounts = value.action_counts;
  const actionCounts = rawCounts && typeof rawCounts === 'object' && !Array.isArray(rawCounts)
    ? Object.fromEntries(PROTECTION_CONFIG_ACTIONS.map((action) => {
      const count = Number(rawCounts[action]);
      return [action, Number.isFinite(count) && count >= 0 ? Math.min(Math.floor(count), MAX_STORED_ACTION_COUNT) : 0];
    }))
    : null;
  return {
    ...buildProtectionConfig({
      enforcementUnit: value.enforcement_unit,
      attachmentLevel: value.attachment_level,
      attachmentPaths: value.attachment_paths,
      pathMatch: value.path_match,
      exclusionCount: value.exclusion_count ?? null,
      exclusionPaths: value.exclusion_paths,
      exclusionMethods: value.exclusion_methods,
      configVersion: value.config_version,
      unsupportedFields: Array.isArray(value.unsupported_fields) ? value.unsupported_fields : [],
    }),
    action_counts: actionCounts,
  };
}

export function buildNormalizedSnapshot({
  provider,
  snapshotKind,
  resourceRef,
  displayRef,
  summary = {},
  observedAt,
  protectionConfig = null,
}) {
  const safeSummary = {
    ...(Array.isArray(summary.hostnames) ? { hostnames: summary.hostnames.map((h) => String(h).trim()).filter(Boolean) } : {}),
    ...(summary.policy_mode ? { policy_mode: normalizePolicyMode(summary.policy_mode) } : {}),
    ...(summary.rule_count != null && String(summary.rule_count).trim() !== '' && Number.isFinite(Number(summary.rule_count)) ? { rule_count: Math.max(0, Math.floor(Number(summary.rule_count))) } : {}),
    ...(Array.isArray(summary.managed_rule_versions)
      ? { managed_rule_versions: summary.managed_rule_versions.map((v) => String(v).trim()).filter(Boolean) }
      : {}),
    ...(typeof summary.last_rule_update_at === 'string' && summary.last_rule_update_at.trim()
      ? { last_rule_update_at: summary.last_rule_update_at.trim() }
      : {}),
    ...(typeof summary.rate_limit_summary === 'string' && summary.rate_limit_summary.trim()
      ? { rate_limit_summary: summary.rate_limit_summary.trim() }
      : {}),
    ...(typeof summary.origin_protection_summary === 'string' && summary.origin_protection_summary.trim()
      ? { origin_protection_summary: summary.origin_protection_summary.trim() }
      : {}),
    ...(Array.isArray(summary.tags)
      ? { tags: summary.tags.map((tag) => String(tag).trim()).filter(Boolean) }
      : {}),
    ...(Array.isArray(summary.permission_gaps)
      ? { permission_gaps: summary.permission_gaps.map((gap) => String(gap).trim()).filter(Boolean) }
      : {}),
    ...(typeof summary.record_type === 'string' && summary.record_type.trim()
      ? { record_type: summary.record_type.trim().toUpperCase() }
      : {}),
    ...(summary.record_ttl != null && String(summary.record_ttl).trim() !== '' && Number.isFinite(Number(summary.record_ttl))
      ? { record_ttl: Math.max(0, Math.floor(Number(summary.record_ttl))) }
      : {}),
    ...(Array.isArray(summary.record_rdata)
      ? { record_rdata: summary.record_rdata.map((v) => String(v).trim()).filter(Boolean) }
      : {}),
    ...(typeof summary.zone === 'string' && summary.zone.trim()
      ? { zone: summary.zone.trim() }
      : {}),
    ...(summary.match_target_order != null && String(summary.match_target_order).trim() !== '' && Number.isFinite(Number(summary.match_target_order))
      ? { match_target_order: Math.floor(Number(summary.match_target_order)) }
      : {}),
  };
  safeSummary.config_hash = computeConfigHash(safeSummary);
  const resourceRefHash = hashRef(`${provider}:${resourceRef}`);
  const configHash = safeSummary.config_hash;
  return {
    snapshot_kind: snapshotKind,
    resource_ref_hash: resourceRefHash,
    display_ref: String(displayRef ?? resourceRef).trim(),
    summary: safeSummary,
    config_hash: configHash,
    observed_at: observedAt ?? new Date().toISOString(),
    provider,
    ...(protectionConfig ? { protection_config: buildProtectionConfig(protectionConfig) } : {}),
  };
}

export function parseProviderSecret(plaintext, provider) {
  const raw = String(plaintext ?? '').trim();
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      if (provider === 'cloudflare') {
        const token = parsed.api_token ?? parsed.token ?? parsed.apiToken ?? null;
        if (typeof token === 'string' && token.trim()) return { api_token: token.trim() };
      }
      if (provider === 'aws_waf') {
        const accessKeyId = parsed.access_key_id ?? parsed.accessKeyId ?? null;
        const secretAccessKey = parsed.secret_access_key ?? parsed.secretAccessKey ?? null;
        const region = parsed.region ?? parsed.aws_region ?? 'us-east-1';
        if (typeof accessKeyId === 'string' && accessKeyId.trim()
          && typeof secretAccessKey === 'string' && secretAccessKey.trim()) {
          return {
            access_key_id: accessKeyId.trim(),
            secret_access_key: secretAccessKey.trim(),
            region: String(region).trim() || 'us-east-1',
            ...(typeof parsed.session_token === 'string' && parsed.session_token.trim()
              ? { session_token: parsed.session_token.trim() }
              : {}),
          };
        }
      }
      if (provider === 'akamai_edgedns' || provider === 'akamai_appsec') {
        const fields = ['host', 'access_token', 'client_token', 'client_secret'];
        if (fields.every((field) => typeof parsed[field] === 'string' && parsed[field].trim())) {
          return Object.fromEntries(fields.map((field) => [field, parsed[field].trim()]));
        }
      }
      if (provider === 'namecheap') {
        const apiUsername = parsed.api_username ?? parsed.username;
        const apiKey = parsed.api_key ?? parsed.key;
        const clientIp = parsed.client_ip ?? parsed.clientIp;
        if ([apiUsername, apiKey, clientIp].every((value) => typeof value === 'string' && value.trim())) {
          return {
            api_username: apiUsername.trim(),
            api_key: apiKey.trim(),
            client_ip: clientIp.trim(),
            env_type: parsed.environment === 'sandbox' || parsed.env_type === 'sandbox' ? 'sandbox' : 'production',
          };
        }
      }
      if (provider === 'godaddy') {
        if (typeof parsed.key === 'string' && parsed.key.trim()
          && typeof parsed.secret === 'string' && parsed.secret.trim()) {
          return { key: parsed.key.trim(), secret: parsed.secret.trim() };
        }
      }
      if (provider === 'ibm_ns1') {
        const apiKey = parsed.api_key ?? parsed.key;
        if (typeof apiKey === 'string' && apiKey.trim()) return { api_key: apiKey.trim() };
      }
    }
  } catch {
    // fall through to plain token handling
  }
  if (provider === 'cloudflare') return { api_token: raw };
  if (provider === 'ibm_ns1') return { api_key: raw };
  return null;
}

export function mapProviderErrorToHealth(err) {
  const code = String(err?.code ?? err?.provider_code ?? '').trim().toLowerCase();
  const status = Number(err?.status ?? err?.http_status ?? 0);
  const message = String(err?.message ?? '').toLowerCase();

  if (code === 'credentials_missing' || code === 'secret_not_found' || code === 'encryption_not_configured') {
    return { status: 'error', health_code: code };
  }
  if (status === 401 || status === 403 || code === 'auth_failed' || message.includes('unauthorized')) {
    return { status: 'revoked', health_code: 'auth_failed' };
  }
  if (status === 429 || code === 'rate_limited' || message.includes('rate limit')) {
    return { status: 'rate_limited', health_code: 'rate_limited' };
  }
  if (code === 'permission_insufficient' || message.includes('permission') || message.includes('forbidden scope')) {
    return { status: 'permission_insufficient', health_code: 'permission_insufficient' };
  }
  if (code === 'degraded' || err?.partial === true) {
    return { status: 'degraded', health_code: 'partial_data' };
  }
  return { status: 'error', health_code: code || 'provider_poll_failed' };
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
