import {
  buildNormalizedSnapshot,
  CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
  CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
  hashRef,
  normalizePolicyMode,
  resolveConnectorPollFetchTimeoutMs,
} from './common.mjs';
import { boundedFetch } from './domainInventory.mjs';

const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4';

const CLOUDFLARE_AUTH_ERROR_CODES = new Set([6003, 6111, 9109, 10000]);

function cloudflareErrorIsAuthentication(body) {
  const errors = Array.isArray(body?.errors) ? body.errors : [];
  return errors.some((entry) => {
    const code = Number(entry?.code ?? 0);
    const message = String(entry?.message ?? '').toLowerCase();
    return CLOUDFLARE_AUTH_ERROR_CODES.has(code)
      || /(?:invalid|missing|malformed).*(?:token|authorization|header)/.test(message)
      || /authentication|invalid api token/.test(message);
  });
}

function cloudflareZoneProofTags(zone) {
  const resourceStatus = String(zone?.status ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '_')
    .slice(0, 64) || 'unknown';
  return [
    'provider_zone_inventory',
    `resource_status:${resourceStatus}`,
    `ownership_eligible:${resourceStatus === 'active' ? 'true' : 'false'}`,
  ];
}

function countRulesetEntries(rulesets) {
  let count = 0;
  for (const ruleset of rulesets ?? []) {
    if (Array.isArray(ruleset.rules)) count += ruleset.rules.length;
    if (Array.isArray(ruleset.entries)) count += ruleset.entries.length;
  }
  return count;
}

function deriveCloudflarePolicyMode(zone, rulesets) {
  const securityLevel = zone?.security_level ?? zone?.settings?.security_level?.value ?? null;
  if (securityLevel) return normalizePolicyMode(securityLevel);
  const hasBlockingRuleset = (rulesets ?? []).some((ruleset) => {
    const phase = String(ruleset.phase ?? '').toLowerCase();
    return phase.includes('waf') || phase.includes('http_request_firewall');
  });
  return hasBlockingRuleset ? 'block' : 'unknown';
}

function zoneMatchesConfig(zone, config = {}) {
  const zoneRefHash = config.zone_ref_hash ?? config.zoneRefHash ?? null;
  if (!zoneRefHash) return true;
  const zoneId = zone?.id ?? zone?.zone_id ?? zone?.name;
  return hashRef(`cloudflare:zone:${zoneId}`) === zoneRefHash
    || hashRef(`cloudflare:zone:${zone?.name}`) === zoneRefHash;
}

async function cloudflareFetch(path, token, fetchFn, options = {}) {
  const timeoutMs = Number.isFinite(options.timeoutMs)
    ? options.timeoutMs
    : resolveConnectorPollFetchTimeoutMs();
  let body;
  try {
    body = await boundedFetch(`${CLOUDFLARE_API_BASE}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
      fetchFn,
      timeoutMs,
    });
  } catch (error) {
    if (cloudflareErrorIsAuthentication(error?.response_body)) {
      error.code = 'auth_failed';
    }
    throw error;
  }
  if (body?.success === false) {
    const authFailure = cloudflareErrorIsAuthentication(body);
    const err = new Error(body?.errors?.[0]?.message ?? 'Cloudflare API request failed');
    err.status = authFailure ? 401 : 403;
    err.code = authFailure ? 'auth_failed' : 'permission_insufficient';
    throw err;
  }
  return body;
}

async function listZones(token, fetchFn, fetchOptions) {
  const zones = [];
  let page = 1;
  let truncated = false;

  while (zones.length < CONNECTOR_POLL_MAX_INVENTORY_ITEMS) {
    const zonesBody = await cloudflareFetch(
      `/zones?per_page=${CONNECTOR_POLL_INVENTORY_PAGE_SIZE}&page=${page}`,
      token,
      fetchFn,
      fetchOptions,
    );
    const batch = Array.isArray(zonesBody?.result) ? zonesBody.result : [];
    if (batch.length === 0) break;

    const remaining = CONNECTOR_POLL_MAX_INVENTORY_ITEMS - zones.length;
    zones.push(...batch.slice(0, remaining));

    if (zones.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS) {
      const totalPages = Number(zonesBody?.result_info?.total_pages);
      const hasMorePages = Number.isFinite(totalPages) && page < totalPages;
      truncated = batch.length > remaining || hasMorePages || batch.length >= CONNECTOR_POLL_INVENTORY_PAGE_SIZE;
      break;
    }

    if (batch.length < CONNECTOR_POLL_INVENTORY_PAGE_SIZE) break;
    page += 1;
  }

  return { zones, truncated };
}

function normalizePrefetchedZones(prefetched, config, observedAt) {
  const zones = Array.isArray(prefetched?.zones) ? prefetched.zones : [];
  const snapshots = [];
  for (const zone of zones) {
    if (!zoneMatchesConfig(zone, config)) continue;
    const rulesets = Array.isArray(zone.rulesets) ? zone.rulesets : [];
    const summary = {
      hostnames: Array.isArray(zone.hostnames)
        ? zone.hostnames
        : (zone.name ? [String(zone.name)] : []),
      tags: cloudflareZoneProofTags(zone),
      policy_mode: deriveCloudflarePolicyMode(zone, rulesets),
      rule_count: Number.isFinite(Number(zone.rule_count))
        ? Number(zone.rule_count)
        : countRulesetEntries(rulesets),
      ...(zone.rate_limit_summary ? { rate_limit_summary: String(zone.rate_limit_summary) } : {}),
      ...(zone.origin_protection_summary
        ? { origin_protection_summary: String(zone.origin_protection_summary) }
        : {}),
      ...(Array.isArray(zone.permission_gaps) ? { permission_gaps: zone.permission_gaps } : {}),
    };
    snapshots.push(buildNormalizedSnapshot({
      provider: 'cloudflare',
      snapshotKind: 'dns_zone',
      resourceRef: zone.id ?? zone.zone_id ?? zone.name,
      displayRef: zone.name ?? zone.id,
      summary,
      observedAt,
    }));
  }
  return snapshots;
}

/**
 * Read-only Cloudflare zone/ruleset metadata poll.
 */
export async function pollCloudflare({
  credentials,
  config = {},
  fetchFn = fetch,
  prefetchedMetadata = null,
  observedAt,
  fetchTimeoutMs,
}) {
  if (prefetchedMetadata) {
    const snapshots = normalizePrefetchedZones(prefetchedMetadata, config, observedAt);
    return {
      snapshots,
      health: snapshots.length > 0 ? 'active' : 'degraded',
      permission_gaps: snapshots.length === 0 ? ['no_zone_metadata'] : [],
    };
  }

  const token = credentials?.api_token;
  if (!token) {
    const err = new Error('Cloudflare credentials missing api_token.');
    err.code = 'credentials_missing';
    throw err;
  }

  const fetchOptions = {
    timeoutMs: Number.isFinite(fetchTimeoutMs)
      ? fetchTimeoutMs
      : resolveConnectorPollFetchTimeoutMs(),
  };
  const { zones, truncated } = await listZones(token, fetchFn, fetchOptions);
  const snapshots = [];
  const permissionGaps = [];
  if (truncated) permissionGaps.push('truncated_inventory');

  for (const zone of zones) {
    if (!zoneMatchesConfig(zone, config)) continue;
    let rulesets = [];
    const zonePermissionGaps = [];
    try {
      const rulesetsBody = await cloudflareFetch(`/zones/${zone.id}/rulesets`, token, fetchFn, fetchOptions);
      rulesets = Array.isArray(rulesetsBody?.result) ? rulesetsBody.result : [];
    } catch (err) {
      if (err.status === 403) {
        zonePermissionGaps.push(`rulesets:${zone.id}`);
        permissionGaps.push(`rulesets:${zone.id}`);
      } else {
        throw err;
      }
    }

    snapshots.push(buildNormalizedSnapshot({
      provider: 'cloudflare',
      snapshotKind: 'dns_zone',
      resourceRef: zone.id,
      displayRef: zone.name ?? zone.id,
      summary: {
        hostnames: zone.name ? [zone.name] : [],
        tags: cloudflareZoneProofTags(zone),
        policy_mode: deriveCloudflarePolicyMode(zone, rulesets),
        rule_count: countRulesetEntries(rulesets),
        ...(zonePermissionGaps.length > 0 ? { permission_gaps: zonePermissionGaps } : {}),
      },
      observedAt,
    }));
  }

  return {
    snapshots,
    health: permissionGaps.length > 0 ? 'degraded' : 'active',
    permission_gaps: permissionGaps,
    inventory_complete: !truncated,
    inventory_truncated: truncated,
  };
}

export const cloudflareProvider = {
  provider: 'cloudflare',
  required_scopes: ['Zone:Read', 'Account:Read'],
  snapshot_kinds: ['waf_policy', 'dns_zone', 'cdn_property'],
  poll: pollCloudflare,
};