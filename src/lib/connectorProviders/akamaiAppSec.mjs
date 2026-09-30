/**
 * Akamai Application Security (WAF match target / security policy) read-only poller.
 *
 * This closes a gap called out for the correlation use case: generic connector snapshots
 * and vendor fingerprint detection existed, but no outbound Akamai Property Manager or
 * Application Security poller was registered — the `akamai` connector name was accepted as
 * configuration metadata without any provider collection implementing it. This module adds
 * the Application Security half: which production security configuration, match target,
 * and security policy (block/monitor mode) actually covers a given hostname today.
 *
 * Per docs: EdgeDNS/property CNAME evidence alone does not establish WAF coverage — only a
 * match target scoped to the hostname, resolved against the *active* config version (its
 * `productionVersion`, not `latestVersion` or `stagingVersion`), does. Match-target ordering
 * (`sequence`) is significant; more than one match target claiming a hostname without a
 * resolvable order is reported as ambiguous by the protection-mapping reconciler, not
 * silently resolved here.
 */

import {
  buildAkamaiEdgeGridAuthorization,
  boundedFetch,
} from './domainInventory.mjs';
import {
  buildNormalizedSnapshot,
  CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
} from './common.mjs';

function providerError(message, { code = 'provider_poll_failed', status = 0 } = {}) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  return error;
}

function requireStrings(credentials, fields, provider) {
  for (const field of fields) {
    if (typeof credentials?.[field] !== 'string' || !credentials[field].trim()) {
      throw providerError(`${provider} credentials are missing ${field}.`, { code: 'credentials_missing' });
    }
  }
}

function normalizeAkamaiHost(value) {
  const host = String(value ?? '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  if (!/^[a-z0-9-]+\.luna\.akamaiapis\.net$/.test(host)) {
    throw providerError('Akamai Application Security host must be a customer luna.akamaiapis.net API host.', { code: 'credentials_missing' });
  }
  return host;
}

async function akamaiAppSecGet({ host, path, credentials, fetchFn, fetchTimeoutMs, now, nonce }) {
  const authorization = buildAkamaiEdgeGridAuthorization({
    host,
    path,
    clientToken: credentials.client_token,
    clientSecret: credentials.client_secret,
    accessToken: credentials.access_token,
    now: now ?? new Date(),
    nonce,
  });
  return boundedFetch(`https://${host}${path}`, {
    headers: { Authorization: authorization },
    fetchFn,
    timeoutMs: fetchTimeoutMs,
  });
}

/**
 * Only the active production config version establishes current coverage. `latestVersion`
 * may be an unreleased draft; `stagingVersion` has not been activated on the production
 * network. Falling back to those would misreport draft/staging config as live protection.
 */
function activeProductionVersion(configEntry) {
  const production = Number(configEntry?.productionVersion);
  return Number.isInteger(production) && production > 0 ? production : null;
}

function policyModeFromAttackGroups(attackGroups) {
  // Akamai enforcement is per-attack-group (action: alert/deny/none/deny_custom_*), not a
  // single policy-level field. webApplicationFirewallMode/KRS/AAG/ASE_AUTO is the ruleset
  // *update* mechanism, not enforcement, and must not be read as block/monitor — that was
  // the wrong field. At least one deny-class action anywhere in the policy means it can
  // block; all-alert means monitor-only; all-none means the WAF rules are effectively off.
  const actions = (attackGroups ?? []).map((g) => String(g?.action ?? '').trim().toLowerCase());
  if (actions.length === 0) return 'unknown';
  if (actions.some((a) => a === 'deny' || a.startsWith('deny_custom_'))) return 'block';
  if (actions.every((a) => a === 'none' || a === '')) return 'disabled';
  if (actions.some((a) => a === 'alert')) return 'monitor';
  return 'unknown';
}

function matchTargetSnapshot({ configEntry, productionVersion, matchTarget, policyModesById, observedAt }) {
  const hostnames = Array.isArray(matchTarget?.hostnames)
    ? matchTarget.hostnames.map((h) => String(h).trim().toLowerCase().replace(/\.+$/, '')).filter(Boolean)
    : [];
  if (hostnames.length === 0) return null;
  const policyId = matchTarget?.securityPolicy?.policyId ?? matchTarget?.securityPolicy?.policyName ?? null;
  const policyMode = policyId != null ? policyModesById.get(String(policyId)) ?? 'unknown' : 'unknown';
  const resourceRef = `${configEntry.id}:${productionVersion}:${matchTarget.targetId ?? hostnames.join(',')}`;
  return buildNormalizedSnapshot({
    provider: 'akamai_appsec',
    snapshotKind: 'waf_policy',
    resourceRef,
    displayRef: `${configEntry.name ?? configEntry.id}::${policyId ?? 'unassigned'}`,
    summary: {
      hostnames,
      policy_mode: policyMode,
      match_target_order: Number.isInteger(Number(matchTarget?.sequence)) ? Number(matchTarget.sequence) : null,
      tags: [
        'akamai_appsec_match_target',
        `config_id:${configEntry.id}`,
        `production_version:${productionVersion}`,
        `match_target_type:${matchTarget?.type ?? 'unknown'}`,
      ],
    },
    observedAt,
  });
}

/**
 * Poll every security configuration's active production version for its match targets and
 * security-policy enforcement mode, producing one 'waf_policy' snapshot per match target
 * (bounded to CONNECTOR_POLL_MAX_INVENTORY_ITEMS across all configs).
 */
export async function pollAkamaiApplicationSecurity({
  credentials,
  fetchFn = fetch,
  observedAt,
  fetchTimeoutMs,
  now,
  nonce,
}) {
  requireStrings(credentials, ['host', 'client_token', 'client_secret', 'access_token'], 'Akamai Application Security');
  const host = normalizeAkamaiHost(credentials.host);

  const configsBody = await akamaiAppSecGet({
    host,
    path: '/appsec/v1/configs',
    credentials,
    fetchFn,
    fetchTimeoutMs,
    now,
    nonce,
  });
  const configs = Array.isArray(configsBody?.configurations) ? configsBody.configurations : [];

  const snapshots = [];
  const permissionGaps = new Set();
  let anyProductionVersionMissing = false;

  for (const configEntry of configs.slice(0, CONNECTOR_POLL_MAX_INVENTORY_ITEMS)) {
    if (snapshots.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS) break;
    const productionVersion = activeProductionVersion(configEntry);
    if (!productionVersion) {
      // No active production version means this config has never been activated on the
      // production network — it cannot be establishing coverage for anything right now.
      anyProductionVersionMissing = true;
      continue;
    }

    let policies = [];
    try {
      const policiesBody = await akamaiAppSecGet({
        host,
        path: `/appsec/v1/configs/${configEntry.id}/versions/${productionVersion}/security-policies`,
        credentials,
        fetchFn,
        fetchTimeoutMs,
        now,
        nonce,
      });
      policies = Array.isArray(policiesBody?.policies) ? policiesBody.policies : [];
    } catch (error) {
      permissionGaps.add(error?.code === 'auth_failed' ? 'permission_insufficient' : 'security_policy_fetch_failed');
      continue;
    }

    // Enforcement mode is derived per policy from its attack-group actions (alert/deny/none),
    // not from webApplicationFirewallMode (which only describes ruleset update mechanics).
    const policyModesById = new Map();
    for (const policyEntry of policies) {
      const policyId = String(policyEntry?.policyId ?? '');
      if (!policyId) continue;
      try {
        const attackGroupsBody = await akamaiAppSecGet({
          host,
          path: `/appsec/v1/configs/${configEntry.id}/versions/${productionVersion}/security-policies/${policyId}/attack-groups`,
          credentials,
          fetchFn,
          fetchTimeoutMs,
          now,
          nonce,
        });
        const attackGroups = Array.isArray(attackGroupsBody?.attackGroupActions)
          ? attackGroupsBody.attackGroupActions
          : Array.isArray(attackGroupsBody)
            ? attackGroupsBody
            : [];
        policyModesById.set(policyId, policyModeFromAttackGroups(attackGroups));
      } catch (error) {
        permissionGaps.add(error?.code === 'auth_failed' ? 'permission_insufficient' : 'attack_group_fetch_failed');
        policyModesById.set(policyId, 'unknown');
      }
    }

    let matchTargets = [];
    try {
      const matchTargetsBody = await akamaiAppSecGet({
        host,
        path: `/appsec/v1/configs/${configEntry.id}/versions/${productionVersion}/match-targets`,
        credentials,
        fetchFn,
        fetchTimeoutMs,
        now,
        nonce,
      });
      matchTargets = Array.isArray(matchTargetsBody?.matchTargets?.websiteTargets)
        ? matchTargetsBody.matchTargets.websiteTargets
        : Array.isArray(matchTargetsBody?.matchTargets)
          ? matchTargetsBody.matchTargets
          : [];
    } catch (error) {
      permissionGaps.add(error?.code === 'auth_failed' ? 'permission_insufficient' : 'match_target_fetch_failed');
      continue;
    }

    for (const matchTarget of matchTargets) {
      if (snapshots.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS) break;
      const snapshot = matchTargetSnapshot({ configEntry, productionVersion, matchTarget, policyModesById, observedAt });
      if (snapshot) snapshots.push(snapshot);
    }
  }

  const truncated = configs.length > CONNECTOR_POLL_MAX_INVENTORY_ITEMS
    || snapshots.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS;
  if (truncated) permissionGaps.add('truncated_inventory');
  if (anyProductionVersionMissing) permissionGaps.add('no_active_production_version');

  return {
    snapshots,
    health: permissionGaps.size ? 'degraded' : 'active',
    permission_gaps: [...permissionGaps],
    inventory_complete: !truncated,
    inventory_truncated: truncated,
  };
}

export const akamaiApplicationSecurityProvider = {
  provider: 'akamai_appsec',
  required_scopes: ['Application Security Configuration:READ-ONLY'],
  snapshot_kinds: ['waf_policy'],
  poll: pollAkamaiApplicationSecurity,
};
