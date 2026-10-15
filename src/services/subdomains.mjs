/**
 * Subdomains of a declared domain target (ADR-0015).
 *
 * Persistence-neutral: the route hands in readers and writers for the active runtime, so the
 * dev store and Postgres share one flow. Discovered hosts become ordinary fqdn targets in the
 * parent's group, tagged `subdomain-of:<parent id>`, and inherit the parent's ownership proof.
 */
import { ownershipProofFromStates } from '../lib/ownershipPolicy.mjs';
import {
  SUBDOMAIN_DETECTION_BATCH,
  SUBDOMAIN_FINGERPRINT_CHECK_ID,
  SUBDOMAIN_SOURCE_LABELS,
  SubdomainSourceError,
  fetchSubdomainsFromSource,
  hostnameOf,
  isDiscoveredSubdomain,
  isStrictSubdomain,
  presentSubdomainRow,
  subdomainParentTag,
  summarizeSubdomains,
} from '../lib/subdomainEnumeration.mjs';

const COHORT_PAGE_LIMIT = 200;
const COHORT_MAX_PAGES = 10;

function fail(error, status, extra = {}) {
  return { error, status, ...extra };
}

async function loadParent(ctx, parentTargetId, deps) {
  const parent = await deps.readTarget(ctx, parentTargetId);
  if (!parent || (parent.tenant_id && parent.tenant_id !== ctx.tenantId)) return { error: fail('not_found', 404) };
  if (parent.kind !== 'fqdn') {
    return { error: fail('subdomain_discovery_requires_domain', 409, { message: 'Subdomain discovery works on domain targets only.' }) };
  }
  return { parent };
}

function parentIsSubdomainError() {
  return fail('subdomain_discovery_parent_is_subdomain', 409, { message: 'Run discovery from the parent domain instead.' });
}

async function readGroupHosts(ctx, parent, deps) {
  const parentHost = hostnameOf(parent);
  const rows = [];
  let cursor = null;
  for (let page = 0; page < COHORT_MAX_PAGES; page += 1) {
    const result = await deps.readCohort({
      target_group_id: parent.target_group_id,
      kind: 'fqdn',
      q: parentHost.slice(-200),
      limit: String(COHORT_PAGE_LIMIT),
      ...(cursor ? { cursor } : {}),
    });
    if (result?.notWired) return { notWired: true };
    if (result?.error) return { error: fail(result.error, result.status ?? 503) };
    rows.push(...(Array.isArray(result?.items) ? result.items : []));
    cursor = result?.next_cursor ?? null;
    if (!cursor) break;
  }
  const parentRow = rows.find((row) => row.id === parent.id) ?? null;
  return {
    parent: { ...parent, tags: parentRow?.tags ?? parent.tags ?? [], verification_state: parentRow?.verification_state ?? parent.verification_state ?? null },
    rows: rows.filter((row) => row.target_group_id === parent.target_group_id
      && row.kind === 'fqdn'
      && isStrictSubdomain(hostnameOf(row), parentHost)),
    truncated: Boolean(cursor),
  };
}

function parentProof(parent) {
  const state = parent.verification_state ?? parent.verification?.state ?? null;
  return ownershipProofFromStates({ targetState: state });
}

function withInheritedVerification(row, parent) {
  const own = ownershipProofFromStates({ targetState: row.verification_state });
  const inherited = parentProof(parent);
  return row.origin === 'discovered' && inherited.verified
    ? { ...row, verification_state: own.verified ? row.verification_state : inherited.state, verification_inherited: true, ownership_verified: true }
    : { ...row, ownership_verified: own.verified };
}

/** Current subdomain inventory for one domain target, with the latest edge result per host. */
export async function listTargetSubdomains(ctx, parentTargetId, deps) {
  const loaded = await loadParent(ctx, parentTargetId, deps);
  if (loaded.error) return loaded.error;
  const hosts = await readGroupHosts(ctx, loaded.parent, deps);
  if (hosts.notWired) return { notWired: true };
  if (hosts.error) return hosts.error;
  const parent = hosts.parent;
  if (isDiscoveredSubdomain(parent)) return parentIsSubdomainError();
  const items = hosts.rows
    .map((row) => withInheritedVerification(presentSubdomainRow(row, parent.id), parent))
    .sort((a, b) => a.hostname.localeCompare(b.hostname));
  return {
    parent: {
      target_id: parent.id,
      target_group_id: parent.target_group_id,
      hostname: hostnameOf(parent),
      ownership_verified: parentProof(parent).verified,
    },
    source: {
      name: deps.config?.source ?? null,
      label: SUBDOMAIN_SOURCE_LABELS[deps.config?.source] ?? null,
      configured: deps.config?.configured === true,
      reason: deps.config?.configured === true ? null : (deps.config?.reason ?? 'not_configured'),
    },
    detection_enabled: deps.detectionEnabled !== false,
    items,
    count: items.length,
    summary: summarizeSubdomains(items),
    meta: {
      truncated: hosts.truncated,
      empty_reason: items.length ? null : 'No subdomains have been discovered or declared under this domain yet.',
    },
  };
}

async function queueDetection(ctx, rows, deps) {
  const queued = [];
  const skipped = [];
  for (const row of rows.slice(0, SUBDOMAIN_DETECTION_BATCH)) {
    const result = await deps.startTestRun(ctx, {
      check_id: SUBDOMAIN_FINGERPRINT_CHECK_ID,
      target_group_id: row.target_group_id,
      target_id: row.target_id,
    });
    if (result?.error) skipped.push({ target_id: row.target_id, hostname: row.hostname, reason: result.error });
    else queued.push({ target_id: row.target_id, hostname: row.hostname, test_run_id: result?.run?.id ?? null });
  }
  return { queued, skipped, deferred: Math.max(0, rows.length - SUBDOMAIN_DETECTION_BATCH) };
}

/**
 * Explicitly import bounded subdomains as child declarations. Detection is a separate reviewed
 * action so the caller can inspect the imported scope before any external worker request.
 */
export async function enumerateTargetSubdomains(ctx, parentTargetId, deps) {
  const loaded = await loadParent(ctx, parentTargetId, deps);
  if (loaded.error) return loaded.error;
  const hosts = await readGroupHosts(ctx, loaded.parent, deps);
  if (hosts.notWired) return { notWired: true };
  if (hosts.error) return hosts.error;
  const parent = hosts.parent;
  if (isDiscoveredSubdomain(parent)) return parentIsSubdomainError();
  const parentHost = hostnameOf(parent);

  let discovered;
  try {
    discovered = await fetchSubdomainsFromSource(parentHost, deps.config, { fetchFn: deps.fetchFn });
  } catch (error) {
    if (error instanceof SubdomainSourceError) {
      return fail(error.code, error.status, { message: error.message, source: deps.config?.source ?? null });
    }
    throw error;
  }

  const existing = new Set(hosts.rows.map((row) => hostnameOf(row)));
  const tag = subdomainParentTag(parent.id);
  const created = [];
  const failed = [];
  for (const hostname of discovered.hostnames) {
    if (existing.has(hostname)) continue;
    const result = await deps.createTarget(ctx, {
      kind: 'fqdn',
      value: hostname,
      target_group_id: parent.target_group_id,
      tags: [tag],
    });
    if (result?.error === 'target_exists') continue;
    if (!result || result.error) {
      failed.push({ hostname, reason: result?.error ?? 'target_create_failed' });
      continue;
    }
    existing.add(hostname);
    created.push({ target_id: result.id, target_group_id: result.target_group_id ?? parent.target_group_id, hostname });
  }

  const detection = { queued: [], skipped: [], deferred: created.length };

  await deps.recordAudit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.subdomains_enumerated',
    resource_type: 'target',
    resource_id: parent.id,
    metadata: {
      target_group_id: parent.target_group_id,
      source: discovered.source,
      found_count: discovered.hostnames.length,
      created_count: created.length,
      created_target_ids: created.map((row) => row.target_id).slice(0, 200),
      failed_count: failed.length,
      detection_queued_count: detection.queued.length,
      truncated: discovered.truncated,
      stop_reason: discovered.stop_reason,
    },
  });

  return {
    parent_target_id: parent.id,
    source: discovered.source,
    source_label: SUBDOMAIN_SOURCE_LABELS[discovered.source] ?? null,
    found: discovered.hostnames.length,
    reported_total: discovered.reported_total,
    truncated: discovered.truncated,
    stop_reason: discovered.stop_reason,
    already_declared: discovered.hostnames.length - created.length - failed.length,
    created,
    failed,
    detection,
  };
}

/** Queue CDN/WAF detection for subdomains that have no current edge result. */
export async function detectTargetSubdomains(ctx, parentTargetId, body, deps) {
  const listed = await listTargetSubdomains(ctx, parentTargetId, deps);
  if (listed.error || listed.notWired) return listed;
  if (deps.detectionEnabled === false) return fail('waf_feature_disabled', 404);
  const scope = body?.scope === 'all' ? 'all' : 'unchecked';
  const rows = listed.items.filter((row) => scope === 'all' || row.exposure === 'not_checked');
  const unverified = rows.filter((row) => row.ownership_verified !== true);
  const detection = await queueDetection(ctx, rows.filter((row) => row.ownership_verified === true), deps);
  detection.skipped.push(...unverified.map((row) => ({ target_id: row.target_id, hostname: row.hostname, reason: 'target_ownership_not_verified' })));
  await deps.recordAudit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.subdomains_detection_queued',
    resource_type: 'target',
    resource_id: parentTargetId,
    metadata: {
      scope,
      queued_count: detection.queued.length,
      skipped_count: detection.skipped.length,
      deferred_count: detection.deferred,
    },
  });
  return { parent_target_id: parentTargetId, scope, ...detection };
}
