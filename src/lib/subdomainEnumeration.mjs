/**
 * Subdomain enumeration for declared domain targets (ADR-0015).
 *
 * Source is the official VirusTotal v3 API, authenticated with a deployment-owned API key.
 * Only hostnames are kept. Each one must sit strictly under the parent domain the customer
 * declared, so a source response cannot introduce an unrelated host.
 */
import { normalizeTargetValue, targetTagsFromRecord } from '../contracts/targetManagement.mjs';

export const SUBDOMAIN_PARENT_TAG_PREFIX = 'subdomain-of:';
export const SUBDOMAIN_SOURCE = 'virustotal';
export const SUBDOMAIN_FINGERPRINT_CHECK_ID = 'waf.fingerprint.safe';

export const VIRUSTOTAL_API_BASE = 'https://www.virustotal.com/api/v3/domains/';
export const VIRUSTOTAL_PAGE_SIZE = 40;
export const SUBDOMAIN_DEFAULT_MAX_RESULTS = 200;
export const SUBDOMAIN_MAX_RESULTS_CEILING = 1000;
export const SUBDOMAIN_REQUEST_TIMEOUT_MS = 15_000;
export const SUBDOMAIN_TOTAL_DEADLINE_MS = 45_000;
export const SUBDOMAIN_DETECTION_BATCH = 50;

export class SubdomainSourceError extends Error {
  constructor(code, message, status = 502) {
    super(message);
    this.name = 'SubdomainSourceError';
    this.code = code;
    this.status = status;
  }
}

function lower(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

export function subdomainParentTag(parentTargetId) {
  return `${SUBDOMAIN_PARENT_TAG_PREFIX}${lower(parentTargetId)}`;
}

/** Parent target id named by the provenance tag, or '' for a target that was not discovered. */
export function subdomainParentId(target) {
  const tag = targetTagsFromRecord(target).map(lower).find((value) => value.startsWith(SUBDOMAIN_PARENT_TAG_PREFIX));
  return tag ? tag.slice(SUBDOMAIN_PARENT_TAG_PREFIX.length) : '';
}

export function isDiscoveredSubdomain(target) {
  return subdomainParentId(target) !== '';
}

export function hostnameOf(target) {
  return lower(target?.normalized_value ?? target?.value).replace(/\.$/, '');
}

export function isStrictSubdomain(hostname, parentHostname) {
  const host = lower(hostname).replace(/\.$/, '');
  const parent = lower(parentHostname).replace(/\.$/, '');
  return Boolean(host && parent) && host !== parent && host.endsWith(`.${parent}`);
}

/**
 * Normalize one source hostname. Wildcards, IPs, malformed names, and anything outside the
 * parent zone are dropped rather than repaired.
 */
export function normalizeSubdomainCandidate(raw, parentHostname) {
  const value = lower(raw).replace(/\.$/, '');
  if (!value || value.includes('*') || value.includes('/')) return null;
  let normalized;
  try {
    const result = normalizeTargetValue('fqdn', value);
    normalized = lower(typeof result === 'string' ? result : result?.normalized_value);
  } catch {
    return null;
  }
  return isStrictSubdomain(normalized, parentHostname) ? normalized : null;
}

export function boundedMaxResults(value) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed < 1) return SUBDOMAIN_DEFAULT_MAX_RESULTS;
  return Math.min(parsed, SUBDOMAIN_MAX_RESULTS_CEILING);
}

function pageUrl(domain, cursor) {
  const url = new URL(`${VIRUSTOTAL_API_BASE}${encodeURIComponent(domain)}/subdomains`);
  url.searchParams.set('limit', String(VIRUSTOTAL_PAGE_SIZE));
  if (cursor) url.searchParams.set('cursor', cursor);
  return url;
}

async function fetchPage(url, { apiKey, fetchFn, timeoutMs }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchFn(url, {
      method: 'GET',
      headers: { accept: 'application/json', 'x-apikey': apiKey },
      redirect: 'manual',
      signal: controller.signal,
    });
  } catch {
    throw new SubdomainSourceError('subdomain_source_unreachable', 'VirusTotal did not respond within the time limit.');
  } finally {
    clearTimeout(timer);
  }
}

function sourceErrorForStatus(status) {
  if (status === 401 || status === 403) {
    return new SubdomainSourceError('subdomain_source_auth_failed', 'VirusTotal rejected the configured API key.', 502);
  }
  if (status === 429) {
    return new SubdomainSourceError('subdomain_source_rate_limited', 'VirusTotal quota reached. Try again in a minute.', 429);
  }
  if (status === 404) return null;
  return new SubdomainSourceError('subdomain_source_failed', `VirusTotal returned HTTP ${status}.`);
}

/**
 * Page through `/api/v3/domains/{domain}/subdomains` until the cursor ends, the result cap is
 * reached, the deadline passes, or the quota runs out. A quota stop after the first page keeps
 * the hostnames already collected and reports `stop_reason: 'rate_limited'`.
 */
export async function fetchVirusTotalSubdomains(parentHostname, options = {}) {
  const apiKey = typeof options.apiKey === 'string' ? options.apiKey.trim() : '';
  if (!apiKey) {
    throw new SubdomainSourceError('subdomain_source_not_configured', 'Subdomain discovery is not configured for this deployment.', 503);
  }
  const fetchFn = options.fetchFn ?? fetch;
  const maxResults = boundedMaxResults(options.maxResults);
  const timeoutMs = options.timeoutMs ?? SUBDOMAIN_REQUEST_TIMEOUT_MS;
  const deadline = (options.now ?? Date.now)() + (options.deadlineMs ?? SUBDOMAIN_TOTAL_DEADLINE_MS);
  const parent = lower(parentHostname).replace(/\.$/, '');
  const found = new Set();
  let cursor = '';
  let pages = 0;
  let reported = null;
  let stopReason = null;

  while (true) {
    if (pages > 0 && (options.now ?? Date.now)() >= deadline) {
      stopReason = 'deadline';
      break;
    }
    const response = await fetchPage(pageUrl(parent, cursor), { apiKey, fetchFn, timeoutMs });
    if (response.status !== 200) {
      const error = sourceErrorForStatus(response.status);
      if (!error) break;
      if (error.code === 'subdomain_source_rate_limited' && pages > 0) {
        stopReason = 'rate_limited';
        break;
      }
      throw error;
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new SubdomainSourceError('subdomain_source_failed', 'VirusTotal returned an unreadable response.');
    }
    pages += 1;
    if (Number.isInteger(payload?.meta?.count)) reported = payload.meta.count;
    for (const item of Array.isArray(payload?.data) ? payload.data : []) {
      const hostname = normalizeSubdomainCandidate(item?.id, parent);
      if (hostname) found.add(hostname);
      if (found.size >= maxResults) break;
    }
    if (found.size >= maxResults) {
      stopReason = 'max_results';
      break;
    }
    const next = typeof payload?.meta?.cursor === 'string' ? payload.meta.cursor : '';
    if (!next || next === cursor) break;
    cursor = next;
  }

  return {
    source: SUBDOMAIN_SOURCE,
    hostnames: [...found].sort(),
    pages,
    reported_total: reported,
    truncated: stopReason !== null,
    stop_reason: stopReason,
  };
}

/**
 * Parent whose ownership proof a discovered subdomain inherits (ADR-0015): same tenant and
 * group, an active fqdn, named by the provenance tag, and a real parent of the hostname.
 */
export function ownershipParentFor(target, candidates = []) {
  if (!target || target.kind !== 'fqdn') return null;
  const parentId = subdomainParentId(target);
  if (!parentId) return null;
  const parent = candidates.find((candidate) => lower(candidate?.id) === parentId
    && candidate.kind === 'fqdn'
    && !candidate.deleted_at
    && (!candidate.tenant_id || !target.tenant_id || candidate.tenant_id === target.tenant_id)
    && (!candidate.target_group_id || candidate.target_group_id === target.target_group_id));
  if (!parent || isDiscoveredSubdomain(parent)) return null;
  return isStrictSubdomain(hostnameOf(target), hostnameOf(parent)) ? parent : null;
}

function familyOf(profile, family) {
  const node = profile?.families?.[family] ?? null;
  return { status: node?.status ?? 'not_checked', provider: node?.provider ?? null };
}

/** Exposure verdict for one subdomain from its current edge row. */
export function subdomainExposure({ waf, cdn, observed }) {
  if (!observed) return 'not_checked';
  if (waf.status === 'detected') return 'protected';
  if (cdn.status === 'detected') return 'cdn_only';
  if (waf.status === 'not_detected' && cdn.status === 'not_detected') return 'exposed';
  return 'inconclusive';
}

/** Presentation row for one subdomain from a declared-host cohort item. */
export function presentSubdomainRow(row, parentTargetId) {
  const profile = row?.protection_profile ?? null;
  const waf = familyOf(profile, 'waf');
  const cdn = familyOf(profile, 'cdn');
  const cloud = {
    status: row?.edge_cloud?.status ?? 'not_checked',
    provider: row?.edge_cloud?.provider ?? null,
  };
  const observedAt = profile?.families?.waf?.observed_at ?? profile?.families?.cdn?.observed_at ?? null;
  const discovered = (Array.isArray(row?.tags) ? row.tags : []).includes(subdomainParentTag(parentTargetId));
  return {
    target_id: row.id,
    target_group_id: row.target_group_id,
    hostname: hostnameOf(row),
    origin: discovered ? 'discovered' : 'declared',
    verification_state: row.verification_state ?? null,
    waf,
    cdn,
    cloud,
    exposure: subdomainExposure({ waf, cdn, observed: Boolean(observedAt) }),
    observed_at: observedAt,
    findings_count: Number.isInteger(row.findings_count) ? row.findings_count : 0,
    last_validation_at: row.last_validation_at ?? null,
  };
}

export function summarizeSubdomains(rows) {
  const exposure = { protected: 0, cdn_only: 0, exposed: 0, inconclusive: 0, not_checked: 0 };
  const providers = new Map();
  for (const row of rows) {
    exposure[row.exposure] = (exposure[row.exposure] ?? 0) + 1;
    for (const [layer, node] of [['waf', row.waf], ['cdn', row.cdn], ['cloud', row.cloud]]) {
      if (node.status !== 'detected' || !node.provider) continue;
      const key = `${layer}\u0000${node.provider}`;
      providers.set(key, { layer, provider: node.provider, count: (providers.get(key)?.count ?? 0) + 1 });
    }
  }
  return {
    total: rows.length,
    exposure,
    providers: [...providers.values()].sort((a, b) => b.count - a.count || a.provider.localeCompare(b.provider)),
  };
}
