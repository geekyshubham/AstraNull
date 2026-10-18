/**
 * Subdomain enumeration for declared domain targets (ADR-0015).
 *
 * Sources are VirusTotal UI through a rotating proxy (ADR-0035), the official VirusTotal v3
 * API (deployment-owned key), or public Certificate Transparency logs via crt.sh (ADR-0031).
 * Only hostnames are kept. Each one must
 * sit strictly under the parent domain the customer declared, so a source response cannot
 * introduce an unrelated host.
 */
import { normalizeTargetValue, targetTagsFromRecord } from '../contracts/targetManagement.mjs';
import { runVirusTotalUiSubdomains } from './virusTotalUiSubdomains.mjs';

export const SUBDOMAIN_PARENT_TAG_PREFIX = 'subdomain-of:';
export const SUBDOMAIN_SOURCE_VIRUSTOTAL = 'virustotal';
export const SUBDOMAIN_SOURCE_CT = 'crtsh';
export const SUBDOMAIN_SOURCE_VIRUSTOTAL_UI = 'virustotal_ui';
export const SUBDOMAIN_SOURCE = SUBDOMAIN_SOURCE_VIRUSTOTAL;
export const SUBDOMAIN_SOURCE_LABELS = Object.freeze({
  [SUBDOMAIN_SOURCE_VIRUSTOTAL]: 'VirusTotal',
  [SUBDOMAIN_SOURCE_CT]: 'Certificate Transparency logs (crt.sh)',
  [SUBDOMAIN_SOURCE_VIRUSTOTAL_UI]: 'VirusTotal',
});
export const SUBDOMAIN_FINGERPRINT_CHECK_ID = 'waf.fingerprint.safe';

export const VIRUSTOTAL_API_BASE = 'https://www.virustotal.com/api/v3/domains/';
export const CRTSH_API_BASE = 'https://crt.sh/';
export const CRTSH_REQUEST_TIMEOUT_MS = 30_000;
export const CRTSH_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
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
    const response = await fetchFn(url, {
      method: 'GET',
      headers: { accept: 'application/json', 'x-apikey': apiKey },
      redirect: 'manual',
      signal: controller.signal,
    });
    if (response.status !== 200) return response;
    try {
      const payload = await response.json();
      return { status: response.status, json: async () => payload };
    } catch {
      if (!controller.signal.aborted) throw new SubdomainSourceError('subdomain_source_failed', 'VirusTotal returned an unreadable response.');
      throw new SubdomainSourceError('subdomain_source_unreachable', 'VirusTotal did not respond within the time limit.');
    }
  } catch (error) {
    if (error instanceof SubdomainSourceError) throw error;
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
  const cursors = new Set();
  const maxPages = Math.ceil(maxResults / VIRUSTOTAL_PAGE_SIZE);

  while (true) {
    if (pages > 0 && (options.now ?? Date.now)() >= deadline) {
      stopReason = 'deadline';
      break;
    }
    const response = await fetchPage(pageUrl(parent, cursor), { apiKey, fetchFn,
      timeoutMs: Math.min(timeoutMs, Math.max(1, deadline - (options.now ?? Date.now)())) });
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
    if (!next) break;
    if (cursors.has(next) || next === cursor) { stopReason = 'cursor_loop'; break; }
    if (pages >= maxPages) { stopReason = 'max_pages'; break; }
    cursors.add(next);
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

/** Bounded UI-source helper; hostnames still pass the same declaration boundary as API/CT. */
export async function fetchVirusTotalUiSubdomains(parentHostname, options = {}) {
  const maxResults = boundedMaxResults(options.maxResults);
  const payload = await (options.runUiFn ?? runVirusTotalUiSubdomains)({
    domain: lower(parentHostname).replace(/\.$/, ''),
    maxResults,
    proxyUrl: options.proxyUrl,
  }, { pythonExecutable: options.pythonExecutable });
  const errors = {
    subdomain_source_not_configured: ['VirusTotal UI transport or proxy is not configured for this deployment.', 503],
    subdomain_source_auth_failed: ['VirusTotal rejected the UI request.', 502],
    subdomain_source_rate_limited: ['VirusTotal rate limit reached. Try again in a minute.', 429],
    subdomain_source_unreachable: ['VirusTotal UI did not respond within the time limit.', 502],
    subdomain_source_response_too_large: ['VirusTotal UI returned more data than one import can read.', 502],
  };
  if (payload?.error) {
    const code = Object.hasOwn(errors, payload.error) ? payload.error : 'subdomain_source_failed';
    const [message, status] = errors[code] ?? ['VirusTotal UI returned an unreadable response.', 502];
    throw new SubdomainSourceError(code, message, status);
  }
  if (!Array.isArray(payload?.hostnames) || !Number.isInteger(payload.pages) || payload.pages < 1) {
    throw new SubdomainSourceError('subdomain_source_failed', 'VirusTotal UI returned an unreadable response.');
  }
  const found = new Set(payload.hostnames.map((host) => normalizeSubdomainCandidate(host, parentHostname)).filter(Boolean));
  const capped = found.size > maxResults;
  return {
    source: SUBDOMAIN_SOURCE_VIRUSTOTAL_UI,
    hostnames: [...found].sort().slice(0, maxResults),
    pages: payload.pages,
    reported_total: Number.isInteger(payload.reported_total) ? payload.reported_total : null,
    truncated: payload.truncated === true || capped,
    stop_reason: capped ? 'max_results' : payload.stop_reason ?? null,
  };
}

/** Blank = keyless VirusTotal UI transport; the official API and CT remain explicit options. */
export function resolveSubdomainSource({ requested, virusTotalApiKey } = {}) {
  const value = lower(requested);
  const hasKey = typeof virusTotalApiKey === 'string' && virusTotalApiKey.trim().length > 0;
  if (!value) {
    return { source: SUBDOMAIN_SOURCE_VIRUSTOTAL_UI, configured: true, reason: null };
  }
  if (value === 'disabled' || value === 'none' || value === 'off' || value === '0') {
    return { source: null, configured: false, reason: 'disabled' };
  }
  if (value === SUBDOMAIN_SOURCE_VIRUSTOTAL) {
    return hasKey
      ? { source: SUBDOMAIN_SOURCE_VIRUSTOTAL, configured: true, reason: null }
      : { source: SUBDOMAIN_SOURCE_VIRUSTOTAL, configured: false, reason: 'virustotal_api_key_missing' };
  }
  if (value === SUBDOMAIN_SOURCE_VIRUSTOTAL_UI) {
    return { source: SUBDOMAIN_SOURCE_VIRUSTOTAL_UI, configured: true, reason: null };
  }
  if (value === SUBDOMAIN_SOURCE_CT || value === 'ct' || value === 'certificate_transparency') {
    return { source: SUBDOMAIN_SOURCE_CT, configured: true, reason: null };
  }
  return { source: null, configured: false, reason: 'invalid_source' };
}

const NOT_CONFIGURED_COPY = {
  disabled: 'Subdomain discovery is disabled for this deployment.',
  virustotal_api_key_missing: 'Subdomain discovery is set to VirusTotal, but no VirusTotal API key is configured for this deployment.',
  invalid_source: 'Subdomain discovery has an unrecognized source configured for this deployment.',
};

export function subdomainSourceNotConfiguredError(reason) {
  return new SubdomainSourceError(
    'subdomain_source_not_configured',
    NOT_CONFIGURED_COPY[reason] ?? 'Subdomain discovery is not configured for this deployment.',
    503,
  );
}

async function readCappedText(response, maxBytes) {
  const declared = Number.parseInt(response.headers?.get?.('content-length') ?? '', 10);
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel?.().catch(() => {});
    return { tooLarge: true };
  }
  const reader = response.body?.getReader?.();
  if (!reader) {
    if (typeof response.text === 'function') {
      const body = await response.text();
      return Buffer.byteLength(body) > maxBytes ? { tooLarge: true } : { text: body };
    }
    return { json: await response.json() };
  }
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel().catch(() => {});
        return { tooLarge: true };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return { text: Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString('utf8') };
}

function crtshUrl(domain) {
  const url = new URL(CRTSH_API_BASE);
  url.searchParams.set('q', `%.${domain}`);
  url.searchParams.set('output', 'json');
  url.searchParams.set('exclude', 'expired');
  url.searchParams.set('deduplicate', 'Y');
  return url;
}

/** One bounded crt.sh read of unexpired certificates; only strict-descendant subject names are kept. */
export async function fetchCertificateTransparencySubdomains(parentHostname, options = {}) {
  const fetchFn = options.fetchFn ?? fetch;
  const maxResults = boundedMaxResults(options.maxResults);
  const timeoutMs = options.timeoutMs ?? CRTSH_REQUEST_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? CRTSH_MAX_RESPONSE_BYTES;
  const parent = lower(parentHostname).replace(/\.$/, '');
  const label = SUBDOMAIN_SOURCE_LABELS[SUBDOMAIN_SOURCE_CT];
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let body;
  try {
    const response = await fetchFn(crtshUrl(parent), {
      method: 'GET',
      headers: { accept: 'application/json' },
      redirect: 'manual',
      signal: controller.signal,
    });
    if (response.status !== 200) {
      await response.body?.cancel?.().catch(() => {});
      if (response.status === 429) {
        throw new SubdomainSourceError('subdomain_source_rate_limited', `${label} rate limit reached. Try again in a minute.`, 429);
      }
      throw new SubdomainSourceError('subdomain_source_failed', `${label} returned HTTP ${response.status}.`);
    }
    body = await readCappedText(response, maxBytes);
  } catch (error) {
    if (error instanceof SubdomainSourceError) throw error;
    throw new SubdomainSourceError('subdomain_source_unreachable', `${label} did not respond within ${Math.round(timeoutMs / 1000)} seconds.`);
  } finally {
    clearTimeout(timer);
  }
  if (body.tooLarge) {
    throw new SubdomainSourceError('subdomain_source_response_too_large', `${label} returned more certificate records than one import can read.`);
  }
  let payload = body.json;
  if (body.text !== undefined) {
    try {
      payload = body.text.trim() ? JSON.parse(body.text) : [];
    } catch {
      throw new SubdomainSourceError('subdomain_source_failed', `${label} returned an unreadable response.`);
    }
  }
  if (!Array.isArray(payload)) {
    throw new SubdomainSourceError('subdomain_source_failed', `${label} returned an unreadable response.`);
  }
  const found = new Set();
  let stopReason = null;
  outer: for (const entry of payload) {
    const names = [entry?.common_name, ...String(entry?.name_value ?? '').split(/\s+/)];
    for (const name of names) {
      const hostname = typeof name === 'string' ? normalizeSubdomainCandidate(name, parent) : null;
      if (!hostname) continue;
      found.add(hostname);
      if (found.size >= maxResults) { stopReason = 'max_results'; break outer; }
    }
  }
  return {
    source: SUBDOMAIN_SOURCE_CT,
    hostnames: [...found].sort(),
    pages: 1,
    reported_total: null,
    truncated: stopReason !== null,
    stop_reason: stopReason,
  };
}

/** Enumerate through the deployment's resolved source; never calls a source that is not configured. */
export async function fetchSubdomainsFromSource(parentHostname, config = {}, { fetchFn, runUiFn } = {}) {
  if (config?.configured !== true) throw subdomainSourceNotConfiguredError(config?.reason);
  if (config.source === SUBDOMAIN_SOURCE_VIRUSTOTAL_UI) {
    return fetchVirusTotalUiSubdomains(parentHostname, {
      maxResults: config.maxResults,
      proxyUrl: config.proxyUrl,
      pythonExecutable: config.pythonExecutable,
      runUiFn,
    });
  }
  if (config.source === SUBDOMAIN_SOURCE_CT) {
    return fetchCertificateTransparencySubdomains(parentHostname, { fetchFn, maxResults: config.maxResults });
  }
  return fetchVirusTotalSubdomains(parentHostname, {
    apiKey: config.virusTotalApiKey,
    maxResults: config.maxResults,
    fetchFn,
  });
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
  if (waf.status === 'detected') return 'waf_detected';
  if (cdn.status === 'detected') return 'cdn_only';
  if (waf.status === 'not_detected' && cdn.status === 'not_detected') return 'no_edge_detected';
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
    latest_detection_run_id: profile?.families?.cdn?.test_run_id ?? profile?.families?.waf?.test_run_id ?? null,
    findings_count: Number.isInteger(row.findings_count) ? row.findings_count : 0,
    last_validation_at: row.last_validation_at ?? null,
  };
}

export function summarizeSubdomains(rows) {
  const exposure = { waf_detected: 0, cdn_only: 0, no_edge_detected: 0, inconclusive: 0, not_checked: 0 };
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
