import { createHmac, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import {
  buildNormalizedSnapshot,
  CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
  resolveConnectorPollFetchTimeoutMs,
} from './common.mjs';

export const PROVIDER_VERIFIED_DNS_PROVIDERS = Object.freeze([
  'cloudflare',
  'akamai_edgedns',
  'namecheap',
  'godaddy',
  'ibm_ns1',
]);

export const PROVIDER_OWNERSHIP_MAX_AGE_MS = 24 * 60 * 60 * 1000;

const PROVIDER_VERIFIED_DNS_PROVIDER_SET = new Set(PROVIDER_VERIFIED_DNS_PROVIDERS);
// Existing inventory projections intentionally omit snapshot summaries. Cache only sanitized
// markers observed while iterating server-loaded durable snapshots; request fields never populate it.
const SNAPSHOT_PROOF_METADATA_CACHE = new WeakMap();

function sameInstant(left, right) {
  const leftMs = Date.parse(String(left ?? ''));
  const rightMs = Date.parse(String(right ?? ''));
  return Number.isFinite(leftMs) && Number.isFinite(rightMs) && leftMs === rightMs;
}

function asPlainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function normalizedMarker(value) {
  return String(value ?? '').trim().toLowerCase();
}

function markerFromTags(tags, name) {
  const prefix = `${name}:`;
  const tag = (Array.isArray(tags) ? tags : [])
    .map(normalizedMarker)
    .find((entry) => entry.startsWith(prefix));
  return tag ? tag.slice(prefix.length) : null;
}

function markerBoolean(value) {
  return value === true || normalizedMarker(value) === 'true';
}

/**
 * Read only provider-authored ownership markers from a durable snapshot summary.
 * Tags are used because both connector runtimes already persist that allowlisted field.
 */
export function getProviderSnapshotProofMetadata(snapshot, providerOverride = null) {
  const summary = asPlainObject(snapshot?.summary ?? snapshot?.summary_json);
  const ownershipMarker = snapshot?.ownership_eligible
    ?? summary.ownership_eligible
    ?? markerFromTags(summary.tags, 'ownership_eligible');
  const resourceStatus = normalizedMarker(
    snapshot?.resource_status
      ?? summary.resource_status
      ?? markerFromTags(summary.tags, 'resource_status'),
  ) || null;
  const providerEnvironment = normalizedMarker(
    snapshot?.provider_environment
      ?? summary.provider_environment
      ?? markerFromTags(summary.tags, 'provider_environment'),
  ) || null;
  const provider = normalizedMarker(providerOverride ?? snapshot?.provider);
  const present = ownershipMarker !== null && ownershipMarker !== undefined;
  let ownershipEligible = present && markerBoolean(ownershipMarker);
  ownershipEligible = ownershipEligible && resourceStatus === 'active';
  if (provider === 'namecheap') ownershipEligible = ownershipEligible && providerEnvironment === 'production';
  return {
    present,
    ownership_eligible: ownershipEligible,
    resource_status: resourceStatus,
    provider_environment: providerEnvironment,
  };
}

function snapshotEvidenceKey(snapshot) {
  const snapshotId = String(snapshot?.snapshot_id ?? snapshot?.id ?? '').trim();
  if (snapshotId) return `id:${snapshotId}`;
  const resourceRef = String(snapshot?.resource_ref ?? snapshot?.resource_ref_hash ?? '').trim();
  const observedAt = String(snapshot?.observed_at ?? '').trim();
  return resourceRef && observedAt ? `resource:${resourceRef}:${observedAt}` : null;
}

function rememberSnapshotProofMetadata(connector, snapshot) {
  if (!connector || typeof connector !== 'object') return;
  const key = snapshotEvidenceKey(snapshot);
  if (!key) return;
  const metadata = getProviderSnapshotProofMetadata(snapshot, connector.provider);
  if (!metadata.present) return;
  let cache = SNAPSHOT_PROOF_METADATA_CACHE.get(connector);
  if (!cache) {
    cache = new Map();
    SNAPSHOT_PROOF_METADATA_CACHE.set(connector, cache);
  }
  cache.set(key, metadata);
}

function evidenceProofMetadata(connector, evidence) {
  const direct = getProviderSnapshotProofMetadata(evidence, connector?.provider);
  if (direct.present) return direct;
  const key = snapshotEvidenceKey(evidence);
  return key ? SNAPSHOT_PROOF_METADATA_CACHE.get(connector)?.get(key) ?? direct : direct;
}

export function isCurrentSuccessfulProviderSnapshot(connector, snapshot, now = new Date()) {
  const connectorRevision = Number(connector?.last_success_revision ?? 0);
  const snapshotRevision = Number(snapshot?.poll_revision ?? 0);
  const successMs = Date.parse(String(connector?.last_success_at ?? ''));
  const nowMs = now instanceof Date ? now.getTime() : Date.parse(String(now));
  const current = snapshot?.evidence_source === 'provider_api'
    && Number.isSafeInteger(connectorRevision)
    && Number.isSafeInteger(snapshotRevision)
    && connectorRevision === snapshotRevision
    && sameInstant(snapshot?.observed_at, connector?.last_success_at)
    && Number.isFinite(successMs)
    && Number.isFinite(nowMs)
    && successMs <= nowMs
    && nowMs - successMs <= PROVIDER_OWNERSHIP_MAX_AGE_MS;
  if (current) rememberSnapshotProofMetadata(connector, snapshot);
  return current;
}

export function isProviderVerifiedDnsEvidence(connector, evidence) {
  const provider = normalizedMarker(connector?.provider);
  const hasSecret = connector?.has_secret === true
    || (typeof connector?.secret_id === 'string' && connector.secret_id.trim().length > 0);
  const proofMetadata = evidenceProofMetadata(connector, evidence);
  return Boolean(
    PROVIDER_VERIFIED_DNS_PROVIDER_SET.has(provider)
    && normalizedMarker(evidence?.provider) === provider
    && evidence?.snapshot_kind === 'dns_zone'
    && evidence?.evidence_source === 'provider_api'
    && evidence?.candidate_source === 'snapshot_inventory'
    && isCurrentSuccessfulProviderSnapshot(connector, evidence)
    && ['fqdn', 'dns_zone'].includes(evidence?.kind)
    && ['active', 'degraded'].includes(normalizedMarker(connector?.status))
    && hasSecret
    && evidence?.snapshot_id
    && evidence?.resource_ref
    && proofMetadata.ownership_eligible === true,
  );
}

function normalizeHostname(value) {
  return String(value ?? '').trim().replace(/\.+$/, '').toLowerCase();
}

/**
 * Revalidates a historical provider verification against the connector's current successful
 * inventory generation. The current snapshot may have a new id after a later successful poll,
 * but it must retain the exact provider resource and hostname bound by the original proof.
 */
export function isCurrentProviderDnsOwnershipProof({ connector, snapshot, sourceRef, target }) {
  const provider = normalizedMarker(connector?.provider);
  const source = asPlainObject(sourceRef);
  const summary = asPlainObject(snapshot?.summary ?? snapshot?.summary_json);
  const targetHostname = normalizeHostname(target?.normalized_value ?? target?.value);
  const hostnames = Array.isArray(summary.hostnames)
    ? summary.hostnames.map(normalizeHostname).filter(Boolean)
    : [];
  const hasSecret = connector?.has_secret === true
    || (typeof connector?.secret_id === 'string' && connector.secret_id.trim().length > 0);
  const snapshotProvider = normalizedMarker(snapshot?.provider ?? provider);
  const proofMetadata = getProviderSnapshotProofMetadata(snapshot, provider);
  return Boolean(
    PROVIDER_VERIFIED_DNS_PROVIDER_SET.has(provider)
    && ['active', 'degraded'].includes(normalizedMarker(connector?.status))
    && hasSecret
    && connector?.id
    && String(source.connector_id ?? '') === String(connector.id)
    && normalizedMarker(source.provider) === provider
    && source.snapshot_kind === 'dns_zone'
    && source.evidence_source === 'provider_api'
    && String(source.snapshot_id ?? '').trim()
    && String(source.resource_ref_hash ?? '').trim()
    && sameInstant(source.observed_at, source.poll_generation)
    && snapshot?.id
    && String(snapshot.connector_id ?? '') === String(connector.id)
    && snapshotProvider === provider
    && snapshot.snapshot_kind === 'dns_zone'
    && snapshot.evidence_source === 'provider_api'
    && String(snapshot.resource_ref_hash ?? '') === String(source.resource_ref_hash)
    && isCurrentSuccessfulProviderSnapshot(connector, snapshot)
    && ['fqdn', 'dns_zone'].includes(target?.kind)
    && targetHostname
    && hostnames.includes(targetHostname)
    && proofMetadata.ownership_eligible === true,
  );
}

const PROVIDER_ORIGINS = Object.freeze({
  namecheap: Object.freeze({
    production: 'https://api.namecheap.com',
    sandbox: 'https://api.sandbox.namecheap.com',
  }),
  godaddy: 'https://api.godaddy.com',
  ibm_ns1: 'https://api.nsone.net',
});

function providerError(message, { code = 'provider_poll_failed', status = 0, partial = false } = {}) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  error.partial = partial;
  return error;
}

export const DOMAIN_INVENTORY_RESPONSE_MAX_BYTES = 1_048_576;

function responseTooLargeError() {
  return providerError('Provider response exceeded the bounded byte limit.', {
    code: 'provider_response_too_large',
  });
}

function abortAndCancelBody(controller, body, reader, reason) {
  const cancellation = reader?.cancel?.(reason) ?? body?.cancel?.(reason);
  if (cancellation && typeof cancellation.catch === 'function') cancellation.catch(() => {});
  controller.abort(reason);
}

function chunkBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new TextEncoder().encode(String(value ?? ''));
}

async function readBoundedStreamBody(response, controller) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let text = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const bytes = chunkBytes(value);
      totalBytes += bytes.byteLength;
      if (totalBytes > DOMAIN_INVENTORY_RESPONSE_MAX_BYTES) {
        const error = responseTooLargeError();
        abortAndCancelBody(controller, response.body, reader, error);
        throw error;
      }
      text += decoder.decode(bytes, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // The body may already be detached by AbortController/cancel.
    }
  }
}

async function readBoundedBody(response, controller, responseType) {
  const contentLength = Number(response.headers?.get?.('content-length') ?? 0);
  if (Number.isFinite(contentLength) && contentLength > DOMAIN_INVENTORY_RESPONSE_MAX_BYTES) {
    const error = responseTooLargeError();
    abortAndCancelBody(controller, response.body, null, error);
    throw error;
  }

  let text;
  if (response.body && typeof response.body.getReader === 'function') {
    text = await readBoundedStreamBody(response, controller);
  } else if (typeof response.text === 'function') {
    text = await response.text();
    if (new TextEncoder().encode(text).byteLength > DOMAIN_INVENTORY_RESPONSE_MAX_BYTES) {
      const error = responseTooLargeError();
      controller.abort(error);
      throw error;
    }
  } else {
    const body = await response.json();
    const encoded = new TextEncoder().encode(JSON.stringify(body));
    if (encoded.byteLength > DOMAIN_INVENTORY_RESPONSE_MAX_BYTES) {
      const error = responseTooLargeError();
      controller.abort(error);
      throw error;
    }
    return body;
  }

  if (responseType === 'text') return text;
  try {
    return JSON.parse(text);
  } catch {
    throw providerError('Provider returned an invalid JSON response.');
  }
}

export async function boundedFetch(url, {
  headers = {},
  fetchFn = fetch,
  timeoutMs,
  responseType = 'json',
  includeHeaders = false,
} = {}) {
  const parsed = new URL(url);
  const controller = new AbortController();
  const boundedTimeoutMs = timeoutMs ?? resolveConnectorPollFetchTimeoutMs();
  let timer;
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => {
      const error = providerError('Provider inventory request failed within the bounded timeout.');
      controller.abort(error);
      reject(error);
    }, boundedTimeoutMs);
  });
  const request = (async () => {
    const response = await fetchFn(parsed.toString(), {
      method: 'GET',
      headers: { Accept: 'application/json', ...headers },
      redirect: 'manual',
      signal: controller.signal,
    });
    if (response.status >= 300 && response.status < 400) {
      throw providerError('Provider redirects are not followed.', { status: response.status });
    }
    if (!response.ok) {
      const code = response.status === 429
        ? 'rate_limited'
        : response.status === 401 || response.status === 403
          ? 'auth_failed'
          : 'provider_poll_failed';
      const error = providerError(`Provider inventory request failed (${response.status}).`, {
        code,
        status: response.status,
      });
      try {
        error.response_body = await readBoundedBody(response, controller, responseType);
      } catch (bodyError) {
        if (bodyError?.code === 'provider_response_too_large') throw bodyError;
      }
      throw error;
    }
    const body = await readBoundedBody(response, controller, responseType);
    return includeHeaders ? { body, headers: response.headers } : body;
  })();
  try {
    return await Promise.race([request, timeout]);
  } catch (cause) {
    if (cause?.code) throw cause;
    throw providerError('Provider inventory request failed within the bounded timeout.');
  } finally {
    clearTimeout(timer);
  }
}

function ownershipProofTags({
  ownershipEligible = true,
  resourceStatus = 'active',
  providerEnvironment = null,
} = {}) {
  return [
    'provider_zone_inventory',
    `ownership_eligible:${ownershipEligible === true ? 'true' : 'false'}`,
    `resource_status:${normalizedMarker(resourceStatus) || 'unknown'}`,
    ...(providerEnvironment
      ? [`provider_environment:${normalizedMarker(providerEnvironment) || 'unknown'}`]
      : []),
  ];
}

function dnsZoneSnapshot(provider, zone, observedAt, proofMetadata = {}) {
  const name = String(zone?.name ?? zone?.zone ?? zone?.domain ?? '').trim().replace(/\.+$/, '').toLowerCase();
  if (!name) return null;
  const resourceRef = zone?.id ?? zone?.zoneId ?? zone?.domainId ?? name;
  return buildNormalizedSnapshot({
    provider,
    snapshotKind: 'dns_zone',
    resourceRef,
    displayRef: name,
    summary: {
      hostnames: [name],
      tags: ownershipProofTags(proofMetadata),
    },
    observedAt,
  });
}

function inventoryResult(provider, zones, observedAt, {
  truncated = false,
  permissionGaps = [],
  proofMetadata = {},
} = {}) {
  const snapshots = zones
    .slice(0, CONNECTOR_POLL_MAX_INVENTORY_ITEMS)
    .map((zone) => dnsZoneSnapshot(
      provider,
      zone,
      observedAt,
      typeof proofMetadata === 'function' ? proofMetadata(zone) : proofMetadata,
    ))
    .filter(Boolean);
  const inventoryTruncated = truncated || zones.length > CONNECTOR_POLL_MAX_INVENTORY_ITEMS;
  const gaps = [...permissionGaps];
  if (inventoryTruncated && !gaps.includes('truncated_inventory')) gaps.push('truncated_inventory');
  return {
    snapshots,
    health: gaps.length ? 'degraded' : 'active',
    permission_gaps: gaps,
    inventory_complete: !inventoryTruncated,
    inventory_truncated: inventoryTruncated,
  };
}

function requireStrings(credentials, fields, provider) {
  for (const field of fields) {
    if (typeof credentials?.[field] !== 'string' || !credentials[field].trim()) {
      throw providerError(`${provider} credentials are missing ${field}.`, { code: 'credentials_missing' });
    }
  }
}

function akamaiTimestamp(date = new Date()) {
  const iso = date.toISOString();
  return `${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}T${iso.slice(11, 19)}+0000`;
}

function hmacBase64(key, data) {
  return createHmac('sha256', key).update(data).digest('base64');
}

export function buildAkamaiEdgeGridAuthorization({
  method = 'GET',
  host,
  path,
  clientToken,
  clientSecret,
  accessToken,
  now = new Date(),
  nonce = randomUUID(),
}) {
  const timestamp = akamaiTimestamp(now);
  const auth = `EG1-HMAC-SHA256 client_token=${clientToken};access_token=${accessToken};timestamp=${timestamp};nonce=${nonce};`;
  const dataToSign = [method.toUpperCase(), 'https', host, path, '', '', auth].join('\t');
  const signingKey = hmacBase64(clientSecret, timestamp);
  return `${auth}signature=${hmacBase64(signingKey, dataToSign)};`;
}

function normalizeAkamaiHost(value) {
  const host = String(value ?? '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  if (!/^[a-z0-9-]+\.luna\.akamaiapis\.net$/.test(host)) {
    throw providerError('Akamai EdgeDNS host must be a customer luna.akamaiapis.net API host.', { code: 'credentials_missing' });
  }
  return host;
}

export async function pollAkamaiEdgeDns({ credentials, fetchFn = fetch, observedAt, fetchTimeoutMs, now, nonce }) {
  requireStrings(credentials, ['host', 'client_token', 'client_secret', 'access_token'], 'Akamai EdgeDNS');
  const host = normalizeAkamaiHost(credentials.host);
  const path = '/config-dns/v2/zones?showAll=true';
  const authorization = buildAkamaiEdgeGridAuthorization({
    host,
    path,
    clientToken: credentials.client_token,
    clientSecret: credentials.client_secret,
    accessToken: credentials.access_token,
    now: now ?? new Date(),
    nonce,
  });
  const body = await boundedFetch(`https://${host}${path}`, {
    headers: { Authorization: authorization },
    fetchFn,
    timeoutMs: fetchTimeoutMs,
  });
  const zones = Array.isArray(body?.zones) ? body.zones : [];
  return inventoryResult('akamai_edgedns', zones, observedAt, {
    truncated: zones.length > CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
  });
}

function decodeXml(value) {
  return String(value ?? '')
    .replaceAll('&quot;', '"')
    .replaceAll('&apos;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&amp;', '&');
}

function parseNamecheapDomains(xml) {
  const domains = [];
  const domainTag = /<Domain\b([^>]*)\/?\s*>/gi;
  let match;
  while ((match = domainTag.exec(xml)) && domains.length <= CONNECTOR_POLL_MAX_INVENTORY_ITEMS) {
    const attrs = match[1];
    const name = /\bName\s*=\s*"([^"]+)"/i.exec(attrs)?.[1];
    const id = /\bID\s*=\s*"([^"]+)"/i.exec(attrs)?.[1];
    const expiredRaw = /\bIsExpired\s*=\s*"([^"]+)"/i.exec(attrs)?.[1];
    const expires = /\bExpires\s*=\s*"([^"]+)"/i.exec(attrs)?.[1];
    if (name) {
      domains.push({
        name: decodeXml(name),
        id: id ? decodeXml(id) : undefined,
        isExpired: typeof expiredRaw === 'string'
          ? normalizedMarker(expiredRaw) === 'true'
          : null,
        expires: expires ? decodeXml(expires) : null,
      });
    }
  }
  return domains;
}

function namecheapTotalItems(xml, fallback) {
  const canonical = /<TotalItems\b[^>]*>\s*(\d+)\s*<\/TotalItems>/i.exec(xml)?.[1];
  const attribute = /\bTotalItems\s*=\s*"(\d+)"/i.exec(xml)?.[1];
  const parsed = Number(canonical ?? attribute ?? fallback);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function assertNamecheapResponse(xml) {
  if (!/Status\s*=\s*"ERROR"/i.test(xml)) return;
  const message = decodeXml(/<Error\b[^>]*>([^<]*)<\/Error>/i.exec(xml)?.[1] ?? 'Namecheap API error');
  throw providerError(message, {
    code: /1011150/.test(xml) ? 'permission_insufficient' : 'auth_failed',
    status: 403,
  });
}

export async function pollNamecheap({ credentials, fetchFn = fetch, observedAt, fetchTimeoutMs }) {
  requireStrings(credentials, ['api_username', 'api_key', 'client_ip'], 'Namecheap');
  if (isIP(credentials.client_ip) !== 4) {
    throw providerError('Namecheap client_ip must be the explicitly configured IPv4 egress address.', { code: 'credentials_invalid' });
  }
  const environment = credentials.env_type === 'sandbox' ? 'sandbox' : 'production';
  const origin = PROVIDER_ORIGINS.namecheap[environment];
  const pageSize = 100;
  const maxPages = Math.ceil(CONNECTOR_POLL_MAX_INVENTORY_ITEMS / pageSize);
  const zones = [];
  const seen = new Set();
  let total = null;
  let incomplete = false;

  for (let page = 1; page <= maxPages; page += 1) {
    const url = new URL('/xml.response', origin);
    url.searchParams.set('ApiUser', credentials.api_username);
    url.searchParams.set('ApiKey', credentials.api_key);
    url.searchParams.set('UserName', credentials.api_username);
    url.searchParams.set('Command', 'namecheap.domains.getList');
    url.searchParams.set('ClientIp', credentials.client_ip);
    url.searchParams.set('PageSize', String(pageSize));
    url.searchParams.set('Page', String(page));
    const xml = await boundedFetch(url, {
      headers: { Accept: 'application/xml' },
      fetchFn,
      timeoutMs: fetchTimeoutMs,
      responseType: 'text',
    });
    assertNamecheapResponse(xml);
    const pageZones = parseNamecheapDomains(xml);
    total = namecheapTotalItems(xml, total ?? pageZones.length);
    let added = 0;
    for (const zone of pageZones) {
      const key = String(zone.id ?? zone.name).trim().toLowerCase();
      if (!key || seen.has(key)) continue;
      seen.add(key);
      zones.push(zone);
      added += 1;
      if (zones.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS) break;
    }
    if (zones.length >= Math.min(total, CONNECTOR_POLL_MAX_INVENTORY_ITEMS)) break;
    if (pageZones.length === 0 || added === 0) {
      incomplete = true;
      break;
    }
  }

  const inventoryTruncated = incomplete || Number(total ?? zones.length) > zones.length;
  return inventoryResult('namecheap', zones, observedAt, {
    truncated: inventoryTruncated,
    proofMetadata: (zone) => {
      const active = environment === 'production' && zone.isExpired === false;
      return {
        ownershipEligible: active,
        resourceStatus: zone.isExpired === false ? 'active' : zone.isExpired === true ? 'expired' : 'unknown',
        providerEnvironment: environment,
      };
    },
  });
}

export async function pollGoDaddy({ credentials, fetchFn = fetch, observedAt, fetchTimeoutMs }) {
  requireStrings(credentials, ['key', 'secret'], 'GoDaddy');
  const url = new URL('/v1/domains', PROVIDER_ORIGINS.godaddy);
  url.searchParams.set('limit', String(CONNECTOR_POLL_MAX_INVENTORY_ITEMS));
  const body = await boundedFetch(url, {
    headers: { Authorization: `sso-key ${credentials.key}:${credentials.secret}` },
    fetchFn,
    timeoutMs: fetchTimeoutMs,
  });
  const zones = Array.isArray(body) ? body : [];
  return inventoryResult('godaddy', zones, observedAt, {
    truncated: zones.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
    proofMetadata: (zone) => {
      const resourceStatus = normalizedMarker(zone?.status) || 'unknown';
      return {
        ownershipEligible: resourceStatus === 'active',
        resourceStatus,
      };
    },
  });
}

export async function pollIbmNs1({ credentials, fetchFn = fetch, observedAt, fetchTimeoutMs }) {
  requireStrings(credentials, ['api_key'], 'IBM NS1');
  const url = new URL('/v1/zones', PROVIDER_ORIGINS.ibm_ns1);
  url.searchParams.set('limit', String(CONNECTOR_POLL_MAX_INVENTORY_ITEMS));
  const result = await boundedFetch(url, {
    headers: { 'X-NSONE-Key': credentials.api_key },
    fetchFn,
    timeoutMs: fetchTimeoutMs,
    includeHeaders: true,
  });
  const body = result.body;
  const zones = Array.isArray(body) ? body : Array.isArray(body?.zones) ? body.zones : [];
  const link = result.headers?.get?.('link') ?? '';
  return inventoryResult('ibm_ns1', zones, observedAt, {
    truncated: zones.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS || /rel="?next"?/i.test(link),
  });
}

export const akamaiEdgeDnsProvider = {
  provider: 'akamai_edgedns',
  required_scopes: ['DNS—Zone Record Management:READ-ONLY'],
  snapshot_kinds: ['dns_zone'],
  poll: pollAkamaiEdgeDns,
};

export const namecheapProvider = {
  provider: 'namecheap',
  required_scopes: ['domains:getList', 'allowlisted_client_ip'],
  snapshot_kinds: ['dns_zone'],
  poll: pollNamecheap,
};

export const godaddyProvider = {
  provider: 'godaddy',
  required_scopes: ['domains:read'],
  snapshot_kinds: ['dns_zone'],
  poll: pollGoDaddy,
};

export const ibmNs1Provider = {
  provider: 'ibm_ns1',
  required_scopes: ['dns.view_zones'],
  snapshot_kinds: ['dns_zone'],
  poll: pollIbmNs1,
};
