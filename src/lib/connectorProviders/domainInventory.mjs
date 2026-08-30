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

const PROVIDER_VERIFIED_DNS_PROVIDER_SET = new Set(PROVIDER_VERIFIED_DNS_PROVIDERS);

function sameInstant(left, right) {
  const leftMs = Date.parse(String(left ?? ''));
  const rightMs = Date.parse(String(right ?? ''));
  return Number.isFinite(leftMs) && Number.isFinite(rightMs) && leftMs === rightMs;
}

export function isCurrentSuccessfulProviderSnapshot(connector, snapshot) {
  return snapshot?.evidence_source === 'provider_api'
    && sameInstant(snapshot?.observed_at, connector?.last_success_at);
}

export function isProviderVerifiedDnsEvidence(connector, evidence) {
  const provider = String(connector?.provider ?? '');
  const hasSecret = connector?.has_secret === true
    || (typeof connector?.secret_id === 'string' && connector.secret_id.trim().length > 0);
  return Boolean(
    PROVIDER_VERIFIED_DNS_PROVIDER_SET.has(provider)
    && String(evidence?.provider ?? '') === provider
    && evidence?.snapshot_kind === 'dns_zone'
    && evidence?.evidence_source === 'provider_api'
    && evidence?.candidate_source === 'snapshot_inventory'
    && isCurrentSuccessfulProviderSnapshot(connector, evidence)
    && ['fqdn', 'dns_zone'].includes(evidence?.kind)
    && ['active', 'degraded'].includes(String(connector?.status ?? '').toLowerCase())
    && hasSecret
    && evidence?.snapshot_id
    && evidence?.resource_ref,
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

async function boundedFetch(url, { headers = {}, fetchFn = fetch, timeoutMs } = {}) {
  const parsed = new URL(url);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs ?? resolveConnectorPollFetchTimeoutMs());
  let response;
  try {
    response = await fetchFn(parsed, {
      method: 'GET',
      headers: { Accept: 'application/json', ...headers },
      redirect: 'manual',
      signal: controller.signal,
    });
  } catch (cause) {
    throw providerError('Provider inventory request failed within the bounded timeout.', { code: 'provider_poll_failed' });
  } finally {
    clearTimeout(timer);
  }
  if (response.status >= 300 && response.status < 400) {
    throw providerError('Provider redirects are not followed.', { status: response.status });
  }
  if (!response.ok) {
    const code = response.status === 429
      ? 'rate_limited'
      : response.status === 401 || response.status === 403
        ? 'auth_failed'
        : 'provider_poll_failed';
    throw providerError(`Provider inventory request failed (${response.status}).`, { code, status: response.status });
  }
  return response;
}

function dnsZoneSnapshot(provider, zone, observedAt) {
  const name = String(zone?.name ?? zone?.zone ?? zone?.domain ?? '').trim().replace(/\.+$/, '').toLowerCase();
  if (!name) return null;
  const resourceRef = zone?.id ?? zone?.zoneId ?? zone?.domainId ?? name;
  return buildNormalizedSnapshot({
    provider,
    snapshotKind: 'dns_zone',
    resourceRef,
    displayRef: name,
    summary: { hostnames: [name], tags: ['provider_zone_inventory'] },
    observedAt,
  });
}

function inventoryResult(provider, zones, observedAt, { truncated = false, permissionGaps = [] } = {}) {
  const snapshots = zones
    .slice(0, CONNECTOR_POLL_MAX_INVENTORY_ITEMS)
    .map((zone) => dnsZoneSnapshot(provider, zone, observedAt))
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

function parseJsonResponse(response) {
  return response.json().catch(() => {
    throw providerError('Provider returned an invalid JSON response.');
  });
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
  const response = await boundedFetch(`https://${host}${path}`, {
    headers: { Authorization: authorization },
    fetchFn,
    timeoutMs: fetchTimeoutMs,
  });
  const body = await parseJsonResponse(response);
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
    if (name) domains.push({ name: decodeXml(name), id: id ? decodeXml(id) : undefined });
  }
  return domains;
}

export async function pollNamecheap({ credentials, fetchFn = fetch, observedAt, fetchTimeoutMs }) {
  requireStrings(credentials, ['api_username', 'api_key', 'client_ip'], 'Namecheap');
  if (isIP(credentials.client_ip) !== 4) {
    throw providerError('Namecheap client_ip must be the explicitly configured IPv4 egress address.', { code: 'credentials_invalid' });
  }
  const environment = credentials.env_type === 'sandbox' ? 'sandbox' : 'production';
  const origin = PROVIDER_ORIGINS.namecheap[environment];
  const url = new URL('/xml.response', origin);
  url.searchParams.set('ApiUser', credentials.api_username);
  url.searchParams.set('ApiKey', credentials.api_key);
  url.searchParams.set('UserName', credentials.api_username);
  url.searchParams.set('Command', 'namecheap.domains.getList');
  url.searchParams.set('ClientIp', credentials.client_ip);
  url.searchParams.set('PageSize', String(CONNECTOR_POLL_MAX_INVENTORY_ITEMS));
  const response = await boundedFetch(url, {
    headers: { Accept: 'application/xml' },
    fetchFn,
    timeoutMs: fetchTimeoutMs,
  });
  const xml = await response.text();
  if (/Status\s*=\s*"ERROR"/i.test(xml)) {
    const message = decodeXml(/<Error\b[^>]*>([^<]*)<\/Error>/i.exec(xml)?.[1] ?? 'Namecheap API error');
    throw providerError(message, { code: /1011150/.test(xml) ? 'permission_insufficient' : 'auth_failed', status: 403 });
  }
  const zones = parseNamecheapDomains(xml);
  const total = Number(/TotalItems\s*=\s*"(\d+)"/i.exec(xml)?.[1] ?? zones.length);
  return inventoryResult('namecheap', zones, observedAt, { truncated: total > zones.length });
}

export async function pollGoDaddy({ credentials, fetchFn = fetch, observedAt, fetchTimeoutMs }) {
  requireStrings(credentials, ['key', 'secret'], 'GoDaddy');
  const url = new URL('/v1/domains', PROVIDER_ORIGINS.godaddy);
  url.searchParams.set('limit', String(CONNECTOR_POLL_MAX_INVENTORY_ITEMS));
  const response = await boundedFetch(url, {
    headers: { Authorization: `sso-key ${credentials.key}:${credentials.secret}` },
    fetchFn,
    timeoutMs: fetchTimeoutMs,
  });
  const body = await parseJsonResponse(response);
  const zones = Array.isArray(body) ? body : [];
  return inventoryResult('godaddy', zones, observedAt, {
    truncated: zones.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
  });
}

export async function pollIbmNs1({ credentials, fetchFn = fetch, observedAt, fetchTimeoutMs }) {
  requireStrings(credentials, ['api_key'], 'IBM NS1');
  const url = new URL('/v1/zones', PROVIDER_ORIGINS.ibm_ns1);
  url.searchParams.set('limit', String(CONNECTOR_POLL_MAX_INVENTORY_ITEMS));
  const response = await boundedFetch(url, {
    headers: { 'X-NSONE-Key': credentials.api_key },
    fetchFn,
    timeoutMs: fetchTimeoutMs,
  });
  const body = await parseJsonResponse(response);
  const zones = Array.isArray(body) ? body : Array.isArray(body?.zones) ? body.zones : [];
  const link = response.headers?.get?.('link') ?? '';
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
