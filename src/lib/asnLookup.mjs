/**
 * ASN and Cloud Provider Lookup Engine (faithful in-process port of asnmap semantics).
 *
 * Provides:
 * 1. Fast, offline, deterministic IP-to-ASN and cloud provider lookup for major hosting/cloud
 *    providers (Hetzner, DigitalOcean, OVHcloud, Vultr, Linode, Scaleway, Leaseweb, etc.).
 * 2. ASN-to-Provider mapping covering hyperscalers, hosting platforms, and edge networks.
 * 3. Optional DNS-based ASN resolution via Team Cymru IP-to-ASN mapping (origin.asn.cymru.com)
 *    when live network hints are enabled.
 *
 * Sends no traffic by default. Operates purely in-memory over packed BGP routing tables.
 */

import { isIP } from 'node:net';
import { resolveTxt } from 'node:dns/promises';
import {
  ASN_CLOUD_ADDRESS_RANGES_PACKED,
  ASN_REGISTRY,
  ASN_PROVIDER_METADATA,
} from './data/asnCloudData.mjs';
import { ASN_EDGE_ADDRESS_RANGES_PACKED, ASN_EDGE_DATA_MANIFEST, ASN_EDGE_DATA_VERSION } from './data/asnEdgeData.mjs';

export { ASN_REGISTRY, ASN_PROVIDER_METADATA, ASN_EDGE_DATA_MANIFEST, ASN_EDGE_DATA_VERSION };

const ASN_MAP_BY_NUMBER = new Map(ASN_REGISTRY.map((entry) => [entry.asn, entry]));

export function getKnownAsnInfo(asnNumber) {
  const num = Number(asnNumber);
  if (!Number.isInteger(num)) return null;
  return ASN_MAP_BY_NUMBER.get(num) ?? null;
}

function ipv4ToBigint(ip) {
  if (isIP(ip) !== 4) return null;
  const parts = ip.split('.').map(Number);
  return (BigInt(parts[0]) << 24n) | (BigInt(parts[1]) << 16n)
    | (BigInt(parts[2]) << 8n) | BigInt(parts[3]);
}

function ipv6Groups(ip) {
  if (isIP(ip) !== 6 || ip.split('::').length > 2) return null;
  const hasCompression = ip.includes('::');
  const [headText, tailText = ''] = ip.toLowerCase().split('::');

  const parseSide = (text) => {
    if (!text) return [];
    const tokens = text.split(':');
    const groups = [];
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index];
      if (token.includes('.')) {
        if (index !== tokens.length - 1) return null;
        const ipv4 = ipv4ToBigint(token);
        if (ipv4 === null) return null;
        groups.push(Number((ipv4 >> 16n) & 0xffffn), Number(ipv4 & 0xffffn));
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(token)) return null;
      groups.push(Number.parseInt(token, 16));
    }
    return groups;
  };

  const head = parseSide(headText);
  const tail = parseSide(tailText);
  if (!head || !tail) return null;
  if (!hasCompression) return head.length === 8 ? head : null;
  const missing = 8 - head.length - tail.length;
  if (missing < 1) return null;
  return [...head, ...Array(missing).fill(0), ...tail];
}

function parseIpAddress(ip) {
  const value = String(ip ?? '').trim();
  const v4 = ipv4ToBigint(value);
  if (v4 !== null) return { version: 4, value: v4 };
  const groups = ipv6Groups(value);
  if (!groups) return null;

  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    return { version: 4, value: (BigInt(groups[6]) << 16n) | BigInt(groups[7]) };
  }

  let numeric = 0n;
  for (const group of groups) numeric = (numeric << 16n) | BigInt(group);
  return { version: 6, value: numeric };
}

function sortAndPack(list) {
  list.sort((a, b) => (
    a.start < b.start ? -1
      : a.start > b.start ? 1
        : a.end < b.end ? -1
          : a.end > b.end ? 1
            : a.provider < b.provider ? -1
              : a.provider > b.provider ? 1 : 0
  ));
  let maxSpan = null;
  for (const row of list) {
    const span = row.end - row.start;
    if (maxSpan === null || span > maxSpan) maxSpan = span;
  }
  return { rows: list, starts: list.map((row) => row.start), maxSpan };
}

function pushInterval(rows, interval, provider) {
  if (interval.version === 4) {
    rows.v4.push({ start: Number(interval.start), end: Number(interval.end), provider });
  } else {
    rows.v6.push({ start: interval.start, end: interval.end, provider });
  }
}

function unpackFamily(encoded, version, provider, rows) {
  const bytes = Buffer.from(String(encoded ?? ''), 'hex');
  const width = version === 4 ? 4 : 16;
  let offset = 0;
  while (offset < bytes.length) {
    const prefix = bytes[offset];
    const kept = Math.ceil(prefix / 8);
    if (prefix > width * 8 || offset + 1 + kept > bytes.length) {
      throw new Error(`invalid packed cloud range for ${provider}`);
    }
    let base = 0n;
    for (let index = 0; index < width; index += 1) {
      base = (base << 8n) | BigInt(index < kept ? bytes[offset + 1 + index] : 0);
    }
    const hostBits = BigInt(width * 8 - prefix);
    const start = (base >> hostBits) << hostBits;
    pushInterval(rows, { version, start, end: start + (1n << hostBits) - 1n }, provider);
    offset += 1 + kept;
  }
}

let compiledAsnIndex = null;

function getAsnAddressIndex() {
  if (compiledAsnIndex) return compiledAsnIndex;
  const rows = { v4: [], v6: [] };
  for (const [provider, families] of Object.entries(ASN_CLOUD_ADDRESS_RANGES_PACKED)) {
    unpackFamily(families.v4, 4, provider, rows);
    unpackFamily(families.v6, 6, provider, rows);
  }
  for (const [asn, families] of Object.entries(ASN_EDGE_ADDRESS_RANGES_PACKED)) {
    unpackFamily(families.v4, 4, `AS${asn}`, rows);
    unpackFamily(families.v6, 6, `AS${asn}`, rows);
  }
  compiledAsnIndex = { v4: sortAndPack(rows.v4), v6: sortAndPack(rows.v6) };
  return compiledAsnIndex;
}

/**
 * Fast in-memory lookup of an IP against the packed cloud provider BGP prefix tables.
 *
 * @param {string} ip
 * @returns {{ provider: string, name: string, org: string, asn: number, country: string, family: string } | null}
 */
export function lookupAsnForIp(ip) {
  const parsed = parseIpAddress(ip);
  if (!parsed) return null;
  const { rows, starts, maxSpan } = getAsnAddressIndex()[parsed.version === 4 ? 'v4' : 'v6'];
  if (rows.length === 0) return null;
  const value = parsed.version === 4 ? Number(parsed.value) : parsed.value;
  let low = 0;
  let high = starts.length - 1;
  let index = -1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (starts[middle] <= value) {
      index = middle;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  if (index < 0) return null;
  const floor = value - maxSpan;
  // Pick the most specific match (shortest span / highest start)
  let bestMatch = null;
  for (let cursor = index; cursor >= 0; cursor -= 1) {
    const row = rows[cursor];
    if (row.start < floor) break;
    if (value >= row.start && value <= row.end) {
      const span = row.end - row.start;
      if (!bestMatch || span < bestMatch.span) {
        bestMatch = { provider: row.provider, span };
      }
    }
  }
  if (!bestMatch) return null;
  if (bestMatch.provider.startsWith('AS')) {
    const registry = ASN_MAP_BY_NUMBER.get(Number(bestMatch.provider.slice(2)));
    if (!registry) return null;
    return { ...registry, source: 'asn_range' };
  }
  const meta = ASN_PROVIDER_METADATA[bestMatch.provider];
  const primaryAsn = meta?.primaryAsn ?? null;
  const reg = primaryAsn ? ASN_MAP_BY_NUMBER.get(primaryAsn) : null;
  return {
    provider: bestMatch.provider,
    name: meta?.name ?? bestMatch.provider,
    org: meta?.org ?? '',
    asn: primaryAsn,
    asns: meta?.asns ?? [],
    family: 'cloud',
    country: reg?.country ?? null,
    source: 'asn_range',
  };
}

/**
 * Given a list of resolved IP addresses, returns all cloud/hosting providers matched via ASN tables.
 *
 * @param {string[]} ips
 * @returns {Array<{ provider: string, name: string, org: string, asn: number, family: string, ip: string, source: string }>}
 */
export function classifyCloudByAsn(ips) {
  const list = (Array.isArray(ips) ? ips : [ips]).slice(0, 64);
  const seen = new Set();
  const results = [];
  for (const raw of list) {
    const ip = String(raw ?? '').trim();
    if (!ip) continue;
    const hit = lookupAsnForIp(ip);
    if (hit) {
      const key = `${hit.family}:${hit.provider}`;
      if (!seen.has(key)) {
        seen.add(key);
        results.push({ ...hit, ip, source: 'asn_lookup' });
      }
    }
  }
  const cloudMatches = results.filter((result) => result.family === 'cloud');
  results.cloud_hosted = cloudMatches.length > 0;
  results.cloud_providers = [...new Set(cloudMatches.map((r) => r.provider))].sort();
  results.asn_matches = [...results];
  results.primary_asn = results[0] ?? null;
  return results;
}

/**
 * Format a reverse DNS query for Team Cymru IP-to-ASN mapping.
 * IPv4: 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com
 * IPv6: expanded nibbles reversed -> ...origin6.asn.cymru.com
 */
export function formatCymruDnsQuery(ip) {
  const parsed = parseIpAddress(ip);
  if (!parsed) return null;
  if (parsed.version === 4) {
    const parts = String(ip).trim().split('.').reverse().join('.');
    return `${parts}.origin.asn.cymru.com`;
  }
  // IPv6 nibble reversal
  const hex = parsed.value.toString(16).padStart(32, '0');
  const nibbles = hex.split('').reverse().join('.');
  return `${nibbles}.origin6.asn.cymru.com`;
}

export const ipToCymruDnsName = formatCymruDnsQuery;

/**
 * Parse a standard Team Cymru TXT record response.
 * Example: "24940 | 49.12.0.0/16 | DE | ripencc | 2010-10-21"
 */
export function parseCymruTxtRecord(txt) {
  const line = String(txt ?? '').trim().replace(/^"|"$/g, '');
  const parts = line.split('|').map((part) => part.trim());
  if (parts.length < 3) return null;
  const asnNumber = Number(parts[0].split(/\s+/)[0]);
  if (!Number.isInteger(asnNumber) || asnNumber <= 0) return null;
  const cidr = parts[1] || '';
  const country = parts[2] || '';
  const registry = parts[3] || '';
  const allocated = parts[4] || '';
  const known = ASN_MAP_BY_NUMBER.get(asnNumber);
  return {
    asn: asnNumber,
    cidr,
    prefix: cidr,
    country,
    registry,
    allocated,
    provider: known?.provider ?? null,
    name: known?.name ?? `AS${asnNumber}`,
    org: known?.org ?? '',
    family: known?.family ?? 'cloud',
  };
}

export const parseCymruAsnTxt = parseCymruTxtRecord;

/**
 * Query Team Cymru origin.asn.cymru.com via DNS TXT record.
 * Bounded single-lookup helper with dependency injection for hermetic testing.
 *
 * @param {string} ip
 * @param {{ resolveTxtFn?: typeof resolveTxt }} [deps]
 */
export async function queryAsnViaDns(ip, deps = {}) {
  const queryName = formatCymruDnsQuery(ip);
  if (!queryName) return null;
  const resolveTxtFn = deps.resolveTxtFn ?? resolveTxt;
  try {
    const records = await resolveTxtFn(queryName);
    if (!Array.isArray(records) || records.length === 0) return null;
    const flat = records.map((entry) => (Array.isArray(entry) ? entry.join('') : String(entry)));
    for (const text of flat) {
      const parsed = parseCymruTxtRecord(text);
      if (parsed) {
        return {
          ...parsed,
          ip: String(ip).trim(),
          source: 'cymru_dns',
        };
      }
    }
  } catch {
    return null;
  }
  return null;
}
