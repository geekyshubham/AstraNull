#!/usr/bin/env node
/**
 * Generates packed ASN and cloud provider CIDR data from RADB/BGP origins.
 *
 * This provides local, offline, deterministic IP-to-ASN mapping and cloud provider detection
 * for providers such as Hetzner, DigitalOcean, OVH, Vultr, Linode, Scaleway, Leaseweb, etc.
 *
 * Output: src/lib/data/asnCloudData.mjs
 */

import { execFileSync } from 'node:child_process';
import { isIP } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

export const TARGET_PROVIDERS = [
  {
    provider: 'hetzner',
    name: 'Hetzner',
    asns: [24940, 213230],
    primaryAsn: 24940,
    org: 'Hetzner Online GmbH',
    country: 'DE',
  },
  {
    provider: 'digitalocean',
    name: 'DigitalOcean',
    asns: [14061, 62567, 393406],
    primaryAsn: 14061,
    org: 'DigitalOcean, LLC',
    country: 'US',
  },
  {
    provider: 'ovh',
    name: 'OVHcloud',
    asns: [16276, 35540],
    primaryAsn: 16276,
    org: 'OVH SAS',
    country: 'FR',
  },
  {
    provider: 'vultr',
    name: 'Vultr',
    asns: [20473],
    primaryAsn: 20473,
    org: 'The Constant Company, LLC',
    country: 'US',
  },
  {
    provider: 'linode',
    name: 'Linode',
    asns: [63949],
    primaryAsn: 63949,
    org: 'Linode, LLC (Akamai Connected Cloud)',
    country: 'US',
  },
  {
    provider: 'scaleway',
    name: 'Scaleway',
    asns: [12876],
    primaryAsn: 12876,
    org: 'SCALEWAY S.A.S.',
    country: 'FR',
  },
  {
    provider: 'leaseweb',
    name: 'Leaseweb',
    asns: [60781, 16265, 28753],
    primaryAsn: 60781,
    org: 'Leaseweb',
    country: 'NL',
  },
  {
    provider: 'oracle',
    name: 'Oracle Cloud',
    asns: [31898],
    primaryAsn: 31898,
    org: 'Oracle Corporation',
    country: 'US',
  },
  {
    provider: 'contabo',
    name: 'Contabo',
    asns: [51167],
    primaryAsn: 51167,
    org: 'Contabo GmbH',
    country: 'DE',
  },
  {
    provider: 'hostinger',
    name: 'Hostinger',
    asns: [47583],
    primaryAsn: 47583,
    org: 'Hostinger International Limited',
    country: 'CY',
  },
  {
    provider: 'upcloud',
    name: 'UpCloud',
    asns: [202154],
    primaryAsn: 202154,
    org: 'UpCloud Ltd',
    country: 'FI',
  },
  {
    provider: 'equinix',
    name: 'Equinix Metal',
    asns: [54888],
    primaryAsn: 54888,
    org: 'Equinix Metal',
    country: 'US',
  },
];

export const ASN_CATALOG = [
  ...TARGET_PROVIDERS.flatMap((tp) => tp.asns.map((asn) => ({
    asn,
    provider: tp.provider,
    name: tp.name,
    org: tp.org,
    family: 'cloud',
    country: tp.country,
  }))),
  // Also include ASNs for major cloud/CDN providers for reverse ASN lookups
  { asn: 16509, provider: 'aws', name: 'AWS', org: 'Amazon.com, Inc.', family: 'cloud', country: 'US' },
  { asn: 14618, provider: 'aws', name: 'AWS', org: 'Amazon.com, Inc.', family: 'cloud', country: 'US' },
  { asn: 15169, provider: 'google', name: 'Google Cloud', org: 'Google LLC', family: 'cloud', country: 'US' },
  { asn: 396982, provider: 'google', name: 'Google Cloud', org: 'Google Cloud', family: 'cloud', country: 'US' },
  { asn: 8075, provider: 'azure', name: 'Microsoft Azure', org: 'Microsoft Corporation', family: 'cloud', country: 'US' },
  { asn: 8068, provider: 'azure', name: 'Microsoft Azure', org: 'Microsoft Corporation', family: 'cloud', country: 'US' },
  { asn: 8069, provider: 'azure', name: 'Microsoft Azure', org: 'Microsoft Corporation', family: 'cloud', country: 'US' },
  { asn: 13335, provider: 'cloudflare', name: 'Cloudflare', org: 'Cloudflare, Inc.', family: 'cdn', country: 'US' },
  { asn: 20940, provider: 'akamai', name: 'Akamai', org: 'Akamai International B.V.', family: 'cdn', country: 'NL' },
  { asn: 16625, provider: 'akamai', name: 'Akamai', org: 'Akamai Technologies, Inc.', family: 'cdn', country: 'US' },
  { asn: 32787, provider: 'akamai', name: 'Akamai', org: 'Akamai Technologies, Inc.', family: 'cdn', country: 'US' },
  { asn: 35994, provider: 'akamai', name: 'Akamai', org: 'Akamai Technologies, Inc.', family: 'cdn', country: 'US' },
  { asn: 54113, provider: 'fastly', name: 'Fastly', org: 'Fastly, Inc.', family: 'cdn', country: 'US' },
  { asn: 45102, provider: 'alibaba', name: 'Alibaba Cloud', org: 'Alibaba (US) Technology Co., Ltd.', family: 'cloud', country: 'US' },
  { asn: 37963, provider: 'alibaba', name: 'Alibaba Cloud', org: 'Hangzhou Alibaba Advertising Co., Ltd.', family: 'cloud', country: 'CN' },
  { asn: 132203, provider: 'tencent', name: 'Tencent Cloud', org: 'Tencent Building, Kejizhongyi Avenue', family: 'cloud', country: 'CN' },
  { asn: 45090, provider: 'tencent', name: 'Tencent Cloud', org: 'Shenzhen Tencent Computer Systems', family: 'cloud', country: 'CN' },
];

function ipv6Bytes(address) {
  const [head, tail = ''] = address.toLowerCase().split('::');
  const expand = (text) => (text ? text.split(':') : []).flatMap((group) => {
    if (group.includes('.')) {
      const octets = group.split('.').map(Number);
      return [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
    }
    return [Number.parseInt(group, 16)];
  });
  const headGroups = expand(head);
  const tailGroups = expand(tail);
  const groups = address.includes('::')
    ? [...headGroups, ...Array(8 - headGroups.length - tailGroups.length).fill(0), ...tailGroups]
    : headGroups;
  if (groups.length !== 8 || groups.some((group) => !Number.isInteger(group) || group < 0 || group > 0xffff)) {
    throw new Error(`cannot pack IPv6 range ${address}`);
  }
  return groups.flatMap((group) => [group >> 8, group & 0xff]);
}

export function packRanges(ranges) {
  const families = { v4: [], v6: [] };
  for (const cidr of ranges) {
    const [address, prefixText] = cidr.split('/');
    const prefix = Number(prefixText);
    const version = isIP(address);
    if (!version || !Number.isInteger(prefix) || prefix < 0 || prefix > (version === 4 ? 32 : 128)) {
      throw new Error(`invalid ASN prefix ${cidr}`);
    }
    const bytes = version === 4 ? address.split('.').map(Number) : ipv6Bytes(address);
    const kept = Math.ceil(prefix / 8);
    families[version === 4 ? 'v4' : 'v6'].push(Buffer.from([prefix, ...bytes.slice(0, kept)]));
  }
  return {
    v4: Buffer.concat(families.v4).toString('hex'),
    v6: Buffer.concat(families.v6).toString('hex'),
    count: ranges.length,
  };
}

/** Current RIS network routes, kept separate from the pinned upstream/cloud corpus. */
export async function generateAsnEdgeData(fetchFn = fetch) {
  const networks = ASN_CATALOG.filter((entry) => [16625, 20940, 13335, 54113, 16509].includes(entry.asn));
  const ranges = {};
  const sources = [];
  for (const network of networks) {
    const url = `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${network.asn}`;
    const response = await fetchFn(url, { signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`RIS lookup failed for AS${network.asn}: ${response.status}`);
    const result = await response.json();
    const data = result.data;
    if (result.status !== 'ok' || String(data?.resource).replace(/^AS/, '') !== String(network.asn) || !data.latest_time) {
      throw new Error(`invalid RIS response for AS${network.asn}`);
    }
    // The API's default window includes withdrawn routes. Retain only routes seen at its latest time.
    const prefixes = [...new Set((data.prefixes ?? [])
      .filter((entry) => entry.timelines?.some((period) => period.starttime <= data.latest_time
        && period.endtime >= data.latest_time))
      .map((entry) => entry.prefix))].sort();
    if (!prefixes.length) throw new Error(`empty current RIS routes for AS${network.asn}`);
    ranges[network.asn] = packRanges(prefixes);
    sources.push({ asn: network.asn, url, observed_at: data.latest_time, count: prefixes.length });
  }
  const version = createHash('sha256').update(JSON.stringify({ sources, ranges })).digest('hex');
  return `/** Generated by scripts/generate-asn-cloud-data.mjs --edge. Network ownership only; no WAF inference. */
export const ASN_EDGE_DATA_VERSION = 'sha256:${version}';
export const ASN_EDGE_DATA_MANIFEST = Object.freeze(${JSON.stringify({ version: 1, sources }, null, 2)});
export const ASN_EDGE_ADDRESS_RANGES_PACKED = Object.freeze(${JSON.stringify(ranges, null, 2)});
`;
}

export function fetchRoutesForAsn(asnStr) {
  try {
    const raw = execFileSync('whois', ['-h', 'whois.radb.net', '--', `-i origin ${asnStr}`], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      timeout: 20000,
    });
    const v4 = [...new Set([...raw.matchAll(/^route:\s*([^\s]+)/gm)].map((m) => m[1]))];
    const v6 = [...new Set([...raw.matchAll(/^route6:\s*([^\s]+)/gm)].map((m) => m[1]))];
    return [...v4, ...v6];
  } catch (err) {
    console.warn(`Warning: failed to query RADB for ${asnStr}: ${err.message}`);
    return [];
  }
}

export async function generateAsnCloudData() {
  const packedData = {};
  const providerStats = {};

  for (const item of TARGET_PROVIDERS) {
    console.log(`Querying BGP routes for ${item.provider} (${item.asns.map((a) => `AS${a}`).join(', ')})...`);
    const allCidrs = [];
    for (const asn of item.asns) {
      const cidrs = fetchRoutesForAsn(`AS${asn}`);
      allCidrs.push(...cidrs);
    }
    const unique = [...new Set(allCidrs)].sort();
    packedData[item.provider] = packRanges(unique);
    providerStats[item.provider] = {
      asns: item.asns,
      totalRanges: unique.length,
      primaryAsn: item.primaryAsn,
      org: item.org,
      name: item.name,
    };
    console.log(`  ${item.provider}: ${unique.length} CIDRs packed`);
  }

  const moduleContent = `/**
 * Packed cloud provider address ranges derived from authoritative BGP ASN origin routes (RADB/IRR).
 * GENERATED by \`scripts/generate-asn-cloud-data.mjs\`.
 *
 * Provides offline, high-performance IP-to-cloud mapping for providers without official JSON feeds
 * (such as Hetzner, DigitalOcean, OVHcloud, Vultr, Linode, Scaleway, Leaseweb, etc.).
 */

export const ASN_CLOUD_ADDRESS_RANGES_PACKED = Object.freeze(${JSON.stringify(packedData, null, 2)});

export const ASN_REGISTRY = Object.freeze(${JSON.stringify(ASN_CATALOG, null, 2)});

export const ASN_PROVIDER_METADATA = Object.freeze(${JSON.stringify(providerStats, null, 2)});
`;

  return moduleContent;
}

async function main() {
  const edgeOnly = process.argv.includes('--edge');
  const content = edgeOnly ? await generateAsnEdgeData() : await generateAsnCloudData();
  const outPath = path.resolve(edgeOnly ? 'src/lib/data/asnEdgeData.mjs' : 'src/lib/data/asnCloudData.mjs');
  writeFileSync(outPath, content, 'utf8');
  console.log(`Wrote ASN ${edgeOnly ? 'edge' : 'cloud'} data to ${outPath}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
