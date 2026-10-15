// DNS path from a recorded edge observation (GET /v1/targets/:id `edge_detection`); never a lookup.

export type DnsPathKind = 'cname' | 'address' | 'address_unchecked' | 'declared_ip' | 'not_observed';

export type DnsPathMatch = { provider: string; family: string };

export type DnsPath = {
  kind: DnsPathKind;
  recordLabel: string;
  summary: string;
  host: string;
  aliases: string[];
  addresses: string[];
  aliasMatch: DnsPathMatch | null;
  addressMatches: DnsPathMatch[];
  observedAt: string;
};

type Rec = Record<string, unknown>;

const HOSTLESS_KINDS = new Set(['ip']);

function asRecord(value: unknown): Rec | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Rec : null;
}

function asList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function normalizeHost(value: unknown) {
  return String(value ?? '').trim().toLowerCase().replace(/\.+$/, '');
}

export function isIpLiteral(value: string) {
  const host = value.replace(/^\[|\]$/g, '');
  if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(host)) return host.split('.').every((part) => Number(part) <= 255);
  return host.includes(':') && /^[0-9a-f:.]+$/i.test(host);
}

/** Hostname (or IP literal) the declared value names. Empty when none can be read. */
export function declaredHost(kind: string, value: string) {
  const raw = value.trim();
  if (!raw) return '';
  const normalizedKind = kind.trim().toLowerCase();
  if (HOSTLESS_KINDS.has(normalizedKind)) return normalizeHost(raw);
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    try {
      return normalizeHost(new URL(raw).hostname).replace(/^\[|\]$/g, '');
    } catch {
      return '';
    }
  }
  if (normalizedKind === 'tcp') {
    const bracketed = raw.match(/^\[([^\]]+)\](?::\d+)?$/);
    if (bracketed) return normalizeHost(bracketed[1]);
    const colons = raw.split(':').length - 1;
    return normalizeHost(colons === 1 ? raw.slice(0, raw.lastIndexOf(':')) : raw);
  }
  return normalizeHost(raw.split('/')[0]);
}

function uniqueHosts(values: unknown[]) {
  const out: string[] = [];
  for (const value of values) {
    const host = normalizeHost(value);
    if (host && !out.includes(host)) out.push(host);
  }
  return out;
}

function addressRecordLabel(addresses: string[]) {
  const v6 = addresses.some((address) => address.includes(':'));
  const v4 = addresses.some((address) => !address.includes(':'));
  if (v4 && v6) return 'A + AAAA';
  return v6 ? 'AAAA' : 'A';
}

function matchFor(evidence: Rec, aliases: string[]): DnsPathMatch | null {
  for (const field of ['cname_cdn_matches', 'cname_matches']) {
    for (const raw of asList(evidence[field])) {
      const match = asRecord(raw);
      const provider = String(match?.provider ?? '').trim();
      if (!provider || !aliases.includes(normalizeHost(match?.host))) continue;
      return { provider, family: String(match?.family ?? match?.type ?? '').trim().toLowerCase() };
    }
  }
  return null;
}

function addressMatchesFrom(evidence: Rec): DnsPathMatch[] {
  const out: DnsPathMatch[] = [];
  for (const raw of asList(evidence.address_matches)) {
    const match = asRecord(raw);
    const provider = String(match?.provider ?? '').trim();
    const family = String(match?.family ?? '').trim().toLowerCase();
    if (!provider || out.some((entry) => entry.provider === provider && entry.family === family)) continue;
    out.push({ provider, family });
  }
  return out;
}

function emptyPath(kind: DnsPathKind, host: string, recordLabel: string, summary: string, observedAt = ''): DnsPath {
  return { kind, recordLabel, summary, host, aliases: [], addresses: [], aliasMatch: null, addressMatches: [], observedAt };
}

/** The recorded chain starts with the queried host; addresses without a chain mean the CNAME lookup was not recorded. */
export function classifyDnsPath({ kind, value, edgeDetection }: { kind: string; value: string; edgeDetection: unknown }): DnsPath {
  const host = declaredHost(kind, value);
  if (host && isIpLiteral(host)) {
    return emptyPath('declared_ip', host, 'IP', 'Declared as an IP address. No DNS record is involved.');
  }
  const edge = asRecord(edgeDetection);
  if (!edge) return emptyPath('not_observed', host, 'Not observed', 'No outside-in edge observation is recorded for this target yet.');
  const evidence = asRecord(edge.evidence) ?? {};
  const observedAt = String(edge.observed_at ?? edge.updated_at ?? '').trim();
  const chain = uniqueHosts(asList(evidence.dns_cname_chain ?? edge.dns_cname_chain));
  const addresses = uniqueHosts(asList(evidence.dns_resolved_ips ?? edge.dns_resolved_ips));
  const aliases = chain.filter((entry) => entry !== host);
  const addressMatches = addressMatchesFrom(evidence);
  if (aliases.length > 0) {
    return {
      kind: 'cname',
      recordLabel: 'CNAME',
      summary: `Alias of ${aliases[aliases.length - 1]}`,
      host,
      aliases,
      addresses,
      aliasMatch: matchFor(evidence, aliases),
      addressMatches,
      observedAt,
    };
  }
  if (addresses.length > 0) {
    const checked = chain.length > 0;
    return {
      kind: checked ? 'address' : 'address_unchecked',
      recordLabel: addressRecordLabel(addresses),
      summary: checked
        ? `No CNAME answer; resolved to ${addresses.length === 1 ? 'one address' : `${addresses.length} addresses`}`
        : 'Addresses recorded; CNAME lookup not recorded',
      host,
      aliases: [],
      addresses,
      aliasMatch: null,
      addressMatches,
      observedAt,
    };
  }
  return emptyPath('not_observed', host, 'Not observed', 'The recorded observation holds no DNS answers.', observedAt);
}
