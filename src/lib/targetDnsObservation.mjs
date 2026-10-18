/**
 * Compact DNS answers from a target's stored edge detection, for the targets list.
 * Recorded evidence only; never a live lookup.
 */

const CHAIN_LIMIT = 8;
const ADDRESS_LIMIT = 16;
const MATCH_LIMIT = 8;

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function bounded(value, maxLength = 253) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function stringList(value, limit) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((entry) => bounded(entry)).filter(Boolean))].slice(0, limit);
}

function matchList(value, { withHost }) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const raw of value) {
    const match = asRecord(raw);
    const provider = bounded(match?.provider, 80);
    if (!provider) continue;
    const entry = { provider, family: bounded(match?.family ?? match?.type, 32).toLowerCase() };
    if (withHost) entry.host = bounded(match?.host);
    out.push(entry);
    if (out.length >= MATCH_LIMIT) break;
  }
  return out;
}

function isoOrNull(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** Accepts the in-memory record, a Postgres row, or a presented edge detection. Null when none is stored. */
export function targetDnsObservation(record) {
  const edge = asRecord(record);
  if (!edge) return null;
  const evidence = asRecord(edge.evidence_json) ?? asRecord(edge.evidence) ?? {};
  return {
    observed_at: isoOrNull(edge.observed_at),
    evidence: {
      dns_cname_chain: stringList(evidence.dns_cname_chain, CHAIN_LIMIT),
      dns_resolved_ips: stringList(evidence.dns_resolved_ips, ADDRESS_LIMIT),
      cname_matches: matchList(evidence.cname_matches, { withHost: true }),
      cname_cdn_matches: matchList(evidence.cname_cdn_matches, { withHost: true }),
      address_matches: matchList(evidence.address_matches, { withHost: false }),
    },
  };
}
