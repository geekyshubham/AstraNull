import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { normalizeSubdomainCandidate } from './subdomainEnumeration.mjs';
import { classifyEdgeByAddress } from './edgeFingerprint.mjs';
import { assertProbeDestinationAllowed } from './probeEndpoint.mjs';

export const ORIGIN_CLUE_MAX_BYTES = 128 * 1024;
export const ORIGIN_CLUE_MAX_RECORDS = 200;
export const ORIGIN_CLUE_LABEL = 'Possible origin association—not verified';
export const ORIGIN_CLUE_LIMITATIONS = Object.freeze([
  'Associations are unverified clues, not origin identity, ownership, probe authorization or a protection verdict.',
  'Coverage is partial. No association observed in these sources does not mean the origin is hidden or protected.',
  'Historical, shared and reassigned infrastructure and wildcard DNS may produce unrelated associations.',
  'Live certificate-host, historical DNS and CT provider feeds are not queried; supplied imports only.',
]);

export class OriginClueError extends Error {
  constructor(code, status = 400, message = code) { super(message); this.code = code; this.status = status; }
}
export function rejectOriginClue(code, message, status = 400) { throw new OriginClueError(code, status, message); }
export function originCluesEnabledFor() {
  return true;
}
export function originClueDigest(value) {
  function canonical(v) {
    if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
    if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
    return JSON.stringify(v);
  }
  return createHash('sha256').update(canonical(value)).digest('hex');
}
export function boundedOriginBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) rejectOriginClue('invalid_origin_clue_body');
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > ORIGIN_CLUE_MAX_BYTES) rejectOriginClue('origin_clue_import_too_large', 'Maximum supplied body is 128 KiB.', 413);
  return body;
}
function onlyKeys(value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) rejectOriginClue('invalid_origin_clue_record');
  for (const key of Object.keys(value)) if (!allowed.includes(key)) rejectOriginClue('unknown_origin_clue_field', `Unsupported field: ${key}`);
}
export function originHostname(raw) {
  if (typeof raw !== 'string' || raw.length > 253 || /[\s/@:*\\]/.test(raw)) rejectOriginClue('invalid_origin_clue_hostname');
  const host = domainToASCII(raw.trim().toLowerCase().replace(/\.$/, ''));
  if (!host || isIP(host) || !host.includes('.') || host.length > 253 || host.split('.').some((s) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s))) rejectOriginClue('invalid_origin_clue_hostname');
  return host;
}
export function originHostnameInScope(raw, parent) {
  const host = originHostname(raw);
  if (host !== parent && !normalizeSubdomainCandidate(host, parent)) rejectOriginClue('origin_clue_hostname_out_of_scope');
  return host;
}
export function canonicalOriginIp(raw) {
  if (typeof raw !== 'string' || raw.includes('%') || !isIP(raw.trim())) rejectOriginClue('invalid_origin_clue_ip');
  const ip = raw.trim();
  const normalized = isIP(ip) === 6 ? new URL(`http://[${ip}]/`).hostname.slice(1, -1) : ip;
  if (!assertProbeDestinationAllowed(normalized).ok) rejectOriginClue('origin_clue_ip_not_public');
  return normalized;
}
function text(raw, field, max = 512) {
  if (typeof raw !== 'string' || !raw.trim() || raw.length > max || /[\u0000-\u001f\u007f]/.test(raw)) rejectOriginClue('invalid_origin_clue_field', `Invalid ${field}.`);
  return raw.trim();
}
function certificateName(raw) {
  if (typeof raw !== 'string') rejectOriginClue('invalid_origin_clue_certificate_name');
  const wildcard = raw.startsWith('*.');
  return `${wildcard ? '*.' : ''}${originHostname(wildcard ? raw.slice(2) : raw)}`;
}
export function certificateMatchesHostname(name, host) {
  if (!name.startsWith('*.')) return name === host;
  const suffix = name.slice(2);
  return host.endsWith(`.${suffix}`) && host.split('.').length === suffix.split('.').length + 1;
}
function observedAt(raw, now) {
  if (raw == null || raw === '') return null;
  if (typeof raw !== 'string' || raw.length > 40 || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(raw) || !Number.isFinite(Date.parse(raw)) || Date.parse(raw) > now.getTime() + 300000) rejectOriginClue('invalid_origin_clue_observed_at');
  const [year, month, day] = raw.slice(0, 10).split('-').map(Number);
  if (new Date(Date.UTC(year, month - 1, day)).toISOString().slice(0, 10) !== raw.slice(0, 10)) rejectOriginClue('invalid_origin_clue_observed_at');
  return new Date(raw).toISOString();
}
export function normalizeOriginClue(record, { parent, sourceKind, sourceRef, now, dns = false }) {
  const host = originHostnameInScope(record.associated_hostname, parent);
  const ip = record.candidate_ip == null && dns ? null : canonicalOriginIp(record.candidate_ip);
  const names = record.certificate_names ?? [];
  if (!Array.isArray(names) || names.length > 32) rejectOriginClue('invalid_origin_clue_certificate_names');
  const certificateNames = [...new Set(names.map(certificateName))].sort();
  if (certificateNames.length && !certificateNames.some((name) => certificateMatchesHostname(name, host))) rejectOriginClue('origin_clue_certificate_name_mismatch');
  if (['certificate_host', 'trickest_csv'].includes(sourceKind) && !certificateNames.length) rejectOriginClue('origin_clue_certificate_names_required');
  const observation = observedAt(record.source_observed_at, now);
  const hits = ip ? classifyEdgeByAddress(ip) : [];
  const limitations = ['Association only; no target, binding or active probe is created.'];
  if (!observation) limitations.push('Source IP observation time is unknown; retrieval time is not an IP observation timestamp.');
  else if (now.getTime() - Date.parse(observation) > 30 * 86400000) limitations.push('Source observation is stale (older than 30 days).');
  if (certificateNames.length) limitations.push('Certificate-name association does not establish ownership, liveness or current serving origin.');
  if (dns) limitations.push('Public DNS association only; wildcard DNS and third-party infrastructure are not disambiguated.');
  const clue = {
    candidate_ip: ip, address_family: ip ? isIP(ip) : null, associated_hostname: host,
    related_hostname: record.related_hostname ? originHostname(record.related_hostname) : null,
    reference: record.reference ? text(record.reference, 'reference') : null,
    source_kind: sourceKind, source_ref: text(sourceRef, 'source_ref'), source_observed_at: observation,
    certificate_names: certificateNames, retrieved_at: now.toISOString(),
    edge_classification: hits.some((hit) => hit.family === 'waf' || (hit.family === 'cdn'
      && !hits.some((other) => other.family === 'cloud' && other.provider === hit.provider))) ? 'known_edge' : 'unknown',
    limitations, state: 'possible_origin_association',
  };
  const { retrieved_at: _time, limitations: _limits, edge_classification: _edge, state: _state, ...provenance } = clue;
  return { ...clue, source_digest: originClueDigest(provenance) };
}

// RFC 4180-style quoting, including escaped quotes and CRLF, with strict bounded fields/rows.
function csvRows(csv) {
  if (typeof csv !== 'string' || !csv.length || Buffer.byteLength(csv) > ORIGIN_CLUE_MAX_BYTES) rejectOriginClue('invalid_origin_clue_csv');
  const rows = []; let row = []; let field = ''; let quoted = false; let closed = false;
  function cell() { row.push(field); field = ''; closed = false; if (row.length > 16) rejectOriginClue('invalid_origin_clue_csv'); }
  function line() { cell(); if (row.some((v) => v !== '')) rows.push(row); row = []; if (rows.length > ORIGIN_CLUE_MAX_RECORDS + 1) rejectOriginClue('origin_clue_row_limit'); }
  for (let i = 0; i < csv.length; i += 1) {
    const ch = csv[i];
    if (quoted) {
      if (ch === '"' && csv[i + 1] === '"') { field += '"'; i += 1; }
      else if (ch === '"') { quoted = false; closed = true; }
      else field += ch;
    } else if (ch === '"') {
      if (field || closed) rejectOriginClue('invalid_origin_clue_csv');
      quoted = true;
    } else if (ch === ',') cell();
    else if (ch === '\n' || ch === '\r') { if (ch === '\r' && csv[i + 1] === '\n') i += 1; line(); }
    else { if (closed) rejectOriginClue('invalid_origin_clue_csv'); field += ch; }
    if (field.length > 4096) rejectOriginClue('origin_clue_field_limit');
  }
  if (quoted) rejectOriginClue('invalid_origin_clue_csv');
  if (field || row.length || closed) line();
  return rows;
}
export function parseOriginClueImport(body, parent, now = new Date()) {
  boundedOriginBody(body);
  onlyKeys(body, ['source_kind', 'source_ref', 'records', 'csv']);
  const sourceKind = body.source_kind;
  if (!['historical_dns', 'certificate_host', 'trickest_csv'].includes(sourceKind)) rejectOriginClue('unsupported_origin_clue_source');
  const sourceRef = text(body.source_ref, 'source_ref');
  let records; let skipped = 0;
  if (sourceKind === 'trickest_csv') {
    if (body.records !== undefined) rejectOriginClue('invalid_origin_clue_body');
    const [headersRaw, ...data] = csvRows(body.csv);
    const headers = headersRaw?.map((h) => h.replace(/^﻿/, '').trim());
    if (!headers || new Set(headers).size !== headers.length || !headers.includes('IP Address') || !(headers.includes('Common Name') || headers.includes('Subject Alternative DNS Name'))) rejectOriginClue('invalid_trickest_csv_headers');
    records = [];
    for (const row of data) {
      if (row.length !== headers.length) rejectOriginClue('invalid_origin_clue_csv');
      const raw = Object.fromEntries(headers.map((h, i) => [h, row[i]]));
      const certificateNames = [raw['Common Name'], ...(raw['Subject Alternative DNS Name'] ?? '').split(/[\s,;]+/)].filter(Boolean).map(certificateName);
      if (certificateNames.length > 32) rejectOriginClue('invalid_origin_clue_certificate_names');
      if (!certificateNames.some((name) => certificateMatchesHostname(name, parent))) { skipped += 1; continue; }
      records.push({ candidate_ip: raw['IP Address'], associated_hostname: parent, certificate_names: certificateNames });
    }
  } else {
    if (body.csv !== undefined || !Array.isArray(body.records)) rejectOriginClue('invalid_origin_clue_body');
    records = body.records;
    for (const record of records) onlyKeys(record, ['candidate_ip', 'associated_hostname', 'source_observed_at', 'certificate_names']);
  }
  if (records.length > ORIGIN_CLUE_MAX_RECORDS) rejectOriginClue('origin_clue_row_limit');
  const clues = records.map((record) => normalizeOriginClue(record, { parent, sourceKind, sourceRef, now }));
  return { clues, skipped };
}
export function originCluePage(query, targetId) {
  const limit = query.limit == null ? 50 : Number(query.limit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) rejectOriginClue('invalid_limit');
  let after = null;
  if (query.cursor) {
    try {
      if (typeof query.cursor !== 'string' || query.cursor.length > 512) throw new Error();
      after = JSON.parse(Buffer.from(query.cursor, 'base64url').toString('utf8'));
      if (after.v !== 1 || after.target_id !== targetId || typeof after.id !== 'string' || !/^[a-z0-9_-]{1,100}$/i.test(after.id) || typeof after.at !== 'string' || new Date(after.at).toISOString() !== after.at) throw new Error();
    } catch { rejectOriginClue('invalid_cursor'); }
  }
  return { limit, after };
}
export function presentOriginCluePage(rows, limit, targetId) {
  const items = rows.slice(0, limit);
  const last = items.at(-1);
  return { target_id: targetId, enabled: true, label: ORIGIN_CLUE_LABEL, items,
    next_cursor: rows.length > limit ? Buffer.from(JSON.stringify({ v: 1, target_id: targetId, at: last.retrieved_at, id: last.id })).toString('base64url') : null,
    coverage: { partial: true, limitations: [...ORIGIN_CLUE_LIMITATIONS] } };
}
export function originClueIdempotencyKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(value)) rejectOriginClue('origin_clue_idempotency_key_required');
  return value;
}
export function normalizeOriginCollectionBody(body) {
  boundedOriginBody(body);
  onlyKeys(body, ['include_mail', 'related_target_ids']);
  if (body.include_mail !== undefined && typeof body.include_mail !== 'boolean') rejectOriginClue('invalid_origin_clue_body');
  const ids = body.related_target_ids ?? [];
  if (!Array.isArray(ids) || ids.length > 7 || ids.some((id) => typeof id !== 'string' || !/^[a-z0-9_-]{1,100}$/i.test(id))) rejectOriginClue('invalid_origin_clue_related_targets');
  return { include_mail: body.include_mail === true, related_target_ids: [...new Set(ids)].sort() };
}
