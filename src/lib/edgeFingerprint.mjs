/**
 * Edge fingerprint classifier: a faithful runtime port of wafw00f's plugin evaluation and
 * cdncheck's address/CNAME lookup over pinned upstream data.
 *
 * wafw00f parity: each plugin's decision tree is evaluated in upstream checklist order
 * (`wafprio.py`). `attack=False` leaves read the normal response and `attack=True` leaves read
 * the central attack response, exactly as `self.rq` / `self.attackres` do upstream. A leaf whose
 * response was never captured is unknown, so compound NOT logic cannot promote missing evidence.
 *
 * cdncheck parity: addresses are checked cdn -> waf -> cloud, AAAA before A, then CNAME suffixes.
 * CNAME matching is a label-boundary suffix match, a strict superset of upstream's public-suffix
 * TLD / SLD.TLD equality. Types come from pinned cdncheck code, never provider-name inference.
 *
 * This module sends no traffic and performs no DNS lookup. Response values are bounded in memory
 * and never included in classification output.
 */

import { isIP } from 'node:net';
import { CVE_SAFE_VALIDATION_CHECK_ID } from '../contracts/cvePipeline.mjs';
import {
  WAF_VENDOR_SIGNATURES,
  CDN_ADDRESS_RANGES,
  WAF_ADDRESS_RANGES,
  EDGE_CNAME_RULES,
  EDGE_CORPUS_STATS,
  EDGE_SIGNATURE_CORPUS_MANIFEST,
  WAF_VENDOR_PRIORITY,
  WAFW00F_ENGINE,
  CDNCHECK_ENGINE,
} from './data/edgeSignatureData.mjs';
import { CLOUD_ADDRESS_RANGES_PACKED } from './data/edgeCloudRangeData.mjs';

export { EDGE_CORPUS_STATS, EDGE_SIGNATURE_CORPUS_MANIFEST, WAFW00F_ENGINE, CDNCHECK_ENGINE };

export const EDGE_SIGNATURE_CORPUS_VERSION = String(EDGE_SIGNATURE_CORPUS_MANIFEST.output_version);

const FINGERPRINT_HEADER_VALUE_MAX_LENGTH = 128;
const FINGERPRINT_HEADER_NAME_MAX_LENGTH = 128;
const FINGERPRINT_HEADER_ENTRIES_MAX = 128;
const FINGERPRINT_ENUMERATED_HEADERS_MAX = 128;
const FINGERPRINT_SET_COOKIE_VALUE_MAX_LENGTH = 512;
const FINGERPRINT_SET_COOKIE_VALUES_MAX = 16;
const FINGERPRINT_SET_COOKIE_TOTAL_MAX_LENGTH = 4096;
export const FINGERPRINT_BODY_MAX_LENGTH = WAFW00F_ENGINE.max_response_bytes;
const FINGERPRINT_REASON_MAX_LENGTH = 256;
const FINGERPRINT_ADDRESS_VALUES_MAX = 64;
const FINGERPRINT_CNAME_VALUES_MAX = 64;

const SINGLE_SIGNAL_CONFIDENCE = 0.45;
const EXTRA_SIGNAL_CONFIDENCE = 0.2;
const MAX_VENDOR_CONFIDENCE = 0.95;

const MATCH_TRUE = 1;
const MATCH_FALSE = 0;
const MATCH_UNKNOWN = -1;

function compilePattern(pattern, context) {
  try {
    return new RegExp(pattern, 'i');
  } catch (error) {
    throw new Error(`invalid generated ${context} regex: ${error.message}`);
  }
}

function compileHeaderName(signature, context) {
  if (signature.header_kind === 'exact') {
    return { exact: String(signature.header).toLowerCase() };
  }
  if (signature.header_kind !== 'regex') {
    throw new Error(`invalid generated ${context} header kind`);
  }
  return { regex: compilePattern(`^(?:${signature.header})$`, `${context} header-name`) };
}

function validateMatcherNode(node, signatureCount, context) {
  if (!node || typeof node !== 'object') throw new Error(`invalid generated ${context} matcher node`);
  if (node.op === 'const') {
    if (typeof node.value !== 'boolean') throw new Error(`invalid generated ${context} const`);
    return;
  }
  if (node.op === 'signal') {
    if (!Number.isInteger(node.id) || node.id < 0 || node.id >= signatureCount) {
      throw new Error(`invalid generated ${context} signal reference ${node.id}`);
    }
    return;
  }
  if (node.op === 'not') {
    validateMatcherNode(node.arg, signatureCount, context);
    return;
  }
  if (node.op === 'and' || node.op === 'or') {
    if (!Array.isArray(node.args) || node.args.length < 2) {
      throw new Error(`invalid generated ${context} ${node.op} node`);
    }
    for (const child of node.args) validateMatcherNode(child, signatureCount, context);
    return;
  }
  if (node.op === 'if') {
    validateMatcherNode(node.condition, signatureCount, context);
    validateMatcherNode(node.then, signatureCount, context);
    validateMatcherNode(node.else, signatureCount, context);
    return;
  }
  throw new Error(`invalid generated ${context} matcher op ${node.op}`);
}

let compiledCorpus = null;

function getCompiledCorpus() {
  if (compiledCorpus) return compiledCorpus;
  const vendors = {};
  const exactHeaderNames = new Set();
  const regexHeaderNames = [];
  let hasCookieMatchers = false;

  for (const [vendorKey, vendor] of Object.entries(WAF_VENDOR_SIGNATURES)) {
    if (vendor.port_status !== 'supported') {
      throw new Error(`generated vendor ${vendorKey} is not safely supported`);
    }
    const signatures = (vendor.signatures ?? []).map((signature, index) => {
      const context = `${vendorKey} signature ${index}`;
      if (signature.signal === 'header') {
        const compiledHeader = compileHeaderName(signature, context);
        const compiledPattern = compilePattern(String(signature.pattern), `${context} value`);
        if (compiledHeader.exact) exactHeaderNames.add(compiledHeader.exact);
        else regexHeaderNames.push(compiledHeader.regex);
        return { ...signature, compiledHeader, compiledPattern };
      }
      if (signature.signal === 'cookie' || signature.signal === 'content') {
        const compiledPattern = compilePattern(String(signature.pattern), context);
        if (signature.signal === 'cookie') hasCookieMatchers = true;
        return { ...signature, compiledPattern };
      }
      if (signature.signal === 'status') {
        if (!Number.isInteger(signature.status)) throw new Error(`invalid generated ${context} status`);
        return { ...signature };
      }
      if (signature.signal === 'reason') {
        if (typeof signature.value !== 'string') throw new Error(`invalid generated ${context} reason`);
        return { ...signature };
      }
      throw new Error(`invalid generated ${context} signal ${signature.signal}`);
    });
    validateMatcherNode(vendor.matcher, signatures.length, vendorKey);
    vendors[vendorKey] = {
      name: vendor.name,
      signatures,
      matcher: vendor.matcher,
    };
  }

  const priority = WAF_VENDOR_PRIORITY.filter((key) => Object.hasOwn(vendors, key));
  if (priority.length !== Object.keys(vendors).length) {
    throw new Error('generated wafw00f priority does not cover every vendor');
  }

  compiledCorpus = Object.freeze({
    vendors: Object.freeze(vendors),
    priority: Object.freeze(priority),
    exactHeaderNames: Object.freeze(exactHeaderNames),
    regexHeaderNames: Object.freeze(regexHeaderNames),
    hasCookieMatchers,
  });
  return compiledCorpus;
}

function safeHeaderGet(headers, name) {
  if (!headers || typeof headers.get !== 'function') return null;
  try {
    return headers.get(name);
  } catch {
    return null;
  }
}

function splitCombinedSetCookie(value) {
  return String(value ?? '')
    .split(/,(?=\s*[^=;,\s]+\s*=)/)
    .map((part) => part.trim())
    .filter(Boolean);
}

function boundSetCookieValues(values) {
  const bounded = [];
  let remaining = FINGERPRINT_SET_COOKIE_TOTAL_MAX_LENGTH;
  for (const raw of values) {
    if (bounded.length >= FINGERPRINT_SET_COOKIE_VALUES_MAX || remaining <= 0) break;
    const value = String(raw ?? '').slice(
      0,
      Math.min(FINGERPRINT_SET_COOKIE_VALUE_MAX_LENGTH, remaining),
    );
    if (!value) continue;
    bounded.push(value);
    remaining -= value.length;
  }
  return bounded;
}

function setCookieValuesFromHeaders(headers) {
  if (!headers) return [];
  if (typeof headers.getSetCookie === 'function') {
    try {
      const values = headers.getSetCookie();
      if (Array.isArray(values)) return boundSetCookieValues(values);
    } catch {
      return [];
    }
  }
  const combined = safeHeaderGet(headers, 'set-cookie');
  if (combined === null || combined === undefined) return [];
  return boundSetCookieValues(splitCombinedSetCookie(combined));
}

function addHeaderEntry(entries, seen, name, value, maxValueLength) {
  if (entries.length >= FINGERPRINT_HEADER_ENTRIES_MAX) return;
  const normalizedName = String(name ?? '').trim().toLowerCase().slice(0, FINGERPRINT_HEADER_NAME_MAX_LENGTH);
  const normalizedValue = String(value ?? '').slice(0, maxValueLength);
  if (!normalizedName || !normalizedValue) return;
  const key = `${normalizedName}\u0000${normalizedValue}`;
  if (seen.has(key)) return;
  seen.add(key);
  entries.push({ name: normalizedName, value: normalizedValue });
}

/**
 * Capture only corpus-relevant response fields for immediate in-memory classification.
 * Values are bounded. Set-Cookie is retained only in this transient return value; callers must
 * never serialize it, and classifier results contain signal metadata rather than raw values.
 *
 * Exact header names use `Headers.get`. Regex header names require an enumerable Headers object
 * (`forEach`, as supplied by Fetch) and are matched against bounded names before values are kept.
 */
export function extractFingerprintHeaderEntries(response) {
  const {
    exactHeaderNames,
    regexHeaderNames,
    hasCookieMatchers,
  } = getCompiledCorpus();
  const headers = response?.headers;
  if (!headers) return [];
  const entries = [];
  const seen = new Set();

  for (const name of exactHeaderNames) {
    if (name === 'set-cookie') continue;
    const value = safeHeaderGet(headers, name);
    if (value === null || value === undefined) continue;
    addHeaderEntry(entries, seen, name, value, FINGERPRINT_HEADER_VALUE_MAX_LENGTH);
  }

  if (regexHeaderNames.length > 0 && typeof headers.forEach === 'function') {
    let enumerated = 0;
    try {
      headers.forEach((value, rawName) => {
        if (enumerated >= FINGERPRINT_ENUMERATED_HEADERS_MAX) return;
        enumerated += 1;
        const name = String(rawName ?? '').trim().toLowerCase().slice(0, FINGERPRINT_HEADER_NAME_MAX_LENGTH);
        if (!name || !regexHeaderNames.some((pattern) => pattern.test(name))) return;
        addHeaderEntry(entries, seen, name, value, FINGERPRINT_HEADER_VALUE_MAX_LENGTH);
      });
    } catch {
      // Exact-name evidence remains usable when a nonstandard header object cannot enumerate.
    }
  }

  if (hasCookieMatchers) {
    const setCookieValues = setCookieValuesFromHeaders(headers);
    if (setCookieValues.length > 0) {
      addHeaderEntry(
        entries,
        seen,
        'set-cookie',
        setCookieValues.join(', '),
        FINGERPRINT_SET_COOKIE_TOTAL_MAX_LENGTH,
      );
    }
  }

  return entries.sort((a, b) => a.name.localeCompare(b.name) || a.value.localeCompare(b.value));
}

function normalizeHeaderEntries(entries) {
  if (!Array.isArray(entries)) return [];
  return entries.slice(0, FINGERPRINT_HEADER_ENTRIES_MAX).flatMap((entry) => {
    const name = String(entry?.name ?? '').trim().toLowerCase().slice(0, FINGERPRINT_HEADER_NAME_MAX_LENGTH);
    if (!name) return [];
    const maxLength = name === 'set-cookie'
      ? FINGERPRINT_SET_COOKIE_TOTAL_MAX_LENGTH
      : FINGERPRINT_HEADER_VALUE_MAX_LENGTH;
    const value = String(entry?.value ?? '').slice(0, maxLength);
    return value ? [{ name, value }] : [];
  });
}

function normalizeSetCookieEvidence(evidence, headerEntries) {
  const candidates = [];
  for (const entry of headerEntries) {
    if (entry.name === 'set-cookie') candidates.push(...splitCombinedSetCookie(entry.value));
  }
  if (Array.isArray(evidence.setCookieHeaders)) {
    for (const value of evidence.setCookieHeaders.slice(0, FINGERPRINT_SET_COOKIE_VALUES_MAX)) {
      candidates.push(...splitCombinedSetCookie(value));
    }
  }
  // Backward-compatible name-only evidence can prove name/equals patterns but deliberately cannot
  // prove regexes that require a non-empty value (for example `=.+`).
  if (Array.isArray(evidence.cookieNames)) {
    for (const name of evidence.cookieNames.slice(0, FINGERPRINT_SET_COOKIE_VALUES_MAX)) {
      const normalized = String(name ?? '').trim().split(/[=;,\r\n]/, 1)[0]
        .slice(0, FINGERPRINT_HEADER_NAME_MAX_LENGTH);
      if (normalized) candidates.push(`${normalized}=`);
    }
  }
  const bounded = boundSetCookieValues(candidates);
  // requests joins repeated Set-Cookie headers with ", " and wafw00f re-splits on ", ", so a
  // piece may begin mid-attribute (for example inside an Expires date). Match that exactly.
  return bounded.length ? bounded.join(', ').split(', ') : [];
}

function normalizeResponseEvidence(evidence) {
  const record = evidence && typeof evidence === 'object' ? evidence : {};
  const headerEntries = normalizeHeaderEntries(record.headerEntries);
  return {
    headerEntries,
    setCookieValues: normalizeSetCookieEvidence(record, headerEntries),
    bodyText: record.bodyText
      ? String(record.bodyText).slice(0, FINGERPRINT_BODY_MAX_LENGTH)
      : '',
    statusCode: Number.isInteger(record.statusCode) ? record.statusCode : null,
    statusReason: String(record.statusReason ?? '').slice(0, FINGERPRINT_REASON_MAX_LENGTH),
  };
}

/**
 * `{ normal, attack }` mirrors wafw00f's `self.rq` / `self.attackres`. The legacy flat shape is
 * one normal response whose attack view exists only when `blockResponse === true`.
 */
function normalizeWafEvidence(evidence = {}) {
  const input = evidence && typeof evidence === 'object' ? evidence : {};
  if ('normal' in input || 'attack' in input) {
    return {
      normal: input.normal ? normalizeResponseEvidence(input.normal) : null,
      attack: input.attack ? normalizeResponseEvidence(input.attack) : null,
    };
  }
  const flat = normalizeResponseEvidence(input);
  return { normal: flat, attack: input.blockResponse === true ? flat : null };
}

function headerEntriesMatch(headerEntries, compiledHeader, pattern) {
  for (const entry of headerEntries) {
    const nameMatches = compiledHeader.exact
      ? entry.name === compiledHeader.exact
      : compiledHeader.regex.test(entry.name);
    if (nameMatches && pattern.test(entry.value)) return true;
  }
  return false;
}

function evaluateSignal(signature, responses) {
  const evidence = signature.tier === 'block_page' ? responses.attack : responses.normal;
  if (!evidence) return MATCH_UNKNOWN;
  if (signature.signal === 'header') {
    return headerEntriesMatch(
      evidence.headerEntries,
      signature.compiledHeader,
      signature.compiledPattern,
    ) ? MATCH_TRUE : MATCH_FALSE;
  }
  if (signature.signal === 'cookie') {
    return evidence.setCookieValues.some((value) => signature.compiledPattern.test(value))
      ? MATCH_TRUE
      : MATCH_FALSE;
  }
  if (signature.signal === 'content') {
    return evidence.bodyText && signature.compiledPattern.test(evidence.bodyText)
      ? MATCH_TRUE
      : MATCH_FALSE;
  }
  if (signature.signal === 'status') {
    return evidence.statusCode === signature.status ? MATCH_TRUE : MATCH_FALSE;
  }
  if (signature.signal === 'reason') {
    // wafw00f uses `str(response.reason) == reasoncode`: exact and case-sensitive.
    return evidence.statusReason === signature.value ? MATCH_TRUE : MATCH_FALSE;
  }
  return MATCH_FALSE;
}

function evaluateMatcher(node, signatures, evidence) {
  if (node.op === 'const') return node.value ? MATCH_TRUE : MATCH_FALSE;
  if (node.op === 'signal') return evaluateSignal(signatures[node.id], evidence);
  if (node.op === 'not') {
    const value = evaluateMatcher(node.arg, signatures, evidence);
    if (value === MATCH_UNKNOWN) return MATCH_UNKNOWN;
    return value === MATCH_TRUE ? MATCH_FALSE : MATCH_TRUE;
  }
  if (node.op === 'and') {
    let sawUnknown = false;
    for (const child of node.args) {
      const value = evaluateMatcher(child, signatures, evidence);
      if (value === MATCH_FALSE) return MATCH_FALSE;
      if (value === MATCH_UNKNOWN) sawUnknown = true;
    }
    return sawUnknown ? MATCH_UNKNOWN : MATCH_TRUE;
  }
  if (node.op === 'or') {
    let sawUnknown = false;
    for (const child of node.args) {
      const value = evaluateMatcher(child, signatures, evidence);
      if (value === MATCH_TRUE) return MATCH_TRUE;
      if (value === MATCH_UNKNOWN) sawUnknown = true;
    }
    return sawUnknown ? MATCH_UNKNOWN : MATCH_FALSE;
  }
  if (node.op === 'if') {
    const condition = evaluateMatcher(node.condition, signatures, evidence);
    if (condition === MATCH_TRUE) return evaluateMatcher(node.then, signatures, evidence);
    if (condition === MATCH_FALSE) return evaluateMatcher(node.else, signatures, evidence);
    const thenValue = evaluateMatcher(node.then, signatures, evidence);
    const elseValue = evaluateMatcher(node.else, signatures, evidence);
    return thenValue === elseValue ? thenValue : MATCH_UNKNOWN;
  }
  return MATCH_UNKNOWN;
}

function matchedSignalDescriptor(signature) {
  if (signature.signal === 'header') {
    return { signal: 'header', header: signature.header, tier: signature.tier };
  }
  if (signature.signal === 'status') {
    return { signal: 'status', status: signature.status, tier: signature.tier };
  }
  if (signature.signal === 'reason') {
    return { signal: 'reason', value: signature.value, tier: signature.tier };
  }
  return { signal: signature.signal, tier: signature.tier };
}

function vendorConfidence(matchedSignals) {
  if (matchedSignals.length === 0) return 0;
  const blockSignals = matchedSignals.filter((signal) => signal.tier === 'block_page').length;
  const passiveSignals = matchedSignals.length - blockSignals;
  const raw = (passiveSignals > 0 ? SINGLE_SIGNAL_CONFIDENCE : 0)
    + Math.max(0, passiveSignals - 1) * EXTRA_SIGNAL_CONFIDENCE
    + blockSignals * EXTRA_SIGNAL_CONFIDENCE;
  return Math.min(MAX_VENDOR_CONFIDENCE, Number(raw.toFixed(3)));
}

/**
 * Evaluate every pinned wafw00f plugin (the `-a/--findall` view) in upstream checklist order.
 * `best` is the first match in that order: the single WAF wafw00f reports without `-a`.
 *
 * @param {{
 *   normal?: object|null,
 *   attack?: object|null,
 *   headerEntries?: { name: string, value: string }[],
 *   setCookieHeaders?: string[],
 *   cookieNames?: string[],
 *   bodyText?: string,
 *   statusCode?: number,
 *   statusReason?: string,
 *   blockResponse?: boolean,
 * }} evidence either `{ normal, attack }` response evidence or the legacy flat shape
 */
export function classifyWafVendorsFromResponseEvidence(evidence = {}) {
  const { vendors, priority } = getCompiledCorpus();
  const responses = normalizeWafEvidence(evidence);
  const matches = [];

  for (const [order, vendorKey] of priority.entries()) {
    const vendor = vendors[vendorKey];
    if (evaluateMatcher(vendor.matcher, vendor.signatures, responses) !== MATCH_TRUE) continue;
    const matchedSignals = vendor.signatures
      .filter((signature) => evaluateSignal(signature, responses) === MATCH_TRUE)
      .map(matchedSignalDescriptor);
    // A constant/absence-only path is never sufficient evidence, even if future upstream syntax
    // makes such a decision tree representable.
    if (matchedSignals.length === 0) continue;
    matches.push({
      vendor: vendorKey,
      name: vendor.name,
      confidence: vendorConfidence(matchedSignals),
      matched_signals: matchedSignals,
      checklist_order: order,
      corpus: 'wafw00f',
    });
  }

  let conflicting = false;
  if (matches.length >= 2) {
    const strongest = Math.max(...matches.map((match) => match.confidence));
    conflicting = matches.filter((match) => strongest - match.confidence <= 0.2).length >= 2;
  }
  return {
    matches,
    best: matches[0] ?? null,
    conflicting_vendor_signals: conflicting,
    attack_response_evaluated: responses.attack !== null,
  };
}

/** wafw00f's `buildResultRecord` split of "Firewall (Manufacturer)". */
export function splitWafw00fName(name) {
  const text = String(name ?? '');
  const open = text.indexOf('(');
  if (open < 0) return { firewall: text.trim(), manufacturer: '' };
  return {
    firewall: text.slice(0, open).trim(),
    manufacturer: text.slice(open + 1).replace(')', '').trim(),
  };
}

// ---------------------------------------------------------------------------
// Address classification — pinned cdncheck ranges, no DNS performed here.
// ---------------------------------------------------------------------------

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

  // Go/net and cdncheck treat IPv4-mapped IPv6 as the mapped IPv4 address. Match that parity for
  // both dotted (`::ffff:108.138.5.5`) and hexadecimal (`::ffff:6c8a:505`) spellings.
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    return { version: 4, value: (BigInt(groups[6]) << 16n) | BigInt(groups[7]) };
  }

  let numeric = 0n;
  for (const group of groups) numeric = (numeric << 16n) | BigInt(group);
  return { version: 6, value: numeric };
}

function cidrToInterval(cidr) {
  const parts = String(cidr).split('/');
  if (parts.length !== 2) return null;
  const parsed = parseIpAddress(parts[0]);
  if (!parsed) return null;
  const prefix = Number(parts[1]);
  const bits = parsed.version === 4 ? 32 : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
  const hostBits = BigInt(bits - prefix);
  const size = 1n << hostBits;
  const base = (parsed.value >> hostBits) << hostBits;
  return { version: parsed.version, start: base, end: base + size - 1n };
}

const ADDRESS_FAMILIES = Object.freeze(CDNCHECK_ENGINE.check_order);
const addressIndexCache = new Map();

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

// IPv4 intervals use Number (exact below 2^53) so the ~93k cloud ranges index without BigInt.
function pushInterval(rows, interval, provider) {
  if (interval.version === 4) {
    rows.v4.push({ start: Number(interval.start), end: Number(interval.end), provider });
  } else {
    rows.v6.push({ start: interval.start, end: interval.end, provider });
  }
}

function buildAddressIndex(group) {
  const rows = { v4: [], v6: [] };
  for (const [provider, ranges] of Object.entries(group ?? {})) {
    for (const cidr of ranges ?? []) {
      const interval = cidrToInterval(cidr);
      if (!interval) throw new Error(`invalid generated CIDR ${provider}:${cidr}`);
      pushInterval(rows, interval, provider);
    }
  }
  return { v4: sortAndPack(rows.v4), v6: sortAndPack(rows.v6) };
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

function buildPackedAddressIndex(packed) {
  const rows = { v4: [], v6: [] };
  for (const [provider, families] of Object.entries(packed ?? {})) {
    unpackFamily(families.v4, 4, provider, rows);
    unpackFamily(families.v6, 6, provider, rows);
  }
  return { v4: sortAndPack(rows.v4), v6: sortAndPack(rows.v6) };
}

function getAddressIndex(family) {
  const cached = addressIndexCache.get(family);
  if (cached) return cached;
  const index = family === 'cloud'
    ? buildPackedAddressIndex(CLOUD_ADDRESS_RANGES_PACKED)
    : buildAddressIndex(family === 'cdn' ? CDN_ADDRESS_RANGES : WAF_ADDRESS_RANGES);
  addressIndexCache.set(family, index);
  return index;
}

function lookupAddress(family, ip) {
  const parsed = parseIpAddress(ip);
  if (!parsed) return [];
  const { rows, starts, maxSpan } = getAddressIndex(family)[parsed.version === 4 ? 'v4' : 'v6'];
  if (rows.length === 0) return [];
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
  const providers = new Set();
  const floor = value - maxSpan;
  for (let cursor = index; cursor >= 0; cursor -= 1) {
    const row = rows[cursor];
    // Rows are ordered by start. Once start is below value-maxSpan, no earlier interval can
    // reach the value; testing `row.end` here would incorrectly skip an earlier wider overlap.
    if (row.start < floor) break;
    if (value >= row.start && value <= row.end) providers.add(row.provider);
  }
  return [...providers].sort().map((provider) => ({ family, provider }));
}

/** Every cdncheck address family (cdn, waf, cloud) containing each resolved IP. */
export function classifyEdgeByAddress(ips) {
  const list = (Array.isArray(ips) ? ips : [ips]).slice(0, FINGERPRINT_ADDRESS_VALUES_MAX);
  const hits = [];
  for (const ip of list) {
    const value = String(ip ?? '').trim();
    if (!value) continue;
    for (const family of ADDRESS_FAMILIES) hits.push(...lookupAddress(family, value));
  }
  const seen = new Set();
  return hits.filter((hit) => {
    const key = `${hit.family}:${hit.provider}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizedHost(raw) {
  return String(raw ?? '').trim().toLowerCase().replace(/\.$/, '');
}

/**
 * CNAME classification. `type` is the explicit pinned cdncheck CheckSuffix result (`waf` at the
 * pinned revision), even for provider names commonly associated with CDNs.
 */
export function classifyEdgeByCnameChain(cnames) {
  const list = (Array.isArray(cnames) ? cnames : [cnames]).slice(0, FINGERPRINT_CNAME_VALUES_MAX);
  const hits = [];
  const seen = new Set();
  for (const raw of list) {
    const host = normalizedHost(raw);
    if (!host || isIP(host)) continue;
    for (const rule of EDGE_CNAME_RULES) {
      for (const suffix of rule.suffixes ?? []) {
        if (host !== suffix && !host.endsWith(`.${suffix}`)) continue;
        const key = `${rule.type}:${rule.provider}:${suffix}`;
        if (seen.has(key)) continue;
        seen.add(key);
        hits.push({ provider: rule.provider, type: rule.type, suffix, host });
      }
    }
  }
  return hits;
}

/**
 * cdncheck `CheckDNSResponse`: first AAAA hit, then first A hit (each checked cdn -> waf ->
 * cloud), then the first CNAME suffix hit. Returns the single verdict cdncheck would print.
 */
export function classifyCdncheckVerdict({ resolvedIps = [], cnameChain = [] } = {}) {
  const ips = (Array.isArray(resolvedIps) ? resolvedIps : []).slice(0, FINGERPRINT_ADDRESS_VALUES_MAX)
    .map((ip) => String(ip ?? '').trim())
    .filter(Boolean);
  const byFamily = {
    aaaa: ips.filter((ip) => isIP(ip) === 6),
    a: ips.filter((ip) => isIP(ip) === 4),
  };
  for (const recordType of CDNCHECK_ENGINE.dns_response_order) {
    if (recordType === 'cname') {
      const hit = classifyEdgeByCnameChain(Array.isArray(cnameChain) ? cnameChain : [])[0];
      if (hit) {
        return { matched: true, provider: hit.provider, item_type: hit.type, source: 'cname', value: hit.host };
      }
      continue;
    }
    for (const ip of byFamily[recordType] ?? []) {
      for (const family of ADDRESS_FAMILIES) {
        const hit = lookupAddress(family, ip)[0];
        if (hit) return { matched: true, provider: hit.provider, item_type: family, source: recordType, value: ip };
      }
    }
  }
  return { matched: false, provider: null, item_type: null, source: null, value: null };
}

// ---------------------------------------------------------------------------
// Combined classification
// ---------------------------------------------------------------------------

function providersForFamily(family, vendorMatches, addressMatches, cnameMatches) {
  const providers = new Set();
  if (family === 'waf') {
    for (const match of vendorMatches) providers.add(match.vendor);
  }
  for (const match of addressMatches) {
    if (match.family === family) providers.add(match.provider);
  }
  for (const match of cnameMatches) {
    if (match.type === family) providers.add(match.provider);
  }
  return [...providers].sort();
}

/**
 * Combine response evidence with DNS metadata.
 *
 * `dnsObserved` states whether the caller actually resolved the target. Without it the CDN and
 * cloud answers are `null` (not checked) instead of a misleading `false`.
 *
 * @param {object} input response evidence (see classifyWafVendorsFromResponseEvidence) plus
 *   `resolvedIps`, `cnameChain` (queried host first), `dnsObserved`, and optional
 *   `genericDetection` from the wafw00f generic pass
 */
export function classifyEdgeFingerprint(input = {}) {
  const vendorResult = classifyWafVendorsFromResponseEvidence(input);
  const resolvedIps = (input.resolvedIps ?? []).filter(Boolean);
  const cnameChain = (input.cnameChain ?? []).filter(Boolean);
  const dnsObserved = typeof input.dnsObserved === 'boolean'
    ? input.dnsObserved
    : resolvedIps.length > 0 || cnameChain.length > 0;
  const addressMatches = classifyEdgeByAddress(resolvedIps);
  const cnameMatches = classifyEdgeByCnameChain(cnameChain);
  const generic = input.genericDetection && typeof input.genericDetection === 'object'
    ? {
        found: input.genericDetection.found === true,
        reason_code: input.genericDetection.reason_code ?? null,
        reason: input.genericDetection.reason ?? null,
      }
    : null;

  // Provider lists are derived only from typed source evidence: wafw00f vendor matches,
  // cdncheck address families, and cdncheck's explicit CNAME type. Names never imply a family.
  const cdnProviders = providersForFamily('cdn', vendorResult.matches, addressMatches, cnameMatches);
  const wafProviders = providersForFamily('waf', vendorResult.matches, addressMatches, cnameMatches);
  const cloudProviders = providersForFamily('cloud', [], addressMatches, []);
  const best = vendorResult.best;
  const bestName = best ? splitWafw00fName(best.name) : null;

  return {
    corpus_version: EDGE_SIGNATURE_CORPUS_VERSION,
    metadata_only: true,
    waf_present: wafProviders.length > 0,
    waf_providers: wafProviders,
    waf_generic_detected: !best && generic?.found === true,
    cdn_detected: dnsObserved ? cdnProviders.length > 0 : null,
    cdn_providers: cdnProviders,
    cloud_hosted: dnsObserved ? cloudProviders.length > 0 : null,
    cloud_providers: cloudProviders,
    dns_observed: dnsObserved,
    vendor_matches: vendorResult.matches,
    best_vendor: best,
    conflicting_vendor_signals: vendorResult.conflicting_vendor_signals,
    attack_response_evaluated: vendorResult.attack_response_evaluated,
    address_matches: addressMatches,
    cname_matches: cnameMatches,
    wafw00f: {
      detected: Boolean(best) || generic?.found === true,
      firewall: best ? bestName.firewall : generic?.found ? 'Generic' : 'None',
      manufacturer: best ? bestName.manufacturer : generic?.found ? 'Unknown' : 'None',
      plugin: best?.vendor ?? null,
      all_matches: vendorResult.matches.map((match) => match.vendor),
      generic,
    },
    cdncheck: dnsObserved
      ? classifyCdncheckVerdict({ resolvedIps, cnameChain })
      : null,
  };
}

/** Probe-evidence metadata fields for signed WAF fingerprint jobs. */
export function edgeSignatureProbeEvidenceFields(checkId) {
  if (checkId !== CVE_SAFE_VALIDATION_CHECK_ID) return {};
  return {
    edge_signature_corpus_version: EDGE_SIGNATURE_CORPUS_VERSION,
    edge_signature_waf_vendors: EDGE_CORPUS_STATS.waf_vendors,
    edge_signature_cdn_ranges: EDGE_CORPUS_STATS.cdn_ranges,
    edge_signature_waf_ranges: EDGE_CORPUS_STATS.waf_ranges,
  };
}
