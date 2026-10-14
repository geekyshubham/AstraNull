import { isIP } from 'node:net';
import { probePerspectiveIds } from '../lib/probePerspectiveRegistry.mjs';

export const CONTROL_DECLARATIONS_VERSION = 1;
export const CONTROL_DECLARATIONS_METADATA_KEY = 'control_declarations';

const HEADER_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const PRINTABLE_ASCII = /^[\x20-\x7E]+$/;
const ABSOLUTE_PATH = /^\/(?!\/)[^\s?#]*$/;
const MAX_NETWORK_RULES = 64;
const MAX_MARKER_PATHS = 5;
const MAX_NOTE = 200;
const MAX_HEADER_NAME = 64;
const MAX_HEADER_VALUE = 256;
const MAX_PATH = 256;
const MAX_URL = 2048;
const MAX_STATUS_CODES = 16;

export const VETTED_BOUNDED_SCAN_PORTS = Object.freeze([
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5432, 6379, 8080, 8443,
  3306, 1433, 1521, 27017, 9200, 6443, 10250, 2379, 2375, 5900, 5985, 389, 636, 139, 2049,
]);
const VETTED_PORT_SET = new Set(VETTED_BOUNDED_SCAN_PORTS);
const MAX_DECLARED_SCAN_PORTS = 15;

const TOP_LEVEL_KEYS = new Set([
  'version', 'network_policy', 'waf', 'origin', 'perspectives', 'canary_sink',
  'connection_limits', 'updated_at', 'updated_by', 'revision',
]);
const WAF_KEYS = new Set(['block_signature', 'expected_action', 'rate_limit_canary', 'marker_paths']);
const BLOCK_SIGNATURE_KEYS = new Set(['header_name', 'header_value', 'status_codes']);
const RATE_LIMIT_KEYS = new Set(['path', 'method', 'threshold', 'window_seconds', 'expected_action']);
const ORIGIN_KEYS = new Set(['lockdown_expected']);
const PERSPECTIVE_KEYS = new Set(['allowlisted_perspective_ids', 'denied_perspective_ids']);
const CANARY_SINK_KEYS = new Set(['url']);
const NETWORK_RULE_KEYS = new Set(['protocol', 'port', 'action', 'address_family', 'note']);
const CONNECTION_LIMIT_KEYS = new Set(['protocol', 'port', 'max_connections_per_source']);

const NETWORK_PROBE_KINDS = new Set([
  'tcp_connect', 'udp_probe', 'port_scan_bounded', 'connection_limit_probe',
  'reflection_service_probe', 'quic_reachability',
]);
const WAF_PROBE_KINDS = new Set([
  'waf_enforcement_probe', 'waf_class_marker_probe', 'waf_evasion_marker_probe',
  'waf_fingerprint_observation', 'waf_inspection_limit_probe', 'outside_in_waf_scan',
  'rate_limit_sequence', 'bot_challenge_probe', 'http_method_matrix', 'header_size_probe',
  'http_head', 'cache_abuse_probe', 'l7_resource_posture_probe',
  'waf_method_policy_probe', 'rate_limit_canary_probe',
]);
const ORIGIN_PROBE_KINDS = new Set(['host_sni_bypass', 'origin_leak_scan']);
const NETWORK_FAMILIES = new Set(['l3_l4', 'reflection', 'amplification']);
const WAF_FAMILIES = new Set(['waf', 'l7', 'path']);
const ORIGIN_FAMILIES = new Set(['origin']);

export class ControlDeclarationsValidationError extends Error {
  constructor(field, message, errors = []) {
    super(message);
    this.name = 'ControlDeclarationsValidationError';
    this.code = 'invalid_control_declarations';
    this.status = 400;
    this.field = field;
    this.errors = errors.length ? errors : [{ field, message }];
  }

  toResponse() {
    return {
      error: this.code,
      status: this.status,
      field: this.field,
      message: this.message,
      errors: this.errors,
    };
  }
}

function rejectUnknownKeys(object, allowed, path) {
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) throwField(`${path}.${key}`, `Unknown field "${key}".`);
  }
}

function throwField(field, message) {
  throw new ControlDeclarationsValidationError(field, message);
}

function asObject(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throwField(field, `${field} must be an object.`);
  }
  return value;
}

function trimmedString(value, field, max) {
  if (typeof value !== 'string') throwField(field, `${field} must be a string.`);
  const trimmed = value.trim();
  if (!trimmed) throwField(field, `${field} must be a non-empty string.`);
  if (trimmed.length > max) throwField(field, `${field} must be at most ${max} characters.`);
  return trimmed;
}

function integerInRange(value, field, min, max) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throwField(field, `${field} must be an integer between ${min} and ${max}.`);
  }
  return value;
}

function portNumber(value, field) {
  return integerInRange(value, field, 1, 65535);
}

function unbracketHost(value) {
  return String(value ?? '').trim().replace(/^\[|\]$/g, '').toLowerCase();
}

export function targetHostFromRecord(target) {
  if (!target) return null;
  const kind = String(target.kind ?? '').trim().toLowerCase();
  const value = String(target.value ?? target.normalized_value ?? '').trim();
  if (!value) return null;
  if (kind === 'url' || /^https?:\/\//i.test(value)) {
    try {
      return unbracketHost(new URL(value).hostname);
    } catch {
      return null;
    }
  }
  if (kind === 'tcp') {
    const v6 = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
    if (v6) return unbracketHost(v6[1]);
    const hostPort = /^([^:]+):\d+$/.exec(value);
    return unbracketHost(hostPort ? hostPort[1] : value);
  }
  if (kind === 'ip') return unbracketHost(value);
  return unbracketHost(value.replace(/\.+$/, ''));
}

function isSameHostOrSubdomain(candidate, targetHost) {
  const host = unbracketHost(candidate);
  const base = unbracketHost(targetHost);
  if (!host || !base) return false;
  if (host === base) return true;
  if (isIP(base) !== 0) return false;
  return host.endsWith(`.${base}`);
}

function absolutePath(value, field) {
  const path = trimmedString(value, field, MAX_PATH);
  if (!ABSOLUTE_PATH.test(path) || path.includes('\\') || path.includes('://')) {
    throwField(field, `${field} must be an absolute path starting with "/".`);
  }
  return path;
}

function normalizeNetworkPolicy(input) {
  if (!Array.isArray(input)) throwField('network_policy', 'network_policy must be an array.');
  if (input.length > MAX_NETWORK_RULES) {
    throwField('network_policy', `At most ${MAX_NETWORK_RULES} network_policy rules are allowed.`);
  }
  const seen = new Set();
  return input.map((raw, index) => {
    const field = `network_policy[${index}]`;
    const rule = asObject(raw, field);
    rejectUnknownKeys(rule, NETWORK_RULE_KEYS, field);
    const protocol = trimmedString(rule.protocol, `${field}.protocol`, 8).toLowerCase();
    if (protocol !== 'tcp' && protocol !== 'udp') throwField(`${field}.protocol`, 'protocol must be "tcp" or "udp".');
    const port = portNumber(rule.port, `${field}.port`);
    const action = trimmedString(rule.action, `${field}.action`, 8).toLowerCase();
    if (action !== 'allow' && action !== 'deny') throwField(`${field}.action`, 'action must be "allow" or "deny".');
    const address_family = trimmedString(rule.address_family, `${field}.address_family`, 8).toLowerCase();
    if (!['ipv4', 'ipv6', 'any'].includes(address_family)) {
      throwField(`${field}.address_family`, 'address_family must be "ipv4", "ipv6", or "any".');
    }
    const key = `${protocol}:${port}:${address_family}`;
    if (seen.has(key)) throwField(field, 'Duplicate network_policy rule for the same protocol, port, and address family.');
    seen.add(key);
    const out = { protocol, port, action, address_family };
    if (rule.note != null && rule.note !== '') out.note = trimmedString(rule.note, `${field}.note`, MAX_NOTE);
    return out;
  });
}

function normalizeBlockSignature(input, field) {
  const sig = asObject(input, field);
  rejectUnknownKeys(sig, BLOCK_SIGNATURE_KEYS, field);
  const header_name = trimmedString(sig.header_name, `${field}.header_name`, MAX_HEADER_NAME).toLowerCase();
  if (!HEADER_TOKEN.test(header_name)) {
    throwField(`${field}.header_name`, 'header_name must be an RFC 7230 token.');
  }
  const header_value = trimmedString(sig.header_value, `${field}.header_value`, MAX_HEADER_VALUE);
  if (!PRINTABLE_ASCII.test(header_value)) {
    throwField(`${field}.header_value`, 'header_value must be printable ASCII of at most 256 characters.');
  }
  const out = { header_name, header_value };
  if (sig.status_codes != null) {
    if (!Array.isArray(sig.status_codes) || sig.status_codes.length === 0) {
      throwField(`${field}.status_codes`, 'status_codes must be a non-empty array of integers 400–599.');
    }
    if (sig.status_codes.length > MAX_STATUS_CODES) {
      throwField(`${field}.status_codes`, `At most ${MAX_STATUS_CODES} status_codes are allowed.`);
    }
    const codes = [];
    const seen = new Set();
    for (let i = 0; i < sig.status_codes.length; i += 1) {
      const code = integerInRange(sig.status_codes[i], `${field}.status_codes[${i}]`, 400, 599);
      if (seen.has(code)) continue;
      seen.add(code);
      codes.push(code);
    }
    out.status_codes = codes;
  }
  return out;
}

function normalizeRateLimitCanary(input, field) {
  const canary = asObject(input, field);
  rejectUnknownKeys(canary, RATE_LIMIT_KEYS, field);
  const path = absolutePath(canary.path, `${field}.path`);
  const method = trimmedString(canary.method, `${field}.method`, 8).toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') throwField(`${field}.method`, 'method must be "GET" or "HEAD".');
  let expected_action = 'block';
  if (canary.expected_action != null) {
    const action = trimmedString(canary.expected_action, `${field}.expected_action`, 32);
    if (action !== 'block' && action !== 'block_or_challenge') {
      throwField(`${field}.expected_action`, 'expected_action must be "block" or "block_or_challenge".');
    }
    expected_action = action;
  }
  return {
    path,
    method,
    threshold: integerInRange(canary.threshold, `${field}.threshold`, 1, 10),
    window_seconds: integerInRange(canary.window_seconds, `${field}.window_seconds`, 1, 60),
    expected_action,
  };
}

function normalizeWaf(input, field) {
  const waf = asObject(input, field);
  rejectUnknownKeys(waf, WAF_KEYS, field);
  const out = {};
  if (waf.block_signature != null) out.block_signature = normalizeBlockSignature(waf.block_signature, `${field}.block_signature`);
  if (waf.expected_action != null) {
    const action = trimmedString(waf.expected_action, `${field}.expected_action`, 32);
    if (!['block', 'challenge', 'block_or_challenge'].includes(action)) {
      throwField(`${field}.expected_action`, 'expected_action must be "block", "challenge", or "block_or_challenge".');
    }
    out.expected_action = action;
  }
  if (waf.rate_limit_canary != null) {
    out.rate_limit_canary = normalizeRateLimitCanary(waf.rate_limit_canary, `${field}.rate_limit_canary`);
  }
  if (waf.marker_paths != null) {
    if (!Array.isArray(waf.marker_paths)) throwField(`${field}.marker_paths`, 'marker_paths must be an array.');
    if (waf.marker_paths.length > MAX_MARKER_PATHS) {
      throwField(`${field}.marker_paths`, `At most ${MAX_MARKER_PATHS} marker_paths are allowed.`);
    }
    const seen = new Set();
    out.marker_paths = waf.marker_paths.map((path, index) => {
      const normalized = absolutePath(path, `${field}.marker_paths[${index}]`);
      if (seen.has(normalized)) throwField(`${field}.marker_paths[${index}]`, 'Duplicate marker_paths entry.');
      seen.add(normalized);
      return normalized;
    });
  }
  return out;
}

function normalizePerspectives(input, field, knownIds) {
  const perspectives = asObject(input, field);
  rejectUnknownKeys(perspectives, PERSPECTIVE_KEYS, field);
  const normalizeIds = (raw, subfield) => {
    if (!Array.isArray(raw)) throwField(subfield, `${subfield} must be an array of perspective ids.`);
    const ids = [];
    const seen = new Set();
    for (let i = 0; i < raw.length; i += 1) {
      const id = trimmedString(raw[i], `${subfield}[${i}]`, 32);
      if (!knownIds.has(id)) throwField(`${subfield}[${i}]`, `Unknown probe perspective "${id}".`);
      if (seen.has(id)) continue;
      seen.add(id);
      ids.push(id);
    }
    return ids;
  };
  const out = {};
  if (perspectives.allowlisted_perspective_ids != null) {
    out.allowlisted_perspective_ids = normalizeIds(perspectives.allowlisted_perspective_ids, `${field}.allowlisted_perspective_ids`);
  }
  if (perspectives.denied_perspective_ids != null) {
    out.denied_perspective_ids = normalizeIds(perspectives.denied_perspective_ids, `${field}.denied_perspective_ids`);
  }
  return out;
}

function normalizeCanarySink(input, field, targetHost) {
  const sink = asObject(input, field);
  rejectUnknownKeys(sink, CANARY_SINK_KEYS, field);
  const url = trimmedString(sink.url, `${field}.url`, MAX_URL);
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throwField(`${field}.url`, 'canary_sink.url must be an absolute HTTPS URL.');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throwField(`${field}.url`, 'canary_sink.url must be HTTPS with no credentials.');
  }
  const sinkHost = unbracketHost(parsed.hostname);
  if (!targetHost || sinkHost.toLowerCase() !== targetHost.toLowerCase()) {
    throwField(`${field}.url`, 'canary_sink.url host must equal the target host.');
  }
  parsed.hash = '';
  return { url: parsed.toString() };
}

function normalizeConnectionLimits(input) {
  if (!Array.isArray(input)) throwField('connection_limits', 'connection_limits must be an array.');
  if (input.length > MAX_NETWORK_RULES) {
    throwField('connection_limits', `At most ${MAX_NETWORK_RULES} connection_limits entries are allowed.`);
  }
  const seen = new Set();
  return input.map((raw, index) => {
    const field = `connection_limits[${index}]`;
    const row = asObject(raw, field);
    rejectUnknownKeys(row, CONNECTION_LIMIT_KEYS, field);
    const protocol = trimmedString(row.protocol, `${field}.protocol`, 8).toLowerCase();
    if (protocol !== 'tcp') throwField(`${field}.protocol`, 'protocol must be "tcp".');
    const port = portNumber(row.port, `${field}.port`);
    const key = `${protocol}:${port}`;
    if (seen.has(key)) throwField(field, 'Duplicate connection_limits entry for the same protocol and port.');
    seen.add(key);
    return {
      protocol,
      port,
      max_connections_per_source: integerInRange(
        row.max_connections_per_source,
        `${field}.max_connections_per_source`,
        1,
        10,
      ),
    };
  });
}

/**
 * Validate and normalize a full-replace control-declarations document.
 * Server-owned `updated_at` / `updated_by` / `revision` are ignored on input.
 *
 * @param {unknown} input
 * @param {{ target?: { kind?: string, value?: string, normalized_value?: string }, env?: NodeJS.ProcessEnv }} [options]
 */
export function normalizeControlDeclarations(input, { target, env } = {}) {
  const source = asObject(input, 'control_declarations');
  rejectUnknownKeys(source, TOP_LEVEL_KEYS, 'control_declarations');
  if (source.version != null && source.version !== CONTROL_DECLARATIONS_VERSION) {
    throwField('version', `version must be ${CONTROL_DECLARATIONS_VERSION}.`);
  }
  const targetHost = targetHostFromRecord(target);
  const knownIds = probePerspectiveIds(env);
  const out = { version: CONTROL_DECLARATIONS_VERSION };
  if (source.network_policy != null) out.network_policy = normalizeNetworkPolicy(source.network_policy);
  if (source.waf != null) out.waf = normalizeWaf(source.waf, 'waf');
  if (source.origin != null) {
    const origin = asObject(source.origin, 'origin');
    rejectUnknownKeys(origin, ORIGIN_KEYS, 'origin');
    if (typeof origin.lockdown_expected !== 'boolean') {
      throwField('origin.lockdown_expected', 'lockdown_expected must be a boolean.');
    }
    out.origin = { lockdown_expected: origin.lockdown_expected };
  }
  if (source.perspectives != null) out.perspectives = normalizePerspectives(source.perspectives, 'perspectives', knownIds);
  if (source.canary_sink != null) out.canary_sink = normalizeCanarySink(source.canary_sink, 'canary_sink', targetHost);
  if (source.connection_limits != null) out.connection_limits = normalizeConnectionLimits(source.connection_limits);
  return out;
}

export function controlDeclarationsFromTarget(target) {
  const meta = target?.metadata ?? target?.metadata_json;
  const value = meta && typeof meta === 'object' ? meta[CONTROL_DECLARATIONS_METADATA_KEY] : null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value;
}

export function declaredNetworkPolicyFor(declarations, { protocol, port, addressFamily } = {}) {
  const rules = declarations?.network_policy;
  if (!Array.isArray(rules)) return null;
  const proto = String(protocol ?? '').toLowerCase();
  const family = String(addressFamily ?? 'any').toLowerCase();
  const portNumberValue = Number(port);
  let anyMatch = null;
  for (const rule of rules) {
    if (rule.protocol !== proto || rule.port !== portNumberValue) continue;
    if (rule.address_family === family) return rule;
    if (rule.address_family === 'any' && anyMatch == null) anyMatch = rule;
  }
  return anyMatch;
}

export function declaredBlockSignature(declarations) {
  const sig = declarations?.waf?.block_signature;
  return sig && typeof sig === 'object' ? sig : null;
}

/**
 * Shape consumed by capabilityProbes / externalObservationOutcomes (`header` + optional
 * `status_code`) plus the contract fields (`header_name`, `header_value`, `status_codes`).
 */
export function mapDeclaredBlockSignatureForProbe(declarations) {
  const sig = declaredBlockSignature(declarations);
  if (!sig) return null;
  const mapped = {
    header_name: sig.header_name,
    header_value: sig.header_value,
    header: { name: sig.header_name, value: sig.header_value },
  };
  if (Array.isArray(sig.status_codes) && sig.status_codes.length) {
    mapped.status_codes = sig.status_codes;
    if (sig.status_codes.length === 1) mapped.status_code = sig.status_codes[0];
  }
  return mapped;
}

export function declaredPortsForBoundedScan(declarations) {
  const rules = declarations?.network_policy;
  if (!Array.isArray(rules)) return [];
  const ports = [];
  const seen = new Set();
  for (const rule of rules) {
    if (!VETTED_PORT_SET.has(rule.port) || seen.has(rule.port)) continue;
    seen.add(rule.port);
    ports.push(rule.port);
    if (ports.length >= MAX_DECLARED_SCAN_PORTS) break;
  }
  return ports;
}

export function probeDeclarationsSubset(declarations, check) {
  if (!declarations || typeof declarations !== 'object') return { version: CONTROL_DECLARATIONS_VERSION };
  const kind = check?.probe_profile?.kind ?? check?.probe_kind ?? null;
  const family = check?.vector_family ?? null;
  const subset = { version: declarations.version ?? CONTROL_DECLARATIONS_VERSION };
  const wantNetwork = NETWORK_PROBE_KINDS.has(kind) || NETWORK_FAMILIES.has(family);
  const wantWaf = WAF_PROBE_KINDS.has(kind) || WAF_FAMILIES.has(family);
  const wantOrigin = ORIGIN_PROBE_KINDS.has(kind) || ORIGIN_FAMILIES.has(family);
  if (wantNetwork && declarations.network_policy) subset.network_policy = declarations.network_policy;
  if (wantNetwork && declarations.connection_limits) subset.connection_limits = declarations.connection_limits;
  if (wantWaf && declarations.waf) subset.waf = declarations.waf;
  if (wantWaf && declarations.canary_sink) subset.canary_sink = declarations.canary_sink;
  if (wantOrigin && declarations.origin) subset.origin = declarations.origin;
  if (declarations.perspectives) subset.perspectives = declarations.perspectives;
  return subset;
}

/** Audit-safe summary: header name and value length, never the value. */
export function summarizeControlDeclarationsForAudit(declarations) {
  if (!declarations || typeof declarations !== 'object') return null;
  const sig = declarations.waf?.block_signature;
  let canaryHost = null;
  if (declarations.canary_sink?.url) {
    try {
      canaryHost = unbracketHost(new URL(declarations.canary_sink.url).hostname);
    } catch {
      canaryHost = null;
    }
  }
  return {
    version: declarations.version ?? CONTROL_DECLARATIONS_VERSION,
    network_policy_count: Array.isArray(declarations.network_policy) ? declarations.network_policy.length : 0,
    connection_limits_count: Array.isArray(declarations.connection_limits) ? declarations.connection_limits.length : 0,
    expected_action: declarations.waf?.expected_action ?? null,
    block_header_name: sig?.header_name ?? null,
    block_header_value_length: typeof sig?.header_value === 'string' ? sig.header_value.length : 0,
    has_rate_limit_canary: Boolean(declarations.waf?.rate_limit_canary),
    marker_path_count: Array.isArray(declarations.waf?.marker_paths) ? declarations.waf.marker_paths.length : 0,
    origin_lockdown_expected: declarations.origin?.lockdown_expected ?? null,
    allowlisted_perspective_ids: declarations.perspectives?.allowlisted_perspective_ids ?? [],
    denied_perspective_ids: declarations.perspectives?.denied_perspective_ids ?? [],
    canary_sink_host: canaryHost,
  };
}

/** Optimistic-concurrency revision of a stored document; documents saved before revisions existed are 0. */
export function controlDeclarationsRevision(declarations) {
  const revision = Number(declarations?.revision);
  return Number.isSafeInteger(revision) && revision >= 0 ? revision : 0;
}

export function controlDeclarationsEtag(revision) {
  return `"decl-r${revision}"`;
}

/** True when an If-Match header names the current revision's entity tag; `*` is not accepted. */
export function controlDeclarationsIfMatch(header, revision) {
  if (typeof header !== 'string' || !header.trim()) return false;
  const current = controlDeclarationsEtag(revision);
  return header.split(',').map((tag) => tag.trim().replace(/^W\//, '')).some((tag) => tag === current);
}

export function emptyControlDeclarations() {
  return { version: CONTROL_DECLARATIONS_VERSION };
}
