import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

const KIND_ALIASES = new Map([
  ['domain', 'fqdn'],
  ['hostname', 'fqdn'],
]);

export const TARGET_KINDS = Object.freeze(['fqdn', 'ip', 'url', 'tcp', 'dns_zone', 'canary']);
const TARGET_KIND_SET = new Set(TARGET_KINDS);

const RESERVED_METADATA_KEYS = new Set([
  'ownership',
  'ownership_status',
  'dns_ownership',
  'verification',
  'verification_state',
  'verify_state',
  'verification_source_kind',
  'verification_source_ref',
  'verification_transitioned_at',
  'eligibility',
  'eligibility_reason',
  'source',
  'target_source',
  'import_source',
  'import_integration',
  'provenance',
  'trusted_provenance',
  'managed_provenance',
  'declared_import',
  'created_by',
  'updated_by',
  'deleted_by',
  'audit',
  'audit_log',
]);

function normalizedKey(value) {
  return String(value).trim().toLowerCase().replace(/[\s.-]+/g, '_');
}

export class TargetValidationError extends Error {
  constructor(field, message, code = 'invalid_target') {
    super(message);
    this.name = 'TargetValidationError';
    this.code = code;
    this.status = 400;
    this.field = field;
  }

  toResponse() {
    return { error: this.code, status: this.status, field: this.field, message: this.message };
  }
}

export function normalizeTargetKind(input) {
  const raw = String(input ?? '').trim().toLowerCase();
  const kind = KIND_ALIASES.get(raw) ?? raw;
  if (!TARGET_KIND_SET.has(kind)) {
    throw new TargetValidationError('kind', `Unsupported target kind: ${raw || '(empty)'}`);
  }
  return kind;
}

function normalizeFqdn(input, field = 'value') {
  const raw = String(input ?? '').trim().replace(/\.+$/, '');
  if (!raw || /[:/@\\?#]/.test(raw)) {
    throw new TargetValidationError(field, 'FQDN targets must be hostnames without a scheme, path, credentials, or port.');
  }
  const ascii = domainToASCII(raw).toLowerCase();
  if (!ascii || ascii.length > 253) {
    throw new TargetValidationError(field, 'FQDN target is not a valid DNS hostname.');
  }
  const labels = ascii.split('.');
  if (labels.some((label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    throw new TargetValidationError(field, 'FQDN target is not a valid DNS hostname.');
  }
  return ascii;
}

function normalizeIp(input, field = 'value') {
  const raw = String(input ?? '').trim();
  if (!raw || !isIP(raw)) {
    throw new TargetValidationError(field, 'IP targets must contain only an IPv4 or IPv6 address; host:port belongs to kind "tcp".');
  }
  if (isIP(raw) === 4) return raw;
  const hostname = new URL(`http://[${raw}]/`).hostname;
  return hostname.slice(1, -1).toLowerCase();
}

function normalizeUrl(input, field = 'value') {
  let parsed;
  try {
    parsed = new URL(String(input ?? '').trim());
  } catch {
    throw new TargetValidationError(field, 'URL targets must be absolute HTTP or HTTPS URLs.');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new TargetValidationError(field, 'URL targets must use HTTP or HTTPS and must not contain credentials.');
  }
  const rawHostname = parsed.hostname.startsWith('[') && parsed.hostname.endsWith(']')
    ? parsed.hostname.slice(1, -1)
    : parsed.hostname;
  const normalizedHostname = isIP(rawHostname) ? normalizeIp(rawHostname, field) : normalizeFqdn(rawHostname, field);
  parsed.hostname = isIP(normalizedHostname) === 6 ? `[${normalizedHostname}]` : normalizedHostname;
  parsed.hash = '';
  return parsed.toString();
}

function normalizeTcp(input, field = 'value') {
  const raw = String(input ?? '').trim();
  const ipv6 = /^\[([^\]]+)]:(\d+)$/.exec(raw);
  const hostPort = /^([^:]+):(\d+)$/.exec(raw);
  const match = ipv6 ?? hostPort;
  if (!match) {
    throw new TargetValidationError(field, 'TCP targets must use host:port or [IPv6]:port.');
  }
  const host = isIP(match[1]) ? normalizeIp(match[1], field) : normalizeFqdn(match[1], field);
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TargetValidationError(field, 'TCP target port must be between 1 and 65535.');
  }
  return isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`;
}

export function normalizeTargetValue(kindInput, value) {
  const kind = normalizeTargetKind(kindInput);
  if (kind === 'fqdn' || kind === 'dns_zone') return normalizeFqdn(value);
  if (kind === 'ip') return normalizeIp(value);
  if (kind === 'url') return normalizeUrl(value);
  if (kind === 'tcp') return normalizeTcp(value);
  if (kind === 'canary') {
    const raw = String(value ?? '').trim();
    return /^https?:\/\//i.test(raw) ? normalizeUrl(raw) : normalizeFqdn(raw);
  }
  throw new TargetValidationError('kind', `Unsupported target kind: ${kind}`);
}

function sanitizeMetadataValue(value, dropped, path, depth) {
  if (depth > 5) return null;
  if (value == null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.slice(0, 100).map((item, index) => sanitizeMetadataValue(item, dropped, `${path}[${index}]`, depth + 1));
  if (typeof value !== 'object') return String(value);

  const output = {};
  for (const [key, child] of Object.entries(value)) {
    const canonical = normalizedKey(key);
    const childPath = path ? `${path}.${key}` : key;
    if (RESERVED_METADATA_KEYS.has(canonical) || canonical.startsWith('ownership_') || canonical.startsWith('verification_') || canonical.startsWith('eligibility_') || canonical.startsWith('provenance_') || ['__proto__', 'prototype', 'constructor'].includes(canonical)) {
      dropped.push(childPath);
      continue;
    }
    output[key] = sanitizeMetadataValue(child, dropped, childPath, depth + 1);
  }
  return output;
}

export function sanitizeClientTargetMetadata(input) {
  const dropped_fields = [];
  const metadata = input && typeof input === 'object' && !Array.isArray(input)
    ? sanitizeMetadataValue(input, dropped_fields, '', 0)
    : {};
  return { metadata, dropped_fields };
}

export function normalizeTargetInput(input, { current = null } = {}) {
  const source = input && typeof input === 'object' ? input : {};
  const kind = normalizeTargetKind(source.kind ?? current?.kind ?? 'fqdn');
  const value = normalizeTargetValue(kind, source.value ?? current?.value);
  const sanitized = source.metadata !== undefined || source.metadata_json !== undefined
    ? sanitizeClientTargetMetadata(source.metadata ?? source.metadata_json)
    : { metadata: current?.metadata ?? current?.metadata_json ?? {}, dropped_fields: [] };
  return {
    kind,
    value,
    normalized_value: value,
    metadata: sanitized.metadata,
    dropped_fields: sanitized.dropped_fields,
  };
}

export function targetDedupeKey(target) {
  const normalized = normalizeTargetInput(target);
  return `${normalized.kind}\u0000${normalized.normalized_value}`;
}

export function targetValidationResponse(error) {
  if (error instanceof TargetValidationError) return error.toResponse();
  throw error;
}
