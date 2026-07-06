import { isIP } from 'node:net';

const DISCOVERED_VIA_VALUES = new Set([
  'operator_env',
  'cloud_metadata',
  'dns_resolve',
  'stun',
]);

const HOSTNAME_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function fail(message) {
  return { ok: false, error: 'invalid_probe_endpoint', message };
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseIpv4Octets(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    octets.push(n);
  }
  return octets;
}

function ipv4IsUnspecified(octets) {
  return octets.every((o) => o === 0);
}

function ipv4IsLoopback(octets) {
  return octets[0] === 127;
}

function ipv4IsLinkLocal(octets) {
  return octets[0] === 169 && octets[1] === 254;
}

function ipv4IsMetadata(ip) {
  return ip === '169.254.169.254';
}

function ipv4IsPrivate(octets) {
  if (octets[0] === 10) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  return false;
}

function parseIpv6Hextets(ip) {
  const lower = ip.toLowerCase();
  if (isIP(lower) !== 6) return null;

  const mapped = lower.match(/^(::ffff:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) {
    const octets = parseIpv4Octets(mapped[2]);
    if (!octets) return null;
    return { kind: 'mapped', octets, embedded: mapped[2] };
  }

  let head = [];
  let tail = [];
  if (lower.includes('::')) {
    const [left, right] = lower.split('::');
    head = left ? left.split(':').filter((s) => s.length > 0) : [];
    tail = right !== undefined && right.length > 0 ? right.split(':') : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    const hextets = [
      ...head.map((h) => parseInt(h, 16)),
      ...Array.from({ length: missing }, () => 0),
      ...tail.map((t) => parseInt(t, 16)),
    ];
    if (hextets.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
    return { kind: 'hextets', hextets };
  }

  const segments = lower.split(':');
  if (segments.length !== 8) return null;
  const hextets = segments.map((s) => parseInt(s, 16));
  if (hextets.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
  return { kind: 'hextets', hextets };
}

function ipv6IsUnspecified(parsed) {
  if (parsed.kind === 'mapped') {
    return ipv4IsUnspecified(parsed.octets);
  }
  return parsed.hextets.every((h) => h === 0);
}

function ipv6IsLoopback(parsed) {
  if (parsed.kind === 'mapped') return false;
  return parsed.hextets.slice(0, 7).every((h) => h === 0) && parsed.hextets[7] === 1;
}

function ipv6IsLinkLocal(parsed) {
  if (parsed.kind === 'mapped') return false;
  return (parsed.hextets[0] & 0xffc0) === 0xfe80;
}

function ipv6IsUla(parsed) {
  if (parsed.kind === 'mapped') return false;
  return (parsed.hextets[0] & 0xfe00) === 0xfc00;
}

function classifyRoutableIp(ip, allowPrivate) {
  const version = isIP(ip);
  if (version === 0) {
    return { ok: false, message: 'invalid IP literal' };
  }

  if (version === 4) {
    const octets = parseIpv4Octets(ip);
    if (!octets) return { ok: false, message: 'invalid IPv4 literal' };
    if (ipv4IsUnspecified(octets)) {
      return { ok: false, message: 'unspecified IPv4 address' };
    }
    if (ipv4IsLoopback(octets)) {
      return { ok: false, message: 'loopback IPv4 address' };
    }
    if (ipv4IsMetadata(ip)) {
      return { ok: false, message: 'cloud metadata IPv4 address' };
    }
    if (ipv4IsLinkLocal(octets)) {
      return { ok: false, message: 'link-local IPv4 address' };
    }
    if (!allowPrivate && ipv4IsPrivate(octets)) {
      return { ok: false, message: 'private IPv4 address' };
    }
    return { ok: true };
  }

  const parsed = parseIpv6Hextets(ip);
  if (!parsed) return { ok: false, message: 'invalid IPv6 literal' };

  if (parsed.kind === 'mapped') {
    return classifyRoutableIp(parsed.embedded, allowPrivate);
  }

  if (ipv6IsUnspecified(parsed)) {
    return { ok: false, message: 'unspecified IPv6 address' };
  }
  if (ipv6IsLoopback(parsed)) {
    return { ok: false, message: 'loopback IPv6 address' };
  }
  if (ipv6IsLinkLocal(parsed)) {
    return { ok: false, message: 'link-local IPv6 address' };
  }
  if (!allowPrivate && ipv6IsUla(parsed)) {
    return { ok: false, message: 'ULA IPv6 address' };
  }
  return { ok: true };
}

function validateIpLiteral(ip, fieldName) {
  if (typeof ip !== 'string' || isIP(ip) === 0) {
    return fail(`${fieldName} must be a valid IPv4 or IPv6 literal`);
  }
  return null;
}

function validateDeclaredFqdn(fqdn) {
  if (typeof fqdn !== 'string') {
    return { error: fail('declared_fqdn must be a string') };
  }
  const lower = fqdn.toLowerCase();
  if (lower.length < 1 || lower.length > 253) {
    return { error: fail('declared_fqdn length must be between 1 and 253') };
  }
  if (
    lower.includes('://')
    || lower.includes('@')
    || lower.includes('/')
    || /\s/.test(lower)
    || lower.includes(':')
  ) {
    return { error: fail('declared_fqdn contains invalid characters') };
  }
  const labels = lower.split('.');
  if (labels.some((label) => label.length === 0 || !HOSTNAME_LABEL.test(label))) {
    return { error: fail('declared_fqdn must match hostname pattern') };
  }
  return { value: lower };
}

function validateListenPort(port) {
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
    return fail('listen_port must be an integer between 1 and 65535');
  }
  return null;
}

function validatePathPrefix(pathPrefix) {
  if (typeof pathPrefix !== 'string') {
    return fail('path_prefix must be a string');
  }
  if (pathPrefix.length < 1 || pathPrefix.length > 128) {
    return fail('path_prefix length must be between 1 and 128');
  }
  if (!pathPrefix.startsWith('/') || /\s/.test(pathPrefix) || pathPrefix.includes('://')) {
    return fail('path_prefix must start with / and contain no whitespace or scheme');
  }
  return null;
}

export function validateProbeEndpoint(endpoint, options = {}) {
  const allowPrivate = options.allowPrivate === true;

  if (!isPlainObject(endpoint)) {
    return fail('probe_endpoint must be a plain object');
  }

  const hasFqdn = endpoint.declared_fqdn !== undefined && endpoint.declared_fqdn !== null;
  const hasDeclaredIp = endpoint.declared_ip !== undefined && endpoint.declared_ip !== null;
  const hasDiscoveredIp = endpoint.discovered_public_ip !== undefined && endpoint.discovered_public_ip !== null;

  if (!hasFqdn && !hasDeclaredIp && !hasDiscoveredIp) {
    return fail('probe_endpoint must include declared_fqdn, declared_ip, or discovered_public_ip');
  }

  const normalized = {};

  if (hasFqdn) {
    const fqdnResult = validateDeclaredFqdn(endpoint.declared_fqdn);
    if (fqdnResult.error) return fqdnResult.error;
    normalized.declared_fqdn = fqdnResult.value;
  }

  if (hasDeclaredIp) {
    const literalError = validateIpLiteral(endpoint.declared_ip, 'declared_ip');
    if (literalError) return literalError;
    const routable = classifyRoutableIp(endpoint.declared_ip, allowPrivate);
    if (!routable.ok) {
      return fail(`declared_ip: ${routable.message}`);
    }
    normalized.declared_ip = endpoint.declared_ip;
  }

  if (hasDiscoveredIp) {
    const literalError = validateIpLiteral(endpoint.discovered_public_ip, 'discovered_public_ip');
    if (literalError) return literalError;
    const routable = classifyRoutableIp(endpoint.discovered_public_ip, allowPrivate);
    if (!routable.ok) {
      return fail(`discovered_public_ip: ${routable.message}`);
    }
    normalized.discovered_public_ip = endpoint.discovered_public_ip;
  }

  if (endpoint.agent_local_ip !== undefined && endpoint.agent_local_ip !== null) {
    const literalError = validateIpLiteral(endpoint.agent_local_ip, 'agent_local_ip');
    if (literalError) return literalError;
    normalized.agent_local_ip = endpoint.agent_local_ip;
  }

  if (endpoint.listen_port !== undefined && endpoint.listen_port !== null) {
    const portError = validateListenPort(endpoint.listen_port);
    if (portError) return portError;
    normalized.listen_port = endpoint.listen_port;
  }

  if (endpoint.path_prefix !== undefined && endpoint.path_prefix !== null) {
    const pathError = validatePathPrefix(endpoint.path_prefix);
    if (pathError) return pathError;
    normalized.path_prefix = endpoint.path_prefix;
  }

  if (endpoint.discovered_via !== undefined && endpoint.discovered_via !== null) {
    if (typeof endpoint.discovered_via !== 'string' || !DISCOVERED_VIA_VALUES.has(endpoint.discovered_via)) {
      return fail('discovered_via must be one of operator_env, cloud_metadata, dns_resolve, stun');
    }
    normalized.discovered_via = endpoint.discovered_via;
  }

  return { ok: true, normalized };
}

export function checkProbeEndpointBinding(
  normalized,
  { prebindFqdn = null, targetGroupFqdns = [], targetGroupResolved = false } = {},
) {
  if (!normalized.declared_fqdn) {
    return { ok: true };
  }

  if (typeof prebindFqdn === 'string' && prebindFqdn.trim() !== '') {
    const expected = prebindFqdn.trim().toLowerCase();
    if (normalized.declared_fqdn !== expected) {
      return {
        ok: false,
        error: 'fqdn_prebind_mismatch',
        message: 'declared_fqdn does not match bootstrap token prebind_fqdn',
      };
    }
  }

  if (targetGroupResolved) {
    const allowed = (Array.isArray(targetGroupFqdns) ? targetGroupFqdns : [])
      .map((fqdn) => String(fqdn).trim().toLowerCase());
    if (allowed.length === 0 || !allowed.includes(normalized.declared_fqdn)) {
      return {
        ok: false,
        error: 'target_group_mismatch',
        message: 'declared_fqdn is not listed in the agent target group',
      };
    }
  } else if (Array.isArray(targetGroupFqdns) && targetGroupFqdns.length > 0) {
    const allowed = targetGroupFqdns.map((fqdn) => String(fqdn).trim().toLowerCase());
    if (!allowed.includes(normalized.declared_fqdn)) {
      return {
        ok: false,
        error: 'target_group_mismatch',
        message: 'declared_fqdn is not listed in the agent target group',
      };
    }
  }

  return { ok: true };
}