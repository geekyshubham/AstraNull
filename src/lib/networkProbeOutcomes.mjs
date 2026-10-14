/**
 * Shared NFW probe outcome fields: TCP/UDP classes, ICMP mapping, port resolution,
 * address-family selection, CDN peer flag, and sample agreement.
 */
import net from 'node:net';
import { classifyEdgeByAddress } from './edgeFingerprint.mjs';
import { sourcePerspectiveFromEnv } from './probeSourcePerspective.mjs';

export const SAMPLE_GAP_MS = 250;
export const MAX_TCP_UDP_SAMPLES = 2;
export const CONNECTION_LIMIT_HARD_CAP = 12;
export const CONNECTION_HOLD_MS = 2000;

export const REJECT_ICMP_MIN_ELAPSED_MS = 5;
export const REJECT_ICMP_MIN_DURATION_MS = 5;

const REJECT_ICMP_CODES = new Set(['EHOSTUNREACH', 'ENETUNREACH']);
const LOCAL_SOCKET_REFUSAL_CODES = new Set(['EACCES', 'EPERM']);
export const DENY_CHECK_IDS = new Set([
  'nfw.declared_deny_tcp.safe',
  'nfw.declared_deny_udp.safe',
  'l3.basic_deny_rule.safe',
  'l3.forbidden_tcp_port.safe',
  'l3.forbidden_udp_port.safe',
]);

// EACCES/EPERM come from the probe host's own socket policy, never from the remote path.
export function isLocalSocketRefusal(code) {
  return LOCAL_SOCKET_REFUSAL_CODES.has(code);
}

export function validNetworkPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

export function icmpKindFromErrno(code) {
  if (code === 'ECONNREFUSED') return 'port_unreachable';
  if (code === 'EHOSTUNREACH') return 'host_unreachable';
  if (code === 'ENETUNREACH') return 'net_unreachable';
  return 'unknown';
}

export function icmpFromErrno(code) {
  if (code == null || code === '' || isLocalSocketRefusal(code)) return null;
  return { kind: icmpKindFromErrno(code), errno: code };
}

export function classifyTcpErrno(code) {
  if (isLocalSocketRefusal(code)) return { tcp_outcome: 'error', icmp: null, local_error: true };
  if (code === 'ECONNREFUSED') return { tcp_outcome: 'refused_rst', icmp: null };
  if (REJECT_ICMP_CODES.has(code)) {
    return { tcp_outcome: 'rejected_icmp', icmp: icmpFromErrno(code) };
  }
  if (code === 'ETIMEOUT' || code === 'ETIMEDOUT') return { tcp_outcome: 'timeout', icmp: null };
  return { tcp_outcome: 'error', icmp: code ? icmpFromErrno(code) : null };
}

export function classifyUdpErrno(code) {
  if (isLocalSocketRefusal(code)) return { udp_outcome: 'error', icmp: null, local_error: true };
  if (code === 'ECONNREFUSED') {
    return { udp_outcome: 'port_unreachable', icmp: icmpFromErrno(code) };
  }
  if (REJECT_ICMP_CODES.has(code)) {
    return { udp_outcome: 'rejected_icmp', icmp: icmpFromErrno(code) };
  }
  if (code === 'ETIMEOUT' || code === 'ETIMEDOUT') return { udp_outcome: 'silent', icmp: null };
  return { udp_outcome: 'error', icmp: code ? icmpFromErrno(code) : null };
}

export function noPortDeclaredResult(probeKind, extra = {}) {
  return {
    external_result: 'error',
    result: 'unsupported_target',
    reason: 'no_port_declared',
    metadata: {
      probe_kind: probeKind,
      error_class: 'unsupported_target',
      reason: 'no_port_declared',
      ...extra,
    },
    requests_sent: 0,
    duration_ms: 0,
  };
}

/** True when the job's expectation is a declared deny (deny-check ids or a profile/expectation saying so). */
export function isDenyCheckJob(job) {
  const profile = job?.probe_profile ?? {};
  if (DENY_CHECK_IDS.has(job?.check_id) || DENY_CHECK_IDS.has(profile.check_id)) return true;
  return profile.expectation === 'deny' || profile.expected_action === 'deny' || job?.expectation === 'deny';
}

/** A port the signed profile or the target itself names; declarations are never consulted here. */
export function explicitNetworkPort(job) {
  const fromProfile = validNetworkPort(job?.probe_profile?.port);
  if (fromProfile) return fromProfile;
  const fromTargetField = validNetworkPort(job?.target?.port);
  if (fromTargetField) return fromTargetField;
  const value = String(job?.target?.value ?? '').trim();
  const hostPort = value.match(/^([^:\s]+):(\d{1,5})$/);
  if (hostPort && net.isIP(value) !== 6) {
    const parsed = validNetworkPort(Number(hostPort[2]));
    if (parsed) return parsed;
  }
  const bracketed = value.match(/^\[([^\]]+)\]:(\d{1,5})$/);
  if (bracketed) return validNetworkPort(Number(bracketed[2]));
  return null;
}

/** Every declared deny port a deny check may probe within `budget` requests; null when the job is single-port. */
export function declaredDenyPortPlan(job, { protocol = 'tcp', budget = 1 } = {}) {
  if (!isDenyCheckJob(job) || explicitNetworkPort(job)) return null;
  const ports = declaredDenyPorts(job, { protocol, limit: Math.max(1, budget) });
  return ports.length > 1 ? ports : null;
}

/** CONTRACT §3: profile.port → target port → declared network_policy port → profile.default_port; deny checks only ever pick a declared deny. */
export function resolveDeclaredNetworkPort(job, { protocol = 'tcp' } = {}) {
  const profile = job?.probe_profile ?? {};
  const explicit = explicitNetworkPort(job);
  if (explicit) return explicit;
  if (isDenyCheckJob(job)) return declaredDenyPorts(job, { protocol, limit: 1 })[0] ?? null;
  const policyPort = portFromNetworkPolicy(profile, protocol);
  if (policyPort) return policyPort;
  return validNetworkPort(profile.default_port);
}

function policyRowsFor(profile, protocol) {
  const rows = profile?.declarations?.network_policy;
  if (!Array.isArray(rows)) return [];
  const family = profile.address_family;
  return rows.filter((row) => {
    if (!row || validNetworkPort(row.port) == null) return false;
    if (row.protocol != null && row.protocol !== protocol) return false;
    if (row.address_family != null && row.address_family !== 'any'
      && family != null && family !== 'both' && row.address_family !== family) return false;
    return true;
  });
}

/** Declared `deny` ports for the protocol, in declaration order, capped at `limit` (the request budget); never an `allow` rule. */
export function declaredDenyPorts(job, { protocol = 'tcp', limit = Infinity } = {}) {
  const ports = [];
  for (const row of policyRowsFor(job?.probe_profile ?? {}, protocol)) {
    if (row.action !== 'deny') continue;
    const port = validNetworkPort(row.port);
    if (port && !ports.includes(port)) ports.push(port);
    if (ports.length >= limit) break;
  }
  return ports;
}

function portFromNetworkPolicy(profile, protocol) {
  return validNetworkPort(policyRowsFor(profile, protocol)[0]?.port);
}

export function requestedAddressFamily(job) {
  const raw = job?.probe_profile?.address_family;
  return raw === 'ipv4' || raw === 'ipv6' ? raw : 'both';
}

export function splitAddressesByFamily(addresses = []) {
  const ipv4 = [];
  const ipv6 = [];
  for (const value of addresses) {
    const version = net.isIP(value);
    if (version === 4) ipv4.push(value);
    else if (version === 6) ipv6.push(value);
  }
  return { ipv4, ipv6 };
}

export function selectFamilyAddresses(pinned, familyPref = 'both') {
  const split = pinned?.families
    ?? splitAddressesByFamily(pinned?.addresses ?? (pinned?.address ? [pinned.address] : []));
  const pick = (list) => (Array.isArray(list) && list.length ? list[0] : null);
  if (familyPref === 'ipv4') return { ipv4: pick(split.ipv4) };
  if (familyPref === 'ipv6') return { ipv6: pick(split.ipv6) };
  return { ipv4: pick(split.ipv4), ipv6: pick(split.ipv6) };
}

export function familyParity(familyResults) {
  const keys = Object.keys(familyResults ?? {}).filter((key) => familyResults[key] != null && familyResults[key].not_sampled !== true);
  if (keys.length <= 1) return 'single_family';
  const outcomes = keys.map((key) => familyResults[key].tcp_outcome ?? familyResults[key].udp_outcome);
  return outcomes.every((value) => value === outcomes[0]) ? 'match' : 'mismatch';
}

function portStateIn(bucket, port) {
  if (bucket.open_ports?.includes(port)) return 'open';
  if (bucket.closed_ports?.includes(port)) return 'closed';
  if (bucket.rejected_ports?.includes(port)) return 'rejected';
  if (bucket.filtered_ports?.includes(port)) return 'filtered';
  return null;
}

/** Port-scan parity compares only ports sampled on both families; an unsampled family is never a mismatch. */
export function portScanParity(families) {
  const sampled = Object.entries(families ?? {})
    .filter(([, bucket]) => bucket && Array.isArray(bucket.ports_sampled) && bucket.ports_sampled.length > 0);
  if (sampled.length < 2) {
    const reason = Object.keys(families ?? {}).length > 1 ? 'family_not_sampled' : null;
    return { parity: 'single_family', parity_ports: [], ...(reason ? { parity_reason: reason } : {}) };
  }
  const [[, first], ...rest] = sampled;
  const shared = first.ports_sampled.filter((port) => rest.every(([, bucket]) => bucket.ports_sampled.includes(port)));
  if (!shared.length) return { parity: 'single_family', parity_ports: [], parity_reason: 'no_shared_ports_sampled' };
  const mismatched = shared.filter((port) => {
    const states = sampled.map(([, bucket]) => portStateIn(bucket, port));
    return states.some((state) => state !== states[0]);
  });
  return { parity: mismatched.length ? 'mismatch' : 'match', parity_ports: shared, ...(mismatched.length ? { parity_mismatch_ports: mismatched } : {}) };
}

export function sampleAgreement(samples) {
  if (!Array.isArray(samples) || samples.length <= 1) return 'single';
  const key = (row) => row.tcp_outcome ?? row.udp_outcome ?? row.outcome;
  return samples.every((row) => key(row) === key(samples[0])) ? 'agree' : 'disagree';
}

export function peerIsCdn(address) {
  if (typeof address !== 'string' || net.isIP(address) === 0) return null;
  try {
    const hits = classifyEdgeByAddress(address);
    return hits.some((hit) => (
      (hit.family === 'cdn' && !hits.some((other) => other.family === 'cloud' && other.provider === hit.provider))
      || hit.family === 'waf'
    ));
  } catch {
    return null;
  }
}

export function stampSourcePerspective(metadata, deps = {}) {
  if (metadata?.source_perspective && typeof metadata.source_perspective === 'object'
    && metadata.source_perspective.id) {
    return metadata;
  }
  const perspective = deps.sourcePerspective ?? sourcePerspectiveFromEnv(deps.env);
  return { ...metadata, source_perspective: perspective };
}

export function addressFamilyNumber(address) {
  const version = net.isIP(address);
  return version === 4 || version === 6 ? version : null;
}

export function sleepMs(ms, signal) {
  const delay = Math.max(0, Number(ms) || 0);
  if (delay === 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(Object.assign(new Error('probe canceled'), { code: 'ETIMEOUT' }));
      return;
    }
    let timer;
    const onAbort = () => {
      clearTimeout(timer);
      reject(Object.assign(new Error('probe canceled'), { code: 'ETIMEOUT' }));
    };
    timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, delay);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
