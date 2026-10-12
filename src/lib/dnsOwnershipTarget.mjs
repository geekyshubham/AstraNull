import { isIP } from 'node:net';
import { deriveAssuranceScope } from './assuranceScope.mjs';
const BINDING_KEYS = ['version', 'tenant_id', 'target_group_id', 'target_id', 'definition_digest'];
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
function dataProperty(object, key) {
  if (!object || typeof object !== 'object') return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

export const DNS_TARGET_BINDING_VERSION = 'dns-ownership-target.v2';

function hostname(value) {
  if (typeof value !== 'string') return null;
  const host = value.toLowerCase().replace(/\.$/, '');
  if (isIP(host) || host.length > 232 || !host.includes('.')
    || /(?:^|\.)(?:localhost|local|internal)$/.test(host)
    || !host.split('.').every((label) => label.length > 0 && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null;
  return host;
}

/** Only derive a TXT name. Never resolve URL addresses or send endpoint requests. */
export function dnsOwnershipDomain(target) {
  if (target?.kind === 'fqdn') return hostname(typeof target.value === 'string' ? target.value.trim() : null);
  if (target?.kind !== 'url' || typeof target.value !== 'string'
    || !/^https?:\/\//i.test(target.value) || /[\s\\?#]/.test(target.value)) return null;
  let endpoint;
  try { endpoint = new URL(target.value); } catch { return null; }
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password
    || endpoint.search || endpoint.hash || target.value.split('/')[2]?.includes('@')) return null;
  const port = Number(endpoint.port || (endpoint.protocol === 'https:' ? 443 : 80));
  if (target.port != null && target.port !== port) return null;
  if (target.protocol != null && target.protocol !== endpoint.protocol.slice(0, -1)) return null;
  return hostname(endpoint.hostname);
}

/** Match the exact declared URL, not just its DNS host. Presentation metadata is excluded. */
export function dnsOwnershipTargetBinding(target) {
  return {
    version: DNS_TARGET_BINDING_VERSION,
    tenant_id: target?.tenant_id ?? null,
    target_group_id: target?.target_group_id ?? null,
    target_id: target?.id ?? null,
    definition_digest: deriveAssuranceScope({ target }).target.definition_digest,
  };
}

function bindingMatches(binding, target) {
  try {
    if (!binding || typeof binding !== 'object' || Object.getPrototypeOf(binding) !== Object.prototype
      || Reflect.ownKeys(binding).length !== BINDING_KEYS.length) return false;
    const expected = dnsOwnershipTargetBinding(target);
    for (const key of BINDING_KEYS) {
      const descriptor = Object.getOwnPropertyDescriptor(binding, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string'
        || descriptor.value !== expected[key]) return false;
    }
    return binding.version === DNS_TARGET_BINDING_VERSION
      && [binding.tenant_id, binding.target_group_id, binding.target_id].every((id) => ID.test(id))
      && /^[a-f0-9]{64}$/.test(binding.definition_digest);
  } catch { return false; }
}

export function dnsOwnershipChallengeMatchesTarget(challenge, target) {
  const domain = dnsOwnershipDomain(target);
  if (!domain || challenge?.tenant_id !== target.tenant_id || challenge?.target_id !== target.id
    || challenge?.target_group_id !== target.target_group_id
    || challenge.record_name !== `_astranull-challenge.${domain}`) return false;
  // Retained FQDN challenges predate this URL prerequisite; never retie an unbound URL.
  return target.kind !== 'url' || bindingMatches(dataProperty(challenge.last_check_result, 'dns_target_binding'), target);
}

/** Review consumers must not promote a retained DNS row to a changed URL declaration. */
export function dnsOwnershipProofMatchesTarget(target, verification) {
  try {
    if (!target || typeof target !== 'object' || typeof target.kind !== 'string') return false;
    if (target.kind !== 'url') return true;
    return Boolean(dnsOwnershipDomain(target) && verification?.tenant_id === target.tenant_id
      && verification?.target_id === target.id
      && bindingMatches(dataProperty(dataProperty(verification, 'source_ref'), 'dns_target_binding'), target));
  } catch { return false; }
}

export function dnsOwnershipLookupTarget(target) {
  return target?.kind === 'url' ? dnsOwnershipTargetBinding(target)
    : [target?.tenant_id, target?.id, target?.target_group_id, target?.kind, target?.value];
}
