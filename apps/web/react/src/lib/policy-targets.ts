import type { DataItem } from './types';

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

const POLICY_TARGET_KIND_ALIASES: Readonly<Record<string, string>> = {
  domain: 'fqdn',
  hostname: 'fqdn',
};

/** Mirror the policy API: persisted aliases are canonical FQDNs and HTTP(S) values are URLs. */
export function effectivePolicyTargetKind(target: DataItem) {
  const value = getString(target, ['value'], '');
  if (/^https?:\/\//i.test(value)) return 'url';
  const kind = getString(target, ['kind'], '').trim().toLowerCase();
  return POLICY_TARGET_KIND_ALIASES[kind] ?? kind;
}

export function policySupportedTargetKinds(check: DataItem | null | undefined) {
  return Array.isArray(check?.supported_targets)
    ? check.supported_targets.map((value) => String(value).trim()).filter(Boolean)
    : [];
}

export function isPolicyTargetCompatible(check: DataItem | null | undefined, target: DataItem) {
  const supportedTargets = policySupportedTargetKinds(check);
  return supportedTargets.length === 0 || supportedTargets.includes(effectivePolicyTargetKind(target));
}
