import { isIP } from 'node:net';
import { assertProbeDestinationAllowed } from './probeEndpoint.mjs';
import { effectiveTargetVerifications } from './effectiveTargetVerification.mjs';
import { ownershipProofFromStates } from './ownershipPolicy.mjs';

export const ORIGIN_LOCKDOWN_CHECK_ID = 'nfw.origin_lockdown.safe';
const PROTECTED_KINDS = new Set(['fqdn', 'hostname', 'domain']);
const VALID_RANK_STATES = Object.freeze(['dns_verified', 'provider_verified', 'user_confirmed']);

function unbracketHost(value) {
  return String(value ?? '').replace(/^\[|\]$/g, '').trim();
}

export function targetLiteralIpAddress(target) {
  const value = String(target?.value ?? '').trim();
  if (/^https?:\/\//i.test(value)) {
    try {
      const host = unbracketHost(new URL(value).hostname);
      return isIP(host) !== 0 ? host : null;
    } catch {
      return null;
    }
  }
  if (target?.kind !== 'ip') return null;
  const host = unbracketHost(value);
  return isIP(host) !== 0 ? host : null;
}

export function publicOriginAddress(value) {
  const address = typeof value === 'string' ? unbracketHost(value) : '';
  if (!address || isIP(address) === 0) return null;
  return assertProbeDestinationAllowed(address).ok ? address : null;
}

export function isOriginLockdownHostnameCheck(check, target) {
  return check?.check_id === ORIGIN_LOCKDOWN_CHECK_ID
    && check?.probe_profile?.kind === 'host_sni_bypass'
    && !targetLiteralIpAddress(target);
}

function isIpLiteral(host) {
  const value = String(host ?? '').replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255 && String(Number(part)) === String(Number(part)));
  }
  return value.includes(':') && /^[0-9a-f:]+$/i.test(value);
}

function declarationOf(target) {
  const raw = target?.declaration_json ?? target?.declaration ?? {};
  return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
}

function hostnameOf(target) {
  if (target?.kind === 'url') {
    try {
      const url = new URL(target.value);
      return url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    } catch {
      return null;
    }
  }
  const host = String(target?.value ?? '').trim().replace(/\.$/, '').toLowerCase();
  return host || null;
}

function urlParts(target) {
  if (target?.kind !== 'url') return { port: null, path: null };
  try {
    const url = new URL(target.value);
    const port = url.port ? Number(url.port) : null;
    const path = url.pathname && url.pathname !== '/' ? url.pathname : null;
    return { port, path };
  } catch {
    return { port: null, path: null };
  }
}

function targetRole(target) {
  const host = hostnameOf(target);
  if (!host) return null;
  if (target?.kind === 'ip' || (target?.kind === 'url' && isIpLiteral(host))) return 'origin';
  if (PROTECTED_KINDS.has(target?.kind) || (target?.kind === 'url' && !isIpLiteral(host))) return 'protected';
  return null;
}

function oneOf(value) {
  if (Array.isArray(value)) return value.length === 1 ? value[0] : undefined;
  return value == null || value === '' ? undefined : value;
}

function scopeError(code, status, extra = {}) {
  return { error: code, status, ...extra };
}

export function deriveBindingScope(protectedTarget, requested = {}) {
  const host = hostnameOf(protectedTarget);
  if (!host || targetRole(protectedTarget) !== 'protected') return scopeError('protected_target_not_hostname', 400);
  const declaration = declarationOf(protectedTarget);
  const allowed = declaration.allowed_scope && typeof declaration.allowed_scope === 'object'
    ? declaration.allowed_scope
    : {};
  if (Array.isArray(allowed.hosts) && allowed.hosts.length && !allowed.hosts.map((item) => String(item).toLowerCase()).includes(host)) {
    return scopeError('declaration_scope_invalid', 400, { field: 'host' });
  }
  const declaredSni = oneOf(allowed.sni);
  const sni = declaredSni == null ? host : String(declaredSni).toLowerCase();
  if (sni !== host) return scopeError('declaration_scope_invalid', 400, { field: 'sni' });
  const url = urlParts(protectedTarget);
  const declaredPorts = Array.isArray(allowed.ports)
    ? allowed.ports.map(Number).filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535)
    : [];
  let port = url.port ?? (Number.isInteger(protectedTarget?.port) ? protectedTarget.port : null);
  if (port == null && declaredPorts.length === 1) port = declaredPorts[0];
  const declaredPaths = Array.isArray(allowed.paths)
    ? allowed.paths.filter((path) => typeof path === 'string' && path.startsWith('/') && path.length <= 200)
    : [];
  let path = url.path;
  if (path == null && declaredPaths.length === 1) path = declaredPaths[0];
  if (requested.host != null && String(requested.host).toLowerCase() !== host) return scopeError('scope_mismatch', 400, { field: 'host' });
  if (requested.sni != null && String(requested.sni).toLowerCase() !== sni) return scopeError('scope_mismatch', 400, { field: 'sni' });
  if (requested.port != null) {
    const requestedPort = Number(requested.port);
    if (!Number.isInteger(requestedPort) || (port != null && requestedPort !== port)) {
      return scopeError('scope_mismatch', 400, { field: 'port' });
    }
    if (port == null && !declaredPorts.includes(requestedPort)) return scopeError('scope_mismatch', 400, { field: 'port' });
    port = requestedPort;
  } else if (port == null && declaredPorts.length > 1) {
    return scopeError('port_unspecified', 400);
  }
  if (requested.path != null) {
    if ((path != null && requested.path !== path) || (path == null && !declaredPaths.includes(requested.path))) {
      return scopeError('scope_mismatch', 400, { field: 'path' });
    }
    path = requested.path;
  } else if (path == null && declaredPaths.length > 1) {
    return scopeError('path_unspecified', 400);
  }
  return { host, sni, port, path };
}

export function currentOriginProof(records, tenantId, targetId) {
  const rawVerifications = records?.targetVerifications ?? records?.verifications ?? [];
  const targetVerifications = rawVerifications.map((row) => (
    row && typeof row === 'object' && row.transitioned_at === undefined
      ? { ...row, transitioned_at: '1970-01-01T00:00:00.000Z' }
      : row
  ));
  const store = {
    targets: records?.targets ?? [],
    targetVerifications,
    wafConnectors: records?.wafConnectors ?? [],
    wafConnectorSnapshots: records?.wafConnectorSnapshots ?? [],
  };
  const verification = effectiveTargetVerifications(store, tenantId, [targetId]).get(targetId);
  return ownershipProofFromStates({ targetState: verification?.state ?? null });
}

function originLockdownRefusal(check, error, status, message, extra = {}) {
  return { error, status, check_id: check?.check_id ?? null, message, ...extra };
}

export function resolveOriginLockdownBinding({
  check, target, tenantId, bindings = [], records = {}, deriveBindingScope: customScope, currentOriginProof: customProof,
} = {}) {
  if (!isOriginLockdownHostnameCheck(check, target)) return null;
  const scopeFn = customScope ?? deriveBindingScope;
  const proofFn = customProof ?? currentOriginProof;
  if (typeof scopeFn !== 'function' || typeof proofFn !== 'function') {
    return originLockdownRefusal(check, 'origin_binding_unavailable', 503, 'Origin binding verification is unavailable.');
  }
  const tid = tenantId ?? target?.tenant_id ?? null;
  const active = (Array.isArray(bindings) ? bindings : []).filter((binding) => binding
    && binding.status === 'active'
    && (binding.tenant_id == null || tid == null || binding.tenant_id === tid)
    && (target?.id == null || binding.protected_target_id === target?.id));
  if (active.length === 0) {
    return originLockdownRefusal(check, 'missing_declared_origin_binding', 400,
      'Origin lockdown on a hostname target requires one active origin binding that protects this target.');
  }
  if (active.length > 1) {
    return originLockdownRefusal(check, 'origin_binding_ambiguous', 409,
      'More than one active origin binding protects this target; archive the extra bindings first.');
  }
  const binding = active[0];
  const originTarget = (records?.targets ?? []).find((row) => row && row.id === binding.origin_target_id && !row.deleted_at);
  const literal = originTarget ? targetLiteralIpAddress(originTarget) : null;
  if (!literal) {
    return originLockdownRefusal(check, 'origin_target_not_verified_address', 400,
      'The declared origin binding does not point at an IP-literal origin target.');
  }
  const address = publicOriginAddress(literal);
  if (!address) {
    return originLockdownRefusal(check, 'origin_destination_not_allowed', 400,
      'The declared origin IP is not a publicly routable probe destination.');
  }
  const protectedTarget = (records?.targets ?? []).find((row) => row && row.id === target?.id && !row.deleted_at) ?? target;
  const scope = scopeFn(protectedTarget, { port: binding.port ?? undefined, path: binding.path ?? undefined });
  if (scope.error || scope.host !== binding.host || scope.sni !== binding.sni
    || (scope.port ?? null) !== (binding.port ?? null) || (scope.path ?? null) !== (binding.path ?? null)) {
    return originLockdownRefusal(check, 'scope_mismatch', 409,
      'The origin binding scope no longer matches the protected target declaration.');
  }
  const proof = proofFn(records, tid, originTarget.id);
  if (!proof.verified) {
    return originLockdownRefusal(check, 'ownership_not_verified', 409,
      'The declared origin target is not verified.', { ownership_state: proof.state ?? null, proof: 'origin' });
  }
  return {
    ok: true,
    binding_id: binding.id,
    address,
    host: scope.host,
    sni: scope.sni,
    port: scope.port ?? null,
    path: scope.path ?? null,
  };
}

export function isBindingActiveAndVerified(binding, target, records = null) {
  if (!binding || typeof binding !== 'object') return false;
  if (binding.status !== 'active') return false;
  if (target?.id && binding.protected_target_id && binding.origin_target_id) {
    if (binding.protected_target_id !== target.id && binding.origin_target_id !== target.id) return false;
  } else if (target?.id && binding.protected_target_id && binding.protected_target_id !== target.id) {
    return false;
  }
  if (binding.verified === false || binding.currently_authorized === false) return false;
  if (records && binding.origin_target_id) {
    const tenantId = target?.tenant_id ?? binding?.tenant_id ?? null;
    const proof = currentOriginProof(records, tenantId, binding.origin_target_id);
    return Boolean(proof.verified);
  }
  const acceptedStates = ['dns_verified', 'provider_verified', 'user_confirmed', 'verified'];
  if (binding.verification_state && !acceptedStates.includes(binding.verification_state)) {
    return false;
  }
  if (binding.state && !acceptedStates.includes(binding.state)) {
    return false;
  }
  const bindingVerified = binding.verified === true
    || binding.currently_authorized === true
    || acceptedStates.includes(binding.verification_state)
    || acceptedStates.includes(binding.state);
  return Boolean(bindingVerified);
}

export function hasActiveVerifiedOriginBinding(target, declarations, originBindings = undefined, check = null) {
  const directList = originBindings
    ?? target?.origin_bindings ?? target?.bindings
    ?? (target?.origin_binding ? [target.origin_binding] : null)
    ?? declarations?.origin_bindings ?? declarations?.bindings
    ?? (declarations?.origin_binding ? [declarations.origin_binding] : null);

  const list = Array.isArray(directList)
    ? directList
    : (Array.isArray(directList?.bindings)
      ? directList.bindings
      : (Array.isArray(directList?.items)
        ? directList.items
        : null));

  if (!Array.isArray(list) || list.length === 0) return false;

  const records = directList?.records ?? null;
  const tenantId = target?.tenant_id ?? null;

  const active = list.filter((b) => b
    && typeof b === 'object'
    && b.status === 'active'
    && (b.tenant_id == null || tenantId == null || b.tenant_id === tenantId)
    && (target?.id == null || b.protected_target_id === target.id || b.origin_target_id === target.id));

  if (active.length !== 1) return false;

  const binding = active[0];

  if (records && Array.isArray(records.targets) && records.targets.length > 0) {
    const originCheck = check ?? { check_id: ORIGIN_LOCKDOWN_CHECK_ID, probe_profile: { kind: 'host_sni_bypass' } };
    const res = resolveOriginLockdownBinding({
      check: originCheck,
      target,
      tenantId,
      bindings: list,
      records,
    });
    return Boolean(res?.ok);
  }

  if (records && binding.origin_target_id) {
    const proof = currentOriginProof(records, tenantId ?? binding.tenant_id, binding.origin_target_id);
    return Boolean(proof?.verified);
  }

  if (target?.value) {
    const scope = deriveBindingScope(target, { port: binding.port ?? undefined, path: binding.path ?? undefined });
    if (scope && !scope.error) {
      if (binding.host && scope.host !== binding.host) return false;
      if (binding.sni && scope.sni !== binding.sni) return false;
      if (binding.port != null && scope.port != null && binding.port !== scope.port) return false;
      if (binding.path != null && scope.path != null && binding.path !== scope.path) return false;
    }
  }

  if (binding.verified === false || binding.currently_authorized === false) return false;
  const acceptedStates = ['dns_verified', 'provider_verified', 'user_confirmed', 'verified'];
  if (binding.verification_state && !acceptedStates.includes(binding.verification_state)) return false;
  if (binding.state && !acceptedStates.includes(binding.state)) return false;

  const bindingVerified = binding.verified === true
    || binding.currently_authorized === true
    || acceptedStates.includes(binding.verification_state)
    || acceptedStates.includes(binding.state);

  return Boolean(bindingVerified);
}
