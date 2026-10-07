/**
 * Declared protected-host to verified-origin bindings.
 *
 * A binding joins two targets that already exist in the same tenant. It does not
 * discover an endpoint, read metadata.direct_ip, or start a probe. Host, SNI, port,
 * and path come from the protected target and its allowed declaration scope.
 * The relation is not an origin lockdown and it is not a capacity assurance.
 */
import { randomBytes } from 'node:crypto';
import { effectiveTargetVerifications } from '../lib/effectiveTargetVerification.mjs';
import { ownershipProofFromStates } from '../lib/ownershipPolicy.mjs';
import { getCheckById } from '../contracts/checks.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { requirePermission } from '../rbac.mjs';
import { audit } from '../audit.mjs';
import { normalizeObservationTimestamp, compareObservationOrder, projectObservation } from './targetHistory.mjs';
import { getStore, persistStore } from '../store.mjs';

const BANNED_KEYS = new Set(['direct_ip', 'discovered_endpoint', 'discovered_endpoints', 'endpoint', 'destination']);
const PROTECTED_KINDS = new Set(['fqdn', 'hostname', 'domain']);
const REACHABLE_OUTCOMES = new Set(['reachable', 'unreachable', 'denied', 'pass', 'fail']);

/** Only a catalog check whose probe profile is host_sni_bypass may prove a bound origin. */
function isApprovedHostSniCheck(checkId) {
  return getCheckById(checkId)?.probe_profile?.kind === 'host_sni_bypass';
}

function error(code, status, extra = {}) {
  return { error: code, status, ...extra };
}

function hasPermission(ctx, permission) {
  if (!roleHasPermission(ctx?.role, permission)) return false;
  if (Array.isArray(ctx?.scopes)) return ctx.scopes.includes('*') || ctx.scopes.includes(permission);
  return true;
}

function gate(ctx, permission) {
  if (hasPermission(ctx, permission)) return { ok: true };
  return requirePermission(ctx, permission, { resource_type: 'origin_binding' });
}

function bindingsOf(store) {
  if (!Array.isArray(store.originBindings)) store.originBindings = [];
  return store.originBindings;
}

function bannedKey(value, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 4) return null;
  for (const key of Object.keys(value)) {
    if (BANNED_KEYS.has(key)) return key;
    const nested = bannedKey(value[key], depth + 1);
    if (nested) return nested;
  }
  return null;
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
  if (target.kind === 'url') {
    let url;
    try {
      url = new URL(target.value);
    } catch {
      return null;
    }
    return url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  }
  const host = String(target.value ?? '').trim().replace(/\.$/, '').toLowerCase();
  return host || null;
}

function urlParts(target) {
  if (target.kind !== 'url') return { port: null, path: null };
  try {
    const url = new URL(target.value);
    const port = url.port ? Number(url.port) : null;
    const path = url.pathname && url.pathname !== '/' ? url.pathname : null;
    return { port, path };
  } catch {
    return { port: null, path: null };
  }
}

export function currentOriginProof(records, tenantId, targetId) {
  const store = {
    targets: records?.targets ?? [],
    targetVerifications: records?.targetVerifications ?? [],
    wafConnectors: records?.wafConnectors ?? [],
    wafConnectorSnapshots: records?.wafConnectorSnapshots ?? [],
  };
  const verification = effectiveTargetVerifications(store, tenantId, [targetId]).get(targetId);
  return ownershipProofFromStates({ targetState: verification?.state ?? null });
}

export function bindingRecordsFromStore(store, tenantId) {
  return {
    targets: (store.targets ?? []).filter((target) => target.tenant_id === tenantId && !target.deleted_at),
    targetVerifications: store.targetVerifications ?? [],
    wafConnectors: store.wafConnectors ?? [],
    wafConnectorSnapshots: store.wafConnectorSnapshots ?? [],
  };
}

function targetRole(target) {
  const host = hostnameOf(target);
  if (!host) return null;
  if (target.kind === 'ip' || (target.kind === 'url' && isIpLiteral(host))) return 'origin';
  if (PROTECTED_KINDS.has(target.kind) || (target.kind === 'url' && !isIpLiteral(host))) return 'protected';
  return null;
}

function oneOf(value) {
  if (Array.isArray(value)) return value.length === 1 ? value[0] : undefined;
  return value == null || value === '' ? undefined : value;
}

export function deriveBindingScope(protectedTarget, requested = {}) {
  const host = hostnameOf(protectedTarget);
  if (!host || targetRole(protectedTarget) !== 'protected') return error('protected_target_not_hostname', 400);
  const declaration = declarationOf(protectedTarget);
  const allowed = declaration.allowed_scope && typeof declaration.allowed_scope === 'object'
    ? declaration.allowed_scope
    : {};
  if (Array.isArray(allowed.hosts) && allowed.hosts.length && !allowed.hosts.map((item) => String(item).toLowerCase()).includes(host)) {
    return error('declaration_scope_invalid', 400, { field: 'host' });
  }
  const declaredSni = oneOf(allowed.sni);
  const sni = declaredSni == null ? host : String(declaredSni).toLowerCase();
  if (sni !== host) return error('declaration_scope_invalid', 400, { field: 'sni' });
  const url = urlParts(protectedTarget);
  const declaredPorts = Array.isArray(allowed.ports)
    ? allowed.ports.map(Number).filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535)
    : [];
  let port = url.port ?? (Number.isInteger(protectedTarget.port) ? protectedTarget.port : null);
  if (port == null && declaredPorts.length === 1) port = declaredPorts[0];
  const declaredPaths = Array.isArray(allowed.paths)
    ? allowed.paths.filter((path) => typeof path === 'string' && path.startsWith('/') && path.length <= 200)
    : [];
  let path = url.path;
  if (path == null && declaredPaths.length === 1) path = declaredPaths[0];
  if (requested.host != null && String(requested.host).toLowerCase() !== host) return error('scope_mismatch', 400, { field: 'host' });
  if (requested.sni != null && String(requested.sni).toLowerCase() !== sni) return error('scope_mismatch', 400, { field: 'sni' });
  if (requested.port != null) {
    const requestedPort = Number(requested.port);
    if (!Number.isInteger(requestedPort) || (port != null && requestedPort !== port)) {
      return error('scope_mismatch', 400, { field: 'port' });
    }
    if (port == null && !declaredPorts.includes(requestedPort)) return error('scope_mismatch', 400, { field: 'port' });
    port = requestedPort;
  } else if (port == null && declaredPorts.length > 1) {
    return error('port_unspecified', 400);
  }
  if (requested.path != null) {
    if ((path != null && requested.path !== path) || (path == null && !declaredPaths.includes(requested.path))) {
      return error('scope_mismatch', 400, { field: 'path' });
    }
    path = requested.path;
  } else if (path == null && declaredPaths.length > 1) {
    return error('path_unspecified', 400);
  }
  return { host, sni, port, path };
}

/**
 * Run start guard. The run target must be the bound origin IP, the check must be
 * an approved host/SNI origin check, and both proofs must be current. Scope is
 * re-derived from the protected declaration and compared to the stored binding.
 */
export function validateOriginBindingForRun({
  binding,
  runTarget,
  protectedTarget,
  check,
  originProof,
  protectedProof,
  body,
} = {}) {
  const banned = bannedKey(body);
  if (banned) return error('scope_not_declared', 400, { field: banned });
  if (!binding || binding.status !== 'active') return error('unknown_origin_binding', 404);
  if (!runTarget || runTarget.id !== binding.origin_target_id) return error('binding_target_mismatch', 409);
  if (targetRole(runTarget) !== 'origin') return error('origin_target_not_verified_address', 400);
  if (!protectedTarget || protectedTarget.id !== binding.protected_target_id) return error('unknown_target', 404);
  if (check?.probe_profile?.kind !== 'host_sni_bypass') return error('origin_check_not_approved', 400);
  // Re-derive with the stored choice so a binding created from a legitimate
  // in-scope choice still starts when the declaration allows several ports or
  // paths. A choice no longer inside the current declaration is scope_mismatch.
  const scope = deriveBindingScope(protectedTarget, {
    port: binding.port ?? undefined,
    path: binding.path ?? undefined,
  });
  if (scope.error) return scope;
  if (scope.host !== binding.host || scope.sni !== binding.sni
    || (scope.port ?? null) !== (binding.port ?? null)
    || (scope.path ?? null) !== (binding.path ?? null)) {
    return error('scope_mismatch', 409);
  }
  if (!originProof?.verified) {
    return error('ownership_not_verified', 409, { ownership_state: originProof?.state ?? null, proof: 'origin' });
  }
  if (!protectedProof?.verified) {
    return error('ownership_not_verified', 409, { ownership_state: protectedProof?.state ?? null, proof: 'protected' });
  }
  return { ok: true, scope };
}

export function planOriginBinding(ctx, body, records, options = {}) {
  const banned = bannedKey(body);
  if (banned) return error('scope_not_declared', 400, { field: banned });
  const targets = records?.targets ?? [];
  const protectedTarget = targets.find((target) => target.id === body?.protected_target_id) ?? null;
  const originTarget = targets.find((target) => target.id === body?.origin_target_id) ?? null;
  if (!protectedTarget) return error('unknown_target', 404, { field: 'protected_target_id' });
  if (!originTarget) return error('unknown_target', 404, { field: 'origin_target_id' });
  if (protectedTarget.id === originTarget.id) return error('binding_target_mismatch', 409);
  if (targetRole(originTarget) !== 'origin') return error('origin_target_not_verified_address', 400);
  const scope = deriveBindingScope(protectedTarget, body?.scope ?? {});
  if (scope.error) return scope;
  const proof = currentOriginProof(records, ctx.tenantId, originTarget.id);
  if (!proof.verified) return error('ownership_not_verified', 409, { ownership_state: proof.state });
  const now = normalizeObservationTimestamp(options.now ?? new Date());
  return {
    record: {
      tenant_id: ctx.tenantId,
      protected_target_id: protectedTarget.id,
      protected_target_group_id: protectedTarget.target_group_id,
      origin_target_id: originTarget.id,
      origin_target_group_id: originTarget.target_group_id,
      host: scope.host,
      sni: scope.sni,
      port: scope.port,
      path: scope.path,
      status: 'active',
      assurance: 'none',
      lockdown: 'not_tested',
      relation: 'declared_binding',
      created_by: ctx.userId ?? null,
      created_at: now,
      archived_at: null,
      archived_by: null,
    },
    proof,
    protected_target: { id: protectedTarget.id, kind: protectedTarget.kind, value: protectedTarget.value },
    origin_target: { id: originTarget.id, kind: originTarget.kind, value: originTarget.value },
  };
}

export function presentOriginBinding(row, proof = null) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    protected_target_id: row.protected_target_id,
    protected_target_group_id: row.protected_target_group_id,
    origin_target_id: row.origin_target_id,
    origin_target_group_id: row.origin_target_group_id,
    host: row.host,
    sni: row.sni,
    port: row.port ?? null,
    path: row.path ?? null,
    status: row.status,
    assurance: 'none',
    lockdown: 'not_tested',
    relation: 'declared_binding',
    capacity_assurance: false,
    currently_authorized: Boolean(proof?.verified) && row.status === 'active',
    authorization_state: proof?.state ?? null,
    created_at: row.created_at,
    archived_at: row.archived_at ?? null,
  };
}

function auditBinding(ctx, action, binding) {
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? null,
    action,
    resource_type: 'origin_binding',
    resource_id: binding.id,
    metadata: {
      protected_target_id: binding.protected_target_id,
      origin_target_id: binding.origin_target_id,
      host: binding.host,
      sni: binding.sni,
      port: binding.port ?? null,
      path: binding.path ?? null,
      status: binding.status,
    },
  });
}

export function createOriginBinding(ctx, body = {}, options = {}) {
  const allowed = gate(ctx, 'target_group:write');
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403 };
  const store = getStore();
  const records = bindingRecordsFromStore(store, ctx.tenantId);
  const planned = planOriginBinding(ctx, body, records, options);
  if (planned.error) return planned;
  const rows = bindingsOf(store);
  const existing = rows.find((row) => row.tenant_id === ctx.tenantId
    && row.status === 'active'
    && row.protected_target_id === planned.record.protected_target_id
    && row.origin_target_id === planned.record.origin_target_id);
  if (existing) {
    // A replay is the exact same stored scope. A different requested scope for the
    // same active pair would silently retarget the run used for reachability, so
    // it is a conflict rather than a replay.
    if (existing.host !== planned.record.host || existing.sni !== planned.record.sni
      || (existing.port ?? null) !== (planned.record.port ?? null)
      || (existing.path ?? null) !== (planned.record.path ?? null)) {
      return error('scope_conflict', 409, { existing_id: existing.id });
    }
    return { ...presentOriginBinding(existing, planned.proof), replayed: true };
  }
  const record = { ...planned.record, id: `obind_${randomBytes(8).toString('hex')}` };
  rows.push(record);
  auditBinding(ctx, 'origin_binding.created', record);
  persistStore();
  return { ...presentOriginBinding(record, planned.proof), replayed: false };
}

export function archiveOriginBinding(ctx, id, options = {}) {
  const allowed = gate(ctx, 'target_group:write');
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403 };
  const row = bindingsOf(getStore()).find((binding) => binding.tenant_id === ctx.tenantId && binding.id === id);
  if (!row) return error('unknown_origin_binding', 404);
  if (row.status !== 'active') return error('already_archived', 409);
  row.status = 'archived';
  row.archived_at = normalizeObservationTimestamp(options.now ?? new Date());
  row.archived_by = ctx.userId ?? null;
  auditBinding(ctx, 'origin_binding.archived', row);
  persistStore();
  const proof = currentOriginProof(bindingRecordsFromStore(getStore(), ctx.tenantId), ctx.tenantId, row.origin_target_id);
  return presentOriginBinding(row, proof);
}

export function getOriginBinding(ctx, id) {
  const allowed = gate(ctx, 'target_group:read');
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403 };
  const store = getStore();
  const row = bindingsOf(store).find((binding) => binding.tenant_id === ctx.tenantId && binding.id === id);
  if (!row) return null;
  const proof = currentOriginProof(bindingRecordsFromStore(store, ctx.tenantId), ctx.tenantId, row.origin_target_id);
  return presentOriginBinding(row, proof);
}

export function listOriginBindings(ctx, query = {}) {
  const allowed = gate(ctx, 'target_group:read');
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403 };
  const store = getStore();
  const records = bindingRecordsFromStore(store, ctx.tenantId);
  const items = bindingsOf(store)
    .filter((row) => row.tenant_id === ctx.tenantId)
    .filter((row) => !query.protected_target_id || row.protected_target_id === query.protected_target_id)
    .filter((row) => !query.status || row.status === query.status)
    .map((row) => presentOriginBinding(row, currentOriginProof(records, ctx.tenantId, row.origin_target_id)));
  return { items, count: items.length };
}

export function assessOriginReachability(binding, observations = [], proof = null) {
  if (!binding || binding.status !== 'active') {
    return {
      status: 'not_tested',
      lockdown: 'not_tested',
      assurance: 'none',
      capacity_assurance: false,
      reason: 'no_active_binding',
      observation_id: null,
    };
  }
  if (!proof?.verified) {
    return {
      status: 'unknown',
      lockdown: 'not_tested',
      assurance: 'none',
      capacity_assurance: false,
      reason: 'authorization_lapsed',
      observation_id: null,
      scope: { host: binding.host, sni: binding.sni, port: binding.port ?? null, path: binding.path ?? null },
    };
  }
  // Live proof only: the row must name this binding from the same tenant, target
  // the bound origin, be an approved host/SNI origin check in the origin_hosting
  // family, come from a signed live producer, and have a finalized source
  // completion at or after the binding was created. A simulation, manual entry,
  // customer declaration, null producer, other family, other check, or other
  // target can never upgrade the profile. Retained wrong rows stay not_tested.
  const bindingCreated = normalizeObservationTimestamp(binding.created_at);
  const atOrAfterBinding = (value) => {
    const timestamp = normalizeObservationTimestamp(value);
    return Boolean(timestamp && bindingCreated && timestamp >= bindingCreated);
  };
  const bound = observations
    .map((row) => projectObservation(row))
    .filter((row) => row
      && row.tenant_id === binding.tenant_id
      && row.target_id === binding.origin_target_id
      && row.origin_binding_id === binding.id
      && row.attempt_class === 'successful'
      && row.family === 'origin_hosting'
      && row.producer_kind === 'signed_probe'
      && isApprovedHostSniCheck(row.check_id)
      && row.source_completed_at
      && atOrAfterBinding(row.source_completed_at)
      && REACHABLE_OUTCOMES.has(row.outcome)
      && atOrAfterBinding(row.observed_at));
  bound.sort((left, right) => compareObservationOrder(right, left));
  const latest = bound[0] ?? null;
  if (!latest) {
    return {
      status: 'not_tested',
      lockdown: 'not_tested',
      assurance: 'none',
      capacity_assurance: false,
      reason: 'no_bound_finalized_evidence',
      observation_id: null,
      scope: { host: binding.host, sni: binding.sni, port: binding.port ?? null, path: binding.path ?? null },
    };
  }
  return {
    status: latest.outcome,
    lockdown: 'not_established',
    assurance: 'none',
    capacity_assurance: false,
    reason: null,
    observation_id: latest.id,
    scope: { host: binding.host, sni: binding.sni, port: binding.port ?? null, path: binding.path ?? null },
    limitations: [
      'scoped_to_bound_host_sni_port_path',
      'not_capacity_assurance',
      'not_origin_lockdown',
      ...(latest.outcome === 'denied' ? ['responsible_control_not_identified'] : []),
      ...(latest.outcome === 'unreachable' ? ['legacy_result_enforcement_unverified'] : []),
    ],
  };
}
