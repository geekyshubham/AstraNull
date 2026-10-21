/**
 * Declared protected-host to verified-origin bindings.
 *
 * A binding joins two targets that already exist in the same tenant. It does not
 * discover an endpoint, read metadata.direct_ip, or start a probe. Host, SNI, port,
 * and path come from the protected target and its allowed declaration scope.
 * The relation is not an origin lockdown and it is not a capacity assurance.
 */
import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { originBindingAuthority, originTargetDescriptor, exactOriginScope, targetLiteralIpAddress, publicOriginAddress } from '../lib/originLockdownResolution.mjs';
import { signedOriginIdentityPair, originIdentityProofBinding } from '../lib/originIdentityPair.mjs';
import { effectiveTargetVerifications } from '../lib/effectiveTargetVerification.mjs';
import { ownershipProofFromStates } from '../lib/ownershipPolicy.mjs';
import { getCheckById } from '../contracts/checks.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { requirePermission } from '../rbac.mjs';
import { audit } from '../audit.mjs';
import { normalizeObservationTimestamp, compareObservationOrder, projectObservation } from './targetHistory.mjs';
import { getStore, persistStore } from '../store.mjs';
import { cancelTestRun } from './testRuns.mjs';

const BANNED_KEYS = new Set(['direct_ip', 'discovered_endpoint', 'discovered_endpoints', 'endpoint', 'destination']);
const PROTECTED_KINDS = new Set(['fqdn', 'hostname', 'domain']);
const REACHABLE_OUTCOMES = new Set(['reachable', 'unreachable', 'denied', 'pass', 'fail']);

/** Only a catalog check whose probe profile is host_sni_bypass may prove a bound origin. */
function isApprovedHostSniCheck(checkId) {
  return ['host_sni_bypass', 'origin_identity_pair'].includes(getCheckById(checkId)?.probe_profile?.kind);
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

export { currentOriginProof, deriveBindingScope } from '../lib/originLockdownResolution.mjs';
import { currentOriginProof, deriveBindingScope } from '../lib/originLockdownResolution.mjs';

export function bindingRecordsFromStore(store, tenantId) {
  const unavailableGroupIds = new Set();
  for (const group of store.targetGroups ?? []) {
    if (group.tenant_id !== tenantId || (!group.deleted_at && !group.archived_at)) continue;
    const id = group.id;
    // Preserve strict ID equality: unlike Set membership, NaN never matched itself.
    if (!Number.isNaN(id)) unavailableGroupIds.add(id);
  }
  return {
    targets: (store.targets ?? []).filter((target) => target.tenant_id === tenantId && !target.deleted_at && !target.archived_at
      && !unavailableGroupIds.has(target.target_group_id)),
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
  if (runTarget.deleted_at || runTarget.archived_at || runTarget.tenant_id !== binding.tenant_id) return error('unknown_target', 404);
  if (targetRole(runTarget) !== 'origin') return error('origin_target_not_verified_address', 400);
  if (!protectedTarget || protectedTarget.id !== binding.protected_target_id
    || protectedTarget.deleted_at || protectedTarget.archived_at || protectedTarget.tenant_id !== binding.tenant_id) return error('unknown_target', 404);
  if (!['host_sni_bypass', 'origin_identity_pair'].includes(check?.probe_profile?.kind)) return error('origin_check_not_approved', 400);
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
  return { ok: true, scope, authority: originBindingAuthority(binding, runTarget, protectedTarget) };
}

/** Immutable run association, never a claim that the binding remains authorized now. */
export function historicalOriginBindingForRun(run) {
  const id = run?.origin_binding_id ?? run?.provenance_json?.origin_lockdown?.binding_id;
  return typeof id === 'string' && id ? { id, status: 'historical', historical_binding_reference: true } : null;
}

/** Shared memory/PostgreSQL eligibility contract at the durable execution grant. */
export function validateOriginBindingForExecution({ job, run, binding, records = {} } = {}) {
  const reference = historicalOriginBindingForRun(run);
  const signedScope = job?.constraints?.origin_scope;
  const signedLockdown = job?.constraints?.origin_lockdown;
  const lockdown = run?.provenance_json?.origin_lockdown;
  // An ordinary unbound probe stays ordinary. A scope carrier without its run binding is not authority.
  if (!reference) return signedScope || signedLockdown || job?.constraints?.origin_authority
    || job?.constraints?.origin_identity_pair ? error('origin_binding_missing', 409) : { ok: true };
  if (!binding || binding.id !== reference.id || binding.tenant_id !== job?.tenant_id
    || run?.tenant_id !== job?.tenant_id || binding.status !== 'active') return error('unknown_origin_binding', 409);
  const originTarget = (records.targets ?? []).find((row) => row.id === binding.origin_target_id && row.tenant_id === job.tenant_id);
  const protectedTarget = (records.targets ?? []).find((row) => row.id === binding.protected_target_id && row.tenant_id === job.tenant_id);
  const check = { probe_profile: job.probe_profile };
  const decision = validateOriginBindingForRun({ binding, runTarget: originTarget, protectedTarget, check,
    originProof: currentOriginProof(records, job.tenant_id, binding.origin_target_id),
    protectedProof: currentOriginProof(records, job.tenant_id, binding.protected_target_id) });
  if (decision.error) return decision;
  const storedScope = run.origin_binding_id ? run.provenance_json?.origin_scope : lockdown;
  if (!exactOriginScope(storedScope, decision.scope) || !exactOriginScope(signedScope, storedScope)) return error('scope_mismatch', 409);
  const storedAuthority = run.provenance_json?.origin_authority ?? lockdown?.authority;
  if (!isDeepStrictEqual(storedAuthority, decision.authority)
    || !isDeepStrictEqual(job.constraints?.origin_authority, storedAuthority)) return error('target_binding_changed', 409);
  const runTarget = run.origin_binding_id ? originTarget : protectedTarget;
  if (run.target_id !== runTarget?.id || job.target_id !== run.target_id
    || job.check_id !== run.check_id || !isDeepStrictEqual(originTargetDescriptor(job.target), originTargetDescriptor(runTarget))) {
    return error('binding_target_mismatch', 409);
  }
  if (!run.origin_binding_id) {
    const address = publicOriginAddress(targetLiteralIpAddress(originTarget));
    if (run.check_id !== 'nfw.origin_lockdown.safe' || !address || lockdown?.address !== address
      || job.probe_profile?.direct_ip !== address) return error('scope_mismatch', 409);
  }
  if (job.probe_profile?.kind === 'origin_identity_pair') {
    const pair = signedOriginIdentityPair(job);
    if (!pair || pair.binding_id !== binding.id || !isDeepStrictEqual(pair, run.provenance_json?.origin_identity_pair)
      || !isDeepStrictEqual(pair.origin_target, originTargetDescriptor(originTarget))
      || !isDeepStrictEqual(pair.protected_target, originTargetDescriptor(protectedTarget))
      || !isDeepStrictEqual(pair.origin_ownership_binding, originIdentityProofBinding(records, job.tenant_id, originTarget.id))
      || !isDeepStrictEqual(pair.protected_ownership_binding, originIdentityProofBinding(records, job.tenant_id, protectedTarget.id))) {
      return error('origin_identity_authority_changed', 409);
    }
  }
  return { ok: true, scope: decision.scope, authority: decision.authority };
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

export function currentOriginBindingAuthorization(binding, records = {}) {
  if (!binding) return { verified: false, state: null, reason: 'unknown_origin_binding' };
  const originTarget = (records.targets ?? []).find((row) => row.id === binding.origin_target_id && row.tenant_id === binding.tenant_id);
  const protectedTarget = (records.targets ?? []).find((row) => row.id === binding.protected_target_id && row.tenant_id === binding.tenant_id);
  const originProof = currentOriginProof(records, binding.tenant_id, binding.origin_target_id);
  const protectedProof = currentOriginProof(records, binding.tenant_id, binding.protected_target_id);
  const decision = validateOriginBindingForRun({ binding, runTarget: originTarget, protectedTarget,
    check: { probe_profile: { kind: 'host_sni_bypass' } }, originProof, protectedProof });
  return { verified: decision.ok === true, state: originProof.state, protected_state: protectedProof.state,
    reason: decision.error ?? null };
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
    authorization_reason: proof?.reason ?? null,
    protected_authorization_state: proof?.protected_state ?? null,
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
    return { ...presentOriginBinding(existing, currentOriginBindingAuthorization(existing, records)), replayed: true };
  }
  const record = { ...planned.record, id: `obind_${randomBytes(8).toString('hex')}` };
  rows.push(record);
  auditBinding(ctx, 'origin_binding.created', record);
  persistStore();
  return { ...presentOriginBinding(record, currentOriginBindingAuthorization(record, records)), replayed: false };
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
  for (const run of getStore().testRuns ?? []) {
    if (run.tenant_id === ctx.tenantId && ['planned', 'running', 'collecting'].includes(run.status)
      && historicalOriginBindingForRun(run)?.id === row.id) {
      cancelTestRun(ctx, run.id, { reason: 'Origin binding archived', source: 'origin_binding' });
    }
  }
  persistStore();
  const proof = currentOriginBindingAuthorization(row, bindingRecordsFromStore(getStore(), ctx.tenantId));
  return presentOriginBinding(row, proof);
}

export function getOriginBinding(ctx, id) {
  const allowed = gate(ctx, 'target_group:read');
  if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403 };
  const store = getStore();
  const row = bindingsOf(store).find((binding) => binding.tenant_id === ctx.tenantId && binding.id === id);
  if (!row) return null;
  const proof = currentOriginBindingAuthorization(row, bindingRecordsFromStore(store, ctx.tenantId));
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
    .map((row) => presentOriginBinding(row, currentOriginBindingAuthorization(row, records)));
  return { items, count: items.length };
}

export function assessOriginReachability(binding, observations = [], proof = null, { runs = [] } = {}) {
  if (!binding) {
    return {
      status: 'not_tested',
      lockdown: 'not_tested',
      assurance: 'none',
      capacity_assurance: false,
      reason: 'no_active_binding',
      observation_id: null,
    };
  }
  const currentlyAuthorized = Boolean(proof?.verified) && binding.status === 'active';
  const authorization = { currently_authorized: currentlyAuthorized,
    authorization_reason: currentlyAuthorized ? null : (proof?.reason ?? (binding.status === 'active' ? 'authorization_lapsed' : 'binding_archived')) };
  const runById = new Map(runs.filter((run) => run?.tenant_id === binding.tenant_id).map((run) => [run.id, run]));
  const exactRun = (row) => {
    const run = runById.get(row.test_run_id);
    if (!run || run.target_id !== row.target_id || run.check_id !== row.check_id
      || historicalOriginBindingForRun(run)?.id !== binding.id) return false;
    const lockdown = run.provenance_json?.origin_lockdown;
    const scope = run.origin_binding_id ? run.provenance_json?.origin_scope : lockdown;
    return exactOriginScope(scope, binding) && (row.target_id === binding.origin_target_id
      || (row.target_id === binding.protected_target_id && row.check_id === 'nfw.origin_lockdown.safe'
        && Boolean(publicOriginAddress(lockdown?.address))));
  };
  // Historical proof only: the row must name this binding from the same tenant, target
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
      && (row.target_id === binding.origin_target_id || row.target_id === binding.protected_target_id)
      && row.origin_binding_id === binding.id
      && exactRun(row)
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
      reason: currentlyAuthorized ? 'no_bound_finalized_evidence' : authorization.authorization_reason,
      ...authorization,
      historical_evidence_valid: false,
      observation_id: null,
      scope: { host: binding.host, sni: binding.sni, port: binding.port ?? null, path: binding.path ?? null },
    };
  }
  const run = runById.get(latest.test_run_id);
  const authority = run.provenance_json?.origin_authority ?? run.provenance_json?.origin_lockdown?.authority;
  return {
    ...authorization,
    historical_evidence_valid: true,
    status: latest.outcome,
    lockdown: 'not_established',
    assurance: 'none',
    capacity_assurance: false,
    reason: null,
    observation_id: latest.id,
    binding_id: binding.id,
    test_run_id: latest.test_run_id,
    check_id: latest.check_id,
    target_id: latest.target_id,
    declared_target: latest.target_id === binding.protected_target_id ? authority?.protected_target ?? null : authority?.origin_target ?? null,
    actual_destination: run.provenance_json?.origin_lockdown?.address ?? targetLiteralIpAddress(authority?.origin_target),
    producer_kind: latest.producer_kind,
    source_kind: latest.source_kind,
    observed_at: latest.observed_at,
    source_completed_at: latest.source_completed_at,
    scope: { host: binding.host, sni: binding.sni, port: binding.port ?? null, path: binding.path ?? null },
    evidence_scope: { host: binding.host, sni: binding.sni, port: binding.port ?? null, path: binding.path ?? null },
    limitations: [
      'scoped_to_bound_host_sni_port_path',
      'not_capacity_assurance',
      'not_origin_lockdown',
      ...(latest.outcome === 'denied' ? ['responsible_control_not_identified'] : []),
      ...(latest.outcome === 'unreachable' ? ['legacy_result_enforcement_unverified'] : []),
    ],
  };
}
