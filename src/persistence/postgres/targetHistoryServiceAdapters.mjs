/**
 * Postgres adapters over the same observation, binding, and lineage rules as the dev store.
 * Public HTTP calls list, get, create, and archive only. appendTargetObservation is not a route.
 * options.internal is server-only and must not be copied from a request body.
 */
import { randomBytes } from 'node:crypto';
import { roleHasPermission } from '../../contracts/roles.mjs';
import { requirePermission } from '../../rbac.mjs';
import { clampPageLimit } from '../../lib/cursorPagination.mjs';
import { isProtectionValidationFinding } from '../../lib/protectionValidationFindings.mjs';
import {
  assessComparability,
  decodeObservationCursor,
  encodeObservationCursor,
  getCurrentFamilyState as currentFromRows,
  normalizeObservationTimestamp,
  OBSERVATION_FAMILIES,
  prepareObservation,
  projectObservation,
} from '../../services/targetHistory.mjs';
import {
  assessOriginReachability,
  currentOriginProof,
  planOriginBinding,
  presentOriginBinding,
} from '../../services/originBindings.mjs';
import {
  planRetestRegistration,
  presentFindingLineage,
} from '../../services/retestLineage.mjs';

function error(code, status) {
  return { error: code, status };
}

function hasPermission(ctx, permission) {
  if (!roleHasPermission(ctx?.role, permission)) return false;
  if (Array.isArray(ctx?.scopes)) return ctx.scopes.includes('*') || ctx.scopes.includes(permission);
  return true;
}

function gate(ctx, permissions, resourceType) {
  if (permissions.some((permission) => hasPermission(ctx, permission))) return { ok: true };
  return requirePermission(ctx, permissions[0], { resource_type: resourceType });
}

function denied(result) {
  return { error: 'forbidden', status: result.status ?? 403, permission: result.body?.permission };
}

function bindingAudit(ctx, action, row) {
  return {
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? null,
    action,
    resource_type: 'origin_binding',
    resource_id: row.id,
    metadata: {
      protected_target_id: row.protected_target_id,
      origin_target_id: row.origin_target_id,
      host: row.host,
      sni: row.sni,
      port: row.port ?? null,
      path: row.path ?? null,
      status: row.status ?? 'active',
    },
  };
}

export function createPostgresTargetHistoryServices({ repository, audit = null }) {
  return {
    assessComparability,

    async appendTargetObservation(ctx, input = {}, options = {}) {
      const allowed = gate(ctx, ['evidence:write', 'test_run:start'], 'target_observation');
      if (!allowed.ok) return denied(allowed);
      const records = input.origin_binding_id
        ? await repository.loadBindingContext(ctx, [input.target_id])
        : null;
      const target = records
        ? records.targets.find((row) => row.id === input.target_id) ?? null
        : (await repository.loadBindingContext(ctx, [input.target_id])).targets.find((row) => row.id === input.target_id) ?? null;
      const loaded = records ?? await repository.loadBindingContext(ctx, [input.target_id]);
      const binding = input.origin_binding_id
        ? await repository.getBinding(ctx, input.origin_binding_id)
        : null;
      const prepared = prepareObservation(input, {
        tenantId: ctx.tenantId,
        target: loaded.targets.find((row) => row.id === input.target_id) ?? target,
        binding,
        now: options.now,
        serverDerived: options.internal === true,
      });
      if (prepared.error) return prepared;
      const record = {
        ...prepared.record,
        id: `obs_${randomBytes(8).toString('hex')}`,
        created_at: normalizeObservationTimestamp(options.now ?? new Date()),
      };
      const stored = await repository.insertObservation(ctx, record);
      if (stored.error) return stored;
      return { ...projectObservation(stored), replayed: stored.replayed === true };
    },

    async listTargetObservations(ctx, query = {}) {
      const allowed = gate(ctx, ['evidence:read', 'target_group:read'], 'target_observation');
      if (!allowed.ok) return denied(allowed);
      const decoded = decodeObservationCursor(query.cursor);
      if (decoded.error) return decoded;
      if (query.family && !OBSERVATION_FAMILIES.includes(query.family)) return error('invalid_family', 400);
      const from = query.from ? normalizeObservationTimestamp(query.from) : null;
      const to = query.to ? normalizeObservationTimestamp(query.to) : null;
      if (query.from && !from) return error('invalid_timestamp', 400);
      if (query.to && !to) return error('invalid_timestamp', 400);
      const limit = clampPageLimit(query.limit, { max: 100, fallback: 50 });
      const rows = await repository.listObservations(ctx, {
        target_id: query.target_id ?? null,
        family: query.family ?? null,
        from,
        to,
        cursor: decoded.cursor,
        limit: limit + 1,
      });
      const page = rows.slice(0, limit);
      return {
        items: page.map(projectObservation),
        count: page.length,
        next_cursor: rows.length > limit ? encodeObservationCursor(page[page.length - 1]) : null,
        filters: { target_id: query.target_id ?? null, family: query.family ?? null, from, to },
      };
    },

    async getCurrentFamilyState(ctx, query = {}) {
      const allowed = gate(ctx, ['evidence:read', 'target_group:read'], 'target_observation');
      if (!allowed.ok) return denied(allowed);
      if (!query.target_id) return error('invalid_target', 400);
      const pointers = await repository.listCurrentPointers(ctx, query);
      const ids = pointers.flatMap((row) => [row.successful_observation_id, row.failed_attempt_observation_id]).filter(Boolean);
      const observations = await repository.observationsByIds(ctx, ids);
      const byId = new Map(observations.map((row) => [row.id, row]));
      return {
        target_id: query.target_id,
        items: pointers.map((pointer) => {
          const successful = byId.get(pointer.successful_observation_id) ?? null;
          const failed = byId.get(pointer.failed_attempt_observation_id) ?? null;
          return {
            family: pointer.family,
            last_successful: projectObservation(successful),
            latest_failed_attempt: projectObservation(failed),
            fresh_negative: successful?.outcome === 'not_detected',
            provider_loss: false,
          };
        }),
      };
    },

    async createOriginBinding(ctx, body = {}, options = {}) {
      const allowed = gate(ctx, ['target_group:write'], 'origin_binding');
      if (!allowed.ok) return denied(allowed);
      const ids = [body.protected_target_id, body.origin_target_id].filter(Boolean);
      const records = await repository.loadBindingContext(ctx, ids);
      const planned = planOriginBinding(ctx, body, records, options);
      if (planned.error) return planned;
      const record = { ...planned.record, id: `obind_${randomBytes(8).toString('hex')}` };
      const stored = await repository.insertBinding(ctx, record, bindingAudit(ctx, 'origin_binding.created', record), audit);
      if (stored.error) return stored;
      return { ...presentOriginBinding(stored, planned.proof), replayed: stored.replayed === true };
    },

    async archiveOriginBinding(ctx, id, options = {}) {
      const allowed = gate(ctx, ['target_group:write'], 'origin_binding');
      if (!allowed.ok) return denied(allowed);
      const existing = await repository.getBinding(ctx, id);
      if (!existing) return error('unknown_origin_binding', 404);
      if (existing.status !== 'active') return error('already_archived', 409);
      const archivedAt = normalizeObservationTimestamp(options.now ?? new Date());
      const stored = await repository.archiveBinding(ctx, id, {
        archived_at: archivedAt,
        archived_by: ctx.userId ?? null,
      }, bindingAudit(ctx, 'origin_binding.archived', { ...existing, status: 'archived' }), audit);
      if (!stored) return error('already_archived', 409);
      const records = await repository.loadBindingContext(ctx, [stored.origin_target_id]);
      return presentOriginBinding(stored, currentOriginProof(records, ctx.tenantId, stored.origin_target_id));
    },

    async getOriginBinding(ctx, id) {
      const allowed = gate(ctx, ['target_group:read'], 'origin_binding');
      if (!allowed.ok) return denied(allowed);
      const row = await repository.getBinding(ctx, id);
      if (!row) return null;
      const records = await repository.loadBindingContext(ctx, [row.origin_target_id]);
      return presentOriginBinding(row, currentOriginProof(records, ctx.tenantId, row.origin_target_id));
    },

    async listOriginBindings(ctx, query = {}) {
      const allowed = gate(ctx, ['target_group:read'], 'origin_binding');
      if (!allowed.ok) return denied(allowed);
      const rows = await repository.listBindings(ctx, query);
      const ids = [...new Set(rows.map((row) => row.origin_target_id))];
      const records = ids.length ? await repository.loadBindingContext(ctx, ids) : { targets: [], targetVerifications: [], wafConnectors: [], wafConnectorSnapshots: [] };
      const items = rows.map((row) => presentOriginBinding(row, currentOriginProof(records, ctx.tenantId, row.origin_target_id)));
      return { items, count: items.length };
    },

    async assessOriginReachability(ctx, bindingId) {
      const allowed = gate(ctx, ['target_group:read'], 'origin_binding');
      if (!allowed.ok) return denied(allowed);
      const binding = await repository.getBinding(ctx, bindingId);
      if (!binding) return error('unknown_origin_binding', 404);
      const records = await repository.loadBindingContext(ctx, [binding.origin_target_id]);
      const proof = currentOriginProof(records, ctx.tenantId, binding.origin_target_id);
      const observations = await repository.listObservations(ctx, {
        target_id: binding.origin_target_id,
        family: null,
        from: null,
        to: null,
        cursor: null,
        limit: 100,
      });
      return assessOriginReachability(binding, observations, proof);
    },

    async registerRetestLineage(ctx, input = {}, options = {}) {
      const allowed = gate(ctx, ['finding:write'], 'finding_retest_lineage');
      if (!allowed.ok) return denied(allowed);
      const finding = await repository.getFinding(ctx, input.finding_id);
      const run = await repository.getRun(ctx, input.test_run_id);
      const existing = finding && run
        ? await repository.findLineage(ctx, { findingId: finding.id, testRunId: run.id })
        : null;
      const authorization = finding && run && !existing && isProtectionValidationFinding(finding)
        ? (options.authorization ?? (await options.resolveProtectionRetestAuthorization?.(ctx, finding, run)) ?? null)
        : null;
      const planned = planRetestRegistration({ finding, run, intent: input.intent, existing, authorization });
      if (planned.error) return planned;
      if (planned.replayed) return { ...existing, replayed: true, sibling_closure: false };
      const record = {
        id: `rtln_${randomBytes(8).toString('hex')}`,
        tenant_id: ctx.tenantId,
        finding_id: finding.id,
        test_run_id: run.id,
        target_id: finding.target_id,
        check_id: finding.check_id,
        created_by: ctx.userId ?? null,
        created_at: normalizeObservationTimestamp(options.now ?? new Date()),
        ...(planned.comparison_context ? { comparison_context: planned.comparison_context } : {}),
      };
      const stored = await repository.insertLineage(ctx, record);
      if (stored.error) return stored;
      return { ...stored, replayed: stored.replayed === true, sibling_closure: false };
    },

    async listFindingLineage(ctx, findingId) {
      const allowed = gate(ctx, ['finding:read'], 'finding_retest_lineage');
      if (!allowed.ok) return denied(allowed);
      const finding = await repository.getFinding(ctx, findingId);
      if (!finding) return error('unknown_finding', 404);
      const [lineage, runs, siblings] = await Promise.all([
        repository.listLineage(ctx, finding.id),
        repository.listRunsForTarget(ctx, finding.target_id),
        repository.listSiblingFindings(ctx, { findingId: finding.id, checkId: finding.check_id }),
      ]);
      return presentFindingLineage({ finding, runs, lineage, siblings });
    },
  };
}

export { assessComparability, currentFromRows };
