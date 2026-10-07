// Binds the PV-05 firewall acceptance service to PV-03 storage so captures and evaluations share one persisted record.
import { FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION, MAX_ENCODED_OBSERVATIONS_BYTES, encodeFirewallObservations } from '../lib/firewallChangeAcceptance.mjs';
import { randomBytes } from 'node:crypto';
import { presentBaselineCapture, presentEvaluation } from './protectionValidation.mjs';

const MAX_EXPECTATIONS_PER_CHANGE = 200;

function scopeFor(tenantId, entry = null) {
  return {
    tenantId,
    userId: entry?.actor_user_id ?? null,
    role: entry?.actor_role ?? null,
  };
}

function firewallOnly(capture) {
  return capture && capture.kind === 'firewall_change' ? capture : null;
}

/** PV-05 repository interface implemented over a PV-03 backend (dev JSON or Postgres). */
export function createFirewallAcceptanceRepository(backend, { recordComparisonEvaluation } = {}) {
  if (!backend) throw new Error('firewall acceptance repository requires a protection validation backend');
  if (typeof recordComparisonEvaluation !== 'function') throw new Error('firewall acceptance repository requires recordComparisonEvaluation');

  async function readCapture(tenantId, captureId) {
    if (!captureId) return null;
    return firewallOnly(presentBaselineCapture(await backend.getBaselineCaptureRows(scopeFor(tenantId), captureId)));
  }

  return {
    async getFirewallExpectation(tenantId, id) {
      const row = await backend.getExpectation(scopeFor(tenantId), id);
      return row && row.tenant_id === tenantId && row.kind === 'firewall_change' ? row : null;
    },

    async listFirewallExpectations(tenantId, { change_id: changeId = null, status = null } = {}) {
      const rows = await backend.listExpectations(scopeFor(tenantId), {
        kind: 'firewall_change',
        status,
        change_id: changeId,
        destination_target_id: null,
        anchor_target_id: null,
        cursor: null,
        limit: MAX_EXPECTATIONS_PER_CHANGE,
      });
      return { items: rows.filter((row) => row.tenant_id === tenantId) };
    },

    async findFirewallBaselineByIdempotencyKey(tenantId, key) {
      const captureId = await backend.findBaselineCaptureIdByKey(scopeFor(tenantId), `fwa:${key}`);
      return readCapture(tenantId, captureId);
    },

    async insertFirewallBaseline(tenantId, record, { auditEntry } = {}) {
      const captureId = `fwb_${randomBytes(8).toString('hex')}`;
      const createdAt = new Date().toISOString();
      const rows = record.entries.map((entry, index) => {
        if (Buffer.byteLength(JSON.stringify(encodeFirewallObservations(entry.observations))) > MAX_ENCODED_OBSERVATIONS_BYTES) {
          return null;
        }
        return {
          kind: entry.kind,
          tenant_id: tenantId,
          anchor_target_id: null,
          entry_path_id: null,
          expectation_id: entry.expectation_id,
          expectation_version: entry.expectation_version,
          expectation_digest: entry.expectation_digest,
          declaration_digest: null,
          target_id: entry.target_id,
          destination_mapping: entry.destination_mapping ?? null,
          references: entry.references,
          captured_at: entry.captured_at,
          freshness_window_seconds: entry.freshness_window_seconds,
          contract_version: entry.contract_version,
          immutable: true,
          baseline_digest: entry.baseline_digest,
          classifier_version: entry.classifier_version ?? FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION,
          observations: entry.observations,
          observations_digest: entry.observations_digest,
          id: index === 0 ? captureId : `${captureId}.${index}`,
          capture_id: captureId,
          capture_index: index,
          capture_digest: record.baseline_digest,
          capture_captured_at: record.captured_at,
          change_id: record.change_id,
          entry_count: record.entries.length,
          declaration_version: null,
          status: 'active',
          idempotency_key: index === 0 ? `fwa:${record.idempotency_key}` : null,
          created_at: createdAt,
          created_by: record.created_by ?? null,
          archived_at: null,
          archived_by: null,
        };
      });
      if (rows.some((row) => row === null)) {
        return { error: 'invalid_comparison_baseline', status: 400, field: 'test_run_ids', message: 'Too many samples for one expectation; capture fewer runs.' };
      }
      const entry = auditEntry ? { ...auditEntry, resource_id: captureId, metadata: { ...(auditEntry.metadata ?? {}), entry_count: rows.length } } : null;
      const stored = await backend.insertBaselineCapture(scopeFor(tenantId, auditEntry), rows, entry);
      if (stored?.error) return stored;
      return readCapture(tenantId, stored.capture_id);
    },

    async getFirewallBaseline(tenantId, id) {
      return readCapture(tenantId, id);
    },

    async listFirewallBaselines(tenantId, { change_id: changeId = null, limit = 50 } = {}) {
      const ctx = scopeFor(tenantId);
      const heads = await backend.listBaselineCaptureHeads(ctx, {
        kind: 'firewall_change', status: null, change_id: changeId, entry_path_id: null, expectation_id: null, cursor: null, limit,
      });
      const ids = heads.map((row) => row.capture_id);
      const grouped = new Map(ids.map((captureId) => [captureId, []]));
      for (const row of ids.length ? await backend.getBaselineCaptureRowsByIds(ctx, ids) : []) grouped.get(row.capture_id)?.push(row);
      const items = ids.map((captureId) => presentBaselineCapture(grouped.get(captureId))).filter(Boolean);
      return { items, count: items.length, next_cursor: null };
    },

    async findFirewallEvaluationByIdempotencyKey(tenantId, key) {
      if (typeof backend.findEvaluationByIdempotencyKey !== 'function') return null;
      const row = await backend.findEvaluationByIdempotencyKey(scopeFor(tenantId), `fwc:${key}`);
      return row && row.kind === 'firewall_change' ? presentEvaluation(row) : null;
    },

    async insertFirewallEvaluation(tenantId, record, { auditEntry } = {}) {
      const stored = await recordComparisonEvaluation(scopeFor(tenantId, auditEntry), {
        kind: 'firewall_change',
        baseline_id: record.baseline_id,
        baseline_digest: record.baseline_digest,
        items: record.items,
        limitations: record.limitations,
        evaluated_at: record.evaluated_at,
        provenance: {
          post_test_run_ids: record.post_test_run_ids,
          classifier_version: record.classifier_version,
          readiness_effect: record.readiness_effect ?? 'none',
          observations: record.observations,
          statement: record.statement,
        },
      }, {
        internal: true,
        actor: record.created_by ?? null,
        idempotencyKey: `fwc:${record.idempotency_key}`,
        auditMetadata: { post_test_run_ids: record.post_test_run_ids, dispatched_traffic: false },
      });
      if (stored?.error) return stored;
      const { replayed: _replayed, ...evaluation } = stored;
      return evaluation;
    },

    async getFirewallEvaluation(tenantId, id) {
      const row = await backend.getEvaluation(scopeFor(tenantId), id);
      return row && row.kind === 'firewall_change' ? presentEvaluation(row) : null;
    },

    async listFirewallEvaluations(tenantId, { change_id: changeId = null, baseline_id: baselineId = null, limit = 50 } = {}) {
      const rows = await backend.listEvaluations(scopeFor(tenantId), {
        kind: 'firewall_change', change_id: changeId, baseline_id: baselineId, anchor_target_id: null, cursor: null, limit,
      });
      const items = rows.map(presentEvaluation);
      return { items, count: items.length, next_cursor: null };
    },
  };
}
