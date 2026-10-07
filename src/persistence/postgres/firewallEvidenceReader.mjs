// Read-only, tenant-scoped run evidence for firewall change acceptance (PV-05) in Postgres mode.
import { withTenantContext } from './tenantContext.mjs';

const EXACT_TIME = (column) => `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`;

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

export function createPostgresFirewallEvidenceReader(pool) {
  const run = (tenantId, callback) => withTenantContext(pool, tenantId, callback);
  return {
    async getTestRun(tenantId, runId) {
      return run(tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, target_group_id, target_id, check_id, status, check_version, scenario_version,
                  producer_kind, origin_binding_id, provenance_json,
                  CASE WHEN completed_at IS NULL THEN NULL ELSE ${EXACT_TIME('completed_at')} END AS completed_at
           FROM test_runs WHERE tenant_id = $1 AND id = $2`,
          [tenantId, runId],
        );
        const row = rows[0];
        return row ? { ...row, provenance_json: asObject(row.provenance_json) } : null;
      });
    },

    async listRunProbeEvents(tenantId, runId) {
      return run(tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, test_run_id, target_id, check_id, signal_type, producer_kind,
                  ${EXACT_TIME('"timestamp"')} AS "timestamp", metadata_json
           FROM events
           WHERE tenant_id = $1 AND test_run_id = $2 AND signal_type = 'probe_result'
           ORDER BY "timestamp", id
           LIMIT 256`,
          [tenantId, runId],
        );
        return rows.map(({ metadata_json: metadata, ...row }) => ({ ...row, metadata: asObject(metadata) }));
      });
    },

    async getRunVerdictId(tenantId, runId) {
      return run(tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id FROM verdicts WHERE tenant_id = $1 AND test_run_id = $2 ORDER BY created_at DESC, id DESC LIMIT 1`,
          [tenantId, runId],
        );
        return rows[0]?.id ?? null;
      });
    },

    async getTarget(tenantId, targetId) {
      if (!targetId) return null;
      return run(tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, target_group_id, kind, value, port,
                  CASE WHEN deleted_at IS NULL THEN NULL ELSE ${EXACT_TIME('deleted_at')} END AS deleted_at
           FROM targets WHERE tenant_id = $1 AND id = $2`,
          [tenantId, targetId],
        );
        return rows[0] ?? null;
      });
    },
  };
}
