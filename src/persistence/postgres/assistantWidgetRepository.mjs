import { randomBytes } from 'node:crypto';
import { withTenantContext } from './tenantContext.mjs';
import { AssistantWidgetError, assertWidgetActor, assertWidgetVersion, normalizeWidgetConfig,
  MAX_ASSISTANT_WIDGETS, publicWidget, widgetAuditEntry } from '../../services/assistantWidgets.mjs';

const COLUMNS = 'id, config_json AS config, version, created_at, updated_at';
function mapRow(row) {
  return row ? publicWidget({ ...row, created_at: new Date(row.created_at).toISOString(), updated_at: new Date(row.updated_at).toISOString() }) : null;
}
function configOf(raw) {
  const config = normalizeWidgetConfig(raw);
  if (!config) throw new AssistantWidgetError('invalid_widget_config');
  return config;
}

/** Every mutation and chained audit use the SAME transaction; no development fallback. */
export function createAssistantWidgetRepository(pool, { auditRepository } = {}) {
  if (typeof auditRepository?.appendAuditEvent !== 'function') throw new Error('Assistant widget audit repository required');
  function personal(ctx, mutation, callback) {
    assertWidgetActor(ctx);
    return withTenantContext(pool, ctx.tenantId, async (client) => {
      // Match the shared audit/catalog lock order before taking any widget row lock.
      if (mutation) await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [ctx.tenantId]);
      await client.query("SELECT set_config('app.user_id', $1, true)", [ctx.userId]);
      return callback(client);
    });
  }
  async function lockedRow(client, ctx, id, version) {
    const row = (await client.query(`SELECT ${COLUMNS} FROM assistant_widgets
      WHERE tenant_id = $1 AND user_id = $2 AND id = $3 FOR UPDATE`, [ctx.tenantId, ctx.userId, id])).rows[0];
    if (!row) throw new AssistantWidgetError('widget_not_found', 404);
    if (row.version !== version) throw new AssistantWidgetError('widget_version_conflict', 409, { current_version: row.version });
    return mapRow(row);
  }
  return {
    list: (ctx) => personal(ctx, false, async (client) => (await client.query(`SELECT ${COLUMNS}
      FROM assistant_widgets WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at, id LIMIT 12`,
    [ctx.tenantId, ctx.userId])).rows.map(mapRow)),
    create(ctx, raw) {
      const config = configOf(raw);
      return personal(ctx, true, async (client) => {
        const occupied = new Set((await client.query('SELECT slot FROM assistant_widgets WHERE tenant_id = $1 AND user_id = $2',
          [ctx.tenantId, ctx.userId])).rows.map((row) => row.slot));
        let slot = 1;
        while (slot <= MAX_ASSISTANT_WIDGETS && occupied.has(slot)) slot += 1;
        if (slot > MAX_ASSISTANT_WIDGETS) throw new AssistantWidgetError('widget_limit_reached', 409);
        const id = `aw_${randomBytes(12).toString('hex')}`;
        const row = mapRow((await client.query(`INSERT INTO assistant_widgets (id, tenant_id, user_id, slot, config_json)
          VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING ${COLUMNS}`, [id, ctx.tenantId, ctx.userId, slot, JSON.stringify(config)])).rows[0]);
        await auditRepository.appendAuditEvent(widgetAuditEntry(ctx, 'created', row), { client });
        return row;
      });
    },
    update(ctx, id, raw, expectedVersion) {
      assertWidgetVersion(expectedVersion);
      const config = configOf(raw);
      return personal(ctx, true, async (client) => {
        await lockedRow(client, ctx, id, expectedVersion);
        const row = mapRow((await client.query(`UPDATE assistant_widgets SET config_json = $4::jsonb,
          version = version + 1, updated_at = NOW() WHERE tenant_id = $1 AND user_id = $2 AND id = $3
          AND version = $5 RETURNING ${COLUMNS}`, [ctx.tenantId, ctx.userId, id, JSON.stringify(config), expectedVersion])).rows[0]);
        if (!row) throw new AssistantWidgetError('widget_version_conflict', 409);
        await auditRepository.appendAuditEvent(widgetAuditEntry(ctx, 'updated', row), { client });
        return row;
      });
    },
    remove(ctx, id, expectedVersion) {
      assertWidgetVersion(expectedVersion);
      return personal(ctx, true, async (client) => {
        const row = await lockedRow(client, ctx, id, expectedVersion);
        const removed = await client.query(`DELETE FROM assistant_widgets WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND version = $4`,
          [ctx.tenantId, ctx.userId, id, expectedVersion]);
        if (!removed.rowCount) throw new AssistantWidgetError('widget_version_conflict', 409);
        await auditRepository.appendAuditEvent(widgetAuditEntry(ctx, 'deleted', row), { client });
        return { deleted: true };
      });
    },
  };
}
