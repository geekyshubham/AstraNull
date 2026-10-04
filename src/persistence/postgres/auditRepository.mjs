import { buildAuditRecord } from '../../audit.mjs';
import { decodeCursor, encodeCursor } from '../../lib/cursorPagination.mjs';
import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';

const LAST_AUDIT_ROW_SQL = `SELECT id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
                  actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
           FROM audit_logs
           WHERE tenant_id = $1
           ORDER BY sequence DESC
           LIMIT 1`;

const INSERT_AUDIT_SQL = `INSERT INTO audit_logs (
             id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
             actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)`;

function auditInsertParams(entry) {
  const metadata = entry.metadata ?? {};
  return [
    entry.id,
    entry.tenant_id,
    entry.timestamp,
    entry.sequence,
    entry.prev_hash ?? null,
    entry.entry_hash,
    entry.actor_user_id ?? null,
    entry.actor_role ?? null,
    entry.action,
    entry.resource_type ?? null,
    entry.resource_id ?? null,
    JSON.stringify(metadata),
  ];
}

/** Matches GET /v1/audit-log dev-store window (`slice(-200)`). */
export const DEFAULT_AUDIT_LIST_LIMIT = 200;
export const MAX_AUDIT_LIST_LIMIT = 500;

function normalizeListLimit(limit) {
  if (limit === undefined || limit === null) {
    return DEFAULT_AUDIT_LIST_LIMIT;
  }
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) {
    return DEFAULT_AUDIT_LIST_LIMIT;
  }
  return Math.min(Math.floor(n), MAX_AUDIT_LIST_LIMIT);
}

export class AuditQueryError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = 'AuditQueryError';
    this.code = code;
    this.status = status;
  }
}

function rejectAudit(code, message) {
  throw new AuditQueryError(code, message, 400);
}

function cleanAuditText(value, field, max) {
  if (value == null || value === '') return null;
  const text = String(value).trim();
  if (!text) return null;
  if (text.length > max) rejectAudit('invalid_query_value', `${field} is too long.`);
  return text;
}

/**
 * UTC timestamp key padded to microseconds.
 * ponytail: offset forms are not converted before padding. Callers send `Z`.
 * Upgrade path: normalize offset strings to UTC before the fraction pad.
 */
export function auditTimestampKey(value) {
  const text = String(value ?? '');
  const match = text.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?/);
  if (!match) return text;
  return `${match[1]}.${(match[2] ?? '').padEnd(6, '0').slice(0, 6)}`;
}

function parseAuditInstant(value, field) {
  if (value == null || value === '') return null;
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) rejectAudit('invalid_query_value', `${field} must be a timestamp.`);
    return value.toISOString();
  }
  const text = String(value).trim();
  if (!text || Number.isNaN(new Date(text).getTime())) {
    rejectAudit('invalid_query_value', `${field} must be a timestamp.`);
  }
  return text;
}

/**
 * Filtered audit read. Unknown keys are rejected. This does not clamp a bad limit
 * down to the recent-200 window.
 *
 * @param {unknown} options
 */
export function normalizeAuditListQuery(options = {}) {
  const source = options && typeof options === 'object' && !Array.isArray(options) ? options : null;
  if (!source) rejectAudit('invalid_query', 'Query must be an object.');
  const allowed = new Set(['resource', 'actor', 'action', 'since', 'until', 'cursor', 'limit', 'envelope']);
  for (const key of Object.keys(source)) {
    if (!allowed.has(key)) rejectAudit('unknown_query_param', `Unknown query parameter "${key}".`);
  }
  let limit = DEFAULT_AUDIT_LIST_LIMIT;
  if (source.limit != null && source.limit !== '') {
    const text = typeof source.limit === 'number' ? String(source.limit) : String(source.limit).trim();
    if (!/^[1-9]\d*$/.test(text)) rejectAudit('invalid_limit', `limit must be an integer from 1 to ${MAX_AUDIT_LIST_LIMIT}.`);
    limit = Number(text);
    if (limit > MAX_AUDIT_LIST_LIMIT) {
      rejectAudit('invalid_limit', `limit must be an integer from 1 to ${MAX_AUDIT_LIST_LIMIT}.`);
    }
  }
  let cursor = null;
  if (source.cursor != null && source.cursor !== '') {
    if (typeof source.cursor !== 'string' || source.cursor.length > 512) rejectAudit('invalid_cursor', 'Cursor is not valid.');
    const decoded = decodeCursor(source.cursor);
    if (!decoded || decoded.v !== 1 || typeof decoded.ts !== 'string' || typeof decoded.id !== 'string' || !decoded.id) {
      rejectAudit('invalid_cursor', 'Cursor is not valid.');
    }
    if (Number.isNaN(new Date(decoded.ts).getTime())) rejectAudit('invalid_cursor', 'Cursor is not valid.');
    cursor = { ts: decoded.ts, id: decoded.id };
  }
  const since = parseAuditInstant(source.since, 'since');
  const until = parseAuditInstant(source.until, 'until');
  if (since && until && auditTimestampKey(since) > auditTimestampKey(until)) {
    rejectAudit('invalid_query_value', 'since must be at or before until.');
  }
  return {
    resource: cleanAuditText(source.resource, 'resource', 200),
    actor: cleanAuditText(source.actor, 'actor', 200),
    action: cleanAuditText(source.action, 'action', 200),
    since,
    until,
    cursor,
    limit,
  };
}

function auditCursor(row) {
  return encodeCursor({ v: 1, ts: row.timestamp_exact, id: row.id });
}

function rowToAuditEntry(row) {
  if (!row) return null;
  const { metadata_json: metadataJson, timestamp_exact: _timestampExact, ...rest } = row;
  const timestamp =
    row.timestamp instanceof Date ? row.timestamp.toISOString() : row.timestamp;
  return {
    ...rest,
    timestamp,
    sequence: Number(row.sequence),
    metadata: metadataJson ?? {},
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createAuditRepository(pool) {
  return {
    /**
     * Newest-window entries in ascending sequence order (matches dev-store list semantics).
     * @param {{ tenantId: string }} ctx
     * @param {{ limit?: number }} [options]
     */
    async listAuditEntries(ctx, options = {}) {
      const tenantId = ctx?.tenantId;
      const boundedLimit = normalizeListLimit(options.limit);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
                  actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
           FROM audit_logs
           WHERE tenant_id = $1
           ORDER BY sequence DESC
           LIMIT $2`,
          [tenantId, boundedLimit],
        );
        return rows.reverse().map(rowToAuditEntry);
      });
    },

    /**
     * Filtered, bounded read. `total` is the predicate count, not the page and not the
     * newest 200. The cursor timestamp is PostgreSQL microsecond text.
     * @param {{ tenantId: string }} ctx
     * @param {object} [options]
     */
    async queryAuditEntries(ctx, options = {}) {
      const tenantId = ctx?.tenantId;
      if (!tenantId) rejectAudit('invalid_tenant', 'Tenant id is required.');
      const query = normalizeAuditListQuery(options);
      return withTenantContext(pool, tenantId, async (client) => {
        const params = [tenantId, query.resource, query.actor, query.action, query.since, query.until];
        const where = `
          tenant_id = $1
          AND ($2::text IS NULL OR resource_type = $2 OR resource_id = $2)
          AND ($3::text IS NULL OR actor_user_id = $3)
          AND ($4::text IS NULL OR action = $4)
          AND ($5::timestamptz IS NULL OR timestamp >= $5::timestamptz)
          AND ($6::timestamptz IS NULL OR timestamp <= $6::timestamptz)`;
        const cursorSql = query.cursor
          ? ` AND (timestamp < $7::timestamptz OR (timestamp = $7::timestamptz AND id < $8))`
          : '';
        const listParams = query.cursor
          ? [...params, query.cursor.ts, query.cursor.id, query.limit + 1]
          : [...params, query.limit + 1];
        const limitParam = query.cursor ? '$9' : '$7';
        const { rows } = await client.query(
          `SELECT id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
                  actor_user_id, actor_role, action, resource_type, resource_id, metadata_json,
                  to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS timestamp_exact
           FROM audit_logs
           WHERE ${where}${cursorSql}
           ORDER BY timestamp DESC, id DESC
           LIMIT ${limitParam}`,
          listParams,
        );
        const more = rows.length > query.limit;
        const page = more ? rows.slice(0, query.limit) : rows;
        const oldest = page[page.length - 1];
        const { rows: counted } = await client.query(
          `SELECT COUNT(*)::int AS total FROM audit_logs WHERE ${where}`,
          params,
        );
        const filters = {};
        if (query.resource) filters.resource = query.resource;
        if (query.actor) filters.actor = query.actor;
        if (query.action) filters.action = query.action;
        if (query.since) filters.since = query.since;
        if (query.until) filters.until = query.until;
        return {
          items: page.slice().reverse().map(rowToAuditEntry),
          count: page.length,
          total: counted[0]?.total ?? 0,
          next_cursor: more && oldest ? auditCursor(oldest) : null,
          filters,
          limit: query.limit,
        };
      });
    },

    /** Exact tenant-scoped audit row. Does not write. */
    async getAuditEntry(ctx, id) {
      const tenantId = ctx?.tenantId;
      if (!tenantId || !id) return null;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
                  actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
           FROM audit_logs
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return rowToAuditEntry(rows[0] ?? null);
      });
    },

    /**
     * Persist a fully formed tamper-evident record (e.g. from `audit()` after wiring).
     * @param {Record<string, unknown>} entry
     */
    async appendAuditEntry(entry) {
      const tenantId = entry?.tenant_id;

      return withTenantContext(pool, tenantId, async (client) => {
        await client.query(INSERT_AUDIT_SQL, auditInsertParams(entry));
        return entry;
      });
    },

    /**
     * Redact, chain, and persist a raw audit event under a tenant-scoped advisory lock.
     * @param {Record<string, unknown>} entry
     * @param {{
     *   now?: Date,
     *   client?: import('pg').PoolClient,
     *   auditLockHeld?: boolean,
     *   idempotency?: {
     *     actions?: string[],
     *     resourceType?: string | null,
     *     resourceId?: string | null,
     *     metadata?: Record<string, unknown>,
     *   },
     * }} [options]
     */
    async appendAuditEvent(entry, options = {}) {
      const tenantId = String(entry?.tenant_id ?? '').trim();
      if (!tenantId) {
        throw new Error('tenant id must be a non-empty string.');
      }

      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        if (options.auditLockHeld !== true) {
          await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [tenantId]);
        }

        if (options.idempotency) {
          const actions = Array.isArray(options.idempotency.actions)
            ? options.idempotency.actions.filter(
              (action) => typeof action === 'string' && action !== '',
            )
            : [entry.action];
          if (actions.length === 0) {
            throw new Error('appendAuditEvent idempotency requires at least one action.');
          }
          const resourceType = options.idempotency.resourceType
            ?? entry.resource_type
            ?? null;
          const resourceId = options.idempotency.resourceId
            ?? entry.resource_id
            ?? null;
          const metadata = options.idempotency.metadata;
          if (metadata != null && (typeof metadata !== 'object' || Array.isArray(metadata))) {
            throw new Error('appendAuditEvent idempotency metadata must be an object.');
          }
          const existing = await client.query(
            `SELECT id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
                    actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
             FROM audit_logs
             WHERE tenant_id = $1
               AND action = ANY($2::text[])
               AND resource_type IS NOT DISTINCT FROM $3
               AND resource_id IS NOT DISTINCT FROM $4
               AND metadata_json @> $5::jsonb
             ORDER BY sequence DESC
             LIMIT 1`,
            [tenantId, actions, resourceType, resourceId, JSON.stringify(metadata ?? {})],
          );
          if (existing.rows[0]) return rowToAuditEntry(existing.rows[0]);
        }

        const { rows } = await client.query(LAST_AUDIT_ROW_SQL, [tenantId]);
        const lastRow = rowToAuditEntry(rows[0] ?? null);
        const record = buildAuditRecord(entry, lastRow, options.now);
        await client.query(INSERT_AUDIT_SQL, auditInsertParams(record));
        return record;
      });
    },

    /**
     * Latest chained row for sequence / prev_hash continuation (per-tenant).
     * @param {string} tenantId
     */
    async getLastAuditEntry(tenantId) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(LAST_AUDIT_ROW_SQL, [tenantId]);
        return rowToAuditEntry(rows[0] ?? null);
      });
    },

    /**
     * Run callback under a per-tenant advisory lock with the latest chained audit row.
     * Use for custody preparation + append in one transaction.
     *
     * @param {string} tenantId
     * @param {(ctx: { client: import('pg').PoolClient, prior: ReturnType<typeof rowToAuditEntry> }) => Promise<unknown>} callback
     */
    async withTenantAuditLock(tenantId, callback) {
      return runWithTenantClient(pool, tenantId, undefined, async (client) => {
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [tenantId]);
        const { rows } = await client.query(LAST_AUDIT_ROW_SQL, [tenantId]);
        const prior = rowToAuditEntry(rows[0] ?? null);
        return callback({ client, prior });
      });
    },
  };
}