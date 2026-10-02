import { withTenantContext } from './tenantContext.mjs';

const RULE_COLUMNS = `id, tenant_id, channel, destination, trigger, triggers_json, enabled, created_at, updated_at`;

const DELIVERY_ATTEMPT_COLUMNS = `id, tenant_id, notification_event_id, rule_id, channel, destination_preview,
                  status, reason, attempt_number, max_attempts, next_retry_at, provider_error, exhausted,
                  provider_status, created_at, attempted_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function parseTriggersJson(row) {
  const raw = row.triggers_json;
  if (Array.isArray(raw) && raw.length > 0) {
    return raw.map((t) => String(t));
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed.map((t) => String(t));
      }
    } catch {
      /* fall through */
    }
  }
  if (row.trigger && String(row.trigger).trim()) {
    return [String(row.trigger).trim()];
  }
  return [];
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapNotificationRuleRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    channel: row.channel,
    destination: row.destination ?? '',
    triggers: parseTriggersJson(row),
    enabled: row.enabled !== false,
    created_at: toIso(row.created_at),
    ...(row.updated_at ? { updated_at: toIso(row.updated_at) } : {}),
  };
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapDeliveryAttemptRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    rule_id: row.rule_id,
    channel: row.channel,
    destination_preview: row.destination_preview ?? '',
    status: row.status,
    reason: row.reason ?? null,
    attempt_number: row.attempt_number == null ? null : Number(row.attempt_number),
    max_attempts: row.max_attempts == null ? null : Number(row.max_attempts),
    next_retry_at: row.next_retry_at ? toIso(row.next_retry_at) : null,
    next_retry_at_cursor: row.next_retry_at_cursor == null ? null : String(row.next_retry_at_cursor),
    created_at_cursor: row.created_at_cursor == null ? null : String(row.created_at_cursor),
    provider_error: row.provider_error ?? null,
    exhausted: row.exhausted == null ? null : row.exhausted === true,
    provider_status: row.provider_status == null ? null : Number(row.provider_status),
    created_at: toIso(row.created_at),
    attempted_at: row.attempted_at ? toIso(row.attempted_at) : null,
  };
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 * @param {import('./notificationRepository.mjs').mapDeliveryAttemptRow[]} attempts
 */
export function mapNotificationEventRow(row, attempts = []) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    trigger: row.trigger,
    subject: row.subject ?? '',
    metadata: row.metadata_json && typeof row.metadata_json === 'object' ? row.metadata_json : {},
    delivery_attempts: attempts,
    created_at: toIso(row.created_at),
  };
}

/**
 * Insert one delivery attempt row inside an open tenant transaction.
 * `created_at` / `attempted_at` are clamped to the database clock: a caller-supplied `as_of` in
 * the future (for example an operator-run retry tick) is only a due cutoff and must never
 * future-date ledger rows, which would otherwise outrank later real-time attempts in every
 * (created_at, attempt_number, id) "latest row" ordering.
 * @param {import('pg').PoolClient} client
 * @param {string} tenantId
 * @param {string} notificationEventId
 * @param {Record<string, unknown>} attempt
 */
async function insertDeliveryAttempt(client, tenantId, notificationEventId, attempt) {
  const { rows } = await client.query(
    `INSERT INTO notification_delivery_attempts (
       id, tenant_id, notification_event_id, rule_id, channel, destination_preview,
       status, reason, attempt_number, max_attempts, next_retry_at, provider_error, exhausted,
       provider_status, created_at, attempted_at
     )
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::timestamptz, $12, $13, $14,
             LEAST($15::timestamptz, clock_timestamp()),
             CASE WHEN $16::timestamptz IS NULL THEN NULL ELSE LEAST($16::timestamptz, clock_timestamp()) END)
     RETURNING ${DELIVERY_ATTEMPT_COLUMNS}`,
    [
      attempt.id,
      tenantId,
      notificationEventId,
      attempt.rule_id,
      attempt.channel,
      attempt.destination_preview,
      attempt.status,
      attempt.reason ?? null,
      attempt.attempt_number ?? null,
      attempt.max_attempts ?? null,
      attempt.next_retry_at ?? null,
      attempt.provider_error ?? null,
      attempt.exhausted ?? null,
      attempt.provider_status ?? null,
      attempt.created_at,
      attempt.attempted_at ?? null,
    ],
  );
  return mapDeliveryAttemptRow(rows[0]);
}

/**
 * Mark the live pending attempt(s) of one event/rule as superseded by a newer attempt, inside an
 * open tenant transaction. Superseded rows are never claimed or recovered again.
 * @param {import('pg').PoolClient} client
 * @param {string} tenantId
 * @param {string} notificationEventId
 * @param {unknown} ruleId
 */
async function supersedePendingAttempts(client, tenantId, notificationEventId, ruleId) {
  await client.query(
    `UPDATE notification_delivery_attempts
     SET superseded_at = clock_timestamp(), lease_expires_at = NULL
     WHERE tenant_id = $1 AND notification_event_id = $2 AND rule_id = $3
       AND status = 'provider_retry_scheduled' AND superseded_at IS NULL`,
    [tenantId, notificationEventId, ruleId],
  );
}

/** SQL predicate on the joined rule `r`: live rule that is turned off (R01 hold; never work). */
const RULE_HELD_PREDICATE = `(r.id IS NOT NULL AND r.deleted_at IS NULL AND r.enabled IS FALSE)`;

/** Reason on an outbox attempt durably queued but not yet sent (mirrors OUTBOX_PENDING_REASON). */
const OUTBOX_PENDING_DELIVERY_REASON = 'outbox_pending_delivery';

/**
 * SQL predicate: a due outbox attempt still awaiting its first send on a channel outside the
 * tick's active channels (`$<n>::text[]`). Such a tick cannot deliver it, so it is deferred —
 * but only work a provider-capable tick could still deliver. Lifecycle cancellations need no
 * channel: a removed rule (`cancelled_rule_removed`) or a rule no longer subscribed to the
 * event's trigger (`cancelled_rule_unsubscribed`) is closed by the gate on any tick, so those
 * rows stay in the page instead of pending forever behind an inactive channel.
 * @param {number} paramIndex
 */
function outboxDeferredPredicate(paramIndex) {
  return `(a.reason = '${OUTBOX_PENDING_DELIVERY_REASON}'
             AND NOT (COALESCE(a.channel, '') = ANY($${paramIndex}::text[]))
             AND r.id IS NOT NULL AND r.deleted_at IS NULL AND r.enabled IS NOT FALSE
             AND r.triggers_json IS NOT NULL AND r.triggers_json @> to_jsonb(e.trigger))`;
}

/**
 * @param {import('pg').Pool} pool
 */
export function createNotificationRepository(pool) {
  return {
    /**
     * @param {{ tenantId: string }} ctx
     */
    async listNotificationRules(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${RULE_COLUMNS}
           FROM notification_rules
           WHERE tenant_id = $1 AND deleted_at IS NULL
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapNotificationRuleRow);
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {{ limit?: number }} [options]
     */
    async listNotificationEvents(ctx, options = {}) {
      const tenantId = ctx.tenantId;
      const limit = Math.min(Math.max(Number(options.limit) || 100, 1), 500);
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows: eventRows } = await client.query(
          `SELECT id, tenant_id, rule_id, trigger, subject, metadata_json, delivery_status, created_at
           FROM notification_events
           WHERE tenant_id = $1
           ORDER BY created_at DESC
           LIMIT $2`,
          [tenantId, limit],
        );
        if (eventRows.length === 0) return [];

        const eventIds = eventRows.map((r) => r.id);
        const { rows: attemptRows } = await client.query(
          `SELECT ${DELIVERY_ATTEMPT_COLUMNS}
           FROM notification_delivery_attempts
           WHERE tenant_id = $1 AND notification_event_id = ANY($2::text[])
           ORDER BY created_at ASC, COALESCE(attempt_number, 0) ASC, id ASC`,
          [tenantId, eventIds],
        );

        const attemptsByEvent = new Map();
        for (const row of attemptRows) {
          const eventId = row.notification_event_id;
          if (!attemptsByEvent.has(eventId)) attemptsByEvent.set(eventId, []);
          attemptsByEvent.get(eventId).push(mapDeliveryAttemptRow(row));
        }

        const events = eventRows.map((row) =>
          mapNotificationEventRow(row, attemptsByEvent.get(row.id) ?? []),
        );
        return events.reverse();
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {Record<string, unknown>} record
     */
    async createNotificationRule(ctx, record) {
      const tenantId = ctx.tenantId;
      const triggers = Array.isArray(record.triggers) ? record.triggers : [];
      const legacyTrigger = triggers[0] ?? null;

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO notification_rules (
             id, tenant_id, channel, destination, trigger, triggers_json, enabled, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::timestamptz)
           RETURNING ${RULE_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.channel,
            record.destination ?? '',
            legacyTrigger,
            JSON.stringify(triggers),
            record.enabled !== false,
            record.created_at,
          ],
        );
        return mapNotificationRuleRow(rows[0]);
      });
    },

    /**
     * One live (not removed) rule, tenant-scoped. Returns null for another tenant's rule.
     * @param {{ tenantId: string }} ctx
     * @param {string} ruleId
     */
    async getNotificationRule(ctx, ruleId) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${RULE_COLUMNS}
           FROM notification_rules
           WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
          [tenantId, ruleId],
        );
        return mapNotificationRuleRow(rows[0]);
      });
    },

    /**
     * Current lifecycle state of one rule for the delivery gate, read right before a send.
     * Unlike getNotificationRule this includes soft-deleted rules (with `deleted_at`), so pending
     * work for a removed rule is cancelled rather than mistaken for an unknown rule. Tenant-scoped;
     * another tenant's rule reads as null.
     * @param {{ tenantId: string }} ctx
     * @param {string} ruleId
     */
    async getNotificationRuleDeliveryState(ctx, ruleId) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${RULE_COLUMNS}, deleted_at
           FROM notification_rules
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, ruleId],
        );
        const row = rows[0];
        if (!row) return null;
        return { ...mapNotificationRuleRow(row), deleted_at: row.deleted_at ? toIso(row.deleted_at) : null };
      });
    },

    /**
     * Apply validated changes to a live rule. Only the provided fields are written.
     * @param {{ tenantId: string, userId?: string }} ctx
     * @param {string} ruleId
     * @param {{ enabled?: boolean, triggers?: string[], destination?: string }} changes
     * @param {{ updated_at: string }} meta
     */
    async updateNotificationRule(ctx, ruleId, changes, meta) {
      const tenantId = ctx.tenantId;
      const params = [tenantId, ruleId, meta.updated_at, ctx.userId ?? null];
      const sets = ['updated_at = $3::timestamptz', 'updated_by = $4'];
      if (changes.enabled !== undefined) {
        params.push(changes.enabled === true);
        sets.push(`enabled = $${params.length}`);
      }
      if (changes.triggers !== undefined) {
        params.push(JSON.stringify(changes.triggers));
        sets.push(`triggers_json = $${params.length}::jsonb`);
        params.push(changes.triggers[0] ?? null);
        sets.push(`trigger = $${params.length}`);
      }
      if (changes.destination !== undefined) {
        params.push(changes.destination);
        sets.push(`destination = $${params.length}`);
      }
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE notification_rules
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
           RETURNING ${RULE_COLUMNS}`,
          params,
        );
        return mapNotificationRuleRow(rows[0]);
      });
    },

    /**
     * Soft-delete a live rule. Delivery history keeps its foreign key to the rule row, and the
     * stored destination (a provider URL or mailbox, i.e. a secret) is cleared so a removed rule
     * can never be delivered to again, including by retry or DLQ redrive.
     * @param {{ tenantId: string, userId?: string }} ctx
     * @param {string} ruleId
     * @param {{ deleted_at: string }} meta
     */
    async deleteNotificationRule(ctx, ruleId, meta) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE notification_rules
           SET deleted_at = $3::timestamptz, updated_at = $3::timestamptz, updated_by = $4, enabled = FALSE,
               destination = ''
           WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
           RETURNING ${RULE_COLUMNS}`,
          [tenantId, ruleId, meta.deleted_at, ctx.userId ?? null],
        );
        return mapNotificationRuleRow(rows[0]);
      });
    },

    /**
     * Authoritative latest delivery attempt per live rule, independent of the bounded
     * recent-events feed. Ties on created_at break by id for a stable answer.
     * @param {{ tenantId: string }} ctx
     */
    async listLatestDeliveryAttemptsByRule(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT DISTINCT ON (a.rule_id)
                  a.id, a.tenant_id, a.notification_event_id, a.rule_id, a.channel, a.destination_preview,
                  a.status, a.reason, a.attempt_number, a.max_attempts, a.next_retry_at, a.provider_error,
                  a.exhausted, a.provider_status, a.created_at, a.attempted_at
           FROM notification_delivery_attempts a
           JOIN notification_rules r ON r.tenant_id = a.tenant_id AND r.id = a.rule_id
           WHERE a.tenant_id = $1 AND r.deleted_at IS NULL
           ORDER BY a.rule_id, a.created_at DESC, a.id DESC`,
          [tenantId],
        );
        return rows.map((row) => ({
          ...mapDeliveryAttemptRow(row),
          notification_event_id: row.notification_event_id,
        }));
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {Record<string, unknown>} event
     */
    async appendNotificationEvent(ctx, event) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO notification_events (
             id, tenant_id, rule_id, trigger, subject, metadata_json, delivery_status, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::timestamptz)
           RETURNING id, tenant_id, rule_id, trigger, subject, metadata_json, delivery_status, created_at`,
          [
            event.id,
            tenantId,
            event.rule_id ?? null,
            event.trigger,
            event.subject,
            JSON.stringify(event.metadata ?? {}),
            event.delivery_status ?? 'metadata_only',
            event.created_at,
          ],
        );
        return mapNotificationEventRow(rows[0], []);
      });
    },

    /**
     * Durable, idempotent outbox enqueue. Records the event and its initial (pending) delivery
     * attempts in ONE tenant transaction, before any external send. A `dedupe_key` collapses
     * replays, concurrent invocations, and other API instances to one event per tenant/identity
     * (uniq_notification_events_dedupe). On conflict the already-recorded event is returned with
     * `inserted: false` and nothing new is written.
     * @param {{ tenantId: string }} ctx
     * @param {Record<string, unknown>} event
     * @param {Record<string, unknown>[]} attempts
     * @returns {Promise<{ inserted: boolean, event: ReturnType<typeof mapNotificationEventRow> }>}
     */
    async enqueueNotificationEvent(ctx, event, attempts = []) {
      const tenantId = ctx.tenantId;
      const dedupeKey = typeof event.dedupe_key === 'string' && event.dedupe_key.trim()
        ? event.dedupe_key.trim()
        : null;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO notification_events (
             id, tenant_id, rule_id, trigger, subject, metadata_json, delivery_status, created_at, dedupe_key
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::timestamptz, $9)
           ON CONFLICT (tenant_id, dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING
           RETURNING id, tenant_id, rule_id, trigger, subject, metadata_json, delivery_status, created_at`,
          [
            event.id,
            tenantId,
            event.rule_id ?? null,
            event.trigger,
            event.subject,
            JSON.stringify(event.metadata ?? {}),
            event.delivery_status ?? 'metadata_only',
            event.created_at,
            dedupeKey,
          ],
        );

        if (!rows[0]) {
          const { rows: existingRows } = await client.query(
            `SELECT id, tenant_id, rule_id, trigger, subject, metadata_json, delivery_status, created_at
             FROM notification_events
             WHERE tenant_id = $1 AND dedupe_key = $2`,
            [tenantId, dedupeKey],
          );
          const existing = existingRows[0] ?? null;
          if (!existing) throw new Error('notification_outbox_conflict_unresolved');
          const { rows: attemptRows } = await client.query(
            `SELECT ${DELIVERY_ATTEMPT_COLUMNS}
             FROM notification_delivery_attempts
             WHERE tenant_id = $1 AND notification_event_id = $2
             ORDER BY created_at ASC, COALESCE(attempt_number, 0) ASC, id ASC`,
            [tenantId, existing.id],
          );
          return {
            inserted: false,
            event: mapNotificationEventRow(existing, attemptRows.map(mapDeliveryAttemptRow)),
          };
        }

        const inserted = [];
        for (const attempt of attempts) {
          inserted.push(await insertDeliveryAttempt(client, tenantId, event.id, attempt));
        }
        return { inserted: true, event: mapNotificationEventRow(rows[0], inserted) };
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {string} notificationEventId
     * @param {Record<string, unknown>[]} attempts
     */
    async appendDeliveryAttempts(ctx, notificationEventId, attempts) {
      const tenantId = ctx.tenantId;
      if (!attempts.length) return [];

      return withTenantContext(pool, tenantId, async (client) => {
        const inserted = [];
        for (const attempt of attempts) {
          // Keep one live pending row per event/rule: a new attempt supersedes the prior pending one.
          await supersedePendingAttempts(client, tenantId, notificationEventId, attempt.rule_id);
          inserted.push(await insertDeliveryAttempt(client, tenantId, notificationEventId, attempt));
        }
        return inserted;
      });
    },

    /**
     * One page of due delivery work, read directly from the attempt ledger (never from the bounded
     * recent-events feed): the latest, unsuperseded `provider_retry_scheduled` attempt per
     * event/rule with `next_retry_at <= asOf`, not under an active lease, and not held by a
     * turned-off rule. Ordered by (next_retry_at, id); `after` is the keyset cursor of the previous
     * page so a drain always advances. Each row carries its event payload for the send.
     *
     * When `activeChannels` is an array, outbox attempts still awaiting their FIRST send
     * (`outbox_pending_delivery`) on a channel outside it are excluded in SQL: the calling tick
     * cannot deliver them, so they must not occupy page slots or the tick's work budget and starve
     * due work ordered behind them. `summarizePendingDeliveryAttempts` counts them instead.
     * @param {{ tenantId: string }} ctx
     * @param {{ asOf: string, limit?: number, after?: { next_retry_at: string, id: string } | null, activeChannels?: string[] }} options
     */
    async listDueDeliveryAttempts(ctx, options) {
      const tenantId = ctx.tenantId;
      const limit = Math.min(Math.max(Number(options.limit) || 100, 1), 500);
      const after = options.after && options.after.next_retry_at && options.after.id ? options.after : null;
      const activeChannels = Array.isArray(options.activeChannels) ? options.activeChannels.map(String) : null;
      const params = [tenantId, options.asOf, after?.next_retry_at ?? null, after?.id ?? null, limit];
      const deferredFilter = activeChannels
        ? `AND NOT ${outboxDeferredPredicate(params.push(activeChannels))}`
        : '';
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT a.id, a.tenant_id, a.notification_event_id, a.rule_id, a.channel, a.destination_preview,
                  a.status, a.reason, a.attempt_number, a.max_attempts, a.next_retry_at, a.provider_error,
                  a.exhausted, a.provider_status, a.created_at, a.attempted_at,
                  a.next_retry_at::text AS next_retry_at_cursor,
                  e.trigger AS event_trigger, e.subject AS event_subject,
                  e.metadata_json AS event_metadata_json, e.created_at AS event_created_at
           FROM notification_delivery_attempts a
           JOIN notification_events e ON e.tenant_id = a.tenant_id AND e.id = a.notification_event_id
           LEFT JOIN notification_rules r ON r.tenant_id = a.tenant_id AND r.id = a.rule_id
           WHERE a.tenant_id = $1
             AND a.status = 'provider_retry_scheduled'
             AND a.superseded_at IS NULL
             AND a.next_retry_at <= $2::timestamptz
             AND (a.lease_expires_at IS NULL OR a.lease_expires_at <= clock_timestamp())
             AND NOT ${RULE_HELD_PREDICATE}
             AND ($3::timestamptz IS NULL OR (a.next_retry_at, a.id) > ($3::timestamptz, $4::text))
             ${deferredFilter}
           ORDER BY a.next_retry_at ASC, a.id ASC
           LIMIT $5`,
          params,
        );
        return rows.map((row) => ({
          event: {
            id: row.notification_event_id,
            tenant_id: row.tenant_id,
            trigger: row.event_trigger,
            subject: row.event_subject ?? '',
            metadata: row.event_metadata_json && typeof row.event_metadata_json === 'object'
              ? row.event_metadata_json
              : {},
            created_at: toIso(row.event_created_at),
          },
          attempt: { ...mapDeliveryAttemptRow(row), notification_event_id: row.notification_event_id },
        }));
      });
    },

    /**
     * Counts over the live pending ledger as of `asOf`: scheduled but not yet due, due but held by
     * a turned-off rule, and due but actively leased by another sender. With `activeChannels`, also
     * `deferred_inactive_channel`: due, unleased, unheld outbox attempts awaiting their first send on
     * a channel outside it (the rows `listDueDeliveryAttempts` excludes for the same channels).
     * @param {{ tenantId: string }} ctx
     * @param {{ asOf: string, activeChannels?: string[] }} options
     */
    async summarizePendingDeliveryAttempts(ctx, options) {
      const tenantId = ctx.tenantId;
      const activeChannels = Array.isArray(options.activeChannels) ? options.activeChannels.map(String) : null;
      const params = [tenantId, options.asOf];
      const deferredCount = activeChannels
        ? `COUNT(*) FILTER (
               WHERE a.next_retry_at <= $2::timestamptz AND NOT ${RULE_HELD_PREDICATE}
                 AND (a.lease_expires_at IS NULL OR a.lease_expires_at <= clock_timestamp())
                 AND ${outboxDeferredPredicate(params.push(activeChannels))}
             )::int`
        : '0';
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT
             COUNT(*) FILTER (
               WHERE a.next_retry_at IS NULL OR a.next_retry_at > $2::timestamptz
             )::int AS scheduled_not_due,
             COUNT(*) FILTER (
               WHERE a.next_retry_at <= $2::timestamptz AND ${RULE_HELD_PREDICATE}
             )::int AS held_due,
             COUNT(*) FILTER (
               WHERE a.next_retry_at <= $2::timestamptz AND NOT ${RULE_HELD_PREDICATE}
                 AND a.lease_expires_at > clock_timestamp()
             )::int AS in_flight,
             ${deferredCount} AS deferred_inactive_channel
           FROM notification_delivery_attempts a
           JOIN notification_events e ON e.tenant_id = a.tenant_id AND e.id = a.notification_event_id
           LEFT JOIN notification_rules r ON r.tenant_id = a.tenant_id AND r.id = a.rule_id
           WHERE a.tenant_id = $1
             AND a.status = 'provider_retry_scheduled'
             AND a.superseded_at IS NULL`,
          params,
        );
        const row = rows[0] ?? {};
        return {
          scheduled_not_due: Number(row.scheduled_not_due ?? 0),
          held_due: Number(row.held_due ?? 0),
          in_flight: Number(row.in_flight ?? 0),
          deferred_inactive_channel: Number(row.deferred_inactive_channel ?? 0),
        };
      });
    },

    /**
     * Atomically claim one pending attempt for delivery before any external I/O. Succeeds only if
     * the attempt is still the live (unsuperseded) `provider_retry_scheduled` row for its event/rule, is not
     * leased by another sender (or that lease has expired), and is due by `dueBy` when given.
     * Competing claims serialize on the row lock, so at most one sender holds the lease. The lease
     * runs on the database clock. Returns the claimed attempt, or null when the claim was lost.
     * @param {{ tenantId: string }} ctx
     * @param {{ attemptId: string, claimToken: string, leaseMs: number, dueBy?: string | null }} claim
     */
    async claimDeliveryAttempt(ctx, claim) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE notification_delivery_attempts a
           SET claimed_by = $3,
               claimed_at = clock_timestamp(),
               lease_expires_at = clock_timestamp() + ($4::int * interval '1 millisecond')
           WHERE a.tenant_id = $1 AND a.id = $2
             AND a.status = 'provider_retry_scheduled'
             AND a.superseded_at IS NULL
             AND (a.lease_expires_at IS NULL OR a.lease_expires_at <= clock_timestamp())
             AND ($5::timestamptz IS NULL OR a.next_retry_at <= $5::timestamptz)
           RETURNING a.id, a.tenant_id, a.notification_event_id, a.rule_id, a.channel, a.destination_preview,
                     a.status, a.reason, a.attempt_number, a.max_attempts, a.next_retry_at, a.provider_error,
                     a.exhausted, a.provider_status, a.created_at, a.attempted_at, a.lease_expires_at`,
          [tenantId, claim.attemptId, claim.claimToken, Math.max(1, Math.trunc(Number(claim.leaseMs) || 1)), claim.dueBy ?? null],
        );
        const row = rows[0];
        if (!row) return null;
        return {
          ...mapDeliveryAttemptRow(row),
          notification_event_id: row.notification_event_id,
          lease_expires_at: toIso(row.lease_expires_at),
        };
      });
    },

    /**
     * Finish a claimed delivery: in ONE tenant transaction, supersede the claimed attempt (only if
     * this claim still owns it) and append the outcome attempt. When the lease was lost to another
     * sender nothing is written and `completed` is false; that sender records its own outcome.
     * @param {{ tenantId: string }} ctx
     * @param {{ attemptId: string, claimToken: string, eventId: string, record: Record<string, unknown> }} input
     */
    async completeDeliveryAttemptClaim(ctx, input) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE notification_delivery_attempts
           SET superseded_at = clock_timestamp(), lease_expires_at = NULL
           WHERE tenant_id = $1 AND id = $2 AND claimed_by = $3 AND notification_event_id = $4
             AND superseded_at IS NULL
           RETURNING id`,
          [tenantId, input.attemptId, input.claimToken, input.eventId],
        );
        if (!rows[0]) return { completed: false, attempt: null };
        const attempt = await insertDeliveryAttempt(client, tenantId, input.eventId, input.record);
        return { completed: true, attempt };
      });
    },

    /**
     * Extend a lease the caller still owns (heartbeat while a send is in flight), so a slow but
     * live sender is never mistaken for a dead one. Returns false once the claim is lost.
     * @param {{ tenantId: string }} ctx
     * @param {{ attemptId: string, claimToken: string, leaseMs: number }} input
     */
    async renewDeliveryAttemptClaim(ctx, input) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rowCount } = await client.query(
          `UPDATE notification_delivery_attempts
           SET lease_expires_at = clock_timestamp() + ($4::int * interval '1 millisecond')
           WHERE tenant_id = $1 AND id = $2 AND claimed_by = $3 AND superseded_at IS NULL
             AND lease_expires_at > clock_timestamp()`,
          [tenantId, input.attemptId, input.claimToken, Math.max(1, Math.trunc(Number(input.leaseMs) || 1))],
        );
        return { renewed: Number(rowCount ?? 0) > 0 };
      });
    },

    /**
     * Give a claim back without recording an outcome (for example the rule was turned off after the
     * claim, so the attempt is held). Only the current owner can release.
     * @param {{ tenantId: string }} ctx
     * @param {{ attemptId: string, claimToken: string }} input
     */
    async releaseDeliveryAttemptClaim(ctx, input) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rowCount } = await client.query(
          `UPDATE notification_delivery_attempts
           SET claimed_by = NULL, claimed_at = NULL, lease_expires_at = NULL
           WHERE tenant_id = $1 AND id = $2 AND claimed_by = $3 AND superseded_at IS NULL`,
          [tenantId, input.attemptId, input.claimToken],
        );
        return { released: Number(rowCount ?? 0) > 0 };
      });
    },

    /**
     * One page of DLQ redrive candidates, read directly from the attempt ledger (never from the
     * bounded recent-events feed): live (unsuperseded) `provider_failed_dlq` attempts that are still
     * the latest attempt for their event/rule. Optional `ruleId` / `attemptIds` filters. Ordered by
     * (created_at, id) with `after` as the keyset cursor. Rows under an active lease are returned with
     * `lease_active: true` (another redrive owns them) so callers can report them as in flight.
     * Rows whose rule is turned off (held) are excluded, like listDueDeliveryAttempts, so they never
     * use up a redrive's work budget (see summarizeHeldDlqDeliveryAttempts); the caller still
     * re-gates each row after claiming it to catch a rule turned off in between.
     * @param {{ tenantId: string }} ctx
     * @param {{ limit?: number, after?: { created_at: string, id: string } | null, ruleId?: string | null, attemptIds?: string[] | null }} [options]
     */
    async listDlqDeliveryAttempts(ctx, options = {}) {
      const tenantId = ctx.tenantId;
      const limit = Math.min(Math.max(Number(options.limit) || 100, 1), 500);
      const after = options.after && options.after.created_at && options.after.id ? options.after : null;
      const attemptIds = Array.isArray(options.attemptIds) && options.attemptIds.length > 0
        ? options.attemptIds.map((id) => String(id))
        : null;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT a.id, a.tenant_id, a.notification_event_id, a.rule_id, a.channel, a.destination_preview,
                  a.status, a.reason, a.attempt_number, a.max_attempts, a.next_retry_at, a.provider_error,
                  a.exhausted, a.provider_status, a.created_at, a.attempted_at,
                  a.created_at::text AS created_at_cursor,
                  (a.lease_expires_at IS NOT NULL AND a.lease_expires_at > clock_timestamp()) AS lease_active,
                  e.trigger AS event_trigger, e.subject AS event_subject,
                  e.metadata_json AS event_metadata_json, e.created_at AS event_created_at
           FROM notification_delivery_attempts a
           JOIN notification_events e ON e.tenant_id = a.tenant_id AND e.id = a.notification_event_id
           LEFT JOIN notification_rules r ON r.tenant_id = a.tenant_id AND r.id = a.rule_id
           WHERE a.tenant_id = $1
             AND a.status = 'provider_failed_dlq'
             AND a.superseded_at IS NULL
             AND NOT EXISTS (
               SELECT 1 FROM notification_delivery_attempts s
               WHERE s.tenant_id = a.tenant_id
                 AND s.notification_event_id = a.notification_event_id
                 AND s.rule_id = a.rule_id
                 AND s.superseded_at IS NULL
                 AND (s.created_at, COALESCE(s.attempt_number, 0), s.id)
                   > (a.created_at, COALESCE(a.attempt_number, 0), a.id)
             )
             AND NOT ${RULE_HELD_PREDICATE}
             AND ($2::text IS NULL OR a.rule_id = $2)
             AND ($3::text[] IS NULL OR a.id = ANY($3::text[]))
             AND ($4::timestamptz IS NULL OR (a.created_at, a.id) > ($4::timestamptz, $5::text))
           ORDER BY a.created_at ASC, a.id ASC
           LIMIT $6`,
          [tenantId, options.ruleId ? String(options.ruleId) : null, attemptIds,
            after?.created_at ?? null, after?.id ?? null, limit],
        );
        return rows.map((row) => ({
          event: {
            id: row.notification_event_id,
            tenant_id: row.tenant_id,
            trigger: row.event_trigger,
            subject: row.event_subject ?? '',
            metadata: row.event_metadata_json && typeof row.event_metadata_json === 'object'
              ? row.event_metadata_json
              : {},
            created_at: toIso(row.event_created_at),
          },
          attempt: { ...mapDeliveryAttemptRow(row), notification_event_id: row.notification_event_id },
          lease_active: row.lease_active === true,
        }));
      });
    },

    /**
     * Live DLQ backlog size for the tenant: unsuperseded `provider_failed_dlq` attempts that are
     * still the latest attempt for their event/rule.
     * @param {{ tenantId: string }} ctx
     */
    async countDlqDeliveryAttempts(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT COUNT(*)::int AS dlq_count
           FROM notification_delivery_attempts a
           WHERE a.tenant_id = $1
             AND a.status = 'provider_failed_dlq'
             AND a.superseded_at IS NULL
             AND NOT EXISTS (
               SELECT 1 FROM notification_delivery_attempts s
               WHERE s.tenant_id = a.tenant_id
                 AND s.notification_event_id = a.notification_event_id
                 AND s.rule_id = a.rule_id
                 AND s.superseded_at IS NULL
                 AND (s.created_at, COALESCE(s.attempt_number, 0), s.id)
                   > (a.created_at, COALESCE(a.attempt_number, 0), a.id)
             )`,
          [tenantId],
        );
        return Number(rows[0]?.dlq_count ?? 0);
      });
    },

    /**
     * Read-only count of live DLQ rows held by a turned-off rule (excluded from
     * listDlqDeliveryAttempts), with the same optional `ruleId` / `attemptIds` filters. When
     * `attemptIds` is given, the matching held ids are returned too so a targeted redrive does not
     * report them as missing. Never claims or writes.
     * @param {{ tenantId: string }} ctx
     * @param {{ ruleId?: string | null, attemptIds?: string[] | null }} [options]
     */
    async summarizeHeldDlqDeliveryAttempts(ctx, options = {}) {
      const tenantId = ctx.tenantId;
      const attemptIds = Array.isArray(options.attemptIds) && options.attemptIds.length > 0
        ? options.attemptIds.map((id) => String(id))
        : null;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT COUNT(*)::int AS held_count,
                  CASE WHEN $3::text[] IS NULL THEN NULL ELSE array_agg(a.id ORDER BY a.created_at, a.id) END
                    AS held_attempt_ids
           FROM notification_delivery_attempts a
           JOIN notification_rules r ON r.tenant_id = a.tenant_id AND r.id = a.rule_id
           WHERE a.tenant_id = $1
             AND a.status = 'provider_failed_dlq'
             AND a.superseded_at IS NULL
             AND a.channel <> 'in_app'
             AND NOT EXISTS (
               SELECT 1 FROM notification_delivery_attempts s
               WHERE s.tenant_id = a.tenant_id
                 AND s.notification_event_id = a.notification_event_id
                 AND s.rule_id = a.rule_id
                 AND s.superseded_at IS NULL
                 AND (s.created_at, COALESCE(s.attempt_number, 0), s.id)
                   > (a.created_at, COALESCE(a.attempt_number, 0), a.id)
             )
             AND ${RULE_HELD_PREDICATE}
             AND ($2::text IS NULL OR a.rule_id = $2)
             AND ($3::text[] IS NULL OR a.id = ANY($3::text[]))`,
          [tenantId, options.ruleId ? String(options.ruleId) : null, attemptIds],
        );
        const row = rows[0] ?? {};
        return {
          held_count: Number(row.held_count ?? 0),
          held_attempt_ids: Array.isArray(row.held_attempt_ids) ? row.held_attempt_ids.map(String) : [],
        };
      });
    },

    /**
     * Atomically claim one DLQ attempt for redrive before any external I/O (same lease protocol as
     * claimDeliveryAttempt). Succeeds only if the attempt is still the live, latest
     * `provider_failed_dlq` row for its event/rule and no other redrive holds an active lease.
     * Finish with completeDeliveryAttemptClaim (supersedes it and appends the outcome) or give it
     * back with releaseDeliveryAttemptClaim. Returns null when the claim was lost.
     * @param {{ tenantId: string }} ctx
     * @param {{ attemptId: string, claimToken: string, leaseMs: number }} claim
     */
    async claimDlqDeliveryAttempt(ctx, claim) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE notification_delivery_attempts a
           SET claimed_by = $3,
               claimed_at = clock_timestamp(),
               lease_expires_at = clock_timestamp() + ($4::int * interval '1 millisecond')
           WHERE a.tenant_id = $1 AND a.id = $2
             AND a.status = 'provider_failed_dlq'
             AND a.superseded_at IS NULL
             AND (a.lease_expires_at IS NULL OR a.lease_expires_at <= clock_timestamp())
             AND NOT EXISTS (
               SELECT 1 FROM notification_delivery_attempts s
               WHERE s.tenant_id = a.tenant_id
                 AND s.notification_event_id = a.notification_event_id
                 AND s.rule_id = a.rule_id
                 AND s.superseded_at IS NULL
                 AND (s.created_at, COALESCE(s.attempt_number, 0), s.id)
                   > (a.created_at, COALESCE(a.attempt_number, 0), a.id)
             )
           RETURNING a.id, a.tenant_id, a.notification_event_id, a.rule_id, a.channel, a.destination_preview,
                     a.status, a.reason, a.attempt_number, a.max_attempts, a.next_retry_at, a.provider_error,
                     a.exhausted, a.provider_status, a.created_at, a.attempted_at, a.lease_expires_at`,
          [tenantId, claim.attemptId, claim.claimToken, Math.max(1, Math.trunc(Number(claim.leaseMs) || 1))],
        );
        const row = rows[0];
        if (!row) return null;
        return {
          ...mapDeliveryAttemptRow(row),
          notification_event_id: row.notification_event_id,
          lease_expires_at: toIso(row.lease_expires_at),
        };
      });
    },
  };
}
