import { normalizeNotificationRuleInput } from './notifications.mjs';

/** Fields a PATCH /v1/notifications/:id body may change. `channel` is fixed at creation. */
export const NOTIFICATION_RULE_UPDATABLE_FIELDS = Object.freeze(['enabled', 'triggers', 'destination']);

/**
 * Validate a rule update against the existing rule, reusing the create-path validation
 * (normalizeNotificationRuleInput) so an update can never store a destination or trigger set
 * that creation would reject: https-only provider URLs, no user:password@ credentials, single
 * email address, no whitespace/control characters, known triggers only.
 *
 * Returns only the fields that actually change, so callers can audit an exact field list and
 * skip writes that would be no-ops.
 *
 * @param {{ channel: string, destination?: string, triggers?: string[], enabled?: boolean }} existing
 * @param {unknown} body
 * @returns {{ ok: true, changes: { enabled?: boolean, triggers?: string[], destination?: string }, changedFields: string[] }
 *   | { error: string, status: number }}
 */
export function normalizeNotificationRuleUpdate(existing, body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { error: 'invalid_body', status: 400 };
  }
  const input = /** @type {Record<string, unknown>} */ (body);
  if (input.channel !== undefined) {
    const requested = typeof input.channel === 'string' ? input.channel.trim().toLowerCase() : input.channel;
    if (requested !== existing.channel) return { error: 'channel_immutable', status: 400 };
  }
  if (input.enabled !== undefined && typeof input.enabled !== 'boolean') {
    return { error: 'invalid_enabled', status: 400 };
  }
  const touchesTriggers = input.triggers !== undefined;
  const touchesDestination = input.destination !== undefined;
  if (input.enabled === undefined && !touchesTriggers && !touchesDestination) {
    return { error: 'no_changes', status: 400 };
  }

  // Validate the merged rule exactly as creation would. Untouched fields keep their stored value.
  const merged = normalizeNotificationRuleInput({
    channel: existing.channel,
    destination: touchesDestination ? input.destination : existing.destination,
    triggers: touchesTriggers ? input.triggers : existing.triggers,
    enabled: input.enabled ?? existing.enabled,
  });
  if (!merged.ok) return { error: merged.error, status: merged.status ?? 400 };

  /** @type {{ enabled?: boolean, triggers?: string[], destination?: string }} */
  const changes = {};
  const changedFields = [];
  if (input.enabled !== undefined && input.enabled !== (existing.enabled !== false)) {
    changes.enabled = input.enabled;
    changedFields.push('enabled');
  }
  const existingTriggers = Array.isArray(existing.triggers) ? existing.triggers : [];
  if (
    touchesTriggers
    && (merged.triggers.length !== existingTriggers.length
      || merged.triggers.some((trigger, index) => trigger !== existingTriggers[index]))
  ) {
    changes.triggers = merged.triggers;
    changedFields.push('triggers');
  }
  if (touchesDestination && merged.destination !== (existing.destination ?? '')) {
    changes.destination = merged.destination;
    changedFields.push('destination');
  }
  return { ok: true, changes, changedFields };
}

/**
 * Audit metadata for a rule update. Never includes the destination itself (a provider URL or
 * mailbox is a secret); only whether it changed.
 * @param {{ channel: string, enabled?: boolean, triggers?: string[] }} rule
 * @param {string[]} changedFields
 */
export function notificationRuleUpdateAuditMetadata(rule, changedFields) {
  return {
    channel: rule.channel,
    changed_fields: [...changedFields],
    enabled: rule.enabled !== false,
    trigger_count: Array.isArray(rule.triggers) ? rule.triggers.length : 0,
    destination_changed: changedFields.includes('destination'),
  };
}

/**
 * Redacted, client-safe view of a delivery attempt for the per-rule "last delivery" read.
 * No destination, provider URL, request/response body, or internal delivery record.
 * @param {Record<string, unknown> | null | undefined} attempt
 * @param {string | null} [eventId]
 */
export function formatLatestDeliveryForRead(attempt, eventId = null) {
  if (!attempt || typeof attempt !== 'object') return null;
  return {
    id: attempt.id ?? null,
    event_id: eventId ?? attempt.notification_event_id ?? attempt.event_id ?? null,
    status: attempt.status ?? null,
    reason: attempt.reason ?? null,
    attempt_number: attempt.attempt_number ?? null,
    created_at: attempt.created_at ?? null,
    attempted_at: attempt.attempted_at ?? null,
  };
}

function attemptSortValue(attempt, fallback) {
  const stamp = Date.parse(String(attempt?.created_at ?? attempt?.attempted_at ?? fallback ?? ''));
  return Number.isFinite(stamp) ? stamp : Number.NEGATIVE_INFINITY;
}

/**
 * Latest attempt per rule across a full (unbounded) event list. Ties keep the later record,
 * so an appended retry/redrive attempt with the same timestamp wins over the one it follows.
 * @param {Array<Record<string, unknown>>} events
 * @returns {Map<string, Record<string, unknown>>}
 */
export function latestDeliveryByRuleFromEvents(events) {
  /** @type {Map<string, { attempt: Record<string, unknown>, eventId: string | null, sort: number }>} */
  const latest = new Map();
  for (const event of Array.isArray(events) ? events : []) {
    const attempts = Array.isArray(event?.delivery_attempts) ? event.delivery_attempts : [];
    for (const attempt of attempts) {
      const ruleId = typeof attempt?.rule_id === 'string' ? attempt.rule_id : '';
      if (!ruleId) continue;
      const sort = attemptSortValue(attempt, event?.created_at);
      const current = latest.get(ruleId);
      if (!current || sort >= current.sort) {
        latest.set(ruleId, { attempt, eventId: typeof event?.id === 'string' ? event.id : null, sort });
      }
    }
  }
  const out = new Map();
  for (const [ruleId, entry] of latest) out.set(ruleId, formatLatestDeliveryForRead(entry.attempt, entry.eventId));
  return out;
}
