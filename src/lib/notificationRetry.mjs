import {
  WEBHOOK_MAX_ATTEMPTS,
  buildEmailPayload,
  buildSlackPayload,
  buildTeamsPayload,
  buildWebhookNotificationBody,
  deliverEmail,
  deliverSlack,
  deliverTeams,
  encodeWebhookPayload,
  finalizeNotificationDeliveryAttempts,
  isDeliveryChannelActive,
  parseNotificationDeliveryModes,
  sendWebhookNotification,
} from './notificationDelivery.mjs';
import { destinationPreview } from './notifications.mjs';

export const NOTIFICATION_RETRY_BACKOFF_MS = 60_000;

/**
 * Rule lifecycle gate applied by every delivery entry point (in-process outbox worker, due-retry
 * processing, DLQ redrive) immediately before a send.
 *
 * - `deliver`: live, enabled rule.
 * - `hold`: live rule that is turned off. Nothing is sent and nothing is recorded, so the attempt
 *   budget is not burned; the pending attempt stays due and resumes once the rule is re-enabled.
 * - `cancel`: soft-deleted rule, or a live rule that no longer subscribes to the event's trigger.
 *   Pending work is closed with a non-sent terminal attempt (`cancelled_rule_removed` or
 *   `cancelled_rule_unsubscribed`, see `cancellation` on the gate result) and is never retried or
 *   redriven. Unsubscribing cancels rather than holds: the rule edit means the work is no longer
 *   owed (reconciliation likewise stops back-filling on a trigger change), and re-adding the
 *   trigger later does not resurrect it. A rule that is both off and unsubscribed holds until it
 *   is turned back on, then cancels if the trigger is still absent.
 * - `unknown`: no such rule for this tenant; callers keep their existing not-deliverable handling.
 */
export const NOTIFICATION_RULE_GATE = Object.freeze({
  DELIVER: 'deliver',
  HOLD: 'hold',
  CANCEL: 'cancel',
  UNKNOWN: 'unknown',
});

/** Non-sent terminal status recorded when a rule is removed with delivery still pending. */
export const NOTIFICATION_RULE_REMOVED_STATUS = 'cancelled_rule_removed';

/**
 * Non-sent terminal status recorded when a live rule dropped the event's trigger with delivery
 * still pending (outbox, retry, or DLQ).
 */
export const NOTIFICATION_RULE_UNSUBSCRIBED_STATUS = 'cancelled_rule_unsubscribed';

/** Status reported (never persisted) for due work held because its rule is turned off. */
export const NOTIFICATION_RULE_HELD_STATUS = 'held_rule_disabled';

/** Every non-sent terminal status the lifecycle gate can record. */
export const NOTIFICATION_RULE_CANCELLED_STATUSES = Object.freeze([
  NOTIFICATION_RULE_REMOVED_STATUS,
  NOTIFICATION_RULE_UNSUBSCRIBED_STATUS,
]);

const RULE_REMOVED_CANCELLATION = Object.freeze({
  status: NOTIFICATION_RULE_REMOVED_STATUS,
  reason: 'rule_removed',
});

const RULE_UNSUBSCRIBED_CANCELLATION = Object.freeze({
  status: NOTIFICATION_RULE_UNSUBSCRIBED_STATUS,
  reason: 'rule_unsubscribed',
});

/**
 * True when the rule's live trigger list no longer contains `trigger`. Unknown inputs (no event
 * trigger, or a rule record without a `triggers` array) are treated as still subscribed so legacy
 * callers keep the enabled/deleted-only behavior.
 * @param {Record<string, unknown>} rule
 * @param {unknown} trigger
 */
function ruleUnsubscribedFromTrigger(rule, trigger) {
  if (typeof trigger !== 'string' || !trigger) return false;
  if (!Array.isArray(rule.triggers)) return false;
  return !rule.triggers.includes(trigger);
}

/**
 * Lifecycle gate plus the terminal attempt shape to record when the gate is `cancel`.
 * @param {{ enabled?: boolean, deleted_at?: string | null, triggers?: string[] } | null | undefined} rule
 * @param {{ trigger?: string | null }} [options] event trigger the pending work was enqueued for
 * @returns {{ gate: string, cancellation: { status: string, reason: string } | null }}
 */
export function evaluateNotificationRuleDeliveryGate(rule, options = {}) {
  if (!rule || typeof rule !== 'object') return { gate: NOTIFICATION_RULE_GATE.UNKNOWN, cancellation: null };
  if (rule.deleted_at) return { gate: NOTIFICATION_RULE_GATE.CANCEL, cancellation: RULE_REMOVED_CANCELLATION };
  // `enabled` is checked first so every path agrees with the SQL held predicate (a turned-off rule's
  // work is never listed): an off rule holds, and the trigger check runs once it is back on.
  if (rule.enabled === false) return { gate: NOTIFICATION_RULE_GATE.HOLD, cancellation: null };
  // Unsubscribed work is cancelled, not held, so it is NOT filtered out of the due/DLQ list SQL:
  // the gate closes it with one terminal write and it never occupies the work budget again.
  if (ruleUnsubscribedFromTrigger(rule, options.trigger)) {
    return { gate: NOTIFICATION_RULE_GATE.CANCEL, cancellation: RULE_UNSUBSCRIBED_CANCELLATION };
  }
  return { gate: NOTIFICATION_RULE_GATE.DELIVER, cancellation: null };
}

/**
 * @param {{ enabled?: boolean, deleted_at?: string | null, triggers?: string[] } | null | undefined} rule
 * @param {{ trigger?: string | null }} [options] event trigger; when given, a rule that no longer
 *   subscribes to it is `cancel`
 */
export function notificationRuleDeliveryGate(rule, options = {}) {
  return evaluateNotificationRuleDeliveryGate(rule, options).gate;
}

/**
 * Current rule state for one attempt, read as late as possible. `resolveRule` (a fresh tenant-
 * scoped read that includes soft-deleted rules) wins over the `rulesById` snapshot. Pass the
 * event's `trigger` so a rule that dropped it is cancelled instead of sent to.
 * @param {{
 *   ruleId: string,
 *   trigger?: string | null,
 *   rulesById?: Map<string, Record<string, unknown>>,
 *   resolveRule?: (ruleId: string) => Promise<Record<string, unknown> | null> | Record<string, unknown> | null,
 * }} input
 * @returns {Promise<{ rule: Record<string, unknown> | undefined, gate: string, cancellation: { status: string, reason: string } | null }>}
 */
export async function resolveNotificationRuleForDelivery(input) {
  const rule = typeof input.resolveRule === 'function'
    ? await input.resolveRule(input.ruleId)
    : input.rulesById?.get(input.ruleId);
  const { gate, cancellation } = evaluateNotificationRuleDeliveryGate(rule, { trigger: input.trigger });
  return { rule: rule ?? undefined, gate, cancellation };
}

/**
 * Reason on the pending attempt an immediate emit records when its rule is disabled at send time
 * (mirrors `OUTBOX_PENDING_REASON` in notificationServiceAdapters.mjs / notificationRepository.mjs).
 */
const IMMEDIATE_HELD_PENDING_REASON = 'outbox_pending_delivery';

/**
 * Resumable pending attempt for an immediate emit whose rule is disabled (R01 hold). Nothing is
 * sent now; the retry worker delivers it once the rule is re-enabled — the held predicate keeps
 * it out of the due list while the rule stays off, exactly like outbox-enqueued pending work.
 */
function buildHeldPendingAttempt(attempt, now) {
  return {
    ...attempt,
    status: 'provider_retry_scheduled',
    reason: IMMEDIATE_HELD_PENDING_REASON,
    attempted_at: null,
    attempt_number: 0,
    max_attempts: Number(attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS),
    next_retry_at: now,
    exhausted: false,
  };
}

/**
 * Immediate-emit delivery with the live rule gate (R01). The emit callers read their rule list
 * once, then finalize sends to it; a rule disabled or removed in between would still receive the
 * send. When a `resolveRule` (a fresh tenant-scoped read that includes soft-deleted rules) is
 * supplied, every outbound attempt is re-gated on the live rule right before its send:
 *
 * - `deliver`: sent by `finalizeNotificationDeliveryAttempts` with the live rule (fresh
 *   destination), not the caller's snapshot copy.
 * - `hold`: rule turned off — nothing is sent; a resumable pending attempt is recorded so the
 *   retry worker delivers it when the rule is re-enabled.
 * - `cancel`: rule removed or unsubscribed from the trigger — the terminal non-sent cancellation
 *   attempt is recorded (no channel needed, same as the retry and redrive paths).
 * - `unknown`: the live rule cannot be resolved — the send is skipped and the initial queued
 *   attempt stands (fail closed).
 *
 * In-app attempts are not gated: recording in the tenant feed is not an outbound send, and a
 * pending in-app row has no worker to resume it. Without a `resolveRule` (legacy callers and
 * repositories without a live rule read) the snapshot behavior is kept unchanged.
 * @param {{
 *   deliveryMode: string,
 *   attempts: Array<Record<string, unknown>>,
 *   rules: Array<Record<string, unknown>>,
 *   event: Record<string, unknown>,
 *   now: string,
 *   resolveRule?: (ruleId: string) => Promise<Record<string, unknown> | null> | Record<string, unknown> | null,
 *   webhookSender?: Function,
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: Function,
 *   slackDeliverer?: Function,
 *   teamsDeliverer?: Function,
 * }} input
 */
export async function finalizeGatedNotificationDeliveryAttempts(input) {
  if (typeof input?.resolveRule !== 'function') {
    return finalizeNotificationDeliveryAttempts(input);
  }
  const rulesById = new Map((input.rules ?? []).map((r) => [r.id, r]));
  const trigger = typeof input.event?.trigger === 'string' ? input.event.trigger : null;
  const out = [];
  for (const attempt of input.attempts ?? []) {
    if (attempt?.channel === 'in_app' || !attempt?.rule_id) {
      out.push(...await finalizeNotificationDeliveryAttempts({ ...input, attempts: [attempt] }));
      continue;
    }
    const { rule, gate, cancellation } = await resolveNotificationRuleForDelivery({
      ruleId: String(attempt.rule_id),
      trigger,
      rulesById,
      resolveRule: input.resolveRule,
    });
    if (gate === NOTIFICATION_RULE_GATE.CANCEL) {
      out.push(buildRuleRemovedCancellationAttempt({
        attempt,
        now: input.now,
        newAttemptId: attempt.id,
        cancellation,
      }));
      continue;
    }
    if (gate === NOTIFICATION_RULE_GATE.HOLD) {
      out.push(buildHeldPendingAttempt(attempt, input.now));
      continue;
    }
    if (gate === NOTIFICATION_RULE_GATE.UNKNOWN) {
      out.push(attempt);
      continue;
    }
    out.push(...await finalizeNotificationDeliveryAttempts({
      ...input,
      attempts: [attempt],
      rules: rule ? [rule] : input.rules,
    }));
  }
  return out;
}

/**
 * Terminal, non-sent attempt closing pending work for a removed (or trigger-unsubscribed) rule.
 * `attempted_at` stays null (no send happened); the attempt number advances only so the ledger
 * orders it after the pending row it supersedes, like a metadata-only retry step.
 * `cancellation` comes from the gate result and defaults to the removed-rule shape.
 * @param {{
 *   attempt: Record<string, unknown>,
 *   now: string,
 *   newAttemptId: string,
 *   cancellation?: { status: string, reason: string } | null,
 * }} input
 */
export function buildRuleRemovedCancellationAttempt(input) {
  const cancellation = input.cancellation ?? RULE_REMOVED_CANCELLATION;
  return {
    id: input.newAttemptId,
    rule_id: input.attempt.rule_id,
    channel: input.attempt.channel,
    destination_preview: input.attempt.destination_preview,
    status: cancellation.status,
    reason: cancellation.reason,
    created_at: input.now,
    attempted_at: null,
    attempt_number: Number(input.attempt.attempt_number ?? 0) + 1,
    max_attempts: Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS),
    next_retry_at: null,
    exhausted: true,
  };
}

/** @param {Record<string, unknown>} record */
function markNetworkSendAttempted(record) {
  Object.defineProperty(record, 'network_send_attempted', {
    value: true,
    enumerable: false,
    configurable: true,
  });
  return record;
}

function addMs(iso, ms) {
  return new Date(new Date(iso).getTime() + ms).toISOString();
}

/**
 * @param {Record<string, unknown>} attempt
 * @param {number} asOfMs
 */
export function isNotificationRetryDue(attempt, asOfMs) {
  if (attempt.status !== 'provider_retry_scheduled') return false;
  const nextRetryAt = attempt.next_retry_at;
  if (typeof nextRetryAt !== 'string') return false;
  const dueMs = new Date(nextRetryAt).getTime();
  return Number.isFinite(dueMs) && dueMs <= asOfMs;
}

/**
 * Latest delivery attempt per rule_id on an event (array order wins).
 *
 * @param {{ delivery_attempts?: Array<Record<string, unknown>> }} event
 */
export function latestDeliveryAttemptsByRule(event) {
  const attempts = Array.isArray(event.delivery_attempts) ? event.delivery_attempts : [];
  /** @type {Map<string, Record<string, unknown>>} */
  const latestByRule = new Map();
  for (const attempt of attempts) {
    if (!attempt || typeof attempt !== 'object') continue;
    const ruleId = attempt.rule_id;
    if (typeof ruleId !== 'string' || !ruleId) continue;
    latestByRule.set(ruleId, attempt);
  }
  return latestByRule;
}

/**
 * @param {Array<Record<string, unknown>>} events
 * @param {string} asOf
 */
export function collectDueNotificationRetries(events, asOf) {
  const asOfMs = new Date(asOf).getTime();
  if (!Number.isFinite(asOfMs)) {
    throw new Error('notification retry: invalid as-of timestamp.');
  }

  /** @type {{ event: Record<string, unknown>, attempt: Record<string, unknown> }[]} */
  const due_items = [];
  let scheduled_not_due = 0;

  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    for (const attempt of latestDeliveryAttemptsByRule(event).values()) {
      if (attempt.status !== 'provider_retry_scheduled') continue;
      if (!isNotificationRetryDue(attempt, asOfMs)) {
        scheduled_not_due += 1;
        continue;
      }
      due_items.push({ event, attempt });
    }
  }

  return {
    due_items,
    scheduled_not_due,
    due_count: due_items.length,
  };
}

/**
 * Metadata-only retry progression (no outbound provider I/O).
 *
 * @param {{
 *   attempt: Record<string, unknown>,
 *   now: string,
 *   newAttemptId: string,
 * }} input
 */
export function buildMetadataOnlyRetryDeliveryAttempt(input) {
  const attemptNumber = Number(input.attempt.attempt_number ?? 1) + 1;
  const maxAttempts = Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS);

  const base = {
    id: input.newAttemptId,
    rule_id: input.attempt.rule_id,
    channel: input.attempt.channel,
    destination_preview: input.attempt.destination_preview,
    created_at: input.now,
    attempted_at: input.now,
    attempt_number: attemptNumber,
    max_attempts: maxAttempts,
  };

  if (attemptNumber >= maxAttempts) {
    return {
      ...base,
      status: 'provider_failed_dlq',
      reason: input.attempt.provider_error ?? 'retry_exhausted_metadata_only',
      provider_error: input.attempt.provider_error ?? 'retry_exhausted_metadata_only',
      exhausted: true,
    };
  }

  return {
    ...base,
    status: 'provider_retry_scheduled',
    reason: input.attempt.provider_error ?? 'retry_planned_metadata_only',
    provider_error: input.attempt.provider_error ?? 'retry_planned_metadata_only',
    next_retry_at: addMs(input.now, NOTIFICATION_RETRY_BACKOFF_MS),
    exhausted: false,
  };
}

function buildRetryAttemptBase(input, channel) {
  const attemptNumber = Number(input.attempt.attempt_number ?? 1) + 1;
  const maxAttempts = Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS);
  const rule = input.rule ?? { id: String(input.attempt.rule_id ?? ''), channel, destination: '' };

  return {
    id: input.newAttemptId,
    rule_id: input.attempt.rule_id,
    channel: input.attempt.channel,
    destination_preview:
      input.attempt.destination_preview ??
      destinationPreview(rule.channel, rule.destination),
    created_at: input.now,
    attempted_at: input.now,
    attempt_number: attemptNumber,
    max_attempts: maxAttempts,
  };
}

function retryChannelNotSupported(base) {
  return {
    ...base,
    status: 'provider_failed_dlq',
    reason: 'retry_channel_not_supported',
    provider_error: 'retry_channel_not_supported',
    exhausted: true,
  };
}

/**
 * @param {Record<string, unknown>} base
 * @param {Record<string, unknown>} result
 * @param {string} now
 */
function mapRetryProviderDeliveryResult(base, result, now) {
  if (result.status === 'queued_provider_not_configured') {
    return {
      ...base,
      status: 'queued_provider_not_configured',
      reason: result.reason,
    };
  }

  if (result.status === 'delivered_provider') {
    return markNetworkSendAttempted({
      ...base,
      status: 'delivered_provider',
      reason: result.reason,
      provider_status: result.provider_status ?? null,
    });
  }

  if (result.status === 'provider_retry_scheduled') {
    return markNetworkSendAttempted({
      ...base,
      status: 'provider_retry_scheduled',
      reason: result.reason,
      provider_error: result.provider_error ?? result.reason,
      next_retry_at: addMs(now, NOTIFICATION_RETRY_BACKOFF_MS),
      exhausted: false,
    });
  }

  return markNetworkSendAttempted({
    ...base,
    status: 'provider_failed_dlq',
    reason: result.reason,
    provider_error: result.provider_error ?? result.reason,
    exhausted: true,
  });
}

/**
 * @param {{
 *   attempt: Record<string, unknown>,
 *   event: { id: string, trigger: string, subject: string, metadata: Record<string, unknown>, created_at: string },
 *   rule: { id: string, channel: string, destination: string },
 *   now: string,
 *   newAttemptId: string,
 *   expectedChannel: string,
 *   deliver: () => Promise<Record<string, unknown>> | Record<string, unknown>,
 * }} input
 */
async function buildAdapterRetryDeliveryAttempt(input) {
  const base = buildRetryAttemptBase(input, input.expectedChannel);
  if (input.attempt.channel !== input.expectedChannel || !input.rule?.destination) {
    return retryChannelNotSupported(base);
  }

  const result = await input.deliver();
  return mapRetryProviderDeliveryResult(base, result, input.now);
}

/**
 * @param {{
 *   attempt: Record<string, unknown>,
 *   event: { id: string, trigger: string, subject: string, metadata: Record<string, unknown>, created_at: string },
 *   rule: { id: string, channel: string, destination: string },
 *   now: string,
 *   newAttemptId: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => Promise<{ ok: boolean, error?: string, status?: number }> | { ok: boolean, error?: string, status?: number },
 *   fetchFn?: typeof fetch,
 * }} input
 */
export async function buildWebhookRetryDeliveryAttempt(input) {
  const base = buildRetryAttemptBase(input, 'webhook');
  const maxAttempts = Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS);
  const attemptNumber = Number(base.attempt_number ?? maxAttempts);

  if (input.attempt.channel !== 'webhook' || !input.rule?.destination) {
    return retryChannelNotSupported(base);
  }

  const body = buildWebhookNotificationBody({
    event_id: input.event.id,
    rule_id: input.attempt.rule_id,
    trigger: input.event.trigger,
    subject: input.event.subject,
    metadata: input.event.metadata,
    created_at: input.event.created_at,
  });
  const encoded = encodeWebhookPayload(body);
  if (!encoded.ok) {
    return {
      ...base,
      status: 'provider_failed_dlq',
      reason: encoded.error,
      provider_error: encoded.error,
      exhausted: true,
    };
  }

  let sendResult;
  if (typeof input.webhookSender === 'function') {
    sendResult = await input.webhookSender(input.rule.destination, body);
  } else {
    sendResult = await sendWebhookNotification(input.rule.destination, encoded.json, {
      fetchFn: input.fetchFn,
    });
  }

  if (sendResult?.ok) {
    return markNetworkSendAttempted({
      ...base,
      status: 'delivered_provider',
      reason: 'webhook_delivered',
      provider_status: sendResult.status ?? null,
    });
  }

  const retryable = attemptNumber < maxAttempts;
  const providerError = sendResult?.error ?? 'webhook_send_failed';
  if (retryable) {
    return markNetworkSendAttempted({
      ...base,
      status: 'provider_retry_scheduled',
      reason: providerError,
      provider_error: providerError,
      next_retry_at: addMs(input.now, NOTIFICATION_RETRY_BACKOFF_MS),
      exhausted: false,
    });
  }

  return markNetworkSendAttempted({
    ...base,
    status: 'provider_failed_dlq',
    reason: providerError,
    provider_error: providerError,
    exhausted: true,
  });
}

/**
 * @param {{
 *   deliveryMode: string,
 *   event: Record<string, unknown>,
 *   attempt: Record<string, unknown>,
 *   rulesById: Map<string, { id: string, channel: string, destination: string }>,
 *   now: string,
 *   newAttemptId: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: (envelope: { from: string, to: string, subject: string, html_body: string }) => unknown,
 *   slackDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 *   teamsDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 * }} input
 */
export async function buildRetryDeliveryAttempt(input) {
  const rule = input.rulesById.get(String(input.attempt.rule_id ?? ''));
  const eventPayload = {
    id: String(input.event.id ?? ''),
    trigger: String(input.event.trigger ?? ''),
    subject:
      typeof input.event.subject === 'string' ? input.event.subject : String(input.event.subject ?? ''),
    metadata:
      input.event.metadata && typeof input.event.metadata === 'object' && !Array.isArray(input.event.metadata)
        ? input.event.metadata
        : {},
    created_at: String(input.event.created_at ?? input.now),
  };

  const modes = parseNotificationDeliveryModes(input.deliveryMode);
  const channel = String(input.attempt.channel ?? '');
  const ruleRecord = rule ?? { id: String(input.attempt.rule_id ?? ''), channel, destination: '' };
  const retryInput = {
    attempt: input.attempt,
    event: eventPayload,
    rule: ruleRecord,
    now: input.now,
    newAttemptId: input.newAttemptId,
  };

  if (channel === 'webhook' && isDeliveryChannelActive(modes, 'webhook')) {
    return buildWebhookRetryDeliveryAttempt({
      ...retryInput,
      webhookSender: input.webhookSender,
      fetchFn: input.fetchFn,
    });
  }

  if (channel === 'email' && isDeliveryChannelActive(modes, 'email')) {
    const deliverer = input.emailDeliverer ?? deliverEmail;
    return buildAdapterRetryDeliveryAttempt({
      ...retryInput,
      expectedChannel: 'email',
      deliver: () => deliverer(buildEmailPayload(eventPayload, ruleRecord)),
    });
  }

  if (channel === 'slack' && isDeliveryChannelActive(modes, 'slack')) {
    const deliverer =
      input.slackDeliverer ??
      ((payload, destination) => deliverSlack(payload, destination, { fetchFn: input.fetchFn }));
    return buildAdapterRetryDeliveryAttempt({
      ...retryInput,
      expectedChannel: 'slack',
      deliver: () => deliverer(buildSlackPayload(eventPayload, ruleRecord), ruleRecord.destination),
    });
  }

  if (channel === 'teams' && isDeliveryChannelActive(modes, 'teams')) {
    const deliverer =
      input.teamsDeliverer ??
      ((payload, destination) => deliverTeams(payload, destination, { fetchFn: input.fetchFn }));
    return buildAdapterRetryDeliveryAttempt({
      ...retryInput,
      expectedChannel: 'teams',
      deliver: () => deliverer(buildTeamsPayload(eventPayload, ruleRecord), ruleRecord.destination),
    });
  }

  return buildMetadataOnlyRetryDeliveryAttempt({
    attempt: input.attempt,
    now: input.now,
    newAttemptId: input.newAttemptId,
  });
}

/**
 * @param {{
 *   deliveryMode: string,
 *   events: Array<Record<string, unknown>>,
 *   rules: Array<{ id: string, channel: string, destination: string, enabled?: boolean, deleted_at?: string | null }>,
 *   resolveRule?: (ruleId: string) => Promise<Record<string, unknown> | null> | Record<string, unknown> | null,
 *   asOf: string,
 *   now?: string,
 *   dryRun?: boolean,
 *   newAttemptId?: (eventId: string, ruleId: string, attemptNumber: number) => string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: (envelope: { from: string, to: string, subject: string, html_body: string }) => unknown,
 *   slackDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 *   teamsDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 * }} input
 */
export async function processDueNotificationRetryBatch(input) {
  const now = input.now ?? input.asOf;
  const dryRun = input.dryRun === true;
  const collected = collectDueNotificationRetries(input.events, input.asOf);
  const rulesById = new Map(input.rules.map((rule) => [rule.id, rule]));

  const newAttemptId =
    input.newAttemptId ??
    ((eventId, ruleId, attemptNumber) => `nretry_${eventId}_${ruleId}_${attemptNumber}`);

  /** @type {Record<string, unknown>[]} */
  const processed = [];
  let network_sends_performed = 0;
  let held_count = 0;
  let cancelled_count = 0;

  for (const { event, attempt } of collected.due_items) {
    const nextAttemptNumber = Number(attempt.attempt_number ?? 1) + 1;
    const ruleId = String(attempt.rule_id ?? '');
    // Lifecycle gate, re-read per item right before its send.
    const { rule: liveRule, gate, cancellation } = await resolveNotificationRuleForDelivery({
      ruleId,
      trigger: typeof event.trigger === 'string' ? event.trigger : null,
      rulesById,
      resolveRule: input.resolveRule,
    });

    if (gate === NOTIFICATION_RULE_GATE.HOLD) {
      held_count += 1;
      processed.push({
        event_id: event.id ?? null,
        attempt_id: attempt.id ?? null,
        rule_id: attempt.rule_id ?? null,
        channel: attempt.channel ?? null,
        status: NOTIFICATION_RULE_HELD_STATUS,
        prior_status: attempt.status ?? null,
        prior_attempt_number: attempt.attempt_number ?? 1,
        dry_run: dryRun,
      });
      continue;
    }

    if (gate === NOTIFICATION_RULE_GATE.CANCEL) {
      cancelled_count += 1;
      if (dryRun) {
        processed.push({
          event_id: event.id ?? null,
          attempt_id: attempt.id ?? null,
          rule_id: attempt.rule_id ?? null,
          channel: attempt.channel ?? null,
          status: cancellation?.status ?? NOTIFICATION_RULE_REMOVED_STATUS,
          prior_status: attempt.status ?? null,
          dry_run: true,
        });
        continue;
      }
      const record = buildRuleRemovedCancellationAttempt({
        attempt,
        now,
        newAttemptId: newAttemptId(String(event.id ?? ''), ruleId, nextAttemptNumber),
        cancellation,
      });
      processed.push({
        event_id: event.id ?? null,
        attempt_id: record.id,
        rule_id: record.rule_id ?? null,
        channel: record.channel ?? null,
        status: record.status,
        prior_status: attempt.status ?? null,
        prior_attempt_id: attempt.id ?? null,
        attempt_number: record.attempt_number,
        max_attempts: record.max_attempts,
        next_retry_at: null,
        exhausted: true,
        dry_run: false,
        delivery_record: record,
      });
      continue;
    }

    if (dryRun) {
      processed.push({
        event_id: event.id ?? null,
        attempt_id: attempt.id ?? null,
        rule_id: attempt.rule_id ?? null,
        channel: attempt.channel ?? null,
        status: 'retry_due',
        prior_status: attempt.status ?? null,
        prior_attempt_number: attempt.attempt_number ?? 1,
        next_attempt_number: nextAttemptNumber,
        dry_run: true,
      });
      continue;
    }

    const record = await buildRetryDeliveryAttempt({
      deliveryMode: input.deliveryMode,
      event,
      attempt,
      // Deliver against the rule state just read, not the earlier snapshot.
      rulesById: liveRule ? new Map([[ruleId, liveRule]]) : new Map(),
      now,
      newAttemptId: newAttemptId(String(event.id ?? ''), String(attempt.rule_id ?? ''), nextAttemptNumber),
      webhookSender: input.webhookSender,
      fetchFn: input.fetchFn,
      emailDeliverer: input.emailDeliverer,
      slackDeliverer: input.slackDeliverer,
      teamsDeliverer: input.teamsDeliverer,
    });

    if (record.network_send_attempted === true) {
      network_sends_performed += 1;
    }

    processed.push({
      event_id: event.id ?? null,
      attempt_id: record.id,
      rule_id: record.rule_id ?? null,
      channel: record.channel ?? null,
      status: record.status,
      prior_status: attempt.status ?? null,
      prior_attempt_id: attempt.id ?? null,
      attempt_number: record.attempt_number ?? null,
      max_attempts: record.max_attempts ?? null,
      next_retry_at: record.next_retry_at ?? null,
      exhausted: record.exhausted ?? null,
      dry_run: false,
      delivery_record: record,
    });
  }

  return {
    as_of: input.asOf,
    delivery_mode: input.deliveryMode,
    dry_run: dryRun,
    due_count: collected.due_count,
    scheduled_not_due_count: collected.scheduled_not_due,
    held_count,
    cancelled_count,
    processed,
    network_sends_performed: dryRun ? 0 : network_sends_performed,
  };
}
