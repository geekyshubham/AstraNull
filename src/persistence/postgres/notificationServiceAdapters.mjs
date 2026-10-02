import { randomUUID } from 'node:crypto';
import { newId } from '../../lib/ids.mjs';
import { incMetric } from '../../lib/metrics.mjs';
import { redactString } from '../../lib/redact.mjs';
import {
  WEBHOOK_MAX_ATTEMPTS,
  isDeliveryChannelActive,
  parseNotificationDeliveryModes,
  resolveNotificationDeliveryMode,
} from '../../lib/notificationDelivery.mjs';
import {
  NOTIFICATION_RETRY_BACKOFF_MS,
  NOTIFICATION_RULE_GATE,
  NOTIFICATION_RULE_HELD_STATUS,
  NOTIFICATION_RULE_REMOVED_STATUS,
  buildRetryDeliveryAttempt,
  buildRuleRemovedCancellationAttempt,
  finalizeGatedNotificationDeliveryAttempts,
  processDueNotificationRetryBatch,
  resolveNotificationRuleForDelivery,
} from '../../lib/notificationRetry.mjs';
import {
  processClaimedNotificationDlqRedrive,
  processNotificationDlqRedriveBatch,
  resolveDlqRedriveDeliveryMode,
} from '../../lib/notificationDlqRedrive.mjs';
import {
  buildNotificationDeliveryAttempt,
  buildRedactedNotificationEventPayload,
  formatNotificationRuleForRead,
  normalizeNotificationRuleInput,
  notificationDeliveryNote,
} from '../../lib/notifications.mjs';
import {
  formatLatestDeliveryForRead,
  normalizeNotificationRuleUpdate,
  notificationRuleUpdateAuditMetadata,
} from '../../lib/notificationRuleUpdate.mjs';

/** @type {readonly string[]} */
export const NOTIFICATION_REPOSITORY_METHODS = Object.freeze([
  'listNotificationRules',
  'listNotificationEvents',
  'createNotificationRule',
  'appendNotificationEvent',
  'appendDeliveryAttempts',
]);

/**
 * Rule lifecycle and authoritative latest-delivery reads. Optional on the repository so older
 * stubs keep constructing; the service answers 503 postgres_route_not_wired when one is absent.
 * @type {readonly string[]}
 */
export const NOTIFICATION_RULE_LIFECYCLE_REPOSITORY_METHODS = Object.freeze([
  'getNotificationRule',
  'updateNotificationRule',
  'deleteNotificationRule',
  'listLatestDeliveryAttemptsByRule',
]);

/**
 * Shared delivery-ownership reads/writes (migration 0061). When all are present, the in-process
 * outbox worker and due-retry recovery both claim an attempt in Postgres before any send.
 * Optional so older stubs keep the legacy (unclaimed) path.
 * @type {readonly string[]}
 */
export const NOTIFICATION_DELIVERY_CLAIM_REPOSITORY_METHODS = Object.freeze([
  'listDueDeliveryAttempts',
  'claimDeliveryAttempt',
  'completeDeliveryAttemptClaim',
  'releaseDeliveryAttemptClaim',
]);

/**
 * Claim-aware DLQ redrive reads/writes. With these (plus the delivery-claim methods), redrive reads
 * DLQ candidates straight from the attempt ledger and claims each row before any send.
 * @type {readonly string[]}
 */
export const NOTIFICATION_DLQ_CLAIM_REPOSITORY_METHODS = Object.freeze([
  'listDlqDeliveryAttempts',
  'claimDlqDeliveryAttempt',
]);

/** Size of the recent-events feed returned by GET /v1/notifications. */
export const POSTGRES_NOTIFICATION_EVENTS_WINDOW = 100;

/** @type {readonly string[]} */
export const POSTGRES_NOTIFICATION_SERVICE_METHODS = Object.freeze([
  'listNotifications',
  'createNotificationRule',
  'updateNotificationRule',
  'deleteNotificationRule',
  'emitNotification',
  'processDueNotificationRetries',
  'redriveNotificationDlq',
]);

const NOT_WIRED = Object.freeze({ error: 'postgres_route_not_wired', status: 503 });

function assertNotificationRepositories(repositories) {
  const notifications = repositories?.notifications;
  if (!notifications || typeof notifications !== 'object') {
    throw new Error('Postgres notification service adapter requires repositories.notifications.');
  }
  for (const method of NOTIFICATION_REPOSITORY_METHODS) {
    if (typeof notifications[method] !== 'function') {
      throw new Error(`Postgres notification service adapter requires notifications.${method}().`);
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit !== 'object') {
    throw new Error('Postgres notification service adapter requires repositories.audit.');
  }
  if (typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres notification service adapter requires audit.appendAuditEvent().');
  }
}

/** Reason recorded on an outbox attempt that is durably queued but not yet sent. */
export const OUTBOX_PENDING_REASON = 'outbox_pending_delivery';

/**
 * Delay before a pending outbox attempt becomes due for recovery. It only gives the in-process
 * worker the first chance to send (avoiding wasted recovery work); it is NOT proof that a job was
 * abandoned. Ownership is decided by the Postgres delivery claim/lease, so a recovery tick never
 * sends an attempt that a healthy worker has claimed, however long that worker has been queued.
 */
export const OUTBOX_RECOVERY_GRACE_MS = 5 * NOTIFICATION_RETRY_BACKOFF_MS;

/**
 * Lease held by a sender on one claimed attempt. Much longer than one bounded provider call
 * (adapter timeouts are 10s), because each attempt is claimed right before its own send. An
 * expired lease means the owner died mid-send; the attempt becomes reclaimable.
 */
export const NOTIFICATION_DELIVERY_LEASE_MS = 2 * 60_000;

/** Recovery drain per tick: page size and total work budget (oldest due first). */
export const NOTIFICATION_RECOVERY_PAGE_SIZE = 100;
export const NOTIFICATION_RECOVERY_MAX_ITEMS = 1000;
/** Read bound for deferred rows an older repository returns unfiltered (not part of the work budget). */
export const NOTIFICATION_RECOVERY_MAX_DEFERRED_SCAN = 100_000;

function boundedInt(value, min, max, fallback) {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n < min) return fallback;
  return Math.min(n, max);
}

const DEFAULT_OUTBOX_CONCURRENCY = 2;
const DEFAULT_OUTBOX_MAX_QUEUE = 1000;

function addMs(iso, ms) {
  return new Date(new Date(iso).getTime() + ms).toISOString();
}

/**
 * Initial attempt for an outbox event. In-app and inactive provider channels are final at enqueue
 * time (no outbound I/O). An active provider channel is recorded as a pending retry
 * (attempt_number 0, due after the recovery grace) so the existing retry worker delivers it if
 * the in-process worker never does; the first real send becomes attempt 1. `recoveryDelayMs` 0
 * makes it due immediately, for events handed to the recovery drain instead of the worker.
 *
 * `modes` null means "do not decide channel activity here": every provider channel with a
 * destination is recorded pending. Reconciliation uses this because the recovering process's
 * delivery mode (the scheduler defaults to metadata_only) need not match the mode the emitting API
 * would have used; finalizing there would silently turn an owed provider send into a terminal
 * `queued_provider_not_configured`. The pending row is instead delivered by the first recovery tick
 * whose mode enables its channel, and deferred (never claimed, never finalized) by any other tick.
 */
function buildOutboxDeliveryAttempt(eventId, rule, now, modes, recoveryDelayMs = OUTBOX_RECOVERY_GRACE_MS) {
  const base = buildNotificationDeliveryAttempt(eventId, rule, now);
  if (rule.channel === 'in_app' || !rule.destination) return base;
  if (modes && !isDeliveryChannelActive(modes, rule.channel)) return base;
  return {
    ...base,
    status: 'provider_retry_scheduled',
    reason: OUTBOX_PENDING_REASON,
    attempt_number: 0,
    max_attempts: WEBHOOK_MAX_ATTEMPTS,
    next_retry_at: addMs(now, recoveryDelayMs),
    exhausted: false,
    attempted_at: null,
  };
}

/**
 * Bounded in-process delivery queue. Jobs never run on the caller's awaited path; a full queue
 * drops the job (the durable pending attempt is still recovered by the retry worker).
 */
function createOutboxDeliveryWorker({ concurrency, maxQueue, deliver }) {
  const queue = [];
  let active = 0;
  const idleWaiters = [];

  function settleIdle() {
    if (active === 0 && queue.length === 0) {
      for (const resolve of idleWaiters.splice(0)) resolve();
    }
  }

  function pump() {
    while (active < concurrency && queue.length > 0) {
      const job = queue.shift();
      active += 1;
      setImmediate(() => {
        Promise.resolve()
          .then(() => deliver(job))
          .catch(() => incMetric('notification_outbox_delivery_failed'))
          .finally(() => {
            active -= 1;
            pump();
            settleIdle();
          });
      });
    }
  }

  return {
    schedule(job) {
      if (queue.length >= maxQueue) {
        incMetric('notification_outbox_queue_full');
        return false;
      }
      queue.push(job);
      pump();
      return true;
    },
    idle() {
      if (active === 0 && queue.length === 0) return Promise.resolve();
      return new Promise((resolve) => idleWaiters.push(resolve));
    },
  };
}

/**
 * @param {{
 *   notifications?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{
 *   now?: () => Date,
 *   newId?: typeof newId,
 *   deliveryMode?: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 * }} [options]
 */
export function createPostgresNotificationServices(repositories, options = {}) {
  assertNotificationRepositories(repositories);
  const notificationRepo = repositories.notifications;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  /**
   * Fresh per-attempt rule read for the lifecycle gate (includes soft-deleted rules so removal
   * cancels instead of looking unknown). There is deliberately no snapshot fallback: a claims-
   * capable repository without this read yields UNKNOWN gates (fail closed, no send), because a
   * `listNotificationRules` snapshot excludes soft-deleted rules and cannot tell a removed rule
   * from a missing one.
   */
  function liveRuleResolver(ctx) {
    if (typeof notificationRepo.getNotificationRuleDeliveryState !== 'function') return undefined;
    return (ruleId) => notificationRepo.getNotificationRuleDeliveryState(ctx, ruleId);
  }

  /** True when the repository supports shared delivery claims (migration 0061). */
  const claimsEnabled = NOTIFICATION_DELIVERY_CLAIM_REPOSITORY_METHODS.every(
    (method) => typeof notificationRepo[method] === 'function',
  );
  const instanceId = String(options.instanceId ?? `nsvc_${randomUUID()}`);
  const leaseMs = boundedInt(options.deliveryLeaseMs, 1, 60 * 60_000, NOTIFICATION_DELIVERY_LEASE_MS);

  function auditDeliveryRecord(ctx, eventId, record, extra) {
    return auditRepo.appendAuditEvent({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId ?? null,
      actor_role: ctx.role ?? null,
      action: 'notification.delivery_attempt_recorded',
      resource_type: 'notification_delivery_attempt',
      resource_id: record.id,
      metadata: {
        event_id: eventId,
        rule_id: record.rule_id,
        channel: record.channel,
        status: record.status,
        ...extra,
      },
    });
  }

  /**
   * Keep a claimed lease alive while its send is in flight, so a slow but live sender is never
   * mistaken for a dead one. Returns a stop function.
   */
  function startLeaseHeartbeat(ctx, attemptId, claimToken) {
    if (typeof notificationRepo.renewDeliveryAttemptClaim !== 'function') return () => {};
    const timer = setInterval(() => {
      Promise.resolve()
        .then(() => notificationRepo.renewDeliveryAttemptClaim(ctx, { attemptId, claimToken, leaseMs }))
        .catch(() => incMetric('notification_delivery_lease_renew_failed'));
    }, Math.max(10, Math.floor(leaseMs / 3)));
    timer.unref?.();
    return () => clearInterval(timer);
  }

  /**
   * Shared ownership protocol used by BOTH the in-process outbox worker and due-retry recovery:
   *
   * 1. Atomically claim the attempt in Postgres (lease) before any external I/O. A lost claim
   *    means another sender owns it (or it is no longer pending): nothing is sent.
   * 2. Re-check eligibility after claiming: the rule lifecycle gate (hold releases the claim
   *    without writing; cancel records `cancelled_rule_removed`).
   * 3. Send while heartbeating the lease, then complete: supersede the claimed row and append the
   *    outcome in one transaction, only if this claim still owns it.
   *
   * An unexpected error after the claim keeps the lease until it expires, so an outcome that may
   * already have reached the provider is not immediately resent.
   * @returns {Promise<{ outcome: 'claim_lost' | 'held' | 'recorded' | 'lease_lost', record?: Record<string, unknown>, cancelled?: boolean }>}
   */
  async function deliverClaimedAttempt({ ctx, event, attempt, deliveryMode, dueBy, newAttemptId, senders }) {
    const claimToken = `${instanceId}:${randomUUID()}`;
    const claimed = await notificationRepo.claimDeliveryAttempt(ctx, {
      attemptId: attempt.id,
      claimToken,
      leaseMs,
      dueBy: dueBy ?? null,
    });
    if (!claimed) {
      incMetric('notification_delivery_claim_lost');
      return { outcome: 'claim_lost' };
    }

    // Ownership must hold over the ENTIRE post-claim interval, not just the send: a rule read
    // that outlasts the lease would let another sender reclaim, complete, and deliver first.
    const stopHeartbeat = startLeaseHeartbeat(ctx, claimed.id, claimToken);
    const ruleId = String(claimed.rule_id ?? '');
    let record;
    let cancelled = false;
    try {
      let gateResult;
      try {
        gateResult = await resolveNotificationRuleForDelivery({
          ruleId,
          trigger: typeof event.trigger === 'string' ? event.trigger : null,
          resolveRule: liveRuleResolver(ctx),
        });
      } catch (err) {
        await notificationRepo.releaseDeliveryAttemptClaim(ctx, { attemptId: claimed.id, claimToken }).catch(() => {});
        throw err;
      }
      const { rule, gate, cancellation } = gateResult;
      if (gate === NOTIFICATION_RULE_GATE.HOLD) {
        incMetric('notification_delivery_held_rule_disabled');
        // A transient release failure must not kill the tick after a clean hold decision; the
        // lease simply expires on its own.
        await notificationRepo.releaseDeliveryAttemptClaim(ctx, { attemptId: claimed.id, claimToken }).catch(() => {});
        return { outcome: 'held' };
      }

      if (gate === NOTIFICATION_RULE_GATE.CANCEL) {
        cancelled = true;
        record = buildRuleRemovedCancellationAttempt({ attempt: claimed, now: senders.now, newAttemptId, cancellation });
      } else {
        // Confirm ownership immediately before provider I/O: renewal returns `renewed: false`
        // when the lease expired and another sender took over (or the row was superseded).
        // A renewal that cannot be verified is treated as lost, never resent on a guess.
        let ownership = null;
        if (typeof notificationRepo.renewDeliveryAttemptClaim === 'function') {
          try {
            ownership = await notificationRepo.renewDeliveryAttemptClaim(ctx, { attemptId: claimed.id, claimToken, leaseMs });
          } catch {
            ownership = { renewed: false };
          }
          if (ownership?.renewed !== true) {
            incMetric('notification_delivery_lease_lost');
            return { outcome: 'lease_lost' };
          }
        }
        record = await buildRetryDeliveryAttempt({
          deliveryMode,
          event,
          attempt: claimed,
          rulesById: rule ? new Map([[ruleId, rule]]) : new Map(),
          now: senders.now,
          newAttemptId,
          webhookSender: senders.webhookSender,
          fetchFn: senders.fetchFn,
          emailDeliverer: senders.emailDeliverer,
          slackDeliverer: senders.slackDeliverer,
          teamsDeliverer: senders.teamsDeliverer,
        });
      }
    } finally {
      stopHeartbeat();
    }

    const completion = await notificationRepo.completeDeliveryAttemptClaim(ctx, {
      attemptId: claimed.id,
      claimToken,
      eventId: String(event.id),
      record,
    });
    if (!completion?.completed) {
      // Lease expired and another sender took over (or a newer attempt superseded it). That
      // sender records its own outcome; this one writes nothing.
      incMetric('notification_delivery_lease_lost');
      return { outcome: 'lease_lost', record, cancelled };
    }
    return { outcome: 'recorded', record, cancelled };
  }

  /**
   * Deliver one durably enqueued event's pending provider attempts. Runs off the caller's path.
   * Each attempt is claimed in Postgres first (dueBy unrestricted: the in-process worker may send
   * before the recovery delay), so a recovery tick can never send the same attempt concurrently.
   */
  async function deliverOutboxEventClaimed(job) {
    const { ctx, event, pendingAttempts } = job;
    const deliveryMode = resolveNotificationDeliveryMode(options);
    const recorded = [];
    for (const attempt of pendingAttempts) {
      const now = nowFn().toISOString();
      const result = await deliverClaimedAttempt({
        ctx,
        event,
        attempt,
        deliveryMode,
        dueBy: null,
        newAttemptId: `${attempt.id}_a${Number(attempt.attempt_number ?? 0) + 1}`,
        senders: { ...options, now },
      });
      if (result.outcome !== 'recorded' || !result.record) continue;
      recorded.push(result.record);
      await auditDeliveryRecord(ctx, event.id, result.record, { outbox: true });
    }
    if (recorded.length > 0 && typeof options.onOutboxDelivered === 'function') {
      options.onOutboxDelivered(event.id, recorded);
    }
  }

  /**
   * Legacy outbox delivery for repositories without delivery claims (older stubs). Production
   * Postgres always has claims; this path has no cross-sender ownership.
   */
  async function deliverOutboxEventLegacy(job) {
    const { ctx, event, pendingAttempts } = job;
    const deliveryMode = resolveNotificationDeliveryMode(options);
    const resolveRule = liveRuleResolver(ctx);
    const snapshot = resolveRule ? null : await notificationRepo.listNotificationRules(ctx);
    const rulesById = new Map((snapshot ?? []).map((r) => [r.id, r]));
    const now = nowFn().toISOString();
    const records = [];
    for (const attempt of pendingAttempts) {
      const ruleId = String(attempt.rule_id ?? '');
      const newAttemptId = `${attempt.id}_a${Number(attempt.attempt_number ?? 0) + 1}`;
      // Lifecycle gate right before the send: a rule turned off after enqueue is held (the
      // pending row stays due and the retry worker resumes it once re-enabled); a removed rule
      // is cancelled without sending.
      const { rule, gate, cancellation } = await resolveNotificationRuleForDelivery({
        ruleId,
        trigger: typeof event.trigger === 'string' ? event.trigger : null,
        rulesById,
        resolveRule,
      });
      if (gate === NOTIFICATION_RULE_GATE.HOLD) {
        incMetric('notification_delivery_held_rule_disabled');
        continue;
      }
      if (gate === NOTIFICATION_RULE_GATE.CANCEL) {
        records.push(buildRuleRemovedCancellationAttempt({ attempt, now, newAttemptId, cancellation }));
        continue;
      }
      const record = await buildRetryDeliveryAttempt({
        deliveryMode,
        event,
        attempt,
        rulesById: rule ? new Map([[ruleId, rule]]) : new Map(),
        now,
        newAttemptId,
        webhookSender: options.webhookSender,
        fetchFn: options.fetchFn,
        emailDeliverer: options.emailDeliverer,
        slackDeliverer: options.slackDeliverer,
        teamsDeliverer: options.teamsDeliverer,
      });
      records.push(record);
    }
    if (records.length === 0) return;
    await notificationRepo.appendDeliveryAttempts(ctx, event.id, records);
    for (const record of records) {
      await auditDeliveryRecord(ctx, event.id, record, { outbox: true });
    }
    if (typeof options.onOutboxDelivered === 'function') options.onOutboxDelivered(event.id, records);
  }

  async function deliverOutboxEvent(job) {
    if (!job.pendingAttempts.length) return;
    if (claimsEnabled) return deliverOutboxEventClaimed(job);
    return deliverOutboxEventLegacy(job);
  }

  /**
   * True when this tick cannot perform provider I/O for a durably queued outbox attempt: the
   * attempt still waits for its FIRST send (`outbox_pending_delivery`) and its channel is not active
   * in the tick's delivery mode. Such a tick must not claim it: claiming would take ownership from
   * the in-process worker (its later claim is lost) and walk the attempt to the DLQ through
   * metadata-only retries without any send ever being made. The row stays due for the worker or a
   * provider-capable recovery tick. A caller-supplied `asOf` therefore cannot pull a pending send
   * out from under the worker either.
   */
  function isOutboxPendingDeferred(attempt, modes) {
    if (attempt?.reason !== OUTBOX_PENDING_REASON) return false;
    return !isDeliveryChannelActive(modes, String(attempt.channel ?? ''));
  }

  /**
   * Due-retry recovery over the durable ledger (R02/R04). Pages through due attempts oldest-first
   * with a keyset cursor until the backlog is drained or the per-tick work budget is spent, and
   * delivers each one through the shared claim protocol. Outbox attempts still awaiting their first
   * send on a channel this tick cannot deliver are left untouched (`deferred_inactive_channel_count`).
   */
  async function processDueRetriesClaimed(ctx, retryOptions) {
    const asOf = retryOptions.asOf ?? nowFn().toISOString();
    const asOfMs = new Date(asOf).getTime();
    if (!Number.isFinite(asOfMs)) throw new Error('notification retry: invalid as-of timestamp.');
    const now = retryOptions.now ?? asOf;
    const dryRun = retryOptions.dryRun === true;
    const deliveryMode = resolveNotificationDeliveryMode(retryOptions);
    const activeModes = parseNotificationDeliveryModes(deliveryMode);
    const pageSize = boundedInt(retryOptions.pageSize, 1, 500, NOTIFICATION_RECOVERY_PAGE_SIZE);
    const maxItems = boundedInt(retryOptions.maxItems, 1, 100_000, NOTIFICATION_RECOVERY_MAX_ITEMS);
    // Separate scan bound for deferred rows a repository failed to filter in SQL (never charged
    // to `maxItems`, so they cannot starve deliverable work; this only bounds the tick's reads).
    const maxDeferredScan = boundedInt(retryOptions.maxDeferredScan, 1, 1_000_000, NOTIFICATION_RECOVERY_MAX_DEFERRED_SCAN);
    const resolveRule = liveRuleResolver(ctx);
    // Channels this tick can actually deliver. Outbox rows awaiting their first send on any other
    // channel are excluded in SQL so they never occupy page slots or the work budget (they would
    // otherwise sit at the head of the (next_retry_at, id) order every tick and starve due work).
    const activeChannels = [...activeModes].filter((channel) => isDeliveryChannelActive(activeModes, channel));

    const summary = typeof notificationRepo.summarizePendingDeliveryAttempts === 'function'
      ? await notificationRepo.summarizePendingDeliveryAttempts(ctx, { asOf, activeChannels })
      : { scheduled_not_due: 0, held_due: 0, in_flight: 0, deferred_inactive_channel: 0 };

    const processed = [];
    let examined = 0;
    let deferredScanned = 0;
    let pages = 0;
    let held_count = Number(summary.held_due ?? 0);
    let cancelled_count = 0;
    let claim_lost_count = 0;
    let lease_lost_count = 0;
    // A repository that reports this count also filters those rows out of listDueDeliveryAttempts.
    const summaryCountsDeferred = typeof summary.deferred_inactive_channel === 'number';
    let deferred_inactive_channel_count = summaryCountsDeferred ? summary.deferred_inactive_channel : 0;
    if (deferred_inactive_channel_count > 0) {
      incMetric('notification_retry_outbox_pending_deferred', deferred_inactive_channel_count);
    }
    let network_sends_performed = 0;
    let budget_exhausted = false;
    let cursor = null;

    outer: for (;;) {
      // Deferred rows a repository failed to filter get their own bound, never the work budget.
      // Only the work budget sets `budget_exhausted`; the deferred-scan bound just stops the reads.
      if (examined >= maxItems) {
        budget_exhausted = true;
        break;
      }
      if (deferredScanned >= maxDeferredScan) break;
      const limit = Math.min(pageSize, maxItems - examined);
      const page = await notificationRepo.listDueDeliveryAttempts(ctx, { asOf, limit, after: cursor, activeChannels });
      pages += 1;
      if (!Array.isArray(page) || page.length === 0) break;

      for (const { event, attempt } of page) {
        if (isOutboxPendingDeferred(attempt, activeModes)) {
          // Defensive: a repository that ignores `activeChannels` returned a row this tick may
          // not be able to deliver. Before deferring it, resolve the rule gate: a removed or
          // unsubscribed rule is a terminal cancellation that needs no channel, so it must be
          // closed by this tick (any tick) instead of pending forever behind an inactive
          // channel. Only work whose gate is still `deliver` is deferred: never claimed, never
          // written, not charged to `maxItems`; the cursor advances.
          const deferredGate = (await resolveNotificationRuleForDelivery({
            ruleId: String(attempt.rule_id ?? ''),
            trigger: typeof event.trigger === 'string' ? event.trigger : null,
            resolveRule,
          })).gate;
          if (deferredGate === NOTIFICATION_RULE_GATE.DELIVER) {
            deferredScanned += 1;
            // Count it even when the summary already reported deferred rows: a rule flipping
            // between the summary and this page read must not make the row vanish from the total.
            deferred_inactive_channel_count += 1;
            incMetric('notification_retry_outbox_pending_deferred');
            if (deferredScanned >= maxDeferredScan) break outer;
            continue;
          }
        }
        examined += 1;
        const base = {
          event_id: event.id ?? null,
          rule_id: attempt.rule_id ?? null,
          channel: attempt.channel ?? null,
          prior_status: attempt.status ?? null,
        };

        if (dryRun) {
          const { gate, cancellation } = await resolveNotificationRuleForDelivery({
            ruleId: String(attempt.rule_id ?? ''),
            trigger: typeof event.trigger === 'string' ? event.trigger : null,
            resolveRule,
          });
          if (gate === NOTIFICATION_RULE_GATE.CANCEL) {
            cancelled_count += 1;
          }
          if (gate === NOTIFICATION_RULE_GATE.HOLD) {
            // Report what the real run would do (hold without writing), matching the batch dry run.
            held_count += 1;
          }
          processed.push({
            ...base,
            attempt_id: attempt.id ?? null,
            status: gate === NOTIFICATION_RULE_GATE.CANCEL
              ? (cancellation?.status ?? NOTIFICATION_RULE_REMOVED_STATUS)
              : gate === NOTIFICATION_RULE_GATE.HOLD
                ? NOTIFICATION_RULE_HELD_STATUS
                : 'retry_due',
            prior_attempt_number: attempt.attempt_number ?? 1,
            next_attempt_number: Number(attempt.attempt_number ?? 1) + 1,
            dry_run: true,
          });
          continue;
        }

        const result = await deliverClaimedAttempt({
          ctx,
          event,
          attempt,
          deliveryMode,
          dueBy: asOf,
          newAttemptId: newIdFn('id'),
          senders: { ...retryOptions, now },
        });
        if (result.outcome === 'claim_lost') {
          claim_lost_count += 1;
          continue;
        }
        if (result.outcome === 'held') {
          held_count += 1;
          processed.push({
            ...base,
            attempt_id: attempt.id ?? null,
            status: NOTIFICATION_RULE_HELD_STATUS,
            prior_attempt_number: attempt.attempt_number ?? 1,
            dry_run: false,
          });
          continue;
        }
        const record = result.record;
        if (record.network_send_attempted === true) network_sends_performed += 1;
        if (result.outcome === 'lease_lost') {
          lease_lost_count += 1;
          continue;
        }
        if (result.cancelled) cancelled_count += 1;
        await auditDeliveryRecord(ctx, event.id, record, { retry: true });
        processed.push({
          ...base,
          attempt_id: record.id,
          status: record.status,
          prior_attempt_id: attempt.id ?? null,
          attempt_number: record.attempt_number ?? null,
          max_attempts: record.max_attempts ?? null,
          next_retry_at: record.next_retry_at ?? null,
          exhausted: record.exhausted ?? null,
          dry_run: false,
        });
      }

      const last = page.at(-1).attempt;
      // Keyset cursor at full database precision (see listDueDeliveryAttempts): a ms-truncated
      // timestamp would re-serve the boundary row and burn the tick's budget on it.
      cursor = { next_retry_at: String(last.next_retry_at_cursor ?? last.next_retry_at), id: last.id };
      if (page.length < limit) break;
    }

    return {
      tenant_id: ctx.tenantId,
      as_of: asOf,
      delivery_mode: deliveryMode,
      dry_run: dryRun,
      due_count: examined + Number(summary.held_due ?? 0),
      scheduled_not_due_count: Number(summary.scheduled_not_due ?? 0),
      held_count,
      cancelled_count,
      in_flight_count: Number(summary.in_flight ?? 0),
      claim_lost_count,
      lease_lost_count,
      deferred_inactive_channel_count,
      pages_read: pages,
      work_budget: maxItems,
      budget_exhausted,
      processed,
      network_sends_performed: dryRun ? 0 : network_sends_performed,
    };
  }

  /** True when the repository supports claim-aware DLQ redrive (ledger reads + DLQ claims). */
  const dlqClaimsEnabled = claimsEnabled && NOTIFICATION_DLQ_CLAIM_REPOSITORY_METHODS.every(
    (method) => typeof notificationRepo[method] === 'function',
  );

  /**
   * Claim-aware DLQ redrive: candidates come straight from the attempt ledger (tenant-scoped,
   * paged oldest-first), and every row is claimed in Postgres and re-gated on the live rule before
   * any send, so redrive never races the outbox worker, recovery, or another redrive.
   */
  async function redriveDlqClaimed(ctx, redriveOptions, deliveryMode, now) {
    const batch = await processClaimedNotificationDlqRedrive({
      deliveryMode,
      listPage: (page) => notificationRepo.listDlqDeliveryAttempts(ctx, page),
      claim: (attemptId, claimToken) => notificationRepo.claimDlqDeliveryAttempt(ctx, { attemptId, claimToken, leaseMs }),
      complete: (input) => notificationRepo.completeDeliveryAttemptClaim(ctx, input),
      release: (attemptId, claimToken) => notificationRepo.releaseDeliveryAttemptClaim(ctx, { attemptId, claimToken }),
      renew: typeof notificationRepo.renewDeliveryAttemptClaim === 'function'
        ? (attemptId, claimToken) => notificationRepo.renewDeliveryAttemptClaim(ctx, { attemptId, claimToken, leaseMs })
        : undefined,
      countDlq: typeof notificationRepo.countDlqDeliveryAttempts === 'function'
        ? () => notificationRepo.countDlqDeliveryAttempts(ctx)
        : undefined,
      summarizeHeld: typeof notificationRepo.summarizeHeldDlqDeliveryAttempts === 'function'
        ? (filters) => notificationRepo.summarizeHeldDlqDeliveryAttempts(ctx, filters)
        : undefined,
      resolveRule: liveRuleResolver(ctx),
      newClaimToken: () => `${instanceId}:${randomUUID()}`,
      leaseMs,
      attemptIds: redriveOptions.attemptIds,
      ruleId: redriveOptions.ruleId,
      dryRun: redriveOptions.dryRun === true,
      now,
      pageSize: redriveOptions.pageSize,
      maxItems: redriveOptions.maxItems,
      newAttemptId: () => newIdFn('id'),
      onLeaseRenewFailed: () => incMetric('notification_delivery_lease_renew_failed'),
      webhookSender: redriveOptions.webhookSender,
      fetchFn: redriveOptions.fetchFn,
      emailDeliverer: redriveOptions.emailDeliverer,
      slackDeliverer: redriveOptions.slackDeliverer,
      teamsDeliverer: redriveOptions.teamsDeliverer,
    });
    if (batch.claim_lost_count > 0) incMetric('notification_delivery_claim_lost', batch.claim_lost_count);
    if (batch.lease_lost_count > 0) incMetric('notification_delivery_lease_lost', batch.lease_lost_count);
    if (batch.held_count > 0) incMetric('notification_delivery_held_rule_disabled', batch.held_count);

    for (const item of batch.processed) {
      const record = item.delivery_record;
      if (!record || typeof record !== 'object') continue;
      await auditDeliveryRecord(ctx, String(item.event_id ?? ''), record, { dlq_redrive: true });
    }

    await auditRepo.appendAuditEvent({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId ?? null,
      actor_role: ctx.role ?? null,
      action: 'notification.dlq_redrive',
      resource_type: 'notification_dlq',
      resource_id: ctx.tenantId,
      metadata: {
        dry_run: batch.dry_run,
        delivery_mode: batch.delivery_mode,
        requeued_count: batch.requeued_count,
        skipped_count: batch.skipped_count,
        still_dlq_count: batch.still_dlq_count,
        held_count: batch.held_count,
        cancelled_count: batch.cancelled_count,
        in_flight_count: batch.in_flight_count,
        claim_lost_count: batch.claim_lost_count,
        lease_lost_count: batch.lease_lost_count,
        processed_count: batch.processed.length,
        rule_id: redriveOptions.ruleId ?? null,
        attempt_ids_count: Array.isArray(redriveOptions.attemptIds) ? redriveOptions.attemptIds.length : 0,
      },
    });

    return {
      tenant_id: ctx.tenantId,
      ...batch,
      processed: batch.processed.map(({ delivery_record: _drop, ...safe }) => safe),
    };
  }

  const outboxWorker = createOutboxDeliveryWorker({
    concurrency: Math.max(1, Number(options.outboxConcurrency) || DEFAULT_OUTBOX_CONCURRENCY),
    maxQueue: Math.max(1, Number(options.outboxMaxQueue) || DEFAULT_OUTBOX_MAX_QUEUE),
    deliver: deliverOutboxEvent,
  });

  /**
   * R03 reconciliation hook: passes registered here run at the start of every recovery tick and
   * enqueue (idempotently, by dedupe key) notifications owed by committed domain records whose
   * initial enqueue never happened. A failing pass never blocks delivery recovery.
   */
  const reconcilers = new Set();
  /**
   * The reconciliation window is anchored to the service clock, never moved back by a
   * caller-supplied retry `asOf` (API `as_of`, runner/scheduler `--as-of`): a past as-of would
   * otherwise reach domain records of any age, defeating the reconciler's lookback bound. A later
   * as-of is honoured so the tick can also drain what it reconciles; it only narrows the lookback
   * side of the window, and the outbox dedupe key keeps a reconciler that outruns the live
   * emitter's grace exactly-once.
   */
  function reconciliationAnchor(retryOptions) {
    const wallMs = new Date(nowFn()).getTime();
    if (retryOptions.asOf === undefined || retryOptions.asOf === null) return new Date(wallMs).toISOString();
    const requestedMs = new Date(retryOptions.asOf).getTime();
    // Reject before any reconciliation side effect (the drain rejects it the same way).
    if (!Number.isFinite(requestedMs)) throw new Error('notification retry: invalid as-of timestamp.');
    return new Date(Math.max(requestedMs, wallMs)).toISOString();
  }
  async function runReconcilers(ctx, retryOptions) {
    if (reconcilers.size === 0) return null;
    const asOf = reconciliationAnchor(retryOptions);
    const results = [];
    for (const reconcile of reconcilers) {
      try {
        results.push(await reconcile(ctx, { asOf, dryRun: retryOptions.dryRun === true }));
      } catch {
        incMetric('notification_reconcile_failed');
        results.push({ error: 'notification_reconcile_failed' });
      }
    }
    return results.length === 1 ? results[0] : results;
  }

  return {
    /**
     * Registers a reconciliation pass run by processDueNotificationRetries before draining due work.
     * @param {(ctx: object, opts: { asOf: string, dryRun: boolean }) => Promise<unknown>} reconcile
     * @returns {() => void} unregister
     */
    registerNotificationReconciler(reconcile) {
      if (typeof reconcile !== 'function') throw new TypeError('registerNotificationReconciler requires a function.');
      reconcilers.add(reconcile);
      return () => reconcilers.delete(reconcile);
    },

    async listNotifications(ctx) {
      const canReadLatest = typeof notificationRepo.listLatestDeliveryAttemptsByRule === 'function';
      const [rules, events, latestAttempts] = await Promise.all([
        notificationRepo.listNotificationRules(ctx),
        notificationRepo.listNotificationEvents(ctx, { limit: POSTGRES_NOTIFICATION_EVENTS_WINDOW }),
        canReadLatest ? notificationRepo.listLatestDeliveryAttemptsByRule(ctx) : Promise.resolve(null),
      ]);
      const eventList = Array.isArray(events) ? events : [];
      const payload = {
        rules: (rules ?? []).map((rule) => formatNotificationRuleForRead(rule)),
        events: eventList,
        events_window: {
          limit: POSTGRES_NOTIFICATION_EVENTS_WINDOW,
          returned: eventList.length,
          // A full page means older events may exist beyond the feed.
          truncated: eventList.length >= POSTGRES_NOTIFICATION_EVENTS_WINDOW,
        },
      };
      // Only claim per-rule latest deliveries when they come from the full attempt history.
      if (Array.isArray(latestAttempts)) {
        const byRule = new Map(latestAttempts.map((attempt) => [attempt.rule_id, attempt]));
        payload.latest_deliveries = Object.fromEntries(
          payload.rules.map((rule) => [rule.id, formatLatestDeliveryForRead(byRule.get(rule.id))]),
        );
      }
      return payload;
    },

    async createNotificationRule(ctx, body) {
      const normalized = normalizeNotificationRuleInput(body);
      if (!normalized.ok) return normalized;

      const now = nowFn().toISOString();
      const id = newIdFn('nrule');
      const persisted = await notificationRepo.createNotificationRule(ctx, {
        id,
        channel: normalized.channel,
        destination: normalized.destination,
        triggers: normalized.triggers,
        enabled: normalized.enabled,
        created_at: now,
      });

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'notification.rule_created',
        resource_type: 'notification_rule',
        resource_id: persisted.id,
        metadata: {
          channel: persisted.channel,
          trigger_count: persisted.triggers.length,
        },
      });

      return {
        ...persisted,
        created_by: ctx.userId,
        delivery_note: notificationDeliveryNote(persisted.channel, { deliveryMode: options.deliveryMode }),
      };
    },

    async updateNotificationRule(ctx, ruleId, body) {
      if (typeof notificationRepo.getNotificationRule !== 'function'
        || typeof notificationRepo.updateNotificationRule !== 'function') {
        return { ...NOT_WIRED };
      }
      const existing = await notificationRepo.getNotificationRule(ctx, ruleId);
      if (!existing) return null;
      const update = normalizeNotificationRuleUpdate(existing, body);
      if (!update.ok) return update;
      if (update.changedFields.length === 0) return existing;

      const updated = await notificationRepo.updateNotificationRule(ctx, ruleId, update.changes, {
        updated_at: nowFn().toISOString(),
      });
      // Removed concurrently between read and write.
      if (!updated) return null;

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'notification.rule_updated',
        resource_type: 'notification_rule',
        resource_id: updated.id,
        metadata: notificationRuleUpdateAuditMetadata(updated, update.changedFields),
      });
      return updated;
    },

    async deleteNotificationRule(ctx, ruleId) {
      if (typeof notificationRepo.deleteNotificationRule !== 'function') return { ...NOT_WIRED };
      const deletedAt = nowFn().toISOString();
      const removed = await notificationRepo.deleteNotificationRule(ctx, ruleId, { deleted_at: deletedAt });
      if (!removed) return null;
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'notification.rule_deleted',
        resource_type: 'notification_rule',
        resource_id: removed.id,
        metadata: { channel: removed.channel },
      });
      return { id: removed.id, deleted: true, deleted_at: deletedAt };
    },

    async emitNotification(ctx, { trigger, subject, metadata = {} }) {
      const now = nowFn().toISOString();
      const rules = (await notificationRepo.listNotificationRules(ctx)).filter(
        (r) => r.enabled && r.triggers.includes(trigger),
      );

      const eventId = newIdFn('nevt');
      const redacted = buildRedactedNotificationEventPayload(subject, metadata);
      const initialAttempts = rules.map((rule) =>
        buildNotificationDeliveryAttempt(eventId, rule, now),
      );
      const delivery_attempts = await finalizeGatedNotificationDeliveryAttempts({
        deliveryMode: resolveNotificationDeliveryMode(options),
        attempts: initialAttempts,
        rules,
        event: {
          id: eventId,
          trigger,
          subject: redacted.subject,
          metadata: redacted.metadata,
          created_at: now,
        },
        now,
        webhookSender: options.webhookSender,
        fetchFn: options.fetchFn,
        // R01: re-gate every rule on its live state right before the send, so a rule disabled or
        // removed after the snapshot above is never delivered to.
        resolveRule: liveRuleResolver(ctx),
      });

      const eventRow = await notificationRepo.appendNotificationEvent(ctx, {
        id: eventId,
        trigger,
        subject: redacted.subject,
        metadata: redacted.metadata,
        delivery_status: 'metadata_only',
        created_at: now,
      });

      const persistedAttempts = await notificationRepo.appendDeliveryAttempts(
        ctx,
        eventId,
        delivery_attempts,
      );

      const event = {
        ...eventRow,
        metadata: redacted.metadata,
        delivery_attempts: persistedAttempts,
      };

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId ?? null,
        actor_role: ctx.role ?? null,
        action: 'notification.event_emitted',
        resource_type: 'notification_event',
        resource_id: event.id,
        metadata: {
          trigger: event.trigger,
          subject_preview: redactString(String(subject ?? '')).slice(0, 80),
          attempt_count: delivery_attempts.length,
        },
      });

      for (const attempt of delivery_attempts) {
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId ?? null,
          actor_role: ctx.role ?? null,
          action: 'notification.delivery_attempt_recorded',
          resource_type: 'notification_delivery_attempt',
          resource_id: attempt.id,
          metadata: {
            event_id: event.id,
            rule_id: attempt.rule_id,
            channel: attempt.channel,
            status: attempt.status,
          },
        });
      }

      return event;
    },

    /**
     * Durable outbox emit for lifecycle triggers (run terminal, report ready). Records the event
     * and its pending attempts in one transaction BEFORE any external send and returns as soon as
     * that commit succeeds; provider delivery runs on a bounded background worker. A `dedupeKey`
     * makes replays, concurrent calls, and other instances collapse to one event per identity.
     * Throws when durable recording fails, so the caller keeps no claim and a replay re-enqueues.
     *
     * Reconciliation (R03) passes `ruleIds` (only rules subscribed when the domain record
     * committed get attempts; rules created or re-enabled since are not back-filled) and
     * `deferToRecovery` (pending attempts are due by the tick's `recoveryAsOf` and are NOT handed
     * to the in-process worker, so the calling recovery tick's claimed drain delivers them before a
     * one-shot runner closes its pool).
     * @param {{ tenantId: string, userId?: string, role?: string }} ctx
     * @param {{ trigger: string, subject: string, metadata?: Record<string, unknown>, dedupeKey?: string, ruleIds?: string[], deferToRecovery?: boolean, recoveryAsOf?: string }} input
     * @returns {Promise<{ inserted: boolean, event: Record<string, unknown> | null, scheduled: number }>}
     */
    async enqueueNotification(ctx, {
      trigger, subject, metadata = {}, dedupeKey, ruleIds, deferToRecovery = false, recoveryAsOf,
    } = {}) {
      const now = nowFn().toISOString();
      const allowedRuleIds = Array.isArray(ruleIds) ? new Set(ruleIds.map(String)) : null;
      const rules = ((await notificationRepo.listNotificationRules(ctx)) ?? []).filter(
        (r) => r.enabled && Array.isArray(r.triggers) && r.triggers.includes(trigger)
          && (!allowedRuleIds || allowedRuleIds.has(String(r.id))),
      );
      if (rules.length === 0) return { inserted: false, event: null, scheduled: 0 };

      // Reconciled (deferToRecovery) attempts never take this process's delivery mode: the
      // recovering scheduler's mode (default metadata_only) need not match the emitting API's, and
      // finalizing here would silently drop an owed provider send. They stay pending for a
      // provider-capable tick; ticks that cannot deliver their channel defer them untouched.
      const modes = deferToRecovery === true
        ? null
        : parseNotificationDeliveryModes(resolveNotificationDeliveryMode(options));
      const eventId = newIdFn('nevt');
      const redacted = buildRedactedNotificationEventPayload(subject, metadata);
      // Deferred attempts must be due for the calling tick (next_retry_at <= its as-of), whichever
      // of the tick's as-of and the wall clock is earlier.
      const asOfMs = recoveryAsOf ? new Date(recoveryAsOf).getTime() : Number.NaN;
      const recoveryDelayMs = deferToRecovery !== true
        ? OUTBOX_RECOVERY_GRACE_MS
        : Math.min(0, Number.isFinite(asOfMs) ? asOfMs - new Date(now).getTime() : 0);
      const attempts = rules.map((rule) => buildOutboxDeliveryAttempt(eventId, rule, now, modes, recoveryDelayMs));
      const eventRecord = {
        id: eventId,
        trigger,
        subject: redacted.subject,
        metadata: redacted.metadata,
        delivery_status: 'metadata_only',
        created_at: now,
        dedupe_key: dedupeKey ?? null,
      };

      let result;
      if (typeof notificationRepo.enqueueNotificationEvent === 'function') {
        result = await notificationRepo.enqueueNotificationEvent(ctx, eventRecord, attempts);
      } else {
        // Older repository without the atomic outbox: still persist before any send.
        const row = await notificationRepo.appendNotificationEvent(ctx, eventRecord);
        const persisted = await notificationRepo.appendDeliveryAttempts(ctx, eventId, attempts);
        result = { inserted: true, event: { ...row, delivery_attempts: persisted ?? attempts } };
      }

      const event = result?.event ?? null;
      if (!event) throw new Error('notification_outbox_enqueue_failed');

      // Idempotent so a replay after a post-commit audit failure records the audit exactly once.
      await auditRepo.appendAuditEvent(
        {
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId ?? null,
          actor_role: ctx.role ?? null,
          action: 'notification.event_emitted',
          resource_type: 'notification_event',
          resource_id: event.id,
          metadata: {
            trigger,
            subject_preview: redactString(String(subject ?? '')).slice(0, 80),
            attempt_count: Array.isArray(event.delivery_attempts) ? event.delivery_attempts.length : 0,
            outbox: true,
          },
        },
        { idempotency: { actions: ['notification.event_emitted'], resourceType: 'notification_event', resourceId: event.id } },
      );

      if (!result.inserted) return { inserted: false, event, scheduled: 0 };
      // Left for the caller's claimed recovery drain (already due); never runs after its pool closes.
      if (deferToRecovery === true) return { inserted: true, event, scheduled: 0 };

      const pendingAttempts = (event.delivery_attempts ?? []).filter(
        (a) => a.status === 'provider_retry_scheduled' && a.reason === OUTBOX_PENDING_REASON,
      );
      const scheduled = pendingAttempts.length > 0
        && outboxWorker.schedule({
          ctx: { tenantId: ctx.tenantId, userId: ctx.userId ?? 'system', role: ctx.role ?? 'system' },
          event: { ...event, subject: redacted.subject, metadata: redacted.metadata, created_at: now },
          pendingAttempts,
        })
        ? pendingAttempts.length
        : 0;
      return { inserted: true, event, scheduled };
    },

    /** Resolves once the in-process outbox worker has no queued or running deliveries. */
    async drainNotificationOutbox() {
      await outboxWorker.idle();
    },

    async processDueNotificationRetries(ctx, options = {}) {
      // R03: enqueue owed-but-missing lifecycle events first so this tick can also deliver them.
      const reconciliation = await runReconcilers(ctx, options);
      if (claimsEnabled) {
        const claimed = await processDueRetriesClaimed(ctx, options);
        return reconciliation ? { ...claimed, reconciliation } : claimed;
      }
      // Legacy path for repositories without delivery claims (older stubs only).
      const asOf = options.asOf ?? nowFn().toISOString();
      const deliveryMode = resolveNotificationDeliveryMode(options);

      const [rules, events] = await Promise.all([
        notificationRepo.listNotificationRules(ctx),
        notificationRepo.listNotificationEvents(ctx, { limit: 500 }),
      ]);

      const batch = await processDueNotificationRetryBatch({
        deliveryMode,
        events,
        rules,
        resolveRule: liveRuleResolver(ctx),
        asOf,
        now: options.now ?? asOf,
        dryRun: options.dryRun === true,
        newAttemptId: (_eventId, _ruleId, _attemptNumber) => newIdFn('id'),
        webhookSender: options.webhookSender,
        fetchFn: options.fetchFn,
        emailDeliverer: options.emailDeliverer,
        slackDeliverer: options.slackDeliverer,
        teamsDeliverer: options.teamsDeliverer,
      });

      if (!batch.dry_run) {
        const attemptsByEvent = new Map();
        for (const item of batch.processed) {
          const record = item.delivery_record;
          if (!record || typeof record !== 'object') continue;
          const eventId = String(item.event_id ?? '');
          if (!eventId) continue;
          if (!attemptsByEvent.has(eventId)) attemptsByEvent.set(eventId, []);
          attemptsByEvent.get(eventId).push(record);

          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId ?? null,
            actor_role: ctx.role ?? null,
            action: 'notification.delivery_attempt_recorded',
            resource_type: 'notification_delivery_attempt',
            resource_id: record.id,
            metadata: {
              event_id: eventId,
              rule_id: record.rule_id,
              channel: record.channel,
              status: record.status,
              retry: true,
            },
          });
        }

        for (const [eventId, attempts] of attemptsByEvent.entries()) {
          await notificationRepo.appendDeliveryAttempts(ctx, eventId, attempts);
        }
      }

      return {
        tenant_id: ctx.tenantId,
        ...batch,
        processed: batch.processed.map(({ delivery_record: _drop, ...safe }) => safe),
        ...(reconciliation ? { reconciliation } : {}),
      };
    },

    async redriveNotificationDlq(ctx, options = {}) {
      const deliveryMode = resolveDlqRedriveDeliveryMode({
        forceMetadataOnly: options.forceMetadataOnly,
        deliveryMode: options.deliveryMode,
      });
      const now = options.now ?? nowFn().toISOString();

      if (dlqClaimsEnabled) return redriveDlqClaimed(ctx, options, deliveryMode, now);
      // Legacy path for repositories without DLQ claims (older stubs only).
      const [rules, events] = await Promise.all([
        notificationRepo.listNotificationRules(ctx),
        notificationRepo.listNotificationEvents(ctx, { limit: 500 }),
      ]);

      const batch = await processNotificationDlqRedriveBatch({
        deliveryMode,
        events,
        rules,
        resolveRule: liveRuleResolver(ctx),
        attemptIds: options.attemptIds,
        ruleId: options.ruleId,
        dryRun: options.dryRun === true,
        now,
        newAttemptId: (_eventId, _ruleId, _attemptId) => newIdFn('id'),
        webhookSender: options.webhookSender,
        fetchFn: options.fetchFn,
        emailDeliverer: options.emailDeliverer,
        slackDeliverer: options.slackDeliverer,
        teamsDeliverer: options.teamsDeliverer,
      });

      if (!batch.dry_run) {
        const attemptsByEvent = new Map();
        for (const item of batch.processed) {
          const record = item.delivery_record;
          if (!record || typeof record !== 'object') continue;
          const eventId = String(item.event_id ?? '');
          if (!eventId) continue;
          if (!attemptsByEvent.has(eventId)) attemptsByEvent.set(eventId, []);
          attemptsByEvent.get(eventId).push(record);

          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId ?? null,
            actor_role: ctx.role ?? null,
            action: 'notification.delivery_attempt_recorded',
            resource_type: 'notification_delivery_attempt',
            resource_id: record.id,
            metadata: {
              event_id: eventId,
              rule_id: record.rule_id,
              channel: record.channel,
              status: record.status,
              dlq_redrive: true,
            },
          });
        }

        for (const [eventId, attempts] of attemptsByEvent.entries()) {
          await notificationRepo.appendDeliveryAttempts(ctx, eventId, attempts);
        }
      }

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId ?? null,
        actor_role: ctx.role ?? null,
        action: 'notification.dlq_redrive',
        resource_type: 'notification_dlq',
        resource_id: ctx.tenantId,
        metadata: {
          dry_run: batch.dry_run,
          delivery_mode: batch.delivery_mode,
          requeued_count: batch.requeued_count,
          skipped_count: batch.skipped_count,
          still_dlq_count: batch.still_dlq_count,
          held_count: batch.held_count ?? 0,
          cancelled_count: batch.cancelled_count ?? 0,
          processed_count: batch.processed.length,
          rule_id: options.ruleId ?? null,
          attempt_ids_count: Array.isArray(options.attemptIds) ? options.attemptIds.length : 0,
        },
      });

      return {
        tenant_id: ctx.tenantId,
        ...batch,
        processed: batch.processed.map(({ delivery_record: _drop, ...safe }) => safe),
      };
    },
  };
}

const HIGH_SEVERITIES = new Set(['high', 'critical']);

/** Outbox identity for a run-completion notification. */
export function safeTestCompletedDedupeKey(runId) {
  return `safe_test.completed:run:${runId}`;
}

/**
 * Outbox identity for a high-severity finding alert, bound to the publication that created the
 * finding (its original verdict). An advanced finding keeps that verdict_id, so it never re-alerts.
 */
export function highSeverityFindingDedupeKey(findingId, verdictId) {
  return `finding.high_severity:finding:${findingId}:verdict:${verdictId}`;
}

/**
 * Postgres emitters for run-driven triggers. On a verdicted run it enqueues `safe_test.completed`,
 * and `finding.high_severity` for a newly created high/critical finding bound to that run.
 *
 * - Only the durable outbox enqueue is awaited; provider delivery is asynchronous, so a slow or
 *   stalled destination never delays run finalization, probe ingest, or the collection sweep.
 * - Deduplication is the database's unique (tenant_id, dedupe_key) index, so replays, concurrent
 *   invocations, and separate API instances record one event per identity. Nothing is remembered
 *   as "done" in process; a failed enqueue leaves no claim and the next replay records it.
 * - Each trigger (and each finding) is isolated, so one failure cannot skip another alert.
 * - Never throws into the run lifecycle.
 * @param {{
 *   testRuns?: { registerRunTerminalHook?: (hook: Function) => unknown },
 *   notifications?: { enqueueNotification?: Function, emitNotification?: Function },
 *   notificationRules?: { listNotificationRules?: Function },
 *   validationEvidence?: { listFindings?: Function },
 * }} deps
 */
export function registerPostgresRunNotificationHook(deps) {
  const { testRuns, notifications, notificationRules, validationEvidence } = deps ?? {};
  if (typeof testRuns?.registerRunTerminalHook !== 'function') return null;
  if (typeof notifications?.enqueueNotification !== 'function') return null;

  async function isolated(fn) {
    try {
      await fn();
    } catch {
      incMetric('notification_emit_failed');
    }
  }

  /**
   * High/critical findings CREATED by this run's publication. The identity is the run's durable
   * verdict: a new finding stores it as verdict_id, and later advancement by another run changes
   * only last_verdict_id/test_run_id. Looking up by the finding binding (not the mutable
   * test_run_id) keeps the alert even if another run advanced the finding before this hook ran.
   */
  async function findingsPublishedByRun(ctx, run) {
    let verdictId = null;
    if (typeof validationEvidence.getVerdictForRun === 'function') {
      const verdict = await validationEvidence.getVerdictForRun(ctx, run.id);
      verdictId = verdict?.id ?? null;
      if (!verdictId) return [];
    }
    const query = verdictId && run.target_group_id && run.target_id && run.check_id
      ? { target_group_id: run.target_group_id, target_id: run.target_id, check_id: run.check_id }
      : { test_run_id: run.id };
    const rows = (await validationEvidence.listFindings(ctx, query)) ?? [];
    return rows.filter((finding) => {
      if (!HIGH_SEVERITIES.has(finding.severity) || !finding.verdict_id) return false;
      if (verdictId) return finding.verdict_id === verdictId;
      // Legacy repository without verdict reads: only a finding still bound to this run's
      // creating publication qualifies.
      return finding.status === 'open'
        && (!finding.last_verdict_id || finding.verdict_id === finding.last_verdict_id);
    });
  }

  return testRuns.registerRunTerminalHook(async (run, context = {}) => {
    if (!run?.tenant_id || !run?.id || context.reason !== 'verdicted') return;
    const ctx = { tenantId: run.tenant_id, userId: 'system', role: 'system' };

    let rules;
    try {
      rules = typeof notificationRules?.listNotificationRules === 'function'
        ? await notificationRules.listNotificationRules(ctx)
        : null;
    } catch {
      // Unknown subscriptions: enqueueNotification re-reads rules per trigger and is a no-op
      // without a subscriber, so each trigger still gets its own chance below.
      incMetric('notification_emit_failed');
      rules = null;
    }
    const wants = (trigger) => rules == null
      || rules.some((r) => r.enabled && Array.isArray(r.triggers) && r.triggers.includes(trigger));

    if (wants('safe_test.completed')) {
      await isolated(() => notifications.enqueueNotification(ctx, {
        trigger: 'safe_test.completed',
        subject: `Safe validation run ${run.id} completed`,
        metadata: { run_id: run.id, check_id: run.check_id ?? null, target_group_id: run.target_group_id ?? null },
        dedupeKey: safeTestCompletedDedupeKey(run.id),
      }));
    }

    if (wants('finding.high_severity') && typeof validationEvidence?.listFindings === 'function') {
      let candidates = [];
      try {
        candidates = await findingsPublishedByRun(ctx, run);
      } catch {
        incMetric('notification_emit_failed');
        return;
      }
      for (const finding of candidates) {
        await isolated(() => notifications.enqueueNotification(ctx, {
          trigger: 'finding.high_severity',
          subject: finding.title ?? `High-severity finding on run ${run.id}`,
          metadata: {
            finding_id: finding.id,
            severity: finding.severity,
            verdict_id: finding.verdict_id,
            test_run_id: run.id,
          },
          dedupeKey: highSeverityFindingDedupeKey(finding.id, finding.verdict_id),
        }));
      }
    }
  });
}
