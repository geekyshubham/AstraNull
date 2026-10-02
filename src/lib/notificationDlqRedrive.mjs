import {
  WEBHOOK_MAX_ATTEMPTS,
  finalizeNotificationDeliveryAttempts,
  parseNotificationDeliveryModes,
} from './notificationDelivery.mjs';
import {
  NOTIFICATION_RETRY_BACKOFF_MS,
  NOTIFICATION_RULE_CANCELLED_STATUSES,
  NOTIFICATION_RULE_GATE,
  NOTIFICATION_RULE_HELD_STATUS,
  NOTIFICATION_RULE_REMOVED_STATUS,
  buildRuleRemovedCancellationAttempt,
  latestDeliveryAttemptsByRule,
  resolveNotificationRuleForDelivery,
} from './notificationRetry.mjs';

/**
 * @param {{ forceMetadataOnly?: boolean }} [options]
 */
export function resolveDlqRedriveDeliveryMode(options = {}) {
  if (options.forceMetadataOnly !== false) {
    return 'metadata_only';
  }
  if (process.env.NODE_ENV === 'test') {
    return 'metadata_only';
  }
  const raw = process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE ?? 'metadata_only';
  const modes = parseNotificationDeliveryModes(raw);
  if (modes.has('metadata_only') && modes.size === 1) {
    return 'metadata_only';
  }
  return [...modes].sort().join(',');
}

/**
 * @param {Array<Record<string, unknown>>} events
 * @param {{ attemptIds?: string[], ruleId?: string }} [filters]
 */
export function collectDlqNotificationAttempts(events, filters = {}) {
  const attemptIdSet =
    Array.isArray(filters.attemptIds) && filters.attemptIds.length > 0
      ? new Set(filters.attemptIds.map((id) => String(id)))
      : null;
  const ruleId = filters.ruleId ? String(filters.ruleId) : null;

  /** @type {{ event: Record<string, unknown>, attempt: Record<string, unknown> }[]} */
  const candidates = [];
  const seenAttemptIds = new Set();

  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    for (const attempt of latestDeliveryAttemptsByRule(event).values()) {
      if (attempt.status !== 'provider_failed_dlq') continue;
      const attemptId = String(attempt.id ?? '');
      if (!attemptId) continue;
      seenAttemptIds.add(attemptId);

      if (ruleId && String(attempt.rule_id ?? '') !== ruleId) continue;
      if (attemptIdSet && !attemptIdSet.has(attemptId)) continue;

      candidates.push({ event, attempt });
    }
  }

  let skipped_count = 0;
  if (attemptIdSet) {
    for (const requestedId of attemptIdSet) {
      if (!seenAttemptIds.has(requestedId)) {
        skipped_count += 1;
      }
    }
  }

  return {
    candidates,
    skipped_count,
    candidate_count: candidates.length,
  };
}

/**
 * @param {{
 *   attempt: Record<string, unknown>,
 *   now: string,
 *   newAttemptId: string,
 * }} input
 */
export function buildMetadataOnlyDlqRedriveAttempt(input) {
  const maxAttempts = Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS);
  return {
    id: input.newAttemptId,
    rule_id: input.attempt.rule_id,
    channel: input.attempt.channel,
    destination_preview: input.attempt.destination_preview,
    status: 'provider_retry_scheduled',
    reason: 'dlq_redrive_metadata_only',
    provider_error: input.attempt.provider_error ?? 'dlq_redrive_metadata_only',
    created_at: input.now,
    attempted_at: input.now,
    attempt_number: 1,
    max_attempts: maxAttempts,
    next_retry_at: input.now,
    exhausted: false,
  };
}

/**
 * @param {{
 *   attempt: Record<string, unknown>,
 *   event: Record<string, unknown>,
 *   rule: { id: string, channel: string, destination: string },
 *   now: string,
 *   newAttemptId: string,
 *   deliveryMode: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: (envelope: { from: string, to: string, subject: string, html_body: string }) => unknown,
 *   slackDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 *   teamsDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 * }} input
 */
export async function buildDlqRedriveDeliveryAttempt(input) {
  const modes = parseNotificationDeliveryModes(input.deliveryMode);
  if (modes.has('metadata_only') && modes.size === 1) {
    return buildMetadataOnlyDlqRedriveAttempt({
      attempt: input.attempt,
      now: input.now,
      newAttemptId: input.newAttemptId,
    });
  }

  const seed = {
    id: input.newAttemptId,
    rule_id: input.attempt.rule_id,
    channel: input.attempt.channel,
    destination_preview: input.attempt.destination_preview,
    status: 'queued_provider_not_configured',
    reason: 'dlq_redrive',
    created_at: input.now,
    attempted_at: null,
    attempt_number: 1,
    max_attempts: Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS),
  };

  const eventPayload = {
    id: String(input.event.id ?? ''),
    trigger: String(input.event.trigger ?? ''),
    subject:
      typeof input.event.subject === 'string'
        ? input.event.subject
        : String(input.event.subject ?? ''),
    metadata:
      input.event.metadata && typeof input.event.metadata === 'object' && !Array.isArray(input.event.metadata)
        ? input.event.metadata
        : {},
    created_at: String(input.event.created_at ?? input.now),
  };

  const [record] = await finalizeNotificationDeliveryAttempts({
    deliveryMode: input.deliveryMode,
    attempts: [seed],
    rules: [input.rule],
    event: eventPayload,
    now: input.now,
    webhookSender: input.webhookSender,
    fetchFn: input.fetchFn,
    emailDeliverer: input.emailDeliverer,
    slackDeliverer: input.slackDeliverer,
    teamsDeliverer: input.teamsDeliverer,
  });

  if (record.status === 'provider_retry_scheduled' && !record.next_retry_at) {
    return {
      ...record,
      next_retry_at: new Date(new Date(input.now).getTime() + NOTIFICATION_RETRY_BACKOFF_MS).toISOString(),
    };
  }

  return record;
}

/**
 * @param {Array<Record<string, unknown>>} events
 */
export function countStillDlqAttempts(events) {
  let count = 0;
  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    for (const attempt of latestDeliveryAttemptsByRule(event).values()) {
      if (attempt.status === 'provider_failed_dlq') count += 1;
    }
  }
  return count;
}

/**
 * @param {{
 *   deliveryMode: string,
 *   events: Array<Record<string, unknown>>,
 *   rules: Array<{ id: string, channel: string, destination: string, enabled?: boolean, deleted_at?: string | null }>,
 *   resolveRule?: (ruleId: string) => Promise<Record<string, unknown> | null> | Record<string, unknown> | null,
 *   attemptIds?: string[],
 *   ruleId?: string,
 *   dryRun?: boolean,
 *   now?: string,
 *   newAttemptId?: (eventId: string, ruleId: string, attemptId: string) => string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: (envelope: { from: string, to: string, subject: string, html_body: string }) => unknown,
 *   slackDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 *   teamsDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 * }} input
 */
export async function processNotificationDlqRedriveBatch(input) {
  const now = input.now ?? new Date().toISOString();
  const dryRun = input.dryRun === true;
  const collected = collectDlqNotificationAttempts(input.events, {
    attemptIds: input.attemptIds,
    ruleId: input.ruleId,
  });
  const rulesById = new Map(input.rules.map((rule) => [rule.id, rule]));
  const adapterModeActive = !(
    parseNotificationDeliveryModes(input.deliveryMode).has('metadata_only')
    && parseNotificationDeliveryModes(input.deliveryMode).size === 1
  );

  const newAttemptId =
    input.newAttemptId ??
    ((eventId, ruleId, attemptId) => `ndlq_${eventId}_${ruleId}_${attemptId}`);

  /** @type {Record<string, unknown>[]} */
  const processed = [];
  let skipped_count = collected.skipped_count;
  let network_sends_performed = 0;
  let held_count = 0;
  let cancelled_count = 0;

  for (const { event, attempt } of collected.candidates) {
    const channel = String(attempt.channel ?? '');
    if (channel === 'in_app') {
      skipped_count += 1;
      continue;
    }

    // Lifecycle gate, re-read per item right before its send (see NOTIFICATION_RULE_GATE).
    const ruleId = String(attempt.rule_id ?? '');
    const { rule, gate, cancellation } = await resolveNotificationRuleForDelivery({
      ruleId,
      trigger: typeof event.trigger === 'string' ? event.trigger : null,
      rulesById,
      resolveRule: input.resolveRule,
    });
    if (gate === NOTIFICATION_RULE_GATE.UNKNOWN || !rule) {
      skipped_count += 1;
      continue;
    }

    if (gate === NOTIFICATION_RULE_GATE.HOLD) {
      // Turned off: leave the DLQ row untouched (nothing sent, nothing recorded) so an operator
      // can redrive it after re-enabling the rule.
      held_count += 1;
      processed.push({
        event_id: event.id ?? null,
        prior_attempt_id: attempt.id ?? null,
        rule_id: attempt.rule_id ?? null,
        channel,
        status: NOTIFICATION_RULE_HELD_STATUS,
        dry_run: dryRun,
      });
      continue;
    }

    if (gate === NOTIFICATION_RULE_GATE.CANCEL) {
      // Removed: close the DLQ row with a non-sent terminal attempt; it can never be redriven.
      cancelled_count += 1;
      if (dryRun) {
        processed.push({
          event_id: event.id ?? null,
          prior_attempt_id: attempt.id ?? null,
          rule_id: attempt.rule_id ?? null,
          channel,
          status: cancellation?.status ?? NOTIFICATION_RULE_REMOVED_STATUS,
          dry_run: true,
        });
        continue;
      }
      const record = buildRuleRemovedCancellationAttempt({
        attempt,
        now,
        newAttemptId: newAttemptId(String(event.id ?? ''), ruleId, String(attempt.id ?? '')),
        cancellation,
      });
      processed.push({
        event_id: event.id ?? null,
        prior_attempt_id: attempt.id ?? null,
        attempt_id: record.id,
        rule_id: record.rule_id ?? null,
        channel: record.channel ?? null,
        status: record.status,
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
        prior_attempt_id: attempt.id ?? null,
        rule_id: attempt.rule_id ?? null,
        channel,
        status: 'redrive_planned',
        dry_run: true,
      });
      continue;
    }

    const record = await buildDlqRedriveDeliveryAttempt({
      attempt,
      event,
      rule,
      now,
      newAttemptId: newAttemptId(
        String(event.id ?? ''),
        String(attempt.rule_id ?? ''),
        String(attempt.id ?? ''),
      ),
      deliveryMode: input.deliveryMode,
      webhookSender: input.webhookSender,
      fetchFn: input.fetchFn,
      emailDeliverer: input.emailDeliverer,
      slackDeliverer: input.slackDeliverer,
      teamsDeliverer: input.teamsDeliverer,
    });

    if (
      adapterModeActive
      && (record.status === 'delivered_provider' || record.status === 'provider_retry_scheduled')
    ) {
      network_sends_performed += 1;
    }

    processed.push({
      event_id: event.id ?? null,
      prior_attempt_id: attempt.id ?? null,
      attempt_id: record.id,
      rule_id: record.rule_id ?? null,
      channel: record.channel ?? null,
      status: record.status,
      attempt_number: record.attempt_number ?? null,
      max_attempts: record.max_attempts ?? null,
      next_retry_at: record.next_retry_at ?? null,
      exhausted: record.exhausted ?? null,
      dry_run: false,
      delivery_record: record,
    });
  }

  const notRequeued = new Set(['provider_failed_dlq', NOTIFICATION_RULE_HELD_STATUS, ...NOTIFICATION_RULE_CANCELLED_STATUSES]);
  const requeued_count = processed.filter((item) =>
    dryRun ? item.status === 'redrive_planned' : !notRequeued.has(String(item.status))).length;

  const projectedEvents = dryRun
    ? input.events
    : applyDlqRedriveRecords(input.events, processed);

  return {
    delivery_mode: input.deliveryMode,
    dry_run: dryRun,
    requeued_count,
    skipped_count,
    still_dlq_count: countStillDlqAttempts(projectedEvents),
    held_count,
    cancelled_count,
    processed,
    network_sends_performed: dryRun ? 0 : network_sends_performed,
  };
}

/** Redrive drain per call: page size and total work budget (oldest DLQ rows first). */
export const NOTIFICATION_DLQ_REDRIVE_PAGE_SIZE = 100;
export const NOTIFICATION_DLQ_REDRIVE_MAX_ITEMS = 1000;

function boundedInt(value, min, max, fallback) {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n < min) return fallback;
  return Math.min(n, max);
}

/**
 * Claim-aware DLQ redrive over a durable ledger (Postgres). Same ownership protocol as the outbox
 * worker and due-retry recovery:
 *
 * 1. Candidates are read directly from the ledger, tenant-scoped and paged oldest-first with a
 *    keyset cursor (`listPage`), never from the bounded recent-events feed. `listPage` excludes
 *    rows whose rule is turned off (held), so held rows never consume the work budget or block
 *    enabled rules' rows behind them; `summarizeHeld` reports them by count without touching them.
 * 2. Each DLQ row is atomically claimed (`claim`, a lease) before any external I/O. A lost claim
 *    (another redrive owns it, or it is no longer the live DLQ row) sends nothing.
 * 3. The rule lifecycle gate runs after the claim, re-reading the rule: `hold` releases the claim
 *    and writes nothing (the DLQ row stays as is; this only happens when a rule is turned off
 *    between listing and claiming), `cancel` records `cancelled_rule_removed`.
 * 4. The send runs while the lease is heartbeated (`renew`), then `complete` supersedes the claimed
 *    row and appends the outcome in one transaction, only if this claim still owns it.
 *
 * Dry runs never claim or write; they report what a redrive would do.
 * @param {{
 *   deliveryMode: string,
 *   listPage: (page: { limit: number, after: { created_at: string, id: string } | null, ruleId: string | null, attemptIds: string[] | null }) => Promise<Array<{ event: Record<string, unknown>, attempt: Record<string, unknown>, lease_active?: boolean }>>,
 *   claim: (attemptId: string, claimToken: string) => Promise<Record<string, unknown> | null>,
 *   complete: (input: { attemptId: string, claimToken: string, eventId: string, record: Record<string, unknown> }) => Promise<{ completed: boolean }>,
 *   release: (attemptId: string, claimToken: string) => Promise<unknown>,
 *   renew?: (attemptId: string, claimToken: string) => Promise<unknown>,
 *   countDlq?: () => Promise<number>,
 *   summarizeHeld?: (filters: { ruleId: string | null, attemptIds: string[] | null }) => Promise<{ held_count: number, held_attempt_ids?: string[] }>,
 *   resolveRule: (ruleId: string) => Promise<Record<string, unknown> | null> | Record<string, unknown> | null,
 *   newClaimToken: () => string,
 *   leaseMs: number,
 *   attemptIds?: string[],
 *   ruleId?: string,
 *   dryRun?: boolean,
 *   now?: string,
 *   pageSize?: number,
 *   maxItems?: number,
 *   newAttemptId?: (eventId: string, ruleId: string, attemptId: string) => string,
 *   onLeaseRenewFailed?: () => void,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: (envelope: { from: string, to: string, subject: string, html_body: string }) => unknown,
 *   slackDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 *   teamsDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 * }} input
 */
export async function processClaimedNotificationDlqRedrive(input) {
  const now = input.now ?? new Date().toISOString();
  const dryRun = input.dryRun === true;
  const pageSize = boundedInt(input.pageSize, 1, 500, NOTIFICATION_DLQ_REDRIVE_PAGE_SIZE);
  const maxItems = boundedInt(input.maxItems, 1, 100_000, NOTIFICATION_DLQ_REDRIVE_MAX_ITEMS);
  const modes = parseNotificationDeliveryModes(input.deliveryMode);
  const adapterModeActive = !(modes.has('metadata_only') && modes.size === 1);
  const ruleIdFilter = input.ruleId ? String(input.ruleId) : null;
  const attemptIds = Array.isArray(input.attemptIds) && input.attemptIds.length > 0
    ? [...new Set(input.attemptIds.map((id) => String(id)))]
    : null;
  const newAttemptId =
    input.newAttemptId ??
    ((eventId, ruleId, attemptId) => `ndlq_${eventId}_${ruleId}_${attemptId}`);

  /** @type {Record<string, unknown>[]} */
  const processed = [];
  const seenAttemptIds = new Set();
  // Rows this call created (an exhausted redrive can land back in the DLQ) are never revisited.
  const createdAttemptIds = new Set();
  let skipped_count = 0;
  let held_count = 0;
  let cancelled_count = 0;
  let in_flight_count = 0;
  let claim_lost_count = 0;
  let lease_lost_count = 0;
  let network_sends_performed = 0;
  let examined = 0;
  let pages = 0;
  let budget_exhausted = false;
  let cursor = null;

  // Held rows (turned-off rules) are excluded from `listPage`; count them up front, read-only, so
  // they are reported without being claimed, gated and released on every call.
  if (typeof input.summarizeHeld === 'function') {
    const held = await input.summarizeHeld({ ruleId: ruleIdFilter, attemptIds });
    held_count += Number(held?.held_count ?? 0);
    for (const id of held?.held_attempt_ids ?? []) seenAttemptIds.add(String(id));
  }

  const summaryBase = (event, attempt) => ({
    event_id: event.id ?? null,
    prior_attempt_id: attempt.id ?? null,
    rule_id: attempt.rule_id ?? null,
    channel: String(attempt.channel ?? ''),
  });

  for (;;) {
    if (examined >= maxItems) {
      budget_exhausted = true;
      break;
    }
    const limit = Math.min(pageSize, maxItems - examined);
    const page = await input.listPage({ limit, after: cursor, ruleId: ruleIdFilter, attemptIds });
    pages += 1;
    if (!Array.isArray(page) || page.length === 0) break;

    for (const { event, attempt, lease_active: leaseActive } of page) {
      const attemptId = String(attempt.id ?? '');
      if (!attemptId || createdAttemptIds.has(attemptId)) continue;
      examined += 1;
      seenAttemptIds.add(attemptId);
      const base = summaryBase(event, attempt);

      if (base.channel === 'in_app') {
        skipped_count += 1;
        continue;
      }
      if (leaseActive === true) {
        // Another redrive owns this row right now; it records its own outcome.
        in_flight_count += 1;
        continue;
      }

      const ruleId = String(attempt.rule_id ?? '');
      const outcomeId = newAttemptId(String(event.id ?? ''), ruleId, attemptId);

      if (dryRun) {
        const { rule, gate, cancellation } = await resolveNotificationRuleForDelivery({
          ruleId,
          trigger: typeof event.trigger === 'string' ? event.trigger : null,
          resolveRule: input.resolveRule,
        });
        if (gate === NOTIFICATION_RULE_GATE.UNKNOWN || !rule) {
          skipped_count += 1;
          continue;
        }
        let status = 'redrive_planned';
        if (gate === NOTIFICATION_RULE_GATE.HOLD) {
          held_count += 1;
          status = NOTIFICATION_RULE_HELD_STATUS;
        } else if (gate === NOTIFICATION_RULE_GATE.CANCEL) {
          cancelled_count += 1;
          status = cancellation?.status ?? NOTIFICATION_RULE_REMOVED_STATUS;
        }
        processed.push({ ...base, status, dry_run: true });
        continue;
      }

      const claimToken = input.newClaimToken();
      const claimed = await input.claim(attemptId, claimToken);
      if (!claimed) {
        claim_lost_count += 1;
        continue;
      }

      // Ownership must hold over the ENTIRE post-claim interval, not just the send: a rule
      // read that outlasts the lease would let another redrive reclaim, complete, and
      // requeue/send first. The heartbeat therefore starts right after the claim, and
      // ownership is re-confirmed immediately before provider I/O below.
      let timer = null;
      if (typeof input.renew === 'function') {
        timer = setInterval(() => {
          Promise.resolve()
            .then(() => input.renew(attemptId, claimToken))
            .catch(() => input.onLeaseRenewFailed?.());
        }, Math.max(10, Math.floor(Number(input.leaseMs) / 3)));
        timer.unref?.();
      }
      let gateResult;
      let record;
      let cancelled = false;
      try {
        try {
          gateResult = await resolveNotificationRuleForDelivery({
            ruleId,
            trigger: typeof event.trigger === 'string' ? event.trigger : null,
            resolveRule: input.resolveRule,
          });
        } catch (err) {
          await Promise.resolve(input.release(attemptId, claimToken)).catch(() => {});
          throw err;
        }
        const { rule, gate } = gateResult;
        if (gate === NOTIFICATION_RULE_GATE.UNKNOWN || !rule) {
          // A transient release failure must not abort the batch; the lease simply expires.
          await Promise.resolve(input.release(attemptId, claimToken)).catch(() => {});
          skipped_count += 1;
          continue;
        }
        if (gate === NOTIFICATION_RULE_GATE.HOLD) {
          // Turned off: give the claim back; the DLQ row stays untouched for a later redrive.
          // Same as above, a failed release must not abort the remaining rows.
          await Promise.resolve(input.release(attemptId, claimToken)).catch(() => {});
          held_count += 1;
          processed.push({ ...base, status: NOTIFICATION_RULE_HELD_STATUS, dry_run: false });
          continue;
        }
        if (gate === NOTIFICATION_RULE_GATE.CANCEL) {
          cancelled = true;
          record = buildRuleRemovedCancellationAttempt({
            attempt: claimed,
            now,
            newAttemptId: outcomeId,
            cancellation: gateResult.cancellation,
          });
        } else {
          // Confirm ownership immediately before provider I/O: renewal returns `renewed: false`
          // when the lease expired and another sender took over (or the row was superseded).
          // A renewal that cannot be verified is treated as lost, never sent on a guess.
          let ownership = null;
          if (typeof input.renew === 'function') {
            try {
              ownership = await input.renew(attemptId, claimToken);
            } catch {
              ownership = { renewed: false };
            }
            if (ownership?.renewed !== true) {
              lease_lost_count += 1;
              continue;
            }
          }
          record = await buildDlqRedriveDeliveryAttempt({
            attempt: claimed,
            event,
            rule,
            now,
            newAttemptId: outcomeId,
            deliveryMode: input.deliveryMode,
            webhookSender: input.webhookSender,
            fetchFn: input.fetchFn,
            emailDeliverer: input.emailDeliverer,
            slackDeliverer: input.slackDeliverer,
            teamsDeliverer: input.teamsDeliverer,
          });
          if (
            adapterModeActive
            && (record.status === 'delivered_provider' || record.status === 'provider_retry_scheduled')
          ) {
            network_sends_performed += 1;
          }
        }
      } finally {
        if (timer) clearInterval(timer);
      }

      const completion = await input.complete({
        attemptId,
        claimToken,
        eventId: String(event.id ?? ''),
        record,
      });
      if (!completion?.completed) {
        // Lease lost mid-send: the new owner records its own outcome; this call writes nothing.
        lease_lost_count += 1;
        continue;
      }
      createdAttemptIds.add(String(record.id));
      if (cancelled) cancelled_count += 1;
      processed.push({
        ...base,
        attempt_id: record.id,
        rule_id: record.rule_id ?? null,
        channel: record.channel ?? null,
        status: record.status,
        attempt_number: record.attempt_number ?? null,
        max_attempts: record.max_attempts ?? null,
        next_retry_at: record.next_retry_at ?? null,
        exhausted: record.exhausted ?? null,
        dry_run: false,
        delivery_record: record,
      });
    }

    const last = page.at(-1).attempt;
    // The cursor must carry the database's full timestamp precision: a Date-mapped created_at
    // loses microseconds (pg parses to ms), so the keyset comparison would re-serve the
    // boundary row on every page and starve everything behind it.
    cursor = { created_at: String(last.created_at_cursor ?? last.created_at), id: String(last.id) };
    if (page.length < limit) break;
  }

  if (attemptIds) {
    for (const requestedId of attemptIds) {
      if (!seenAttemptIds.has(requestedId)) skipped_count += 1;
    }
  }

  const notRequeued = new Set(['provider_failed_dlq', NOTIFICATION_RULE_HELD_STATUS, ...NOTIFICATION_RULE_CANCELLED_STATUSES]);
  const requeued_count = processed.filter((item) =>
    dryRun ? item.status === 'redrive_planned' : !notRequeued.has(String(item.status))).length;
  const still_dlq_count = typeof input.countDlq === 'function' ? await input.countDlq() : null;

  return {
    delivery_mode: input.deliveryMode,
    dry_run: dryRun,
    requeued_count,
    skipped_count,
    still_dlq_count,
    held_count,
    cancelled_count,
    in_flight_count,
    claim_lost_count,
    lease_lost_count,
    pages_read: pages,
    work_budget: maxItems,
    budget_exhausted,
    processed,
    network_sends_performed: dryRun ? 0 : network_sends_performed,
  };
}

/**
 * @param {Array<Record<string, unknown>>} events
 * @param {Array<Record<string, unknown>>} processed
 */
export function applyDlqRedriveRecords(events, processed) {
  const byEventId = new Map();
  for (const item of processed) {
    const record = item.delivery_record;
    if (!record || typeof record !== 'object') continue;
    const eventId = String(item.event_id ?? '');
    if (!eventId) continue;
    if (!byEventId.has(eventId)) byEventId.set(eventId, []);
    byEventId.get(eventId).push(record);
  }

  return events.map((event) => {
    const eventId = String(event.id ?? '');
    const additions = byEventId.get(eventId);
    if (!additions?.length) return event;
    const attempts = Array.isArray(event.delivery_attempts) ? [...event.delivery_attempts] : [];
    attempts.push(...additions);
    return { ...event, delivery_attempts: attempts };
  });
}