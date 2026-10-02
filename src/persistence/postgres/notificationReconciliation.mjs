import { incMetric } from '../../lib/metrics.mjs';
import { withTenantContext } from './tenantContext.mjs';
import {
  highSeverityFindingDedupeKey,
  safeTestCompletedDedupeKey,
} from './notificationServiceAdapters.mjs';

/**
 * Durable reconciliation for lifecycle notifications (R03).
 *
 * The run/report emitters enqueue the outbox event in a transaction separate from the domain
 * write (report row, verdict + finding publication). If that enqueue fails, or the process dies
 * between the domain commit and the enqueue, the domain row is the durable record that a
 * notification is owed. This pass discovers committed domain records whose notification identity
 * (dedupe key) has no `notification_events` row and enqueues it through the same idempotent
 * outbox (`INSERT ... ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`), so a live emitter racing
 * the pass, two concurrent passes, or repeated passes still record exactly one event per identity.
 *
 * Only records produced while a subscribing rule was already live, enabled, and unchanged are
 * reconciled (rule `created_at` and `updated_at` at or before the record time), and the event is
 * addressed only to those rules, so creating, re-enabling, or re-subscribing a rule never
 * back-fills old records. A high-severity finding qualifies only if its creating verdict was
 * high, matching the live hook. Reconciled pending attempts are left for the calling recovery
 * tick's claimed drain rather than the in-process worker. Records are bounded to a lookback
 * window and must be older than a short grace so the live emitter normally wins.
 *
 * Reconciliation floor (upgrade safety): builds before migration 0062 had no Postgres live emitter
 * for these triggers, so records they committed were never owed a notification even though a
 * long-standing rule was subscribed. Every pass therefore also requires the record time to be at
 * or after a floor: the `applied_at` of migration 0062 in `schema_migrations` (the deploy that
 * introduced the live emitters), raised further by an optional configured `reconcileSince`. If the
 * floor cannot be established the pass reconciles nothing (fail closed).
 */

/** Records older than this are not reconciled (the scheduler must run within this window). */
export const NOTIFICATION_RECONCILE_LOOKBACK_MS = 24 * 60 * 60_000;
/** Records younger than this are left to the live emitter. */
export const NOTIFICATION_RECONCILE_GRACE_MS = 60_000;
/** Maximum records enqueued per trigger per pass; the next pass continues with the rest. */
export const NOTIFICATION_RECONCILE_BATCH_LIMIT = 200;
/**
 * Migration shipped with the Postgres lifecycle emitters and this pass. Its `applied_at` is the
 * reconciliation floor: records committed earlier came from a build that never notified them.
 */
export const NOTIFICATION_RECONCILE_FLOOR_MIGRATION = '0062_notification_outbox_reconciliation';

const REPORT_READY_KEY_PREFIX = 'report.ready:report:';
const SAFE_TEST_COMPLETED_KEY_PREFIX = 'safe_test.completed:run:';
const HIGH_SEVERITY_KEY_PREFIX = 'finding.high_severity:finding:';
const HIGH_SEVERITY_KEY_VERDICT_SEP = ':verdict:';

/** Outbox identity for a report.ready notification. */
export function reportReadyDedupeKey(reportId) {
  return `${REPORT_READY_KEY_PREFIX}${reportId}`;
}

/**
 * report.ready payload, shared by the live emitter and reconciliation so both produce the same
 * event for one report.
 * @param {{ id?: string | null, title?: string | null, kind?: string | null }} report
 */
export function reportReadyNotification(report) {
  const reportId = report?.id ?? null;
  return {
    trigger: 'report.ready',
    subject: `Report ready: ${report?.title ?? 'AstraNull Readiness Summary'}`,
    metadata: { report_id: reportId, kind: report?.kind ?? null },
    dedupeKey: reportId ? reportReadyDedupeKey(reportId) : undefined,
  };
}

/**
 * safe_test.completed payload; matches registerPostgresRunNotificationHook.
 * @param {{ id: string, check_id?: string | null, target_group_id?: string | null }} run
 */
export function safeTestCompletedNotification(run) {
  return {
    trigger: 'safe_test.completed',
    subject: `Safe validation run ${run.id} completed`,
    metadata: { run_id: run.id, check_id: run.check_id ?? null, target_group_id: run.target_group_id ?? null },
    dedupeKey: safeTestCompletedDedupeKey(run.id),
  };
}

/**
 * finding.high_severity payload; matches registerPostgresRunNotificationHook.
 * @param {{ id: string, title?: string | null, severity: string, verdict_id: string }} finding
 * @param {string} runId
 */
export function highSeverityFindingNotification(finding, runId) {
  return {
    trigger: 'finding.high_severity',
    subject: finding.title ?? `High-severity finding on run ${runId}`,
    metadata: {
      finding_id: finding.id,
      severity: finding.severity,
      verdict_id: finding.verdict_id,
      test_run_id: runId,
    },
    dedupeKey: highSeverityFindingDedupeKey(finding.id, finding.verdict_id),
  };
}

function toIso(value) {
  if (value == null) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

/**
 * Verdicts whose publication creates a high-severity finding (FINDING_VERDICT_SEVERITY in
 * validationServiceAdapters.mjs). A finding created by any other verdict (edge_exposed -> medium)
 * and later raised to high by another run's verdict never got a live alert, so it is not owed.
 */
const HIGH_SEVERITY_CREATING_VERDICTS = Object.freeze(['bypassable', 'penetrated']);

/**
 * Rules that were live, enabled, and subscribed to $2 when the record at `timeExpr` committed, as
 * an `eligible_rule_ids` text[] (NULL when none). That is the set the live emitter would have
 * addressed, so only those rules are owed the notification.
 *
 * The rule row keeps only its current state, so a rule qualifies only if that state already held
 * at record time: created at or before it, and not changed since (`updated_at`, which every
 * enable/disable, trigger, destination change and removal sets). A rule that was off, or did not
 * list the trigger, when the record committed and was re-enabled or re-subscribed later is
 * therefore never back-filled (R01 hold semantics). The trade-off is conservative: a rule edited
 * between the record and the reconcile pass is not reconciled for that record, so recovery can
 * miss a notification but never sends one the live path would not have.
 */
function eligibleRulesLateral(timeExpr) {
  return `CROSS JOIN LATERAL (
    SELECT array_agg(nr.id ORDER BY nr.id) AS rule_ids
    FROM notification_rules nr
    WHERE nr.tenant_id = $1
      AND nr.deleted_at IS NULL
      AND nr.enabled IS NOT FALSE
      AND nr.created_at <= ${timeExpr}
      AND (nr.updated_at IS NULL OR nr.updated_at <= ${timeExpr})
      AND (
        nr.triggers_json ? $2
        OR (jsonb_array_length(COALESCE(nr.triggers_json, '[]'::jsonb)) = 0 AND nr.trigger = $2)
      )
  ) er`;
}

function toRuleIds(value) {
  return Array.isArray(value) ? value.map(String) : [];
}

/**
 * Tenant-scoped anti-join reads: committed domain records with no outbox event for their identity.
 * Each read returns at most `limit` rows ordered oldest first.
 * @param {import('pg').Pool} pool
 */
export function createNotificationReconciliationRepository(pool) {
  /** applied_at never changes once recorded, so the first successful read is reused. */
  let cachedFloor = null;
  return {
    /**
     * Reconciliation floor: when migration 0062 (live emitters + reconciliation) was applied, as
     * an ISO string, or null when it is not recorded. `schema_migrations` is a global table
     * without tenant RLS; the read still runs inside the caller's tenant context.
     */
    async getReconciliationFloor(ctx) {
      if (cachedFloor) return cachedFloor;
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT applied_at FROM schema_migrations WHERE version = $1`,
          [NOTIFICATION_RECONCILE_FLOOR_MIGRATION],
        );
        cachedFloor = rows[0]?.applied_at ? toIso(rows[0].applied_at) : null;
        return cachedFloor;
      });
    },

    async listUnnotifiedReports(ctx, { from, to, limit }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT r.id, r.kind, r.title, r.created_at, er.rule_ids AS eligible_rule_ids
           FROM reports r
           ${eligibleRulesLateral('r.created_at')}
           WHERE r.tenant_id = $1
             AND r.status = 'ready'
             AND r.created_at >= $3::timestamptz AND r.created_at <= $4::timestamptz
             AND NOT EXISTS (
               SELECT 1 FROM notification_events e
               WHERE e.tenant_id = r.tenant_id AND e.dedupe_key = $6 || r.id
             )
             AND er.rule_ids IS NOT NULL
           ORDER BY r.created_at ASC, r.id ASC
           LIMIT $5`,
          [ctx.tenantId, 'report.ready', from, to, limit, REPORT_READY_KEY_PREFIX],
        );
        return rows.map((row) => ({
          id: row.id,
          kind: row.kind,
          title: row.title,
          created_at: toIso(row.created_at),
          eligible_rule_ids: toRuleIds(row.eligible_rule_ids),
        }));
      });
    },

    async listUnnotifiedVerdictedRuns(ctx, { from, to, limit }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT r.id, r.check_id, r.target_group_id, v.id AS verdict_id, v.created_at AS published_at,
                  er.rule_ids AS eligible_rule_ids
           FROM verdicts v
           JOIN test_runs r ON r.tenant_id = v.tenant_id AND r.id = v.test_run_id
           ${eligibleRulesLateral('v.created_at')}
           WHERE v.tenant_id = $1
             AND r.status = 'verdicted'
             AND v.created_at >= $3::timestamptz AND v.created_at <= $4::timestamptz
             AND NOT EXISTS (
               SELECT 1 FROM notification_events e
               WHERE e.tenant_id = r.tenant_id AND e.dedupe_key = $6 || r.id
             )
             AND er.rule_ids IS NOT NULL
           ORDER BY v.created_at ASC, v.id ASC
           LIMIT $5`,
          [ctx.tenantId, 'safe_test.completed', from, to, limit, SAFE_TEST_COMPLETED_KEY_PREFIX],
        );
        return rows.map((row) => ({
          id: row.id,
          check_id: row.check_id ?? null,
          target_group_id: row.target_group_id ?? null,
          verdict_id: row.verdict_id,
          published_at: toIso(row.published_at),
          eligible_rule_ids: toRuleIds(row.eligible_rule_ids),
        }));
      });
    },

    /**
     * High/critical findings created high by a verdicted run's publication (finding.verdict_id
     * whose own verdict maps to high). A finding created medium and escalated later by another
     * run keeps its creating verdict_id, and the live hook alerts for neither run, so it is
     * excluded here too.
     */
    async listUnnotifiedHighSeverityFindings(ctx, { from, to, limit }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT f.id, f.title, f.severity, f.verdict_id, v.test_run_id, f.created_at,
                  er.rule_ids AS eligible_rule_ids
           FROM findings f
           JOIN verdicts v ON v.tenant_id = f.tenant_id AND v.id = f.verdict_id
           JOIN test_runs r ON r.tenant_id = v.tenant_id AND r.id = v.test_run_id
           ${eligibleRulesLateral('f.created_at')}
           WHERE f.tenant_id = $1
             AND f.severity IN ('high', 'critical')
             AND v.verdict = ANY($8::text[])
             AND r.status = 'verdicted'
             AND f.created_at >= $3::timestamptz AND f.created_at <= $4::timestamptz
             AND NOT EXISTS (
               SELECT 1 FROM notification_events e
               WHERE e.tenant_id = f.tenant_id
                 AND e.dedupe_key = $6 || f.id || $7 || f.verdict_id
             )
             AND er.rule_ids IS NOT NULL
           ORDER BY f.created_at ASC, f.id ASC
           LIMIT $5`,
          [
            ctx.tenantId,
            'finding.high_severity',
            from,
            to,
            limit,
            HIGH_SEVERITY_KEY_PREFIX,
            HIGH_SEVERITY_KEY_VERDICT_SEP,
            [...HIGH_SEVERITY_CREATING_VERDICTS],
          ],
        );
        return rows.map((row) => ({
          id: row.id,
          title: row.title ?? null,
          severity: row.severity,
          verdict_id: row.verdict_id,
          test_run_id: row.test_run_id,
          created_at: toIso(row.created_at),
          eligible_rule_ids: toRuleIds(row.eligible_rule_ids),
        }));
      });
    },
  };
}

function boundedMs(value, fallback) {
  const n = Math.trunc(Number(value));
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

const MAX_AUDITED_EVENT_IDS = 50;

/**
 * Builds the reconciliation pass registered on the notification service. Each discovered record is
 * enqueued independently (one failure never skips another) and a failed record is simply found
 * again by the next pass, because nothing is marked done outside the outbox itself.
 * @param {{
 *   repository: ReturnType<typeof createNotificationReconciliationRepository>,
 *   notifications: { enqueueNotification: Function },
 *   audit?: { appendAuditEvent?: Function },
 *   lookbackMs?: number,
 *   graceMs?: number,
 *   batchLimit?: number,
 * }} deps
 */
export function createNotificationOutboxReconciler(deps) {
  const { repository, notifications, audit } = deps;
  const lookbackMs = boundedMs(deps.lookbackMs, NOTIFICATION_RECONCILE_LOOKBACK_MS);
  const graceMs = boundedMs(deps.graceMs, NOTIFICATION_RECONCILE_GRACE_MS);
  const batchLimit = Math.max(1, Math.min(1000, boundedMs(deps.batchLimit, NOTIFICATION_RECONCILE_BATCH_LIMIT) || 1));
  let configuredSinceMs = null;
  if (deps.reconcileSince != null && deps.reconcileSince !== '') {
    configuredSinceMs = new Date(deps.reconcileSince).getTime();
    if (!Number.isFinite(configuredSinceMs)) {
      throw new Error('notification reconciliation: invalid reconcileSince timestamp.');
    }
  }

  /**
   * Earliest record time owed by reconciliation, in ms, or null when there is no floor. A
   * repository that exposes `getReconciliationFloor` (the Postgres one) must return a timestamp;
   * a missing one means the live-emitter migration is not recorded, so nothing is owed (NaN).
   */
  async function resolveFloorMs(ctx) {
    let floorMs = configuredSinceMs;
    if (typeof repository.getReconciliationFloor === 'function') {
      const floor = await repository.getReconciliationFloor(ctx);
      const deployedMs = floor == null ? Number.NaN : new Date(floor).getTime();
      if (!Number.isFinite(deployedMs)) return Number.NaN;
      floorMs = floorMs == null ? deployedMs : Math.max(floorMs, deployedMs);
    }
    return floorMs;
  }

  /** @type {Array<{ trigger: string, list: Function, build: (row: any) => Record<string, unknown> }>} */
  const sources = [
    {
      trigger: 'report.ready',
      list: repository.listUnnotifiedReports,
      build: (row) => reportReadyNotification(row),
    },
    {
      trigger: 'safe_test.completed',
      list: repository.listUnnotifiedVerdictedRuns,
      build: (row) => safeTestCompletedNotification(row),
    },
    {
      trigger: 'finding.high_severity',
      list: repository.listUnnotifiedHighSeverityFindings,
      build: (row) => highSeverityFindingNotification(row, row.test_run_id),
    },
  ].filter((source) => typeof source.list === 'function');

  return async function reconcileNotificationOutbox(ctx, { asOf, dryRun = false } = {}) {
    const asOfMs = new Date(asOf).getTime();
    if (!Number.isFinite(asOfMs)) throw new Error('notification reconciliation: invalid as-of timestamp.');
    const toMs = asOfMs - graceMs;
    let fromMs = asOfMs - lookbackMs;
    // Upgrade safety: never reconcile records committed before the live emitters shipped.
    let floorMs = null;
    let floorFailed = false;
    try {
      floorMs = await resolveFloorMs(ctx);
    } catch {
      incMetric('notification_reconcile_failed');
      floorFailed = true;
    }
    const floorUnknown = floorFailed || Number.isNaN(floorMs);
    if (floorMs != null && Number.isFinite(floorMs)) fromMs = Math.max(fromMs, floorMs);
    const window = {
      from: new Date(fromMs).toISOString(),
      to: new Date(toMs).toISOString(),
      limit: batchLimit,
    };
    // Fail closed: an unknown floor or an empty window reads nothing.
    const skipReads = floorUnknown || fromMs > toMs;

    const byTrigger = {};
    const eventIds = [];
    let missing = 0;
    let reconciled = 0;
    let alreadyRecorded = 0;
    let noSubscriber = 0;
    let failed = floorFailed ? 1 : 0;

    for (const source of sources) {
      const counts = { missing: 0, reconciled: 0, failed: 0 };
      byTrigger[source.trigger] = counts;
      if (skipReads) continue;
      let rows;
      try {
        rows = (await source.list.call(repository, ctx, window)) ?? [];
      } catch {
        incMetric('notification_reconcile_failed');
        counts.failed += 1;
        failed += 1;
        continue;
      }
      counts.missing = rows.length;
      missing += rows.length;
      if (dryRun) continue;

      for (const row of rows) {
        try {
          const result = await notifications.enqueueNotification(ctx, {
            ...source.build(row),
            // Only rules subscribed when the record committed are owed it (R03 fan-out).
            ...(Array.isArray(row.eligible_rule_ids) ? { ruleIds: row.eligible_rule_ids } : {}),
            // The calling recovery tick's claimed drain delivers it; never the in-process worker,
            // which a one-shot runner would cut off by closing its pool mid-send.
            deferToRecovery: true,
            recoveryAsOf: new Date(asOfMs).toISOString(),
          });
          if (result?.inserted) {
            counts.reconciled += 1;
            reconciled += 1;
            if (result.event?.id) eventIds.push(result.event.id);
          } else if (result?.event) {
            alreadyRecorded += 1;
          } else {
            noSubscriber += 1;
          }
        } catch {
          incMetric('notification_reconcile_failed');
          counts.failed += 1;
          failed += 1;
        }
      }
    }

    if (reconciled > 0) incMetric('notification_reconciled', reconciled);
    if (reconciled > 0 && typeof audit?.appendAuditEvent === 'function') {
      await audit.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId ?? null,
        actor_role: ctx.role ?? null,
        action: 'notification.outbox_reconciled',
        resource_type: 'notification_outbox',
        resource_id: ctx.tenantId,
        metadata: {
          as_of: new Date(asOfMs).toISOString(),
          reconciled_count: reconciled,
          by_trigger: Object.fromEntries(
            Object.entries(byTrigger).map(([trigger, c]) => [trigger, c.reconciled]),
          ),
          event_ids: eventIds.slice(0, MAX_AUDITED_EVENT_IDS),
        },
      });
    }

    return {
      dry_run: dryRun,
      window_from: window.from,
      window_to: window.to,
      floor: floorUnknown ? null : floorMs == null ? null : new Date(floorMs).toISOString(),
      floor_unavailable: floorUnknown,
      missing_count: missing,
      reconciled_count: dryRun ? 0 : reconciled,
      already_recorded_count: alreadyRecorded,
      no_subscriber_count: noSubscriber,
      failed_count: failed,
      by_trigger: byTrigger,
    };
  };
}

/**
 * Wires reconciliation into `notifications.processDueNotificationRetries` (the recovery worker),
 * so every scheduler/runner tick also closes the domain-commit -> enqueue gap.
 * @param {{
 *   pool?: import('pg').Pool,
 *   repository?: ReturnType<typeof createNotificationReconciliationRepository>,
 *   notifications: { enqueueNotification?: Function, registerNotificationReconciler?: Function },
 *   audit?: { appendAuditEvent?: Function },
 *   lookbackMs?: number,
 *   graceMs?: number,
 *   batchLimit?: number,
 * }} deps
 * @returns {(() => void) | null} unregister function, or null when the service cannot host it
 */
export function registerPostgresNotificationReconciliation(deps) {
  const { notifications } = deps ?? {};
  if (typeof notifications?.registerNotificationReconciler !== 'function') return null;
  if (typeof notifications.enqueueNotification !== 'function') return null;
  const repository = deps.repository ?? (deps.pool ? createNotificationReconciliationRepository(deps.pool) : null);
  if (!repository) return null;
  return notifications.registerNotificationReconciler(
    createNotificationOutboxReconciler({ ...deps, repository }),
  );
}
