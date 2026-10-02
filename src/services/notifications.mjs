import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { redactString } from '../lib/redact.mjs';
import {
  resolveNotificationDeliveryMode,
} from '../lib/notificationDelivery.mjs';
import {
  finalizeGatedNotificationDeliveryAttempts,
} from '../lib/notificationRetry.mjs';
import {
  buildNotificationDeliveryAttempt,
  buildRedactedNotificationEventPayload,
  notificationDeliveryNote,
  formatNotificationRuleForRead,
  normalizeNotificationRuleInput,
} from '../lib/notifications.mjs';
import {
  latestDeliveryByRuleFromEvents,
  normalizeNotificationRuleUpdate,
  notificationRuleUpdateAuditMetadata,
} from '../lib/notificationRuleUpdate.mjs';
import { getStore, persistStore } from '../store.mjs';
import { incMetric } from '../lib/metrics.mjs';
import { registerRunTerminalHook } from './runTerminalHooks.mjs';

function ensure() {
  const store = getStore();
  if (!store.notificationRules) store.notificationRules = [];
  if (!store.notificationEvents) store.notificationEvents = [];
  return store;
}

export { destinationPreview } from '../lib/notifications.mjs';

/** Size of the recent-events feed returned by GET /v1/notifications. */
export const NOTIFICATION_EVENTS_WINDOW = 100;

function liveTenantRules(store, ctx) {
  return store.notificationRules.filter((r) => r.tenant_id === ctx.tenantId && !r.deleted_at);
}

export function listNotifications(ctx) {
  const store = ensure();
  const rules = liveTenantRules(store, ctx);
  const tenantEvents = store.notificationEvents.filter((e) => e.tenant_id === ctx.tenantId);
  // The per-rule latest delivery is computed over the full tenant history, not the bounded feed,
  // so a quiet rule is never reported as "never delivered" just because other rules were busy.
  const latestByRule = latestDeliveryByRuleFromEvents(tenantEvents);
  const latest_deliveries = {};
  for (const rule of rules) latest_deliveries[rule.id] = latestByRule.get(rule.id) ?? null;
  const events = tenantEvents.slice(-NOTIFICATION_EVENTS_WINDOW);
  return {
    rules: rules.map((r) => formatNotificationRuleForRead(r)),
    events,
    latest_deliveries,
    events_window: {
      limit: NOTIFICATION_EVENTS_WINDOW,
      returned: events.length,
      truncated: tenantEvents.length > events.length,
    },
  };
}

function findLiveRule(store, ctx, ruleId) {
  return store.notificationRules.find(
    (r) => r.id === ruleId && r.tenant_id === ctx.tenantId && !r.deleted_at,
  ) ?? null;
}

/**
 * Update a rule's enabled flag, triggers, or destination. Tenant-scoped: another tenant's rule
 * id resolves to null (404). Validation reuses the create path.
 * @returns {Record<string, unknown> | null | { error: string, status: number }}
 */
export function updateNotificationRule(ctx, ruleId, body) {
  const store = ensure();
  const rule = findLiveRule(store, ctx, ruleId);
  if (!rule) return null;
  const update = normalizeNotificationRuleUpdate(rule, body);
  if (!update.ok) return update;
  if (update.changedFields.length === 0) return rule;

  Object.assign(rule, update.changes, {
    updated_at: new Date().toISOString(),
    updated_by: ctx.userId,
  });
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'notification.rule_updated',
    resource_type: 'notification_rule',
    resource_id: rule.id,
    metadata: notificationRuleUpdateAuditMetadata(rule, update.changedFields),
  });
  persistStore();
  return rule;
}

/**
 * Remove a rule. Soft delete: delivery history stays attributable, the stored destination is
 * cleared, and the rule never emits, retries, or redrives again.
 * @returns {{ id: string, deleted: true, deleted_at: string } | null}
 */
export function deleteNotificationRule(ctx, ruleId) {
  const store = ensure();
  const rule = findLiveRule(store, ctx, ruleId);
  if (!rule) return null;
  const now = new Date().toISOString();
  Object.assign(rule, {
    enabled: false,
    destination: '',
    deleted_at: now,
    updated_at: now,
    updated_by: ctx.userId,
  });
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'notification.rule_deleted',
    resource_type: 'notification_rule',
    resource_id: rule.id,
    metadata: { channel: rule.channel },
  });
  persistStore();
  return { id: rule.id, deleted: true, deleted_at: now };
}

export function createNotificationRule(ctx, body) {
  const normalized = normalizeNotificationRuleInput(body);
  if (!normalized.ok) return normalized;

  const store = ensure();
  const rule = {
    id: newId('nrule'),
    tenant_id: ctx.tenantId,
    channel: normalized.channel,
    destination: normalized.destination,
    triggers: normalized.triggers,
    enabled: normalized.enabled,
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
    delivery_note: notificationDeliveryNote(normalized.channel),
  };
  store.notificationRules.push(rule);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'notification.rule_created',
    resource_type: 'notification_rule',
    resource_id: rule.id,
    metadata: { channel: rule.channel, trigger_count: rule.triggers.length },
  });
  persistStore();
  return rule;
}

/** True when the tenant has at least one enabled rule for the trigger (avoids empty ledger rows). */
export function hasActiveNotificationRule(ctx, trigger) {
  const store = ensure();
  return store.notificationRules.some(
    (r) => r.tenant_id === ctx.tenantId && r.enabled && Array.isArray(r.triggers) && r.triggers.includes(trigger),
  );
}

/**
 * Fire-and-forget emit used by domain services. Skips tenants with no matching rule and never
 * lets a notification failure break the caller.
 */
export function emitNotificationIfSubscribed(ctx, input) {
  if (!hasActiveNotificationRule(ctx, input.trigger)) return;
  emitNotification(ctx, input).catch(() => incMetric('notification_emit_failed'));
}

// safe_test.completed: a safe validation run reached a verdict.
registerRunTerminalHook((run, context = {}) => {
  if (!run || context.reason !== 'verdicted' || !run.tenant_id) return;
  emitNotificationIfSubscribed(
    { tenantId: run.tenant_id, userId: 'system', role: 'system' },
    {
      trigger: 'safe_test.completed',
      subject: `Safe validation run ${run.id} completed`,
      metadata: { run_id: run.id, check_id: run.check_id ?? null, target_group_id: run.target_group_id ?? null },
    },
  );
});

export async function emitNotification(ctx, { trigger, subject, metadata = {} }, options = {}) {
  const store = ensure();
  const now = new Date().toISOString();
  const rules = store.notificationRules.filter(
    (r) => r.tenant_id === ctx.tenantId && r.enabled && r.triggers.includes(trigger),
  );

  const eventId = newId('nevt');
  const redacted = buildRedactedNotificationEventPayload(subject, metadata);
  const initialAttempts = rules.map((rule) => buildNotificationDeliveryAttempt(eventId, rule, now));
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
    // R01: re-gate every rule on its live store state right before the send, so a rule disabled
    // or removed after the snapshot above is never delivered to.
    resolveRule: (ruleId) =>
      store.notificationRules.find((r) => r.tenant_id === ctx.tenantId && r.id === ruleId) ?? null,
  });

  const event = {
    id: eventId,
    tenant_id: ctx.tenantId,
    trigger,
    subject: redacted.subject,
    metadata: redacted.metadata,
    delivery_attempts,
    created_at: now,
  };
  store.notificationEvents.push(event);

  audit({
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
    audit({
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

  persistStore();
  return event;
}
