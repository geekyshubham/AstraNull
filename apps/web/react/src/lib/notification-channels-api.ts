import { requestJson } from './api';
import type { PortalConfig, Session } from './types';

/** Rule shape returned by GET/POST /v1/notifications (formatNotificationRuleForRead). */
export type NotificationRule = {
  id: string;
  channel: string;
  destination_preview: string;
  triggers: string[];
  enabled: boolean;
  created_at?: string;
  created_by?: string;
  updated_at?: string;
  delivery_note?: string;
};

export type NotificationDeliveryAttempt = {
  id?: string;
  rule_id?: string;
  channel?: string;
  destination_preview?: string;
  status?: string;
  reason?: string;
  created_at?: string;
  attempted_at?: string | null;
};

export type NotificationEvent = {
  id?: string;
  trigger?: string;
  subject?: string;
  created_at?: string;
  delivery_attempts?: NotificationDeliveryAttempt[];
};

/**
 * Window metadata for the bounded recent-events feed. `truncated` means older events exist
 * beyond what was returned, so absence in `events` is not absence in history.
 */
export type NotificationEventsWindow = {
  limit: number;
  returned: number;
  truncated: boolean;
};

export type NotificationsPayload = {
  rules: NotificationRule[];
  events: NotificationEvent[];
  /**
   * Authoritative latest delivery attempt per rule id, computed by the server over the full
   * attempt history. `null` for a rule means the server has no attempt for it. Absent (`null`
   * here) when the server is too old to provide it; the UI then falls back to `events`.
   */
  latestDeliveries: Record<string, NotificationDeliveryAttempt | null> | null;
  eventsWindow: NotificationEventsWindow | null;
};

export type UpdateNotificationRuleInput = {
  enabled?: boolean;
  triggers?: string[];
  /** Replacement destination. Omit to keep the stored one (the UI only sees a redacted preview). */
  destination?: string;
};

export type CreateNotificationRuleInput = {
  channel: 'slack' | 'teams' | 'email' | 'webhook';
  destination: string;
  triggers: string[];
  enabled: boolean;
};

function asRule(value: unknown): NotificationRule | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  if (typeof item.id !== 'string' || typeof item.channel !== 'string') return null;
  return {
    id: item.id,
    channel: item.channel,
    // Never fall back to a raw destination: the API only exposes the redacted preview.
    destination_preview: typeof item.destination_preview === 'string' ? item.destination_preview : '',
    triggers: Array.isArray(item.triggers) ? item.triggers.map(String) : [],
    enabled: item.enabled !== false,
    created_at: typeof item.created_at === 'string' ? item.created_at : undefined,
    created_by: typeof item.created_by === 'string' ? item.created_by : undefined,
    delivery_note: typeof item.delivery_note === 'string' ? item.delivery_note : undefined
  };
}

function asAttempt(value: unknown): NotificationDeliveryAttempt | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  const text = (key: string) => (typeof item[key] === 'string' ? (item[key] as string) : undefined);
  return {
    id: text('id'),
    rule_id: text('rule_id'),
    status: text('status'),
    reason: text('reason'),
    created_at: text('created_at'),
    attempted_at: typeof item.attempted_at === 'string' ? item.attempted_at : null
  };
}

function asLatestDeliveries(value: unknown): Record<string, NotificationDeliveryAttempt | null> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const out: Record<string, NotificationDeliveryAttempt | null> = {};
  for (const [ruleId, attempt] of Object.entries(value as Record<string, unknown>)) {
    out[ruleId] = asAttempt(attempt);
  }
  return out;
}

function asEventsWindow(value: unknown): NotificationEventsWindow | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  const limit = Number(item.limit);
  const returned = Number(item.returned);
  if (!Number.isFinite(limit) || limit <= 0) return null;
  return {
    limit,
    returned: Number.isFinite(returned) ? returned : 0,
    truncated: item.truncated === true
  };
}

export function normalizeNotificationsPayload(payload: unknown): NotificationsPayload {
  const body = payload && typeof payload === 'object' ? (payload as Record<string, unknown>) : {};
  const rules = Array.isArray(body.rules) ? body.rules.map(asRule).filter((rule): rule is NotificationRule => rule !== null) : [];
  const events = Array.isArray(body.events) ? (body.events as NotificationEvent[]) : [];
  return {
    rules,
    events,
    latestDeliveries: asLatestDeliveries(body.latest_deliveries),
    eventsWindow: asEventsWindow(body.events_window)
  };
}

export async function fetchNotifications(config: PortalConfig, session: Session): Promise<NotificationsPayload> {
  const payload = await requestJson(config, session, '/v1/notifications');
  return normalizeNotificationsPayload(payload);
}

export async function createNotificationChannelRule(
  config: PortalConfig,
  session: Session,
  input: CreateNotificationRuleInput
): Promise<NotificationRule> {
  const payload = await requestJson(config, session, '/v1/notifications', {
    method: 'POST',
    body: {
      channel: input.channel,
      destination: input.destination,
      triggers: input.triggers,
      enabled: input.enabled
    }
  });
  const rule = asRule(payload);
  if (!rule) throw new Error('The server did not return the created channel.');
  return rule;
}

export async function updateNotificationChannelRule(
  config: PortalConfig,
  session: Session,
  ruleId: string,
  input: UpdateNotificationRuleInput
): Promise<NotificationRule> {
  const body: Record<string, unknown> = {};
  if (input.enabled !== undefined) body.enabled = input.enabled;
  if (input.triggers !== undefined) body.triggers = input.triggers;
  if (input.destination !== undefined) body.destination = input.destination;
  const payload = await requestJson(config, session, `/v1/notifications/${encodeURIComponent(ruleId)}`, {
    method: 'PATCH',
    body
  });
  const rule = asRule(payload);
  if (!rule) throw new Error('The server did not return the updated channel.');
  return rule;
}

export async function deleteNotificationChannelRule(config: PortalConfig, session: Session, ruleId: string): Promise<void> {
  await requestJson(config, session, `/v1/notifications/${encodeURIComponent(ruleId)}`, { method: 'DELETE' });
}
