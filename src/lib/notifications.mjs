import { redactObject, redactString } from './redact.mjs';
import {
  isDeliveryChannelActive,
  parseNotificationDeliveryModes,
  rejectProviderDestinationWithCredentials,
} from './notificationDelivery.mjs';

export const ALLOWED_CHANNELS = new Set(['in_app', 'webhook', 'email', 'slack', 'teams']);

export const ALLOWED_TRIGGERS = new Set([
  'finding.high_severity',
  'safe_test.completed',
  'high_scale.state_change',
  'report.ready',
]);

export const DEFAULT_TRIGGERS = ['finding.high_severity', 'high_scale.state_change'];

export const MAX_DESTINATION_LENGTH = 2048;

// Whitespace and control characters are never valid in a destination. Rejecting them server-side
// keeps CR/LF out of SMTP envelopes and headers no matter which client created the rule.
const CONTROL_OR_SPACE = /[\s\u0000-\u001f\u007f]/;
// Same single addr-spec shape the portal enforces (apps/web/react/src/lib/notification-channels.mjs).
const EMAIL_PATTERN = /^[^@\s<>()[\]\\,;:"]+@[^@\s<>()[\]\\,;:"]+\.[^@\s<>()[\]\\,;:".]{2,}$/;

const CHANNEL_DISPLAY_NAMES = Object.freeze({
  webhook: 'Webhook',
  email: 'Email',
  slack: 'Slack',
  teams: 'Microsoft Teams',
});

/**
 * Honest, mode-aware note for a newly created rule. Replaces the old fixed "metadata only" note,
 * which was wrong once an operator enabled outbound delivery.
 * @param {string} channel
 * @param {{ deliveryMode?: string, smtpHost?: string }} [options]
 */
export function notificationDeliveryNote(channel, options = {}) {
  if (channel === 'in_app') return 'Events are recorded in the in-app feed.';
  const name = CHANNEL_DISPLAY_NAMES[channel] ?? channel;
  const modes = parseNotificationDeliveryModes(
    options.deliveryMode ?? process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE,
  );
  if (!isDeliveryChannelActive(modes, channel)) {
    return `Outbound delivery for ${name} is not enabled on this server, so events are recorded in the delivery ledger only.`;
  }
  if (channel === 'email') {
    const host = options.smtpHost ?? process.env.ASTRANULL_SMTP_HOST;
    if (!host || !String(host).trim()) {
      return 'Email delivery is enabled, but no SMTP relay is configured, so events are recorded in the delivery ledger only.';
    }
  }
  return `Outbound delivery for ${name} is enabled.`;
}

function normalizeChannel(raw) {
  if (typeof raw !== 'string') return null;
  const channel = raw.trim().toLowerCase();
  return ALLOWED_CHANNELS.has(channel) ? channel : null;
}

function normalizeTriggers(raw) {
  if (raw === undefined || raw === null) return [...DEFAULT_TRIGGERS];
  const list = Array.isArray(raw) ? raw : [raw];
  if (list.length === 0) return null;
  const out = [];
  for (const item of list) {
    if (typeof item !== 'string' || !item.trim()) return null;
    const trigger = item.trim();
    if (!ALLOWED_TRIGGERS.has(trigger)) return null;
    if (!out.includes(trigger)) out.push(trigger);
  }
  return out;
}

function isAllowedWebhookDestination(destination) {
  let url;
  try {
    url = new URL(destination);
  } catch {
    return false;
  }
  if (url.protocol === 'https:') return true;
  if (url.protocol !== 'http:') return false;
  const host = url.hostname.toLowerCase();
  if (host === '127.0.0.1' || host === 'localhost') return true;
  if (host.endsWith('.invalid')) return true;
  return false;
}

function validateDestination(channel, destination) {
  if (channel === 'in_app') return { ok: true, destination: '' };
  if (typeof destination !== 'string' || !destination.trim()) {
    return { error: 'missing_destination', status: 400 };
  }
  const normalized = destination.trim();
  if (normalized.length > MAX_DESTINATION_LENGTH || CONTROL_OR_SPACE.test(normalized)) {
    return { error: 'invalid_destination', status: 400 };
  }
  if (channel === 'email') {
    if (!EMAIL_PATTERN.test(normalized)) return { error: 'invalid_email_destination', status: 400 };
    return { ok: true, destination: normalized };
  }
  // webhook, slack, teams: https (http only for dev hosts) and never user:password@ credentials.
  if (!isAllowedWebhookDestination(normalized)) {
    return { error: 'invalid_webhook_destination', status: 400 };
  }
  const credentialCheck = rejectProviderDestinationWithCredentials(normalized);
  if (!credentialCheck.ok) return { error: credentialCheck.error, status: 400 };
  return { ok: true, destination: normalized };
}

/**
 * @param {Record<string, unknown> | null | undefined} body
 */
export function normalizeNotificationRuleInput(body) {
  const channel = normalizeChannel(body?.channel ?? 'webhook');
  if (!channel) {
    return { error: 'invalid_channel', status: 400 };
  }

  const triggers = normalizeTriggers(body?.triggers);
  if (!triggers) {
    return { error: 'invalid_trigger', status: 400 };
  }

  const destCheck = validateDestination(channel, body?.destination);
  if (!destCheck.ok) return destCheck;

  return {
    ok: true,
    channel,
    destination: destCheck.destination,
    triggers,
    enabled: body?.enabled !== false,
  };
}

export function destinationPreview(channel, destination) {
  const redacted = redactString(String(destination ?? ''));
  if (channel === 'webhook') {
    try {
      const u = new URL(destination);
      const pathHint = u.pathname && u.pathname !== '/' ? '…' : '';
      return `webhook://${u.hostname}${pathHint}`;
    } catch {
      return `webhook:${redacted.slice(0, 40)}`;
    }
  }
  if (channel === 'email') {
    const at = redacted.indexOf('@');
    if (at > 0) return `email:${redacted[0]}…@${redacted.slice(at + 1)}`;
    return `email:${redacted.slice(0, 24)}`;
  }
  if (channel === 'in_app') return 'in_app:feed';
  if (channel === 'slack' || channel === 'teams') {
    // Slack and Teams webhook URLs are secrets; show only the host.
    try {
      const u = new URL(destination);
      return `${channel}://${u.hostname}${u.pathname && u.pathname !== '/' ? '…' : ''}`;
    } catch {
      return `${channel}:${redacted.slice(0, 24)}`;
    }
  }
  return `${channel}:${redacted.slice(0, 32)}`;
}

export function formatNotificationRuleForRead(rule) {
  return {
    id: rule.id,
    tenant_id: rule.tenant_id,
    channel: rule.channel,
    destination_preview: destinationPreview(rule.channel, rule.destination),
    triggers: Array.isArray(rule.triggers) ? [...rule.triggers] : [],
    enabled: rule.enabled !== false,
    created_at: rule.created_at,
    ...(rule.created_by ? { created_by: rule.created_by } : {}),
    ...(rule.delivery_note ? { delivery_note: rule.delivery_note } : {}),
  };
}

function deliveryStatusForChannel(channel) {
  if (channel === 'in_app') {
    return {
      status: 'delivered_in_app',
      reason: 'recorded_in_tenant_in_app_feed',
      attempted: true,
    };
  }
  return {
    status: 'queued_provider_not_configured',
    reason: 'outbound_provider_not_configured_opt_in',
    attempted: false,
  };
}

/**
 * @param {string} eventId
 * @param {{ id: string, channel: string, destination: string }} rule
 * @param {string} now
 */
export function buildNotificationDeliveryAttempt(eventId, rule, now) {
  const { status, reason, attempted } = deliveryStatusForChannel(rule.channel);
  return {
    id: `natt_${eventId}_${rule.id}`,
    rule_id: rule.id,
    channel: rule.channel,
    destination_preview: destinationPreview(rule.channel, rule.destination),
    status,
    reason,
    created_at: now,
    attempted_at: attempted ? now : null,
  };
}

/**
 * @param {string} subject
 * @param {Record<string, unknown>} [metadata]
 */
export function buildRedactedNotificationEventPayload(subject, metadata = {}) {
  return {
    subject: redactString(subject),
    metadata: redactObject(metadata),
  };
}
