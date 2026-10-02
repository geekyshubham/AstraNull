/**
 * Pure helpers for the Notification channels panel (Slack, Microsoft Teams, Email, Webhook).
 *
 * Plain ESM so node:test exercises the shipped logic directly. Validation mirrors the backend
 * contract in src/lib/notifications.mjs (rule creation) and src/lib/notificationDelivery.mjs
 * (outbound precheck), and is intentionally a little stricter: the UI refuses a destination the
 * delivery path would later reject, so a rule is never saved that can only ever fail.
 */

export const MAX_DESTINATION_LENGTH = 2048;

/** Channels offered as connectable cards. `in_app` is a backend channel but not a connector. */
export const NOTIFICATION_CHANNELS = Object.freeze([
  Object.freeze({
    id: 'slack',
    label: 'Slack',
    kind: 'Incoming webhook',
    description: 'Post readiness alerts to a Slack channel as Block Kit messages.',
    destinationLabel: 'Slack webhook URL',
    placeholder: 'https://hooks.slack.com/services/…',
    hint: 'Starts with https://hooks.slack.com/services/. The URL is a secret; it is stored server-side and only a host preview is shown back.',
    docsUrl: 'https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/',
    docsLabel: 'Slack incoming webhooks guide',
    inputType: 'url',
  }),
  Object.freeze({
    id: 'teams',
    label: 'Microsoft Teams',
    kind: 'Workflows webhook',
    description: 'Post Adaptive Cards to a Teams channel through a Workflows webhook.',
    destinationLabel: 'Workflows webhook URL',
    placeholder: 'https://…/workflows/…',
    hint: 'Copy the URL shown after saving the Workflows template. Legacy Microsoft 365 connector URLs are being retired.',
    docsUrl: 'https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook',
    docsLabel: 'Microsoft Learn: create an incoming webhook',
    inputType: 'url',
  }),
  Object.freeze({
    id: 'email',
    label: 'Email',
    kind: 'SMTP',
    description: 'Send an HTML summary to a team inbox or distribution list.',
    destinationLabel: 'Recipient address',
    placeholder: 'alerts@example.com',
    hint: 'One address per channel. A shared distribution list works best for on-call rotations.',
    docsUrl: '',
    docsLabel: '',
    inputType: 'email',
  }),
  Object.freeze({
    id: 'webhook',
    label: 'Webhook',
    kind: 'HTTPS POST',
    description: 'POST redacted event JSON to your own endpoint, SIEM, or automation.',
    destinationLabel: 'Endpoint URL',
    placeholder: 'https://hooks.example.com/astranull',
    hint: 'HTTPS only. Redirects are not followed and credentials in the URL are rejected.',
    docsUrl: '',
    docsLabel: '',
    inputType: 'url',
  }),
]);

/** Mirrors ALLOWED_TRIGGERS in src/lib/notifications.mjs (parity is asserted in unit tests). */
export const NOTIFICATION_TRIGGER_OPTIONS = Object.freeze([
  Object.freeze({ id: 'finding.high_severity', label: 'High-severity finding', detail: 'A new high or critical finding is recorded.' }),
  Object.freeze({ id: 'high_scale.state_change', label: 'High-scale state change', detail: 'A SOC-governed high-scale request changes state.' }),
  Object.freeze({ id: 'safe_test.completed', label: 'Safe test completed', detail: 'A safe validation run finishes.' }),
  Object.freeze({ id: 'report.ready', label: 'Report ready', detail: 'A readiness report is generated.' }),
]);

/** Mirrors DEFAULT_TRIGGERS in src/lib/notifications.mjs. */
export const DEFAULT_NOTIFICATION_TRIGGERS = Object.freeze(['finding.high_severity', 'high_scale.state_change']);

const SLACK_HOSTS = new Set(['hooks.slack.com', 'hooks.slack-gov.com']);
// Control characters and whitespace are never valid in a destination. Rejecting them in the UI
// also keeps CR/LF out of anything that is later written into an SMTP envelope or header.
const CONTROL_OR_SPACE = /[\s\u0000-\u001f\u007f]/;
const EMAIL_PATTERN = /^[^@\s<>()[\]\\,;:"]+@[^@\s<>()[\]\\,;:"]+\.[^@\s<>()[\]\\,;:".]{2,}$/;

export function findNotificationChannel(channelId) {
  return NOTIFICATION_CHANNELS.find((channel) => channel.id === channelId) ?? null;
}

export function notificationChannelLabel(channelId) {
  if (channelId === 'in_app') return 'In-app';
  return findNotificationChannel(channelId)?.label ?? String(channelId ?? '').replace(/_/g, ' ');
}

export function notificationTriggerLabel(triggerId) {
  const known = NOTIFICATION_TRIGGER_OPTIONS.find((option) => option.id === triggerId);
  if (known) return known.label;
  return String(triggerId ?? '').replace(/[._]/g, ' ');
}

function isDevOnlyHttpHost(hostname) {
  const host = hostname.toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host.endsWith('.invalid');
}

/**
 * Parse an outbound HTTPS destination using the same rules as the delivery precheck
 * (rejectWebhookDestinationWithCredentials): https, or plain http only for dev hosts,
 * and never with user:password@ credentials.
 */
function parseHttpsDestination(destination, { allowDevHttp }) {
  let url;
  try {
    url = new URL(destination);
  } catch {
    return { error: 'Enter a full URL, starting with https://.' };
  }
  if (url.username || url.password) {
    return { error: 'Remove the user:password@ part. Credentials in the URL are not allowed.' };
  }
  if (url.protocol === 'https:') return { url, devOnly: false };
  if (url.protocol === 'http:' && allowDevHttp && isDevOnlyHttpHost(url.hostname)) {
    return { url, devOnly: true };
  }
  return { error: 'Use an https:// URL. Plain http is only accepted for local development hosts.' };
}

/**
 * @param {string} channel
 * @param {unknown} raw
 * @returns {{ ok: true, destination: string, warning?: string } | { ok: false, error: string }}
 */
export function validateChannelDestination(channel, raw) {
  const destination = typeof raw === 'string' ? raw.trim() : '';
  const meta = findNotificationChannel(channel);
  if (!meta) return { ok: false, error: 'Choose Slack, Microsoft Teams, Email, or Webhook.' };
  if (!destination) return { ok: false, error: `Enter the ${meta.destinationLabel.toLowerCase()}.` };
  if (destination.length > MAX_DESTINATION_LENGTH) {
    return { ok: false, error: `Keep the destination under ${MAX_DESTINATION_LENGTH} characters.` };
  }
  if (CONTROL_OR_SPACE.test(destination)) {
    return { ok: false, error: 'Remove spaces or line breaks from the destination.' };
  }

  if (channel === 'email') {
    if (!EMAIL_PATTERN.test(destination)) {
      return { ok: false, error: 'Enter a single email address, such as alerts@example.com.' };
    }
    return { ok: true, destination };
  }

  const parsed = parseHttpsDestination(destination, { allowDevHttp: true });
  if ('error' in parsed) return { ok: false, error: parsed.error };
  const host = parsed.url.hostname.toLowerCase();
  const devWarning = parsed.devOnly
    ? 'Plain http is accepted for local development only. Use https:// in production.'
    : undefined;

  if (channel === 'slack') {
    if (!SLACK_HOSTS.has(host) || !parsed.url.pathname.startsWith('/services/')) {
      return {
        ok: true,
        destination,
        warning: devWarning ?? 'This does not look like a Slack incoming webhook (https://hooks.slack.com/services/…). Check the URL you copied.',
      };
    }
    return { ok: true, destination };
  }

  if (channel === 'teams') {
    if (host.endsWith('.webhook.office.com') || host === 'outlook.office.com') {
      return {
        ok: true,
        destination,
        warning: 'This is a legacy Microsoft 365 connector URL. Microsoft is retiring these; create a Workflows webhook instead.',
      };
    }
    return devWarning ? { ok: true, destination, warning: devWarning } : { ok: true, destination };
  }

  return devWarning ? { ok: true, destination, warning: devWarning } : { ok: true, destination };
}

/**
 * Validate a trigger selection against the allowed set; returns the list in canonical order.
 * @param {unknown} selected
 */
export function normalizeSelectedTriggers(selected) {
  const list = Array.isArray(selected) ? selected : [];
  const out = NOTIFICATION_TRIGGER_OPTIONS.map((option) => option.id).filter((id) => list.includes(id));
  if (out.length === 0) return { ok: false, error: 'Pick at least one event to notify on.' };
  return { ok: true, triggers: out };
}

/**
 * Honest wording for a delivery-attempt status recorded by the backend ledger.
 *
 * When there is no attempt, the wording depends on where that absence came from:
 * - `source: 'authoritative'`: the server checked the full attempt history for the rule, so
 *   "nothing recorded yet" is a true statement.
 * - otherwise: only the bounded recent-events feed was searched, so we say exactly that and never
 *   claim that no event has ever fired.
 * @param {unknown} status
 * @param {{ source?: 'authoritative' | 'window', windowSize?: number }} [context]
 */
export function deliveryStatusPresentation(status, context = {}) {
  switch (status) {
    case 'delivered_provider':
      return { label: 'Delivered', tone: 'success', detail: 'The provider accepted the last message.' };
    case 'delivered_in_app':
      return { label: 'In-app feed', tone: 'success', detail: 'Recorded in the tenant in-app feed.' };
    case 'queued_provider_not_configured':
      return {
        label: 'Recorded, not sent',
        tone: 'muted',
        detail: 'Outbound delivery for this channel is not enabled on the server, so the event was recorded in the ledger only.',
      };
    case 'provider_retry_scheduled':
      return { label: 'Retry scheduled', tone: 'warn', detail: 'The last send failed and a retry is scheduled.' };
    case 'provider_failed_dlq':
      return { label: 'Failed', tone: 'danger', detail: 'Retries were exhausted and the attempt is in the dead-letter queue.' };
    default:
      if (typeof status === 'string' && status) {
        return { label: status.replace(/_/g, ' '), tone: 'info', detail: 'The server recorded this delivery status.' };
      }
      if (context.source === 'authoritative') {
        return {
          label: 'No deliveries yet',
          tone: 'muted',
          detail: 'The server has no delivery attempt recorded for this channel.',
        };
      }
      return {
        label: 'None in recent history',
        tone: 'muted',
        detail: noAttemptInWindowDetail(context.windowSize),
      };
  }
}

function noAttemptInWindowDetail(windowSize) {
  const size = Number(windowSize);
  const scope = Number.isFinite(size) && size > 0
    ? `the ${size} most recent notification events loaded`
    : 'the recent notification events loaded';
  return `No delivery attempt for this channel appears in ${scope}. Older history is not shown here.`;
}

/**
 * Pick the latest delivery for one rule. The server's per-rule answer (computed over the full
 * attempt history) wins; the bounded events feed is only a fallback for older servers.
 * @param {string} ruleId
 * @param {{
 *   latestDeliveries?: Record<string, Record<string, unknown> | null> | null,
 *   eventsLatest?: Map<string, Record<string, unknown>>,
 *   windowSize?: number,
 * }} input
 * @returns {{ attempt: Record<string, unknown> | null, source: 'authoritative' | 'window', windowSize?: number }}
 */
export function resolveRuleLatestDelivery(ruleId, input = {}) {
  const authoritative = input.latestDeliveries;
  if (authoritative && typeof authoritative === 'object' && Object.prototype.hasOwnProperty.call(authoritative, ruleId)) {
    const attempt = authoritative[ruleId];
    return { attempt: attempt && typeof attempt === 'object' ? attempt : null, source: 'authoritative' };
  }
  const fromWindow = input.eventsLatest instanceof Map ? input.eventsLatest.get(ruleId) ?? null : null;
  return { attempt: fromWindow, source: 'window', windowSize: input.windowSize };
}

/**
 * Identity a notifications response belongs to. A response fetched for one tenant/user/token must
 * never be applied after the session switched to another.
 * @param {unknown} session
 */
export function notificationSessionKey(session) {
  const value = session && typeof session === 'object' ? /** @type {Record<string, unknown>} */ (session) : {};
  return [value.tenant_id, value.user_id, value.role, value.access_token]
    .map((part) => (part == null ? '' : String(part)))
    .join('|');
}

/**
 * Latest-request-wins guard for overlapping loads. Each `begin(key)` supersedes every earlier
 * request; `isCurrent(token, key)` is true only for the newest request issued for that same
 * identity and not yet cancelled. `cancel()` (unmount/cleanup) invalidates everything in flight.
 */
export function createLatestRequestGuard() {
  let generation = 0;
  let activeKey = null;
  return {
    /** @param {string} key */
    begin(key) {
      generation += 1;
      activeKey = key;
      return { generation, key };
    },
    /**
     * @param {{ generation: number, key: string }} token
     * @param {string} [currentKey] identity at resolution time; defaults to the token's own key
     */
    isCurrent(token, currentKey = token?.key) {
      return Boolean(token)
        && token.generation === generation
        && token.key === activeKey
        && token.key === currentKey;
    },
    cancel() {
      generation += 1;
      activeKey = null;
    },
  };
}

/**
 * Edit-dialog validation for an existing rule. A blank destination keeps the stored one (the UI
 * only ever sees a redacted preview); a filled one is validated like a new connection.
 * @param {string} channel
 * @param {{ destination?: unknown, triggers?: unknown }} draft
 * @returns {{ ok: true, body: { triggers: string[], destination?: string }, warning?: string } | { ok: false, field: 'destination' | 'triggers', error: string }}
 */
export function buildRuleUpdateBody(channel, draft) {
  const triggers = normalizeSelectedTriggers(draft?.triggers);
  if (!triggers.ok) return { ok: false, field: 'triggers', error: triggers.error };
  const raw = typeof draft?.destination === 'string' ? draft.destination.trim() : '';
  if (!raw) return { ok: true, body: { triggers: triggers.triggers } };
  const destination = validateChannelDestination(channel, raw);
  if (!destination.ok) return { ok: false, field: 'destination', error: destination.error };
  return {
    ok: true,
    body: { triggers: triggers.triggers, destination: destination.destination },
    ...(destination.warning ? { warning: destination.warning } : {}),
  };
}

/**
 * Latest delivery attempt per rule id, across the events returned by GET /v1/notifications.
 * @param {unknown} events
 * @returns {Map<string, Record<string, unknown>>}
 */
export function latestAttemptByRule(events) {
  const latest = new Map();
  if (!Array.isArray(events)) return latest;
  for (const event of events) {
    const attempts = event && Array.isArray(event.delivery_attempts) ? event.delivery_attempts : [];
    for (const attempt of attempts) {
      const ruleId = attempt && typeof attempt.rule_id === 'string' ? attempt.rule_id : '';
      if (!ruleId) continue;
      const stamp = Date.parse(String(attempt.attempted_at ?? attempt.created_at ?? event.created_at ?? ''));
      const current = latest.get(ruleId);
      const currentStamp = current ? Number(current.__sort ?? Number.NEGATIVE_INFINITY) : Number.NEGATIVE_INFINITY;
      const sortValue = Number.isFinite(stamp) ? stamp : Number.NEGATIVE_INFINITY;
      if (!current || sortValue >= currentStamp) {
        latest.set(ruleId, { ...attempt, __sort: sortValue });
      }
    }
  }
  for (const [ruleId, attempt] of latest) {
    const { __sort, ...rest } = attempt;
    void __sort;
    latest.set(ruleId, rest);
  }
  return latest;
}

/**
 * Connected/enabled counts per channel id.
 * @param {unknown} rules
 */
export function summarizeChannelRules(rules) {
  /** @type {Record<string, { total: number, enabled: number }>} */
  const summary = {};
  for (const channel of NOTIFICATION_CHANNELS) summary[channel.id] = { total: 0, enabled: 0 };
  if (!Array.isArray(rules)) return summary;
  for (const rule of rules) {
    const id = rule && typeof rule.channel === 'string' ? rule.channel : '';
    if (!summary[id]) summary[id] = { total: 0, enabled: 0 };
    summary[id].total += 1;
    if (rule.enabled !== false) summary[id].enabled += 1;
  }
  return summary;
}

/** Placeholder shown in the Teams sample; the real link is built from the server's portal URL. */
export const SAMPLE_PORTAL_URL = 'https://<your-portal>/app#notifications';

const SAMPLE_EVENT = Object.freeze({
  event_id: 'nevt_example',
  rule_id: 'nrule_example',
  trigger: 'finding.high_severity',
  subject: 'High-severity finding on api.example.com',
  metadata: { target: 'api.example.com', severity: 'high' },
  created_at: '<ISO-8601 timestamp>',
});

/**
 * Example of the body AstraNull sends for a channel. Shapes mirror buildSlackPayload,
 * buildTeamsPayload, buildEmailPayload, and buildWebhookNotificationBody (asserted in tests).
 * @param {string} channel
 */
export function buildSampleChannelPayload(channel) {
  const metadataSummary = Object.entries(SAMPLE_EVENT.metadata).map(([key, value]) => `${key}: ${value}`).join('\n');
  if (channel === 'slack') {
    return {
      blocks: [
        { type: 'section', text: { type: 'mrkdwn', text: `*${SAMPLE_EVENT.trigger}*\n${SAMPLE_EVENT.subject}` } },
        { type: 'context', elements: [{ type: 'mrkdwn', text: `Recorded at ${SAMPLE_EVENT.created_at}` }] },
        { type: 'section', text: { type: 'mrkdwn', text: metadataSummary } },
      ],
    };
  }
  if (channel === 'teams') {
    return {
      type: 'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          content: {
            $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
            type: 'AdaptiveCard',
            version: '1.4',
            body: [
              { type: 'TextBlock', text: SAMPLE_EVENT.trigger, weight: 'Bolder', size: 'Medium' },
              { type: 'TextBlock', text: SAMPLE_EVENT.subject, wrap: true },
              { type: 'TextBlock', text: metadataSummary, wrap: true },
              { type: 'TextBlock', text: SAMPLE_EVENT.created_at, isSubtle: true },
            ],
            // Sent only when the server has ASTRANULL_PORTAL_URL (or ASTRANULL_PUBLIC_BASE_URL) set.
            actions: [{ type: 'Action.OpenUrl', title: 'View in AstraNull', url: SAMPLE_PORTAL_URL }],
          },
        },
      ],
    };
  }
  if (channel === 'email') {
    return {
      to: 'alerts@example.com',
      subject: `[AstraNull] ${SAMPLE_EVENT.subject}`,
      html_body: 'Table with Trigger, Subject, Metadata, and Timestamp rows',
    };
  }
  return {
    event_id: SAMPLE_EVENT.event_id,
    rule_id: SAMPLE_EVENT.rule_id,
    trigger: SAMPLE_EVENT.trigger,
    subject: SAMPLE_EVENT.subject,
    metadata: { ...SAMPLE_EVENT.metadata },
    created_at: SAMPLE_EVENT.created_at,
  };
}
