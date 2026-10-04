import { useCallback, useEffect, useId, useMemo, useRef, useState, type FocusEvent, type FormEvent, type ReactNode } from 'react';
import type { HTMLAttributes } from 'react';
import { BellRing, CircleCheck, CircleDashed, ExternalLink, Info, Pencil, Plus, Power, RefreshCw, Trash2 } from 'lucide-react';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card } from '../ui/card';
import { EmptyState } from '../ui/empty-state';
import { RoleRestrictedCard } from '../ui/role-restricted';
import { DataTable, type TableColumn } from '../ui/table';
import { ConfirmModal, FormModal } from '../../lib/crud-ui';
import { canReadDataset, sessionHasPermission } from '../../lib/dataset-access.mjs';
import { apiErrorMessage } from '../../lib/error-messages';
import {
  createNotificationChannelRule,
  deleteNotificationChannelRule,
  fetchNotifications,
  updateNotificationChannelRule,
  type NotificationDeliveryAttempt,
  type NotificationEvent,
  type NotificationEventsWindow,
  type NotificationRule
} from '../../lib/notification-channels-api';
import {
  DEFAULT_NOTIFICATION_TRIGGERS,
  NOTIFICATION_CHANNELS,
  NOTIFICATION_TRIGGER_OPTIONS,
  buildRuleUpdateBody,
  buildSampleChannelPayload,
  createLatestRequestGuard,
  deliveryStatusPresentation,
  findNotificationChannel,
  latestAttemptByRule,
  normalizeSelectedTriggers,
  notificationChannelLabel,
  notificationSessionKey,
  notificationTriggerLabel,
  resolveRuleLatestDelivery,
  summarizeChannelRules,
  validateChannelDestination,
  type NotificationChannelId,
  type NotificationChannelMeta
} from '../../lib/notification-channels.mjs';
import type { PortalConfig, Session } from '../../lib/types';
import { formatDate, formatNumber } from '../../lib/utils';
import { ChannelLogo } from './channel-logos';
import { INTEGRATION_TILE_STYLES } from './integration-tile-styles';
import { NOTIFICATION_CHANNELS_STYLES } from './notification-channels-styles';

type LoadState = 'loading' | 'ready' | 'error';

const DELIVERY_MODE_NOTE =
  'Outbound delivery is opt-in on the server. Until an operator enables it for a channel, AstraNull records each event in the delivery ledger and does not send it.';

function DocsLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a className="nc-docs-link" href={href} target="_blank" rel="noopener noreferrer">
      {children}
      <ExternalLink size={14} aria-hidden="true" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}

/** Setup steps verified against the providers' current documentation. */
function SetupInstructions({ channel }: { channel: NotificationChannelMeta }) {
  if (channel.id === 'slack') {
    return (
      <section className="nc-setup" aria-label="Slack setup steps">
        <h4>Create a Slack incoming webhook</h4>
        <ol className="nc-steps">
          <li>Open <strong>api.slack.com/apps</strong>, choose <strong>Create New App</strong>, then <strong>From scratch</strong>, and pick your workspace.</li>
          <li>Under <strong>Features</strong>, open <strong>Incoming Webhooks</strong> and switch <strong>Activate Incoming Webhooks</strong> on.</li>
          <li>Select <strong>Add New Webhook to Workspace</strong>, choose the channel that should receive alerts, and select <strong>Authorize</strong>.</li>
          <li>Copy the webhook URL. It looks like <code>https://hooks.slack.com/services/T…/B…/…</code>. Paste it below.</li>
        </ol>
        <p className="nc-note">Treat the URL like a password. Slack revokes webhook URLs it finds published online.</p>
        <DocsLink href={channel.docsUrl}>{channel.docsLabel}</DocsLink>
      </section>
    );
  }
  if (channel.id === 'teams') {
    return (
      <section className="nc-setup" aria-label="Microsoft Teams setup steps">
        <h4>Create a Teams Workflows webhook</h4>
        <ol className="nc-steps">
          <li>In Microsoft Teams, go to the channel that should receive alerts, select <strong>More options (…)</strong>, then <strong>Workflows</strong>.</li>
          <li>Search for the template <strong>Send webhook alerts to a channel</strong> and select it.</li>
          <li>Confirm the team and channel, then select <strong>Save</strong>.</li>
          <li>Copy the webhook URL shown once the workflow is created. Paste it below.</li>
        </ol>
        <p className="nc-note">
          Microsoft 365 (Office 365) connectors are being retired, so use Workflows rather than the legacy Incoming Webhook connector.
          A workflow belongs to the person who created it; add a co-owner so alerts keep flowing if that person leaves. Teams messages are limited to 28 KB, and larger cards are refused before sending. The card includes a View in AstraNull button when your operator sets <code>ASTRANULL_PORTAL_URL</code>.
        </p>
        <DocsLink href={channel.docsUrl}>{channel.docsLabel}</DocsLink>
      </section>
    );
  }
  if (channel.id === 'email') {
    return (
      <section className="nc-setup" aria-label="Email setup steps">
        <h4>Send alerts to an inbox</h4>
        <ol className="nc-steps">
          <li>Pick a shared mailbox or distribution list that your on-call team reads.</li>
          <li>Enter the address below and choose which events should send mail.</li>
          <li>Ask your mail admin to allow the AstraNull sender address so alerts are not filtered as spam.</li>
        </ol>
        <p className="nc-note">
          Email is sent through the SMTP relay your operator configures (<code>ASTRANULL_SMTP_HOST</code>). STARTTLS is required by default, and AstraNull never stores mailbox passwords for recipients.
        </p>
      </section>
    );
  }
  return (
    <section className="nc-setup" aria-label="Webhook setup steps">
      <h4>Receive events on your own endpoint</h4>
      <ol className="nc-steps">
        <li>Expose an <strong>HTTPS</strong> endpoint that accepts <code>POST</code> with <code>Content-Type: application/json</code>.</li>
        <li>Return any <code>2xx</code> status within 10 seconds. Redirects (<code>3xx</code>) are treated as failures and are not followed.</li>
        <li>Requests carry no signature header yet, so use a long, unguessable path segment and check that <code>event_id</code> is new before acting on it.</li>
        <li>Paste the endpoint URL below. Payloads are capped at 32 KB and are redacted before they leave AstraNull.</li>
      </ol>
      <p className="nc-note">Never put <code>user:password@</code> credentials in the URL; they are rejected.</p>
    </section>
  );
}

function ConnectChannelDialog({
  channel,
  config,
  session,
  onClose,
  onConnected
}: {
  channel: NotificationChannelMeta;
  config: PortalConfig;
  session: Session;
  onClose: () => void;
  onConnected: (rule: NotificationRule) => void;
}) {
  const fieldId = useId();
  const hintId = `${fieldId}-hint`;
  const errorId = `${fieldId}-error`;
  const warningId = `${fieldId}-warning`;
  const triggerErrorId = `${fieldId}-trigger-error`;
  const [destination, setDestination] = useState('');
  const [destinationError, setDestinationError] = useState('');
  const [destinationWarning, setDestinationWarning] = useState('');
  const [triggers, setTriggers] = useState<string[]>([...DEFAULT_NOTIFICATION_TRIGGERS]);
  const [triggerError, setTriggerError] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');
  const destinationRef = useRef<HTMLInputElement>(null);
  const triggerFieldsetRef = useRef<HTMLFieldSetElement>(null);
  const samplePayload = useMemo(() => JSON.stringify(buildSampleChannelPayload(channel.id), null, 2), [channel.id]);

  function checkDestination(value: string) {
    const result = validateChannelDestination(channel.id, value);
    if (!result.ok) {
      setDestinationError(result.error);
      setDestinationWarning('');
      return null;
    }
    setDestinationError('');
    setDestinationWarning(result.warning ?? '');
    return result.destination;
  }

  function handleBlur(event: FocusEvent<HTMLInputElement>) {
    if (event.currentTarget.value.trim()) checkDestination(event.currentTarget.value);
  }

  function toggleTrigger(id: string) {
    setTriggerError('');
    setTriggers((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]));
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitError('');
    const validDestination = checkDestination(destination);
    const triggerCheck = normalizeSelectedTriggers(triggers);
    if (!triggerCheck.ok) setTriggerError(triggerCheck.error);
    if (!validDestination || !triggerCheck.ok) {
      // Decide from the local results: React has not re-rendered aria-invalid yet at this point.
      if (!validDestination) destinationRef.current?.focus();
      else triggerFieldsetRef.current?.focus();
      return;
    }
    setSubmitting(true);
    try {
      const rule = await createNotificationChannelRule(config, session, {
        channel: channel.id,
        destination: validDestination,
        triggers: triggerCheck.triggers,
        enabled
      });
      onConnected(rule);
    } catch (err) {
      setSubmitError(apiErrorMessage(err, `Could not connect ${channel.label}. Try again.`));
    } finally {
      setSubmitting(false);
    }
  }

  const describedBy = [hintId, destinationError ? errorId : '', destinationWarning ? warningId : ''].filter(Boolean).join(' ');

  return (
    <FormModal
      open
      wide
      title={`Connect ${channel.label}`}
      description={channel.description}
      onClose={() => {
        if (!submitting) onClose();
      }}
    >
      <div className="nc-dialog-body">
        <SetupInstructions channel={channel} />
        <form className="product-form nc-form" onSubmit={handleSubmit} noValidate aria-busy={submitting || undefined}>
          <label className="full" htmlFor={fieldId}>
            <span>{channel.destinationLabel}</span>
            <input
              ref={destinationRef}
              id={fieldId}
              name="destination"
              type={channel.inputType}
              inputMode={channel.inputType === 'email' ? 'email' : 'url'}
              autoComplete="off"
              spellCheck={false}
              placeholder={channel.placeholder}
              value={destination}
              onChange={(event) => {
                setDestination(event.target.value);
                if (destinationError) setDestinationError('');
              }}
              onBlur={handleBlur}
              aria-invalid={destinationError ? true : undefined}
              aria-describedby={describedBy}
              disabled={submitting}
              required
            />
          </label>
          <p id={hintId} className="nc-field-hint full">{channel.hint}</p>
          {destinationError ? <p id={errorId} className="nc-field-error full" role="alert">{destinationError}</p> : null}
          {destinationWarning ? <p id={warningId} className="nc-field-warning full">{destinationWarning}</p> : null}

          <fieldset
            ref={triggerFieldsetRef}
            className="full"
            aria-invalid={triggerError ? true : undefined}
            aria-describedby={triggerError ? triggerErrorId : undefined}
            tabIndex={-1}
            disabled={submitting}
          >
            <legend>Notify on</legend>
            {NOTIFICATION_TRIGGER_OPTIONS.map((option) => (
              <label key={option.id} className="check-row">
                <input
                  type="checkbox"
                  name="triggers"
                  value={option.id}
                  checked={triggers.includes(option.id)}
                  onChange={() => toggleTrigger(option.id)}
                />
                <span>
                  {option.label}
                  <span className="sr-only">: </span>
                  <span className="nc-field-hint" style={{ display: 'block' }}>{option.detail}</span>
                </span>
              </label>
            ))}
          </fieldset>
          {triggerError ? <p id={triggerErrorId} className="nc-field-error full" role="alert">{triggerError}</p> : null}

          <label className="check-row full">
            <input type="checkbox" name="enabled" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} disabled={submitting} />
            <span>Turn this channel on now</span>
          </label>

          <details className="nc-payload full">
            <summary>Example payload</summary>
            <pre aria-label={`Example ${channel.label} payload`}>{samplePayload}</pre>
          </details>

          <div className="callout info full">
            <Info size={18} aria-hidden="true" />
            <span>{DELIVERY_MODE_NOTE}</span>
          </div>

          {submitError ? <p className="form-banner error full" role="alert">{submitError}</p> : null}

          <div className="form-actions full">
            <Button type="button" variant="ghost" onClick={onClose} disabled={submitting}>Cancel</Button>
            <Button type="submit" loading={submitting}>Connect {channel.label}</Button>
          </div>
        </form>
      </div>
    </FormModal>
  );
}

function EditChannelDialog({
  rule,
  config,
  session,
  onClose,
  onSaved
}: {
  rule: NotificationRule;
  config: PortalConfig;
  session: Session;
  onClose: () => void;
  onSaved: (rule: NotificationRule) => void;
}) {
  const channel = findNotificationChannel(rule.channel);
  const fieldId = useId();
  const hintId = `${fieldId}-hint`;
  const errorId = `${fieldId}-error`;
  const warningId = `${fieldId}-warning`;
  const triggerErrorId = `${fieldId}-trigger-error`;
  const [destination, setDestination] = useState('');
  const [destinationError, setDestinationError] = useState('');
  const [destinationWarning, setDestinationWarning] = useState('');
  const [triggers, setTriggers] = useState<string[]>([...rule.triggers]);
  const [triggerError, setTriggerError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');
  const destinationRef = useRef<HTMLInputElement>(null);
  const triggerFieldsetRef = useRef<HTMLFieldSetElement>(null);
  const label = notificationChannelLabel(rule.channel);

  function toggleTrigger(id: string) {
    setTriggerError('');
    setTriggers((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]));
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitError('');
    setDestinationError('');
    setTriggerError('');
    const result = buildRuleUpdateBody(rule.channel, { destination, triggers });
    if (!result.ok) {
      if (result.field === 'destination') {
        setDestinationError(result.error);
        destinationRef.current?.focus();
      } else {
        setTriggerError(result.error);
        triggerFieldsetRef.current?.focus();
      }
      return;
    }
    setDestinationWarning(result.warning ?? '');
    setSubmitting(true);
    try {
      const updated = await updateNotificationChannelRule(config, session, rule.id, result.body);
      onSaved(updated);
    } catch (err) {
      setSubmitError(apiErrorMessage(err, `Could not update ${label}. Try again.`));
    } finally {
      setSubmitting(false);
    }
  }

  const describedBy = [hintId, destinationError ? errorId : '', destinationWarning ? warningId : ''].filter(Boolean).join(' ');

  return (
    <FormModal
      open
      title={`Edit ${label} channel`}
      description={`Currently sending to ${rule.destination_preview || 'a hidden destination'}.`}
      onClose={() => {
        if (!submitting) onClose();
      }}
    >
      <form className="product-form nc-form" onSubmit={handleSubmit} noValidate aria-busy={submitting || undefined}>
        {channel ? (
          <>
            <label className="full" htmlFor={fieldId}>
              <span>New {channel.destinationLabel.toLowerCase()} (optional)</span>
              <input
                ref={destinationRef}
                id={fieldId}
                name="destination"
                type={channel.inputType}
                inputMode={channel.inputType === 'email' ? 'email' : 'url'}
                autoComplete="off"
                spellCheck={false}
                placeholder={channel.placeholder}
                value={destination}
                onChange={(event) => {
                  setDestination(event.target.value);
                  if (destinationError) setDestinationError('');
                }}
                aria-invalid={destinationError ? true : undefined}
                aria-describedby={describedBy}
                disabled={submitting}
              />
            </label>
            <p id={hintId} className="nc-field-hint full">
              Leave blank to keep the current destination. The stored value is a secret and is never shown back.
            </p>
            {destinationError ? <p id={errorId} className="nc-field-error full" role="alert">{destinationError}</p> : null}
            {destinationWarning ? <p id={warningId} className="nc-field-warning full">{destinationWarning}</p> : null}
          </>
        ) : null}

        <fieldset
          ref={triggerFieldsetRef}
          className="full"
          aria-invalid={triggerError ? true : undefined}
          aria-describedby={triggerError ? triggerErrorId : undefined}
          tabIndex={-1}
          disabled={submitting}
        >
          <legend>Notify on</legend>
          {NOTIFICATION_TRIGGER_OPTIONS.map((option) => (
            <label key={option.id} className="check-row">
              <input
                type="checkbox"
                name="triggers"
                value={option.id}
                checked={triggers.includes(option.id)}
                onChange={() => toggleTrigger(option.id)}
              />
              <span>{option.label}</span>
            </label>
          ))}
        </fieldset>
        {triggerError ? <p id={triggerErrorId} className="nc-field-error full" role="alert">{triggerError}</p> : null}

        {submitError ? <p className="form-banner error full" role="alert">{submitError}</p> : null}

        <div className="form-actions full">
          <Button type="button" variant="ghost" onClick={onClose} disabled={submitting}>Cancel</Button>
          <Button type="submit" loading={submitting}>Save changes</Button>
        </div>
      </form>
    </FormModal>
  );
}

export type NotificationChannelsPanelProps = {
  config: PortalConfig;
  session: Session;
  /** Called after a channel is connected so the host page can refresh shared datasets. */
  onChanged?: () => void | Promise<void>;
  /** DOM id for the panel heading, so a host page can move focus to it (for example from a CTA). */
  headingId?: string;
};

/**
 * Notification connectors (Slack, Microsoft Teams, Email, Webhook).
 *
 * Reads GET /v1/notifications and creates rules with POST /v1/notifications. Only the redacted
 * `destination_preview` is ever rendered; full URLs and addresses stay server-side.
 */
export function NotificationChannelsPanel({ config, session, onChanged, headingId: headingIdProp }: NotificationChannelsPanelProps) {
  const generatedHeadingId = useId();
  const headingId = headingIdProp ?? generatedHeadingId;
  const canRead = canReadDataset(session, 'notifications');
  const canWrite = sessionHasPermission(session, 'notification:write');
  const [loadState, setLoadState] = useState<LoadState>('loading');
  const [loadError, setLoadError] = useState('');
  const [rules, setRules] = useState<NotificationRule[]>([]);
  const [events, setEvents] = useState<NotificationEvent[]>([]);
  const [latestDeliveries, setLatestDeliveries] = useState<Record<string, NotificationDeliveryAttempt | null> | null>(null);
  const [eventsWindow, setEventsWindow] = useState<NotificationEventsWindow | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [activeChannel, setActiveChannel] = useState<NotificationChannelId | null>(null);
  const [editingRule, setEditingRule] = useState<NotificationRule | null>(null);
  const [removingRule, setRemovingRule] = useState<NotificationRule | null>(null);
  const [busyRuleId, setBusyRuleId] = useState('');
  const [actionError, setActionError] = useState('');
  const [message, setMessage] = useState('');
  const [focusRuleId, setFocusRuleId] = useState(() => {
    if (typeof window === 'undefined') return '';
    const hash = window.location.hash.replace(/^#/, '');
    const index = hash.indexOf('?');
    return new URLSearchParams(index >= 0 ? hash.slice(index + 1) : '').get('focus') ?? '';
  });

  // Latest-request-wins: an older or other-session response never overwrites newer state (F04).
  const guardRef = useRef(createLatestRequestGuard());
  const sessionKey = notificationSessionKey(session);
  const sessionKeyRef = useRef(sessionKey);
  sessionKeyRef.current = sessionKey;
  const hasLoadedRef = useRef(false);

  const load = useCallback(async () => {
    const token = guardRef.current.begin(sessionKey);
    if (hasLoadedRef.current) {
      setRefreshing(true);
    } else {
      setLoadState('loading');
    }
    setLoadError('');
    try {
      const payload = await fetchNotifications(config, session);
      if (!guardRef.current.isCurrent(token, sessionKeyRef.current)) return;
      setRules(payload.rules);
      setEvents(payload.events);
      setLatestDeliveries(payload.latestDeliveries);
      setEventsWindow(payload.eventsWindow);
      hasLoadedRef.current = true;
      setLoadState('ready');
    } catch (err) {
      if (!guardRef.current.isCurrent(token, sessionKeyRef.current)) return;
      setLoadError(apiErrorMessage(err, 'Could not load notification channels.'));
      setLoadState('error');
    } finally {
      if (guardRef.current.isCurrent(token, sessionKeyRef.current)) setRefreshing(false);
    }
  }, [config, session, sessionKey]);

  useEffect(() => {
    // A new identity starts from a clean slate; nothing from the previous session stays visible.
    hasLoadedRef.current = false;
    setRules([]);
    setEvents([]);
    setLatestDeliveries(null);
    setEventsWindow(null);
  }, [sessionKey]);

  useEffect(() => {
    if (!canRead) return undefined;
    void load();
    const guard = guardRef.current;
    return () => {
      // Unmount or dependency change: results of anything still in flight are discarded.
      guard.cancel();
      setRefreshing(false);
    };
  }, [canRead, load]);

  const connectorRules = useMemo(() => rules.filter((rule) => findNotificationChannel(rule.channel)), [rules]);
  const focusRule = focusRuleId ? rules.find((rule) => rule.id === focusRuleId) ?? null : null;

  useEffect(() => {
    if (!focusRuleId || loadState !== 'ready') return;
    const frame = window.requestAnimationFrame(() => {
      const row = document.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(focusRuleId)}"]`);
      const heading = document.getElementById(headingId);
      (row ?? heading)?.scrollIntoView({ block: 'center' });
      heading?.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [focusRuleId, loadState, headingId]);
  const summary = useMemo(() => summarizeChannelRules(connectorRules), [connectorRules]);
  const latestByRule = useMemo(() => latestAttemptByRule(events), [events]);
  const active = activeChannel ? findNotificationChannel(activeChannel) : null;
  const windowSize = eventsWindow?.limit ?? (events.length || undefined);

  if (!canRead) {
    return (
      <RoleRestrictedCard
        title="Notification channels are restricted"
        body="Your role cannot view notification channels. Ask a tenant owner or admin if you need access."
      />
    );
  }

  async function handleConnected(rule: NotificationRule) {
    setActiveChannel(null);
    const note = rule.delivery_note ? ` ${rule.delivery_note}` : '';
    setMessage(`${notificationChannelLabel(rule.channel)} connected (${rule.destination_preview || 'destination hidden'}).${note}`);
    await load();
    await onChanged?.();
  }

  async function handleEdited(rule: NotificationRule) {
    setEditingRule(null);
    setMessage(`${notificationChannelLabel(rule.channel)} channel updated (${rule.destination_preview || 'destination hidden'}).`);
    await load();
    await onChanged?.();
  }

  async function toggleRule(rule: NotificationRule) {
    setActionError('');
    setMessage('');
    setBusyRuleId(rule.id);
    try {
      const updated = await updateNotificationChannelRule(config, session, rule.id, { enabled: !rule.enabled });
      setMessage(`${notificationChannelLabel(updated.channel)} channel turned ${updated.enabled ? 'on' : 'off'}.`);
      await load();
      await onChanged?.();
    } catch (err) {
      setActionError(apiErrorMessage(err, `Could not turn ${rule.enabled ? 'off' : 'on'} this channel. Try again.`));
    } finally {
      setBusyRuleId('');
    }
  }

  async function confirmRemove() {
    const rule = removingRule;
    if (!rule) return;
    setActionError('');
    setMessage('');
    setBusyRuleId(rule.id);
    try {
      await deleteNotificationChannelRule(config, session, rule.id);
      setRemovingRule(null);
      setMessage(`${notificationChannelLabel(rule.channel)} channel removed. Its delivery history is kept.`);
      await load();
      await onChanged?.();
    } catch (err) {
      setRemovingRule(null);
      setActionError(apiErrorMessage(err, 'Could not remove this channel. Try again.'));
    } finally {
      setBusyRuleId('');
    }
  }

  const writeDisabledReason = canWrite ? '' : 'Owner or admin role is required to connect or change channels.';

  const columns: TableColumn<NotificationRule>[] = [
    {
      key: 'channel',
      label: 'Channel',
      render: (rule) => (
        <span className="nc-channel-cell">
          <ChannelLogo channel={rule.channel} size="sm" />
          {notificationChannelLabel(rule.channel)}
        </span>
      )
    },
    {
      key: 'destination',
      label: 'Destination',
      render: (rule) => <span className="nc-preview">{rule.destination_preview || 'Hidden'}</span>
    },
    {
      key: 'events',
      label: 'Notifies on',
      render: (rule) => <span className="nc-events">{rule.triggers.map((trigger) => notificationTriggerLabel(trigger)).join(', ') || 'None'}</span>
    },
    {
      key: 'enabled',
      label: 'Sending',
      render: (rule) => <Badge tone="muted">{rule.enabled ? 'Enabled' : 'Disabled'}</Badge>
    },
    {
      key: 'delivery',
      label: 'Last attempt',
      render: (rule) => {
        const resolved = resolveRuleLatestDelivery(rule.id, {
          latestDeliveries,
          eventsLatest: latestByRule,
          windowSize
        });
        const presentation = deliveryStatusPresentation(resolved.attempt?.status, {
          source: resolved.source,
          windowSize: resolved.windowSize
        });
        return (
          <span className="nc-delivery-cell">
            <Badge tone={presentation.tone} title={presentation.detail}>{presentation.label}</Badge>
            <span className="sr-only">: {presentation.detail}</span>
          </span>
        );
      }
    },
    {
      key: 'created',
      label: 'Added',
      render: (rule) => (rule.created_at ? formatDate(rule.created_at) : 'Not recorded')
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (rule) => {
        const label = notificationChannelLabel(rule.channel);
        const target = `${label} channel ${rule.destination_preview || ''}`.trim();
        const busy = busyRuleId === rule.id;
        const disabled = !canWrite || Boolean(busyRuleId);
        return (
          <span className="nc-row-actions">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => void toggleRule(rule)}
              disabled={disabled}
              loading={busy && !removingRule}
              title={writeDisabledReason || undefined}
              aria-label={`${rule.enabled ? 'Turn off' : 'Turn on'} ${target}`}
            >
              <Power size={14} aria-hidden="true" />
              {rule.enabled ? 'Turn off' : 'Turn on'}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setMessage('');
                setActionError('');
                setEditingRule(rule);
              }}
              disabled={disabled}
              title={writeDisabledReason || undefined}
              aria-label={`Edit ${target}`}
            >
              <Pencil size={14} aria-hidden="true" />
              Edit
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setMessage('');
                setActionError('');
                setRemovingRule(rule);
              }}
              disabled={disabled}
              title={writeDisabledReason || undefined}
              aria-label={`Remove ${target}`}
            >
              <Trash2 size={14} aria-hidden="true" />
              Remove
            </Button>
          </span>
        );
      }
    }
  ];

  return (
    <Card className="notification-channels" role="region" aria-labelledby={headingId}>
      <style>{INTEGRATION_TILE_STYLES}</style>
      <style>{NOTIFICATION_CHANNELS_STYLES}</style>
      <div className="nc-heading">
        <div>
          <h2 id={headingId} className="card-title" tabIndex={-1}>Notification channels</h2>
          <p>Destinations for readiness alerts. A configured channel is not proof of delivery: check its last attempt. Routing rules and failed deliveries are managed on <a href="#notifications">Notifications</a>.</p>
        </div>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => void load()}
          disabled={loadState === 'loading' || refreshing}
          loading={refreshing}
          loadingText="Refreshing…"
          aria-label={refreshing ? 'Refreshing notification channels' : 'Refresh notification channels'}
        >
          <RefreshCw size={16} aria-hidden="true" />
          Refresh
        </Button>
      </div>

      {focusRuleId ? (
        <p className="form-banner neutral nc-focus-banner" role="status">
          {focusRule
            ? <>Showing the {notificationChannelLabel(focusRule.channel)} channel {focusRule.destination_preview || ''} from a delivery failure. It is highlighted below.</>
            : loadState === 'ready' ? 'The channel from that delivery failure no longer exists; it may have been removed.' : 'Loading the channel from that delivery failure…'}
          {' '}<button type="button" className="rf-link-button" onClick={() => setFocusRuleId('')}>Clear</button>
        </p>
      ) : null}
      {message ? <p className="form-banner" role="status">{message}</p> : null}
      {actionError ? <p className="form-banner error" role="alert">{actionError}</p> : null}
      {refreshing ? <p className="sr-only" role="status">Refreshing notification channels</p> : null}
      {eventsWindow?.truncated ? (
        <p className="nc-footnote">
          {`Showing the ${formatNumber(eventsWindow.returned)} most recent notification events. Last delivery per channel is read from the full history.`}
        </p>
      ) : null}

      <ul className="integration-tile-grid" aria-label="Available notification channels">
        {NOTIFICATION_CHANNELS.map((channel) => {
          const counts = summary[channel.id] ?? { total: 0, enabled: 0 };
          const connected = counts.total > 0;
          return (
            <li key={channel.id} className="integration-tile" data-connected={connected || undefined}>
              <div className="integration-tile-head">
                <div className="integration-identity">
                  <ChannelLogo channel={channel.id} />
                  <div className="integration-tile-name">
                    <strong>{channel.label}</strong>
                    <span>{channel.kind}</span>
                  </div>
                </div>
                {connected ? <Badge tone="muted">{`${formatNumber(counts.total)} configured`}</Badge> : null}
              </div>
              <p className="integration-tile-desc">{channel.description}</p>
              <div className="integration-tile-footer">
                <span className="integration-chip" data-tone={connected && counts.enabled > 0 ? 'positive' : 'neutral'}>
                  {connected ? <CircleCheck size={13} aria-hidden="true" /> : <CircleDashed size={13} aria-hidden="true" />}
                  {connected ? `${formatNumber(counts.enabled)} of ${formatNumber(counts.total)} enabled` : 'Not configured'}
                </span>
                <div className="integration-tile-actions">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => {
                      setMessage('');
                      setActiveChannel(channel.id);
                    }}
                    disabled={!canWrite}
                    title={writeDisabledReason || undefined}
                    aria-label={connected ? `Add another ${channel.label} channel` : `Connect ${channel.label}`}
                  >
                    <Plus size={14} aria-hidden="true" />
                    {connected ? 'Add' : 'Connect'}
                  </Button>
                </div>
              </div>
            </li>
          );
        })}
      </ul>
      {!canWrite ? <p className="nc-footnote">{writeDisabledReason}</p> : null}

      {loadState === 'loading' && rules.length === 0 ? (
        <div className="nc-loading" role="status" aria-busy="true">
          <span className="sr-only">Loading connected channels</span>
          <span className="skeleton-row" aria-hidden="true" />
          <span className="skeleton-row" aria-hidden="true" />
        </div>
      ) : (
        <DataTable
          columns={columns}
          items={connectorRules}
          getRowId={(rule) => rule.id}
          selectedId={focusRuleId || null}
          getRowProps={(rule) => ({ 'data-row-id': rule.id }) as HTMLAttributes<HTMLTableRowElement>}
          loadError={loadState === 'error' ? loadError : null}
          onRetry={() => void load()}
          empty={
            <EmptyState
              icon={BellRing}
              title="No channels connected yet"
              body={canWrite
                ? 'Connect Slack, Microsoft Teams, email, or a webhook to hear about high-severity findings and SOC state changes.'
                : 'An owner or admin can connect Slack, Microsoft Teams, email, or a webhook.'}
              actionLabel={canWrite ? 'Connect Slack' : undefined}
              onAction={canWrite ? () => setActiveChannel('slack') : undefined}
            />
          }
        />
      )}

      <p className="nc-footnote">{DELIVERY_MODE_NOTE}</p>

      {active && canWrite ? (
        <ConnectChannelDialog
          key={active.id}
          channel={active}
          config={config}
          session={session}
          onClose={() => setActiveChannel(null)}
          onConnected={(rule) => void handleConnected(rule)}
        />
      ) : null}

      {editingRule && canWrite ? (
        <EditChannelDialog
          key={editingRule.id}
          rule={editingRule}
          config={config}
          session={session}
          onClose={() => setEditingRule(null)}
          onSaved={(rule) => void handleEdited(rule)}
        />
      ) : null}

      <ConfirmModal
        open={Boolean(removingRule) && canWrite}
        title={removingRule ? `Remove ${notificationChannelLabel(removingRule.channel)} channel?` : 'Remove channel?'}
        description={removingRule
          ? `${removingRule.destination_preview || 'This destination'} will stop receiving alerts, including pending retries. The stored destination is deleted. Delivery history stays in the ledger.`
          : ''}
        confirmLabel="Remove channel"
        confirmTone="danger"
        busy={Boolean(removingRule) && busyRuleId === removingRule?.id}
        onCancel={() => {
          if (!busyRuleId) setRemovingRule(null);
        }}
        onConfirm={() => void confirmRemove()}
      />
    </Card>
  );
}
