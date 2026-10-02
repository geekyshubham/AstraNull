import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  DEFAULT_NOTIFICATION_TRIGGERS,
  NOTIFICATION_CHANNELS,
  NOTIFICATION_TRIGGER_OPTIONS,
  SAMPLE_PORTAL_URL,
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
} from '../../apps/web/react/src/lib/notification-channels.mjs';
import {
  ALLOWED_CHANNELS,
  ALLOWED_TRIGGERS,
  DEFAULT_TRIGGERS,
  normalizeNotificationRuleInput,
} from '../../src/lib/notifications.mjs';
import {
  buildSlackPayload,
  buildTeamsPayload,
  buildWebhookNotificationBody,
  rejectWebhookDestinationWithCredentials,
} from '../../src/lib/notificationDelivery.mjs';

test('channel cards cover slack, teams, email, webhook and are all backend channels', () => {
  assert.deepEqual(NOTIFICATION_CHANNELS.map((c) => c.id), ['slack', 'teams', 'email', 'webhook']);
  for (const channel of NOTIFICATION_CHANNELS) {
    assert.ok(ALLOWED_CHANNELS.has(channel.id), `${channel.id} must be a backend channel`);
    assert.ok(channel.label && channel.destinationLabel && channel.hint);
    if (channel.docsUrl) assert.match(channel.docsUrl, /^https:\/\//);
  }
  assert.equal(findNotificationChannel('in_app'), null);
  assert.equal(notificationChannelLabel('teams'), 'Microsoft Teams');
  assert.equal(notificationChannelLabel('in_app'), 'In-app');
});

test('trigger options and defaults match the backend contract', () => {
  assert.deepEqual(new Set(NOTIFICATION_TRIGGER_OPTIONS.map((o) => o.id)), ALLOWED_TRIGGERS);
  assert.deepEqual([...DEFAULT_NOTIFICATION_TRIGGERS], DEFAULT_TRIGGERS);
  assert.equal(notificationTriggerLabel('report.ready'), 'Report ready');
  assert.equal(notificationTriggerLabel('custom.thing'), 'custom thing');
});

test('normalizeSelectedTriggers requires one and returns canonical order', () => {
  assert.equal(normalizeSelectedTriggers([]).ok, false);
  assert.equal(normalizeSelectedTriggers(['bogus']).ok, false);
  assert.deepEqual(normalizeSelectedTriggers(['report.ready', 'finding.high_severity', 'bogus']), {
    ok: true,
    triggers: ['finding.high_severity', 'report.ready'],
  });
});

const ACCEPTED = [
  ['slack', 'https://hooks.slack.com/services/T000/B000/XXXX'],
  ['teams', 'https://prod-00.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke'],
  ['email', 'alerts@example.com'],
  ['webhook', 'https://hooks.example.com/astranull/abc123'],
  ['webhook', 'http://localhost:8080/hook'],
];

test('every destination the UI accepts is accepted by the backend and delivery precheck', () => {
  for (const [channel, destination] of ACCEPTED) {
    const ui = validateChannelDestination(channel, `  ${destination}  `);
    assert.equal(ui.ok, true, `${channel} ${destination}`);
    assert.equal(ui.destination, destination);
    const backend = normalizeNotificationRuleInput({ channel, destination: ui.destination, triggers: ['report.ready'] });
    assert.equal(backend.ok, true, `backend rejected ${channel} ${destination}`);
    if (channel !== 'email') {
      assert.equal(rejectWebhookDestinationWithCredentials(ui.destination).ok, true);
    }
  }
});

test('UI rejects destinations the delivery path would reject', () => {
  const rejected = [
    ['webhook', ''],
    ['webhook', 'not a url'],
    ['webhook', 'http://hooks.example.com/x'],
    ['webhook', 'ftp://hooks.example.com/x'],
    ['webhook', 'https://user:pass@hooks.example.com/x'],
    ['slack', 'https://user:pass@hooks.slack.com/services/T/B/X'],
    ['teams', 'http://example.com/workflows/x'],
    ['email', 'not-an-email'],
    ['email', 'a@b.com, c@d.com'],
    ['email', 'a@b.com\r\nBcc: x@y.com'],
    ['webhook', `https://hooks.example.com/${'a'.repeat(2100)}`],
    ['in_app', 'anything'],
  ];
  for (const [channel, destination] of rejected) {
    const result = validateChannelDestination(channel, destination);
    assert.equal(result.ok, false, `${channel} ${JSON.stringify(destination).slice(0, 60)}`);
    assert.ok(result.error.length > 0);
    assert.ok(!result.error.includes('pass@'), 'errors must not echo the destination');
  }
  for (const [channel, destination] of rejected.filter(([c, d]) => c !== 'email' && c !== 'in_app' && /^\w+:\/\//.test(d))) {
    const backendCreate = normalizeNotificationRuleInput({ channel, destination });
    const precheck = rejectWebhookDestinationWithCredentials(destination);
    assert.ok(!backendCreate.ok || !precheck.ok || destination.length > 2048, `${channel} ${destination.slice(0, 60)}`);
  }
});

test('provider-specific warnings are advisory, not blocking', () => {
  const slack = validateChannelDestination('slack', 'https://example.com/hook');
  assert.equal(slack.ok, true);
  assert.match(slack.warning, /Slack incoming webhook/);
  const teams = validateChannelDestination('teams', 'https://contoso.webhook.office.com/webhookb2/x');
  assert.equal(teams.ok, true);
  assert.match(teams.warning, /legacy/i);
  const dev = validateChannelDestination('webhook', 'http://127.0.0.1/hook');
  assert.equal(dev.ok, true);
  assert.match(dev.warning, /local development/);
  assert.equal(validateChannelDestination('webhook', 'https://hooks.example.com/x').warning, undefined);
});

test('sample payloads mirror backend payload builders', () => {
  const event = {
    event_id: 'nevt_example',
    rule_id: 'nrule_example',
    trigger: 'finding.high_severity',
    subject: 'High-severity finding on api.example.com',
    metadata: { target: 'api.example.com', severity: 'high' },
    created_at: '<ISO-8601 timestamp>',
  };
  const rule = { destination: 'https://hooks.example.com/x' };

  assert.deepEqual(buildSampleChannelPayload('slack'), buildSlackPayload(event, rule));
  assert.deepEqual(buildSampleChannelPayload('webhook'), buildWebhookNotificationBody(event));

  const teamsBackend = buildTeamsPayload(event, rule, { portalUrl: 'https://portal.example.com' });
  const teamsSample = buildSampleChannelPayload('teams');
  assert.equal(teamsSample.type, teamsBackend.type);
  const backendCard = teamsBackend.attachments[0];
  const sampleCard = teamsSample.attachments[0];
  assert.equal(sampleCard.contentType, backendCard.contentType);
  assert.equal(sampleCard.content.version, backendCard.content.version);
  assert.deepEqual(sampleCard.content.body, backendCard.content.body);
  // Actions match except for the URL, which the sample shows as a placeholder.
  assert.deepEqual(
    sampleCard.content.actions.map((a) => ({ ...a, url: a.url === SAMPLE_PORTAL_URL ? 'PORTAL' : a.url })),
    backendCard.content.actions.map((a) => ({ ...a, url: a.url.endsWith('/app#notifications') ? 'PORTAL' : a.url })),
  );

  const email = buildSampleChannelPayload('email');
  assert.match(email.subject, /^\[AstraNull\] /);
});

test('deliveryStatusPresentation gives honest labels for every ledger status', () => {
  assert.equal(deliveryStatusPresentation('delivered_provider').label, 'Delivered');
  assert.equal(deliveryStatusPresentation('delivered_in_app').tone, 'success');
  const queued = deliveryStatusPresentation('queued_provider_not_configured');
  assert.equal(queued.label, 'Recorded, not sent');
  assert.equal(queued.tone, 'muted');
  assert.equal(deliveryStatusPresentation('provider_retry_scheduled').tone, 'warn');
  assert.equal(deliveryStatusPresentation('provider_failed_dlq').tone, 'danger');
  // Absence of an attempt in the bounded feed must not read as "never fired" (F11).
  const windowed = deliveryStatusPresentation(undefined, { source: 'window', windowSize: 100 });
  assert.equal(windowed.label, 'None in recent history');
  assert.match(windowed.detail, /100 most recent/);
  assert.doesNotMatch(windowed.detail, /has fired|ever/i);
  assert.equal(deliveryStatusPresentation(undefined, { source: 'authoritative' }).label, 'No deliveries yet');
});

test('latestAttemptByRule picks the newest attempt per rule', () => {
  const events = [
    {
      created_at: '2024-01-01T00:00:00.000Z',
      delivery_attempts: [
        { rule_id: 'r1', status: 'queued_provider_not_configured', created_at: '2024-01-01T00:00:00.000Z' },
        { rule_id: 'r2', status: 'provider_failed_dlq', created_at: '2024-01-01T00:00:00.000Z' },
      ],
    },
    {
      created_at: '2024-01-02T00:00:00.000Z',
      delivery_attempts: [{ rule_id: 'r1', status: 'delivered_provider', attempted_at: '2024-01-02T00:00:00.000Z' }],
    },
    { delivery_attempts: [{ status: 'delivered_provider' }] },
  ];
  const latest = latestAttemptByRule(events);
  assert.equal(latest.size, 2);
  assert.equal(latest.get('r1').status, 'delivered_provider');
  assert.equal(latest.get('r2').status, 'provider_failed_dlq');
  assert.equal('__sort' in latest.get('r1'), false);
  assert.equal(latestAttemptByRule(null).size, 0);
});

test('summarizeChannelRules counts total and enabled per channel', () => {
  const summary = summarizeChannelRules([
    { channel: 'slack', enabled: true },
    { channel: 'slack', enabled: false },
    { channel: 'email' },
  ]);
  assert.deepEqual(summary.slack, { total: 2, enabled: 1 });
  assert.deepEqual(summary.email, { total: 1, enabled: 1 });
  assert.deepEqual(summary.teams, { total: 0, enabled: 0 });
  assert.deepEqual(summarizeChannelRules(undefined).webhook, { total: 0, enabled: 0 });
});

// ---------------------------------------------------------------------------
// F04: overlapping notification loads. These drive the same guard the panel uses, with the
// panel's apply/discard rule, so a stale response can never overwrite newer state.
// ---------------------------------------------------------------------------

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** Mirrors NotificationChannelsPanel.load(): apply success or error only when still current. */
function createPanelModel(initialSessionKey) {
  const guard = createLatestRequestGuard();
  const state = { sessionKey: initialSessionKey, rules: null, error: '', refreshing: false };
  return {
    state,
    guard,
    load(fetcher) {
      const token = guard.begin(state.sessionKey);
      state.refreshing = true;
      return fetcher().then(
        (payload) => {
          if (!guard.isCurrent(token, state.sessionKey)) return;
          state.rules = payload.rules;
          state.error = '';
        },
        (err) => {
          if (!guard.isCurrent(token, state.sessionKey)) return;
          state.error = String(err.message);
        },
      ).finally(() => {
        if (guard.isCurrent(token, state.sessionKey)) state.refreshing = false;
      });
    },
  };
}

test('F04: newer response wins when the older request resolves last', async () => {
  const model = createPanelModel('ten_demo|usr_admin|admin|tok');
  const older = deferred();
  const newer = deferred();
  const p1 = model.load(() => older.promise);
  const p2 = model.load(() => newer.promise);
  newer.resolve({ rules: ['new'] });
  await p2;
  assert.deepEqual(model.state.rules, ['new']);
  assert.equal(model.state.refreshing, false);
  older.resolve({ rules: ['stale'] });
  await p1;
  assert.deepEqual(model.state.rules, ['new'], 'late older response is discarded');
});

test('F04: newer response wins when the older request resolves first', async () => {
  const model = createPanelModel('k');
  const older = deferred();
  const newer = deferred();
  const p1 = model.load(() => older.promise);
  const p2 = model.load(() => newer.promise);
  older.resolve({ rules: ['stale'] });
  await p1;
  assert.equal(model.state.rules, null, 'superseded response is never applied');
  assert.equal(model.state.refreshing, true, 'refresh still in progress for the newer request');
  newer.resolve({ rules: ['new'] });
  await p2;
  assert.deepEqual(model.state.rules, ['new']);
  assert.equal(model.state.refreshing, false);
});

test('F04: an older failure after a newer success does not surface an error', async () => {
  const model = createPanelModel('k');
  const older = deferred();
  const newer = deferred();
  const p1 = model.load(() => older.promise);
  const p2 = model.load(() => newer.promise);
  newer.resolve({ rules: ['new'] });
  await p2;
  older.reject(new Error('network down'));
  await p1;
  assert.equal(model.state.error, '');
  assert.deepEqual(model.state.rules, ['new']);
});

test('F04: a response fetched for a previous session is never applied', async () => {
  const model = createPanelModel(notificationSessionKey({ tenant_id: 'ten_a', user_id: 'u1', role: 'admin', access_token: 't1' }));
  const pending = deferred();
  const p1 = model.load(() => pending.promise);
  model.state.sessionKey = notificationSessionKey({ tenant_id: 'ten_b', user_id: 'u2', role: 'admin', access_token: 't2' });
  pending.resolve({ rules: ['tenant-a-rule'] });
  await p1;
  assert.equal(model.state.rules, null);
});

test('F04: cancel() on unmount discards anything still in flight', async () => {
  const model = createPanelModel('k');
  const pending = deferred();
  const p1 = model.load(() => pending.promise);
  model.guard.cancel();
  pending.resolve({ rules: ['late'] });
  await p1;
  assert.equal(model.state.rules, null);
});

test('F04: session key distinguishes tenant, user, role and token', () => {
  const base = { tenant_id: 't', user_id: 'u', role: 'admin', access_token: 'x' };
  const key = notificationSessionKey(base);
  for (const field of ['tenant_id', 'user_id', 'role', 'access_token']) {
    assert.notEqual(notificationSessionKey({ ...base, [field]: 'other' }), key, field);
  }
  assert.equal(notificationSessionKey(null), '|||');
});

test('F04: panel wires the guard, cleanup, and a separate refreshing state into Refresh', () => {
  const source = readFileSync(
    new URL('../../apps/web/react/src/components/integrations/notification-channels.tsx', import.meta.url),
    'utf8',
  );
  assert.match(source, /createLatestRequestGuard\(\)/);
  assert.match(source, /isCurrent\(token, sessionKeyRef\.current\)/);
  assert.match(source, /guard\.cancel\(\)/);
  assert.match(source, /disabled=\{loadState === 'loading' \|\| refreshing\}/);
  assert.match(source, /loading=\{refreshing\}/);
  // The bounded feed must not be the only source for "Last delivery".
  assert.match(source, /resolveRuleLatestDelivery\(rule\.id/);
});

// ---------------------------------------------------------------------------
// F11: authoritative latest delivery wins over the bounded feed.
// ---------------------------------------------------------------------------

test('F11: server latest_deliveries wins over the events window', () => {
  const eventsLatest = new Map([['r1', { status: 'provider_failed_dlq' }]]);
  const resolved = resolveRuleLatestDelivery('r1', {
    latestDeliveries: { r1: { status: 'delivered_provider' } },
    eventsLatest,
    windowSize: 100,
  });
  assert.equal(resolved.source, 'authoritative');
  assert.equal(resolved.attempt.status, 'delivered_provider');
});

test('F11: a rule missing from the 100-event feed still shows its authoritative latest delivery', () => {
  const resolved = resolveRuleLatestDelivery('quiet', {
    latestDeliveries: { quiet: { status: 'delivered_in_app' } },
    eventsLatest: new Map(),
    windowSize: 100,
  });
  assert.equal(deliveryStatusPresentation(resolved.attempt?.status, resolved).label, 'In-app feed');
});

test('F11: without server data, absence is described as the loaded window, not "never"', () => {
  const resolved = resolveRuleLatestDelivery('quiet', { latestDeliveries: null, eventsLatest: new Map(), windowSize: 100 });
  assert.equal(resolved.source, 'window');
  const presentation = deliveryStatusPresentation(resolved.attempt?.status, resolved);
  assert.equal(presentation.label, 'None in recent history');
  assert.match(presentation.detail, /100 most recent notification events loaded/);
  assert.doesNotMatch(presentation.label + presentation.detail, /No events yet|has fired/);
});

test('F11: authoritative null means no attempt recorded at all', () => {
  const resolved = resolveRuleLatestDelivery('r1', { latestDeliveries: { r1: null }, eventsLatest: new Map([['r1', { status: 'delivered_provider' }]]) });
  assert.equal(resolved.source, 'authoritative');
  assert.equal(resolved.attempt, null);
  assert.equal(deliveryStatusPresentation(undefined, resolved).label, 'No deliveries yet');
});

test('deliveryStatusPresentation does not mislabel an unknown recorded status as absent', () => {
  const presentation = deliveryStatusPresentation('provider_rejected');
  assert.equal(presentation.label, 'provider rejected');
  assert.equal(presentation.tone, 'info');
});

// ---------------------------------------------------------------------------
// G01: edit dialog body.
// ---------------------------------------------------------------------------

test('G01: buildRuleUpdateBody keeps the stored destination when the field is blank', () => {
  const result = buildRuleUpdateBody('webhook', { destination: '  ', triggers: ['report.ready'] });
  assert.equal(result.ok, true);
  assert.deepEqual(result.body, { triggers: ['report.ready'] });
});

test('G01: buildRuleUpdateBody validates a replacement destination like a new connection', () => {
  const creds = buildRuleUpdateBody('webhook', { destination: 'https://u:p@hooks.example.com/x', triggers: ['report.ready'] });
  assert.equal(creds.ok, false);
  assert.equal(creds.field, 'destination');
  const email = buildRuleUpdateBody('email', { destination: 'nope', triggers: ['report.ready'] });
  assert.equal(email.ok, false);
  const noTriggers = buildRuleUpdateBody('webhook', { destination: '', triggers: [] });
  assert.equal(noTriggers.ok, false);
  assert.equal(noTriggers.field, 'triggers');
  const ok = buildRuleUpdateBody('email', { destination: 'ops@example.com', triggers: ['report.ready'] });
  assert.deepEqual(ok.body, { triggers: ['report.ready'], destination: 'ops@example.com' });
  // Anything the UI accepts must be accepted by the backend create/update normalizer.
  assert.equal(normalizeNotificationRuleInput({ channel: 'email', ...ok.body }).ok, true);
});
