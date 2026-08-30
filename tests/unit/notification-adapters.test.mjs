import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { afterEach, describe, it } from 'node:test';
import { collectForbiddenEvidenceFields } from '../../src/lib/redact.mjs';
import {
  buildEmailPayload,
  buildSlackPayload,
  buildTeamsPayload,
  buildWebhookNotificationBody,
  deliverEmail,
  deliverSlack,
  deliverTeams,
  finalizeNotificationDeliveryAttempts,
  isDeliveryChannelActive,
  parseNotificationDeliveryModes,
  resolveNotificationDeliveryMode,
  sendProviderHttpsPost,
  sendWebhookNotification,
} from '../../src/lib/notificationDelivery.mjs';

const sampleEvent = {
  id: 'nevt_test123',
  trigger: 'finding.high_severity',
  subject: 'Critical finding [REDACTED]',
  metadata: { detail: '[REDACTED]', agent_id: 'ag_1' },
  created_at: '2026-07-02T12:00:00.000Z',
};

const sampleRule = {
  id: 'nrule_test123',
  channel: 'email',
  destination: 'alerts@customer.example',
};

const forbiddenExtra = new Set(['raw_payload', 'credentials', 'tokens', 'secrets']);

class ScriptedSmtpSocket extends EventEmitter {
  constructor(responder) {
    super();
    this.responder = responder;
    this.writes = [];
    this.destroyed = false;
    this.ended = false;
  }

  write(value) {
    const command = String(value).replace(/\r\n$/, '');
    this.writes.push(command);
    const response = this.responder(command);
    if (response) queueMicrotask(() => this.emit('data', Buffer.from(response)));
    return true;
  }

  destroy() {
    this.destroyed = true;
  }

  end() {
    this.ended = true;
  }

  greet() {
    this.emit('data', Buffer.from('220 smtp.example.test ready\r\n'));
  }
}

function smtpConnect(socket) {
  return (_options, connected) => {
    queueMicrotask(() => {
      connected();
      queueMicrotask(() => socket.greet());
    });
    return socket;
  };
}

function assertNoForbiddenFields(value, label) {
  const findings = collectForbiddenEvidenceFields(value, '', { extraForbiddenKeys: forbiddenExtra });
  assert.deepEqual(
    findings,
    [],
    `${label} must not include forbidden fields, found: ${findings.join(', ')}`,
  );
}

describe('notification delivery adapters', () => {
  const envSnapshot = { ...process.env };

  afterEach(() => {
    process.env = { ...envSnapshot };
    delete process.env.ASTRANULL_SMTP_HOST;
    delete process.env.ASTRANULL_SMTP_FROM;
    delete process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE;
  });

  it('buildEmailPayload produces valid envelope with redacted metadata', () => {
    process.env.ASTRANULL_SMTP_FROM = 'alerts@astranull.local';
    const envelope = buildEmailPayload(sampleEvent, sampleRule);

    assert.equal(envelope.from, 'alerts@astranull.local');
    assert.equal(envelope.to, 'alerts@customer.example');
    assert.equal(envelope.subject, '[AstraNull] Critical finding [REDACTED]');
    assert.match(envelope.html_body, /<table/);
    assert.match(envelope.html_body, /finding\.high_severity/);
    assert.match(envelope.html_body, /\[REDACTED\]/);
    assert.ok(!envelope.html_body.includes('ast_secret'));
    assertNoForbiddenFields(envelope, 'email envelope');
  });

  it('buildSlackPayload produces valid Block Kit JSON', () => {
    const payload = buildSlackPayload(sampleEvent, { ...sampleRule, channel: 'slack', destination: 'https://hooks.slack.invalid/abc' });

    assert.ok(Array.isArray(payload.blocks));
    assert.equal(payload.blocks[0].type, 'section');
    assert.equal(payload.blocks[1].type, 'context');
    assert.match(payload.blocks[0].text.text, /finding\.high_severity/);
    assert.match(payload.blocks[2].text.text, /\[REDACTED\]/);
    assertNoForbiddenFields(payload, 'slack payload');
  });

  it('buildTeamsPayload produces valid Adaptive Card JSON', () => {
    const payload = buildTeamsPayload(sampleEvent, { ...sampleRule, channel: 'teams', destination: 'https://teams.invalid/hook' });

    assert.equal(payload.type, 'message');
    assert.equal(payload.attachments[0].contentType, 'application/vnd.microsoft.card.adaptive');
    assert.equal(payload.attachments[0].content.type, 'AdaptiveCard');
    assert.ok(payload.attachments[0].content.body.length >= 3);
    assert.ok(payload.attachments[0].content.actions.length >= 1);
    const cardText = JSON.stringify(payload);
    assert.match(cardText, /\[REDACTED\]/);
    assertNoForbiddenFields(payload, 'teams payload');
  });

  it('deliverEmail returns queued_provider_not_configured when SMTP host missing', async () => {
    delete process.env.ASTRANULL_SMTP_HOST;
    const envelope = buildEmailPayload(sampleEvent, sampleRule);
    const result = await deliverEmail(envelope);
    assert.equal(result.status, 'queued_provider_not_configured');
    assert.equal(result.reason, 'smtp_host_not_configured');
  });

  it('fails closed before MAIL or DATA when STARTTLS is required but not advertised', async () => {
    const plaintext = new ScriptedSmtpSocket((command) => {
      if (command === 'EHLO astranull.local') return '250 smtp.example.test\r\n';
      return null;
    });
    const result = await deliverEmail(buildEmailPayload(sampleEvent, sampleRule), {
      smtpHost: 'smtp.example.test',
      smtpStartTls: true,
      connect: smtpConnect(plaintext),
    });

    assert.equal(result.status, 'provider_retry_scheduled');
    assert.equal(result.reason, 'smtp_starttls_required');
    assert.deepEqual(plaintext.writes, ['EHLO astranull.local']);
    assert.equal(plaintext.writes.some((line) => /^(MAIL FROM|RCPT TO|DATA|AUTH )/.test(line)), false);
    assert.equal(plaintext.destroyed, true);
  });

  it('performs SMTP auth only on verified TLS and completes the bounded mail transaction', async () => {
    const plaintext = new ScriptedSmtpSocket((command) => {
      if (command === 'EHLO astranull.local') return '250-smtp.example.test\r\n250 STARTTLS\r\n';
      if (command === 'STARTTLS') return '220 begin TLS\r\n';
      return null;
    });
    const secure = new ScriptedSmtpSocket((command) => {
      if (command === 'EHLO astranull.local') return '250-smtp.example.test\r\n250 AUTH PLAIN\r\n';
      if (command.startsWith('AUTH PLAIN ')) return '235 authenticated\r\n';
      if (command.startsWith('MAIL FROM:')) return '250 sender ok\r\n';
      if (command.startsWith('RCPT TO:')) return '250 recipient ok\r\n';
      if (command === 'DATA') return '354 send data\r\n';
      if (command.startsWith('From: ')) return '250 queued\r\n';
      return null;
    });
    let tlsOptions;
    const result = await deliverEmail(buildEmailPayload(sampleEvent, sampleRule), {
      smtpHost: 'smtp.example.test',
      smtpStartTls: true,
      smtpUsername: 'smtp-user',
      smtpPassword: 'smtp-password',
      connect: smtpConnect(plaintext),
      secureConnect(options, connected) {
        tlsOptions = options;
        queueMicrotask(connected);
        return secure;
      },
    });

    assert.equal(result.status, 'delivered_provider');
    assert.equal(tlsOptions.servername, 'smtp.example.test');
    assert.equal(tlsOptions.rejectUnauthorized, true);
    assert.equal(plaintext.writes.some((line) => /^(MAIL FROM|RCPT TO|DATA|AUTH )/.test(line)), false);
    assert.ok(secure.writes[0] === 'EHLO astranull.local');
    assert.ok(secure.writes[1].startsWith('AUTH PLAIN '));
    assert.ok(secure.writes.indexOf('DATA') > secure.writes.findIndex((line) => line.startsWith('AUTH PLAIN ')));
    assert.equal(secure.ended, true);
  });

  it('deliverSlack rejects non-HTTPS destination except localhost/invalid', async () => {
    const payload = buildSlackPayload(sampleEvent, { ...sampleRule, channel: 'slack' });
    const result = await deliverSlack(payload, 'http://public.example.com/hook');
    assert.equal(result.status, 'provider_retry_scheduled');
    assert.equal(result.reason, 'invalid_webhook_destination');

    const localResult = await deliverSlack(payload, 'http://127.0.0.1:9/slack', {
      fetchFn: async () => ({ ok: false, status: 503 }),
    });
    assert.equal(localResult.status, 'provider_retry_scheduled');
    assert.equal(localResult.reason, 'provider_http_error');
  });

  it('deliverTeams rejects URL-embedded credentials', async () => {
    const payload = buildTeamsPayload(sampleEvent, { ...sampleRule, channel: 'teams' });
    const result = await deliverTeams(payload, 'https://user:pass@teams.invalid/hook');
    assert.equal(result.status, 'provider_retry_scheduled');
    assert.equal(result.reason, 'webhook_url_credentials_not_allowed');
  });

  it('parses delivery modes for webhook,email, all, and metadata_only', () => {
    const both = parseNotificationDeliveryModes('webhook,email');
    assert.ok(isDeliveryChannelActive(both, 'webhook'));
    assert.ok(isDeliveryChannelActive(both, 'email'));
    assert.equal(isDeliveryChannelActive(both, 'slack'), false);

    const all = parseNotificationDeliveryModes('all');
    assert.ok(isDeliveryChannelActive(all, 'webhook'));
    assert.ok(isDeliveryChannelActive(all, 'email'));
    assert.ok(isDeliveryChannelActive(all, 'slack'));
    assert.ok(isDeliveryChannelActive(all, 'teams'));

    const metadataOnly = parseNotificationDeliveryModes('metadata_only');
    assert.equal(isDeliveryChannelActive(metadataOnly, 'webhook'), false);
    assert.equal(isDeliveryChannelActive(metadataOnly, 'email'), false);

    assert.equal(resolveNotificationDeliveryMode({ deliveryMode: 'webhook,email' }), 'email,webhook');
    assert.equal(resolveNotificationDeliveryMode({ deliveryMode: 'all' }), 'email,slack,teams,webhook');
    assert.equal(resolveNotificationDeliveryMode({ deliveryMode: 'metadata_only' }), 'metadata_only');
    assert.equal(resolveNotificationDeliveryMode({}), 'metadata_only');
  });

  it('default mode keeps external channels queued_provider_not_configured', async () => {
    const attempts = [
      {
        id: 'natt_1',
        rule_id: 'nrule_w',
        channel: 'webhook',
        destination_preview: 'webhook://hooks.example.invalid',
        status: 'queued_provider_not_configured',
        reason: 'outbound_provider_not_configured_opt_in',
        created_at: sampleEvent.created_at,
        attempted_at: null,
      },
      {
        id: 'natt_2',
        rule_id: 'nrule_e',
        channel: 'email',
        destination_preview: 'email:a…@customer.example',
        status: 'queued_provider_not_configured',
        reason: 'outbound_provider_not_configured_opt_in',
        created_at: sampleEvent.created_at,
        attempted_at: null,
      },
    ];
    const rules = [
      { id: 'nrule_w', channel: 'webhook', destination: 'https://hooks.example.invalid/h' },
      { id: 'nrule_e', channel: 'email', destination: 'alerts@customer.example' },
    ];

    const out = await finalizeNotificationDeliveryAttempts({
      deliveryMode: 'metadata_only',
      attempts,
      rules,
      event: sampleEvent,
      now: sampleEvent.created_at,
    });

    assert.equal(out[0].status, 'queued_provider_not_configured');
    assert.equal(out[1].status, 'queued_provider_not_configured');
  });

  it('webhook,email activates both webhook and email delivery paths', async () => {
    const sent = { webhook: 0, email: 0 };
    const attempts = [
      {
        id: 'natt_w',
        rule_id: 'nrule_w',
        channel: 'webhook',
        destination_preview: 'webhook://hooks.example.invalid',
        status: 'queued_provider_not_configured',
        reason: 'outbound_provider_not_configured_opt_in',
        created_at: sampleEvent.created_at,
        attempted_at: null,
      },
      {
        id: 'natt_e',
        rule_id: 'nrule_e',
        channel: 'email',
        destination_preview: 'email:a…@customer.example',
        status: 'queued_provider_not_configured',
        reason: 'outbound_provider_not_configured_opt_in',
        created_at: sampleEvent.created_at,
        attempted_at: null,
      },
    ];
    const rules = [
      { id: 'nrule_w', channel: 'webhook', destination: 'https://hooks.example.invalid/h' },
      { id: 'nrule_e', channel: 'email', destination: 'alerts@customer.example' },
    ];

    const out = await finalizeNotificationDeliveryAttempts({
      deliveryMode: 'webhook,email',
      attempts,
      rules,
      event: sampleEvent,
      now: sampleEvent.created_at,
      webhookSender: async () => {
        sent.webhook += 1;
        return { ok: true, status: 202 };
      },
      emailDeliverer: async () => {
        sent.email += 1;
        return { status: 'delivered_provider', reason: 'email_delivered' };
      },
    });

    assert.equal(sent.webhook, 1);
    assert.equal(sent.email, 1);
    assert.equal(out[0].status, 'delivered_provider');
    assert.equal(out[1].status, 'delivered_provider');
  });

  it('all mode activates webhook, email, slack, and teams delivery paths', async () => {
    const sent = { webhook: 0, email: 0, slack: 0, teams: 0 };
    const channels = ['webhook', 'email', 'slack', 'teams'];
    const attempts = channels.map((channel, index) => ({
      id: `natt_${channel}`,
      rule_id: `nrule_${channel}`,
      channel,
      destination_preview: `${channel}:preview`,
      status: 'queued_provider_not_configured',
      reason: 'outbound_provider_not_configured_opt_in',
      created_at: sampleEvent.created_at,
      attempted_at: null,
      _index: index,
    }));
    const rules = [
      { id: 'nrule_webhook', channel: 'webhook', destination: 'https://hooks.example.invalid/h' },
      { id: 'nrule_email', channel: 'email', destination: 'alerts@customer.example' },
      { id: 'nrule_slack', channel: 'slack', destination: 'https://hooks.slack.invalid/abc' },
      { id: 'nrule_teams', channel: 'teams', destination: 'https://teams.invalid/hook' },
    ];

    const out = await finalizeNotificationDeliveryAttempts({
      deliveryMode: 'all',
      attempts,
      rules,
      event: sampleEvent,
      now: sampleEvent.created_at,
      webhookSender: async () => {
        sent.webhook += 1;
        return { ok: true, status: 202 };
      },
      emailDeliverer: async () => {
        sent.email += 1;
        return { status: 'delivered_provider', reason: 'email_delivered' };
      },
      slackDeliverer: async () => {
        sent.slack += 1;
        return { status: 'delivered_provider', reason: 'slack_delivered' };
      },
      teamsDeliverer: async () => {
        sent.teams += 1;
        return { status: 'delivered_provider', reason: 'teams_delivered' };
      },
    });

    assert.equal(sent.webhook, 1);
    assert.equal(sent.email, 1);
    assert.equal(sent.slack, 1);
    assert.equal(sent.teams, 1);
    assert.ok(out.every((attempt) => attempt.status === 'delivered_provider'));
  });

  it('preserves existing webhook delivery behavior', async () => {
    const body = buildWebhookNotificationBody({
      event_id: sampleEvent.id,
      rule_id: 'nrule_w',
      trigger: sampleEvent.trigger,
      subject: sampleEvent.subject,
      metadata: sampleEvent.metadata,
      created_at: sampleEvent.created_at,
    });
    assertNoForbiddenFields(body, 'webhook body');

    const insecure = await sendWebhookNotification('http://public.example.com/hook', JSON.stringify(body));
    assert.equal(insecure.ok, false);
    assert.equal(insecure.error, 'invalid_webhook_destination');

    const creds = await sendWebhookNotification('https://user:pass@hooks.example.invalid/h', JSON.stringify(body));
    assert.equal(creds.ok, false);
    assert.equal(creds.error, 'webhook_url_credentials_not_allowed');

    const attempts = [
      {
        id: 'natt_w',
        rule_id: 'nrule_w',
        channel: 'webhook',
        destination_preview: 'webhook://hooks.example.invalid',
        status: 'queued_provider_not_configured',
        reason: 'outbound_provider_not_configured_opt_in',
        created_at: sampleEvent.created_at,
        attempted_at: null,
      },
    ];

    const delivered = await finalizeNotificationDeliveryAttempts({
      deliveryMode: 'webhook',
      attempts,
      rules: [{ id: 'nrule_w', channel: 'webhook', destination: 'https://hooks.example.invalid/h' }],
      event: sampleEvent,
      now: sampleEvent.created_at,
      webhookSender: async () => ({ ok: true, status: 202 }),
    });
    assert.equal(delivered[0].status, 'delivered_provider');
    assert.equal(delivered[0].reason, 'webhook_delivered');

    const failed = await finalizeNotificationDeliveryAttempts({
      deliveryMode: 'webhook',
      attempts,
      rules: [{ id: 'nrule_w', channel: 'webhook', destination: 'https://hooks.example.invalid/h' }],
      event: sampleEvent,
      now: sampleEvent.created_at,
      webhookSender: async () => ({ ok: false, error: 'webhook_http_error', status: 503 }),
    });
    assert.equal(failed[0].status, 'provider_retry_scheduled');
    assert.equal(failed[0].attempt_number, 1);
    assert.equal(failed[0].max_attempts, 3);
  });
});


describe('notification HTTP destination safety', () => {
  function successfulHttpsRequest(captured) {
    return (options, callback) => {
      captured.push(options);
      const request = new EventEmitter();
      request.write = () => true;
      request.end = () => queueMicrotask(() => {
        const response = Readable.from([]);
        response.statusCode = 204;
        response.headers = {};
        callback(response);
      });
      request.destroy = (error) => {
        if (error) queueMicrotask(() => request.emit('error', error));
      };
      return request;
    };
  }

  it('rejects private and zero-answer webhook/provider destinations before opening a socket', async () => {
    let socketAttempts = 0;
    const httpsRequestFn = () => {
      socketAttempts += 1;
      throw new Error('socket must not open');
    };

    const privateResult = await sendWebhookNotification('https://127.0.0.1/hook', '{}', {
      transportDeps: { httpsRequestFn },
    });
    assert.equal(privateResult.ok, false);
    assert.match(privateResult.error, /private|loopback|destination/i);

    const unresolvedResult = await sendProviderHttpsPost('https://hooks.example.test/provider', '{}', {
      transportDeps: {
        resolve4Fn: async () => [],
        resolve6Fn: async () => [],
        httpsRequestFn,
      },
    });
    assert.equal(unresolvedResult.ok, false);
    assert.match(unresolvedResult.error, /did not resolve/i);
    assert.equal(socketAttempts, 0);
  });

  it('pins webhook and provider sockets to the classified public address while preserving Host and SNI', async () => {
    for (const sender of [sendWebhookNotification, sendProviderHttpsPost]) {
      const requests = [];
      let resolve4Calls = 0;
      let resolve6Calls = 0;
      const result = await sender('https://hooks.example.test:8443/notify', '{}', {
        transportDeps: {
          resolve4Fn: async (host) => {
            resolve4Calls += 1;
            assert.equal(host, 'hooks.example.test');
            return ['93.184.216.34'];
          },
          resolve6Fn: async (host) => {
            resolve6Calls += 1;
            assert.equal(host, 'hooks.example.test');
            return [];
          },
          httpsRequestFn: successfulHttpsRequest(requests),
        },
      });

      assert.deepEqual(result, { ok: true, status: 204, transport: 'http' });
      assert.equal(resolve4Calls, 1);
      assert.equal(resolve6Calls, 1);
      assert.equal(requests.length, 1);
      assert.equal(requests[0].hostname, '93.184.216.34');
      assert.equal(requests[0].servername, 'hooks.example.test');
      assert.equal(requests[0].headers.Host, 'hooks.example.test:8443');
    }
  });
});
