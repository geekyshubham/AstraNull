import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import { activityUrl, normalizeProbeActivityBatch, projectRunActivity } from '../../src/lib/probeActivity.mjs';
import { pinnedFetch } from '../../src/lib/pinnedHttpRequest.mjs';
import { createProbeActivityReporter } from '../../workers/probe-activity-reporter.mjs';
import { countEventsForRun } from '../../src/services/safeTestPolicy.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

test('activity retains method/path and query names without credentials, bodies, or header values', () => {
  const at = new Date().toISOString();
  const job = { leased_at: at };
  const item = { sequence: 1, at, stage: 'request_started', method: 'GET', url: 'https://user:secret@owned.test/path?token=private#password' };
  const parsed = normalizeProbeActivityBatch({ leased_at: at, items: [item] }, job);
  assert.equal(parsed.items[0].method, 'GET');
  assert.equal(parsed.items[0].url, 'https://owned.test/path?token=%5Bredacted%5D');
  assert.equal(/private|password|user:secret/.test(JSON.stringify(parsed)), false);
  for (const field of ['body', 'headers', 'authorization', 'nonce', 'producer_kind']) {
    assert.equal(normalizeProbeActivityBatch({ leased_at: at, items: [{ ...item, [field]: 'secret' }] }, job).error, 'invalid_probe_activity');
  }
  assert.equal(normalizeProbeActivityBatch({ leased_at: 'old-lease', items: [item] }, job).status, 409);
  assert.equal(normalizeProbeActivityBatch({ leased_at: at, items: [{ ...item, sequence: 257 }] }, job).status, 400);
  assert.equal(activityUrl('file:///etc/passwd'), null);
});

test('activity read keeps unsigned claims out, preserves zero, and does not consume evidence budgets', () => {
  freshStore();
  const run = { id: 'run_activity', tenant_id: 'ten_demo', target_id: 'tgt_activity', check_id: 'check_activity', status: 'running' };
  const at = new Date().toISOString();
  const event = { id: 'event_activity', tenant_id: run.tenant_id, test_run_id: run.id, signal_type: 'probe_activity', producer_kind: 'signed_probe', timestamp: at,
    metadata: { activity: { sequence: 1, at, stage: 'request_not_sent', reason: 'ownership_refused' } } };
  getStore().events.push(event);
  assert.equal(countEventsForRun(run.id), 0);
  const events = [event, { ...event, id: 'spoofed', producer_kind: 'public_api' }, { ...event, id: 'foreign', tenant_id: 'ten_other' }];
  const projected = projectRunActivity(run, events);
  assert.equal(projected.items.length, 1);
  assert.equal(projected.items[0].stage, 'request_not_sent');
  assert.equal(projected.requests_sent, null);
  const zero = projectRunActivity(run, [...events, { id: 'zero', tenant_id: run.tenant_id, test_run_id: run.id, producer_kind: 'signed_probe', signal_type: 'probe_result', timestamp: at,
    metadata: { external_result: 'not_run', safety_attestation: { requests_sent: 0 } } }]);
  assert.equal(zero.requests_sent, 0);
});

test('final activity retains bounded protocol and port observations without exposing arbitrary metadata', () => {
  const run = { id: 'run_protocol_activity', tenant_id: 'ten_demo', target_id: 'target_1', check_id: 'l3.firewall_exposure_scan.safe', status: 'verdicted' };
  const event = { id: 'evt_protocol_activity', tenant_id: run.tenant_id, test_run_id: run.id, signal_type: 'probe_result', producer_kind: 'signed_probe', timestamp: new Date().toISOString(),
    metadata: { external_result: 'connected', open_ports: [443, '22', -1, 65536], filtered_ports: [22], closed_ports: [3389], query_type: 'SOA', record_count: 2, password: 'never-render-this' } };
  const result = projectRunActivity(run, [event]);
  assert.deepEqual(result.items[0].port_observations, { open_ports: [443], filtered_ports: [22], closed_ports: [3389] });
  assert.equal(result.items[0].observations.query_type, 'SOA');
  assert.equal(result.items[0].observations.record_count, 2);
  assert.equal(JSON.stringify(result).includes('never-render-this'), false);
});

test('pinned HTTP logs capture actual method, MIME format, redacted payloads, and preserve the original response', async () => {
  const body = JSON.stringify({ marker: 'astranull-inert', password: 'private-password' });
  const responseBody = JSON.stringify({ message: 'Request blocked', token: 'private-token' });
  let received;
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    received = Buffer.concat(chunks).toString();
    res.writeHead(418, { 'content-type': 'application/json', 'set-cookie': 'private=value' }); res.end(responseBody);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const logs = [];
    const result = await pinnedFetch(`http://127.0.0.1:${server.address().port}/probe?secret=hidden`, { method: 'POST', body, headers: { authorization: 'Bearer secret', 'content-type': 'application/json' } },
      { destinationPolicy: { allowLoopback: true, allowPrivate: false }, onProbeActivity: (item) => logs.push(item) });
    const actualBody = await new Response(result.body).text();
    assert.equal(received, body);
    assert.equal(actualBody, responseBody);
    assert.deepEqual(logs.map((item) => item.stage), ['request_started', 'response_received', 'response_payload', 'response_body_completed']);
    assert.equal(logs[0].method, 'POST');
    assert.equal(logs[0].body_bytes, Buffer.byteLength(body));
    assert.equal(logs[0].request_content_type, 'application/json');
    assert.match(logs[0].request_payload_preview, /astranull-inert/);
    assert.equal(JSON.parse(logs[0].request_payload_preview).password, '[redacted]');
    assert.equal(logs[1].status_code, 418);
    assert.equal(logs[1].response_content_type, 'application/json');
    assert.equal(JSON.parse(logs[3].response_payload_preview).message, 'Request blocked');
    assert.equal(JSON.parse(logs[3].response_payload_preview).token, '[redacted]');
    assert.equal(logs[3].response_payload_truncated, false);
    assert.equal(logs[3].response_bytes_observed, Buffer.byteLength(responseBody));
    assert.equal(/hidden|Bearer secret|private-password|private-token|private=value/.test(JSON.stringify(logs)), false);
  } finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
});

test('activity reporter bounds batches and cooperatively aborts on a revoked job', async () => {
  const sent = [];
  const cancellation = new AbortController();
  const job = { leased_at: new Date().toISOString() };
  const reporter = createProbeActivityReporter(job, async (batch) => {
    sent.push(batch); return { status: sent.length === 1 ? 201 : 409 };
  }, { onStop: () => cancellation.abort(), heartbeatMs: 10_000 });
  for (let i = 0; i < 300; i += 1) reporter.record({ stage: 'attempt_started', operation: 'tcp_connect' });
  await reporter.close();
  assert.equal(cancellation.signal.aborted, true);
  assert.ok(sent.every((batch) => batch.items.length <= 16));
  assert.ok(sent.flatMap((batch) => batch.items).every((item) => item.sequence <= 256));
});
