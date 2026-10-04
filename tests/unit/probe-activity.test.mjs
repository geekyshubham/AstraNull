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

test('pinned HTTP logs come from real transport starts and responses and contain no raw payload', async () => {
  const server = http.createServer((_req, res) => { res.writeHead(418, { 'set-cookie': 'private=value' }); res.end('private response body'); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const logs = [];
    const result = await pinnedFetch(`http://127.0.0.1:${server.address().port}/probe?secret=hidden`, { method: 'POST', body: 'private request body', headers: { authorization: 'Bearer secret' } },
      { destinationPolicy: { allowLoopback: true, allowPrivate: false }, onProbeActivity: (item) => logs.push(item) });
    await result.body.cancel();
    assert.deepEqual(logs.map((item) => item.stage), ['request_started', 'response_received']);
    assert.equal(logs[0].method, 'POST');
    assert.equal(logs[0].body_bytes, Buffer.byteLength('private request body'));
    assert.equal(logs[1].status_code, 418);
    assert.equal(/hidden|Bearer secret|private request body|private response body|private=value/.test(JSON.stringify(logs)), false);
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
