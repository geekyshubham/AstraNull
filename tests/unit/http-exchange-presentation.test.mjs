import assert from 'node:assert/strict';
import { test } from 'node:test';
import { captureHeaders, exchangeCopyText, recordedExchanges, safeCaptureText, safeCaptureUrl } from '../../apps/web/react/src/lib/http-exchanges.mjs';
import { activityRequestsSentLabel, activityRequestLimitLabel } from '../../apps/web/react/src/lib/activity-labels.mjs';

const source = { job_id: 'job_original', worker_id: 'worker_1', leased_at: '2030-01-01T00:00:00.000Z' };
const event = (stage, extra = {}) => ({ id: `evt_${stage}`, capture_version: 'http-exchange.v1', exchange_id: 'exchange_1', source_context: source, stage, sequence: 1, ...extra });

test('pairs only explicit exchange identity and the original per-event job and lease', () => {
  const items = [event('request_started'), event('response_received'),
    event('response_received', { source_context: { ...source, job_id: 'job_other' } }),
    event('response_received', { source_context: { ...source, leased_at: '2030-01-02T00:00:00.000Z' } }),
    event('request_started', { exchange_id: undefined }),
    event('response_received', { source_context: undefined }),
    event('response_received', { source_context: { job_id: source.job_id } })];
  const grouped = recordedExchanges(items);
  assert.equal(grouped.exchanges.length, 3);
  assert.equal(grouped.lifecycle.length, 3);
  assert.equal(grouped.exchanges[0].events.length, 2);
  assert.equal(grouped.exchanges[1].request, null);
  assert.equal(grouped.exchanges[2].request, null);
});

test('unknown and absent capture versions remain unpaired lifecycle records', () => {
  const legacy = [event('request_started', { capture_version: undefined }), event('response_received', { capture_version: 'http-exchange.v2' })];
  assert.deepEqual(recordedExchanges(legacy), { exchanges: [], lifecycle: legacy });
});

test('conflicting same-exchange facts stay partial and are withheld, never synthesized', () => {
  for (const records of [
    [event('request_started', { method: 'GET' }), event('request_started', { method: 'POST', sequence: 2 })],
    [event('response_received', { status_code: 200 }), event('response_received', { status_code: 403, sequence: 2 })],
    [event('request_started', { url: 'https://owned.example/one' }), event('response_received', { url: 'https://owned.example/two' })],
  ]) {
    const exchange = recordedExchanges(records).exchanges[0];
    assert.equal(exchange.state, 'partial');
    assert.ok(exchange.conflictFields.length > 0);
    assert.match(exchangeCopyText(exchange), /Capture conflict/);
    if (exchange.conflictFields.some((field) => field.startsWith('request.') || field.startsWith('exchange.'))) assert.equal(exchange.request, null);
    if (exchange.conflictFields.some((field) => field.startsWith('response.') || field.startsWith('exchange.'))) assert.equal(exchange.response, null);
  }
});

test('different request and response HTTP versions are not a capture conflict', () => {
  const exchange = recordedExchanges([event('request_started', { http_version: 'HTTP/1.1' }), event('response_body_completed', { http_version: 'HTTP/1.0', sequence: 2 })]).exchanges[0];
  assert.equal(exchange.state, 'captured');
  assert.deepEqual(exchange.conflictFields, []);
  assert.equal(exchange.request.http_version, 'HTTP/1.1');
  assert.equal(exchange.response.http_version, 'HTTP/1.0');
  const inconsistent = recordedExchanges([event('request_started', { http_version: 'HTTP/1.1' }), event('request_started', { http_version: 'HTTP/2', sequence: 2 })]).exchanges[0];
  assert.equal(inconsistent.state, 'partial');
  assert.equal(inconsistent.request, null);
  assert.deepEqual(inconsistent.conflictFields, ['request.http_version']);
});

test('does not pair legacy events using URL, timestamp, phase, attempt or operation heuristics', () => {
  const legacy = ['request_started', 'response_received'].map((stage) => ({ id: stage, stage, at: source.leased_at, url: 'https://owned.example', phase: 'same', attempt_id: 'a', operation_id: 'o' }));
  assert.deepEqual(recordedExchanges(legacy), { exchanges: [], lifecycle: legacy });
});

test('latest body completion supersedes header-only availability without inventing a body', () => {
  const [exchange] = recordedExchanges([
    event('response_body_completed', { sequence: 3, response_payload_available: true, response_payload_preview: '', response_bytes_observed: 0 }),
    event('request_started', { sequence: 1, request_payload_preview: '' }),
    event('response_received', { sequence: 2, response_payload_available: false, reason: 'response_not_consumed', status_code: 200 }),
  ]).exchanges;
  assert.equal(exchange.state, 'captured');
  assert.equal(exchange.response.response_payload_available, true);
  assert.equal(exchange.response.response_payload_preview, '');
  assert.match(exchangeCopyText(exchange), /empty recorded body/);
  assert.doesNotMatch(exchangeCopyText(exchange), /Not consumed/);
});

test('separates missing halves, failures and partial previews from complete capture', () => {
  assert.equal(recordedExchanges([event('request_started')]).exchanges[0].state, 'partial');
  const failed = recordedExchanges([event('request_started'), event('attempt_failed', { error_class: 'timeout' })]).exchanges[0];
  assert.equal(failed.state, 'failed');
  assert.equal(failed.response, null);
  assert.match(exchangeCopyText(failed), /Failure: timeout/);
});

test('display and clipboard preserve nested values, duplicate headers, URLs and binary data', () => {
  const body = '{"Password":"must-not-leak","nested":{"clientSecret":"also-private"},"marker":"inert"}';
  assert.equal(safeCaptureText(body), body);
  const url = 'https://person:private@owned.example/a?token=hidden&marker=inert';
  assert.equal(safeCaptureUrl(url), url);
  const headers = [{ name: 'Set-Cookie', value: 'secret-cookie' }, { name: 'X-Trace', value: 'one' }, { name: 'X-Trace', value: 'two' }];
  assert.deepEqual(captureHeaders(headers), headers);
  const exchange = recordedExchanges([event('request_started', { url, request_headers: [{ name: 'Authorization', value: 'Basic secret' }], request_payload_preview: body }), event('response_body_completed', { sequence: 2, response_payload_preview: 'c2VjcmV0', response_payload_encoding: 'base64' })]).exchanges[0];
  const copied = exchangeCopyText(exchange);
  for (const value of [url, body, 'Authorization: Basic secret', 'c2VjcmV0', 'Body encoding: Base64']) assert.ok(copied.includes(value), value);
  assert.match(copied, /Job: job_original/);
  const long = 'x'.repeat(100_000);
  assert.equal(safeCaptureText(long), long);
});

test('accounting labels distinguish logical operations from HTTP requests', () => {
  assert.equal(activityRequestsSentLabel(null), 'Logical operations: not recorded');
  assert.equal(activityRequestsSentLabel(0), '0 logical operations (attested)');
  assert.equal(activityRequestsSentLabel(3), '3 logical operations (attested)');
  assert.equal(activityRequestLimitLabel(4), 'Signed probe allowance: up to 4 logical attempts');
});
