import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import { pinnedFetch } from '../../src/lib/pinnedHttpRequest.mjs';
import { normalizeProbeActivityItem, normalizeProbeActivityBatch, probeActivityEvent, projectRunActivity } from '../../src/lib/probeActivity.mjs';
import { MAX_CAPTURE_BODY_BYTES, captureResponsePayload } from '../../src/lib/probePayloadPreview.mjs';
import { createProbeActivityReporter } from '../../workers/probe-activity-reporter.mjs';
import { recordedExchanges, exchangeCopyText } from '../../apps/web/react/src/lib/http-exchanges.mjs';

const source = { job_id: 'job_full', leased_at: new Date().toISOString() };
function projection(events) {
  return events.map((event, index) => ({ ...event, sequence: index + 1, source_context: source }));
}

test('full 64 KiB request and 1 MiB response survive real HTTP, signed-size batches, ingestion, projection and copy', async () => {
  const requestSuffix = '&password=raw-request-value';
  const requestBody = `${'x'.repeat(64 * 1024 - requestSuffix.length)}${requestSuffix}`;
  const responseBody = `${'x'.repeat(8191)}€${'y'.repeat(MAX_CAPTURE_BODY_BYTES - 8191 - 3 - Buffer.byteLength('password=raw-reply-value!'))}password=raw-reply-value!`;
  assert.equal(Buffer.byteLength(responseBody), MAX_CAPTURE_BODY_BYTES);
  let received;
  const headers = Object.fromEntries(Array.from({ length: 30 }, (_, index) => [`x-custom-${index}`, `value-${index}`]));
  const server = http.createServer(async (req, res) => {
    const body = [];
    for await (const chunk of req) body.push(chunk);
    received = Buffer.concat(body).toString();
    res.writeHead(200, { ...headers, 'content-type': 'text/html; charset=UTF-8',
      'set-cookie': ['session=raw-session; HttpOnly', 'other=raw-cookie'],
      'x-powered-by': 'raw-server', 'vary': ['Accept', 'Accept-Encoding'] });
    res.end(responseBody);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const job = { id: source.job_id, leased_at: source.leased_at, tenant_id: 'tenant_full', test_run_id: 'run_full', check_id: 'check_full' };
  const events = [];
  const batches = [];
  const reporter = createProbeActivityReporter(job, async (body) => {
    batches.push(body);
    const parsed = normalizeProbeActivityBatch(body, job);
    assert.equal(parsed.error, undefined);
    events.push(...parsed.items.map((item) => probeActivityEvent(job, item, 'worker_full')));
    return { status: 201 };
  });
  try {
    const response = await pinnedFetch(`http://127.0.0.1:${server.address().port}/?an_cb=b9276787caa9&token=raw-query&tag=one&tag=two`,
      { method: 'POST', body: requestBody, headers: { authorization: 'Bearer raw-authorization', 'content-type': 'application/x-www-form-urlencoded' } },
      { destinationPolicy: { allowLoopback: true, allowPrivate: false }, onProbeActivity: reporter.record });
    assert.equal(await new Response(response.body).text(), responseBody);
    const stats = await reporter.close();
    assert.equal(stats.dropped_count, 0);
    assert.equal(stats.delivery_failures, 0);
    assert.ok(batches.every((batch) => Buffer.byteLength(JSON.stringify(batch)) < 32 * 1024));
    assert.ok(events.length < 256);
    assert.equal(received, requestBody);
    const feed = projectRunActivity({ id: job.test_run_id, tenant_id: job.tenant_id, status: 'verdicted' }, events, { limit: 256 });
    const [exchange] = recordedExchanges(feed.items).exchanges;
    assert.equal(exchange.state, 'captured');
    assert.equal(exchange.request.request_payload_preview, requestBody);
    assert.equal(exchange.response.response_payload_preview, responseBody);
    assert.equal(exchange.response.response_payload_encoding, 'utf8');
    assert.equal(exchange.response.response_payload_truncated, false);
    const recorded = exchange.response.response_headers;
    assert.ok(recorded.some((header) => header.name === 'x-custom-29' && header.value === 'value-29'));
    assert.equal(recorded.filter((header) => header.name === 'set-cookie').length, 2);
    assert.equal(recorded.filter((header) => header.name === 'vary').length, 2);
    assert.ok(recorded.some((header) => header.name === 'x-powered-by' && header.value === 'raw-server'));
    assert.deepEqual(JSON.parse(exchange.request.request_query_preview).tag, ['one', 'two']);
    const copied = exchangeCopyText(exchange);
    for (const value of [requestBody, responseBody, 'b9276787caa9', 'raw-query', 'Bearer raw-authorization', 'session=raw-session']) assert.ok(copied.includes(value), value.slice(0, 60));
    assert.doesNotMatch(copied, /\[redacted\]|withheld/);
  } finally {
    await reporter.close();
    server.closeAllConnections(); await new Promise((resolve) => server.close(resolve));
  }
});

test('chunked binary bodies retain exact bytes, while missing or contradictory chunks never read as complete', () => {
  const bytes = Buffer.alloc(24_577);
  for (let index = 0; index < bytes.length; index++) bytes[index] = index % 256;
  const events = [{ capture_version: 'http-exchange.v1', exchange_id: 'binary', stage: 'request_started', method: 'GET', body_bytes: 0 }];
  const capture = captureResponsePayload({ onProbeActivity: (event) => events.push(event) },
    { capture_version: 'http-exchange.v1', exchange_id: 'binary', method: 'GET' }, 'application/octet-stream');
  capture.chunk(bytes.subarray(0, 8193)); capture.chunk(bytes.subarray(8193)); capture.complete();
  const feed = projection(events);
  const [complete] = recordedExchanges(feed).exchanges;
  assert.equal(complete.state, 'captured');
  assert.equal(complete.response.response_payload_encoding, 'base64');
  assert.deepEqual(Buffer.from(complete.response.response_payload_preview, 'base64'), bytes);
  const [missing] = recordedExchanges(feed.filter((event) => event.response_payload_offset !== 8192)).exchanges;
  assert.equal(missing.state, 'partial');
  assert.equal(missing.response.response_payload_truncated, true);
  const chunk = feed.find((event) => event.response_payload_offset === 8192);
  const [conflicting] = recordedExchanges([...feed, { ...chunk, sequence: 250, response_payload_preview: Buffer.from('different').toString('base64') }]).exchanges;
  assert.equal(conflicting.state, 'partial');
  assert.equal(conflicting.response, null);
  assert.deepEqual(conflicting.conflictFields, ['response.payload_chunk']);
});

test('payload chunk ingestion rejects invalid offsets, encodings and oversized chunks', () => {
  const chunk = { sequence: 1, at: new Date().toISOString(), capture_version: 'http-exchange.v1', exchange_id: 'chunks',
    stage: 'response_payload', response_payload_offset: 0, response_payload_preview: Buffer.from('valid').toString('base64'), response_payload_encoding: 'base64' };
  assert.ok(normalizeProbeActivityItem(chunk));
  for (const override of [
    { response_payload_offset: -1 }, { response_payload_offset: 1.5 }, { response_payload_offset: MAX_CAPTURE_BODY_BYTES },
    { response_payload_preview: '!invalid' }, { response_payload_encoding: 'utf8' }, { stage: 'request_started' },
    { response_payload_preview: Buffer.alloc(8193).toString('base64') },
    { response_payload_preview: Buffer.alloc(8192).toString('base64'), response_headers: [{ name: 'x-long', value: 'x'.repeat(16_384) }] },
  ]) assert.equal(normalizeProbeActivityItem({ ...chunk, ...override }), null, JSON.stringify(Object.keys(override)));
});

test('chunk reconstruction preserves UTF-8 BOM bytes and represents non-printable binary bytes as Base64', () => {
  for (const [bytes, encoding] of [[Buffer.from('\uFEFF' + 'x'.repeat(10_000)), 'utf8'], [Buffer.alloc(10_000, 1), 'base64']]) {
    const identity = { capture_version: 'http-exchange.v1', exchange_id: 'bytes' };
    const events = [{ ...identity, stage: 'request_started', body_bytes: 0 }];
    const capture = captureResponsePayload({ onProbeActivity: (event) => events.push(event) }, identity, 'application/octet-stream');
    capture.chunk(bytes); capture.complete();
    const [exchange] = recordedExchanges(projection(events)).exchanges;
    assert.equal(exchange.response.response_payload_encoding, encoding);
    assert.deepEqual(Buffer.from(exchange.response.response_payload_preview, encoding), bytes);
  }
});
