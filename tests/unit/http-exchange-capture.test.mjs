import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import { EventEmitter } from 'node:events';
import { captureHttpHeaders, captureUrl, HTTP_CAPTURE_VERSION } from '../../src/lib/probeHttpCapture.mjs';
import { normalizeProbeActivityItem, projectRunActivity } from '../../src/lib/probeActivity.mjs';
import { captureResponsePayload } from '../../src/lib/probePayloadPreview.mjs';
import { pinnedFetch, pinnedHttp2Request } from '../../src/lib/pinnedHttpRequest.mjs';

const item = (extra = {}) => ({ sequence: 1, at: new Date().toISOString(), stage: 'request_started',
  capture_version: HTTP_CAPTURE_VERSION, exchange_id: 'exchange_1', attempt_id: 'attempt_1', operation_id: 'operation_1', ...extra });

test('HTTP capture preserves every header value and duplicate entry', () => {
  const entries = captureHttpHeaders(['Content-Type', 'text/plain; charset=UTF-8', 'Vary', 'Accept', 'Vary', 'Accept-Encoding',
    'Authorization', 'Bearer private-value', 'Set-Cookie', 'session=private', 'X-Customer', 'private-customer',
    'Date', 'Sun, 18 Oct 2026 12:00:00 GMT', 'Location', '/login?session=private-session&next=private-path#fragment']);
  assert.deepEqual(entries.slice(1, 3), [{ name: 'vary', value: 'Accept' }, { name: 'vary', value: 'Accept-Encoding' }]);
  assert.equal(entries.find((entry) => entry.name === 'authorization').value, 'Bearer private-value');
  assert.equal(entries.find((entry) => entry.name === 'set-cookie').value, 'session=private');
  assert.equal(entries.find((entry) => entry.name === 'x-customer').value, 'private-customer');
  assert.equal(entries.find((entry) => entry.name === 'location').value, '/login?session=private-session&next=private-path#fragment');
  assert.doesNotMatch(JSON.stringify(entries), /\[redacted\]/);
  assert.equal(captureHttpHeaders(Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`x-header-${i}`, `value-${i}`]))).length, 100);
});

test('captured URLs retain paths, credentials, query values and duplicate keys', () => {
  assert.equal(captureUrl('https://user:private@owned.test/a%2Fb?marker=one&marker=two#fragment'),
    'https://user:private@owned.test/a%2Fb?marker=one&marker=two');
  assert.equal(captureUrl('/reset/private-token?token=private', { relative: true }), '/reset/private-token?token=private');
  assert.equal(captureUrl('javascript:alert(1)', { relative: true }), null);
  assert.equal(captureUrl('https://owned.test/private-marker', { sensitiveValues: ['private-marker'] }), 'https://owned.test/private-marker');
});

test('strict capture fields preserve values at ingestion and still reject malformed metadata', () => {
  const normalized = normalizeProbeActivityItem(item({ request_headers: [{ name: 'Cookie', value: 'private' }], http_version: '2.0' }));
  assert.deepEqual(normalized.request_headers, [{ name: 'cookie', value: 'private' }]);
  assert.equal(normalized.http_version, '2.0');
  assert.equal(normalizeProbeActivityItem(item({ capture_version: 'future' })), null);
  assert.equal(normalizeProbeActivityItem(item({ request_headers: [{ name: 'x', value: 'v', raw: 'private' }] })), null);
  assert.equal(normalizeProbeActivityItem(item({ request_headers: Array.from({ length: 2049 }, () => ({ name: 'host', value: 'owned.test' })) })), null);
  assert.equal(normalizeProbeActivityItem(item({ exchange_id: 'spaces are invalid' })), null);
  assert.equal(normalizeProbeActivityItem(item({ http_version: 'https' })), null);
  assert.equal(normalizeProbeActivityItem(item({ capture_version: undefined, request_headers: [] })), null);
});

test('binary and partial payloads retain their bytes and explicit capture state', () => {
  const encoded = Buffer.from([0, 1, 2, 255]).toString('base64');
  const binary = normalizeProbeActivityItem(item({ response_payload_encoding: 'base64', response_payload_preview: encoded }));
  assert.equal(binary.response_payload_encoding, 'base64');
  assert.equal(binary.response_payload_preview, encoded);
  for (const side of ['request', 'response']) {
    const fields = { [`${side}_payload_preview`]: 'private-incomplete-prefix', [`${side}_payload_encoding`]: 'utf8', [`${side}_payload_truncated`]: true };
    const normalized = normalizeProbeActivityItem(item(fields));
    assert.equal(normalized[`${side}_payload_preview`], 'private-incomplete-prefix');
    assert.equal(normalized[`${side}_payload_truncated`], true);
  }
});

test('response capture preserves text across chunks including supplied sensitive values', () => {
  const events = [];
  const capture = captureResponsePayload({ onProbeActivity: (event) => events.push(event), activitySensitiveValues: ['customer-private'] },
    { capture_version: HTTP_CAPTURE_VERSION, exchange_id: 'exchange_1' }, 'text/plain');
  capture.chunk(Buffer.from('customer-'));
  assert.equal(events[0].response_payload_preview, 'customer-');
  capture.chunk(Buffer.from('private')); capture.complete();
  assert.equal(events.at(-1).response_payload_preview, 'customer-private');
  assert.equal(events.at(-1).response_payload_truncated, false);
});

test('HTML, XML and multipart bodies are preserved as inert text through capture and ingestion', () => {
  for (const [body, type] of [
    ['<form><input name="csrf" value="private-form-value"></form><script>alert(1)</script>', 'text/html'],
    ['<response><token>private-xml-value</token></response>', 'application/xml'],
    ['--boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\nprivate-multipart-value\r\n--boundary--', 'multipart/form-data; boundary=boundary'],
  ]) {
    const events = [];
    const capture = captureResponsePayload({ onProbeActivity: (event) => events.push(event) }, { capture_version: HTTP_CAPTURE_VERSION }, type);
    capture.chunk(Buffer.from(body)); capture.complete();
    assert.equal(events.at(-1).response_payload_encoding, 'utf8');
    assert.equal(events.at(-1).response_payload_preview, body);
    const normalized = normalizeProbeActivityItem(item({ response_content_type: type, response_payload_preview: body, response_payload_encoding: 'utf8' }));
    assert.equal(normalized.response_payload_preview, body);
    assert.equal(normalized.response_payload_encoding, 'utf8');
  }
});

test('projection does not apply branding substitutions to immutable recorded URL, headers or payload text', () => {
  const at = new Date().toISOString();
  const run = { id: 'run_capture', tenant_id: 'tenant_1', check_id: 'check_1', status: 'verdicted' };
  const event = { id: 'evt_1', tenant_id: run.tenant_id, test_run_id: run.id, signal_type: 'probe_activity', producer_kind: 'signed_probe',
    timestamp: at, metadata: { probe_job_id: 'job_1', leased_at: at, activity: item({ at, url: 'https://owned.test/wafw00f',
      response_headers: [{ name: 'server', value: 'cdncheck' }], response_payload_preview: 'wafw00f cdncheck' }) } };
  const projected = projectRunActivity(run, [event]);
  assert.equal(projected.items[0].url, 'https://owned.test/wafw00f');
  assert.equal(projected.items[0].response_headers[0].value, 'cdncheck');
  assert.equal(projected.items[0].response_payload_preview, 'wafw00f cdncheck');
});

test('activity preserves legacy total while exposing distinct nullable logical operation accounting', () => {
  const run = { id: 'run_counts', tenant_id: 'tenant_1', status: 'verdicted' };
  const event = { id: 'evt_result', tenant_id: run.tenant_id, test_run_id: run.id, signal_type: 'probe_result', producer_kind: 'signed_probe',
    timestamp: new Date().toISOString(), metadata: { request_counting_basis: 'logical_operations',
      safety_attestation: { requests_sent: 7, probe_requests_sent: 5, destination_resolver_attempts: 2, total_operations: 7 } } };
  const result = projectRunActivity(run, [event]);
  assert.equal(result.requests_sent, 7);
  assert.deepEqual(result.accounting, { probe_logical_attempts: 5, destination_vetting_resolver_attempts: 2, total_operations: 7, counting_basis: 'logical_operations' });
  const legacy = projectRunActivity(run, [{ ...event, metadata: { safety_attestation: { requests_sent: 7 } } }]);
  assert.equal(legacy.accounting.probe_logical_attempts, null);
  assert.equal(legacy.accounting.destination_vetting_resolver_attempts, null);
});

test('HTTP/2 response capture preserves header values, MIME parameters and consumed bodies', async () => {
  const events = [];
  const session = new EventEmitter();
  const stream = new EventEmitter();
  let deliveredHeaders;
  let deliveredBody;
  session.request = (headers) => { deliveredHeaders = headers; return stream; };
  session.destroy = () => {};
  stream.close = () => {};
  stream.end = (body) => {
    deliveredBody = body;
    queueMicrotask(() => {
      stream.emit('response', { ':status': 200, 'set-cookie': ['session=private-response-cookie'],
        server: 'private-response-cookie', 'content-type': 'text/plain; charset=private-response-cookie' });
      stream.emit('data', Buffer.from('reply private-response-cookie'));
      stream.emit('end');
    });
  };
  const response = await pinnedHttp2Request('https://owned.test/probe', { method: 'POST', body: 'inert-body',
    headers: { authorization: 'Bearer private' }, captureResponseBody: true }, {
    vettedHost: 'owned.test', vettedAddresses: ['203.0.113.10'], http2ConnectFn: () => session,
    onProbeActivity: (event) => events.push(event),
  });
  assert.equal(deliveredHeaders.authorization, 'Bearer private');
  assert.equal(deliveredBody.toString(), 'inert-body');
  assert.equal(response.responseBody.toString(), 'reply private-response-cookie');
  assert.equal(events.find((event) => event.stage === 'response_received').response_content_type, 'text/plain; charset=private-response-cookie');
  assert.equal(events.at(-1).response_payload_preview, 'reply private-response-cookie');
  assert.match(JSON.stringify(events), /private-response-cookie/);
  assert.match(JSON.stringify(events), /Bearer private/);
});

test('structured request capture preserves the exact delivered multipart body', async () => {
  const body = '--boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\nprivate-form-value\r\n--boundary--';
  let received = '';
  const server = http.createServer(async (req, res) => {
    for await (const chunk of req) received += chunk.toString();
    res.end('recorded response');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const events = [];
    const response = await pinnedFetch(`http://127.0.0.1:${server.address().port}/form`, { method: 'POST', body,
      headers: { 'Content-Type': 'multipart/form-data; boundary=boundary' } },
    { destinationPolicy: { allowLoopback: true, allowPrivate: false }, onProbeActivity: (event) => events.push(event) });
    await new Response(response.body).text();
    assert.equal(received, body);
    assert.equal(events[0].request_payload_preview, body);
    assert.equal(events[0].request_payload_encoding, 'utf8');
    assert.match(JSON.stringify(events), /private-form-value/);
  } finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
});

test('actual concurrent same-URL transports have separate identities and do not change request bytes', async () => {
  const received = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    received.push({ method: req.method, url: req.url, body: Buffer.concat(chunks).toString(), authorization: req.headers.authorization });
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=private-response-cookie', 'Set-Cookie': 'session=private-response-cookie',
      Server: 'private-response-cookie', 'Vary': ['Accept', 'Accept-Encoding'] });
    res.end('recorded response private-response-cookie');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const events = [];
    const url = `http://127.0.0.1:${server.address().port}/same?token=private`;
    const deps = { destinationPolicy: { allowLoopback: true, allowPrivate: false }, onProbeActivity: (event) => events.push(event) };
    const responses = await Promise.all([1, 2].map(() => pinnedFetch(url, { method: 'POST', body: 'inert-body', headers: {
      'Content-Type': 'text/plain', authorization: 'Bearer private' } }, deps)));
    assert.deepEqual(await Promise.all(responses.map((response) => new Response(response.body).text())), ['recorded response private-response-cookie', 'recorded response private-response-cookie']);
    assert.equal(received.length, 2);
    assert.ok(received.every((request) => request.method === 'POST' && request.url === '/same?token=private'
      && request.body === 'inert-body' && request.authorization === 'Bearer private'));
    const starts = events.filter((event) => event.stage === 'request_started');
    assert.equal(new Set(starts.map((event) => event.exchange_id)).size, 2);
    for (const start of starts) {
      const exchange = events.filter((event) => event.exchange_id === start.exchange_id);
      assert.deepEqual(exchange.map((event) => event.stage), ['request_started', 'response_received', 'response_payload', 'response_body_completed']);
      assert.equal(exchange[1].http_version, '1.1');
      assert.equal(exchange[1].response_headers.find((header) => header.name === 'set-cookie').value, 'session=private-response-cookie');
      assert.equal(exchange[1].response_headers.find((header) => header.name === 'server').value, 'private-response-cookie');
      assert.equal(exchange[1].response_headers.find((header) => header.name === 'content-type').value, 'text/plain; charset=private-response-cookie');
      assert.equal(exchange[1].response_content_type, 'text/plain; charset=private-response-cookie');
      assert.equal(exchange.at(-1).response_payload_preview, 'recorded response private-response-cookie');
    }
    assert.match(JSON.stringify(events), /Bearer private/);
    assert.match(JSON.stringify(events), /token=private/);
  } finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
});
