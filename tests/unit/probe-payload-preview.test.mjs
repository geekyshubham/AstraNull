import assert from 'node:assert/strict';
import { test } from 'node:test';
import { previewRequest, previewBytes, redactPayloadPreview, captureResponsePayload } from '../../src/lib/probePayloadPreview.mjs';
import { createProbeActivityReporter } from '../../workers/probe-activity-reporter.mjs';

test('generated GET markers are readable while declared/private query values stay redacted', () => {
  const preview = previewRequest('https://owned.test/path?account=private-account&marker=astranull-inert&token=secret-token', {}, { activityBaseUrl: 'https://owned.test/path?account=private-account' });
  const query = JSON.parse(preview.request_query_preview);
  assert.equal(query.marker, 'astranull-inert');
  assert.equal(query.account, '[redacted]');
  assert.equal(query.token, '[redacted]');
  assert.equal(preview.request_payload_preview, '');
});
test('payload preview is bounded, redacts nested credentials, and preserves prototype marker keys safely', () => {
  const preview = redactPayloadPreview('{"__proto__":{"marker":"inert"},"auth":{"access_token":"hidden"},"password":"secret"}');
  const parsed = JSON.parse(preview);
  assert.deepEqual(parsed.__proto__, { marker: 'inert' });
  assert.equal(parsed.auth.access_token, '[redacted]');
  assert.equal(parsed.password, '[redacted]');
  assert.equal(previewBytes(Buffer.from('x'.repeat(5000)), 'text/plain').truncated, true);
  assert.equal(previewBytes(Buffer.from('x'.repeat(5000)), 'text/plain').preview.length, 2048);
});
test('binary HTTP application previews report their actual encoding without treating them as text', () => {
  const bytes = Buffer.from([0, 1, 2, 3]);
  const preview = previewBytes(bytes, 'application/grpc');
  assert.equal(preview.encoding, 'base64');
  assert.deepEqual(Buffer.from(preview.preview, 'base64'), bytes);
});
test('response observation emits only consumed bytes and states when the sample is partial', () => {
  const logs = [];
  const capture = captureResponsePayload({ onProbeActivity: (entry) => logs.push(entry) }, { method: 'GET' }, 'text/plain');
  capture.chunk(Buffer.from('x'.repeat(3000))); capture.complete();
  assert.equal(logs[0].response_bytes_observed, 3000);
  assert.equal(logs[0].response_bytes_captured, 2048);
  assert.equal(logs[1].response_payload_truncated, true);
  assert.equal(logs[1].response_payload_preview.length, 2048);
});
test('reporter splits verbose previews to fit signed body limits and retries the same immutable ordinals', async () => {
  const batches = [];
  let calls = 0;
  const reporter = createProbeActivityReporter({ leased_at: new Date().toISOString() }, async (batch) => {
    calls += 1;
    batches.push(batch);
    return { status: calls === 1 ? 503 : 201 };
  }, { heartbeatMs: 10_000 });
  for (let i = 0; i < 40; i += 1) reporter.record({ stage: 'request_started', operation: 'http_request', request_payload_preview: 'x'.repeat(4000) });
  await reporter.close();
  assert.ok(batches.every((batch) => Buffer.byteLength(JSON.stringify(batch)) <= 32 * 1024));
  assert.equal(batches[0].items[0].sequence, batches[1].items[0].sequence);
  const accepted = new Set(batches.slice(1).flatMap((batch) => batch.items.map((item) => item.sequence)));
  assert.equal(accepted.size, 40);
});
