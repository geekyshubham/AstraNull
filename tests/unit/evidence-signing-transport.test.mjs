import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { describe, it } from 'node:test';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { buildCustodySigningEnvelope } from '../../src/lib/evidenceSigning.mjs';
import { createExternalKmsEvidenceSigningAdapter } from '../../src/lib/evidenceSigningKmsAdapter.mjs';
import { validateEvidenceSigningTransportConfig } from '../../src/lib/evidenceSigningTransport.mjs';

const tenantId = 'ten_transport';
const keyReference = 'key://transport/v1';
const digest = 'a'.repeat(64);
function fixture(extra = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const receipt = { signature: sign(null, Buffer.from(canonicalJsonStringify(buildCustodySigningEnvelope({ tenantId, custodyManifestDigest: digest }))), privateKey).toString('base64'),
    public_key_fingerprint_sha256: createHash('sha256').update(der).digest('hex') };
  const env = { NODE_ENV: 'production', ASTRANULL_DEPLOYMENT_PROFILE: 'production',
    ASTRANULL_KMS_SIGNING_ALLOWED_ORIGINS: 'https://signer.example.test', ASTRANULL_KMS_SIGNING_BEARER_TOKEN: 'fixture-auth',
    ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({ [tenantId]: { [keyReference]: {
      algorithm: 'ed25519', public_key_spki_der_base64: der.toString('base64'),
    } } }), ...extra };
  return { receipt, env };
}
async function run(f, config = {}) {
  return createExternalKmsEvidenceSigningAdapter({ endpoint: 'https://signer.example.test', env: f.env, ...config })
    .signDigest({ tenantId, keyReference, digest, algorithm: 'ed25519' });
}

describe('bounded authenticated custody signer transport', () => {
  for (const [name, extra, config] of [
    ['cleartext production', {}, { endpoint: 'http://127.0.0.1' }],
    ['nonlocal cleartext development', { NODE_ENV: 'test', ASTRANULL_DEPLOYMENT_PROFILE: 'local-staging' }, { endpoint: 'http://signer.example.test' }],
    ['URL credentials', {}, { endpoint: 'https://user:password@signer.example.test' }],
    ['URL query', {}, { endpoint: 'https://signer.example.test?token=secret' }],
    ['URL fragment', {}, { endpoint: 'https://signer.example.test#fragment' }],
    ['unapproved origin', { ASTRANULL_KMS_SIGNING_ALLOWED_ORIGINS: 'https://other.example.test' }, {}],
    ['missing approved origins', { ASTRANULL_KMS_SIGNING_ALLOWED_ORIGINS: '' }, {}],
    ['missing authentication', { ASTRANULL_KMS_SIGNING_BEARER_TOKEN: '' }, {}],
    ['header injection', { ASTRANULL_KMS_SIGNING_BEARER_TOKEN: 'first\r\nsecond' }, {}],
    ['zero timeout', {}, { fetchTimeoutMs: 0 }],
    ['nonfinite timeout', {}, { fetchTimeoutMs: Infinity }],
    ['fractional timeout', {}, { fetchTimeoutMs: 1.5 }],
    ['oversized timeout', {}, { fetchTimeoutMs: 30001 }],
    ['zero body cap', {}, { maxResponseBytes: 0 }],
    ['oversized body cap', {}, { maxResponseBytes: 65537 }],
  ]) it(`rejects ${name} before contacting the signer`, async () => {
    const f = fixture(extra);
    let calls = 0;
    const result = await run(f, { ...config, fetchFn: async () => { calls++; return Response.json(f.receipt); } });
    assert.ok(result.error);
    assert.equal(calls, 0);
  });
  it('does not expose credentials in configuration readiness', () => {
    const f = fixture();
    const result = validateEvidenceSigningTransportConfig({ endpoint: 'https://signer.example.test', env: f.env });
    assert.deepEqual(result, { ok: true, origin: 'https://signer.example.test' });
    assert.ok(!JSON.stringify(result).includes('fixture-auth'));
  });
  it('authenticates the request and forbids automatic redirects', async () => {
    const f = fixture();
    const result = await run(f, { fetchFn: async (url, init) => {
      assert.equal(url, 'https://signer.example.test/v1/sign');
      assert.equal(init.redirect, 'manual');
      assert.equal(init.headers.authorization, 'Bearer fixture-auth');
      assert.deepEqual(JSON.parse(init.body), { tenant_id: tenantId, key_reference: keyReference, algorithm: 'ed25519', digest });
      return Response.json(f.receipt);
    } });
    assert.equal(result.error, undefined);
  });
  it('does not follow a signer redirect', async () => {
    const f = fixture();
    let calls = 0;
    const result = await run(f, { fetchFn: async () => { calls++; return new Response(null, { status: 302, headers: { location: 'https://other.example.test' } }); } });
    assert.equal(result.error, 'kms_signing_unavailable');
    assert.equal(calls, 1);
  });
  for (const [name, response] of [
    ['oversized streamed body', () => new Response('x'.repeat(2048), { headers: { 'content-type': 'application/json' } })],
    ['oversized declared body', () => new Response('{}', { headers: { 'content-type': 'application/json', 'content-length': '2048' } })],
    ['malformed JSON', () => new Response('{', { headers: { 'content-type': 'application/json' } })],
    ['array receipt', () => Response.json([])],
    ['wrong content type', () => new Response('{}', { headers: { 'content-type': 'text/html' } })],
  ]) it(`rejects ${name}`, async () => {
    const f = fixture();
    const result = await run(f, { maxResponseBytes: 512, fetchFn: async () => response() });
    assert.equal(result.error, 'kms_signing_response_invalid');
  });
  it('bounds body consumption after headers arrive and cancels the reader', async () => {
    const f = fixture();
    let cancelled = false;
    let signal;
    const result = await run(f, { fetchTimeoutMs: 25, fetchFn: async (_, init) => {
      signal = init.signal;
      return new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('{')); },
        cancel() { cancelled = true; } }), { headers: { 'content-type': 'application/json' } });
    } });
    assert.equal(result.error, 'kms_signing_unavailable');
    assert.equal(result.detail, 'timeout');
    assert.equal(signal.aborted, true);
    assert.equal(cancelled, true);
  });
  it('bounds a fetch that ignores cancellation', async () => {
    const f = fixture();
    const result = await run(f, { fetchTimeoutMs: 25, fetchFn: () => new Promise(() => {}) });
    assert.equal(result.error, 'kms_signing_unavailable');
    assert.equal(result.detail, 'timeout');
  });
  it('cancels a late response even when fetch ignores the aborted signal', { timeout: 1000 }, async () => {
    const f = fixture();
    let signal;
    let cancelCount = 0;
    let resolveCancelled;
    const cancelled = new Promise((resolve) => { resolveCancelled = resolve; });
    const result = await run(f, { fetchTimeoutMs: 10, fetchFn: (_, init) => {
      signal = init.signal;
      return new Promise((resolve) => setTimeout(() => resolve(new Response(new ReadableStream({
        cancel() { cancelCount++; resolveCancelled(); },
      }), { headers: { 'content-type': 'application/json' } })), 35));
    } });
    assert.equal(result.detail, 'timeout');
    assert.equal(signal.aborted, true);
    await cancelled;
    assert.equal(cancelCount, 1);
  });
  it('uses native bounded HTTP against an explicitly local fixture only', async () => {
    const f = fixture({ NODE_ENV: 'test', ASTRANULL_DEPLOYMENT_PROFILE: 'local-staging', ASTRANULL_KMS_SIGNING_ALLOWED_ORIGINS: '' });
    let calls = 0;
    const server = createServer((req, res) => {
      calls++;
      assert.equal(req.headers.authorization, 'Bearer fixture-auth');
      assert.equal(req.url, '/v1/sign');
      req.resume();
      req.on('end', () => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(f.receipt)); });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const result = await run(f, { endpoint: `http://127.0.0.1:${server.address().port}` });
      assert.equal(result.error, undefined);
      assert.equal(calls, 1);
    } finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
  });
});
