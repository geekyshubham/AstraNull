import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import { constants } from 'node:crypto';
import { after, describe, it } from 'node:test';
import { probeTlsSession } from '../../src/lib/safeNetworkProbes.mjs';
import { createTlsFixture } from './protocol-transport-socket.fixture.mjs';

const cert = createTlsFixture({ includeLoopbackIp: true });

async function listen(options, onSecure = () => {}) {
  const server = tls.createServer({ key: cert.key, cert: cert.cert, ...options }, onSecure);
  server.on('tlsClientError', () => {});
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: 0 }, resolve);
  });
  assert.equal(server.address().family, 'IPv4');
  return server;
}

function job(checkId, port) {
  return { check_id: checkId, target: { type: 'ip', value: '127.0.0.1', port }, probe_profile: { kind: 'tls_session', max_requests: 1 }, constraints: { timeout_ms: 3000 } };
}

const deps = { destinationPolicy: { allowLoopback: true } };

describe('client renegotiation probe (owned loopback TLS servers)', () => {
  const servers = [];
  after(async () => {
    await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  });

  it('records an accepted renegotiation on a TLS 1.2 server that allows it', async () => {
    const server = await listen({ maxVersion: 'TLSv1.2' });
    servers.push(server);
    const result = await probeTlsSession(job('tls.renegotiation.readiness', server.address().port), deps);
    assert.equal(result.external_result, 'connected');
    assert.equal(result.requests_sent, 1);
    assert.equal(result.metadata.tls_protocol, 'TLSv1.2');
    assert.equal(result.metadata.client_renegotiation_attempted, true);
    assert.equal(result.metadata.client_renegotiation_accepted, true);
  });

  it('records a refused renegotiation without turning it into a probe error', async () => {
    const server = await listen({ maxVersion: 'TLSv1.2', secureOptions: constants.SSL_OP_NO_RENEGOTIATION });
    servers.push(server);
    const result = await probeTlsSession(job('tls.renegotiation.readiness', server.address().port), deps);
    assert.equal(result.external_result, 'connected');
    assert.equal(result.metadata.client_renegotiation_attempted, true);
    assert.equal(result.metadata.client_renegotiation_accepted, false);
  });

  it('does not attempt renegotiation on TLS 1.3', async () => {
    const server = await listen({ minVersion: 'TLSv1.3' });
    servers.push(server);
    const result = await probeTlsSession(job('tls.renegotiation.readiness', server.address().port), deps);
    assert.equal(result.metadata.tls_protocol, 'TLSv1.3');
    assert.equal(result.metadata.client_renegotiation_attempted, false);
    assert.equal(result.metadata.client_renegotiation_accepted, false);
  });

  it('never attempts renegotiation for any other check id', async () => {
    const server = await listen({ maxVersion: 'TLSv1.2' });
    servers.push(server);
    const result = await probeTlsSession(job('tls.some_other.readiness', server.address().port), deps);
    assert.equal(result.metadata.tls_protocol, 'TLSv1.2');
    assert.equal('client_renegotiation_attempted' in result.metadata, false);
  });
});
