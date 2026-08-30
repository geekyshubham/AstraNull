import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import http2 from 'node:http2';
import net from 'node:net';
import { pinnedWebSocketUpgrade } from '../../src/lib/pinnedHttpRequest.mjs';
import { probeGrpcReflection } from '../../src/lib/capabilityProbes.mjs';
import { executeProbeForJob } from '../../workers/probe-worker.mjs';

function createTlsFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'astranull-protocol-tls-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-keyout', keyPath, '-out', certPath, '-days', '1',
    '-subj', '/CN=grpc.test', '-addext', 'subjectAltName=DNS:grpc.test',
  ], { stdio: 'ignore' });
  return {
    dir,
    key: readFileSync(keyPath),
    cert: readFileSync(certPath),
  };
}

function loopbackDeps(host) {
  return {
    vettedHost: host,
    vettedAddresses: ['127.0.0.1'],
    resolve4Fn: async () => { throw new Error('resolver must not run after preflight'); },
    resolve6Fn: async () => { throw new Error('resolver must not run after preflight'); },
    destinationPolicy: { allowLoopback: true },
  };
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function preflightHttp1Fixture() {
  let observedHost = null;
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests += 1;
    observedHost = request.headers.host;
    response.statusCode = 204;
    response.end();
  });
  const port = await listen(server);
  let resolve4Calls = 0;
  let resolve6Calls = 0;

  try {
    const result = await executeProbeForJob({
      id: 'pj_socket_http1',
      tenant_id: 'ten_socket',
      target: { id: 'tgt_socket', kind: 'url', value: `http://preflight.test:${port}/health` },
      vector_family: 'path',
      probe_profile: { kind: 'http_head', max_requests: 1, timeout_ms: 1000 },
      constraints: { timeout_ms: 1000, max_requests: 1 },
    }, {
      resolve4Fn: async (host) => {
        resolve4Calls += 1;
        assert.equal(host, 'preflight.test');
        return resolve4Calls === 1
          ? ['203.0.113.10']
          : ['198.51.100.99', '10.0.0.8'];
      },
      resolve6Fn: async () => { resolve6Calls += 1; return []; },
      httpRequestFn: (options, callback) => {
        assert.equal(options.hostname, '203.0.113.10');
        return http.request({
          ...options,
          createConnection: (socketOptions) => {
            assert.equal(socketOptions.host, '203.0.113.10');
            return net.connect({ host: '127.0.0.1', port });
          },
        }, callback);
      },
    });

    assert.equal(result.external_result, 'connected');
    assert.equal(result.requests_sent, 1);
    assert.equal(requests, 1);
    assert.equal(observedHost, `preflight.test:${port}`);
    assert.equal(resolve4Calls, 1);
    assert.equal(resolve6Calls, 1);
  } finally {
    await close(server);
  }
}

async function websocketFixture() {
  const upgradeServer = http.createServer();
  let requestHeaders;
  let upgradedSocket;
  upgradeServer.on('upgrade', (request, socket) => {
    requestHeaders = request.headers;
    upgradedSocket = socket;
    socket.write([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      '',
      '',
    ].join('\r\n'));
    socket.resume();
  });
  const port = await listen(upgradeServer);

  try {
    const started = Date.now();
    const response = await pinnedWebSocketUpgrade(`http://ws.test:${port}/socket`, {
      headers: {
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': Buffer.from('0123456789abcdef').toString('base64'),
        'x-astranull-marker': 'socket-fixture-marker',
      },
      timeoutMs: 500,
    }, loopbackDeps('ws.test'));
    assert.equal(response.status, 101);
    assert.equal(response.pinnedAddress, '127.0.0.1');
    assert.equal(response.headers.get('upgrade'), 'websocket');
    assert.equal(requestHeaders.host, `ws.test:${port}`);
    assert.equal(requestHeaders['x-astranull-marker'], 'socket-fixture-marker');
    assert.ok(Date.now() - started < 500, '101 must settle before the transport timeout');
  } finally {
    upgradedSocket?.destroy();
    await close(upgradeServer);
  }

  const captureServer = http.createServer();
  let redirectedRequests = 0;
  captureServer.on('request', (_request, response) => {
    redirectedRequests += 1;
    response.end();
  });
  captureServer.on('upgrade', (_request, socket) => {
    redirectedRequests += 1;
    socket.destroy();
  });
  const capturePort = await listen(captureServer);
  const redirectServer = http.createServer();
  let firstHopMarker = null;
  redirectServer.on('upgrade', (request, socket) => {
    firstHopMarker = request.headers['x-astranull-marker'];
    socket.end([
      'HTTP/1.1 302 Found',
      `Location: http://127.0.0.1:${capturePort}/should-not-run`,
      'Content-Length: 0',
      '',
      '',
    ].join('\r\n'));
  });
  const redirectPort = await listen(redirectServer);

  try {
    const response = await pinnedWebSocketUpgrade(`http://redirect.test:${redirectPort}/socket`, {
      headers: {
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'x-astranull-marker': 'redirect-secret-marker',
      },
      timeoutMs: 500,
    }, loopbackDeps('redirect.test'));
    assert.equal(response.status, 302);
    assert.equal(firstHopMarker, 'redirect-secret-marker');
    await delay(50);
    assert.equal(redirectedRequests, 0, 'upgrade headers must not cross a redirect');
  } finally {
    await Promise.all([close(redirectServer), close(captureServer)]);
  }
}

async function grpcFixture() {
  const tlsFixture = createTlsFixture();
  const server = http2.createSecureServer({ key: tlsFixture.key, cert: tlsFixture.cert, allowHTTP1: false });
  const sessions = new Set();
  let observedServername = null;
  let observedHeaders = null;
  let observedBody = null;

  server.on('session', (session) => {
    sessions.add(session);
    session.once('close', () => sessions.delete(session));
  });
  server.on('secureConnection', (socket) => {
    observedServername = socket.servername;
  });
  server.on('stream', (stream, headers) => {
    const chunks = [];
    observedHeaders = headers;
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('end', () => {
      observedBody = Buffer.concat(chunks);
      stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true });
      stream.once('wantTrailers', () => {
        stream.sendTrailers({ 'grpc-status': '0', 'grpc-message': 'fixture-ok' });
      });
      stream.end(Buffer.from([0, 0, 0, 0, 0]));
    });
  });

  const port = await listen(server);
  try {
    const result = await probeGrpcReflection({
      job_id: 'pj_socket_grpc',
      tenant_id: 'ten_socket',
      target: { id: 'tgt_socket', kind: 'url', value: `https://grpc.test:${port}` },
      probe_profile: { kind: 'grpc_reflection_probe', max_requests: 1, timeout_ms: 1000 },
      constraints: { timeout_ms: 1000, max_requests: 1 },
    }, {
      ...loopbackDeps('grpc.test'),
      tlsCa: tlsFixture.cert,
    });

    assert.equal(result.external_result, 'connected');
    assert.equal(result.metadata.grpc_transport, 'h2_tls');
    assert.equal(result.metadata.grpc_status, '0');
    assert.equal(result.metadata.grpc_status_source, 'trailers');
    assert.equal(result.metadata.grpc_message_present, true);
    assert.equal(result.metadata.pinned_address, '127.0.0.1');
    assert.equal(result.metadata.reflection_service_routed, true);
    assert.equal(result.metadata.reflection_service_exposed, true);
    assert.equal(observedServername, 'grpc.test');
    assert.equal(observedHeaders[':authority'], `grpc.test:${port}`);
    assert.equal(
      observedHeaders[':path'],
      '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
    );
    assert.deepEqual(observedBody, Buffer.from([0, 0, 0, 0, 2, 0x3a, 0]));
  } finally {
    for (const session of sessions) session.destroy();
    rmSync(tlsFixture.dir, { recursive: true, force: true });
    await close(server);
  }
}

const mode = process.argv[2];
try {
  if (mode === 'preflight-http1') await preflightHttp1Fixture();
  else if (mode === 'websocket') await websocketFixture();
  else if (mode === 'grpc') await grpcFixture();
  else throw new Error(`unknown protocol fixture mode: ${mode}`);
  process.stdout.write(`${mode}:ok\n`);
} catch (error) {
  console.error(error?.stack ?? error);
  process.exitCode = 1;
}
