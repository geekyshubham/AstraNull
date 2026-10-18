import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runWafClassMarkerProbe } from '../../src/lib/vectorProbes/wafClassProbes.mjs';

function createMockWafServer() {
  const recordedRequests = [];
  const sockets = new Set();

  const server = http.createServer((req, res) => {
    recordedRequests.push({
      method: req.method,
      url: req.url,
      headers: { ...req.headers }
    });

    const parsedUrl = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
    let decodedPath = '';
    try {
      decodedPath = decodeURIComponent(parsedUrl.pathname);
    } catch {
      decodedPath = parsedUrl.pathname;
    }

    const queryHasMarker = Array.from(parsedUrl.searchParams.values()).some((val) =>
      val.includes('../../astranull-probe')
    );
    const pathHasMarker = decodedPath.includes('../../astranull-probe');
    const headerMarker = req.headers['x-astranull-marker'];
    const headerHasMarker = headerMarker === '../../astranull-probe';

    if (pathHasMarker || queryHasMarker || headerHasMarker) {
      res.writeHead(403, {
        'content-type': 'text/plain',
        'x-waf-block': '1'
      });
      res.end('waf-blocked');
    } else {
      res.writeHead(200, {
        'content-type': 'text/plain'
      });
      res.end('origin-ok');
    }
  });

  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  async function close() {
    for (const socket of sockets) {
      socket.destroy();
    }
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    await new Promise((resolve) => server.close(resolve));
  }

  return { server, recordedRequests, close };
}

describe('WAF class marker probe - path traversal semantics regression', () => {
  test('nested base path /scope preserves traversal marker without URL normalization', async () => {
    const { server, recordedRequests, close } = createMockWafServer();
    try {
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      const { port } = server.address();

      const probeUrl = `http://127.0.0.1:${port}/scope`;
      const result = await runWafClassMarkerProbe({
        url: probeUrl,
        marker_class: 'path_traversal',
        fetchFn: (url, opts) => fetch(url, opts)
      });

      assert.ok(result, 'Expected probe execution result');
      assert.equal(result.posture, 'protected', 'Overall posture must be protected');
      assert.ok(
        result.requests_sent <= 8,
        `Expected requests_sent <= 8, got ${result.requests_sent}`
      );
      assert.ok(
        recordedRequests.length <= 8,
        `Expected <= 8 total recorded requests, got ${recordedRequests.length}`
      );

      // Verify no state-changing methods were used
      for (const req of recordedRequests) {
        assert.equal(
          req.method,
          'GET',
          `Expected only non-state-changing GET requests, got ${req.method}`
        );
      }

      // Verify URL normalization never collapsed request to bare /astranull-probe
      for (const req of recordedRequests) {
        const reqPath = req.url.split('?')[0];
        assert.notEqual(
          reqPath,
          '/astranull-probe',
          'Wire request must not be collapsed to bare /astranull-probe'
        );
        assert.ok(
          !reqPath.startsWith('/astranull-probe'),
          `Wire request must not start with bare /astranull-probe: ${req.url}`
        );
      }

      // Assert real wire path leg is /scope/..%2F..%2Fastranull-probe (case-insensitive hex)
      const pathMarkerPattern = /^\/scope\/\.\.(?:%2f|%2F)\.\.(?:%2f|%2F)astranull-probe$/i;
      const pathMarkerReq = recordedRequests.find((r) =>
        pathMarkerPattern.test(r.url.split('?')[0])
      );
      assert.ok(
        pathMarkerReq,
        `Expected real wire path leg /scope/..%2F..%2Fastranull-probe, recorded: ${recordedRequests.map((r) => r.url).join(', ')}`
      );

      // Assert decoded marker preserved with base prefix
      const wirePath = pathMarkerReq.url.split('?')[0];
      assert.equal(
        decodeURIComponent(wirePath),
        '/scope/../../astranull-probe',
        'Decoded marker must preserve /scope prefix along with traversal segments'
      );

      // Assert path marker row outcome blocked
      const pathRow = Array.isArray(result.marker_results)
        ? result.marker_results.find((r) =>
            r?.channel === 'path' ||
            r?.type === 'path' ||
            r?.placement === 'path' ||
            r?.location === 'path' ||
            r?.marker_type === 'path' ||
            r?.vector === 'path' ||
            r?.injection_point === 'path' ||
            (typeof r?.marker === 'string' && r.marker.includes('astranull-probe')) ||
            (typeof r?.url === 'string' && /%2f/i.test(r.url))
          )
        : (result.marker_results?.path || result.marker_results?.path_traversal);

      assert.ok(pathRow, 'Expected path marker row in marker_results');
      assert.equal(pathRow.outcome, 'blocked', `Expected path marker outcome blocked, got ${pathRow.outcome}`);
    } finally {
      await close();
    }
  });

  test('root base path preserves traversal marker without leading double slashes or bare collapse', async () => {
    const { server, recordedRequests, close } = createMockWafServer();
    try {
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      const { port } = server.address();

      const probeUrl = `http://127.0.0.1:${port}/`;
      const result = await runWafClassMarkerProbe({
        url: probeUrl,
        marker_class: 'path_traversal',
        fetchFn: (url, opts) => fetch(url, opts)
      });

      assert.ok(result, 'Expected probe execution result');
      assert.equal(result.posture, 'protected', 'Overall posture must be protected');
      assert.ok(
        result.requests_sent <= 8,
        `Expected requests_sent <= 8, got ${result.requests_sent}`
      );
      assert.ok(
        recordedRequests.length <= 8,
        `Expected <= 8 total recorded requests, got ${recordedRequests.length}`
      );

      // Verify no state-changing methods
      for (const req of recordedRequests) {
        assert.equal(req.method, 'GET', `Expected only GET requests, got ${req.method}`);
        const reqPath = req.url.split('?')[0];
        assert.notEqual(reqPath, '/astranull-probe', 'Wire request must not be bare /astranull-probe');
        assert.ok(!reqPath.startsWith('/astranull-probe'), 'Wire request must not start with bare /astranull-probe');
      }

      // Assert real wire path leg is /..%2F..%2Fastranull-probe
      const rootPathMarkerPattern = /^\/\.\.(?:%2f|%2F)\.\.(?:%2f|%2F)astranull-probe$/i;
      const pathMarkerReq = recordedRequests.find((r) =>
        rootPathMarkerPattern.test(r.url.split('?')[0])
      );
      assert.ok(
        pathMarkerReq,
        `Expected root wire path leg /..%2F..%2Fastranull-probe, recorded: ${recordedRequests.map((r) => r.url).join(', ')}`
      );

      const wirePath = pathMarkerReq.url.split('?')[0];
      assert.ok(!wirePath.startsWith('//'), 'Root path must not produce double slashes');
      assert.equal(
        decodeURIComponent(wirePath),
        '/../../astranull-probe',
        'Decoded marker must equal /../../astranull-probe'
      );

      const pathRow = Array.isArray(result.marker_results)
        ? result.marker_results.find((r) =>
            r?.channel === 'path' ||
            r?.type === 'path' ||
            r?.placement === 'path' ||
            r?.location === 'path' ||
            r?.marker_type === 'path' ||
            r?.vector === 'path' ||
            r?.injection_point === 'path' ||
            (typeof r?.marker === 'string' && r.marker.includes('astranull-probe')) ||
            (typeof r?.url === 'string' && /%2f/i.test(r.url))
          )
        : (result.marker_results?.path || result.marker_results?.path_traversal);

      assert.ok(pathRow, 'Expected path marker row in marker_results');
      assert.equal(pathRow.outcome, 'blocked');
    } finally {
      await close();
    }
  });
});
