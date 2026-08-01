import assert from 'node:assert/strict';
import http from 'node:http';
import { Readable } from 'node:stream';
import { describe, it } from 'node:test';
import {
  HttpBodyError,
  json,
  readBodyText,
  readJsonBody,
  respondBodyError,
  securityHeaders,
} from '../../src/lib/http.mjs';

function mockReq(chunks) {
  return Readable.from(chunks.map((c) => (typeof c === 'string' ? Buffer.from(c) : c)));
}

/**
 * Instrumented request stub: records how many chunks were actually pulled and
 * whether the body was abandoned, so we can assert on WORK DONE rather than only
 * on the status code. The point of the size cap is to stop reading, and a test
 * that only checks for 413 cannot tell the difference between rejecting early and
 * draining the whole upload first.
 */
function instrumentedReq({ chunkCount, chunkSize = 32, contentLength = null }) {
  const state = { chunksRead: 0, paused: false, unpiped: false, destroyed: false };
  const headers = {};
  if (contentLength !== null) headers['content-length'] = String(contentLength);
  return {
    state,
    headers,
    pause() { state.paused = true; },
    unpipe() { state.unpiped = true; },
    destroy() { state.destroyed = true; },
    async *[Symbol.asyncIterator]() {
      for (let i = 0; i < chunkCount; i++) {
        state.chunksRead += 1;
        yield Buffer.alloc(chunkSize, 0x78);
      }
    },
  };
}

describe('readJsonBody', () => {
  it('returns {} for empty body', async () => {
    const body = await readJsonBody(mockReq([]), 1024);
    assert.deepEqual(body, {});
  });

  it('returns {} for whitespace-only body', async () => {
    const body = await readJsonBody(mockReq(['   \n']), 1024);
    assert.deepEqual(body, {});
  });

  it('parses valid JSON', async () => {
    const body = await readJsonBody(mockReq(['{"a":1}']), 1024);
    assert.deepEqual(body, { a: 1 });
  });

  it('throws invalid_json for malformed JSON', async () => {
    await assert.rejects(
      () => readJsonBody(mockReq(['{not-json']), 1024),
      (err) => {
        assert.ok(err instanceof HttpBodyError);
        assert.equal(err.code, 'invalid_json');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  it('throws payload_too_large when body exceeds maxBytes', async () => {
    const big = 'x'.repeat(200);
    await assert.rejects(
      () => readJsonBody(mockReq([big]), 64),
      (err) => {
        assert.ok(err instanceof HttpBodyError);
        assert.equal(err.code, 'payload_too_large');
        assert.equal(err.status, 413);
        return true;
      },
    );
  });
});

describe('readBodyText oversized-body abort', () => {
  it('rejects an oversized Content-Length without reading a single chunk', async () => {
    const req = instrumentedReq({ chunkCount: 500, chunkSize: 1024, contentLength: 512_000 });
    await assert.rejects(
      () => readBodyText(req, 64),
      (err) => {
        assert.ok(err instanceof HttpBodyError);
        assert.equal(err.code, 'payload_too_large');
        assert.equal(err.status, 413);
        return true;
      },
    );
    // The whole point: zero body bytes consumed.
    assert.equal(req.state.chunksRead, 0);
    assert.equal(req.state.paused, true);
  });

  it('stops reading a chunked oversized stream on the first chunk past the cap', async () => {
    // 200 chunks of 32B = 6400B offered, cap is 64B. Without the early exit the
    // old implementation drained all 200 chunks before raising 413.
    const req = instrumentedReq({ chunkCount: 200, chunkSize: 32 });
    await assert.rejects(
      () => readBodyText(req, 64),
      (err) => err instanceof HttpBodyError && err.code === 'payload_too_large',
    );
    // Cap of 64 with 32-byte chunks: exceeded on the 3rd chunk, so the loop must
    // exit there rather than consuming all 200.
    assert.equal(req.state.chunksRead, 3);
    assert.ok(req.state.chunksRead < 200, 'must not drain the full stream');
    assert.equal(req.state.paused, true);
  });

  it('marks the error so the caller closes the connection', async () => {
    const req = instrumentedReq({ chunkCount: 50, chunkSize: 32 });
    const err = await readBodyText(req, 64).catch((e) => e);
    assert.ok(err instanceof HttpBodyError);
    assert.equal(err.closeConnection, true);
  });

  it('still accepts a body exactly at the cap', async () => {
    const body = await readBodyText(mockReq(['y'.repeat(64)]), 64);
    assert.equal(body.length, 64);
  });

  it('accepts a body whose declared Content-Length is within the cap', async () => {
    const req = instrumentedReq({ chunkCount: 1, chunkSize: 10, contentLength: 10 });
    const body = await readBodyText(req, 64);
    assert.equal(body.length, 10);
    assert.equal(req.state.chunksRead, 1);
  });
});

describe('respondBodyError', () => {
  /** Round-trip through a real server so we observe what a client actually gets. */
  async function requestWithBody(handler, { body, headers = {} }) {
    const server = http.createServer(handler);
    await new Promise((resolve) => server.listen(0, resolve));
    const { port } = server.address();
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`, { method: 'POST', body, headers });
      return { status: res.status, json: await res.json(), headers: res.headers };
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  }

  it('delivers a 413 to the client instead of dropping the connection', async () => {
    // Regression guard: destroying the request synchronously killed the socket
    // the response was being written to, so the client saw a connection failure
    // rather than a 413.
    const res = await requestWithBody(
      async (req, response) => {
        try {
          await readBodyText(req, 64);
          json(response, 200, { ok: true });
        } catch (err) {
          if (err instanceof HttpBodyError) return respondBodyError(response, err);
          json(response, 500, { error: 'internal' });
        }
      },
      { body: 'x'.repeat(200_000) },
    );
    assert.equal(res.status, 413);
    assert.deepEqual(res.json, { error: 'payload_too_large' });
    assert.equal(res.headers.get('connection'), 'close');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  });
});

describe('security headers', () => {
  it('sets nosniff, referrer policy, and framing denial', () => {
    const h = securityHeaders();
    assert.equal(h['X-Content-Type-Options'], 'nosniff');
    assert.equal(h['Referrer-Policy'], 'no-referrer');
    assert.equal(h['X-Frame-Options'], 'DENY');
    assert.match(h['Content-Security-Policy'], /frame-ancestors 'none'/);
  });

  it('does NOT emit HSTS from the app process (TLS terminates upstream)', () => {
    const h = securityHeaders();
    assert.equal(h['Strict-Transport-Security'], undefined);
  });

  it('allows the portal font origins in the report-only policy', () => {
    const csp = securityHeaders()['Content-Security-Policy-Report-Only'];
    // apps/web/index.html links fonts.googleapis.com and preconnects gstatic.
    assert.match(csp, /style-src[^;]*https:\/\/fonts\.googleapis\.com/);
    assert.match(csp, /font-src[^;]*https:\/\/fonts\.gstatic\.com/);
    assert.match(csp, /object-src 'none'/);
  });
});