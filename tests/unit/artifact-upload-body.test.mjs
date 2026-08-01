import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { describe, it } from 'node:test';
import { readArtifactUploadBody, readBodyBuffer } from '../../src/lib/authorizationArtifactLedger.mjs';
import { HttpBodyError } from '../../src/lib/http.mjs';

/**
 * Instrumented request stub: records how many chunks were actually pulled and whether the
 * body was abandoned, so we assert on WORK DONE rather than only on the status code. The
 * point of the size cap is to stop reading, and a test that only checks for 413 cannot tell
 * the difference between rejecting early and draining the whole upload first — which is
 * exactly how this defect survived in the artifact-upload reader after the shared
 * readBodyText() was fixed.
 */
function instrumentedReq({ chunkCount, chunkSize = 32, contentLength = null, contentType = null }) {
  const state = { chunksRead: 0, paused: false, unpiped: false, destroyed: false };
  const headers = {};
  if (contentLength !== null) headers['content-length'] = String(contentLength);
  if (contentType !== null) headers['content-type'] = contentType;
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

function mockReq(chunks, headers = {}) {
  const stream = Readable.from(chunks.map((c) => (typeof c === 'string' ? Buffer.from(c) : c)));
  stream.headers = headers;
  return stream;
}

// Lowercase boundary token on purpose: readArtifactUploadBody() lowercases the whole
// Content-Type header before extracting the boundary, so an uppercase token in the fixture
// would never match the body bytes. Pre-existing behaviour, unrelated to the size cap.
const MULTIPART_BOUNDARY = 'bnd0040';
const MULTIPART_TYPE = `multipart/form-data; boundary=${MULTIPART_BOUNDARY}`;

function multipartBody(fields) {
  const parts = Object.entries(fields).map(
    ([name, value]) =>
      `--${MULTIPART_BOUNDARY}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`,
  );
  return `${parts.join('')}--${MULTIPART_BOUNDARY}--\r\n`;
}

describe('readBodyBuffer oversized-body abort', () => {
  it('rejects an oversized Content-Length without reading a single chunk', async () => {
    const req = instrumentedReq({ chunkCount: 500, chunkSize: 1024, contentLength: 512_000 });
    await assert.rejects(
      () => readBodyBuffer(req, 64),
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
    assert.equal(req.state.unpiped, true);
  });

  it('stops reading a chunked oversized stream on the first chunk past the cap', async () => {
    // 200 chunks of 32B = 6400B offered, cap is 64B. The pre-fix implementation set a
    // `tooLarge` flag and kept iterating, so it drained all 200 chunks before raising 413.
    const req = instrumentedReq({ chunkCount: 200, chunkSize: 32 });
    await assert.rejects(
      () => readBodyBuffer(req, 64),
      (err) => err instanceof HttpBodyError && err.code === 'payload_too_large',
    );
    // Cap of 64 with 32-byte chunks: exceeded on the 3rd chunk, so the loop must exit there.
    assert.equal(req.state.chunksRead, 3);
    assert.ok(req.state.chunksRead < 200, 'must not drain the full stream');
    assert.equal(req.state.paused, true);
  });

  it('marks the error so the caller closes the connection', async () => {
    const req = instrumentedReq({ chunkCount: 50, chunkSize: 32 });
    const err = await readBodyBuffer(req, 64).catch((e) => e);
    assert.ok(err instanceof HttpBodyError);
    assert.equal(err.closeConnection, true);
  });

  it('does not destroy the request synchronously, so the 413 can still be written', async () => {
    // Mirrors the shared helper: destroying the request also destroys the response socket,
    // turning an observable 413 into a dropped connection. Teardown belongs in
    // respondBodyError() after the status has flushed.
    const req = instrumentedReq({ chunkCount: 50, chunkSize: 32 });
    await readBodyBuffer(req, 64).catch(() => {});
    assert.equal(req.state.destroyed, false);
  });

  it('still accepts a body exactly at the cap', async () => {
    const buffer = await readBodyBuffer(mockReq(['y'.repeat(64)]), 64);
    assert.equal(buffer.length, 64);
  });

  it('accepts a body whose declared Content-Length is within the cap', async () => {
    const req = instrumentedReq({ chunkCount: 1, chunkSize: 10, contentLength: 10 });
    const buffer = await readBodyBuffer(req, 64);
    assert.equal(buffer.length, 10);
    assert.equal(req.state.chunksRead, 1);
  });

  it('rejects a non-positive maxBytes', async () => {
    await assert.rejects(
      () => readBodyBuffer(mockReq(['x']), 0),
      /readBodyBuffer requires a positive integer maxBytes/,
    );
  });

  it('returns raw bytes undecoded, which is why it stays separate from readBodyText', async () => {
    // 0x80-0xff round-trip intact: a utf8 decode would replace these with U+FFFD, which is
    // why the multipart path needs a Buffer reader of its own.
    const raw = Buffer.from([0x80, 0xfe, 0xff, 0x00]);
    const buffer = await readBodyBuffer(mockReq([raw]), 64);
    assert.deepEqual([...buffer], [0x80, 0xfe, 0xff, 0x00]);
  });
});

describe('readArtifactUploadBody size cap', () => {
  it('aborts an oversized multipart upload without draining it', async () => {
    const req = instrumentedReq({
      chunkCount: 200,
      chunkSize: 32,
      contentType: MULTIPART_TYPE,
    });
    await assert.rejects(
      () => readArtifactUploadBody(req, 64),
      (err) => err instanceof HttpBodyError && err.code === 'payload_too_large',
    );
    assert.equal(req.state.chunksRead, 3);
    assert.equal(req.state.paused, true);
  });

  it('rejects an oversized multipart Content-Length before reading', async () => {
    const req = instrumentedReq({
      chunkCount: 500,
      chunkSize: 1024,
      contentLength: 512_000,
      contentType: MULTIPART_TYPE,
    });
    await assert.rejects(
      () => readArtifactUploadBody(req, 64),
      (err) => err instanceof HttpBodyError && err.code === 'payload_too_large',
    );
    assert.equal(req.state.chunksRead, 0);
  });

  it('aborts an oversized JSON upload without draining it', async () => {
    // The JSON branch delegates to the shared readBodyText(), so it inherits the same abort.
    const req = instrumentedReq({ chunkCount: 200, chunkSize: 32, contentType: 'application/json' });
    await assert.rejects(
      () => readArtifactUploadBody(req, 64),
      (err) => err instanceof HttpBodyError && err.code === 'payload_too_large',
    );
    assert.equal(req.state.chunksRead, 3);
  });

  it('still parses a within-cap multipart upload', async () => {
    const body = multipartBody({ request_id: 'req_1', kind: 'loa' });
    const req = mockReq([body], { 'content-type': MULTIPART_TYPE });
    const upload = await readArtifactUploadBody(req, 4096);
    assert.equal(upload.envelope, 'multipart_metadata');
    assert.equal(upload.body.request_id, 'req_1');
    assert.equal(upload.body.kind, 'loa');
  });

  it('still parses a within-cap JSON upload', async () => {
    const req = mockReq([JSON.stringify({ request_id: 'req_2', kind: 'loa' })], {
      'content-type': 'application/json',
    });
    const upload = await readArtifactUploadBody(req, 4096);
    assert.equal(upload.envelope, 'json');
    assert.equal(upload.body.request_id, 'req_2');
  });
});
