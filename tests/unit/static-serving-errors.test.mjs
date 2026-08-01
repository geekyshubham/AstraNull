/**
 * How `serveStatic` reports failures that are NOT "the file is absent".
 *
 * The dispatcher treats a falsy return from `serveStatic` as "no static route here" and falls
 * through to its catch-all 404. `serveStatic` used to end in a bare `catch { return false; }`,
 * which handed that same falsy value back for *every* failure. Two consequences, both
 * reproduced against a real server before this file existed:
 *
 *  - A file that exists but cannot be read (EACCES, EMFILE, EIO) answered 404, byte-identical
 *    to a genuine miss, and logged nothing. A permissions fault or fd exhaustion on a shipped
 *    asset therefore looked to operators like a routing bug, with no diagnostic at all.
 *  - `decodeURIComponent` on a malformed escape (`/%ZZ`) throws URIError *before* the catch,
 *    so it escaped the function entirely, hit the dispatcher's catch-all, and produced
 *    `500 internal_error` plus a logged stack. Any unauthenticated caller could flood the
 *    error log with server-fault entries using a two-character URL.
 *
 * These tests drive a real server over HTTP rather than calling `serveStatic` directly,
 * because the defect lived in the seam between its return value and the dispatcher — a unit
 * test of the function alone would not have observed either bug.
 */
import assert from 'node:assert/strict';
import { chmodSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { request } from '../helpers/http.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
/** Lives under the real static root, since WEB_ROOT is resolved relative to the source. */
const UNREADABLE_REL = '/__static_error_probe.html';
const unreadablePath = path.join(repoRoot, 'apps/web', UNREADABLE_REL.slice(1));

/** root bypasses the permission bits, so the EACCES case cannot be staged there. */
const canStageUnreadableFile = typeof process.getuid === 'function' && process.getuid() !== 0;

let baseUrl;
let server;

before(async () => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  if (canStageUnreadableFile) {
    writeFileSync(unreadablePath, '<!doctype html><title>probe</title>');
    chmodSync(unreadablePath, 0o000);
  }
  server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  if (canStageUnreadableFile) {
    // Restore the mode first: rm cannot remove a 000 file in every environment.
    try { chmodSync(unreadablePath, 0o644); } catch {}
    rmSync(unreadablePath, { force: true });
  }
  server?.close();
});

describe('static serving distinguishes "absent" from "unreadable"', () => {
  it('still answers 404 for a file that genuinely does not exist', async () => {
    for (const missing of ['/__definitely_absent.html', '/app.js', '/styles.css']) {
      const res = await request(baseUrl, 'GET', missing);
      assert.equal(res.status, 404, `${missing} should be a plain miss`);
    }
  });

  it('answers 404 for path shapes that can never be a file', async () => {
    // EISDIR and ENOTDIR are as legitimately "not a file here" as ENOENT is, so they must
    // not be escalated to 500 by the rethrow.
    assert.equal((await request(baseUrl, 'GET', '/react')).status, 404, 'directory');
    assert.equal((await request(baseUrl, 'GET', '/index.html/nope')).status, 404, 'via file');
  });

  it('serves the real shell and bundle unchanged', async () => {
    // Guards against the error handling swallowing the success path.
    for (const [servable, needle] of [['/', 'id="root"'], ['/app', 'id="root"']]) {
      const res = await request(baseUrl, 'GET', servable);
      assert.equal(res.status, 200, servable);
      assert.ok(res.text.includes(needle), `${servable} should render the SPA shell`);
    }
    assert.equal((await request(baseUrl, 'GET', '/react-app.js')).status, 200);
  });

  it('reports an existing-but-unreadable file as a server fault, not a miss', async (t) => {
    if (!canStageUnreadableFile) {
      t.skip('running as root: permission bits do not apply');
      return;
    }
    const res = await request(baseUrl, 'GET', UNREADABLE_REL);
    assert.equal(
      res.status,
      500,
      'an unreadable file must not be indistinguishable from an absent one',
    );
    const payload = JSON.parse(res.text);
    assert.equal(payload.error, 'internal_error');
    // The correlation id is the only link the caller gets to the logged stack.
    assert.ok(payload.correlation_id, 'response must carry a correlation id');
    // The body must not leak the filesystem path or the errno.
    assert.doesNotMatch(res.text, /EACCES|apps\/web|permission denied/i);
  });
});

describe('static serving rejects malformed request paths', () => {
  it('answers 400 for a malformed percent-escape instead of 500', async () => {
    for (const malformed of ['/%ZZ', '/%', '/%E0%A4%A']) {
      const res = await request(baseUrl, 'GET', malformed);
      assert.equal(
        res.status,
        400,
        `${malformed} is a bad request; 500 would let any caller flood the error log`,
      );
      assert.doesNotMatch(res.text, /internal_error|correlation_id/,
        'a client-side encoding error must not be reported as a server fault');
    }
  });

  it('still serves a legitimately percent-encoded path', async () => {
    // The 400 must key on decode failure, not on the mere presence of an escape.
    const res = await request(baseUrl, 'GET', '/react-app%2Ejs');
    assert.equal(res.status, 200, '%2E decodes to "." and should resolve normally');
  });

  it('keeps traversal attempts forbidden', async () => {
    // `..` is rejected before any read, and an encoded `..` must not slip past by decoding
    // after that check.
    const res = await request(baseUrl, 'GET', '/%2E%2E%2Fpackage.json');
    assert.ok([403, 404].includes(res.status), `expected 403/404, got ${res.status}`);
    assert.doesNotMatch(res.text, /"name":\s*"astranull"/, 'must not serve files above the web root');
  });
});
