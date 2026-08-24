/**
 * Cache validators and HEAD support on the static path.
 *
 * `serveStatic` used to emit only security headers and a Content-Type. With fixed asset
 * filenames (`react-app.js` is never content-hashed) and no validator at all, browsers
 * apply heuristic freshness and keep serving a pre-deploy bundle across reloads — observed
 * live in a real browser session. The fix is revalidation, not long-lived caching: a strong
 * ETag plus `Cache-Control: no-cache` on every static response, and `If-None-Match` honoured
 * with a bodiless 304.
 *
 * HEAD was a separate defect in the same seam: the dispatcher guarded the static branch on
 * `GET` alone, so `curl -I /react-app.js` answered `404 text/plain`.
 *
 * Driven over real HTTP because both defects live between `serveStatic` and the dispatcher.
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { closeServer } from '../helpers/http.mjs';

const SECURITY_HEADERS = [
  'x-content-type-options',
  'referrer-policy',
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
];

/** Assets covering every Content-Type branch the portal actually ships. */
const ASSETS = [
  ['/react-app.js', 'application/javascript; charset=utf-8'],
  ['/react-app.css', 'text/css; charset=utf-8'],
  ['/', 'text/html; charset=utf-8'],
];

let baseUrl;
let server;

/** fetch that always drains the body, so keep-alive sockets do not outlive the assertion. */
async function get(path, headers = {}) {
  const res = await fetch(`${baseUrl}${path}`, { headers });
  const body = Buffer.from(await res.arrayBuffer());
  return { status: res.status, headers: res.headers, body };
}

async function head(path, headers = {}) {
  const res = await fetch(`${baseUrl}${path}`, { method: 'HEAD', headers });
  const body = Buffer.from(await res.arrayBuffer());
  return { status: res.status, headers: res.headers, body };
}

before(async () => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await closeServer(server);
});

describe('static assets carry revalidation validators', () => {
  it('sends a strong ETag and Cache-Control: no-cache on every asset type', async () => {
    for (const [path, contentType] of ASSETS) {
      const res = await get(path);
      assert.equal(res.status, 200, path);
      assert.equal(res.headers.get('content-type'), contentType, path);
      assert.equal(res.headers.get('cache-control'), 'no-cache', `${path} must revalidate`);
      const etag = res.headers.get('etag');
      assert.ok(etag, `${path} must carry an ETag`);
      assert.match(etag, /^"[A-Za-z0-9_-]+"$/, `${path} ETag must be strong and quoted`);
      assert.ok(res.headers.get('last-modified'), `${path} must carry Last-Modified`);
    }
  });

  it('never uses long-lived or immutable caching, which fixed filenames cannot support', async () => {
    for (const [path] of ASSETS) {
      const cacheControl = (await get(path)).headers.get('cache-control');
      assert.doesNotMatch(cacheControl, /immutable/, path);
      assert.doesNotMatch(cacheControl, /max-age=[1-9]/, `${path} must not be heuristically fresh`);
    }
  });

  it('derives the ETag from content, so two assets never share a validator', async () => {
    const js = (await get('/react-app.js')).headers.get('etag');
    const css = (await get('/react-app.css')).headers.get('etag');
    assert.notEqual(js, css);
  });

  it('is stable across repeated requests for an unchanged file', async () => {
    const first = await get('/react-app.js');
    const second = await get('/react-app.js');
    assert.equal(first.headers.get('etag'), second.headers.get('etag'));
    assert.deepEqual(first.body, second.body);
  });
});

describe('If-None-Match revalidation', () => {
  it('answers 304 with an empty body, the same ETag and the security headers', async () => {
    for (const [path] of ASSETS) {
      const fresh = await get(path);
      const etag = fresh.headers.get('etag');
      const revalidated = await get(path, { 'If-None-Match': etag });
      assert.equal(revalidated.status, 304, path);
      assert.equal(revalidated.body.length, 0, `${path} 304 must not carry a body`);
      assert.equal(revalidated.headers.get('etag'), etag, path);
      assert.equal(revalidated.headers.get('cache-control'), 'no-cache', path);
      for (const header of SECURITY_HEADERS) {
        assert.ok(revalidated.headers.get(header), `${path} 304 must keep ${header}`);
      }
    }
  });

  it('accepts the weak-prefixed and wildcard forms of the validator', async () => {
    const etag = (await get('/react-app.js')).headers.get('etag');
    assert.equal((await get('/react-app.js', { 'If-None-Match': `W/${etag}` })).status, 304);
    assert.equal((await get('/react-app.js', { 'If-None-Match': '*' })).status, 304);
    assert.equal(
      (await get('/react-app.js', { 'If-None-Match': `"other", ${etag}` })).status,
      304,
      'a list containing the current validator matches',
    );
  });

  it('serves the full body when the presented validator is stale or absent', async () => {
    const stale = await get('/react-app.js', { 'If-None-Match': '"not-the-current-bundle"' });
    assert.equal(stale.status, 200, 'a stale validator must deliver the new bundle');
    assert.ok(stale.body.length > 0);
    const empty = await get('/react-app.js', { 'If-None-Match': '' });
    assert.equal(empty.status, 200, 'an empty header must not be treated as a match');
  });
});

describe('HEAD on the static path', () => {
  it('mirrors GET status, Content-Type, Content-Length and ETag with no body', async () => {
    for (const [path, contentType] of ASSETS) {
      const getRes = await get(path);
      const headRes = await head(path);
      assert.equal(headRes.status, getRes.status, path);
      assert.equal(headRes.status, 200, `${path} HEAD must not be a 404`);
      assert.equal(headRes.headers.get('content-type'), contentType, path);
      assert.equal(headRes.headers.get('etag'), getRes.headers.get('etag'), path);
      assert.equal(headRes.headers.get('cache-control'), 'no-cache', path);
      assert.equal(
        headRes.headers.get('content-length'),
        String(getRes.body.length),
        `${path} HEAD must report the entity length`,
      );
      assert.equal(headRes.body.length, 0, `${path} HEAD must not carry a body`);
      for (const header of SECURITY_HEADERS) {
        assert.ok(headRes.headers.get(header), `${path} HEAD must keep ${header}`);
      }
    }
  });

  it('still 404s for a genuine miss and stays 403 on traversal', async () => {
    assert.equal((await head('/__definitely_absent.js')).status, 404);
    const traversal = await head('/%2E%2E%2Fpackage.json');
    assert.ok([403, 404].includes(traversal.status), `got ${traversal.status}`);
  });

  it('honours If-None-Match, so a HEAD probe can revalidate too', async () => {
    const etag = (await head('/react-app.js')).headers.get('etag');
    const res = await head('/react-app.js', { 'If-None-Match': etag });
    assert.equal(res.status, 304);
    assert.equal(res.body.length, 0);
  });
});
