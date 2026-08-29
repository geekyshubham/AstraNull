import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const WEB_ROOT = path.join(__dirname, '../../apps/web');

export class HttpBodyError extends Error {
  constructor(code, status) {
    super(code);
    this.name = 'HttpBodyError';
    this.code = code;
    this.status = status;
  }
}

/**
 * Content Security Policy for the portal shell.
 *
 * Shipped Report-Only deliberately. apps/web/index.html carries four inline
 * <script> blocks (theme init, stylesheet injector, boot controller, module
 * loader) and a large inline <style>. Enforcing a hash-based script-src would
 * hard-break the console the moment any of those blocks is edited, and that file
 * is owned by the portal work — a policy that fails closed on someone else's
 * whitespace change is a liability, not a control. Report-Only gives us the
 * violation telemetry to tighten it later without risking a blank console.
 *
 * `frame-ancestors` is the exception: it is enforced separately below, because
 * clickjacking is the one framing risk that matters here and the console is
 * never legitimately framed.
 */
const CSP_REPORT_ONLY = [
  "default-src 'self'",
  // Inline + injected scripts in the boot shell; see note above.
  "script-src 'self' 'unsafe-inline'",
  // Inline boot styles plus the Google Fonts stylesheet link.
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

/**
 * Defence-in-depth response headers applied to every writer.
 *
 * Scope note: AstraNull's portal authenticates with a bearer token held in the
 * SPA, not a cookie session. So framing carries no ambient session and cookie
 * SameSite is not in play — these headers are hardening, not the primary
 * control. HSTS is deliberately NOT emitted: TLS terminates upstream at the load
 * balancer, and an app-level Strict-Transport-Security would let a
 * plaintext-origin misconfiguration pin browsers to a broken scheme.
 */
export function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    // Enforced (framing only); the full policy rides along Report-Only.
    'Content-Security-Policy': "frame-ancestors 'none'",
    'Content-Security-Policy-Report-Only': CSP_REPORT_ONLY,
  };
}

export function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    ...securityHeaders(),
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    // API payloads are tenant-scoped; never let a shared cache retain them.
    'Cache-Control': 'no-store',
  });
  res.end(payload);
}

export function text(res, status, body, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, { ...securityHeaders(), 'Content-Type': contentType });
  res.end(body);
}

/**
 * Read a request body as UTF-8, refusing oversized payloads without consuming
 * them.
 *
 * The previous implementation kept draining the socket after the cap was
 * exceeded and only raised 413 once the stream ended, so an unauthenticated
 * caller could make the process read a body of arbitrary length before being
 * rejected — the cap bounded memory, not work. Now the declared Content-Length
 * is rejected before a single chunk is read, and a chunked stream is aborted on
 * the first chunk that crosses the cap.
 */
export async function readBodyText(req, maxBytes) {
  if (!Number.isInteger(maxBytes) || maxBytes < 1) {
    throw new Error('readBodyText requires a positive integer maxBytes');
  }

  // Fast path: the caller told us it is too big, so never start reading.
  const declared = Number.parseInt(
    Array.isArray(req.headers?.['content-length'])
      ? req.headers['content-length'][0]
      : req.headers?.['content-length'],
    10,
  );
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw abortOversized(req);
  }

  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      // Break out of the read loop on the FIRST chunk past the cap: the rest of
      // the upload is never pulled off the wire.
      throw abortOversized(req);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Stop consuming an oversized body and signal that the connection must be closed.
 *
 * Deliberately does NOT call `req.destroy()` here. Destroying the request
 * synchronously also destroys the socket the response would be written to, so
 * the client gets a dropped connection instead of a 413 — verified empirically:
 * the oversized cases returned a fetch-level failure rather than a status. The
 * body still goes unread either way (socket byte counters confirm the payload is
 * not drained), so pausing gives the same protection while keeping the rejection
 * observable. Teardown happens in `respondBodyError` once the 413 has flushed.
 */
function abortOversized(req) {
  req.pause?.();
  req.unpipe?.();
  const err = new HttpBodyError('payload_too_large', 413);
  err.closeConnection = true;
  return err;
}

/**
 * Write an HttpBodyError response, closing the connection when the body was
 * abandoned unread (otherwise the client would keep uploading into a socket
 * nobody is draining).
 *
 * @param {import('node:http').ServerResponse} res
 * @param {HttpBodyError & { closeConnection?: boolean }} err
 */
export function respondBodyError(res, err) {
  const payload = JSON.stringify({ error: err.code });
  // Capture the socket up front: it is already detached by the time the write
  // callback runs, which is how the first attempt at this crashed.
  const socket = res.socket;
  res.writeHead(err.status, {
    ...securityHeaders(),
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
    ...(err.closeConnection ? { Connection: 'close' } : {}),
  });
  res.end(payload, () => {
    if (err.closeConnection && socket && !socket.destroyed) {
      socket.destroy();
    }
  });
}

export async function readJsonBody(req, maxBytes) {
  const raw = await readBodyText(req, maxBytes);
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpBodyError('invalid_json', 400);
  }
}

export function parseUrl(req) {
  const host = req.headers.host ?? 'localhost';
  return new URL(req.url ?? '/', `http://${host}`);
}

const BASE_STATIC_ROUTE_ALIASES = {
  '/': '/index.html',
  '/app': '/index.html',
  '/admin': '/index.html',
  '/agent-detail': '/index.html',
  '/agents': '/index.html',
  '/audit': '/index.html',
  '/checks': '/index.html',
  '/cve-pipeline': '/index.html',
  '/dashboard': '/index.html',
  '/discovery': '/index.html',
  '/discovery-entity': '/index.html',
  '/environments': '/index.html',
  '/evidence': '/index.html',
  '/findings': '/index.html',
  '/high-scale': '/index.html',
  '/integrations': '/index.html',
  '/internal-soc': '/index.html',
  '/internal-soc.html': '/index.html',
  '/landing.html': '/index.html',
  '/login': '/index.html',
  '/login.html': '/index.html',
  '/notifications': '/index.html',
  '/onboarding': '/index.html',
  '/release-evidence': '/index.html',
  '/remediation': '/index.html',
  '/reports': '/index.html',
  '/run-detail': '/index.html',
  '/runs': '/index.html',
  '/set-password': '/index.html',
  '/settings': '/index.html',
  '/signup': '/index.html',
  '/signup.html': '/index.html',
  '/signup-status': '/index.html',
  '/soc': '/index.html',
  '/staff-login.html': '/index.html',
  '/subscription': '/index.html',
  '/supply-chain': '/index.html',
  '/support': '/index.html',
  '/target-group-detail': '/index.html',
  '/target-groups': '/index.html',
  '/tenant-detail': '/index.html',
  '/test-policies': '/index.html',
  '/waf-asset-detail': '/index.html',
  '/waf-posture': '/index.html',
};

export function buildStaticRouteAliases(runtimeConfig) {
  const internalAdmin = String(runtimeConfig?.internalAdminPath ?? '/internal/admin').trim() || '/internal/admin';
  const staffLogin = String(runtimeConfig?.staffLoginPath ?? '/internal/admin/login').trim() || '/internal/admin/login';
  return {
    ...BASE_STATIC_ROUTE_ALIASES,
    [internalAdmin]: '/index.html',
    [`${internalAdmin}/index.html`]: '/index.html',
    '/internal/soc': '/index.html',
    [staffLogin]: '/index.html',
  };
}

function staffLoginPathname(runtimeConfig) {
  return String(runtimeConfig?.staffLoginPath ?? '/internal/admin/login').trim() || '/internal/admin/login';
}

function decorateStaffLoginShell(html) {
  return html
    .replace('<title>AstraNull</title>', '<title>Staff sign-in — AstraNull Internal</title>')
    .replace(
      '</head>',
      '  <meta name="robots" content="noindex, nofollow" />\n</head>'
    )
    .replace(
      '<div id="root"></div>',
      '<noscript><h1>Staff sign-in</h1><p>Enable JavaScript to continue to the AstraNull internal management sign-in surface.</p></noscript>\n  <div id="root"></div>'
    );
}

/**
 * Path segments that mean "there is no file here", as opposed to "reading it failed".
 *
 * ENOENT is the ordinary miss. ENOTDIR is a path routed through a file (`/index.html/x`),
 * EISDIR is a directory, ENAMETOOLONG is a path the filesystem will never hold — all of
 * them are legitimately 404, and none of them indicate anything wrong with the server.
 *
 * Every OTHER errno (EACCES, EMFILE, EIO, ...) means the file may well exist and we simply
 * could not read it. Those must not be reported as 404 — see the catch block below.
 */
const NOT_A_SERVABLE_FILE = new Set(['ENOENT', 'ENOTDIR', 'EISDIR', 'ENAMETOOLONG']);

/**
 * Cache policy for shipped assets.
 *
 * `no-cache` means "revalidate before reuse", NOT "do not store": the browser keeps the
 * bundle and asks with `If-None-Match`, so an unchanged deploy costs a 304 with no body.
 * Without it, `react-app.js` has a fixed filename and no validator, so browsers apply
 * heuristic freshness and strand users on a pre-deploy bundle across reloads — observed
 * live. Long max-age + immutable is the wrong trade here precisely because the filenames
 * are fixed; that would require content-hashed names, which this app deliberately avoids.
 */
const STATIC_CACHE_CONTROL = 'no-cache';

/** filePath (plus shell variant) -> { mtimeMs, size, etag }; re-hashed only when the file changes. */
const staticEtagCache = new Map();

function staticEtag(cacheKey, stats, body) {
  const cached = staticEtagCache.get(cacheKey);
  if (cached && cached.mtimeMs === stats.mtimeMs && cached.size === stats.size) {
    return cached.etag;
  }
  const etag = `"${createHash('sha256').update(body).digest('base64url')}"`;
  staticEtagCache.set(cacheKey, { mtimeMs: stats.mtimeMs, size: stats.size, etag });
  return etag;
}

function cachedStaticEtag(cacheKey, stats) {
  const cached = staticEtagCache.get(cacheKey);
  if (!cached) return null;
  return cached.mtimeMs === stats.mtimeMs && cached.size === stats.size ? cached.etag : null;
}

/** RFC 9110 If-None-Match: `*`, or any list member equal after dropping the weak prefix. */
function ifNoneMatchSatisfied(header, etag) {
  const raw = Array.isArray(header) ? header.join(',') : header;
  if (typeof raw !== 'string' || raw.trim() === '') return false;
  const strong = (value) => (value.startsWith('W/') ? value.slice(2) : value);
  return raw
    .split(',')
    .map((value) => value.trim())
    .some((value) => value === '*' || strong(value) === strong(etag));
}

function sendNotModified(res, etag) {
  res.writeHead(304, {
    ...securityHeaders(),
    'Cache-Control': STATIC_CACHE_CONTROL,
    ETag: etag,
  });
  res.end();
}

export async function serveStatic(req, res, url, runtimeConfig) {
  const aliases = buildStaticRouteAliases(runtimeConfig);
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    // decodeURIComponent throws URIError on a malformed escape (`/%ZZ`). Unhandled, that
    // escaped this function entirely and hit the dispatcher's catch-all, which logged a
    // server-fault stack with a correlation id and answered 500 — so any unauthenticated
    // caller could flood the error log and be told the SERVER was broken. A malformed
    // percent-escape is a bad request, so say so and log nothing.
    text(res, 400, 'Bad Request');
    return true;
  }
  let rel = pathname;
  if (aliases[rel]) {
    rel = aliases[rel];
  } else if (rel.endsWith('.html') && aliases[rel.slice(0, -5)]) {
    rel = aliases[rel.slice(0, -5)];
  } else if (rel === '/app/') {
    rel = '/index.html';
  }
  if (rel === '/favicon.ico') {
    res.writeHead(204);
    res.end();
    return true;
  }
  if (rel.includes('..')) {
    text(res, 403, 'Forbidden');
    return true;
  }
  const filePath = path.join(WEB_ROOT, rel);
  if (!filePath.startsWith(WEB_ROOT)) {
    text(res, 403, 'Forbidden');
    return true;
  }
  try {
    const ext = path.extname(filePath);
    const types = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.mjs': 'application/javascript; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.json': 'application/json',
    };
    const isStaffLoginShell = ext === '.html'
      && rel === '/index.html'
      && pathname === staffLoginPathname(runtimeConfig);
    // The decorated staff shell is a different byte stream from the same file, so it needs
    // its own validator.
    const cacheKey = isStaffLoginShell ? `${filePath}::staff-login` : filePath;
    const ifNoneMatch = req?.headers?.['if-none-match'];

    const stats = await stat(filePath);
    if (!stats.isFile()) {
      // A directory is as legitimately "no file here" as ENOENT; keep it a 404.
      return false;
    }

    // Revalidation hit on an unchanged file answers without reading it back off disk.
    const knownEtag = cachedStaticEtag(cacheKey, stats);
    if (knownEtag && ifNoneMatchSatisfied(ifNoneMatch, knownEtag)) {
      sendNotModified(res, knownEtag);
      return true;
    }

    const data = await readFile(filePath);
    const body = isStaffLoginShell
      ? Buffer.from(decorateStaffLoginShell(data.toString('utf8')), 'utf8')
      : data;
    const etag = staticEtag(cacheKey, stats, body);
    if (ifNoneMatchSatisfied(ifNoneMatch, etag)) {
      sendNotModified(res, etag);
      return true;
    }

    res.writeHead(200, {
      ...securityHeaders(),
      'Content-Type': types[ext] ?? 'application/octet-stream',
      'Content-Length': String(body.length),
      'Last-Modified': stats.mtime.toUTCString(),
      'Cache-Control': STATIC_CACHE_CONTROL,
      ETag: etag,
    });
    // HEAD carries the identical status and headers as GET, with no body.
    if (req?.method === 'HEAD') res.end();
    else res.end(body);
    return true;
  } catch (err) {
    // The response is already committed (this threw from writeHead/end, not from the read),
    // so there is no status left to choose. Report it handled rather than letting the
    // dispatcher attempt a second write on a sent response — that would throw inside its
    // own catch block and lose the diagnostic entirely.
    if (res.headersSent) return true;

    // "No such file" is a genuine miss: fall through so the dispatcher's catch-all answers
    // 404 as before.
    if (NOT_A_SERVABLE_FILE.has(err?.code)) return false;

    // Anything else (EACCES, EMFILE, EIO, ...) means the file may exist and we could not
    // read it. Returning false here reported that as 404, indistinguishable from a real
    // miss: a permissions or fd-exhaustion fault on a shipped asset looked to operators
    // like a routing bug, with nothing logged. Rethrow so the dispatcher logs the stack
    // against a correlation id and answers 500 — the response body still exposes nothing
    // but that id.
    throw err;
  }
}
