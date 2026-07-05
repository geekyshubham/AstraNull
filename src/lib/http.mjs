import { readFile } from 'node:fs/promises';
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

export function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

export function text(res, status, body, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': contentType });
  res.end(body);
}

export async function readBodyText(req, maxBytes) {
  if (!Number.isInteger(maxBytes) || maxBytes < 1) {
    throw new Error('readBodyText requires a positive integer maxBytes');
  }
  const chunks = [];
  let total = 0;
  let tooLarge = false;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) tooLarge = true;
    else chunks.push(chunk);
  }
  if (tooLarge) {
    throw new HttpBodyError('payload_too_large', 413);
  }
  return Buffer.concat(chunks).toString('utf8');
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

export async function serveStatic(req, res, url, runtimeConfig) {
  const aliases = buildStaticRouteAliases(runtimeConfig);
  const pathname = decodeURIComponent(url.pathname);
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
    const data = await readFile(filePath);
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
    const body = isStaffLoginShell
      ? decorateStaffLoginShell(data.toString('utf8'))
      : data;
    res.writeHead(200, { 'Content-Type': types[ext] ?? 'application/octet-stream' });
    res.end(body);
    return true;
  } catch {
    return false;
  }
}
