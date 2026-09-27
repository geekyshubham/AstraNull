#!/usr/bin/env node
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import process from 'node:process';
import { chromium } from 'playwright-core';
import { canAccessRoute } from '../apps/web/react/src/lib/route-access.mjs';
import { roleHasPermission } from '../src/contracts/roles.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SESSION_KEY = 'astranull.portal.session.v1';
const DEFAULT_ROLES = ['owner', 'admin', 'engineer', 'soc', 'auditor', 'viewer'];
const EXPECTED_ROUTE_IDS = [
  'dashboard', 'environments', 'target-groups', 'targets', 'agents', 'checks',
  'test-policies', 'runs', 'findings', 'reports', 'integrations', 'notifications',
  'audit', 'release-evidence', 'settings', 'support', 'subscription', 'admin',
  'internal-soc', 'environment-detail', 'check-detail', 'policy-detail',
  'target-group-detail', 'target-detail', 'agent-detail', 'run-detail',
  'scan-detail', 'finding-detail', 'evidence-detail', 'report-detail',
  'tenant-detail', 'queue-detail',
];
const REQUIRED_TARGET_GROUP_IDS = ['tg_demo_origin', 'tg_e667ec494cba38ec'];
const REQUIRED_TARGET_IDS = ['tgt_6a31fa8a3ebc162f', 'tgt_be430ffbeba98c0b', 'tgt_demo_1'];
const API_PATH_RE = /^\/(?:v1|internal)\//;
const PRODUCTION_HOST = 'astranull.site';
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);
const LOADING_SELECTOR = '#portal-main [aria-busy="true"], #portal-main .skeleton, #portal-main [class*="skeleton"]';
const MACHINE_TOKEN_RE = /\b[a-z]+(?:_[a-z0-9]+)+\b/g;
const MACHINE_ID_PREFIX_RE = /^(?:tgt|tg|run|fnd|evt|agt|env|rpt|scan|usr|ten|wof|id|job|evd|btok|dns)_/;
const JARGON_PATTERNS = [
  ['api', /\bAPI\b/g],
  ['hydrator', /\bhydrator\b/gi],
  ['canonical', /\bcanonical\b/gi],
  ['producer_attribution', /\bproducer attribution\b/gi],
];
const RAW_ERROR_PATTERNS = [
  ['postgres_route_not_wired', /\bpostgres_route_not_wired\b/i],
  ['internal_error', /\binternal_error\b/i],
  ['undefined', /\bundefined\b/i],
  ['NaN', /\bNaN\b/],
  ['object_object', /\[object Object\]/i],
  ['epoch_milliseconds', /\b1[6-9]\d{11}\b/],
  ['stack_trace', /(?:^|\n)\s*at\s+[\w.$<>]+\s*\([^\n]+:\d+:\d+\)/],
];
const FRIENDLY_ACCESS_RE = /not available for the .+ role|role does not include this permission|current role cannot access|ask (?:a tenant )?(?:owner or )?admin if you need access|does not permit this action/i;
const FRIENDLY_CONNECTOR_DISABLED_RE = /connector[^\n]{0,100}(?:disabled|not enabled|turned off|unavailable)|(?:disabled|not enabled|turned off)[^\n]{0,100}connector/i;
const FRIENDLY_DISCOVERY_DISABLED_RE = /discovery[^\n]{0,100}(?:disabled|not enabled|turned off|unavailable)|(?:disabled|not enabled|turned off)[^\n]{0,100}discovery/i;
const MUTATING_CONTROL_RULES = [
  { re: /^Declare environment$/i, permission: 'environment:write', routes: ['environments'] },
  { re: /^(?:Add single domain|Add declared domain|Create group & add domain)$/i, permission: 'target_group:write' },
  { re: /^(?:Create schedule|New schedule|Set weekly cadence|Pause|Resume|Archive)$/i, permission: 'test_policy:write', routes: ['test-policies'] },
  { re: /^Generate & export$/i, permission: 'report:create', routes: ['reports'] },
  { re: /^(?:Request SOC-gated run|New request|Attach letter|Submit for SOC review)$/i, permission: 'high_scale:request', routes: ['runs'] },
  { re: /^(?:Save triage|Accept risk|Close finding|Reassign owner|Mark delivered)$/i, permission: 'finding:write', routes: ['finding-detail'] },
  { re: /^Retest$/i, permission: 'test_run:start', routes: ['finding-detail'] },
  { re: /^(?:Open target group & sign LOA|Review DNS status|Issue DNS challenge|Issue new challenge|Check now|Verify)$/i, permission: 'target_group:write', routes: ['target-group-detail'] },
  { re: /^(?:Run selected check|Run test|Detect edge|Run placement test)$/i, permission: 'test_run:start' },
  { re: /(?:create|add|remove|delete|archive|restore|edit) (?:target|target group)|import (?:target|inventory)/i, permission: 'target_group:write' },
  { re: /(?:create|add|edit|save) environment/i, permission: 'environment:write' },
  { re: /(?:create|save|edit|archive) (?:test )?polic|save schedule/i, permission: 'test_policy:write' },
  { re: /(?:start|run|launch) (?:safe |bounded )?(?:test|run|check)|finalize run|cancel run/i, permission: 'test_run:start' },
  { re: /(?:assign|update|close) finding|accept risk|mark delivered/i, permission: 'finding:write' },
  { re: /(?:create|generate) report/i, permission: 'report:create' },
  { re: /(?:create|add|save|toggle|enable|disable) notification|process retries|redrive/i, permission: 'notification:write' },
  { re: /(?:create|request|schedule) high.scale/i, permission: 'high_scale:request' },
  { re: /revoke agent/i, permission: 'agent:revoke' },
  { re: /(?:create|add) bootstrap token/i, permission: 'bootstrap_token:create' },
  { re: /revoke bootstrap token/i, permission: 'bootstrap_token:revoke' },
  { re: /create service account/i, permission: 'service_account:create' },
  { re: /(?:revoke|rotate) service account/i, permission: 'service_account:revoke' },
  { re: /(?:create|add|save) secret/i, permission: 'secret:write' },
  { re: /rotate secret/i, permission: 'secret:rotate' },
  { re: /(?:save organization|save retention|edit organization)/i, permission: 'tenant:write' },
  { re: /(?:create|setup|connect|validate|poll|disable) connector/i, permission: 'waf:connector_write' },
];

function parseArgs(argv) {
  const options = {
    baseUrl: 'https://astranull.site',
    tokensPath: '',
    shotsDir: '/tmp/an-live/shots',
    outputPath: '/tmp/an-live/live-portal-sweep.json',
    roles: [...DEFAULT_ROLES],
    detailLimit: 2,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--base-url') options.baseUrl = requiredArg(argv, ++index, arg);
    else if (arg === '--tokens') options.tokensPath = requiredArg(argv, ++index, arg);
    else if (arg === '--shots-dir') options.shotsDir = requiredArg(argv, ++index, arg);
    else if (arg === '--output') options.outputPath = requiredArg(argv, ++index, arg);
    else if (arg === '--roles') options.roles = requiredArg(argv, ++index, arg).split(',').map((value) => value.trim()).filter(Boolean);
    else if (arg === '--detail-limit') options.detailLimit = Number(requiredArg(argv, ++index, arg));
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!options.help && !options.tokensPath) throw new Error('--tokens is required');
  if (!Number.isInteger(options.detailLimit) || options.detailLimit < 1 || options.detailLimit > 5) {
    throw new Error('--detail-limit must be an integer from 1 to 5');
  }
  const unknownRoles = options.roles.filter((role) => !DEFAULT_ROLES.includes(role));
  if (unknownRoles.length || new Set(options.roles).size !== options.roles.length) {
    throw new Error('Roles must be a unique subset of owner,admin,engineer,soc,auditor,viewer');
  }
  options.baseUrl = normalizedBaseUrl(options.baseUrl);
  options.shotsDir = path.resolve(options.shotsDir);
  options.outputPath = path.resolve(options.outputPath);
  options.tokensPath = path.resolve(options.tokensPath);
  return options;
}

function requiredArg(argv, index, flag) {
  const value = argv[index];
  if (!value || value.startsWith('--')) throw new Error(`${flag} requires a value`);
  return value;
}

export function normalizedBaseUrl(value) {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash) throw new Error('--base-url must not contain credentials, query, or hash');
  const productionOrigin = url.protocol === 'https:' && url.hostname === PRODUCTION_HOST && url.port === '';
  const loopbackOrigin = url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
  if (url.pathname !== '/' || (!productionOrigin && !loopbackOrigin)) {
    throw new Error(`--base-url must be https://${PRODUCTION_HOST} or an HTTP loopback development origin`);
  }
  return url.origin;
}

function usage() {
  return [
    'Usage: node scripts/live-portal-sweep.mjs --tokens PATH [options]',
    '  --base-url URL       Portal origin (default: https://astranull.site)',
    '  --shots-dir PATH     Screenshot directory (default: /tmp/an-live/shots)',
    '  --output PATH        JSON result (default: /tmp/an-live/live-portal-sweep.json)',
    '  --roles CSV          Unique role subset (default: all six customer roles)',
    '  --detail-limit N     Recent records per dynamic detail kind, 1..5 (default: 2)',
  ].join('\n');
}

async function readTokens(tokensPath, roles) {
  const document = JSON.parse(await readFile(tokensPath, 'utf8'));
  const tokens = {};
  for (const role of roles) {
    const record = document?.[role];
    if (!record || typeof record.token !== 'string' || !record.token.trim()) throw new Error(`Token record missing for ${role}`);
    if (record.tenant_id !== 'ten_demo' || typeof record.user_id !== 'string') throw new Error(`Token identity invalid for ${role}`);
    if (!Number.isFinite(Number(record.expires_at)) || Number(record.expires_at) <= Date.now()) throw new Error(`Token expired for ${role}`);
    tokens[role] = record;
  }
  return tokens;
}

function redactor(tokenRecords) {
  const secrets = Object.values(tokenRecords).map((record) => record.token).filter(Boolean);
  return (value, max = 800) => {
    let text = String(value ?? '');
    for (const secret of secrets) text = text.replaceAll(secret, '[redacted]');
    text = text
      .replace(/Bearer\s+[A-Za-z0-9._~-]+/gi, 'Bearer [redacted]')
      .replace(/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, '[redacted-jwt]');
    return text.slice(0, max);
  };
}

function items(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.data)) return payload.data;
  return [];
}

function idOf(item, keys = ['id']) {
  for (const key of keys) {
    const value = item?.[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function labelOf(item, fallback) {
  return idOf(item, ['name', 'title', 'display_name', 'hostname', 'value', 'label']) || fallback;
}

function newest(records) {
  return [...records].sort((left, right) => {
    const l = Date.parse(left?.started_at ?? left?.created_at ?? left?.updated_at ?? '') || 0;
    const r = Date.parse(right?.started_at ?? right?.created_at ?? right?.updated_at ?? '') || 0;
    return r - l;
  });
}

async function safeGet(baseUrl, token, pathname, redact) {
  const url = new URL(pathname, baseUrl);
  if (url.origin !== baseUrl) throw new Error(`Refusing cross-origin fixture request: ${url.origin}`);
  let response;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    response = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      headers: { accept: 'application/json', authorization: `Bearer ${token}` },
    });
    if (response.status !== 429 || attempt === 2) break;
    const retryAfter = Math.min(5_000, Math.max(250, Number(response.headers.get('retry-after') ?? 1) * 1000));
    await new Promise((resolve) => setTimeout(resolve, retryAfter));
  }
  if (!response || response.status < 200 || response.status >= 300) {
    const body = redact(await response?.text().catch(() => ''), 240);
    throw new Error(`Fixture GET ${url.pathname} failed with ${response?.status ?? 'network error'}${body ? ` (${body})` : ''}`);
  }
  return response.json();
}

async function assertRouteInventory() {
  const source = await readFile(path.join(REPO_ROOT, 'apps/web/react/src/lib/navigation.ts'), 'utf8');
  const declared = [...source.matchAll(/\bid:\s*'([a-z-]+)'/g)].map((match) => match[1]);
  const unique = [...new Set(declared)];
  const missing = unique.filter((route) => !EXPECTED_ROUTE_IDS.includes(route));
  const stale = EXPECTED_ROUTE_IDS.filter((route) => !unique.includes(route));
  if (missing.length || stale.length) {
    throw new Error(`Sweep route inventory is out of sync (missing=${missing.join(',') || 'none'} stale=${stale.join(',') || 'none'})`);
  }
}

function requireRecords(kind, records) {
  if (!records.length) throw new Error(`Production fixture discovery found no ${kind}`);
  return records;
}

async function discoverFixtures(baseUrl, ownerToken, detailLimit, redact) {
  const endpoints = {
    environments: '/v1/environments', targetGroups: '/v1/target-groups', targets: '/v1/targets',
    agents: '/v1/agents', checks: '/v1/checks', policies: '/v1/test-policies', runs: '/v1/test-runs?limit=100',
    scans: '/v1/validation-scans?limit=50', findings: '/v1/findings', evidence: '/v1/evidence',
    reports: '/v1/reports', highScale: '/v1/high-scale-requests',
  };
  const values = Object.fromEntries(await Promise.all(Object.entries(endpoints).map(async ([key, endpoint]) => [
    key, items(await safeGet(baseUrl, ownerToken, endpoint, redact)),
  ])));
  for (const kind of ['environments', 'targetGroups', 'targets', 'agents', 'checks', 'runs', 'findings', 'evidence', 'reports']) {
    requireRecords(kind, values[kind]);
  }

  const byId = (records, id, keys = ['id']) => records.find((item) => idOf(item, keys) === id);
  for (const id of REQUIRED_TARGET_GROUP_IDS) {
    if (!byId(values.targetGroups, id)) throw new Error(`Required production target group not found: ${id}`);
  }
  for (const id of REQUIRED_TARGET_IDS) {
    if (!byId(values.targets, id)) throw new Error(`Required production target not found: ${id}`);
  }

  const take = (records, keys = ['id']) => newest(records)
    .map((item) => ({ id: idOf(item, keys), label: labelOf(item, idOf(item, keys)), item }))
    .filter((entry) => entry.id)
    .slice(0, detailLimit);
  const first = (records, keys = ['id']) => {
    const result = take(records, keys)[0];
    if (!result) throw new Error(`Production record has no usable identifier (${keys.join(',')})`);
    return result;
  };

  return {
    environment: first(values.environments, ['id', 'environment_id']),
    check: first(values.checks, ['check_id', 'id']),
    policy: values.policies.length ? first(values.policies) : null,
    targetGroups: REQUIRED_TARGET_GROUP_IDS.map((id) => {
      const item = byId(values.targetGroups, id);
      return { id, label: labelOf(item, id), item };
    }),
    targets: REQUIRED_TARGET_IDS.map((id) => {
      const item = byId(values.targets, id);
      return { id, label: labelOf(item, id), item };
    }),
    agents: take(values.agents), runs: take(values.runs),
    scans: take([
      ...values.scans.filter((entry) => ['completed', 'cancelled', 'canceled', 'failed', 'aborted'].includes(String(entry?.status ?? '').toLowerCase())),
      ...values.scans.filter((entry) => !['completed', 'cancelled', 'canceled', 'failed', 'aborted'].includes(String(entry?.status ?? '').toLowerCase())),
    ]),
    findings: take(values.findings), evidence: take(values.evidence, ['id', 'artifact_id']),
    reports: take(values.reports), queue: values.highScale.length ? first(values.highScale) : null,
    tenant: { id: 'ten_demo', label: 'ten_demo' },
    unavailableDetailRoutes: [
      ...(!values.policies.length ? ['policy-detail'] : []),
      ...(!values.scans.length ? ['scan-detail'] : []),
      ...(!values.highScale.length ? ['queue-detail'] : []),
    ],
    counts: Object.fromEntries(Object.entries(values).map(([key, records]) => [key, records.length])),
  };
}

function caseName(route, entity) {
  return entity ? `${route}-${entity.id}` : route;
}

function routeCases(fixtures) {
  const basic = [
    'dashboard', 'environments', 'target-groups', 'targets', 'agents', 'checks', 'test-policies',
    'runs', 'findings', 'reports', 'integrations', 'notifications', 'audit', 'release-evidence',
    'settings', 'support', 'subscription', 'admin', 'internal-soc',
  ].map((route) => ({ route, name: route, hash: route, expectedToken: '' }));
  const detail = [];
  const push = (route, entity, extras = '') => detail.push({
    route,
    name: caseName(route, entity),
    hash: `${route}?id=${encodeURIComponent(entity.id)}${extras}`,
    expectedToken: entity.id,
    fixtureUnavailable: false,
  });
  const pushUnavailable = (route) => detail.push({
    route, name: `${route}-no-production-record`, hash: route, expectedToken: '', fixtureUnavailable: true,
  });
  push('environment-detail', fixtures.environment);
  push('check-detail', fixtures.check);
  if (fixtures.policy) push('policy-detail', fixtures.policy);
  else pushUnavailable('policy-detail');
  fixtures.targetGroups.forEach((entry) => push('target-group-detail', entry));
  fixtures.targets.forEach((entry) => push('target-detail', entry));
  fixtures.agents.forEach((entry) => push('agent-detail', entry));
  fixtures.runs.forEach((entry) => push('run-detail', entry));
  if (fixtures.scans.length) fixtures.scans.forEach((entry) => push('scan-detail', entry));
  else pushUnavailable('scan-detail');
  fixtures.findings.forEach((entry) => push('finding-detail', entry));
  fixtures.evidence.forEach((entry) => push('evidence-detail', entry));
  fixtures.reports.forEach((entry) => push('report-detail', entry));
  push('tenant-detail', fixtures.tenant);
  if (fixtures.queue) push('queue-detail', fixtures.queue);
  else pushUnavailable('queue-detail');
  return [...basic, ...detail];
}

function safeFilename(value) {
  return value.replace(/[^a-zA-Z0-9_.-]+/g, '-').slice(0, 120);
}

async function launchBrowser() {
  try {
    return await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    return chromium.launch({ headless: true });
  }
}

function apiErrorCode(body) {
  if (!body) return '';
  try {
    const parsed = JSON.parse(body);
    return typeof parsed?.error === 'string' ? parsed.error : '';
  } catch {
    return '';
  }
}

function classifyApiErrors(record, bodyText) {
  const friendlyAccess = FRIENDLY_ACCESS_RE.test(bodyText);
  const friendlyConnectorDisabled = FRIENDLY_CONNECTOR_DISABLED_RE.test(bodyText);
  const friendlyDiscoveryDisabled = FRIENDLY_DISCOVERY_DISABLED_RE.test(bodyText);
  for (const failure of record.apiErrors) {
    failure.expected = (
      ([401, 403].includes(failure.status) && friendlyAccess)
      || (failure.status === 404 && failure.code === 'connector_feature_disabled' && friendlyConnectorDisabled)
      || (failure.status === 404 && failure.code === 'discovery_feature_disabled' && friendlyDiscoveryDisabled)
    );
  }
}

function inspectRawErrors(text, viewport) {
  return RAW_ERROR_PATTERNS.flatMap(([kind, pattern]) => {
    const match = text.match(pattern);
    if (!match) return [];
    const start = Math.max(0, Number(match.index ?? 0) - 80);
    return [{ kind, viewport, snippet: text.slice(start, start + 260).replace(/\s+/g, ' ').trim() }];
  });
}

function diagnosticSnippet(text, index, length) {
  const start = Math.max(0, index - 90);
  return text.slice(start, Math.min(text.length, index + length + 170)).replace(/\s+/g, ' ').trim();
}

function dottedIdentifierAt(text, index, length) {
  let start = index;
  let end = index + length;
  while (start > 0 && /[a-z0-9_.-]/i.test(text[start - 1])) start -= 1;
  while (end < text.length && /[a-z0-9_.-]/i.test(text[end])) end += 1;
  const envelope = text.slice(start, end).replace(/^\.+|\.+$/g, '');
  return envelope.includes('.') && /^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/i.test(envelope);
}

export function inspectVisibleLanguage(value, viewport = 'unknown') {
  const text = String(value ?? '');
  const machineTokens = [];
  const seenTokens = new Set();
  for (const match of text.matchAll(new RegExp(MACHINE_TOKEN_RE.source, 'g'))) {
    const token = match[0];
    const index = Number(match.index ?? 0);
    if (MACHINE_ID_PREFIX_RE.test(token) || dottedIdentifierAt(text, index, token.length) || seenTokens.has(token)) continue;
    seenTokens.add(token);
    machineTokens.push({ token, viewport, snippet: diagnosticSnippet(text, index, token.length) });
  }

  const jargon = [];
  for (const [kind, pattern] of JARGON_PATTERNS) {
    const match = new RegExp(pattern.source, pattern.flags).exec(text);
    if (!match) continue;
    jargon.push({ kind, term: match[0], viewport, snippet: diagnosticSnippet(text, Number(match.index ?? 0), match[0].length) });
  }
  return { machineTokens, jargon };
}

async function inspectPage(page, role, routeCase, viewport, redact) {
  const state = await page.evaluate(() => ({
    text: document.body?.innerText ?? '',
    emptyStates: [...document.querySelectorAll('.empty-state:not(.empty-state-skeleton)')]
      .filter((node) => {
        const style = getComputedStyle(node);
        return style.display !== 'none' && style.visibility !== 'hidden';
      })
      .map((node) => (node.textContent ?? '').replace(/\s+/g, ' ').trim()).filter(Boolean),
    controls: [...document.querySelectorAll('button, [role="button"], input[type="submit"]')]
      .filter((node) => {
        const style = getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
      })
      .map((node) => ({
        label: (node.getAttribute('aria-label') || node.textContent || node.getAttribute('value') || '').replace(/\s+/g, ' ').trim(),
        disabled: node.hasAttribute('disabled') || node.getAttribute('aria-disabled') === 'true',
      })).filter((entry) => entry.label),
    busy: [...document.querySelectorAll('#portal-main [aria-busy="true"]')].length,
    loadingPlaceholders: [...document.querySelectorAll('#portal-main [aria-busy="true"], #portal-main .skeleton, #portal-main [class*="skeleton"]')]
      .filter((node) => {
        const style = getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
      })
      .map((node) => ({
        tag: node.tagName.toLowerCase(),
        classes: [...node.classList].slice(0, 5).join(' '),
        ariaBusy: node.getAttribute('aria-busy') ?? '',
      })),
    horizontalOverflows: (() => {
      const candidates = new Set();
      for (const table of document.querySelectorAll('#portal-main table')) {
        let node = table.parentElement;
        for (let depth = 0; node && depth < 6 && node.id !== 'portal-main'; depth += 1, node = node.parentElement) {
          if (depth === 0 || node.matches('.table-wrap, .table-scroller, [role="region"]')) candidates.add(node);
        }
      }
      return [...candidates].flatMap((node) => {
        const style = getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        const overflow = node.scrollWidth - node.clientWidth;
        if (style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || overflow <= 1) return [];
        if (style.overflowX === 'auto' || style.overflowX === 'scroll') return [];
        return [{
          element: node.tagName.toLowerCase(),
          classes: [...node.classList].slice(0, 6).join(' '),
          role: node.getAttribute('role') ?? '',
          overflowX: style.overflowX,
          clientWidth: node.clientWidth,
          scrollWidth: node.scrollWidth,
        }];
      });
    })(),
    accessNotice: document.querySelector('.route-access-notice')?.textContent?.replace(/\s+/g, ' ').trim() ?? '',
  }));
  const text = redact(state.text, 100_000);
  const rawErrors = inspectRawErrors(text, viewport).map((entry) => ({ ...entry, snippet: redact(entry.snippet, 260) }));
  const language = inspectVisibleLanguage(text, viewport);
  const expectedAccess = canAccessRoute(role, routeCase.route, { principal: 'customer' });
  const missingExpectedToken = expectedAccess && routeCase.expectedToken && !text.includes(routeCase.expectedToken)
    ? [{ viewport, expected: routeCase.expectedToken, symptom: 'Expected real record identifier is not visible.' }]
    : [];
  const missingAccessState = !expectedAccess && !FRIENDLY_ACCESS_RE.test(`${state.accessNotice}\n${text}`)
    ? [{ viewport, symptom: 'Route was role-gated without a visible friendly no-access state.' }]
    : [];
  const staleAccessState = expectedAccess && state.accessNotice
    ? [{ viewport, symptom: 'A prior denied-route notice remained visible on this permitted route.', notice: redact(state.accessNotice, 300) }]
    : [];
  const unauthorizedControls = state.controls.flatMap((control) => {
    if (control.disabled) return [];
    const rule = MUTATING_CONTROL_RULES.find((candidate) =>
      candidate.re.test(control.label) && (!candidate.routes || candidate.routes.includes(routeCase.route))
    );
    if (!rule || roleHasPermission(role, rule.permission)) return [];
    return [{ viewport, label: redact(control.label, 160), requiredPermission: rule.permission }];
  });
  return {
    text,
    emptyStates: state.emptyStates.map((value) => redact(value, 300)),
    rawErrors,
    missingExpectedToken,
    missingAccessState,
    staleAccessState,
    unauthorizedControls,
    machineTokens: language.machineTokens.map((entry) => ({ ...entry, snippet: redact(entry.snippet, 300) })),
    jargon: language.jargon.map((entry) => ({ ...entry, snippet: redact(entry.snippet, 300) })),
    horizontalOverflows: state.horizontalOverflows.map((entry) => ({ ...entry, viewport })),
    loadingPlaceholders: state.loadingPlaceholders.map((entry) => ({ ...entry, viewport })),
    busyCount: state.busy,
    accessNotice: redact(state.accessNotice, 300),
  };
}

async function settlePortal(page) {
  await page.waitForLoadState('networkidle', { timeout: 30_000 }).catch(() => {});
  await page.waitForFunction((selector) => {
    if (!document.querySelector('#portal-main')) return false;
    return ![...document.querySelectorAll(selector)].some((node) => {
      const style = getComputedStyle(node);
      const rect = node.getBoundingClientRect();
      return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
    });
  }, LOADING_SELECTOR, { timeout: 45_000 }).catch(() => {});
  await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});
  await page.waitForTimeout(250);
}

async function settleViewport(page, width) {
  await page.waitForFunction((expectedWidth) => {
    if (window.innerWidth !== expectedWidth) return false;
    const sidebar = document.querySelector('.sidebar');
    if (!sidebar) return true;
    const style = getComputedStyle(sidebar);
    return expectedWidth > 1120
      ? style.position === 'sticky' && style.visibility === 'visible'
      : !sidebar.classList.contains('open') && style.visibility === 'hidden';
  }, width, { timeout: 3_000 }).catch(() => {});
}

async function sweepRole({ browser, baseUrl, role, tokenRecord, cases, shotsDir, redact }) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, serviceWorkers: 'block' });
  const session = {
    mode: 'oidc', access_token: tokenRecord.token, principal: 'customer', tenant_id: tokenRecord.tenant_id,
    user_id: tokenRecord.user_id, role, expires_at: tokenRecord.expires_at,
  };
  await context.addInitScript(({ key, value }) => {
    try { sessionStorage.setItem(key, JSON.stringify(value)); } catch { /* opaque frame */ }
  }, { key: SESSION_KEY, value: session });

  const allowedOrigins = new Set([baseUrl, 'https://fonts.googleapis.com', 'https://fonts.gstatic.com']);
  let activeRecord = null;
  await context.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (!allowedOrigins.has(url.origin)) {
      activeRecord?.blockedHosts.push({ method: request.method(), url: redact(`${url.origin}${url.pathname}`, 300) });
      await route.abort('blockedbyclient');
      return;
    }
    if (request.method() !== 'GET') {
      activeRecord?.nonGetRequests.push({ method: request.method(), url: redact(`${url.origin}${url.pathname}`, 300) });
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });

  const page = await context.newPage();
  const pendingResponses = new Set();
  page.on('pageerror', (error) => activeRecord?.pageErrors.push(redact(error?.stack || error?.message || error, 800)));
  page.on('console', (message) => {
    if (message.type() === 'error') activeRecord?.consoleErrors.push(redact(message.text(), 800));
  });
  page.on('response', (response) => {
    const url = new URL(response.url());
    if (!activeRecord || url.origin !== baseUrl || !API_PATH_RE.test(url.pathname) || response.status() < 400) return;
    const target = activeRecord;
    const promise = response.text().catch(() => '').then((body) => {
      const safeBody = redact(body, 500);
      target.apiErrors.push({
        method: response.request().method(), path: `${url.pathname}${url.search}`, status: response.status(),
        code: apiErrorCode(safeBody), detail: safeBody, expected: false,
      });
    }).finally(() => pendingResponses.delete(promise));
    pendingResponses.add(promise);
  });

  const records = [];
  try {
    for (let index = 0; index < cases.length; index += 1) {
      const routeCase = cases[index];
      const record = {
        role, route: routeCase.route, case: routeCase.name, requestedHash: routeCase.hash,
        expectedAccess: canAccessRoute(role, routeCase.route, { principal: 'customer' }),
        finalUrl: '', navigationError: '', pageErrors: [], consoleErrors: [], apiErrors: [], nonGetRequests: [],
        blockedHosts: [], rawErrors: [], missingExpectedData: [], missingAccessState: [], staleAccessState: [], unauthorizedControls: [],
        machineTokens: [], jargon: [], horizontalOverflows: [], loadingPlaceholders: [],
        emptyStates: [], busyCounts: {}, screenshots: [],
      };
      activeRecord = record;
      const target = `${baseUrl}/app#${routeCase.hash}`;
      try {
        await page.goto(target, { waitUntil: 'networkidle', timeout: 45_000 });
      } catch (error) {
        record.navigationError = redact(error instanceof Error ? error.message : error, 600);
      }
      await settlePortal(page);
      await Promise.all([...pendingResponses]);
      record.finalUrl = redact(page.url(), 500);

      await page.setViewportSize({ width: 1440, height: 1000 });
      await settleViewport(page, 1440);
      const desktop = await inspectPage(page, role, routeCase, '1440', redact);
      const stem = `${String(index + 1).padStart(2, '0')}-${safeFilename(routeCase.name)}`;
      const desktopPath = path.join(shotsDir, role, `${stem}-1440.png`);
      await page.screenshot({ path: desktopPath, fullPage: true });
      record.screenshots.push(desktopPath);

      await page.setViewportSize({ width: 390, height: 844 });
      await settleViewport(page, 390);
      const mobile = await inspectPage(page, role, routeCase, '390', redact);
      const mobilePath = path.join(shotsDir, role, `${stem}-390.png`);
      await page.screenshot({ path: mobilePath, fullPage: true });
      record.screenshots.push(mobilePath);
      await page.setViewportSize({ width: 1440, height: 1000 });
      await settleViewport(page, 1440);

      record.rawErrors.push(...desktop.rawErrors, ...mobile.rawErrors);
      record.missingExpectedData.push(...desktop.missingExpectedToken, ...mobile.missingExpectedToken);
      record.missingAccessState.push(...desktop.missingAccessState, ...mobile.missingAccessState);
      record.staleAccessState.push(...desktop.staleAccessState, ...mobile.staleAccessState);
      record.unauthorizedControls.push(...desktop.unauthorizedControls, ...mobile.unauthorizedControls);
      record.machineTokens.push(...desktop.machineTokens, ...mobile.machineTokens);
      record.jargon.push(...desktop.jargon, ...mobile.jargon);
      record.horizontalOverflows.push(...desktop.horizontalOverflows, ...mobile.horizontalOverflows);
      record.loadingPlaceholders.push(...desktop.loadingPlaceholders, ...mobile.loadingPlaceholders);
      record.emptyStates = [...new Set([...desktop.emptyStates, ...mobile.emptyStates])];
      record.busyCounts = { 1440: desktop.busyCount, 390: mobile.busyCount };
      record.accessNotice = desktop.accessNotice || mobile.accessNotice;
      classifyApiErrors(record, `${desktop.text}\n${mobile.text}`);
      records.push(record);
    }
  } finally {
    activeRecord = null;
    await context.close();
  }
  return records;
}

function uniqueDiagnostics(records, key, formatter = (value) => JSON.stringify(value)) {
  const seen = new Set();
  const values = [];
  for (const record of records) {
    for (const entry of record[key] ?? []) {
      const signature = `${record.role}|${record.case}|${formatter(entry)}`;
      if (!seen.has(signature)) {
        seen.add(signature);
        const detail = entry && typeof entry === 'object' && !Array.isArray(entry)
          ? entry
          : { detail: String(entry) };
        values.push({ role: record.role, route: record.route, case: record.case, ...detail });
      }
    }
  }
  return values;
}

function buildSummary(records, cases, roles, fixtureCounts) {
  const apiErrors = records.flatMap((record) => record.apiErrors);
  const routeCoverage = Object.fromEntries(roles.map((role) => [role, new Set(records.filter((record) => record.role === role).map((record) => record.route)).size]));
  const screenshotCount = records.reduce((sum, record) => sum + record.screenshots.length, 0);
  const counts = {
    roles: roles.length, uniqueRoutes: EXPECTED_ROUTE_IDS.length, routeCases: cases.length, visits: records.length,
    screenshots: screenshotCount, pageErrors: records.reduce((sum, record) => sum + record.pageErrors.length, 0),
    consoleErrors: records.reduce((sum, record) => sum + record.consoleErrors.length, 0),
    apiErrors: apiErrors.length, expectedApiErrors: apiErrors.filter((entry) => entry.expected).length,
    unexpectedApiErrors: apiErrors.filter((entry) => !entry.expected).length,
    nonGetRequests: records.reduce((sum, record) => sum + record.nonGetRequests.length, 0),
    blockedHosts: records.reduce((sum, record) => sum + record.blockedHosts.length, 0),
    rawErrors: records.reduce((sum, record) => sum + record.rawErrors.length, 0),
    missingExpectedData: records.reduce((sum, record) => sum + record.missingExpectedData.length, 0),
    missingAccessStates: records.reduce((sum, record) => sum + record.missingAccessState.length, 0),
    staleAccessStates: records.reduce((sum, record) => sum + record.staleAccessState.length, 0),
    unauthorizedControls: records.reduce((sum, record) => sum + record.unauthorizedControls.length, 0),
    machineTokens: records.reduce((sum, record) => sum + record.machineTokens.length, 0),
    jargon: records.reduce((sum, record) => sum + record.jargon.length, 0),
    horizontalOverflows: records.reduce((sum, record) => sum + record.horizontalOverflows.length, 0),
    loadingPlaceholders: records.reduce((sum, record) => sum + record.loadingPlaceholders.length, 0),
    navigationErrors: records.filter((record) => record.navigationError).length,
  };
  const unexpectedCount = counts.pageErrors + counts.consoleErrors + counts.unexpectedApiErrors + counts.nonGetRequests
    + counts.blockedHosts + counts.rawErrors + counts.missingExpectedData + counts.missingAccessStates
    + counts.staleAccessStates + counts.unauthorizedControls + counts.navigationErrors
    + counts.machineTokens + counts.jargon + counts.horizontalOverflows + counts.loadingPlaceholders;
  return {
    counts: { ...counts, unexpectedFindings: unexpectedCount }, routeCoverage, fixtureCounts,
    screenshotContractSatisfied: screenshotCount === records.length * 2,
    routeContractSatisfied: Object.values(routeCoverage).every((count) => count === EXPECTED_ROUTE_IDS.length),
  };
}

export async function runLivePortalSweep(options) {
  await assertRouteInventory();
  const tokenRecords = await readTokens(options.tokensPath, options.roles);
  const redact = redactor(tokenRecords);
  const owner = tokenRecords.owner ?? JSON.parse(await readFile(options.tokensPath, 'utf8')).owner;
  if (!owner?.token) throw new Error('Owner token is required for read-only fixture discovery');
  const fixtures = await discoverFixtures(options.baseUrl, owner.token, options.detailLimit, redact);
  const cases = routeCases(fixtures);
  await Promise.all(options.roles.map((role) => mkdir(path.join(options.shotsDir, role), { recursive: true })));

  const browser = await launchBrowser();
  const records = [];
  try {
    for (const role of options.roles) {
      records.push(...await sweepRole({
        browser, baseUrl: options.baseUrl, role, tokenRecord: tokenRecords[role], cases,
        shotsDir: options.shotsDir, redact,
      }));
    }
  } finally {
    await browser.close();
  }

  const summary = buildSummary(records, cases, options.roles, fixtures.counts);
  const result = {
    schema_version: 2, artifact_type: 'astranull_live_portal_read_only_sweep', created_at: new Date().toISOString(),
    base_url: options.baseUrl, read_only: true, roles: options.roles, route_ids: EXPECTED_ROUTE_IDS,
    detail_records: cases.filter((entry) => entry.expectedToken).map((entry) => ({ route: entry.route, id: entry.expectedToken })),
    unavailable_detail_routes: fixtures.unavailableDetailRoutes,
    summary, findings: {
      pageErrors: uniqueDiagnostics(records, 'pageErrors', String),
      consoleErrors: uniqueDiagnostics(records, 'consoleErrors', String),
      apiErrors: records.flatMap((record) => record.apiErrors.filter((entry) => !entry.expected).map((entry) => ({ role: record.role, route: record.route, case: record.case, ...entry }))),
      expectedApiErrors: records.flatMap((record) => record.apiErrors.filter((entry) => entry.expected).map((entry) => ({ role: record.role, route: record.route, case: record.case, ...entry }))),
      nonGetRequests: uniqueDiagnostics(records, 'nonGetRequests'), blockedHosts: uniqueDiagnostics(records, 'blockedHosts'),
      rawErrors: uniqueDiagnostics(records, 'rawErrors'), missingExpectedData: uniqueDiagnostics(records, 'missingExpectedData'),
      missingAccessStates: uniqueDiagnostics(records, 'missingAccessState'), staleAccessStates: uniqueDiagnostics(records, 'staleAccessState'),
      unauthorizedControls: uniqueDiagnostics(records, 'unauthorizedControls'),
      machineTokens: uniqueDiagnostics(records, 'machineTokens'),
      jargon: uniqueDiagnostics(records, 'jargon'),
      horizontalOverflows: uniqueDiagnostics(records, 'horizontalOverflows'),
      loadingPlaceholders: uniqueDiagnostics(records, 'loadingPlaceholders'),
      navigationErrors: records.filter((record) => record.navigationError).map((record) => ({ role: record.role, route: record.route, case: record.case, detail: record.navigationError })),
    },
    observations: records.map((record) => ({
      role: record.role, route: record.route, case: record.case, expectedAccess: record.expectedAccess,
      finalUrl: record.finalUrl, emptyStates: record.emptyStates, busyCounts: record.busyCounts,
      accessNotice: record.accessNotice, screenshots: record.screenshots,
    })),
  };
  await mkdir(path.dirname(options.outputPath), { recursive: true });
  await writeFile(options.outputPath, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  return result;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    return 0;
  }
  const result = await runLivePortalSweep(options);
  console.log(JSON.stringify({
    artifact_type: result.artifact_type, output: options.outputPath, shots: options.shotsDir,
    summary: result.summary,
  }, null, 2));
  return result.summary.counts.unexpectedFindings === 0 ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().then((code) => { process.exitCode = code; }).catch((error) => {
    console.error(`Live portal sweep failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
  });
}
