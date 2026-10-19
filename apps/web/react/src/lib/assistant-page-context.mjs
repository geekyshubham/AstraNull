/**
 * Page context for the assistant: which page is open, which record it shows, its filters and the
 * facts it already displays. Everything is capped and re-validated before it leaves the browser.
 */

export const MAX_FILTERS = 12;
export const MAX_FACTS = 24;
export const MAX_FACT_VALUE = 200;

export const ENTITY_TYPES = Object.freeze(['target', 'finding', 'run', 'check', 'scan', 'report', 'schedule', 'group']);

const ROUTES = Object.freeze({
  dashboard: { kind: 'dashboard', title: 'Dashboard' },
  targets: { kind: 'targets', title: 'Targets' },
  'target-detail': { kind: 'target', title: 'Target detail', entity: 'target', param: 'id' },
  checks: { kind: 'check_library', title: 'Check library' },
  'check-detail': { kind: 'check', title: 'Check detail', entity: 'check', param: 'id' },
  'test-policies': { kind: 'schedules', title: 'Validation schedules' },
  'policy-detail': { kind: 'schedule', title: 'Schedule detail', entity: 'schedule', param: 'id' },
  findings: { kind: 'findings', title: 'Findings' },
  'finding-detail': { kind: 'finding', title: 'Finding detail', entity: 'finding', param: 'id' },
  'finding-group-detail': { kind: 'finding_group', title: 'Finding group', entity: 'group', param: 'key' },
  runs: { kind: 'runs', title: 'Test runs' },
  'run-detail': { kind: 'run', title: 'Run detail', entity: 'run', param: 'id' },
  'scan-detail': { kind: 'scan', title: 'Validation scan', entity: 'scan', param: 'id' },
  reports: { kind: 'reports', title: 'Reports' },
  'report-detail': { kind: 'report', title: 'Report detail', entity: 'report', param: 'id' },
  'evidence-detail': { kind: 'evidence', title: 'Evidence detail' },
  integrations: { kind: 'integrations', title: 'Integrations' },
  notifications: { kind: 'notifications', title: 'Notifications' },
  audit: { kind: 'audit', title: 'Audit log' },
  settings: { kind: 'settings', title: 'Settings' },
  support: { kind: 'support', title: 'Support' },
});

const SKIPPED_PARAMS = new Set(['id', 'key', 'tab', 'tenant', 'tenant_id', 'entity_id', 'inspect', 'focus', 'add', 'variant']);
const SECRET_KEY = /(token|secret|password|passwd|cookie|session|authorization|api[_-]?key|credential|signature)/i;
const SECRET_VALUE = /(bearer\s+\S+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN|(?:sk|ghp|xox[bp])[-_][A-Za-z0-9]{12,})/i;
const VERIFIED = new Set(['dns_verified', 'provider_verified', 'user_confirmed', 'verified']);

/** @param {unknown} value @param {number} max */
function clean(value, max) {
  if (value === null || value === undefined) return '';
  const raw = typeof value === 'number' || typeof value === 'boolean' ? String(value) : typeof value === 'string' ? value : '';
  return raw.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

/** @param {unknown} source @param {number} limit @param {number} keyMax */
function cleanRecord(source, limit, keyMax) {
  if (!source || typeof source !== 'object' || Array.isArray(source)) return {};
  const out = {};
  for (const [rawKey, rawValue] of Object.entries(source)) {
    if (Object.keys(out).length >= limit) break;
    const key = clean(rawKey, keyMax);
    const value = clean(rawValue, MAX_FACT_VALUE);
    if (!key || !value || SECRET_KEY.test(key) || SECRET_VALUE.test(value)) continue;
    out[key] = value;
  }
  return out;
}

/** Caps and validates a page context; anything malformed is dropped rather than repaired. */
export function sanitizePageContext(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const route = clean(value.route, 60).replace(/[^a-z0-9-]/gi, '');
  if (!route) return null;
  const page = { route, title: clean(value.title, 120) || ROUTES[route]?.title || route, kind: clean(value.kind, 40).replace(/[^a-z0-9_]/gi, '') || ROUTES[route]?.kind || 'page' };
  const entity = value.entity && typeof value.entity === 'object' ? value.entity : null;
  const entityType = clean(entity?.type, 20);
  const entityId = clean(entity?.id, 160);
  if (entityType && entityId && ENTITY_TYPES.includes(entityType)) page.entity = { type: entityType, id: entityId };
  const tab = clean(value.tab, 40);
  if (tab) page.tab = tab;
  const filters = cleanRecord(value.filters, MAX_FILTERS, 40);
  if (Object.keys(filters).length) page.filters = filters;
  const facts = cleanRecord(value.facts, MAX_FACTS, 60);
  if (Object.keys(facts).length) page.facts = facts;
  return page;
}

/** Route id and query parameters from a hash such as `#target-detail?id=t1&tab=validate`. */
export function parseRouteHash(hash) {
  const raw = String(hash ?? '').replace(/^#/, '');
  const index = raw.indexOf('?');
  const route = (index >= 0 ? raw.slice(0, index) : raw).replace(/[^a-z0-9-]/gi, '') || 'dashboard';
  const params = {};
  for (const [key, value] of new URLSearchParams(index >= 0 ? raw.slice(index + 1) : '')) params[key] = value;
  return { route, params };
}

function str(item, keys) {
  if (!item || typeof item !== 'object') return '';
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  }
  return '';
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

function countBy(items, key) {
  const out = {};
  for (const item of items) {
    const value = str(item, [key]).toLowerCase() || 'unknown';
    out[value] = (out[value] ?? 0) + 1;
  }
  return out;
}

function openFindings(findings) {
  return list(findings).filter((item) => ['open', 'in_progress', 'reopened', 'remediation_pending'].includes(str(item, ['status', 'state']).toLowerCase()));
}

function verdictOf(run) {
  const verdict = run?.verdict;
  if (typeof verdict === 'string') return verdict;
  return str(verdict, ['verdict', 'status', 'result']);
}

/** Facts the portal already holds for this route, before a page adds its own. */
export function derivedFacts(route, entityId, data) {
  const facts = {};
  const targets = list(data?.targets);
  const findings = list(data?.findings);
  const runs = list(data?.runs);
  const checks = list(data?.checks);
  const targetValue = (id) => str(targets.find((item) => str(item, ['id']) === id), ['value', 'hostname']);
  if (route === 'dashboard') {
    const score = data?.state?.readiness?.score;
    if (typeof score === 'number') facts['Readiness score'] = `${score}/100`;
    facts['Declared targets'] = String(targets.length);
    facts['Ownership verified'] = String(targets.filter((item) => VERIFIED.has(str(item, ['verification_state', 'verify_state']).toLowerCase())).length);
    const total = data?.findingsMeta?.total;
    facts['Open findings (loaded)'] = String(openFindings(findings).length);
    if (typeof total === 'number') facts['Findings total'] = String(total);
  } else if (route === 'targets') {
    facts['Declared targets'] = String(targets.length);
  } else if (route === 'target-detail' && entityId) {
    const target = targets.find((item) => str(item, ['id']) === entityId);
    if (target) {
      facts.Target = str(target, ['value', 'hostname']);
      facts.Kind = str(target, ['kind']);
      facts.Ownership = str(target, ['verification_state', 'verify_state']) || 'unverified';
    }
    facts['Open findings (loaded)'] = String(openFindings(findings).filter((item) => str(item, ['target_id']) === entityId).length);
  } else if (route === 'findings') {
    const total = data?.findingsMeta?.total;
    if (typeof total === 'number') facts['Findings total'] = String(total);
    const severities = countBy(openFindings(findings), 'severity');
    for (const [severity, count] of Object.entries(severities).slice(0, 6)) facts[`Open ${severity} (loaded)`] = String(count);
  } else if (route === 'finding-detail' && entityId) {
    const finding = findings.find((item) => str(item, ['id']) === entityId);
    if (finding) {
      facts.Finding = str(finding, ['title', 'summary']);
      facts.Severity = str(finding, ['severity']);
      facts.Status = str(finding, ['status', 'state']);
      facts.Check = str(finding, ['check_id']);
      const target = targetValue(str(finding, ['target_id']));
      if (target) facts.Target = target;
    }
  } else if (route === 'run-detail' && entityId) {
    const run = runs.find((item) => str(item, ['id']) === entityId);
    if (run) {
      facts.Check = str(run, ['check_id']);
      facts.Status = str(run, ['status']);
      const verdict = verdictOf(run);
      if (verdict) facts.Verdict = verdict;
      const target = targetValue(str(run, ['target_id']));
      if (target) facts.Target = target;
    }
  } else if (route === 'check-detail' && entityId) {
    const check = checks.find((item) => str(item, ['check_id', 'id']) === entityId);
    if (check) {
      facts.Check = str(check, ['name']);
      facts.Family = str(check, ['vector_family']);
      facts['Safety class'] = str(check, ['safety_class']);
    }
  } else if (route === 'checks') {
    facts['Catalog checks'] = String(checks.length);
  } else if (route === 'test-policies') {
    const policies = list(data?.testPolicies);
    facts.Schedules = String(policies.length);
    const states = countBy(policies, 'state');
    for (const [state, count] of Object.entries(states).slice(0, 4)) facts[`Schedules ${state}`] = String(count);
  } else if (route === 'policy-detail' && entityId) {
    const policy = list(data?.testPolicies).find((item) => str(item, ['id']) === entityId);
    if (policy) {
      facts.Schedule = str(policy, ['name']);
      facts.Check = str(policy, ['check_id']);
      facts.Cadence = str(policy, ['cadence']);
      const target = targetValue(str(policy, ['target_id']));
      if (target) facts.Target = target;
    }
  } else if (route === 'runs') {
    facts['Runs loaded'] = String(runs.length);
  } else if (route === 'scan-detail' && entityId) {
    const scan = list(data?.validationScans).find((item) => str(item, ['id']) === entityId);
    if (scan) {
      facts.Status = str(scan, ['status']);
      const target = targetValue(str(scan, ['target_id']));
      if (target) facts.Target = target;
    }
  } else if (route === 'reports') {
    facts.Reports = String(list(data?.reports).length);
  } else if (route === 'report-detail' && entityId) {
    const report = list(data?.reports).find((item) => str(item, ['id']) === entityId);
    if (report) {
      facts.Report = str(report, ['title', 'name', 'kind']);
      facts.Status = str(report, ['status']);
    }
  }
  return Object.fromEntries(Object.entries(facts).filter(([, value]) => value));
}

/**
 * The page context sent with a question: the route's identity and filters, the facts the portal
 * holds, then whatever the open page published for the same route (it wins on conflicts).
 */
export function buildPageContext({ route, params = {}, title = '', data = null, published = null }) {
  const meta = ROUTES[route] ?? { kind: 'page', title: route };
  const entityId = meta.param ? clean(params[meta.param], 160) : '';
  const filters = {};
  for (const [key, value] of Object.entries(params)) {
    if (SKIPPED_PARAMS.has(key) || key.startsWith('ev_')) continue;
    filters[key] = value;
  }
  const own = published && published.route === route ? published : null;
  return sanitizePageContext({
    route,
    title: own?.title || title || meta.title,
    kind: meta.kind,
    entity: own?.entity ?? (meta.entity && entityId ? { type: meta.entity, id: entityId } : undefined),
    tab: own?.tab ?? params.tab,
    filters: { ...filters, ...(own?.filters ?? {}) },
    facts: { ...derivedFacts(route, entityId, data), ...(own?.facts ?? {}) },
  });
}

/** Record ids the server resolves itself, taken from the page entity. */
export function contextIds(page) {
  const entity = page?.entity;
  if (!entity) return {};
  const key = { target: 'target_id', finding: 'finding_id', run: 'run_id', check: 'check_id', scan: 'scan_id' }[entity.type];
  return key ? { [key]: entity.id } : {};
}

/** Short label for the context chip. */
export function describePageContext(page) {
  if (!page) return '';
  const subject = page.facts?.Target || page.facts?.Finding || page.facts?.Check || page.facts?.Schedule || page.facts?.Report || '';
  if (subject && subject !== page.title) return `${page.title} · ${subject}`;
  return page.title;
}

const SUGGESTIONS = {
  dashboard: ['Summarise my readiness and the top risks', 'Chart open findings by severity', 'Which targets need attention first?', 'What should I fix this week?'],
  targets: ['Which targets have no results yet?', 'Chart targets by ownership state', 'Which domains have the most open findings?'],
  target: ["What's missing on this target?", 'Show recent results for this target', 'How do I lock my origin to my CDN?', 'Which checks should I run next here?'],
  findings: ['Group my open findings by check', 'Chart open findings by severity', 'Which findings are oldest?', 'What should I fix first?'],
  finding: ['What is missing and how do I fix it?', 'Show the steps for my CDN/WAF provider', 'How do I verify the fix?'],
  finding_group: ['Which targets share this finding?', 'How do I fix this everywhere at once?', 'How do I verify the fix?'],
  check_library: ['Which checks cover rate limiting?', 'Which checks can I run on my targets?', 'Chart checks by category'],
  check: ['What does this check prove?', 'Where has this check found gaps?', 'How do I pass this check?'],
  schedules: ['Which schedules are not dispatching and why?', 'What should I schedule weekly?', 'Chart schedules by state'],
  schedule: ['Why is this schedule not running?', 'What does this check prove?'],
  runs: ['Chart recent run results', 'Which runs failed and why?'],
  run: ['Explain this result', 'What should I do about this result?'],
  scan: ['Summarise this scan', 'Which checks in this scan found gaps?'],
  reports: ['What should my next report cover?', 'Summarise my current readiness'],
  report: ['Summarise this report'],
};

const GENERAL = ['How do I add a rate-limiting rule on my WAF?', 'How do I stop attackers reaching my origin directly?', 'What should a DDoS runbook include?', 'How do I block a port on my cloud firewall?'];

export function pageSuggestions(kind) {
  return SUGGESTIONS[kind] ?? GENERAL;
}
