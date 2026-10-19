import { requirePermission } from '../rbac.mjs';
import { redactSecrets, wrapUntrusted } from '../lib/assistantSafety.mjs';

// Read-only, tenant-scoped data tools the assistant can call through its runner. Every tool runs
// with the job owner's captured context, is gated by the permission of the matching /v1 route,
// and returns plain, redacted JSON. Nothing here writes to stores or reaches another tenant.

export const MAX_TOOL_CALLS = 8;
export const TOOL_RESULT_MAX_CHARS = 12000;
const MAX_DATA_ROWS = 200;

function text(value) {
  return value === undefined || value === null ? '' : String(value);
}

function idArg(value) {
  const raw = text(value).trim();
  return /^[A-Za-z0-9_.:-]{1,120}$/.test(raw) ? raw : '';
}

function limitArg(value, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 1) return fallback;
  return Math.min(Math.floor(number), max);
}

function enumArg(value, allowed) {
  const raw = text(value).trim().toLowerCase();
  return allowed.includes(raw) ? raw : '';
}

function shortText(value, max = 300) {
  return text(value).replace(/\s+/g, ' ').trim().slice(0, max);
}

function pick(record, fields) {
  if (!record || typeof record !== 'object') return null;
  const out = {};
  for (const key of fields) {
    const value = record[key];
    if (value === undefined || value === null || value === '') continue;
    out[key] = typeof value === 'string' ? shortText(value, 400) : value;
  }
  return out;
}

function verdictOf(run) {
  const raw = run?.verdict;
  if (typeof raw === 'string') return raw;
  return text(raw?.verdict ?? raw?.status ?? raw?.result);
}

function items(value) {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value.items)) return value.items;
  return [];
}

function targetSummary(target) {
  const out = pick(target, ['id', 'value', 'kind', 'verification_state', 'eligibility', 'expected_behavior', 'last_validation_at', 'created_at']);
  if (!out) return null;
  if (Array.isArray(target.tags) && target.tags.length) out.tags = target.tags.slice(0, 12).map((tag) => shortText(tag, 60));
  const edge = target.edge_detection ?? target.edge;
  if (edge && typeof edge === 'object') out.edge = edgeSummary(edge);
  return out;
}

function edgeSummary(edge) {
  if (!edge || typeof edge !== 'object') return null;
  const family = (key) => {
    const entry = edge[key] ?? edge.families?.[key];
    if (!entry || typeof entry !== 'object') return undefined;
    return pick(entry, ['status', 'provider', 'provider_name', 'observed_at', 'freshness']);
  };
  const out = {};
  for (const key of ['waf', 'cdn', 'cloud', 'dns', 'origin_hosting']) {
    const value = family(key);
    if (value && Object.keys(value).length) out[key] = value;
  }
  if (edge.observed_at) out.observed_at = edge.observed_at;
  return out;
}

function findingSummary(finding, detail = false) {
  const out = pick(finding, ['id', 'title', 'severity', 'status', 'check_id', 'target_id', 'vector_family', 'created_at', 'last_observed_at', 'owner']);
  if (!out) return null;
  if (!out.status && findingStatusOf(finding)) out.status = findingStatusOf(finding);
  if (detail) {
    Object.assign(out, pick(finding, ['system_summary', 'remediation_template', 'test_run_id', 'verdict_id']) ?? {});
    if (Array.isArray(finding.evidence_ids)) out.evidence_ids = finding.evidence_ids.slice(0, 20);
    const missing = finding.missing_control;
    if (missing && typeof missing === 'object') {
      out.missing_control = pick(missing, ['headline', 'control_family', 'control_label', 'layer', 'missing_control', 'required_policy', 'evidence_statement']);
      const guidance = Array.isArray(missing.provider_guidance) ? missing.provider_guidance : [];
      if (guidance.length) {
        out.missing_control.provider_guidance = guidance.slice(0, 4).map((entry) => ({
          ...pick(entry, ['provider', 'provider_label', 'control', 'detection_source', 'layer']),
          steps: (Array.isArray(entry?.steps) ? entry.steps : []).slice(0, 6).map((step) => shortText(step, 240)),
          docs: (Array.isArray(entry?.docs) ? entry.docs : []).slice(0, 4).map((doc) => (typeof doc === 'string' ? doc : pick(doc, ['title', 'url']))),
        }));
      }
    }
  }
  return out;
}

function runSummary(run, detail = false) {
  const out = pick(run, ['id', 'check_id', 'target_id', 'status', 'created_at', 'started_at', 'completed_at']);
  if (!out) return null;
  const verdict = verdictOf(run);
  if (verdict) out.verdict = verdict;
  if (detail) {
    const record = run.verdict && typeof run.verdict === 'object' ? run.verdict : null;
    if (record) {
      Object.assign(out, pick(record, ['explanation', 'expected_behavior', 'observed']) ?? {});
      if (Array.isArray(record.evidence_ids)) out.evidence_ids = record.evidence_ids.slice(0, 20);
      if (Array.isArray(record.reasons)) out.reasons = record.reasons.slice(0, 8).map((reason) => shortText(reason, 200));
    }
    if (Array.isArray(run.events)) out.event_count = run.events.length;
  }
  return out;
}

function checkSummary(check, detail = false) {
  const out = pick(check, ['check_id', 'name', 'vector_family', 'safety_class', 'risk_class', 'evidence_tier', 'section']);
  if (!out) return null;
  if (Array.isArray(check.supported_targets)) out.supported_targets = check.supported_targets;
  if (detail) {
    Object.assign(out, pick(check, ['description', 'verdict_logic', 'default_expected_behavior', 'remediation_template']) ?? {});
    const missing = check.missing_control;
    if (missing && typeof missing === 'object') out.missing_control = pick(missing, ['control_family', 'control_label', 'layer', 'missing_control', 'required_policy']);
  }
  return out;
}

function matches(value, wanted) {
  return !wanted || text(value).toLowerCase() === wanted.toLowerCase();
}

function dayOf(value) {
  const ms = Date.parse(text(value));
  return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : '';
}

function findingStatusOf(row) {
  return text(row?.status ?? row?.state);
}

function edgeProvider(target) {
  const edge = target?.edge_detection ?? target?.edge;
  const provider = edge?.cdn?.provider ?? edge?.waf?.provider ?? edge?.families?.cdn?.provider ?? edge?.families?.waf?.provider;
  return text(provider) || 'unknown';
}

const DATASETS = Object.freeze({
  findings: {
    permission: 'finding:read',
    label: 'findings',
    groupBy: { severity: (row) => row.severity, status: findingStatusOf, check_id: (row) => row.check_id, target_id: (row) => row.target_id, vector_family: (row) => row.vector_family },
    filters: ['severity', 'status', 'check_id', 'target_id', 'vector_family'],
    columns: [['id', 'Finding', 'string'], ['title', 'Title', 'string'], ['severity', 'Severity', 'string'], ['status', 'Status', 'string'], ['check_id', 'Check', 'string'], ['target_id', 'Target', 'string'], ['created_at', 'Opened', 'date']],
  },
  targets: {
    permission: 'target_group:read',
    label: 'targets',
    groupBy: { kind: (row) => row.kind, verification_state: (row) => row.verification_state, edge_provider: edgeProvider },
    filters: ['kind', 'verification_state'],
    columns: [['id', 'Target', 'string'], ['value', 'Value', 'string'], ['kind', 'Kind', 'string'], ['verification_state', 'Ownership', 'string'], ['created_at', 'Added', 'date']],
  },
  runs: {
    permission: 'test_run:read',
    label: 'validation runs',
    groupBy: { status: (row) => row.status, verdict: (row) => verdictOf(row) || 'none', check_id: (row) => row.check_id, target_id: (row) => row.target_id, day: (row) => dayOf(row.completed_at ?? row.created_at) },
    filters: ['status', 'check_id', 'target_id'],
    columns: [['id', 'Run', 'string'], ['check_id', 'Check', 'string'], ['target_id', 'Target', 'string'], ['status', 'Status', 'string'], ['verdict', 'Verdict', 'string'], ['created_at', 'Started', 'date']],
  },
  checks: {
    permission: 'check:read',
    label: 'catalog checks',
    groupBy: { vector_family: (row) => row.vector_family, safety_class: (row) => row.safety_class, evidence_tier: (row) => row.evidence_tier },
    filters: ['vector_family', 'safety_class', 'evidence_tier'],
    columns: [['check_id', 'Check', 'string'], ['name', 'Name', 'string'], ['vector_family', 'Family', 'string'], ['safety_class', 'Safety', 'string'], ['evidence_tier', 'Tier', 'string']],
  },
});

export const ASSISTANT_TOOL_SPECS = Object.freeze([
  { name: 'list_targets', permission: 'target_group:read', args: '{"query"?: text, "verification"?: "verified"|"unverified", "kind"?: text, "limit"?: 1-100}', description: 'Declared targets (domains, hosts, IPs) with ownership and edge provider.' },
  { name: 'get_target', permission: 'target_group:read', args: '{"target_id": id}', description: 'One target with ownership, latest WAF/CDN/cloud detection, subdomain count and recent verdicts.' },
  { name: 'list_findings', permission: 'finding:read', args: '{"status"?: text, "severity"?: text, "target_id"?: id, "check_id"?: id, "limit"?: 1-100}', description: 'Findings (security gaps) with severity and lifecycle status.' },
  { name: 'get_finding', permission: 'finding:read', args: '{"finding_id": id}', description: 'One finding with its missing control, provider guidance and evidence ids.' },
  { name: 'list_runs', permission: 'test_run:read', args: '{"target_id"?: id, "check_id"?: id, "status"?: text, "limit"?: 1-100}', description: 'Validation runs with verdicts, newest first.' },
  { name: 'get_run', permission: 'test_run:read', args: '{"run_id": id}', description: 'One run with verdict explanation, reasons and evidence ids.' },
  { name: 'list_checks', permission: 'check:read', args: '{"query"?: text, "vector_family"?: text, "limit"?: 1-100}', description: 'The check catalog.' },
  { name: 'get_check', permission: 'check:read', args: '{"check_id": id}', description: 'One check with what it tests, its verdict logic and the control it covers.' },
  { name: 'get_readiness', permission: 'tenant:read', args: '{}', description: 'Workspace readiness score, its factors and posture counts.' },
  { name: 'get_edge_coverage', permission: 'target_group:read', args: '{"family": "waf"|"cdn"}', description: 'How many declared hosts have a WAF or CDN detected, not detected or unknown.' },
  { name: 'list_schedules', permission: 'test_policy:read', args: '{}', description: 'Validation schedules and their cadence.' },
  { name: 'list_audit_events', permission: 'audit:read', args: '{"limit"?: 1-50}', description: 'Recent audit log events (admins and auditors only).' },
  { name: 'query_data', permission: 'per dataset', args: '{"dataset": "findings"|"targets"|"runs"|"checks", "group_by"?: field, "filters"?: {field: value}, "limit"?: 1-200}', description: 'Counts or rows over a dataset; registers the table as Qn so it can be shown as a chart. group_by fields: findings severity|status|check_id|target_id|vector_family; targets kind|verification_state|edge_provider; runs status|verdict|check_id|target_id|day; checks vector_family|safety_class|evidence_tier.' },
]);

const TOOL_NAMES = new Set(ASSISTANT_TOOL_SPECS.map((spec) => spec.name));

export function isAssistantToolName(name) {
  return TOOL_NAMES.has(text(name));
}

/** Prompt section that documents the data tools and the call protocol. */
export function assistantToolGuide() {
  return [
    'Data tools (read-only, scoped to this customer\'s workspace):',
    ...ASSISTANT_TOOL_SPECS.map((spec) => `- ${spec.name} ${spec.args}: ${spec.description}`),
    '',
    'To call a data tool, reply with ONLY one fenced block and nothing else:',
    '```astranull-tool',
    '{"name": "list_findings", "args": {"status": "open"}}',
    '```',
    `You will receive the result and can call more tools (at most ${MAX_TOOL_CALLS} per answer) before you answer.`,
    'Use data tools for anything about the customer\'s own environment and never guess their numbers. Use web search only for vendor documentation.',
    'To show a chart or table, call query_data, then put a marker on its own line in your answer: [[data:Q1]] or [[data:Q1|bar]] (types: table, bar, line, donut). Only reference ids you received from query_data.',
  ].join('\n');
}

function permissionFor(name, args) {
  if (name === 'query_data') return DATASETS[enumArg(args?.dataset, Object.keys(DATASETS))]?.permission ?? null;
  return ASSISTANT_TOOL_SPECS.find((spec) => spec.name === name)?.permission ?? null;
}

function rowsToTable(rows, columns) {
  return {
    columns: columns.map(([key, label, type]) => ({ key, label, type })),
    rows: rows.slice(0, MAX_DATA_ROWS).map((row) => columns.map(([key]) => {
      const value = key === 'verdict' ? verdictOf(row) : key === 'status' ? text(row?.status ?? row?.state) : row?.[key];
      return value === undefined || value === null ? '' : (typeof value === 'number' ? value : shortText(value, 160));
    })),
  };
}

async function datasetRows(dataset, ctx, deps) {
  if (dataset === 'findings') return items(await deps.listFindings(ctx, { limit: MAX_DATA_ROWS }));
  if (dataset === 'targets') return items(await deps.listTargets(ctx));
  if (dataset === 'runs') return items(await deps.listRuns(ctx, { limit: 100 }));
  return items(await deps.listChecks(ctx));
}

async function queryData(ctx, args, deps) {
  const dataset = enumArg(args?.dataset, Object.keys(DATASETS));
  if (!dataset) return { error: 'invalid_args', message: 'dataset must be findings, targets, runs or checks.' };
  const spec = DATASETS[dataset];
  const groupBy = text(args?.group_by).trim();
  if (groupBy && !spec.groupBy[groupBy]) return { error: 'invalid_args', message: `group_by for ${dataset} must be one of ${Object.keys(spec.groupBy).join(', ')}.` };
  const filters = args?.filters && typeof args.filters === 'object' && !Array.isArray(args.filters) ? args.filters : {};
  for (const key of Object.keys(filters)) {
    if (!spec.filters.includes(key)) return { error: 'invalid_args', message: `filters for ${dataset} may use ${spec.filters.join(', ')}.` };
  }
  const limit = limitArg(args?.limit, MAX_DATA_ROWS, 50);
  let rows = await datasetRows(dataset, ctx, deps);
  rows = rows.filter((row) => Object.entries(filters).every(([key, value]) => matches(spec.groupBy[key] ? spec.groupBy[key](row) : row?.[key], text(value))));
  const filterNote = Object.entries(filters).map(([key, value]) => `${key}=${shortText(value, 40)}`).join(', ');
  if (groupBy) {
    const counts = new Map();
    for (const row of rows) {
      const key = text(spec.groupBy[groupBy](row)) || 'unknown';
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const ordered = [...counts.entries()].sort((left, right) => (groupBy === 'day' ? left[0].localeCompare(right[0]) : right[1] - left[1])).slice(0, limit);
    return {
      table: {
        title: `${spec.label[0].toUpperCase()}${spec.label.slice(1)} by ${groupBy.replace(/_/g, ' ')}${filterNote ? ` (${filterNote})` : ''}`,
        columns: [{ key: groupBy, label: groupBy.replace(/_/g, ' '), type: groupBy === 'day' ? 'date' : 'string' }, { key: 'count', label: 'Count', type: 'number' }],
        rows: ordered.map(([key, count]) => [key, count]),
        suggested_visual: groupBy === 'day' ? 'line' : ordered.length <= 6 ? 'donut' : 'bar',
      },
      total: rows.length,
    };
  }
  const table = rowsToTable(rows.slice(0, limit), spec.columns);
  return { table: { title: `${spec.label[0].toUpperCase()}${spec.label.slice(1)}${filterNote ? ` (${filterNote})` : ''}`, ...table, suggested_visual: 'table' }, total: rows.length };
}

async function runTool(name, ctx, args, deps) {
  switch (name) {
    case 'list_targets': {
      const query = shortText(args?.query, 120).toLowerCase();
      const verification = enumArg(args?.verification, ['verified', 'unverified']);
      const kind = shortText(args?.kind, 40).toLowerCase();
      const verified = (row) => ['dns_verified', 'provider_verified', 'user_confirmed', 'verified'].includes(text(row.verification_state ?? row.verification?.state).toLowerCase());
      const rows = items(await deps.listTargets(ctx))
        .filter((row) => !query || text(row.value).toLowerCase().includes(query) || (Array.isArray(row.tags) && row.tags.some((tag) => text(tag).toLowerCase().includes(query))))
        .filter((row) => !verification || (verification === 'verified' ? verified(row) : !verified(row)))
        .filter((row) => !kind || text(row.kind).toLowerCase() === kind);
      return { total: rows.length, items: rows.slice(0, limitArg(args?.limit, 100, 50)).map(targetSummary) };
    }
    case 'get_target': {
      const id = idArg(args?.target_id);
      if (!id) return { error: 'invalid_args', message: 'target_id is required.' };
      const target = await deps.getTarget(ctx, id);
      if (!target) return { error: 'not_found' };
      const out = targetSummary(target);
      const edge = await deps.getEdgeDetection?.(ctx, id);
      if (edge) out.edge = edgeSummary(edge);
      const all = items(await deps.listTargets(ctx));
      const host = text(target.value).toLowerCase();
      if (host) out.subdomain_count = all.filter((row) => row.id !== target.id && text(row.value).toLowerCase().endsWith(`.${host}`)).length;
      out.recent_runs = items(await deps.listRuns(ctx, { target_id: id, limit: 10 })).map((run) => runSummary(run));
      return out;
    }
    case 'list_findings': {
      const options = { limit: limitArg(args?.limit, 100, 50) };
      for (const key of ['status', 'severity']) if (args?.[key]) options[key] = shortText(args[key], 40).toLowerCase();
      for (const key of ['target_id', 'check_id']) if (idArg(args?.[key])) options[key] = idArg(args[key]);
      const listed = await deps.listFindings(ctx, options);
      if (listed?.error) return { error: 'invalid_args', message: shortText(listed.message ?? listed.error, 200) };
      return { total: Number.isFinite(listed?.total) ? listed.total : items(listed).length, items: items(listed).map((row) => findingSummary(row)) };
    }
    case 'get_finding': {
      const id = idArg(args?.finding_id);
      if (!id) return { error: 'invalid_args', message: 'finding_id is required.' };
      const finding = await deps.getFinding(ctx, id);
      return finding ? findingSummary(finding, true) : { error: 'not_found' };
    }
    case 'list_runs': {
      const options = { limit: limitArg(args?.limit, 100, 25) };
      for (const key of ['target_id', 'check_id']) if (idArg(args?.[key])) options[key] = idArg(args[key]);
      const status = shortText(args?.status, 40).toLowerCase();
      const rows = items(await deps.listRuns(ctx, options)).filter((row) => !status || text(row.status).toLowerCase() === status);
      return { total: rows.length, items: rows.map((run) => runSummary(run)) };
    }
    case 'get_run': {
      const id = idArg(args?.run_id);
      if (!id) return { error: 'invalid_args', message: 'run_id is required.' };
      const run = await deps.getRun(ctx, id);
      return run ? runSummary(run, true) : { error: 'not_found' };
    }
    case 'list_checks': {
      const query = shortText(args?.query, 120).toLowerCase();
      const family = shortText(args?.vector_family, 40).toLowerCase();
      const rows = items(await deps.listChecks(ctx))
        .filter((row) => !query || `${text(row.check_id)} ${text(row.name)}`.toLowerCase().includes(query))
        .filter((row) => !family || text(row.vector_family).toLowerCase() === family);
      return { total: rows.length, items: rows.slice(0, limitArg(args?.limit, 100, 40)).map((row) => checkSummary(row)) };
    }
    case 'get_check': {
      const id = idArg(args?.check_id);
      if (!id) return { error: 'invalid_args', message: 'check_id is required.' };
      const check = await deps.getCheck(ctx, id);
      return check ? checkSummary(check, true) : { error: 'not_found' };
    }
    case 'get_readiness': {
      const state = await deps.getState(ctx);
      const readiness = state?.readiness ?? {};
      return {
        score: readiness.score ?? null,
        score_status: readiness.score_status ?? null,
        posture: readiness.posture ?? null,
        factors: (Array.isArray(readiness.factors) ? readiness.factors : []).map((factor) => pick(factor, ['key', 'label', 'weight', 'score', 'detail'])),
        open_findings: state?.open_findings ?? null,
      };
    }
    case 'get_edge_coverage': {
      const family = enumArg(args?.family, ['waf', 'cdn']);
      if (!family) return { error: 'invalid_args', message: 'family must be waf or cdn.' };
      const payload = await deps.getEdgeCoverage(ctx, family);
      if (!payload) return { error: 'not_available' };
      return {
        family,
        denominator: payload.denominator ?? null,
        segments: (Array.isArray(payload.segments) ? payload.segments : []).map((segment) => pick(segment, ['key', 'count'])),
        unknown_count: payload.unknown_count ?? null,
        as_of: payload.as_of ?? null,
      };
    }
    case 'list_schedules': {
      const rows = items(await deps.listSchedules(ctx));
      return { total: rows.length, items: rows.slice(0, 50).map((row) => pick(row, ['id', 'name', 'check_id', 'target_id', 'cadence', 'timezone', 'state', 'next_run_at', 'expected_verdict'])) };
    }
    case 'list_audit_events': {
      const listed = await deps.listAuditEvents(ctx, limitArg(args?.limit, 50, 25));
      return { items: items(listed).map((row) => pick(row, ['id', 'timestamp', 'action', 'actor_user_id', 'actor_role', 'resource_type', 'resource_id'])) };
    }
    case 'query_data':
      return queryData(ctx, args, deps);
    default:
      return { error: 'unknown_tool' };
  }
}

/**
 * Runs one data tool for a job owner. Returns { ok, result_text, data_result? } or { error, status }.
 * The result text is redacted, capped and fenced as untrusted data for the next prompt.
 */
export async function executeAssistantTool(ctx, name, args, deps, { nextDataId } = {}) {
  if (!isAssistantToolName(name)) return { error: 'unknown_tool', status: 400 };
  if (args !== undefined && args !== null && (typeof args !== 'object' || Array.isArray(args))) return { error: 'invalid_args', status: 400 };
  const permission = permissionFor(name, args ?? {});
  if (!permission) return { error: 'invalid_args', status: 400, message: 'dataset must be findings, targets, runs or checks.' };
  let result;
  if (!requirePermission(ctx, permission, { resource_type: 'assistant_tool', metadata: { tool: name } }).ok) {
    result = { error: 'permission_denied', permission };
  } else {
    try {
      result = await runTool(name, ctx, args ?? {}, deps);
    } catch {
      result = { error: 'tool_failed' };
    }
  }
  let dataResult = null;
  if (name === 'query_data' && result?.table) {
    dataResult = { id: nextDataId?.() ?? 'Q1', ...result.table };
    result = { data_result_id: dataResult.id, title: dataResult.title, total: result.total, columns: dataResult.columns.map((column) => column.key), rows: dataResult.rows.slice(0, 60), suggested_visual: dataResult.suggested_visual };
  }
  let json = redactSecrets(JSON.stringify(result ?? {}));
  if (json.length > TOOL_RESULT_MAX_CHARS) json = `${json.slice(0, TOOL_RESULT_MAX_CHARS)}…(truncated)`;
  return { ok: !result?.error, result_text: wrapUntrusted(`tool result ${name}`, json), data_result: dataResult, error_code: result?.error ?? null };
}
