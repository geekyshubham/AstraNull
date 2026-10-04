/**
 * Read-only GET /v1/evidence-context.
 *
 * The loader uses existing tenant-scoped reads (dev-json or injected Postgres services).
 * Postgres mode never falls through to the dev store. `resolveEvidenceContext` does not
 * start probes, advance scans, export, verify custody, or send notifications.
 *
 * Provider `subject.proof` arrays are strings only, capped at 16:
 * `{ matched_signals, methods, cnames, addresses, fingerprints }`.
 * Tokens are an allowlist: signal/method/fingerprint names, hostnames, or IPv4.
 * Cookie, Set-Cookie, and Authorization/Basic values are omitted. The summary
 * renderer drops arrays; read `subject.proof` directly.
 *
 * Additive operation fields (absent when nothing was recorded):
 * `request_summary.request_count` `{ status, requests_sent?, requests_sent_source?, requests_simulated?, requests_simulated_source? }`.
 * `request_summary.provenance` and `evaluation.provenance` `{ status, kind?, source_field?, live_external? }`.
 * `expected_behavior_source` is `verdict.expected_behavior` or `run.expected_behavior`.
 * A known event id outside the history window is `status: "referenced"` with `ref_status`
 * `missing` | `scope_conflict` | `multiple`, and `truncation.events.referenced_event_ids`,
 * `referenced_loaded`, `referenced_missing`. `evaluation.confidence` stays `external_only`.
 */

import { requirePermission } from '../rbac.mjs';
import { redactObject, redactString } from '../lib/redact.mjs';
import { scrubAgentPlacementText } from '../lib/outsideInEvidence.mjs';
import { presentProductDetectionEvidence } from '../lib/productDetectionEvidence.mjs';
import { getStore } from '../store.mjs';
import * as findings from './findings.mjs';
import * as testRuns from './testRuns.mjs';
import * as evidence from './evidence.mjs';
import * as reports from './reports.mjs';
import * as targetDetail from './targetDetail.mjs';
import { getTargetEdgeDetection } from './targetEdgeDetectionStore.mjs';

const ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const VERIFIED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const METHOD_RE = /^[a-z0-9_.:-]{1,64}$/;
const PROVIDER_FAMILIES = new Set(['cdn', 'waf', 'cloud', 'dns', 'origin_hosting']);
const FINALIZED_RUN = new Set(['verdicted', 'completed']);
const ENTRY_PERMISSION = {
  finding: 'finding:read',
  group_member: 'finding:read',
  check_result: 'test_run:read',
  provider: 'target_group:read',
  artifact: 'evidence:read',
  report: 'report:read',
  audit: 'audit:read',
};
const LIMITATIONS = ['external_only', 'bounded_check_not_capacity'];
const RUN_LIST_LIMIT = 20;
const EVIDENCE_LOAD_LIMIT = 32;
const EVENT_LIMIT = 20;
const EVENT_LOOKUP_LIMIT = 32;
const PROOF_LIST_LIMIT = 16;
const NAME_RE = /^[A-Za-z0-9_.:-]{1,80}$/;
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/i;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const CREDENTIAL_RE = /authorization|cookie|bearer\s|set-cookie|password|secret|\bbasic\s+[a-z0-9+/=]{8,}/i;
const SCOPE_FIELDS = ['tenant_id', 'test_run_id', 'target_id', 'check_id'];

const REQUEST_FIELDS = ['engine', 'method', 'http_method', 'path', 'protocol', 'max_requests', 'timeout_ms'];
const RESPONSE_FIELDS = ['external_result', 'status_code', 'response_status', 'received_at'];

function queryRecord(input) {
  if (!input) return {};
  if (typeof input.entries === 'function' && typeof input.get === 'function') {
    return Object.fromEntries(input.entries());
  }
  return input;
}

function exactId(value) {
  if (value == null || value === '') return null;
  const text = String(value);
  return ID_RE.test(text) ? text : undefined;
}

function collectIds(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const item of value) {
    if (typeof item !== 'string' || !ID_RE.test(item) || out.includes(item)) continue;
    out.push(item);
  }
  return out;
}

function capIds(ids, limit = EVIDENCE_LOAD_LIMIT) {
  const list = Array.isArray(ids) ? ids : [];
  const returned = list.slice(0, limit);
  return {
    ids: returned,
    source_count: list.length,
    returned: returned.length,
    limit,
    truncated: list.length > limit,
  };
}

function safeText(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  return scrubAgentPlacementText(redactString(value)).replace(/\?[^\s#]*/g, '').slice(0, 500);
}

function safeToken(value, max = 180) {
  if (typeof value !== 'string') return null;
  const text = redactString(value).replace(/\?[^\s#]*/g, '').replace(/[\r\n\t]/g, '').trim();
  if (!text || CREDENTIAL_RE.test(text)) return null;
  return text.slice(0, max);
}

function cleanPath(value) {
  if (typeof value !== 'string' || value === '') return null;
  const text = value.trim();
  try {
    if (text.includes('://')) {
      const url = new URL(text);
      return `${url.origin}${url.pathname}`;
    }
  } catch {
    // Fall through to a query strip. The raw query is never returned.
  }
  return text.split('?')[0].split('#')[0];
}

function primitive(value) {
  if (value == null) return null;
  const kind = typeof value;
  // Recorded operation fields are tokens, not prose. Do not recase them.
  if (kind === 'string') return redactString(value).replace(/\?[^\s#]*/g, '').slice(0, 200);
  if (kind === 'number' && Number.isFinite(value)) return value;
  if (kind === 'boolean') return value;
  return undefined;
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function finiteNumber(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  return null;
}

function deny(status, body) {
  return { status, body };
}

function notFound() {
  return deny(404, { error: 'not_found', state: 'not_found' });
}

function parseEvidenceQuery(input) {
  const query = queryRecord(input);
  if (query.group_id != null && query.group_id !== '') {
    return deny(400, { error: 'group_id_not_supported', state: 'unavailable' });
  }
  const entry = query.entry;
  if (!Object.hasOwn(ENTRY_PERMISSION, entry)) {
    return deny(400, { error: 'invalid_entry', state: 'unavailable' });
  }
  const ids = {};
  for (const key of ['finding_id', 'evidence_id', 'report_id', 'audit_id', 'target_id', 'check_id', 'test_run_id', 'verdict_id']) {
    if (query[key] == null || query[key] === '') continue;
    const id = exactId(query[key]);
    if (id === undefined) return deny(400, { error: 'invalid_id', field: key, state: 'unavailable' });
    ids[key] = id;
  }
  if (entry === 'finding' || entry === 'group_member') {
    if (!ids.finding_id) return deny(400, { error: 'missing_finding_id', state: 'unavailable' });
  } else if (entry === 'check_result') {
    if (!ids.target_id || !ids.check_id || !ids.test_run_id) {
      return deny(400, { error: 'missing_check_result_ids', state: 'unavailable' });
    }
  } else if (entry === 'provider') {
    if (!ids.target_id) return deny(400, { error: 'missing_target_id', state: 'unavailable' });
    if (!PROVIDER_FAMILIES.has(query.family)) {
      return deny(400, { error: 'invalid_family', state: 'unavailable' });
    }
    ids.family = query.family;
  } else if (entry === 'artifact') {
    if (!ids.evidence_id) return deny(400, { error: 'missing_evidence_id', state: 'unavailable' });
  } else if (entry === 'report') {
    if (!ids.report_id) return deny(400, { error: 'missing_report_id', state: 'unavailable' });
  } else if (entry === 'audit') {
    if (!ids.audit_id) return deny(400, { error: 'missing_audit_id', state: 'unavailable' });
  }
  return { entry, ids };
}

function missingRead(name) {
  return async () => {
    throw new Error(`missing_configured_read:${name}`);
  };
}

function bindReads(deps = {}) {
  const postgres = deps?.persistenceMode === 'postgres';
  const pick = (bag, name, devFn) => {
    const fn = typeof bag?.[name] === 'function' ? bag[name] : (postgres ? missingRead(name) : devFn);
    return fn.bind(bag ?? {});
  };
  return {
    getFinding: pick(deps.findings, 'getFinding', findings.getFinding),
    getTestRun: pick(deps.testRuns, 'getTestRun', testRuns.getTestRun),
    getRunEvents: (ctx, id, options) => pick(deps.testRuns, 'getRunEvents', testRuns.getRunEvents)(ctx, id, options),
    listTestRuns: (ctx, options) => pick(deps.testRuns, 'listTestRuns', testRuns.listTestRuns)(ctx, options),
    getEvidence: pick(deps.evidence, 'getEvidence', evidence.getEvidence),
    getReport: pick(deps.reports, 'getReport', reports.getReport),
    getTargetDetail: pick(deps.targetDetail, 'getTargetDetail', targetDetail.getTargetDetail),
    getAuditEntry: async (ctx, id) => {
      if (typeof deps.audit?.getAuditEntry === 'function') return deps.audit.getAuditEntry(ctx, id);
      if (postgres) throw new Error('missing_configured_read:getAuditEntry');
      return getStore().auditLog?.find((row) => row.tenant_id === ctx.tenantId && row.id === id) ?? null;
    },
    getEdgeDetection: async (ctx, targetId) => {
      if (typeof deps.evidence?.getTargetEdgeDetection === 'function') {
        return deps.evidence.getTargetEdgeDetection(ctx, targetId);
      }
      if (postgres) throw new Error('missing_configured_read:getTargetEdgeDetection');
      return getTargetEdgeDetection(ctx.tenantId, targetId);
    },
  };
}

function referencedEventIds(rows, runId) {
  const ids = [];
  const push = (value) => {
    if (typeof value !== 'string' || !ID_RE.test(value) || ids.includes(value) || ids.length >= EVENT_LOOKUP_LIMIT) return;
    ids.push(value);
  };
  for (const row of rows ?? []) {
    if (!row || (runId && row.test_run_id && row.test_run_id !== runId)) continue;
    push(row.related_event_id);
    push(row.probe_event_id);
    push(asObject(row.metadata)?.probe_event_id);
  }
  return ids;
}

function eventSeen(event, seen) {
  const id = eventIdOf(event);
  if (id) seen.add(id);
  if (typeof event?.event_id === 'string') seen.add(event.event_id);
}

async function loadEvents(ctx, reads, runId, scope = {}) {
  const referenced = referencedEventIds(scope.rows, runId);
  const base = {
    source_count: 0,
    returned: 0,
    limit: EVENT_LIMIT,
    truncated: false,
    referenced_event_ids: referenced,
    referenced_loaded: [],
    referenced_missing: referenced,
  };
  if (!runId) return { ...base, events: [] };
  const fetched = await reads.getRunEvents(ctx, runId, { limit: EVENT_LIMIT + 1 });
  if (!Array.isArray(fetched)) return { ...base, events: [] };
  const knownTotal = Number.isInteger(fetched.sourceCount) ? fetched.sourceCount : null;
  const truncated = knownTotal != null ? knownTotal > EVENT_LIMIT : fetched.length > EVENT_LIMIT;
  const history = fetched.slice(0, EVENT_LIMIT);
  const seen = new Set();
  history.forEach((event) => eventSeen(event, seen));
  const missing = referenced.filter((id) => !seen.has(id));
  const extras = [];
  if (missing.length) {
    const exact = await reads.getRunEvents(ctx, runId, {
      ids: missing,
      target_id: scope.target_id,
      check_id: scope.check_id,
    });
    if (Array.isArray(exact)) {
      for (const event of exact) {
        if ([event?.id, event?.event_id].some((value) => typeof value === 'string' && seen.has(value))) continue;
        extras.push(event);
        eventSeen(event, seen);
      }
    }
  }
  return {
    events: history.concat(extras),
    source_count: knownTotal != null ? knownTotal : (truncated ? null : history.length),
    returned: history.length,
    limit: EVENT_LIMIT,
    truncated,
    referenced_event_ids: referenced,
    referenced_loaded: referenced.filter((id) => seen.has(id)),
    referenced_missing: referenced.filter((id) => !seen.has(id)),
  };
}

async function loadEvidenceMap(ctx, reads, ids) {
  const evidenceById = new Map();
  const missingEvidenceIds = [];
  for (const id of ids) {
    const row = await reads.getEvidence(ctx, id);
    if (!row || (row.tenant_id && row.tenant_id !== ctx.tenantId)) missingEvidenceIds.push(id);
    else evidenceById.set(id, row);
  }
  return { evidenceById, missingEvidenceIds };
}

function sameTenant(row, ctx) {
  return row && (!row.tenant_id || row.tenant_id === ctx.tenantId);
}

function originAccepted(finding, run) {
  if (!finding?.tenant_id || !finding.target_id || !finding.check_id || !finding.test_run_id) return false;
  if (!run?.id || run.id !== finding.test_run_id) return false;
  if (run.tenant_id !== finding.tenant_id) return false;
  if (run.target_id !== finding.target_id || run.check_id !== finding.check_id) return false;
  return true;
}

function classifyRecorded(record, expected, requirePresent) {
  if (!record || typeof record !== 'object') return 'missing';
  let missing = false;
  for (const field of SCOPE_FIELDS) {
    if (!expected?.[field]) continue;
    const value = record[field];
    if (value == null || value === '') {
      if (requirePresent) missing = true;
      continue;
    }
    if (value !== expected[field]) return 'conflict';
  }
  return missing ? 'missing' : 'match';
}

async function loadSnapshot(ctx, parsed, reads) {
  const base = { entry: parsed.entry, tenantId: ctx.tenantId, ids: parsed.ids };
  if (parsed.entry === 'finding' || parsed.entry === 'group_member') {
    const finding = await reads.getFinding(ctx, parsed.ids.finding_id);
    if (!sameTenant(finding, ctx)) return { ...base, missing: true };
    if (parsed.ids.target_id && finding.target_id !== parsed.ids.target_id) return { ...base, missing: true };
    if (parsed.ids.check_id && finding.check_id !== parsed.ids.check_id) return { ...base, missing: true };
    if (parsed.ids.test_run_id && finding.test_run_id !== parsed.ids.test_run_id) return { ...base, missing: true };
    const originRaw = finding.test_run_id ? await reads.getTestRun(ctx, finding.test_run_id) : null;
    const linkage = originLinkage(finding, originRaw);
    const originRun = linkage === 'match' ? originRaw : null;
    const originVerdict = originRun?.verdict?.id && finding.verdict_id === originRun.verdict.id
      ? originRun.verdict
      : null;
    const findingIds = collectIds(finding.evidence_ids);
    const originIds = collectIds(originVerdict?.evidence_ids);
    if (parsed.ids.evidence_id && !findingIds.includes(parsed.ids.evidence_id) && !originIds.includes(parsed.ids.evidence_id)) {
      return { ...base, missing: true };
    }
    const laterRuns = finding.target_id && finding.check_id
      ? await reads.listTestRuns(ctx, {
        target_id: finding.target_id,
        check_id: finding.check_id,
        limit: RUN_LIST_LIMIT,
      })
      : [];
    const proofIds = findingIds.length ? findingIds : originIds;
    const alternativeIds = findingIds.length ? originIds.filter((id) => !findingIds.includes(id)) : [];
    const union = capIds([...new Set([...proofIds, ...alternativeIds])]);
    const loaded = await loadEvidenceMap(ctx, reads, union.ids);
    const window = await loadEvents(ctx, reads, finding.test_run_id, {
      rows: [...loaded.evidenceById.values()],
      target_id: finding.target_id,
      check_id: finding.check_id,
    });
    return {
      ...base,
      finding,
      originRun,
      originLinkage: linkage,
      laterRuns: Array.isArray(laterRuns) ? laterRuns : [],
      primaryIds: proofIds.filter((id) => union.ids.includes(id)),
      alternativeIds: alternativeIds.filter((id) => union.ids.includes(id)),
      evidenceRefs: {
        source_count: union.source_count,
        returned: union.returned,
        limit: union.limit,
        truncated: union.truncated,
      },
      events: window.events,
      eventWindow: window,
      ...loaded,
    };
  }
  if (parsed.entry === 'check_result') {
    const run = await reads.getTestRun(ctx, parsed.ids.test_run_id);
    if (!sameTenant(run, ctx) || run.target_id !== parsed.ids.target_id || run.check_id !== parsed.ids.check_id) {
      return { ...base, missing: true };
    }
    const proofIds = capIds(collectIds(run.verdict?.evidence_ids));
    const loaded = await loadEvidenceMap(ctx, reads, proofIds.ids);
    const window = await loadEvents(ctx, reads, run.id, {
      rows: [...loaded.evidenceById.values()],
      target_id: run.target_id,
      check_id: run.check_id,
    });
    return {
      ...base,
      originRun: run,
      primaryIds: proofIds.ids,
      alternativeIds: [],
      laterRuns: [],
      evidenceRefs: proofIds,
      events: window.events,
      eventWindow: window,
      ...loaded,
    };
  }
  if (parsed.entry === 'artifact') {
    const row = await reads.getEvidence(ctx, parsed.ids.evidence_id);
    if (!sameTenant(row, ctx)) return { ...base, missing: true };
    if (parsed.ids.test_run_id && row.test_run_id !== parsed.ids.test_run_id) return { ...base, missing: true };
    let originRun = null;
    if (row.test_run_id) {
      const run = await reads.getTestRun(ctx, row.test_run_id);
      if (run && !sameTenant(run, ctx)) return { ...base, missing: true };
      if (parsed.ids.target_id && run && run.target_id !== parsed.ids.target_id) return { ...base, missing: true };
      if (parsed.ids.check_id && run && run.check_id !== parsed.ids.check_id) return { ...base, missing: true };
      originRun = sameTenant(run, ctx) ? run : null;
    } else if (parsed.ids.target_id || parsed.ids.check_id) {
      return { ...base, missing: true };
    }
    if (parsed.ids.finding_id) {
      const finding = await reads.getFinding(ctx, parsed.ids.finding_id);
      if (!sameTenant(finding, ctx)) return { ...base, missing: true };
      const owned = new Set(collectIds(finding.evidence_ids));
      if (!owned.has(parsed.ids.evidence_id)) {
        const linked = finding.test_run_id ? await reads.getTestRun(ctx, finding.test_run_id) : null;
        const originIds = originAccepted(finding, linked) && linked.verdict?.id === finding.verdict_id
          ? collectIds(linked.verdict.evidence_ids)
          : [];
        if (!originIds.includes(parsed.ids.evidence_id)) return { ...base, missing: true };
      }
    }
    const window = await loadEvents(ctx, reads, row.test_run_id, {
      rows: [row],
      target_id: originRun?.target_id,
      check_id: originRun?.check_id,
    });
    return {
      ...base,
      artifact: row,
      originRun,
      primaryIds: [row.id],
      evidenceById: new Map([[row.id, row]]),
      missingEvidenceIds: [],
      evidenceRefs: { source_count: 1, returned: 1, limit: EVIDENCE_LOAD_LIMIT, truncated: false },
      events: window.events,
      eventWindow: window,
    };
  }
  if (parsed.entry === 'provider') {
    const detail = await reads.getTargetDetail(ctx, parsed.ids.target_id);
    if (!detail || detail.error || detail.target == null) return { ...base, missing: true };
    if (detail.target.tenant_id && detail.target.tenant_id !== ctx.tenantId) return { ...base, missing: true };
    const edge = await reads.getEdgeDetection(ctx, parsed.ids.target_id);
    const scopedEdge = sameTenant(edge, ctx) ? edge : null;
    const window = scopedEdge?.test_run_id ? await loadEvents(ctx, reads, scopedEdge.test_run_id) : {
      events: [], source_count: 0, returned: 0, limit: EVENT_LIMIT, truncated: false,
    };
    return {
      ...base,
      target: detail.target,
      edge: scopedEdge,
      events: window.events,
      eventWindow: window,
      evidenceRefs: { source_count: 0, returned: 0, limit: EVIDENCE_LOAD_LIMIT, truncated: false },
    };
  }
  if (parsed.entry === 'report') {
    const report = await reads.getReport(ctx, parsed.ids.report_id);
    if (!sameTenant(report, ctx)) return { ...base, missing: true };
    const summary = asObject(report.summary) ?? {};
    const runCap = capIds(collectIds(report.run_ids));
    const evidenceCap = capIds(collectIds(summary.evidence_ids));
    const loaded = await loadEvidenceMap(ctx, reads, evidenceCap.ids);
    return {
      ...base,
      report,
      summary,
      runIds: runCap.ids,
      runRefs: runCap,
      primaryIds: evidenceCap.ids,
      evidenceRefs: evidenceCap,
      events: [],
      eventWindow: { events: [], source_count: 0, returned: 0, limit: EVENT_LIMIT, truncated: false },
      ...loaded,
    };
  }
  const audit = await reads.getAuditEntry(ctx, parsed.ids.audit_id);
  if (!sameTenant(audit, ctx)) return { ...base, missing: true };
  return {
    ...base,
    audit,
    events: [],
    eventWindow: { events: [], source_count: 0, returned: 0, limit: EVENT_LIMIT, truncated: false },
    evidenceRefs: { source_count: 0, returned: 0, limit: EVIDENCE_LOAD_LIMIT, truncated: false },
  };
}

function digestOf(row) {
  const candidates = [row?.sha256, row?.content_sha256, row?.metadata?.sha256, row?.metadata?.digest];
  return candidates.find((value) => typeof value === 'string' && value.trim() !== '') ?? null;
}

function customerClaim(row) {
  if (row?.verified_at || row?.verify_method || row?.metadata?.verified_at || row?.metadata?.verify_method) return true;
  // A customer-named method on the row is a claim. It is not a stored verification.
  return asObject(row?.verification)?.method === 'customer_supplied';
}

function authoritativeVerification(row) {
  const verification = asObject(row?.verification);
  if (!verification || !row?.id) return null;
  if (typeof verification.method !== 'string' || !METHOD_RE.test(verification.method)) return null;
  if (verification.method === 'customer_supplied') return null;
  if (typeof verification.verified_at !== 'string' || !VERIFIED_AT_RE.test(verification.verified_at)) return null;
  const covered = Array.isArray(verification.covered_refs) ? verification.covered_refs : null;
  if (!covered || !covered.includes(row.id)) return null;
  if (verification.ok !== true && verification.ok !== false) return null;
  return { ok: verification.ok === true, method: verification.method, verified_at: verification.verified_at };
}

function refIntegrity(id, row) {
  const base = { evidence_id: id ?? null, verified_at: null, method: null };
  if (!row) return { ...base, status: 'not_recorded' };
  const auth = authoritativeVerification(row);
  if (auth?.ok === true) {
    return { evidence_id: row.id, status: 'verified', verified_at: auth.verified_at, method: auth.method };
  }
  if (auth?.ok === false) return { ...base, evidence_id: row.id, status: 'not_verified' };
  if (digestOf(row)) return { ...base, evidence_id: row.id, status: 'recorded_digest' };
  if (customerClaim(row)) return { ...base, evidence_id: row.id, status: 'not_verified' };
  return { ...base, evidence_id: row.id ?? id ?? null, status: 'not_recorded' };
}

function integrityFor(rows, evidenceIds) {
  const list = (rows ?? []).filter(Boolean);
  const ids = evidenceIds?.length ? evidenceIds : list.map((row) => row.id).filter(Boolean);
  const byId = new Map(list.map((row) => [row.id, row]));
  const refs = ids.map((id) => refIntegrity(id, byId.get(id) ?? null));
  let status = 'not_recorded';
  if (refs.length && refs.every((ref) => ref.status === 'verified')) status = 'verified';
  else if (refs.some((ref) => ref.status === 'recorded_digest')) status = 'recorded_digest';
  else if (refs.some((ref) => ref.status === 'not_verified' || ref.status === 'verified')) status = 'not_verified';
  const verified = refs.filter((ref) => ref.status === 'verified');
  const sameTime = status === 'verified' && new Set(verified.map((ref) => ref.verified_at)).size === 1;
  const sameMethod = status === 'verified' && new Set(verified.map((ref) => ref.method)).size === 1;
  return {
    status,
    verified_at: sameTime ? verified[0].verified_at : null,
    method: sameMethod ? verified[0].method : null,
    refs,
  };
}

function proof(testRunId, verdictId, evidenceIds, observedAt, rows) {
  return {
    test_run_id: testRunId ?? null,
    verdict_id: verdictId ?? null,
    evidence_ids: evidenceIds,
    observed_at: observedAt ?? null,
    integrity: integrityFor(rows, evidenceIds),
  };
}

function readNamed(event, field) {
  const layers = [
    ['metadata', asObject(event?.metadata)],
    ['request_snapshot', asObject(event?.request_snapshot)],
    ['event', event],
  ];
  for (const [label, source] of layers) {
    if (!source || typeof source !== 'object') continue;
    const value = source[field];
    if (typeof value === 'number' && Number.isFinite(value)) {
      return { value, source_field: label === 'event' ? field : `${label}.${field}` };
    }
    if (typeof value === 'string' && value.trim() !== '') {
      return { value: value.trim(), source_field: label === 'event' ? field : `${label}.${field}` };
    }
  }
  return null;
}

function liveExternal(field, kind) {
  if (field === 'manual_source' || field === 'simulation') return false;
  if (kind === 'internal_simulation' || kind === 'manual_declaration' || kind === 'customer_declaration' || kind === 'manual') return false;
  if (kind === 'signed_probe' || kind === 'external') return true;
  return null;
}

function provenanceFromLayers(layers) {
  for (const [source_field, value, field] of layers) {
    if (typeof value !== 'string' || value.trim() === '') continue;
    const kind = value.trim();
    return { status: 'recorded', kind, source_field, live_external: liveExternal(field, kind) };
  }
  return { status: 'not_recorded' };
}

function provenanceOfEvent(event) {
  const fields = ['provenance_kind', 'producer_kind', 'source_kind', 'manual_source', 'simulation'];
  const layers = [];
  for (const field of fields) {
    const found = readNamed(event, field);
    if (found && typeof found.value === 'string') layers.push([found.source_field, found.value, field]);
  }
  return provenanceFromLayers(layers);
}

function requestFacts(event) {
  const request_count = { status: 'not_recorded' };
  for (const field of ['requests_sent', 'requests_simulated']) {
    const found = readNamed(event, field);
    if (!found || typeof found.value !== 'number') continue;
    request_count.status = 'recorded';
    request_count[field] = found.value;
    request_count[`${field}_source`] = found.source_field;
  }
  return { request_count, provenance: provenanceOfEvent(event) };
}

function fieldsFromEvent(event, fields, kind) {
  const sources = [];
  if (asObject(event?.metadata)) sources.push(event.metadata);
  if (asObject(event?.request_snapshot)) sources.push(event.request_snapshot);
  sources.push(event);
  const projected = {};
  for (const source of sources) {
    if (!source || typeof source !== 'object') continue;
    for (const field of fields) {
      if (projected[field] != null) continue;
      const value = primitive(source[field]);
      if (value !== undefined && value !== null) projected[field] = value;
    }
  }
  if (kind === 'request') {
    if (projected.method == null && projected.http_method != null) projected.method = projected.http_method;
    delete projected.http_method;
    if (projected.path != null) projected.path = cleanPath(projected.path);
  }
  if (kind === 'response' && projected.response_status != null && projected.status_code == null) {
    projected.status_code = projected.response_status;
  }
  const keys = Object.keys(projected).filter((key) => projected[key] != null);
  const facts = kind === 'request' ? requestFacts(event) : null;
  const hasFacts = facts && (facts.request_count.status === 'recorded' || facts.provenance.status === 'recorded');
  if (keys.length === 0 && !hasFacts) return { status: 'not_recorded' };
  const eventId = typeof event?.id === 'string' ? event.id : (typeof event?.event_id === 'string' ? event.event_id : null);
  return { status: 'recorded', ...(eventId ? { event_id: eventId } : {}), ...projected, ...(facts ?? {}) };
}

function eventIdOf(event) {
  if (typeof event?.id === 'string') return event.id;
  if (typeof event?.event_id === 'string') return event.event_id;
  return null;
}

function findEventById(events, id) {
  return (events ?? []).find((event) => event?.id === id || event?.event_id === id) ?? null;
}

function referencedSummary(id, refStatus) {
  return { status: 'referenced', ...(id ? { event_id: id } : {}), ref_status: refStatus };
}

function projectOperation(events, evidenceRows, expected) {
  const alternatives = [];
  const matched = [];
  for (const event of events ?? []) {
    const scope = classifyRecorded(event, expected, true);
    const id = eventIdOf(event);
    if (scope === 'conflict') {
      alternatives.push({ event_id: id, relationship: 'scope_conflict' });
      continue;
    }
    if (scope !== 'match') {
      alternatives.push({ event_id: id, relationship: 'unmatched_operation' });
      continue;
    }
    matched.push(event);
  }
  const blank = { status: 'not_recorded' };
  const finish = (request, response, partial) => ({
    request,
    response,
    alternatives,
    partial: partial || alternatives.some((item) => item.relationship === 'scope_conflict'),
  });
  const relatedIds = referencedEventIds(evidenceRows, expected?.test_run_id);
  const pushUnmatched = (skip) => {
    for (const event of matched) {
      const id = eventIdOf(event);
      if (skip?.has(id) || skip?.has(event.event_id)) continue;
      alternatives.push({ event_id: id, relationship: 'unmatched_operation' });
    }
  };
  if (relatedIds.length > 1) {
    for (const id of relatedIds) {
      const chosen = matched.find((event) => event.id === id || event.event_id === id);
      if (chosen) {
        alternatives.push({
          event_id: id,
          relationship: 'correlated_operation',
          request_summary: fieldsFromEvent(chosen, REQUEST_FIELDS, 'request'),
          response_summary: fieldsFromEvent(chosen, RESPONSE_FIELDS, 'response'),
        });
        continue;
      }
      const seen = findEventById(events, id);
      const refStatus = seen && classifyRecorded(seen, expected, true) === 'conflict' ? 'scope_conflict' : 'missing';
      alternatives.push({
        event_id: id,
        relationship: refStatus === 'scope_conflict' ? 'scope_conflict' : 'correlated_operation',
        ref_status: refStatus,
      });
    }
    pushUnmatched(new Set(relatedIds));
    return finish(referencedSummary(null, 'multiple'), referencedSummary(null, 'multiple'), true);
  }
  if (relatedIds.length === 1) {
    const related = relatedIds[0];
    const chosen = matched.find((event) => event.id === related || event.event_id === related);
    pushUnmatched(new Set([related, chosen ? eventIdOf(chosen) : null].filter(Boolean)));
    if (!chosen) {
      const seen = findEventById(events, related);
      const refStatus = seen && classifyRecorded(seen, expected, true) === 'conflict' ? 'scope_conflict' : 'missing';
      if (!alternatives.some((item) => item.event_id === related)) {
        alternatives.push({
          event_id: related,
          relationship: refStatus === 'scope_conflict' ? 'scope_conflict' : 'correlated_operation',
          ref_status: refStatus,
        });
      }
      return finish(referencedSummary(related, refStatus), referencedSummary(related, refStatus), true);
    }
    return finish(
      fieldsFromEvent(chosen, REQUEST_FIELDS, 'request'),
      fieldsFromEvent(chosen, RESPONSE_FIELDS, 'response'),
      false,
    );
  }
  if (matched.length === 1) {
    return finish(
      fieldsFromEvent(matched[0], REQUEST_FIELDS, 'request'),
      fieldsFromEvent(matched[0], RESPONSE_FIELDS, 'response'),
      false,
    );
  }
  pushUnmatched();
  return finish(blank, blank, (events ?? []).length > 0);
}

function expectedFrom(verdict, run) {
  if (typeof verdict?.expected_behavior === 'string' && verdict.expected_behavior.trim() !== '') {
    return { expected_behavior: verdict.expected_behavior, expected_behavior_source: 'verdict.expected_behavior' };
  }
  if (typeof run?.expected_behavior === 'string' && run.expected_behavior.trim() !== '') {
    return { expected_behavior: run.expected_behavior, expected_behavior_source: 'run.expected_behavior' };
  }
  return { expected_behavior: null, expected_behavior_source: null };
}

function provenanceOfVerdict(verdict, run) {
  return provenanceFromLayers([
    ['verdict.provenance_kind', verdict?.provenance_kind, 'provenance_kind'],
    ['verdict.producer_kind', verdict?.producer_kind, 'producer_kind'],
    ['verdict.source_kind', verdict?.source_kind, 'source_kind'],
    ['run.provenance_kind', run?.provenance_kind, 'provenance_kind'],
    ['run.producer_kind', run?.producer_kind, 'producer_kind'],
    ['run.source_kind', run?.source_kind, 'source_kind'],
    ['run.manual_source', run?.manual_source, 'manual_source'],
    ['run.simulation', run?.simulation, 'simulation'],
  ]);
}

function projectEvaluation(verdict, run) {
  const expected = expectedFrom(verdict, run);
  const provenance = provenanceOfVerdict(verdict, run);
  if (!verdict || typeof verdict !== 'object') {
    if (expected.expected_behavior == null && provenance.status !== 'recorded') return { status: 'not_recorded' };
    return {
      status: 'recorded',
      ...expected,
      observed: null,
      verdict: null,
      reasons: [],
      rule_version: null,
      confidence: 'external_only',
      provenance,
    };
  }
  const reasons = Array.isArray(verdict.reasons)
    ? verdict.reasons.filter((reason) => typeof reason === 'string').slice(0, 16).map((reason) => safeText(reason)).filter(Boolean)
    : [];
  return {
    status: 'recorded',
    ...expected,
    observed: typeof verdict.observed === 'string' ? verdict.observed : (verdict.verdict ?? null),
    verdict: verdict.verdict ?? null,
    reasons,
    rule_version: typeof verdict.rule_version === 'string' ? verdict.rule_version : null,
    confidence: 'external_only',
    provenance,
  };
}

function answerFromVerdict(verdict, finding, run) {
  const expected = expectedFrom(verdict, run);
  return {
    outcome: verdict?.verdict ?? finding?.status ?? finding?.state ?? null,
    explanation: safeText(verdict?.explanation ?? finding?.notes ?? null),
    limitations: [...LIMITATIONS],
    expected_behavior: expected.expected_behavior,
    expected_behavior_source: expected.expected_behavior_source,
    observed_behavior: typeof verdict?.observed === 'string' ? verdict.observed : (verdict?.verdict ?? null),
  };
}

function laterQualifies(finding, run) {
  if (!finding?.tenant_id || !finding.target_id || !finding.check_id) return false;
  if (!run?.id || run.tenant_id !== finding.tenant_id) return false;
  if (run.target_id !== finding.target_id || run.check_id !== finding.check_id) return false;
  if (!FINALIZED_RUN.has(run.status)) return false;
  if (finding.test_run_id && run.id === finding.test_run_id) return false;
  const verdict = run.verdict;
  if (!verdict?.id || typeof verdict.verdict !== 'string' || verdict.verdict.trim() === '') return false;
  if (finding.verdict_id && verdict.id === finding.verdict_id) return false;
  if (verdict.tenant_id && verdict.tenant_id !== finding.tenant_id) return false;
  if (verdict.target_id && verdict.target_id !== finding.target_id) return false;
  if (verdict.check_id && verdict.check_id !== finding.check_id) return false;
  return collectIds(verdict.evidence_ids).length > 0;
}

function laterProof(run, relationship) {
  const verdict = run.verdict;
  const ids = capIds(collectIds(verdict.evidence_ids));
  return {
    test_run_id: run.id ?? null,
    verdict_id: verdict.id,
    evidence_ids: ids.ids,
    evidence_ref_count: ids.source_count,
    evidence_refs_truncated: ids.truncated,
    observed_at: verdict.created_at ?? run.completed_at ?? run.created_at ?? null,
    relationship,
    closes_finding: false,
  };
}

function selectLater(finding, runs) {
  const matches = (runs ?? []).filter((run) => laterQualifies(finding, run));
  matches.sort((left, right) => String(right.verdict?.created_at ?? right.created_at ?? '').localeCompare(
    String(left.verdict?.created_at ?? left.created_at ?? ''),
  ));
  return matches[0] ?? null;
}

function emptyProof() {
  return { matched_signals: [], methods: [], cnames: [], addresses: [], fingerprints: [] };
}

function cleanProofString(value) {
  if (typeof value !== 'string') return null;
  const text = value.replace(/[\r\n\t]/g, '').trim();
  if (!text || text.length > 180 || redactString(text) !== text || CREDENTIAL_RE.test(text) || text.includes('=')) return null;
  return text;
}

function credentialHeader(value) {
  return typeof value === 'string' && /^(cookie|set-cookie|authorization|proxy-authorization)$/i.test(value.trim());
}

function nameToken(value) {
  const text = cleanProofString(value);
  if (!text || !NAME_RE.test(text) || credentialHeader(text)) return null;
  return text;
}

function hostToken(value) {
  const text = cleanProofString(value);
  if (!text || !HOST_RE.test(text)) return null;
  return text;
}

function ipToken(value) {
  const text = cleanProofString(value);
  if (!text || !IPV4_RE.test(text)) return null;
  return text;
}

function recordedType(item) {
  if (!item || typeof item !== 'object') return null;
  const value = item.item_type ?? item.type ?? item.record_type;
  return typeof value === 'string' ? value.toLowerCase() : null;
}

function signalToken(item) {
  if (typeof item === 'string') return nameToken(item);
  if (!item || typeof item !== 'object') return null;
  if (credentialHeader(item.header ?? item.name ?? item.key)) return null;
  return nameToken(item.signal);
}

function methodToken(item) {
  if (typeof item === 'string') return nameToken(item);
  if (!item || typeof item !== 'object') return null;
  return nameToken(item.method ?? item.source);
}

function fingerprintToken(item) {
  if (typeof item === 'string') return nameToken(item);
  if (!item || typeof item !== 'object') return null;
  if (credentialHeader(item.header ?? item.name)) return null;
  return nameToken(item.fingerprint ?? item.name);
}

function cnameToken(item, arrayTyped) {
  if (typeof item === 'string') return arrayTyped ? hostToken(item) : null;
  if (!item || typeof item !== 'object') return null;
  const type = recordedType(item);
  if (type && type !== 'cname' && type !== 'domain') return null;
  if (!arrayTyped && !type && item.suffix == null && item.cname == null) return null;
  return hostToken(item.suffix ?? item.cname ?? (type || arrayTyped ? item.value : null));
}

function addressToken(item, arrayTyped) {
  if (typeof item === 'string') return arrayTyped ? ipToken(item) : null;
  if (!item || typeof item !== 'object') return null;
  const type = recordedType(item);
  if (type && type !== 'ip' && type !== 'address' && type !== 'ipv4' && type !== 'ipv6') return null;
  if (!arrayTyped && !type) return null;
  return ipToken(item.address ?? item.ip ?? item.value);
}

function pushProof(list, value) {
  if (typeof value !== 'string' || list.includes(value) || list.length >= PROOF_LIST_LIMIT) return;
  list.push(value);
}

function proofHasSignals(proof) {
  return proof.matched_signals.length + proof.cnames.length + proof.addresses.length + proof.fingerprints.length > 0;
}

function familyView(edge, family) {
  const json = asObject(edge?.evidence_json) ?? {};
  const explicit = asObject(json[family]);
  const layers = (Array.isArray(json.layers) ? json.layers : []).filter((layer) => layer?.family === family);
  const proof = emptyProof();
  const providers = [];
  const byProvider = new Map();
  const remember = (value) => {
    const token = safeToken(value);
    if (!token || providers.includes(token)) return token;
    providers.push(token);
    return token;
  };
  const bucket = (provider) => {
    const token = remember(provider);
    if (!token) return null;
    if (!byProvider.has(token)) byProvider.set(token, emptyProof());
    return byProvider.get(token);
  };
  const addScoped = (provider, listName, value) => {
    if (typeof value !== 'string') return;
    pushProof(proof[listName], value);
    const scoped = bucket(provider);
    if (scoped) pushProof(scoped[listName], value);
  };
  const proofToken = {
    matched_signals: (item) => signalToken(item),
    methods: (item) => methodToken(item),
    cnames: (item) => cnameToken(item, true),
    addresses: (item) => addressToken(item, true),
    fingerprints: (item) => fingerprintToken(item),
  };

  if (family === 'cdn') {
    remember(edge?.cdn_provider);
    for (const provider of Array.isArray(edge?.cdn_providers) ? edge.cdn_providers : []) remember(provider);
    pushProof(proof.methods, methodToken(edge?.cdn_type));
  } else if (family === 'waf') {
    remember(edge?.waf_vendor);
    for (const provider of Array.isArray(edge?.waf_providers) ? edge.waf_providers : []) remember(provider);
    pushProof(proof.methods, methodToken(edge?.waf_type));
  } else if (family === 'cloud') {
    for (const provider of Array.isArray(json.cloud_providers) ? json.cloud_providers : []) remember(provider);
  }

  for (const layer of layers) {
    remember(layer.provider);
    const scoped = bucket(layer.provider);
    for (const source of Array.isArray(layer.sources) ? layer.sources : []) {
      const token = methodToken(source);
      pushProof(proof.methods, token);
      if (scoped) pushProof(scoped.methods, token);
    }
    for (const signal of Array.isArray(layer.matched_signals) ? layer.matched_signals : []) {
      addScoped(layer.provider, 'matched_signals', signalToken(signal));
    }
  }

  if (explicit) {
    remember(explicit.provider);
    pushProof(proof.methods, methodToken(explicit.method));
    pushProof(proof.methods, methodToken(explicit.type));
    for (const key of Object.keys(proofToken)) {
      for (const item of Array.isArray(explicit[key]) ? explicit[key] : []) {
        addScoped(explicit.provider, key, proofToken[key](item));
      }
    }
  }

  const considerMatch = (item, listName, token) => {
    if (typeof item === 'string') {
      addScoped(null, listName, token);
      return;
    }
    if (!item || typeof item !== 'object') return;
    if (item.family && item.family !== family) return;
    addScoped(item.provider, listName, token);
  };
  if (family === 'cdn' || family === 'dns') {
    for (const item of Array.isArray(json.dns_cname_chain) ? json.dns_cname_chain : []) {
      considerMatch(item, 'cnames', cnameToken(item, true));
    }
    for (const item of Array.isArray(json.dns_resolved_ips) ? json.dns_resolved_ips : []) {
      considerMatch(item, 'addresses', addressToken(item, true));
    }
  }
  if (family === 'cdn') {
    for (const item of Array.isArray(json.cname_cdn_matches) ? json.cname_cdn_matches : []) {
      if (item?.family && item.family !== 'cdn') continue;
      considerMatch(item, 'cnames', cnameToken(item, false));
    }
    for (const item of Array.isArray(json.cname_matches) ? json.cname_matches : []) {
      if (item?.family && item.family !== 'cdn') continue;
      considerMatch(item, 'cnames', cnameToken(item, true));
    }
    for (const item of Array.isArray(json.address_matches) ? json.address_matches : []) {
      if (item?.family !== 'cdn') continue;
      considerMatch(item, 'addresses', addressToken(item, true));
    }
    const cdncheck = asObject(json.cdncheck);
    if (cdncheck) {
      remember(cdncheck.provider);
      pushProof(proof.methods, methodToken(cdncheck.source));
      const typed = recordedType(cdncheck);
      if (typed === 'ip' || typed === 'address' || typed === 'ipv4' || typed === 'ipv6') {
        addScoped(cdncheck.provider, 'addresses', addressToken(cdncheck, false));
      } else if (typed === 'cname' || typed === 'domain') {
        addScoped(cdncheck.provider, 'cnames', cnameToken(cdncheck, false));
      }
    }
  }
  if (family === 'waf') {
    for (const match of Array.isArray(json.vendor_matches) ? json.vendor_matches : []) {
      if (!asObject(match)) continue;
      remember(match.vendor);
      addScoped(match.vendor, 'fingerprints', fingerprintToken(match));
      for (const signal of Array.isArray(match.matched_signals) ? match.matched_signals : []) {
        addScoped(match.vendor, 'matched_signals', signalToken(signal));
      }
    }
    const firewall = asObject(json.wafw00f)?.firewall;
    if (typeof firewall === 'string' && firewall !== 'None') pushProof(proof.fingerprints, fingerprintToken(firewall));
  }

  const observed = Boolean(
    explicit || layers.length || providers.length || proof.methods.length || proofHasSignals(proof)
    || (family === 'cdn' && edge?.cdn_status) || (family === 'waf' && edge?.waf_status),
  );
  let status = 'not_recorded';
  let reason = null;
  if (family === 'cdn') status = edge?.cdn_status || 'not_recorded';
  else if (family === 'waf') status = edge?.waf_status || 'not_recorded';
  else if (family === 'origin_hosting') {
    status = explicit?.status || 'unknown';
    if (!explicit && layers.length === 0) reason = 'no_origin_hosting_observation';
  } else status = explicit?.status || 'not_recorded';
  if (!reason && typeof explicit?.reason === 'string') reason = safeToken(explicit.reason);

  const layerConfidence = layers.map((layer) => finiteNumber(layer.confidence)).filter((value) => value != null);
  let confidence = null;
  if (layerConfidence.length === 1) confidence = layerConfidence[0];
  else if (explicit && finiteNumber(explicit.confidence) != null && layerConfidence.length === 0) {
    confidence = finiteNumber(explicit.confidence);
  } else if ((family === 'cdn' || family === 'waf') && observed && layerConfidence.length === 0) {
    confidence = finiteNumber(edge?.confidence);
  }
  let conflict = null;
  if (observed) {
    conflict = providers.length > 1;
    if (family === 'waf' && edge?.conflicting_vendor_signals === true) conflict = true;
    if (family === 'cdn' && json.conflicting_provider_signals === true) conflict = true;
    if (layers.some((layer) => layer.conflicting === true)) conflict = true;
    if (explicit?.conflict === true || explicit?.conflicting === true) conflict = true;
  }
  let corpus = null;
  if (observed && !(family === 'origin_hosting' && !explicit && layers.length === 0)) {
    corpus = safeToken(explicit?.corpus ?? explicit?.corpus_version);
    if (!corpus && (family === 'cdn' || family === 'waf')) corpus = safeToken(edge?.corpus_version);
  }
  const observedAt = typeof explicit?.observed_at === 'string'
    ? explicit.observed_at
    : (observed && !(family === 'origin_hosting' && !explicit) ? (edge?.observed_at ?? null) : null);
  const product = safeToken(explicit?.product) ?? (layers.length === 1 ? safeToken(layers[0].display_name) : null);
  const alternatives = [...byProvider.entries()].map(([provider, scoped]) => ({
    relationship: 'provider_layer',
    provider,
    status,
    confidence: finiteNumber(layers.find((layer) => layer.provider === provider)?.confidence) ?? confidence,
    conflict,
    corpus,
    observed_at: observedAt,
    ...scoped,
  }));
  for (const provider of providers) {
    if (byProvider.has(provider)) continue;
    alternatives.push({
      relationship: 'provider_layer',
      provider,
      status,
      confidence,
      conflict,
      corpus,
      observed_at: observedAt,
      ...emptyProof(),
    });
  }
  return {
    status,
    provider: providers.length === 1 ? providers[0] : null,
    product,
    source: proof.methods.length === 1 ? proof.methods[0] : 'not_recorded',
    reason,
    test_run_id: observed && !(family === 'origin_hosting' && !explicit && layers.length === 0)
      ? (explicit?.test_run_id ?? edge?.test_run_id ?? null)
      : null,
    observed_at: observedAt,
    confidence,
    conflict,
    corpus,
    proof,
    alternatives,
    has_proof: proofHasSignals(proof),
  };
}

function rowsFor(ids, evidenceById) {
  return (ids ?? []).map((id) => evidenceById?.get(id)).filter(Boolean);
}

function originLinkage(finding, run) {
  if (!finding?.test_run_id) return 'missing';
  if (!run) return 'missing';
  if (run.id !== finding.test_run_id) return 'conflict';
  for (const field of ['tenant_id', 'target_id', 'check_id']) {
    if (!finding[field] || !run[field]) return 'missing';
    if (run[field] !== finding[field]) return 'conflict';
  }
  return 'match';
}

function partitionEvidence(ids, evidenceById, expected, linkage = 'match') {
  const accepted = [];
  const alternatives = [];
  let partial = false;
  for (const id of ids ?? []) {
    const row = evidenceById?.get(id) ?? null;
    if (!row) continue;
    const tiedToUnprovenRun = linkage !== 'match' && expected?.test_run_id && row.test_run_id === expected.test_run_id;
    const scope = classifyRecorded(row, expected, false);
    const runMissing = Boolean(expected?.test_run_id) && !row.test_run_id;
    const tenantMissing = Boolean(expected?.tenant_id) && !row.tenant_id;
    if (scope === 'conflict' || (tiedToUnprovenRun && linkage === 'conflict')) {
      alternatives.push({ evidence_id: id, relationship: 'scope_conflict' });
      partial = true;
      continue;
    }
    if (scope === 'missing' || runMissing || tenantMissing || tiedToUnprovenRun) {
      alternatives.push({ evidence_id: id, relationship: 'unbound_evidence' });
      partial = true;
      continue;
    }
    accepted.push(row);
  }
  return { accepted, alternatives, partial };
}

function truncationOf(snapshot) {
  const evidenceRefs = snapshot.evidenceRefs ?? {
    source_count: (snapshot.primaryIds ?? []).length,
    returned: (snapshot.primaryIds ?? []).length,
    limit: EVIDENCE_LOAD_LIMIT,
    truncated: false,
  };
  const events = snapshot.eventWindow ?? {
    source_count: (snapshot.events ?? []).length,
    returned: (snapshot.events ?? []).length,
    limit: EVENT_LIMIT,
    truncated: false,
  };
  const body = {
    evidence_refs: {
      source_count: evidenceRefs.source_count,
      returned: evidenceRefs.returned,
      limit: evidenceRefs.limit,
      truncated: evidenceRefs.truncated === true,
    },
    events: {
      source_count: events.source_count ?? null,
      returned: events.returned ?? (snapshot.events ?? []).length,
      limit: events.limit ?? EVENT_LIMIT,
      truncated: events.truncated === true,
      referenced_event_ids: events.referenced_event_ids ?? [],
      referenced_loaded: events.referenced_loaded ?? [],
      referenced_missing: events.referenced_missing ?? [],
    },
  };
  if (snapshot.runRefs) {
    body.run_refs = {
      source_count: snapshot.runRefs.source_count,
      returned: snapshot.runRefs.returned,
      limit: snapshot.runRefs.limit,
      truncated: snapshot.runRefs.truncated === true,
    };
  }
  return body;
}

function envelope(snapshot, fields) {
  const missingEvidenceIds = fields.missingEvidenceIds ?? [];
  const reason = Object.hasOwn(fields, 'unavailable_reason')
    ? fields.unavailable_reason
    : (missingEvidenceIds.length || fields.partial ? 'partial' : (!fields.primary ? 'no_refs' : null));
  const body = {
    entry: snapshot.entry,
    tenant_id: snapshot.tenantId,
    subject: fields.subject,
    answer: fields.answer,
    primary: fields.primary ?? null,
    latest_distinct: fields.latest_distinct ?? null,
    alternatives: fields.alternatives ?? [],
    request_summary: fields.request_summary ?? { status: 'not_recorded' },
    response_summary: fields.response_summary ?? { status: 'not_recorded' },
    evaluation: fields.evaluation ?? { status: 'not_recorded' },
    unavailable_reason: reason,
    state: reason === 'partial' ? 'partial' : reason === 'no_refs' ? 'no_refs' : 'ready',
    truncation: truncationOf(snapshot),
  };
  if (snapshot.entry === 'finding' || snapshot.entry === 'group_member') {
    body.originating = fields.originating ?? null;
    body.latest_same_check = fields.latest_same_check ?? null;
  }
  if (missingEvidenceIds.length) body.missing_evidence_ids = missingEvidenceIds;
  return { status: 200, body: presentProductDetectionEvidence(redactObject(body, 0, { omitSensitiveKeys: true })) };
}

function snapshotScore(summary) {
  const value = summary?.readiness_score ?? summary?.score;
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function snapshotFactors(summary) {
  const value = summary?.readiness_factors ?? summary?.factors;
  if (Array.isArray(value)) return value.slice(0, 32);
  return asObject(value);
}

function snapshotAsOf(summary) {
  const value = summary?.as_of ?? summary?.generated_at;
  return typeof value === 'string' && value.trim() !== '' ? value : null;
}

function storedId(value) {
  return typeof value === 'string' && ID_RE.test(value) ? value : null;
}

function recordedReportPrimary(report, summary, runIds, evidenceIds) {
  const runId = storedId(summary?.primary_test_run_id) ?? storedId(report?.primary_test_run_id);
  const evidenceId = storedId(summary?.primary_evidence_id) ?? storedId(report?.primary_evidence_id);
  const run = runId && runIds.includes(runId) ? runId : null;
  const evidenceIdOk = evidenceId && evidenceIds.includes(evidenceId) ? evidenceId : null;
  if (!run && !evidenceIdOk) return null;
  return { run, evidence: evidenceIdOk };
}

/**
 * @param {object} snapshot tenant-scoped records already loaded for one entry
 * @returns {{ status: number, body: object }}
 */
export function resolveEvidenceContext(snapshot) {
  if (!snapshot || snapshot.missing) return notFound();
  const events = snapshot.events ?? [];

  if (snapshot.entry === 'finding' || snapshot.entry === 'group_member') {
    const finding = snapshot.finding;
    const expected = {
      tenant_id: finding.tenant_id || snapshot.tenantId,
      target_id: finding.target_id ?? null,
      check_id: finding.check_id ?? null,
      test_run_id: finding.test_run_id ?? null,
    };
    const linkage = snapshot.originLinkage ?? originLinkage(finding, snapshot.originRun);
    const originOk = linkage === 'match';
    const verdict = originOk && snapshot.originRun.verdict?.id === finding.verdict_id ? snapshot.originRun.verdict : null;
    const primaryIds = snapshot.primaryIds ?? [];
    const partitioned = partitionEvidence(primaryIds, snapshot.evidenceById, expected, linkage);
    const operation = linkage === 'conflict'
      ? {
        request: { status: 'not_recorded' },
        response: { status: 'not_recorded' },
        alternatives: events.map((event) => ({ event_id: eventIdOf(event), relationship: 'scope_conflict' })),
        partial: true,
      }
      : projectOperation(events, partitioned.accepted, expected);
    const primary = primaryIds.length
      ? proof(
        finding.test_run_id ?? null,
        finding.verdict_id ?? null,
        primaryIds,
        finding.created_at ?? verdict?.created_at ?? null,
        partitioned.accepted,
      )
      : null;
    const later = selectLater(finding, snapshot.laterRuns);
    const pointerDiffers = Boolean(finding.last_verdict_id) && finding.last_verdict_id !== finding.verdict_id;
    const pointed = pointerDiffers
      ? (snapshot.laterRuns ?? []).find((run) => run?.verdict?.id === finding.last_verdict_id)
      : null;
    const latestDistinct = pointed && laterQualifies(finding, pointed)
      ? laterProof(pointed, 'later_run_same_target_check')
      : null;
    const latestSame = later ? laterProof(later, 'later_run_same_target_check') : null;
    const partial = partitioned.partial || operation.partial || (Boolean(finding.test_run_id) && !originOk)
      || snapshot.evidenceRefs?.truncated === true || snapshot.eventWindow?.truncated === true;
    return envelope(snapshot, {
      subject: {
        finding_id: finding.id,
        target_id: finding.target_id ?? null,
        check_id: finding.check_id ?? null,
        ...(snapshot.entry === 'group_member' ? { member_finding_id: finding.id } : {}),
      },
      answer: answerFromVerdict(verdict, finding, originOk ? snapshot.originRun : null),
      primary,
      originating: {
        test_run_id: finding.test_run_id ?? null,
        verdict_id: finding.verdict_id ?? null,
        evidence_ids: primaryIds,
        observed_at: finding.created_at ?? verdict?.created_at ?? null,
      },
      latest_distinct: latestDistinct,
      latest_same_check: latestSame,
      alternatives: [
        ...(snapshot.alternativeIds ?? []).map((id) => ({ evidence_id: id, relationship: 'originating_verdict_evidence' })),
        ...partitioned.alternatives,
        ...operation.alternatives,
      ],
      request_summary: operation.request,
      response_summary: operation.response,
      evaluation: projectEvaluation(verdict, originOk ? snapshot.originRun : null),
      missingEvidenceIds: snapshot.missingEvidenceIds ?? [],
      partial: partial || (snapshot.missingEvidenceIds ?? []).length > 0,
    });
  }

  if (snapshot.entry === 'check_result') {
    const run = snapshot.originRun;
    if (!run || (snapshot.ids?.target_id && run.target_id !== snapshot.ids.target_id)) return notFound();
    if (snapshot.ids?.check_id && run.check_id !== snapshot.ids.check_id) return notFound();
    if (run.tenant_id && snapshot.tenantId && run.tenant_id !== snapshot.tenantId) return notFound();
    const expected = {
      tenant_id: run.tenant_id || snapshot.tenantId,
      target_id: run.target_id,
      check_id: run.check_id,
      test_run_id: run.id,
    };
    const primaryIds = snapshot.primaryIds ?? [];
    const partitioned = partitionEvidence(primaryIds, snapshot.evidenceById, expected);
    const operation = projectOperation(events, partitioned.accepted, expected);
    const verdict = run.verdict ?? null;
    const primary = primaryIds.length
      ? proof(run.id, verdict?.id ?? null, primaryIds, verdict?.created_at ?? run.completed_at ?? null, partitioned.accepted)
      : null;
    const partial = partitioned.partial || operation.partial || snapshot.evidenceRefs?.truncated === true;
    return envelope(snapshot, {
      subject: { target_id: run.target_id, check_id: run.check_id, test_run_id: run.id },
      answer: answerFromVerdict(verdict, null, run),
      primary,
      latest_distinct: null,
      alternatives: [...partitioned.alternatives, ...operation.alternatives],
      request_summary: operation.request,
      response_summary: operation.response,
      evaluation: projectEvaluation(verdict, run),
      missingEvidenceIds: snapshot.missingEvidenceIds ?? [],
      partial,
    });
  }

  if (snapshot.entry === 'artifact') {
    const row = snapshot.artifact;
    const expected = {
      tenant_id: snapshot.tenantId,
      test_run_id: row.test_run_id ?? null,
      target_id: snapshot.originRun?.target_id ?? snapshot.ids?.target_id ?? null,
      check_id: snapshot.originRun?.check_id ?? snapshot.ids?.check_id ?? null,
    };
    const operation = projectOperation(events, [row], expected);
    return envelope(snapshot, {
      subject: { evidence_id: row.id, test_run_id: row.test_run_id ?? null },
      answer: {
        outcome: null,
        explanation: safeText(row.label ?? null),
        limitations: [...LIMITATIONS],
        expected_behavior: null,
        expected_behavior_source: null,
        observed_behavior: null,
      },
      primary: proof(row.test_run_id ?? null, null, [row.id], row.created_at ?? null, [row]),
      latest_distinct: null,
      alternatives: operation.alternatives,
      request_summary: operation.request,
      response_summary: operation.response,
      evaluation: { status: 'not_recorded' },
      missingEvidenceIds: [],
      partial: operation.partial,
    });
  }

  if (snapshot.entry === 'provider') {
    const view = familyView(snapshot.edge, snapshot.ids.family);
    const expected = {
      tenant_id: snapshot.tenantId,
      target_id: snapshot.ids.target_id,
      test_run_id: view.test_run_id,
    };
    const operation = projectOperation(events, [], expected);
    const primary = view.has_proof
      ? proof(view.test_run_id, null, [], view.observed_at, [])
      : null;
    const classes = [];
    if (view.proof.matched_signals.length) classes.push('matched_signals');
    if (view.proof.cnames.length) classes.push('cname');
    if (view.proof.addresses.length) classes.push('address');
    if (view.proof.fingerprints.length) classes.push('fingerprint');
    return envelope(snapshot, {
      subject: {
        target_id: snapshot.ids.target_id,
        family: snapshot.ids.family,
        status: view.status,
        provider: view.provider,
        product: view.product,
        source: view.source,
        reason: view.reason,
        confidence: view.confidence,
        conflict: view.conflict,
        corpus: view.corpus,
        observed_at: view.observed_at,
        proof: view.proof,
      },
      answer: {
        outcome: view.status,
        explanation: classes.length ? classes.join(', ') : null,
        limitations: [...LIMITATIONS],
        expected_behavior: null,
        expected_behavior_source: null,
        observed_behavior: view.status,
      },
      primary,
      latest_distinct: null,
      alternatives: [...view.alternatives, ...operation.alternatives],
      request_summary: operation.request,
      response_summary: operation.response,
      evaluation: view.has_proof
        ? {
          status: 'recorded',
          provider: view.provider,
          confidence: view.confidence,
          conflict: view.conflict,
          corpus: view.corpus,
          observed_at: view.observed_at,
        }
        : { status: 'not_recorded' },
      unavailable_reason: view.has_proof ? (operation.partial ? 'partial' : null) : 'no_refs',
    });
  }

  if (snapshot.entry === 'report') {
    const report = snapshot.report;
    const summary = asObject(snapshot.summary) ?? {};
    const asOf = snapshotAsOf(summary);
    const runIds = snapshot.runIds ?? [];
    const primaryIds = snapshot.primaryIds ?? [];
    const recorded = recordedReportPrimary(report, summary, runIds, primaryIds);
    const accepted = recorded?.evidence
      ? rowsFor([recorded.evidence], snapshot.evidenceById)
      : [];
    const primary = recorded
      ? proof(recorded.run, null, recorded.evidence ? [recorded.evidence] : [], asOf, accepted)
      : null;
    const hasRefs = runIds.length > 0 || primaryIds.length > 0;
    return envelope(snapshot, {
      subject: {
        report_id: report.id,
        as_of: asOf,
        score: snapshotScore(summary),
        factors: snapshotFactors(summary),
        run_ids: runIds,
        evidence_ids: primaryIds,
      },
      answer: {
        outcome: report.status ?? null,
        explanation: safeText(report.title ?? null),
        limitations: [...LIMITATIONS],
        expected_behavior: null,
        expected_behavior_source: null,
        observed_behavior: null,
      },
      primary,
      latest_distinct: null,
      alternatives: [
        ...runIds.map((id) => ({ test_run_id: id, relationship: 'report_snapshot_run' })),
        ...primaryIds.map((id) => ({
          evidence_id: id,
          relationship: 'report_snapshot_evidence',
          integrity: integrityFor(rowsFor([id], snapshot.evidenceById), [id]),
        })),
      ],
      request_summary: { status: 'not_recorded' },
      response_summary: { status: 'not_recorded' },
      evaluation: { status: 'not_recorded' },
      missingEvidenceIds: snapshot.missingEvidenceIds ?? [],
      unavailable_reason: (snapshot.missingEvidenceIds ?? []).length
        ? 'partial'
        : (hasRefs ? null : 'no_refs'),
    });
  }

  const audit = snapshot.audit;
  return envelope(snapshot, {
    subject: {
      audit_id: audit.id,
      actor_user_id: audit.actor_user_id ?? null,
      actor_role: audit.actor_role ?? null,
      action: audit.action ?? null,
      resource_type: audit.resource_type ?? null,
      resource_id: audit.resource_id ?? null,
      timestamp: audit.timestamp ?? null,
    },
    answer: {
      outcome: audit.action ?? null,
      explanation: 'Audit action record. It does not prove an infrastructure fix.',
      limitations: [...LIMITATIONS],
      expected_behavior: null,
      expected_behavior_source: null,
      observed_behavior: null,
    },
    primary: null,
    latest_distinct: null,
    alternatives: [],
    request_summary: { status: 'not_recorded' },
    response_summary: { status: 'not_recorded' },
    evaluation: { status: 'not_recorded' },
    unavailable_reason: null,
  });
}

/**
 * Permission is checked before any record read. `deps` may be the dev service map or
 * the Postgres runtime services (`findings`, `testRuns`, `evidence`, `reports`, `targetDetail`, `audit`).
 *
 * @param {{ tenantId: string, userId?: string, role?: string }} ctx
 * @param {URLSearchParams | Record<string, string>} query
 * @param {object} [deps]
 */
export async function getEvidenceContext(ctx, query, deps = {}) {
  const parsed = parseEvidenceQuery(query);
  if (parsed.status) return parsed;
  const evidenceGate = requirePermission(ctx, 'evidence:read', {
    resource_type: 'evidence_context',
    resource_id: parsed.entry,
  });
  if (!evidenceGate.ok) {
    return { status: evidenceGate.status, body: { ...evidenceGate.body, state: 'denied' } };
  }
  const entryPermission = ENTRY_PERMISSION[parsed.entry];
  if (entryPermission !== 'evidence:read') {
    const gate = requirePermission(ctx, entryPermission, {
      resource_type: 'evidence_context',
      resource_id: parsed.entry,
    });
    if (!gate.ok) return { status: gate.status, body: { ...gate.body, state: 'denied' } };
  }
  try {
    const snapshot = await loadSnapshot(ctx, parsed, bindReads(deps));
    return resolveEvidenceContext(snapshot);
  } catch {
    return {
      status: 503,
      body: { error: 'unavailable', unavailable_reason: 'fetch_failed', state: 'unavailable' },
    };
  }
}
