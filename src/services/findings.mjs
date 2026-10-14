import { audit } from '../audit.mjs';
import {
  buildFindingListEnvelope,
  findingListQueryFailure,
  findingMatchesListQuery,
  parseFindingListQuery,
} from '../lib/findingList.mjs';
import { planFindingPatch, planFixVerifiedFromRetest, computeDenyRulesDigest } from '../lib/findingLifecycle.mjs';
import { controlDeclarationsFromTarget } from '../contracts/controlDeclarations.mjs';
import { newId } from '../lib/ids.mjs';
import { scrubFindingForCustomer } from '../lib/outsideInEvidence.mjs';
import { getStore, persistStore } from '../store.mjs';
import { emitNotificationIfSubscribed } from './notifications.mjs';
import { presentFindingLineage } from './retestLineage.mjs';
import {
  applyProtectionFindingPatch,
  dedupeProtectionFindingCandidates,
  deriveProtectionFindingCandidates,
  isProtectionValidationFinding,
  planProtectionFindingUpsert,
  protectionFindingClosureSignal,
  protectionRetestRunScopeMatches,
  toProtectionFindingRow,
} from '../lib/protectionValidationFindings.mjs';

export { FINDING_LIFECYCLE, authorizeFindingWrite, planFindingPatch, planFixVerifiedFromRetest } from '../lib/findingLifecycle.mjs';
export { applyProtectionFindingPatch } from '../lib/protectionValidationFindings.mjs';

export function upsertFindingFromVerdict(ctx, verdict, run, target) {
  const store = getStore();
  const existing = store.findings.find(
    (f) =>
      f.tenant_id === ctx.tenantId &&
      (f.target_group_id ?? null) === (run.target_group_id ?? null) &&
      f.target_id === target.id &&
      f.check_id === run.check_id &&
      f.status === 'open' &&
      !isProtectionValidationFinding(f),
  );
  if (existing) {
    existing.last_verdict_id = verdict.id;
    existing.system_summary = verdict.explanation ?? existing.system_summary ?? null;
    existing.updated_at = new Date().toISOString();
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'finding.updated',
      resource_type: 'finding',
      resource_id: existing.id,
    });
    persistStore();
    return existing;
  }
  const finding = {
    id: newId('finding'),
    tenant_id: ctx.tenantId,
    target_group_id: run.target_group_id,
    target_id: target.id,
    check_id: run.check_id,
    check_version: run.check_version ?? verdict.check_version ?? null,
    grading_version: verdict.grading_version ?? run.grading_version ?? run.provenance_json?.grading_version ?? null,
    source_perspective: verdict.source_perspective ?? run.source_perspective ?? run.probe_metadata?.source_perspective ?? null,
    test_run_id: run.id,
    verdict_id: verdict.id,
    title: `Finding: ${verdict.verdict} on ${target.value}`,
    severity: verdict.severity ?? 'medium',
    status: 'open',
    assignee: null,
    notes: null,
    system_summary: verdict.explanation ?? null,
    evidence_ids: verdict.evidence_ids,
    declaration_digest: computeDenyRulesDigest(controlDeclarationsFromTarget(target)),
    declared_deny_ports: run?.probe_metadata?.declared_deny_ports ?? run?.probe_metadata?.ports_probed ?? (run?.probe_metadata?.port != null ? [Number(run.probe_metadata.port)] : []),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  store.findings.push(finding);
  if (['high', 'critical'].includes(finding.severity)) {
    // Parity with Postgres: record only for subscribed tenants, never fail finding creation.
    emitNotificationIfSubscribed(ctx, {
      trigger: 'finding.high_severity',
      subject: finding.title,
      metadata: { finding_id: finding.id, severity: finding.severity, verdict_id: verdict.id },
    });
  }
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.created',
    resource_type: 'finding',
    resource_id: finding.id,
  });
  persistStore();
  return finding;
}

function stampFrom(run, verdict) {
  return {
    check_version: run?.check_version ?? verdict?.check_version ?? null,
    grading_version: verdict?.grading_version ?? run?.grading_version ?? run?.provenance_json?.grading_version ?? null,
  };
}

/** Complete passing retest closes matching open/in_progress findings. Partial or inconclusive never close. */
export function applyPassingRetestToFindings(ctx, { verdict, run, target = null, now = new Date() } = {}) {
  const store = getStore();
  const at = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
  const closed = [];
  const targetId = target?.id ?? run?.target_id ?? verdict?.target_id ?? null;
  const decls = controlDeclarationsFromTarget(target);
  for (const finding of store.findings ?? []) {
    if (finding.tenant_id !== ctx.tenantId) continue;
    if (!['open', 'in_progress'].includes(finding.status)) continue;
    if (finding.check_id !== run?.check_id) continue;
    if (finding.target_id && targetId && finding.target_id !== targetId) continue;
    if (isProtectionValidationFinding(finding) && !protectionRetestRunScopeMatches(finding, run)) continue;
    const plan = planFixVerifiedFromRetest({ finding, run, verdict, declarations: decls, now });
    if (plan.action !== 'fix_verified') continue;
    Object.assign(finding, plan.patch, stampFrom(run, verdict));
    finding.updated_at = at;
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId ?? 'system',
      actor_role: ctx.role ?? 'system',
      action: 'finding.fix_verified',
      resource_type: 'finding',
      resource_id: finding.id,
      metadata: {
        verifying_run_id: run?.id ?? null,
        verdict_id: verdict?.id ?? null,
        check_id: run?.check_id ?? null,
        ...(plan.verification_basis ? { verification_basis: plan.verification_basis } : {}),
      },
    });
    closed.push(finding.id);
  }
  if (closed.length) persistStore();
  return { closed };
}

/**
 * Derive deduplicated findings from a recorded, digest-verified comparison evaluation.
 * A complete passing retest of the same scope and versions moves open findings to fix_verified.
 */
export function upsertProtectionFindingsFromEvaluation(ctx, evaluation, {
  entryPaths = [],
  expectations = [],
  baseline = null,
  now = new Date(),
} = {}) {
  const derived = deriveProtectionFindingCandidates({ evaluation, entryPaths, expectations, baseline });
  if (!derived.ok) return { ok: false, error: derived.error, created: [], updated: [], retained: [] };
  const store = getStore();
  const at = new Date(now).toISOString();
  const created = [];
  const updated = [];
  const retained = [];
  for (const candidate of dedupeProtectionFindingCandidates(derived.candidates)) {
    if (candidate.tenant_id !== ctx.tenantId) continue;
    const existing = store.findings.filter((row) => row.tenant_id === ctx.tenantId && isProtectionValidationFinding(row));
    const plan = planProtectionFindingUpsert({ existingFindings: existing, candidate });
    const auditMeta = {
      source: 'protection_validation',
      dedupe_key: candidate.dedupe_key,
      finding_class: candidate.finding_class,
      evaluation_id: candidate.comparison_context.evaluation_id,
      upsert_action: plan.action,
    };
    if (plan.action === 'create') {
      const row = toProtectionFindingRow(candidate, { id: newId('finding'), now: at, upsert: plan });
      store.findings.push(row);
      created.push(row.id);
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId ?? 'system',
        actor_role: ctx.role ?? 'system',
        action: 'finding.created',
        resource_type: 'finding',
        resource_id: row.id,
        metadata: auditMeta,
      });
      if (['high', 'critical'].includes(row.severity)) {
        emitNotificationIfSubscribed(ctx, {
          trigger: 'finding.high_severity',
          subject: row.title,
          metadata: { finding_id: row.id, severity: row.severity, source: 'protection_validation' },
        });
      }
      continue;
    }
    if (['escalate', 'record_observation', 'exception_retained'].includes(plan.action) && plan.finding_id) {
      const index = store.findings.findIndex((row) => row.id === plan.finding_id && row.tenant_id === ctx.tenantId);
      if (index < 0) continue;
      store.findings[index] = applyProtectionFindingPatch(store.findings[index], plan.patch ?? {}, at);
      (plan.action === 'exception_retained' ? retained : updated).push(plan.finding_id);
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId ?? 'system',
        actor_role: ctx.role ?? 'system',
        action: 'finding.updated',
        resource_type: 'finding',
        resource_id: plan.finding_id,
        metadata: auditMeta,
      });
    }
  }
  const verified = [];
  for (const observation of derived.passing ?? []) {
    for (const row of store.findings.filter((finding) => finding.tenant_id === ctx.tenantId && isProtectionValidationFinding(finding))) {
      const signal = protectionFindingClosureSignal({ finding: row, passingObservation: observation });
      if (signal.action !== 'fix_verified' || !signal.finding_id) continue;
      const index = store.findings.findIndex((finding) => finding.id === signal.finding_id && finding.tenant_id === ctx.tenantId);
      if (index < 0) continue;
      const current = store.findings[index];
      if (!['open', 'in_progress'].includes(current.status)) continue;
      store.findings[index] = {
        ...current,
        status: 'fix_verified',
        closed_at: current.closed_at ?? at,
        verifying_run_id: signal.verifying_run_id ?? observation.test_run_id ?? null,
        updated_at: at,
      };
      verified.push(signal.finding_id);
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId ?? 'system',
        actor_role: ctx.role ?? 'system',
        action: 'finding.fix_verified',
        resource_type: 'finding',
        resource_id: signal.finding_id,
        metadata: {
          source: 'protection_validation',
          dedupe_key: observation.dedupe_key,
          verifying_run_id: signal.verifying_run_id ?? observation.test_run_id ?? null,
          evaluation_id: observation.evaluation_id,
        },
      });
    }
  }
  if (created.length || updated.length || retained.length || verified.length) persistStore();
  return { ok: true, error: null, created, updated, retained, verified, passing: derived.passing.length, skipped: derived.skipped.length };
}

function groupMemberIds(tenantId, groupId) {
  const ids = new Set();
  if (!groupId) return ids;
  for (const target of getStore().targets ?? []) {
    if (target.tenant_id !== tenantId || target.id == null) continue;
    if (target.target_group_id !== groupId || target.deleted_at) continue;
    ids.add(target.id);
  }
  return ids;
}

function selectFindings(ctx, query) {
  const members = groupMemberIds(ctx.tenantId, query.target_group_id);
  const rows = getStore().findings.filter((row) => (
    row.tenant_id === ctx.tenantId && findingMatchesListQuery(row, query, members)
  ));
  rows.sort((left, right) =>
    String(right.created_at ?? right.opened_at ?? '').localeCompare(
      String(left.created_at ?? left.opened_at ?? ''),
    ) || String(right.id ?? '').localeCompare(String(left.id ?? '')),
  );
  if (query.limit == null) return query.offset ? rows.slice(query.offset) : rows;
  return rows.slice(query.offset, query.offset + query.limit);
}

export function listFindings(ctx, options = {}) {
  const query = parseFindingListQuery(options, { paginate: false });
  // EVIDENCE-01 / ADR-0008: customer list items must read external-only — scrub notes/remediation.
  return selectFindings(ctx, query).map(scrubFindingForCustomer);
}

export function listFindingsEnvelope(ctx, options = {}) {
  let query;
  try {
    query = parseFindingListQuery(options, { paginate: true });
  } catch (err) {
    const failure = findingListQueryFailure(err);
    if (failure) return failure;
    throw err;
  }
  const matched = selectFindings(ctx, { ...query, limit: null, offset: 0 });
  const items = matched.slice(query.offset, query.offset + query.limit).map(scrubFindingForCustomer);
  return buildFindingListEnvelope(items, matched.length, query);
}

/** Live store row for internal mutation (patch). Not customer-facing — never scrubbed. */
function findFindingRow(ctx, id) {
  return getStore().findings.find((f) => f.id === id && f.tenant_id === ctx.tenantId) ?? null;
}

export function getFinding(ctx, id) {
  const row = findFindingRow(ctx, id);
  // EVIDENCE-01 / ADR-0008: customer finding detail must read external-only. Scrub the projection;
  // the stored row (returned by findFindingRow for mutation) is untouched.
  if (!row) return null;
  const view = scrubFindingForCustomer(row);
  const store = getStore();
  const lineage = (store.findingRetestLineage ?? []).filter((item) => item.tenant_id === ctx.tenantId && item.finding_id === row.id);
  const runs = (store.testRuns ?? []).filter((item) => item.tenant_id === ctx.tenantId);
  const siblings = (store.findings ?? []).filter((item) => item.tenant_id === ctx.tenantId
    && item.id !== row.id
    && item.check_id === row.check_id);
  const presented = presentFindingLineage({ finding: row, runs, lineage, siblings });
  view.closed_at = row.closed_at ?? null;
  view.risk_acceptance = row.risk_acceptance ?? null;
  view.lineage = presented;
  view.retests = presented.retests;
  view.originating = presented.originating;
  view.latest = presented.latest;
  return view;
}

export function patchFinding(ctx, id, body) {
  const f = findFindingRow(ctx, id);
  if (!f) return null;
  const planned = planFindingPatch(body, ctx, { findingId: id });
  if (planned.error) return planned;
  if (planned.patch.status) f.status = planned.patch.status;
  if (planned.patch.risk_acceptance !== undefined) f.risk_acceptance = planned.patch.risk_acceptance;
  if (planned.patch.closed_at === null) f.closed_at = null;
  else if (planned.patch.closed_at && !f.closed_at) f.closed_at = planned.patch.closed_at;
  if (planned.patch.status === 'open' || planned.patch.status === 'in_progress') {
    f.verification_basis = null;
  }
  if (body.assignee !== undefined) f.assignee = body.assignee;
  if (body.notes !== undefined) f.notes = body.notes;
  f.updated_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.updated',
    resource_type: 'finding',
    resource_id: id,
    metadata: body,
  });
  persistStore();
  // Scrub the customer-facing PATCH response; the stored row stays as mutated above.
  return scrubFindingForCustomer(f);
}

/**
 * Evidence bundle hydrator stub (portal revamp §4.2).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} findingId
 */
export function getEvidenceBundle(ctx, findingId) {
  const finding = getFinding(ctx, findingId);
  if (!finding) {
    return {
      finding: null,
      bundle: null,
      artifacts: [],
      custody_chain: [],
      verify_url: '/v1/custody/verify',
      meta: { empty_reason: 'finding_not_found', finding_id: findingId },
    };
  }

  const vault = (getStore().evidenceVault ?? []).filter(
    (row) => row.tenant_id === ctx.tenantId && row.test_run_id === finding.test_run_id,
  );
  const bundles = (getStore().evidenceBundles ?? []).filter(
    (row) => row.tenant_id === ctx.tenantId && (row.finding_id === findingId || row.test_run_id === finding.test_run_id),
  );
  const bundle = bundles[0] ?? null;

  if (!bundle && vault.length === 0) {
    return {
      finding: { id: finding.id, title: finding.title ?? null, run_id: finding.test_run_id ?? null },
      bundle: null,
      artifacts: [],
      custody_chain: [],
      verify_url: '/v1/custody/verify',
      meta: { empty_reason: 'no_evidence_bundle_sealed_for_finding', finding_id: findingId },
    };
  }

  const artifacts = vault.map((row) => ({
    id: row.id,
    kind: row.label ?? row.kind ?? 'metadata_evidence',
    run_id: row.test_run_id ?? finding.test_run_id ?? null,
    sha256: row.sha256 ?? row.content_sha256 ?? row.metadata?.sha256 ?? null,
    sealed_at: row.sealed_at ?? row.created_at ?? null,
    size_bytes: row.size_bytes ?? row.metadata?.size_bytes ?? null,
  }));

  const custody_chain = artifacts
    .filter((art) => art.sha256)
    .map((art, index) => ({
      step: index + 1,
      kind: `${art.kind}_sealed`,
      sha256: art.sha256,
      at: art.sealed_at,
    }));

  const response = {
    finding: { id: finding.id, title: finding.title ?? null, run_id: finding.test_run_id ?? null },
    bundle: bundle
      ? {
          id: bundle.id,
          sha256: bundle.sha256,
          sealed_at: bundle.sealed_at,
          size_bytes: bundle.size_bytes,
          custody_schema_version: bundle.custody_schema_version ?? 'astranull.custody.v1',
        }
      : null,
    artifacts,
    custody_chain,
    verify_url: '/v1/custody/verify',
  };
  if (!bundle && artifacts.length === 0) {
    response.meta = { empty_reason: 'no_evidence_bundle_sealed_for_finding', finding_id: findingId };
  }
  return response;
}