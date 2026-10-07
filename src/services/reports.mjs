import {
  audit,
  getLatestChainedAuditEntry,
  getLatestChainedAuditEntryForTenant,
} from '../audit.mjs';
import { buildCustodyManifest } from '../lib/custody.mjs';
import { getCheckById } from '../contracts/checks.mjs';
import { redactObject } from '../lib/redact.mjs';
import {
  scrubAgentPlacementText,
  scrubReportSummaryForCustomer,
  scrubVerdictForReportExport,
} from '../lib/outsideInEvidence.mjs';
import { newId } from '../lib/ids.mjs';
import {
  buildProtectionValidationReport,
  protectionValidationReportCsv,
} from '../lib/protectionValidationReport.mjs';
import { getStore, persistStore } from '../store.mjs';
import { computeReadiness } from './readiness.mjs';
import { listSocNotes } from './highScale.mjs';
import { emitNotificationIfSubscribed } from './notifications.mjs';
import {
  buildComplianceMapping,
  buildHtmlComplianceSection,
  buildMarkdownComplianceSection,
} from '../contracts/complianceReports.mjs';
import {
  MAX_CAPTURED_RUNS,
  MAX_DECLARED_MEMBERS,
  MAX_SNAPSHOT_EVIDENCE,
  MAX_SNAPSHOT_FINDINGS,
  asArray,
  buildGeneratedReportRecord,
  compareNewest,
  isActiveGroup,
  isActiveTarget,
  parseReportCreateBody,
  readinessExportText,
  reportExportSources,
  reportPeriodBounds,
  rowInstantMs,
  runInstantMs,
  withinPeriod,
} from '../lib/reportSnapshot.mjs';

export {
  MAX_CAPTURED_RUNS,
  MAX_DECLARED_MEMBERS,
  MAX_REPORT_SCOPE_IDS,
  MAX_SNAPSHOT_EVIDENCE,
  MAX_SNAPSHOT_FINDINGS,
  buildGeneratedReportRecord,
  parseReportCreateBody,
  readinessExportText,
  reportExportSources,
  reportPeriodBounds,
  worldFromListSamples,
} from '../lib/reportSnapshot.mjs';

function decorateMember(target, group) {
  return {
    id: target.id,
    target_group_id: target.target_group_id ?? null,
    kind: target.kind ?? null,
    value: target.value ?? null,
    deleted_at: target.deleted_at ?? null,
    declaration: target.declaration ?? target.declaration_json ?? {},
    group_declaration: group?.declaration ?? group?.declaration_json ?? {},
  };
}

/**
 * In-memory world for the dev store. Postgres `readReportGenerationWorld` returns the same shape.
 * @param {Record<string, unknown[]>} store
 */
export function loadDevReportWorld(store, tenantId, parsed, bounds) {
  const targets = asArray(store.targets).filter((row) => row.tenant_id === tenantId);
  const groups = asArray(store.targetGroups).filter((row) => row.tenant_id === tenantId);
  const groupById = new Map(groups.map((row) => [row.id, row]));
  const runs = asArray(store.testRuns).filter((row) => row.tenant_id === tenantId);
  const findings = asArray(store.findings).filter((row) => row.tenant_id === tenantId);
  const verdicts = asArray(store.verdicts).filter((row) => row.tenant_id === tenantId);
  const evidence = asArray(store.evidenceVault).filter((row) => row.tenant_id === tenantId);

  const foundTargets = parsed.targetIds
    ? parsed.targetIds.map((id) => targets.find((row) => row.id === id)).filter(Boolean)
    : null;
  const foundGroups = parsed.targetGroupIds
    ? parsed.targetGroupIds.map((id) => groups.find((row) => row.id === id)).filter(Boolean)
    : null;
  const foundRuns = parsed.runIds
    ? parsed.runIds.map((id) => runs.find((row) => row.id === id)).filter(Boolean)
    : null;

  let memberPool;
  if (parsed.targetIds) {
    memberPool = (foundTargets ?? []).filter((row) => isActiveTarget(row));
  } else if (parsed.targetGroupIds) {
    const wanted = new Set(parsed.targetGroupIds);
    memberPool = targets.filter((row) => isActiveTarget(row) && wanted.has(row.target_group_id) && isActiveGroup(groupById.get(row.target_group_id)));
  } else {
    memberPool = targets.filter((row) => isActiveTarget(row) && isActiveGroup(groupById.get(row.target_group_id)));
  }
  const memberTotal = memberPool.length;
  const memberRows = parsed.targetIds || parsed.targetGroupIds
    ? memberPool
    : memberPool.slice().sort((left, right) => String(left.id).localeCompare(String(right.id))).slice(0, MAX_DECLARED_MEMBERS);

  const scopeTargetIds = parsed.targetIds
    ? new Set(parsed.targetIds)
    : parsed.targetGroupIds
      ? new Set(memberPool.map((row) => row.id))
      : null;
  const scopeGroupIds = parsed.targetGroupIds ? new Set(parsed.targetGroupIds) : null;
  const inRunScope = (run) => {
    if (scopeTargetIds && !scopeTargetIds.has(run.target_id)) return false;
    if (scopeGroupIds && !scopeGroupIds.has(run.target_group_id)) return false;
    return true;
  };
  const scopedRuns = parsed.runIds ? foundRuns ?? [] : runs.filter(inRunScope);
  const windowedRuns = parsed.runIds
    ? scopedRuns
    : scopedRuns.filter((run) => withinPeriod(runInstantMs(run), bounds) === true);
  const includedRuns = parsed.runIds
    ? []
    : windowedRuns.slice().sort(compareNewest(runInstantMs)).slice(0, MAX_CAPTURED_RUNS);

  const inFindingScope = (finding) => {
    if (scopeTargetIds && !scopeTargetIds.has(finding.target_id)) return false;
    if (scopeGroupIds && !scopeGroupIds.has(finding.target_group_id)) return false;
    if (parsed.runIds && !parsed.runIds.includes(finding.test_run_id)) return false;
    return true;
  };
  const scopedFindings = findings.filter(inFindingScope);
  const windowedFindings = scopedFindings.filter((finding) => withinPeriod(rowInstantMs(finding, ['created_at']), bounds) === true);
  const includedFindings = windowedFindings
    .slice()
    .sort(compareNewest((finding) => rowInstantMs(finding, ['created_at'])))
    .slice(0, MAX_SNAPSHOT_FINDINGS);

  const includedRunIds = new Set((parsed.runIds ? parsed.runIds : includedRuns.map((run) => run.id)));
  const includedVerdicts = verdicts.filter((verdict) => includedRunIds.has(verdict.test_run_id));
  const evidencePool = evidence.filter((row) => includedRunIds.has(row.test_run_id));

  return {
    legacy: false,
    found_targets: foundTargets,
    found_groups: foundGroups,
    found_runs: foundRuns,
    members: memberRows.map((row) => decorateMember(row, groupById.get(row.target_group_id))),
    member_total: memberTotal,
    runs: includedRuns,
    run_total: parsed.runIds ? parsed.runIds.length : windowedRuns.length,
    run_total_unwindowed: parsed.runIds ? parsed.runIds.length : scopedRuns.length,
    findings: includedFindings,
    finding_total: windowedFindings.length,
    finding_total_unwindowed: scopedFindings.length,
    open_finding_total: windowedFindings.filter((finding) => finding.status === 'open').length,
    verdicts: includedVerdicts,
    evidence: evidencePool.slice(0, MAX_SNAPSHOT_EVIDENCE),
    evidence_total: evidencePool.length,
  };
}

/**
 * Passive protection-validation projection over already-loaded tenant records (dev or Postgres).
 * It never runs checks, records evaluations, or emits notifications.
 */
export function buildProtectionValidationReportProjection({
  tenantId,
  generatedAt = new Date(),
  targets = [],
  entryPaths = [],
  expectations = [],
  evaluations = [],
  detections = [],
  checkCatalog = [],
  scope = {},
  format = 'json',
} = {}) {
  const owned = (rows) => asArray(rows).filter((row) => row?.tenant_id === tenantId);
  const tenantExpectations = owned(expectations);
  const tenantEvaluations = owned(evaluations);
  const report = buildProtectionValidationReport({
    tenantId,
    generatedAt,
    targets: owned(targets),
    entryPaths: owned(entryPaths),
    pathEvaluations: tenantEvaluations.filter((row) => row.kind === 'path_validation'),
    pathExpectations: tenantExpectations.filter((row) => row.kind === 'path_validation'),
    firewallExpectations: tenantExpectations.filter((row) => row.kind === 'firewall_change'),
    firewallEvaluations: tenantEvaluations.filter((row) => row.kind === 'firewall_change'),
    detections,
    checkCatalog,
    scope,
  });
  if (format === 'csv') return { format: 'csv', content: protectionValidationReportCsv(report), report_kind: report.report_kind };
  return report;
}

export function createReport(ctx, body) {
  const parsed = parseReportCreateBody(body);
  if (!parsed.ok) return parsed.error;
  const now = new Date().toISOString();
  const store = getStore();
  const world = loadDevReportWorld(store, ctx.tenantId, parsed.value, reportPeriodBounds(parsed.value.period, now));
  const readiness = parsed.value.explicit ? null : computeReadiness(ctx.tenantId);
  const built = buildGeneratedReportRecord({
    ctx,
    parsed: parsed.value,
    world,
    readiness,
    now,
    id: newId('report'),
    readinessSource: 'published_tenant_formula',
  });
  if (!built.ok) return built.error;
  const report = built.record;
  store.reports.push(report);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'report.generated',
    resource_type: 'report',
    resource_id: report.id,
  });
  persistStore();
  emitNotificationIfSubscribed(ctx, {
    trigger: 'report.ready',
    subject: `Report ready: ${report.title}`,
    metadata: { report_id: report.id, kind: report.kind },
  });
  return projectReport(report);
}

/** Reports stored before `period` existed must still read back with an explicit null. */
function projectReport(report) {
  if (!report) return report;
  return { ...report, period: report.period ?? report.summary?.period ?? null };
}

export function getReport(ctx, id) {
  const report = getStore().reports.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  return report ? projectReport(report) : null;
}

export function listReports(ctx, options = {}) {
  const limitValue = Number(options.limit ?? 100);
  const limit = Number.isFinite(limitValue) && limitValue > 0 ? Math.min(Math.floor(limitValue), 500) : 100;
  return getStore().reports
    .filter((r) => r.tenant_id === ctx.tenantId)
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
    .slice(0, limit)
    .map(projectReport);
}

function buildExportPayload(ctx, report) {
  const frozen = reportExportSources(report);
  const store = getStore();
  const runs = frozen.frozen
    ? frozen.runs
    : (report.run_ids ?? [])
      .map((rid) => store.testRuns.find((r) => r.id === rid && r.tenant_id === ctx.tenantId))
      .filter(Boolean);
  const verdicts = frozen.frozen
    ? frozen.verdicts
    : runs.map((r) => store.verdicts.find((v) => v.test_run_id === r.id)).filter(Boolean);
  const hs = store.highScaleRequests.filter((h) => h.tenant_id === ctx.tenantId);
  const socNotes = hs.flatMap((h) => listSocNotes(ctx, h.id) ?? []);
  const complianceMapping = buildComplianceMapping(report.kind);
  return redactObject({
    report_id: report.id,
    title: report.title,
    kind: report.kind,
    // EVIDENCE-01 / ADR-0008: strip obsolete agent/placement keys and the legacy
    // "Agent placement & health" readiness factor from the customer-facing summary. Stored
    // summary is untouched; this is an export-time projection only.
    summary: scrubReportSummaryForCustomer(report.summary),
    compliance_mapping: complianceMapping,
    runs: runs.map((r) => ({
      id: r.id,
      check_id: r.check_id,
      vector_family: r.vector_family ?? getCheckById(r.check_id)?.vector_family,
      safety_class: r.safety_class ?? getCheckById(r.check_id)?.safety_class,
      status: r.status,
    })),
    // EVIDENCE-01 / ADR-0008: customer-facing export must read as external-probe only. Drop the
    // legacy `placement_confidence` field name and rewrite agent/placement wording in the
    // explanation; preserve verdict/confidence/evidence linkage (no fabricated evidence).
    verdicts: verdicts.map((v) =>
      scrubVerdictForReportExport({
        test_run_id: v.test_run_id,
        verdict: v.verdict,
        confidence: v.confidence,
        placement_confidence: v.placement_confidence ?? null,
        evidence_ids: v.evidence_ids,
        explanation: v.explanation,
      }),
    ),
    soc_notes: socNotes.map((n) => ({ request_id: n.high_scale_request_id, body: n.body, at: n.created_at })),
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function collectReportExportSubjectIds(report, payload) {
  const ids = new Set([report.id]);
  for (const r of payload.runs ?? []) {
    if (r.id) ids.add(r.id);
  }
  for (const v of payload.verdicts ?? []) {
    if (v.test_run_id) ids.add(v.test_run_id);
    for (const eid of v.evidence_ids ?? []) {
      if (eid) ids.add(eid);
    }
  }
  return [...ids];
}

function custodyAuditMetadata(custody) {
  return {
    format: custody.format,
    content_sha256: custody.content_sha256,
    custody_schema_version: custody.schema_version,
  };
}

function buildMarkdownCustodySection(custody) {
  const lines = [
    '## Custody',
    `- artifact_id: ${custody.artifact_id}`,
    `- content_sha256: ${custody.content_sha256}`,
    `- canonicalization: ${custody.content_canonicalization}`,
    `- created_at: ${custody.created_at}`,
  ];
  if (custody.previous_audit_hash) {
    lines.push(`- previous_audit_hash: ${custody.previous_audit_hash}`);
  }
  return lines;
}

function buildHtmlCustodySection(custody) {
  const prev = custody.previous_audit_hash
    ? `<li>previous_audit_hash: ${escapeHtml(custody.previous_audit_hash)}</li>`
    : '';
  return `<h2>Custody</h2>
<ul>
<li>artifact_id: ${escapeHtml(custody.artifact_id)}</li>
<li>content_sha256: ${escapeHtml(custody.content_sha256)}</li>
<li>canonicalization: ${escapeHtml(custody.content_canonicalization)}</li>
<li>created_at: ${escapeHtml(custody.created_at)}</li>
${prev}
</ul>`;
}

function buildHtmlExport(payload, custody) {
  const runs = (payload.runs ?? [])
    .map(
      (r) =>
        `<tr><td>${escapeHtml(r.id)}</td><td>${escapeHtml(r.check_id)}</td><td>${escapeHtml(r.vector_family ?? '')}</td><td>${escapeHtml(r.status)}</td></tr>`,
    )
    .join('');
  const verdicts = (payload.verdicts ?? [])
    .map(
      (v) =>
        `<tr><td>${escapeHtml(v.test_run_id)}</td><td>${escapeHtml(v.verdict)}</td><td>${escapeHtml((v.evidence_ids ?? []).join(', '))}</td></tr>`,
    )
    .join('');
  const socNotes = (payload.soc_notes ?? [])
    .map((n) => `<li>${escapeHtml(n.at)}: ${escapeHtml(n.body)}</li>`)
    .join('');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(payload.title)}</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a;line-height:1.5}
h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:1.5rem}
table{border-collapse:collapse;width:100%;margin:0.5rem 0}
th,td{border:1px solid #ccc;padding:0.4rem 0.6rem;text-align:left;font-size:0.9rem}
th{background:#f4f4f4}
.muted{color:#555;font-size:0.85rem}
.score{font-size:2rem;font-weight:600}
</style>
</head>
<body>
<h1>${escapeHtml(payload.title)}</h1>
<p class="muted">AstraNull readiness report · kind: ${escapeHtml(payload.kind)} · metadata-only export</p>
<p>Readiness score: <span class="score">${escapeHtml(readinessExportText(payload.summary))}</span></p>
<p>Open findings: ${escapeHtml(String(payload.summary?.open_findings ?? 0))}</p>
<h2>Recent runs</h2>
<table><thead><tr><th>Run</th><th>Check</th><th>Vector</th><th>Status</th></tr></thead><tbody>${runs || '<tr><td colspan="4">None</td></tr>'}</tbody></table>
<h2>Verdicts</h2>
<table><thead><tr><th>Run</th><th>Verdict</th><th>Evidence</th></tr></thead><tbody>${verdicts || '<tr><td colspan="3">None</td></tr>'}</tbody></table>
<h2>SOC notes</h2>
<ul>${socNotes || '<li>None</li>'}</ul>
${buildHtmlComplianceSection(payload.compliance_mapping)}
${buildHtmlCustodySection(custody)}
<p class="muted">Secrets redacted. No external assets. Review this export before sharing outside your organization.</p>
</body>
</html>`;
}

export function exportReport(ctx, id, format) {
  const report = getReport(ctx, id);
  if (!report) return null;
  const payload = buildExportPayload(ctx, report);
  const exportFormat = format === 'html' || format === 'markdown' ? format : 'json';
  const priorGlobal = getLatestChainedAuditEntry();
  const priorTenant = getLatestChainedAuditEntryForTenant(ctx.tenantId);
  const custody = buildCustodyManifest({
    tenant_id: ctx.tenantId,
    artifact_type: 'report_export',
    artifact_id: report.id,
    format: exportFormat,
    created_by: ctx.userId,
    content: payload,
    subject_ids: collectReportExportSubjectIds(report, payload),
    previous_audit_hash: priorGlobal?.entry_hash ?? null,
    previous_tenant_audit_hash: priorTenant?.entry_hash ?? null,
  });
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'report.exported',
    resource_type: 'report',
    resource_id: id,
    metadata: custodyAuditMetadata(custody),
  });
  persistStore();
  if (format === 'html') {
    return { format: 'html', content: buildHtmlExport(payload, custody), payload, custody };
  }
  if (format === 'markdown') {
    const lines = [
      `# ${payload.title}`,
      '',
      `Readiness score: **${readinessExportText(payload.summary)}**`,
      '',
      '## Recent runs',
      ...(payload.runs ?? []).map(
        (r) => `- ${r.id}: ${r.check_id} (${r.vector_family}) → ${r.status}`,
      ),
      '',
      '## Verdicts',
      ...(payload.verdicts ?? []).map(
        (v) => `- Run ${v.test_run_id}: **${v.verdict}** — evidence: ${(v.evidence_ids ?? []).join(', ')}`,
      ),
      '',
      '## SOC notes',
      ...(payload.soc_notes ?? []).map((n) => `- ${n.at}: ${n.body}`),
      '',
      ...buildMarkdownComplianceSection(payload.compliance_mapping),
      ...buildMarkdownCustodySection(custody),
      '',
      '_Metadata-only export; secrets redacted._',
    ];
    return { format: 'markdown', content: lines.join('\n'), payload, custody };
  }
  return { format: 'json', payload, custody };
}

export function exportFinding(ctx, id) {
  const store = getStore();
  const finding = store.findings.find((f) => f.id === id && f.tenant_id === ctx.tenantId);
  if (!finding) return null;
  const check = getCheckById(finding.check_id);
  // EVIDENCE-01 / ADR-0008: finding export (customer artifact) must read external-only. Scrub the
  // free-text prose (notes, remediation copy) before it is hashed into the custody digest.
  const payload = redactObject({
    finding_id: finding.id,
    title: finding.title,
    severity: finding.severity,
    status: finding.status,
    check_id: finding.check_id,
    vector_family: check?.vector_family,
    remediation_template: scrubAgentPlacementText(check?.remediation_template),
    evidence_ids: finding.evidence_ids,
    notes: scrubAgentPlacementText(finding.notes),
  });
  const priorGlobal = getLatestChainedAuditEntry();
  const priorTenant = getLatestChainedAuditEntryForTenant(ctx.tenantId);
  const subjectIds = [finding.id, ...(finding.evidence_ids ?? [])].filter(Boolean);
  const custody = buildCustodyManifest({
    tenant_id: ctx.tenantId,
    artifact_type: 'finding_export',
    artifact_id: finding.id,
    format: 'json',
    created_by: ctx.userId,
    content: payload,
    subject_ids: subjectIds,
    previous_audit_hash: priorGlobal?.entry_hash ?? null,
    previous_tenant_audit_hash: priorTenant?.entry_hash ?? null,
  });
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.exported',
    resource_type: 'finding',
    resource_id: id,
    metadata: custodyAuditMetadata(custody),
  });
  persistStore();
  return { ...payload, custody };
}
