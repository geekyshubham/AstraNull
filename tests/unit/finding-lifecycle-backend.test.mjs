import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { beforeEach, describe, it } from 'node:test';
import {
  normalizeComparisonEvaluation,
  normalizeEntryPathDeclaration,
  classifyPathValidationItem,
} from '../../src/contracts/protectionValidation.mjs';
import { buildWafPostureFindingSummary, extractFindingRemediationContext } from '../../src/contracts/wafPosture.mjs';
import { roleHasPermission } from '../../src/contracts/roles.mjs';
import { planFindingPatch, validateRiskAcceptance } from '../../src/lib/findingLifecycle.mjs';
import { scrubFindingForCustomer } from '../../src/lib/outsideInEvidence.mjs';
import { toProtectionFindingRow } from '../../src/lib/protectionValidationFindings.mjs';
import { getEvidenceContext } from '../../src/services/evidenceContext.mjs';
import { exportFinding } from '../../src/services/reports.mjs';
import { createPostgresProtectionFindingsRepository } from '../../src/persistence/postgres/protectionFindingsRepository.mjs';
import { createWafPostureRepository } from '../../src/persistence/postgres/wafPostureRepository.mjs';
import { getFinding, patchFinding, upsertFindingFromVerdict } from '../../src/services/findings.mjs';
import { createActionItemFromFinding } from '../../src/services/wafPosture.mjs';
import { getStore } from '../../src/store.mjs';
import {
  createPostgresValidationServices,
  VALIDATION_AUDIT_REPOSITORY_METHODS,
  VALIDATION_CORE_CATALOG_REPOSITORY_METHODS,
  VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  VALIDATION_KILL_SWITCH_REPOSITORY_METHODS,
  VALIDATION_PROBE_JOB_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { findingNoteSections } from '../../apps/web/react/src/lib/finding-groups.mjs';
import { freshStore } from '../helpers/reset.mjs';

const NOW = new Date('2026-10-13T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const REASON = 'Compensating control: origin is IP-allowlisted to the CDN.';

function ctx(role = 'owner', userId = `usr_${role}`) {
  return { tenantId: 'ten_demo', userId, role };
}

function acceptance(overrides = {}) {
  return { reason: REASON, review_at: new Date(NOW.getTime() + 90 * DAY).toISOString(), ...overrides };
}

function seedVerdictFinding() {
  const store = getStore();
  const run = { id: 'run_origin', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'origin.direct_bypass.safe', status: 'verdicted' };
  const verdict = {
    id: 'vd_origin',
    tenant_id: 'ten_demo',
    test_run_id: run.id,
    target_id: 'tgt_1',
    check_id: run.check_id,
    verdict: 'edge_exposed',
    severity: 'high',
    explanation: 'Origin answered directly without the edge in the path.',
    evidence_ids: ['ev_cited'],
    created_at: NOW.toISOString(),
  };
  store.testRuns.push(run);
  store.verdicts.push(verdict);
  store.evidenceVault.push(
    { id: 'ev_cited', tenant_id: 'ten_demo', test_run_id: run.id, label: 'probe', created_at: NOW.toISOString() },
    { id: 'ev_sealed', tenant_id: 'ten_demo', test_run_id: run.id, label: 'sealed_bundle', created_at: NOW.toISOString() },
    { id: 'ev_other_run', tenant_id: 'ten_demo', test_run_id: 'run_other', label: 'probe', created_at: NOW.toISOString() },
    { id: 'ev_other_tenant', tenant_id: 'ten_other', test_run_id: run.id, label: 'probe', created_at: NOW.toISOString() },
  );
  return upsertFindingFromVerdict(ctx('engineer'), verdict, run, getStore().targets[0]);
}

describe('finding risk acceptance', () => {
  beforeEach(() => freshStore());

  it('grants finding:accept_risk to owner and admin only', () => {
    assert.equal(roleHasPermission('owner', 'finding:accept_risk'), true);
    assert.equal(roleHasPermission('admin', 'finding:accept_risk'), true);
    for (const role of ['engineer', 'soc', 'auditor', 'viewer']) {
      assert.equal(roleHasPermission(role, 'finding:accept_risk'), false, role);
    }
  });

  it('denies an engineer with 403 and records the denial', () => {
    const finding = seedVerdictFinding();
    const result = patchFinding(ctx('engineer'), finding.id, { status: 'accepted_risk', risk_acceptance: acceptance() });
    assert.equal(result.error, 'forbidden');
    assert.equal(result.status, 403);
    assert.equal(getStore().findings[0].status, 'open');
    const denial = getStore().auditLog.find((row) => row.action === 'rbac.denied');
    assert.equal(denial.metadata.permission, 'finding:accept_risk');
    assert.equal(denial.resource_id, finding.id);
  });

  it('rejects acceptance without a reason or a valid review date', () => {
    const missing = planFindingPatch({ status: 'accepted_risk' }, ctx(), { now: NOW });
    assert.equal(missing.error, 'risk_acceptance_required');
    assert.equal(missing.status, 400);
    assert.equal(planFindingPatch({ status: 'accepted_risk', risk_acceptance: acceptance({ reason: 'too short' }) }, ctx(), { now: NOW }).error, 'risk_acceptance_required');
    assert.equal(planFindingPatch({ status: 'accepted_risk', risk_acceptance: acceptance({ reason: 'x'.repeat(2001) }) }, ctx(), { now: NOW }).error, 'risk_acceptance_required');
    assert.equal(validateRiskAcceptance(acceptance({ review_at: new Date(NOW.getTime() - DAY).toISOString() }), NOW).field, 'risk_acceptance.review_at');
    assert.equal(validateRiskAcceptance(acceptance({ review_at: new Date(NOW.getTime() + 366 * DAY).toISOString() }), NOW).field, 'risk_acceptance.review_at');
    assert.equal(validateRiskAcceptance(acceptance({ review_at: 'next quarter' }), NOW).field, 'risk_acceptance.review_at');
  });

  it('stores the accepting user, keeps closed_at and clears the decision on reopen', () => {
    const finding = seedVerdictFinding();
    const accepted = patchFinding(ctx('admin', 'usr_jordan'), finding.id, {
      status: 'accepted_risk',
      risk_acceptance: { ...acceptance(), reason: `  ${REASON}  `, accepted_by: 'usr_forged' },
    });
    assert.equal(accepted.status, 'accepted_risk');
    assert.equal(accepted.risk_acceptance.reason, REASON);
    assert.equal(accepted.risk_acceptance.accepted_by, 'usr_jordan');
    assert.ok(accepted.risk_acceptance.accepted_at);
    assert.ok(accepted.closed_at);
    assert.equal(getFinding(ctx(), finding.id).risk_acceptance.accepted_by, 'usr_jordan');
    const updates = getStore().auditLog.filter((row) => row.action === 'finding.updated' && row.resource_id === finding.id);
    assert.equal(updates.at(-1).metadata.status, 'accepted_risk');

    const reopened = patchFinding(ctx('engineer'), finding.id, { status: 'open', notes: 'Compensating control removed.' });
    assert.equal(reopened.status, 'open');
    assert.equal(reopened.risk_acceptance, null);
    assert.equal(reopened.closed_at, null);
    assert.equal(getFinding(ctx(), finding.id).risk_acceptance, null);
  });

  it('lets an engineer close, resolve or mark false positive without the accept permission', () => {
    const finding = seedVerdictFinding();
    for (const status of ['in_progress', 'resolved', 'false_positive', 'closed']) {
      const result = patchFinding(ctx('engineer'), finding.id, { status, notes: `Moved to ${status} after review.` });
      assert.equal(result.status, status);
    }
  });

  it('passes the decision through the Postgres adapter and denies an engineer before writing', async () => {
    const writes = [];
    const audits = [];
    const repositories = {
      validationEvidence: Object.fromEntries(VALIDATION_EVIDENCE_REPOSITORY_METHODS.map((name) => [name, async () => null])),
      audit: Object.fromEntries(VALIDATION_AUDIT_REPOSITORY_METHODS.map((name) => [name, async () => null])),
      coreCatalog: Object.fromEntries(VALIDATION_CORE_CATALOG_REPOSITORY_METHODS.map((name) => [name, async () => null])),
      probeJobs: Object.fromEntries(VALIDATION_PROBE_JOB_REPOSITORY_METHODS.map((name) => [name, async () => null])),
      killSwitch: Object.fromEntries(VALIDATION_KILL_SWITCH_REPOSITORY_METHODS.map((name) => [name, async () => null])),
    };
    repositories.validationEvidence.patchFinding = async (_ctx, id, patch) => {
      writes.push(patch);
      return { id, tenant_id: 'ten_demo', status: patch.status, risk_acceptance: patch.risk_acceptance, system_summary: 'machine text' };
    };
    repositories.audit.appendAuditEvent = async (entry) => { audits.push(entry); };
    const { findings } = createPostgresValidationServices(repositories, { now: () => NOW });
    const auditService = { appendAuditEvent: async (entry) => { audits.push(entry); } };

    const denied = await findings.patchFinding({ ...ctx('engineer'), persistenceMode: 'postgres', auditService }, 'fnd_pg', {
      status: 'accepted_risk',
      risk_acceptance: acceptance(),
    });
    assert.equal(denied.status, 403);
    assert.equal(writes.length, 0);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(audits.some((entry) => entry.action === 'rbac.denied' && entry.metadata.permission === 'finding:accept_risk'), true);

    const accepted = await findings.patchFinding({ ...ctx('owner', 'usr_owner'), persistenceMode: 'postgres', auditService }, 'fnd_pg', {
      status: 'accepted_risk',
      risk_acceptance: acceptance(),
    });
    assert.equal(accepted.status, 'accepted_risk');
    assert.equal(writes[0].risk_acceptance.accepted_by, 'usr_owner');
    assert.equal(writes[0].risk_acceptance.review_at, acceptance().review_at);

    await findings.patchFinding({ ...ctx('engineer'), persistenceMode: 'postgres', auditService }, 'fnd_pg', { status: 'in_progress' });
    assert.equal(writes[1].risk_acceptance, null);

    const immutable = await findings.patchFinding(ctx('owner'), 'fnd_pg', { system_summary: 'customer rewrite' });
    assert.equal(immutable.error, 'system_summary_immutable');
    assert.equal(writes.length, 2);
  });
});

describe('machine summary is separate from human notes', () => {
  beforeEach(() => freshStore());

  it('writes system_summary and leaves notes empty for every machine creator', () => {
    const finding = seedVerdictFinding();
    assert.equal(finding.system_summary, 'Origin answered directly without the edge in the path.');
    assert.equal(finding.notes, null);
  });

  it('builds protection findings with system_summary and no notes', () => {
    const row = toProtectionFindingRow({
      tenant_id: 'ten_demo',
      target_id: 'tgt_1',
      check_id: 'waf.marker.sqli',
      test_run_id: 'run_1',
      verdict_id: 'vd_1',
      title: 'Bypass',
      summary: 'A response was observed on this declared path.',
      severity: 'high',
      evidence_ids: [],
      dedupe_key: `pvf_${'a'.repeat(64)}`,
      finding_class: 'suspected_bypass',
      priority: 'p2',
      comparison_context: { evaluation_id: 'eval_1' },
    }, { id: 'fnd_pv', now: NOW.toISOString() });
    assert.equal(row.system_summary, 'A response was observed on this declared path.');
    assert.equal(row.notes, null);
  });

  it('keeps the evidence explanation when a human note is saved', async () => {
    const finding = seedVerdictFinding();
    const before = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: finding.id });
    patchFinding(ctx('engineer'), finding.id, { notes: 'Ticket OPS-12: CDN team owns the fix.' });
    const after = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: finding.id });
    assert.equal(after.status, 200);
    assert.equal(after.body.answer.explanation, before.body.answer.explanation);
    assert.equal(JSON.stringify(after.body).includes('OPS-12'), false);
    assert.equal(getStore().findings[0].system_summary, 'Origin answered directly without the edge in the path.');
  });

  it('falls back to system_summary, never notes, when the verdict has no explanation', async () => {
    const finding = seedVerdictFinding();
    getStore().verdicts[0].explanation = undefined;
    patchFinding(ctx('engineer'), finding.id, { notes: 'Human triage note.' });
    const context = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: finding.id });
    assert.equal(context.body.answer.explanation, 'Origin answered directly without the edge in the path.');
  });

  it('keeps WAF remediation reason codes and action-item codes when a note mentions other codes', () => {
    const store = getStore();
    store.wafAssets = [{ id: 'waf_asset_1', tenant_id: 'ten_demo', target_group_id: 'tg_1', canonical_url: 'https://checkout.example.test' }];
    store.wafActionItems = [];
    const finding = {
      id: 'fnd_waf',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      check_id: 'waf.posture.waf_asset_1',
      title: 'WAF posture underprotected',
      severity: 'high',
      status: 'open',
      system_summary: 'Posture status: underprotected. Reason codes: origin_bypass_confirmed, rule_gap. WAF asset id: waf_asset_1.',
      notes: null,
      evidence_ids: [],
    };
    store.findings.push(finding);
    const before = extractFindingRemediationContext(finding);
    patchFinding(ctx('engineer'), 'fnd_waf', { notes: 'Reason codes: customer_typed. Waiting on vendor.' });
    const after = extractFindingRemediationContext(store.findings.find((row) => row.id === 'fnd_waf'));
    assert.deepEqual(after.reason_codes, ['origin_bypass_confirmed', 'rule_gap']);
    assert.deepEqual(after.reason_codes, before.reason_codes);

    const result = createActionItemFromFinding(ctx('engineer'), store.findings.find((row) => row.id === 'fnd_waf'));
    assert.equal(result.error, undefined);
    assert.match(result.action_item.evidence.summary, /origin_bypass_confirmed, rule_gap/);
    assert.equal(result.action_item.evidence.summary.includes('customer_typed'), false);
  });

  it('reads legacy notes only when a row has no system_summary', () => {
    const legacy = extractFindingRemediationContext({ check_id: 'waf.posture.a1', notes: 'Reason codes: legacy_code.' });
    assert.deepEqual(legacy.reason_codes, ['legacy_code']);
    const current = extractFindingRemediationContext({ check_id: 'waf.posture.a1', system_summary: 'No codes recorded.', notes: 'Reason codes: typed.' });
    assert.deepEqual(current.reason_codes, []);
  });

  it('rejects a PATCH that tries to edit system_summary', () => {
    const finding = seedVerdictFinding();
    const result = patchFinding(ctx('owner'), finding.id, { system_summary: 'rewritten', notes: 'x' });
    assert.equal(result.error, 'system_summary_immutable');
    assert.equal(result.status, 400);
    assert.equal(getStore().findings[0].system_summary, 'Origin answered directly without the edge in the path.');
    assert.equal(getStore().findings[0].notes, null);
  });

  it('scrubs system_summary like notes in customer projections', () => {
    const scrubbed = scrubFindingForCustomer({ id: 'f', system_summary: 'Agent placement confirmed the gap.' });
    assert.equal(/agent/i.test(scrubbed.system_summary), false);
  });

  it('labels the recorded explanation and human triage notes separately for the group page', () => {
    assert.deepEqual(findingNoteSections({ system_summary: 'Machine text', notes: null }), [
      { id: 'recorded', label: 'Recorded explanation', text: 'Machine text' },
    ]);
    assert.deepEqual(findingNoteSections({ system_summary: 'Machine text', notes: '  Human note ' }), [
      { id: 'recorded', label: 'Recorded explanation', text: 'Machine text' },
      { id: 'triage', label: 'Triage notes', text: 'Human note' },
    ]);
    assert.deepEqual(findingNoteSections({ system_summary: '', notes: '' }), []);
  });
});

describe('evidence context for the originating run', () => {
  beforeEach(() => freshStore());

  it('lists sealed artifacts of the originating run without cross-run or cross-tenant leakage', async () => {
    const finding = seedVerdictFinding();
    const context = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: finding.id });
    assert.equal(context.status, 200);
    const runArtifacts = context.body.alternatives.filter((item) => item.relationship === 'originating_run_artifact');
    assert.deepEqual(runArtifacts.map((item) => item.evidence_id), ['ev_sealed']);
    assert.deepEqual(context.body.primary.evidence_ids, ['ev_cited']);
    const text = JSON.stringify(context.body);
    assert.equal(text.includes('ev_other_run'), false);
    assert.equal(text.includes('ev_other_tenant'), false);
  });

  it('never gives a group member the lead finding artifacts', async () => {
    seedVerdictFinding();
    const store = getStore();
    store.testRuns.push({ id: 'run_member', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'dns.zone.safe', status: 'verdicted' });
    store.verdicts.push({ id: 'vd_member', tenant_id: 'ten_demo', test_run_id: 'run_member', target_id: 'tgt_1', check_id: 'dns.zone.safe', verdict: 'edge_exposed', evidence_ids: [], created_at: NOW.toISOString() });
    store.findings.push({ id: 'fnd_member', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'dns.zone.safe', test_run_id: 'run_member', verdict_id: 'vd_member', status: 'open', evidence_ids: [], created_at: NOW.toISOString() });
    const context = await getEvidenceContext(ctx(), { entry: 'group_member', finding_id: 'fnd_member' });
    assert.equal(context.status, 200);
    assert.equal(context.body.alternatives.some((item) => item.relationship === 'originating_run_artifact'), false);
    assert.equal(JSON.stringify(context.body).includes('ev_sealed'), false);
  });

  it('reports a collecting run without a verdict as pending', async () => {
    const store = getStore();
    store.testRuns.push({ id: 'run_collecting', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'origin.direct_bypass.safe', status: 'collecting', collection_deadline_at: new Date(Date.now() + DAY).toISOString() });
    const context = await getEvidenceContext(ctx(), {
      entry: 'check_result',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      test_run_id: 'run_collecting',
    });
    assert.equal(context.status, 200);
    assert.equal(context.body.state, 'pending');
    assert.equal(context.body.unavailable_reason, 'pending');
    assert.equal(context.body.subject.run_status, 'collecting');
  });
});

function recordingPool(handler) {
  const client = {
    queries: [],
    async query(text, params = []) {
      this.queries.push({ text, params });
      return handler(text, params) ?? { rows: [] };
    },
    release() {},
  };
  return { client, async connect() { return client; } };
}

const MIGRATION_0080 = readFileSync(new URL('../../db/migrations/0080_finding_system_summary_and_risk_acceptance.sql', import.meta.url), 'utf8');

function migrationPatterns() {
  return [...MIGRATION_0080.matchAll(/notes ~ '([^']+)'/g)].map((match) => new RegExp(match[1]));
}

describe('Postgres creators write system_summary and keep human notes', () => {
  const WAF_ROW = {
    id: 'fnd_waf_pg', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: null, test_run_id: 'run_2',
    check_id: 'waf.posture.waf_1', title: 'WAF posture underprotected: https://app.example.test', severity: 'high',
    status: 'open', evidence_ids: [], notes: 'Edge team owns this. Ticket SEC-9.', system_summary: null,
    remediation_template: 'waf_posture_remediation', verdict_id: null, last_verdict_id: null, assignee: 'edge-team',
    created_at: NOW, updated_at: NOW,
  };

  it('updates system_summary on WAF re-validation without touching human notes', async () => {
    const summary = buildWafPostureFindingSummary({ postureStatus: 'underprotected', reasonCodes: ['monitor_only_behavior'], wafAssetId: 'waf_1', wafValidationRunId: 'wvr_2' });
    const pool = recordingPool((sql, params) => {
      if (/FROM findings/i.test(sql) && /IS NOT DISTINCT FROM/i.test(sql)) return { rows: [{ ...WAF_ROW }] };
      if (/UPDATE findings/i.test(sql)) return { rows: [{ ...WAF_ROW, system_summary: params[6] }] };
      return { rows: [] };
    });
    const result = await createWafPostureRepository(pool).upsertWafPostureFinding(ctx('admin'), {
      id: 'fnd_new', target_group_id: 'tg_1', target_id: null, test_run_id: 'run_2', check_id: 'waf.posture.waf_1',
      title: WAF_ROW.title, severity: 'high', notes: null, system_summary: summary,
      remediation_template: 'waf_posture_remediation', evidence_ids: [], created_at: NOW.toISOString(), updated_at: NOW.toISOString(),
    });
    const update = pool.client.queries.find((query) => /UPDATE findings/i.test(query.text));
    assert.match(update.text, /system_summary = \$7/);
    assert.doesNotMatch(update.text, /\bnotes\s*=/);
    assert.equal(update.params[6], summary);
    assert.equal(result.finding.notes, 'Edge team owns this. Ticket SEC-9.');
    assert.equal(result.finding.system_summary, summary);
    assert.deepEqual(extractFindingRemediationContext(result.finding).reason_codes, ['monitor_only_behavior']);
  });

  it('inserts a new WAF finding with null notes and the server summary', async () => {
    const summary = buildWafPostureFindingSummary({ postureStatus: 'unprotected', reasonCodes: ['marker_rule_not_blocking'], wafAssetId: 'waf_1', wafValidationRunId: 'wvr_1' });
    const pool = recordingPool((sql, params) => {
      if (/INSERT INTO findings/i.test(sql)) return { rows: [{ ...WAF_ROW, notes: null, system_summary: params[10] }] };
      return { rows: [] };
    });
    const result = await createWafPostureRepository(pool).upsertWafPostureFinding(ctx('admin'), {
      id: 'fnd_waf_pg', target_group_id: 'tg_1', target_id: null, test_run_id: 'run_1', check_id: 'waf.posture.waf_1',
      title: WAF_ROW.title, severity: 'high', notes: 'ignored machine text', system_summary: summary,
      remediation_template: 'waf_posture_remediation', evidence_ids: [], created_at: NOW.toISOString(), updated_at: NOW.toISOString(),
    });
    const insert = pool.client.queries.find((query) => /INSERT INTO findings/i.test(query.text));
    assert.match(insert.text, /notes, system_summary/);
    assert.equal(insert.params.includes('ignored machine text'), false);
    assert.equal(insert.params[10], summary);
    assert.equal(result.finding.notes, null);
    assert.deepEqual(extractFindingRemediationContext(result.finding).reason_codes, ['marker_rule_not_blocking']);
  });

  it('inserts protection findings with the summary in system_summary and notes null', async () => {
    const tenantId = 'ten_demo';
    const relation = (id, body) => ({ ...normalizeEntryPathDeclaration(body, { tenantId, anchorTargetId: 'tgt_app', declarationVersion: 1 }), id });
    const primary = relation('ep_primary', { entry_target_id: 'tgt_app', relation_kind: 'primary_route', owner: 'App Team', purpose: 'Main site', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] });
    const alt = relation('ep_alt', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', owner: 'App Team', purpose: 'Legacy host', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] });
    const ref = (run, targetId) => ({
      test_run_id: run, check_id: 'waf.marker.sqli', check_version: '1.1.0', scenario_version: 's1', verdict_id: `vrd_${run}`,
      evidence_ids: [`ev_${run}`], target_id: targetId, observed_at: NOW.toISOString(), run_status: 'verdicted',
      source_perspective: 'public-worker-eu', worker_id: 'worker_eu_1',
    });
    const item = (rel, args, refs) => ({
      entry_path_id: rel.id, scenario: 'waf.sqli.marker',
      ...classifyPathValidationItem({ relation: rel, primaryBaselineHealth: 'healthy', primaryEnforcement: 'enforced', ...args }),
      evidence_refs: refs,
    });
    const evaluation = {
      ...normalizeComparisonEvaluation({
        kind: 'path_validation', tenant_id: tenantId, evaluated_at: NOW.toISOString(),
        items: [
          item(primary, { observation: 'explicit_denial_observed', enforcement: 'enforced' }, [ref('run_p', 'tgt_app')]),
          item(alt, { observation: 'application_identity_confirmed', enforcement: 'not_enforced' }, [ref('run_a', 'tgt_alt')]),
        ],
      }),
      id: 'pvc_pg', anchor_target_id: 'tgt_app', primary_entry_path_id: 'ep_primary', reviewed_plan_digest: 'a'.repeat(64),
    };
    const pool = recordingPool((sql) => (/INSERT INTO findings/i.test(sql) ? { rows: [{ id: 'fnd_inserted' }] } : { rows: [] }));
    const result = await createPostgresProtectionFindingsRepository(pool).upsertProtectionFindingsFromEvaluation(ctx('admin'), evaluation, { entryPaths: [primary, alt], now: NOW });
    assert.equal(result.ok, true);
    const insert = pool.client.queries.find((query) => /INSERT INTO findings/i.test(query.text));
    assert.ok(insert, 'expected a protection finding insert');
    assert.match(insert.text, /notes, system_summary/);
    assert.match(insert.text, /'open', \$8::text\[\], NULL, \$9/);
    assert.match(insert.params[8], /nonce-bound application response/);
  });

  it('carries the recorded summary into the finding evidence export', () => {
    freshStore();
    const finding = seedVerdictFinding();
    patchFinding(ctx('engineer'), finding.id, { notes: 'Ticket OPS-12.' });
    const payload = exportFinding(ctx(), finding.id);
    assert.equal(payload.system_summary, 'Origin answered directly without the edge in the path.');
    assert.equal(payload.notes, 'Ticket OPS-12.');
  });
});

describe('migration 0080 backfill keeps human notes editable', () => {
  it('never copies notes into system_summary for verdict-linked rows', () => {
    const verdictBackfill = MIGRATION_0080.slice(MIGRATION_0080.indexOf('-- Verdict-linked'), MIGRATION_0080.indexOf('-- Findings without a verdict'));
    assert.match(verdictBackfill, /SET system_summary = v\.explanation/);
    assert.doesNotMatch(verdictBackfill.replace(/--.*$/gm, ''), /notes/);
  });

  it('moves only unedited server WAF text and leaves human notes in place', () => {
    const patterns = migrationPatterns();
    assert.equal(patterns.length, 2);
    const matches = (text) => patterns.some((pattern) => pattern.test(text));
    const current = buildWafPostureFindingSummary({ postureStatus: 'unprotected', reasonCodes: ['marker_rule_not_blocking', 'monitor_only_behavior'], wafAssetId: 'waf_1', wafValidationRunId: 'wvr_1' });
    const legacyPostgres = 'WAF posture finding. reason_codes: marker_rule_not_blocking, monitor_only_behavior waf_validation_run_id: wvr_1 waf_asset_id: waf_1 Retest with a safe WAF validation after remediation.';
    assert.equal(matches(current), true);
    assert.equal(matches(legacyPostgres), true);
    assert.equal(matches('Edge team owns this. Ticket SEC-9.'), false);
    assert.equal(matches(`${legacyPostgres} Talked to the edge team.`), false);
    assert.equal(matches(`Note: ${current}`), false);
  });

  it('lists every protection summary the server writes', () => {
    const source = readFileSync(new URL('../../src/lib/protectionValidationFindings.mjs', import.meta.url), 'utf8');
    const summaries = [...source.matchAll(/summary: '([^']+)'/g)].map((match) => match[1]);
    assert.ok(summaries.length >= 9);
    for (const summary of summaries) assert.ok(MIGRATION_0080.includes(`'${summary}'`), `migration is missing: ${summary}`);
    assert.match(MIGRATION_0080, /notes = NULL\s+WHERE notes IS NOT NULL AND system_summary IS NOT NULL AND notes = system_summary/);
  });
});
