import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import {
  getTestRun as devGetTestRun,
  listTestRuns as devListTestRuns,
} from '../../src/services/testRuns.mjs';
import {
  getFinding as devGetFinding,
  listFindings as devListFindings,
  listFindingsEnvelope as devListFindingsEnvelope,
  patchFinding as devPatchFinding,
} from '../../src/services/findings.mjs';
import { exportFinding as devExportFinding } from '../../src/services/reports.mjs';
import { containsAgentPlacementVocabulary } from '../../src/lib/outsideInEvidence.mjs';
import {
  createPostgresValidationServices,
  VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  VALIDATION_AUDIT_REPOSITORY_METHODS,
  VALIDATION_CORE_CATALOG_REPOSITORY_METHODS,
  VALIDATION_PROBE_JOB_REPOSITORY_METHODS,
  VALIDATION_KILL_SWITCH_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createPostgresReportServices } from '../../src/persistence/postgres/reportServiceAdapters.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

// Exact production-like pre-ADR-0008 agent/placement phrasing. If any of these survive to a
// customer-facing payload, EVIDENCE-01 is leaking obsolete vocabulary.
const AGENT_EXPLANATION =
  'External response indicated block/timeout but the agent observed traffic — penetration suspected.';
const AGENT_NOTES =
  'External response indicated block/timeout but the agent observed traffic reaching origin.';
const AGENT_PLACEMENT = {
  level: 'Medium',
  status: 'observed_this_run',
  reason: 'Bound online agent reported agent placement broader than host-level.',
  agent_id: 'agt_e563ad3b5baa04fd',
  observation_mode: 'unknown',
  evidence_event_id: 'evt_69904bb30d1df772',
};

function assertCleanVerdict(verdict, label) {
  assert.ok(verdict, `${label}: verdict present`);
  assert.ok(!containsAgentPlacementVocabulary(verdict.explanation), `${label}: explanation leaks: ${verdict.explanation}`);
  assert.equal('agent_id' in (verdict.placement_confidence ?? {}), false, `${label}: agent_id leaked`);
  assert.equal('observation_mode' in (verdict.placement_confidence ?? {}), false, `${label}: observation_mode leaked`);
  assert.ok(!containsAgentPlacementVocabulary(verdict.placement_confidence?.reason), `${label}: placement reason leaks`);
  // Enum/status/evidence fields are API contracts and must survive.
  assert.equal(verdict.verdict, 'penetrated', `${label}: verdict enum preserved`);
  assert.equal(verdict.confidence, 'external_only', `${label}: confidence preserved`);
  assert.equal(verdict.placement_confidence.level, 'Medium', `${label}: level preserved`);
  assert.equal(verdict.placement_confidence.status, 'observed_this_run', `${label}: status preserved`);
}

function seedRunAndFinding() {
  freshStore();
  const store = getStore();
  const run = {
    id: 'run_1',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    check_id: 'dns.safe',
    status: 'completed',
    started_at: '2026-07-01T00:00:00.000Z',
    created_at: '2026-07-01T00:00:00.000Z',
    correlation: { nonce_hash: 'nonce_1' },
  };
  store.testRuns.push(run);
  store.verdicts.push({
    id: 'verdict_1',
    tenant_id: 'ten_demo',
    test_run_id: 'run_1',
    verdict: 'penetrated',
    confidence: 'external_only',
    explanation: AGENT_EXPLANATION,
    placement_confidence: { ...AGENT_PLACEMENT },
    evidence_ids: ['evt_1'],
  });
  store.findings.push({
    id: 'find_1',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    test_run_id: 'run_1',
    check_id: 'dns.safe',
    title: 'Finding',
    severity: 'high',
    status: 'open',
    notes: AGENT_NOTES,
    evidence_ids: ['evt_1'],
    created_at: '2026-07-01T00:00:00.000Z',
    updated_at: '2026-07-01T00:00:00.000Z',
  });
  return { store, run };
}

describe('EVIDENCE-01 customer projection scrubbing (dev-json)', () => {
  it('scrubs the nested verdict in run detail without mutating stored evidence', () => {
    seedRunAndFinding();
    const detail = devGetTestRun(CTX, 'run_1');
    assertCleanVerdict(detail.verdict, 'dev run detail');
    // Stored verdict row is untouched (internal/historical evidence preserved).
    const stored = getStore().verdicts.find((v) => v.id === 'verdict_1');
    assert.match(stored.explanation, /the agent observed traffic/);
    assert.equal(stored.placement_confidence.agent_id, 'agt_e563ad3b5baa04fd');
  });

  it('scrubs the nested verdict in run list items', () => {
    seedRunAndFinding();
    const [item] = devListTestRuns(CTX, {});
    assertCleanVerdict(item.verdict, 'dev run list');
  });

  it('scrubs finding notes in finding detail, list, and envelope', () => {
    seedRunAndFinding();
    const detail = devGetFinding(CTX, 'find_1');
    assert.ok(!containsAgentPlacementVocabulary(detail.notes), `dev finding detail notes leak: ${detail.notes}`);
    assert.equal(detail.severity, 'high'); // enum preserved
    assert.equal(detail.status, 'open');

    const [listed] = devListFindings(CTX, {});
    assert.ok(!containsAgentPlacementVocabulary(listed.notes), 'dev finding list notes leak');

    const [enveloped] = devListFindingsEnvelope(CTX, {}).items;
    assert.ok(!containsAgentPlacementVocabulary(enveloped.notes), 'dev finding envelope notes leak');

    // Stored row untouched.
    assert.match(getStore().findings.find((f) => f.id === 'find_1').notes, /the agent observed traffic/);
  });

  it('scrubs the PATCH finding response while persisting the mutation', () => {
    seedRunAndFinding();
    const patched = devPatchFinding(CTX, 'find_1', { status: 'accepted_risk' });
    assert.equal(patched.status, 'accepted_risk');
    assert.ok(!containsAgentPlacementVocabulary(patched.notes), 'dev patch response notes leak');
    assert.equal(getStore().findings.find((f) => f.id === 'find_1').status, 'accepted_risk');
  });

  it('scrubs finding notes in the finding JSON export before custody digest', () => {
    seedRunAndFinding();
    const exported = devExportFinding(CTX, 'find_1');
    assert.ok(!containsAgentPlacementVocabulary(exported.notes), `dev finding export notes leak: ${exported.notes}`);
    assert.ok(!containsAgentPlacementVocabulary(exported.remediation_template ?? ''), 'dev finding export remediation leak');
    // Shape preserved: enum/id fields intact and custody present.
    assert.equal(exported.finding_id, 'find_1');
    assert.equal(exported.severity, 'high');
    assert.ok(exported.custody?.content_sha256, 'custody digest present');
  });
});

function stubFrom(methodNames, impls = {}) {
  const stub = {};
  for (const name of methodNames) {
    stub[name] = impls[name] ?? (async () => null);
  }
  return { ...stub, ...impls };
}

function buildPostgresServices(verdictRow, findingRows) {
  const validationEvidence = stubFrom(VALIDATION_EVIDENCE_REPOSITORY_METHODS, {
    async getTestRun(_ctx, id) {
      return { id, tenant_id: 'ten_demo', check_id: 'dns.safe', status: 'completed' };
    },
    async getVerdictForRun() {
      return verdictRow;
    },
    async getFinding(_ctx, id) {
      return findingRows.find((f) => f.id === id) ?? null;
    },
    async listFindings() {
      return findingRows.map((f) => ({ ...f }));
    },
  });
  const audit = stubFrom(VALIDATION_AUDIT_REPOSITORY_METHODS);
  const coreCatalog = stubFrom(VALIDATION_CORE_CATALOG_REPOSITORY_METHODS);
  const probeJobs = stubFrom(VALIDATION_PROBE_JOB_REPOSITORY_METHODS);
  const killSwitch = stubFrom(VALIDATION_KILL_SWITCH_REPOSITORY_METHODS);
  return createPostgresValidationServices({ validationEvidence, audit, coreCatalog, probeJobs, killSwitch });
}

describe('EVIDENCE-01 customer projection scrubbing (postgres adapters)', () => {
  const verdictRow = {
    id: 'verdict_1',
    tenant_id: 'ten_demo',
    test_run_id: 'run_1',
    verdict: 'penetrated',
    confidence: 'external_only',
    explanation: AGENT_EXPLANATION,
    placement_confidence: { ...AGENT_PLACEMENT },
    evidence_ids: ['evt_1'],
  };
  const findingRow = {
    id: 'find_1',
    tenant_id: 'ten_demo',
    check_id: 'dns.safe',
    title: 'Finding',
    severity: 'high',
    status: 'open',
    notes: AGENT_NOTES,
    remediation_template: 'Review edge protection and agent placement for this vector.',
    evidence_ids: ['evt_1'],
  };

  it('scrubs the nested verdict in the postgres run-detail adapter', async () => {
    const svc = buildPostgresServices(verdictRow, [findingRow]);
    const run = await svc.testRuns.getTestRun(CTX, 'run_1');
    assertCleanVerdict(run.verdict, 'postgres run detail');
    // Source row untouched.
    assert.match(verdictRow.explanation, /the agent observed traffic/);
    assert.equal(verdictRow.placement_confidence.agent_id, 'agt_e563ad3b5baa04fd');
  });

  it('scrubs finding notes in the postgres finding detail/list adapters', async () => {
    const svc = buildPostgresServices(verdictRow, [findingRow]);
    const detail = await svc.findings.getFinding(CTX, 'find_1');
    assert.ok(!containsAgentPlacementVocabulary(detail.notes), `postgres finding detail notes leak: ${detail.notes}`);
    assert.ok(!containsAgentPlacementVocabulary(detail.remediation_template), 'postgres finding detail remediation leak');
    assert.equal(detail.severity, 'high');

    const [listed] = await svc.findings.listFindings(CTX, {});
    assert.ok(!containsAgentPlacementVocabulary(listed.notes), 'postgres finding list notes leak');

    const [enveloped] = (await svc.findings.listFindingsEnvelope(CTX, {})).items;
    assert.ok(!containsAgentPlacementVocabulary(enveloped.notes), 'postgres finding envelope notes leak');
  });

  it('scrubs finding notes/remediation in the postgres finding JSON export before custody digest', async () => {
    const reportsRepo = {
      async createReport() { return null; },
      async getReport() { return null; },
      async listReports() { return []; },
      async listRunsForReport() { return []; },
      async listVerdictsForRunIds() { return []; },
    };
    const validationEvidence = {
      async listTestRuns() { return []; },
      async listFindings() { return [{ ...findingRow }]; },
      async getFinding() {
        // Export carries agent-worded notes AND agent-worded remediation_template.
        return { ...findingRow, remediation_template: 'Review edge protection and agent placement for this vector.' };
      },
    };
    const audit = {
      async appendAuditEvent() { return null; },
      async getLastAuditEntry() { return null; },
    };
    const { reports } = createPostgresReportServices({ reports: reportsRepo, validationEvidence, audit });
    const exported = await reports.exportFinding(CTX, 'find_1');
    assert.ok(!containsAgentPlacementVocabulary(exported.notes), `postgres finding export notes leak: ${exported.notes}`);
    assert.ok(!containsAgentPlacementVocabulary(exported.remediation_template), 'postgres finding export remediation leak');
    // Shape + custody preserved.
    assert.equal(exported.finding_id, 'find_1');
    assert.equal(exported.severity, 'high');
    assert.ok(exported.custody?.content_sha256, 'custody digest present');
  });
});
