import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { createPostgresReportServices } from '../../src/persistence/postgres/reportServiceAdapters.mjs';
import { createPostgresSubscriptionServices } from '../../src/persistence/postgres/subscriptionServiceAdapters.mjs';
import { createReport, exportReport, getReport, listReports } from '../../src/services/reports.mjs';
import { getCurrentSubscriptionSummary } from '../../src/services/subscriptions.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_test', role: 'admin' };
const HEADER_MARKER = 'synthetic-vault-header-marker';
const NOTE_MARKER = 'synthetic-finding-note-marker';

function auditActions() {
  return getStore().auditLog.map((entry) => entry.action);
}

describe('current-release report scope and snapshot', () => {
  beforeEach(() => {
    freshStore();
  });

  it('rejects unrecognized scope before any report, audit, or notification row', () => {
    const result = createReport(CTX, { targets: ['tgt_1'], api_key: 'must-not-audit-token' });
    assert.equal(result.error, 'unrecognized_scope');
    assert.equal(result.status, 400);
    assert.deepEqual(result.fields, ['targets']);
    assert.equal(getStore().reports.length, 0);
    assert.deepEqual(auditActions(), []);
    assert.equal((getStore().notificationEvents ?? []).length, 0);
    assert.equal(JSON.stringify(result).includes('must-not-audit-token'), false);
  });

  it('rejects empty, duplicate, oversized, foreign, inactive, and mismatched scope without writing', () => {
    const store = getStore();
    store.targets.push({
      id: 'tgt_foreign',
      tenant_id: 'ten_other',
      target_group_id: 'tg_other',
      kind: 'fqdn',
      value: 'foreign.example',
    });
    store.targets.push({
      id: 'tgt_dead',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      kind: 'fqdn',
      value: 'gone.example',
      deleted_at: '2026-01-01T00:00:00.000Z',
    });
    store.targetGroups.push({ id: 'tg_2', tenant_id: 'ten_demo', name: 'Second' });

    assert.equal(createReport(CTX, { target_ids: [] }).error, 'invalid_scope');
    assert.equal(createReport(CTX, { run_ids: ['run_1', 'run_1'] }).error, 'invalid_scope');
    assert.equal(createReport(CTX, { target_ids: Array.from({ length: 101 }, (_, i) => `tgt_${i}`) }).error, 'scope_too_large');
    const foreign = createReport(CTX, { target_ids: ['tgt_foreign'] });
    assert.equal(foreign.error, 'unknown_target');
    assert.equal(JSON.stringify(foreign).includes('foreign.example'), false);
    assert.equal(createReport(CTX, { target_group_ids: ['tg_missing'] }).error, 'unknown_target_group');
    assert.equal(createReport(CTX, { target_ids: ['tgt_dead'] }).error, 'inactive_target');
    assert.equal(createReport(CTX, { target_ids: ['tgt_1'], target_group_ids: ['tg_2'] }).error, 'scope_mismatch');
    const emptyGroup = createReport(CTX, { target_ids: ['tgt_1'], target_group_ids: ['tg_1', 'tg_2'] });
    assert.equal(emptyGroup.error, 'scope_mismatch');
    assert.equal(emptyGroup.reason, 'group_has_no_requested_target');
    assert.equal(store.reports.length, 0);
    assert.deepEqual(auditActions(), []);
  });

  it('keeps an omitted tenant window honest and leaves an explicit score unknown', () => {
    const store = getStore();
    const now = Date.now();
    store.targets[0].declaration = {
      purpose: 'checkout',
      service_roles: ['api'],
      owner_label: 'ops',
      criticality: 'high',
    };
    for (let i = 0; i <= 10; i += 1) {
      const started = i === 0 ? now - 40 * 24 * 60 * 60 * 1000 : now - (10 - i) * 60_000;
      store.testRuns.push({
        id: `run_${String(i).padStart(2, '0')}`,
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'origin.direct_bypass.safe',
        status: 'verdicted',
        started_at: new Date(started).toISOString(),
        created_at: new Date(started).toISOString(),
      });
    }
    store.verdicts.push({
      id: 'vd_05',
      tenant_id: 'ten_demo',
      test_run_id: 'run_05',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      verdict: 'fail',
      confidence: 'high',
      explanation: 'blocked at the edge',
      evidence_ids: ['ev_1'],
      created_at: new Date(now).toISOString(),
    });
    store.evidenceVault.push({
      id: 'ev_1',
      tenant_id: 'ten_demo',
      test_run_id: 'run_05',
      label: 'probe',
      metadata: { authorization: HEADER_MARKER },
      metadata_json: { authorization: HEADER_MARKER },
      created_at: new Date(now).toISOString(),
    });
    store.findings.push({
      id: 'fnd_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      test_run_id: 'run_05',
      check_id: 'origin.direct_bypass.safe',
      title: 'Open gap',
      severity: 'high',
      status: 'open',
      notes: NOTE_MARKER,
      evidence_ids: ['ev_1'],
      created_at: new Date(now).toISOString(),
    });

    const omitted = createReport(CTX, { kind: 'technical', title: 'Estate', period: 'all-time' });
    assert.equal(omitted.kind, 'technical');
    assert.equal(omitted.title, 'Estate');
    assert.equal(omitted.period, 'all-time');
    assert.equal(typeof omitted.summary.readiness_score, 'number');
    assert.equal(omitted.summary.readiness_score_status, 'published');
    assert.equal(omitted.summary.readiness_score_scope, 'tenant');
    assert.equal(omitted.summary.primary_run_id, null);
    assert.equal(omitted.summary.run_capture.total, 11);
    assert.equal(omitted.summary.run_capture.included, 10);
    assert.equal(omitted.summary.run_capture.excluded, 1);
    assert.equal(omitted.summary.run_capture.total_status, 'complete');
    assert.equal(omitted.summary.run_ids[0], 'run_10');
    assert.equal(omitted.summary.run_ids.includes('run_00'), false);
    assert.equal(omitted.summary.scope.selection, 'omitted_defaults_to_tenant');
    assert.equal(omitted.summary.scope.mode, 'tenant');
    assert.equal(omitted.summary.snapshot_frozen, true);
    assert.equal(JSON.stringify(omitted.summary).includes(HEADER_MARKER), false);
    assert.equal(JSON.stringify(omitted.summary).includes(NOTE_MARKER), false);

    store.testRuns.push({
      id: 'run_other',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_other',
      check_id: 'origin.direct_bypass.safe',
      status: 'verdicted',
      started_at: new Date(now).toISOString(),
      created_at: new Date(now).toISOString(),
    });
    store.testRuns.push({
      id: 'run_untimed',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      status: 'verdicted',
    });
    assert.equal(createReport(CTX, { target_ids: ['tgt_1'], run_ids: ['run_other'] }).error, 'run_outside_scope');
    assert.equal(createReport(CTX, { run_ids: ['run_00'], period: 'last-7-days' }).error, 'run_outside_period');
    assert.equal(createReport(CTX, { run_ids: ['run_untimed'], period: 'last-7-days' }).error, 'run_time_not_recorded');
    assert.equal(createReport(CTX, { run_ids: ['run_missing'] }).error, 'unknown_run');

    const scoped = createReport(CTX, {
      kind: 'technical',
      title: 'Scoped',
      target_ids: ['tgt_1'],
      run_ids: ['run_02', 'run_05'],
    });
    assert.deepEqual(scoped.run_ids, ['run_02', 'run_05']);
    assert.deepEqual(scoped.summary.run_ids, ['run_02', 'run_05']);
    assert.equal(scoped.summary.primary_run_id, null);
    assert.equal(scoped.summary.primary_target_id, null);
    assert.equal(scoped.summary.readiness_score, null);
    assert.deepEqual(scoped.summary.readiness_factors, []);
    assert.equal(scoped.summary.readiness_score_status, 'unknown');
    assert.equal(scoped.summary.readiness_score_reason, 'published_readiness_formula_is_tenant_wide');
    assert.equal(scoped.summary.readiness_score_scope, 'not_target_scoped');
    assert.equal(scoped.summary.snapshot_frozen, true);
    assert.equal(scoped.summary.as_of_source, 'report_generation_clock');
    assert.equal(scoped.summary.sections.protection_profile.status, 'not_included');
    assert.equal(scoped.summary.sections.protection_profile.reason, 'no_frozen_protection_profile_on_declared_target');
    assert.equal(scoped.summary.declaration_snapshot.items[0].purpose, 'checkout');
    assert.deepEqual(scoped.summary.declaration_snapshot.items[0].service_roles, ['api']);
    assert.equal(scoped.summary.declaration_snapshot.items[0].owner_label, 'ops');
    assert.equal(scoped.summary.declaration_snapshot.items[0].criticality, 'high');
    assert.equal(scoped.summary.findings_snapshot.items[0].status, 'open');
    assert.equal(scoped.summary.findings_snapshot.items[0].id, 'fnd_1');
    assert.ok(scoped.summary.evidence_ids.includes('ev_1'));
    assert.equal(JSON.stringify(scoped.summary).includes(HEADER_MARKER), false);
    assert.equal(JSON.stringify(scoped.summary).includes(NOTE_MARKER), false);

    const frozen = JSON.parse(JSON.stringify(scoped.summary));
    store.findings[0].status = 'closed';
    store.testRuns.push({
      id: 'run_pass',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      status: 'verdicted',
      started_at: new Date(now + 60_000).toISOString(),
      created_at: new Date(now + 60_000).toISOString(),
    });
    store.verdicts.push({
      id: 'vd_pass',
      tenant_id: 'ten_demo',
      test_run_id: 'run_pass',
      target_id: 'tgt_1',
      verdict: 'pass',
      explanation: 'later pass',
      created_at: new Date(now + 60_000).toISOString(),
    });

    const reread = getReport(CTX, scoped.id);
    assert.deepEqual(reread.summary, frozen);
    assert.equal(auditActions().includes('report.exported'), false);
    listReports(CTX);
    assert.equal(auditActions().includes('report.exported'), false);

    const exported = exportReport(CTX, scoped.id, 'json');
    assert.deepEqual(exported.payload.runs.map((run) => run.id), ['run_02', 'run_05']);
    assert.equal(exported.payload.runs.find((run) => run.id === 'run_05').status, 'verdicted');
    assert.equal(exported.payload.summary.findings_snapshot.items[0].status, 'open');
    assert.equal(JSON.stringify(exported.payload).includes('run_pass'), false);
    assert.equal(JSON.stringify(exported).includes(HEADER_MARKER), false);
    assert.equal(auditActions().filter((action) => action === 'report.generated').length, 2);
    assert.equal(auditActions().filter((action) => action === 'report.exported').length, 1);
    assert.equal((store.notificationEvents ?? []).length, 0);
    assert.deepEqual(getReport(CTX, scoped.id).summary, frozen);
  });

  it('exports an older report from live rows when no snapshot was stored', () => {
    const store = getStore();
    store.testRuns.push({
      id: 'run_live',
      tenant_id: 'ten_demo',
      target_id: 'tgt_1',
      target_group_id: 'tg_1',
      check_id: 'origin.direct_bypass.safe',
      status: 'running',
      created_at: new Date().toISOString(),
    });
    store.reports.push({
      id: 'report_old',
      tenant_id: 'ten_demo',
      kind: 'technical',
      title: 'Old',
      status: 'ready',
      period: null,
      summary: { open_findings: 0, period: null, readiness_score: 12 },
      run_ids: ['run_live'],
      created_at: '2026-01-01T00:00:00.000Z',
      created_by: 'usr_test',
    });
    const first = exportReport(CTX, 'report_old', 'json');
    assert.equal(first.payload.runs[0].status, 'running');
    store.testRuns[0].status = 'verdicted';
    const second = exportReport(CTX, 'report_old', 'json');
    assert.equal(second.payload.runs[0].status, 'verdicted');
    assert.equal(second.payload.summary.readiness_score, 12);
  });
});

describe('support recorded audit time', () => {
  beforeEach(() => {
    freshStore();
  });

  it('maps dev audit timestamp and a created_at alias without SLA or contact fields', () => {
    const store = getStore();
    store.auditLog.push({
      id: 'aud_alias',
      tenant_id: 'ten_demo',
      action: 'note',
      actor_role: 'admin',
      resource_type: 'report',
      resource_id: 'report_x',
      created_at: '2026-02-02T00:00:00.000Z',
    });
    const summary = getCurrentSubscriptionSummary(CTX);
    const row = summary.support.recent_audit[0];
    assert.equal(row.timestamp, '2026-02-02T00:00:00.000Z');
    assert.equal(row.timestamp_source, 'audit_log.created_at_alias');
    assert.equal('created_at' in row, false);
    assert.equal(summary.as_of_source, 'subscription_summary_clock');
    assert.equal(summary.support.as_of, summary.as_of);
    for (const key of ['sla', 'support_hours', 'contact', 'coverage', 'contact_uri']) {
      assert.equal(key in summary.support, false);
      assert.equal(key in summary, false);
    }
    assert.deepEqual(Object.keys(summary.usage).sort(), [
      'agents',
      'audit_events',
      'open_findings',
      'pending_high_scale_requests',
      'safe_runs_started_last_hour',
      'target_groups',
      'users',
    ]);
  });

  it('maps a Postgres created_at alias back to timestamp and records the summary clock', async () => {
    const service = createPostgresSubscriptionServices({
      internalManagement: {
        getTenantDetail: async () => ({
          account: { support_owner: null, lifecycle_state: 'active', region: null },
          users: [],
          subscription: null,
          recent_tenant_audit: [{
            id: 'aud_1',
            action: 'report.generated',
            staff_role: 'admin',
            resource_type: 'report',
            resource_id: 'report_1',
            created_at: '2026-03-01T00:00:00.000Z',
          }],
        }),
      },
      coreCatalog: { listTargetGroups: async () => [] },
      validationEvidence: { listTestRuns: async () => [], listFindings: async () => [] },
      highScale: { listHighScaleRequests: async () => [] },
    }, { now: () => new Date('2026-04-01T00:00:00.000Z') });

    const summary = await service.getCurrentSubscriptionSummary({ tenantId: 'ten_demo', userId: 'usr_test', role: 'admin' });
    assert.equal(summary.as_of, '2026-04-01T00:00:00.000Z');
    assert.equal(summary.as_of_source, 'subscription_summary_clock');
    assert.equal(summary.support.as_of, summary.as_of);
    assert.equal(summary.support.recent_audit[0].timestamp, '2026-03-01T00:00:00.000Z');
    assert.equal(summary.support.recent_audit[0].timestamp_source, 'audit_log.created_at_alias');
    assert.equal('created_at' in summary.support.recent_audit[0], false);
    assert.equal(summary.usage.users, 0);
  });
});

describe('postgres report adapter scope gate', () => {
  it('does not fall back to an estate report when the repository cannot validate scope', async () => {
    const calls = [];
    const { reports } = createPostgresReportServices({
      reports: {
        createReport: async () => {
          calls.push('create');
          return {};
        },
        getReport: async () => null,
        listReports: async () => [],
        listRunsForReport: async () => [],
        listVerdictsForRunIds: async () => [],
      },
      validationEvidence: {
        listTestRuns: async () => {
          calls.push('runs');
          return [];
        },
        listFindings: async () => [],
        getFinding: async () => null,
      },
      audit: {
        appendAuditEvent: async () => {
          calls.push('audit');
        },
        getLastAuditEntry: async () => null,
      },
    });
    const result = await reports.createReport(CTX, { target_ids: ['tgt_1'] });
    assert.equal(result.error, 'report_scope_unavailable');
    assert.deepEqual(calls, []);
  });

  it('uses the generation world and a frozen export without a live run reread', async () => {
    const calls = [];
    let stored = null;
    const { reports } = createPostgresReportServices({
      reports: {
        readReportGenerationWorld: async () => ({
          legacy: false,
          found_targets: [{ id: 'tgt_1', target_group_id: 'tg_1', deleted_at: null }],
          found_groups: null,
          found_runs: [{
            id: 'run_b',
            target_id: 'tgt_1',
            target_group_id: 'tg_1',
            check_id: 'origin.direct_bypass.safe',
            status: 'verdicted',
            created_at: '2026-06-01T00:00:00.000Z',
          }, {
            id: 'run_a',
            target_id: 'tgt_1',
            target_group_id: 'tg_1',
            check_id: 'origin.direct_bypass.safe',
            status: 'verdicted',
            created_at: '2026-06-02T00:00:00.000Z',
          }],
          members: [{ id: 'tgt_1', target_group_id: 'tg_1', kind: 'fqdn', value: 'origin.test', declaration: {}, group_declaration: {} }],
          member_total: 1,
          runs: [],
          run_total: 2,
          run_total_unwindowed: 2,
          findings: [],
          finding_total: 0,
          finding_total_unwindowed: 0,
          open_finding_total: 0,
          verdicts: [],
          evidence: [],
          evidence_total: 0,
        }),
        createReport: async (_ctx, record) => {
          stored = record;
          return record;
        },
        getReport: async () => stored,
        listReports: async () => [],
        listRunsForReport: async () => {
          calls.push('live-runs');
          return [];
        },
        listVerdictsForRunIds: async () => {
          calls.push('live-verdicts');
          return [];
        },
      },
      validationEvidence: {
        listTestRuns: async () => {
          calls.push('list-runs');
          return [];
        },
        listFindings: async () => [],
        getFinding: async () => null,
      },
      audit: {
        appendAuditEvent: async () => {},
        getLastAuditEntry: async () => ({ entry_hash: 'prev' }),
      },
    }, { now: () => new Date('2026-06-03T00:00:00.000Z'), newId: () => 'report_world' });

    const created = await reports.createReport(CTX, { target_ids: ['tgt_1'], run_ids: ['run_b', 'run_a'] });
    assert.deepEqual(created.run_ids, ['run_b', 'run_a']);
    assert.equal(created.summary.primary_run_id, null);
    assert.equal(created.summary.snapshot_frozen, true);
    assert.equal(created.summary.readiness_score_status, 'unknown');
    assert.equal(calls.includes('list-runs'), false);
    const exported = await reports.exportReport(CTX, created.id, 'json');
    assert.deepEqual(exported.payload.runs.map((run) => run.id), ['run_b', 'run_a']);
    assert.equal(calls.includes('live-runs'), false);
    assert.equal(calls.includes('live-verdicts'), false);
  });
});
