import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { sha256Hex } from '../../src/lib/authorizationArtifactLedger.mjs';
import { computeScopeHashFromTargets } from '../../src/lib/scopeHash.mjs';
import { WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES } from '../../src/contracts/wafOffensive.mjs';
import { createPostgresWafOffensiveServices } from '../../src/persistence/postgres/wafOffensiveServiceAdapters.mjs';

const NOW = new Date('2026-09-27T03:00:00.000Z');
const CTX_ENGINEER = { tenantId: 'ten_a', userId: 'usr_eng', role: 'engineer' };
const CTX_SOC_A = { tenantId: 'ten_a', userId: 'usr_soc_a', role: 'soc' };
const CTX_SOC_B = { tenantId: 'ten_a', userId: 'usr_soc_b', role: 'soc' };
const TARGETS = [{ id: 'tgt_a', kind: 'fqdn', value: 'app.example.test' }];

function clone(value) {
  return value == null ? value : structuredClone(value);
}

function createMemoryHarness() {
  const state = {
    requests: [],
    reports: [],
    audit: [],
    validationRuns: [],
    killSwitchActive: false,
    targetGroup: { id: 'tg_a', targets: clone(TARGETS) },
  };
  let idSequence = 0;

  const wafOffensive = {
    async createOffensiveRequest(ctx, record) {
      const stored = { ...clone(record), tenant_id: ctx.tenantId };
      state.requests.push(stored);
      return clone(stored);
    },
    async listOffensiveRequests(ctx) {
      return state.requests.filter((row) => row.tenant_id === ctx.tenantId).map(clone);
    },
    async getOffensiveRequest(ctx, id) {
      return clone(state.requests.find((row) => row.tenant_id === ctx.tenantId && row.id === id) ?? null);
    },
    async withLockedOffensiveRequest(ctx, id, callback) {
      const row = state.requests.find((entry) => entry.tenant_id === ctx.tenantId && entry.id === id);
      if (!row) return null;
      return callback(clone(row), { client: { transaction: 'fake' } });
    },
    async saveOffensiveRequest(ctx, record) {
      const index = state.requests.findIndex(
        (entry) => entry.tenant_id === ctx.tenantId && entry.id === record.id,
      );
      if (index < 0) return null;
      state.requests[index] = { ...clone(record), tenant_id: ctx.tenantId };
      return clone(state.requests[index]);
    },
    async getOffensiveReport(ctx, requestId) {
      return clone(state.reports.find(
        (entry) => entry.tenant_id === ctx.tenantId
          && entry.waf_offensive_request_id === requestId,
      ) ?? null);
    },
    async upsertOffensiveReport(ctx, requestId, report) {
      const index = state.reports.findIndex(
        (entry) => entry.tenant_id === ctx.tenantId
          && entry.waf_offensive_request_id === requestId,
      );
      const stored = { ...clone(report), tenant_id: ctx.tenantId };
      if (index < 0) state.reports.push(stored);
      else state.reports[index] = { ...state.reports[index], ...stored };
      return clone(index < 0 ? stored : state.reports[index]);
    },
    async createOffensiveWafValidationRun(ctx, record) {
      const stored = { ...clone(record), tenant_id: ctx.tenantId };
      state.validationRuns.push(stored);
      return clone(stored);
    },
  };

  const repositories = {
    wafOffensive,
    wafPosture: {
      async getWafAsset(ctx, id) {
        if (ctx.tenantId !== 'ten_a' || id !== 'waf_a') return null;
        return { id: 'waf_a', tenant_id: 'ten_a', target_group_id: 'tg_a', target_id: 'tgt_a' };
      },
    },
    coreCatalog: {
      async getTargetGroup(ctx, id) {
        if (ctx.tenantId !== 'ten_a' || id !== state.targetGroup?.id) return null;
        return clone(state.targetGroup);
      },
    },
    killSwitch: {
      async isKillSwitchActiveForTenant() {
        return state.killSwitchActive;
      },
    },
    audit: {
      async appendAuditEvent(event, options) {
        if (options?.client) assert.equal(options.client.transaction, 'fake');
        state.audit.push(clone(event));
        return event;
      },
    },
  };

  const wafPostureServices = {
    async createSocOffensiveWafValidation(ctx, body, options) {
      assert.equal(options.client.transaction, 'fake');
      const run = {
        id: `wafrun_${state.validationRuns.length + 1}`,
        tenant_id: ctx.tenantId,
        waf_asset_id: body.waf_asset_id,
        offensive_request_id: body.offensive_request_id,
        mode: body.modes[0],
        status: 'planned',
        execution_class: 'offensive_suite',
      };
      state.validationRuns.push(run);
      return { validation_run: clone(run) };
    },
  };

  const service = createPostgresWafOffensiveServices(repositories, {
    now: () => new Date(NOW),
    newId: (prefix) => `${prefix}_${++idSequence}`,
    wafPostureServices,
  });
  return { service, state, repositories, wafPostureServices };
}

function requestBody() {
  return {
    waf_asset_id: 'waf_a',
    objective: 'Validate bounded staging WAF behavior',
    requested_suites: ['sqli_offensive', 'xss_offensive'],
    emergency_contacts: ['ops@example.invalid'],
    stop_criteria: 'Stop on origin impact',
    scope_confirmation: true,
    staging_only: true,
  };
}

function artifactBody(type) {
  return {
    type,
    content_sha256: sha256Hex(`unit-waf-offensive:${type}`),
    reference_uri: `metadata://waf-offensive/${type}`,
    approval_reference: 'WOF-UNIT-001',
    approver: 'Customer approver',
    valid_window: {
      valid_from: new Date(NOW.getTime() - 60_000).toISOString(),
      valid_to: new Date(NOW.getTime() + 3_600_000).toISOString(),
    },
    approved_targets: ['tg_a'],
    approved_scenario_families: ['sqli_offensive', 'xss_offensive'],
    emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
    abort_criteria: { threshold: 'origin_impact', auto_stop: true },
  };
}

async function prepareScheduled(service) {
  const created = await service.createOffensiveRequest(CTX_ENGINEER, requestBody());
  const requestId = created.offensive_request.id;
  for (const type of WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES) {
    const uploaded = await service.addArtifact(CTX_ENGINEER, requestId, artifactBody(type));
    const reviewed = await service.reviewArtifact(
      CTX_SOC_A,
      requestId,
      uploaded.artifact.id,
      { status: 'accepted' },
    );
    assert.equal(reviewed.authorization_pack_status.complete, type === WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES.at(-1));
  }
  const approved = await service.transitionOffensiveRequest(CTX_SOC_A, requestId, 'approve');
  assert.equal(approved.offensive_request.state, 'approved');
  assert.equal(
    approved.offensive_request.scope_hash,
    computeScopeHashFromTargets('tg_a', TARGETS),
  );
  const scheduled = await service.transitionOffensiveRequest(CTX_SOC_A, requestId, 'schedule', {
    window_start: new Date(NOW.getTime() - 60_000).toISOString(),
    window_end: new Date(NOW.getTime() + 3_600_000).toISOString(),
  });
  assert.equal(scheduled.offensive_request.state, 'scheduled');
  return requestId;
}

describe('Postgres WAF offensive service adapter', () => {
  it('fails construction when a required repository or WAF validation service is absent', () => {
    assert.throws(
      () => createPostgresWafOffensiveServices({}, {}),
      /repositories\.wafOffensive/,
    );
    const { repositories } = createMemoryHarness();
    assert.throws(
      () => createPostgresWafOffensiveServices(repositories, {}),
      /createSocOffensiveWafValidation/,
    );
  });

  it('runs the locked two-person workflow and audits every mutation', async () => {
    const { service, state } = createMemoryHarness();
    const requestId = await prepareScheduled(service);

    const started = await service.transitionOffensiveRequest(CTX_SOC_A, requestId, 'start');
    assert.equal(started.offensive_request.state, 'running');
    assert.equal(started.offensive_request.waf_validation_run_id, 'wafrun_1');
    assert.equal(state.validationRuns[0].execution_class, 'offensive_suite');

    const stopped = await service.transitionOffensiveRequest(
      CTX_SOC_A,
      requestId,
      'stop',
      { reason: 'suite_complete' },
    );
    assert.equal(stopped.offensive_request.state, 'stopped');

    const results = await service.recordOffensiveSuiteResults(CTX_SOC_A, requestId, {
      suite_results: [{
        suite_id: 'sqli_offensive',
        observed_action: 'block',
        passed: true,
        confidence: 0.95,
        evidence_summary: { block_page_signature_id: 'vendor-403' },
        probes_attempted: 10,
        blocked_count: 10,
      }],
    });
    assert.equal(results.suite_results.length, 1);
    assert.equal(results.suite_results[0].test_material_type, 'soc_gated_offensive_suite');

    const report = await service.upsertOffensivePostTestReport(CTX_SOC_A, requestId, {
      executive_summary: 'Approved bounded probes were blocked.',
      blocking_verdict: 'effective',
    });
    assert.equal(report.created, true);
    assert.deepEqual(report.report.suite_results, results.suite_results);

    const closed = await service.transitionOffensiveRequest(CTX_SOC_A, requestId, 'close');
    assert.equal(closed.offensive_request.state, 'closed');

    const actions = state.audit.map((entry) => entry.action);
    for (const action of [
      'waf.offensive_request.submitted',
      'waf.offensive_artifact.uploaded',
      'waf.offensive_artifact.reviewed',
      'waf.offensive_request.approved',
      'waf.offensive_request.scheduled',
      'waf.offensive_request.execution_started',
      'waf.offensive_request.execution_stopped',
      'waf.offensive_request.results_recorded',
      'waf.offensive_report.created',
      'waf.offensive_request.closed',
    ]) {
      assert.ok(actions.includes(action), `missing audit action ${action}`);
    }
    assert.equal(
      state.requests.find((entry) => entry.id === requestId).soc_approvals.length,
      1,
    );
  });

  it('starts even when an artifact was rejected after approval', async () => {
    const { service, state } = createMemoryHarness();
    const requestId = await prepareScheduled(service);
    state.requests.find((entry) => entry.id === requestId).artifacts[0].status = 'rejected';
    const started = await service.transitionOffensiveRequest(CTX_SOC_A, requestId, 'start');
    assert.equal(started.offensive_request.state, 'running');
    assert.equal(state.validationRuns.length, 1);
  });

  it('refuses start while the Postgres kill switch is active', async () => {
    const { service, state } = createMemoryHarness();
    const requestId = await prepareScheduled(service);
    state.killSwitchActive = true;
    const denied = await service.transitionOffensiveRequest(CTX_SOC_A, requestId, 'start');
    assert.equal(denied.error, 'kill_switch_active');
    assert.equal(denied.status, 409);
    assert.equal(state.validationRuns.length, 0);
    assert.equal(state.requests.find((entry) => entry.id === requestId).state, 'scheduled');
  });

  it('plans a canary-sink body suite against the stored declaration and records observations without a validation run', async () => {
    const { service, state } = createMemoryHarness();
    const requestId = await prepareScheduled(service);
    state.targetGroup.targets[0].metadata = { control_declarations: { version: 1, canary_sink: { url: 'https://app.example.test/canary' } } };
    const runsBefore = state.validationRuns.length;
    const planned = await service.planCanarySinkBody(CTX_SOC_A, requestId, {
      declared_canary_sink_url: 'https://attacker.example.invalid/sink',
      variants: ['json'],
    });
    assert.ok(planned.plan, JSON.stringify(planned));
    assert.equal(planned.plan.canary_sink_url, 'https://app.example.test/canary');
    assert.equal(planned.target_id, 'tgt_a');
    assert.equal(planned.plan.requests.length, 1);
    assert.equal(state.validationRuns.length, runsBefore);
    const observed = await service.recordCanarySinkBodyObservations(CTX_SOC_A, requestId, {
      observations: [{ id: 'json_marker', blocked: true, status_code: 403 }],
    });
    assert.equal(observed.results.variant_results[0].outcome, 'blocked');
    assert.equal(state.validationRuns.length, runsBefore);
    const stored = state.requests.find((entry) => entry.id === requestId);
    const entry = stored.suite_results.find((row) => row.kind === 'canary_sink_body_plan');
    assert.equal(entry.target_id, 'tgt_a');
    assert.equal(entry.results.variant_results[0].outcome, 'blocked');
    assert.ok(state.audit.some((row) => row.action === 'waf.offensive_canary_sink_body.planned'));
    assert.ok(state.audit.some((row) => row.action === 'waf.offensive_canary_sink_body.observed'));
  });
});
