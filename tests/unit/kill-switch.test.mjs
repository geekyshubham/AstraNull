import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { setKillSwitch } from '../../src/services/highScale.mjs';
import { isKillSwitchActiveForTenant } from '../../src/services/killSwitchState.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { createPostgresHighScaleServices, HIGH_SCALE_REPOSITORY_METHODS } from '../../src/persistence/postgres/highScaleServiceAdapters.mjs';
import {
  createPostgresValidationServices,
  VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS,
  VALIDATION_EVIDENCE_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createPostgresProbeJobServices } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';

const demoCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'soc' };
const otherCtx = { tenantId: 'ten_other', userId: 'u2', role: 'soc' };

function seedAgent(tenantId = 'ten_demo') {
  getStore().agents.push({
    id: `ag_${tenantId}`,
    tenant_id: tenantId,
    status: 'online',
    capabilities: ['canary', 'packet', 'heartbeat'],
    target_group_id: 'tg_1',
  });
}

function seedOtherTenant() {
  getStore().tenants.push({ id: 'ten_other', name: 'Other' });
  getStore().targetGroups.push({
    id: 'tg_other',
    tenant_id: 'ten_other',
    environment_id: 'env_demo',
    name: 'Other TG',
    expected_behavior_default: 'must_block_before_origin',
  });
  getStore().targets.push({
    id: 'tgt_other',
    tenant_id: 'ten_other',
    target_group_id: 'tg_other',
    kind: 'fqdn',
    value: 'other.test',
    expected_behavior: 'must_block_before_origin',
  });
}

describe('SOC kill switch — safe runs', () => {
  it('activating kill switch cancels active safe runs and returns cancelled_run_ids', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(demoCtx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(started.run);
    assert.equal(started.run.status, 'collecting');

    const ks = setKillSwitch(demoCtx, true, 'incident');
    assert.ok(ks.cancelled_run_ids.includes(started.run.id));
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    assert.equal(run.status, 'cancelled');
    assert.equal(run.cancelled_by_kill_switch, true);
    assert.ok(run.completed_at);
    assert.ok(
      getStore().auditLog.some(
        (a) => a.action === 'test_run.kill_switch_auto_cancel' && a.resource_id === started.run.id,
      ),
    );
  });

  it('blocks new safe run starts while kill switch is active for tenant', () => {
    freshStore();
    seedAgent();
    setKillSwitch(demoCtx, true, 'hold');
    const blocked = startTestRun(
      { tenantId: 'ten_demo', userId: 'eng', role: 'engineer' },
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    );
    assert.equal(blocked.error, 'kill_switch_active');
    assert.equal(blocked.status, 423);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.kill_switch_denied'));
  });

  it('clearing kill switch permits safe starts again', () => {
    freshStore();
    seedAgent();
    setKillSwitch(demoCtx, true, 'hold');
    setKillSwitch(demoCtx, false, 'cleared');
    const started = startTestRun(
      { tenantId: 'ten_demo', userId: 'eng', role: 'engineer' },
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    );
    assert.ok(started.run);
    assert.equal(isKillSwitchActiveForTenant('ten_demo'), false);
  });

  it('tenant-scoped kill switch does not block other tenants', () => {
    freshStore();
    seedAgent();
    seedOtherTenant();
    seedAgent('ten_other');
    getStore().socKillSwitch = {
      active: true,
      tenant_id: 'ten_other',
      reason: 'other tenant only',
      updated_at: new Date().toISOString(),
    };
    assert.equal(isKillSwitchActiveForTenant('ten_other'), true);
    assert.equal(isKillSwitchActiveForTenant('ten_demo'), false);

    const demoStart = startTestRun(
      { tenantId: 'ten_demo', userId: 'eng', role: 'engineer' },
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    );
    assert.ok(demoStart.run);

    const otherBlocked = startTestRun(otherCtx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_other',
      target_id: 'tgt_other',
    });
    assert.equal(otherBlocked.error, 'kill_switch_active');
  });

  it('legacy global active kill switch without tenant_id blocks all tenants', () => {
    freshStore();
    seedAgent();
    getStore().socKillSwitch = { active: true, reason: 'global', updated_at: new Date().toISOString() };
    assert.equal(isKillSwitchActiveForTenant('ten_demo'), true);
    const blocked = startTestRun(
      { tenantId: 'ten_demo', userId: 'eng', role: 'engineer' },
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    );
    assert.equal(blocked.error, 'kill_switch_active');
  });

  it('does not cancel verdicted or already cancelled runs on activation', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(demoCtx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    run.status = 'verdicted';
    run.completed_at = new Date().toISOString();

    getStore().testRuns.push({
      id: 'run_cancelled',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      status: 'cancelled',
      created_at: new Date().toISOString(),
    });

    const ks = setKillSwitch(demoCtx, true, 'noop');
    assert.deepEqual(ks.cancelled_run_ids, []);
    assert.equal(run.status, 'verdicted');
  });
});

/**
 * Interleaving harness for the IN-MEMORY kill-switch path.
 *
 * The memory sweep is synchronous, so there is no await point to hook the way the postgres
 * harness uses `onRunCancelled`. Instead we replace the iterator on the store's testRuns
 * array: the sweep walks it with `for...of`, so a generator that runs `hook()` at a chosen
 * point reproduces the same window — code executing while the sweep is partway through.
 * Index-based iteration keeps runs appended mid-sweep visible to the pass in progress,
 * which is how the real array behaves.
 *
 * `when: 'mid'`  -> fires after the first run is yielded (a caller racing the sweep).
 * `when: 'after'`-> fires once pass one has finished, so only pass two can observe it.
 */
function hookTestRunsSweep(when, hook) {
  const runs = getStore().testRuns;
  let fired = false;
  Object.defineProperty(runs, Symbol.iterator, {
    configurable: true,
    writable: true,
    value: function* sweepIterator() {
      for (let i = 0; i < this.length; i += 1) {
        yield this[i];
        if (when === 'mid' && !fired) {
          fired = true;
          hook();
        }
      }
      if (when === 'after' && !fired) {
        fired = true;
        hook();
      }
    },
  });
}

describe('SOC kill switch — in-memory mitigation window', () => {
  it('writes the active flag before sweeping so a mid-sweep start is rejected 423', () => {
    freshStore();
    seedAgent();
    const first = startTestRun(demoCtx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(first.run);

    let interleavedStart = null;
    hookTestRunsSweep('mid', () => {
      // Racing caller: this is the exact window in which the pre-fix code had already begun
      // sweeping but had not yet written `active`, so the start gate was still open.
      interleavedStart = startTestRun(
        { tenantId: 'ten_demo', userId: 'eng', role: 'engineer' },
        {
          check_id: 'origin.direct_bypass.safe',
          target_group_id: 'tg_1',
          target_id: 'tgt_1',
        },
      );
    });

    setKillSwitch(demoCtx, true, 'incident');

    assert.ok(interleavedStart, 'the interleaved start never ran');
    assert.equal(interleavedStart.error, 'kill_switch_active');
    assert.equal(interleavedStart.status, 423);
    assert.equal(interleavedStart.run, undefined);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.kill_switch_denied'));
    // Nothing survived the emergency stop.
    assert.equal(
      getStore().testRuns.every((r) => r.status === 'cancelled'),
      true,
    );
  });

  it('reports runs that landed during the first sweep pass in cancelled_run_ids', () => {
    freshStore();
    seedAgent();
    const first = startTestRun(demoCtx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(first.run);

    // A run that had already cleared the start gate when the flag landed, so it is written
    // to the store after pass one enumerated it. Injected directly because the gate is
    // (correctly) closed by now; only the second pass can catch it.
    hookTestRunsSweep('after', () => {
      getStore().testRuns.push({
        id: 'run_late',
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'origin.direct_bypass.safe',
        status: 'collecting',
        created_at: new Date().toISOString(),
      });
    });

    const ks = setKillSwitch(demoCtx, true, 'incident');

    assert.ok(ks.cancelled_run_ids.includes(first.run.id));
    assert.ok(
      ks.cancelled_run_ids.includes('run_late'),
      `second pass missed the late run: ${JSON.stringify(ks.cancelled_run_ids)}`,
    );
    // Merged, not concatenated: a run cancelled in pass one is reported exactly once.
    assert.equal(new Set(ks.cancelled_run_ids).size, ks.cancelled_run_ids.length);
    assert.equal(getStore().testRuns.find((r) => r.id === 'run_late').status, 'cancelled');
  });

  it('leaves the switch active when the sweep throws (fail-closed)', () => {
    freshStore();
    seedAgent();
    startTestRun(demoCtx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });

    hookTestRunsSweep('mid', () => {
      throw new Error('sweep crashed');
    });

    assert.throws(() => setKillSwitch(demoCtx, true, 'incident'), /sweep crashed/);
    // The flag is already committed, so no new traffic can start even though the sweep
    // did not finish. Failing in this direction is the point of writing the flag first.
    assert.equal(isKillSwitchActiveForTenant('ten_demo'), true);
  });
});

const PG_SOC_CTX = { tenantId: 'ten_demo', userId: 'soc_1', role: 'soc' };
const PG_ENG_CTX = { tenantId: 'ten_demo', userId: 'eng_1', role: 'engineer' };
const PG_WORKER_CTX = { tenantId: 'ten_demo', workerId: 'pw_1', role: 'probe_worker' };
const SAFE_CHECK_ID = 'origin.direct_bypass.safe';
const VALID_PROBE_BODY = Object.freeze({
  external_result: 'connected',
  safety_attestation: { requests_sent: 1, duration_ms: 10 },
});

/**
 * Interleaving harness for the postgres kill-switch path.
 *
 * The high-scale, validation and probe-job adapters are wired over ONE shared state and one
 * shared killSwitch repository, so a `startTestRun` issued from inside the sweep observes
 * exactly the flag state the sweep has committed. `onRunCancelled` fires once, immediately
 * after the first run is marked cancelled during sweep pass one — that is the window in
 * which the pre-fix code left the start gate open.
 */
function createKillSwitchInterleavingHarness(options = {}) {
  const state = {
    testRuns: [],
    probeJobs: [],
    events: [],
    audit: [],
    requests: [],
    killSwitch: { active: false },
  };
  const leaseCalls = [];
  let onRunCancelled = options.onRunCancelled ?? null;
  let failNextCancelWrite = false;

  const killSwitch = {
    async isKillSwitchActiveForTenant(ctx) {
      return ctx.tenantId === 'ten_demo' && state.killSwitch.active === true;
    },
    async getKillSwitchRecord(ctx) {
      return { ...state.killSwitch, tenant_id: ctx.tenantId };
    },
    async upsertKillSwitch(ctx, patch) {
      state.killSwitch = { ...state.killSwitch, ...patch, tenant_id: ctx.tenantId };
      return { ...state.killSwitch };
    },
  };

  const validationEvidence = {};
  for (const method of VALIDATION_EVIDENCE_REPOSITORY_METHODS) {
    validationEvidence[method] = async () => undefined;
  }
  Object.assign(validationEvidence, {
    async listTestRuns(ctx, opts = {}) {
      let runs = state.testRuns.filter((r) => r.tenant_id === ctx.tenantId);
      if (opts.targetGroupId) runs = runs.filter((r) => r.target_group_id === opts.targetGroupId);
      if (opts.statuses) runs = runs.filter((r) => opts.statuses.includes(r.status));
      if (opts.limit) runs = runs.slice(0, opts.limit);
      return runs.map((r) => ({ ...r }));
    },
    async getTestRun(ctx, id) {
      const run = state.testRuns.find((r) => r.tenant_id === ctx.tenantId && r.id === id);
      return run ? { ...run } : null;
    },
    async createTestRun(ctx, record) {
      const row = { ...record, tenant_id: ctx.tenantId };
      state.testRuns.push(row);
      return { ...row };
    },
    async updateTestRun(ctx, id, patch) {
      const idx = state.testRuns.findIndex((r) => r.id === id);
      if (idx < 0) return null;
      state.testRuns[idx] = { ...state.testRuns[idx], ...patch };
      return { ...state.testRuns[idx] };
    },
    async cancelTestRunAtomic(ctx, id, patch) {
      if (failNextCancelWrite) {
        failNextCancelWrite = false;
        throw new Error('sweep crashed');
      }
      const idx = state.testRuns.findIndex((r) => r.id === id && r.tenant_id === ctx.tenantId);
      if (idx < 0) return null;
      if (!['planned', 'running', 'collecting'].includes(state.testRuns[idx].status)) {
        return { run: { ...state.testRuns[idx] }, cancelled: false, cancelled_jobs: [] };
      }
      state.testRuns[idx] = {
        ...state.testRuns[idx],
        status: 'cancelled',
        completed_at: patch.completed_at,
        summary: patch.summary ?? state.testRuns[idx].summary,
      };
      const cancelledJobs = state.probeJobs.filter(
        (job) => job.tenant_id === ctx.tenantId
          && job.test_run_id === id
          && ['pending', 'leased'].includes(job.status),
      );
      for (const job of cancelledJobs) {
        job.status = 'cancelled';
        job.completed_at = patch.completed_at;
      }
      if (onRunCancelled) {
        const hook = onRunCancelled;
        onRunCancelled = null;
        await hook(id);
      }
      return {
        run: { ...state.testRuns[idx] },
        cancelled: true,
        cancelled_jobs: cancelledJobs.map((job) => ({ ...job })),
      };
    },
    async withRunMutationLock(ctx, runId, callback) {
      return { acquired: true, result: await callback() };
    },
    async withRunFinalizationLock(ctx, runId, callback) {
      return { acquired: true, result: await callback() };
    },
    async listRunEvents(ctx, runId, opts = {}) {
      return state.events.filter(
        (e) => e.test_run_id === runId && (!opts.signalType || e.signal_type === opts.signalType),
      );
    },
    async appendEvent(ctx, event) {
      state.events.push(event);
      return event;
    },
    async appendEventIdempotent(ctx, event) {
      state.events.push(event);
      return event;
    },
    async appendProbeResultEventIdempotent(ctx, event) {
      state.events.push(event);
      return event;
    },
    async appendEvidence(ctx, record) {
      return { id: 'ev_1', ...record };
    },
    async getVerdictForRun() {
      return null;
    },
    async createVerdictIfAbsent(ctx, record) {
      return { ...record, id: 'ver_1' };
    },
  });

  const coreCatalog = {
    async getTargetGroup(ctx, id) {
      if (id !== 'tg_1') return null;
      return {
        id: 'tg_1',
        tenant_id: 'ten_demo',
        safe_test_windows: [],
        // Pinned so the interleaved start is gated only by the kill switch, never by the
        // rate or interval guards.
        safety_policy: { max_runs_per_hour: 100, min_seconds_between_runs: 0 },
        targets: [
          {
            id: 'tgt_1',
            kind: 'ip',
            value: '203.0.113.1',
            expected_behavior: 'must_block_before_origin',
          },
        ],
      };
    },
  };

  const agentControl = {};
  for (const method of VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS) {
    agentControl[method] = async () => undefined;
  }
  agentControl.listAgents = async () => [
    {
      id: 'ag_1',
      status: 'online',
      capabilities: ['canary', 'heartbeat', 'packet'],
      target_group_id: 'tg_1',
    },
  ];
  agentControl.createAgentJob = async (ctx, job) => job;

  const probeJobs = {
    async leasePendingJobsForWorker(ctx, workerId) {
      leaseCalls.push({ tenantId: ctx.tenantId, workerId });
      const leased = state.probeJobs.filter(
        (j) => j.tenant_id === ctx.tenantId && j.status === 'pending',
      );
      for (const job of leased) {
        job.status = 'leased';
        job.leased_by = workerId;
      }
      return leased.map((j) => ({ ...j }));
    },
    async getJobById(ctx, id) {
      const job = state.probeJobs.find((j) => j.tenant_id === ctx.tenantId && j.id === id);
      return job ? { ...job } : null;
    },
    async claimPendingJobForWorker(ctx, id, workerId, leasedAt) {
      const job = state.probeJobs.find((j) => j.id === id);
      if (!job) return null;
      job.status = 'leased';
      job.leased_by = workerId;
      job.leased_at = leasedAt;
      return { ...job };
    },
    // Optimistic claim for result ingest: mirrors the production UPDATE's guard clause
    // (probeJobRepository.claimJobForResult) — expected status defaults to 'pending' and
    // the lease columns compare null-safe (`IS NOT DISTINCT FROM`), so a stale expectation
    // (status moved, lease changed hands) claims nothing and ingest 409s.
    async claimJobForResult(ctx, id, workerId, leasedAt, expected = {}) {
      const job = state.probeJobs.find(
        (j) => j.tenant_id === ctx.tenantId && j.id === id,
      );
      if (!job) return null;
      if (
        job.status !== (expected.status ?? 'pending')
        || (job.leased_by ?? null) !== (expected.leased_by ?? null)
        || (job.leased_at ?? null) !== (expected.leased_at ?? null)
      ) {
        return null;
      }
      job.status = 'leased';
      job.leased_by = workerId;
      job.leased_at = leasedAt;
      return { ...job };
    },
    async markJobCompleted(ctx, id, completedAt) {
      const job = state.probeJobs.find((j) => j.id === id);
      if (!job) return null;
      job.status = 'completed';
      job.completed_at = completedAt;
      return { ...job };
    },
    async createProbeJob(ctx, record) {
      const row = { ...record, tenant_id: ctx.tenantId };
      state.probeJobs.push(row);
      return { ...row };
    },
    async cancelOpenProbeJobsForTestRuns(ctx, testRunIds, cancelledAt) {
      const open = state.probeJobs.filter(
        (j) =>
          j.tenant_id === ctx.tenantId &&
          testRunIds.includes(j.test_run_id) &&
          (j.status === 'pending' || j.status === 'leased'),
      );
      for (const job of open) {
        job.status = 'cancelled';
        job.completed_at = cancelledAt;
      }
      return open.map((j) => ({ ...j }));
    },
  };

  const highScale = {};
  for (const method of HIGH_SCALE_REPOSITORY_METHODS) {
    highScale[method] = async () => undefined;
  }
  highScale.listRunningHighScaleRequests = async () => [];
  highScale.updateHighScaleRequest = async (ctx, id, patch) => ({ id, ...patch });

  const audit = {
    async appendAuditEvent(entry) {
      state.audit.push(entry);
      return entry;
    },
  };

  const repositories = {
    highScale,
    coreCatalog,
    audit,
    killSwitch,
    validationEvidence,
    probeJobs,
    agentControl,
  };

  return {
    state,
    leaseCalls,
    setOnRunCancelled(hook) {
      onRunCancelled = hook;
    },
    failNextCancelWrite() {
      failNextCancelWrite = true;
    },
    highScaleSvc: createPostgresHighScaleServices(repositories),
    validationSvc: createPostgresValidationServices(repositories),
    probeJobSvc: createPostgresProbeJobServices(repositories),
    seedActiveRun(id, overrides = {}) {
      const row = {
        id,
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: SAFE_CHECK_ID,
        status: 'collecting',
        created_at: new Date(Date.now() - 60_000).toISOString(),
        ...overrides,
      };
      state.testRuns.push(row);
      return row;
    },
    seedProbeJob(id, overrides = {}) {
      const row = {
        id,
        tenant_id: 'ten_demo',
        test_run_id: 'run_1',
        target_id: 'tgt_1',
        check_id: SAFE_CHECK_ID,
        vector_family: 'origin',
        status: 'leased',
        leased_by: 'pw_1',
        nonce_hash: `nh_${id}`,
        constraints: { max_requests: 1, timeout_ms: 5000 },
        ...overrides,
      };
      state.probeJobs.push(row);
      return row;
    },
  };
}

describe('SOC kill switch — postgres adapter mitigation window', () => {
  it('writes the active flag before sweeping so a mid-sweep start is rejected 423', async () => {
    const harness = createKillSwitchInterleavingHarness();
    harness.seedActiveRun('run_1');

    let flagDuringSweep = null;
    let interleavedStart = null;
    harness.setOnRunCancelled(async () => {
      // Observed from inside sweep pass one: this is the window the defect left open.
      flagDuringSweep = harness.state.killSwitch.active;
      interleavedStart = await harness.validationSvc.testRuns.startTestRun(PG_ENG_CTX, {
        check_id: SAFE_CHECK_ID,
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      });
    });

    const ks = await harness.highScaleSvc.setKillSwitch(PG_SOC_CTX, true, 'incident');

    assert.equal(flagDuringSweep, true, 'kill switch must already be active during the sweep');
    assert.equal(interleavedStart.error, 'kill_switch_active');
    assert.equal(interleavedStart.status, 423);
    assert.equal(interleavedStart.run, undefined);
    assert.equal(ks.active, true);
    assert.ok(ks.cancelled_run_ids.includes('run_1'));

    // The rejected start must not have produced a run at all.
    assert.equal(harness.state.testRuns.length, 1);
    assert.equal(harness.state.testRuns[0].status, 'cancelled');
    assert.ok(harness.state.audit.some((e) => e.action === 'test_run.kill_switch_denied'));
  });

  it('reports runs that landed during the first sweep pass in cancelled_run_ids', async () => {
    const harness = createKillSwitchInterleavingHarness();
    harness.seedActiveRun('run_1');

    // A run that cleared the start gate microseconds before the flag write and became
    // visible only after pass one had listed its runs. Pass two must catch it.
    harness.setOnRunCancelled(async () => {
      harness.seedActiveRun('run_inflight', { status: 'running' });
    });

    const ks = await harness.highScaleSvc.setKillSwitch(PG_SOC_CTX, true, 'incident');

    assert.ok(ks.cancelled_run_ids.includes('run_1'));
    assert.ok(
      ks.cancelled_run_ids.includes('run_inflight'),
      'cancelled_run_ids must be truthful about runs cancelled during the sweep',
    );
    assert.equal(new Set(ks.cancelled_run_ids).size, ks.cancelled_run_ids.length);
    for (const run of harness.state.testRuns) {
      assert.equal(run.status, 'cancelled');
    }

    // The audit event carries the same merged set as the API response.
    const activated = harness.state.audit.find((e) => e.action === 'soc.kill_switch.activated');
    assert.deepEqual(activated.metadata.cancelled_run_ids, ks.cancelled_run_ids);
    const autoCancels = harness.state.audit.filter(
      (e) => e.action === 'test_run.kill_switch_auto_cancel',
    );
    assert.deepEqual(autoCancels.map((e) => e.resource_id).sort(), ['run_1', 'run_inflight']);
  });

  it('refuses probe leases and result ingest for a kill-switched tenant', async () => {
    const harness = createKillSwitchInterleavingHarness();
    harness.seedActiveRun('run_1', { status: 'running', correlation: {} });
    harness.seedProbeJob('pjob_leased', { status: 'leased' });

    // Leased before activation: the fleet is working normally.
    harness.seedProbeJob('pjob_pending', { status: 'pending', nonce_hash: 'nh_pending' });
    const leasedBefore = await harness.probeJobSvc.listPendingProbeJobsForWorker(PG_WORKER_CTX);
    assert.equal(leasedBefore.length, 1);
    assert.equal(harness.leaseCalls.length, 1);

    await harness.highScaleSvc.setKillSwitch(PG_SOC_CTX, true, 'incident');

    // Lease path: no work is handed out, and the repository is never even queried.
    const leasedAfter = await harness.probeJobSvc.listPendingProbeJobsForWorker(PG_WORKER_CTX);
    assert.deepEqual(leasedAfter, []);
    assert.equal(harness.leaseCalls.length, 1);

    // Ingest path: the job leased before activation cannot record its probe.
    const ingest = await harness.probeJobSvc.ingestProbeResult(
      PG_WORKER_CTX,
      'pjob_leased',
      VALID_PROBE_BODY,
    );
    assert.equal(ingest.error, 'kill_switch_active');
    assert.equal(ingest.status, 423);
    assert.equal(
      harness.state.events.some((e) => e.signal_type === 'probe_result'),
      false,
      'no probe result may be recorded after the emergency stop',
    );
    const job = harness.state.probeJobs.find((j) => j.id === 'pjob_leased');
    assert.notEqual(job.status, 'completed');
    assert.ok(harness.state.audit.some((e) => e.action === 'probe_job.kill_switch_denied'));
  });

  it('leaves the switch active with runs uncancelled when the sweep fails (fail-closed)', async () => {
    const harness = createKillSwitchInterleavingHarness();
    harness.seedActiveRun('run_1');
    harness.failNextCancelWrite();

    await assert.rejects(
      () => harness.highScaleSvc.setKillSwitch(PG_SOC_CTX, true, 'incident'),
      /sweep crashed/,
    );

    // Fail-closed: the flag is already committed even though the run was NOT cancelled, so
    // nothing new can start. Re-invoking setKillSwitch completes the sweep.
    assert.equal(harness.state.killSwitch.active, true);
    assert.equal(harness.state.testRuns[0].status, 'collecting');
    const blocked = await harness.validationSvc.testRuns.startTestRun(PG_ENG_CTX, {
      check_id: SAFE_CHECK_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(blocked.error, 'kill_switch_active');

    const repaired = await harness.highScaleSvc.setKillSwitch(PG_SOC_CTX, true, 'incident');
    assert.ok(repaired.cancelled_run_ids.includes('run_1'));
  });

  it('clearing the switch restores starts and leaves no run wedged', async () => {
    const harness = createKillSwitchInterleavingHarness();
    harness.seedActiveRun('run_1');

    await harness.highScaleSvc.setKillSwitch(PG_SOC_CTX, true, 'incident');
    const cleared = await harness.highScaleSvc.setKillSwitch(PG_SOC_CTX, false, 'resolved');

    assert.equal(cleared.active, false);
    assert.deepEqual(cleared.cancelled_run_ids, []);
    assert.deepEqual(cleared.stopped_request_ids, []);
    assert.equal(harness.state.killSwitch.active, false);
    assert.ok(harness.state.audit.some((e) => e.action === 'soc.kill_switch.cleared'));

    // Runs cancelled by the activation stay cancelled; none is left mid-flight.
    assert.equal(harness.state.testRuns.every((r) => r.status === 'cancelled'), true);

    // The fleet and the start gate are both open again.
    const started = await harness.validationSvc.testRuns.startTestRun(PG_ENG_CTX, {
      check_id: SAFE_CHECK_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(started.run, `expected a run, got ${JSON.stringify(started)}`);
    harness.seedProbeJob('pjob_after', { status: 'pending', nonce_hash: 'nh_after' });
    const leased = await harness.probeJobSvc.listPendingProbeJobsForWorker(PG_WORKER_CTX);
    assert.equal(leased.length, 1);
  });
});