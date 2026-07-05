import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u', role: 'owner' };

describe('probe scheduling token gate', () => {
  it('does not enqueue jobs for agents with last_token_validation_status invalid', () => {
    freshStore();

    const runnableCheck = getStore().checkCatalog.find(
      (c) => c.safety_constraints?.customer_runnable !== false,
    );
    assert.ok(runnableCheck, 'expected at least one customer-runnable check in catalog');

    getStore().agents.push(
      {
        id: 'agent_ok',
        tenant_id: 'ten_demo',
        status: 'online',
        target_group_id: 'tg_1',
        capabilities: ['canary', 'packet', 'heartbeat'],
      },
      {
        id: 'agent_bad',
        tenant_id: 'ten_demo',
        status: 'online',
        target_group_id: 'tg_1',
        last_token_validation_status: 'invalid',
        capabilities: ['canary', 'packet', 'heartbeat'],
      },
    );

    const result = startTestRun(ctx, {
      target_group_id: 'tg_1',
      check_id: runnableCheck.check_id,
      target_id: 'tgt_1',
    });

    assert.equal(result.error, undefined);
    assert.ok(result.run);

    const jobs = getStore().agentJobs;
    assert.ok(jobs.some((j) => j.agent_id === 'agent_ok'), 'expected job for agent_ok');
    assert.equal(
      jobs.filter((j) => j.agent_id === 'agent_bad').length,
      0,
      'expected no jobs for token-invalid agent',
    );
  });
});