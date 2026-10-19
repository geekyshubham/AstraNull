import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { matchesDemoAccount, isExplicitDemoTenant } from '../../src/lib/demoAutoVerify.mjs';
import { CHECK_CATALOG, isCustomerRunnable } from '../../src/contracts/checks.mjs';
import { getTenantDeploymentFeatures } from '../../src/services/tenantDeploymentFeatures.mjs';
import { startTestRun, cancelTestRun } from '../../src/services/testRuns.mjs';
import { freshStore } from '../helpers/reset.mjs';

const demo = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const reported = CHECK_CATALOG.filter((check) => ['exploit', 'pattern', 'high_scale'].includes(check.vector_family));

test('production demo login IDs are recognized together without granting other users or tenants the exception', () => {
  assert.equal(matchesDemoAccount(demo), true);
  assert.equal(matchesDemoAccount({ tenant_id: demo.tenantId, user_id: demo.userId }), true);
  assert.equal(isExplicitDemoTenant(demo, {}), true);
  for (const other of ['ten_demo', 'usr_admin', { tenantId: 'ten_demo', userId: 'someone_else' }, { tenantId: 'another_tenant', userId: 'usr_admin' }]) {
    assert.equal(matchesDemoAccount(other), false, JSON.stringify(other));
    for (const check of reported.filter((check) => check.vector_family === 'high_scale')) assert.equal(isCustomerRunnable(check, other), false);
  }
  assert.equal(getTenantDeploymentFeatures(demo, { featureFlags: {} }).demo_tenant, true);
});

test('the actual production demo admin can start all 18 reported checks and records high-scale bypass audits', () => {
  const previous = process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
  delete process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
  try {
    const store = freshStore();
    const group = store.targetGroups.find((item) => item.id === 'tg_1');
    group.safety_policy = { max_runs_per_hour: 1, min_seconds_between_runs: 30 };
    assert.equal(reported.length, 18);
    for (const check of reported) {
      const result = startTestRun(demo, { target_group_id: 'tg_1', target_id: 'tgt_1', check_id: check.check_id }, { probeMode: 'simulation' });
      assert.equal(result.error, undefined, `${check.check_id}: ${JSON.stringify(result)}`);
      assert.ok(result.run?.id, check.check_id);
      if (check.vector_family === 'high_scale') assert.ok(store.auditLog.some((entry) => entry.resource_id === result.run.id && entry.action === 'test_run.demo_gates_bypassed' && entry.metadata.bypassed.includes('soc_gated')));
      if (['running', 'collecting', 'planned'].includes(result.run.status)) assert.equal(cancelTestRun(demo, result.run.id, { reason: 'Finish isolated demo admission regression' }).error, undefined);
    }
  } finally {
    if (previous === undefined) delete process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
    else process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = previous;
  }
});
