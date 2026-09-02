import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildPortalDemoStore, PORTAL_DEMO_IDS } from '../fixtures/portal-demo/seed.mjs';

describe('portal demo seed fixture', () => {
  it('fills every major portal surface for ten_demo', () => {
    const store = buildPortalDemoStore();
    const tenantId = PORTAL_DEMO_IDS.tenantId;

    assert.ok(store.tenants.some((row) => row.id === tenantId));
    assert.ok(store.environments.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.targetGroups.filter((row) => row.tenant_id === tenantId).length >= 1);
    assert.ok(store.targets.filter((row) => row.tenant_id === tenantId).length >= 5);
    assert.ok(store.agents.filter((row) => row.tenant_id === tenantId).length >= 1);
    assert.ok(store.testRuns.filter((row) => row.tenant_id === tenantId).length >= 3);
    assert.ok(store.findings.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.reports.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.notificationRules.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.notificationEvents.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.auditLog.filter((row) => row.tenant_id === tenantId).length >= 4);
    assert.ok(store.tenantSubscriptions.some((row) => row.tenant_id === tenantId));
    assert.ok(store.signupRequests.length >= 2);
    assert.ok(store.highScaleRequests.filter((row) => row.tenant_id === tenantId).length >= 3);
    assert.ok(store.productionReleaseEvidence.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.wafConnectors.filter((row) => row.tenant_id === tenantId).length >= 1);
    assert.ok(store.bootstrapTokens.filter((row) => row.tenant_id === tenantId).length >= 1);
    assert.ok(store.reports.some((row) => row.id === PORTAL_DEMO_IDS.reportId));
  });

  it('does not fabricate agent attribution fields on test runs', () => {
    const store = buildPortalDemoStore();
    const unsupportedFields = ['agent_id', 'agentId', 'agent_ids', 'agentIds'];
    assert.ok(
      store.testRuns.every((run) => unsupportedFields.every((field) => !Object.hasOwn(run, field))),
      'agent attribution belongs to exact run-event provenance, not test-run fixtures',
    );
  });

  it('binds readiness evidence to the remapped durable portal-demo run', () => {
    const store = buildPortalDemoStore();
    const run = store.testRuns.find((entry) => (
      entry.id === PORTAL_DEMO_IDS.runId && entry.check_id === 'origin.leak_scan.safe'
    ));
    assert.ok(run);

    for (const record of [
      store.events.find((entry) => entry.id === 'evt_portal_baseline_boost'),
      store.verdicts.find((entry) => entry.id === 'vrd_portal_baseline_boost'),
    ]) {
      assert.ok(record);
      assert.equal(record.tenant_id, PORTAL_DEMO_IDS.tenantId);
      assert.equal(record.test_run_id, run.id);
      assert.equal(record.target_group_id, run.target_group_id);
      assert.equal(record.target_id, run.target_id);
      assert.equal(record.check_id, run.check_id);
    }
  });
});
