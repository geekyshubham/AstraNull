import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildPortalDemoStore, PORTAL_DEMO_IDS } from '../fixtures/portal-demo/seed.mjs';
import { rebaseDemoStoreTimestamps } from '../../scripts/seed-dev-portal-demo.mjs';
import { validateManifest, verifyDetachedManifestSignature } from '../../src/lib/agentUpdates.mjs';
import { listAgentUpdateReleases } from '../../src/services/agentUpdates.mjs';
import { transitionHighScale } from '../../src/services/highScale.mjs';
import { resetStoreForTests } from '../../src/store.mjs';

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

  it('seeds a signed agent update release whose signer is an active trust key', () => {
    const store = buildPortalDemoStore();
    resetStoreForTests(store);
    const [release] = store.agentUpdateReleases;
    assert.equal(validateManifest(release.manifest, release.version), null);
    assert.equal(verifyDetachedManifestSignature(release.manifest, release.signature), null);

    const items = listAgentUpdateReleases({ tenantId: PORTAL_DEMO_IDS.tenantId });
    assert.equal(items.length, 1);
    const trustKey = store.agentUpdateTrustKeys.find((key) => key.status === 'active');
    assert.equal(items[0].signing_fingerprint_sha256, trustKey.fingerprint_sha256);
  });

  it('lets SOC schedule the approved demo request inside its governed window', () => {
    const now = new Date();
    resetStoreForTests(rebaseDemoStoreTimestamps(buildPortalDemoStore(), now));
    const result = transitionHighScale(
      { tenantId: PORTAL_DEMO_IDS.tenantId, userId: 'usr_soc', role: 'soc' },
      'hsr_demo_approved',
      'schedule',
      {
        window_start: new Date(now.getTime() - 60_000).toISOString(),
        window_end: new Date(now.getTime() + 3_600_000).toISOString(),
      },
    );
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.equal(result.state, 'scheduled');
  });

  it('seeds only test policies the policy contract accepts, so demo edits (Pause/Resume) work', async () => {
    const { normalizePolicyInput } = await import('../../src/contracts/testPolicyManagement.mjs');
    const { buildPortalBaselineStore } = await import('../fixtures/portal-baseline/seed.mjs').catch(() => ({}));
    const stores = [['portal-demo', buildPortalDemoStore()]];
    if (buildPortalBaselineStore) stores.push(['portal-baseline', buildPortalBaselineStore()]);
    for (const [name, store] of stores) {
      for (const policy of store.testPolicies ?? []) {
        // A PATCH re-validates the merged record, so an invalid seed breaks every later edit.
        assert.doesNotThrow(
          () => normalizePolicyInput({ state: 'paused' }, { current: policy }),
          `${name} policy ${policy.id} (cadence=${policy.cadence}, state=${policy.state}) is not editable`,
        );
      }
    }
  });
});
