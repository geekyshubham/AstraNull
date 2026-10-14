import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { getCheckById, targetInputRefusal, customerSelectableChecks } from '../../src/contracts/checks.mjs';
import { resolveOriginLockdownBinding } from '../../src/lib/probeJobs.mjs';
import { deriveBindingScope, currentOriginProof } from '../../src/services/originBindings.mjs';
import { assertTenantEntitlement, assertSubscriptionLimit } from '../../src/services/subscriptions.mjs';
import { getTenantDeploymentFeatures } from '../../src/services/tenantDeploymentFeatures.mjs';
import { effectiveTargetVerifications } from '../../src/lib/effectiveTargetVerification.mjs';

describe('Ticket R6 — origin-binding pre-check demo-tenant bypass and parity', () => {
  let prevDemoTenants;

  beforeEach(() => {
    prevDemoTenants = process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
  });

  afterEach(() => {
    if (prevDemoTenants === undefined) {
      delete process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
    } else {
      process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = prevDemoTenants;
    }
  });

  const check = getCheckById('nfw.origin_lockdown.safe');
  const decl = { version: 1, origin: { lockdown_expected: true } };

  function makeFixture(tenantId) {
    const target = {
      id: `tgt_app_${tenantId}`,
      tenant_id: tenantId,
      kind: 'fqdn',
      value: 'app.example.com',
      metadata: { control_declarations: decl },
    };
    const origin = {
      id: `tgt_origin_${tenantId}`,
      tenant_id: tenantId,
      kind: 'ip',
      value: '203.0.113.10',
    };
    const binding = {
      id: `ob_${tenantId}`,
      tenant_id: tenantId,
      status: 'active',
      protected_target_id: target.id,
      origin_target_id: origin.id,
      host: 'app.example.com',
      sni: 'app.example.com',
      port: null,
      path: null,
    };
    const records = {
      targets: [target, origin],
      targetVerifications: [],
    };
    const originBindings = { bindings: [binding], records };
    return { target, origin, binding, records, originBindings };
  }

  it('(a) demo tenant with no stored verification row is runnable and selectable', () => {
    process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = 'ten_demo';
    const { target, originBindings } = makeFixture('ten_demo');

    const refusal = targetInputRefusal(check, target, decl, { originBindings });
    assert.equal(refusal, null);

    const selectable = customerSelectableChecks([check], { target, declarations: decl, originBindings });
    assert.equal(selectable.length, 1);
    assert.equal(selectable[0].check_id, 'nfw.origin_lockdown.safe');
  });

  it('(b) non-demo tenant with the same data returns origin_binding_required', () => {
    process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = 'ten_demo';
    const { target, originBindings } = makeFixture('ten_prod');

    const refusal = targetInputRefusal(check, target, decl, { originBindings });
    assert.ok(refusal);
    assert.equal(refusal.error, 'origin_binding_required');

    const selectable = customerSelectableChecks([check], { target, declarations: decl, originBindings });
    assert.equal(selectable.length, 0);
  });

  it('(c) parity: pre-check result agrees with start-path resolver for demo and non-demo tenants', () => {
    process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = 'ten_demo';

    const demo = makeFixture('ten_demo');
    const demoRefusal = targetInputRefusal(check, demo.target, decl, { originBindings: demo.originBindings });
    const demoResolved = resolveOriginLockdownBinding({
      check,
      target: demo.target,
      tenantId: 'ten_demo',
      bindings: [demo.binding],
      records: demo.records,
      deriveBindingScope,
      currentOriginProof,
    });
    assert.equal(demoRefusal, null);
    assert.equal(demoResolved.ok, true);
    assert.equal(demoResolved.address, '203.0.113.10');

    const prod = makeFixture('ten_prod');
    const prodRefusal = targetInputRefusal(check, prod.target, decl, { originBindings: prod.originBindings });
    const prodResolved = resolveOriginLockdownBinding({
      check,
      target: prod.target,
      tenantId: 'ten_prod',
      bindings: [prod.binding],
      records: prod.records,
      deriveBindingScope,
      currentOriginProof,
    });
    assert.ok(prodRefusal);
    assert.equal(prodRefusal.error, 'origin_binding_required');
    assert.ok(prodResolved.error);
    assert.equal(prodResolved.error, 'ownership_not_verified');
  });

  it('(d) regression guard: entitlements, limits, deployment features, and demo auto-verify', () => {
    process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = 'ten_demo';

    const ent = assertTenantEntitlement('ten_demo', 'waf_posture');
    assert.equal(ent.ok, true);

    const lim = assertSubscriptionLimit('ten_demo', 'targets', 100);
    assert.equal(lim.ok, true);

    const features = getTenantDeploymentFeatures({ tenantId: 'ten_demo' }, { featureFlags: {} });
    assert.equal(features.demo_tenant, true);
    assert.equal(features.waf_posture, true);
    assert.equal(features.connectors, true);
    assert.equal(features.external_discovery, true);
    const nonDemoFeatures = getTenantDeploymentFeatures({ tenantId: 'ten_other' }, { featureFlags: {} });
    assert.equal(nonDemoFeatures.demo_tenant, false);

    const unverifiedTarget = {
      id: 'tgt_demo_guard',
      tenant_id: 'ten_demo',
      target_group_id: 'grp_demo',
      kind: 'fqdn',
      value: 'guard.demo.internal',
    };
    const verifications = effectiveTargetVerifications(
      { targets: [unverifiedTarget], targetVerifications: [] },
      'ten_demo',
      [unverifiedTarget.id],
    );
    const row = verifications.get(unverifiedTarget.id);
    assert.ok(row);
    assert.equal(row.state, 'user_confirmed');
    assert.equal(row.source_ref?.method, 'demo_auto_verify');
  });
});
