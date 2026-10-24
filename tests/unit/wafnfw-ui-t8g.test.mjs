import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, checkAdditionalInputReason, checkRequiresAdditionalInput } from '../../src/contracts/checks.mjs';
import { targetRunnableIndex } from '../../apps/web/react/src/lib/control-declarations.mjs';
import { demoTenantSignal } from '../../apps/web/react/src/lib/target-detail.mjs';
import {
  assessmentChecks,
  individualChecks,
  targetCheckRequirement,
  withTargetRunnableChecks,
} from '../../apps/web/react/src/lib/domain-checks.mjs';

const DEMO_ENV = { ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: 'ten_demo' };
const DEMO_TARGET = { id: 'tgt_demo', kind: 'fqdn', value: 'shop.example.com', tenant_id: 'ten_demo' };
const CUSTOMER_TARGET = { id: 'tgt_cust', kind: 'fqdn', value: 'shop.example.com', tenant_id: 'ten_customer' };
const GATED_IDS = ['ops.alert_workflow_marker.safe', 'origin.host_sni_bypass.safe', 'origin.direct_bypass.safe', 'l7.api_quota_exhaustion.safe'];
const GATED = GATED_IDS.map((id) => CHECK_CATALOG.find((check) => check.check_id === id));

function serverTargetCatalog(target) {
  return GATED.map((check) => {
    const requires = checkRequiresAdditionalInput(check, { target, env: DEMO_ENV, tenantId: target.tenant_id });
    const reason = requires ? checkAdditionalInputReason(check, { target, env: DEMO_ENV, tenantId: target.tenant_id }) : undefined;
    return { ...check, requires_additional_input: requires, ...(reason ? { additional_input_reason: reason } : {}) };
  });
}

function contextFor(catalog, demoTenant) {
  return { serverRunnableIndex: targetRunnableIndex(catalog), serverSuppliesInput: demoTenant };
}

const ids = (checks) => checks.map((check) => check.check_id).sort();

describe('T8g demo tenants follow the server runnability answer for dedicated-input checks', () => {
  it('the fixture covers alert webhook, Host/SNI bypass and declared probe path checks', () => {
    assert.ok(GATED.every(Boolean));
    assert.deepEqual(new Set(GATED.map((check) => check.probe_profile.kind)), new Set(['alert_webhook_ping', 'host_sni_bypass', 'rate_limit_sequence']));
    assert.ok(GATED.find((check) => check.check_id === 'l7.api_quota_exhaustion.safe').required_customer_setup.includes('declared_api_probe_path'));
  });

  it('includes the checks in assessment and individual lists when the server says they are runnable for a demo tenant', () => {
    const catalog = serverTargetCatalog(DEMO_TARGET);
    assert.ok(catalog.every((check) => check.requires_additional_input === false && !check.additional_input_reason));
    const context = contextFor(catalog, true);
    const targetChecks = withTargetRunnableChecks([], catalog, { serverSuppliesInput: true });
    assert.deepEqual(ids(targetChecks), [...GATED_IDS].sort());
    assert.deepEqual(ids(individualChecks(targetChecks, DEMO_TARGET, context)), [...GATED_IDS].sort());
    assert.deepEqual(ids(assessmentChecks(targetChecks, DEMO_TARGET, context)), [...GATED_IDS].sort());
    for (const check of catalog) assert.equal(targetCheckRequirement(check, DEMO_TARGET, context), '');
  });

  it('sends only check ids: no callback URL or scope is derived from catalog metadata', () => {
    const catalog = serverTargetCatalog(DEMO_TARGET);
    const runAll = assessmentChecks(withTargetRunnableChecks([], catalog, { serverSuppliesInput: true }), DEMO_TARGET, contextFor(catalog, true));
    const alert = runAll.find((check) => check.check_id === 'ops.alert_workflow_marker.safe');
    assert.equal(alert, catalog.find((check) => check.check_id === 'ops.alert_workflow_marker.safe'), 'the server row is passed through untouched');
    assert.equal(alert.callback_url, undefined);
    assert.equal(alert.probe_profile.callback_url, undefined);
  });

  it('keeps a demo check out when the server answer is missing or says it is not runnable', () => {
    const catalog = serverTargetCatalog(DEMO_TARGET);
    assert.deepEqual(individualChecks(catalog, DEMO_TARGET, { serverSuppliesInput: true }), []);
    const refused = catalog.map((check) => ({ ...check, requires_additional_input: true, additional_input_reason: 'alert_webhook_required' }));
    const context = contextFor(refused, true);
    assert.deepEqual(withTargetRunnableChecks([], refused, { serverSuppliesInput: true }), []);
    assert.deepEqual(individualChecks(refused, DEMO_TARGET, context), []);
    assert.deepEqual(assessmentChecks(refused, DEMO_TARGET, context), []);
  });

  it('treats a non-demo tenant the same way: the server runnable answer decides', () => {
    const catalog = serverTargetCatalog(CUSTOMER_TARGET);
    assert.ok(catalog.every((check) => check.requires_additional_input === false));
    const context = contextFor(catalog, false);
    assert.deepEqual(ids(withTargetRunnableChecks([], catalog)), [...GATED_IDS].sort());
    assert.deepEqual(ids(individualChecks(catalog, CUSTOMER_TARGET, context)), [...GATED_IDS].sort());
    assert.deepEqual(ids(assessmentChecks(catalog, CUSTOMER_TARGET, context)), [...GATED_IDS].sort());
    const alert = catalog.find((check) => check.check_id === 'ops.alert_workflow_marker.safe');
    assert.match(targetCheckRequirement(alert, CUSTOMER_TARGET, context), /approved signed alert-webhook scope/);
  });
});

describe('T8g demo tenant signal comes only from explicit server flags', () => {
  it('reads the demo auto-verify ownership record or a demo_tenant deployment feature', () => {
    assert.equal(demoTenantSignal({ verification: { state: 'user_confirmed', source_kind: 'manual_override', source_ref: { method: 'demo_auto_verify', demo: true } } }), true);
    assert.equal(demoTenantSignal({ deploymentFeatures: { demo_tenant: true } }), true);
  });

  it('does not guess from tenant ids, other feature flags or ordinary verification', () => {
    assert.equal(demoTenantSignal(), false);
    assert.equal(demoTenantSignal({ verification: { state: 'dns_verified', source_kind: 'dns_txt', source_ref: { record: 'txt' } } }), false);
    assert.equal(demoTenantSignal({ deploymentFeatures: { waf_posture: true, connectors: true, external_discovery: true, protection_validation: true } }), false);
    assert.equal(demoTenantSignal({ deploymentFeatures: { demo_tenant: 'true' }, verification: { tenant_id: 'ten_demo', source_ref: { demo: 'yes' } } }), false);
  });
});
