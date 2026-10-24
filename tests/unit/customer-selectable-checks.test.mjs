import { test } from 'node:test';
import assert from 'node:assert/strict';
import { listChecks } from '../../src/services/testRuns.mjs';
import { freshStore } from '../helpers/reset.mjs';
import {
  CHECK_CATALOG,
  checkRequiresAdditionalInput,
  customerSelectableChecks,
  getCheckById,
} from '../../src/contracts/checks.mjs';

const INPUT_REQUIRING = [
  'ops.alert_workflow_marker.safe',
  'origin.direct_reachability.safe',
  'origin.direct_bypass.safe',
  'origin.host_sni_bypass.safe',
  'origin.identity_pair.head.v1',
  'origin.identity_pair.get.v1',
  'waf.origin_bypass.safe',
  'l7.login_abuse_flow.safe',
  'l7.api_quota_exhaustion.safe',
  'l7.search_abuse.validation',
  'l7.export_abuse.validation',
  'l7.oauth_token_abuse.validation',
  'l7.signup_registration_abuse.validation',
  'l3.forbidden_tcp_port.safe',
  'l3.forbidden_udp_port.safe',
  'l3.basic_deny_rule.safe',
  'l3.tcp_flag_anomaly.readiness',
  'l3.tcp_connection_flood.readiness',
  'reflect.tcp_middlebox_exposure.safe',
  'nfw.perspective_allowlist.safe',
  'waf.rate_limit_canary.validation',
  'nfw.declared_deny_tcp.safe',
  'nfw.declared_deny_udp.safe',
  'nfw.connection_limit.safe',
  'nfw.origin_lockdown.safe',
];

test('no check requires additional input any more', () => {
  for (const id of INPUT_REQUIRING) {
    const check = getCheckById(id);
    assert.ok(check, `check ${id} should still exist in the catalog`);
    assert.equal(checkRequiresAdditionalInput(check), false, `${id} should not require additional input`);
  }
});

test('customerSelectableChecks includes every check', () => {
  const selectable = customerSelectableChecks(CHECK_CATALOG);
  const ids = new Set(selectable.map((c) => c.check_id));
  for (const id of INPUT_REQUIRING) {
    assert.equal(ids.has(id), true, `${id} must be customer-selectable`);
  }
  assert.equal(selectable.some((c) => checkRequiresAdditionalInput(c)), false);
  assert.equal(selectable.length, CHECK_CATALOG.length);
  assert.ok(selectable.length > 0);
});

test('definitions remain resolvable for internal/orchestrator use', () => {
  for (const id of INPUT_REQUIRING) {
    assert.ok(getCheckById(id), `${id} must remain in CHECK_CATALOG for getCheckById`);
  }
});

test('full catalog browsing matches the default selection', () => {
  freshStore();
  const defaults = listChecks();
  const full = listChecks({ scope: 'all' });
  assert.equal(full.length, CHECK_CATALOG.length);
  assert.equal(defaults.length, CHECK_CATALOG.length);
  for (const id of INPUT_REQUIRING) {
    assert.equal(full.find((check) => check.check_id === id).requires_additional_input, false);
    assert.ok(defaults.some((check) => check.check_id === id));
  }
  assert.ok(full.some((check) => check.risk_class === 'soc_gated'));
  assert.equal(listChecks({ scope: 'unknown' }).length, defaults.length);
});
