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
  'origin.direct_reachability.safe',
  'origin.direct_bypass.safe',
  'origin.host_sni_bypass.safe',
  'waf.origin_bypass.safe',
  'l7.login_abuse_flow.safe',
  'l7.api_quota_exhaustion.safe',
  'l7.search_abuse.validation',
  'l7.export_abuse.validation',
  'l7.oauth_token_abuse.validation',
  'l7.signup_registration_abuse.validation',
];

test('checkRequiresAdditionalInput flags host_sni_bypass and declared probe-path checks', () => {
  for (const id of INPUT_REQUIRING) {
    const check = getCheckById(id);
    assert.ok(check, `check ${id} should still exist in the catalog`);
    assert.equal(checkRequiresAdditionalInput(check), true, `${id} should require additional input`);
  }
});

test('customerSelectableChecks excludes every input-requiring check', () => {
  const selectable = customerSelectableChecks(CHECK_CATALOG);
  const ids = new Set(selectable.map((c) => c.check_id));
  for (const id of INPUT_REQUIRING) {
    assert.equal(ids.has(id), false, `${id} must not be customer-selectable`);
  }
  // No selectable check requires additional input.
  assert.equal(selectable.some((c) => checkRequiresAdditionalInput(c)), false);
  // Sanity: filtering removed exactly the known set and left a non-empty catalog.
  assert.equal(CHECK_CATALOG.length - selectable.length, INPUT_REQUIRING.length);
  assert.ok(selectable.length > 0);
});

test('definitions remain resolvable for internal/orchestrator use', () => {
  for (const id of INPUT_REQUIRING) {
    assert.ok(getCheckById(id), `${id} must remain in CHECK_CATALOG for getCheckById`);
  }
});

test('full catalog browsing exposes setup requirements without broadening default dispatch selection', () => {
  freshStore();
  const defaults = listChecks();
  const full = listChecks({ scope: 'all' });
  assert.equal(full.length, CHECK_CATALOG.length);
  for (const id of INPUT_REQUIRING) {
    assert.equal(full.find((check) => check.check_id === id).requires_additional_input, true);
    assert.ok(!defaults.some((check) => check.check_id === id));
  }
  assert.ok(full.some((check) => check.risk_class === 'soc_gated'));
  assert.equal(listChecks({ scope: 'unknown' }).length, defaults.length);
});
