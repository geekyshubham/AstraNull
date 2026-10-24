import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  SOC_GOVERNED_REASON,
  filterScheduleCheckEntries,
  isScheduleCheckSelectable,
  scheduleCheckCategoryCounts,
  scheduleCheckEntries,
} from '../../apps/web/react/src/lib/schedule-checks.mjs';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { isCustomerRunnable } from '../../src/contracts/checks.mjs';
import { getTenantDeploymentFeatures } from '../../src/services/tenantDeploymentFeatures.mjs';

const socGated = { check_id: 'hs.flood.governed', name: 'Governed flood', vector_family: 'high_scale', risk_class: 'soc_gated', safety_class: 'soc_gated' };
const notCustomer = { check_id: 'ops.manual.only', name: 'Manual only', vector_family: 'operations', safety_constraints: { customer_runnable: false } };
const waf = { check_id: 'waf.marker_rule.safe', name: 'WAF marker', vector_family: 'waf', risk_class: 'safe', safety_class: 'safe' };

describe('schedule check picker model', () => {
  it('lists every catalog check as selectable', () => {
    const entries = scheduleCheckEntries([socGated, notCustomer, waf]);
    assert.equal(entries.length, 3);
    assert.ok(entries.every((entry) => entry.selectable && entry.reason === ''));
  });

  it('makes every check selectable when the server says all checks are customer-runnable', () => {
    const entries = scheduleCheckEntries([socGated, notCustomer, waf], { allChecksRunnable: true });
    assert.ok(entries.every((entry) => entry.selectable && entry.reason === ''));
  });

  it('mirrors the server rule for every catalog check', () => {
    for (const check of CHECK_CATALOG) {
      assert.equal(isScheduleCheckSelectable(check), isCustomerRunnable(check, null), check.check_id);
    }
  });

  it('filters by name, id and category and keeps the selected check visible', () => {
    const entries = scheduleCheckEntries([socGated, notCustomer, waf]);
    assert.deepEqual(filterScheduleCheckEntries(entries, { query: 'marker' }).map((entry) => entry.id), ['waf.marker_rule.safe']);
    assert.deepEqual(filterScheduleCheckEntries(entries, { category: 'waf' }).map((entry) => entry.id), ['waf.marker_rule.safe']);
    assert.deepEqual(filterScheduleCheckEntries(entries, { query: 'zzz', keepId: 'ops.manual.only' }).map((entry) => entry.id), ['ops.manual.only']);
    const counts = scheduleCheckCategoryCounts(entries);
    assert.equal(counts[0].count, 3);
    assert.ok(counts.some((entry) => entry.id === 'waf' && entry.count === 1));
  });
});

describe('deployment features expose the all-checks rule exactly as the server applies it', () => {
  it('is true for every account', () => {
    assert.equal(getTenantDeploymentFeatures({ tenantId: 'ten_demo', userId: 'usr_admin' }, {}).all_checks_customer_runnable, true);
    assert.equal(getTenantDeploymentFeatures({ tenantId: 'ten_other', userId: 'usr_admin' }, {}).all_checks_customer_runnable, true);
  });
});
