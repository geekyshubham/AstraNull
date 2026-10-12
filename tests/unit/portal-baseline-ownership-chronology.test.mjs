import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { effectiveTargetVerifications } from '../../src/lib/effectiveTargetVerification.mjs';
import { buildPortalBaselineStore, PORTAL_BASELINE_IDS as ids } from '../fixtures/portal-baseline/seed.mjs';
import {
  applyPortalProvenanceDnsLadderBaseline,
  applyPortalProvenanceDnsLadderExpanded,
  PROVENANCE_DNS_LADDER,
} from '../fixtures/portal-baseline/provenance.mjs';

function dnsCount(store) {
  return [...effectiveTargetVerifications(store, ids.tenantId).values()]
    .filter((row) => row.state === 'dns_verified').length;
}

test('portal DNS ladder fixture has ordered proof history and still changes from three to four', () => {
  const store = buildPortalBaselineStore();
  applyPortalProvenanceDnsLadderBaseline(store);
  assert.equal(dnsCount(store), PROVENANCE_DNS_LADDER.baselineDnsVerified);
  for (const row of store.targetVerifications.filter((candidate) => candidate.state === 'dns_verified')) {
    const pending = store.targetVerifications.find((candidate) => candidate.target_id === row.target_id
      && candidate.tenant_id === row.tenant_id && candidate.state === 'pending');
    assert.ok(Date.parse(pending.transitioned_at) < Date.parse(row.transitioned_at));
  }
  applyPortalProvenanceDnsLadderExpanded(store);
  assert.equal(dnsCount(store), PROVENANCE_DNS_LADDER.mutatedDnsVerified);
});

test('a conflicting fixture tie still withholds proof rather than choosing the stronger state', () => {
  const store = buildPortalBaselineStore();
  for (const row of store.targetVerifications) row.transitioned_at = ids.frozenAt;
  const current = effectiveTargetVerifications(store, ids.tenantId);
  assert.equal(dnsCount(store), 0);
  assert.equal(current.get(ids.targetId).state, 'pending');
  assert.equal(current.get(ids.targetId).source_kind, 'ownership_ambiguous');
});
