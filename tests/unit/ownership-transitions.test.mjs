import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { effectiveTargetVerifications } from '../../src/lib/effectiveTargetVerification.mjs';
import { issueChallenge, verifyChallenge } from '../../src/services/dnsOwnership.mjs';
import { confirmOwnership, confirmTarget, targetOwnershipProof, getLadder } from '../../src/services/ownershipVerification.mjs';
import { bulkImportTargets, backfillDemoAutoVerifications } from '../../src/services/targetGroups.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'owner' };
const originalDemo = process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
afterEach(() => {
  if (originalDemo === undefined) delete process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS;
  else process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = originalDemo;
  freshStore();
});
function row(at, overrides = {}) {
  return { id: 'tv', tenant_id: ctx.tenantId, target_id: 'tgt_1', state: 'dns_verified',
    source_kind: 'dns_txt', source_ref: { dns_challenge_id: 'dns_1' }, transitioned_at: at, ...overrides };
}
function projection(rows, targets = [{ id: 'tgt_1', tenant_id: ctx.tenantId }]) {
  return effectiveTargetVerifications({ targets, targetVerifications: rows }, ctx.tenantId).get('tgt_1');
}

for (const rows of [
  [row('2026-01-01T01:00:00+01:00'), row('2026-01-01T00:30:00Z', { state: 'pending' })],
  [row('2026-01-01T00:00:00.100Z'), row('2026-01-01T00:00:00.100001Z', { state: 'pending' })],
  [row('2026-01-01T00:00:00.1Z'), row('2026-01-01T00:00:00.100001Z', { state: 'pending' })],
]) {
  test(`latest uses exact UTC instant: ${rows.map((item) => item.transitioned_at).join(' / ')}`, () => {
    assert.equal(projection(rows).state, 'pending');
    assert.equal(projection([...rows].reverse()).state, 'pending');
  });
}
for (const conflict of [{ state: 'pending' }, { source_kind: 'user_attestation' }, { source_ref: { dns_challenge_id: 'dns_other' } }]) {
  test(`conflicting equal-time ${Object.keys(conflict)[0]} fails closed without history mutation`, () => {
    const rows = [row('2026-01-01T00:00:00.1Z'), row('2026-01-01T01:00:00.100000+01:00', conflict)];
    const before = JSON.stringify(rows);
    for (const candidate of [rows, [...rows].reverse()]) {
      const latest = projection(candidate);
      assert.equal(latest.state, 'pending');
      assert.equal(latest.source_kind, 'ownership_ambiguous');
    }
    assert.equal(JSON.stringify(rows), before);
  });
}
test('equivalent duplicate provenance ignores row ID and object key order', () => {
  const source_ref = { dns_challenge_id: 'dns_1', details: { a: 1, b: 2 } };
  const latest = projection([row('2026-01-01T00:00:00.1Z', { source_ref }),
    row('2026-01-01T01:00:00.100000+01:00', { id: 'duplicate', source_ref: { details: { b: 2, a: 1 }, dns_challenge_id: 'dns_1' } })]);
  assert.equal(latest.state, 'dns_verified');
});
test('a strictly later valid row supersedes historical equal-time ambiguity', () => {
  assert.equal(projection([row('2026-01-01T00:00:00Z'), row('2026-01-01T00:00:00Z', { state: 'pending' }),
    row('2026-01-01T00:00:00.001Z')]).state, 'dns_verified');
});
for (const at of [undefined, null, '', 'not-a-date', 'infinity', '2026-02-30T00:00:00Z', '2026-01-01T00:00:00', '2026-01-01T00:00:60Z']) {
  test(`malformed history clock ${String(at)} fails closed`, () => {
    const rows = [row(at), row('2026-01-01T00:00:00Z')];
    assert.equal(projection(rows).state, 'pending');
    assert.equal(projection(rows.reverse()).state, 'pending');
  });
}
test('malformed foreign tenant/target rows do not poison the requested target', () => {
  assert.equal(projection([row('2026-01-01T00:00:00Z'), row(null, { tenant_id: 'other' }), row(null, { target_id: 'other' })]).state, 'dns_verified');
});
for (const demo of [false, true]) {
  test(`inheritance and demo=${demo} do not upgrade own ambiguous history or ownership gate`, () => {
    freshStore();
    process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = demo ? ctx.tenantId : '';
    const store = getStore();
    store.targets[0].value = 'child.origin.test';
    store.targets[0].metadata = { tags: ['subdomain-of:parent'] };
    store.targets.push({ id: 'parent', tenant_id: ctx.tenantId, target_group_id: 'tg_1', kind: 'fqdn', value: 'origin.test' });
    store.targetVerifications = [row('2026-01-01T00:00:00Z'), row('2026-01-01T00:00:00Z', { state: 'pending' }),
      row('2026-01-01T00:00:00Z', { target_id: 'parent' })];
    assert.equal(effectiveTargetVerifications(store, ctx.tenantId).get('tgt_1').state, 'pending');
    assert.equal(targetOwnershipProof(ctx, store.targetGroups[0], 'tgt_1').verified, false);
    if (demo) assert.equal(getLadder(ctx, 'tg_1').steps.find((step) => step.id === 'user_confirmed').done, false);
  });
}

test('allocator advances above complete scoped maximum and never mutates history', async () => {
  const { allocateOwnershipTransitionAt } = await import('../../src/lib/ownershipTransitions.mjs');
  const rows = [row('2026-01-01T00:00:00.100001Z'), row('2026-01-01T00:00:00.050Z'),
    row(null, { tenant_id: 'other' }), row('+275760-09-13T00:00:00.000Z', { target_id: 'other' })];
  const store = { targetVerifications: rows };
  const before = JSON.stringify(rows);
  const now = Date.parse('2026-01-01T00:00:00.010Z');
  assert.equal(allocateOwnershipTransitionAt(store, ctx.tenantId, 'tgt_1', now), '2026-01-01T00:00:00.101Z');
  assert.equal(JSON.stringify(rows), before);
  rows.push(row('2026-01-01T00:00:00.101Z'));
  assert.equal(allocateOwnershipTransitionAt(store, ctx.tenantId, 'tgt_1', now), '2026-01-01T00:00:00.102Z');
});
for (const at of ['not-a-date', null, '+275760-09-13T00:00:00.000Z', '+275760-09-13T01:00:00+01:00']) {
  test(`allocator rejects malformed/non-advancable history ${String(at)}`, async () => {
    const { allocateOwnershipTransitionAt } = await import('../../src/lib/ownershipTransitions.mjs');
    assert.throws(() => allocateOwnershipTransitionAt({ targetVerifications: [row(at)] }, ctx.tenantId, 'tgt_1', 0),
      (error) => error.code === 'ownership_transition_invalid');
  });
}
test('allocator preserves the wall clock when already later and handles epoch/boundaries exactly', async () => {
  const { allocateOwnershipTransitionAt } = await import('../../src/lib/ownershipTransitions.mjs');
  for (const [at, now, expected] of [
    ['1969-12-31T23:59:59.999001Z', -100, '1970-01-01T00:00:00.000Z'],
    ['2026-01-01T00:00:00.100Z', 0, '2026-01-01T00:00:00.101Z'],
    ['2026-01-01T00:00:00.100001Z', Date.parse('2026-01-01T00:00:00.200Z'), '2026-01-01T00:00:00.200Z'],
    ['+275760-09-12T23:59:59.999999Z', 0, '+275760-09-13T00:00:00.000Z'],
    ['-271821-04-20T00:00:00.000001Z', -8640000000000000, '-271821-04-20T00:00:00.001Z'],
    ['-271821-04-19T23:00:00.000001-01:00', -8640000000000000, '-271821-04-20T00:00:00.001Z'],
  ]) assert.equal(allocateOwnershipTransitionAt({ targetVerifications: [row(at)] }, ctx.tenantId, 'tgt_1', now), expected);
});
for (const now of [NaN, Infinity, -Infinity, 0.5, 8640000000000001]) {
  test(`allocator rejects invalid wall clock ${String(now)}`, async () => {
    const { allocateOwnershipTransitionAt } = await import('../../src/lib/ownershipTransitions.mjs');
    assert.throws(() => allocateOwnershipTransitionAt({}, ctx.tenantId, 'tgt_1', now),
      (error) => error.code === 'ownership_transition_invalid');
  });
}

test('provider proof still requires current eligible provider evidence', () => {
  const observedAt = new Date(Date.now() - 1000).toISOString();
  const source_ref = { connector_id: 'connector', provider: 'cloudflare', snapshot_kind: 'dns_zone',
    evidence_source: 'provider_api', snapshot_id: 'snapshot', resource_ref_hash: 'resource',
    observed_at: observedAt, poll_generation: observedAt };
  const store = {
    targets: [{ id: 'tgt_1', tenant_id: ctx.tenantId, kind: 'fqdn', value: 'origin.test' }],
    targetVerifications: [row(observedAt, { state: 'provider_verified', source_kind: 'provider_account', source_ref })],
    wafConnectors: [{ id: 'connector', tenant_id: ctx.tenantId, provider: 'cloudflare', status: 'active',
      has_secret: true, last_success_at: observedAt, last_success_revision: 1 }],
    wafConnectorSnapshots: [{ id: 'snapshot', tenant_id: ctx.tenantId, connector_id: 'connector',
      provider: 'cloudflare', snapshot_kind: 'dns_zone', evidence_source: 'provider_api', resource_ref_hash: 'resource',
      observed_at: observedAt, poll_revision: 1, summary: { hostnames: ['origin.test'], ownership_eligible: true, resource_status: 'active' } }],
  };
  const latest = () => effectiveTargetVerifications(store, ctx.tenantId).get('tgt_1').state;
  assert.equal(latest(), 'provider_verified');
  store.wafConnectors[0].status = 'revoked';
  assert.equal(latest(), 'pending');
  store.wafConnectors[0].status = 'active';
  store.wafConnectorSnapshots[0].summary.ownership_eligible = false;
  assert.equal(latest(), 'pending');
  store.wafConnectorSnapshots[0].summary.ownership_eligible = true;
  store.wafConnectorSnapshots[0].poll_revision = 2;
  assert.equal(latest(), 'pending');
});

test('demo backfill cannot append over conflicting pending source references', () => {
  freshStore();
  process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = ctx.tenantId;
  const store = getStore();
  store.targetVerifications = [row('2026-01-01T00:00:00Z', { state: 'pending' }),
    row('2026-01-01T00:00:00Z', { state: 'pending', source_ref: { dns_challenge_id: 'other' } })];
  const before = JSON.stringify(store.targetVerifications);
  assert.deepEqual(backfillDemoAutoVerifications(ctx), { verified_count: 0, target_ids: [] });
  assert.equal(store.auditLog.length, 0);
  assert.equal(JSON.stringify(store.targetVerifications), before);
});

function seedLegacy() {
  const store = getStore();
  store.ownershipVerifications = [{ id: 'own', tenant_id: ctx.tenantId, target_group_id: 'tg_1', target_id: 'tgt_1',
    declared_fqdn: store.targets[0].value, status: 'verified', created_at: '2020-01-01T00:00:00Z' }];
}
const future = '2099-01-01T00:00:00.100001Z';
test('DNS append advances past fractional future history and remains idempotent', async () => {
  freshStore();
  getStore().targetVerifications = [row(future, { state: 'pending' })];
  const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
  const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async () => [[issued.challenge.record_value]] });
  assert.equal(result.verified, true);
  assert.equal(getStore().targetVerifications.at(-1).transitioned_at, '2099-01-01T00:00:00.101Z');
  const count = getStore().auditLog.length;
  await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async () => { throw new Error('must not resolve'); } });
  assert.equal(getStore().targetVerifications.length, 2);
  assert.equal(getStore().auditLog.length, count);
});
for (const path of ['legacy', 'loa', 'demo']) {
  test(`${path} append advances past fractional future history`, () => {
    freshStore();
    getStore().targetVerifications = [row(future, path === 'demo' ? { state: 'pending' } : {})];
    if (path === 'legacy') { seedLegacy(); assert.equal(confirmOwnership(ctx, 'own').error, undefined); }
    if (path === 'loa') assert.equal(confirmTarget(ctx, 'tg_1', 'tgt_1').error, undefined);
    if (path === 'demo') {
      process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = ctx.tenantId;
      assert.equal(backfillDemoAutoVerifications(ctx).verified_count, 1);
    }
    assert.equal(getStore().targetVerifications.at(-1).transitioned_at, '2099-01-01T00:00:00.101Z');
  });
}
test('import and demo append are strictly ordered with a fixed clock', (t) => {
  freshStore();
  process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = ctx.tenantId;
  t.mock.timers.enable({ apis: ['Date'], now: Date.parse('2026-01-01T00:00:00.100Z') });
  const imported = bulkImportTargets(ctx, 'tg_1', { items: [{ kind: 'fqdn', value: 'import.example.test' }] });
  assert.equal(imported.count, 1);
  const rows = getStore().targetVerifications.filter((item) => item.target_id === imported.imported[0].id);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].transitioned_at, '2026-01-01T00:00:00.100Z');
  assert.equal(rows[1].transitioned_at, '2026-01-01T00:00:00.101Z');
});
test('import rejects an invalid allocation clock before target mutation or success audit', (t) => {
  freshStore();
  const store = getStore();
  const before = JSON.stringify({ targets: store.targets, rows: store.targetVerifications, audits: store.auditLog });
  t.mock.method(Date, 'now', () => Infinity);
  assert.throws(() => bulkImportTargets(ctx, 'tg_1', { items: [{ kind: 'fqdn', value: 'clock.example.test' }] }),
    (error) => error.code === 'ownership_transition_invalid');
  assert.equal(JSON.stringify({ targets: store.targets, rows: store.targetVerifications, audits: store.auditLog }), before);
});
for (const path of ['dns', 'legacy', 'loa', 'demo']) {
  test(`${path} malformed chronology produces no success audit, append, or ownership mutation`, async () => {
    freshStore();
    const store = getStore();
    store.targetVerifications = [row(null)];
    let action;
    if (path === 'dns') {
      const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
      action = () => verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async () => [[issued.challenge.record_value]] });
    } else if (path === 'legacy') { seedLegacy(); action = () => confirmOwnership(ctx, 'own'); }
    else if (path === 'loa') action = () => confirmTarget(ctx, 'tg_1', 'tgt_1');
    else {
      store.targetVerifications[0].state = 'pending';
      process.env.ASTRANULL_DEMO_AUTO_VERIFY_TENANTS = ctx.tenantId;
      action = () => backfillDemoAutoVerifications(ctx);
    }
    const audits = store.auditLog.length;
    const before = JSON.stringify({ rows: store.targetVerifications, targets: store.targets, challenges: store.dnsChallenges, ownership: store.ownershipVerifications });
    try {
      const result = await action();
      if (path === 'demo') assert.equal(result.verified_count, 0);
      else assert.ok(result.error, 'malformed chronology must not return a success');
    } catch (error) { assert.equal(error.code, 'ownership_transition_invalid'); }
    assert.equal(store.auditLog.length, audits);
    assert.equal(JSON.stringify({ rows: store.targetVerifications, targets: store.targets, challenges: store.dnsChallenges, ownership: store.ownershipVerifications }), before);
  });
}
