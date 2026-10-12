import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  issueChallenge,
  listChallenges,
  verifyChallenge,
} from '../../src/services/dnsOwnership.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { normalizeChallengeStateForRead } from '../../src/lib/ownershipPolicy.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'owner' };

afterEach(() => {
  freshStore();
});

describe('dns ownership', () => {
  it('issues challenge with _astranull-challenge record on fqdn target', () => {
    freshStore();
    const result = issueChallenge(ctx, 'tg_1', 'tgt_1');
    assert.equal(result.error, undefined);
    assert.ok(result.challenge);
    assert.equal(result.challenge.state, 'pending');
    assert.equal(result.challenge.record_name, '_astranull-challenge.origin.test');
    assert.match(result.challenge.record_value, /^[A-Z2-7]+$/);
    const row = getStore().dnsChallenges.find((c) => c.id === result.challenge.id);
    assert.equal(row.record_value, result.challenge.record_value);
  });

  it('verify succeeds when TXT matches token', async () => {
    freshStore();
    const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
    const resolveTxt = async () => [[issued.challenge.record_value]];

    const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt });
    assert.equal(result.verified, true);
    assert.equal(result.challenge.state, 'resolved');
    const verification = getStore().targetVerifications.find(
      (v) => v.source_ref?.dns_challenge_id === issued.challenge.id,
    );
    assert.equal(verification?.state, 'dns_verified');
  });

  it('rejects wrong-route and expired challenges before DNS resolution', async () => {
    freshStore();
    const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
    const wrongRoute = await verifyChallenge(ctx, issued.challenge.id, {
      targetGroupId: 'tg_other',
      resolveTxt: async () => [[issued.challenge.record_value]],
    });
    assert.equal(wrongRoute.error, 'challenge_not_found');

    const stored = getStore().dnsChallenges.find((row) => row.id === issued.challenge.id);
    stored.expires_at = '2000-01-01T00:00:00.000Z';
    let resolverCalls = 0;
    const expired = await verifyChallenge(ctx, issued.challenge.id, {
      targetGroupId: 'tg_1',
      resolveTxt: async () => { resolverCalls += 1; return [[issued.challenge.record_value]]; },
    });
    assert.equal(expired.error, 'challenge_expired');
    assert.equal(expired.status, 409);
    assert.equal(expired.challenge.state, 'expired');
    assert.equal(resolverCalls, 0);
  });

  it('requires a bound active target and never falls back from an invalid explicit target', async () => {
    freshStore();
    const missing = issueChallenge(ctx, 'tg_1', 'tgt_missing');
    assert.deepEqual(missing, { error: 'target_not_found', status: 404 });

    const target = getStore().targets.find((row) => row.id === 'tgt_1');
    const originalKind = target.kind;
    target.kind = 'ip';
    const notFqdn = issueChallenge(ctx, 'tg_1', 'tgt_1');
    assert.deepEqual(notFqdn, { error: 'no_fqdn_target', status: 409 });
    target.kind = originalKind;

    const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
    const stored = getStore().dnsChallenges.find((row) => row.id === issued.challenge.id);
    stored.target_id = null;
    const unbound = await verifyChallenge(ctx, issued.challenge.id, { targetGroupId: 'tg_1' });
    assert.equal(unbound.error, 'challenge_target_not_bound');

    stored.target_id = 'tgt_1';
    target.deleted_at = new Date().toISOString();
    const deleted = await verifyChallenge(ctx, issued.challenge.id, { targetGroupId: 'tg_1' });
    assert.equal(deleted.error, 'target_not_found');
  });

  it('verify fails when TXT does not match', async () => {
    freshStore();
    const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
    const resolveTxt = async () => [['wrong-token']];

    const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt });
    assert.equal(result.verified, false);
    assert.equal(result.challenge.state, 'pending');
  });
});

describe('dns ownership malformed pending challenge clocks', () => {
  for (const [field, value] of [['kind', 'ip'], ['value', 'changed.example.test']]) {
    it(`rejects a previously changed target ${field} before TXT lookup`, async () => {
      freshStore();
      const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
      getStore().targets.find((row) => row.id === 'tgt_1')[field] = value;
      let resolverCalls = 0;
      const before = getStore().auditLog.length;
      const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async () => {
        resolverCalls += 1; return [[issued.challenge.record_value]];
      } });
      assert.equal(result.error, 'challenge_binding_changed');
      assert.equal(result.status, 409);
      assert.equal(resolverCalls, 0);
      assert.equal(getStore().auditLog.length, before);
      assert.equal((getStore().targetVerifications ?? []).length, 0);
    });
  }
  for (const [field, value] of [['expires_at', null], ['expires_at', 'not-a-date'], ['expires_at', 'infinity'],
    ['issued_at', null], ['issued_at', 'not-a-date']]) {
    it(`rejects ${field} ${String(value)} before TXT lookup or audit`, async () => {
      freshStore();
      const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
      const challenge = getStore().dnsChallenges.find((row) => row.id === issued.challenge.id);
      challenge[field] = value;
      const count = getStore().auditLog.length;
      let resolverCalls = 0;
      const result = await verifyChallenge(ctx, challenge.id, { resolveTxt: async () => {
        resolverCalls += 1; return [[issued.challenge.record_value]];
      } });
      assert.equal(result.error, 'challenge_binding_changed');
      assert.equal(result.status, 409);
      assert.equal(resolverCalls, 0);
      assert.equal(getStore().auditLog.length, count);
      assert.equal((getStore().targetVerifications ?? []).length, 0);
      assert.equal(challenge.state, 'pending');
    });
  }
});

describe('dns ownership asynchronous finalization', () => {
  let sequence = 0;
  function deferredVerification() {
    freshStore();
    const target = getStore().targets[0];
    getStore().targetVerifications = [];
    target.id = `tgt_dns_deferred_${++sequence}`;
    const issued = issueChallenge(ctx, 'tg_1', target.id);
    assert.equal(issued.error, undefined);
    let finish;
    const lookup = new Promise((resolve) => { finish = resolve; });
    const challenge = getStore().dnsChallenges.find((row) => row.id === issued.challenge.id);
    let calls = 0;
    const pending = verifyChallenge(ctx, challenge.id, { resolveTxt: (name) => {
      calls += 1;
      assert.equal(name, issued.challenge.record_name);
      return lookup;
    } });
    assert.equal(calls, 1);
    return { target, challenge, pending, finish: () => finish([[issued.challenge.record_value]]) };
  }
  for (const [name, change, error] of [
    ['target deletion', ({ target }) => { target.deleted_at = new Date().toISOString(); }, 'target_not_found'],
    ['group archive', () => { getStore().targetGroups[0].archived_at = new Date().toISOString(); }, 'target_group_not_found'],
    ['target group change', ({ target }) => { target.target_group_id = 'tg_elsewhere'; }, 'target_not_found'],
    ['target kind change', ({ target }) => { target.kind = 'ip'; }, 'challenge_binding_changed'],
    ['target value change', ({ target }) => { target.value = 'different.example.test'; }, 'challenge_binding_changed'],
    ['challenge removal', () => { getStore().dnsChallenges = []; }, 'challenge_not_found'],
    ['challenge rebind', ({ challenge }) => { challenge.target_id = 'tgt_different'; }, 'challenge_binding_changed'],
    ['challenge token replacement', ({ challenge }) => { challenge.record_value = 'REPLACED'; }, 'challenge_binding_changed'],
  ]) it(`rejects ${name} during lookup without a verification or success audit`, async () => {
    const state = deferredVerification();
    const auditCount = getStore().auditLog.length;
    change(state);
    state.finish();
    const result = await state.pending;
    assert.equal(result.error, error);
    assert.equal(result.status, error.endsWith('_not_found') ? 404 : 409);
    assert.equal(getStore().targetVerifications.length, 0);
    assert.equal(getStore().auditLog.length, auditCount);
    assert.equal(state.challenge.state, 'pending');
  });
  it('returns the first completed result without duplicate proof or audit after a parallel lookup', async () => {
    const state = deferredVerification();
    let finishSecond;
    const secondLookup = new Promise((resolve) => { finishSecond = resolve; });
    const second = verifyChallenge(ctx, state.challenge.id, { resolveTxt: () => secondLookup });
    state.finish();
    const first = await state.pending;
    assert.equal(first.verified, true);
    const auditCount = getStore().auditLog.length;
    finishSecond([[state.challenge.record_value]]);
    const replay = await second;
    assert.equal(replay.verified, true);
    assert.equal(getStore().targetVerifications.length, 1);
    assert.equal(getStore().auditLog.length, auditCount);
    assert.equal(replay.audit_entry_id, first.audit_entry_id);
  });
  for (const laterState of ['pending', 'unverified', 'user_confirmed']) it(`preserves intervening ${laterState} ownership`, async () => {
    const state = deferredVerification();
    getStore().targetVerifications.push({ id: 'tv_intervening', tenant_id: ctx.tenantId, target_id: state.target.id,
      state: laterState, transitioned_at: new Date().toISOString(), source_kind: 'test_fixture' });
    const before = structuredClone(getStore().targetVerifications);
    const auditCount = getStore().auditLog.length;
    state.finish();
    const result = await state.pending;
    assert.equal(result.error, 'ownership_state_changed');
    assert.equal(result.status, 409);
    assert.deepEqual(getStore().targetVerifications, before);
    assert.equal(getStore().auditLog.length, auditCount);
    assert.equal(state.challenge.state, 'pending');
  });
  it('retains fresh expiry rejection after the resolver waits', async () => {
    const state = deferredVerification();
    state.challenge.expires_at = '2000-01-01T00:00:00.000Z';
    state.finish();
    const result = await state.pending;
    assert.equal(result.error, 'challenge_expired');
    assert.equal(result.status, 409);
    assert.equal(state.challenge.state, 'expired');
    assert.equal(getStore().targetVerifications.length, 0);
    assert.equal(getStore().auditLog.filter((row) => row.action === 'dns_ownership.challenge_expired').length, 1);
  });
  it('updates only the verified tenant target when a foreign fixture shares its id', async () => {
    const state = deferredVerification();
    const foreign = { ...state.target, tenant_id: 'ten_foreign', verify_state: 'pending' };
    getStore().targets.unshift(foreign);
    state.finish();
    const result = await state.pending;
    assert.equal(result.verified, true);
    assert.equal(state.target.verify_state, 'dns_verified');
    assert.equal(foreign.verify_state, 'pending');
  });
  it('still accepts a matching lookup after unrelated declaration or foreign ownership changes', async () => {
    const state = deferredVerification();
    state.target.declaration_json = { purpose: 'updated declaration' };
    getStore().targetVerifications.push({ id: 'tv_foreign', tenant_id: 'ten_other', target_id: state.target.id,
      state: 'pending', transitioned_at: new Date().toISOString() });
    state.finish();
    const result = await state.pending;
    assert.equal(result.verified, true);
    assert.equal(getStore().targetVerifications.filter((row) => row.tenant_id === ctx.tenantId).length, 1);
  });
});

describe('dns ownership complete history generation', () => {
  let sequence = 0;
  for (const [field, value] of [['source_kind', 'loa'], ['source_ref', { changed: true }],
    ['transitioned_by', 'other_actor'], ['audit_entry_id', 'audit_changed']]) {
    it(`withholds proof for in-place ${field} mutation during await`, async () => {
      freshStore();
      const target = getStore().targets[0];
      target.id = `tgt_history_${++sequence}`;
      const row = { id: 'tv_existing', tenant_id: ctx.tenantId, target_id: target.id,
        state: 'pending', source_kind: 'dns_txt', source_ref: { a: 1, b: 2 },
        transitioned_at: new Date(Date.now() - 1000).toISOString(), transitioned_by: 'u1', audit_entry_id: 'audit_original' };
      getStore().targetVerifications = [row];
      const issued = issueChallenge(ctx, 'tg_1', target.id);
      const before = getStore().auditLog.length;
      const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async () => {
        row[field] = value;
        return [[issued.challenge.record_value]];
      } });
      assert.equal(result.error, 'ownership_state_changed');
      assert.equal(getStore().targetVerifications.length, 1);
      assert.equal(getStore().auditLog.length, before);
    });
  }
  it('allows history reordering, canonical source-ref key order and foreign/unrelated provenance changes', async () => {
    freshStore();
    const target = getStore().targets[0];
    target.id = `tgt_history_${++sequence}`;
    const row = { id: 'tv_existing', tenant_id: ctx.tenantId, target_id: target.id, state: 'pending',
      source_kind: 'dns_txt', source_ref: { a: 1, b: 2 }, transitioned_at: new Date(Date.now() - 1000).toISOString() };
    const foreign = { ...row, tenant_id: 'ten_other' };
    const unrelated = { ...row, id: 'tv_unrelated', target_id: 'tgt_unrelated' };
    getStore().targetVerifications = [row, foreign, unrelated];
    const issued = issueChallenge(ctx, 'tg_1', target.id);
    const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async () => {
      row.source_ref = { b: 2, a: 1 };
      foreign.source_kind = unrelated.source_kind = 'changed';
      getStore().targetVerifications.reverse();
      return [[issued.challenge.record_value]];
    } });
    assert.equal(result.verified, true);
  });
});

describe('dns ownership read-time expiry normalization (OWNERSHIP-01)', () => {
  it('normalizeChallengeStateForRead reports expired only for pending rows past expiry', () => {
    const now = Date.parse('2026-10-01T08:58:00.000Z');
    // pending + past expiry -> expired
    assert.equal(normalizeChallengeStateForRead('pending', '2026-10-01T08:44:52.103Z', now), 'expired');
    // pending + future expiry -> pending (still actionable)
    assert.equal(normalizeChallengeStateForRead('pending', '2026-10-01T09:10:00.000Z', now), 'pending');
    // pending + exactly-at expiry -> expired (fail closed on the boundary)
    assert.equal(normalizeChallengeStateForRead('pending', '2026-10-01T08:58:00.000Z', now), 'expired');
    // non-pending states are never rewritten
    assert.equal(normalizeChallengeStateForRead('resolved', '2000-01-01T00:00:00.000Z', now), 'resolved');
    assert.equal(normalizeChallengeStateForRead('expired', '2000-01-01T00:00:00.000Z', now), 'expired');
    // missing/invalid expiry leaves pending untouched
    assert.equal(normalizeChallengeStateForRead('pending', null, now), 'pending');
    assert.equal(normalizeChallengeStateForRead('pending', 'not-a-date', now), 'pending');
  });

  it('listChallenges presents an expired state for a time-expired pending row without a DB write', () => {
    freshStore();
    const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
    const stored = getStore().dnsChallenges.find((row) => row.id === issued.challenge.id);
    // Simulate the challenge living past its 15-minute lifetime without ever being verified.
    stored.expires_at = '2000-01-01T00:00:00.000Z';

    const listed = listChallenges(ctx, 'tg_1');
    const item = listed.items.find((row) => row.id === issued.challenge.id);
    assert.equal(item.state, 'expired', 'read must present expired, not a dead actionable pending');
    // The stored row is untouched: the authoritative transition still only happens on verify.
    assert.equal(stored.state, 'pending', 'read normalization must not persist a state change');
    assert.equal(stored.last_checked_at, null, 'no audit/DB side effect on a plain read');
  });

  it('a read-expired challenge still verifies to 409 challenge_expired (race-safe, authoritative)', async () => {
    freshStore();
    const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
    const stored = getStore().dnsChallenges.find((row) => row.id === issued.challenge.id);
    stored.expires_at = '2000-01-01T00:00:00.000Z';

    // The presented list says expired...
    assert.equal(listChallenges(ctx, 'tg_1').items[0].state, 'expired');
    // ...and a verify against the still-pending stored row flips it to expired authoritatively.
    const verified = await verifyChallenge(ctx, issued.challenge.id, {
      targetGroupId: 'tg_1',
      resolveTxt: async () => [[issued.challenge.record_value]],
    });
    assert.equal(verified.error, 'challenge_expired');
    assert.equal(verified.status, 409);
    assert.equal(getStore().dnsChallenges[0].state, 'expired');
  });

  it('reissue is allowed once the prior pending challenge has passed its expiry', () => {
    freshStore();
    const first = issueChallenge(ctx, 'tg_1', 'tgt_1');
    // A second issue while the first is still active is blocked.
    assert.deepEqual(issueChallenge(ctx, 'tg_1', 'tgt_1'), { error: 'challenge_active', status: 409 });
    // Once the first is time-expired, a fresh challenge can be issued (reissue path stays open).
    const stored = getStore().dnsChallenges.find((row) => row.id === first.challenge.id);
    stored.expires_at = '2000-01-01T00:00:00.000Z';
    const reissued = issueChallenge(ctx, 'tg_1', 'tgt_1');
    assert.equal(reissued.error, undefined);
    assert.notEqual(reissued.challenge.id, first.challenge.id);
    assert.equal(reissued.challenge.state, 'pending');
  });
});