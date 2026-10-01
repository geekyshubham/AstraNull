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