import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  confirmOwnership,
  confirmTarget,
  createOwnershipChallenge,
  recordOwnershipSignal,
  recordOwnershipSignalByNonce,
  verifyOwnershipSetup,
} from '../../src/services/ownershipVerification.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'owner' };

afterEach(() => {
  freshStore();
});

// ADR-0008 (outside-in only): the agent-observed ownership challenge is removed. A `verified`
// ownership_verifications row can only originate from a legacy record now; the DNS challenge in
// dnsOwnership.mjs is the live path to `dns_verified`. These helpers seed the post-DNS state
// directly to exercise confirmation without the removed agent flow.
function seedVerifiedOwnershipRecord() {
  const store = getStore();
  store.ownershipVerifications = store.ownershipVerifications ?? [];
  const target = store.targets.find((t) => t.id === 'tgt_1');
  const record = {
    id: 'own_1',
    tenant_id: ctx.tenantId,
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    declared_fqdn: String(target?.value ?? 'origin.test').toLowerCase(),
    status: 'verified',
    challenge_nonce_hash: 'sha256:legacy',
    probe_observed: true,
    verified_at: '2026-06-01T00:00:00.000Z',
    confirmed_by_user_id: null,
    confirmed_at: null,
    created_at: '2026-05-01T00:00:00.000Z',
    created_by: ctx.userId,
  };
  store.ownershipVerifications.push(record);
  // DNS proof for the target so confirmOwnership can elevate it to user_confirmed.
  store.targetVerifications = store.targetVerifications ?? [];
  store.targetVerifications.push({
    id: 'tv_dns', tenant_id: ctx.tenantId, target_id: 'tgt_1', state: 'dns_verified',
    source_kind: 'dns_txt', source_ref: {}, transitioned_at: '2026-06-01T00:00:00.000Z',
  });
  return record;
}

describe('ownership verification (outside-in, no agent flow)', () => {
  it('createOwnershipChallenge fails closed — agent flow removed', () => {
    freshStore();
    const result = createOwnershipChallenge(ctx, { target_group_id: 'tg_1' });
    assert.equal(result.error, 'ownership_agent_flow_removed');
    assert.equal(result.status, 410);
    assert.equal((getStore().ownershipVerifications ?? []).length, 0);
  });

  it('verifyOwnershipSetup fails closed — agent flow removed', () => {
    freshStore();
    const result = verifyOwnershipSetup(ctx, { target_group_id: 'tg_1' });
    assert.equal(result.dry_run, true);
    assert.equal(result.ready, false);
    assert.equal(result.error, 'ownership_agent_flow_removed');
    assert.equal(result.status, 410);
  });

  it('recordOwnershipSignal fails closed — agent flow removed', () => {
    freshStore();
    assert.equal(
      recordOwnershipSignal(ctx, 'own_x', { source: 'probe', nonce_hash: 'x' }).error,
      'ownership_agent_flow_removed',
    );
    assert.equal(
      recordOwnershipSignalByNonce({ tenantId: ctx.tenantId }, { source: 'probe', nonce_hash: 'x' }).error,
      'ownership_agent_flow_removed',
    );
  });

  it('confirmOwnership elevates a verified record to user_confirmed and derives the group summary', () => {
    freshStore();
    seedVerifiedOwnershipRecord();

    const confirmed = confirmOwnership(ctx, 'own_1');
    assert.equal(confirmed.error, undefined);
    assert.equal(confirmed.verification.confirmed_by_user_id, 'u1');
    assert.ok(confirmed.verification.confirmed_at);
    assert.equal(confirmed.target_id, 'tgt_1');
    assert.equal(confirmed.target_verification.state, 'user_confirmed');
    assert.equal(
      confirmed.target_verification.source_ref.ownership_verification_id,
      'own_1',
    );
    // No agent_id leaks into the user-confirmed source_ref.
    assert.equal('agent_id' in confirmed.target_verification.source_ref, false);

    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    assert.equal(group.ownership_status, 'user_confirmed');
  });

  it('confirmOwnership is idempotent', () => {
    freshStore();
    seedVerifiedOwnershipRecord();
    const first = confirmOwnership(ctx, 'own_1');
    const confirmedAt = first.verification.confirmed_at;
    const tvId = first.target_verification.id;
    const repeated = confirmOwnership(ctx, 'own_1');
    assert.equal(repeated.verification.confirmed_at, confirmedAt);
    assert.equal(repeated.target_verification.id, tvId);
    assert.equal(
      getStore().targetVerifications.filter(
        (row) => row.target_id === 'tgt_1' && row.state === 'user_confirmed',
      ).length,
      1,
    );
  });

  it('confirmOwnership rejects before verified', () => {
    freshStore();
    const store = getStore();
    store.ownershipVerifications = store.ownershipVerifications ?? [];
    store.ownershipVerifications.push({
      id: 'own_pending', tenant_id: ctx.tenantId, target_group_id: 'tg_1', target_id: 'tgt_1',
      declared_fqdn: 'origin.test', status: 'challenge_sent', challenge_nonce_hash: 'sha256:x',
      probe_observed: false, verified_at: null, confirmed_at: null, created_at: '2026-05-01T00:00:00.000Z',
    });
    const result = confirmOwnership(ctx, 'own_pending');
    assert.equal(result.error, 'ownership_not_verified');
    assert.equal(result.status, 409);
  });

  it('confirmTarget requires DNS proof (dns_verified) as the prerequisite, not an agent rung', () => {
    freshStore();
    const store = getStore();
    store.targetVerifications = store.targetVerifications ?? [];
    store.targetVerifications.push({
      id: 'tv_dns', tenant_id: ctx.tenantId, target_id: 'tgt_1', state: 'dns_verified',
      transitioned_at: '2026-06-01T00:00:00.000Z',
    });
    store.loaSignatures = [{
      id: 'loa_1', tenant_id: ctx.tenantId, target_group_id: 'tg_1', state: 'signed',
      scope_snapshot: { targets: [] }, custody_digest_sha256: 'digest_loa_1',
    }];

    const excluded = confirmTarget(ctx, 'tg_1', 'tgt_1', { signer: 'attacker' });
    assert.equal(excluded.error, 'target_not_in_loa_scope');

    store.loaSignatures[0].scope_snapshot.targets = [{ target_id: 'tgt_1' }];
    const confirmed = confirmTarget(ctx, 'tg_1', 'tgt_1', { signer: 'attacker', note: 'approved' });
    assert.equal(confirmed.verification.state, 'user_confirmed');
    assert.equal(confirmed.verification.source_ref.signer, ctx.userId);
    assert.equal(confirmed.verification.source_ref.loa_id, 'loa_1');
    assert.equal(confirmed.verification.source_ref.loa_custody_digest_sha256, 'digest_loa_1');

    store.targetGroups.push({ id: 'tg_other', tenant_id: ctx.tenantId, name: 'Other' });
    const wrongGroup = confirmTarget(ctx, 'tg_other', 'tgt_1');
    assert.equal(wrongGroup.error, 'target_not_found');
  });

  it('confirmTarget rejects a pending target with no DNS/provider proof', () => {
    freshStore();
    const store = getStore();
    store.loaSignatures = [{
      id: 'loa_1', tenant_id: ctx.tenantId, target_group_id: 'tg_1', state: 'signed',
      scope_snapshot: { targets: [{ target_id: 'tgt_1' }] }, custody_digest_sha256: 'd',
    }];
    const result = confirmTarget(ctx, 'tg_1', 'tgt_1');
    assert.equal(result.error, 'verify_prereq_not_met');
    assert.equal(result.status, 409);
  });

  it('does not accept an expired signed LOA for confirmation', () => {
    freshStore();
    const store = getStore();
    store.targetVerifications = store.targetVerifications ?? [];
    store.targetVerifications.push({
      id: 'tv_dns', tenant_id: ctx.tenantId, target_id: 'tgt_1', state: 'dns_verified',
      transitioned_at: '2026-06-01T00:00:00.000Z',
    });
    store.loaSignatures = [{
      id: 'loa_expired', tenant_id: ctx.tenantId, target_group_id: 'tg_1', state: 'signed',
      expires_at: '2000-01-01T00:00:00.000Z', scope_snapshot: { targets: ['tgt_1'] },
    }];
    const result = confirmTarget(ctx, 'tg_1', 'tgt_1');
    assert.equal(result.error, 'loa_missing');
  });
});
