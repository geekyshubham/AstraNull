import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { issueChallenge, verifyChallenge, verifyDnsOwnership } from '../../src/services/dnsOwnership.mjs';
import { dnsOwnershipDomain, dnsOwnershipTargetBinding, dnsOwnershipProofMatchesTarget } from '../../src/lib/dnsOwnershipTarget.mjs';
const ctx = { tenantId: 'ten_demo', userId: 'usr_url_dns', role: 'owner' };
let sequence = 0;
function fixture(overrides = {}) {
  freshStore();
  getStore().targetVerifications = [];
  const target = { id: `tgt_url_dns_${++sequence}`, tenant_id: ctx.tenantId, target_group_id: 'tg_1',
    kind: 'url', value: 'https://owned.example.test:8443/diagnostic', protocol: 'https', port: 8443,
    expected_behavior: 'allow', declaration_json: {}, ...overrides };
  getStore().targets.push(target);
  return target;
}
afterEach(() => freshStore());
describe('exact declared URL DNS ownership', () => {
  it('issues host-only TXT for an explicit URL, proves only that target and preserves immutable expiry/binding/replay', async () => {
    const target = fixture();
    const sibling = { ...target, id: 'tgt_url_sibling', value: 'https://owned.example.test:8443/other' };
    getStore().targets.push(sibling);
    const implicit = issueChallenge(ctx, 'tg_1');
    assert.equal(implicit.challenge.target_id, 'tgt_1');
    const issued = issueChallenge(ctx, 'tg_1', target.id);
    assert.equal(issued.challenge.record_name, '_astranull-challenge.owned.example.test');
    const binding = dnsOwnershipTargetBinding(target);
    assert.deepEqual(issued.challenge.last_check_result, { dns_target_binding: binding });
    assert.equal(issueChallenge(ctx, 'tg_1', target.id).error, 'challenge_active');
    const failed = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async () => [['wrong']] });
    assert.equal(failed.verified, false);
    assert.deepEqual(failed.challenge.last_check_result.dns_target_binding, binding);
    const success = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async (name) => {
      assert.equal(name, issued.challenge.record_name); return [[issued.challenge.record_value]];
    } });
    assert.equal(success.verified, true);
    assert.equal(success.challenge.expires_at, issued.challenge.expires_at);
    assert.deepEqual(success.challenge.last_check_result.dns_target_binding, binding);
    const proof = getStore().targetVerifications[0];
    assert.equal(proof.target_id, target.id);
    assert.deepEqual(proof.source_ref, { dns_challenge_id: issued.challenge.id, dns_target_binding: binding });
    assert.equal(dnsOwnershipProofMatchesTarget(target, proof), true);
    assert.equal(dnsOwnershipProofMatchesTarget(sibling, proof), false);
    assert.equal(getStore().targets.find((row) => row.id === 'tgt_1').verify_state, undefined);
    const count = getStore().auditLog.length;
    const replay = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: () => { throw new Error('must not resolve'); } });
    assert.deepEqual(replay, success);
    assert.equal(getStore().auditLog.length, count);
    assert.equal(getStore().targetVerifications.length, 1);
    target.value = 'https://owned.example.test:8443/new-path';
    assert.equal(dnsOwnershipProofMatchesTarget(target, proof), false);
    assert.equal((await verifyChallenge(ctx, issued.challenge.id)).error, 'challenge_binding_changed');
  });
  it('implicit group selection never chooses a URL when no FQDN remains', () => {
    fixture(); getStore().targets = getStore().targets.filter((row) => row.kind === 'url');
    assert.equal(issueChallenge(ctx, 'tg_1').error, 'no_fqdn_target');
  });
  it('implicit group verification never selects a URL challenge', async () => {
    const target = fixture();
    issueChallenge(ctx, 'tg_1', target.id);
    const result = await verifyDnsOwnership(ctx, { target_group_id: 'tg_1' }, { resolveTxt: () => {
      throw new Error('must not select URL implicitly');
    } });
    assert.equal(result.error, 'no_dns_challenge');
    assert.equal(getStore().targetVerifications.length, 0);
  });
  for (const value of ['https://user:secret@owned.example.test/x', 'https://@owned.example.test/x',
    'https://owned.example.test/x?value=1', 'https://owned.example.test/x?', 'https://owned.example.test/x#fragment',
    'ftp://owned.example.test/x', 'https://127.0.0.1/x', 'https://[::1]/x', 'https://2130706433/x',
    'https://0x7f000001/x', 'https://localhost/x', 'https://metadata.internal/x', 'https://bad_.example.test/x',
    'https://-bad.example.test/x', 'https://owned.example.test:70000/x', 'https:\\owned.example.test/x', 'not a URL']) {
    it(`rejects unsafe or malformed URL ${value} without audit or DNS`, () => {
      const target = fixture({ value, protocol: null, port: null });
      const count = getStore().auditLog.length;
      assert.equal(issueChallenge(ctx, 'tg_1', target.id).error, 'invalid_dns_ownership_target');
      assert.equal(getStore().auditLog.length, count);
      assert.equal((getStore().dnsChallenges ?? []).length, 0);
    });
  }
  for (const change of [{ port: 443 }, { protocol: 'http' }]) it(`rejects conflicting ${Object.keys(change)[0]}`, () => {
    const target = fixture(change);
    assert.equal(issueChallenge(ctx, 'tg_1', target.id).error, 'invalid_dns_ownership_target');
  });
  for (const [field, value] of [['value', 'https://owned.example.test:8443/new-path'], ['value', 'http://owned.example.test:8443/diagnostic'],
    ['port', 443], ['protocol', 'http'], ['expected_behavior', 'deny'], ['declaration_json', { scope: 'changed' }]]) {
    for (const during of [false, true]) it(`withholds proof for ${field} material edit ${during ? 'during' : 'before'} lookup`, async () => {
      const target = fixture();
      const issued = issueChallenge(ctx, 'tg_1', target.id);
      const count = getStore().auditLog.length;
      let calls = 0;
      if (!during) target[field] = value;
      const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async () => {
        calls++; target[field] = value; return [[issued.challenge.record_value]];
      } });
      assert.equal(result.error, 'challenge_binding_changed');
      assert.equal(calls, during ? 1 : 0);
      assert.equal(getStore().targetVerifications.length, 0);
      assert.equal(getStore().auditLog.length, count);
    });
  }
  for (const binding of [null, {}, { version: 'dns-ownership-target.v1' }]) it('does not retie an old/malformed URL challenge', async () => {
    const target = fixture(); const issued = issueChallenge(ctx, 'tg_1', target.id);
    getStore().dnsChallenges[0].last_check_result = binding ? { dns_target_binding: binding } : null;
    const count = getStore().auditLog.length;
    const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: () => { throw new Error('must not resolve'); } });
    assert.equal(result.error, 'challenge_binding_changed');
    assert.equal(getStore().auditLog.length, count);
  });
  it('retains exact binding on expiry without proof', async () => {
    const target = fixture(); const issued = issueChallenge(ctx, 'tg_1', target.id);
    const stored = getStore().dnsChallenges[0]; stored.expires_at = '2000-01-01T00:00:00.000Z';
    const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: () => { throw new Error('must not resolve'); } });
    assert.equal(result.error, 'challenge_expired');
    assert.deepEqual(result.challenge.last_check_result.dns_target_binding, dnsOwnershipTargetBinding(target));
    assert.equal(getStore().targetVerifications.length, 0);
  });
  it('accepts unrelated presentation edits and requires complete history beyond the projection cap', async () => {
    const target = fixture();
    getStore().targetVerifications = Array.from({ length: 301 }, (_, i) => ({ id: `tv_old_${i}`, tenant_id: ctx.tenantId,
      target_id: target.id, state: 'pending', source_kind: 'dns_txt', source_ref: {}, transitioned_at: new Date(Date.now() - 1000 + i).toISOString() }));
    const issued = issueChallenge(ctx, 'tg_1', target.id);
    const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt: async () => {
      target.name = 'New label'; target.tags = ['presentation'];
      getStore().targetVerifications[0].source_ref = { changed: true };
      return [[issued.challenge.record_value]];
    } });
    assert.equal(result.error, 'ownership_state_changed');
    assert.equal(getStore().targetVerifications.length, 301);
  });
});
describe('strict URL proof binding data schema', () => {
  const bad = [
    (b) => ({ ...b, extra: undefined }), (b) => ({ ...b, definition_digest: b.definition_digest.toUpperCase() }),
    (b) => ({ ...b, target_id: 42 }), (b) => ({ ...b, definition_digest: NaN }),
    (b) => Object.assign(Object.create(b), {}), (b) => Object.assign(Object.create(null), b),
    (b) => Object.assign({ ...b }, { [Symbol('extra')]: true }),
    (b) => Object.defineProperty({ ...b }, 'definition_digest', { get() { throw new Error('must not invoke getter'); } }),
    (b) => new Proxy(b, { ownKeys() { throw new Error('malformed'); } }),
    (b) => Object.defineProperty({ ...b }, 'definition_digest', { value: b.definition_digest, enumerable: false }),
  ];
  for (const [i, change] of bad.entries()) it(`rejects malformed data binding ${i} without throwing`, () => {
    const target = fixture();
    const verification = { tenant_id: ctx.tenantId, target_id: target.id,
      source_ref: { dns_target_binding: change(dnsOwnershipTargetBinding(target)) } };
    assert.equal(dnsOwnershipProofMatchesTarget(target, verification), false);
  });
  it('does not execute source-ref or binding accessors', () => {
    const target = fixture();
    for (const proof of [Object.defineProperty({ tenant_id: ctx.tenantId, target_id: target.id }, 'source_ref',
      { get() { throw new Error('must not invoke getter'); } }),
    { tenant_id: ctx.tenantId, target_id: target.id, source_ref: Object.defineProperty({}, 'dns_target_binding',
      { get() { throw new Error('must not invoke getter'); } }) }]) assert.equal(dnsOwnershipProofMatchesTarget(target, proof), false);
  });
  it('supports legitimate HTTP URL and canonical DNS label limits', () => {
    assert.equal(dnsOwnershipDomain(fixture({ value: 'http://owned.example.test/diagnostic', protocol: 'http', port: 80 })), 'owned.example.test');
    assert.equal(dnsOwnershipDomain(fixture({ value: `https://${'a'.repeat(64)}.example.test/`, protocol: 'https', port: 443 })), null);
  });
});
