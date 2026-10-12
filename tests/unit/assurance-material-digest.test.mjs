import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalDefinitionDigest } from '../../src/lib/checkDefinitionVersion.mjs';
import { canonicalJsonStringify, sha256CanonicalJson } from '../../src/lib/custody.mjs';
import { deriveAssuranceScope, currentAssuranceGap } from '../../src/lib/assuranceScope.mjs';
import { dnsOwnershipTargetBinding, dnsOwnershipChallengeMatchesTarget, dnsOwnershipProofMatchesTarget } from '../../src/lib/dnsOwnershipTarget.mjs';

const target = { id: 'tgt_material', tenant_id: 'ten_material', target_group_id: 'tg_material', kind: 'url',
  value: 'https://owned.example.test/authorization:first', protocol: 'https', port: 443,
  expected_behavior: 'allow', declaration_json: {} };
const scope = (row = target, extra = {}) => deriveAssuranceScope({ target: row, ...extra });

for (const value of ['https://owned.example.test/authorization:second', 'https://not-owned.example.test/authorization:second']) {
  test(`material scope and exact DNS proof cannot collide after URL edit: ${value}`, () => {
    const changed = { ...target, value };
    const binding = dnsOwnershipTargetBinding(target);
    const proof = { tenant_id: target.tenant_id, target_id: target.id, source_ref: { dns_target_binding: binding } };
    const challenge = { tenant_id: target.tenant_id, target_group_id: target.target_group_id, target_id: target.id,
      record_name: '_astranull-challenge.owned.example.test', last_check_result: { dns_target_binding: binding } };
    assert.notEqual(scope().target.definition_digest, scope(changed).target.definition_digest);
    assert.equal(dnsOwnershipProofMatchesTarget(changed, proof), false);
    assert.equal(dnsOwnershipChallengeMatchesTarget(challenge, changed), false);
    assert.equal(currentAssuranceGap({ run: { target_id: target.id, tenant_id: target.tenant_id,
      safety_constraints: { assurance_scope: scope() } }, target: changed }), 'target_definition_changed');
  });
}

for (const field of ['authorization', 'cookie', 'token', 'secret', 'api_key']) {
  test(`material declaration keeps exact ${field} semantics in the digest without returning it`, () => {
    const first = { ...target, declaration_json: { [field]: 'first-sensitive-value' } };
    const second = { ...target, declaration_json: { [field]: 'second-sensitive-value' } };
    assert.notEqual(scope(first).target.definition_digest, scope(second).target.definition_digest);
    assert.equal(JSON.stringify(scope(first)).includes('first-sensitive-value'), false);
    const policy = { id: 'pol_material', safety_constraints: { [field]: 'first-sensitive-value' } };
    const changed = { ...policy, safety_constraints: { [field]: 'second-sensitive-value' } };
    assert.notEqual(scope(target, { policy }).policy.definition_digest, scope(target, { policy: changed }).policy.definition_digest);
    const group = { id: target.target_group_id, declaration_json: { [field]: 'first-sensitive-value' } };
    const groupChanged = { ...group, declaration_json: { [field]: 'second-sensitive-value' } };
    assert.notEqual(scope(target, { targetGroup: group }).target_group.definition_digest,
      scope(target, { targetGroup: groupChanged }).target_group.definition_digest);
  });
}

test('lossless material hashing is key-order stable, ignores presentation and does not alter catalog credential versioning', () => {
  assert.equal(scope({ ...target, name: 'New label', tags: ['presentation'], updated_at: '2026-10-10' }).target.definition_digest,
    scope().target.definition_digest);
  const first = { ...target, declaration_json: { z: 1, nested: { authorization: 'one', a: true } } };
  const reordered = { ...target, declaration_json: { nested: { a: true, authorization: 'one' }, z: 1 } };
  assert.equal(scope(first).target.definition_digest, scope(reordered).target.definition_digest);
  assert.equal(canonicalDefinitionDigest({ check_id: 'fixture', password: 'one' }),
    canonicalDefinitionDigest({ check_id: 'fixture', password: 'two' }));
});

test('canonical authority preserves own __proto__ material at every nesting level', () => {
  const first = JSON.parse('{"nested":{"__proto__":{"path":"first"}},"__proto__":{"path":"first"}}');
  const second = JSON.parse('{"__proto__":{"path":"second"},"nested":{"__proto__":{"path":"second"}}}');
  const reordered = JSON.parse('{"__proto__":{"path":"first"},"nested":{"__proto__":{"path":"first"}}}');
  const before = structuredClone(first);
  assert.equal(canonicalJsonStringify(first), '{"__proto__":{"path":"first"},"nested":{"__proto__":{"path":"first"}}}');
  assert.equal(sha256CanonicalJson(first), sha256CanonicalJson(reordered));
  assert.notEqual(sha256CanonicalJson(first), sha256CanonicalJson(second));
  assert.notEqual(sha256CanonicalJson(JSON.parse('{"__proto__":null}')), sha256CanonicalJson({}));
  const original = { ...target, declaration_json: first };
  const changed = { ...target, declaration_json: second };
  const absent = { ...target, declaration_json: {} };
  assert.notEqual(scope(original).target.definition_digest, scope(changed).target.definition_digest);
  assert.notEqual(scope(original).target.definition_digest, scope(absent).target.definition_digest);
  const proof = { tenant_id: target.tenant_id, target_id: target.id, source_ref: { dns_target_binding: dnsOwnershipTargetBinding(original) } };
  const challenge = { tenant_id: target.tenant_id, target_group_id: target.target_group_id, target_id: target.id,
    record_name: '_astranull-challenge.owned.example.test', last_check_result: { dns_target_binding: dnsOwnershipTargetBinding(original) } };
  assert.equal(dnsOwnershipProofMatchesTarget(changed, proof), false);
  assert.equal(dnsOwnershipChallengeMatchesTarget(challenge, changed), false);
  for (const [field, record] of [['policy', { id: 'pol_material', safety_constraints: first }],
    ['target_group', { id: target.target_group_id, declaration_json: first }]]) {
    const key = field === 'policy' ? 'policy' : 'targetGroup';
    const material = field === 'policy' ? 'safety_constraints' : 'declaration_json';
    const digest = (value) => scope(target, { [key]: { ...record, [material]: value } })[field].definition_digest;
    assert.notEqual(digest(first), digest(second));
    assert.notEqual(digest(first), digest({}));
  }
  assert.deepEqual(first, before);
  assert.equal(Object.prototype.path, undefined);
});

test('older DNS material binding cannot be upgraded into current URL proof', () => {
  const old = { ...dnsOwnershipTargetBinding(target), version: 'dns-ownership-target.v1' };
  const proof = { tenant_id: target.tenant_id, target_id: target.id, source_ref: { dns_target_binding: old } };
  const before = structuredClone(proof);
  assert.equal(dnsOwnershipProofMatchesTarget(target, proof), false);
  assert.deepEqual(proof, before);
});

test('older redacted material scope cannot supply current authority or be rewritten', () => {
  const recorded = { ...scope(), version: 'assurance-scope.v2' };
  const run = { tenant_id: target.tenant_id, target_id: target.id, safety_constraints: { assurance_scope: recorded } };
  const before = structuredClone(run);
  assert.equal(currentAssuranceGap({ run, target }), 'assurance_scope_version_mismatch');
  assert.deepEqual(run, before);
});
