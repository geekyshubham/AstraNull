import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  DEMO_AUTO_VERIFY_AUDIT_ACTION,
  DEMO_AUTO_VERIFY_ENV,
  demoAutoVerifyTenants,
  isDemoAutoVerifyTenant,
} from '../../src/lib/demoAutoVerify.mjs';
import { targetOwnershipProof } from '../../src/services/ownershipVerification.mjs';
import {
  backfillDemoAutoVerifications,
  createTargetDirect,
  importTargets,
  listTargets,
} from '../../src/services/targetGroups.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const DEMO = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
const OTHER = { tenantId: 'ten_other', userId: 'u2', role: 'admin' };

function groupOf(target) {
  return { id: target.target_group_id };
}

describe('demo auto-verify allowlist', () => {
  it('parses a comma separated tenant list and ignores blanks', () => {
    const env = { [DEMO_AUTO_VERIFY_ENV]: ' ten_demo, ,ten_two ' };
    assert.deepEqual([...demoAutoVerifyTenants(env)], ['ten_demo', 'ten_two']);
    assert.equal(isDemoAutoVerifyTenant('ten_demo', env), true);
    assert.equal(isDemoAutoVerifyTenant('ten_other', env), false);
    assert.equal(isDemoAutoVerifyTenant('ten_demo', {}), false);
  });
});

describe('demo auto-verify on target creation', () => {
  let previous;
  beforeEach(() => {
    previous = process.env[DEMO_AUTO_VERIFY_ENV];
    process.env[DEMO_AUTO_VERIFY_ENV] = 'ten_demo';
    freshStore();
  });
  afterEach(() => {
    if (previous === undefined) delete process.env[DEMO_AUTO_VERIFY_ENV];
    else process.env[DEMO_AUTO_VERIFY_ENV] = previous;
    freshStore();
  });

  it('marks a new target of the demo tenant verified and audits it as demo', () => {
    const target = createTargetDirect(DEMO, { kind: 'fqdn', value: 'anything.example.org' });
    const proof = targetOwnershipProof(DEMO, groupOf(target), target.id);
    assert.equal(proof.verified, true);
    assert.equal(proof.state, 'user_confirmed');

    const presented = listTargets(DEMO).find((row) => row.id === target.id);
    assert.equal(presented.verification_state, 'user_confirmed');
    assert.equal(presented.verification.source_kind, 'manual_override');
    assert.equal(presented.verification.source_ref.method, 'demo_auto_verify');

    const entry = getStore().auditLog.find((row) => row.action === DEMO_AUTO_VERIFY_AUDIT_ACTION);
    assert.equal(entry?.resource_id, target.id);
    assert.equal(entry?.tenant_id, 'ten_demo');
  });

  it('leaves other tenants unverified', () => {
    const target = createTargetDirect(OTHER, { kind: 'fqdn', value: 'anything.example.org' });
    assert.equal(targetOwnershipProof(OTHER, groupOf(target), target.id).verified, false);
    assert.equal(getStore().auditLog.some((row) => row.action === DEMO_AUTO_VERIFY_AUDIT_ACTION), false);
  });

  it('verifies CSV imported targets of the demo tenant', () => {
    const seed = createTargetDirect(DEMO, { kind: 'fqdn', value: 'seed.example.org' });
    const result = importTargets(DEMO, seed.target_group_id, [{ kind: 'fqdn', value: 'csv.example.org' }]);
    assert.equal(result.created.length, 1);
    assert.equal(targetOwnershipProof(DEMO, groupOf(seed), result.created[0].id).verified, true);
  });

  it('backfills targets that existed before the tenant was allowlisted', () => {
    delete process.env[DEMO_AUTO_VERIFY_ENV];
    const target = createTargetDirect(DEMO, { kind: 'fqdn', value: 'old.example.org' });
    assert.equal(targetOwnershipProof(DEMO, groupOf(target), target.id).verified, false);
    assert.equal(backfillDemoAutoVerifications(DEMO).error, 'demo_auto_verify_not_enabled');

    process.env[DEMO_AUTO_VERIFY_ENV] = 'ten_demo';
    const result = backfillDemoAutoVerifications(DEMO);
    assert.ok(result.target_ids.includes(target.id));
    assert.equal(targetOwnershipProof(DEMO, groupOf(target), target.id).verified, true);
    assert.equal(backfillDemoAutoVerifications(DEMO).verified_count, 0);
  });
});
