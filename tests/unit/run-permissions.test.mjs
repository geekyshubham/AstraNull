import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ROLES, roleHasPermission } from '../../src/contracts/roles.mjs';
import { RUN_START_ROLES, canStartRun } from '../../apps/web/react/src/lib/run-permissions.mjs';

describe('portal run-start permission helper', () => {
  it('matches the backend test_run:start permission for every role', () => {
    for (const role of ROLES) {
      assert.equal(canStartRun(role), roleHasPermission(role, 'test_run:start'), role);
    }
    assert.deepEqual([...RUN_START_ROLES].sort(), ROLES.filter((role) => roleHasPermission(role, 'test_run:start')).sort());
  });

  it('normalizes casing and rejects unknown or empty roles', () => {
    assert.equal(canStartRun(' Owner '), true);
    assert.equal(canStartRun('ENGINEER'), true);
    assert.equal(canStartRun('viewer'), false);
    assert.equal(canStartRun(''), false);
    assert.equal(canStartRun(undefined), false);
    assert.equal(canStartRun('soc_analyst'), false);
  });
});
