/** Mirrors `test_run:start` in src/contracts/roles.mjs; parity is asserted by tests/unit/run-permissions.test.mjs. */
export const RUN_START_ROLES = Object.freeze(['owner', 'admin', 'engineer']);

export function canStartRun(role) {
  return RUN_START_ROLES.includes(String(role ?? '').trim().toLowerCase());
}
