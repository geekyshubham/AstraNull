import { AsyncLocalStorage } from 'node:async_hooks';

const tenantTransactions = new AsyncLocalStorage();

/** An external side effect must never follow a merely nested, rollbackable callback. */
export function assertNoManagedTenantTransaction() {
  if (tenantTransactions.getStore()?.active) {
    throw Object.assign(new Error('reviewed_grant_enclosing_transaction'), {
      code: 'reviewed_grant_enclosing_transaction', status: 409,
    });
  }
}

/** Returns only after this invocation's own COMMIT acknowledgement. No automatic retry. */
export async function withStandaloneTenantContext(pool, tenantId, callback) {
  assertNoManagedTenantTransaction();
  return withTenantContext(pool, tenantId, callback);
}

/** Run with an explicit tenant client or the active same-pool transaction. */
export async function runWithTenantClient(pool, tenantId, client, callback) {
  if (client) return callback(client);
  return withTenantContext(pool, tenantId, callback);
}

/**
 * Lock-sensitive consumers may accept only the exact client of an active managed
 * same-pool/same-tenant transaction. A Pool, autocommit client or even an untracked
 * manual BEGIN cannot establish a lifetime guarantee for their authority locks.
 * Keep runWithTenantClient's existing, more permissive repository contract intact.
 */
export async function withManagedTenantClient(pool, tenantId, client, callback) {
  if (client !== undefined) {
    const held = tenantTransactions.getStore();
    if (!held?.active || held.pool !== pool || held.tenantId !== tenantId || held.client !== client) {
      throw Object.assign(new Error('reviewed_operation_authority_client_invalid'), {
        code: 'reviewed_operation_authority_client_invalid', status: 400,
        grants_execution: false, execution_available: false,
      });
    }
  }
  // This also records nested callback failures in the held scope, so an outer
  // caller cannot swallow the exception and commit its partial authority work.
  return withTenantContext(pool, tenantId, callback);
}

/** Repository callbacks share the admission transaction, not just its advisory lock. */
export async function withTenantContext(pool, tenantId, callback) {
  const normalized = String(tenantId ?? '').trim();
  if (!normalized) throw new Error('tenant id must be a non-empty string.');

  const held = tenantTransactions.getStore();
  if (held?.active && held.pool === pool) {
    if (held.tenantId !== normalized) throw new Error('tenant context mismatch.');
    try {
      return await callback(held.client);
    } catch (error) {
      held.failure ??= error;
      throw error;
    }
  }

  const client = await pool.connect();
  const scope = { active: true, pool, tenantId: normalized, client, failure: null };
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.tenant_id', $1, true)`, [normalized]);
    const result = await tenantTransactions.run(scope, () => callback(client));
    if (scope.failure) throw scope.failure;
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* Preserve the original failure. */ }
    throw error;
  } finally {
    scope.active = false;
    client.release();
  }
}
