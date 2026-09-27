import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

describe('postgres pool idle-client termination', () => {
  it('survives a server-side termination of an idle pooled connection and reconnects', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (adminPool, { databaseName }) => {
      const url = new URL(availability.env.ASTRANULL_ADMIN_DATABASE_URL.replace(/^postgresql:/, 'postgres:'));
      url.pathname = `/${databaseName}`;
      const pool = createPgPool({ connectionString: url.toString().replace(/^postgres:/, 'postgresql:'), max: 1 });
      let uncaught = null;
      const onUncaught = (err) => { uncaught = err; };
      process.on('uncaughtException', onUncaught);
      try {
        const { rows } = await pool.query('SELECT pg_backend_pid() AS pid');
        // The client is now idle in the pool; kill its backend the way a DBA, restart, or failover would.
        await adminPool.query('SELECT pg_terminate_backend($1)', [rows[0].pid]);
        await new Promise((resolve) => setTimeout(resolve, 300));
        assert.equal(uncaught, null, 'idle-client termination must not become an uncaught exception');
        const again = await pool.query('SELECT 1 AS ok');
        assert.equal(again.rows[0].ok, 1, 'the pool reconnects on the next query');
      } finally {
        process.off('uncaughtException', onUncaught);
        await closePgPool(pool);
      }
    }, availability.env, { applyMigrations: false });
  });
});
