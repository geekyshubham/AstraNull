import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createInternalManagementRepository } from '../../src/persistence/postgres/internalManagementRepository.mjs';
import { createPostgresInternalManagementServices } from '../../src/persistence/postgres/internalManagementServiceAdapters.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import {
  activateBreakGlass,
  breakGlassStatus,
  resetBreakGlassStore,
} from '../../src/services/breakGlass.mjs';
import {
  databaseUrlWithDatabase,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const staffCtx = { staffId: 'staff_admin', staffRole: 'internal_admin' };

/**
 * Builds a service instance over its OWN pool, i.e. a separate connection from any other
 * instance in the test. Restarting the "service" means discarding these objects and building
 * a fresh set: nothing carries over except what is in the database.
 */
function connectServices(databaseUrl) {
  const pool = createPgPool({ ASTRANULL_DATABASE_URL: databaseUrl });
  const repo = createInternalManagementRepository(pool);
  return { pool, services: createPostgresInternalManagementServices({ internalManagement: repo }) };
}

describe('postgres break-glass activation durability', () => {
  it('survives a service restart and is visible from a second connection', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    process.env.ASTRANULL_NO_PERSIST = '1';

    await withEphemeralPostgres(
      async (ownerPool, { databaseName }) => {
        const databaseUrl = databaseUrlWithDatabase(
          ownerPool.options.connectionString,
          databaseName,
        );

        // --- connection 1: activate through the real service + audit writer ---
        const first = connectServices(databaseUrl);
        let activationId;
        try {
          resetBreakGlassStore();
          const result = await activateBreakGlass(
            staffCtx,
            {
              reason: 'Durability check for INC-DURABLE',
              ticket_reference: 'INC-DURABLE',
              duration_minutes: 60,
            },
            {
              store: first.services,
              audit: (event) => first.services.appendInternalAudit(staffCtx, event),
            },
          );
          assert.ok(result.activation?.id, 'activation must be created');
          activationId = result.activation.id;

          // The audit entry must be durable too, not just the activation.
          const audits = await first.services.listInternalAudit({
            action: 'break_glass.activated',
          });
          const entry = audits.find((item) => item.resource_id === activationId);
          assert.ok(entry, 'break_glass.activated must be recorded in internal_audit_log');
          assert.equal(entry.staff_id, 'staff_admin');
          assert.equal(entry.resource_type, 'break_glass_activation');
          assert.equal(entry.metadata.ticket_reference, 'INC-DURABLE');
        } finally {
          await closePgPool(first.pool);
        }

        // --- restart: fresh pool, fresh repository, fresh service, empty process memory ---
        const second = connectServices(databaseUrl);
        try {
          // Proves the read below cannot be served from module-level process state: if the
          // activation were still process-local (the original defect) status would be false.
          resetBreakGlassStore();

          const status = await breakGlassStatus(new Date(), { store: second.services });
          assert.equal(status.active, true, 'activation must survive a service restart');
          assert.equal(status.activation.id, activationId);
          assert.equal(status.activation.ticket_reference, 'INC-DURABLE');
          assert.equal(status.enforcement, 'reporting_only');

          const activations = await second.services.listBreakGlassActivations();
          assert.equal(activations.length, 1);
          assert.equal(activations[0].status, 'active');
          assert.equal(activations[0].duration_minutes, 60);
        } finally {
          await closePgPool(second.pool);
        }

        // --- a third, concurrent connection observes the same durable state ---
        const observer = connectServices(databaseUrl);
        const actor = connectServices(databaseUrl);
        try {
          const observedBefore = await breakGlassStatus(new Date(), { store: observer.services });
          assert.equal(observedBefore.activation.id, activationId);

          // Supersede from a different connection; the observer must see the new activation,
          // which is what process-local state could never deliver across workers.
          const next = await activateBreakGlass(
            staffCtx,
            {
              reason: 'Superseding activation for INC-SECOND',
              ticket_reference: 'INC-SECOND',
              duration_minutes: 30,
            },
            {
              store: actor.services,
              audit: (event) => actor.services.appendInternalAudit(staffCtx, event),
            },
          );

          const observedAfter = await breakGlassStatus(new Date(), { store: observer.services });
          assert.equal(observedAfter.activation.id, next.activation.id);
          assert.equal(observedAfter.activation.ticket_reference, 'INC-SECOND');

          const all = await observer.services.listBreakGlassActivations();
          assert.equal(all.length, 2);
          assert.equal(
            all.filter((entry) => entry.status === 'active').length,
            1,
            'at most one activation may be active',
          );
          assert.equal(
            all.find((entry) => entry.id === activationId).status,
            'superseded',
          );
        } finally {
          await closePgPool(observer.pool);
          await closePgPool(actor.pool);
        }
      },
      process.env,
      { databaseName: `astranull_bg_${Date.now().toString(36)}` },
    );
  });

  it('database rejects a second concurrent active activation', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(
      async (ownerPool) => {
        // The partial unique index is the backstop behind the application's supersede step:
        // even if two writers raced past it, the database cannot hold two 'active' rows.
        const insert = async (id, ticket) => ownerPool.query(
          `INSERT INTO break_glass_activations (
             id, status, ticket_reference, activated_at, expires_at, duration_minutes
           ) VALUES ($1, 'active', $2, NOW(), NOW() + INTERVAL '1 hour', 60)`,
          [id, ticket],
        );

        await insert('bg_one', 'INC-ONE');
        await assert.rejects(
          () => insert('bg_two', 'INC-TWO'),
          /idx_break_glass_activations_single_active|duplicate key/i,
        );
      },
      process.env,
      { databaseName: `astranull_bg_uniq_${Date.now().toString(36)}` },
    );
  });
});
