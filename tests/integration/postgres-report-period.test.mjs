import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createReportRepository } from '../../src/persistence/postgres/reportRepository.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresReportServices } from '../../src/persistence/postgres/reportServiceAdapters.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const TENANT = 'ten_report_period';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };

function buildReportServices(pool) {
  return createPostgresReportServices({
    reports: createReportRepository(pool),
    validationEvidence: createValidationEvidenceRepository(pool),
    audit: createAuditRepository(pool),
  });
}

async function seedTenant(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'report period tenant')`, [
      TENANT,
    ]);
  });
}

describe('postgres report period persistence', () => {
  it('round-trips the reporting period through create, get, and list', async (t) => {
    const availability = await resolvePostgresHarnessAvailability();
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);
      const { reports } = buildReportServices(pool);

      const created = await reports.createReport(CTX, { kind: 'technical', period: 'last-7-days' });
      assert.equal(created.period, 'last-7-days');

      const fetched = await reports.getReport(CTX, created.id);
      assert.equal(fetched.period, 'last-7-days');
      assert.equal(fetched.summary.period, 'last-7-days');

      const listed = await reports.listReports(CTX, {});
      assert.equal(listed.length, 1);
      assert.equal(listed[0].period, 'last-7-days');
    });
  });

  it('stores null for an omitted or unknown period without inventing a window', async (t) => {
    const availability = await resolvePostgresHarnessAvailability();
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);
      const { reports } = buildReportServices(pool);

      const omitted = await reports.createReport(CTX, { kind: 'technical' });
      assert.equal(omitted.period, null);
      assert.equal((await reports.getReport(CTX, omitted.id)).period, null);

      // The route rejects unknown windows before this layer; the adapter must not store a guess.
      const unknown = await reports.createReport(CTX, { kind: 'technical', period: 'last-decade' });
      assert.equal(unknown.period, null);
      assert.equal((await reports.getReport(CTX, unknown.id)).period, null);
    });
  });
});
