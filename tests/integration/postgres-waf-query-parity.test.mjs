import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createWafPostureRepository } from '../../src/persistence/postgres/wafPostureRepository.mjs';
import { createPostgresWafPostureServices } from '../../src/persistence/postgres/wafPostureServiceAdapters.mjs';
import { getWafCoverage as getDevWafCoverage } from '../../src/services/wafPosture.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const TENANT = 'ten_waf_query_parity';
const CTX = { tenantId: TENANT, userId: 'waf-query-parity-test', role: 'viewer' };
const CASES = [
  [{}, 90],
  [{ window_days: 'not-a-number' }, 90],
  [{ window_days: '0' }, 90],
  [{ window_days: '-4' }, 90],
  [{ window_days: '45.9' }, 45],
  [{ window_days: '9999' }, 365],
];

describe('postgres WAF coverage query parity', () => {
  it('normalizes window_days identically in Postgres and dev-json', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await pool.query('INSERT INTO tenants (id, name) VALUES ($1, $1)', [TENANT]);
      const postgres = createPostgresWafPostureServices({
        wafPosture: createWafPostureRepository(pool),
        coreCatalog: createCoreCatalogRepository(pool),
        audit: createAuditRepository(pool),
        validationEvidence: createValidationEvidenceRepository(pool),
      }, { connectorEncryptionKey: null });

      resetStoreForTests({
        tenants: [{ id: TENANT, name: TENANT }],
        environments: [],
        targetGroups: [],
        targets: [],
        testRuns: [],
        findings: [],
        events: [],
        verdicts: [],
        evidenceVault: [],
        discoveryEntities: [],
      });

      for (const [query, expected] of CASES) {
        const postgresPayload = await postgres.getWafCoverage(CTX, query);
        const devPayload = getDevWafCoverage(CTX, query);
        assert.equal(postgresPayload.window_days, expected, `Postgres ${JSON.stringify(query)}`);
        assert.equal(devPayload.window_days, expected, `dev-json ${JSON.stringify(query)}`);
        assert.deepEqual(devPayload, postgresPayload);
      }
    }, availability.env ?? process.env);
  });
});
