import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { listFindingsEnvelope as listDevFindingsEnvelope } from '../../src/services/findings.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const TENANT = 'ten_finding_parity';
const OTHER_TENANT = 'ten_finding_parity_other';
const CTX = { tenantId: TENANT, userId: 'finding-parity-test', role: 'viewer' };

const FINDINGS = [
  {
    id: 'fnd_old',
    tenant_id: TENANT,
    target_group_id: 'tg_find_a',
    target_id: 'tgt_find_a',
    test_run_id: 'run_find_old',
    check_id: 'origin.host_sni_bypass.safe',
    title: 'Older origin finding',
    severity: 'medium',
    status: 'open',
    evidence_ids: ['evt_old'],
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
  },
  {
    id: 'fnd_new',
    tenant_id: TENANT,
    target_group_id: 'tg_find_a',
    target_id: 'tgt_find_a',
    test_run_id: 'run_find_new',
    check_id: 'origin.direct_bypass.safe',
    title: 'Newest origin finding',
    severity: 'high',
    status: 'open',
    evidence_ids: ['evt_new'],
    created_at: '2026-01-03T00:00:00.000Z',
    updated_at: '2026-01-03T00:00:00.000Z',
  },
  {
    id: 'fnd_group_b',
    tenant_id: TENANT,
    target_group_id: 'tg_find_b',
    target_id: 'tgt_find_b',
    test_run_id: 'run_find_b',
    check_id: 'path.protected_canary.safe',
    title: 'Other group finding',
    severity: 'low',
    status: 'closed',
    evidence_ids: [],
    created_at: '2026-01-02T00:00:00.000Z',
    updated_at: '2026-01-02T00:00:00.000Z',
  },
];

async function seed(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query('INSERT INTO tenants (id, name) VALUES ($1, $1), ($2, $2)', [TENANT, OTHER_TENANT]);
    await client.query(
      "INSERT INTO environments (id, tenant_id, name) VALUES ('env_find_a', $1, 'prod'), ('env_find_other', $2, 'prod')",
      [TENANT, OTHER_TENANT],
    );
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES
         ('tg_find_a', $1, 'env_find_a', 'A'),
         ('tg_find_b', $1, 'env_find_a', 'B'),
         ('tg_find_other', $2, 'env_find_other', 'Other')`,
      [TENANT, OTHER_TENANT],
    );
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value) VALUES
         ('tgt_find_a', $1, 'tg_find_a', 'fqdn', 'a.example.test', 'a.example.test'),
         ('tgt_find_b', $1, 'tg_find_b', 'fqdn', 'b.example.test', 'b.example.test'),
         ('tgt_find_other', $2, 'tg_find_other', 'fqdn', 'other.example.test', 'other.example.test')`,
      [TENANT, OTHER_TENANT],
    );
    await client.query(
      `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, created_at) VALUES
         ('run_find_old', $1, 'tg_find_a', 'tgt_find_a', 'origin.host_sni_bypass.safe', 'verdicted', '2026-01-01T00:00:00.000Z'),
         ('run_find_new', $1, 'tg_find_a', 'tgt_find_a', 'origin.direct_bypass.safe', 'verdicted', '2026-01-03T00:00:00.000Z'),
         ('run_find_b', $1, 'tg_find_b', 'tgt_find_b', 'path.protected_canary.safe', 'verdicted', '2026-01-02T00:00:00.000Z')`,
      [TENANT],
    );
    for (const finding of FINDINGS) {
      await client.query(
        `INSERT INTO findings (
           id, tenant_id, target_group_id, target_id, test_run_id, check_id, title,
           severity, status, evidence_ids, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text[], $11, $12)`,
        [
          finding.id,
          finding.tenant_id,
          finding.target_group_id,
          finding.target_id,
          finding.test_run_id,
          finding.check_id,
          finding.title,
          finding.severity,
          finding.status,
          finding.evidence_ids,
          finding.created_at,
          finding.updated_at,
        ],
      );
    }
    await client.query(
      `INSERT INTO findings (id, tenant_id, target_group_id, target_id, title, severity, status)
       VALUES ('fnd_other_tenant', $1, 'tg_find_other', 'tgt_find_other', 'Do not leak', 'critical', 'open')`,
      [OTHER_TENANT],
    );
  });
}

function createServices(pool) {
  return createPostgresValidationServices({
    validationEvidence: createValidationEvidenceRepository(pool),
    audit: createAuditRepository(pool),
    coreCatalog: createCoreCatalogRepository(pool),
    probeJobs: createProbeJobRepository(pool),
    killSwitch: createKillSwitchRepository(pool),
  }).findings;
}

describe('postgres findings list API parity', () => {
  it('honours every list option and returns the dev-json envelope and fields', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const findings = createServices(pool);

      const all = await findings.listFindingsEnvelope(CTX);
      assert.deepEqual(all.items.map((item) => item.id), ['fnd_new', 'fnd_group_b', 'fnd_old']);
      assert.equal(all.count, 3);
      assert.equal(all.meta.empty_reason, null);
      assert.equal(all.items[0].title, 'Newest origin finding');
      assert.equal(all.items[0].target_id, 'tgt_find_a');
      assert.equal(all.items[0].test_run_id, 'run_find_new');

      const byGroup = await findings.listFindingsEnvelope(CTX, { target_group_id: 'tg_find_a' });
      assert.deepEqual(byGroup.items.map((item) => item.id), ['fnd_new', 'fnd_old']);

      const byTarget = await findings.listFindingsEnvelope(CTX, { target_id: 'tgt_find_b' });
      assert.deepEqual(byTarget.items.map((item) => item.id), ['fnd_group_b']);

      const byRun = await findings.listFindingsEnvelope(CTX, { test_run_id: 'run_find_old' });
      assert.deepEqual(byRun.items.map((item) => item.id), ['fnd_old']);

      const limited = await findings.listFindingsEnvelope(CTX, { target_group_id: 'tg_find_a', limit: '1' });
      assert.deepEqual(limited.items.map((item) => item.id), ['fnd_new']);

      for (const [options, reason] of [
        [{ target_group_id: 'tg_missing' }, 'No findings match this target group filter.'],
        [{ target_id: 'tgt_missing' }, 'No findings match this target filter.'],
        [{ test_run_id: 'run_missing' }, 'No findings match this test run filter.'],
      ]) {
        const empty = await findings.listFindingsEnvelope(CTX, options);
        assert.deepEqual(empty.items, []);
        assert.equal(empty.count, 0);
        assert.equal(empty.meta.empty_reason, reason);
      }

      resetStoreForTests({ findings: [...FINDINGS] });
      const dev = listDevFindingsEnvelope(CTX, { target_group_id: 'tg_find_a' });
      assert.deepEqual(dev.items.map((item) => item.id), byGroup.items.map((item) => item.id));
      assert.deepEqual(dev.meta, byGroup.meta);
    }, availability.env ?? process.env);
  });
});
