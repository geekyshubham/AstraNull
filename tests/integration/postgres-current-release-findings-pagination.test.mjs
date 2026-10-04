import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { containsAgentPlacementVocabulary } from '../../src/lib/outsideInEvidence.mjs';
import {
  createPostgresValidationServices,
  VALIDATION_AUDIT_REPOSITORY_METHODS,
  VALIDATION_CORE_CATALOG_REPOSITORY_METHODS,
  VALIDATION_KILL_SWITCH_REPOSITORY_METHODS,
  VALIDATION_PROBE_JOB_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
  withTenantContextAsAppRole,
} from '../helpers/pg-harness.mjs';

const TENANT_A = 'ten_find_a';
const TENANT_B = 'ten_find_b';

function stubFrom(methodNames) {
  const stub = {};
  for (const name of methodNames) stub[name] = async () => null;
  return stub;
}

describe('postgres current-release findings pagination', () => {
  it('pages one snapshot and applies the same group and status predicate', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await pool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')`, [TENANT_A, TENANT_B]);
      await pool.query(
        `INSERT INTO environments (id, tenant_id, name) VALUES ('env_a', $1, 'A'), ('env_b', $2, 'B')`,
        [TENANT_A, TENANT_B],
      );
      await pool.query(
        `INSERT INTO target_groups (id, tenant_id, environment_id, name)
         VALUES
           ('tg_page', $1, 'env_a', 'page'),
           ('tg_a', $1, 'env_a', 'active'),
           ('tg_other', $1, 'env_a', 'other'),
           ('tg_stale', $1, 'env_a', 'stale'),
           ('tg_b', $2, 'env_b', 'foreign')`,
        [TENANT_A, TENANT_B],
      );
      await pool.query(
        `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, deleted_at)
         VALUES
           ('tgt_page', $1, 'tg_page', 'fqdn', 'page.example.com', 'page.example.com', NULL),
           ('tgt_a', $1, 'tg_a', 'fqdn', 'a.example.com', 'a.example.com', NULL),
           ('tgt_moved', $1, 'tg_a', 'fqdn', 'moved.example.com', 'moved.example.com', NULL),
           ('tgt_dead', $1, 'tg_a', 'fqdn', 'dead.example.com', 'dead.example.com', now()),
           ('tgt_b', $2, 'tg_b', 'fqdn', 'b.example.com', 'b.example.com', NULL)`,
        [TENANT_A, TENANT_B],
      );
      const rows = [
        ['f3', TENANT_A, 'tg_page', 'tgt_page', 'chk_page', 'open', 'medium', 'Page three', '2026-08-03T00:00:00.000Z', null],
        ['f2', TENANT_A, 'tg_page', 'tgt_page', 'chk_page_2', 'open', 'medium', 'Page two', '2026-08-02T00:00:00.000Z', null],
        ['f1', TENANT_A, 'tg_page', 'tgt_page', 'chk_page_1', 'open', 'medium', 'Page one', '2026-08-01T00:00:00.000Z', null],
        ['f_open', TENANT_A, 'tg_a', 'tgt_a', 'chk_open', 'open', 'high', 'Edge gap', '2026-07-02T00:00:00.000Z', null],
        ['f_closed', TENANT_A, 'tg_a', 'tgt_a', 'chk_closed', 'closed', 'low', 'Old gap', '2026-07-01T00:00:00.000Z', null],
        ['f_member', TENANT_A, 'tg_other', 'tgt_moved', 'chk_member', 'open', 'medium', 'Moved member', '2026-07-03T00:00:00.000Z', null],
        ['f_dead', TENANT_A, 'tg_stale', 'tgt_dead', 'chk_dead', 'open', 'medium', 'Dead member', '2026-07-04T00:00:00.000Z', null],
        [
          'f_hidden_title', TENANT_A, 'tg_a', 'tgt_a', 'chk_secret', 'open', 'medium',
          'Visible title', '2026-07-06T00:00:00.000Z', 'super-secret-note agent placement',
        ],
        [
          'f_padded_open', TENANT_A, 'tg_a', 'tgt_a', 'chk_padded', '  Open  ', 'medium',
          'Padded status', '2026-07-07T00:00:00.000Z', null,
        ],
        // Severity alias classes: S1/S2/moderate tokens label the same classes
        // the UI shows for critical/high/medium, and an unrecognized token is
        // the unknown class, not low.
        [
          'f_s1_alias', TENANT_A, 'tg_a', 'tgt_a', 'chk_s1', 'open', 'S1',
          'S1 alias row', '2026-07-08T00:00:00.000Z', null,
        ],
        [
          'f_s2_alias', TENANT_A, 'tg_a', 'tgt_a', 'chk_s2', 'open', 'S2',
          'S2 alias row', '2026-07-08T01:00:00.000Z', null,
        ],
        [
          'f_moderate_alias', TENANT_A, 'tg_a', 'tgt_a', 'chk_moderate', 'open', 'moderate',
          'Moderate alias row', '2026-07-08T02:00:00.000Z', null,
        ],
        [
          'f_unknown_alias', TENANT_A, 'tg_a', 'tgt_a', 'chk_unknown', 'open', 'weird-class',
          'Unknown class row', '2026-07-08T03:00:00.000Z', null,
        ],
        ['f_b', TENANT_B, 'tg_b', 'tgt_b', 'chk_b', 'open', 'high', 'Foreign gap', '2026-07-06T00:00:00.000Z', null],
      ];
      for (const [id, tenant, group, target, check, status, severity, title, created, notes] of rows) {
        await pool.query(
          `INSERT INTO findings (
             id, tenant_id, target_group_id, target_id, check_id, title, severity, status, notes, created_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz)`,
          [id, tenant, group, target, check, title, severity, status, notes, created],
        );
      }

      const repo = createValidationEvidenceRepository(pool);
      const services = createPostgresValidationServices({
        validationEvidence: repo,
        audit: stubFrom(VALIDATION_AUDIT_REPOSITORY_METHODS),
        coreCatalog: stubFrom(VALIDATION_CORE_CATALOG_REPOSITORY_METHODS),
        probeJobs: stubFrom(VALIDATION_PROBE_JOB_REPOSITORY_METHODS),
        killSwitch: stubFrom(VALIDATION_KILL_SWITCH_REPOSITORY_METHODS),
      });
      const read = (tenantId, filters) => withTenantContextAsAppRole(pool, tenantId, (client) => {
        const texts = [];
        const wrapped = {
          query(text, params) {
            texts.push(String(text));
            assert.equal(String(text).includes('super-secret-note'), false);
            return client.query(text, params);
          },
        };
        return services.findings.listFindingsEnvelope(
          { tenantId, userId: 'usr_admin', role: 'admin' },
          { ...filters, client: wrapped },
        ).then((body) => ({ body, texts }));
      });

      const page = await read(TENANT_A, { target_group_id: 'tg_page', limit: 2 });
      // Count and page must share one statement snapshot: a single SQL text with both.
      assert.equal(page.texts.length, 1);
      assert.equal(page.texts[0].includes('COUNT(*)::int AS total'), true);
      assert.equal(page.texts[0].includes('LIMIT $'), true);
      assert.equal(page.texts[0].includes('f.tenant_id = $1'), true);
      assert.equal(page.texts.some((text) => /coalesce\(f\.(notes|remediation_template)/.test(text)), false);
      assert.equal(page.body.total, 3);
      assert.equal(page.body.count, 3);
      assert.equal(page.body.pages, 2);
      assert.equal(page.body.has_more, true);
      assert.deepEqual(page.body.items.map((item) => item.id), ['f3', 'f2']);

      const second = await read(TENANT_A, { target_group_id: 'tg_page', limit: 2, page: 2 });
      assert.equal(second.body.total, 3);
      assert.equal(second.body.count, 3);
      assert.notEqual(second.body.count, second.body.items.length);
      assert.equal(second.body.has_more, false);
      assert.deepEqual(second.body.items.map((item) => item.id), ['f1']);

      const beyond = await read(TENANT_A, { target_group_id: 'tg_page', limit: 2, page: 99 });
      assert.equal(beyond.texts.length, 1);
      assert.equal(beyond.body.total, 3);
      assert.equal(beyond.body.count, 3);
      assert.deepEqual(beyond.body.items, []);
      assert.equal(beyond.body.has_more, false);
      assert.equal(beyond.body.meta.empty_reason, null);

      const grouped = await read(TENANT_A, { target_group_id: 'tg_a', limit: 50 });
      assert.deepEqual(grouped.body.items.map((item) => item.id).sort(), [
        'f_closed', 'f_hidden_title', 'f_member', 'f_moderate_alias', 'f_open',
        'f_padded_open', 'f_s1_alias', 'f_s2_alias', 'f_unknown_alias',
      ]);
      assert.equal(grouped.body.total, grouped.body.count, 'count stays the full match count');
      const openGroup = await read(TENANT_A, { target_group_id: 'tg_a', status: 'open', limit: 50 });
      assert.deepEqual(openGroup.body.items.map((item) => item.id).sort(), [
        'f_hidden_title', 'f_member', 'f_moderate_alias', 'f_open',
        'f_padded_open', 'f_s1_alias', 'f_s2_alias', 'f_unknown_alias',
      ]);
      const allStatus = await read(TENANT_A, { target_group_id: 'tg_a', status: 'all', limit: 50 });
      assert.equal(allStatus.body.total, grouped.body.total);
      const closed = await read(TENANT_A, { target_group_id: 'tg_a', status: 'closed', severity: 'low', limit: 50 });
      assert.deepEqual(closed.body.items.map((item) => item.id), ['f_closed']);

      // Canonical severity aliases match every equivalent recorded class and
      // keep count/page parity. A padded or mixed-case open status row is
      // still the open lifecycle.
      const paddedStatus = await read(TENANT_A, { status: 'open', target_group_id: 'tg_a', limit: 2, page: 2 });
      assert.equal(paddedStatus.body.total, openGroup.body.total);
      assert.equal(paddedStatus.texts.length, 1);
      const severityHigh = await read(TENANT_A, { severity: 'high', target_group_id: 'tg_a', limit: 50 });
      assert.deepEqual(severityHigh.body.items.map((item) => item.id).sort(), ['f_open', 'f_s2_alias']);
      assert.equal(severityHigh.body.total, severityHigh.body.count);
      const severityAlias = await read(TENANT_A, { severity: 'S2', target_group_id: 'tg_a', limit: 50 });
      assert.deepEqual(severityAlias.body.items.map((item) => item.id), severityHigh.body.items.map((item) => item.id));
      const severityCritical = await read(TENANT_A, { severity: 'critical', target_group_id: 'tg_a', limit: 50 });
      assert.deepEqual(severityCritical.body.items.map((item) => item.id), ['f_s1_alias']);
      const severityUnknown = await read(TENANT_A, { severity: 'unknown', target_group_id: 'tg_a', limit: 50 });
      assert.deepEqual(severityUnknown.body.items.map((item) => item.id), ['f_unknown_alias']);
      assert.equal(listTextHasSeverityEquality(severityUnknown.texts), false, 'severity never compares the raw token');

      const secret = await read(TENANT_A, { q: 'super-secret-note', limit: 50 });
      assert.equal(secret.body.total, 0);
      assert.equal(secret.body.meta.empty_reason, 'No findings match this search.');
      const visible = await read(TENANT_A, { q: 'Visible', limit: 50 });
      assert.deepEqual(visible.body.items.map((item) => item.id), ['f_hidden_title']);
      assert.equal(containsAgentPlacementVocabulary(visible.body.items[0].notes), false);

      const missing = await read(TENANT_A, { check_id: 'chk_missing' });
      assert.equal(missing.body.total, 0);
      assert.equal(missing.body.pages, 0);
      assert.equal(missing.body.has_more, false);
      assert.equal(missing.body.meta.empty_reason, 'No findings match this check filter.');

      const hidden = await read(TENANT_B, { target_group_id: 'tg_a', limit: 50 });
      assert.equal(hidden.body.total, 0);
      assert.equal(hidden.body.items.length, 0);
      const own = await read(TENANT_B, { limit: 50 });
      assert.deepEqual(own.body.items.map((item) => item.id), ['f_b']);

      const invalid = await read(TENANT_A, { status: 'nope' });
      assert.equal(invalid.body.status, 400);
      assert.equal(invalid.body.error, 'invalid_query_value');
      assert.equal(invalid.texts.length, 0);

      const listed = await withTenantContextAsAppRole(pool, TENANT_A, (client) => (
        repo.listFindings({ tenantId: TENANT_A }, { client })
      ));
      assert.equal(listed.length, 13);
      assert.equal(listed.length > 2, true);
    }, availability.env);
  });
});

/** True when any SQL text still compares the raw stored severity token. */
function listTextHasSeverityEquality(texts) {
  return texts.some((text) => /f\.severity\s*=\s*\$/.test(String(text)));
}
