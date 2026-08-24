import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  LEAN_GROUP_LOOKUP,
  TARGET_GROUP_FINDINGS_LIMIT,
  TARGET_GROUP_RUNS_RECENT_LIMIT,
  createCoreCatalogRepository,
  mapDetailTargetRow,
  mapEnvironmentRow,
  mapTargetGroupDetail,
  mapTargetGroupRow,
  mapTargetRow,
  mapTenantRow,
} from '../../src/persistence/postgres/coreCatalogRepository.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const CORE_CATALOG_REPO_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/coreCatalogRepository.mjs'),
  'utf8',
);

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    failOn: null,
    async query(text, params) {
      this.queries.push({ text, params });
      if (this.failOn && this.failOn(text)) {
        throw new Error('simulated query failure');
      }
      return handler(text, params, this.queries);
    },
    release() {
      this.released = true;
    },
  };
  return {
    client,
    async connect() {
      return client;
    },
  };
}

function dataQueries(client) {
  return client.queries.filter((q) => {
    const t = q.text.trim();
    return t !== 'BEGIN' && t !== 'COMMIT' && t !== 'ROLLBACK' && !t.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function assertTenantWrapped(client, tenantId) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

function assertUsesTenantPredicate(sql, params, tenantId) {
  const hasWherePredicate = /tenant_id\s*=\s*\$\d+/i.test(sql);
  const hasInsertColumn = /INSERT\s+INTO\s+\w+\s*\([^)]*tenant_id/i.test(sql);
  assert.ok(
    hasWherePredicate || hasInsertColumn,
    `expected tenant_id predicate or INSERT column in: ${sql}`,
  );
  assert.ok(params.includes(tenantId), `expected tenant id in params for: ${sql}`);
}

function assertNoInterpolatedValue(sql, value) {
  if (value == null || value === '') return;
  assert.ok(!sql.includes(String(value)), `value must not be interpolated into SQL: ${value}`);
}

describe('postgres core catalog repository', () => {
  it('does not reference dev store or safeTestPolicy service module in source', () => {
    assert.equal(/\bservices\/safeTestPolicy\b/.test(CORE_CATALOG_REPO_SOURCE), false);
    assert.equal(/\bgetStore\b/.test(CORE_CATALOG_REPO_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(CORE_CATALOG_REPO_SOURCE), false);
  });

  it('maps tenant, environment, target group, and target rows', () => {
    const tenant = mapTenantRow({
      id: 'ten_demo',
      name: 'Demo',
      privacy_settings: {},
      created_at: new Date(FIXED_NOW),
    });
    assert.equal(tenant.id, 'ten_demo');
    assert.equal(tenant.privacy_settings.metadata_retention_days, 365);

    const env = mapEnvironmentRow({
      id: 'env_1',
      tenant_id: 'ten_demo',
      name: 'Prod',
      status: 'active',
      privacy_settings: {},
      settings_json: { description: 'desc', created_by: 'usr_admin', updated_at: FIXED_NOW },
      created_at: FIXED_NOW,
    });
    assert.equal(env.description, 'desc');
    assert.equal(env.created_by, 'usr_admin');
    assert.equal(env.updated_at, FIXED_NOW);

    const group = mapTargetGroupRow({
      id: 'tg_1',
      tenant_id: 'ten_demo',
      environment_id: 'env_1',
      name: 'G',
      safety_policy: {},
      safe_test_windows: [{ start_at: FIXED_NOW, end_at: FIXED_NOW }],
      created_at: FIXED_NOW,
    });
    assert.equal(group.safety_policy.max_runs_per_hour, 60);
    assert.equal(group.timezone, 'UTC');

    const target = mapTargetRow({
      id: 'tgt_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      kind: 'fqdn',
      value: 'a.example',
      metadata_json: { note: 'x' },
      created_at: FIXED_NOW,
    });
    assert.deepEqual(target.metadata, { note: 'x' });
  });

  it('getCurrentTenant uses tenant context and parameterized tenant id', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM tenants')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Demo Organization',
              privacy_settings: {},
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const tenant = await repo.getCurrentTenant(CTX);
    assert.equal(tenant.name, 'Demo Organization');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /WHERE id = \$1/);
    assert.deepEqual(q.params, [CTX.tenantId]);
    assertNoInterpolatedValue(q.text, CTX.tenantId);
  });

  it('getCurrentTenant returns null when row missing', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.getCurrentTenant(CTX), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('patchCurrentTenant returns null when tenant missing and only selects', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM tenants')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.patchCurrentTenant(CTX, { name: 'x' }), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const selects = dataQueries(pool.client).filter((q) => q.text.includes('SELECT'));
    assert.equal(selects.length, 1);
    assert.match(selects[0].text, /FROM tenants/);
    assert.match(selects[0].text, /WHERE id = \$1/);
    assert.deepEqual(selects[0].params, [CTX.tenantId]);
    assertNoInterpolatedValue(selects[0].text, CTX.tenantId);
    assert.ok(!dataQueries(pool.client).some((q) => q.text.startsWith('UPDATE tenants')));
  });

  it('patchCurrentTenant no-op returns current tenant without UPDATE', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM tenants')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Demo Organization',
              privacy_settings: {},
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const tenant = await repo.patchCurrentTenant(CTX, {});
    assert.equal(tenant.name, 'Demo Organization');
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.ok(!dataQueries(pool.client).some((q) => q.text.startsWith('UPDATE tenants')));
  });

  it('patchCurrentTenant updates name and merged normalized privacy settings', async () => {
    const existingPrivacy = {
      evidence_retention: { legal_hold: true },
    };
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM tenants') && text.includes('SELECT')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Old Name',
              privacy_settings: existingPrivacy,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.startsWith('UPDATE tenants')) {
        assert.match(text, /name = \$1/);
        assert.match(text, /privacy_settings = \$2::jsonb/);
        assert.match(text, /WHERE id = \$3/);
        assert.deepEqual(params[0], 'New Name');
        assertNoInterpolatedValue(text, 'New Name');
        assertNoInterpolatedValue(text, CTX.tenantId);
        const merged = JSON.parse(params[1]);
        assert.equal(merged.metadata_retention_days, 3650);
        assert.equal(merged.evidence_retention.legal_hold, true);
        assert.deepEqual(params[2], CTX.tenantId);
        return {
          rows: [
            {
              id: 'ten_demo',
              name: params[0],
              privacy_settings: merged,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const tenant = await repo.patchCurrentTenant(CTX, {
      name: 'New Name',
      privacy_settings: { metadata_retention_days: 5000 },
    });
    assert.equal(tenant.name, 'New Name');
    assert.equal(tenant.privacy_settings.metadata_retention_days, 3650);
    assert.equal(tenant.privacy_settings.evidence_retention.legal_hold, true);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('patchCurrentTenant enforces retention in the same tenant transaction when privacy changes', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM tenants') && text.includes('SELECT')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Old Name',
              privacy_settings: { metadata_retention_days: 30 },
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.startsWith('UPDATE tenants')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Old Name',
              privacy_settings: JSON.parse(params[0]),
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.includes('FROM events') && text.includes('COUNT(*)')) return { rows: [{ count: '1' }] };
      if (text.includes('FROM evidence_vault') && text.includes('COUNT(*)')) {
        return { rows: [{ count: '0' }] };
      }
      if (text.includes('FROM reports') && text.includes('COUNT(*)')) return { rows: [{ count: '0' }] };
      if (text.includes('FROM notification_events') && text.includes('COUNT(*)')) {
        return { rows: [{ count: '0' }] };
      }
      if (text.startsWith('DELETE FROM events')) return { rowCount: 1, rows: [] };
      if (text.startsWith('DELETE FROM evidence_vault')) return { rowCount: 0, rows: [] };
      if (text.startsWith('DELETE FROM reports')) return { rowCount: 0, rows: [] };
      if (text.startsWith('DELETE FROM notification_events')) return { rowCount: 0, rows: [] };
      if (text.includes('pg_advisory_xact_lock(hashtext($1))')) return { rows: [] };
      if (text.includes('FROM audit_logs') && text.includes('ORDER BY sequence DESC')) {
        return { rows: [] };
      }
      if (text.startsWith('INSERT INTO audit_logs')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const tenant = await repo.patchCurrentTenant(
      CTX,
      { privacy_settings: { metadata_retention_days: 7 } },
      { now: FIXED_NOW },
    );

    assert.equal(tenant.privacy_settings.metadata_retention_days, 7);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const dataSql = dataQueries(pool.client).map((q) => q.text);
    assert.ok(dataSql.some((sql) => sql.includes('DELETE FROM events')));
    assert.ok(dataSql.some((sql) => sql.includes('INSERT INTO audit_logs')));
  });

  it('listEnvironments filters archived and scopes tenant', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM environments')) {
        return {
          rows: [
            {
              id: 'env_1',
              tenant_id: 'ten_demo',
              name: 'Prod',
              status: 'active',
              privacy_settings: {},
              settings_json: {},
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const items = await repo.listEnvironments(CTX);
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /status <> \$\d+/);
    assert.equal(q.params.includes('archived'), true);
  });

  it('createEnvironment inserts with tenant_id param and maps settings_json', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO environments')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'My Env');
        return {
          rows: [
            {
              id: params[0],
              tenant_id: params[1],
              name: params[2],
              status: 'active',
              privacy_settings: JSON.parse(params[4]),
              settings_json: JSON.parse(params[5]),
              created_at: params[6],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const env = await repo.createEnvironment(
      CTX,
      { name: 'My Env', description: 'line', privacy_settings: { metadata_retention_days: 30 } },
      { id: 'env_test', now: FIXED_NOW },
    );
    assert.equal(env.id, 'env_test');
    assert.equal(env.description, 'line');
    assert.equal(env.created_by, CTX.userId);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('patchEnvironment returns null when not found', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM environments')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.patchEnvironment(CTX, 'env_missing', { name: 'x' }), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const selects = dataQueries(pool.client).filter((q) => q.text.includes('SELECT'));
    assert.equal(selects.length, 1);
    assertUsesTenantPredicate(selects[0].text, selects[0].params, CTX.tenantId);
    assertNoInterpolatedValue(selects[0].text, 'env_missing');
    assert.ok(selects[0].params.includes('env_missing'));
  });

  it('patchEnvironment updates with tenant predicate', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM environments')) {
        return {
          rows: [
            {
              id: 'env_1',
              tenant_id: 'ten_demo',
              name: 'Old',
              status: 'active',
              privacy_settings: {},
              settings_json: { description: '' },
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.startsWith('UPDATE environments')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'env_1');
        return {
          rows: [
            {
              id: 'env_1',
              tenant_id: 'ten_demo',
              name: 'New',
              status: 'active',
              privacy_settings: {},
              settings_json: { description: 'd', updated_at: FIXED_NOW },
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const env = await repo.patchEnvironment(
      CTX,
      'env_1',
      { name: 'New', description: 'd' },
      { now: FIXED_NOW },
    );
    assert.equal(env.name, 'New');
    assert.equal(env.updated_at, FIXED_NOW);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('listTargetGroups scopes by tenant_id', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) {
        return {
          rows: [
            {
              id: 'tg_1',
              tenant_id: 'ten_demo',
              environment_id: 'env_1',
              name: 'G',
              safety_policy: {},
              safe_test_windows: [],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const groups = await repo.listTargetGroups(CTX);
    assert.equal(groups.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
  });

  it('listTargetGroups joins target_count and loa_state in one tenant-scoped query', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) {
        return {
          rows: [
            {
              id: 'tg_1',
              tenant_id: 'ten_demo',
              environment_id: 'env_1',
              name: 'G',
              safety_policy: {},
              safe_test_windows: [],
              created_at: FIXED_NOW,
              target_count: 3,
              loa_state: 'signed',
            },
            {
              id: 'tg_2',
              tenant_id: 'ten_demo',
              environment_id: 'env_1',
              name: 'H',
              safety_policy: {},
              safe_test_windows: [],
              created_at: FIXED_NOW,
              target_count: 0,
              loa_state: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const groups = await repo.listTargetGroups(CTX);

    assert.equal(groups[0].target_count, 3);
    assert.equal(groups[0].loa_state, 'signed');
    assert.equal(groups[1].target_count, 0);
    assert.equal(groups[1].loa_state, 'required');
    for (const group of groups) {
      assert.equal(group.targets, undefined);
      assert.equal(group.runs_recent, undefined);
      assert.equal(group.findings_on_group, undefined);
    }

    // One query, not one per group: the counts must come from a join, never an N+1 loop.
    const queries = dataQueries(pool.client);
    assert.equal(queries.length, 1);
    const [q] = queries;
    assert.match(q.text, /FROM\s+targets/);
    assert.match(q.text, /FROM\s+loa_signatures/);
    for (const fragment of q.text.split(/FROM\s+(?:targets|loa_signatures)/).slice(1)) {
      assert.match(fragment, /tenant_id\s*=\s*\$1/);
    }
    assert.deepEqual(q.params, [CTX.tenantId]);
  });

  it('mapTargetGroupRow omits summary keys for callers that do not select them', () => {
    const mapped = mapTargetGroupRow({
      id: 'tg_1',
      tenant_id: 'ten_demo',
      name: 'G',
      safety_policy: {},
      safe_test_windows: [],
      created_at: FIXED_NOW,
    });
    assert.equal('target_count' in mapped, false);
    assert.equal('loa_state' in mapped, false);
  });

  it('getTargetGroup returns null when group missing', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.getTargetGroup(CTX, 'tg_missing'), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const groupQ = dataQueries(pool.client)[0];
    assertUsesTenantPredicate(groupQ.text, groupQ.params, CTX.tenantId);
    assertNoInterpolatedValue(groupQ.text, 'tg_missing');
  });

  it('getTargetGroup returns group with targets array', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM target_groups')) {
        return {
          rows: [
            {
              id: 'tg_1',
              tenant_id: 'ten_demo',
              environment_id: 'env_1',
              name: 'G',
              safety_policy: {},
              safe_test_windows: [],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.includes('FROM targets')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'tg_1');
        return {
          rows: [
            {
              id: 'tgt_1',
              tenant_id: 'ten_demo',
              target_group_id: 'tg_1',
              kind: 'fqdn',
              value: 'origin.example',
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const group = await repo.getTargetGroup(CTX, 'tg_1');
    assert.equal(group.id, 'tg_1');
    assert.equal(group.targets.length, 1);
    assert.equal(group.targets[0].value, 'origin.example');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('getTargetGroup enriches the detail payload from one tenant-scoped join query', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM target_groups')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'tg_1');
        return {
          rows: [
            {
              id: 'tg_1',
              tenant_id: 'ten_demo',
              environment_id: 'env_1',
              name: 'G',
              safety_policy: {},
              safe_test_windows: [],
              created_at: FIXED_NOW,
              loa_state: 'signed',
              loa_signer_name: 'Signer',
              loa_signed_at: FIXED_NOW,
              loa_custody_digest_sha256: 'sha256-detail',
              runs_recent: [
                { id: 'run_2', check_id: 'chk_2', status: 'running', started_at: FIXED_NOW },
                { id: 'run_1', check_id: 'chk_1', status: 'completed', started_at: FIXED_NOW },
              ],
              findings_on_group: [
                {
                  id: 'fnd_1',
                  target_id: 'tgt_1',
                  title: 'Origin reachable',
                  severity: 'high',
                  status: 'open',
                },
                {
                  id: 'fnd_2',
                  target_id: null,
                  title: 'Group drift',
                  severity: 'medium',
                  status: null,
                },
              ],
              findings_on_group_total: 7,
            },
          ],
        };
      }
      if (text.includes('FROM targets')) {
        return {
          rows: [
            {
              id: 'tgt_1',
              tenant_id: 'ten_demo',
              target_group_id: 'tg_1',
              kind: 'fqdn',
              value: 'origin.example',
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const group = await repo.getTargetGroup(CTX, 'tg_1');

    assert.equal(group.target_count, 1);
    assert.equal(group.loa_state, 'signed');
    assert.deepEqual(group.loa, {
      state: 'signed',
      signer_name: 'Signer',
      signed_at: FIXED_NOW,
      custody_digest_sha256: 'sha256-detail',
    });
    assert.deepEqual(group.runs_recent, [
      {
        id: 'run_2',
        policy_id: null,
        check_count: 'chk_2',
        verdict: 'running',
        started_at: FIXED_NOW,
        agent_id: null,
      },
      {
        id: 'run_1',
        policy_id: null,
        check_count: 'chk_1',
        verdict: 'completed',
        started_at: FIXED_NOW,
        agent_id: null,
      },
    ]);
    assert.deepEqual(group.findings_on_group, [
      { id: 'fnd_1', target_id: 'tgt_1', title: 'Origin reachable', severity: 'high', status: 'open' },
      { id: 'fnd_2', target_id: null, title: 'Group drift', severity: 'medium', status: 'open' },
    ]);
    // The list is capped; the total reports every finding on the group so the UI can say
    // "showing N of total" without a second round trip.
    assert.equal(group.findings_on_group_total, 7);
    assert.deepEqual(group.meta, {
      targets_empty_reason: null,
      runs_empty_reason: null,
      findings_empty_reason: null,
    });

    // Two reads only: the group query carries the LOA/runs/findings joins, no N+1 loops.
    const queries = dataQueries(pool.client);
    assert.equal(queries.length, 2);
    const [groupQuery] = queries;
    assert.deepEqual(groupQuery.params, [
      'tg_1',
      CTX.tenantId,
      TARGET_GROUP_RUNS_RECENT_LIMIT,
      TARGET_GROUP_FINDINGS_LIMIT,
    ]);
    assert.match(groupQuery.text, /FROM\s+loa_signatures/);
    assert.match(groupQuery.text, /FROM\s+test_runs/);
    assert.match(groupQuery.text, /FROM\s+findings/);
    assert.match(groupQuery.text, /LIMIT\s+\$3/);
    // Findings are bounded and newest-first, with the cap parameterized like the runs cap.
    assert.match(groupQuery.text, /LIMIT\s+\$4/);
    assert.match(groupQuery.text, /ORDER BY created_at DESC, id DESC\s+LIMIT\s+\$4/);
    assert.match(groupQuery.text, /count\(\*\)::int/);
    for (const fragment of groupQuery.text
      .split(/FROM\s+(?:loa_signatures|test_runs|findings)/)
      .slice(1)) {
      assert.match(fragment, /tenant_id\s*=\s*\$2/);
    }
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('only the HTTP detail handler asks for the enriched target group', () => {
    // Fails loudly if a new internal adapter call site forgets the lean option and silently
    // starts paying for the detail aggregates again.
    const adapterDir = path.join(ROOT, 'src/persistence/postgres');
    const offenders = [];
    for (const file of readdirSync(adapterDir).filter((name) => name.endsWith('ServiceAdapters.mjs'))) {
      const source = readFileSync(path.join(adapterDir, file), 'utf8');
      // `[^)]` skips the zero-arg mentions inside "requires coreCatalog.getTargetGroup()" guards.
      for (const call of source.matchAll(/coreCatalog\.getTargetGroup\((\s*[^)][\s\S]*?)\);/g)) {
        if (!call[1].includes('LEAN_GROUP_LOOKUP')) offenders.push(`${file}: ${call[0].slice(0, 80)}`);
      }
    }
    assert.deepEqual(offenders, []);
  });

  it('getTargetGroup detail stamps verification_state on every target (dev-json parity)', async () => {
    // dev-json's getTargetGroup maps each target with `verification_state ?? verify_state ??
    // 'unverified'`; Postgres omitted the field entirely, so the portal verify chip read a
    // real state on one backend and its own default on the other.
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) {
        return { rows: [{ id: 'tg_1', tenant_id: 'ten_demo', environment_id: 'env_1', name: 'G', safety_policy: {}, safe_test_windows: [], created_at: FIXED_NOW }] };
      }
      if (text.includes('FROM targets')) {
        return {
          rows: [
            { id: 'tgt_plain', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'a.example', created_at: FIXED_NOW },
            { id: 'tgt_meta', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'b.example', created_at: FIXED_NOW, metadata_json: { verification_state: 'verified' } },
            { id: 'tgt_legacy', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'c.example', created_at: FIXED_NOW, metadata_json: { verify_state: 'pending' } },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const group = await repo.getTargetGroup(CTX, 'tg_1');
    assert.deepEqual(
      group.targets.map((t) => [t.id, t.verification_state]),
      [['tgt_plain', 'unverified'], ['tgt_meta', 'verified'], ['tgt_legacy', 'pending']],
    );
  });

  it('mapDetailTargetRow adds verification_state where mapTargetRow deliberately does not', () => {
    const row = { id: 'tgt_1', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'a.example', created_at: FIXED_NOW };
    // add/patch target responses carry no verification_state on either backend; only detail does.
    assert.equal('verification_state' in mapTargetRow(row), false);
    assert.equal(mapDetailTargetRow(row).verification_state, 'unverified');
    assert.equal(mapDetailTargetRow(null), null);
  });

  it('getTargetGroup lean lookup skips the LOA/runs/findings aggregates entirely', async () => {
    // ~12 internal callers (run start/collect/ingest, WAF orchestration, high-scale, policy
    // enrichment, agent binding) read only the group row and its targets, yet paid for the
    // detail LATERALs.
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) {
        assert.doesNotMatch(text, /FROM\s+loa_signatures/, 'lean lookup must not join LOA');
        assert.doesNotMatch(text, /FROM\s+test_runs/, 'lean lookup must not join runs');
        assert.doesNotMatch(text, /FROM\s+findings/, 'lean lookup must not join findings');
        assert.doesNotMatch(text, /LATERAL/, 'lean lookup must not use LATERAL aggregates');
        return { rows: [{ id: 'tg_1', tenant_id: 'ten_demo', environment_id: 'env_1', name: 'G', validation_mode: 'external_only', ownership_status: 'dns_verified', safety_policy: {}, safe_test_windows: [], created_at: FIXED_NOW }] };
      }
      if (text.includes('FROM targets')) {
        return { rows: [{ id: 'tgt_1', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'origin.example', created_at: FIXED_NOW }] };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const group = await repo.getTargetGroup(CTX, 'tg_1', LEAN_GROUP_LOOKUP);

    // Everything the internal callers actually read is still present.
    assert.equal(group.id, 'tg_1');
    assert.equal(group.environment_id, 'env_1');
    assert.equal(group.validation_mode, 'external_only');
    assert.equal(group.ownership_status, 'dns_verified');
    assert.deepEqual(group.targets.map((t) => t.id), ['tgt_1']);
    assert.equal(group.target_count, 1);

    // Nothing the detail route adds.
    assert.equal('runs_recent' in group, false);
    assert.equal('findings_on_group' in group, false);
    assert.equal('findings_on_group_total' in group, false);
    assert.equal('loa' in group, false);
    assert.equal('meta' in group, false);

    const queries = dataQueries(pool.client);
    assert.equal(queries.length, 2, 'group row + targets, no aggregate round trips');
    assert.deepEqual(queries[0].params, ['tg_1', CTX.tenantId], 'no runs-recent LIMIT param');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('lean lookup still hides archived and deleted groups, and stays tenant-scoped', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM target_groups')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'tg_missing');
        assert.match(text, /deleted_at IS NULL/);
        assert.match(text, /archived_at IS NULL/);
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.getTargetGroup(CTX, 'tg_missing', LEAN_GROUP_LOOKUP), null);
    assert.equal(dataQueries(pool.client).length, 1, 'a miss must not read targets');
  });

  it('the enriched detail path is unchanged when no options are passed', async () => {
    const seen = [];
    const pool = createRecordingPool((text) => {
      seen.push(text);
      if (text.includes('FROM target_groups')) {
        return { rows: [{ id: 'tg_1', tenant_id: 'ten_demo', environment_id: 'env_1', name: 'G', safety_policy: {}, safe_test_windows: [], created_at: FIXED_NOW, loa_state: 'signed', runs_recent: [], findings_on_group: [] }] };
      }
      if (text.includes('FROM targets')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const group = await repo.getTargetGroup(CTX, 'tg_1');
    assert.match(seen[2] ?? seen[0], /LATERAL/);
    assert.ok(group.loa, 'detail route keeps the LOA panel');
    assert.deepEqual(group.runs_recent, []);
    assert.deepEqual(group.findings_on_group, []);
    assert.ok(group.meta, 'detail route keeps the empty-state reasons');
  });

  it('getTargetGroup detail mapper reports empty-state reasons and a null LOA', () => {
    const detail = mapTargetGroupDetail(
      { runs_recent: null, findings_on_group: null, loa_state: null },
      [],
    );
    assert.deepEqual(detail.runs_recent, []);
    assert.deepEqual(detail.findings_on_group, []);
    assert.equal(detail.findings_on_group_total, 0);
    assert.equal(detail.loa, null);
    assert.equal(detail.target_count, 0);
    assert.deepEqual(detail.meta, {
      targets_empty_reason: 'No targets have been declared for this group yet.',
      runs_empty_reason: 'No test runs have been recorded for this target group yet.',
      findings_empty_reason: 'No findings are published for this target group yet.',
    });
  });

  it('createTargetGroup inserts tenant-scoped row with normalized policy', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('SELECT id FROM environments')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return { rows: [{ id: params[1] }] };
      }
      if (text.startsWith('INSERT INTO target_groups')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'tg_new');
        return {
          rows: [
            {
              id: params[0],
              tenant_id: params[1],
              environment_id: params[2],
              name: params[3],
              description: params[4],
              expected_behavior_default: params[5],
              timezone: params[6],
              safe_test_windows: JSON.parse(params[7]),
              safety_policy: JSON.parse(params[8]),
              created_at: params[9],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const group = await repo.createTargetGroup(
      CTX,
      { name: 'Origin', environment_id: 'env_demo', safety_policy: { max_runs_per_hour: 10 } },
      { id: 'tg_new', now: FIXED_NOW },
    );
    assert.equal(group.id, 'tg_new');
    assert.equal(group.safety_policy.max_runs_per_hour, 10);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createTargetGroup returns invalid_environment error when environment is missing for tenant', async () => {
    const pool = createRecordingPool((text) => {
      if (text.startsWith('SELECT id FROM environments')) {
        return { rows: [] };
      }
      if (text.startsWith('INSERT INTO target_groups')) {
        throw new Error('INSERT should not run when environment is missing');
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const result = await repo.createTargetGroup(
      CTX,
      { name: 'Origin', environment_id: 'prod' },
      { id: 'tg_new', now: FIXED_NOW },
    );
    assert.equal(result.error, 'invalid_environment');
    assert.equal(result.status, 400);
    assert.equal(result.field, 'environment_id');
    assert.match(result.message, /prod/);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('addTarget returns null when group missing', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.addTarget(CTX, 'tg_missing', { value: 'a.example' }), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
  });

  it('addTarget inserts with tenant_id and group id params', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM target_groups')) {
        return { rows: [{ id: 'tg_1', expected_behavior_default: 'must_block_before_origin' }] };
      }
      if (text.startsWith('INSERT INTO targets')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'origin.demo.example');
        assert.ok(params.includes('tg_1'));
        return {
          rows: [
            {
              id: params[0],
              tenant_id: params[1],
              target_group_id: params[2],
              kind: params[3],
              value: params[4],
              expected_behavior: params[5],
              metadata_json: JSON.parse(params[6]),
              created_at: params[7],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const target = await repo.addTarget(
      CTX,
      'tg_1',
      { value: 'origin.demo.example' },
      { id: 'tgt_new', now: FIXED_NOW },
    );
    assert.equal(target.id, 'tgt_new');
    assert.equal(target.expected_behavior, undefined);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('rolls back when a catalog query fails inside tenant context', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) {
        throw new Error('db read failed');
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    await assert.rejects(() => repo.getTargetGroup(CTX, 'tg_1'), /db read failed/);
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.ok(!pool.client.queries.some((q) => q.text.trim() === 'COMMIT'));
    assert.equal(pool.client.released, true);
  });
});
