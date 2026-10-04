import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  DECLARED_HOST_BATCH_SQL,
  presentDeclaredTargetRow,
  readDeclaredHostAnalytics,
} from '../../src/persistence/postgres/declaredHostAnalyticsRepository.mjs';
import { DeclaredHostQueryError } from '../../src/services/declaredHostAnalytics.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
  withTenantContextAsAppRole,
} from '../helpers/pg-harness.mjs';

const TENANT_A = 'ten_ana_a';
const TENANT_B = 'ten_ana_b';
const OBSERVED_AT = '2026-09-01T00:00:00.000Z';
const COMPLETED_AT = '2026-10-01T00:00:00.000Z';

describe('postgres declared host analytics', () => {
  it('filters active declared targets with the shared predicate under RLS', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    assert.equal(DECLARED_HOST_BATCH_SQL.includes('evidence_json'), false);
    assert.equal(DECLARED_HOST_BATCH_SQL.includes('source_ref'), false);
    assert.equal(DECLARED_HOST_BATCH_SQL.includes('target_verification_current'), true);
    assert.equal(DECLARED_HOST_BATCH_SQL.includes('FROM target_verifications'), false);
    assert.equal(DECLARED_HOST_BATCH_SQL.includes('$1'), true);
    assert.equal(DECLARED_HOST_BATCH_SQL.includes('${'), false);

    await withEphemeralPostgres(async (pool) => {
      await pool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')`, [TENANT_A, TENANT_B]);
      await pool.query(
        `INSERT INTO environments (id, tenant_id, name) VALUES ('env_a', $1, 'A'), ('env_b', $2, 'B')`,
        [TENANT_A, TENANT_B],
      );
      await pool.query(
        `INSERT INTO target_groups (id, tenant_id, environment_id, name, declaration_json, archived_at)
         VALUES
           ('tg_a', $1, 'env_a', 'active', $3::jsonb, NULL),
           ('tg_arch', $1, 'env_a', 'archived', '{}'::jsonb, now()),
           ('tg_b', $2, 'env_b', 'other', '{}'::jsonb, NULL)`,
        [TENANT_A, TENANT_B, JSON.stringify({
          criticality: 'high',
          service_roles: ['website'],
          owner_label: 'Group Owner',
        })],
      );

      const targets = [
        ['tgt_host', TENANT_A, 'tg_a', 'fqdn', 'Example.com', 'example.com', { service_roles: ['website'], criticality: 'critical', owner_label: 'Edge' }, { tags: ['prod'] }],
        ['tgt_url', TENANT_A, 'tg_a', 'url', 'https://Example.com/login', 'https://example.com/login', { service_roles: ['login'] }, {}],
        ['tgt_api', TENANT_A, 'tg_a', 'fqdn', 'api.example.com', 'api.example.com', { service_roles: ['api', 'login'], criticality: 'high' }, {}],
        ['tgt_down', TENANT_A, 'tg_a', 'fqdn', 'down.example.com', 'down.example.com', { service_roles: [], criticality: null, owner_label: null }, {}],
        ['tgt_inherit', TENANT_A, 'tg_a', 'fqdn', 'inherited.example.com', 'inherited.example.com', {}, {}],
        ['tgt_conflict', TENANT_A, 'tg_a', 'fqdn', 'conflict.example.com', 'conflict.example.com', { service_roles: ['website'] }, {}],
        ['tgt_tag', TENANT_A, 'tg_a', 'fqdn', 'tags.example.com', 'tags.example.com', { service_roles: ['dns'] }, { tags: ['api', 'login'], connector_token: 'super-secret-metadata' }],
        ['tgt_ip', TENANT_A, 'tg_a', 'ip', '203.0.113.10', '203.0.113.10', { service_roles: ['network'] }, {}],
        ['tgt_ipurl', TENANT_A, 'tg_a', 'url', 'https://203.0.113.10/admin', 'https://203.0.113.10/admin', { service_roles: [] }, {}],
        ['tgt_cidr', TENANT_A, 'tg_a', 'cidr', '203.0.113.0/24', '203.0.113.0/24', { service_roles: [] }, {}],
        ['tgt_arch', TENANT_A, 'tg_arch', 'fqdn', 'archived.example.com', 'archived.example.com', {}, {}],
        ['tgt_deleted', TENANT_A, 'tg_a', 'fqdn', 'deleted.example.com', 'deleted.example.com', {}, {}],
        ['tgt_b', TENANT_B, 'tg_b', 'fqdn', 'other.example.com', 'other.example.com', { service_roles: ['api'] }, {}],
      ];
      for (const [id, tenant, group, kind, value, normalized, declaration, metadata] of targets) {
        await pool.query(
          `INSERT INTO targets (
             id, tenant_id, target_group_id, kind, value, normalized_value, declaration_json, metadata_json, deleted_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9)`,
          [id, tenant, group, kind, value, normalized, JSON.stringify(declaration), JSON.stringify(metadata), id === 'tgt_deleted' ? COMPLETED_AT : null],
        );
      }

      await pool.query(
        `INSERT INTO target_verifications (
           id, tenant_id, target_id, state, source_kind, source_ref, transitioned_by, audit_entry_id
         ) VALUES ('tv_down', $1, 'tgt_down', 'unverified', 'dns_txt', '{}'::jsonb, 'system', 'aud_down')`,
        [TENANT_A],
      );
      await pool.query(
        `INSERT INTO findings (
           id, tenant_id, target_group_id, target_id, check_id, title, severity, status
         ) VALUES
           ('f_open', $1, 'tg_a', 'tgt_api', 'edge.fingerprint', 'Open', 'medium', 'open'),
           ('f_closed', $1, 'tg_a', 'tgt_api', 'edge.fingerprint', 'Closed', 'medium', 'closed'),
           ('f_b', $2, 'tg_b', 'tgt_b', 'edge.fingerprint', 'Other', 'medium', 'open')`,
        [TENANT_A, TENANT_B],
      );

      const edges = [
        ['run_host', 'edge_host', 'tgt_host', false, 'detected', 'not_detected', OBSERVED_AT, null],
        ['run_url', 'edge_url', 'tgt_url', false, 'detected', 'not_detected', OBSERVED_AT, null],
        ['run_api', 'edge_api', 'tgt_api', false, 'detected', 'detected', OBSERVED_AT, COMPLETED_AT],
        ['run_conflict', 'edge_conflict', 'tgt_conflict', true, 'detected', 'not_detected', OBSERVED_AT, null],
      ];
      for (const [runId, edgeId, targetId, conflict, wafStatus, cdnStatus, observedAt, completedAt] of edges) {
        await pool.query(
          `INSERT INTO test_runs (
             id, tenant_id, target_group_id, target_id, check_id, status, completed_at
           ) VALUES ($1, $2, 'tg_a', $3, 'edge.fingerprint', 'completed', $4)`,
          [runId, TENANT_A, targetId, completedAt],
        );
        await pool.query(
          `INSERT INTO target_edge_detections (
             id, tenant_id, target_group_id, target_id, test_run_id, waf_status, cdn_status,
             waf_vendor, cdn_provider, conflicting_vendor_signals, observed_at, evidence_json
           ) VALUES (
             $1, $2, 'tg_a', $3, $4, $5, $6, 'waf-vendor', 'cdn-vendor', $7, $8, $9::jsonb
           )`,
          [
            edgeId,
            TENANT_A,
            targetId,
            runId,
            wafStatus,
            cdnStatus,
            conflict,
            observedAt,
            JSON.stringify({ authorization: 'super-secret-evidence' }),
          ],
        );
      }

      const queries = [];
      let presented = 0;
      const result = await withTenantContextAsAppRole(pool, TENANT_A, async (client) => {
        const wrapped = {
          release: client.release.bind(client),
          query(text, values) {
            queries.push(text);
            assert.equal(String(text).includes('super-secret'), false);
            return client.query(text, values);
          },
        };
        return readDeclaredHostAnalytics(wrapped, TENANT_A, { unit: 'hostname', limit: 1 }, {
          asOf: '2026-10-04T00:00:00.000Z',
          presentRow(raw) {
            presented += 1;
            assert.equal(Object.hasOwn(raw, 'evidence_json'), false);
            assert.equal(JSON.stringify(raw).includes('super-secret'), false);
            return presentDeclaredTargetRow(raw);
          },
        });
      });

      const payload = JSON.stringify(result);
      assert.equal(payload.includes('super-secret'), false);
      assert.equal(payload.includes('other.example.com'), false);
      assert.equal(payload.includes('archived.example.com'), false);
      assert.equal(payload.includes('deleted.example.com'), false);
      assert.equal(result.complete, true);
      assert.equal(result.count, 1);
      assert.equal(result.total, 6);
      assert.equal(result.rollup.total, 6);
      assert.equal(result.rollup.segments.all.count, 6);
      assert.equal(result.historical, false);
      assert.equal(queries.length, 1);
      assert.equal(presented, 10);

      const full = await withTenantContextAsAppRole(pool, TENANT_A, (client) => (
        readDeclaredHostAnalytics(client, TENANT_A, { unit: 'hostname', limit: 50 }, {
          asOf: '2026-10-04T00:00:00.000Z',
        })
      ));
      const example = full.items.find((item) => item.analytics.host_key === 'example.com');
      assert.equal(example.analytics.member_count, 2);
      assert.deepEqual(example.analytics.target_ids, ['tgt_host', 'tgt_url']);
      assert.equal(full.items.some((item) => item.analytics.host_key === '203.0.113.10'), false);
      assert.equal(full.items.some((item) => String(item.value).includes('203.0.113.10')), false);
      const tagHost = full.items.find((item) => item.id === 'tgt_tag');
      assert.equal(tagHost.analytics.unclassified, true);
      assert.equal(tagHost.analytics.segment_roles.includes('api'), false);
      const inherited = full.items.find((item) => item.id === 'tgt_inherit');
      assert.equal(inherited.declaration.criticality.status, 'inherited');
      assert.equal(inherited.declaration.criticality.value, 'high');
      assert.equal(inherited.declaration.service_roles_status, 'inherited');
      const conflict = full.items.find((item) => item.id === 'tgt_conflict');
      assert.equal(conflict.analytics.families.waf.bucket, 'conflict');
      assert.equal(conflict.analytics.families.cdn.bucket, 'stale');
      assert.equal(conflict.protection_profile.families.waf.freshness, 'stale');
      assert.equal(conflict.protection_profile.families.waf.conflict, true);
      assert.equal(conflict.protection_profile.families.cdn.freshness, 'stale');
      const api = full.items.find((item) => item.id === 'tgt_api');
      assert.equal(api.findings_count, 1);
      assert.equal(api.last_validation_at, new Date(COMPLETED_AT).toISOString());
      assert.equal(api.analytics.families.waf.bucket, 'stale');
      assert.equal(api.protection_profile.families.waf.status, 'detected');
      const unknownVerification = full.items.find((item) => item.id === 'tgt_host');
      assert.equal(unknownVerification.verification_state, null);
      const unverified = await withTenantContextAsAppRole(pool, TENANT_A, (client) => (
        readDeclaredHostAnalytics(client, TENANT_A, {
          unit: 'hostname',
          verification_state: 'unverified',
          limit: 50,
        })
      ));
      assert.deepEqual(unverified.items.map((item) => item.id), ['tgt_down']);

      const targetsResult = await withTenantContextAsAppRole(pool, TENANT_A, (client) => (
        readDeclaredHostAnalytics(client, TENANT_A, { unit: 'target', limit: 50 })
      ));
      assert.equal(targetsResult.total, 10);
      assert.equal(targetsResult.items.some((item) => item.id === 'tgt_ip'), true);
      assert.equal(targetsResult.items.some((item) => item.id === 'tgt_cidr'), true);

      const bucket = full.rollup.segments.all.waf.list_queries.conflict;
      assert.equal(bucket.list_query_exact, true);
      const roundTrip = await withTenantContextAsAppRole(pool, TENANT_A, (client) => (
        readDeclaredHostAnalytics(client, TENANT_A, { ...bucket.list_query, limit: 50 })
      ));
      assert.equal(roundTrip.total, full.rollup.segments.all.waf.conflict);

      const empty = await withTenantContextAsAppRole(pool, TENANT_A, (client) => (
        readDeclaredHostAnalytics(client, TENANT_A, { unit: 'hostname', criticality: 'low', limit: 50 })
      ));
      assert.equal(empty.total, 0);
      assert.equal(empty.rollup.segments.all.waf.percentages.detected, null);

      await assert.rejects(
        () => withTenantContextAsAppRole(pool, TENANT_A, (client) => (
          readDeclaredHostAnalytics(client, TENANT_A, { unit: 'hostname', cursor: '@@@' })
        )),
        (error) => error instanceof DeclaredHostQueryError && error.code === 'invalid_cursor',
      );

      const bounded = await withTenantContextAsAppRole(pool, TENANT_A, (client) => (
        readDeclaredHostAnalytics(client, TENANT_A, { unit: 'target', limit: 50 }, { rowBound: 1, batchSize: 1 })
      ));
      assert.equal(bounded.complete, false);
      assert.equal(bounded.total, null);
      assert.equal(bounded.rollup, null);
      assert.notEqual(bounded.total, 1);

      const stale = await withTenantContextAsAppRole(pool, TENANT_A, (client) => (
        readDeclaredHostAnalytics(client, TENANT_A, {
          unit: 'hostname',
          family: 'waf',
          family_status: 'stale',
          limit: 50,
        }, {
          presentRow(raw) {
            const projected = presentDeclaredTargetRow(raw);
            const observed = raw.edge_observed_at ? new Date(raw.edge_observed_at).getTime() : null;
            if (observed != null && Date.now() - observed > 8 * 24 * 60 * 60 * 1000 && projected.edge_conflict !== true) {
              projected.protection_profile.families.waf = {
                ...projected.protection_profile.families.waf,
                freshness: 'stale',
              };
              projected.protection_profile.families.cdn = {
                ...projected.protection_profile.families.cdn,
                freshness: 'stale',
              };
            }
            return projected;
          },
        })
      ));
      assert.equal(stale.items.some((item) => item.id === 'tgt_api'), true);
      assert.equal(stale.items.some((item) => item.id === 'tgt_conflict'), false);

      const hidden = await withTenantContextAsAppRole(pool, TENANT_B, (client) => (
        readDeclaredHostAnalytics(client, TENANT_A, { unit: 'target', limit: 50 })
      ));
      assert.equal(hidden.total, 0);
      const other = await withTenantContextAsAppRole(pool, TENANT_B, (client) => (
        readDeclaredHostAnalytics(client, TENANT_B, { unit: 'hostname', limit: 50 })
      ));
      assert.equal(other.total, 1);
      assert.equal(other.items[0].id, 'tgt_b');
      assert.equal(other.items[0].findings_count, 1);

      let inserted = false;
      const snapshot = await readDeclaredHostAnalytics(pool, TENANT_A, { unit: 'target', limit: 50 }, {
        asOf: '2026-10-04T00:00:00.000Z',
        batchSize: 1,
        async presentRow(raw) {
          if (!inserted) {
            inserted = true;
            await pool.query(
              `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
               VALUES ('zzz_late', $1, 'tg_a', 'fqdn', 'late.example.com', 'late.example.com')`,
              [TENANT_A],
            );
          }
          return presentDeclaredTargetRow(raw, { now: '2026-10-04T00:00:00.000Z' });
        },
      });
      assert.equal(inserted, true);
      assert.equal(snapshot.complete, true);
      assert.equal(snapshot.total, 10);
      assert.equal(snapshot.items.some((item) => item.id === 'zzz_late'), false);
      const afterInsert = await readDeclaredHostAnalytics(pool, TENANT_A, { unit: 'target', limit: 50 }, {
        asOf: '2026-10-04T00:00:00.000Z',
      });
      assert.equal(afterInsert.total, 11);
      assert.equal(afterInsert.items.some((item) => item.id === 'zzz_late'), true);

      const secret = 'super-secret-connector';
      await pool.query(
        `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
         VALUES
           ('tgt_dns_ok', $1, 'tg_a', 'fqdn', 'dns-ok.example.com', 'dns-ok.example.com'),
           ('tgt_provider', $1, 'tg_a', 'fqdn', 'proof.example.com', 'proof.example.com')`,
        [TENANT_A],
      );
      await pool.query(
        `INSERT INTO encrypted_secrets (
           id, tenant_id, purpose, name, rotation, envelope_json, created_by
         ) VALUES ('sec_ana', $1, 'waf_provider_credential', 'provider', 1, '{}'::jsonb, 'seed')`,
        [TENANT_A],
      );
      await pool.query(
        `WITH stamp AS (SELECT clock_timestamp() AS ts)
         INSERT INTO waf_connectors (
           id, tenant_id, provider, name, secret_id, config_json, status,
           last_success_at, poll_revision, last_success_revision
         )
         SELECT 'conn_ana', $1, 'cloudflare', 'Cloudflare DNS', 'sec_ana',
                '{"read_only":true}'::jsonb, 'active', stamp.ts, 7, 7
         FROM stamp`,
        [TENANT_A],
      );
      await pool.query(
        `INSERT INTO waf_connector_snapshots (
           id, tenant_id, connector_id, provider, snapshot_kind, resource_ref_hash,
           display_ref, summary_json, observed_at, evidence_source, inventory_complete,
           inventory_truncated, poll_revision
         )
         SELECT 'snap_ana', $1, 'conn_ana', 'cloudflare', 'dns_zone', 'zone_hash_ana',
                'proof.example.com',
                '{"hostnames":["proof.example.com"],"tags":["ownership_eligible:true","resource_status:active"]}'::jsonb,
                c.last_success_at, 'provider_api', TRUE, FALSE, 7
         FROM waf_connectors c
         WHERE c.id = 'conn_ana'`,
        [TENANT_A],
      );
      await pool.query(
        `INSERT INTO tenant_connector_features (tenant_id, enabled, updated_by, revision)
         VALUES ($1, FALSE, 'seed', 1)`,
        [TENANT_A],
      );
      await pool.query(
        `INSERT INTO target_verifications (
           id, tenant_id, target_id, state, source_kind, source_ref, transitioned_by, audit_entry_id
         ) VALUES
           ('tv_dns_ok', $1, 'tgt_dns_ok', 'dns_verified', 'dns_txt', '{}'::jsonb, 'system', 'aud_dns_ok'),
           ('tv_provider', $1, 'tgt_provider', 'provider_verified', 'provider_account', $2::jsonb, 'system', 'aud_provider')`,
        [TENANT_A, JSON.stringify({
          connector_id: 'conn_ana',
          provider: 'cloudflare',
          resource_ref_hash: 'zone_hash_ana',
          token: secret,
        })],
      );

      async function verificationPage(filters = {}) {
        return withTenantContextAsAppRole(pool, TENANT_A, (client) => (
          readDeclaredHostAnalytics(client, TENANT_A, { unit: 'target', limit: 50, ...filters })
        ));
      }
      function stateOf(page, id) {
        return page.items.find((item) => item.id === id)?.verification_state ?? null;
      }

      const disabled = await verificationPage();
      assert.equal(JSON.stringify(disabled).includes(secret), false);
      assert.equal(stateOf(disabled, 'tgt_provider'), 'pending');
      assert.equal(stateOf(disabled, 'tgt_dns_ok'), 'dns_verified');
      const disabledVerified = await verificationPage({ verification_state: 'provider_verified' });
      assert.equal(disabledVerified.total, 0);
      const disabledPending = await verificationPage({ verification_state: 'pending' });
      assert.equal(disabledPending.items.some((item) => item.id === 'tgt_provider'), true);
      assert.equal(JSON.stringify(disabledPending).includes(secret), false);

      await pool.query(
        `UPDATE tenant_connector_features SET enabled = TRUE, revision = 2 WHERE tenant_id = $1`,
        [TENANT_A],
      );
      const current = await verificationPage();
      assert.equal(JSON.stringify(current).includes(secret), false);
      assert.equal(stateOf(current, 'tgt_provider'), 'provider_verified');
      assert.equal(stateOf(current, 'tgt_dns_ok'), 'dns_verified');
      const currentVerified = await verificationPage({ verification_state: 'provider_verified' });
      assert.equal(currentVerified.items.some((item) => item.id === 'tgt_provider'), true);

      await pool.query(`UPDATE waf_connectors SET status = 'revoked' WHERE id = 'conn_ana'`);
      const revoked = await verificationPage();
      assert.equal(JSON.stringify(revoked).includes(secret), false);
      assert.equal(stateOf(revoked, 'tgt_provider'), 'pending');
      assert.equal(stateOf(revoked, 'tgt_dns_ok'), 'dns_verified');
      const revokedVerified = await verificationPage({ verification_state: 'provider_verified' });
      assert.equal(revokedVerified.total, 0);
      assert.equal(revokedVerified.items.some((item) => item.id === 'tgt_provider'), false);
    }, availability.env);
  });
});
