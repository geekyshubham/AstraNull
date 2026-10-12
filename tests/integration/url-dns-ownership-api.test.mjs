// Real loopback HTTP and actual app-role PostgreSQL. All DNS results are injected;
// declaration destinations are never contacted, and no successful DNS proof is seeded.
import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { mintSignedSessionToken } from '../../src/context.mjs';
import * as dnsOwnership from '../../src/services/dnsOwnership.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, closeServer, signedSessionHeaders } from '../helpers/http.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres, databaseUrlWithDatabase } from '../helpers/pg-harness.mjs';
import { createPgPool, closePgPool } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { createPostgresPortalRevampServices } from '../../src/persistence/postgres/portalRevampServiceAdapters.mjs';
import { createReviewedOperationRepository } from '../../src/persistence/postgres/reviewedOperationRepository.mjs';
import { createReviewedOperationService } from '../../src/services/reviewedOperations.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
const SECRET = 'url-dns-local-signed-session-secret';
const TENANT = 'ten_url_dns_api', OTHER = 'ten_url_dns_other', GROUP = 'tg_url_dns_api';
const CTX = { tenantId: TENANT, userId: 'usr_url_dns_api', role: 'owner' };
const headers = (tenant = TENANT, role = 'owner') => signedSessionHeaders(role, tenant, `usr_url_dns_api`, SECRET, mintSignedSessionToken);
async function waitForLookup(promise, message) {
  let timer;
  try {
    await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), 3000);
    })]);
  } finally { clearTimeout(timer); }
}

const baseEnv = { NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'signed-session', ASTRANULL_SESSION_SECRET: SECRET,
  ASTRANULL_PROBE_MODE: 'simulation', ASTRANULL_HIGH_SCALE_ADAPTER_MODE: 'disabled', ASTRANULL_NO_PERSIST: '1',
  ASTRANULL_RATE_LIMIT_DISABLED: '1', ASTRANULL_RUN_PUBLIC_DNS: '0' };

for (const mode of ['dev-json', 'postgres']) test(`${mode}: exact URL challenge -> injected DNS proof -> passive review over HTTP`, { timeout: 120_000 }, async (t) => {
  async function run(pool) {
    freshStore();
    let repository, audit, portalDns;
    let resolver = async () => [];
    let dnsCalls = 0;
    const resolveTxt = (name) => { dnsCalls++; return resolver(name); };
    const sql = (tenant, text, params = []) => withTenantContext(pool, tenant, (client) => client.query(text, params));
    let services;
    if (pool) {
      const role = (await pool.query(`SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`)).rows[0];
      assert.deepEqual(role, { role: 'astranull_app', rolsuper: false, rolbypassrls: false });
      audit = createAuditRepository(pool); repository = createPortalRevampRepository(pool);
      portalDns = createPostgresPortalRevampServices({ repositories: { portalRevamp: repository, audit } }).portalDns;
      services = { targetGroups: { getTarget: async (ctx, id) => (await sql(ctx.tenantId,
        'SELECT * FROM targets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL', [ctx.tenantId, id])).rows[0] ?? null },
      dnsOwnership: { ...portalDns, verifyDnsOwnership: (ctx, body) => portalDns.verifyDnsOwnership(ctx, body, { resolveTxt }) },
      reviewedOperations: createReviewedOperationService({ backend: createReviewedOperationRepository(pool, audit) }) };
    } else {
      getStore().tenants.push({ id: TENANT, name: 'URL DNS API' }, { id: OTHER, name: 'Other URL DNS API' });
      getStore().targetGroups.push({ id: GROUP, tenant_id: TENANT, name: 'URL DNS', validation_mode: 'external_only' });
      getStore().targetVerifications = []; getStore().dnsChallenges = []; getStore().reviewedOperations = [];
      services = { dnsOwnership: { ...dnsOwnership,
        verifyDnsOwnership: (ctx, body) => dnsOwnership.verifyDnsOwnership(ctx, body, { resolveTxt }) } };
    }
    const env = { ...baseEnv, ASTRANULL_PERSISTENCE_MODE: mode };
    const server = createServer({ env, runtimeConfig: loadRuntimeConfig(env), services });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    if (!pool) { getStore().testRuns = []; getStore().probeJobs = []; }
    let sequence = 0;
    async function target(overrides = {}, tenant = TENANT) {
      const id = `tgt_url_api_${++sequence}`;
      const row = { id, tenant_id: tenant, target_group_id: GROUP, kind: 'url',
        value: `https://owned.example.test:8443/diagnostic-${id}`, protocol: 'https', port: 8443,
        expected_behavior: 'intentionally_public', declaration_json: {}, deleted_at: null, ...overrides };
      if (pool) await sql(tenant, `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, protocol, port, expected_behavior, declaration_json)
        VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9::jsonb)`, [id, tenant, GROUP, row.kind, row.value, row.protocol, row.port, row.expected_behavior, JSON.stringify(row.declaration_json)]);
      else getStore().targets.push(row);
      return row;
    }
    const route = (row, operation = '') => `/v1/targets/${row.id}/dns-ownership${operation ? `/${operation}` : ''}`;
    const call = (method, path, body, h = headers()) => request(base, method, path, { headers: h, ...(body === undefined ? {} : { body }) });
    async function issue(row, body = {}) {
      const result = await call('POST', route(row, 'issue'), body);
      assert.equal(result.status, 201, result.text);
      assert.equal(result.json.challenge.target_id, row.id);
      assert.equal(result.json.challenge.record_name, '_astranull-challenge.owned.example.test');
      return result.json.challenge;
    }
    const verify = (row, challenge, body = {}) => call('POST', route(row, 'verify'), { challenge_id: challenge.id, ...body });
    const input = (row) => ({ target_id: row.id, check_id: 'waf.evasion_alt_charset.safe', template: 'marker-query-v1',
      semantics: 'inert_diagnostic', side_effects: 'none', expires_at: new Date(Date.now() + 3600_000).toISOString() });
    async function counts() {
      if (pool) return (await sql(TENANT, `SELECT (SELECT count(*)::int FROM target_verifications) AS proofs,
        (SELECT count(*)::int FROM reviewed_operations) AS reviews, (SELECT count(*)::int FROM audit_logs) AS audits,
        (SELECT count(*)::int FROM test_runs) AS runs, (SELECT count(*)::int FROM probe_jobs) AS jobs`)).rows[0];
      const store = getStore(); return { proofs: store.targetVerifications.filter((r) => r.tenant_id === TENANT).length,
        reviews: store.reviewedOperations.length, audits: store.auditLog.filter((r) => r.tenant_id === TENANT).length,
        runs: store.testRuns.length, jobs: store.probeJobs.length };
    }
    async function patch(row, changes) {
      if (pool) await sql(TENANT, `UPDATE targets SET ${Object.keys(changes).map((key, i) => `${key}=$${i + 3}${key === 'declaration_json' ? '::jsonb' : ''}`).join(', ')}
        WHERE tenant_id=$1 AND id=$2`, [TENANT, row.id, ...Object.entries(changes).map(([key, value]) => key === 'declaration_json' ? JSON.stringify(value) : value)]);
      else Object.assign(getStore().targets.find((r) => r.id === row.id && r.tenant_id === TENANT), changes);
    }
    try {
      await t.test('real challenge reaches direct proof and review; replay/siblings/edited URLs never inherit it', async () => {
        const row = await target(); const sibling = await target({ value: 'https://owned.example.test:8443/sibling' });
        const fqdn = await target({ kind: 'fqdn', value: 'owned.example.test', protocol: null, port: null });
        assert.equal((await call('POST', '/v1/reviewed-operations/preview', input(row))).json.error, 'ownership_not_verified');
        const challenge = await issue(row, { endpoint: 'http://127.0.0.1/override', dns_target_binding: { forged: true } });
        const before = await counts();
        const implicitCalls = dnsCalls;
        const implicit = pool ? await portalDns.verifyDnsOwnership(CTX, { target_group_id: GROUP }, { resolveTxt })
          : await dnsOwnership.verifyDnsOwnership(CTX, { target_group_id: GROUP }, { resolveTxt });
        assert.equal(implicit.error, pool ? 'challenge_not_found' : 'no_dns_challenge');
        assert.equal(dnsCalls, implicitCalls, 'implicit group verification cannot select a URL');
        assert.deepEqual(await counts(), before);
        resolver = async (name) => { assert.equal(name, challenge.record_name); return [['wrong']]; };
        assert.equal((await verify(row, challenge)).json.verified, false);
        resolver = async (name) => { assert.equal(name, challenge.record_name); return [[challenge.record_value]]; };
        const success = await verify(row, challenge, { resolveTxt: 'forged', endpoint: 'http://127.0.0.1/override' });
        assert.equal(success.status, 200, success.text); assert.equal(success.json.verified, true);
        assert.equal(success.json.challenge.expires_at, challenge.expires_at);
        const history = pool ? (await sql(TENANT, 'SELECT * FROM target_verifications WHERE target_id=$1', [row.id])).rows
          : getStore().targetVerifications.filter((r) => r.target_id === row.id && r.tenant_id === TENANT);
        assert.equal(history.length, 1);
        assert.deepEqual(history[0].source_ref.dns_target_binding, dnsOwnershipTargetBinding(row));
        const after = await counts(); assert.equal(after.proofs, before.proofs + 1);
        const calls = dnsCalls; const replay = await verify(row, challenge);
        assert.equal(replay.json.audit_entry_id, success.json.audit_entry_id);
        assert.equal(dnsCalls, calls); assert.deepEqual(await counts(), after);
        for (const other of [sibling, fqdn]) assert.equal((await verify(other, challenge)).json.error, 'target_challenge_not_found');
        assert.equal((await call('POST', '/v1/reviewed-operations/preview', input(sibling))).json.error, 'ownership_not_verified');
        const body = input(row); const preview = await call('POST', '/v1/reviewed-operations/preview', body);
        assert.equal(preview.status, 200, preview.text);
        const approval = await call('POST', '/v1/reviewed-operations', { ...body, reviewed_plan_digest: preview.json.plan_digest });
        assert.equal(approval.status, 201, approval.text);
        assert.equal(approval.json.current_review_gap, null);
        assert.equal(approval.json.grants_execution, false); assert.equal(approval.json.execution_available, false);
        await patch(row, { value: 'https://owned.example.test:8443/new-path' });
        const changed = await call('GET', `/v1/reviewed-operations/${approval.json.id}`);
        assert.equal(changed.json.current_review_gap, 'operation_target_changed');
        const newReview = await call('POST', '/v1/reviewed-operations/preview', input(row));
        assert.equal(newReview.json.error, 'ownership_not_verified');
        assert.equal((await counts()).runs, 0); assert.equal((await counts()).jobs, 0);
      });
      await t.test('signed permissions, foreign scope and caller metadata cannot supply proof', async () => {
        const row = await target(); const before = await counts(); const calls = dnsCalls;
        assert.equal((await call('POST', route(row, 'issue'), {}, {})).status, 401);
        assert.equal((await call('POST', route(row, 'issue'), {}, headers(TENANT, 'viewer'))).status, 403);
        assert.equal((await call('POST', route(row, 'issue'), {}, headers(OTHER))).status, 404);
        assert.equal(dnsCalls, calls);
        const after = await counts();
        assert.deepEqual({ ...after, audits: before.audits }, before);
        if (!pool) assert.equal(after.audits, before.audits + 1, 'permission denial is audited, never DNS proof');
        else assert.equal(after.audits, before.audits);
      });
      for (const value of ['https://u:p@owned.example.test/x', 'https://owned.example.test/x?query=1',
        'https://owned.example.test/x#fragment', 'https://127.0.0.1/x', 'https://[::1]/x',
        'ftp://owned.example.test/x', 'https://localhost/x', 'https://bad_.example.test/x']) {
        await t.test(`rejects declared unsafe URL ${value}`, async () => {
          const row = await target({ value, protocol: null, port: null }); const before = await counts(), calls = dnsCalls;
          const result = await call('POST', route(row, 'issue'), {});
          assert.equal(result.status, 400, result.text); assert.equal(result.json.error, 'invalid_dns_ownership_target');
          assert.equal(dnsCalls, calls); assert.deepEqual(await counts(), before);
        });
      }
      for (const [field, value] of [['value', 'https://owned.example.test:8443/new-path'], ['port', 443], ['protocol', 'http'],
        ['expected_behavior', 'must_deny'], ['declaration_json', { path: 'changed' }]]) {
        for (const during of [false, true]) await t.test(`${field} changes ${during ? 'during' : 'before'} resolver withhold proof/audit`, async () => {
          const row = await target(); const challenge = await issue(row); const before = await counts(), calls = dnsCalls;
          const changedValue = field === 'value' ? `${value}-${row.id}` : value;
          if (!during) await patch(row, { [field]: changedValue });
          resolver = async () => { await patch(row, { [field]: changedValue }); return [[challenge.record_value]]; };
          const result = await verify(row, challenge);
          assert.equal(result.json.error, 'challenge_binding_changed', result.text);
          assert.equal(dnsCalls, calls + (during ? 1 : 0)); assert.deepEqual(await counts(), before);
        });
      }
      await t.test('unrelated presentation changes allow proof and failed-check metadata retains issuance scope', async () => {
        const row = await target(); const challenge = await issue(row);
        resolver = async () => [];
        const failed = await verify(row, challenge); assert.equal(failed.json.verified, false);
        resolver = async () => { await patch(row, { metadata_json: { friendly_label: 'changed' } }); return [[challenge.record_value]]; };
        assert.equal((await verify(row, challenge)).json.verified, true);
      });
      for (const change of ['deleted_target', 'missing_challenge', 'token', 'binding', 'missing_binding', 'issued_at_microsecond', 'expires_at_microsecond']) {
        await t.test(`URL ${change} during DNS cannot finalize stale proof`, async () => {
          const row = await target(); const challenge = await issue(row); const before = await counts();
          resolver = async () => {
            if (change === 'deleted_target') await patch(row, { deleted_at: new Date().toISOString() });
            else if (pool) {
              if (change === 'missing_challenge') await sql(TENANT, 'DELETE FROM dns_challenges WHERE id=$1', [challenge.id]);
              else if (change === 'token') await sql(TENANT, 'UPDATE dns_challenges SET record_value=$2 WHERE id=$1', [challenge.id, 'CHANGED']);
              else if (change.endsWith('_microsecond')) {
                const field = change.replace('_microsecond', '');
                await sql(TENANT, `UPDATE dns_challenges SET ${field}=${field}+interval '0.0001 seconds' WHERE id=$1`, [challenge.id]);
              }
              else await sql(TENANT, 'UPDATE dns_challenges SET last_check_result=$2::jsonb WHERE id=$1',
                [challenge.id, JSON.stringify(change === 'missing_binding' ? {} : { dns_target_binding: { version: 'forged' } })]);
            } else {
              const stored = getStore().dnsChallenges.find((r) => r.id === challenge.id);
              if (change === 'missing_challenge') getStore().dnsChallenges = getStore().dnsChallenges.filter((r) => r.id !== challenge.id);
              else if (change === 'token') stored.record_value = 'CHANGED';
              else if (change.endsWith('_microsecond')) {
                const field = change.replace('_microsecond', '');
                stored[field] = stored[field].replace(/(\.\d{3})Z$/, (_, part) => `${part}100Z`);
              }
              else stored.last_check_result = change === 'missing_binding' ? {} : { dns_target_binding: { version: 'forged' } };
            }
            return [[challenge.record_value]];
          };
          const result = await verify(row, challenge);
          const expected = change === 'deleted_target' ? 'target_not_found' : change === 'missing_challenge' ? 'challenge_not_found' : 'challenge_binding_changed';
          assert.equal(result.json.error, expected, result.text); assert.deepEqual(await counts(), before);
        });
      }
      await t.test('parallel URL completion retains one proof, original expiry and first success audit', async () => {
        const row = await target(); const challenge = await issue(row); const before = await counts();
        const finishes = []; let started = 0, reachedFirst, reached;
        const firstReady = new Promise((resolve) => { reachedFirst = resolve; });
        const ready = new Promise((resolve) => { reached = resolve; });
        resolver = () => new Promise((resolve) => {
          finishes.push(resolve);
          if (++started === 1) reachedFirst();
          if (started === 2) reached();
        });
        const first = verify(row, challenge);
        await waitForLookup(firstReady, 'first URL DNS lookup must start');
        const second = verify(row, challenge);
        await waitForLookup(ready, 'both URL DNS lookups must start without held locks');
        finishes[0]([[challenge.record_value]]); const accepted = await first;
        assert.equal(accepted.json.verified, true, accepted.text); const after = await counts();
        finishes[1]([[challenge.record_value]]); const replay = await second;
        assert.equal(replay.json.verified, true, replay.text);
        assert.equal(replay.json.audit_entry_id, accepted.json.audit_entry_id);
        assert.equal(replay.json.challenge.expires_at, challenge.expires_at);
        assert.equal(after.proofs, before.proofs + 1); assert.deepEqual(await counts(), after);
      });
      for (const change of ['value', 'token', 'binding', 'missing_binding', 'issued_at', 'expires_at', 'malformed_issued_at', 'malformed_expires_at']) {
        await t.test(`parallel resolved replay rejects intervening ${change} without another proof/audit`, async () => {
          const row = await target(); const challenge = await issue(row);
          const finishes = []; let started = 0, reachedFirst, reached;
          const firstReady = new Promise((resolve) => { reachedFirst = resolve; });
          const ready = new Promise((resolve) => { reached = resolve; });
          resolver = () => new Promise((resolve) => {
            finishes.push(resolve);
            if (++started === 1) reachedFirst();
            if (started === 2) reached();
          });
          const first = verify(row, challenge);
          await waitForLookup(firstReady, 'first terminal-race lookup must start');
          let secondCompleted = false;
          const second = verify(row, challenge).then((result) => { secondCompleted = true; return result; });
          await waitForLookup(ready, 'both terminal-race lookups must start');
          finishes[0]([[challenge.record_value]]);
          const accepted = await first;
          assert.equal(accepted.json.verified, true, accepted.text);
          assert.equal(secondCompleted, false, 'second verifier must still await its injected DNS result');
          if (change === 'value') await patch(row, { value: `${row.value}/changed` });
          else if (pool) {
            if (change === 'token') await sql(TENANT, 'UPDATE dns_challenges SET record_value=$2 WHERE id=$1', [challenge.id, 'CHANGED']);
            else if (['issued_at', 'expires_at'].includes(change)) await sql(TENANT,
              `UPDATE dns_challenges SET ${change}=${change}+interval '0.0001 seconds' WHERE id=$1`, [challenge.id]);
            else if (change.startsWith('malformed_')) await sql(TENANT,
              `UPDATE dns_challenges SET ${change.slice('malformed_'.length)}='infinity'::timestamptz WHERE id=$1`, [challenge.id]);
            else await sql(TENANT, 'UPDATE dns_challenges SET last_check_result=$2::jsonb WHERE id=$1',
              [challenge.id, JSON.stringify(change === 'missing_binding' ? {} : { dns_target_binding: { version: 'forged' } })]);
          } else {
            const stored = getStore().dnsChallenges.find((item) => item.id === challenge.id);
            if (change === 'token') stored.record_value = 'CHANGED';
            else if (['issued_at', 'expires_at'].includes(change)) stored[change] = stored[change].replace(/(\.\d{3})Z$/, (_, fraction) => `${fraction}100Z`);
            else if (change.startsWith('malformed_')) stored[change.slice('malformed_'.length)] = 'not-a-date';
            else stored.last_check_result = change === 'missing_binding' ? {} : { dns_target_binding: { version: 'forged' } };
          }
          const afterMutation = await counts();
          finishes[1]([[challenge.record_value]]);
          const stale = await second;
          assert.equal(stale.json.error, 'challenge_binding_changed', stale.text);
          assert.notEqual(stale.json.verified, true);
          assert.deepEqual(await counts(), afterMutation);
        });
      }
      for (const change of ['append', 'source_kind', 'source_ref', 'transitioned_by', 'audit_entry_id']) {
        await t.test(`complete URL ownership generation rejects intervening ${change}`, async () => {
          const row = await target(); const verification = { id: `tv_generation_${row.id}`, tenant_id: TENANT, target_id: row.id,
            state: 'pending', source_kind: 'dns_txt', source_ref: {}, transitioned_at: new Date(Date.now() - 1000).toISOString(), transitioned_by: CTX.userId };
          if (pool) await repository.insertTargetVerification(CTX, verification, audit);
          else getStore().targetVerifications.push(verification);
          const challenge = await issue(row); let afterChange;
          resolver = async () => {
            if (change === 'append') {
              const appended = { ...verification, id: `${verification.id}_later`, transitioned_at: new Date().toISOString() };
              if (pool) await repository.insertTargetVerification(CTX, appended, audit);
              else getStore().targetVerifications.push(appended);
            } else {
              const value = change === 'source_ref' ? { changed: true } : change === 'source_kind' ? 'user_attestation' : 'changed';
              if (pool) await sql(TENANT, `UPDATE target_verifications SET ${change}=$2${change === 'source_ref' ? '::jsonb' : ''} WHERE id=$1`,
                [verification.id, change === 'source_ref' ? JSON.stringify(value) : value]);
              else verification[change] = value;
            }
            afterChange = await counts(); return [[challenge.record_value]];
          };
          const result = await verify(row, challenge);
          assert.equal(result.json.error, 'ownership_state_changed', result.text);
          assert.deepEqual(await counts(), afterChange);
        });
      }
      await t.test('expired URL challenge retains original material metadata and never creates proof', async () => {
        const row = await target(); const challenge = await issue(row); const before = await counts(), calls = dnsCalls;
        if (pool) await sql(TENANT, 'UPDATE dns_challenges SET expires_at=$2::timestamptz WHERE id=$1', [challenge.id, '2000-01-01T00:00:00.000Z']);
        else getStore().dnsChallenges.find((r) => r.id === challenge.id).expires_at = '2000-01-01T00:00:00.000Z';
        const result = await verify(row, challenge);
        assert.equal(result.json.error, 'challenge_expired', result.text);
        const retained = pool ? await repository.findDnsChallenge(CTX, challenge.id) : getStore().dnsChallenges.find((r) => r.id === challenge.id);
        assert.deepEqual(retained.last_check_result.dns_target_binding, dnsOwnershipTargetBinding(row));
        assert.equal((await counts()).proofs, before.proofs); assert.equal(dnsCalls, calls);
      });
      if (pool) {
        await t.test('audit insertion failure rolls back proof/challenge and preserves issuance binding', async () => {
          const row = await target(); const challenge = await issue(row); const before = await counts();
          const failing = createPostgresPortalRevampServices({ repositories: { portalRevamp: repository,
            audit: { appendAuditEvent: async (entry, options) => {
              if (entry.action === 'target_verification.transitioned') throw new Error('injected audit failure');
              return audit.appendAuditEvent(entry, options);
            } } } }).portalDns;
          await assert.rejects(failing.verifyDnsOwnership(CTX, { target_group_id: GROUP, challenge_id: challenge.id },
            { resolveTxt: async () => [[challenge.record_value]] }), /injected audit failure/);
          const retained = await repository.findDnsChallenge(CTX, challenge.id);
          assert.equal(retained.state, 'pending'); assert.deepEqual(retained.last_check_result.dns_target_binding, dnsOwnershipTargetBinding(row));
          assert.deepEqual(await counts(), before);
        });
        await t.test('RLS denies bare foreign exact challenges and their proofs', async () => {
          assert.equal((await sql(OTHER, 'SELECT * FROM dns_challenges')).rows.length, 0);
          assert.equal((await sql(OTHER, 'SELECT * FROM target_verifications')).rows.length, 0);
        });
      }
      const final = await counts(); assert.equal(final.runs, 0); assert.equal(final.jobs, 0);
      t.diagnostic(`app=${mode}; injected DNS calls=${dnsCalls}; proofs=${final.proofs}; passive reviews=${final.reviews}; runs=${final.runs}; jobs=${final.jobs}`);
    } finally { await closeServer(server); }
  }
  if (mode === 'dev-json') return run(null);
  const available = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
  if (!available.available) return t.skip(available.reason);
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    await owner.query(`INSERT INTO tenants (id,name) VALUES ($1,'URL DNS API'),($2,'Other URL DNS API')`, [TENANT, OTHER]);
    await owner.query(`INSERT INTO target_groups (id,tenant_id,name,validation_mode) VALUES ($1,$2,'URL DNS API','external_only')`, [GROUP, TENANT]);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    url.searchParams.set('options', '-c timezone=UTC -c statement_timeout=15000');
    const app = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    try { await run(app); } finally { await closePgPool(app); }
  }, available.env);
});
