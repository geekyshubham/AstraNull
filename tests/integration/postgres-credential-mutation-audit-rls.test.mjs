import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { test } from 'node:test';
import pg from 'pg';
import { grantPostgresAppRolePrivileges } from '../../scripts/postgres-grant-app-role.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createAuthTokenRepository } from '../../src/persistence/postgres/authTokenRepository.mjs';
import { createPostgresAuthServices } from '../../src/persistence/postgres/authServiceAdapters.mjs';
import { createSecretVaultRepository } from '../../src/persistence/postgres/secretVaultRepository.mjs';
import { createPostgresSecretVaultServices } from '../../src/persistence/postgres/secretVaultServiceAdapters.mjs';
import { fetchAppliedMigrationVersions, listMigrationFiles, runMigrations } from '../../src/persistence/postgres/migrations.mjs';
import { closePgPool, createPgPool, pingPostgres } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import {
  buildEphemeralDatabaseName, createEphemeralDatabase, databaseUrlWithDatabase,
  dropEphemeralDatabase, MIGRATIONS_DIR,
} from '../helpers/pg-harness.mjs';

const caller = { tenantId: 'ten_credential_caller', userId: 'usr_credential_caller', role: 'admin' };
const foreign = { tenantId: 'ten_credential_owner', userId: 'usr_credential_owner', role: 'admin' };
const protectedTables = ['service_accounts', 'encrypted_secrets', 'waf_connectors', 'connector_poll_jobs', 'probe_jobs'];
const digest = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');

// Explicit local configuration only: never discover another database, start Docker,
// or mutate the shared app role. Normalize localhost to a literal loopback address.
function validateOwnedUrl(value) {
  const url = new URL(value);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol), 'PostgreSQL URL required');
  if (url.hostname === 'localhost') url.hostname = '127.0.0.1';
  const host = url.hostname.replace(/^\[|\]$/g, '');
  assert.ok((isIP(host) === 4 && host.startsWith('127.')) || (isIP(host) === 6 && host === '::1'), 'PostgreSQL URL must explicitly select a valid loopback literal');
  for (const key of url.searchParams.keys()) {
    // pg-connection-string/libpq keys are case sensitive. Conservatively reject
    // case variants too; URLSearchParams already decodes percent-encoded keys.
    assert.ok(!['host', 'hostaddr', 'port', 'database', 'dbname', 'user', 'username', 'connectionstring', 'service', 'servicefile'].includes(key.toLowerCase()), 'URL query must not override the selected database endpoint');
  }
  return url.toString();
}

test('selected PostgreSQL URL guard rejects malformed loopback and decoded routing overrides without connecting', () => {
  for (const host of ['127.999.0.1', '127.0.0.999', '127.0.0.1.evil.invalid', '127.0.0', '127.1', '127.0.0.1.', '127.0.0.01', '127.0.0.0x1', '%31%32%37.0.0.1', 'remote.invalid', '[::ffff:127.0.0.1]']) {
    assert.throws(() => validateOwnedUrl(`postgresql://fixture_owner@${host}:15432/fixture_db`));
  }
  for (const query of [
    'host=remote.invalid', '%68ost=remote.invalid', 'h%6fst=remote.invalid', 'HOST=remote.invalid',
    'hostaddr=192.0.2.1', 'HostAddr=192.0.2.1', 'port=5432', 'PORT=5432',
    'database=other', 'dbname=other', 'user=other', 'username=other',
    'connectionString=postgresql%3A%2F%2Fremote.invalid%2Fother', 'ConnectionString=ignored',
    'service=production', 'servicefile=%2Ftmp%2Fpg_service.conf',
    'application_name=fixture&host=127.0.0.1&host=remote.invalid',
  ]) {
    assert.throws(() => validateOwnedUrl(`postgresql://fixture_owner@127.0.0.1:15432/fixture_db?${query}`));
  }
  for (const [host, expectedHost] of [['127.0.0.1', '127.0.0.1'], ['127.255.255.255', '127.255.255.255'], ['localhost', '127.0.0.1'], ['[::1]', '::1']]) {
    const selected = validateOwnedUrl(`postgresql://different_owner@${host}:15432/different_db?application_name=credential_guard&sslmode=disable`);
    // Exercise the actual installed pg parser, but never call connect().
    const parsed = new pg.Client({ connectionString: selected }).connectionParameters;
    assert.equal(parsed.host.replace(/^\[|\]$/g, ''), expectedHost);
    assert.equal(parsed.port, 15432);
    assert.equal(parsed.user, 'different_owner');
    assert.equal(parsed.database, 'different_db');
  }
});

async function selectedPostgresAvailability() {
  const explicit = process.env.ASTRANULL_ADMIN_DATABASE_URL?.trim() || process.env.ASTRANULL_DATABASE_URL?.trim();
  if (!explicit) return { available: false, reason: 'PostgreSQL unconfigured: explicitly select an owned loopback database URL.' };
  const databaseUrl = validateOwnedUrl(explicit);
  // Same ping/cleanup as resolvePostgresHarnessAvailability with tryDocker:false,
  // but probe ONLY this selected URL: that helper also probes unrelated local
  // defaults when unavailable and cannot currently disable those fallbacks.
  const pool = createPgPool({ ASTRANULL_DATABASE_URL: databaseUrl });
  try {
    await pingPostgres(pool);
    return { available: true, databaseUrl };
  } catch {
    return { available: false, reason: 'Explicitly selected loopback PostgreSQL is unavailable (no fallback attempted).' };
  } finally {
    await closePgPool(pool);
  }
}

async function tenantSnapshot(pool, ctx, includeAudit = false) {
  return withTenantContext(pool, ctx.tenantId, async (client) => {
    const result = {};
    for (const table of [...protectedTables, ...(includeAudit ? ['audit_logs'] : [])]) {
      const { rows } = await client.query(`SELECT to_jsonb(record) AS record FROM ${table} record WHERE tenant_id = $1 ORDER BY id`, [ctx.tenantId]);
      // Hash whole rows, including credential material, without printing secrets on failure.
      result[table] = { count: rows.length, digest: digest(rows) };
    }
    return result;
  });
}

function sensitiveStrings(value) {
  if (typeof value === 'string') return value.length >= 8 ? [value] : [];
  if (Array.isArray(value)) return value.flatMap(sensitiveStrings);
  if (value && typeof value === 'object') return Object.values(value).flatMap(sensitiveStrings);
  return [];
}

function assertNoCredentialLeak(value, sensitive) {
  const serialized = JSON.stringify(value);
  for (const [index, secret] of sensitive.entries()) {
    assert.equal(serialized.includes(secret), false, `credential material ${index} must not appear in denial/audit`);
  }
  assert.doesNotMatch(serialized, /"(?:plaintext|secret_hash|secret_salt|envelope(?:_json)?|ciphertext|auth_tag)"\s*:/);
}

test('real PostgreSQL/RLS persists one safe caller audit for absent and foreign credential mutations', { timeout: 120_000 }, async (t) => {
  const availability = await selectedPostgresAvailability();
  if (!availability.available) { t.skip(availability.reason); return; }
  const databaseUrl = availability.databaseUrl;
  const databaseName = buildEphemeralDatabaseName('credential_audit_rls');
  const adminPool = createPgPool({ ASTRANULL_DATABASE_URL: databaseUrl });
  let created = false;
  let ownerPool;
  let appPool;
  let readerPool;
  try {
    await createEphemeralDatabase(adminPool, databaseName);
    created = true;
    const ephemeralUrl = databaseUrlWithDatabase(databaseUrl, databaseName);
    ownerPool = createPgPool({ ASTRANULL_DATABASE_URL: ephemeralUrl });
    const files = listMigrationFiles(MIGRATIONS_DIR).filter(({ name }) => /^\d{4}_/.test(name) && Number(name.slice(0, 4)) <= 78);
    assert.ok(files.length > 0);
    assert.equal(files.at(-1).version, '0078_reviewed_execution_grant_issuances');
    await runMigrations(ownerPool, { migrationsDir: MIGRATIONS_DIR, files });
    const applied = [...await fetchAppliedMigrationVersions(ownerPool)].sort();
    assert.deepEqual(applied, files.map(({ version }) => version));
    assert.equal(applied.some((version) => Number(version.slice(0, 4)) > 78), false);
    t.diagnostic(`ephemeral migrations=${applied.length}; head=${applied.at(-1)}; held0079=not_applied`);

    const role = await ownerPool.query("SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'astranull_app'");
    assert.deepEqual(role.rows, [{ rolname: 'astranull_app', rolsuper: false, rolbypassrls: false, rolcanlogin: true }], 'existing app role must be safe; this test does not create/alter shared roles');
    await grantPostgresAppRolePrivileges(ownerPool);
    const appUrl = new URL(ephemeralUrl);
    appUrl.username = 'astranull_app';
    appUrl.password = process.env.ASTRANULL_DATABASE_APP_PASSWORD ?? 'astranull_app_local_dev';
    appPool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl.toString() });
    readerPool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl.toString() });
    const identity = await appPool.query('SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user');
    assert.deepEqual(identity.rows, [{ role: 'astranull_app', rolsuper: false, rolbypassrls: false }]);
    const rls = await appPool.query(`SELECT relname, relrowsecurity, relforcerowsecurity,
      pg_get_userbyid(relowner) = current_user AS owns_table FROM pg_class
      WHERE oid = ANY($1::regclass[]) ORDER BY relname`, [['service_accounts', 'encrypted_secrets', 'audit_logs']]);
    assert.equal(rls.rows.length, 3);
    for (const row of rls.rows) {
      assert.equal(row.relrowsecurity, true);
      assert.equal(row.relforcerowsecurity, true);
      assert.equal(row.owns_table, false);
    }
    t.diagnostic('production adapter connection: role=astranull_app; superuser=false; bypassrls=false; credential/audit tables FORCE RLS; app role is not table owner');
    await ownerPool.query('INSERT INTO tenants (id, name) VALUES ($1, $2), ($3, $4)', [caller.tenantId, 'Caller', foreign.tenantId, 'Credential owner']);

    const repositories = {
      authTokens: createAuthTokenRepository(appPool),
      secretVault: createSecretVaultRepository(appPool),
      audit: createAuditRepository(appPool),
    };
    const readAudit = createAuditRepository(readerPool);
    const { serviceAccounts } = createPostgresAuthServices(repositories);
    const vault = createPostgresSecretVaultServices(repositories, { connectorEncryptionKey: Buffer.alloc(32, 0x3a) });
    const plaintext = 'synthetic-foreign-credential-never-log';
    const deniedPlaintext = 'synthetic-denied-rotation-never-log';
    const createdAccount = await serviceAccounts.createServiceAccount(foreign, { name: 'Foreign credential', role: 'viewer', scopes: ['report:read'] });
    assert.ok(createdAccount.account?.id);
    assert.ok(createdAccount.secret);
    await repositories.authTokens.recordServiceAccountLastUsed({ tenantId: foreign.tenantId, id: createdAccount.account.id }, '2026-01-01T00:00:00.000Z');
    const storedSecret = await vault.storeEncryptedSecret(foreign, { purpose: 'connector', name: 'Foreign vault record', plaintext, metadata: { fixture: 'owner-only' } });
    assert.ok(storedSecret.secret?.id);
    const accountId = createdAccount.account.id;
    const secretId = storedSecret.secret.id;
    const foreignAccount = await repositories.authTokens.getServiceAccountById(foreign, accountId);
    const foreignSecret = await repositories.secretVault.getEncryptedSecretById(foreign, secretId);
    assert.ok(foreignAccount.secret_hash && foreignAccount.secret_salt);
    assert.ok(foreignAccount.last_used_at);
    assert.ok(foreignSecret.envelope);
    const sensitive = [plaintext, deniedPlaintext, createdAccount.secret, foreignAccount.secret_hash, foreignAccount.secret_salt, ...sensitiveStrings(foreignSecret.envelope)];

    // Inert database-only connector/pending-job fixtures make rotation side effects observable.
    // No scheduler, worker, API server, or provider is started.
    await withTenantContext(ownerPool, foreign.tenantId, async (client) => {
      await client.query(`INSERT INTO waf_connectors (id, tenant_id, provider, name, secret_id, status, last_success_at, poll_revision, last_success_revision)
        VALUES ('conn_credential_owner', $1, 'cloudflare', 'Inert audit fixture', $2, 'active', now(), 1, 1)`, [foreign.tenantId, secretId]);
      const envelope = { job_id: 'cpjob_credential_owner', tenant_id: foreign.tenantId, connector_id: 'conn_credential_owner', provider: 'cloudflare', poll_revision: 1, operation: 'read_only_provider_inventory' };
      await client.query(`INSERT INTO connector_poll_jobs (id, tenant_id, connector_id, provider, poll_revision, status, envelope_json, job_signature, expires_at)
        VALUES ('cpjob_credential_owner', $1, 'conn_credential_owner', 'cloudflare', 1, 'pending', $2::jsonb, 'inert-not-executable-signature', now() + interval '1 hour')`, [foreign.tenantId, JSON.stringify(envelope)]);
    });

    // Direct SQL omits a tenant predicate: invisibility must come from actual RLS,
    // not just the repositories' WHERE tenant_id clauses.
    await withTenantContext(appPool, caller.tenantId, async (client) => {
      assert.equal((await client.query('SELECT id FROM service_accounts WHERE id = $1', [accountId])).rowCount, 0);
      assert.equal((await client.query('SELECT id FROM encrypted_secrets WHERE id = $1', [secretId])).rowCount, 0);
      assert.equal((await client.query('SELECT id FROM audit_logs')).rowCount, 0);
      assert.equal((await client.query('UPDATE service_accounts SET revoked_at = now() WHERE id = $1 RETURNING id', [accountId])).rowCount, 0);
    });
    const foreignBefore = await tenantSnapshot(ownerPool, foreign, true);
    assert.equal(foreignBefore.service_accounts.count, 1);
    assert.equal(foreignBefore.encrypted_secrets.count, 1);
    assert.equal(foreignBefore.waf_connectors.count, 1);
    assert.equal(foreignBefore.connector_poll_jobs.count, 1);
    assert.equal(foreignBefore.audit_logs.count, 2);

    const operations = [
      { name: 'service-account.rotate', type: 'service_account', action: 'service_account.mutation_not_found', foreignId: accountId, absentId: 'sacc_absent_credential_audit', invoke: (id) => serviceAccounts.rotateServiceAccount(caller, id) },
      { name: 'service-account.revoke', type: 'service_account', action: 'service_account.mutation_not_found', foreignId: accountId, absentId: 'sacc_absent_credential_audit', invoke: (id) => serviceAccounts.revokeServiceAccount(caller, id) },
      { name: 'vault.rotate', type: 'encrypted_secret', action: 'secret.rotate_not_found', foreignId: secretId, absentId: 'secret_absent_credential_audit', invoke: (id) => vault.rotateEncryptedSecret(caller, id, { plaintext: deniedPlaintext, metadata: { fixture: 'must-not-replace' } }) },
    ];
    for (const operation of operations) {
      const denials = [];
      for (const [membership, id] of [['absent', operation.absentId], ['foreign', operation.foreignId]]) {
        await t.test(`${operation.name}: ${membership} is generic null with exactly one committed caller-tenant safe audit`, async () => {
          const callerBefore = await tenantSnapshot(ownerPool, caller);
          const beforeAudit = await readAudit.listAuditEntries(caller);
          const result = await operation.invoke(id);
          assert.equal(result, null);
          denials.push(result);
          const afterAudit = await readAudit.listAuditEntries(caller);
          assert.equal(afterAudit.length, beforeAudit.length + 1, 'independent app-role connection must see exactly one committed audit');
          assert.deepEqual(afterAudit.slice(0, -1), beforeAudit);
          const entry = afterAudit.at(-1);
          assert.equal(entry.tenant_id, caller.tenantId);
          assert.equal(entry.actor_user_id, caller.userId);
          assert.equal(entry.actor_role, caller.role);
          assert.equal(entry.action, operation.action);
          assert.equal(entry.resource_type, operation.type);
          assert.equal(entry.resource_id, id);
          assert.deepEqual(entry.metadata, {});
          assert.equal(entry.sequence, beforeAudit.length + 1);
          assert.equal(entry.prev_hash, beforeAudit.at(-1)?.entry_hash ?? null);
          assert.match(entry.entry_hash, /^[a-f0-9]{64}$/);
          assert.ok(Number.isFinite(Date.parse(entry.timestamp)));
          assertNoCredentialLeak({ result, entry }, sensitive);
          assert.deepEqual(await readAudit.getAuditEntry(caller, entry.id), entry);
          assert.equal(await readAudit.getAuditEntry(foreign, entry.id), null);
          assert.deepEqual(await tenantSnapshot(ownerPool, caller), callerBefore, 'denied mutation cannot create/update caller credentials or work');
          assert.deepEqual(await tenantSnapshot(ownerPool, foreign, true), foreignBefore, 'all owning-tenant credential/audit/connector/job rows must remain unchanged');
        });
      }
      assert.deepEqual(denials, [null, null], 'foreign and absent adapter failures must be indistinguishable');
    }
    assert.equal((await readAudit.listAuditEntries(caller)).length, 6);
    assert.deepEqual(await tenantSnapshot(ownerPool, foreign, true), foreignBefore);
  } finally {
    try {
      await Promise.all([readerPool, appPool, ownerPool].filter(Boolean).map(closePgPool));
    } finally {
      try {
        if (created) {
          await dropEphemeralDatabase(adminPool, databaseName);
          assert.equal((await adminPool.query('SELECT 1 FROM pg_database WHERE datname = $1', [databaseName])).rowCount, 0, 'unique ephemeral database must be removed');
        }
      } finally {
        await closePgPool(adminPool);
      }
    }
  }
});
