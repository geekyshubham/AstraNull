import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';
import { validateDbSchema } from '../../scripts/validate-db-schema.mjs';

const NAME = '0077_ownership_transition_order.sql';
const schemaSql = readFileSync(new URL('../../db/schema.sql', import.meta.url), 'utf8');
const migrationSqls = readdirSync(new URL('../../db/migrations/', import.meta.url))
  .filter((name) => name.endsWith('.sql')).sort()
  .map((name) => ({ name, sql: readFileSync(new URL(`../../db/migrations/${name}`, import.meta.url), 'utf8') }));
const orderSql = migrationSqls.find(({ name }) => name === NAME).sql;

test('ownership chronology migration exactly matches its additive schema block', () => {
  assert.ok(schemaSql.includes(orderSql));
  const result = validateDbSchema({ schemaSql, migrationSqls });
  assert.equal(result.ok, true, result.errors.join('; '));
});

test('ownership chronology migration is a required additive upgrade', () => {
  const result = validateDbSchema({ schemaSql, migrationSqls: migrationSqls.filter(({ name }) => name !== NAME) });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes(`missing required file ${NAME}`)));
});

for (const [label, before, after] of [
  ['append clock trigger', 'BEFORE INSERT ON target_verifications', 'AFTER INSERT ON target_verifications'],
  ['audit-first serialization', 'pg_advisory_xact_lock(hashtext(NEW.tenant_id))', 'pg_advisory_xact_lock(hashtext(NEW.target_id))'],
  ['millisecond advancement', "date_trunc('milliseconds', previous_at) + interval '1 millisecond'", "previous_at + interval '1 microsecond'"],
  ['representable finite history', 'OR abs(extract(epoch FROM transitioned_at) * 1000) > 8640000000000000', 'OR false'],
  ['successor overflow rejection', 'Ownership transition clock cannot advance', 'Clock accepted'],
  ['authority-equivalent ties', 'count(DISTINCT jsonb_build_array(state, source_kind, source_ref)) > 1', 'count(DISTINCT state) > 1'],
  ['ambiguous history denies proof', "WHEN latest.ambiguous OR NOT isfinite(latest.transitioned_at) THEN 'pending'", "WHEN latest.ambiguous THEN 'dns_verified'"],
  ['tenant-invoker current projection', 'WITH (security_invoker = true) AS\n  WITH ranked', 'WITH (security_invoker = false) AS\n  WITH ranked'],
]) {
  for (const scope of ['schema', 'migration:0077']) {
    test(`schema validator denies removal of ${scope} ${label}`, () => {
      assert.ok(orderSql.includes(before));
      const changed = orderSql.replaceAll(before, after);
      const result = validateDbSchema({
        schemaSql: scope === 'schema' ? schemaSql.replace(orderSql, changed) : schemaSql,
        migrationSqls: scope === 'schema' ? migrationSqls
          : migrationSqls.map((migration) => migration.name === NAME ? { ...migration, sql: changed } : migration),
      });
      assert.equal(result.ok, false);
      assert.ok(result.errors.some((error) => error.includes(`${scope}:ownership_order:${label}`)), result.errors.join('; '));
    });
  }
}
