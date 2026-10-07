import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { stripSqlComments, validateDbSchema } from '../../scripts/validate-db-schema.mjs';
import {
  COMPATIBILITY_REASONS,
  ENTRY_PATH_EXPECTED_BEHAVIORS,
  ENTRY_PATH_RELATION_KINDS,
  FIREWALL_EXPECTED_BEHAVIORS,
  FIREWALL_PROTOCOLS,
  MAX_COMPARISON_ITEMS,
  MAX_EVIDENCE_IDS_PER_REFERENCE,
  MAX_EVIDENCE_REFERENCES,
  MAX_FRESHNESS_WINDOW_SECONDS,
  MIN_FRESHNESS_WINDOW_SECONDS,
  PATH_LAYER_EXPECTED_OUTCOMES,
  PROTECTION_LAYERS,
  PROTECTION_VALIDATION_LIMITATIONS,
  REQUIRED_LIMITATIONS,
} from '../../src/contracts/protectionValidation.mjs';

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), '../..');
const MIGRATIONS_DIR = path.join(ROOT, 'db', 'migrations');
const MIGRATION_NAME = '0068_protection_validation.sql';
const SCHEMA_MARKER = '-- Additive sync of db/migrations/0068_protection_validation.sql.';

const migrationSql = stripSqlComments(readFileSync(path.join(MIGRATIONS_DIR, MIGRATION_NAME), 'utf8'));
const schemaText = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
const schemaBlockStart = schemaText.indexOf(SCHEMA_MARKER);
const nextSyncMarker = schemaText.indexOf('-- Additive sync of db/migrations/', schemaBlockStart + SCHEMA_MARKER.length);
const schemaBlock = stripSqlComments(schemaText.slice(schemaBlockStart, nextSyncMarker < 0 ? undefined : nextSyncMarker));

const TABLES = Object.freeze([
  'application_entry_paths',
  'protection_expectations',
  'protection_comparison_baselines',
  'protection_comparison_evaluations',
  'protection_comparison_evidence_refs',
]);

const TENANT_FKS = Object.freeze({
  fk_application_entry_paths_anchor_target_tenant: ['anchor_target_id', 'targets'],
  fk_application_entry_paths_entry_target_tenant: ['entry_target_id', 'targets'],
  fk_application_entry_paths_origin_binding_tenant: ['origin_binding_id', 'origin_bindings'],
  fk_protection_expectations_anchor_target_tenant: ['anchor_target_id', 'targets'],
  fk_protection_expectations_destination_target_tenant: ['destination_target_id', 'targets'],
  fk_protection_expectations_pre_destination_tenant: ['pre_destination_target_id', 'targets'],
  fk_protection_expectations_post_destination_tenant: ['post_destination_target_id', 'targets'],
  fk_protection_comparison_baselines_target_tenant: ['target_id', 'targets'],
  fk_protection_comparison_baselines_anchor_target_tenant: ['anchor_target_id', 'targets'],
  fk_protection_comparison_baselines_entry_path_tenant: ['entry_path_id', 'application_entry_paths'],
  fk_protection_comparison_baselines_expectation_tenant: ['expectation_id', 'protection_expectations'],
  fk_protection_comparison_baselines_pre_destination_tenant: ['pre_destination_target_id', 'targets'],
  fk_protection_comparison_baselines_post_destination_tenant: ['post_destination_target_id', 'targets'],
  fk_protection_comparison_evaluations_baseline_tenant: ['baseline_id', 'protection_comparison_baselines'],
  fk_protection_comparison_evaluations_anchor_target_tenant: ['anchor_target_id', 'targets'],
  fk_protection_comparison_evaluations_primary_entry_path_tenant: ['primary_entry_path_id', 'application_entry_paths'],
  fk_protection_comparison_evidence_refs_baseline_tenant: ['baseline_id', 'protection_comparison_baselines'],
  fk_protection_comparison_evidence_refs_evaluation_tenant: ['evaluation_id', 'protection_comparison_evaluations'],
  fk_protection_comparison_evidence_refs_expectation_tenant: ['expectation_id', 'protection_expectations'],
  fk_protection_comparison_evidence_refs_entry_path_tenant: ['entry_path_id', 'application_entry_paths'],
  fk_protection_comparison_evidence_refs_run_tenant: ['test_run_id', 'test_runs'],
  fk_protection_comparison_evidence_refs_verdict_tenant: ['verdict_id', 'verdicts'],
  fk_protection_comparison_evidence_refs_target_tenant: ['target_id', 'targets'],
  fk_protection_comparison_evidence_refs_origin_binding_tenant: ['origin_binding_id', 'origin_bindings'],
});

function escapeRe(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function tableBody(sql, table) {
  const match = new RegExp(`CREATE TABLE(?: IF NOT EXISTS)? ${table} \\(([\\s\\S]*?)\\n\\);`).exec(sql);
  assert.ok(match, `missing CREATE TABLE ${table}`);
  return match[1];
}

function constraintBody(sql, table, name) {
  const body = tableBody(sql, table);
  const match = new RegExp(`CONSTRAINT ${name}\\b([\\s\\S]*?)(?=,\\n  CONSTRAINT |$)`).exec(body);
  assert.ok(match, `missing constraint ${name} on ${table}`);
  return match[1];
}

function quotedList(values) {
  return values.map((value) => `'${value}'`);
}

function assertListsExactly(text, values, label) {
  const found = [...text.matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(found)].sort(), [...values].sort(), label);
}

describe('PV-03 protection validation schema (0068)', () => {
  it('is the next sequential additive migration and keeps the repo schema contract valid', () => {
    const names = readdirSync(MIGRATIONS_DIR).filter((name) => name.endsWith('.sql')).sort();
    assert.ok(names.includes(MIGRATION_NAME));
    assert.ok(names.includes('0067_demo_tenant_auto_verify_backfill.sql'));
    assert.equal(names.filter((name) => name.startsWith('0068_')).length, 1);
    assert.doesNotMatch(migrationSql, /\bDROP TABLE\b|\bDROP COLUMN\b|\bTRUNCATE\b|\bDELETE FROM\b|\bUPDATE\s+\w+\s+SET\b/i);
    assert.doesNotMatch(migrationSql, /\bGRANT\b|\bSECURITY DEFINER\b|\bBYPASSRLS\b/i);
    const result = validateDbSchema({
      schemaSql: schemaText,
      migrationSqls: names.map((name) => ({ name, sql: readFileSync(path.join(MIGRATIONS_DIR, name), 'utf8') })),
    });
    assert.equal(result.ok, true, result.errors.join('; '));
  });

  for (const [label, sql] of [['migration', migrationSql], ['schema.sql', schemaBlock]]) {
    it(`${label}: every table is tenant-owned with ENABLE + FORCE RLS and an app.tenant_id policy`, () => {
      for (const table of TABLES) {
        const body = tableBody(sql, table);
        assert.match(body, /^\s*id TEXT PRIMARY KEY,/m, `${table} id`);
        assert.match(body, /tenant_id TEXT NOT NULL REFERENCES tenants\(id\)/, `${table} tenant_id`);
        assert.match(sql, new RegExp(`ADD CONSTRAINT ${table}_tenant_id_id_key UNIQUE \\(tenant_id, id\\)`), `${table} parent key`);
        assert.match(sql, new RegExp(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`), `${table} enable`);
        assert.match(sql, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`), `${table} force`);
        assert.match(
          sql,
          new RegExp(
            `CREATE POLICY tenant_isolation_${table} ON ${table}\\s+USING \\(tenant_id = current_setting\\('app\\.tenant_id', true\\)\\)\\s+WITH CHECK \\(tenant_id = current_setting\\('app\\.tenant_id', true\\)\\)`,
          ),
          `${table} policy`,
        );
      }
    });

    it(`${label}: every reference is a same-tenant composite foreign key`, () => {
      for (const [name, [column, parent]] of Object.entries(TENANT_FKS)) {
        assert.match(
          sql,
          new RegExp(`ADD CONSTRAINT ${name}\\s+FOREIGN KEY \\(tenant_id, ${column}\\) REFERENCES ${parent} \\(tenant_id, id\\)`),
          name,
        );
      }
      assert.doesNotMatch(sql, /REFERENCES (targets|test_runs|verdicts|origin_bindings|application_entry_paths|protection_\w+)\s*\(id\)/);
    });

    it(`${label}: idempotency keys are unique per tenant`, () => {
      for (const table of TABLES.filter((t) => t !== 'protection_comparison_evidence_refs')) {
        assert.match(tableBody(sql, table), /idempotency_key TEXT,/);
        assert.match(
          sql,
          new RegExp(`CREATE UNIQUE INDEX uniq_${table}_idempotency\\s+ON ${table} \\(tenant_id, idempotency_key\\) WHERE idempotency_key IS NOT NULL`.replace('CREATE UNIQUE INDEX', 'CREATE UNIQUE INDEX(?: IF NOT EXISTS)?')),
          `${table} idempotency`,
        );
      }
    });

    it(`${label}: declarations are versioned with one active scope and sha256 digests`, () => {
      assert.match(sql, /uniq_application_entry_paths_active_scope\s+ON application_entry_paths \(\s*tenant_id, anchor_target_id, entry_target_id, relation_kind, COALESCE\(origin_binding_id, ''\)\s*\)\s+WHERE status = 'active'/);
      assert.match(sql, /uniq_application_entry_paths_scope_version[\s\S]*?declaration_version\s*\);/);
      assert.match(sql, /uniq_protection_expectations_scope_version\s+ON protection_expectations \(tenant_id, kind, scope_key, expectation_version\)/);
      assert.match(sql, /uniq_protection_expectations_active_scope\s+ON protection_expectations \(tenant_id, kind, scope_key\) WHERE status = 'active'/);
      assert.match(constraintBody(sql, 'application_entry_paths', 'application_entry_paths_digest_check'), /declaration_digest ~ '\^\[a-f0-9\]\{64\}\$'/);
      assert.match(constraintBody(sql, 'protection_expectations', 'protection_expectations_digest_check'), /expectation_digest ~ '\^\[a-f0-9\]\{64\}\$'/);
      assert.match(constraintBody(sql, 'protection_comparison_baselines', 'protection_comparison_baselines_digest_check'), /baseline_digest ~ /);
      assert.match(constraintBody(sql, 'protection_comparison_evaluations', 'protection_comparison_evaluations_digest_check'), /evaluation_digest ~ /);
      for (const table of ['protection_comparison_baselines', 'protection_comparison_evaluations']) {
        assert.match(sql, new RegExp(`uniq_${table}_digest\\s+ON ${table} \\(tenant_id, \\w+_digest\\)`));
      }
    });

    it(`${label}: origin relations reuse an origin binding and never duplicate its scope`, () => {
      assert.match(
        constraintBody(sql, 'application_entry_paths', 'application_entry_paths_origin_binding_check'),
        /\(relation_kind = 'origin'\) = \(origin_binding_id IS NOT NULL\)/,
      );
      const body = tableBody(sql, 'application_entry_paths');
      assert.doesNotMatch(body, /\b(host|sni|port|path|direct_ip|destination|endpoint)\b\s+(TEXT|INT)/);
    });

    it(`${label}: archive is one-way and history is never updated in place or deleted`, () => {
      for (const table of ['application_entry_paths', 'protection_expectations', 'protection_comparison_baselines']) {
        assert.match(sql, new RegExp(`CREATE TRIGGER ${table}_archive_only\\s+BEFORE UPDATE OR DELETE ON ${table}\\s+FOR EACH ROW EXECUTE FUNCTION astranull_protection_record_archive_only\\(\\)`));
        assert.match(
          constraintBody(sql, table, `${table}_archive_check`),
          /status = 'active' AND archived_at IS NULL AND archived_by IS NULL[\s\S]*status = 'archived' AND archived_at IS NOT NULL/,
        );
      }
      for (const table of ['protection_comparison_evaluations', 'protection_comparison_evidence_refs']) {
        assert.match(sql, new RegExp(`CREATE TRIGGER ${table}_immutable\\s+BEFORE UPDATE OR DELETE ON ${table}\\s+FOR EACH ROW EXECUTE FUNCTION astranull_reject_protection_comparison_mutation\\(\\)`));
      }
      const fn = /FUNCTION astranull_protection_record_archive_only\(\)[\s\S]*?\$\$;/.exec(sql)?.[0] ?? '';
      assert.match(fn, /TG_OP = 'DELETE'[\s\S]*?RAISE EXCEPTION/);
      assert.match(fn, /OLD\.status = 'archived'[\s\S]*?RAISE EXCEPTION/);
      assert.match(fn, /to_jsonb\(NEW\) - ARRAY\['status', 'archived_at', 'archived_by'\]/);
    });

    it(`${label}: provenance and result payloads are bounded objects/arrays`, () => {
      for (const table of TABLES.filter((t) => t !== 'protection_comparison_evidence_refs')) {
        assert.match(
          constraintBody(sql, table, `${table}_provenance_object`),
          /jsonb_typeof\(provenance_json\) = 'object'\s+AND octet_length\(provenance_json::text\) <= 16384/,
        );
      }
      const items = constraintBody(sql, 'protection_comparison_evaluations', 'protection_comparison_evaluations_items_check');
      assert.match(items, /jsonb_typeof\(items_json\) = 'array'/);
      assert.match(items, /jsonb_array_length\(items_json\) = total_count/);
      assert.match(items, /octet_length\(items_json::text\) <= \d+/);
      assert.match(
        constraintBody(sql, 'protection_comparison_evaluations', 'protection_comparison_evaluations_counts_check'),
        new RegExp(`total_count BETWEEN 0 AND ${MAX_COMPARISON_ITEMS}`),
      );
      assert.match(
        constraintBody(sql, 'protection_comparison_baselines', 'protection_comparison_baselines_reference_count_check'),
        new RegExp(`reference_count BETWEEN 1 AND ${MAX_EVIDENCE_REFERENCES}`),
      );
      assert.match(
        constraintBody(sql, 'protection_comparison_evidence_refs', 'protection_comparison_evidence_refs_evidence_ids_check'),
        new RegExp(`cardinality\\(evidence_ids\\) <= ${MAX_EVIDENCE_IDS_PER_REFERENCE}`),
      );
      assert.match(
        constraintBody(sql, 'protection_comparison_evidence_refs', 'protection_comparison_evidence_refs_ordinal_check'),
        new RegExp(`ordinal BETWEEN 0 AND ${MAX_EVIDENCE_REFERENCES - 1}`),
      );
      assert.match(
        constraintBody(sql, 'protection_comparison_baselines', 'protection_comparison_baselines_freshness_check'),
        new RegExp(`freshness_window_seconds BETWEEN ${MIN_FRESHNESS_WINDOW_SECONDS} AND ${MAX_FRESHNESS_WINDOW_SECONDS}`),
      );
      for (const table of TABLES) {
        assert.doesNotMatch(tableBody(sql, table), /\b(raw_payload|request_body|response_body|header_dump|packet_capture|credential|password|secret|api_key)\b/);
      }
    });

    it(`${label}: zero items, incompatible, or stale evidence can never be accepted`, () => {
      const accepted = constraintBody(sql, 'protection_comparison_evaluations', 'protection_comparison_evaluations_accepted_check');
      assert.match(accepted, /NOT accepted\s+OR \(total_count > 0 AND \(kind <> 'firewall_change' OR \(comparable AND NOT stale\)\)\)/);
      assert.match(
        constraintBody(sql, 'protection_comparison_evaluations', 'protection_comparison_evaluations_firewall_baseline_check'),
        /kind <> 'firewall_change' OR \(baseline_id IS NOT NULL AND baseline_digest IS NOT NULL\)/,
      );
      assert.match(
        constraintBody(sql, 'protection_comparison_evidence_refs', 'protection_comparison_evidence_refs_baseline_source_check'),
        /baseline_id IS NULL OR \(source_perspective IS NOT NULL AND worker_id IS NOT NULL\)/,
      );
      assert.match(
        constraintBody(sql, 'protection_comparison_evidence_refs', 'protection_comparison_evidence_refs_owner_check'),
        /\(baseline_id IS NULL\) <> \(evaluation_id IS NULL\)/,
      );
    });

    it(`${label}: CHECK enums match the PV-02 contract exactly`, () => {
      assertListsExactly(constraintBody(sql, 'application_entry_paths', 'application_entry_paths_relation_kind_check'), ENTRY_PATH_RELATION_KINDS, 'relation kinds');
      assertListsExactly(constraintBody(sql, 'application_entry_paths', 'application_entry_paths_expected_behavior_check'), ENTRY_PATH_EXPECTED_BEHAVIORS, 'entry expected behavior');
      assertListsExactly(constraintBody(sql, 'application_entry_paths', 'application_entry_paths_required_layers_check'), PROTECTION_LAYERS, 'layers');
      assertListsExactly(constraintBody(sql, 'protection_expectations', 'protection_expectations_protocol_check'), FIREWALL_PROTOCOLS, 'protocols');
      assertListsExactly(constraintBody(sql, 'protection_expectations', 'protection_expectations_expected_check'), FIREWALL_EXPECTED_BEHAVIORS, 'firewall expected');
      const outcomes = constraintBody(sql, 'protection_expectations', 'protection_expectations_layer_outcomes_check');
      for (const value of PATH_LAYER_EXPECTED_OUTCOMES) assert.ok(outcomes.includes(`@ == "${value}"`), value);
      for (const value of quotedList(PROTECTION_LAYERS)) assert.ok(outcomes.includes(value), value);
      for (const table of ['protection_expectations', 'protection_comparison_baselines', 'protection_comparison_evaluations']) {
        assertListsExactly(constraintBody(sql, table, `${table}_kind_check`), ['path_validation', 'firewall_change'], `${table} kind`);
      }
      assertListsExactly(
        constraintBody(sql, 'protection_comparison_evaluations', 'protection_comparison_evaluations_compatibility_reasons_check'),
        COMPATIBILITY_REASONS,
        'compatibility reasons',
      );
      const limitations = constraintBody(sql, 'protection_comparison_evaluations', 'protection_comparison_evaluations_limitations_check');
      const allowed = /limitations <@ ARRAY\[([\s\S]*?)\]::TEXT\[\]/.exec(limitations)?.[1] ?? '';
      assertListsExactly(allowed, PROTECTION_VALIDATION_LIMITATIONS, 'limitations');
      for (const [kind, required] of Object.entries(REQUIRED_LIMITATIONS)) {
        const block = new RegExp(`kind <> '${kind}'\\s+OR limitations @> ARRAY\\[([\\s\\S]*?)\\]::TEXT\\[\\]`).exec(limitations)?.[1] ?? '';
        assertListsExactly(block, required, `${kind} required limitations`);
      }
      for (const table of ['application_entry_paths', 'protection_expectations', 'protection_comparison_baselines']) {
        assertListsExactly(constraintBody(sql, table, `${table}_status_check`), ['active', 'archived'], `${table} status`);
      }
    });
  }

  it('schema.sql block mirrors the migration DDL without guard clauses', () => {
    assert.ok(schemaText.includes(SCHEMA_MARKER));
    assert.doesNotMatch(schemaBlock, /IF NOT EXISTS|DROP (CONSTRAINT|TRIGGER|POLICY) IF EXISTS/);
    const normalize = (sql) => sql
      .replace(/ALTER TABLE \w+\n  DROP CONSTRAINT IF EXISTS \w+;\n/g, '')
      .replace(/DROP (TRIGGER|POLICY) IF EXISTS [^\n]*;\n/g, '')
      .replace(/IF NOT EXISTS /g, '')
      .replace(/\s+/g, ' ')
      .trim();
    assert.equal(normalize(schemaBlock), normalize(migrationSql));
    for (const table of TABLES) {
      assert.equal(schemaText.match(new RegExp(`CREATE TABLE ${escapeRe(table)} \\(`, 'g'))?.length, 1, table);
    }
  });
});
