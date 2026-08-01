import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  auditSourceFile,
  buildTenantTableRe,
  deriveTenantScopedTables,
  enclosingScopeContext,
  hasTenantContext,
  hasTenantPredicate,
  stripCommentBodies,
  TENANT_SCOPED_TABLES,
} from '../../scripts/postgres-tenant-query-audit.mjs';

/**
 * These cover the two fail-open holes in the tenant-scoping gate:
 *   1. any mention of `tenant_id` anywhere satisfied the check, so unscoped queries passed;
 *   2. the tenant-scoped table list was hand-maintained and had drifted from the RLS DDL,
 *      so queries against omitted tables were never inspected at all.
 */
describe('postgres tenant query audit scoping', () => {
  it('requires tenant_id in a predicate, not just anywhere in the statement', () => {
    // Each of these mentions tenant_id but none of them constrain the result set.
    assert.equal(hasTenantPredicate('SELECT * FROM findings ORDER BY tenant_id'), false);
    assert.equal(hasTenantPredicate('SELECT tenant_id, title FROM findings'), false);
    assert.equal(hasTenantPredicate('SELECT count(*) FROM findings GROUP BY tenant_id'), false);
    assert.equal(hasTenantPredicate('SELECT * FROM findings /* tenant_id */'), false);

    // Real predicates and tenant-carrying writes.
    assert.equal(hasTenantPredicate('SELECT * FROM findings WHERE tenant_id = $1'), true);
    assert.equal(hasTenantPredicate('SELECT * FROM findings WHERE f.tenant_id = $1'), true);
    assert.equal(hasTenantPredicate('SELECT * FROM findings WHERE tenant_id IN ($1, $2)'), true);
    assert.equal(hasTenantPredicate('SELECT * FROM findings WHERE tenant_id = ANY($1::uuid[])'), true);
    assert.equal(hasTenantPredicate('UPDATE findings SET x = $2 WHERE tenant_id = $1'), true);
    assert.equal(hasTenantPredicate('INSERT INTO findings (tenant_id, id) VALUES ($1, $2)'), true);
    assert.equal(
      hasTenantPredicate('SELECT * FROM findings f JOIN targets t ON t.tenant_id = f.tenant_id'),
      true,
    );
  });

  it('flags an ORDER BY tenant_id query and passes a WHERE-scoped one', () => {
    const unscoped = auditSourceFile(
      'src/persistence/postgres/exampleRepository.mjs',
      'const rows = await client.query(`SELECT * FROM findings ORDER BY tenant_id`);',
    );
    assert.equal(unscoped.length, 1);
    assert.equal(unscoped[0].check, 'missing_tenant_context');
    assert.equal(unscoped[0].table, 'findings');

    const scoped = auditSourceFile(
      'src/persistence/postgres/exampleRepository.mjs',
      'const rows = await client.query(`SELECT * FROM findings WHERE tenant_id = $1`, [tenantId]);',
    );
    assert.deepEqual(scoped, []);
  });

  it('still accepts an explicit withTenantContext wrapper in surrounding context', () => {
    const source = [
      'export async function listFindings(pool, tenantId) {',
      '  return withTenantContext(pool, tenantId, async (client) => {',
      '    const { rows } = await client.query(`SELECT * FROM findings ORDER BY created_at`);',
      '    return rows;',
      '  });',
      '}',
    ].join('\n');
    assert.deepEqual(auditSourceFile('src/persistence/postgres/exampleRepository.mjs', source), []);
    assert.equal(
      hasTenantContext('SELECT * FROM findings', 'findings', 'withTenantContext(pool, tenantId,'),
      true,
    );
  });

  it('inspects bare single-quoted pool.query calls against internal tables', () => {
    // internal_audit_log was missing from the hand-maintained list, so this query was
    // never inspected. It is now derived from the RLS DDL and fails closed.
    const findings = auditSourceFile(
      'src/persistence/postgres/exampleRepository.mjs',
      "const { rows } = await pool.query('SELECT * FROM internal_audit_log ORDER BY created_at DESC');",
    );
    assert.equal(findings.length, 1);
    assert.equal(findings[0].table, 'internal_audit_log');
    assert.equal(findings[0].check, 'missing_tenant_context');
  });

  it('derives the tenant-scoped table list from the RLS DDL', () => {
    const derived = deriveTenantScopedTables();
    // Tables the previous hand-maintained list omitted.
    for (const table of [
      'tenant_accounts',
      'internal_audit_log',
      'signup_queue_events',
      'finding_remediations',
      'dns_challenges',
      'test_policies',
    ]) {
      assert.ok(derived.includes(table), `expected derived RLS table list to include ${table}`);
    }
    assert.deepEqual([...TENANT_SCOPED_TABLES], [...derived]);
    // Documented global exceptions must never be treated as tenant-scoped.
    assert.equal(derived.includes('schema_migrations'), false);
    assert.equal(derived.includes('platform_metrics'), false);
  });

  it('matches the longest table name so alternation cannot settle for a prefix', () => {
    const re = buildTenantTableRe(['waf_assets', 'waf_asset']);
    re.lastIndex = 0;
    assert.equal(re.exec('SELECT * FROM waf_assets')?.[1], 'waf_assets');
  });

  /**
   * Materialized views are the one relation kind the RLS scan structurally cannot find:
   * PostgreSQL does not apply row-level security to a matview, so no ENABLE ROW LEVEL
   * SECURITY statement exists to derive it from. That inverts the usual safety margin —
   * an unscoped query against an RLS table is still contained by the database, while an
   * unscoped read here returns every tenant's rows.
   */
  describe('materialized view coverage', () => {
    it('covers waf_coverage_summary despite it having no RLS DDL', () => {
      assert.ok(
        TENANT_SCOPED_TABLES.includes('waf_coverage_summary'),
        'matview must be audited: RLS cannot protect it, so the query predicate is the only control',
      );
    });

    it('flags an unscoped matview read and accepts the scoped read plus REFRESH', () => {
      const unscoped = auditSourceFile(
        'src/persistence/postgres/exampleRepository.mjs',
        'const { rows } = await pool.query(`SELECT * FROM waf_coverage_summary`);',
      );
      assert.equal(unscoped.length, 1);
      assert.equal(unscoped[0].table, 'waf_coverage_summary');
      assert.equal(unscoped[0].check, 'missing_tenant_context');

      // REFRESH is whole-view maintenance with no rows returned to a caller, so it must
      // not be mistaken for an unscoped read; the real read carries tenant_id = $1.
      const legitimate = auditSourceFile(
        'src/persistence/postgres/exampleRepository.mjs',
        [
          "await pool.query('REFRESH MATERIALIZED VIEW CONCURRENTLY waf_coverage_summary');",
          'const { rows } = await client.query(',
          '  `SELECT * FROM waf_coverage_summary WHERE tenant_id = $1`, [ctx.tenantId]);',
        ].join('\n'),
      );
      assert.deepEqual(legitimate, []);
    });

    it('fails closed when the RLS scan finds nothing but a matview still matches', () => {
      // Guards the derivation itself: if the RLS regex silently stopped matching, a lone
      // matview would keep the list non-empty and every RLS table would go unaudited.
      const root = mkdtempSync(path.join(tmpdir(), 'astranull-audit-'));
      mkdirSync(path.join(root, 'db', 'migrations'), { recursive: true });
      writeFileSync(
        path.join(root, 'db', 'migrations', '0001_only_a_matview.sql'),
        'CREATE MATERIALIZED VIEW tenant_rollup AS SELECT tenant_id FROM things;',
      );
      assert.throws(
        () => deriveTenantScopedTables(root),
        /No ENABLE ROW LEVEL SECURITY statements found/,
      );
      rmSync(root, { recursive: true, force: true });
    });
  });

  /**
   * Two fail-opens in how surrounding context was gathered. Both let the gate PASS a query that
   * reads across tenants, which is the one outcome it exists to prevent.
   */
  describe('context scoping cannot be borrowed', () => {
    /** An unscoped read of an audited table. Flagged whenever context does not excuse it. */
    const UNSCOPED = 'export async function listEverything(pool) {\n'
      + '  const { rows } = await pool.query(`SELECT * FROM findings ORDER BY created_at DESC`);\n'
      + '  return rows;\n'
      + '}';
    const FILE = 'src/persistence/postgres/exampleRepository.mjs';

    it('flags the unscoped read on its own (control for the cases below)', () => {
      const findings = auditSourceFile(FILE, UNSCOPED);
      assert.equal(findings.length, 1, 'baseline must flag, or the later assertions prove nothing');
      assert.equal(findings[0].table, 'findings');
    });

    it('does not credit an unrelated earlier function for a later unscoped query', () => {
      // The original defect: contextBefore was a flat 2400-char slice, so a DIFFERENT function's
      // withTenantContext (and its tenant_id = $1) silenced this one. Measured before the fix:
      // this exact source produced 0 findings.
      const source = [
        'export async function listScoped(pool, tenantId) {',
        '  return withTenantContext(pool, tenantId, async (client) => {',
        '    const { rows } = await client.query(`SELECT * FROM findings WHERE tenant_id = $1`, [tenantId]);',
        '    return rows;',
        '  });',
        '}',
        '',
        UNSCOPED,
      ].join('\n');
      const findings = auditSourceFile(FILE, source);
      assert.equal(findings.length, 1, 'a closed sibling scope must not excuse the next query');
      assert.equal(findings[0].table, 'findings');
    });

    it('still accepts a query genuinely nested inside the scoping wrapper', () => {
      // The counterpart risk: dropping too much context would flag correct code. An ancestor scope
      // that has NOT closed yet must still count.
      const source = [
        'export async function listScoped(pool, tenantId) {',
        '  return withTenantContext(pool, tenantId, async (client) => {',
        '    if (tenantId) {',
        '      const { rows } = await client.query(`SELECT * FROM findings ORDER BY created_at`);',
        '      return rows;',
        '    }',
        '    return [];',
        '  });',
        '}',
      ].join('\n');
      assert.deepEqual(auditSourceFile(FILE, source), []);
    });

    it('keeps ancestor scope headers and drops closed sibling blocks', () => {
      const source = 'function sibling() { withTenantContext(a, b); }\nfunction outer() {\n  QUERY';
      const context = enclosingScopeContext(source, source.indexOf('QUERY'));
      assert.match(context, /function outer\(\) \{/, 'the enclosing header must survive');
      assert.doesNotMatch(
        context,
        /withTenantContext/,
        'a sibling body that already closed must be dropped',
      );
    });

    /**
     * Comments described scoping and the gate believed them.
     *
     * Found while checking that the two legitimate allow markers were load-bearing: removing them
     * changed nothing, because the justification prose around them mentioned withTenantContext,
     * app.tenant_id and tenant_id = $1. Any developer comment explaining tenant scoping had the
     * same effect.
     */
    for (const [label, comment] of [
      ['withTenantContext', '// callers wrap this in withTenantContext before calling'],
      ['app.tenant_id', '// relies on app.tenant_id being set by the caller'],
      ['tenant_id = $1', '// equivalent to tenant_id = $1 but resolved elsewhere'],
      ['block comment', '/* scoped via withTenantContext upstream */'],
      ['sql line comment', '-- app.tenant_id is set for this transaction'],
    ]) {
      it(`does not accept a comment mentioning ${label} as scoping`, () => {
        const findings = auditSourceFile(FILE, `${comment}\n${UNSCOPED}`);
        assert.equal(findings.length, 1, `prose mentioning ${label} must not silence the check`);
      });
    }

    it('still honours the explicit allow marker, which is meant to be a comment', () => {
      // Checked against raw text before stripping: this one is a reviewed opt-out, not prose.
      const source = '// tenant-query-audit: allow — reviewed cross-tenant staff aggregate\n'
        + UNSCOPED;
      assert.deepEqual(auditSourceFile(FILE, source), []);
    });

    it('blanks comment bodies without disturbing line structure', () => {
      const input = 'const a = 1; // withTenantContext\nconst b = 2;';
      const stripped = stripCommentBodies(input);
      assert.equal(stripped.length, input.length, 'offsets must survive');
      assert.equal(stripped.split('\n').length, 2, 'line count must survive');
      assert.doesNotMatch(stripped, /withTenantContext/);
      assert.match(stripped, /const a = 1;/, 'code outside the comment is untouched');
      assert.match(stripped, /const b = 2;/);
    });

    it('does not let a // inside a block comment resurrect the rest of the line', () => {
      const stripped = stripCommentBodies('/* // withTenantContext */ realCode()');
      assert.doesNotMatch(stripped, /withTenantContext/);
      assert.match(stripped, /realCode\(\)/, 'code after the block comment must remain');
    });

    it('does not treat real code as a comment', () => {
      // A scoped query must still pass: stripping may only remove comment text.
      assert.deepEqual(
        auditSourceFile(
          FILE,
          'const { rows } = await client.query(`SELECT * FROM findings WHERE tenant_id = $1`, [t]);',
        ),
        [],
      );
      assert.equal(
        hasTenantContext('SELECT * FROM findings', 'findings', 'withTenantContext(pool, tenantId,'),
        true,
        'real code evidence must still count',
      );
    });
  });
});
