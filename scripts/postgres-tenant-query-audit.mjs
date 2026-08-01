#!/usr/bin/env node
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const ROOT = path.resolve(__dirname, '..');

export const ARTIFACT_TYPE = 'postgres_tenant_query_audit';
export const SCHEMA_VERSION = 1;

/** Basenames skipped entirely (migrations, pool, runtime wiring, tenant helper). */
export const SKIP_FILE_BASENAMES = new Set([
  'migrations.mjs',
  'pool.mjs',
  'tenantContext.mjs',
  'runtime.mjs',
]);

/** Tables without per-tenant RLS (documented global exceptions). */
export const GLOBAL_TABLES = new Set(['schema_migrations', 'platform_metrics']);

/**
 * Statements that place a table under per-tenant row-level security.
 *
 * The RLS DDL is the authoritative definition of "tenant-scoped", so the audit derives
 * its table list from these statements instead of a hand-maintained copy that silently
 * drifts as migrations add tables. Policy *names* are deliberately not used as the
 * source: db/schema.sql omits the five internal-management policies, so a name-based
 * scan would miss those tables entirely.
 */
const RLS_ENABLE_RE =
  /ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"?([a-z_][a-z0-9_]*)"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;

/**
 * Materialized views carrying a `tenant_id`, matched up to the statement-terminating
 * semicolon so the body can be inspected.
 *
 * These need auditing precisely *because* the RLS DDL above can never name them:
 * PostgreSQL does not apply row-level security to materialized views, so there is no
 * `ENABLE ROW LEVEL SECURITY` statement to derive them from. That makes them the
 * inverse of every other tenant table here — an RLS table whose query forgets its
 * tenant predicate is still contained by the database, whereas an unscoped read of
 * one of these views returns every tenant's rows with nothing to stop it. Deriving
 * them from DDL rather than a hand-kept list keeps that from depending on whoever
 * adds the next view remembering to register it.
 *
 * Every materialized view is included, without inspecting the body for a `tenant_id`
 * column. Sniffing the body would fail in the wrong direction: the check would have to
 * guess where the statement ends, and a body that defeated the guess would be silently
 * dropped from the audit — the exact failure this exists to prevent. Including a view
 * that turns out to be genuinely platform-wide costs one `GLOBAL_TABLES` entry or an
 * explicit `tenant-query-audit: allow` comment, and that registration is a deliberate,
 * reviewable act rather than a regex outcome.
 */
const MATERIALIZED_VIEW_RE =
  /CREATE\s+MATERIALIZED\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z_][a-z0-9_]*)"?/gi;

/**
 * SQL sources scanned for RLS DDL: the consolidated schema plus every migration, since
 * tables added after schema.sql was last regenerated only appear in migrations.
 * @param {string} root
 */
export function tenantScopedTableSqlSources(root = ROOT) {
  const sources = [];
  const schemaPath = path.join(root, 'db', 'schema.sql');
  if (existsSync(schemaPath)) sources.push(schemaPath);
  const migrationsDir = path.join(root, 'db', 'migrations');
  if (existsSync(migrationsDir)) {
    sources.push(
      ...readdirSync(migrationsDir)
        .filter((name) => name.endsWith('.sql'))
        .sort()
        .map((name) => path.join(migrationsDir, name)),
    );
  }
  return sources;
}

/**
 * Tenant-scoped relations, derived from DDL so the list cannot drift from the schema.
 *
 * Two sources, because one cannot cover the other: RLS statements for tables, and
 * `CREATE MATERIALIZED VIEW` for views that RLS structurally cannot protect.
 * @param {string} root
 */
export function deriveTenantScopedTables(root = ROOT) {
  const tables = new Set();
  let sawRls = false;
  for (const sqlPath of tenantScopedTableSqlSources(root)) {
    const sql = readFileSync(sqlPath, 'utf8');
    for (const re of [RLS_ENABLE_RE, MATERIALIZED_VIEW_RE]) {
      re.lastIndex = 0;
      let match = re.exec(sql);
      while (match) {
        if (re === RLS_ENABLE_RE) sawRls = true;
        const table = match[1].toLowerCase();
        if (!GLOBAL_TABLES.has(table)) tables.add(table);
        match = re.exec(sql);
      }
    }
  }
  // Fail closed: an empty list would silently pass every query in the repo. The RLS
  // check is separate from `tables.size` because a schema whose only match came from
  // a materialized view means the RLS scan silently broke.
  if (!sawRls) {
    throw new Error(
      'No ENABLE ROW LEVEL SECURITY statements found in db/schema.sql or db/migrations; '
      + 'cannot derive tenant-scoped table list.',
    );
  }
  if (tables.size === 0) {
    throw new Error('Derived tenant-scoped relation list is empty; refusing to pass every query.');
  }
  return Object.freeze([...tables].sort());
}

export const TENANT_SCOPED_TABLES = deriveTenantScopedTables();

/**
 * Longest table names first so alternation cannot settle for a shorter prefix match.
 * @param {readonly string[]} tables
 */
export function buildTenantTableRe(tables = TENANT_SCOPED_TABLES) {
  const ordered = [...tables].sort((a, b) => b.length - a.length);
  return new RegExp(
    `\\b(?:FROM|INTO|UPDATE|JOIN|DELETE\\s+FROM)\\s+"?(${ordered.join('|')})"?\\b`,
    'gi',
  );
}

const TENANT_TABLE_RE = buildTenantTableRe();

const CONTEXT_BEFORE_CHARS = 2400;
const MAX_QUERY_LABEL_LEN = 48;

const FORBIDDEN_OUTPUT_PATTERNS = [
  /\bcustomer_data\b/i,
  /postgres(?:ql)?:\/\//i,
  /\bINSERT\s+INTO\s+\w+\s*\([^)]{40,}/i,
  /\bSELECT\s+[\w*,\s]{60,}\s+FROM\b/i,
];

const ALLOW_COMMENT_RE = /tenant-query-audit:\s*(?:allow|global)/i;

/**
 * @param {string} root
 */
export function defaultPostgresAuditPaths(root = ROOT) {
  const dir = path.join(root, 'src', 'persistence', 'postgres');
  return readdirSync(dir)
    .filter(
      (name) =>
        (name.endsWith('Repository.mjs') || name.endsWith('ServiceAdapters.mjs')) &&
        !SKIP_FILE_BASENAMES.has(name),
    )
    .map((name) => path.join(dir, name))
    .sort();
}

/**
 * @param {string[]} argv
 */
export function parseArgs(argv) {
  const options = {
    paths: [],
    out: '',
    evidenceUri: '',
    allowFindings: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      options.help = true;
      continue;
    }
    if (arg === '--allow-findings') {
      options.allowFindings = true;
      continue;
    }
    if (arg === '--evidence-uri') {
      options.evidenceUri = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--out') {
      options.out = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--paths') {
      const value = argv[i + 1] ?? '';
      i += 1;
      if (!value.trim()) {
        throw new Error('--paths requires a comma-separated file list.');
      }
      options.paths.push(
        ...value
          .split(',')
          .map((entry) => entry.trim())
          .filter(Boolean),
      );
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return options;
}

function lineNumberAt(source, index) {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i += 1) {
    if (source[i] === '\n') line += 1;
  }
  return line;
}

/**
 * @param {string} source
 */
export function extractTemplateLiteralRegions(source) {
  /** @type {Array<{ content: string, startIndex: number, startLine: number }>} */
  const regions = [];
  let i = 0;
  while (i < source.length) {
    if (source[i] !== '`') {
      i += 1;
      continue;
    }
    const startIndex = i;
    const startLine = lineNumberAt(source, startIndex);
    i += 1;
    let content = '';
    while (i < source.length) {
      const ch = source[i];
      if (ch === '\\') {
        content += ' ';
        i += 2;
        continue;
      }
      if (ch === '$' && source[i + 1] === '{') {
        content += ' ';
        i += 2;
        let depth = 1;
        while (i < source.length && depth > 0) {
          if (source[i] === '{') depth += 1;
          else if (source[i] === '}') depth -= 1;
          i += 1;
        }
        continue;
      }
      if (ch === '`') {
        i += 1;
        regions.push({ content, startIndex, startLine });
        break;
      }
      content += ch;
      i += 1;
    }
  }
  return regions;
}

/**
 * @param {string} sql
 * @param {string} table
 */
export function buildQueryLabel(sql, table) {
  const compact = sql.replace(/\s+/g, ' ').trim();
  const match = compact.match(
    /\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]*?\b(?:FROM|INTO)\s+([a-z_][a-z0-9_]*)/i,
  );
  const verb = match?.[1]?.toUpperCase() ?? 'QUERY';
  const label = `${verb}:${table}`;
  if (label.length <= MAX_QUERY_LABEL_LEN) return label;
  return label.slice(0, MAX_QUERY_LABEL_LEN);
}

/**
 * @param {string} sql
 * @param {string} table
 * @param {string} contextBefore
 */
const CROSS_TENANT_ENUMERATION_RE = /\bSELECT\s+DISTINCT\s+tenant_id\b/i;

/**
 * Ways a query can genuinely constrain rows to one tenant.
 *
 * A bare mention of `tenant_id` anywhere in the statement is not one of them: it also
 * matches `ORDER BY tenant_id`, `SELECT tenant_id`, and `GROUP BY tenant_id`, none of
 * which scope the result set. The reference has to appear in a predicate, a join
 * condition, or an INSERT column list.
 */
const TENANT_PREDICATE_RES = [
  // WHERE / AND / OR / ON [alias.]tenant_id = $1 | IN (...) | = ANY($1)
  /\b(?:WHERE|AND|OR|ON)\s+\(*\s*(?:[a-z_][a-z0-9_]*\.)?"?tenant_id"?\s*(?:=|\bIN\b)/i,
  // JOIN ... USING (tenant_id)
  /\bUSING\s*\(\s*[^)]*\btenant_id\b/i,
  // INSERT INTO t (tenant_id, ...) — the column list carries the tenant
  /\bINSERT\s+INTO\s+[^(]*\(\s*[^)]*\btenant_id\b/i,
  // Equality against a bound parameter or a correlated column, wherever it appears
  /\btenant_id"?\s*=\s*(?:\$\d+|ANY\s*\(|(?:[a-z_][a-z0-9_]*\.)?"?tenant_id"?)/i,
];

/**
 * @param {string} sql
 */
export function hasTenantPredicate(sql) {
  return TENANT_PREDICATE_RES.some((re) => re.test(sql));
}

/**
 * Blank out comment bodies so PROSE cannot satisfy a scoping check.
 *
 * Every heuristic below looks for evidence of tenant scoping as raw text, and `contextBefore`
 * included comments — so a comment that merely MENTIONED `withTenantContext`, `app.tenant_id`, or
 * `tenant_id = $1` silenced the check for the next query. Found the hard way: the justification
 * comments written for the two queries this gate legitimately allows referenced all three tokens,
 * and removing their `tenant-query-audit: allow` markers changed nothing, because the surrounding
 * prose was doing the silencing. Any developer explaining tenant scoping in a comment would have
 * had the same effect, which makes it a fail-open in the gate rather than a one-off mistake.
 *
 * Replaces content with spaces rather than deleting it, so offsets and line structure survive for
 * anything downstream that measures them.
 *
 * The allow marker is deliberately checked BEFORE this runs: that one is meant to be a comment.
 *
 * @param {string} text
 * @returns {string}
 */
export function stripCommentBodies(text) {
  const blank = (match) => match.replace(/[^\n]/g, ' ');
  return text
    // Block comments first: a `//` inside one must not be treated as a line comment.
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/\/\/[^\n]*/g, blank)
    // SQL line comments, for query text carrying its own commentary.
    .replace(/--[^\n]*/g, blank);
}

export function hasTenantContext(sql, table, contextBefore) {
  // Checked on the RAW context: this marker is an explicit, reviewed opt-out and is supposed to be
  // a comment. Everything after this point reads comment-stripped text instead.
  if (ALLOW_COMMENT_RE.test(contextBefore)) return true;

  // Prose must not count as scoping. Stripping can only REMOVE apparent evidence, so the failure
  // direction is a finding on correct code (loud, caught in CI) rather than a silent pass.
  const code = stripCommentBodies(contextBefore);
  const sqlCode = stripCommentBodies(sql);

  if (CROSS_TENANT_ENUMERATION_RE.test(sql) && !/\bwithTenantContext\b/.test(code)) {
    return false;
  }
  if (hasTenantPredicate(sql) && !CROSS_TENANT_ENUMERATION_RE.test(sql)) return true;
  if (/app\.tenant_id|set_config\s*\(\s*['"]app\.tenant_id['"]|current_setting\s*\(\s*['"]app\.tenant_id['"]/i.test(
    `${code}\n${sqlCode}`,
  )) {
    return true;
  }
  if (/\bwithTenantContext\b/.test(code)) return true;
  if (/\btenant_id\s*=\s*\$/i.test(code)) return true;
  if (/['"]tenant_id\s*=\s*\$1['"]/.test(code)) return true;
  if (/\['tenant_id\s*=\s*\$1'\]/.test(code)) return true;
  if (/\bconditions\s*=\s*\[[^\]]*tenant_id\s*=\s*\$1/.test(code)) return true;
  if (table === 'tenants' && /\bWHERE\s+id\s*=\s*\$/i.test(sql)) return true;
  return false;
}

/**
 * @param {string} filePath
 * @param {string} root
 */
export function normalizeAuditPath(filePath, root = ROOT) {
  const resolved = path.resolve(filePath);
  const rootResolved = path.resolve(root);
  const prefix = `${rootResolved}${path.sep}`;
  if (resolved === rootResolved) return '';
  if (resolved.startsWith(prefix)) {
    return path.relative(rootResolved, resolved).split(path.sep).join('/');
  }
  return filePath;
}

/**
 * @param {ReturnType<typeof auditFiles>} report
 * @param {string} [root]
 */
export function normalizeAuditReport(report, root = ROOT) {
  return {
    ...report,
    scanned_files: report.scanned_files.map((file) => normalizeAuditPath(file, root)),
    findings: report.findings.map((finding) => ({
      ...finding,
      file: normalizeAuditPath(finding.file, root),
    })),
  };
}

/**
 * @param {string} source
 */
export function extractSingleQuotedQueryRegions(source) {
  /** @type {Array<{ content: string, startIndex: number, startLine: number }>} */
  const regions = [];
  const re = /\.query\s*\(\s*'((?:\\'|[^'])*)'/g;
  let match = re.exec(source);
  while (match) {
    const content = match[1].replace(/\\'/g, "'");
    const startIndex = match.index;
    regions.push({
      content,
      startIndex,
      startLine: lineNumberAt(source, startIndex),
    });
    match = re.exec(source);
  }
  return regions;
}

/**
 * Text preceding a query, with completed sibling blocks removed.
 *
 * A flat `source.slice(startIndex - N, startIndex)` window credits scoping that belongs to an
 * entirely different function. Measured before this existed: an unscoped
 * `pool.query('SELECT * FROM findings ORDER BY created_at DESC')` is correctly flagged on its own,
 * but goes UNFLAGGED when any earlier function in the file used `withTenantContext` or ran a query
 * carrying `tenant_id = $1` within the window. That is a false negative in a gate whose whole job is
 * catching cross-tenant reads — it passed a query returning every tenant's rows.
 *
 * So walk backwards instead of slicing. Maintaining brace depth means a balanced `{...}` block that
 * has already closed before the query is a SIBLING scope and is dropped wholesale, while an
 * unmatched `{` is an ancestor scope opening and is kept along with the header that introduced it.
 * That keeps `withTenantContext(pool, tenantId, async (client) => {` — real scoping the query is
 * genuinely inside — and discards the closed function next door.
 *
 * HEURISTIC, deliberately: this counts braces without parsing, so a brace inside a string literal,
 * a regex, or a comment can skew the depth. The failure directions are not symmetric, which is why
 * a heuristic is acceptable here. Keeping too LITTLE context reports a finding on correct code —
 * loud, and caught by CI immediately. Keeping too MUCH reproduces the false negative above, which is
 * silent. Since dropped siblings only ever REMOVE text that a flat window would have included, the
 * bias is toward the loud direction.
 *
 * @param {string} source
 * @param {number} startIndex
 * @returns {string}
 */
export function enclosingScopeContext(source, startIndex) {
  // Bounds the backwards walk. Larger than the kept-context cap because dropped sibling blocks do
  // not count toward it: a query after several long functions still has to reach its own header.
  const SCAN_BUDGET = 200_000;
  const scanStart = Math.max(0, startIndex - SCAN_BUDGET);
  /** @type {string[]} */
  const kept = [];
  let keptLength = 0;
  let depth = 0;

  for (let i = startIndex - 1; i >= scanStart; i -= 1) {
    const char = source[i];
    if (char === '}') {
      // Walking backwards, a closing brace opens a sibling block: skip until it balances.
      depth += 1;
      continue;
    }
    if (char === '{') {
      if (depth > 0) {
        depth -= 1;
        continue;
      }
      // Unmatched: an ancestor scope's opening brace. Keep it and the header before it.
      kept.push(char);
      keptLength += 1;
      if (keptLength >= CONTEXT_BEFORE_CHARS) break;
      continue;
    }
    if (depth > 0) continue;
    kept.push(char);
    keptLength += 1;
    if (keptLength >= CONTEXT_BEFORE_CHARS) break;
  }

  return kept.reverse().join('');
}

function auditSqlRegions(filePath, source, regions) {
  /** @type {Array<{ file: string, line: number, check: string, table: string, query_label: string }>} */
  const findings = [];

  for (const region of regions) {
    const contextBefore = enclosingScopeContext(source, region.startIndex);
    TENANT_TABLE_RE.lastIndex = 0;
    let match = TENANT_TABLE_RE.exec(region.content);
    while (match) {
      const table = match[1].toLowerCase();
      if (!GLOBAL_TABLES.has(table)) {
        if (!hasTenantContext(region.content, table, contextBefore)) {
          const line = region.startLine + (region.content.slice(0, match.index).match(/\n/g)?.length ?? 0);
          findings.push({
            file: filePath,
            line,
            check: 'missing_tenant_context',
            table,
            query_label: buildQueryLabel(region.content, table),
          });
        }
      }
      match = TENANT_TABLE_RE.exec(region.content);
    }
  }

  return findings;
}

/**
 * @param {string} filePath
 * @param {string} source
 */
export function auditSourceFile(filePath, source) {
  const basename = path.basename(filePath);
  if (SKIP_FILE_BASENAMES.has(basename)) {
    return [];
  }

  const templateRegions = extractTemplateLiteralRegions(source);
  const quotedRegions = extractSingleQuotedQueryRegions(source);
  return auditSqlRegions(filePath, source, [...templateRegions, ...quotedRegions]);
}

/**
 * @param {{ root?: string, paths?: string[], evidenceUri?: string, allowFindings?: boolean }} [options]
 */
export function buildProductionTenantQueryAuditEvidence(options = {}) {
  const root = options.root ?? ROOT;
  const filePaths =
    options.paths?.length > 0
      ? options.paths.map((entry) => path.resolve(root, entry))
      : defaultPostgresAuditPaths(root);
  const report = normalizeAuditReport(auditFiles(filePaths), root);
  assertReportMetadataOnly(report);
  if (report.finding_count > 0 && !options.allowFindings) {
    throw new Error(`postgres tenant query audit has ${report.finding_count} finding(s)`);
  }
  const evidence = {
    ...report,
    evidence_uri: options.evidenceUri ?? 'evidence://db/tenant-query-audit',
  };
  const validation = validateProductionReleaseEvidence('postgres_tenant_query_audit', evidence);
  if (!validation.ok) {
    const problems = [
      ...validation.missing_fields.map((field) => `missing:${field}`),
      ...validation.forbidden_fields.map((field) => `forbidden:${field}`),
      validation.invalid_kind ? `invalid_kind:${validation.invalid_kind}` : null,
    ].filter(Boolean);
    throw new Error(`postgres tenant query audit evidence invalid (${problems.join(', ')})`);
  }
  return evidence;
}

/**
 * @param {string[]} filePaths
 */
export function auditFiles(filePaths) {
  /** @type {Array<{ file: string, line: number, check: string, table: string, query_label: string }>} */
  const findings = [];
  const scanned_files = [];

  for (const filePath of filePaths) {
    const basename = path.basename(filePath);
    if (SKIP_FILE_BASENAMES.has(basename)) continue;
    scanned_files.push(filePath);
    const source = readFileSync(filePath, 'utf8');
    findings.push(...auditSourceFile(filePath, source));
  }

  return {
    artifact_type: ARTIFACT_TYPE,
    schema_version: SCHEMA_VERSION,
    scanned_files,
    finding_count: findings.length,
    findings,
  };
}

/**
 * @param {ReturnType<typeof auditFiles>} report
 */
export function assertReportMetadataOnly(report) {
  const serialized = JSON.stringify(report);
  for (const pattern of FORBIDDEN_OUTPUT_PATTERNS) {
    if (pattern.test(serialized)) {
      throw new Error(`Report violates metadata-only contract: ${pattern}`);
    }
  }
  for (const finding of report.findings) {
    if (!finding.query_label || finding.query_label.length > MAX_QUERY_LABEL_LEN) {
      throw new Error('query_label exceeds allowed length.');
    }
    if (/\b(WHERE|VALUES|RETURNING)\b/i.test(finding.query_label)) {
      throw new Error('query_label must not embed SQL fragments.');
    }
  }
  return true;
}

/**
 * @param {string[]} argv
 */
export function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(
      [
        'Usage: node scripts/postgres-tenant-query-audit.mjs [options]',
        '',
        '  --paths <a.mjs,b.mjs>   Comma-separated files (default: postgres repositories/adapters)',
        '  --out <file.json>       Write metadata-only JSON report',
        '  --evidence-uri <uri>    Attach production release evidence custody pointer',
        '  --allow-findings        Exit 0 even when findings are present',
        '  -h, --help              Show help',
        '',
      ].join('\n'),
    );
    return 0;
  }

  const filePaths =
    options.paths.length > 0 ? options.paths.map((p) => path.resolve(p)) : defaultPostgresAuditPaths();

  let report = auditFiles(filePaths);
  report = normalizeAuditReport(report, ROOT);
  assertReportMetadataOnly(report);
  if (options.evidenceUri) {
    report = { ...report, evidence_uri: options.evidenceUri };
  }

  const payload = `${JSON.stringify(report, null, 2)}\n`;
  if (options.out) {
    const outPath = path.resolve(options.out);
    mkdirSync(path.dirname(outPath), { recursive: true });
    writeFileSync(outPath, payload);
  } else {
    process.stdout.write(payload);
  }

  if (report.finding_count > 0 && !options.allowFindings) {
    return 1;
  }
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  process.exitCode = main();
}