#!/usr/bin/env node
/**
 * Projects the ignored source catalog into a deterministic, public-safe module.
 * This script performs metadata transformation only; it never executes probes.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const VECTOR_CATALOG_SOURCE_PATH = path.join(
  REPO_ROOT,
  'one_sheet_global_ddos_waf_attack_vector_catalog_2026-09-01.csv',
);
export const VECTOR_CATALOG_OUTPUT_PATH = path.join(
  REPO_ROOT,
  'src/lib/data/vectorCatalog.generated.mjs',
);
export const VECTOR_CATALOG_EXPECTED_ROWS = 721;

const PUBLIC_FIELD_MAP = Object.freeze([
  ['vector_id', 'Vector ID'],
  ['section', 'Catalog section'],
  ['domain', 'Domain'],
  ['scope', 'Primary layer / scope'],
  ['family', 'Family / area'],
  ['canonical_name', 'Canonical vector'],
  ['protocol_service', 'Protocol / service / common ports'],
  ['delivery_mechanism', 'Delivery / mechanism'],
  ['how_it_works', 'How it works'],
  ['targeted_resource_or_assumption', 'Security effect / resource / assumption targeted'],
  ['defensive_indicators', 'Typical defensive indicators'],
  ['primary_controls', 'Primary mitigations / required controls'],
  ['boundaries', 'Important boundaries'],
  ['validation_tier', 'Validation tier'],
]);

export const VECTOR_CATALOG_PUBLIC_FIELDS = Object.freeze(
  PUBLIC_FIELD_MAP.map(([field]) => field),
);

/** RFC 4180-compatible parser for the source's quoted multiline fields. */
export function parseCsv(input) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    if (quoted) {
      if (char === '"') {
        if (input[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"') {
      if (field.length !== 0) throw new Error(`Invalid CSV quote at character ${index}.`);
      quoted = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n' || char === '\r') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      if (char === '\r' && input[index + 1] === '\n') index += 1;
    } else {
      field += char;
    }
  }

  if (quoted) throw new Error('Invalid CSV: unterminated quoted field.');
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  while (rows.length > 0 && rows.at(-1).every((value) => value === '')) rows.pop();
  return rows;
}

function normalizePublicField(value) {
  return String(value ?? '').replace(/\r\n?/g, '\n').trim();
}

export function projectVectorCatalog(csvText) {
  const records = parseCsv(csvText);
  if (records.length === 0) throw new Error('Vector catalog CSV is empty.');

  const headers = records[0].map((header, index) => (
    index === 0 ? header.replace(/^\uFEFF/, '') : header
  ));
  const headerIndex = new Map(headers.map((header, index) => [header, index]));
  for (const [, sourceHeader] of PUBLIC_FIELD_MAP) {
    if (!headerIndex.has(sourceHeader)) throw new Error(`Missing required CSV header: ${sourceHeader}`);
  }

  const projection = records.slice(1).map((record, rowIndex) => {
    if (record.length !== headers.length) {
      throw new Error(
        `CSV row ${rowIndex + 2} has ${record.length} columns; expected ${headers.length}.`,
      );
    }
    return Object.fromEntries(PUBLIC_FIELD_MAP.map(([field, sourceHeader]) => [
      field,
      normalizePublicField(record[headerIndex.get(sourceHeader)]),
    ]));
  });

  if (projection.length !== VECTOR_CATALOG_EXPECTED_ROWS) {
    throw new Error(
      `Vector catalog must contain exactly ${VECTOR_CATALOG_EXPECTED_ROWS} rows; found ${projection.length}.`,
    );
  }

  const seen = new Set();
  for (const row of projection) {
    if (!/^(NET|AMP|APP|WAF|EVA)-\d{3}$/.test(row.vector_id)) {
      throw new Error(`Invalid Vector ID: ${row.vector_id || '(empty)'}`);
    }
    if (seen.has(row.vector_id)) throw new Error(`Duplicate Vector ID: ${row.vector_id}`);
    seen.add(row.vector_id);
  }

  projection.sort((left, right) => (
    left.vector_id < right.vector_id ? -1 : left.vector_id > right.vector_id ? 1 : 0
  ));
  return projection;
}

export function renderVectorCatalogModule(rows, sourceSha256) {
  return `/**\n * GENERATED FILE — DO NOT EDIT.\n * Safe public metadata projected by scripts/generate-vector-catalog.mjs.\n * The source CSV is intentionally gitignored and is not part of this module.\n */\n\nexport const VECTOR_CATALOG_SOURCE_SHA256 = '${sourceSha256}';\nexport const VECTOR_CATALOG_TOTAL = ${VECTOR_CATALOG_EXPECTED_ROWS};\nexport const VECTOR_CATALOG = Object.freeze(${JSON.stringify(rows, null, 2)}.map((row) => Object.freeze(row)));\n`;
}

export function generateVectorCatalog({
  sourcePath = VECTOR_CATALOG_SOURCE_PATH,
  outputPath = VECTOR_CATALOG_OUTPUT_PATH,
  check = false,
} = {}) {
  const source = readFileSync(sourcePath);
  const rows = projectVectorCatalog(source.toString('utf8'));
  const sourceSha256 = createHash('sha256').update(source).digest('hex');
  const rendered = renderVectorCatalogModule(rows, sourceSha256);

  if (check) {
    const existing = readFileSync(outputPath, 'utf8');
    if (existing !== rendered) throw new Error(`Generated vector catalog is stale: ${outputPath}`);
    return { rows: rows.length, outputPath, sourceSha256, checked: true };
  }

  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, rendered, 'utf8');
  return { rows: rows.length, outputPath, sourceSha256, checked: false };
}

function main(argv = process.argv.slice(2)) {
  const unknown = argv.filter((argument) => argument !== '--check');
  if (unknown.length > 0) throw new Error(`Unknown argument: ${unknown[0]}`);
  const result = generateVectorCatalog({ check: argv.includes('--check') });
  process.stdout.write(
    `vector-catalog: ${result.checked ? 'in sync' : 'wrote projection'} (${result.rows} rows)\n`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(`vector-catalog: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
